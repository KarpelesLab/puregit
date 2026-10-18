//! Object-graph traversal — reachability and revision walking.
//!
//! Almost every non-trivial git operation needs to answer "what objects does
//! this commit reach?": packing a fetch/push response, `git log`, garbage
//! collection, and connectivity checks all walk the object graph. This module
//! provides that over any [`ObjectDatabase`]:
//!
//! - [`reachable_objects`] — the full closure of object ids reachable from a
//!   set of roots (commits → parents and tree; trees → entries; tags → target).
//! - [`objects_to_send`] — the closure of `wants` with everything reachable
//!   from `haves` excluded: exactly the object set a fetch/push must transfer.
//! - [`RevWalk`] — an iterator over commits in `git log` (newest-first date) order.
//!
//! Gitlink (submodule) tree entries are *not* followed — they name commits in
//! another repository. Objects missing from the database are skipped rather
//! than erroring, so a traversal bounded by `haves` (whose own history may be
//! incomplete in a shallow clone) does not fail.

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::object::tree::FileMode;
use crate::object::{Commit, ObjectType, Tag, Tree};
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;

/// Returns every object id reachable from `roots` (inclusive).
pub fn reachable_objects<D: ObjectDatabase>(
    odb: &D,
    roots: &[ObjectId],
) -> Result<BTreeSet<ObjectId>> {
    let exclude = BTreeSet::new();
    collect_closure(odb, roots, &exclude)
}

/// Returns every object id reachable from `roots` (inclusive) without entering
/// any id in `exclude` — the closure of `roots` minus an already-computed set,
/// e.g. the objects a fetch client is known to hold.
pub fn reachable_objects_excluding<D: ObjectDatabase>(
    odb: &D,
    roots: &[ObjectId],
    exclude: &BTreeSet<ObjectId>,
) -> Result<BTreeSet<ObjectId>> {
    collect_closure(odb, roots, exclude)
}

/// Collects the objects reachable from tree `tree_id` — the tree itself, its
/// subtrees, and their blobs — that are **not present** in `odb`, descending
/// only as far as the present objects allow: a missing subtree is recorded but
/// not walked into (its contents are unknown until it is fetched).
///
/// This is the promisor backfill scan: iterating *fetch the returned ids, then
/// re-scan* until it returns empty makes a partial (`--filter`) clone's full
/// tree closure local, so the working tree can be checked out. Gitlink
/// (submodule) commits are not included — they name objects in another
/// repository.
pub fn missing_tree_objects<D: ObjectDatabase>(
    odb: &D,
    tree_id: &ObjectId,
) -> Result<Vec<ObjectId>> {
    let mut missing = Vec::new();
    let mut seen = BTreeSet::new();
    collect_missing(odb, tree_id, &mut missing, &mut seen)?;
    Ok(missing)
}

fn collect_missing<D: ObjectDatabase>(
    odb: &D,
    tree_id: &ObjectId,
    missing: &mut Vec<ObjectId>,
    seen: &mut BTreeSet<ObjectId>,
) -> Result<()> {
    if !seen.insert(*tree_id) {
        return Ok(());
    }
    // A missing tree is recorded as a leaf: we cannot descend until it arrives.
    let (ty, payload) = match odb.read(tree_id) {
        Ok(v) => v,
        Err(Error::NotFound(_)) => {
            missing.push(*tree_id);
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if ty != ObjectType::Tree {
        return Ok(());
    }
    let tree = Tree::parse(odb.algo(), &payload)?;
    for entry in tree.entries {
        match entry.mode {
            FileMode::Tree => collect_missing(odb, &entry.id, missing, seen)?,
            FileMode::Gitlink => {} // a commit in another repository
            _ => {
                // A blob (regular file, executable, or symlink target).
                if seen.insert(entry.id) && !odb.contains(&entry.id) {
                    missing.push(entry.id);
                }
            }
        }
    }
    Ok(())
}

/// Returns the objects a transfer must send to give a peer `wants`, given that
/// it already has `haves`: the closure of `wants` minus everything reachable
/// from `haves`.
///
/// This is the object set for a fetch response or a push pack. It is the
/// standard (not maximally minimal) computation: any object reachable from a
/// `have` is assumed already present and is neither sent nor traversed into.
pub fn objects_to_send<D: ObjectDatabase>(
    odb: &D,
    wants: &[ObjectId],
    haves: &[ObjectId],
) -> Result<BTreeSet<ObjectId>> {
    let exclude = collect_closure(odb, haves, &BTreeSet::new())?;
    collect_closure(odb, wants, &exclude)
}

/// The result of a depth-limited traversal for a shallow fetch.
pub struct ShallowResult {
    /// Every object id to send: the included commits plus their tree/blob
    /// closures.
    pub objects: BTreeSet<ObjectId>,
    /// The shallow boundary — included commits whose parents were cut because
    /// they lie just beyond `depth`. These are the `shallow <oid>` lines.
    pub shallow: BTreeSet<ObjectId>,
}

/// Computes the objects for a shallow fetch: history truncated to `depth`
/// commits per want (depth 1 = the want commits only), plus the shallow
/// boundary.
///
/// Starting from the `wants`, commits are visited breadth-first by depth; a
/// commit at exactly `depth` that still has parents becomes a boundary
/// (`shallow`) commit and its parents are not traversed. Every included commit
/// contributes its full tree/blob closure. A commit already at the client's
/// existing shallow boundary (`already_shallow`) is treated as having no parents.
pub fn shallow_objects_to_send<D: ObjectDatabase>(
    odb: &D,
    wants: &[ObjectId],
    depth: u32,
    already_shallow: &BTreeSet<ObjectId>,
) -> Result<ShallowResult> {
    let depth = depth.max(1);
    let mut best_depth: alloc::collections::BTreeMap<ObjectId, u32> =
        alloc::collections::BTreeMap::new();
    let mut shallow = BTreeSet::new();
    let mut trees: Vec<ObjectId> = Vec::new();
    let mut commits: BTreeSet<ObjectId> = BTreeSet::new();

    let mut queue: VecDeque<(ObjectId, u32)> = wants.iter().map(|w| (*w, 1u32)).collect();
    while let Some((id, d)) = queue.pop_front() {
        // Skip if we've already reached this commit at an equal-or-shallower
        // depth (a commit reachable by several paths keeps its shallowest).
        if best_depth.get(&id).is_some_and(|&prev| prev <= d) {
            continue;
        }
        best_depth.insert(id, d);

        // A want may name a tag or tree directly; peel/collect accordingly.
        let (ty, payload) = match odb.read(&id) {
            Ok(v) => v,
            Err(Error::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        match ty {
            ObjectType::Commit => {
                commits.insert(id);
                let commit = Commit::parse(odb.algo(), &payload)?;
                trees.push(commit.tree);
                let at_boundary = d >= depth || already_shallow.contains(&id);
                if at_boundary {
                    if !commit.parents.is_empty() {
                        shallow.insert(id);
                    }
                } else {
                    for parent in commit.parents {
                        queue.push_back((parent, d + 1));
                    }
                }
            }
            ObjectType::Tag => {
                let tag = Tag::parse(odb.algo(), &payload)?;
                // Follow the tag to its target at the same depth.
                queue.push_back((tag.object, d));
                commits.insert(id); // the tag object itself must be sent
            }
            ObjectType::Tree => trees.push(id),
            ObjectType::Blob => {
                commits.insert(id);
            }
        }
    }

    // The tree/blob closure of every included commit, plus the commits/tags.
    let mut objects = collect_closure(odb, &trees, &BTreeSet::new())?;
    objects.extend(commits);
    Ok(ShallowResult { objects, shallow })
}

/// Walks the object graph from `roots`, never entering an id in `exclude`,
/// returning the set of visited ids (excluding the excluded ones).
fn collect_closure<D: ObjectDatabase>(
    odb: &D,
    roots: &[ObjectId],
    exclude: &BTreeSet<ObjectId>,
) -> Result<BTreeSet<ObjectId>> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<ObjectId> = roots
        .iter()
        .copied()
        .filter(|id| !exclude.contains(id))
        .collect();

    while let Some(id) = stack.pop() {
        if exclude.contains(&id) || !seen.insert(id) {
            continue;
        }
        let (ty, payload) = match odb.read(&id) {
            Ok(v) => v,
            Err(Error::NotFound(_)) => continue, // boundary / submodule / shallow
            Err(e) => return Err(e),
        };
        match ty {
            ObjectType::Commit => {
                let commit = Commit::parse(odb.algo(), &payload)?;
                push_if_new(&mut stack, &seen, exclude, commit.tree);
                for parent in commit.parents {
                    push_if_new(&mut stack, &seen, exclude, parent);
                }
            }
            ObjectType::Tree => {
                let tree = Tree::parse(odb.algo(), &payload)?;
                for entry in tree.entries {
                    if entry.mode == FileMode::Gitlink {
                        continue; // a commit in another repository
                    }
                    push_if_new(&mut stack, &seen, exclude, entry.id);
                }
            }
            ObjectType::Tag => {
                let tag = Tag::parse(odb.algo(), &payload)?;
                push_if_new(&mut stack, &seen, exclude, tag.object);
            }
            ObjectType::Blob => {}
        }
    }
    Ok(seen)
}

fn push_if_new(
    stack: &mut Vec<ObjectId>,
    seen: &BTreeSet<ObjectId>,
    exclude: &BTreeSet<ObjectId>,
    id: ObjectId,
) {
    if !seen.contains(&id) && !exclude.contains(&id) {
        stack.push(id);
    }
}

/// Whether `ancestor` is reachable from `descendant` by following commit
/// parents (a commit is its own ancestor). This is the fast-forward test:
/// pushing `new` over `old` is a fast-forward iff `old` is an ancestor of
/// `new`. Missing commits stop that branch of the walk rather than erroring.
pub fn is_ancestor<D: ObjectDatabase>(
    odb: &D,
    ancestor: &ObjectId,
    descendant: &ObjectId,
) -> Result<bool> {
    if ancestor == descendant {
        return Ok(true);
    }
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(*descendant);
    seen.insert(*descendant);
    while let Some(id) = queue.pop_front() {
        let payload = match odb.read_typed(&id, ObjectType::Commit) {
            Ok(p) => p,
            Err(Error::NotFound(_)) | Err(Error::UnexpectedType { .. }) => continue,
            Err(e) => return Err(e),
        };
        let commit = Commit::parse(odb.algo(), &payload)?;
        for parent in commit.parents {
            if &parent == ancestor {
                return Ok(true);
            }
            if seen.insert(parent) {
                queue.push_back(parent);
            }
        }
    }
    Ok(false)
}

/// Finds the best merge base of two commits (`git merge-base a b`), or `None`
/// if they share no history.
///
/// A *best* common ancestor is one that is not itself an ancestor of another
/// common ancestor. (A breadth-first "first common commit found" is not
/// enough: following a merge's first parent can reach an older common
/// ancestor before the newer one behind the second parent.) Criss-cross
/// histories have several best bases; [`merge_bases`] returns them all, and
/// this picks the one with the newest committer date (ties broken by id) —
/// always one of the bases `git merge-base --all` reports.
pub fn merge_base<D: ObjectDatabase>(
    odb: &D,
    a: &ObjectId,
    b: &ObjectId,
) -> Result<Option<ObjectId>> {
    let mut best: Option<(i64, ObjectId)> = None;
    for id in merge_bases(odb, a, b)? {
        let time = Commit::parse(odb.algo(), &odb.read_typed(&id, ObjectType::Commit)?)?
            .committer
            .time;
        // Newest first; on a date tie the smaller id wins, deterministically.
        if best.is_none_or(|(t, _)| time > t) {
            best = Some((time, id));
        }
    }
    Ok(best.map(|(_, id)| id))
}

/// All best common ancestors of two commits (`git merge-base --all a b`),
/// sorted by id; empty if the histories are unrelated.
///
/// The common ancestors form an ancestor-closed set, so a common ancestor is
/// redundant exactly when it is a parent of some other common ancestor; the
/// best bases are the common ancestors no common ancestor has as a parent.
/// Missing commits (a shallow boundary) end their branch of the walk.
pub fn merge_bases<D: ObjectDatabase>(
    odb: &D,
    a: &ObjectId,
    b: &ObjectId,
) -> Result<Vec<ObjectId>> {
    let ancestors_of_a = commit_ancestors(odb, a)?;
    let ancestors_of_b = commit_ancestors(odb, b)?;
    let common: BTreeSet<ObjectId> = ancestors_of_a
        .intersection(&ancestors_of_b)
        .copied()
        .collect();
    let mut redundant = BTreeSet::new();
    for id in &common {
        let payload = match odb.read_typed(id, ObjectType::Commit) {
            Ok(p) => p,
            Err(Error::NotFound(_)) | Err(Error::UnexpectedType { .. }) => continue,
            Err(e) => return Err(e),
        };
        for parent in Commit::parse(odb.algo(), &payload)?.parents {
            if common.contains(&parent) {
                redundant.insert(parent);
            }
        }
    }
    Ok(common
        .into_iter()
        .filter(|id| !redundant.contains(id) && odb.contains(id))
        .collect())
}

/// Collects a commit and all its ancestors.
fn commit_ancestors<D: ObjectDatabase>(odb: &D, tip: &ObjectId) -> Result<BTreeSet<ObjectId>> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(*tip);
    seen.insert(*tip);
    while let Some(id) = queue.pop_front() {
        let payload = match odb.read_typed(&id, ObjectType::Commit) {
            Ok(p) => p,
            Err(Error::NotFound(_)) | Err(Error::UnexpectedType { .. }) => continue,
            Err(e) => return Err(e),
        };
        for parent in Commit::parse(odb.algo(), &payload)?.parents {
            if seen.insert(parent) {
                queue.push_back(parent);
            }
        }
    }
    Ok(seen)
}

/// One entry of a tree-to-tree diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDiffEntry {
    /// The path (relative to the tree root).
    pub path: alloc::vec::Vec<u8>,
    /// How the path changed from the old tree to the new.
    pub change: TreeChange,
}

/// How a path differs between two trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeChange {
    /// Only in the new tree.
    Added,
    /// In both, with a different id or mode.
    Modified,
    /// Only in the old tree.
    Deleted,
}

/// Computes the name-status diff between two trees (`git diff --name-status` /
/// `git diff-tree`): every path that was added, modified, or deleted, sorted by
/// path. Either id may be `None` to diff against the empty tree.
pub fn diff_trees<D: ObjectDatabase>(
    odb: &D,
    old: Option<&ObjectId>,
    new: Option<&ObjectId>,
) -> Result<alloc::vec::Vec<TreeDiffEntry>> {
    let old_map = match old {
        Some(id) => flatten_tree(odb, id)?,
        None => alloc::collections::BTreeMap::new(),
    };
    let new_map = match new {
        Some(id) => flatten_tree(odb, id)?,
        None => alloc::collections::BTreeMap::new(),
    };

    let mut out = alloc::vec::Vec::new();
    for (path, (old_mode, old_id)) in &old_map {
        match new_map.get(path) {
            None => out.push(TreeDiffEntry {
                path: path.clone(),
                change: TreeChange::Deleted,
            }),
            Some((new_mode, new_id)) if new_mode != old_mode || new_id != old_id => {
                out.push(TreeDiffEntry {
                    path: path.clone(),
                    change: TreeChange::Modified,
                })
            }
            Some(_) => {}
        }
    }
    for path in new_map.keys() {
        if !old_map.contains_key(path) {
            out.push(TreeDiffEntry {
                path: path.clone(),
                change: TreeChange::Added,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Recursively flattens a tree into a `path → (mode, id)` map, with `/`-joined
/// paths relative to the tree root (the shape `git status`/`diff` compare
/// against). Subtrees are descended into; gitlinks are included as-is.
pub fn flatten_tree<D: ObjectDatabase>(
    odb: &D,
    tree_id: &ObjectId,
) -> Result<alloc::collections::BTreeMap<alloc::vec::Vec<u8>, (FileMode, ObjectId)>> {
    let mut out = alloc::collections::BTreeMap::new();
    flatten_into(odb, tree_id, &[], &mut out)?;
    Ok(out)
}

fn flatten_into<D: ObjectDatabase>(
    odb: &D,
    tree_id: &ObjectId,
    prefix: &[u8],
    out: &mut alloc::collections::BTreeMap<alloc::vec::Vec<u8>, (FileMode, ObjectId)>,
) -> Result<()> {
    let payload = odb.read_typed(tree_id, ObjectType::Tree)?;
    let tree = Tree::parse(odb.algo(), &payload)?;
    for entry in tree.entries {
        let mut path = prefix.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(&entry.name);
        if entry.mode == FileMode::Tree {
            flatten_into(odb, &entry.id, &path, out)?;
        } else {
            out.insert(path, (entry.mode, entry.id));
        }
    }
    Ok(())
}

/// A commit waiting in a [`RevWalk`] queue, ordered like git's date-sorted
/// commit list: newest committer date first, and among equal dates the one
/// queued first.
struct Queued {
    time: i64,
    seq: u64,
    id: ObjectId,
    commit: Commit,
}

impl PartialEq for Queued {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == core::cmp::Ordering::Equal
    }
}
impl Eq for Queued {}
impl PartialOrd for Queued {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Queued {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // BinaryHeap is a max-heap: a later date, then an *earlier* sequence
        // number, compares greater.
        self.time
            .cmp(&other.time)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

/// An iterator over commits reachable from one or more tips, in `git log` /
/// `git rev-list` default order.
///
/// Like git's default (unlimited) revision walk, commits are emitted newest
/// committer date first: the walk keeps a date-ordered queue seeded with the
/// tips, pops the newest commit, and queues its not-yet-seen parents; commits
/// with equal dates come out in the order they were queued. Each commit is
/// yielded once. Commits missing from the database (a shallow boundary) are
/// skipped.
pub struct RevWalk<'a, D: ObjectDatabase> {
    odb: &'a D,
    /// Tips not yet loaded into `queue` (loaded lazily by the first step).
    pending_tips: Vec<ObjectId>,
    queue: alloc::collections::BinaryHeap<Queued>,
    seen: BTreeSet<ObjectId>,
    seq: u64,
}

impl<'a, D: ObjectDatabase> RevWalk<'a, D> {
    /// Starts a walk from the given commit tips.
    pub fn new(odb: &'a D, tips: &[ObjectId]) -> Self {
        RevWalk {
            odb,
            pending_tips: tips.to_vec(),
            queue: alloc::collections::BinaryHeap::new(),
            seen: BTreeSet::new(),
            seq: 0,
        }
    }

    /// Reads `id` and queues it (once); a missing commit is skipped.
    fn enqueue(&mut self, id: ObjectId) -> Result<()> {
        if !self.seen.insert(id) {
            return Ok(());
        }
        let payload = match self.odb.read_typed(&id, ObjectType::Commit) {
            Ok(p) => p,
            Err(Error::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        let commit = Commit::parse(self.odb.algo(), &payload)?;
        self.seq += 1;
        self.queue.push(Queued {
            time: commit.committer.time,
            seq: self.seq,
            id,
            commit,
        });
        Ok(())
    }

    /// Advances to the next commit, returning its id and parsed value.
    fn step(&mut self) -> Result<Option<(ObjectId, Commit)>> {
        for tip in core::mem::take(&mut self.pending_tips) {
            self.enqueue(tip)?;
        }
        let Some(Queued { id, commit, .. }) = self.queue.pop() else {
            return Ok(None);
        };
        for &parent in &commit.parents {
            self.enqueue(parent)?;
        }
        Ok(Some((id, commit)))
    }
}

impl<'a, D: ObjectDatabase> Iterator for RevWalk<'a, D> {
    type Item = Result<(ObjectId, Commit)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.step().transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::tree::TreeEntry;
    use crate::object::{Signature, Tree};
    use crate::odb::MemoryOdb;
    use crate::oid::HashAlgo;

    fn sig() -> Signature {
        Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 0,
            tz: b"+0000".to_vec(),
        }
    }

    fn commit(odb: &MemoryOdb, tree: ObjectId, parents: Vec<ObjectId>) -> ObjectId {
        commit_msg(odb, tree, parents, b"m\n")
    }

    fn commit_msg(odb: &MemoryOdb, tree: ObjectId, parents: Vec<ObjectId>, msg: &[u8]) -> ObjectId {
        let c = Commit {
            tree,
            parents,
            author: sig(),
            committer: sig(),
            extra_headers: Vec::new(),
            message: msg.to_vec(),
        };
        odb.write(ObjectType::Commit, &c.serialize()).unwrap()
    }

    #[test]
    fn reachability_and_send_set() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let blob = odb.write(ObjectType::Blob, b"hello\n").unwrap();
        let tree = Tree {
            entries: alloc::vec![TreeEntry {
                mode: FileMode::Regular,
                name: b"a".to_vec(),
                id: blob,
            }],
        };
        let tree_id = odb.write(ObjectType::Tree, &tree.serialize()).unwrap();
        let c1 = commit(&odb, tree_id, Vec::new());
        let c2 = commit(&odb, tree_id, alloc::vec![c1]);

        // Closure of c2 includes both commits, the tree, and the blob.
        let all = reachable_objects(&odb, &[c2]).unwrap();
        assert!(all.contains(&c1) && all.contains(&c2));
        assert!(all.contains(&tree_id) && all.contains(&blob));
        assert_eq!(all.len(), 4);

        // What to send for c2 given the peer has c1: only c2 (tree+blob shared).
        let send = objects_to_send(&odb, &[c2], &[c1]).unwrap();
        assert!(send.contains(&c2));
        assert!(!send.contains(&c1) && !send.contains(&tree_id) && !send.contains(&blob));
        assert_eq!(send.len(), 1);
    }

    #[test]
    fn missing_tree_objects_reports_absent_blobs_across_subtrees() {
        // The root tree references a top-level blob and a subtree; the subtree
        // references an inner blob. The local odb (a `blob:none` partial clone)
        // holds both trees but neither blob.
        let full = MemoryOdb::new(HashAlgo::Sha1);
        let top = full.write(ObjectType::Blob, b"top\n").unwrap();
        let inner = full.write(ObjectType::Blob, b"inner\n").unwrap();
        let subtree = Tree {
            entries: alloc::vec![TreeEntry {
                mode: FileMode::Regular,
                name: b"inner.txt".to_vec(),
                id: inner,
            }],
        };
        let subtree_id = full.write(ObjectType::Tree, &subtree.serialize()).unwrap();
        let root = Tree {
            entries: alloc::vec![
                TreeEntry {
                    mode: FileMode::Regular,
                    name: b"top.txt".to_vec(),
                    id: top,
                },
                TreeEntry {
                    mode: FileMode::Tree,
                    name: b"sub".to_vec(),
                    id: subtree_id,
                },
            ],
        };
        let root_id = full.write(ObjectType::Tree, &root.serialize()).unwrap();

        // A partial clone: trees present, blobs absent.
        let local = MemoryOdb::new(HashAlgo::Sha1);
        local.write(ObjectType::Tree, &subtree.serialize()).unwrap();
        local.write(ObjectType::Tree, &root.serialize()).unwrap();

        let mut missing = missing_tree_objects(&local, &root_id).unwrap();
        missing.sort();
        let mut expected = alloc::vec![top, inner];
        expected.sort();
        assert_eq!(missing, expected, "both blobs are reported missing");

        // After backfilling the blobs, nothing is missing.
        local.write(ObjectType::Blob, b"top\n").unwrap();
        local.write(ObjectType::Blob, b"inner\n").unwrap();
        assert!(missing_tree_objects(&local, &root_id).unwrap().is_empty());

        // A missing subtree is itself reported (and not descended into).
        let empty = MemoryOdb::new(HashAlgo::Sha1);
        empty.write(ObjectType::Tree, &root.serialize()).unwrap();
        let missing = missing_tree_objects(&empty, &root_id).unwrap();
        assert!(missing.contains(&subtree_id));
        assert!(missing.contains(&top));
    }

    #[test]
    fn shallow_walk_truncates_history_and_marks_the_boundary() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let tree = odb
            .write(ObjectType::Tree, &Tree::default().serialize())
            .unwrap();
        // A linear chain c1 → c2 → c3 (c3 is the tip).
        let c1 = commit(&odb, tree, Vec::new());
        let c2 = commit_msg(&odb, tree, alloc::vec![c1], b"c2\n");
        let c3 = commit_msg(&odb, tree, alloc::vec![c2], b"c3\n");
        let none = BTreeSet::new();

        // Depth 1: only the tip; the tip is the shallow boundary.
        let d1 = shallow_objects_to_send(&odb, &[c3], 1, &none).unwrap();
        assert!(d1.objects.contains(&c3) && d1.objects.contains(&tree));
        assert!(!d1.objects.contains(&c2) && !d1.objects.contains(&c1));
        assert_eq!(d1.shallow, BTreeSet::from([c3]));

        // Depth 2: tip and its parent; the parent is the boundary.
        let d2 = shallow_objects_to_send(&odb, &[c3], 2, &none).unwrap();
        assert!(d2.objects.contains(&c3) && d2.objects.contains(&c2));
        assert!(!d2.objects.contains(&c1));
        assert_eq!(d2.shallow, BTreeSet::from([c2]));

        // Depth 3 reaches the root, which has no parents → no shallow boundary.
        let d3 = shallow_objects_to_send(&odb, &[c3], 3, &none).unwrap();
        assert!(d3.objects.contains(&c1));
        assert!(d3.shallow.is_empty());
    }

    #[test]
    fn ancestry_and_merge_base() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let tree = odb
            .write(ObjectType::Tree, &Tree::default().serialize())
            .unwrap();
        // root → a → {b, c} (a fork; b and c differ by message so their ids differ)
        let root = commit(&odb, tree, Vec::new());
        let a = commit(&odb, tree, alloc::vec![root]);
        let b = commit_msg(&odb, tree, alloc::vec![a], b"b\n");
        let c = commit_msg(&odb, tree, alloc::vec![a], b"c\n");

        assert!(is_ancestor(&odb, &root, &b).unwrap());
        assert!(is_ancestor(&odb, &a, &c).unwrap());
        assert!(is_ancestor(&odb, &b, &b).unwrap()); // reflexive
        assert!(!is_ancestor(&odb, &b, &c).unwrap()); // siblings
        assert!(!is_ancestor(&odb, &c, &a).unwrap()); // descendant is not ancestor

        // The merge base of the two forks is their common parent `a`.
        assert_eq!(merge_base(&odb, &b, &c).unwrap(), Some(a));
        // A linear pair's base is the older commit.
        assert_eq!(merge_base(&odb, &root, &b).unwrap(), Some(root));
    }

    #[test]
    fn tree_diff_name_status() {
        use crate::object::tree::TreeEntry;
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let blob1 = odb.write(ObjectType::Blob, b"one\n").unwrap();
        let blob2 = odb.write(ObjectType::Blob, b"two\n").unwrap();

        // old: {keep, gone}
        let old = odb
            .write(
                ObjectType::Tree,
                &Tree {
                    entries: alloc::vec![
                        TreeEntry {
                            mode: FileMode::Regular,
                            name: b"keep".to_vec(),
                            id: blob1
                        },
                        TreeEntry {
                            mode: FileMode::Regular,
                            name: b"gone".to_vec(),
                            id: blob1
                        },
                    ],
                }
                .serialize(),
            )
            .unwrap();
        // new: {keep (changed), added}
        let new = odb
            .write(
                ObjectType::Tree,
                &Tree {
                    entries: alloc::vec![
                        TreeEntry {
                            mode: FileMode::Regular,
                            name: b"keep".to_vec(),
                            id: blob2
                        },
                        TreeEntry {
                            mode: FileMode::Regular,
                            name: b"added".to_vec(),
                            id: blob1
                        },
                    ],
                }
                .serialize(),
            )
            .unwrap();

        let diff = diff_trees(&odb, Some(&old), Some(&new)).unwrap();
        let find = |p: &[u8]| diff.iter().find(|e| e.path == p).map(|e| e.change);
        assert_eq!(find(b"added"), Some(TreeChange::Added));
        assert_eq!(find(b"keep"), Some(TreeChange::Modified));
        assert_eq!(find(b"gone"), Some(TreeChange::Deleted));
        assert_eq!(diff.len(), 3);
    }

    #[test]
    fn revwalk_yields_history() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let tree = odb
            .write(ObjectType::Tree, &Tree::default().serialize())
            .unwrap();
        let c1 = commit(&odb, tree, Vec::new());
        let c2 = commit(&odb, tree, alloc::vec![c1]);
        let c3 = commit(&odb, tree, alloc::vec![c2]);

        let ids: Vec<ObjectId> = RevWalk::new(&odb, &[c3]).map(|r| r.unwrap().0).collect();
        assert_eq!(ids, alloc::vec![c3, c2, c1]);
    }

    fn commit_at(odb: &MemoryOdb, parents: Vec<ObjectId>, time: i64) -> ObjectId {
        let tree = odb.write(ObjectType::Tree, b"").unwrap();
        let mut s = sig();
        s.time = time;
        let c = Commit {
            tree,
            parents,
            author: s.clone(),
            committer: s,
            extra_headers: Vec::new(),
            message: alloc::format!("at {time}\n").into_bytes(),
        };
        odb.write(ObjectType::Commit, &c.serialize()).unwrap()
    }

    #[test]
    fn merge_base_prefers_the_newest_common_ancestor() {
        // o ← a1 ← a2          (a)
        //  ↖     ↖
        //    m ───┘             (b = merge [o, a1])
        // Breadth-first from b meets `o` (first parent) before `a1`, but a1 is
        // the best base: o is an ancestor of a1.
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let o = commit_at(&odb, alloc::vec![], 1);
        let a1 = commit_at(&odb, alloc::vec![o], 2);
        let a2 = commit_at(&odb, alloc::vec![a1], 3);
        let m = commit_at(&odb, alloc::vec![o, a1], 4);
        assert_eq!(merge_base(&odb, &a2, &m).unwrap(), Some(a1));
        assert_eq!(merge_base(&odb, &m, &a2).unwrap(), Some(a1));
        assert_eq!(merge_bases(&odb, &a2, &m).unwrap(), alloc::vec![a1]);

        // Criss-cross: p and q each merge the other's parent → two bases.
        let p1 = commit_at(&odb, alloc::vec![a2], 5);
        let q1 = commit_at(&odb, alloc::vec![a2], 6);
        let p2 = commit_at(&odb, alloc::vec![p1, q1], 7);
        let q2 = commit_at(&odb, alloc::vec![q1, p1], 8);
        let mut want = alloc::vec![p1, q1];
        want.sort();
        assert_eq!(merge_bases(&odb, &p2, &q2).unwrap(), want);
        // The single answer is the newer of the two.
        assert_eq!(merge_base(&odb, &p2, &q2).unwrap(), Some(q1));
    }

    #[test]
    fn revwalk_is_date_ordered_like_rev_list() {
        // A merge of a long branch and a short one: breadth-first would emit
        // the short branch's old commit before the long branch's newer ones.
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let root = commit_at(&odb, alloc::vec![], 10);
        let short = commit_at(&odb, alloc::vec![root], 20);
        let l1 = commit_at(&odb, alloc::vec![root], 30);
        let l2 = commit_at(&odb, alloc::vec![l1], 40);
        let l3 = commit_at(&odb, alloc::vec![l2], 50);
        let merge = commit_at(&odb, alloc::vec![short, l3], 60);
        let ids: Vec<ObjectId> = RevWalk::new(&odb, &[merge]).map(|r| r.unwrap().0).collect();
        assert_eq!(ids, alloc::vec![merge, l3, l2, l1, short, root]);
    }
}
