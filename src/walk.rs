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
//! - [`RevWalk`] — an iterator over commits in parent order, for `git log`.
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

/// An iterator over commits reachable from one or more tips, in parent order.
///
/// This is a breadth-first walk by commit parentage (not a strict topological
/// sort — that is a later refinement). Each commit is yielded once. Use it for
/// `git log`-style history listing.
pub struct RevWalk<'a, D: ObjectDatabase> {
    odb: &'a D,
    queue: VecDeque<ObjectId>,
    seen: BTreeSet<ObjectId>,
}

impl<'a, D: ObjectDatabase> RevWalk<'a, D> {
    /// Starts a walk from the given commit tips.
    pub fn new(odb: &'a D, tips: &[ObjectId]) -> Self {
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::new();
        for &tip in tips {
            if seen.insert(tip) {
                queue.push_back(tip);
            }
        }
        RevWalk { odb, queue, seen }
    }

    /// Advances to the next commit, returning its id and parsed value.
    fn step(&mut self) -> Result<Option<(ObjectId, Commit)>> {
        while let Some(id) = self.queue.pop_front() {
            let payload = match self.odb.read_typed(&id, ObjectType::Commit) {
                Ok(p) => p,
                Err(Error::NotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            let commit = Commit::parse(self.odb.algo(), &payload)?;
            for &parent in &commit.parents {
                if self.seen.insert(parent) {
                    self.queue.push_back(parent);
                }
            }
            return Ok(Some((id, commit)));
        }
        Ok(None)
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
        let c = Commit {
            tree,
            parents,
            author: sig(),
            committer: sig(),
            extra_headers: Vec::new(),
            message: b"m\n".to_vec(),
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
}
