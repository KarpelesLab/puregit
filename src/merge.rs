//! Three-way merge of trees and commits.
//!
//! [`merge_trees`] combines two trees against their common-ancestor tree,
//! resolving each path: a side that did not change from the base yields to the
//! side that did; identical changes on both sides are kept once; regular files
//! changed on both sides are merged line-by-line via [`crate::diff::merge3`];
//! anything else that changed on both sides (mode/type change, or a content
//! merge that still conflicts) is reported as a conflict. [`Repository::merge`]
//! drives this for a `git merge`: fast-forward when possible, otherwise a real
//! three-way merge that produces a merge commit (or reports conflicts).

use alloc::vec::Vec;

use crate::diff;
use crate::error::{Error, Result};
use crate::object::tree::FileMode;
use crate::object::{Object, ObjectType, Signature};
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;
use crate::repository::Repository;
use crate::tree_builder::write_tree_from_entries;
use crate::walk;

/// The outcome of merging two trees.
pub struct TreeMergeResult {
    /// The id of the merged tree (conflicted files contain conflict markers).
    pub tree: ObjectId,
    /// Paths that could not be merged cleanly.
    pub conflicts: Vec<Vec<u8>>,
}

/// Three-way merges `ours` and `theirs` against their `base` tree (`None` for
/// an empty base), writing the merged tree and returning it plus any conflicted
/// paths.
pub fn merge_trees<D: ObjectDatabase>(
    odb: &D,
    base: Option<&ObjectId>,
    ours: &ObjectId,
    theirs: &ObjectId,
) -> Result<TreeMergeResult> {
    use alloc::collections::{BTreeMap, BTreeSet};

    let base_map = match base {
        Some(id) => walk::flatten_tree(odb, id)?,
        None => BTreeMap::new(),
    };
    let ours_map = walk::flatten_tree(odb, ours)?;
    let theirs_map = walk::flatten_tree(odb, theirs)?;

    let mut paths: BTreeSet<&Vec<u8>> = BTreeSet::new();
    paths.extend(base_map.keys());
    paths.extend(ours_map.keys());
    paths.extend(theirs_map.keys());

    let mut entries: Vec<(Vec<u8>, FileMode, ObjectId)> = Vec::new();
    let mut conflicts: Vec<Vec<u8>> = Vec::new();

    for path in paths {
        let b = base_map.get(path).copied();
        let o = ours_map.get(path).copied();
        let t = theirs_map.get(path).copied();

        if o == t {
            // Same on both sides (including both absent).
            if let Some((mode, id)) = o {
                entries.push((path.clone(), mode, id));
            }
        } else if o == b {
            // Ours unchanged from base → take theirs (or accept its deletion).
            if let Some((mode, id)) = t {
                entries.push((path.clone(), mode, id));
            }
        } else if t == b {
            // Theirs unchanged → take ours.
            if let Some((mode, id)) = o {
                entries.push((path.clone(), mode, id));
            }
        } else {
            // Both sides changed differently — attempt a content merge for
            // regular files with a common base blob.
            match (b, o, t) {
                (Some((bm, bid)), Some((om, oid)), Some((tm, tid)))
                    if is_file(bm) && is_file(om) && is_file(tm) && om == tm =>
                {
                    let base_bytes = read_blob(odb, &bid)?;
                    let ours_bytes = read_blob(odb, &oid)?;
                    let theirs_bytes = read_blob(odb, &tid)?;
                    let m = diff::merge3(&base_bytes, &ours_bytes, &theirs_bytes);
                    let merged_id = odb.write(ObjectType::Blob, &m.merged)?;
                    entries.push((path.clone(), om, merged_id));
                    if m.conflicted {
                        conflicts.push(path.clone());
                    }
                }
                _ => {
                    // Unmergeable (add/add, mode/type change, delete/modify):
                    // keep ours in the tree and flag the conflict.
                    conflicts.push(path.clone());
                    if let Some((mode, id)) = o {
                        entries.push((path.clone(), mode, id));
                    } else if let Some((mode, id)) = t {
                        entries.push((path.clone(), mode, id));
                    }
                }
            }
        }
    }

    let tree = write_tree_from_entries(odb, entries)?;
    Ok(TreeMergeResult { tree, conflicts })
}

fn is_file(mode: FileMode) -> bool {
    matches!(mode, FileMode::Regular | FileMode::Executable)
}

fn read_blob<D: ObjectDatabase>(odb: &D, id: &ObjectId) -> Result<Vec<u8>> {
    match Object::parse(
        odb.algo(),
        ObjectType::Blob,
        &odb.read_typed(id, ObjectType::Blob)?,
    )? {
        Object::Blob(b) => Ok(b),
        _ => Err(Error::Parse("merge: expected a blob".into())),
    }
}

/// The outcome of [`Repository::merge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    /// `HEAD` already contained `theirs`; nothing to do.
    AlreadyUpToDate,
    /// `HEAD` was fast-forwarded to `theirs` (the new tip).
    FastForward(ObjectId),
    /// A merge commit was created with the given id.
    Merged(ObjectId),
    /// The merge conflicted on these paths; no commit was made.
    Conflicts(Vec<Vec<u8>>),
}

impl Repository {
    /// Merges the commit `theirs` into the current branch.
    ///
    /// Fast-forwards when `HEAD` is an ancestor of `theirs`; otherwise performs
    /// a three-way merge against the merge base and, if it is conflict-free,
    /// writes a two-parent merge commit and advances the branch (and updates the
    /// work tree). On conflicts, no commit is made and the conflicted paths are
    /// returned for the caller to resolve.
    pub fn merge(
        &self,
        theirs: &ObjectId,
        author: Signature,
        committer: Signature,
        message: &[u8],
    ) -> Result<MergeOutcome> {
        let ours = self.head_id()?;
        if ours == *theirs {
            return Ok(MergeOutcome::AlreadyUpToDate);
        }
        // If theirs is already an ancestor of ours, we're up to date.
        if walk::is_ancestor(self.objects(), theirs, &ours)? {
            return Ok(MergeOutcome::AlreadyUpToDate);
        }
        // If ours is an ancestor of theirs, fast-forward.
        if walk::is_ancestor(self.objects(), &ours, theirs)? {
            self.update_current_branch(theirs)?;
            self.checkout_commit_worktree(theirs)?;
            return Ok(MergeOutcome::FastForward(*theirs));
        }

        let base = walk::merge_base(self.objects(), &ours, theirs)?;
        let base_tree = match base {
            Some(id) => Some(self.commit_tree(&id)?),
            None => None,
        };
        let ours_tree = self.commit_tree(&ours)?;
        let theirs_tree = self.commit_tree(theirs)?;

        let result = merge_trees(self.objects(), base_tree.as_ref(), &ours_tree, &theirs_tree)?;

        if !result.conflicts.is_empty() {
            return Ok(MergeOutcome::Conflicts(result.conflicts));
        }

        let commit = crate::object::Commit {
            tree: result.tree,
            parents: alloc::vec![ours, *theirs],
            author,
            committer,
            extra_headers: Vec::new(),
            message: message.to_vec(),
        };
        let id = self
            .objects()
            .write(ObjectType::Commit, &commit.serialize())?;
        self.update_current_branch(&id)?;
        self.checkout_commit_worktree(&id)?;
        Ok(MergeOutcome::Merged(id))
    }

    /// The tree id of a commit.
    fn commit_tree(&self, commit_id: &ObjectId) -> Result<ObjectId> {
        match self.read_object(commit_id)? {
            Object::Commit(c) => Ok(c.tree),
            other => Err(Error::UnexpectedType {
                expected: ObjectType::Commit,
                actual: other.object_type(),
            }),
        }
    }

    /// Materializes a commit's tree into the working tree (best-effort; only
    /// used after a clean merge/fast-forward).
    fn checkout_commit_worktree(&self, commit_id: &ObjectId) -> Result<()> {
        if let Some(work) = self.work_tree() {
            let work = work.to_path_buf();
            if let Object::Commit(c) = self.read_object(commit_id)? {
                crate::worktree::checkout_tree(self, &c.tree, &work)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig() -> Signature {
        Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 0,
            tz: b"+0000".to_vec(),
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(alloc::format!("puregit-merge-{name}-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn clean_three_way_merge() {
        let dir = scratch("clean");
        let repo = Repository::init(&dir).unwrap();

        // Base: two files on main.
        std::fs::write(dir.join("x.txt"), b"x-base\n").unwrap();
        std::fs::write(dir.join("y.txt"), b"y-base\n").unwrap();
        repo.add_path("x.txt").unwrap();
        repo.add_path("y.txt").unwrap();
        repo.commit(b"base\n", sig(), sig()).unwrap();

        // Branch `feature` off the base; change y there.
        repo.create_branch("feature", None).unwrap();
        repo.checkout("feature").unwrap();
        std::fs::write(dir.join("y.txt"), b"y-feature\n").unwrap();
        repo.add_path("y.txt").unwrap();
        let their = repo.commit(b"feature edits y\n", sig(), sig()).unwrap();

        // Back on main, change x (a different file → no conflict).
        repo.checkout("main").unwrap();
        std::fs::write(dir.join("x.txt"), b"x-main\n").unwrap();
        repo.add_path("x.txt").unwrap();
        repo.commit(b"main edits x\n", sig(), sig()).unwrap();

        // Merge feature into main.
        let outcome = repo
            .merge(&their, sig(), sig(), b"merge feature\n")
            .unwrap();
        let merge_id = match outcome {
            MergeOutcome::Merged(id) => id,
            other => panic!("expected a merge commit, got {other:?}"),
        };

        // The merge commit has two parents and the merged tree has both edits.
        let commit = match repo.read_object(&merge_id).unwrap() {
            Object::Commit(c) => c,
            _ => panic!("not a commit"),
        };
        assert_eq!(commit.parents.len(), 2);
        assert_eq!(std::fs::read(dir.join("x.txt")).unwrap(), b"x-main\n");
        assert_eq!(std::fs::read(dir.join("y.txt")).unwrap(), b"y-feature\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conflicting_merge_reports_paths() {
        let dir = scratch("conflict");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), b"line1\nline2\nline3\n").unwrap();
        repo.add_path("f.txt").unwrap();
        repo.commit(b"base\n", sig(), sig()).unwrap();

        repo.create_branch("feature", None).unwrap();
        repo.checkout("feature").unwrap();
        std::fs::write(dir.join("f.txt"), b"line1\nTHEIRS\nline3\n").unwrap();
        repo.add_path("f.txt").unwrap();
        let their = repo.commit(b"theirs\n", sig(), sig()).unwrap();

        repo.checkout("main").unwrap();
        std::fs::write(dir.join("f.txt"), b"line1\nOURS\nline3\n").unwrap();
        repo.add_path("f.txt").unwrap();
        repo.commit(b"ours\n", sig(), sig()).unwrap();

        match repo.merge(&their, sig(), sig(), b"m\n").unwrap() {
            MergeOutcome::Conflicts(paths) => assert!(paths.iter().any(|p| p == b"f.txt")),
            other => panic!("expected a conflict, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
