//! Working-tree status — comparing `HEAD`, the index, and the working tree.
//!
//! [`status`] computes the three-way comparison `git status` reports:
//!
//! - **staged** — the index versus the `HEAD` tree (what a commit would record).
//! - **unstaged** — the working tree versus the index (changes not yet `add`ed).
//! - **untracked** — files in the working tree absent from the index.
//!
//! Paths are raw bytes relative to the working-tree root. Gitignore matching is
//! not yet applied (every non-`.git` file is considered), and rename detection
//! is out of scope — both are roadmap refinements.

use alloc::vec::Vec;
use std::path::Path;

use crate::error::{Error, Result};
use crate::hash::hash_object;
use crate::object::{Object, ObjectType};
use crate::repository::Repository;

/// How a path changed between two of the three states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    /// Present on the newer side, absent on the older.
    Added,
    /// Present on both with differing content.
    Modified,
    /// Absent on the newer side, present on the older.
    Deleted,
}

/// The result of [`status`]: staged, unstaged, and untracked path lists.
#[derive(Debug, Clone, Default)]
pub struct Status {
    /// Index versus `HEAD` (staged for the next commit).
    pub staged: Vec<(Vec<u8>, Change)>,
    /// Working tree versus index (not yet staged).
    pub unstaged: Vec<(Vec<u8>, Change)>,
    /// Working-tree paths not in the index.
    pub untracked: Vec<Vec<u8>>,
}

impl Status {
    /// Whether the working tree and index are clean relative to `HEAD`.
    pub fn is_clean(&self) -> bool {
        self.staged.is_empty() && self.unstaged.is_empty() && self.untracked.is_empty()
    }
}

/// Computes the working-tree status of `repo` (requires a non-bare repository).
pub fn status(repo: &Repository) -> Result<Status> {
    use alloc::collections::{BTreeMap, BTreeSet};

    let work = repo
        .work_tree()
        .ok_or_else(|| Error::Io("status: bare repository has no work tree".into()))?
        .to_path_buf();

    // HEAD tree, flattened to path → id (empty on an unborn branch).
    let head_map: BTreeMap<Vec<u8>, crate::oid::ObjectId> = match repo.head_id() {
        Ok(commit_id) => {
            let commit = match repo.read_object(&commit_id)? {
                Object::Commit(c) => c,
                _ => return Err(Error::Parse("HEAD is not a commit".into())),
            };
            crate::walk::flatten_tree(repo.objects(), &commit.tree)?
                .into_iter()
                .map(|(p, (_, id))| (p, id))
                .collect()
        }
        Err(_) => BTreeMap::new(),
    };

    // Index, path → id.
    let index = repo.index()?;
    let index_map: BTreeMap<Vec<u8>, crate::oid::ObjectId> = index
        .entries
        .iter()
        .filter(|e| e.stage == 0)
        .map(|e| (e.path.clone(), e.id))
        .collect();

    // Staged: index vs HEAD.
    let mut staged = Vec::new();
    for (path, id) in &index_map {
        match head_map.get(path) {
            None => staged.push((path.clone(), Change::Added)),
            Some(h) if h != id => staged.push((path.clone(), Change::Modified)),
            Some(_) => {}
        }
    }
    for path in head_map.keys() {
        if !index_map.contains_key(path) {
            staged.push((path.clone(), Change::Deleted));
        }
    }

    // Working-tree files, relative paths.
    let mut worktree_files = BTreeSet::new();
    collect_files(&work, &work, &mut worktree_files)?;

    // Unstaged: index vs working tree.
    let mut unstaged = Vec::new();
    for (path, id) in &index_map {
        let full = join_rel(&work, path);
        match std::fs::read(&full) {
            Err(_) => unstaged.push((path.clone(), Change::Deleted)),
            Ok(content) => {
                let wt_id = hash_object(repo.algo(), ObjectType::Blob, &content);
                if &wt_id != id {
                    unstaged.push((path.clone(), Change::Modified));
                }
            }
        }
    }

    // Untracked: working-tree files not in the index.
    let mut untracked = Vec::new();
    for path in &worktree_files {
        if !index_map.contains_key(path) {
            untracked.push(path.clone());
        }
    }

    staged.sort();
    unstaged.sort();
    untracked.sort();
    Ok(Status {
        staged,
        unstaged,
        untracked,
    })
}

/// Recursively collects working-tree file paths (relative to `root`), skipping
/// the `.git` directory.
fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut alloc::collections::BTreeSet<Vec<u8>>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files(root, &path, out)?;
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.insert(path_to_bytes(rel));
        }
    }
    Ok(())
}

/// Joins a raw byte path (relative) onto the work-tree root.
fn join_rel(root: &Path, rel: &[u8]) -> std::path::PathBuf {
    let s = String::from_utf8_lossy(rel);
    root.join(s.as_ref())
}

#[cfg(unix)]
fn path_to_bytes(p: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_to_bytes(p: &Path) -> Vec<u8> {
    // On non-Unix, normalize separators to `/` to match git's path form.
    p.to_string_lossy().replace('\\', "/").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Signature;

    fn sig() -> Signature {
        Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 0,
            tz: b"+0000".to_vec(),
        }
    }

    #[test]
    fn reports_staged_unstaged_untracked() {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-status-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();

        // Commit one file.
        std::fs::write(dir.join("committed.txt"), b"v1\n").unwrap();
        repo.add_path("committed.txt").unwrap();
        repo.commit(b"c\n", sig(), sig()).unwrap();
        assert!(status(&repo).unwrap().is_clean());

        // Modify the committed file in the working tree (unstaged).
        std::fs::write(dir.join("committed.txt"), b"v2\n").unwrap();
        // Stage a brand-new file (staged add).
        std::fs::write(dir.join("staged.txt"), b"new\n").unwrap();
        repo.add_path("staged.txt").unwrap();
        // Leave an untracked file.
        std::fs::write(dir.join("untracked.txt"), b"loose\n").unwrap();

        let st = status(&repo).unwrap();
        assert!(
            st.staged
                .iter()
                .any(|(p, c)| p == b"staged.txt" && *c == Change::Added)
        );
        assert!(
            st.unstaged
                .iter()
                .any(|(p, c)| p == b"committed.txt" && *c == Change::Modified)
        );
        assert!(st.untracked.iter().any(|p| p == b"untracked.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
