//! The working tree — materializing trees to disk and reporting status.
//!
//! This is the std-only layer that bridges the object store and the user's
//! files. Today it implements [`checkout_tree`], which writes a tree's blobs
//! into the working directory (the core of `git checkout` / `git clone`'s final
//! step). Index-aware status and diff (comparing the work tree against the index
//! and `HEAD`) are scaffolded by [`FileStatus`] and land next — see the roadmap.

use alloc::string::String;
use alloc::vec::Vec;
use std::path::Path;

use crate::error::{Error, Result};
use crate::object::tree::FileMode;
use crate::object::tree::is_safe_path_component;
use crate::object::{Object, Tree};
use crate::oid::ObjectId;
use crate::repository::Repository;

/// The status of a path relative to the index / `HEAD` (for `git status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// Tracked and unchanged.
    Unmodified,
    /// Tracked and modified in the working tree.
    Modified,
    /// Present in the working tree but not the index.
    Untracked,
    /// In the index but missing from the working tree.
    Deleted,
    /// Newly staged (in the index, not in `HEAD`).
    Added,
}

/// Recursively writes the contents of the tree `tree_id` into `dest`.
///
/// Regular and executable files are created with their blob contents; subtrees
/// become subdirectories. Symlinks and gitlinks (submodules) are recognized but
/// not yet materialized — they are reported via [`Error::Unsupported`] so a
/// caller never silently produces a wrong working tree. Existing files at the
/// destination are overwritten.
pub fn checkout_tree(repo: &Repository, tree_id: &ObjectId, dest: &Path) -> Result<()> {
    let tree = match repo.read_object(tree_id)? {
        Object::Tree(t) => t,
        other => {
            return Err(Error::UnexpectedType {
                expected: crate::object::ObjectType::Tree,
                actual: other.object_type(),
            });
        }
    };
    write_tree(repo, &tree, dest)
}

fn write_tree(repo: &Repository, tree: &Tree, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in &tree.entries {
        // The name comes from a possibly hostile remote. Reject anything that
        // is not a single safe component (traversal, absolute path, `.git`)
        // *before* it is joined onto the destination (D1).
        if !is_safe_path_component(&entry.name) {
            return Err(Error::Unsupported(alloc::format!(
                "checkout: unsafe tree entry name {:?}",
                String::from_utf8_lossy(&entry.name)
            )));
        }
        let name = std::str::from_utf8(&entry.name)
            .map_err(|_| Error::Unsupported("non-utf8 path component in checkout".into()))?;
        let path = dest.join(name);
        // Defense in depth: refuse to write through an existing symlink at this
        // component, which could redirect the write outside the tree
        // (CVE-2021-21300 class, D2). `symlink_metadata` does not follow links.
        if let Ok(md) = std::fs::symlink_metadata(&path)
            && md.file_type().is_symlink()
        {
            return Err(Error::Unsupported(alloc::format!(
                "checkout: refusing to write through existing symlink {name:?}"
            )));
        }
        // Belt-and-braces: `dest` was just created and validated on the way
        // down, so its canonical form is the trusted anchor. Confirm that the
        // canonicalized parent of `path` is still exactly `dest`, catching any
        // symlink-in-`dest` trickery the per-component check might miss.
        if let Ok(canon_dest) = std::fs::canonicalize(dest) {
            let parent_ok = path
                .parent()
                .and_then(|p| std::fs::canonicalize(p).ok())
                .map(|c| c == canon_dest)
                .unwrap_or(false);
            if !parent_ok {
                return Err(Error::Unsupported(alloc::format!(
                    "checkout: entry {name:?} would escape the working tree"
                )));
            }
        }
        match entry.mode {
            FileMode::Tree => {
                let sub = match repo.read_object(&entry.id)? {
                    Object::Tree(t) => t,
                    _ => return Err(Error::Parse("checkout: tree entry is not a tree".into())),
                };
                write_tree(repo, &sub, &path)?;
            }
            FileMode::Regular | FileMode::Executable => {
                let blob = read_blob(repo, &entry.id)?;
                // Apply the LFS smudge filter: an LFS pointer whose object is in
                // the local store is materialized to its real content.
                let content = repo.lfs_smudge(&blob)?;
                std::fs::write(&path, &content)?;
                set_executable(&path, entry.mode == FileMode::Executable)?;
            }
            FileMode::Symlink => {
                return Err(Error::Unsupported(
                    "checkout of symlinks is not yet implemented".into(),
                ));
            }
            FileMode::Gitlink => {
                return Err(Error::Unsupported(
                    "checkout of submodules (gitlinks) is not yet implemented".into(),
                ));
            }
        }
    }
    Ok(())
}

fn read_blob(repo: &Repository, id: &ObjectId) -> Result<Vec<u8>> {
    match repo.read_object(id)? {
        Object::Blob(b) => Ok(b),
        other => Err(Error::UnexpectedType {
            expected: crate::object::ObjectType::Blob,
            actual: other.object_type(),
        }),
    }
}

#[cfg(unix)]
fn set_executable(path: &Path, exec: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    let mode = if exec { 0o755 } else { 0o644 };
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _exec: bool) -> Result<()> {
    // The executable bit is not represented on non-Unix filesystems.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;
    use crate::object::tree::TreeEntry;

    /// Builds a fresh repository in a per-test-unique temp directory.
    fn temp_repo(tag: &str) -> (std::path::PathBuf, Repository) {
        let dir = std::env::temp_dir().join(alloc::format!(
            "puregit-checkout-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();
        (dir, repo)
    }

    /// Writes a tree whose single entry has the raw `name`, bypassing the
    /// `Tree::parse` name invariant, and attempts to check it out. The tree is
    /// hashed and stored via the object database directly so `checkout_tree`
    /// reads it back through `Tree::parse` — proving the checkout guard fires
    /// for names that survive parsing (`.git`, `..`).
    fn checkout_with_entry_name(repo: &Repository, name: &[u8], dest: &Path) -> Result<()> {
        let blob = repo.write_object(ObjectType::Blob, b"data").unwrap();
        let tree = Tree {
            entries: alloc::vec![TreeEntry {
                mode: FileMode::Regular,
                name: name.to_vec(),
                id: blob,
            }],
        };
        let tree_id = repo
            .write_object(ObjectType::Tree, &tree.serialize())
            .unwrap();
        checkout_tree(repo, &tree_id, dest)
    }

    #[test]
    fn rejects_dotdot_entry_name() {
        let (dir, repo) = temp_repo("dotdot");
        let out = dir.join("work");
        let err = checkout_with_entry_name(&repo, b"..", &out).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
        // Nothing was written above the destination.
        assert!(!dir.join("data").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_dot_git_entry_name() {
        let (dir, repo) = temp_repo("dotgit");
        let out = dir.join("work");
        // Plain, trailing-dot, and 8.3 short-name forms all reject.
        for name in [&b".git"[..], b".git.", b".GIT", b"git~1"] {
            let err = checkout_with_entry_name(&repo, name, &out).unwrap_err();
            assert!(
                matches!(err, Error::Unsupported(_)),
                "name {name:?} should be rejected"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_absolute_path_entry_name() {
        // An absolute path contains a `/`, so it is rejected already at
        // `Tree::parse` — the guarantee holds at the parse boundary. Craft the
        // raw tree bytes so the slash is not stripped by any helper.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"100644 ");
        payload.extend_from_slice(b"/etc/passwd");
        payload.push(0);
        payload.extend_from_slice(&[0u8; 20]);
        let err = Tree::parse(crate::oid::HashAlgo::Sha1, &payload).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn parse_rejects_slash_and_empty_names() {
        // A `/` in the name is not a single component.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"100644 a/b");
        payload.push(0);
        payload.extend_from_slice(&[0u8; 20]);
        assert!(Tree::parse(crate::oid::HashAlgo::Sha1, &payload).is_err());

        // An empty name.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"100644 ");
        payload.push(0);
        payload.extend_from_slice(&[0u8; 20]);
        assert!(Tree::parse(crate::oid::HashAlgo::Sha1, &payload).is_err());
    }

    #[test]
    fn safe_component_matrix() {
        assert!(is_safe_path_component(b"src"));
        assert!(is_safe_path_component(b"a.txt"));
        assert!(!is_safe_path_component(b""));
        assert!(!is_safe_path_component(b"."));
        assert!(!is_safe_path_component(b".."));
        assert!(!is_safe_path_component(b"a/b"));
        assert!(!is_safe_path_component(b"a\\b"));
        assert!(!is_safe_path_component(b".git"));
        assert!(!is_safe_path_component(b".GIT"));
        assert!(!is_safe_path_component(b".git."));
        assert!(!is_safe_path_component(b".git "));
        assert!(!is_safe_path_component(b"git~1"));
        assert!(!is_safe_path_component(b"C:"));
    }
}
