//! The working tree — materializing trees to disk and reporting status.
//!
//! This is the std-only layer that bridges the object store and the user's
//! files. Today it implements [`checkout_tree`], which writes a tree's blobs
//! into the working directory (the core of `git checkout` / `git clone`'s final
//! step). Index-aware status and diff (comparing the work tree against the index
//! and `HEAD`) are scaffolded by [`FileStatus`] and land next — see the roadmap.

use alloc::vec::Vec;
use std::path::Path;

use crate::error::{Error, Result};
use crate::object::tree::FileMode;
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
        let name = std::str::from_utf8(&entry.name)
            .map_err(|_| Error::Unsupported("non-utf8 path component in checkout".into()))?;
        let path = dest.join(name);
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
