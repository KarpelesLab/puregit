//! The filesystem abstraction.
//!
//! Git is, at heart, a content-addressed store laid out on a filesystem. To
//! keep the core `no_std` and to allow alternative backends (in-memory for
//! tests, a remote object store, a bare repository inside an archive), all
//! filesystem access in the higher layers goes through the [`crate::vfs::Vfs`] trait rather
//! than `std::fs` directly.
//!
//! Paths are passed as `&str` using forward slashes. Git's own metadata paths
//! (`objects/…`, `refs/…`, `HEAD`, `config`, …) are ASCII, so this is lossless
//! for the repository internals. Working-tree paths with non-UTF-8 components
//! are a known limitation tracked in the roadmap (the index stores raw bytes;
//! the worktree writer will grow a bytes-path entry point).
//!
//! The standard-library backend [`StdFs`] is available with the `std` feature.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Result;

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink,
}

/// A directory entry: its leaf name and type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name within its parent directory (no path separators).
    pub name: String,
    /// The entry's type.
    pub file_type: FileType,
}

/// An abstract filesystem the repository layers read and write through.
///
/// Implementations must be safe to share behind `&self`; mutation is expressed
/// through `&self` methods because a `Repository` holds the backend immutably
/// and concurrent readers are expected. The std backend uses ordinary syscalls
/// (which are themselves `&self`-safe), and an in-memory backend would use
/// interior mutability.
pub trait Vfs {
    /// Reads an entire file into a byte vector.
    fn read(&self, path: &str) -> Result<Vec<u8>>;

    /// Writes `data` to `path`, creating or truncating it. Implementations
    /// should make this as atomic as the backend allows (the std backend writes
    /// to a temporary sibling and renames — see [`StdFs::write`]).
    fn write(&self, path: &str, data: &[u8]) -> Result<()>;

    /// Whether a path exists (following symlinks).
    fn exists(&self, path: &str) -> bool;

    /// The type of the entry at `path`, or an error if it does not exist.
    fn metadata(&self, path: &str) -> Result<FileType>;

    /// Creates `path` and any missing parent directories.
    fn create_dir_all(&self, path: &str) -> Result<()>;

    /// Lists the entries of a directory (names are leaf names, unordered).
    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>>;

    /// Removes a file (not a directory).
    fn remove_file(&self, path: &str) -> Result<()>;

    /// Renames/moves a path, replacing the destination if it exists. Used for
    /// the write-temp-then-rename pattern that makes ref and object updates
    /// crash-safe.
    fn rename(&self, from: &str, to: &str) -> Result<()>;
}

#[cfg(feature = "std")]
mod std_impl;
#[cfg(feature = "std")]
pub use std_impl::StdFs;
