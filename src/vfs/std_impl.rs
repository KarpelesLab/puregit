//! The standard-library [`crate::vfs::Vfs`] backend.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;

use super::{DirEntry, FileType, Vfs};

/// A [`crate::vfs::Vfs`] backed by `std::fs`, rooted at a base directory.
///
/// All paths handed to the trait methods are interpreted relative to `root`
/// (absolute inputs are still joined under it via `Path::join`, which for an
/// absolute component replaces the base — callers pass repository-relative
/// paths, so this is the intended "chroot-lite" behavior for the common case).
#[derive(Debug, Clone)]
pub struct StdFs {
    root: PathBuf,
}

impl StdFs {
    /// Creates a backend rooted at `root` (e.g. a repository's `.git`
    /// directory, or a working-tree root).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        StdFs { root: root.into() }
    }

    fn resolve(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }
}

impl Vfs for StdFs {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        Ok(fs::read(self.resolve(path))?)
    }

    fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        // Write to a temp sibling then rename, so a reader never sees a
        // half-written object or ref. The temp name embeds the target leaf to
        // avoid collisions between concurrent writers of different files.
        let full = self.resolve(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = tmp_sibling(&full);
        fs::write(&tmp, data)?;
        match fs::rename(&tmp, &full) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(e.into())
            }
        }
    }

    fn exists(&self, path: &str) -> bool {
        self.resolve(path).exists()
    }

    fn metadata(&self, path: &str) -> Result<FileType> {
        let md = fs::symlink_metadata(self.resolve(path))?;
        let ft = md.file_type();
        Ok(if ft.is_dir() {
            FileType::Dir
        } else if ft.is_symlink() {
            FileType::Symlink
        } else {
            FileType::File
        })
    }

    fn create_dir_all(&self, path: &str) -> Result<()> {
        Ok(fs::create_dir_all(self.resolve(path))?)
    }

    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.resolve(path))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let ft = entry.file_type()?;
            let file_type = if ft.is_dir() {
                FileType::Dir
            } else if ft.is_symlink() {
                FileType::Symlink
            } else {
                FileType::File
            };
            out.push(DirEntry { name, file_type });
        }
        Ok(out)
    }

    fn remove_file(&self, path: &str) -> Result<()> {
        Ok(fs::remove_file(self.resolve(path))?)
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        Ok(fs::rename(self.resolve(from), self.resolve(to))?)
    }
}

/// Builds a temporary sibling path (`<name>.<n>.tmp`) for atomic writes.
fn tmp_sibling(full: &Path) -> PathBuf {
    let leaf = full
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    // A monotonic-ish suffix without pulling in randomness: the address of the
    // path buffer is unique among concurrent calls within a process; combined
    // with the leaf name it avoids collisions in practice. (A future revision
    // can use an O_EXCL create loop for stronger guarantees.)
    let suffix = leaf.as_ptr() as usize;
    let mut s = String::with_capacity(leaf.len() + 24);
    s.push('.');
    s.push_str(&leaf);
    s.push('.');
    s.push_str(&suffix.to_string());
    s.push_str(".tmp");
    full.with_file_name(s)
}
