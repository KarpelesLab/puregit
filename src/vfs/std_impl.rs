//! The standard-library [`crate::vfs::Vfs`] backend.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

use super::{DirEntry, FileType, Vfs};

/// A [`crate::vfs::Vfs`] backed by `std::fs`, rooted at a base directory.
///
/// All paths handed to the trait methods are interpreted relative to `root`
/// and are confined under it (a real "chroot-lite" invariant, D6). A path that
/// is absolute or contains a `..` component is rejected with [`Error::Io`]
/// rather than being joined — `Path::join` would otherwise let an absolute
/// component replace the root, or a `..` climb above it. Every internal caller
/// passes repository-relative slash paths (`config`, `HEAD`, `index`,
/// `refs/heads/main`, `objects/…`, `packed-refs`), which are unaffected.
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

    /// Joins `path` onto the root after confirming it stays within the root.
    ///
    /// Rejects absolute paths, Windows drive prefixes / root-dir components,
    /// and any `..` (`ParentDir`) component. `.` (`CurDir`) components are
    /// harmless and allowed. Normal and root-relative-normal paths pass
    /// through, so legitimate repo-internal paths keep working.
    fn resolve(&self, path: &str) -> Result<PathBuf> {
        let p = Path::new(path);
        for comp in p.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(Error::Io(alloc::format!(
                        "vfs: path escapes the root via `..`: {path:?}"
                    )));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(Error::Io(alloc::format!(
                        "vfs: absolute path rejected: {path:?}"
                    )));
                }
            }
        }
        Ok(self.root.join(p))
    }
}

impl Vfs for StdFs {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        Ok(fs::read(self.resolve(path)?)?)
    }

    fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        // Write to a temp sibling then rename, so a reader never sees a
        // half-written object or ref. The temp name embeds the target leaf to
        // avoid collisions between concurrent writers of different files.
        let full = self.resolve(path)?;
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
        // A path that fails containment does not "exist" for this backend.
        match self.resolve(path) {
            Ok(full) => full.exists(),
            Err(_) => false,
        }
    }

    fn metadata(&self, path: &str) -> Result<FileType> {
        let md = fs::symlink_metadata(self.resolve(path)?)?;
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
        Ok(fs::create_dir_all(self.resolve(path)?)?)
    }

    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.resolve(path)?)? {
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
        Ok(fs::remove_file(self.resolve(path)?)?)
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        Ok(fs::rename(self.resolve(from)?, self.resolve(to)?)?)
    }

    fn create_new(&self, path: &str, data: &[u8]) -> Result<()> {
        use std::io::Write;
        let full = self.resolve(path)?;
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        // `create_new(true)` maps to `O_EXCL`: the open fails if the path exists.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&full)?;
        f.write_all(data)?;
        Ok(())
    }

    fn open_relative(&self, path: &str) -> Result<Self> {
        // Trusted config (an alternates entry): an absolute path stands alone,
        // a relative one is resolved against this root. Deliberately *not* run
        // through `resolve`, which would reject the escape a legitimate
        // alternate needs.
        let p = Path::new(path);
        let root = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.root.join(p)
        };
        Ok(StdFs::new(root))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(alloc::format!("puregit-vfs-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rejects_parent_dir_and_absolute() {
        let root = temp_root("reject");
        let fs = StdFs::new(&root);

        // `..` traversal is refused on every entry point.
        assert!(fs.read("../secret").is_err());
        assert!(fs.write("../secret", b"x").is_err());
        assert!(fs.create_dir_all("a/../..").is_err());
        assert!(!fs.exists("../secret")); // exists() returns false, never escapes

        // An absolute path is refused rather than replacing the root.
        assert!(fs.read("/etc/passwd").is_err());
        assert!(fs.write("/tmp/escape", b"x").is_err());
        assert!(!fs.exists("/etc/passwd"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn create_new_is_exclusive() {
        let root = temp_root("createnew");
        let fs = StdFs::new(&root);
        // First create succeeds, even creating the parent dir.
        fs.create_new("refs/heads/x.lock", b"first\n").unwrap();
        // A second create of the same path fails (O_EXCL), leaving it unchanged.
        assert!(fs.create_new("refs/heads/x.lock", b"second\n").is_err());
        assert_eq!(fs.read("refs/heads/x.lock").unwrap(), b"first\n");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn allows_legit_relative_paths() {
        let root = temp_root("legit");
        let fs = StdFs::new(&root);

        // The paths the repository layers actually use must still work.
        fs.write("config", b"[core]\n").unwrap();
        assert_eq!(fs.read("config").unwrap(), b"[core]\n");
        fs.write("refs/heads/main", b"deadbeef\n").unwrap();
        assert!(fs.exists("refs/heads/main"));
        fs.create_dir_all("objects/pack").unwrap();
        assert!(fs.exists("objects/pack"));
        // A `.` component is harmless and allowed.
        fs.write("./HEAD", b"ref: refs/heads/main\n").unwrap();
        assert!(fs.exists("HEAD"));

        let _ = fs::remove_dir_all(&root);
    }
}
