//! The local LFS object store.
//!
//! Git LFS keeps the real content of tracked files under
//! `.git/lfs/objects/<ab>/<cd>/<oid>`, content-addressed by the SHA-256 the
//! [`Pointer`] carries and stored *uncompressed* (unlike git objects). This is
//! that store, over the [`Vfs`] trait, so it works on disk or any backend.

use alloc::vec::Vec;

use crate::error::{Error, ObjectKindHint, Result};
use crate::vfs::Vfs;

use super::Pointer;

/// A local LFS content store rooted at the `lfs/` directory (so objects live at
/// `objects/<ab>/<cd>/<oid>`).
#[derive(Debug, Clone)]
pub struct LfsStore<V: Vfs> {
    vfs: V,
}

impl<V: Vfs> LfsStore<V> {
    /// Creates a store over `vfs` (rooted at `<git-dir>/lfs`).
    pub fn new(vfs: V) -> Self {
        LfsStore { vfs }
    }

    fn object_path(oid: &str) -> alloc::string::String {
        alloc::format!("objects/{}/{}/{}", &oid[..2], &oid[2..4], oid)
    }

    /// Whether the object with this SHA-256 hex id is present locally.
    pub fn contains(&self, oid: &str) -> bool {
        if oid.len() < 4 {
            return false;
        }
        self.vfs.exists(&Self::object_path(oid))
    }

    /// Reads an object's content by SHA-256 hex id, verifying it hashes back to
    /// `oid` (LFS stores are content-addressed, so a mismatch is corruption).
    pub fn read(&self, oid: &str) -> Result<Vec<u8>> {
        if !self.contains(oid) {
            return Err(Error::NotFound(ObjectKindHint::Object(oid.into())));
        }
        let content = self.vfs.read(&Self::object_path(oid))?;
        let actual = Pointer::for_content(&content);
        if actual.oid != oid {
            return Err(Error::InvalidOid(alloc::format!(
                "lfs object {oid} hashes to {}",
                actual.oid
            )));
        }
        Ok(content)
    }

    /// Stores `content` and returns its [`Pointer`]. Storing content already
    /// present is a no-op (objects are immutable and content-addressed).
    pub fn write(&self, content: &[u8]) -> Result<Pointer> {
        let pointer = Pointer::for_content(content);
        let path = Self::object_path(&pointer.oid);
        if !self.vfs.exists(&path) {
            self.vfs.write(&path, content)?;
        }
        Ok(pointer)
    }

    /// Stores content that is expected to match `pointer`, verifying its hash
    /// and size first (used when receiving an object from an LFS server).
    pub fn write_verified(&self, pointer: &Pointer, content: &[u8]) -> Result<()> {
        let actual = Pointer::for_content(content);
        if &actual != pointer {
            return Err(Error::InvalidOid(
                "lfs object content does not match its pointer".into(),
            ));
        }
        let path = Self::object_path(&pointer.oid);
        if !self.vfs.exists(&path) {
            self.vfs.write(&path, content)?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::vfs::StdFs;

    #[test]
    fn store_roundtrip() {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-lfs-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let store = LfsStore::new(StdFs::new(&dir));
        let pointer = store.write(b"the real large content").unwrap();
        assert!(store.contains(&pointer.oid));
        assert_eq!(store.read(&pointer.oid).unwrap(), b"the real large content");

        // write_verified accepts matching content, rejects mismatched.
        assert!(
            store
                .write_verified(&pointer, b"the real large content")
                .is_ok()
        );
        assert!(store.write_verified(&pointer, b"tampered").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
