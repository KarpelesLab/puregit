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

    /// Computes the on-disk sub-path for a *validated* oid.
    ///
    /// The byte-index slices below (`&oid[..2]`, `&oid[2..4]`) are sound only
    /// because every caller runs `validate_oid` first: it guarantees the oid
    /// is exactly 64 ASCII lowercase hex chars, so indices 2 and 4 are always
    /// on char boundaries and no path segment can contain `.`, `/`, or any
    /// traversal sequence. Never call this on an unvalidated oid.
    fn object_path(oid: &str) -> alloc::string::String {
        alloc::format!("objects/{}/{}/{}", &oid[..2], &oid[2..4], oid)
    }

    /// Whether the object with this SHA-256 hex id is present locally.
    ///
    /// An oid that is not a well-formed SHA-256 (see `validate_oid`) cannot
    /// name a valid object, so this returns `false` rather than touching the
    /// filesystem — and, crucially, never slices at a non-char boundary or
    /// lets a crafted oid escape the store directory.
    pub fn contains(&self, oid: &str) -> bool {
        if validate_oid(oid).is_err() {
            return false;
        }
        self.vfs.exists(&Self::object_path(oid))
    }

    /// Reads an object's content by SHA-256 hex id, verifying it hashes back to
    /// `oid` (LFS stores are content-addressed, so a mismatch is corruption).
    pub fn read(&self, oid: &str) -> Result<Vec<u8>> {
        validate_oid(oid)?;
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
        // `for_content` always produces a 64-char lowercase-hex oid, but we
        // validate before slicing a path from it so `object_path` is never
        // reachable with an unchecked oid regardless of how it was produced.
        validate_oid(&pointer.oid)?;
        let path = Self::object_path(&pointer.oid);
        if !self.vfs.exists(&path) {
            self.vfs.write(&path, content)?;
        }
        Ok(pointer)
    }

    /// Stores content that is expected to match `pointer`, verifying its hash
    /// and size first (used when receiving an object from an LFS server).
    pub fn write_verified(&self, pointer: &Pointer, content: &[u8]) -> Result<()> {
        // The pointer's oid arrives from callers that may have parsed it from
        // untrusted input; validate before it reaches `object_path`.
        validate_oid(&pointer.oid)?;
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

/// Validates that `oid` is a well-formed LFS object id: exactly 64 ASCII
/// lowercase hex characters (the hex SHA-256 git-lfs content-addresses by).
///
/// This is the store's defense-in-depth gate. The path built from an oid slices
/// it by byte index (`&oid[..2]`) and joins the raw string into a filesystem
/// path, so an unvalidated oid could (a) panic by slicing a multibyte char at a
/// non-boundary (e.g. `"aé23"`), or (b) contain traversal segments (`..`, `/`,
/// leading `/`) and escape the store. Enforcing the strict SHA-256 shape here
/// makes both impossible before any slicing or path join happens, independent
/// of whatever the caller or the underlying [`Vfs`] does.
fn validate_oid(oid: &str) -> Result<()> {
    if oid.len() == 64 && oid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(Error::InvalidOid(alloc::format!(
            "lfs oid is not 64 lowercase hex chars: {oid:?}"
        )))
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

    #[test]
    fn invalid_oid_never_panics() {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-lfs-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = LfsStore::new(StdFs::new(&dir));

        // E2/C2: a multibyte, short, wrong-length, uppercase, or traversal oid
        // must be *rejected*, never slice at a non-char boundary (panic) or
        // escape the store directory.
        let bad = [
            "aé23", // multibyte char at byte index 2 would panic on slice
            "ab",   // too short
            "",     // empty
            "../../etc/passwd",
            "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789", // uppercase
            "z891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03", // non-hex
        ];
        for oid in bad {
            assert!(!store.contains(oid), "contains({oid:?}) should be false");
            assert!(store.read(oid).is_err(), "read({oid:?}) should error");
        }

        // write_verified with a bad-oid pointer errors rather than slicing.
        let bogus = Pointer {
            oid: "aé23".into(),
            size: 3,
        };
        assert!(store.write_verified(&bogus, b"abc").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
