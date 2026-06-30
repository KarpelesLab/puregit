//! The on-disk loose-object [`ObjectDatabase`].
//!
//! A loose object lives at `objects/<first-2-hex>/<remaining-hex>` relative to
//! the object directory, and its bytes are the zlib-compressed loose form
//! (`"<type> <size>\0" || payload`). This backend reads and writes that layout
//! through a [`crate::vfs::Vfs`], so it works on the real filesystem ([`crate::vfs::StdFs`])
//! or any other backend.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::compress;
use crate::error::{Error, ObjectKindHint, Result};
use crate::hash::hash_object;
use crate::object::{ObjectType, parse_loose, serialize_loose};
use crate::oid::{HashAlgo, ObjectId};
use crate::vfs::Vfs;

use super::ObjectDatabase;

/// A loose-object store rooted at an `objects/` directory.
///
/// Generic over the [`crate::vfs::Vfs`] backend `V`. The backend's paths are interpreted
/// relative to the object directory, i.e. this type emits paths like
/// `ab/cdef…`; compose the backend so that root maps to `<git-dir>/objects`.
#[derive(Debug, Clone)]
pub struct LooseOdb<V: Vfs> {
    vfs: V,
    algo: HashAlgo,
    /// Cap on the declared uncompressed size we will inflate, as a guard
    /// against corrupt/hostile headers. Defaults to 1 GiB.
    max_object_size: usize,
}

impl<V: Vfs> LooseOdb<V> {
    /// Creates a loose store over `vfs`, naming objects with `algo`.
    pub fn new(vfs: V, algo: HashAlgo) -> Self {
        LooseOdb {
            vfs,
            algo,
            max_object_size: 1 << 30,
        }
    }

    /// Overrides the maximum object size this store will inflate.
    pub fn with_max_object_size(mut self, max: usize) -> Self {
        self.max_object_size = max;
        self
    }

    /// Borrows the underlying VFS (e.g. to enumerate objects).
    pub fn vfs(&self) -> &V {
        &self.vfs
    }

    /// The `ab/cdef…` path of an object within the object directory.
    fn object_path(&self, id: &ObjectId) -> String {
        let hex = id.to_hex();
        format!("{}/{}", &hex[..2], &hex[2..])
    }
}

impl<V: Vfs> ObjectDatabase for LooseOdb<V> {
    fn algo(&self) -> HashAlgo {
        self.algo
    }

    fn contains(&self, id: &ObjectId) -> bool {
        self.vfs.exists(&self.object_path(id))
    }

    fn read(&self, id: &ObjectId) -> Result<(ObjectType, Vec<u8>)> {
        let path = self.object_path(id);
        if !self.vfs.exists(&path) {
            return Err(Error::NotFound(ObjectKindHint::Object(id.to_hex())));
        }
        let compressed = self.vfs.read(&path)?;
        // The declared size lives inside the decompressed header, so we cannot
        // size the cap exactly before inflating; bound it to the configured
        // maximum and let parse_loose validate the precise length.
        let raw = compress::inflate_capped(&compressed, self.max_object_size)?;
        let (ty, payload) = parse_loose(&raw)?;
        // Integrity: the stored bytes must hash back to the id we looked up.
        let computed = hash_object(self.algo, ty, payload);
        if &computed != id {
            return Err(Error::InvalidOid(format!(
                "loose object {id} hashes to {computed}"
            )));
        }
        Ok((ty, payload.to_vec()))
    }

    fn write(&self, ty: ObjectType, payload: &[u8]) -> Result<ObjectId> {
        let id = hash_object(self.algo, ty, payload);
        let path = self.object_path(&id);
        // Objects are immutable: if it already exists, don't rewrite it.
        if self.vfs.exists(&path) {
            return Ok(id);
        }
        let raw = serialize_loose(ty, payload);
        let compressed = compress::deflate(&raw)?;
        self.vfs.write(&path, &compressed)?;
        Ok(id)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::vfs::StdFs;

    #[test]
    fn write_read_roundtrip_on_disk() {
        let dir = std::env::temp_dir().join(format!("puregit-odb-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let odb = LooseOdb::new(StdFs::new(&dir), HashAlgo::Sha1);
        let id = odb.write(ObjectType::Blob, b"hello\n").unwrap();
        assert_eq!(id.to_hex(), "ce013625030ba8dba906f756967f9e9ca394464a");
        assert!(odb.contains(&id));
        let (ty, payload) = odb.read(&id).unwrap();
        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(payload, b"hello\n");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
