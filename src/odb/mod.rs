//! The object database — reading and writing git objects by id.
//!
//! [`ObjectDatabase`] is the abstraction the rest of the crate reads and writes
//! objects through. Two backends ship here:
//!
//! - [`MemoryOdb`] — an in-memory map, for tests and for staging objects before
//!   they are flushed to disk or streamed into a pack.
//! - [`LooseOdb`] — the classic on-disk loose-object store
//!   (`objects/ab/cdef…`), zlib-compressed, read and written through a [`crate::vfs::Vfs`].
//!
//! Packed objects (the `objects/pack/*.pack` + `*.idx` files) are read by
//! [`crate::pack`]; a combined backend that consults loose objects first and
//! then every pack index is the on-disk repository's real ODB and is assembled
//! in [`crate::repository`].

mod combined;
mod loose;
mod memory;

pub use combined::CombinedOdb;
pub use loose::LooseOdb;
pub use memory::MemoryOdb;

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::object::{Object, ObjectType};
use crate::oid::{HashAlgo, ObjectId};

/// Reading and writing git objects, content-addressed by [`ObjectId`].
pub trait ObjectDatabase {
    /// The hash algorithm this database names objects with.
    fn algo(&self) -> HashAlgo;

    /// Whether an object with the given id is present.
    fn contains(&self, id: &ObjectId) -> bool;

    /// Reads an object, returning its `(type, payload)`. The payload is the
    /// canonical content (the bytes after the loose header / the inflated
    /// packed content). Returns [`Error::NotFound`] if absent.
    fn read(&self, id: &ObjectId) -> Result<(ObjectType, Vec<u8>)>;

    /// Stores `payload` as an object of type `ty`, returning its id. Writing an
    /// object that already exists is a no-op that returns the same id.
    fn write(&self, ty: ObjectType, payload: &[u8]) -> Result<ObjectId>;

    /// Reads and parses an object into a typed [`Object`].
    fn read_object(&self, id: &ObjectId) -> Result<Object> {
        let (ty, payload) = self.read(id)?;
        Object::parse(self.algo(), ty, &payload)
    }

    /// Reads an object, requiring it to be of `expected` type, returning its
    /// payload. Yields [`Error::UnexpectedType`] on a type mismatch — the
    /// building block for "resolve this ref to a tree", etc.
    fn read_typed(&self, id: &ObjectId, expected: ObjectType) -> Result<Vec<u8>> {
        let (ty, payload) = self.read(id)?;
        if ty != expected {
            return Err(Error::UnexpectedType {
                expected,
                actual: ty,
            });
        }
        Ok(payload)
    }
}
