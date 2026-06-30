//! An in-memory [`ObjectDatabase`].

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::error::ObjectKindHint;
use crate::error::{Error, Result};
use crate::hash::hash_object;
use crate::object::ObjectType;
use crate::oid::{HashAlgo, ObjectId};

use super::ObjectDatabase;

/// A simple object store backed by a [`BTreeMap`] in memory.
///
/// Useful for tests, for building a pack in memory, and as the write buffer for
/// an index/commit operation before the objects are persisted. Interior
/// mutability (`RefCell`) lets it satisfy the `&self` [`ObjectDatabase`]
/// contract; it is therefore **not** `Sync` and is meant for single-threaded
/// staging.
#[derive(Debug)]
pub struct MemoryOdb {
    algo: HashAlgo,
    objects: RefCell<BTreeMap<ObjectId, (ObjectType, Vec<u8>)>>,
}

impl MemoryOdb {
    /// Creates an empty store naming objects with `algo`.
    pub fn new(algo: HashAlgo) -> Self {
        MemoryOdb {
            algo,
            objects: RefCell::new(BTreeMap::new()),
        }
    }

    /// The number of distinct objects stored.
    pub fn len(&self) -> usize {
        self.objects.borrow().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.objects.borrow().is_empty()
    }
}

impl ObjectDatabase for MemoryOdb {
    fn algo(&self) -> HashAlgo {
        self.algo
    }

    fn contains(&self, id: &ObjectId) -> bool {
        self.objects.borrow().contains_key(id)
    }

    fn read(&self, id: &ObjectId) -> Result<(ObjectType, Vec<u8>)> {
        self.objects
            .borrow()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(ObjectKindHint::Object(id.to_hex())))
    }

    fn write(&self, ty: ObjectType, payload: &[u8]) -> Result<ObjectId> {
        let id = hash_object(self.algo, ty, payload);
        self.objects
            .borrow_mut()
            .entry(id)
            .or_insert_with(|| (ty, payload.to_vec()));
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let id = odb.write(ObjectType::Blob, b"hello\n").unwrap();
        assert_eq!(id.to_hex(), "ce013625030ba8dba906f756967f9e9ca394464a");
        assert!(odb.contains(&id));
        let (ty, payload) = odb.read(&id).unwrap();
        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(payload, b"hello\n");
        // Idempotent write.
        let id2 = odb.write(ObjectType::Blob, b"hello\n").unwrap();
        assert_eq!(id, id2);
        assert_eq!(odb.len(), 1);
    }

    #[test]
    fn missing_is_not_found() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let id = ObjectId::zero(HashAlgo::Sha1);
        assert!(matches!(odb.read(&id), Err(Error::NotFound(_))));
    }
}
