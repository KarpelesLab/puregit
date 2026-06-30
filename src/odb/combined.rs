//! The combined loose + packed object database.
//!
//! A real on-disk repository stores objects two ways: as individual zlib loose
//! files (`objects/ab/cdef…`) and inside packfiles (`objects/pack/*.pack` with
//! their `*.idx`). [`CombinedOdb`] presents both as a single
//! [`ObjectDatabase`]: a read consults the loose store first, then every pack
//! index; a write always lands as a new loose object.
//!
//! Pack delta resolution (`REF_DELTA`) may reference a base that lives in
//! another pack or in the loose store — including, for a *thin* pack received
//! over the wire, an object the receiver already had. [`CombinedOdb`] supplies
//! itself as the resolver, so a delta chain is followed across every backend.

use alloc::format;
use alloc::vec::Vec;

use crate::error::{Error, ObjectKindHint, Result};
use crate::oid::{HashAlgo, ObjectId};
use crate::pack::{Pack, PackIndex};
use crate::vfs::Vfs;

use super::{LooseOdb, ObjectDatabase};

/// One loaded pack: its index (for id→offset lookup) and the pack bytes.
struct LoadedPack {
    index: PackIndex,
    pack: Pack,
}

/// A repository object store backed by loose objects plus every packfile.
///
/// Generic over the [`Vfs`] backend, which must be rooted at the `objects/`
/// directory (so loose objects are at `ab/cdef…` and packs at `pack/…`).
pub struct CombinedOdb<V: Vfs + Clone> {
    loose: LooseOdb<V>,
    packs: Vec<LoadedPack>,
    algo: HashAlgo,
    /// Bound on recursion through delta chains, to stop a maliciously crafted
    /// cyclic `REF_DELTA` from recursing without limit.
    max_delta_depth: usize,
}

impl<V: Vfs + Clone> CombinedOdb<V> {
    /// Opens the combined store over `vfs` (rooted at `objects/`), loading every
    /// pack found under `pack/` into memory.
    pub fn open(vfs: V, algo: HashAlgo) -> Result<Self> {
        let mut packs = Vec::new();

        if vfs.exists("pack") {
            for entry in vfs.read_dir("pack")? {
                if !entry.name.ends_with(".idx") {
                    continue;
                }
                let stem = &entry.name[..entry.name.len() - 4];
                let idx_path = format!("pack/{}", entry.name);
                let pack_path = format!("pack/{stem}.pack");
                if !vfs.exists(&pack_path) {
                    continue; // .idx without its .pack — skip rather than fail
                }
                let index = PackIndex::parse(algo, &vfs.read(&idx_path)?)?;
                let pack = Pack::new(vfs.read(&pack_path)?, algo)?;
                packs.push(LoadedPack { index, pack });
            }
        }

        Ok(CombinedOdb {
            loose: LooseOdb::new(vfs, algo),
            packs,
            algo,
            max_delta_depth: 50,
        })
    }

    /// The number of packs loaded.
    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }

    /// Reads an object, tracking delta-resolution depth so cyclic or
    /// pathologically deep `REF_DELTA` chains are rejected.
    fn read_depth(
        &self,
        id: &ObjectId,
        depth: usize,
    ) -> Result<(crate::object::ObjectType, Vec<u8>)> {
        if depth > self.max_delta_depth {
            return Err(Error::Pack("delta chain too deep (possible cycle)".into()));
        }
        if self.loose.contains(id) {
            return self.loose.read(id);
        }
        for lp in &self.packs {
            if let Some(offset) = lp.index.offset_of(id) {
                // Resolve any REF_DELTA base by recursing through the whole
                // store (loose + every pack), one level deeper.
                let resolver = |base: &ObjectId| self.read_depth(base, depth + 1);
                return lp.pack.read_at(offset, &resolver);
            }
        }
        Err(Error::NotFound(ObjectKindHint::Object(id.to_hex())))
    }
}

impl<V: Vfs + Clone> ObjectDatabase for CombinedOdb<V> {
    fn algo(&self) -> HashAlgo {
        self.algo
    }

    fn contains(&self, id: &ObjectId) -> bool {
        self.loose.contains(id) || self.packs.iter().any(|lp| lp.index.contains(id))
    }

    fn read(&self, id: &ObjectId) -> Result<(crate::object::ObjectType, Vec<u8>)> {
        self.read_depth(id, 0)
    }

    fn write(&self, ty: crate::object::ObjectType, payload: &[u8]) -> Result<ObjectId> {
        // New objects always land loose; packing is an explicit maintenance op.
        self.loose.write(ty, payload)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::object::ObjectType;
    use crate::vfs::StdFs;

    #[test]
    fn reads_loose_through_combined() {
        let dir = std::env::temp_dir().join(format!("puregit-combined-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Stage a loose object via the loose backend.
        let loose = LooseOdb::new(StdFs::new(&dir), HashAlgo::Sha1);
        let id = loose.write(ObjectType::Blob, b"hello\n").unwrap();

        // The combined store (no packs) finds it.
        let odb = CombinedOdb::open(StdFs::new(&dir), HashAlgo::Sha1).unwrap();
        assert_eq!(odb.pack_count(), 0);
        assert!(odb.contains(&id));
        let (ty, payload) = odb.read(&id).unwrap();
        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(payload, b"hello\n");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
