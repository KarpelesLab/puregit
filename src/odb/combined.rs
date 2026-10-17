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
    /// Alternate object stores from `objects/info/alternates`, consulted after
    /// this store's own loose and packed objects. Only one level deep: an
    /// alternate's own alternates are not followed, so a cyclic `alternates`
    /// file cannot cause an infinite lookup.
    alternates: Vec<CombinedOdb<V>>,
    algo: HashAlgo,
    /// Bound on recursion through delta chains, to stop a maliciously crafted
    /// cyclic `REF_DELTA` from recursing without limit.
    max_delta_depth: usize,
}

impl<V: Vfs + Clone> CombinedOdb<V> {
    /// Opens the combined store over `vfs` (rooted at `objects/`), loading every
    /// pack under `pack/` and every alternate object store listed in
    /// `info/alternates`.
    pub fn open(vfs: V, algo: HashAlgo) -> Result<Self> {
        let alternates = Self::load_alternates(&vfs, algo)?;
        Self::open_inner(vfs, algo, alternates)
    }

    /// Opens the loose + packed store over `vfs` with the given (already-loaded)
    /// alternates. Alternates themselves are opened with none, so the graph is
    /// at most one level deep.
    fn open_inner(vfs: V, algo: HashAlgo, alternates: Vec<CombinedOdb<V>>) -> Result<Self> {
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
            alternates,
            algo,
            max_delta_depth: 50,
        })
    }

    /// Reads `info/alternates` and opens each listed object store (no nested
    /// alternates). A missing/blank file yields no alternates; an unreadable or
    /// unopenable entry is skipped rather than failing the open.
    fn load_alternates(vfs: &V, algo: HashAlgo) -> Result<Vec<CombinedOdb<V>>> {
        let mut out = Vec::new();
        let Ok(bytes) = vfs.read("info/alternates") else {
            return Ok(out);
        };
        let text = core::str::from_utf8(&bytes).unwrap_or("");
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(sub) = vfs.open_relative(line)
                && let Ok(alt) = Self::open_inner(sub, algo, Vec::new())
            {
                out.push(alt);
            }
        }
        Ok(out)
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
                // REF_DELTA bases in this same pack are followed iteratively
                // inside the pack reader (git packs written with
                // `repack.useDeltaBaseOffset=false` chain them deeply); only a
                // base living elsewhere recurses through the whole store
                // (loose + every pack), one level deeper.
                let locate = |base: &ObjectId| lp.index.offset_of(base);
                let resolver = |base: &ObjectId| self.read_depth(base, depth + 1);
                return lp.pack.read_at_with(offset, &locate, &resolver);
            }
        }
        // Not in this store: try each alternate object store.
        for alt in &self.alternates {
            if let Ok(obj) = alt.read_depth(id, depth) {
                return Ok(obj);
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
        self.loose.contains(id)
            || self.packs.iter().any(|lp| lp.index.contains(id))
            || self.alternates.iter().any(|alt| alt.contains(id))
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

    #[test]
    fn reads_through_an_alternate_object_store() {
        let base = std::env::temp_dir().join(format!("puregit-alt-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&base);
        let main_obj = base.join("main");
        let alt_obj = base.join("alt");
        std::fs::create_dir_all(&main_obj).unwrap();
        std::fs::create_dir_all(&alt_obj).unwrap();

        // An object living only in the alternate store.
        let alt = LooseOdb::new(StdFs::new(&alt_obj), HashAlgo::Sha1);
        let id = alt.write(ObjectType::Blob, b"in the alternate\n").unwrap();

        // The main store does not have it...
        let plain = CombinedOdb::open(StdFs::new(&main_obj), HashAlgo::Sha1).unwrap();
        assert!(!plain.contains(&id));

        // ...until info/alternates points at the alternate objects dir.
        std::fs::create_dir_all(main_obj.join("info")).unwrap();
        std::fs::write(
            main_obj.join("info/alternates"),
            format!("{}\n", alt_obj.display()),
        )
        .unwrap();
        let odb = CombinedOdb::open(StdFs::new(&main_obj), HashAlgo::Sha1).unwrap();
        assert!(odb.contains(&id));
        assert_eq!(odb.read(&id).unwrap().1, b"in the alternate\n");

        let _ = std::fs::remove_dir_all(&base);
    }
}
