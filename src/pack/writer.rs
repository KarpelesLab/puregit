//! Writing packfiles and their indexes.
//!
//! [`PackWriter`] serializes a set of objects into a version-2 packfile and the
//! matching v2 `.idx`. Each object is delta-compressed against a small window of
//! recent same-type objects (`OFS_DELTA`, via [`super::delta::create_delta`])
//! when that yields a smaller on-pack stream, and stored as its own zlib stream
//! otherwise. The pack this produces is read back by [`super::Pack`] /
//! [`super::PackIndex`], and is exactly what a fetch/push/serve path streams to
//! a peer.
//!
//! The `.idx` carries the per-object CRC-32 git stores for integrity, computed
//! over each object's on-pack bytes (header + compressed data).

use alloc::vec::Vec;
use purecrypto::hash::{Digest, Sha1, Sha256};

use crate::compress;
use crate::error::Result;
use crate::hash::hash_object;
use crate::object::ObjectType;
use crate::oid::{HashAlgo, ObjectId};

/// Accumulates objects and emits a packfile plus its index.
pub struct PackWriter {
    algo: HashAlgo,
    /// Unique objects to write, keyed by id (dedup on insert).
    entries: Vec<Entry>,
}

struct Entry {
    id: ObjectId,
    ty: ObjectType,
    payload: Vec<u8>,
}

/// The packfile type tag for an `OFS_DELTA` entry.
const OFS_DELTA_TAG: u8 = 6;

/// Objects larger than this are never deltified (and never used as a base): the
/// `create_delta` base index holds one entry per base byte, so we bound its cost
/// and memory. Larger objects are stored raw — still correct, just not deltified.
const MAX_DELTA_SIZE: usize = 1 << 20;

/// How many recent same-type bases to try deltifying each object against.
const DELTA_WINDOW: usize = 10;

/// A candidate delta base: a full (undeltified) object already written to the
/// pack, referenced by its type, byte offset, and index into `entries`.
struct BaseCand {
    ty: ObjectType,
    offset: u64,
    idx: usize,
}

/// Encodes an `OFS_DELTA` base distance the way [`super::Pack`] decodes it: a
/// big-endian base-128 varint with the "-1 per continuation" bias.
fn encode_ofs(mut ofs: u64) -> Vec<u8> {
    let mut buf = alloc::vec![(ofs & 0x7f) as u8];
    ofs >>= 7;
    while ofs != 0 {
        ofs -= 1;
        buf.push(0x80 | (ofs & 0x7f) as u8);
        ofs >>= 7;
    }
    buf.reverse();
    buf
}

impl PackWriter {
    /// Creates an empty writer naming objects with `algo`.
    pub fn new(algo: HashAlgo) -> Self {
        PackWriter {
            algo,
            entries: Vec::new(),
        }
    }

    /// Adds an object, returning its id. Adding the same object twice is a
    /// no-op (the pack contains one copy).
    pub fn add(&mut self, ty: ObjectType, payload: &[u8]) -> ObjectId {
        let id = hash_object(self.algo, ty, payload);
        if !self.entries.iter().any(|e| e.id == id) {
            self.entries.push(Entry {
                id,
                ty,
                payload: payload.to_vec(),
            });
        }
        id
    }

    /// The number of distinct objects queued.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no objects are queued.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serializes the pack and index, returning `(pack_bytes, idx_bytes)`.
    ///
    /// The two share a trailer hash (the pack checksum), so they form a valid
    /// matched pair: write them as `pack-<hash>.pack` / `pack-<hash>.idx`.
    pub fn finish(&self) -> Result<PackOutput> {
        // --- pack body ---
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());

        // Per-object pack offset and CRC-32, for the index.
        let mut meta: Vec<(ObjectId, u64, u32)> = Vec::with_capacity(self.entries.len());
        // Recent *full* (undeltified) entries, as candidate delta bases. An
        // OFS_DELTA's base must be earlier in the pack and — since the reader
        // takes the delta object's type from its base — of the same type. We
        // only base on full objects, keeping delta chains at depth 1.
        let mut bases: Vec<BaseCand> = Vec::new();
        for (k, e) in self.entries.iter().enumerate() {
            let offset = pack.len() as u64;
            let entry_start = pack.len();
            let raw = compress::deflate(&e.payload)?;

            // Consider deltifying against a small window of recent same-type
            // bases; pick the smallest on-pack delta that beats the raw stream.
            let mut best: Option<(u64, Vec<u8>, Vec<u8>, usize)> = None;
            if e.payload.len() <= MAX_DELTA_SIZE {
                for cand in bases
                    .iter()
                    .rev()
                    .filter(|c| c.ty == e.ty)
                    .take(DELTA_WINDOW)
                {
                    let base = &self.entries[cand.idx].payload;
                    if base.len() > MAX_DELTA_SIZE {
                        continue;
                    }
                    let delta = super::delta::create_delta(base, &e.payload);
                    let zdelta = compress::deflate(&delta)?;
                    let ofs = encode_ofs(offset - cand.offset);
                    if zdelta.len() + ofs.len() < raw.len()
                        && best.as_ref().is_none_or(|b| zdelta.len() < b.1.len())
                    {
                        best = Some((cand.offset, zdelta, ofs, delta.len()));
                    }
                }
            }

            match best {
                Some((_base_offset, zdelta, ofs, delta_len)) => {
                    // OFS_DELTA: header size is the *delta* stream's length.
                    write_entry_header(&mut pack, OFS_DELTA_TAG, delta_len);
                    pack.extend_from_slice(&ofs);
                    pack.extend_from_slice(&zdelta);
                    // A delta is not itself used as a base (keeps chains shallow).
                }
                None => {
                    write_entry_header(&mut pack, pack_tag(e.ty), e.payload.len());
                    pack.extend_from_slice(&raw);
                    bases.push(BaseCand {
                        ty: e.ty,
                        offset,
                        idx: k,
                    });
                }
            }
            let crc = crc32(&pack[entry_start..]);
            meta.push((e.id, offset, crc));
        }
        let pack_hash = hash_bytes(self.algo, &pack);
        pack.extend_from_slice(&pack_hash);

        // --- index ---
        let idx = build_index(self.algo, &mut meta, &pack_hash);

        Ok(PackOutput {
            pack,
            idx,
            hash: ObjectId::from_bytes(self.algo, &pack_hash).expect("hash length matches algo"),
        })
    }
}

/// The result of [`PackWriter::finish`]: the two files and their shared name.
pub struct PackOutput {
    /// The `.pack` bytes.
    pub pack: Vec<u8>,
    /// The `.idx` bytes.
    pub idx: Vec<u8>,
    /// The pack trailer hash — use its hex as the `pack-<hash>` filename stem.
    pub hash: ObjectId,
}

/// Builds the v2 `.idx` from per-object `(id, offset, crc)` metadata.
fn build_index(algo: HashAlgo, meta: &mut [(ObjectId, u64, u32)], pack_hash: &[u8]) -> Vec<u8> {
    let id_len = algo.raw_len();
    meta.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    let mut idx = Vec::new();
    idx.extend_from_slice(b"\xfftOc");
    idx.extend_from_slice(&2u32.to_be_bytes());

    // Fanout: cumulative count of objects whose first id byte is <= n.
    let mut fanout = [0u32; 256];
    for (id, _, _) in meta.iter() {
        let first = id.as_bytes()[0] as usize;
        fanout[first] += 1;
    }
    let mut acc = 0u32;
    for slot in fanout.iter_mut() {
        acc += *slot;
        *slot = acc;
    }
    for count in fanout {
        idx.extend_from_slice(&count.to_be_bytes());
    }

    // Sorted object ids.
    for (id, _, _) in meta.iter() {
        idx.extend_from_slice(&id.as_bytes()[..id_len]);
    }
    // CRC-32 of each object's pack bytes.
    for (_, _, crc) in meta.iter() {
        idx.extend_from_slice(&crc.to_be_bytes());
    }
    // Offsets: 31-bit inline, or a high-bit-flagged index into the 64-bit table.
    let mut large: Vec<u64> = Vec::new();
    for (_, offset, _) in meta.iter() {
        if *offset < 0x8000_0000 {
            idx.extend_from_slice(&(*offset as u32).to_be_bytes());
        } else {
            let large_idx = large.len() as u32;
            idx.extend_from_slice(&(0x8000_0000 | large_idx).to_be_bytes());
            large.push(*offset);
        }
    }
    for off in large {
        idx.extend_from_slice(&off.to_be_bytes());
    }

    // Trailer: the pack hash, then the idx's own hash over everything above.
    idx.extend_from_slice(pack_hash);
    let idx_hash = hash_bytes(algo, &idx);
    idx.extend_from_slice(&idx_hash);
    idx
}

/// Writes a packfile entry header: the type tag and the uncompressed size as
/// git's little-endian base-128 (low 4 bits in the first byte).
fn write_entry_header(out: &mut Vec<u8>, tag: u8, size: usize) {
    let mut byte = (tag << 4) | (size & 0x0f) as u8;
    let mut rest = size >> 4;
    if rest != 0 {
        byte |= 0x80;
    }
    out.push(byte);
    while rest != 0 {
        let mut b = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

fn pack_tag(ty: ObjectType) -> u8 {
    match ty {
        ObjectType::Commit => 1,
        ObjectType::Tree => 2,
        ObjectType::Blob => 3,
        ObjectType::Tag => 4,
    }
}

fn hash_bytes(algo: HashAlgo, data: &[u8]) -> Vec<u8> {
    match algo {
        HashAlgo::Sha1 => Sha1::digest(data).as_ref().to_vec(),
        HashAlgo::Sha256 => Sha256::digest(data).as_ref().to_vec(),
    }
}

/// CRC-32 (IEEE 802.3 / zlib polynomial), the variant git stores in `.idx`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{Pack, PackIndex};

    #[test]
    fn write_then_read_back() {
        let mut w = PackWriter::new(HashAlgo::Sha1);
        let blob = w.add(ObjectType::Blob, b"hello\n");
        let tree = w.add(ObjectType::Tree, b""); // empty tree payload
        let out = w.finish().unwrap();

        // The pack reads back with the right object count and bytes.
        let pack = Pack::new(out.pack.clone(), HashAlgo::Sha1).unwrap();
        assert_eq!(pack.object_count(), 2);

        let index = PackIndex::parse(HashAlgo::Sha1, &out.idx).unwrap();
        assert_eq!(index.len(), 2);
        assert!(index.contains(&blob));
        assert!(index.contains(&tree));

        // Resolve the blob through the index → pack.
        let never = |_: &ObjectId| -> Result<(ObjectType, Vec<u8>)> {
            panic!("no external bases in this pack")
        };
        let off = index.offset_of(&blob).unwrap();
        let (ty, payload) = pack.read_at(off, &never).unwrap();
        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(payload, b"hello\n");
    }

    #[test]
    fn deltifies_similar_objects_and_reads_back() {
        use crate::pack::explode_pack;

        // Two large, similar blobs: the second should be stored as a delta.
        let base: Vec<u8> = (0..8000u32)
            .map(|i| i.wrapping_mul(2654435761).rotate_left(7) as u8)
            .collect();
        let mut variant = base.clone();
        for b in variant.iter_mut().skip(4000).take(200) {
            *b = b.wrapping_add(1);
        }

        let mut w = PackWriter::new(HashAlgo::Sha1);
        let id_base = w.add(ObjectType::Blob, &base);
        let id_var = w.add(ObjectType::Blob, &variant);
        let out = w.finish().unwrap();

        // The whole pack is smaller than the two raw payloads concatenated —
        // evidence the variant was deltified rather than stored in full.
        assert!(
            out.pack.len() < base.len() + variant.len(),
            "expected delta compression to shrink the pack"
        );

        // Both objects resolve correctly through the index/pack...
        let index = PackIndex::parse(HashAlgo::Sha1, &out.idx).unwrap();
        let pack = Pack::new(out.pack.clone(), HashAlgo::Sha1).unwrap();
        let never = |_: &ObjectId| -> Result<(ObjectType, Vec<u8>)> { panic!("no external bases") };
        let (ty, payload) = pack
            .read_at(index.offset_of(&id_var).unwrap(), &never)
            .unwrap();
        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(payload, variant);

        // ...and via the sequential exploder (the ingest path), with correct ids.
        let objs = explode_pack(&out.pack, HashAlgo::Sha1, &never).unwrap();
        assert_eq!(objs.len(), 2);
        assert!(objs.iter().any(|(id, ty, p)| *id == id_base
            && *ty == ObjectType::Blob
            && p.as_slice() == base.as_slice()));
        assert!(objs.iter().any(|(id, ty, p)| *id == id_var
            && *ty == ObjectType::Blob
            && p.as_slice() == variant.as_slice()));
    }

    #[test]
    fn crc32_known_vector() {
        // CRC-32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
