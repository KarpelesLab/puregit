//! Packfiles — git's compressed, delta-encoded object container.
//!
//! A packfile (`objects/pack/pack-*.pack`) stores many objects back-to-back,
//! each as a small type+size header followed by a zlib stream of either the raw
//! object content or a *delta* against another object (by in-pack offset for
//! `OFS_DELTA`, or by object id for `REF_DELTA`). A sibling pack *index*
//! (`*.idx`) maps object ids to their byte offset in the pack so objects can be
//! found without scanning.
//!
//! This module provides:
//! - [`Pack`] — random access to objects by offset, resolving delta chains
//!   (using a caller-supplied resolver for `REF_DELTA` bases that live outside
//!   the pack).
//! - [`PackIndex`] — parsing and id→offset lookup for the v2 `.idx` format.
//! - [`PackWriter`] — serializing objects into a v2 pack and matching `.idx`.
//! - [`explode_pack`] — sequentially decoding a received pack (no index needed)
//!   into fully-resolved objects, the ingest path for clone/fetch/push.
//! - [`delta`] — the delta instruction codec.
//!
//! Delta *compression* on write (emitting `OFS_DELTA`/`REF_DELTA` rather than
//! one zlib stream per object) is a later optimization; the writer is correct
//! and self-contained today.

pub mod delta;
mod writer;

pub use writer::{PackOutput, PackWriter};

use alloc::vec::Vec;

use crate::compress;
use crate::error::{Error, Result};
use crate::object::ObjectType;
use crate::oid::{HashAlgo, ObjectId};

const PACK_SIGNATURE: &[u8; 4] = b"PACK";
const IDX_MAGIC: &[u8; 4] = b"\xfftOc";

/// Maximum depth of an in-pack `OFS_DELTA` chain that [`Pack::read_at`] will
/// follow before giving up. Each level recurses on the Rust call stack, so an
/// attacker-supplied pack with a very long linear delta chain could otherwise
/// overflow the stack; a small fixed cap keeps recursion bounded. (Real git
/// packs are delta-depth limited — 50 is git's own default `pack.depth`.)
const MAX_DELTA_CHAIN_DEPTH: usize = 50;

/// The smallest number of bytes a single pack entry can plausibly occupy: a
/// one-byte type/size header plus a minimal (two-byte) zlib stream. Used only to
/// bound an untrusted object count against the remaining input so a hostile
/// header cannot drive a huge pre-allocation (see [`explode_pack`]).
const MIN_PACK_ENTRY_SIZE: usize = 3;

/// Resolves a `REF_DELTA` base object that is not in the current pack — i.e. a
/// callback into the surrounding object database, returning `(type, payload)`.
pub type ExternalResolver<'a> = dyn Fn(&ObjectId) -> Result<(ObjectType, Vec<u8>)> + 'a;

/// The object type tag stored in a packfile entry header (a superset of
/// [`ObjectType`] that adds the two delta encodings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    /// Delta against a base earlier in the pack, referenced by relative offset.
    OfsDelta,
    /// Delta against a base referenced by object id (may be outside the pack).
    RefDelta,
}

impl PackObjectType {
    fn from_tag(tag: u8) -> Result<Self> {
        Ok(match tag {
            1 => PackObjectType::Commit,
            2 => PackObjectType::Tree,
            3 => PackObjectType::Blob,
            4 => PackObjectType::Tag,
            6 => PackObjectType::OfsDelta,
            7 => PackObjectType::RefDelta,
            other => {
                use alloc::format;
                return Err(Error::Pack(format!("unknown pack object type {other}")));
            }
        })
    }

    fn as_object_type(self) -> Option<ObjectType> {
        Some(match self {
            PackObjectType::Commit => ObjectType::Commit,
            PackObjectType::Tree => ObjectType::Tree,
            PackObjectType::Blob => ObjectType::Blob,
            PackObjectType::Tag => ObjectType::Tag,
            _ => return None,
        })
    }
}

/// A packfile loaded into memory, addressable by object offset.
#[derive(Debug, Clone)]
pub struct Pack {
    data: Vec<u8>,
    algo: HashAlgo,
    object_count: u32,
}

impl Pack {
    /// Parses a packfile's header and takes ownership of its bytes.
    ///
    /// Validates the `PACK` signature and version (2 or 3). Object access is
    /// performed lazily by [`Pack::read_at`].
    pub fn new(data: Vec<u8>, algo: HashAlgo) -> Result<Self> {
        if data.len() < 12 {
            return Err(Error::Pack("pack: too short".into()));
        }
        if &data[..4] != PACK_SIGNATURE {
            return Err(Error::Pack("pack: bad signature".into()));
        }
        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version != 2 && version != 3 {
            use alloc::format;
            return Err(Error::Pack(format!("pack: unsupported version {version}")));
        }
        let object_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        Ok(Pack {
            data,
            algo,
            object_count,
        })
    }

    /// The number of objects the header declares.
    pub fn object_count(&self) -> u32 {
        self.object_count
    }

    /// Reads the object whose entry begins at `offset`, fully resolving any
    /// delta chain.
    ///
    /// `resolve_external` is consulted for a `REF_DELTA` whose base id is not
    /// found inside this pack — typically a "thin pack" received over the wire
    /// whose bases are objects the receiver already has. Pass a closure that
    /// reads from the surrounding object database (or one that always errors for
    /// a self-contained pack).
    pub fn read_at(
        &self,
        offset: usize,
        resolve_external: &ExternalResolver<'_>,
    ) -> Result<(ObjectType, Vec<u8>)> {
        self.read_at_depth(offset, resolve_external, 0)
    }

    /// Depth-tracked worker behind [`Pack::read_at`].
    ///
    /// `depth` counts how many `OFS_DELTA` bases we have followed on the way to
    /// this entry. An `OFS_DELTA` base always lives *earlier* in the pack, so a
    /// well-formed chain is finite; but a hostile pack can encode either a
    /// self-referential offset (relative offset `0`, so the base is the entry
    /// itself → infinite recursion) or an arbitrarily long linear chain (which
    /// recurses just as deep on the call stack). We reject a zero relative
    /// offset outright and cap the chain length at [`MAX_DELTA_CHAIN_DEPTH`] so
    /// neither can exhaust the stack.
    fn read_at_depth(
        &self,
        offset: usize,
        resolve_external: &ExternalResolver<'_>,
        depth: usize,
    ) -> Result<(ObjectType, Vec<u8>)> {
        if depth > MAX_DELTA_CHAIN_DEPTH {
            return Err(Error::Pack("pack: ofs-delta chain too deep".into()));
        }
        let (ptype, size, hdr_len) = self.parse_entry_header(offset)?;
        let body_start = offset + hdr_len;

        if let Some(ty) = ptype.as_object_type() {
            let content = compress::inflate_capped(&self.data[body_start..], size)?;
            return Ok((ty, content));
        }

        match ptype {
            PackObjectType::OfsDelta => {
                let (rel, n) = read_offset_varint(&self.data, body_start)?;
                // The base must lie strictly before this entry. `rel == 0` would
                // point the delta at itself (infinite recursion); `checked_sub`
                // guards the underflow when `rel > offset`.
                if rel == 0 {
                    return Err(Error::Pack(
                        "pack: ofs-delta base is self-referential".into(),
                    ));
                }
                let base_offset = offset
                    .checked_sub(rel)
                    .ok_or_else(|| Error::Pack("pack: ofs-delta base before pack start".into()))?;
                let delta = compress::inflate_capped(&self.data[body_start + n..], size)?;
                let (base_ty, base) =
                    self.read_at_depth(base_offset, resolve_external, depth + 1)?;
                let target = delta::apply_delta(&base, &delta)?;
                Ok((base_ty, target))
            }
            PackObjectType::RefDelta => {
                let id_len = self.algo.raw_len();
                if body_start + id_len > self.data.len() {
                    return Err(Error::Pack("pack: truncated ref-delta base id".into()));
                }
                let base_id =
                    ObjectId::from_bytes(self.algo, &self.data[body_start..body_start + id_len])?;
                let delta = compress::inflate_capped(&self.data[body_start + id_len..], size)?;
                // The base may be in this pack or already in the object store.
                let (base_ty, base) = resolve_external(&base_id)?;
                let target = delta::apply_delta(&base, &delta)?;
                Ok((base_ty, target))
            }
            _ => unreachable!("non-delta handled above"),
        }
    }

    /// Parses an entry's `(type, uncompressed-size, header-length)` at `offset`.
    fn parse_entry_header(&self, offset: usize) -> Result<(PackObjectType, usize, usize)> {
        parse_entry_header_at(&self.data, offset)
    }
}

/// A fully-resolved object recovered from a packfile: its id, type, and bytes.
pub type ExplodedObject = (ObjectId, ObjectType, alloc::vec::Vec<u8>);

/// Sequentially decodes every object in a raw packfile, resolving all deltas,
/// and returns the objects with their ids.
///
/// This is the read side of receiving a pack (clone/fetch ingest, or a server
/// accepting a push): unlike [`Pack::read_at`], which needs a `.idx` for random
/// access, this walks the pack front to back, so it can index a pack that has
/// no index yet. `OFS_DELTA` bases are resolved against earlier objects in the
/// same pack; `REF_DELTA` bases are looked up among already-decoded objects and
/// then via `resolve_external` (for a *thin* pack whose bases the receiver
/// already has).
///
/// Objects are held in memory while the pack is processed (delta bases must be
/// available), so peak memory is the pack's uncompressed size — acceptable for
/// the first implementation; streaming/windowed resolution is a later refinement.
pub fn explode_pack(
    data: &[u8],
    algo: HashAlgo,
    resolve_external: &ExternalResolver<'_>,
) -> Result<alloc::vec::Vec<ExplodedObject>> {
    use crate::hash::hash_object;
    use alloc::collections::BTreeMap;

    if data.len() < 12 || &data[..4] != PACK_SIGNATURE {
        return Err(Error::Pack("pack: bad signature".into()));
    }
    let count = be32(&data[8..12]);

    let id_len = algo.raw_len();
    let mut by_offset: BTreeMap<usize, (ObjectType, alloc::vec::Vec<u8>)> = BTreeMap::new();
    let mut by_id: BTreeMap<ObjectId, (ObjectType, alloc::vec::Vec<u8>)> = BTreeMap::new();
    // `count` is attacker-controlled (up to `u32::MAX`); reserving it directly
    // would let a 12-byte pack request a multi-gigabyte allocation. The pack
    // can hold at most `data.len() / MIN_PACK_ENTRY_SIZE` entries regardless of
    // what the header claims, so clamp the reservation to that ceiling and let
    // the vec grow if the (bounded) real count somehow exceeds it.
    let reserve = (count as usize).min(data.len() / MIN_PACK_ENTRY_SIZE);
    let mut results = alloc::vec::Vec::with_capacity(reserve);

    let mut offset = 12usize;
    for _ in 0..count {
        let (ptype, size, hdr_len) = parse_entry_header_at(data, offset)?;
        let body = offset + hdr_len;

        let (obj_type, content, next) = match ptype.as_object_type() {
            Some(ty) => {
                let (content, clen) = compress::inflate_exact(&data[body..], size)?;
                (ty, content, body + clen)
            }
            None => match ptype {
                PackObjectType::OfsDelta => {
                    let (rel, n) = read_offset_varint(data, body)?;
                    let base_offset = offset.checked_sub(rel).ok_or_else(|| {
                        Error::Pack("pack: ofs-delta base before pack start".into())
                    })?;
                    let (delta, clen) = compress::inflate_exact(&data[body + n..], size)?;
                    let (base_ty, base) = by_offset
                        .get(&base_offset)
                        .ok_or_else(|| Error::Pack("pack: ofs-delta base not yet seen".into()))?;
                    let target = delta::apply_delta(base, &delta)?;
                    (*base_ty, target, body + n + clen)
                }
                PackObjectType::RefDelta => {
                    if body + id_len > data.len() {
                        return Err(Error::Pack("pack: truncated ref-delta base id".into()));
                    }
                    let base_id = ObjectId::from_bytes(algo, &data[body..body + id_len])?;
                    let (delta, clen) = compress::inflate_exact(&data[body + id_len..], size)?;
                    let (base_ty, base) = match by_id.get(&base_id) {
                        Some((t, b)) => (*t, b.clone()),
                        None => resolve_external(&base_id)?,
                    };
                    let target = delta::apply_delta(&base, &delta)?;
                    (base_ty, target, body + id_len + clen)
                }
                _ => unreachable!("base types handled above"),
            },
        };

        let id = hash_object(algo, obj_type, &content);
        by_offset.insert(offset, (obj_type, content.clone()));
        by_id.insert(id, (obj_type, content.clone()));
        results.push((id, obj_type, content));
        offset = next;
    }

    Ok(results)
}

/// Parses a packfile entry header (`type`, uncompressed `size`, header length)
/// at `offset` — the free-function form used by [`explode_pack`].
fn parse_entry_header_at(data: &[u8], offset: usize) -> Result<(PackObjectType, usize, usize)> {
    let mut p = offset;
    let first = *data
        .get(p)
        .ok_or_else(|| Error::Pack("pack: offset past end".into()))?;
    p += 1;
    let ptype = PackObjectType::from_tag((first >> 4) & 0x7)?;
    let mut size = (first & 0x0f) as usize;
    let mut shift = 4;
    let mut c = first;
    while c & 0x80 != 0 {
        c = *data
            .get(p)
            .ok_or_else(|| Error::Pack("pack: truncated entry header".into()))?;
        p += 1;
        size |= ((c & 0x7f) as usize)
            .checked_shl(shift)
            .ok_or_else(|| Error::Pack("pack: size varint overflow".into()))?;
        shift += 7;
    }
    Ok((ptype, size, p - offset))
}

/// Reads git's "offset encoding" varint (the `OFS_DELTA` relative base offset),
/// returning `(value, bytes_consumed)`.
fn read_offset_varint(data: &[u8], start: usize) -> Result<(usize, usize)> {
    let mut p = start;
    let mut c = *data
        .get(p)
        .ok_or_else(|| Error::Pack("pack: truncated ofs-delta offset".into()))?;
    p += 1;
    let mut value = (c & 0x7f) as usize;
    while c & 0x80 != 0 {
        c = *data
            .get(p)
            .ok_or_else(|| Error::Pack("pack: truncated ofs-delta offset".into()))?;
        p += 1;
        value = ((value + 1) << 7) | (c & 0x7f) as usize;
    }
    Ok((value, p - start))
}

/// Returns the offset just past the packfile frame that begins at `offset` (the
/// start of the next entry), without resolving any delta.
///
/// This delimits one object's on-wire bytes — the entry header, then the zlib
/// stream (for a delta, the base reference precedes it) — so a streaming reader
/// can walk a pack whose total length it does not know in advance (the SSH
/// `receive-pack` path, where the pack is followed by no terminator). Returns an
/// error if `data` ends before the frame is complete — the caller reads more
/// bytes and retries the same offset — or if the entry is malformed.
pub fn pack_frame_end(data: &[u8], offset: usize, algo: HashAlgo) -> Result<usize> {
    let (ptype, size, hdr_len) = parse_entry_header_at(data, offset)?;
    let body = offset + hdr_len;
    let consumed = match ptype {
        PackObjectType::OfsDelta => {
            let (_rel, n) = read_offset_varint(data, body)?;
            let (_delta, clen) = compress::inflate_exact(&data[body + n..], size)?;
            hdr_len + n + clen
        }
        PackObjectType::RefDelta => {
            let id_len = algo.raw_len();
            if body + id_len > data.len() {
                return Err(Error::Pack("pack: truncated ref-delta base id".into()));
            }
            let (_delta, clen) = compress::inflate_exact(&data[body + id_len..], size)?;
            hdr_len + id_len + clen
        }
        _ => {
            let (_content, clen) = compress::inflate_exact(&data[body..], size)?;
            hdr_len + clen
        }
    };
    Ok(offset + consumed)
}

/// A parsed v2 pack index (`*.idx`): the id→offset map for a [`Pack`].
#[derive(Debug, Clone)]
pub struct PackIndex {
    algo: HashAlgo,
    /// Sorted object ids (raw, `count * id_len` bytes).
    oids: Vec<u8>,
    /// 4-byte big-endian offsets, one per object (high bit ⇒ large-offset idx).
    offsets: Vec<u8>,
    /// 8-byte big-endian large offsets, for objects past 2 GiB.
    large_offsets: Vec<u8>,
    count: usize,
}

impl PackIndex {
    /// Parses a v2 `.idx` file.
    pub fn parse(algo: HashAlgo, data: &[u8]) -> Result<Self> {
        let id_len = algo.raw_len();
        if data.len() < 8 + 256 * 4 {
            return Err(Error::Pack("idx: too short".into()));
        }
        if &data[..4] != IDX_MAGIC {
            return Err(Error::Pack(
                "idx: bad magic (v1 indexes unsupported)".into(),
            ));
        }
        let version = be32(&data[4..8]);
        if version != 2 {
            use alloc::format;
            return Err(Error::Pack(format!("idx: unsupported version {version}")));
        }
        // Fanout table: 256 cumulative counts; the last is the total.
        let fanout_start = 8;
        let count = be32(&data[fanout_start + 255 * 4..fanout_start + 256 * 4]) as usize;

        // These products and running offsets can overflow `usize` on 32-bit
        // targets when `count` is large, which would wrap to a small value that
        // spuriously passes the bounds check below and then panics on slicing.
        // Do every multiply/add with checked arithmetic and treat overflow as a
        // truncated/corrupt index.
        let overflow = || Error::Pack("idx: truncated".into());
        let oids_start = fanout_start + 256 * 4;
        let oids_len = count.checked_mul(id_len).ok_or_else(overflow)?;
        let crc_start = oids_start.checked_add(oids_len).ok_or_else(overflow)?;
        let crc_len = count.checked_mul(4).ok_or_else(overflow)?;
        let off_start = crc_start.checked_add(crc_len).ok_or_else(overflow)?;
        let off_len = count.checked_mul(4).ok_or_else(overflow)?;
        let large_start = off_start.checked_add(off_len).ok_or_else(overflow)?;
        if large_start > data.len() {
            return Err(Error::Pack("idx: truncated".into()));
        }
        // The large-offset table sits between the small offsets and the two
        // trailing hashes (pack hash + idx hash).
        let large_end = data.len().saturating_sub(2 * id_len);
        let large_offsets = data[large_start..large_end.max(large_start)].to_vec();

        Ok(PackIndex {
            algo,
            oids: data[oids_start..oids_start + oids_len].to_vec(),
            offsets: data[off_start..off_start + off_len].to_vec(),
            large_offsets,
            count,
        })
    }

    /// The number of objects indexed.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Looks up the pack offset of an object id, or `None` if not in this pack.
    pub fn offset_of(&self, id: &ObjectId) -> Option<usize> {
        let idx = self.position_of(id)?;
        let raw = be32(&self.offsets[idx * 4..idx * 4 + 4]);
        if raw & 0x8000_0000 == 0 {
            return Some(raw as usize);
        }
        // High bit set: index into the 8-byte large-offset table.
        let large_idx = (raw & 0x7fff_ffff) as usize;
        let off = large_idx * 8;
        if off + 8 > self.large_offsets.len() {
            return None;
        }
        let v = be64(&self.large_offsets[off..off + 8]);
        Some(v as usize)
    }

    /// Whether the index contains an object id.
    pub fn contains(&self, id: &ObjectId) -> bool {
        self.position_of(id).is_some()
    }

    /// The object id at a row (0..[`len`](PackIndex::len)), in sorted order.
    pub fn id_at(&self, row: usize) -> Option<ObjectId> {
        let id_len = self.algo.raw_len();
        let bytes = self.oids.get(row * id_len..row * id_len + id_len)?;
        ObjectId::from_bytes(self.algo, bytes).ok()
    }

    /// The pack offset of the object at a row, resolving the large-offset table.
    pub fn offset_at(&self, row: usize) -> Option<u64> {
        let raw = be32(self.offsets.get(row * 4..row * 4 + 4)?);
        if raw & 0x8000_0000 == 0 {
            return Some(raw as u64);
        }
        let off = (raw & 0x7fff_ffff) as usize * 8;
        Some(be64(self.large_offsets.get(off..off + 8)?))
    }

    /// Binary-searches the sorted id table for `id`, returning its row index.
    fn position_of(&self, id: &ObjectId) -> Option<usize> {
        if id.algo() != self.algo {
            return None;
        }
        let id_len = self.algo.raw_len();
        let needle = id.as_bytes();
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let row = &self.oids[mid * id_len..mid * id_len + id_len];
            match row.cmp(needle) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }
}

/// The outcome of [`verify_pack`].
#[derive(Debug, Clone, Default)]
pub struct PackVerification {
    /// Number of objects decoded from the pack.
    pub objects: usize,
    /// Integrity problems found (empty means the pack verifies).
    pub problems: alloc::vec::Vec<alloc::string::String>,
}

impl PackVerification {
    /// Whether the pack is intact (no problems).
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Verifies a packfile against its `.idx` (`git verify-pack`).
///
/// Every object in the pack is decoded (resolving all deltas) and re-hashed;
/// because the id is derived from the decoded content, any corruption changes an
/// object's id so it no longer matches the index. The check therefore confirms
/// that (a) all deltas resolve, (b) every decoded object's id is present in the
/// index, and (c) the object counts agree. `resolve_external` supplies bases for
/// a *thin* pack; pass a resolver that errors (e.g. `|_| Err(Error::NotFound…)`)
/// for a self-contained pack.
pub fn verify_pack(
    pack: &[u8],
    idx: &[u8],
    algo: HashAlgo,
    resolve_external: &ExternalResolver<'_>,
) -> Result<PackVerification> {
    let index = PackIndex::parse(algo, idx)?;
    let objects = explode_pack(pack, algo, resolve_external)?;

    let mut problems = alloc::vec::Vec::new();
    for (id, _, _) in &objects {
        if !index.contains(id) {
            problems.push(alloc::format!(
                "object {id} decoded from the pack is absent from the index (corrupt or wrong idx)"
            ));
        }
    }
    if objects.len() != index.len() {
        problems.push(alloc::format!(
            "pack contains {} object(s) but the index lists {}",
            objects.len(),
            index.len()
        ));
    }

    Ok(PackVerification {
        objects: objects.len(),
        problems,
    })
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_pack_signature() {
        assert!(Pack::new(alloc::vec![0u8; 32], HashAlgo::Sha1).is_err());
    }

    #[test]
    fn verify_pack_accepts_good_and_flags_corrupt() {
        use crate::pack::writer::PackWriter;

        let mut w = PackWriter::new(HashAlgo::Sha1);
        w.add(ObjectType::Blob, b"hello\n");
        w.add(ObjectType::Blob, b"another object\n");
        let out = w.finish().unwrap();
        let no_ext = |id: &ObjectId| {
            Err(Error::NotFound(crate::error::ObjectKindHint::Object(
                id.to_hex(),
            )))
        };

        // A freshly written pack + idx verifies cleanly.
        let v = verify_pack(&out.pack, &out.idx, HashAlgo::Sha1, &no_ext).unwrap();
        assert!(v.is_ok(), "unexpected problems: {:?}", v.problems);
        assert_eq!(v.objects, 2);

        // Flip a byte in an object's compressed body: the object either fails to
        // decode (Err) or decodes to different content whose id is not in the
        // index (a recorded problem). Either way it does not verify clean.
        let mut bad = out.pack.clone();
        let i = bad.len() - 25; // inside the second object's zlib stream
        bad[i] ^= 0xff;
        // A corrupt pack either fails to decode (Err) or decodes to content whose
        // id is not in the index (a recorded problem) — never a clean verify.
        if let Ok(v) = verify_pack(&bad, &out.idx, HashAlgo::Sha1, &no_ext) {
            assert!(!v.is_ok(), "corrupt pack unexpectedly verified");
        }
    }

    #[test]
    fn parses_pack_header() {
        let mut data = Vec::new();
        data.extend_from_slice(b"PACK");
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&7u32.to_be_bytes());
        data.resize(64, 0);
        let pack = Pack::new(data, HashAlgo::Sha1).unwrap();
        assert_eq!(pack.object_count(), 7);
    }

    #[test]
    fn offset_varint_roundtrip() {
        // Encode 200 in git's offset encoding and decode it back.
        // 200 = encode: byte sequence per the (value+1)<<7 rule.
        let encoded = [0x80u8, 0x48]; // git offset-encoding of value 200
        let (v, n) = read_offset_varint(&encoded, 0).unwrap();
        assert_eq!(n, 2);
        assert_eq!(v, 200);
    }

    /// Builds a packfile entry header (type tag in bits 4–6, uncompressed size
    /// as a base-128 varint) — the minimal encoder the fixtures below need.
    fn entry_header(tag: u8, mut size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut first = (tag << 4) | (size & 0x0f) as u8;
        size >>= 4;
        if size != 0 {
            first |= 0x80;
        }
        out.push(first);
        while size != 0 {
            let mut b = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                b |= 0x80;
            }
            out.push(b);
        }
        out
    }

    #[test]
    fn read_at_rejects_self_referential_ofs_delta() {
        // A single OFS_DELTA entry whose relative base offset is 0 points at
        // itself; without the `rel == 0` guard this recurses forever (A1).
        // Deflate a trivial delta body so the entry parses far enough to hit
        // the offset varint.
        let delta_body = compress::deflate(b"\x00\x00").unwrap(); // base=0, target=0
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        // OFS_DELTA (tag 6); uncompressed size = 2 (the delta body length).
        pack.extend_from_slice(&entry_header(6, 2));
        pack.push(0x00); // relative offset varint == 0 → self-reference
        pack.extend_from_slice(&delta_body);
        pack.resize(pack.len() + 20, 0); // trailing pack hash (unused here)

        let pack = Pack::new(pack, HashAlgo::Sha1).unwrap();
        let never =
            |_: &ObjectId| -> Result<(ObjectType, Vec<u8>)> { Err(Error::Pack("unused".into())) };
        let err = pack.read_at(12, &never).unwrap_err();
        assert!(matches!(err, Error::Pack(_)));
    }

    #[test]
    fn read_at_rejects_deep_ofs_delta_chain() {
        // A long linear chain of OFS_DELTA entries, each pointing one entry
        // back, must be rejected once it exceeds MAX_DELTA_CHAIN_DEPTH rather
        // than recursing that deep on the stack (A1). Build depth+2 entries:
        // a base blob at the front, then a chain of deltas.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());

        // Base object: an empty blob.
        let base_off = pack.len();
        pack.extend_from_slice(&entry_header(3, 0)); // blob, size 0
        pack.extend_from_slice(&compress::deflate(b"").unwrap());

        // Chain of identity deltas (base size 0, target size 0), each pointing
        // to the immediately preceding entry.
        let delta_body = compress::deflate(b"\x00\x00").unwrap();
        let mut prev = base_off;
        let mut last = base_off;
        for _ in 0..(MAX_DELTA_CHAIN_DEPTH + 5) {
            let here = pack.len();
            let rel = here - prev;
            pack.extend_from_slice(&entry_header(6, 2)); // OFS_DELTA, size 2
            // Encode `rel` in git's offset varint (small values fit in the loop below).
            let mut bytes = Vec::new();
            let mut v = rel;
            bytes.push((v & 0x7f) as u8);
            v >>= 7;
            while v != 0 {
                v -= 1;
                bytes.push(0x80 | (v & 0x7f) as u8);
                v >>= 7;
            }
            bytes.reverse();
            pack.extend_from_slice(&bytes);
            pack.extend_from_slice(&delta_body);
            prev = here;
            last = here;
        }
        pack.resize(pack.len() + 20, 0); // trailing pack hash

        let pack = Pack::new(pack, HashAlgo::Sha1).unwrap();
        let never =
            |_: &ObjectId| -> Result<(ObjectType, Vec<u8>)> { Err(Error::Pack("unused".into())) };
        // Reading the deepest entry follows the whole chain and must error out
        // (too deep) instead of overflowing the stack.
        let err = pack.read_at(last, &never).unwrap_err();
        assert!(matches!(err, Error::Pack(_)));
    }

    #[test]
    fn explode_pack_does_not_preallocate_untrusted_count() {
        // A 12-byte pack whose header claims u32::MAX objects must not attempt a
        // multi-gigabyte reservation (A3); with no object bytes following, the
        // loop simply errors on the first (missing) entry.
        let mut data = Vec::new();
        data.extend_from_slice(b"PACK");
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&u32::MAX.to_be_bytes());

        let never =
            |_: &ObjectId| -> Result<(ObjectType, Vec<u8>)> { Err(Error::Pack("unused".into())) };
        let err = explode_pack(&data, HashAlgo::Sha1, &never).unwrap_err();
        assert!(matches!(err, Error::Pack(_)));
    }

    #[test]
    fn pack_index_parse_rejects_overflowing_count() {
        // A minimal idx header whose fanout total is a huge count would overflow
        // `count * id_len` on 32-bit targets; the checked arithmetic must reject
        // it as truncated rather than wrapping and later panicking (A4). On
        // 64-bit the product doesn't wrap, but the bounds check still rejects it
        // as truncated — either way `parse` returns an error, never panics.
        let mut data = Vec::new();
        data.extend_from_slice(IDX_MAGIC);
        data.extend_from_slice(&2u32.to_be_bytes()); // version
        // Fanout: 255 entries of 0, last entry = u32::MAX (the total count).
        for _ in 0..255 {
            data.extend_from_slice(&0u32.to_be_bytes());
        }
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        // No object tables follow.
        let err = PackIndex::parse(HashAlgo::Sha1, &data).unwrap_err();
        assert!(matches!(err, Error::Pack(_)));
    }

    #[test]
    fn writer_then_explode_roundtrip() {
        use crate::pack::PackWriter;

        // Build a pack with several undeltified objects of different types.
        let mut w = PackWriter::new(HashAlgo::Sha1);
        let blob = w.add(ObjectType::Blob, b"hello world\n");
        let empty_tree = w.add(ObjectType::Tree, b"");
        let commitish = w.add(ObjectType::Commit, b"tree x\n\nmsg\n");
        let out = w.finish().unwrap();

        // Explode it back; with no deltas the external resolver is never called.
        let never = |_: &ObjectId| -> Result<(ObjectType, Vec<u8>)> {
            Err(Error::Pack("no external bases expected".into()))
        };
        let objs = explode_pack(&out.pack, HashAlgo::Sha1, &never).unwrap();
        assert_eq!(objs.len(), 3);

        // Every written object comes back with the same id, type, and bytes.
        let find = |id: &ObjectId| objs.iter().find(|(oid, _, _)| oid == id).cloned();
        assert_eq!(find(&blob).unwrap().2, b"hello world\n");
        assert_eq!(find(&empty_tree).unwrap().1, ObjectType::Tree);
        assert_eq!(find(&empty_tree).unwrap().2, b"");
        assert_eq!(find(&commitish).unwrap().1, ObjectType::Commit);
    }
}
