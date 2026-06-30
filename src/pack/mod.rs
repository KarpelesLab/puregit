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
//! - [`delta`] — the delta instruction codec.
//!
//! Writing packs (and computing the index from a pack) is on the roadmap; this
//! is the read side that clone/fetch needs to ingest a received pack.

pub mod delta;

use alloc::vec::Vec;

use crate::compress;
use crate::error::{Error, Result};
use crate::object::ObjectType;
use crate::oid::{HashAlgo, ObjectId};

const PACK_SIGNATURE: &[u8; 4] = b"PACK";
const IDX_MAGIC: &[u8; 4] = b"\xfftOc";

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
        let (ptype, size, hdr_len) = self.parse_entry_header(offset)?;
        let body_start = offset + hdr_len;

        if let Some(ty) = ptype.as_object_type() {
            let content = compress::inflate_capped(&self.data[body_start..], size)?;
            return Ok((ty, content));
        }

        match ptype {
            PackObjectType::OfsDelta => {
                let (rel, n) = read_offset_varint(&self.data, body_start)?;
                let base_offset = offset
                    .checked_sub(rel)
                    .ok_or_else(|| Error::Pack("pack: ofs-delta base before pack start".into()))?;
                let delta = compress::inflate_capped(&self.data[body_start + n..], size)?;
                let (base_ty, base) = self.read_at(base_offset, resolve_external)?;
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
        let data = &self.data;
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

        let oids_start = fanout_start + 256 * 4;
        let oids_len = count * id_len;
        let crc_start = oids_start + oids_len;
        let crc_len = count * 4;
        let off_start = crc_start + crc_len;
        let off_len = count * 4;
        let large_start = off_start + off_len;
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
}
