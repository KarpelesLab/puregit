//! The multi-pack-index (`objects/pack/multi-pack-index`).
//!
//! A MIDX indexes the objects of *several* packfiles in one lookup structure, so
//! a repository with many packs resolves an id to `(pack, offset)` with a single
//! binary search instead of consulting every `.idx`. This module writes and
//! reads git's v1 format, so a MIDX puregit writes passes real git's
//! `git multi-pack-index verify`.
//!
//! Layout: a 12-byte header, a chunk lookup table, then the `PNAM` (sorted pack
//! names), `OIDF` (256-entry fanout), `OIDL` (sorted ids), `OOFF` (per-object
//! pack id + offset) and optional `LOFF` (64-bit offsets) chunks, closed by a
//! hash-checksum trailer.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::{HashAlgo, ObjectId};

use crate::pack::PackIndex;

const SIGNATURE: &[u8; 4] = b"MIDX";
const CHUNK_PNAM: u32 = 0x504e_414d; // "PNAM"
const CHUNK_OIDF: u32 = 0x4f49_4446; // "OIDF"
const CHUNK_OIDL: u32 = 0x4f49_444c; // "OIDL"
const CHUNK_OOFF: u32 = 0x4f4f_4646; // "OOFF"
const CHUNK_LOFF: u32 = 0x4c4f_4646; // "LOFF"

/// Serializes a multi-pack-index over `packs`, each a `(idx_file_name, index)`
/// pair (the name is the on-disk `pack-<hash>.idx`). Objects present in more than
/// one pack are recorded once (from the first pack, in sorted-name order).
pub fn write_multi_pack_index(algo: HashAlgo, packs: &[(String, &PackIndex)]) -> Result<Vec<u8>> {
    let hlen = algo.raw_len();

    // Pack names are stored sorted; a pack's index in that order is its pack id.
    let mut order: Vec<usize> = (0..packs.len()).collect();
    order.sort_by(|&a, &b| packs[a].0.cmp(&packs[b].0));

    // Collect (id, pack_id, offset), keeping the first occurrence of each id.
    let mut entries: Vec<(ObjectId, u32, u64)> = Vec::new();
    let mut seen: alloc::collections::BTreeSet<ObjectId> = alloc::collections::BTreeSet::new();
    for (pack_id, &pi) in order.iter().enumerate() {
        let index = packs[pi].1;
        for row in 0..index.len() {
            let id = index
                .id_at(row)
                .ok_or_else(|| Error::Pack("midx: bad idx id".into()))?;
            let off = index
                .offset_at(row)
                .ok_or_else(|| Error::Pack("midx: bad idx offset".into()))?;
            if seen.insert(id) {
                entries.push((id, pack_id as u32, off));
            }
        }
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let n = entries.len();

    // --- chunks ---
    // PNAM: sorted, NUL-terminated names, padded to a 4-byte boundary.
    let mut pnam = Vec::new();
    for &pi in &order {
        pnam.extend_from_slice(packs[pi].0.as_bytes());
        pnam.push(0);
    }
    while pnam.len() % 4 != 0 {
        pnam.push(0);
    }

    // OIDF fanout.
    let mut oidf = Vec::with_capacity(256 * 4);
    let mut acc = 0u32;
    for b in 0..=255u8 {
        acc += entries.iter().filter(|e| e.0.as_bytes()[0] == b).count() as u32;
        oidf.extend_from_slice(&acc.to_be_bytes());
    }

    // OIDL sorted ids.
    let mut oidl = Vec::with_capacity(n * hlen);
    for e in &entries {
        oidl.extend_from_slice(&e.0.as_bytes()[..hlen]);
    }

    // OOFF: pack id + offset; offsets that do not fit 31 bits go to LOFF.
    let mut ooff = Vec::with_capacity(n * 8);
    let mut loff: Vec<u64> = Vec::new();
    for e in &entries {
        ooff.extend_from_slice(&e.1.to_be_bytes());
        if e.2 < 0x8000_0000 {
            ooff.extend_from_slice(&(e.2 as u32).to_be_bytes());
        } else {
            let large_idx = loff.len() as u32;
            ooff.extend_from_slice(&(0x8000_0000 | large_idx).to_be_bytes());
            loff.push(e.2);
        }
    }
    let mut loff_bytes = Vec::with_capacity(loff.len() * 8);
    for v in &loff {
        loff_bytes.extend_from_slice(&v.to_be_bytes());
    }

    // --- assemble ---
    let mut chunks: Vec<(u32, &[u8])> = alloc::vec![
        (CHUNK_PNAM, pnam.as_slice()),
        (CHUNK_OIDF, oidf.as_slice()),
        (CHUNK_OIDL, oidl.as_slice()),
        (CHUNK_OOFF, ooff.as_slice()),
    ];
    if !loff_bytes.is_empty() {
        chunks.push((CHUNK_LOFF, loff_bytes.as_slice()));
    }
    let num_chunks = chunks.len() as u8;

    let header_len = 12;
    let table_len = (num_chunks as usize + 1) * 12;
    let mut offset = (header_len + table_len) as u64;
    let mut table = Vec::with_capacity(table_len);
    for (id, data) in &chunks {
        table.extend_from_slice(&id.to_be_bytes());
        table.extend_from_slice(&offset.to_be_bytes());
        offset += data.len() as u64;
    }
    // Terminating chunk-table entry: id 0, offset = end of last chunk.
    table.extend_from_slice(&0u32.to_be_bytes());
    table.extend_from_slice(&offset.to_be_bytes());

    let mut out = Vec::with_capacity(offset as usize + hlen);
    out.extend_from_slice(SIGNATURE);
    out.push(1); // version
    out.push(if algo == HashAlgo::Sha256 { 2 } else { 1 });
    out.push(num_chunks);
    out.push(0); // base MIDX count
    out.extend_from_slice(&(packs.len() as u32).to_be_bytes());
    out.extend_from_slice(&table);
    for (_, data) in &chunks {
        out.extend_from_slice(data);
    }

    let checksum = crate::hash::hash_bytes(algo, &out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// A parsed multi-pack-index, offering id → `(pack, offset)` lookup.
pub struct MultiPackIndex {
    algo: HashAlgo,
    pack_names: Vec<String>,
    oids: Vec<u8>,
    ooff: Vec<u8>,
    loff: Vec<u8>,
    count: usize,
}

impl MultiPackIndex {
    /// Parses a multi-pack-index file, validating its trailer checksum.
    pub fn parse(algo: HashAlgo, data: &[u8]) -> Result<Self> {
        let hlen = algo.raw_len();
        if data.len() < 12 + hlen || &data[..4] != SIGNATURE {
            return Err(Error::Pack("midx: bad header".into()));
        }
        if data[4] != 1 {
            return Err(Error::Unsupported("midx: unsupported version".into()));
        }
        let body = &data[..data.len() - hlen];
        if crate::hash::hash_bytes(algo, body).as_slice() != &data[data.len() - hlen..] {
            return Err(Error::Pack("midx: checksum mismatch".into()));
        }
        let num_chunks = data[6] as usize;
        let num_packs = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;

        // Chunk table.
        let table = 12;
        let mut entries: Vec<(u32, u64)> = Vec::with_capacity(num_chunks + 1);
        for i in 0..=num_chunks {
            let base = table + i * 12;
            if base + 12 > body.len() {
                return Err(Error::Pack("midx: truncated chunk table".into()));
            }
            let id =
                u32::from_be_bytes([data[base], data[base + 1], data[base + 2], data[base + 3]]);
            let off = u64::from_be_bytes(data[base + 4..base + 12].try_into().expect("8 bytes"));
            entries.push((id, off));
        }
        let chunk = |want: u32| -> Option<(usize, usize)> {
            for w in entries.windows(2) {
                if w[0].0 == want {
                    let (s, e) = (w[0].1 as usize, w[1].1 as usize);
                    if s <= e && e <= body.len() {
                        return Some((s, e));
                    }
                }
            }
            None
        };

        let (ps, pe) = chunk(CHUNK_PNAM).ok_or_else(|| Error::Pack("midx: no PNAM".into()))?;
        let (ls, le) = chunk(CHUNK_OIDL).ok_or_else(|| Error::Pack("midx: no OIDL".into()))?;
        let (os, oe) = chunk(CHUNK_OOFF).ok_or_else(|| Error::Pack("midx: no OOFF".into()))?;
        let (lfs, lfe) = chunk(CHUNK_LOFF).unwrap_or((0, 0));

        // Pack names: NUL-separated.
        let mut pack_names = Vec::with_capacity(num_packs);
        for name in data[ps..pe].split(|&b| b == 0) {
            if name.is_empty() {
                continue;
            }
            pack_names.push(String::from_utf8_lossy(name).into_owned());
        }

        let oids = data[ls..le].to_vec();
        let ooff = data[os..oe].to_vec();
        let loff = data[lfs..lfe].to_vec();
        let count = oids.len() / hlen;
        if count * 8 != ooff.len() {
            return Err(Error::Pack("midx: OIDL/OOFF size mismatch".into()));
        }
        Ok(MultiPackIndex {
            algo,
            pack_names,
            oids,
            ooff,
            loff,
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

    /// The sorted pack names the index covers.
    pub fn pack_names(&self) -> &[String] {
        &self.pack_names
    }

    /// Resolves an object id to `(pack_name, offset)`, or `None` if absent.
    pub fn find(&self, id: &ObjectId) -> Option<(&str, u64)> {
        if id.algo() != self.algo {
            return None;
        }
        let hlen = self.algo.raw_len();
        let needle = &id.as_bytes()[..hlen];
        let (mut lo, mut hi) = (0usize, self.count);
        let mut row = None;
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.oids[mid * hlen..mid * hlen + hlen].cmp(needle) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => {
                    row = Some(mid);
                    break;
                }
            }
        }
        let row = row?;
        let rec = &self.ooff[row * 8..row * 8 + 8];
        let pack_id = u32::from_be_bytes([rec[0], rec[1], rec[2], rec[3]]) as usize;
        let raw = u32::from_be_bytes([rec[4], rec[5], rec[6], rec[7]]);
        let offset = if raw & 0x8000_0000 == 0 {
            raw as u64
        } else {
            let o = (raw & 0x7fff_ffff) as usize * 8;
            u64::from_be_bytes(self.loff.get(o..o + 8)?.try_into().ok()?)
        };
        Some((self.pack_names.get(pack_id)?.as_str(), offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;
    use crate::pack::PackWriter;

    #[test]
    fn write_parse_finds_objects_across_packs() {
        // Two packs, each with distinct blobs.
        let mut w1 = PackWriter::new(HashAlgo::Sha1);
        let a = w1.add(ObjectType::Blob, b"alpha\n");
        let out1 = w1.finish().unwrap();
        let idx1 = PackIndex::parse(HashAlgo::Sha1, &out1.idx).unwrap();

        let mut w2 = PackWriter::new(HashAlgo::Sha1);
        let b = w2.add(ObjectType::Blob, b"beta object\n");
        let out2 = w2.finish().unwrap();
        let idx2 = PackIndex::parse(HashAlgo::Sha1, &out2.idx).unwrap();

        let name1 = alloc::format!("pack-{}.idx", out1.hash.to_hex());
        let name2 = alloc::format!("pack-{}.idx", out2.hash.to_hex());
        let midx = write_multi_pack_index(
            HashAlgo::Sha1,
            &[(name1.clone(), &idx1), (name2.clone(), &idx2)],
        )
        .unwrap();

        let m = MultiPackIndex::parse(HashAlgo::Sha1, &midx).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m.pack_names().len(), 2);

        // Each object resolves to its pack + the offset the pack's own idx gives.
        let (pn_a, off_a) = m.find(&a).unwrap();
        assert_eq!(pn_a, name1);
        assert_eq!(off_a as usize, idx1.offset_of(&a).unwrap());
        let (pn_b, off_b) = m.find(&b).unwrap();
        assert_eq!(pn_b, name2);
        assert_eq!(off_b as usize, idx2.offset_of(&b).unwrap());

        // A tampered trailer is rejected.
        let mut bad = midx.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        assert!(MultiPackIndex::parse(HashAlgo::Sha1, &bad).is_err());
    }
}
