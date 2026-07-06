//! Reachability `.bitmap` writer.
//!
//! A pack bitmap stores, for a set of selected commits, an [`Ewah`] bitmap of
//! every object reachable from that commit. Four more bitmaps record each
//! object's type. With these, a server answers "what does this commit reach?" by
//! reading a bitmap instead of walking the graph, which is what makes bitmapped
//! fetch/`repack` fast.
//!
//! Two object position spaces are in play, and getting them right is the whole
//! trick:
//! - The **bitmap bits** (type and reachability) index objects by their *pack
//!   order* (rank by pack offset).
//! - Each commit entry's 4-byte field names its commit by its *`.idx` row*
//!   (oid-sorted position) instead.
//!
//! The pack **reverse index** (`.rev`, [`write_reverse_index`]) connects the two
//! and must accompany the bitmap.
//!
//! The file layout git reads (all integers big-endian):
//!
//! ```text
//! "BITM"  uint16 version(=1)  uint16 flags  uint32 entry_count  pack_checksum
//! EWAH commits · EWAH trees · EWAH blobs · EWAH tags          (pack-order bits)
//! entry_count × { uint32 idx_row  uint8 xor_offset  uint8 flags  EWAH }
//! trailing checksum of everything above
//! ```
//!
//! This writer emits a self-contained (no XOR-chained) bitmap over a single
//! pack, which git accepts and verifies with `git rev-list --test-bitmap`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::object::ObjectType;
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;

use super::PackIndex;
use super::ewah::Ewah;

/// The bitmap format version this writer emits.
const BITMAP_VERSION: u16 = 1;
/// `BITMAP_OPT_FULL_DAG`: the bitmaps span the pack's whole history.
const FLAG_FULL_DAG: u16 = 1;

/// Writes a reachability `.bitmap` for `commits` over the pack described by
/// `idx` (whose objects `odb` can read) and identified by `pack_hash` (the
/// pack's trailing checksum).
///
/// Every object reachable from a selected commit must live in this pack — the
/// normal case after an all-into-one `repack`. Each commit's bitmap is emitted
/// standalone (no XOR delta against another), which is larger but simplest and
/// still valid.
pub fn write_bitmap<D: ObjectDatabase>(
    odb: &D,
    idx: &PackIndex,
    pack_hash: &ObjectId,
    commits: &[ObjectId],
) -> Result<Vec<u8>> {
    let algo = odb.algo();
    let count = idx.len();

    // Bitmap positions are the objects' order *in the pack* (by pack offset),
    // not the `.idx`'s oid-sorted order — git writes commits, then trees, then
    // blobs, and the bitmaps index that layout. Build the offset order once.
    let mut by_offset: Vec<(u64, ObjectId)> = (0..count)
        .filter_map(|row| Some((idx.offset_at(row)?, idx.id_at(row)?)))
        .collect();
    if by_offset.len() != count {
        return Err(Error::Pack("bitmap: idx row out of range".into()));
    }
    by_offset.sort_unstable_by_key(|(off, _)| *off);

    // Object id → its pack-order position (used by the type and reachability
    // bitmaps).
    let mut position: BTreeMap<ObjectId, usize> = BTreeMap::new();
    for (pos, (_, id)) in by_offset.iter().enumerate() {
        position.insert(*id, pos);
    }
    // Object id → its `.idx` (oid-sorted) row, which is how a commit entry names
    // its commit — a different space from the bitmap positions above.
    let mut idx_row: BTreeMap<ObjectId, usize> = BTreeMap::new();
    for row in 0..count {
        if let Some(id) = idx.id_at(row) {
            idx_row.insert(id, row);
        }
    }

    // Type bitmaps: one set of positions per object type, in pack order.
    let (mut commits_b, mut trees_b, mut blobs_b, mut tags_b) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (pos, (_, id)) in by_offset.iter().enumerate() {
        let (ty, _) = odb.read(id)?;
        match ty {
            ObjectType::Commit => commits_b.push(pos),
            ObjectType::Tree => trees_b.push(pos),
            ObjectType::Blob => blobs_b.push(pos),
            ObjectType::Tag => tags_b.push(pos),
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"BITM");
    out.extend_from_slice(&BITMAP_VERSION.to_be_bytes());
    out.extend_from_slice(&FLAG_FULL_DAG.to_be_bytes());
    out.extend_from_slice(&(commits.len() as u32).to_be_bytes());
    out.extend_from_slice(pack_hash.as_bytes());

    // The four type bitmaps, in git's fixed order.
    for set in [&commits_b, &trees_b, &blobs_b, &tags_b] {
        out.extend_from_slice(&type_bitmap(set).to_bytes());
    }

    // One entry per selected commit. The 4-byte position names the commit by its
    // `.idx` row; the entry's bitmap marks reachable objects by pack position.
    let mut entries: Vec<(usize, ObjectId)> = commits
        .iter()
        .filter_map(|c| idx_row.get(c).map(|&p| (p, *c)))
        .collect();
    entries.sort_unstable_by_key(|(p, _)| *p);

    for (row, commit) in entries {
        let reachable = crate::walk::reachable_objects(odb, &[commit])?;
        let mut positions: Vec<usize> = reachable
            .iter()
            .filter_map(|id| position.get(id).copied())
            .collect();
        positions.sort_unstable();

        out.extend_from_slice(&(row as u32).to_be_bytes());
        out.push(0); // xor offset: this bitmap stands alone
        out.push(0); // flags
        out.extend_from_slice(&type_bitmap(&positions).to_bytes());
    }

    // Trailing checksum over everything written so far.
    let checksum = crate::hash::hash_bytes(algo, &out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// Writes the pack **reverse index** (`.rev`) that a bitmap needs: the mapping
/// from an object's pack-order position (by offset) to its `.idx` position (by
/// oid). git reads this to turn a bitmap bit back into an object.
///
/// Layout: `"RIDX"`, version 1, hash id (1 = SHA-1, 2 = SHA-256), then one `u32`
/// per object (in pack order) giving its idx row, then the pack checksum and a
/// trailing checksum of the file.
pub fn write_reverse_index(idx: &PackIndex, pack_hash: &ObjectId) -> Result<Vec<u8>> {
    let algo = idx.algo();
    let count = idx.len();
    // (offset, idx-row) for every object, sorted into pack order.
    let mut by_offset: Vec<(u64, u32)> = (0..count)
        .filter_map(|row| Some((idx.offset_at(row)?, row as u32)))
        .collect();
    if by_offset.len() != count {
        return Err(Error::Pack("rev-index: idx row out of range".into()));
    }
    by_offset.sort_unstable_by_key(|(off, _)| *off);

    let hash_id: u32 = match algo {
        crate::oid::HashAlgo::Sha1 => 1,
        crate::oid::HashAlgo::Sha256 => 2,
    };
    let mut out = Vec::new();
    out.extend_from_slice(b"RIDX");
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&hash_id.to_be_bytes());
    for (_, idx_row) in &by_offset {
        out.extend_from_slice(&idx_row.to_be_bytes());
    }
    out.extend_from_slice(pack_hash.as_bytes());
    let checksum = crate::hash::hash_bytes(algo, &out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// Builds an [`Ewah`] over `set` sized like git's — `last_bit + 1` bits (or 0
/// when empty).
fn type_bitmap(set: &[usize]) -> Ewah {
    let bit_size = set.last().map_or(0, |&b| b + 1);
    Ewah::from_set_bits(set, bit_size)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::pack::PackWriter;

    #[test]
    fn writes_a_parseable_bitmap_header() {
        // Build a tiny repo, pack all its objects, and write a bitmap for its
        // one commit; then re-read the header and the commit's bitmap.
        let dir =
            std::env::temp_dir().join(alloc::format!("puregit-bitmap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let repo = crate::repository::Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let tip = repo
            .commit(
                b"c\n",
                crate::object::Signature {
                    name: b"T".to_vec(),
                    email: b"t@e".to_vec(),
                    time: 0,
                    tz: b"+0000".to_vec(),
                },
                crate::object::Signature {
                    name: b"T".to_vec(),
                    email: b"t@e".to_vec(),
                    time: 0,
                    tz: b"+0000".to_vec(),
                },
            )
            .unwrap();

        // Pack every reachable object.
        let objs = crate::walk::reachable_objects(repo.objects(), &[tip]).unwrap();
        let mut writer = PackWriter::new(repo.algo());
        for id in &objs {
            let (ty, payload) = crate::odb::ObjectDatabase::read(repo.objects(), id).unwrap();
            writer.add(ty, &payload);
        }
        let out = writer.finish().unwrap();
        let idx = PackIndex::parse(repo.algo(), &out.idx).unwrap();

        let bitmap = write_bitmap(repo.objects(), &idx, &out.hash, &[tip]).unwrap();

        // Header: magic, version, flags, entry count, pack checksum.
        assert_eq!(&bitmap[..4], b"BITM");
        assert_eq!(u16::from_be_bytes([bitmap[4], bitmap[5]]), 1);
        assert_eq!(
            u32::from_be_bytes([bitmap[8], bitmap[9], bitmap[10], bitmap[11]]),
            1
        );
        let id_len = repo.algo().raw_len();
        assert_eq!(&bitmap[12..12 + id_len], out.hash.as_bytes());

        // The four type bitmaps parse; the commits one has exactly one bit (the
        // single commit's position).
        let mut off = 12 + id_len;
        let (commits_ewah, n) = Ewah::from_bytes(&bitmap[off..]).unwrap();
        assert_eq!(commits_ewah.set_bits().len(), 1);
        off += n;
        for _ in 0..3 {
            let (_, n) = Ewah::from_bytes(&bitmap[off..]).unwrap();
            off += n;
        }

        // The single commit entry: position, xor, flags, then its reachability
        // bitmap covering every object in the pack.
        off += 4 + 1 + 1;
        let (reach, _) = Ewah::from_bytes(&bitmap[off..]).unwrap();
        assert_eq!(reach.set_bits().len(), objs.len());

        // The reverse index has the expected header and one u32 per object.
        let rev = write_reverse_index(&idx, &out.hash).unwrap();
        assert_eq!(&rev[..4], b"RIDX");
        assert_eq!(u32::from_be_bytes([rev[4], rev[5], rev[6], rev[7]]), 1);
        // "RIDX" + version + hash-id + n·u32 + pack hash + file hash.
        assert_eq!(rev.len(), 12 + idx.len() * 4 + 2 * id_len);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
