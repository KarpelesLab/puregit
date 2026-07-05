//! The commit-graph file (`objects/info/commit-graph`).
//!
//! A commit-graph is a cache of commit metadata — each commit's root tree, its
//! parents (by position, not id), its committer date, and a **generation
//! number** — laid out for O(1) lookup so history queries (`log`, `merge-base`,
//! ancestry) avoid inflating every commit object. This module writes and reads
//! git's v1 format, so a graph puregit writes is verifiable by real git
//! (`git commit-graph verify`) and vice versa.
//!
//! Layout: an 8-byte header, a chunk lookup table, then the `OIDF` (256-entry
//! fanout), `OIDL` (sorted ids), and `CDAT` (per-commit data) chunks, closed by
//! a hash-checksum trailer. Octopus merges (more than two parents, which need
//! the `EDGE` chunk) are not yet emitted — [`write_commit_graph`] errors on one.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::object::{Commit, ObjectType};
use crate::odb::ObjectDatabase;
use crate::oid::{HashAlgo, ObjectId};

const SIGNATURE: &[u8; 4] = b"CGPH";
const CHUNK_OIDF: u32 = 0x4f49_4446; // "OIDF"
const CHUNK_OIDL: u32 = 0x4f49_444c; // "OIDL"
const CHUNK_CDAT: u32 = 0x4344_4154; // "CDAT"

/// A parent slot with no parent (`GRAPH_PARENT_NONE`).
const PARENT_NONE: u32 = 0x7000_0000;

/// Serializes a commit-graph for the given `commits` (which must be a
/// parent-closed set — every parent of an included commit must also be
/// included). Returns the file bytes, ready to write to
/// `objects/info/commit-graph`.
pub fn write_commit_graph<D: ObjectDatabase>(odb: &D, commits: &[ObjectId]) -> Result<Vec<u8>> {
    let algo = odb.algo();
    let hlen = algo.raw_len();

    // Sorted, de-duplicated ids define each commit's position.
    let mut ids: Vec<ObjectId> = commits.to_vec();
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ids.dedup();
    let pos_of: BTreeMap<&[u8], u32> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_bytes(), i as u32))
        .collect();

    // Read every commit once.
    let mut parsed: Vec<Commit> = Vec::with_capacity(ids.len());
    for id in &ids {
        let (ty, payload) = odb.read(id)?;
        if ty != ObjectType::Commit {
            return Err(Error::Pack("commit-graph: non-commit id supplied".into()));
        }
        parsed.push(Commit::parse(algo, &payload)?);
    }

    // Generation numbers: gen = 1 + max(parent gens), 1 for a root. Computed by
    // repeated relaxation over positions (the set is a DAG, so this converges).
    let n = ids.len();
    let mut gens = alloc::vec![0u32; n];
    let mut changed = true;
    let mut guard = 0usize;
    while changed {
        changed = false;
        guard += 1;
        if guard > n + 1 {
            return Err(Error::Pack("commit-graph: parent cycle".into()));
        }
        for (i, c) in parsed.iter().enumerate() {
            let mut g = 1u32;
            for p in &c.parents {
                let pp = *pos_of
                    .get(p.as_bytes())
                    .ok_or_else(|| Error::Pack("commit-graph: parent not in the set".into()))?;
                g = g.max(gens[pp as usize] + 1);
            }
            if g != gens[i] {
                gens[i] = g;
                changed = true;
            }
        }
    }

    // --- chunks ---
    // OIDF: cumulative count of ids whose first byte is <= b.
    let mut oidf = Vec::with_capacity(256 * 4);
    let mut acc = 0u32;
    for b in 0..=255u8 {
        acc += ids.iter().filter(|id| id.as_bytes()[0] == b).count() as u32;
        oidf.extend_from_slice(&acc.to_be_bytes());
    }

    // OIDL: the sorted ids.
    let mut oidl = Vec::with_capacity(n * hlen);
    for id in &ids {
        oidl.extend_from_slice(&id.as_bytes()[..hlen]);
    }

    // CDAT: per-commit record.
    let mut cdat = Vec::with_capacity(n * (hlen + 16));
    for (i, c) in parsed.iter().enumerate() {
        cdat.extend_from_slice(&c.tree.as_bytes()[..hlen]);
        let parent_pos = |k: usize| -> Result<u32> {
            match c.parents.get(k) {
                None => Ok(PARENT_NONE),
                Some(p) => Ok(*pos_of
                    .get(p.as_bytes())
                    .ok_or_else(|| Error::Pack("commit-graph: parent not in the set".into()))?),
            }
        };
        if c.parents.len() > 2 {
            return Err(Error::Unsupported(
                "commit-graph: octopus merges (EDGE chunk) not yet supported".into(),
            ));
        }
        cdat.extend_from_slice(&parent_pos(0)?.to_be_bytes());
        cdat.extend_from_slice(&parent_pos(1)?.to_be_bytes());
        // 8 bytes: top 2 bits of the 34-bit date + 30-bit generation, then the
        // low 32 bits of the date.
        let date = c.committer.time.max(0) as u64;
        let hi2 = ((date >> 32) & 0x3) as u32;
        let word0 = (hi2 << 30) | (gens[i] & 0x3fff_ffff);
        cdat.extend_from_slice(&word0.to_be_bytes());
        cdat.extend_from_slice(&((date & 0xffff_ffff) as u32).to_be_bytes());
    }

    // --- assemble: header + chunk table + chunks + trailer ---
    let num_chunks = 3u8;
    let header_len = 8;
    let table_len = (num_chunks as usize + 1) * 12;
    let mut offset = (header_len + table_len) as u64;
    let oidf_off = offset;
    offset += oidf.len() as u64;
    let oidl_off = offset;
    offset += oidl.len() as u64;
    let cdat_off = offset;
    offset += cdat.len() as u64;
    let end_off = offset;

    let mut out = Vec::with_capacity(end_off as usize + hlen);
    out.extend_from_slice(SIGNATURE);
    out.push(1); // version
    out.push(if algo == HashAlgo::Sha256 { 2 } else { 1 });
    out.push(num_chunks);
    out.push(0); // base graphs
    for (id, off) in [
        (CHUNK_OIDF, oidf_off),
        (CHUNK_OIDL, oidl_off),
        (CHUNK_CDAT, cdat_off),
        (0, end_off),
    ] {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&off.to_be_bytes());
    }
    out.extend_from_slice(&oidf);
    out.extend_from_slice(&oidl);
    out.extend_from_slice(&cdat);

    let checksum = crate::hash::hash_bytes(algo, &out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// A parsed commit-graph, offering position/parent/generation lookups.
pub struct CommitGraph {
    algo: HashAlgo,
    /// Sorted object ids (raw), `count * hlen` bytes.
    oids: Vec<u8>,
    /// The `CDAT` chunk bytes.
    cdat: Vec<u8>,
    count: usize,
}

impl CommitGraph {
    /// Parses a commit-graph file, validating its trailer checksum.
    pub fn parse(algo: HashAlgo, data: &[u8]) -> Result<Self> {
        let hlen = algo.raw_len();
        if data.len() < 8 + hlen || &data[..4] != SIGNATURE {
            return Err(Error::Pack("commit-graph: bad header".into()));
        }
        if data[4] != 1 {
            return Err(Error::Unsupported(
                "commit-graph: unsupported version".into(),
            ));
        }
        let body = &data[..data.len() - hlen];
        if crate::hash::hash_bytes(algo, body) != data[data.len() - hlen..] {
            return Err(Error::Pack("commit-graph: checksum mismatch".into()));
        }
        let num_chunks = data[6] as usize;

        // Chunk table: locate OIDL and CDAT and their extents from the offsets.
        let table = 8;
        let mut chunks: BTreeMap<u32, (usize, usize)> = BTreeMap::new();
        let mut entries: Vec<(u32, u64)> = Vec::with_capacity(num_chunks + 1);
        for i in 0..=num_chunks {
            let base = table + i * 12;
            if base + 12 > body.len() {
                return Err(Error::Pack("commit-graph: truncated chunk table".into()));
            }
            let id =
                u32::from_be_bytes([data[base], data[base + 1], data[base + 2], data[base + 3]]);
            let off = u64::from_be_bytes(data[base + 4..base + 12].try_into().expect("8 bytes"));
            entries.push((id, off));
        }
        for w in entries.windows(2) {
            let (id, start) = w[0];
            let (_, end) = w[1];
            if (start as usize) > body.len() || (end as usize) > body.len() || end < start {
                return Err(Error::Pack("commit-graph: bad chunk offsets".into()));
            }
            chunks.insert(id, (start as usize, end as usize));
        }

        let (ol_start, ol_end) = *chunks
            .get(&CHUNK_OIDL)
            .ok_or_else(|| Error::Pack("commit-graph: no OIDL chunk".into()))?;
        let (cd_start, cd_end) = *chunks
            .get(&CHUNK_CDAT)
            .ok_or_else(|| Error::Pack("commit-graph: no CDAT chunk".into()))?;

        let oids = data[ol_start..ol_end].to_vec();
        let cdat = data[cd_start..cd_end].to_vec();
        let count = oids.len() / hlen;
        if count * (hlen + 16) != cdat.len() {
            return Err(Error::Pack("commit-graph: OIDL/CDAT size mismatch".into()));
        }
        Ok(CommitGraph {
            algo,
            oids,
            cdat,
            count,
        })
    }

    /// The number of commits in the graph.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The position (row index) of a commit id, or `None` if absent.
    pub fn position_of(&self, id: &ObjectId) -> Option<usize> {
        if id.algo() != self.algo {
            return None;
        }
        let hlen = self.algo.raw_len();
        let needle = &id.as_bytes()[..hlen];
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.oids[mid * hlen..mid * hlen + hlen].cmp(needle) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    /// The id at a row position.
    pub fn id_at(&self, pos: usize) -> Option<ObjectId> {
        let hlen = self.algo.raw_len();
        let row = self.oids.get(pos * hlen..pos * hlen + hlen)?;
        ObjectId::from_bytes(self.algo, row).ok()
    }

    fn record(&self, pos: usize) -> &[u8] {
        let hlen = self.algo.raw_len();
        let sz = hlen + 16;
        &self.cdat[pos * sz..pos * sz + sz]
    }

    /// The root tree id of the commit at `pos`.
    pub fn tree_at(&self, pos: usize) -> Option<ObjectId> {
        let hlen = self.algo.raw_len();
        ObjectId::from_bytes(self.algo, &self.record(pos)[..hlen]).ok()
    }

    /// The parent ids of the commit at `pos` (up to two; octopus merges are not
    /// stored by this writer).
    pub fn parents_at(&self, pos: usize) -> Vec<ObjectId> {
        let hlen = self.algo.raw_len();
        let rec = self.record(pos);
        let mut out = Vec::new();
        for k in 0..2 {
            let off = hlen + k * 4;
            let v = u32::from_be_bytes([rec[off], rec[off + 1], rec[off + 2], rec[off + 3]]);
            if v == PARENT_NONE || v >= 0x8000_0000 {
                continue;
            }
            if let Some(id) = self.id_at(v as usize) {
                out.push(id);
            }
        }
        out
    }

    /// The generation number of the commit at `pos`.
    pub fn generation_at(&self, pos: usize) -> u32 {
        let hlen = self.algo.raw_len();
        let rec = self.record(pos);
        let off = hlen + 8;
        let word0 = u32::from_be_bytes([rec[off], rec[off + 1], rec[off + 2], rec[off + 3]]);
        word0 & 0x3fff_ffff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Signature;
    use crate::odb::MemoryOdb;

    fn sig(t: i64) -> Signature {
        Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: t,
            tz: b"+0000".to_vec(),
        }
    }

    #[test]
    fn write_parse_round_trip() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let tree = odb.write(ObjectType::Tree, b"").unwrap();
        let mk = |parents: Vec<ObjectId>, t: i64| {
            let c = Commit {
                tree,
                parents,
                author: sig(t),
                committer: sig(t),
                extra_headers: Vec::new(),
                message: b"m\n".to_vec(),
            };
            odb.write(ObjectType::Commit, &c.serialize()).unwrap()
        };
        let c1 = mk(alloc::vec![], 1000);
        let c2 = mk(alloc::vec![c1], 2000);
        let c3 = mk(alloc::vec![c2, c1], 3000); // a 2-parent merge

        let bytes = write_commit_graph(&odb, &[c1, c2, c3]).unwrap();
        let g = CommitGraph::parse(HashAlgo::Sha1, &bytes).unwrap();
        assert_eq!(g.len(), 3);

        // Generations: c1 root=1, c2=2, c3=3.
        let p3 = g.position_of(&c3).unwrap();
        assert_eq!(g.generation_at(p3), 3);
        assert_eq!(g.generation_at(g.position_of(&c1).unwrap()), 1);
        assert_eq!(g.generation_at(g.position_of(&c2).unwrap()), 2);

        // c3's parents round-trip (order-independent).
        let mut ps = g.parents_at(p3);
        ps.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut want = alloc::vec![c1, c2];
        want.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(ps, want);
        assert_eq!(g.tree_at(p3), Some(tree));

        // A tampered trailer is rejected.
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        assert!(CommitGraph::parse(HashAlgo::Sha1, &bad).is_err());
    }
}
