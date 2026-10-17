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
//! fanout), `OIDL` (sorted ids), `CDAT` (per-commit data) and — when an octopus
//! merge (more than two parents) is present — `EDGE` (the extra parents)
//! chunks, closed by a hash-checksum trailer. Other chunks git may add
//! (generation data `GDA2`/`GDO2`, Bloom filters) are ignored on read.

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
const CHUNK_EDGE: u32 = 0x4544_4745; // "EDGE"

/// A parent slot with no parent (`GRAPH_PARENT_NONE`).
const PARENT_NONE: u32 = 0x7000_0000;

/// In the second parent slot: "the rest are in `EDGE`, starting at the index
/// in the low bits". In an `EDGE` word: "this is the last parent".
const EDGE_LAST: u32 = 0x8000_0000;

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

    // CDAT: per-commit record. EDGE: the 2nd..nth parents of octopus merges.
    let mut cdat = Vec::with_capacity(n * (hlen + 16));
    let mut edge: Vec<u8> = Vec::new();
    for (i, c) in parsed.iter().enumerate() {
        cdat.extend_from_slice(&c.tree.as_bytes()[..hlen]);
        let mut positions = Vec::with_capacity(c.parents.len());
        for p in &c.parents {
            positions.push(
                *pos_of
                    .get(p.as_bytes())
                    .ok_or_else(|| Error::Pack("commit-graph: parent not in the set".into()))?,
            );
        }
        let first = positions.first().copied().unwrap_or(PARENT_NONE);
        let second = match positions.len() {
            0 | 1 => PARENT_NONE,
            2 => positions[1],
            _ => {
                // Octopus: the second slot points into EDGE, which lists the
                // remaining parents with the last one flagged.
                let start = (edge.len() / 4) as u32;
                let rest = &positions[1..];
                for (k, pos) in rest.iter().enumerate() {
                    let v = if k + 1 == rest.len() {
                        pos | EDGE_LAST
                    } else {
                        *pos
                    };
                    edge.extend_from_slice(&v.to_be_bytes());
                }
                EDGE_LAST | start
            }
        };
        cdat.extend_from_slice(&first.to_be_bytes());
        cdat.extend_from_slice(&second.to_be_bytes());
        // 8 bytes: the 30-bit generation (topological level) in the *high*
        // bits of the first word, with bits 33–34 of the 34-bit date in its
        // two low bits; then the low 32 bits of the date.
        let date = c.committer.time.max(0) as u64;
        let hi2 = ((date >> 32) & 0x3) as u32;
        let word0 = ((gens[i] & 0x3fff_ffff) << 2) | hi2;
        cdat.extend_from_slice(&word0.to_be_bytes());
        cdat.extend_from_slice(&((date & 0xffff_ffff) as u32).to_be_bytes());
    }

    // --- assemble: header + chunk table + chunks + trailer ---
    let mut chunks: Vec<(u32, &[u8])> = alloc::vec![
        (CHUNK_OIDF, oidf.as_slice()),
        (CHUNK_OIDL, oidl.as_slice()),
        (CHUNK_CDAT, cdat.as_slice()),
    ];
    if !edge.is_empty() {
        chunks.push((CHUNK_EDGE, edge.as_slice()));
    }
    let num_chunks = chunks.len() as u8;
    let header_len = 8;
    let table_len = (chunks.len() + 1) * 12;
    let mut offset = (header_len + table_len) as u64;

    let mut out = Vec::with_capacity(header_len + table_len + hlen);
    out.extend_from_slice(SIGNATURE);
    out.push(1); // version
    out.push(if algo == HashAlgo::Sha256 { 2 } else { 1 });
    out.push(num_chunks);
    out.push(0); // base graphs
    for (id, data) in &chunks {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        offset += data.len() as u64;
    }
    // Terminating table entry: id 0, offset = end of the last chunk.
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    for (_, data) in &chunks {
        out.extend_from_slice(data);
    }

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
    /// The `EDGE` chunk bytes (octopus parents; empty if absent).
    edge: Vec<u8>,
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
        let edge = chunks
            .get(&CHUNK_EDGE)
            .map(|&(s, e)| data[s..e].to_vec())
            .unwrap_or_default();
        let count = oids.len() / hlen;
        if count * (hlen + 16) != cdat.len() {
            return Err(Error::Pack("commit-graph: OIDL/CDAT size mismatch".into()));
        }
        Ok(CommitGraph {
            algo,
            oids,
            cdat,
            edge,
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

    /// The parent ids of the commit at `pos`, in order — including every parent
    /// of an octopus merge (read from the `EDGE` chunk).
    pub fn parents_at(&self, pos: usize) -> Vec<ObjectId> {
        let hlen = self.algo.raw_len();
        let rec = self.record(pos);
        let word = |b: &[u8], off: usize| -> Option<u32> {
            Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
        };
        let mut out = Vec::new();
        let first = word(rec, hlen).unwrap_or(PARENT_NONE);
        if first == PARENT_NONE {
            return out;
        }
        out.extend(self.id_at(first as usize));
        let second = word(rec, hlen + 4).unwrap_or(PARENT_NONE);
        if second == PARENT_NONE {
            return out;
        }
        if second & EDGE_LAST == 0 {
            out.extend(self.id_at(second as usize));
            return out;
        }
        // Octopus: walk EDGE from the given index until the flagged last word.
        let mut i = (second & !EDGE_LAST) as usize;
        while let Some(v) = word(&self.edge, i * 4) {
            out.extend(self.id_at((v & !EDGE_LAST) as usize));
            if v & EDGE_LAST != 0 {
                break;
            }
            i += 1;
        }
        out
    }

    /// The generation number (topological level) of the commit at `pos`.
    pub fn generation_at(&self, pos: usize) -> u32 {
        self.date_words(pos).0 >> 2
    }

    /// The committer date (seconds since the epoch, 34 bits) of the commit at
    /// `pos`.
    pub fn commit_time_at(&self, pos: usize) -> u64 {
        let (word0, word1) = self.date_words(pos);
        (((word0 & 0x3) as u64) << 32) | word1 as u64
    }

    /// The two big-endian words of the generation/date field of a record.
    fn date_words(&self, pos: usize) -> (u32, u32) {
        let hlen = self.algo.raw_len();
        let rec = self.record(pos);
        let off = hlen + 8;
        let w = |o: usize| u32::from_be_bytes([rec[o], rec[o + 1], rec[o + 2], rec[o + 3]]);
        (w(off), w(off + 4))
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

    #[test]
    fn octopus_parents_round_trip_through_edge() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let tree = odb.write(ObjectType::Tree, b"").unwrap();
        let mk = |parents: Vec<ObjectId>, t: i64| {
            let c = Commit {
                tree,
                parents,
                author: sig(t),
                committer: sig(t),
                extra_headers: Vec::new(),
                message: alloc::format!("{t}\n").into_bytes(),
            };
            odb.write(ObjectType::Commit, &c.serialize()).unwrap()
        };
        let root = mk(alloc::vec![], 1);
        let a = mk(alloc::vec![root], 2);
        let b = mk(alloc::vec![root], 3);
        let c = mk(alloc::vec![root], 4);
        let octo = mk(alloc::vec![a, b, c], 5);
        let five = mk(alloc::vec![octo, a, b, c, root], 6);
        let all = [root, a, b, c, octo, five];
        let g =
            CommitGraph::parse(HashAlgo::Sha1, &write_commit_graph(&odb, &all).unwrap()).unwrap();
        // Parent order is preserved exactly, across the EDGE list.
        assert_eq!(
            g.parents_at(g.position_of(&octo).unwrap()),
            alloc::vec![a, b, c]
        );
        assert_eq!(
            g.parents_at(g.position_of(&five).unwrap()),
            alloc::vec![octo, a, b, c, root]
        );
        assert_eq!(g.parents_at(g.position_of(&a).unwrap()), alloc::vec![root]);
        assert!(g.parents_at(g.position_of(&root).unwrap()).is_empty());
        assert_eq!(g.generation_at(g.position_of(&five).unwrap()), 4);
    }

    #[test]
    fn generation_and_date_bit_layout_matches_git() {
        // git packs the level into the high 30 bits of the first word and the
        // date's bits 33–34 into its low 2 bits.
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let tree = odb.write(ObjectType::Tree, b"").unwrap();
        let far_future: i64 = (1 << 33) + 12345; // needs 34 bits
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
        let c1 = mk(alloc::vec![], 1_700_000_000);
        let c2 = mk(alloc::vec![c1], far_future);
        let bytes = write_commit_graph(&odb, &[c1, c2]).unwrap();
        let g = CommitGraph::parse(HashAlgo::Sha1, &bytes).unwrap();
        let p2 = g.position_of(&c2).unwrap();
        assert_eq!(g.generation_at(p2), 2);
        assert_eq!(g.commit_time_at(p2), far_future as u64);
        assert_eq!(g.commit_time_at(g.position_of(&c1).unwrap()), 1_700_000_000);
        // Raw layout: word0 = (2 << 2) | 2 for c2.
        let (w0, _) = g.date_words(p2);
        assert_eq!(w0, (2 << 2) | 2);
    }
}
