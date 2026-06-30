//! The staging index (`.git/index`).
//!
//! The index is git's staging area: a sorted list of entries mapping a path to
//! the blob id and stat metadata that will form the next commit's tree. The
//! file is the binary `DIRC` format — a header, a run of fixed-then-variable
//! entries, optional extensions, and a trailing hash checksum over everything
//! before it.
//!
//! This implementation reads and writes index versions 2 and 3 (the formats in
//! everyday use). Version 4's path-prefix compression is not yet decoded — such
//! a file is reported as [`Error::Unsupported`] rather than mis-parsed. Unknown
//! trailing *extensions* are preserved verbatim so a round-trip through
//! [`Index::parse`] / [`Index::serialize`] does not drop cache-tree or
//! untracked-cache data it does not interpret.

use alloc::format;
use alloc::vec::Vec;
use purecrypto::hash::{Digest, Sha1, Sha256};

use crate::error::{Error, Result};
use crate::oid::{HashAlgo, ObjectId};

const SIGNATURE: &[u8; 4] = b"DIRC";

/// A single index entry: a path plus its blob id and cached stat data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Seconds/nanoseconds of last metadata change (`ctime`).
    pub ctime: (u32, u32),
    /// Seconds/nanoseconds of last data modification (`mtime`).
    pub mtime: (u32, u32),
    /// Device id (stat `st_dev`).
    pub dev: u32,
    /// Inode number (stat `st_ino`).
    pub ino: u32,
    /// The entry mode (e.g. `0o100644`).
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Cached file size, truncated to 32 bits as git stores it.
    pub size: u32,
    /// The blob id of the staged content.
    pub id: ObjectId,
    /// The merge stage (0 = normal; 1/2/3 = conflict base/ours/theirs).
    pub stage: u8,
    /// "Assume valid" / "assume unchanged" bit.
    pub assume_valid: bool,
    /// The path, as raw bytes (git paths are not required to be UTF-8).
    pub path: Vec<u8>,
}

/// The parsed index.
#[derive(Debug, Clone)]
pub struct Index {
    /// The file format version (2 or 3).
    pub version: u32,
    /// The hash algorithm (determines id width and checksum function).
    pub algo: HashAlgo,
    /// The entries, kept in git's sort order by [`Index::serialize`].
    pub entries: Vec<IndexEntry>,
    /// Trailing extension blocks (signature + payload), preserved verbatim.
    extensions: Vec<u8>,
}

impl Index {
    /// A new, empty index of the given version and algorithm.
    pub fn new(algo: HashAlgo) -> Self {
        Index {
            version: 2,
            algo,
            entries: Vec::new(),
            extensions: Vec::new(),
        }
    }

    /// Parses an index file. `algo` is the repository's hash algorithm.
    pub fn parse(algo: HashAlgo, data: &[u8]) -> Result<Self> {
        let id_len = algo.raw_len();
        let checksum_len = id_len;
        if data.len() < 12 + checksum_len {
            return Err(Error::Parse("index: file too short".into()));
        }
        // Verify the trailing checksum over everything before it.
        let body = &data[..data.len() - checksum_len];
        let stored = &data[data.len() - checksum_len..];
        let computed = hash_bytes(algo, body);
        if stored != computed.as_slice() {
            return Err(Error::Parse("index: checksum mismatch".into()));
        }

        if &data[..4] != SIGNATURE {
            return Err(Error::Parse("index: bad signature".into()));
        }
        let version = be32(&data[4..8]);
        if version != 2 && version != 3 {
            return Err(Error::Unsupported(format!(
                "index version {version} (only 2 and 3 are supported)"
            )));
        }
        let count = be32(&data[8..12]) as usize;

        let mut pos = 12;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let (entry, next) = parse_entry(algo, data, pos, version)?;
            entries.push(entry);
            pos = next;
        }

        // Whatever remains (before the checksum) is extension data.
        let extensions = body[pos..].to_vec();

        Ok(Index {
            version,
            algo,
            entries,
            extensions,
        })
    }

    /// Serializes the index to its on-disk bytes, including the trailing
    /// checksum. Entries are written in git's canonical order (by path, then
    /// stage).
    pub fn serialize(&self) -> Vec<u8> {
        let mut sorted: Vec<&IndexEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.path.cmp(&b.path).then(a.stage.cmp(&b.stage)));

        let mut out = Vec::new();
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
        for e in sorted {
            write_entry(&mut out, e, self.version);
        }
        out.extend_from_slice(&self.extensions);

        let checksum = hash_bytes(self.algo, &out);
        out.extend_from_slice(&checksum);
        out
    }

    /// Looks up an entry by path at stage 0.
    pub fn get(&self, path: &[u8]) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.stage == 0 && e.path == path)
    }
}

fn parse_entry(
    algo: HashAlgo,
    data: &[u8],
    start: usize,
    version: u32,
) -> Result<(IndexEntry, usize)> {
    let id_len = algo.raw_len();
    let fixed = 40 + id_len + 2; // 10 u32 fields + oid + 2-byte flags
    if start + fixed > data.len() {
        return Err(Error::Parse("index: truncated entry".into()));
    }
    // Ten big-endian u32 stat fields, in order.
    let f = |i: usize| be32(&data[start + i * 4..start + i * 4 + 4]);
    let ctime = (f(0), f(1));
    let mtime = (f(2), f(3));
    let dev = f(4);
    let ino = f(5);
    let mode = f(6);
    let uid = f(7);
    let gid = f(8);
    let size = f(9);

    let mut p = start + 40;
    let id = ObjectId::from_bytes(algo, &data[p..p + id_len])?;
    p += id_len;

    let flags = be16(&data[p..p + 2]);
    p += 2;
    let assume_valid = flags & 0x8000 != 0;
    let extended = flags & 0x4000 != 0;
    let stage = ((flags >> 12) & 0x3) as u8;
    let name_len = (flags & 0x0fff) as usize;

    if extended {
        if version < 3 {
            return Err(Error::Parse("index: extended flag in v2 entry".into()));
        }
        p += 2; // skip the v3 extended flags (reserved bits)
    }

    // The name runs to a NUL; the 12-bit length is exact unless it is 0xFFF
    // (meaning "0xFFF or longer", so scan for the NUL).
    let name_start = p;
    let name_end = if name_len < 0x0fff {
        name_start + name_len
    } else {
        data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| name_start + i)
            .ok_or_else(|| Error::Parse("index: unterminated long path".into()))?
    };
    if name_end > data.len() {
        return Err(Error::Parse("index: path past end".into()));
    }
    let path = data[name_start..name_end].to_vec();

    // Entry is padded with NULs to a multiple of 8 bytes (including the NUL
    // terminator), measured from the entry start.
    let unpadded = name_end - start + 1; // +1 for the NUL terminator
    let padded = (unpadded + 7) & !7;
    let next = start + padded;

    Ok((
        IndexEntry {
            ctime,
            mtime,
            dev,
            ino,
            mode,
            uid,
            gid,
            size,
            id,
            stage,
            assume_valid,
            path,
        },
        next,
    ))
}

fn write_entry(out: &mut Vec<u8>, e: &IndexEntry, version: u32) {
    let start = out.len();
    out.extend_from_slice(&e.ctime.0.to_be_bytes());
    out.extend_from_slice(&e.ctime.1.to_be_bytes());
    out.extend_from_slice(&e.mtime.0.to_be_bytes());
    out.extend_from_slice(&e.mtime.1.to_be_bytes());
    out.extend_from_slice(&e.dev.to_be_bytes());
    out.extend_from_slice(&e.ino.to_be_bytes());
    out.extend_from_slice(&e.mode.to_be_bytes());
    out.extend_from_slice(&e.uid.to_be_bytes());
    out.extend_from_slice(&e.gid.to_be_bytes());
    out.extend_from_slice(&e.size.to_be_bytes());
    out.extend_from_slice(e.id.as_bytes());

    let name_len = e.path.len().min(0x0fff) as u16;
    let mut flags = name_len;
    if e.assume_valid {
        flags |= 0x8000;
    }
    flags |= (e.stage as u16 & 0x3) << 12;
    // We never set the extended bit on write (no v3 extended flags are stored),
    // so v2 and v3 entries serialize identically here.
    let _ = version;
    out.extend_from_slice(&flags.to_be_bytes());

    out.extend_from_slice(&e.path);
    out.push(0); // NUL terminator

    let unpadded = out.len() - start;
    let padded = (unpadded + 7) & !7;
    out.resize(start + padded, 0);
}

fn hash_bytes(algo: HashAlgo, data: &[u8]) -> Vec<u8> {
    match algo {
        HashAlgo::Sha1 => Sha1::digest(data).as_ref().to_vec(),
        HashAlgo::Sha256 => Sha256::digest(data).as_ref().to_vec(),
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &[u8], byte: u8) -> IndexEntry {
        IndexEntry {
            ctime: (1, 2),
            mtime: (3, 4),
            dev: 5,
            ino: 6,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 42,
            id: ObjectId::from_bytes(HashAlgo::Sha1, &[byte; 20]).unwrap(),
            stage: 0,
            assume_valid: false,
            path: path.to_vec(),
        }
    }

    #[test]
    fn roundtrip() {
        let mut idx = Index::new(HashAlgo::Sha1);
        idx.entries.push(entry(b"src/main.rs", 0xaa));
        idx.entries.push(entry(b"README.md", 0xbb));
        let bytes = idx.serialize();
        assert_eq!(&bytes[..4], b"DIRC");

        let back = Index::parse(HashAlgo::Sha1, &bytes).unwrap();
        assert_eq!(back.entries.len(), 2);
        // Sorted by path on write.
        assert_eq!(back.entries[0].path, b"README.md");
        assert_eq!(back.entries[1].path, b"src/main.rs");
        assert_eq!(back.get(b"src/main.rs").unwrap().size, 42);
    }

    #[test]
    fn detects_corruption() {
        let mut idx = Index::new(HashAlgo::Sha1);
        idx.entries.push(entry(b"a", 1));
        let mut bytes = idx.serialize();
        let n = bytes.len();
        bytes[n - 1] ^= 0xff; // corrupt the checksum
        assert!(Index::parse(HashAlgo::Sha1, &bytes).is_err());
    }
}
