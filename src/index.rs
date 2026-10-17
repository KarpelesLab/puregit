//! The staging index (`.git/index`).
//!
//! The index is git's staging area: a sorted list of entries mapping a path to
//! the blob id and stat metadata that will form the next commit's tree. The
//! file is the binary `DIRC` format — a header, a run of fixed-then-variable
//! entries, optional extensions, and a trailing hash checksum over everything
//! before it.
//!
//! This implementation reads and writes index versions 2, 3 (extended entry
//! flags: intent-to-add, skip-worktree) and 4 (path-prefix compression). A
//! trailing checksum of all zeros (`index.skipHash`) is accepted, as git does.
//!
//! Trailing *extensions* are preserved verbatim while the entries are
//! unchanged, so a round-trip through [`Index::parse`] / [`Index::serialize`]
//! reproduces git's file byte-for-byte. Once the entries change, the
//! extensions that describe them (the cache-tree `TREE`, the untracked cache,
//! fsmonitor state, entry offset tables, …) would be stale — git trusts a
//! valid-looking cache-tree when it writes the next tree, so a stale one would
//! make `git commit` record the *old* tree — and are dropped; only the
//! path-keyed resolve-undo (`REUC`) data is kept. A split index (`link`
//! extension), whose entries live partly in a second file, is reported as
//! [`Error::Unsupported`] rather than mis-read.

use alloc::format;
use alloc::vec::Vec;
use purecrypto::hash::{Digest, Sha1, Sha256};

use crate::error::{Error, Result};
use crate::oid::{HashAlgo, ObjectId};

const SIGNATURE: &[u8; 4] = b"DIRC";

/// A conservative lower bound on the on-disk size of one index entry, used to
/// cap the pre-allocation in [`Index::parse`] against a lying entry count (D3).
/// Every entry carries far more than this in fixed fields, so
/// `data.len() / MIN_ENTRY_SIZE` is always at least the true entry count while
/// still bounding the allocation.
const MIN_ENTRY_SIZE: usize = 8;

/// The `extended` bit of the 16-bit entry flags: a v3+ entry carries a second
/// 16-bit flags word.
const FLAG_EXTENDED: u16 = 0x4000;

/// Extended-flags bit: the entry is `git add -N` (intent-to-add).
pub const EXT_INTENT_TO_ADD: u16 = 0x2000;
/// Extended-flags bit: the entry is skip-worktree (sparse checkout).
pub const EXT_SKIP_WORKTREE: u16 = 0x4000;

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
    /// The v3+ extended flags word, as stored on disk: a combination of
    /// [`EXT_INTENT_TO_ADD`] and [`EXT_SKIP_WORKTREE`] (0 for an ordinary
    /// entry). A nonzero value makes [`Index::serialize`] write at least a
    /// version-3 index, as git does.
    pub extended_flags: u16,
    /// The path, as raw bytes (git paths are not required to be UTF-8).
    pub path: Vec<u8>,
}

/// The parsed index.
#[derive(Debug, Clone)]
pub struct Index {
    /// The file format version (2, 3 or 4). Versions 2 and 3 are chosen
    /// automatically on write (3 exactly when an entry has extended flags);
    /// set 4 to write the path-compressed format.
    pub version: u32,
    /// The hash algorithm (determines id width and checksum function).
    pub algo: HashAlgo,
    /// The entries, kept in git's sort order by [`Index::serialize`].
    pub entries: Vec<IndexEntry>,
    /// Trailing extension blocks (signature + payload), preserved verbatim.
    extensions: Vec<u8>,
    /// The version and serialized entry block as parsed, used to detect
    /// whether the entries changed (and the extensions went stale) on write.
    parsed: Option<(u32, Vec<u8>)>,
}

impl Index {
    /// A new, empty index of the given version and algorithm.
    pub fn new(algo: HashAlgo) -> Self {
        Index {
            version: 2,
            algo,
            entries: Vec::new(),
            extensions: Vec::new(),
            parsed: None,
        }
    }

    /// Parses an index file. `algo` is the repository's hash algorithm.
    pub fn parse(algo: HashAlgo, data: &[u8]) -> Result<Self> {
        let id_len = algo.raw_len();
        let checksum_len = id_len;
        if data.len() < 12 + checksum_len {
            return Err(Error::Parse("index: file too short".into()));
        }
        // Verify the trailing checksum over everything before it. An all-zero
        // trailer means git skipped computing it (`index.skipHash`).
        let body = &data[..data.len() - checksum_len];
        let stored = &data[data.len() - checksum_len..];
        if stored.iter().any(|&b| b != 0) {
            let computed = hash_bytes(algo, body);
            if stored != computed.as_slice() {
                return Err(Error::Parse("index: checksum mismatch".into()));
            }
        }

        if &data[..4] != SIGNATURE {
            return Err(Error::Parse("index: bad signature".into()));
        }
        let version = be32(&data[4..8]);
        if !(2..=4).contains(&version) {
            return Err(Error::Unsupported(format!(
                "index version {version} (only 2, 3 and 4 are supported)"
            )));
        }
        let count = be32(&data[8..12]) as usize;

        let mut pos = 12;
        // `count` is attacker-controlled (up to 0xFFFFFFFF) and the trailing
        // checksum is attacker-computable, so it is no defense. Cap the
        // pre-allocation to what the remaining bytes could possibly hold — an
        // entry cannot be smaller than `MIN_ENTRY_SIZE` bytes — so a bogus
        // count can never trigger a giant allocation / OOM abort (D3). If the
        // real count is honest we still avoid reallocs; if it lies, the entry
        // loop below fails on the truncated data.
        let cap = count.min(data.len() / MIN_ENTRY_SIZE);
        let mut entries = Vec::with_capacity(cap);
        let mut prev_path: Vec<u8> = Vec::new();
        for _ in 0..count {
            let (entry, next) = parse_entry(algo, body, pos, version, &prev_path)?;
            prev_path.clone_from(&entry.path);
            entries.push(entry);
            pos = next;
        }

        // Whatever remains (before the checksum) is extension data.
        let extensions = body[pos..].to_vec();
        for (sig, _) in extension_blocks(&extensions) {
            if &sig == b"link" {
                return Err(Error::Unsupported(
                    "index: split index (core.splitIndex) is not supported".into(),
                ));
            }
        }

        Ok(Index {
            version,
            algo,
            entries,
            extensions,
            parsed: Some((version, body[12..pos].to_vec())),
        })
    }

    /// Serializes the index to its on-disk bytes, including the trailing
    /// checksum. Entries are written in git's canonical order (by path, then
    /// stage).
    pub fn serialize(&self) -> Vec<u8> {
        let mut sorted: Vec<&IndexEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.path.cmp(&b.path).then(a.stage.cmp(&b.stage)));

        // Like git: v2 and v3 differ only in whether extended flags are
        // present, so pick whichever the entries need; v4 is kept as asked.
        let extended = sorted.iter().any(|e| e.extended_flags != 0);
        let version = match self.version {
            4 => 4,
            _ if extended => 3,
            _ => 2,
        };

        let mut body = Vec::new();
        let mut prev: &[u8] = &[];
        for e in &sorted {
            write_entry(&mut body, e, version, prev);
            prev = &e.path;
        }

        let mut out = Vec::with_capacity(12 + body.len() + self.extensions.len() + 32);
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
        let unchanged = self
            .parsed
            .as_ref()
            .is_some_and(|(v, bytes)| *v == version && *bytes == body);
        out.extend_from_slice(&body);
        if unchanged {
            out.extend_from_slice(&self.extensions);
        } else {
            // The entries changed: keep only extensions that stay valid.
            for (sig, block) in extension_blocks(&self.extensions) {
                if &sig == b"REUC" {
                    out.extend_from_slice(block);
                }
            }
        }

        let checksum = hash_bytes(self.algo, &out);
        out.extend_from_slice(&checksum);
        out
    }

    /// Looks up an entry by path at stage 0.
    pub fn get(&self, path: &[u8]) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.stage == 0 && e.path == path)
    }
}

/// Splits the raw extension area into `(signature, whole block)` pairs (each
/// block is the 4-byte signature, a 4-byte big-endian length, and the
/// payload). Stops at the first malformed block.
fn extension_blocks(mut data: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let mut out = Vec::new();
    while data.len() >= 8 {
        let len = be32(&data[4..8]) as usize;
        let Some(end) = len.checked_add(8).filter(|&e| e <= data.len()) else {
            break;
        };
        out.push(([data[0], data[1], data[2], data[3]], &data[..end]));
        data = &data[end..];
    }
    out
}

/// Validates a full (slash-separated) index entry path against traversal.
///
/// A git path is relative and uses `/` separators. This splits the path on `/`
/// and requires each component to be a safe single component per
/// [`crate::object::tree::is_safe_path_component`] — which already rejects empty
/// components (so leading/trailing/doubled `/`), `.`/`..`, embedded NUL, and
/// `.git` in every form. That subsumes the "absolute path" and "leading `/`"
/// cases: a leading `/` produces an empty first component, and any absolute or
/// drive-relative form contains a rejected component. Reused for D4.
pub(crate) fn is_safe_index_path(path: &[u8]) -> bool {
    if path.is_empty() {
        return false;
    }
    path.split(|&b| b == b'/')
        .all(crate::object::tree::is_safe_path_component)
}

fn parse_entry(
    algo: HashAlgo,
    data: &[u8],
    start: usize,
    version: u32,
    prev_path: &[u8],
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
    let extended = flags & FLAG_EXTENDED != 0;
    let stage = ((flags >> 12) & 0x3) as u8;
    let name_len = (flags & 0x0fff) as usize;

    let mut extended_flags = 0;
    if extended {
        if version < 3 {
            return Err(Error::Parse("index: extended flag in v2 entry".into()));
        }
        if p + 2 > data.len() {
            return Err(Error::Parse("index: truncated entry".into()));
        }
        extended_flags = be16(&data[p..p + 2]);
        p += 2;
    }

    let (path, next) = if version >= 4 {
        // v4: a varint counting bytes to drop from the end of the previous
        // entry's path, then the NUL-terminated suffix to append. No padding.
        let (strip, n) = read_varint(data, p)?;
        p += n;
        let keep = prev_path
            .len()
            .checked_sub(strip)
            .ok_or_else(|| Error::Parse("index: v4 prefix longer than previous path".into()))?;
        let nul = data[p..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::Parse("index: unterminated path".into()))?;
        let mut path = prev_path[..keep].to_vec();
        path.extend_from_slice(&data[p..p + nul]);
        (path, p + nul + 1)
    } else {
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
        // Entry is padded with NULs to a multiple of 8 bytes (including the NUL
        // terminator), measured from the entry start.
        let unpadded = name_end - start + 1; // +1 for the NUL terminator
        let padded = (unpadded + 7) & !7;
        (data[name_start..name_end].to_vec(), start + padded)
    };
    if next > data.len() {
        return Err(Error::Parse("index: path past end".into()));
    }
    // A hostile `.git/index` can carry paths that escape the working tree
    // (absolute, `..`, `.git/…`); every filesystem sink that trusts these
    // paths — LFS smudge writes, status reads — would then read or write
    // outside the tree. Reject them at the parse boundary (D4).
    if !is_safe_index_path(&path) {
        return Err(Error::Parse("index: unsafe entry path".into()));
    }

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
            extended_flags,
            path,
        },
        next,
    ))
}

fn write_entry(out: &mut Vec<u8>, e: &IndexEntry, version: u32, prev_path: &[u8]) {
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
    let extended = version >= 3 && e.extended_flags != 0;
    if extended {
        flags |= FLAG_EXTENDED;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    if extended {
        out.extend_from_slice(&e.extended_flags.to_be_bytes());
    }

    if version >= 4 {
        let common = prev_path
            .iter()
            .zip(&e.path)
            .take_while(|(a, b)| a == b)
            .count();
        write_varint(out, prev_path.len() - common);
        out.extend_from_slice(&e.path[common..]);
        out.push(0);
    } else {
        out.extend_from_slice(&e.path);
        out.push(0); // NUL terminator
        let unpadded = out.len() - start;
        let padded = (unpadded + 7) & !7;
        out.resize(start + padded, 0);
    }
}

/// Reads git's offset-style varint (as in `OFS_DELTA` and index v4 path
/// prefixes), returning `(value, bytes consumed)`.
fn read_varint(data: &[u8], start: usize) -> Result<(usize, usize)> {
    let mut p = start;
    let truncated = || Error::Parse("index: truncated varint".into());
    let mut c = *data.get(p).ok_or_else(truncated)?;
    p += 1;
    let mut value = (c & 0x7f) as usize;
    while c & 0x80 != 0 {
        c = *data.get(p).ok_or_else(truncated)?;
        p += 1;
        value = value
            .checked_add(1)
            .and_then(|v| v.checked_mul(128))
            .ok_or_else(|| Error::Parse("index: varint overflow".into()))?
            | (c & 0x7f) as usize;
    }
    Ok((value, p - start))
}

/// Writes git's offset-style varint (the inverse of [`read_varint`]).
fn write_varint(out: &mut Vec<u8>, mut value: usize) {
    let mut buf = [0u8; 16];
    let mut pos = buf.len() - 1;
    buf[pos] = (value & 0x7f) as u8;
    value >>= 7;
    while value != 0 {
        value -= 1;
        pos -= 1;
        buf[pos] = 0x80 | (value & 0x7f) as u8;
        value >>= 7;
    }
    out.extend_from_slice(&buf[pos..]);
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
            extended_flags: 0,
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

    #[test]
    fn huge_count_does_not_abort() {
        // A tiny file that claims 0xFFFFFFFF entries. The cap keeps the
        // pre-allocation bounded by the real byte count, so `parse` returns a
        // normal error instead of aborting on a giant allocation (D3).
        let mut data = Vec::new();
        data.extend_from_slice(SIGNATURE);
        data.extend_from_slice(&2u32.to_be_bytes()); // version
        data.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // lying count
        let checksum = hash_bytes(HashAlgo::Sha1, &data);
        data.extend_from_slice(&checksum);
        // Must not abort; the truncated entries make it a parse error.
        let res = Index::parse(HashAlgo::Sha1, &data);
        assert!(matches!(res, Err(Error::Parse(_))));
    }

    #[test]
    fn parse_rejects_traversal_paths() {
        for bad in [
            &b"../evil"[..],
            b"a/../b",
            b"/abs",
            b".git/hooks/post-checkout",
            b".git",
        ] {
            let mut idx = Index::new(HashAlgo::Sha1);
            idx.entries.push(entry(bad, 7));
            let bytes = idx.serialize();
            assert!(
                matches!(Index::parse(HashAlgo::Sha1, &bytes), Err(Error::Parse(_))),
                "path {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn safe_index_path_matrix() {
        assert!(is_safe_index_path(b"src/main.rs"));
        assert!(is_safe_index_path(b"README.md"));
        assert!(!is_safe_index_path(b""));
        assert!(!is_safe_index_path(b"/abs"));
        assert!(!is_safe_index_path(b"a/../b"));
        assert!(!is_safe_index_path(b"../x"));
        assert!(!is_safe_index_path(b".git/config"));
        assert!(!is_safe_index_path(b"a//b")); // empty component
    }

    fn sample() -> Index {
        let mut idx = Index::new(HashAlgo::Sha1);
        for (p, b) in [
            (&b"src/lib.rs"[..], 1u8),
            (b"src/main.rs", 2),
            (b"src/bin/tool.rs", 3),
            (b"README.md", 4),
            (b"a-very/long/shared/prefix/one.txt", 5),
            (b"a-very/long/shared/prefix/two.txt", 6),
        ] {
            idx.entries.push(entry(p, b));
        }
        idx
    }

    #[test]
    fn v4_path_compression_roundtrip() {
        let mut idx = sample();
        idx.version = 4;
        let bytes = idx.serialize();
        assert_eq!(be32(&bytes[4..8]), 4);
        // Prefix compression makes it smaller than the padded v2 form.
        let mut v2 = idx.clone();
        v2.version = 2;
        assert!(bytes.len() < v2.serialize().len());
        let back = Index::parse(HashAlgo::Sha1, &bytes).unwrap();
        assert_eq!(back.version, 4);
        let mut want = idx.entries.clone();
        want.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(back.entries, want);
        // Byte-exact on re-serialization.
        assert_eq!(back.serialize(), bytes);
    }

    #[test]
    fn varint_roundtrip() {
        for v in [
            0usize,
            1,
            127,
            128,
            255,
            16383,
            16384,
            1 << 20,
            usize::MAX >> 8,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            assert_eq!(read_varint(&buf, 0).unwrap(), (v, buf.len()));
        }
    }

    #[test]
    fn extended_flags_force_v3_and_roundtrip() {
        let mut idx = sample();
        idx.entries[0].extended_flags = EXT_INTENT_TO_ADD;
        idx.entries[1].extended_flags = EXT_SKIP_WORKTREE;
        let bytes = idx.serialize();
        assert_eq!(be32(&bytes[4..8]), 3);
        let back = Index::parse(HashAlgo::Sha1, &bytes).unwrap();
        assert_eq!(
            back.get(b"src/lib.rs").unwrap().extended_flags,
            EXT_INTENT_TO_ADD
        );
        assert_eq!(
            back.get(b"src/main.rs").unwrap().extended_flags,
            EXT_SKIP_WORKTREE
        );
        assert_eq!(back.get(b"README.md").unwrap().extended_flags, 0);
        assert_eq!(back.serialize(), bytes);
        // Without extended flags, a v3 request is written as v2 (as git does).
        let mut plain = sample();
        plain.version = 3;
        assert_eq!(be32(&plain.serialize()[4..8]), 2);
    }

    #[test]
    fn skip_hash_trailer_is_accepted() {
        let mut bytes = sample().serialize();
        let n = bytes.len();
        bytes[n - 20..].fill(0);
        let idx = Index::parse(HashAlgo::Sha1, &bytes).unwrap();
        assert_eq!(idx.entries.len(), 6);
    }

    /// Appends an extension block and re-checksums.
    fn with_extension(mut bytes: Vec<u8>, sig: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        bytes.truncate(bytes.len() - 20);
        bytes.extend_from_slice(sig);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        let sum = hash_bytes(HashAlgo::Sha1, &bytes);
        bytes.extend_from_slice(&sum);
        bytes
    }

    #[test]
    fn stale_extensions_are_dropped_when_entries_change() {
        let bytes = with_extension(sample().serialize(), b"TREE", b"cache-tree");
        let bytes = with_extension(bytes, b"REUC", b"resolve-undo");
        let idx = Index::parse(HashAlgo::Sha1, &bytes).unwrap();
        // Unchanged: byte-exact, extensions kept.
        assert_eq!(idx.serialize(), bytes);
        // Changed: the cache-tree no longer describes the entries and goes;
        // the path-keyed resolve-undo data stays.
        let mut changed = idx.clone();
        changed.entries[0].id = ObjectId::from_bytes(HashAlgo::Sha1, &[9; 20]).unwrap();
        let out = changed.serialize();
        let back = Index::parse(HashAlgo::Sha1, &out).unwrap();
        let sigs: Vec<[u8; 4]> = extension_blocks(&back.extensions)
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        assert_eq!(sigs, alloc::vec![*b"REUC"]);
    }

    #[test]
    fn split_index_is_unsupported() {
        let bytes = with_extension(sample().serialize(), b"link", &[0u8; 20]);
        assert!(matches!(
            Index::parse(HashAlgo::Sha1, &bytes),
            Err(Error::Unsupported(_))
        ));
    }
}
