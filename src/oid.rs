//! Object identifiers — git's content-addressed object name.
//!
//! Every object (blob, tree, commit, tag) is named by the hash of its
//! serialized form (see [`crate::hash`]). Historically that hash is SHA-1
//! (20 bytes); the SHA-256 object format (32 bytes, "hash function transition")
//! is also represented here. An [`ObjectId`] therefore carries its algorithm
//! alongside the digest so SHA-1 and SHA-256 repositories never silently mix.

use alloc::string::String;

use crate::error::Error;

/// The hash algorithm a repository uses to name objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgo {
    /// SHA-1 (the historical and still-default object format), 20-byte ids.
    Sha1,
    /// SHA-256 (the "hash function transition" format), 32-byte ids.
    Sha256,
}

impl HashAlgo {
    /// The raw digest length, in bytes (20 for SHA-1, 32 for SHA-256).
    pub const fn raw_len(self) -> usize {
        match self {
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha256 => 32,
        }
    }

    /// The hex-encoded id length, in characters (twice [`Self::raw_len`]).
    pub const fn hex_len(self) -> usize {
        self.raw_len() * 2
    }

    /// The canonical name used in config (`objectformat`) and on the wire.
    pub const fn name(self) -> &'static str {
        match self {
            HashAlgo::Sha1 => "sha1",
            HashAlgo::Sha256 => "sha256",
        }
    }
}

/// A git object id: a hash algorithm plus its fixed-length digest.
///
/// Stored inline in a 32-byte buffer (large enough for SHA-256); for SHA-1 only
/// the first 20 bytes are meaningful. Construct one from raw bytes with
/// [`ObjectId::from_bytes`], from hex with [`ObjectId::from_hex`], or by hashing
/// object content with the helpers in [`crate::hash`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId {
    algo: HashAlgo,
    /// Only the first `algo.raw_len()` bytes are significant.
    bytes: [u8; 32],
}

impl ObjectId {
    /// Builds an id from a raw digest. The slice length must match the
    /// algorithm's [`raw_len`](HashAlgo::raw_len), else [`Error::InvalidOid`].
    pub fn from_bytes(algo: HashAlgo, raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != algo.raw_len() {
            return Err(Error::InvalidOid(invalid_len_msg(algo, raw.len())));
        }
        let mut bytes = [0u8; 32];
        bytes[..raw.len()].copy_from_slice(raw);
        Ok(ObjectId { algo, bytes })
    }

    /// Parses an id from its lowercase or uppercase hex form. The string length
    /// must equal the algorithm's [`hex_len`](HashAlgo::hex_len).
    pub fn from_hex(algo: HashAlgo, hex: &str) -> Result<Self, Error> {
        if hex.len() != algo.hex_len() {
            return Err(Error::InvalidOid(invalid_len_msg(algo, hex.len() / 2)));
        }
        let mut bytes = [0u8; 32];
        let raw = &mut bytes[..algo.raw_len()];
        decode_hex_into(hex, raw)?;
        Ok(ObjectId { algo, bytes })
    }

    /// The algorithm this id was produced with.
    pub fn algo(&self) -> HashAlgo {
        self.algo
    }

    /// The significant digest bytes (length is `algo().raw_len()`).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.algo.raw_len()]
    }

    /// The all-zero id for the given algorithm — git's "null" object, used on
    /// the wire to mean "no such object" (e.g. the old-oid of a created ref).
    pub fn zero(algo: HashAlgo) -> Self {
        ObjectId {
            algo,
            bytes: [0u8; 32],
        }
    }

    /// Whether this is the null id (all bytes zero).
    pub fn is_zero(&self) -> bool {
        self.as_bytes().iter().all(|&b| b == 0)
    }

    /// Lowercase hex encoding (the canonical textual form).
    pub fn to_hex(&self) -> String {
        let raw = self.as_bytes();
        let mut s = String::with_capacity(raw.len() * 2);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in raw {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }

    /// The first `n` hex characters — a short id for display and abbreviation.
    /// Clamped to the full hex length.
    pub fn to_hex_short(&self, n: usize) -> String {
        let full = self.to_hex();
        let n = n.min(full.len());
        full[..n].into()
    }
}

impl core::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Stream hex without an intermediate allocation.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in self.as_bytes() {
            f.write_str(core::str::from_utf8(&[HEX[(b >> 4) as usize]]).unwrap())?;
            f.write_str(core::str::from_utf8(&[HEX[(b & 0xf) as usize]]).unwrap())?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ObjectId({}:{})", self.algo.name(), self.to_hex())
    }
}

// Ordering by raw bytes, matching git's sort order for tree entries and pack
// indexes (algorithm first so the two families never interleave).
impl PartialOrd for ObjectId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ObjectId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.algo.raw_len(), self.as_bytes()).cmp(&(other.algo.raw_len(), other.as_bytes()))
    }
}

fn invalid_len_msg(algo: HashAlgo, got: usize) -> String {
    use alloc::format;
    format!(
        "{} id must be {} bytes, got {}",
        algo.name(),
        algo.raw_len(),
        got
    )
}

/// Decodes `hex` (must be `2 * out.len()` chars) into `out`.
fn decode_hex_into(hex: &str, out: &mut [u8]) -> Result<(), Error> {
    let bytes = hex.as_bytes();
    debug_assert_eq!(bytes.len(), out.len() * 2);
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(())
}

fn hex_val(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::InvalidOid(bad_hex_char(c))),
    }
}

fn bad_hex_char(c: u8) -> String {
    use alloc::format;
    format!("non-hex character {:?} in object id", c as char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_hex_roundtrip() {
        let hex = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"; // the empty blob
        let id = ObjectId::from_hex(HashAlgo::Sha1, hex).unwrap();
        assert_eq!(id.algo(), HashAlgo::Sha1);
        assert_eq!(id.to_hex(), hex);
        assert_eq!(id.as_bytes().len(), 20);
        assert!(!id.is_zero());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(ObjectId::from_hex(HashAlgo::Sha1, "abcd").is_err());
        assert!(ObjectId::from_bytes(HashAlgo::Sha256, &[0u8; 20]).is_err());
    }

    #[test]
    fn rejects_bad_hex() {
        let bad = "z69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
        assert!(ObjectId::from_hex(HashAlgo::Sha1, bad).is_err());
    }

    #[test]
    fn zero_id() {
        let z = ObjectId::zero(HashAlgo::Sha1);
        assert!(z.is_zero());
        assert_eq!(z.to_hex(), "0".repeat(40));
    }
}
