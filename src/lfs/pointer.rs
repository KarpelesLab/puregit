//! The Git LFS pointer-file format.
//!
//! A pointer is a tiny text blob committed in place of a large file:
//!
//! ```text
//! version https://git-lfs.github.com/spec/v1
//! oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393
//! size 12345
//! ```
//!
//! The first line is always `version`; the remaining keys are sorted
//! alphabetically (`oid`, then `size` for v1). The object id is the lowercase
//! hex SHA-256 of the *file content* (not a git object hash). This module
//! parses, serializes, and cheaply detects that format.

use alloc::string::String;
use alloc::vec::Vec;
use purecrypto::hash::{Digest, Sha256};

use crate::error::{Error, Result};

/// The v1 pointer version URL (the first line's value).
pub const VERSION_URL: &str = "https://git-lfs.github.com/spec/v1";

/// The largest blob size we will consider as a possible pointer. Git LFS uses
/// the same 1 KiB bound: real content is never this small *and* shaped like a
/// pointer, so this keeps detection cheap and safe.
pub const MAX_POINTER_LEN: usize = 1024;

/// A parsed LFS pointer: the content's SHA-256 (lowercase hex) and byte size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pointer {
    /// Lowercase hex SHA-256 of the file content (64 chars).
    pub oid: String,
    /// The content size in bytes.
    pub size: u64,
}

impl Pointer {
    /// Builds the pointer for a piece of content (hashes it with SHA-256).
    pub fn for_content(content: &[u8]) -> Pointer {
        let digest = Sha256::digest(content);
        Pointer {
            oid: hex_lower(digest.as_ref()),
            size: content.len() as u64,
        }
    }

    /// The `sha256:<hex>` object id string used in the LFS API and pointer.
    pub fn oid_with_algo(&self) -> String {
        let mut s = String::with_capacity(7 + self.oid.len());
        s.push_str("sha256:");
        s.push_str(&self.oid);
        s
    }

    /// The `ab/cd/<oid>` storage sub-path git-lfs uses under `lfs/objects/`.
    pub fn storage_path(&self) -> String {
        alloc::format!("{}/{}/{}", &self.oid[..2], &self.oid[2..4], self.oid)
    }

    /// Serializes to the canonical pointer bytes (keys sorted, trailing `\n`).
    pub fn serialize(&self) -> Vec<u8> {
        alloc::format!(
            "version {VERSION_URL}\noid sha256:{}\nsize {}\n",
            self.oid,
            self.size
        )
        .into_bytes()
    }

    /// Cheaply tests whether `blob` *looks like* a pointer (small, and starts
    /// with the version line). Use [`Pointer::parse`] to fully validate.
    pub fn is_pointer(blob: &[u8]) -> bool {
        blob.len() <= MAX_POINTER_LEN
            && blob.starts_with(b"version https://git-lfs.github.com/spec/v1")
    }

    /// Parses a pointer blob, validating the version line, the `sha256:` oid
    /// (64 lowercase hex chars), and the numeric size.
    pub fn parse(blob: &[u8]) -> Result<Pointer> {
        if blob.len() > MAX_POINTER_LEN {
            return Err(Error::Parse("lfs pointer: too large".into()));
        }
        let text =
            core::str::from_utf8(blob).map_err(|_| Error::Parse("lfs pointer: non-utf8".into()))?;

        let mut version = None;
        let mut oid = None;
        let mut size = None;
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once(' ')
                .ok_or_else(|| Error::Parse("lfs pointer: malformed line".into()))?;
            match key {
                "version" => version = Some(value),
                "oid" => oid = Some(value),
                "size" => size = Some(value),
                // Unknown extension keys are allowed by the spec; ignore them.
                _ => {}
            }
        }

        if version != Some(VERSION_URL) {
            return Err(Error::Parse("lfs pointer: wrong or missing version".into()));
        }
        let oid = oid.ok_or_else(|| Error::Parse("lfs pointer: missing oid".into()))?;
        let oid = oid
            .strip_prefix("sha256:")
            .ok_or_else(|| Error::Parse("lfs pointer: oid is not sha256".into()))?;
        if oid.len() != 64
            || !oid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::Parse("lfs pointer: invalid sha256 oid".into()));
        }
        let size: u64 = size
            .ok_or_else(|| Error::Parse("lfs pointer: missing size".into()))?
            .parse()
            .map_err(|_| Error::Parse("lfs pointer: invalid size".into()))?;

        Ok(Pointer {
            oid: oid.into(),
            size,
        })
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_content_matches_known_sha256() {
        // SHA-256 of "hello\n".
        let p = Pointer::for_content(b"hello\n");
        assert_eq!(
            p.oid,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
        assert_eq!(p.size, 6);
        assert_eq!(
            p.storage_path(),
            "58/91/5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    #[test]
    fn serialize_parse_roundtrip() {
        let p = Pointer::for_content(b"some large content here");
        let bytes = p.serialize();
        assert!(Pointer::is_pointer(&bytes));
        let back = Pointer::parse(&bytes).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn detects_and_rejects() {
        let good = b"version https://git-lfs.github.com/spec/v1\noid sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03\nsize 6\n";
        assert!(Pointer::is_pointer(good));
        assert!(Pointer::parse(good).is_ok());

        assert!(!Pointer::is_pointer(b"just a normal file\n"));
        // Wrong version.
        assert!(
            Pointer::parse(b"version https://example.com/v9\noid sha256:00\nsize 1\n").is_err()
        );
        // Uppercase / short oid rejected.
        assert!(
            Pointer::parse(b"version https://git-lfs.github.com/spec/v1\noid sha256:ABC\nsize 1\n")
                .is_err()
        );
    }
}
