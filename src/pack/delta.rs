//! Git delta encoding (used by `OFS_DELTA` / `REF_DELTA` packed objects).
//!
//! A delta reconstructs a *target* object from a *base* object using a compact
//! instruction stream: a header with the base and target sizes (little-endian
//! base-128 varints), followed by two kinds of instruction —
//!
//! - **copy** (`0x80` bit set): copy a run of bytes from the base at a given
//!   offset and length, both encoded sparsely by the low bits of the opcode.
//! - **insert** (`0x80` bit clear, nonzero): the opcode *is* the length (1–127)
//!   of literal bytes that follow inline.
//!
//! [`apply_delta`] applies one delta to a base buffer; the packfile reader uses
//! it after resolving each delta's base (another object in the pack, by offset
//! for `OFS_DELTA` or by id for `REF_DELTA`).

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Applies a git delta to `base`, returning the reconstructed target bytes.
///
/// Validates the declared base size against `base.len()` and the declared
/// target size against the produced output, rejecting a malformed or truncated
/// delta rather than producing a wrong object.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;

    let base_size = read_varint(delta, &mut pos)?;
    if base_size != base.len() {
        return Err(Error::Pack("delta: base size mismatch".into()));
    }
    let target_size = read_varint(delta, &mut pos)?;

    let mut out = Vec::with_capacity(target_size);
    while pos < delta.len() {
        let opcode = delta[pos];
        pos += 1;

        if opcode & 0x80 != 0 {
            // Copy from base: assemble offset and size from the selected bytes.
            let mut offset = 0usize;
            for i in 0..4 {
                if opcode & (1 << i) != 0 {
                    offset |= (next_byte(delta, &mut pos)? as usize) << (8 * i);
                }
            }
            let mut size = 0usize;
            for i in 0..3 {
                if opcode & (1 << (4 + i)) != 0 {
                    size |= (next_byte(delta, &mut pos)? as usize) << (8 * i);
                }
            }
            if size == 0 {
                size = 0x10000; // a size of 0 means 64 KiB
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| Error::Pack("delta: copy range overflow".into()))?;
            if end > base.len() {
                return Err(Error::Pack("delta: copy past end of base".into()));
            }
            out.extend_from_slice(&base[offset..end]);
        } else if opcode != 0 {
            // Insert: the opcode is the literal length.
            let len = opcode as usize;
            if pos + len > delta.len() {
                return Err(Error::Pack("delta: insert past end of delta".into()));
            }
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
        } else {
            return Err(Error::Pack("delta: invalid zero opcode".into()));
        }
    }

    if out.len() != target_size {
        return Err(Error::Pack("delta: target size mismatch".into()));
    }
    Ok(out)
}

/// Reads a little-endian base-128 varint (the size-header encoding).
fn read_varint(data: &[u8], pos: &mut usize) -> Result<usize> {
    let mut value = 0usize;
    let mut shift = 0u32;
    loop {
        let byte = next_byte(data, pos)?;
        value |= ((byte & 0x7f) as usize)
            .checked_shl(shift)
            .ok_or_else(|| Error::Pack("delta: varint overflow".into()))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn next_byte(data: &[u8], pos: &mut usize) -> Result<u8> {
    let b = *data
        .get(*pos)
        .ok_or_else(|| Error::Pack("delta: unexpected end".into()))?;
    *pos += 1;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a size as a base-128 varint (test helper / future encoder seed).
    fn varint(mut n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                break;
            }
        }
        out
    }

    #[test]
    fn insert_only() {
        let base = b"";
        let mut delta = Vec::new();
        delta.extend_from_slice(&varint(0)); // base size
        delta.extend_from_slice(&varint(5)); // target size
        delta.push(5); // insert 5 bytes
        delta.extend_from_slice(b"hello");
        assert_eq!(apply_delta(base, &delta).unwrap(), b"hello");
    }

    #[test]
    fn copy_then_insert() {
        let base = b"the quick brown fox";
        // Target: "the quick red fox": copy "the quick ", insert "red", copy " fox".
        let target = b"the quick red fox";
        let mut delta = Vec::new();
        delta.extend_from_slice(&varint(base.len()));
        delta.extend_from_slice(&varint(target.len()));
        // copy offset=0 size=10
        delta.push(0x80 | 0x01 | 0x10); // offset byte0 + size byte0
        delta.push(0); // offset = 0
        delta.push(10); // size = 10
        // insert "red"
        delta.push(3);
        delta.extend_from_slice(b"red");
        // copy offset=15 size=4 (" fox")
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(15);
        delta.push(4);
        assert_eq!(apply_delta(base, &delta).unwrap(), target);
    }

    #[test]
    fn rejects_base_size_mismatch() {
        let mut delta = Vec::new();
        delta.extend_from_slice(&varint(99));
        delta.extend_from_slice(&varint(0));
        assert!(apply_delta(b"abc", &delta).is_err());
    }
}
