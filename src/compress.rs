//! zlib (RFC 1950) compression, the on-disk encoding for git data.
//!
//! Both loose objects and the object contents inside a packfile are stored as
//! zlib streams. These are thin one-shot wrappers over [`compcol`]'s pure-Rust
//! `zlib` codec, mapping its errors into [`crate::Error`].
//!
//! The capped [`inflate_capped`] variant is the one object/pack code should
//! prefer: a loose object header declares its uncompressed size, so we can
//! bound the output and refuse a corrupt or hostile stream that would otherwise
//! decompress without limit.

use alloc::vec::Vec;
use compcol::zlib::Zlib;

use crate::error::Result;

/// Compresses `data` into a zlib stream (default compression level).
pub fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    Ok(compcol::vec::compress_to_vec::<Zlib>(data)?)
}

/// Decompresses a complete zlib stream with no explicit output bound.
///
/// Prefer [`inflate_capped`] wherever the expected size is known (it always is
/// for git objects, which prefix their uncompressed length).
pub fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    Ok(compcol::vec::decompress_to_vec::<Zlib>(data)?)
}

/// Decompresses a zlib stream, refusing to produce more than `max` bytes.
///
/// Used by the loose-object and packfile readers, which know the declared
/// uncompressed size up front: a stream that tries to exceed it is corrupt (or
/// malicious) and is rejected rather than allowed to exhaust memory.
pub fn inflate_capped(data: &[u8], max: usize) -> Result<Vec<u8>> {
    Ok(compcol::vec::decompress_to_vec_capped::<Zlib>(
        data, max as u64,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let msg = b"the quick brown fox jumps over the lazy dog";
        let z = deflate(msg).unwrap();
        assert_eq!(inflate(&z).unwrap(), msg);
        assert_eq!(inflate_capped(&z, msg.len()).unwrap(), msg);
    }

    #[test]
    fn cap_is_enforced() {
        let z = deflate(&[7u8; 4096]).unwrap();
        assert!(inflate_capped(&z, 16).is_err());
    }
}
