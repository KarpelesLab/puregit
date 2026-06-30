//! Computing object ids.
//!
//! A git object's id is the hash of its *loose* serialized form:
//!
//! ```text
//! "<type> <size>\0" || <content>
//! ```
//!
//! where `<type>` is `blob`/`tree`/`commit`/`tag` and `<size>` is the decimal
//! byte length of `<content>`. The hash function is the repository's
//! [`HashAlgo`] — SHA-1 by default, SHA-256 for the transition format. These
//! helpers build that header and run the digest from [`purecrypto`].

use alloc::vec::Vec;
use purecrypto::hash::{Digest, Sha1, Sha256};

use crate::error::Error;
use crate::object::ObjectType;
use crate::oid::{HashAlgo, ObjectId};

/// Computes the [`ObjectId`] of `content` stored as object type `ty`, under the
/// given hash algorithm.
///
/// This is the operation git calls "hash-object": it does *not* compress or
/// store anything, it only derives the content-addressed name.
pub fn hash_object(algo: HashAlgo, ty: ObjectType, content: &[u8]) -> ObjectId {
    match algo {
        HashAlgo::Sha1 => digest_with::<Sha1>(algo, ty, content),
        HashAlgo::Sha256 => digest_with::<Sha256>(algo, ty, content),
    }
}

/// Computes an id over an already-serialized loose object body — i.e. the bytes
/// that follow the `"<type> <size>\0"` header — without re-deriving the type.
/// This is the inner half of [`hash_object`], exposed for the object database,
/// which has the header and content laid out contiguously.
pub fn hash_loose_payload(algo: HashAlgo, ty: ObjectType, payload: &[u8]) -> ObjectId {
    hash_object(algo, ty, payload)
}

fn digest_with<D: Digest>(algo: HashAlgo, ty: ObjectType, content: &[u8]) -> ObjectId {
    let mut d = D::new();
    d.update(&loose_header(ty, content.len()));
    d.update(content);
    let out = d.finalize();
    // `out` is exactly `algo.raw_len()` bytes by construction, so this never
    // returns the length error.
    ObjectId::from_bytes(algo, out.as_ref()).expect("digest length matches algo")
}

/// Builds the `"<type> <size>\0"` loose-object header.
pub(crate) fn loose_header(ty: ObjectType, len: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(ty.as_str().as_bytes());
    header.push(b' ');
    push_decimal(&mut header, len);
    header.push(0);
    header
}

fn push_decimal(buf: &mut Vec<u8>, mut n: usize) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let start = buf.len();
    while n > 0 {
        buf.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    buf[start..].reverse();
}

/// Verifies that `content` of type `ty` hashes to `expected`, returning an
/// [`Error::InvalidOid`] on mismatch. Used when reading objects to detect
/// corruption (git's "fsck"-style integrity check).
pub fn verify(expected: &ObjectId, ty: ObjectType, content: &[u8]) -> Result<(), Error> {
    let got = hash_object(expected.algo(), ty, content);
    if &got == expected {
        Ok(())
    } else {
        use alloc::format;
        Err(Error::InvalidOid(format!(
            "object hash mismatch: expected {expected}, computed {got}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blob_sha1() {
        // The well-known id of the empty blob.
        let id = hash_object(HashAlgo::Sha1, ObjectType::Blob, b"");
        assert_eq!(id.to_hex(), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }

    #[test]
    fn hello_blob_sha1() {
        // `printf 'hello\n' | git hash-object --stdin`
        let id = hash_object(HashAlgo::Sha1, ObjectType::Blob, b"hello\n");
        assert_eq!(id.to_hex(), "ce013625030ba8dba906f756967f9e9ca394464a");
    }

    #[test]
    fn empty_blob_sha256() {
        let id = hash_object(HashAlgo::Sha256, ObjectType::Blob, b"");
        assert_eq!(
            id.to_hex(),
            "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
        );
    }

    #[test]
    fn verify_roundtrip() {
        let id = hash_object(HashAlgo::Sha1, ObjectType::Blob, b"hello\n");
        assert!(verify(&id, ObjectType::Blob, b"hello\n").is_ok());
        assert!(verify(&id, ObjectType::Blob, b"goodbye\n").is_err());
    }
}
