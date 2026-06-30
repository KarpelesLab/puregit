//! The git object model: blobs, trees, commits, and tags.
//!
//! Every object has a *type* and a *payload*. On disk a loose object is the
//! payload prefixed with a `"<type> <size>\0"` header and zlib-compressed; in a
//! packfile the same payload appears with a different (varint) header. This
//! module owns the type tag ([`ObjectType`]), the decompressed loose framing
//! ([`parse_loose`] / [`serialize_loose`]), and the typed object
//! representations ([`Object`] and its [`commit`], [`tree`], [`tag`]
//! submodules). Blobs are just opaque bytes.

pub mod commit;
pub mod signature;
pub mod tag;
pub mod tree;

pub use commit::Commit;
pub use signature::Signature;
pub use tag::Tag;
pub use tree::{FileMode, Tree, TreeEntry};

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::hash::loose_header;
use crate::oid::HashAlgo;

/// The four git object types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    /// File contents — opaque bytes.
    Blob,
    /// A directory listing: name → (mode, child object id).
    Tree,
    /// A commit: tree, parents, author/committer, message.
    Commit,
    /// An annotated tag pointing at another object.
    Tag,
}

impl ObjectType {
    /// The keyword used in the loose-object header and tree/tag fields.
    pub const fn as_str(self) -> &'static str {
        match self {
            ObjectType::Blob => "blob",
            ObjectType::Tree => "tree",
            ObjectType::Commit => "commit",
            ObjectType::Tag => "tag",
        }
    }

    /// Parses a type keyword (`blob`/`tree`/`commit`/`tag`).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "blob" => ObjectType::Blob,
            "tree" => ObjectType::Tree,
            "commit" => ObjectType::Commit,
            "tag" => ObjectType::Tag,
            other => {
                use alloc::format;
                return Err(Error::Parse(format!("unknown object type {other:?}")));
            }
        })
    }
}

impl core::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed git object.
///
/// Use [`Object::parse`] to decode a `(type, payload)` pair (as produced by
/// [`parse_loose`] or the packfile reader) into a typed value, and
/// [`Object::payload`] to re-serialize it back to the canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    /// A blob's raw bytes.
    Blob(Vec<u8>),
    /// A parsed tree.
    Tree(Tree),
    /// A parsed commit.
    Commit(Commit),
    /// A parsed tag.
    Tag(Tag),
}

impl Object {
    /// The object's type tag.
    pub fn object_type(&self) -> ObjectType {
        match self {
            Object::Blob(_) => ObjectType::Blob,
            Object::Tree(_) => ObjectType::Tree,
            Object::Commit(_) => ObjectType::Commit,
            Object::Tag(_) => ObjectType::Tag,
        }
    }

    /// Decodes a typed object from its canonical payload (the bytes after the
    /// loose header, or a packed object's inflated content).
    ///
    /// `algo` is the repository's hash algorithm; it is needed because tree
    /// entries embed object ids in their fixed-width *binary* form (20 bytes
    /// for SHA-1, 32 for SHA-256). Commits and tags carry ids as hex and ignore
    /// it; blobs are opaque.
    pub fn parse(algo: HashAlgo, ty: ObjectType, payload: &[u8]) -> Result<Self> {
        Ok(match ty {
            ObjectType::Blob => Object::Blob(payload.to_vec()),
            ObjectType::Tree => Object::Tree(Tree::parse(algo, payload)?),
            ObjectType::Commit => Object::Commit(Commit::parse(algo, payload)?),
            ObjectType::Tag => Object::Tag(Tag::parse(algo, payload)?),
        })
    }

    /// Serializes the object back to its canonical payload bytes (no header).
    pub fn payload(&self) -> Vec<u8> {
        match self {
            Object::Blob(b) => b.clone(),
            Object::Tree(t) => t.serialize(),
            Object::Commit(c) => c.serialize(),
            Object::Tag(t) => t.serialize(),
        }
    }
}

/// Splits a decompressed loose object into its `(type, payload)`.
///
/// Parses the `"<type> <size>\0"` header, validates the declared size against
/// the actual payload length, and returns the type plus a slice of the content.
pub fn parse_loose(bytes: &[u8]) -> Result<(ObjectType, &[u8])> {
    let space = bytes
        .iter()
        .position(|&b| b == b' ')
        .ok_or_else(|| Error::Parse("loose object: missing space in header".into()))?;
    let nul = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::Parse("loose object: missing NUL in header".into()))?;
    if nul < space {
        return Err(Error::Parse("loose object: malformed header".into()));
    }

    let ty = core::str::from_utf8(&bytes[..space])
        .map_err(|_| Error::Parse("loose object: non-utf8 type".into()))?;
    let ty = ObjectType::from_str(ty)?;

    let size_str = core::str::from_utf8(&bytes[space + 1..nul])
        .map_err(|_| Error::Parse("loose object: non-utf8 size".into()))?;
    let size: usize = size_str
        .parse()
        .map_err(|_| Error::Parse("loose object: invalid size".into()))?;

    let payload = &bytes[nul + 1..];
    if payload.len() != size {
        use alloc::format;
        return Err(Error::Parse(format!(
            "loose object: declared size {size} != payload length {}",
            payload.len()
        )));
    }
    Ok((ty, payload))
}

/// Builds the canonical loose-object bytes (`header || payload`) ready to be
/// zlib-compressed and stored. Hashing this (via [`crate::hash`]) yields the
/// object's id.
pub fn serialize_loose(ty: ObjectType, payload: &[u8]) -> Vec<u8> {
    let mut out = loose_header(ty, payload.len());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loose_roundtrip() {
        let bytes = serialize_loose(ObjectType::Blob, b"hello\n");
        assert_eq!(&bytes[..5], b"blob ");
        let (ty, payload) = parse_loose(&bytes).unwrap();
        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(payload, b"hello\n");
    }

    #[test]
    fn rejects_size_mismatch() {
        let mut bytes = serialize_loose(ObjectType::Blob, b"hello\n");
        bytes.push(b'!'); // payload now longer than declared size
        assert!(parse_loose(&bytes).is_err());
    }

    #[test]
    fn object_parse_blob() {
        let o = Object::parse(HashAlgo::Sha1, ObjectType::Blob, b"xyz").unwrap();
        assert_eq!(o.object_type(), ObjectType::Blob);
        assert_eq!(o.payload(), b"xyz");
    }
}
