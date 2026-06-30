//! Annotated tag objects.
//!
//! A tag's payload mirrors a commit's header/message shape:
//!
//! ```text
//! object <hex-oid>\n
//! type <object-type>\n
//! tag <tag-name>\n
//! tagger <name> <email> <timestamp> <tz>\n
//! \n
//! <message bytes>          (often followed by a PGP/SSH signature)
//! ```
//!
//! The `tagger` line is optional in very old tags, so it is modeled as
//! [`Option`]. The signature, when present, lives inside the message bytes
//! (git does not separate it), so it round-trips for free.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::object::ObjectType;
use crate::oid::{HashAlgo, ObjectId};

use super::signature::Signature;

/// A parsed annotated tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// The object this tag points at.
    pub object: ObjectId,
    /// The type of the pointed-at object.
    pub object_type: ObjectType,
    /// The tag's short name (e.g. `v1.0.0`), raw bytes.
    pub name: Vec<u8>,
    /// Who created the tag (absent in some historical tags).
    pub tagger: Option<Signature>,
    /// The tag message and any trailing signature, raw bytes.
    pub message: Vec<u8>,
}

impl Tag {
    /// Parses a tag payload under the repository's hash algorithm.
    pub fn parse(algo: HashAlgo, payload: &[u8]) -> Result<Self> {
        let split = find_double_newline(payload)
            .ok_or_else(|| Error::Parse("tag: missing blank line before message".into()))?;
        let header = &payload[..split];
        let message = payload[split + 2..].to_vec();

        let mut object = None;
        let mut object_type = None;
        let mut name = None;
        let mut tagger = None;

        for line in header.split(|&b| b == b'\n') {
            if let Some(v) = line.strip_prefix(b"object ") {
                let s = core::str::from_utf8(v)
                    .map_err(|_| Error::Parse("tag: non-utf8 oid".into()))?;
                object = Some(ObjectId::from_hex(algo, s.trim())?);
            } else if let Some(v) = line.strip_prefix(b"type ") {
                let s = core::str::from_utf8(v)
                    .map_err(|_| Error::Parse("tag: non-utf8 type".into()))?;
                object_type = Some(ObjectType::from_str(s.trim())?);
            } else if let Some(v) = line.strip_prefix(b"tag ") {
                name = Some(v.to_vec());
            } else if let Some(v) = line.strip_prefix(b"tagger ") {
                tagger = Some(Signature::parse(v)?);
            }
        }

        Ok(Tag {
            object: object.ok_or_else(|| Error::Parse("tag: missing object".into()))?,
            object_type: object_type.ok_or_else(|| Error::Parse("tag: missing type".into()))?,
            name: name.ok_or_else(|| Error::Parse("tag: missing tag name".into()))?,
            tagger,
            message,
        })
    }

    /// Serializes the tag back to its canonical payload bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"object ");
        out.extend_from_slice(self.object.to_hex().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(b"type ");
        out.extend_from_slice(self.object_type.as_str().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(b"tag ");
        out.extend_from_slice(&self.name);
        out.push(b'\n');
        if let Some(t) = &self.tagger {
            out.extend_from_slice(b"tagger ");
            t.write_to(&mut out);
            out.push(b'\n');
        }
        out.push(b'\n');
        out.extend_from_slice(&self.message);
        out
    }
}

fn find_double_newline(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"object 0123456789012345678901234567890123456789\n\
type commit\n\
tag v1.0.0\n\
tagger Alice <alice@example.com> 1700000000 +0900\n\
\n\
Release 1.0.0\n";

    #[test]
    fn roundtrip() {
        let t = Tag::parse(HashAlgo::Sha1, SAMPLE).unwrap();
        assert_eq!(t.object_type, ObjectType::Commit);
        assert_eq!(t.name, b"v1.0.0");
        assert_eq!(t.tagger.as_ref().unwrap().name, b"Alice");
        assert_eq!(t.serialize(), SAMPLE);
    }
}
