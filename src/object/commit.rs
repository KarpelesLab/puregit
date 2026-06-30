//! Commit objects.
//!
//! A commit's payload is a header block followed by a blank line and the
//! message:
//!
//! ```text
//! tree <hex-oid>\n
//! parent <hex-oid>\n        (zero or more, in order)
//! author <name> <email> <timestamp> <tz>\n
//! committer <name> <email> <timestamp> <tz>\n
//! <extra headers...>        (e.g. gpgsig, encoding, mergetag)\n
//! \n
//! <message bytes>
//! ```
//!
//! [`Commit`] parses the four well-known headers into typed fields and keeps
//! any remaining header lines verbatim ([`Commit::extra_headers`]) so signed or
//! otherwise-extended commits round-trip byte-for-byte through
//! [`Commit::serialize`].

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::{HashAlgo, ObjectId};

use super::signature::Signature;

/// A parsed commit object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// The root tree this commit snapshots.
    pub tree: ObjectId,
    /// Parent commits, in order (empty for a root commit, 2+ for a merge).
    pub parents: Vec<ObjectId>,
    /// Who wrote the change.
    pub author: Signature,
    /// Who created the commit (may differ from author, e.g. after a rebase).
    pub committer: Signature,
    /// Any header lines after `committer` and before the blank line, kept
    /// verbatim (including their trailing newline and any continuation lines).
    /// This preserves `gpgsig`, `encoding`, `mergetag`, etc.
    pub extra_headers: Vec<u8>,
    /// The commit message (everything after the blank line), raw bytes.
    pub message: Vec<u8>,
}

impl Commit {
    /// Parses a commit payload under the repository's hash algorithm.
    pub fn parse(algo: HashAlgo, payload: &[u8]) -> Result<Self> {
        // Split header block from message at the first blank line ("\n\n").
        let split = find_double_newline(payload)
            .ok_or_else(|| Error::Parse("commit: missing blank line before message".into()))?;
        let header = &payload[..split];
        let message = payload[split + 2..].to_vec();

        let mut tree = None;
        let mut parents = Vec::new();
        let mut author = None;
        let mut committer = None;
        let mut extra = Vec::new();

        for line in HeaderLines::new(header) {
            if let Some(v) = line.strip_prefix(b"tree ") {
                tree = Some(parse_hex_oid(algo, v)?);
            } else if let Some(v) = line.strip_prefix(b"parent ") {
                parents.push(parse_hex_oid(algo, v)?);
            } else if let Some(v) = line.strip_prefix(b"author ") {
                author = Some(Signature::parse(v)?);
            } else if let Some(v) = line.strip_prefix(b"committer ") {
                committer = Some(Signature::parse(v)?);
            } else {
                // Unknown header (or a continuation line, which HeaderLines
                // keeps attached) — preserve verbatim.
                extra.extend_from_slice(line);
                extra.push(b'\n');
            }
        }

        Ok(Commit {
            tree: tree.ok_or_else(|| Error::Parse("commit: missing tree".into()))?,
            parents,
            author: author.ok_or_else(|| Error::Parse("commit: missing author".into()))?,
            committer: committer.ok_or_else(|| Error::Parse("commit: missing committer".into()))?,
            extra_headers: extra,
            message,
        })
    }

    /// Serializes the commit back to its canonical payload bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"tree ");
        out.extend_from_slice(self.tree.to_hex().as_bytes());
        out.push(b'\n');
        for p in &self.parents {
            out.extend_from_slice(b"parent ");
            out.extend_from_slice(p.to_hex().as_bytes());
            out.push(b'\n');
        }
        out.extend_from_slice(b"author ");
        self.author.write_to(&mut out);
        out.push(b'\n');
        out.extend_from_slice(b"committer ");
        self.committer.write_to(&mut out);
        out.push(b'\n');
        out.extend_from_slice(&self.extra_headers);
        out.push(b'\n');
        out.extend_from_slice(&self.message);
        out
    }

    /// The first line of the message (the commit summary).
    pub fn summary(&self) -> &[u8] {
        let end = self
            .message
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(self.message.len());
        &self.message[..end]
    }
}

/// Iterator over header lines that folds RFC-822-style continuation lines
/// (those beginning with a space) into the preceding logical line, so a
/// multi-line `gpgsig` header is yielded as one slice.
struct HeaderLines<'a> {
    rest: &'a [u8],
}

impl<'a> HeaderLines<'a> {
    fn new(header: &'a [u8]) -> Self {
        HeaderLines { rest: header }
    }
}

impl<'a> Iterator for HeaderLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        let mut idx = 0;
        loop {
            match self.rest[idx..].iter().position(|&b| b == b'\n') {
                None => {
                    let line = self.rest;
                    self.rest = &[];
                    return Some(line);
                }
                Some(nl) => {
                    let abs = idx + nl;
                    // A following line starting with ' ' is a continuation.
                    if self.rest.get(abs + 1) == Some(&b' ') {
                        idx = abs + 1;
                        continue;
                    }
                    let line = &self.rest[..abs];
                    self.rest = &self.rest[abs + 1..];
                    return Some(line);
                }
            }
        }
    }
}

fn parse_hex_oid(algo: HashAlgo, v: &[u8]) -> Result<ObjectId> {
    let s = core::str::from_utf8(v).map_err(|_| Error::Parse("commit: non-utf8 oid".into()))?;
    ObjectId::from_hex(algo, s.trim())
}

/// Finds the byte offset of the first `\n\n` (header/message separator).
fn find_double_newline(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"tree 0123456789012345678901234567890123456789\n\
parent abcdefabcdefabcdefabcdefabcdefabcdefabcd\n\
author Alice <alice@example.com> 1700000000 +0900\n\
committer Bob <bob@example.com> 1700000100 -0500\n\
\n\
Initial commit\n\nBody text.\n";

    #[test]
    fn roundtrip() {
        let c = Commit::parse(HashAlgo::Sha1, SAMPLE).unwrap();
        assert_eq!(c.parents.len(), 1);
        assert_eq!(c.author.name, b"Alice");
        assert_eq!(c.committer.email, b"bob@example.com");
        assert_eq!(c.summary(), b"Initial commit");
        assert_eq!(c.serialize(), SAMPLE);
    }
}
