//! Author / committer / tagger signatures.
//!
//! A git signature is the `name <email> timestamp tz` line that appears in
//! commit `author`/`committer` and tag `tagger` headers. The name and email are
//! kept as raw bytes (git does not require UTF-8), and the time is stored as
//! seconds since the Unix epoch plus the committer's textual timezone offset
//! (`+0900`, `-0500`), preserved exactly so signatures round-trip.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// A `name <email> <unix-seconds> <tz>` identity-and-time stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Display name (raw bytes; everything before ` <`).
    pub name: Vec<u8>,
    /// Email address (raw bytes; between `<` and `>`).
    pub email: Vec<u8>,
    /// Seconds since the Unix epoch.
    pub time: i64,
    /// Timezone offset as written, e.g. `+0900` — kept verbatim because git
    /// reproduces the original string rather than normalizing it.
    pub tz: Vec<u8>,
}

impl Signature {
    /// Parses a signature line (the bytes after `author `/`committer `/
    /// `tagger `, with no trailing newline).
    pub fn parse(line: &[u8]) -> Result<Self> {
        let lt = line
            .iter()
            .position(|&b| b == b'<')
            .ok_or_else(|| Error::Parse("signature: missing '<'".into()))?;
        let gt = line
            .iter()
            .position(|&b| b == b'>')
            .ok_or_else(|| Error::Parse("signature: missing '>'".into()))?;
        if gt < lt {
            return Err(Error::Parse("signature: '>' before '<'".into()));
        }

        // Name is everything before " <", trimmed of the single separating space.
        let name = trim_trailing_space(&line[..lt]).to_vec();
        let email = line[lt + 1..gt].to_vec();

        // After "> " comes "<seconds> <tz>".
        let rest = trim_leading_space(&line[gt + 1..]);
        let sp = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| Error::Parse("signature: missing time/tz separator".into()))?;
        let secs = core::str::from_utf8(&rest[..sp])
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| Error::Parse("signature: invalid timestamp".into()))?;
        let tz = rest[sp + 1..].to_vec();

        Ok(Signature {
            name,
            email,
            time: secs,
            tz,
        })
    }

    /// Appends the canonical `name <email> seconds tz` form to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.name);
        out.extend_from_slice(b" <");
        out.extend_from_slice(&self.email);
        out.extend_from_slice(b"> ");
        push_i64(out, self.time);
        out.push(b' ');
        out.extend_from_slice(&self.tz);
    }
}

fn trim_trailing_space(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && s[end - 1] == b' ' {
        end -= 1;
    }
    &s[..end]
}

fn trim_leading_space(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && s[start] == b' ' {
        start += 1;
    }
    &s[start..]
}

fn push_i64(out: &mut Vec<u8>, n: i64) {
    use alloc::string::ToString;
    out.extend_from_slice(n.to_string().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let line = b"Alice Example <alice@example.com> 1700000000 +0900";
        let sig = Signature::parse(line).unwrap();
        assert_eq!(sig.name, b"Alice Example");
        assert_eq!(sig.email, b"alice@example.com");
        assert_eq!(sig.time, 1700000000);
        assert_eq!(sig.tz, b"+0900");
        let mut out = Vec::new();
        sig.write_to(&mut out);
        assert_eq!(out, line);
    }
}
