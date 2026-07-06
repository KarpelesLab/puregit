//! Partial-clone object filters (`git clone --filter=…`).
//!
//! A `filter` spec lets a fetch omit some objects — most commonly the blobs — so
//! a client can clone a large history without its file contents and lazily fetch
//! them later (a "partial" or "promisor" clone). This module parses the small
//! subset of filter specs puregit's server honours and decides which objects a
//! pack keeps.

use alloc::string::String;

/// A parsed object filter for a partial clone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFilter {
    /// `blob:none` — omit every blob.
    BlobNone,
    /// `blob:limit=<n>` — omit blobs of at least `n` bytes (smaller blobs are
    /// kept). Git's `blob:limit` is an *at-or-above* threshold.
    BlobLimit(u64),
    /// No filtering, or an unrecognised spec — every reachable object is sent.
    /// (Sending more than requested is always safe; the client keeps what it
    /// asked for.)
    None,
}

impl ObjectFilter {
    /// Parses a filter spec (`blob:none`, `blob:limit=<n>` with an optional
    /// `k`/`m`/`g` suffix). Anything else parses to [`ObjectFilter::None`].
    pub fn parse(spec: &str) -> Self {
        let spec = spec.trim();
        if spec == "blob:none" {
            return ObjectFilter::BlobNone;
        }
        if let Some(limit) = spec.strip_prefix("blob:limit=")
            && let Some(bytes) = parse_size(limit)
        {
            return ObjectFilter::BlobLimit(bytes);
        }
        ObjectFilter::None
    }

    /// Whether a blob of `size` bytes is kept under this filter.
    pub fn keeps_blob(&self, size: usize) -> bool {
        match self {
            ObjectFilter::BlobNone => false,
            ObjectFilter::BlobLimit(limit) => (size as u64) < *limit,
            ObjectFilter::None => true,
        }
    }

    /// Whether this filter omits any objects at all (a real partial clone).
    pub fn is_active(&self) -> bool {
        !matches!(self, ObjectFilter::None)
    }
}

/// Parses a byte count with an optional `k`/`m`/`g` (1024-based) suffix.
fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let (digits, mult) = match text.chars().last() {
        Some('k') | Some('K') => (&text[..text.len() - 1], 1024),
        Some('m') | Some('M') => (&text[..text.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&text[..text.len() - 1], 1024 * 1024 * 1024),
        _ => (text, 1),
    };
    digits.parse::<u64>().ok().map(|n| n * mult)
}

/// Turns an optional filter spec string into an [`ObjectFilter`].
pub fn from_spec(spec: Option<&str>) -> ObjectFilter {
    spec.map(ObjectFilter::parse).unwrap_or(ObjectFilter::None)
}

/// A filter spec as a [`String`] for a request line, if active.
pub fn to_spec(filter: &ObjectFilter) -> Option<String> {
    match filter {
        ObjectFilter::BlobNone => Some("blob:none".into()),
        ObjectFilter::BlobLimit(n) => Some(alloc::format!("blob:limit={n}")),
        ObjectFilter::None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_applies_filters() {
        assert_eq!(ObjectFilter::parse("blob:none"), ObjectFilter::BlobNone);
        assert!(!ObjectFilter::BlobNone.keeps_blob(0));
        assert!(!ObjectFilter::BlobNone.keeps_blob(1000));

        assert_eq!(
            ObjectFilter::parse("blob:limit=1k"),
            ObjectFilter::BlobLimit(1024)
        );
        let f = ObjectFilter::parse("blob:limit=100");
        assert!(f.keeps_blob(99)); // below the limit is kept
        assert!(!f.keeps_blob(100)); // at the limit is omitted
        assert!(!f.keeps_blob(500));

        // Unknown specs disable filtering (safe: send everything).
        assert_eq!(ObjectFilter::parse("tree:0"), ObjectFilter::None);
        assert!(ObjectFilter::None.keeps_blob(usize::MAX));
        assert!(!ObjectFilter::None.is_active());
    }

    #[test]
    fn round_trips_a_spec() {
        for spec in ["blob:none", "blob:limit=2048"] {
            let f = ObjectFilter::parse(spec);
            assert_eq!(to_spec(&f).as_deref(), Some(spec));
        }
    }
}
