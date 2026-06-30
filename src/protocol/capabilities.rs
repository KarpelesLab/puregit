//! Protocol capabilities.
//!
//! In the smart protocol the server advertises a space-separated capability
//! list (on the first ref line in v0/v1, or in the `capabilities^{}` section in
//! v2). Capabilities are either flags (`thin-pack`, `ofs-delta`) or `key=value`
//! (`agent=git/2.40`, `object-format=sha256`). This is a small ordered,
//! case-sensitive set with convenience accessors.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A parsed capability set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    items: Vec<(String, Option<String>)>,
}

impl Capabilities {
    /// An empty set.
    pub fn new() -> Self {
        Capabilities::default()
    }

    /// Parses a space-separated capability string (NUL-trimmed by the caller).
    pub fn parse(s: &str) -> Self {
        let mut items = Vec::new();
        for token in s.split(' ').filter(|t| !t.is_empty()) {
            match token.split_once('=') {
                Some((k, v)) => items.push((k.to_string(), Some(v.to_string()))),
                None => items.push((token.to_string(), None)),
            }
        }
        Capabilities { items }
    }

    /// Whether a capability (by key) is present.
    pub fn has(&self, key: &str) -> bool {
        self.items.iter().any(|(k, _)| k == key)
    }

    /// The value of a `key=value` capability, if present and valued.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref())
    }

    /// Adds a flag capability.
    pub fn add_flag(&mut self, key: &str) {
        self.items.push((key.to_string(), None));
    }

    /// Adds a `key=value` capability.
    pub fn add_value(&mut self, key: &str, value: &str) {
        self.items.push((key.to_string(), Some(value.to_string())));
    }

    /// Serializes back to the space-separated wire form.
    pub fn to_wire(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(self.items.len());
        for (k, v) in &self.items {
            match v {
                Some(v) => parts.push(alloc::format!("{k}={v}")),
                None => parts.push(k.clone()),
            }
        }
        parts.join(" ")
    }

    /// The advertised `object-format`, mapped to a [`crate::oid::HashAlgo`] when recognized.
    pub fn object_format(&self) -> Option<crate::oid::HashAlgo> {
        match self.get("object-format") {
            Some("sha1") => Some(crate::oid::HashAlgo::Sha1),
            Some("sha256") => Some(crate::oid::HashAlgo::Sha256),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_query() {
        let caps = Capabilities::parse(
            "multi_ack thin-pack ofs-delta agent=git/2.40 object-format=sha256",
        );
        assert!(caps.has("thin-pack"));
        assert!(caps.has("ofs-delta"));
        assert_eq!(caps.get("agent"), Some("git/2.40"));
        assert_eq!(caps.object_format(), Some(crate::oid::HashAlgo::Sha256));
        assert!(!caps.has("missing"));
    }
}
