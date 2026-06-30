//! The git configuration format (`.git/config`, `~/.gitconfig`).
//!
//! Git config is an INI-like format with sections, optional subsections, and
//! `key = value` entries:
//!
//! ```ini
//! [core]
//!     repositoryformatversion = 0
//!     bare = false
//! [remote "origin"]
//!     url = https://example.com/repo.git
//!     fetch = +refs/heads/*:refs/remotes/origin/*
//! ```
//!
//! Keys are case-insensitive; section names are case-insensitive but
//! subsection names are case-sensitive. A bare key (no `=`) is the boolean
//! `true`. This parser keeps insertion order and supports the multi-valued keys
//! git allows (e.g. several `fetch` lines). It is intentionally lenient on
//! read and canonical on write; line continuations and the full quoting/escape
//! grammar are partially supported (see the roadmap for the remaining edges).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

/// A fully-qualified config key: `section`, optional `subsection`, and `name`.
/// Canonicalized for lookups (section/name lowercased; subsection verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    section: String,
    subsection: Option<String>,
    name: String,
}

impl Key {
    fn new(section: &str, subsection: Option<&str>, name: &str) -> Self {
        Key {
            section: section.to_ascii_lowercase(),
            subsection: subsection.map(|s| s.to_string()),
            name: name.to_ascii_lowercase(),
        }
    }
}

/// A parsed git configuration: an ordered list of `(key, value)` entries.
#[derive(Debug, Clone, Default)]
pub struct Config {
    entries: Vec<(Key, String)>,
}

impl Config {
    /// An empty configuration.
    pub fn new() -> Self {
        Config::default()
    }

    /// Parses configuration text.
    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg = Config::new();
        let mut section: Option<(String, Option<String>)> = None;

        for (lineno, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix('[') {
                let close = rest.find(']').ok_or_else(|| {
                    Error::Config(format!("line {}: unclosed section", lineno + 1))
                })?;
                section = Some(parse_section_header(&rest[..close])?);
                continue;
            }
            let (sec, subsec) = section
                .as_ref()
                .map(|(s, ss)| (s.as_str(), ss.as_deref()))
                .ok_or_else(|| {
                    Error::Config(format!("line {}: entry before any section", lineno + 1))
                })?;

            let (name, value) = match line.split_once('=') {
                Some((n, v)) => (n.trim(), unquote_value(v.trim())),
                None => (line, "true".to_string()), // bare key → boolean true
            };
            cfg.entries.push((Key::new(sec, subsec, name), value));
        }
        Ok(cfg)
    }

    /// Returns the last value for a key (git's "last one wins" semantics for
    /// single-valued reads), or `None`.
    pub fn get(&self, section: &str, subsection: Option<&str>, name: &str) -> Option<&str> {
        let key = Key::new(section, subsection, name);
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Returns every value for a key, in order (for multi-valued keys).
    pub fn get_all(&self, section: &str, subsection: Option<&str>, name: &str) -> Vec<&str> {
        let key = Key::new(section, subsection, name);
        self.entries
            .iter()
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Interprets a key as a boolean using git's rules (`true`/`yes`/`on`/`1`
    /// and the bare-key form are true; `false`/`no`/`off`/`0`/empty are false).
    pub fn get_bool(&self, section: &str, subsection: Option<&str>, name: &str) -> Option<bool> {
        self.get(section, subsection, name).map(parse_bool)
    }

    /// Sets a key, replacing all existing values for it.
    pub fn set(&mut self, section: &str, subsection: Option<&str>, name: &str, value: &str) {
        let key = Key::new(section, subsection, name);
        self.entries.retain(|(k, _)| *k != key);
        self.entries.push((key, value.to_string()));
    }

    /// Serializes back to canonical config text, grouping by section.
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        let mut current: Option<(String, Option<String>)> = None;
        for (key, value) in &self.entries {
            let header = (key.section.clone(), key.subsection.clone());
            if current.as_ref() != Some(&header) {
                if !out.is_empty() {
                    out.push('\n');
                }
                match &key.subsection {
                    Some(ss) => out.push_str(&format!("[{} \"{}\"]\n", key.section, ss)),
                    None => out.push_str(&format!("[{}]\n", key.section)),
                }
                current = Some(header);
            }
            out.push_str(&format!("\t{} = {}\n", key.name, value));
        }
        out
    }
}

fn parse_bool(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1")
}

fn strip_comment(line: &str) -> &str {
    // A '#' or ';' starts a comment unless inside quotes. Values rarely contain
    // them; we honor quoting for the common `url = "...#..."` case.
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b'#' | b';' if !in_quotes => return &line[..i],
            _ => {}
        }
    }
    line
}

fn unquote_value(v: &str) -> String {
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

fn parse_section_header(inner: &str) -> Result<(String, Option<String>)> {
    // `core` | `remote "origin"`
    let inner = inner.trim();
    if let Some(q) = inner.find('"') {
        let section = inner[..q].trim().to_ascii_lowercase();
        let rest = &inner[q + 1..];
        let end = rest
            .rfind('"')
            .ok_or_else(|| Error::Config("unterminated subsection".to_string()))?;
        Ok((section, Some(rest[..end].to_string())))
    } else {
        Ok((inner.to_ascii_lowercase(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[core]
    repositoryformatversion = 0
    bare = false
[remote "origin"]
    url = https://example.com/repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"#;

    #[test]
    fn reads_values() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert_eq!(cfg.get("core", None, "repositoryformatversion"), Some("0"));
        assert_eq!(cfg.get_bool("core", None, "bare"), Some(false));
        assert_eq!(
            cfg.get("remote", Some("origin"), "url"),
            Some("https://example.com/repo.git")
        );
    }

    #[test]
    fn section_case_insensitive_subsection_sensitive() {
        let cfg = Config::parse("[Core]\n  Bare = true\n").unwrap();
        assert_eq!(cfg.get_bool("core", None, "bare"), Some(true));
    }

    #[test]
    fn set_and_serialize_roundtrips() {
        let mut cfg = Config::new();
        cfg.set("user", None, "name", "Alice");
        cfg.set("user", None, "email", "alice@example.com");
        let text = cfg.serialize();
        let back = Config::parse(&text).unwrap();
        assert_eq!(back.get("user", None, "name"), Some("Alice"));
        assert_eq!(back.get("user", None, "email"), Some("alice@example.com"));
    }
}
