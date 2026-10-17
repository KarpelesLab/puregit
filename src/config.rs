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
//! git allows (e.g. several `fetch` lines). Values follow git's quoting,
//! escape, comment and line-continuation rules on read, and are quoted and
//! escaped on write exactly as far as git needs to read them back unchanged
//! (`git config` / libgit2 agree on every value either side writes).

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
    ///
    /// Follows git's grammar: `[section]`, `[section "subsection"]` (with `\"`
    /// and `\\` escapes in the subsection) and the legacy `[section.subsection]`
    /// headers; `name = value` entries whose value may be partly or wholly
    /// double-quoted, may use the `\n`, `\t`, `\b`, `\"` and `\\` escapes, may
    /// continue onto the next line with a trailing backslash, and ends at an
    /// unquoted `#` or `;` comment. Unquoted whitespace is trimmed at both ends
    /// and every unquoted whitespace character inside the value reads as a
    /// space (a tab must be quoted or escaped to survive); a bare `name` (no
    /// `=`) is the boolean `true`.
    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg = Config::new();
        let mut p = Parser {
            b: text.strip_prefix('\u{feff}').unwrap_or(text).as_bytes(),
            i: 0,
            line: 1,
        };
        let mut section: Option<(String, Option<String>)> = None;
        loop {
            p.skip_whitespace();
            let Some(c) = p.peek() else { break };
            match c {
                b'#' | b';' => p.skip_line(),
                b'[' => {
                    p.i += 1;
                    section = Some(p.section_header()?);
                }
                c if c.is_ascii_alphabetic() => {
                    let (sec, subsec) = section.as_ref().ok_or_else(|| {
                        Error::Config(format!("line {}: entry before any section", p.line))
                    })?;
                    let name = p.key_name();
                    p.skip_blanks();
                    let value = if p.peek() == Some(b'=') {
                        p.i += 1;
                        p.value()?
                    } else {
                        match p.peek() {
                            None | Some(b'\n' | b'\r' | b'#' | b';') => "true".to_string(),
                            Some(_) => {
                                return Err(Error::Config(format!(
                                    "line {}: bad config line",
                                    p.line
                                )));
                            }
                        }
                    };
                    cfg.entries
                        .push((Key::new(sec, subsec.as_deref(), &name), value));
                }
                _ => {
                    return Err(Error::Config(format!("line {}: bad config line", p.line)));
                }
            }
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
                    Some(ss) => out.push_str(&format!(
                        "[{} \"{}\"]\n",
                        key.section,
                        escape_subsection(ss)
                    )),
                    None => out.push_str(&format!("[{}]\n", key.section)),
                }
                current = Some(header);
            }
            out.push('\t');
            out.push_str(&key.name);
            out.push_str(" = ");
            out.push_str(&quote_value(value));
            out.push('\n');
        }
        out
    }
}

fn parse_bool(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1")
}

/// Formats a value so git (and libgit2) read back exactly `value`: special
/// characters are escaped, and the whole value is double-quoted when it starts
/// or ends with a space or contains a comment character (git's `quote_value`).
fn quote_value(value: &str) -> String {
    let needs_quotes = value.starts_with(' ')
        || value.ends_with(' ')
        || value.contains('#')
        || value.contains(';');
    let mut out = String::with_capacity(value.len() + 2);
    if needs_quotes {
        out.push('"');
    }
    for c in value.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    if needs_quotes {
        out.push('"');
    }
    out
}

/// Escapes a subsection name for a `[section "subsection"]` header.
fn escape_subsection(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A cursor over config text. Every syntactic character is ASCII, so the
/// parser works on bytes and only ever splits the UTF-8 input at ASCII
/// boundaries.
struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    line: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        if c == b'\n' {
            self.line += 1;
        }
        Some(c)
    }

    /// Skips whitespace, including newlines.
    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            self.bump();
        }
    }

    /// Skips spaces and tabs (not newlines).
    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r')) {
            self.i += 1;
        }
    }

    /// Skips to (and past) the end of the current line.
    fn skip_line(&mut self) {
        while let Some(c) = self.bump() {
            if c == b'\n' {
                break;
            }
        }
    }

    fn text(&self, start: usize, end: usize) -> String {
        String::from_utf8_lossy(&self.b[start..end]).into_owned()
    }

    /// A key name: alphanumerics and `-`.
    fn key_name(&mut self) -> String {
        let start = self.i;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            self.i += 1;
        }
        self.text(start, self.i)
    }

    /// The rest of a section header after `[`, through `]`.
    fn section_header(&mut self) -> Result<(String, Option<String>)> {
        let start = self.i;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
        {
            self.i += 1;
        }
        let name = self.text(start, self.i).to_ascii_lowercase();
        if name.is_empty() {
            return Err(Error::Config(format!(
                "line {}: empty section name",
                self.line
            )));
        }
        match self.bump() {
            Some(b']') => {
                // Legacy `[section.subsection]`: the subsection is
                // case-insensitive and stored lowercased.
                Ok(match name.split_once('.') {
                    Some((sec, sub)) => (sec.to_string(), Some(sub.to_string())),
                    None => (name, None),
                })
            }
            Some(b' ' | b'\t') => {
                self.skip_blanks();
                if self.bump() != Some(b'"') {
                    return Err(Error::Config(format!(
                        "line {}: bad section header",
                        self.line
                    )));
                }
                let mut sub = Vec::new();
                loop {
                    match self.bump() {
                        None | Some(b'\n') => {
                            return Err(Error::Config(format!(
                                "line {}: unterminated subsection",
                                self.line
                            )));
                        }
                        Some(b'"') => break,
                        Some(b'\\') => match self.bump() {
                            None | Some(b'\n') => {
                                return Err(Error::Config(format!(
                                    "line {}: unterminated subsection",
                                    self.line
                                )));
                            }
                            Some(c) => sub.push(c),
                        },
                        Some(c) => sub.push(c),
                    }
                }
                if self.bump() != Some(b']') {
                    return Err(Error::Config(format!(
                        "line {}: bad section header",
                        self.line
                    )));
                }
                Ok((name, Some(String::from_utf8_lossy(&sub).into_owned())))
            }
            _ => Err(Error::Config(format!(
                "line {}: unclosed section",
                self.line
            ))),
        }
    }

    /// A value after `=`, through the end of its (possibly continued) line.
    fn value(&mut self) -> Result<String> {
        let mut out: Vec<u8> = Vec::new();
        let mut in_quotes = false;
        let mut in_comment = false;
        let mut pending_space = 0usize;
        loop {
            let Some(c) = self.bump() else {
                if in_quotes {
                    return Err(Error::Config(format!(
                        "line {}: unterminated quoted value",
                        self.line
                    )));
                }
                break;
            };
            if c == b'\n' {
                if in_quotes {
                    return Err(Error::Config(format!(
                        "line {}: unterminated quoted value",
                        self.line - 1
                    )));
                }
                break;
            }
            if in_comment {
                continue;
            }
            if c.is_ascii_whitespace() && !in_quotes {
                if !out.is_empty() {
                    pending_space += 1;
                }
                continue;
            }
            if !in_quotes && (c == b'#' || c == b';') {
                in_comment = true;
                continue;
            }
            out.extend(core::iter::repeat_n(
                b' ',
                core::mem::take(&mut pending_space),
            ));
            match c {
                b'\\' => match self.bump() {
                    Some(b'\n') => {} // line continuation
                    Some(b'\r') if self.peek() == Some(b'\n') => {
                        self.bump();
                    }
                    Some(b'n') => out.push(b'\n'),
                    Some(b't') => out.push(b'\t'),
                    Some(b'b') => out.push(0x08),
                    Some(c @ (b'"' | b'\\')) => out.push(c),
                    _ => {
                        return Err(Error::Config(format!(
                            "line {}: bad escape in value",
                            self.line
                        )));
                    }
                },
                b'"' => in_quotes = !in_quotes,
                c => out.push(c),
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
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
    fn parses_quotes_escapes_comments_and_continuations() {
        let text = concat!(
            "[interop]\n",
            "\tquoted = \"  padded  \"\n",
            "\thash = \"has # hash\" ; trailing comment\n",
            "\tescapes = \"say \\\"hi\\\"\" C:\\\\dir a\\tb l1\\nl2\n",
            "\tpartial = un\"quoted # part\"  rest   # comment\n",
            "\tspaces =   a  b\t \n",
            "\tcont = first \\\n",
            "  second\n",
            "\tempty =\n",
            "\tbare\n",
            "[remote \"we\\\"ird \\\\ name\"] # comment\n",
            "\turl = x\r\n",
            "[Legacy.SubSection]\n",
            "\tkey = v\n",
        );
        let cfg = Config::parse(text).unwrap();
        let get = |n: &str| cfg.get("interop", None, n);
        assert_eq!(get("quoted"), Some("  padded  "));
        assert_eq!(get("hash"), Some("has # hash"));
        assert_eq!(get("escapes"), Some("say \"hi\" C:\\dir a\tb l1\nl2"));
        assert_eq!(get("partial"), Some("unquoted # part  rest"));
        assert_eq!(get("spaces"), Some("a  b"));
        assert_eq!(get("cont"), Some("first   second"));
        assert_eq!(get("empty"), Some(""));
        assert_eq!(cfg.get_bool("interop", None, "bare"), Some(true));
        assert_eq!(cfg.get("remote", Some("we\"ird \\ name"), "url"), Some("x"));
        assert_eq!(cfg.get("legacy", Some("subsection"), "key"), Some("v"));
        assert!(Config::parse("[a]\n\tk = \"open\n").is_err());
        assert!(Config::parse("[a]\n\tk = bad \\q escape\n").is_err());
    }

    #[test]
    fn serialize_quotes_and_escapes_what_git_needs() {
        let values = [
            "  padded  ",
            "has # hash",
            "semi ; colon",
            "say \"hi\"",
            "C:\\Users\\x",
            "a\tb",
            "l1\nl2",
            "",
            "plain words",
        ];
        let mut cfg = Config::new();
        for (i, v) in values.iter().enumerate() {
            cfg.set("interop", None, &format!("k{i}"), v);
        }
        cfg.set("remote", Some("we\"ird \\ name"), "url", "x");
        let text = cfg.serialize();
        assert!(text.contains("\tk0 = \"  padded  \"\n"));
        assert!(text.contains("\tk3 = say \\\"hi\\\"\n"));
        assert!(text.contains("\tk4 = C:\\\\Users\\\\x\n"));
        assert!(text.contains("[remote \"we\\\"ird \\\\ name\"]\n"));
        let back = Config::parse(&text).unwrap();
        for (i, v) in values.iter().enumerate() {
            assert_eq!(back.get("interop", None, &format!("k{i}")), Some(*v));
        }
        assert_eq!(
            back.get("remote", Some("we\"ird \\ name"), "url"),
            Some("x")
        );
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
