//! `.gitattributes` matching for LFS.
//!
//! Git LFS marks paths with a `.gitattributes` entry like
//! `*.psd filter=lfs diff=lfs merge=lfs -text`. [`Attributes`] parses those
//! lines and answers whether a given path is LFS-tracked, applying the usual
//! git rule that the *last* matching pattern wins.
//!
//! Pattern support covers the common cases: `*` (any run within a path
//! component), `?` (one character), a leading `/` or an embedded `/` anchors the
//! pattern to the repository root, and a pattern without a slash matches by
//! basename in any directory. Full brace/character-class globs are a later
//! refinement.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Parsed `.gitattributes` LFS rules.
#[derive(Debug, Clone, Default)]
pub struct Attributes {
    /// `(pattern, lfs?)` in file order; a later match overrides an earlier one.
    rules: Vec<(String, bool)>,
}

impl Attributes {
    /// Parses `.gitattributes` text, keeping only the `filter=lfs` rules (and
    /// their negations `-filter`/`filter=` which un-track a path).
    pub fn parse(text: &str) -> Attributes {
        let mut rules = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(pattern) = parts.next() else {
                continue;
            };
            let mut lfs: Option<bool> = None;
            for attr in parts {
                if attr == "filter=lfs" {
                    lfs = Some(true);
                } else if attr == "-filter" || attr == "filter=" || attr == "!filter" {
                    lfs = Some(false);
                }
            }
            if let Some(is_lfs) = lfs {
                rules.push((pattern.to_string(), is_lfs));
            }
        }
        Attributes { rules }
    }

    /// Whether any LFS rule was found at all (so an empty file is cheap to skip).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether `path` (relative, `/`-separated bytes) is LFS-tracked — the last
    /// matching rule decides.
    pub fn is_lfs(&self, path: &[u8]) -> bool {
        let path = core::str::from_utf8(path).unwrap_or("");
        let mut tracked = false;
        for (pattern, is_lfs) in &self.rules {
            if pattern_matches(pattern, path) {
                tracked = *is_lfs;
            }
        }
        tracked
    }
}

/// Matches a gitattributes `pattern` against a repository-relative `path`.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let anchored = pattern.contains('/');
    let pat = pattern.strip_prefix('/').unwrap_or(pattern);
    if anchored {
        glob_match(pat.as_bytes(), path.as_bytes())
    } else {
        // Unanchored: match the basename in any directory.
        let base = path.rsplit('/').next().unwrap_or(path);
        glob_match(pat.as_bytes(), base.as_bytes())
    }
}

/// A small `*`/`?` glob matcher (`*` spans any bytes, including `/`).
fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    // Iterative backtracking wildcard match.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None, 0usize);
    while t < text.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_pattern() {
        let a = Attributes::parse("*.bin filter=lfs diff=lfs merge=lfs -text\n");
        assert!(a.is_lfs(b"a.bin"));
        assert!(a.is_lfs(b"sub/dir/big.bin"));
        assert!(!a.is_lfs(b"a.txt"));
    }

    #[test]
    fn anchored_and_negation() {
        let a = Attributes::parse("assets/** filter=lfs\nassets/small.txt -filter\n# comment\n");
        assert!(a.is_lfs(b"assets/img/photo.png"));
        assert!(!a.is_lfs(b"assets/small.txt")); // negated by the later rule
        assert!(!a.is_lfs(b"src/main.rs"));
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match(b"*.bin", b"x.bin"));
        assert!(glob_match(b"a?c", b"abc"));
        assert!(glob_match(b"assets/**", b"assets/a/b.png"));
        assert!(!glob_match(b"*.bin", b"x.txt"));
    }
}
