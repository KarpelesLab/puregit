//! Gitignore matching.
//!
//! [`Ignore`] compiles a set of `.gitignore` / `info/exclude` patterns and
//! decides whether a repository-relative path is ignored. It implements the
//! common gitignore semantics:
//!
//! - blank lines and `#` comments are skipped; a trailing unescaped space run is
//!   trimmed;
//! - a leading `!` negates (re-includes) — the **last** matching pattern wins;
//! - a trailing `/` restricts the pattern to directories (so it ignores a
//!   directory and everything under it, but not a same-named file);
//! - a leading `/` — or any interior `/` — anchors the pattern to the ignore
//!   file's directory; an otherwise slash-free pattern floats and matches at any
//!   depth (by basename / any path component);
//! - `*` and `?` match within a single path component; `**` spans whole
//!   components (`**/foo`, `a/**/b`, `foo/**`).
//!
//! Character classes (`[...]`) and per-directory nesting of `.gitignore` files
//! are refinements not yet modeled: patterns are matched against the full
//! repository-relative path, which covers a root `.gitignore` plus
//! `.git/info/exclude` (the overwhelmingly common setup).

use alloc::vec::Vec;

/// A compiled ordered set of gitignore patterns.
#[derive(Debug, Clone, Default)]
pub struct Ignore {
    patterns: Vec<Pattern>,
}

#[derive(Debug, Clone)]
struct Pattern {
    /// `!`-prefixed: a match re-includes rather than ignores.
    negated: bool,
    /// Trailing `/`: matches directories (and their contents) only.
    dir_only: bool,
    /// Leading or interior `/`: anchored to the ignore file's root.
    anchored: bool,
    /// The `/`-separated pattern tokens (a token may be `**`).
    toks: Vec<Vec<u8>>,
}

impl Ignore {
    /// An empty ignore set (ignores nothing).
    pub fn new() -> Self {
        Ignore {
            patterns: Vec::new(),
        }
    }

    /// Appends every pattern in a `.gitignore`/`exclude` file's raw bytes.
    pub fn add_bytes(&mut self, data: &[u8]) {
        for line in data.split(|&b| b == b'\n') {
            self.add_line(line);
        }
    }

    /// Compiles and appends a single pattern line (a no-op for blanks/comments).
    fn add_line(&mut self, raw: &[u8]) {
        let mut line = raw;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        // Trim a trailing run of (unescaped) spaces, as git does.
        while line.last() == Some(&b' ') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() || line[0] == b'#' {
            return;
        }

        let mut negated = false;
        if line[0] == b'!' {
            negated = true;
            line = &line[1..];
        }
        let mut dir_only = false;
        if line.last() == Some(&b'/') {
            dir_only = true;
            line = &line[..line.len() - 1];
        }
        let leading_slash = line.first() == Some(&b'/');
        if leading_slash {
            line = &line[1..];
        }
        let anchored = leading_slash || line.contains(&b'/');

        let toks: Vec<Vec<u8>> = line
            .split(|&b| b == b'/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_vec())
            .collect();
        if toks.is_empty() {
            return;
        }
        self.patterns.push(Pattern {
            negated,
            dir_only,
            anchored,
            toks,
        });
    }

    /// Whether the set contains no patterns.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether `path` (a repository-relative, `/`-separated file path) is
    /// ignored. The last matching pattern decides, so a later `!pattern` can
    /// re-include a path an earlier pattern ignored.
    pub fn is_ignored(&self, path: &[u8]) -> bool {
        let comps: Vec<&[u8]> = path
            .split(|&b| b == b'/')
            .filter(|s| !s.is_empty())
            .collect();
        if comps.is_empty() {
            return false;
        }
        let mut ignored = false;
        for p in &self.patterns {
            if p.matches(&comps) {
                ignored = !p.negated;
            }
        }
        ignored
    }
}

impl Pattern {
    fn matches(&self, comps: &[&[u8]]) -> bool {
        if self.anchored {
            self.match_anchored(comps)
        } else {
            // A floating pattern is a single token matched against any component
            // (for a directory-only pattern, any *ancestor* component — never the
            // final file component).
            let tok = &self.toks[0];
            let limit = if self.dir_only {
                comps.len().saturating_sub(1)
            } else {
                comps.len()
            };
            comps[..limit].iter().any(|c| glob_seg(tok, c))
        }
    }

    /// Anchored match: do the tokens match a prefix of `comps`? Uses a small
    /// reachability DP so `**` (match zero or more components) stays linear in
    /// `tokens × components` rather than exploring exponentially.
    fn match_anchored(&self, comps: &[&[u8]]) -> bool {
        let t = self.toks.len();
        let c = comps.len();
        let width = c + 1;
        let mut reach = alloc::vec![false; (t + 1) * width];
        reach[0] = true; // reach[0][0]
        for i in 0..=t {
            for j in 0..=c {
                if !reach[i * width + j] {
                    continue;
                }
                if i < t {
                    if self.toks[i] == b"**" {
                        reach[(i + 1) * width + j] = true; // ** matches zero comps
                        if j < c {
                            reach[i * width + (j + 1)] = true; // ** keeps consuming
                        }
                    } else if j < c && glob_seg(&self.toks[i], comps[j]) {
                        reach[(i + 1) * width + (j + 1)] = true;
                    }
                }
            }
        }
        // All tokens consumed after matching comps[..j]; the pattern matches the
        // path when that prefix is the whole path or an ancestor of it. A
        // directory-only pattern additionally requires a strict ancestor (j < c),
        // so it never matches a same-named file.
        for j in 0..=c {
            if reach[t * width + j] && (!self.dir_only || j < c) {
                return true;
            }
        }
        false
    }
}

/// Globs a single path component: `*` spans any run of bytes, `?` one byte
/// (components never contain `/`, so neither crosses a separator). Iterative
/// backtracking, O(pattern × text).
fn glob_seg(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
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

    fn ig(rules: &str) -> Ignore {
        let mut i = Ignore::new();
        i.add_bytes(rules.as_bytes());
        i
    }

    #[test]
    fn floating_basename_and_extension() {
        let i = ig("*.o\nfoo\n");
        assert!(i.is_ignored(b"a.o"));
        assert!(i.is_ignored(b"sub/dir/a.o"));
        assert!(i.is_ignored(b"foo"));
        assert!(i.is_ignored(b"x/foo"));
        assert!(!i.is_ignored(b"a.c"));
        assert!(!i.is_ignored(b"foobar"));
    }

    #[test]
    fn anchored_and_directory_only() {
        let i = ig("/build\ntarget/\n");
        assert!(i.is_ignored(b"build")); // anchored file or dir
        assert!(i.is_ignored(b"build/out.bin"));
        assert!(!i.is_ignored(b"src/build")); // anchored to root only
        assert!(i.is_ignored(b"target/debug/app")); // dir-only ignores contents
        assert!(!i.is_ignored(b"target")); // ...but not a same-named file
    }

    #[test]
    fn double_star_and_interior_slash() {
        let i = ig("**/gen\na/**/z\n");
        assert!(i.is_ignored(b"gen"));
        assert!(i.is_ignored(b"x/y/gen"));
        assert!(i.is_ignored(b"a/z"));
        assert!(i.is_ignored(b"a/b/c/z"));
        // `a/**/z` matches the directory `a/z`, so its contents are ignored too.
        assert!(i.is_ignored(b"a/z/keep"));
        // ...but a path that never reaches a `z` component is not matched.
        assert!(!i.is_ignored(b"a/b/y"));
    }

    #[test]
    fn negation_reincludes() {
        let i = ig("*.log\n!keep.log\n");
        assert!(i.is_ignored(b"debug.log"));
        assert!(!i.is_ignored(b"keep.log"));
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let i = ig("# a comment\n\n  \n*.tmp\n");
        assert!(i.is_ignored(b"x.tmp"));
        assert!(!i.is_ignored(b"x.txt"));
    }
}
