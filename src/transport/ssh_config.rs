//! Minimal `~/.ssh/config` resolution.
//!
//! Before connecting, OpenSSH resolves a host *alias* through `~/.ssh/config`:
//! `Host` blocks whose pattern matches the alias contribute settings —
//! `HostName`, `User`, `Port`, `IdentityFile` — and, as in real ssh, the **first**
//! value obtained for each key wins. This lets `git clone myserver:repo.git` work
//! when `myserver` is only an alias for a real host, user, and port.
//!
//! This is a deliberately small subset (the keys a git-over-SSH clone needs);
//! `Match` blocks, `Include`, and token expansion are not handled.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The settings resolved for a host alias (each `None` if unset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostConfig {
    /// The real host to connect to (`HostName`).
    pub hostname: Option<String>,
    /// The login user (`User`).
    pub user: Option<String>,
    /// The port (`Port`).
    pub port: Option<u16>,
    /// A private-key file (`IdentityFile`).
    pub identity_file: Option<String>,
}

/// Resolves `alias` against the text of an `ssh_config`, applying every matching
/// `Host` block in order with first-value-wins semantics.
pub fn resolve(config: &str, alias: &str) -> HostConfig {
    let mut out = HostConfig::default();
    // Patterns of the block we are currently inside (None until the first Host).
    let mut current: Option<Vec<String>> = None;

    for raw in config.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = match split_kv(line) {
            Some(kv) => kv,
            None => continue,
        };

        if key.eq_ignore_ascii_case("Host") {
            // Host patterns are separated by whitespace or commas.
            current = Some(
                value
                    .split(|c: char| c.is_whitespace() || c == ',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect(),
            );
            continue;
        }

        // A setting outside any Host block, or in a block that does not match the
        // alias, is ignored.
        let matches = current
            .as_ref()
            .is_some_and(|pats| host_matches(pats, alias));
        if !matches {
            continue;
        }

        // First value wins.
        if key.eq_ignore_ascii_case("HostName") {
            out.hostname.get_or_insert_with(|| value.to_string());
        } else if key.eq_ignore_ascii_case("User") {
            out.user.get_or_insert_with(|| value.to_string());
        } else if key.eq_ignore_ascii_case("Port") {
            if out.port.is_none()
                && let Ok(p) = value.trim().parse()
            {
                out.port = Some(p);
            }
        } else if key.eq_ignore_ascii_case("IdentityFile") {
            out.identity_file.get_or_insert_with(|| value.to_string());
        }
    }
    out
}

/// Removes a `#` comment (ssh config comments run to end of line).
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Splits an ssh-config line into `(key, value)`. The separator is whitespace or
/// an `=` (both are allowed by ssh); the value is the trimmed remainder.
fn split_kv(line: &str) -> Option<(&str, &str)> {
    let sep = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = line[..sep].trim();
    let value = line[sep..].trim_start_matches(['=', ' ', '\t']).trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Whether any of `patterns` matches `alias`, honouring `!` negation (a matched
/// negated pattern excludes the alias outright).
fn host_matches(patterns: &[String], alias: &str) -> bool {
    let mut matched = false;
    for pat in patterns {
        if let Some(neg) = pat.strip_prefix('!') {
            if glob_match(neg, alias) {
                return false;
            }
        } else if glob_match(pat, alias) {
            matched = true;
        }
    }
    matched
}

/// Matches an ssh-config host pattern (`*` any run, `?` one char) against `text`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    // Iterative backtracking wildcard match.
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "\
# a comment
Host gh github
    HostName github.com
    User git
    Port 2222
    IdentityFile ~/.ssh/id_gh

Host *.internal
    User deploy

Host *
    User fallback
    Port 22
";

    #[test]
    fn resolves_an_exact_alias() {
        let c = resolve(CONFIG, "gh");
        assert_eq!(c.hostname.as_deref(), Some("github.com"));
        assert_eq!(c.user.as_deref(), Some("git"));
        assert_eq!(c.port, Some(2222));
        assert_eq!(c.identity_file.as_deref(), Some("~/.ssh/id_gh"));
    }

    #[test]
    fn second_alias_on_the_same_host_line() {
        assert_eq!(resolve(CONFIG, "github").user.as_deref(), Some("git"));
    }

    #[test]
    fn first_value_wins_across_blocks() {
        // `box.internal` matches `*.internal` (User deploy) then `*` (User
        // fallback); the first wins.
        let c = resolve(CONFIG, "box.internal");
        assert_eq!(c.user.as_deref(), Some("deploy"));
        // Port only comes from the `*` block.
        assert_eq!(c.port, Some(22));
    }

    #[test]
    fn wildcard_only_match() {
        let c = resolve(CONFIG, "random");
        assert_eq!(c.user.as_deref(), Some("fallback"));
        assert!(c.hostname.is_none());
    }

    #[test]
    fn glob_and_negation() {
        assert!(glob_match("*.example.com", "a.example.com"));
        assert!(glob_match("h?st", "host"));
        assert!(!glob_match("h?st", "haste"));
        // A negated pattern excludes the alias.
        let cfg = "Host *,!secret\n    User general\n";
        assert_eq!(resolve(cfg, "public").user.as_deref(), Some("general"));
        assert!(resolve(cfg, "secret").user.is_none());
    }
}
