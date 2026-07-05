//! Remotes and refspecs.
//!
//! A [`Refspec`] maps ref names on one side of a fetch/push to the other, e.g.
//! `+refs/heads/*:refs/remotes/origin/*`. A [`Remote`] bundles a named remote's
//! URL with its fetch refspecs, loaded from `[remote "<name>"]` in the config.
//!
//! This is the data model and matching logic; wiring it into fetch (creating
//! remote-tracking refs) is a separate step.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::config::Config;
use crate::error::{Error, Result};

/// A single refspec: an optional `+` (force), a source pattern, and a
/// destination pattern. Either side may end in `*` to match/rewrite a suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refspec {
    /// Whether the update is forced (`+` prefix): allowed to be non-fast-forward.
    pub force: bool,
    /// The source side (e.g. `refs/heads/*`).
    pub src: String,
    /// The destination side (e.g. `refs/remotes/origin/*`); empty if the refspec
    /// had no `:` (a bare source, used to name refs to fetch without mapping).
    pub dst: String,
}

impl Refspec {
    /// Parses a refspec string. Rejects a spec where exactly one side is a
    /// wildcard (both sides must use `*`, or neither), or with more than one `*`
    /// on a side.
    pub fn parse(s: &str) -> Result<Self> {
        let (force, rest) = match s.strip_prefix('+') {
            Some(r) => (true, r),
            None => (false, s),
        };
        let (src, dst) = match rest.split_once(':') {
            Some((a, b)) => (a.to_string(), b.to_string()),
            None => (rest.to_string(), String::new()),
        };
        if src.matches('*').count() > 1 || dst.matches('*').count() > 1 {
            return Err(Error::Config(alloc::format!(
                "refspec {s:?}: at most one '*' per side"
            )));
        }
        // A wildcard on one side requires a wildcard on the other (unless the
        // destination is empty, i.e. a bare source pattern).
        if !dst.is_empty() && src.contains('*') != dst.contains('*') {
            return Err(Error::Config(alloc::format!(
                "refspec {s:?}: '*' must appear on both sides or neither"
            )));
        }
        Ok(Refspec { force, src, dst })
    }

    /// If `name` matches the source side, returns the mapped destination ref
    /// name. A wildcard source captures the suffix and substitutes it into the
    /// destination wildcard; a literal source maps to the literal destination
    /// (or to itself when the destination is empty).
    pub fn dst_for(&self, name: &str) -> Option<String> {
        match self.src.strip_suffix('*') {
            Some(prefix) => {
                let tail = name.strip_prefix(prefix)?;
                let dprefix = self.dst.strip_suffix('*')?;
                Some(alloc::format!("{dprefix}{tail}"))
            }
            None if self.src == name => {
                if self.dst.is_empty() {
                    Some(name.to_string())
                } else {
                    Some(self.dst.clone())
                }
            }
            None => None,
        }
    }

    /// Serializes back to the `[+]src[:dst]` wire/config form.
    pub fn to_string_form(&self) -> String {
        let plus = if self.force { "+" } else { "" };
        if self.dst.is_empty() {
            alloc::format!("{plus}{}", self.src)
        } else {
            alloc::format!("{plus}{}:{}", self.src, self.dst)
        }
    }
}

/// A configured remote: its name, URL, and fetch refspecs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    /// The remote's short name (e.g. `origin`).
    pub name: String,
    /// The fetch/push URL (`remote.<name>.url`).
    pub url: String,
    /// The fetch refspecs (`remote.<name>.fetch`, possibly repeated).
    pub fetch: Vec<Refspec>,
}

impl Remote {
    /// Loads `[remote "<name>"]` from `config`, or `None` if it has no URL.
    /// Malformed fetch refspecs are skipped.
    pub fn from_config(config: &Config, name: &str) -> Option<Remote> {
        let url = config.get("remote", Some(name), "url")?.to_string();
        let fetch = config
            .get_all("remote", Some(name), "fetch")
            .iter()
            .filter_map(|s| Refspec::parse(s).ok())
            .collect();
        Some(Remote {
            name: name.to_string(),
            url,
            fetch,
        })
    }

    /// The default fetch layout for a freshly-cloned remote:
    /// `+refs/heads/*:refs/remotes/<name>/*`.
    pub fn default_fetch(name: &str) -> Refspec {
        Refspec {
            force: true,
            src: "refs/heads/*".to_string(),
            dst: alloc::format!("refs/remotes/{name}/*"),
        }
    }

    /// Maps a remote ref name to its local remote-tracking ref under the first
    /// matching fetch refspec, or `None` if none matches.
    pub fn map_fetch(&self, name: &str) -> Option<String> {
        self.fetch.iter().find_map(|spec| spec.dst_for(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_refspec_maps_suffix() {
        let s = Refspec::parse("+refs/heads/*:refs/remotes/origin/*").unwrap();
        assert!(s.force);
        assert_eq!(
            s.dst_for("refs/heads/main").as_deref(),
            Some("refs/remotes/origin/main")
        );
        assert_eq!(
            s.dst_for("refs/heads/feature/x").as_deref(),
            Some("refs/remotes/origin/feature/x")
        );
        assert_eq!(s.dst_for("refs/tags/v1"), None);
    }

    #[test]
    fn literal_refspec_and_bare_source() {
        let s = Refspec::parse("refs/heads/main:refs/heads/upstream").unwrap();
        assert!(!s.force);
        assert_eq!(
            s.dst_for("refs/heads/main").as_deref(),
            Some("refs/heads/upstream")
        );
        assert_eq!(s.dst_for("refs/heads/other"), None);

        let bare = Refspec::parse("refs/heads/main").unwrap();
        assert_eq!(
            bare.dst_for("refs/heads/main").as_deref(),
            Some("refs/heads/main")
        );
        assert_eq!(bare.to_string_form(), "refs/heads/main");
    }

    #[test]
    fn mismatched_wildcards_rejected() {
        assert!(Refspec::parse("refs/heads/*:refs/remotes/origin/main").is_err());
        assert!(Refspec::parse("refs/**/*:x/*").is_err());
    }

    #[test]
    fn loads_remote_from_config() {
        let text = "[remote \"origin\"]\n\turl = https://example.com/r.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n";
        let cfg = Config::parse(text).unwrap();
        let remote = Remote::from_config(&cfg, "origin").unwrap();
        assert_eq!(remote.url, "https://example.com/r.git");
        assert_eq!(remote.fetch.len(), 1);
        assert_eq!(
            remote.map_fetch("refs/heads/main").as_deref(),
            Some("refs/remotes/origin/main")
        );
        assert!(Remote::from_config(&cfg, "nonexistent").is_none());
    }
}
