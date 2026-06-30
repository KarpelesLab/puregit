//! References — branches, tags, `HEAD`, and the ref store.
//!
//! A reference is a named pointer. It is either *direct* (it holds an
//! [`ObjectId`]) or *symbolic* (it holds the name of another ref, like `HEAD →
//! refs/heads/main`). On disk a ref is either a "loose" file under
//! `refs/…` (or a top-level pseudo-ref like `HEAD`) containing one line, or an
//! entry in the consolidated `packed-refs` file.
//!
//! This module owns:
//! - [`is_valid_ref_name`] — git's reference-name rules (`git-check-ref-format`).
//! - [`Reference`] — the direct/symbolic value, with [`Reference::parse`] for a
//!   loose ref file's contents.
//! - [`parse_packed_refs`] — the `packed-refs` file format (incl. peeled tags).
//! - [`RefStore`] — a [`crate::vfs::Vfs`]-backed store that resolves and updates refs.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, ObjectKindHint, Result};
use crate::oid::{HashAlgo, ObjectId};
use crate::vfs::Vfs;

/// The value of a reference: a direct object id or a pointer to another ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    /// Points directly at an object.
    Direct(ObjectId),
    /// Points at another reference by name (`ref: refs/heads/main`).
    Symbolic(String),
}

impl Reference {
    /// Parses the contents of a loose ref file.
    ///
    /// A symbolic ref is `ref: <target>\n`; otherwise the file holds a single
    /// hex object id. Trailing whitespace is tolerated.
    pub fn parse(algo: HashAlgo, contents: &[u8]) -> Result<Self> {
        let text = core::str::from_utf8(contents)
            .map_err(|_| Error::Reference("non-utf8 ref contents".to_string()))?
            .trim();
        if let Some(target) = text.strip_prefix("ref:") {
            let target = target.trim();
            if !is_valid_ref_name(target) {
                return Err(Error::Reference(format!(
                    "symbolic ref target is not a valid name: {target:?}"
                )));
            }
            Ok(Reference::Symbolic(target.to_string()))
        } else {
            Ok(Reference::Direct(ObjectId::from_hex(algo, text)?))
        }
    }

    /// Serializes the ref to its loose-file contents (with trailing newline).
    pub fn to_file_contents(&self) -> Vec<u8> {
        let mut s = match self {
            Reference::Direct(id) => id.to_hex(),
            Reference::Symbolic(target) => format!("ref: {target}"),
        };
        s.push('\n');
        s.into_bytes()
    }
}

/// Validates a reference name against git's rules (a subset of
/// `git-check-ref-format`): no `..`, no leading/trailing or doubled `/`, no
/// control or special characters (` `, `~`, `^`, `:`, `?`, `*`, `[`, `\`), no
/// component starting with `.` or ending in `.lock`, and not the single
/// character `@`.
pub fn is_valid_ref_name(name: &str) -> bool {
    if name.is_empty() || name == "@" {
        return false;
    }
    if name.starts_with('/') || name.ends_with('/') || name.contains("//") {
        return false;
    }
    if name.contains("..") || name.contains("@{") {
        return false;
    }
    if name.ends_with('.') || name.ends_with(".lock") {
        return false;
    }
    for component in name.split('/') {
        if component.is_empty() || component.starts_with('.') || component.ends_with(".lock") {
            return false;
        }
    }
    for &b in name.as_bytes() {
        match b {
            0..=0x20 | 0x7f => return false, // control chars and space
            b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\' => return false,
            _ => {}
        }
    }
    true
}

/// One parsed entry from a `packed-refs` file: the ref name, its object id, and
/// (for annotated tags) the peeled commit id from the following `^…` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedRef {
    /// The full ref name (e.g. `refs/tags/v1.0`).
    pub name: String,
    /// The object the ref points at.
    pub id: ObjectId,
    /// For an annotated tag, the underlying commit (the `^<oid>` peel line).
    pub peeled: Option<ObjectId>,
}

/// Parses a `packed-refs` file into its entries.
///
/// The format is a `# pack-refs with: …` header line, then `"<oid> <name>"`
/// lines, each optionally followed by a `"^<oid>"` line giving the peeled
/// target of an annotated tag.
pub fn parse_packed_refs(algo: HashAlgo, contents: &[u8]) -> Result<Vec<PackedRef>> {
    let text = core::str::from_utf8(contents)
        .map_err(|_| Error::Reference("non-utf8 packed-refs".to_string()))?;
    let mut out: Vec<PackedRef> = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(peel) = line.strip_prefix('^') {
            let id = ObjectId::from_hex(algo, peel.trim())?;
            let last = out
                .last_mut()
                .ok_or_else(|| Error::Reference("packed-refs: peel line without ref".into()))?;
            last.peeled = Some(id);
            continue;
        }
        let (oid, name) = line
            .split_once(' ')
            .ok_or_else(|| Error::Reference("packed-refs: malformed line".into()))?;
        out.push(PackedRef {
            name: name.trim().to_string(),
            id: ObjectId::from_hex(algo, oid.trim())?,
            peeled: None,
        });
    }
    Ok(out)
}

/// A [`crate::vfs::Vfs`]-backed reference store rooted at the git directory.
///
/// Resolves loose refs first, then falls back to `packed-refs`, and follows
/// symbolic refs (with a depth limit) to a final object id.
#[derive(Debug, Clone)]
pub struct RefStore<V: Vfs> {
    vfs: V,
    algo: HashAlgo,
}

const MAX_SYMREF_DEPTH: usize = 5;

impl<V: Vfs> RefStore<V> {
    /// Creates a ref store over a VFS rooted at the git directory (so it reads
    /// `HEAD`, `refs/…`, and `packed-refs` directly).
    pub fn new(vfs: V, algo: HashAlgo) -> Self {
        RefStore { vfs, algo }
    }

    /// Reads a single ref's value without following symrefs. Consults the loose
    /// file first, then `packed-refs`. Returns [`Error::NotFound`] if neither
    /// has it.
    pub fn lookup(&self, name: &str) -> Result<Reference> {
        if self.vfs.exists(name) {
            let contents = self.vfs.read(name)?;
            return Reference::parse(self.algo, &contents);
        }
        for entry in self.packed()? {
            if entry.name == name {
                return Ok(Reference::Direct(entry.id));
            }
        }
        Err(Error::NotFound(ObjectKindHint::Reference(name.to_string())))
    }

    /// Resolves a ref all the way to an object id, following symbolic refs.
    pub fn resolve(&self, name: &str) -> Result<ObjectId> {
        let mut current = name.to_string();
        for _ in 0..MAX_SYMREF_DEPTH {
            match self.lookup(&current)? {
                Reference::Direct(id) => return Ok(id),
                Reference::Symbolic(target) => current = target,
            }
        }
        Err(Error::Reference(format!(
            "symref chain too deep starting at {name}"
        )))
    }

    /// Writes a ref's value as a loose ref file (creating parent dirs). This
    /// does not update `packed-refs`; a loose ref shadows any packed entry of
    /// the same name, which is exactly git's precedence.
    pub fn update(&self, name: &str, value: &Reference) -> Result<()> {
        if !is_valid_ref_name(name) && name != "HEAD" {
            return Err(Error::Reference(format!("invalid ref name {name:?}")));
        }
        self.vfs.write(name, &value.to_file_contents())
    }

    /// Reads and parses `packed-refs` (empty if the file is absent).
    pub fn packed(&self) -> Result<Vec<PackedRef>> {
        if !self.vfs.exists("packed-refs") {
            return Ok(Vec::new());
        }
        let contents = self.vfs.read("packed-refs")?;
        parse_packed_refs(self.algo, &contents)
    }

    /// Lists all refs (loose and packed) under `refs/`, resolved to ids,
    /// as a name→id map. Loose refs win over packed on conflict.
    pub fn list(&self) -> Result<BTreeMap<String, ObjectId>> {
        let mut map = BTreeMap::new();
        for entry in self.packed()? {
            map.insert(entry.name, entry.id);
        }
        self.collect_loose("refs", &mut map)?;
        Ok(map)
    }

    fn collect_loose(&self, dir: &str, map: &mut BTreeMap<String, ObjectId>) -> Result<()> {
        if !self.vfs.exists(dir) {
            return Ok(());
        }
        for entry in self.vfs.read_dir(dir)? {
            let child = format!("{dir}/{}", entry.name);
            match entry.file_type {
                crate::vfs::FileType::Dir => self.collect_loose(&child, map)?,
                _ => {
                    if let Ok(id) = self.resolve(&child) {
                        map.insert(child, id);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(is_valid_ref_name("refs/heads/main"));
        assert!(is_valid_ref_name("refs/tags/v1.0.0"));
        assert!(!is_valid_ref_name("refs/heads/"));
        assert!(!is_valid_ref_name("refs//heads"));
        assert!(!is_valid_ref_name("refs/heads/..hidden"));
        assert!(!is_valid_ref_name("refs/heads/foo.lock"));
        assert!(!is_valid_ref_name("refs/heads/a b"));
        assert!(!is_valid_ref_name("@"));
    }

    #[test]
    fn parse_symbolic_head() {
        let r = Reference::parse(HashAlgo::Sha1, b"ref: refs/heads/main\n").unwrap();
        assert_eq!(r, Reference::Symbolic("refs/heads/main".to_string()));
        assert_eq!(r.to_file_contents(), b"ref: refs/heads/main\n");
    }

    #[test]
    fn parse_direct() {
        let hex = "ce013625030ba8dba906f756967f9e9ca394464a";
        let r = Reference::parse(HashAlgo::Sha1, format!("{hex}\n").as_bytes()).unwrap();
        match r {
            Reference::Direct(id) => assert_eq!(id.to_hex(), hex),
            _ => panic!("expected direct"),
        }
    }

    #[test]
    fn packed_refs_with_peel() {
        let hex_tag = "1111111111111111111111111111111111111111";
        let hex_commit = "2222222222222222222222222222222222222222";
        let contents = format!(
            "# pack-refs with: peeled fully-peeled sorted\n{hex_tag} refs/tags/v1\n^{hex_commit}\n"
        );
        let parsed = parse_packed_refs(HashAlgo::Sha1, contents.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "refs/tags/v1");
        assert_eq!(parsed[0].peeled.as_ref().unwrap().to_hex(), hex_commit);
    }
}
