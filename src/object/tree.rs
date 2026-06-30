//! Tree objects — git's directory representation.
//!
//! A tree is a sorted list of entries, each pairing a filename with a mode and
//! the object id of its contents. The on-disk encoding of one entry is:
//!
//! ```text
//! <mode-octal-ascii> SP <name> NUL <raw-oid>
//! ```
//!
//! where the mode has no leading zero (`40000` for a subtree, `100644` for a
//! regular file) and the id is in fixed-width binary form (20 bytes for SHA-1,
//! 32 for SHA-256). Entries are sorted by name, with subtree names compared as
//! though they ended in `/` — [`Tree::serialize`] re-applies that ordering.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::{HashAlgo, ObjectId};

/// A file mode in a tree entry. Git uses a small fixed set of values rather
/// than full POSIX modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    /// `40000` — a subdirectory (the entry's id names another tree).
    Tree,
    /// `100644` — a regular, non-executable file.
    Regular,
    /// `100755` — a regular, executable file.
    Executable,
    /// `120000` — a symbolic link (the blob holds the link target).
    Symlink,
    /// `160000` — a gitlink / submodule (the id is a commit in another repo).
    Gitlink,
}

impl FileMode {
    /// The octal-ASCII form written on the wire (no leading zero).
    pub const fn as_octal(self) -> &'static str {
        match self {
            FileMode::Tree => "40000",
            FileMode::Regular => "100644",
            FileMode::Executable => "100755",
            FileMode::Symlink => "120000",
            FileMode::Gitlink => "160000",
        }
    }

    /// Parses an octal-ASCII mode from a tree entry.
    pub fn from_octal(s: &[u8]) -> Result<Self> {
        Ok(match s {
            b"40000" | b"040000" => FileMode::Tree,
            b"100644" => FileMode::Regular,
            b"100755" => FileMode::Executable,
            b"120000" => FileMode::Symlink,
            b"160000" => FileMode::Gitlink,
            other => {
                use alloc::format;
                return Err(Error::Parse(format!(
                    "tree: unknown file mode {:?}",
                    core::str::from_utf8(other).unwrap_or("<non-utf8>")
                )));
            }
        })
    }

    /// Whether this entry names a subtree (affects sort ordering).
    pub fn is_tree(self) -> bool {
        matches!(self, FileMode::Tree)
    }

    /// Maps a raw index/stat mode (e.g. `0o100644`) to a tree [`FileMode`].
    /// Any regular-file mode without the executable bit is treated as
    /// [`FileMode::Regular`], matching git's normalization.
    pub fn from_mode_bits(mode: u32) -> Result<Self> {
        Ok(match mode & 0o170000 {
            0o040000 => FileMode::Tree,
            0o120000 => FileMode::Symlink,
            0o160000 => FileMode::Gitlink,
            0o100000 => {
                if mode & 0o111 != 0 {
                    FileMode::Executable
                } else {
                    FileMode::Regular
                }
            }
            _ => {
                use alloc::format;
                return Err(Error::Parse(format!("tree: unrepresentable mode {mode:o}")));
            }
        })
    }
}

/// One entry in a [`Tree`]: a mode, a name, and the id of the named object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// The file mode.
    pub mode: FileMode,
    /// The entry name (a single path component; never contains `/` or NUL).
    /// Stored as raw bytes because git filenames are not required to be UTF-8.
    pub name: Vec<u8>,
    /// The id of the blob, subtree, or (for gitlinks) commit.
    pub id: ObjectId,
}

/// A parsed tree object: its entries in git's canonical order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    /// The entries. Kept sorted by [`Tree::serialize`]; callers may push in any
    /// order and rely on serialization to canonicalize.
    pub entries: Vec<TreeEntry>,
}

impl Tree {
    /// Parses a tree payload under the repository's hash algorithm.
    pub fn parse(algo: HashAlgo, mut payload: &[u8]) -> Result<Self> {
        let id_len = algo.raw_len();
        let mut entries = Vec::new();

        while !payload.is_empty() {
            let space = payload
                .iter()
                .position(|&b| b == b' ')
                .ok_or_else(|| Error::Parse("tree: entry missing mode separator".into()))?;
            let mode = FileMode::from_octal(&payload[..space])?;

            let rest = &payload[space + 1..];
            let nul = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| Error::Parse("tree: entry missing name terminator".into()))?;
            let name = rest[..nul].to_vec();

            let after_name = &rest[nul + 1..];
            if after_name.len() < id_len {
                return Err(Error::Parse("tree: truncated entry id".into()));
            }
            let id = ObjectId::from_bytes(algo, &after_name[..id_len])?;

            entries.push(TreeEntry { mode, name, id });
            payload = &after_name[id_len..];
        }
        Ok(Tree { entries })
    }

    /// Serializes the tree to its canonical bytes, sorting entries the way git
    /// does (by name, treating subtree names as if suffixed with `/`).
    pub fn serialize(&self) -> Vec<u8> {
        let mut sorted: Vec<&TreeEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| cmp_entry_names(a, b));

        let mut out = Vec::new();
        for e in sorted {
            out.extend_from_slice(e.mode.as_octal().as_bytes());
            out.push(b' ');
            out.extend_from_slice(&e.name);
            out.push(0);
            out.extend_from_slice(e.id.as_bytes());
        }
        out
    }

    /// Finds an entry by exact name.
    pub fn get(&self, name: &[u8]) -> Option<&TreeEntry> {
        self.entries.iter().find(|e| e.name == name)
    }
}

/// Compares two entries' names using git's tree-sort rule: a subtree sorts as
/// though its name had a trailing `/`, so `foo` (file) sorts before `foo/`
/// (subtree) when another entry named `foo.txt` exists between them.
fn cmp_entry_names(a: &TreeEntry, b: &TreeEntry) -> core::cmp::Ordering {
    let a_name = effective_name(a);
    let b_name = effective_name(b);
    a_name.cmp(&b_name)
}

fn effective_name(e: &TreeEntry) -> Vec<u8> {
    let mut n = e.name.clone();
    if e.mode.is_tree() {
        n.push(b'/');
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(byte: u8) -> ObjectId {
        ObjectId::from_bytes(HashAlgo::Sha1, &[byte; 20]).unwrap()
    }

    #[test]
    fn roundtrip() {
        let tree = Tree {
            entries: alloc::vec![
                TreeEntry {
                    mode: FileMode::Regular,
                    name: b"a.txt".to_vec(),
                    id: oid(1)
                },
                TreeEntry {
                    mode: FileMode::Tree,
                    name: b"sub".to_vec(),
                    id: oid(2)
                },
            ],
        };
        let bytes = tree.serialize();
        let back = Tree::parse(HashAlgo::Sha1, &bytes).unwrap();
        assert_eq!(back.entries.len(), 2);
        assert_eq!(back.get(b"a.txt").unwrap().mode, FileMode::Regular);
        assert_eq!(back.get(b"sub").unwrap().mode, FileMode::Tree);
    }

    #[test]
    fn sort_treats_subtree_with_slash() {
        // `foo` (file), `foo.txt`, `foo` (tree) must serialize as foo, foo.txt? No:
        // file "foo" < "foo.txt" < tree "foo/" — verify the tree sorts last here.
        let tree = Tree {
            entries: alloc::vec![
                TreeEntry {
                    mode: FileMode::Tree,
                    name: b"foo".to_vec(),
                    id: oid(3)
                },
                TreeEntry {
                    mode: FileMode::Regular,
                    name: b"foo.txt".to_vec(),
                    id: oid(1)
                },
                TreeEntry {
                    mode: FileMode::Regular,
                    name: b"foo".to_vec(),
                    id: oid(2)
                },
            ],
        };
        let back = Tree::parse(HashAlgo::Sha1, &tree.serialize()).unwrap();
        let names: Vec<&[u8]> = back.entries.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(
            names,
            alloc::vec![&b"foo"[..], &b"foo.txt"[..], &b"foo"[..]]
        );
    }
}
