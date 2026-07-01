//! Building tree objects from a flat path list (`git write-tree`).
//!
//! The staging index is a flat, sorted list of `path → (mode, blob id)`. A
//! commit, however, points at a *tree*, which is a nested directory structure.
//! [`write_tree_from_index`] turns the former into the latter: it groups index
//! entries by directory, writes a tree object for each directory bottom-up
//! (children before parents, as content-addressing requires), and returns the
//! id of the root tree.
//!
//! Only stage-0 entries are used — an index with unresolved merge conflicts
//! (stages 1–3) cannot be turned into a tree, which mirrors git refusing
//! `write-tree` on a conflicted index.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::index::Index;
use crate::object::ObjectType;
use crate::object::tree::{FileMode, Tree, TreeEntry};
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;

/// Writes the tree objects described by `index` into `odb`, returning the root
/// tree id. Errors if the index has conflict-stage entries.
pub fn write_tree_from_index<D: ObjectDatabase>(odb: &D, index: &Index) -> Result<ObjectId> {
    // Collect stage-0 entries as (path, mode, id), sorted by path so entries of
    // the same directory are contiguous.
    let mut flat: Vec<(Vec<u8>, FileMode, ObjectId)> = Vec::new();
    for e in &index.entries {
        if e.stage != 0 {
            return Err(Error::Reference(
                "cannot write-tree: index has unmerged (conflict) entries".into(),
            ));
        }
        flat.push((e.path.clone(), FileMode::from_mode_bits(e.mode)?, e.id));
    }
    write_tree_from_entries(odb, flat)
}

/// Builds nested tree objects from a flat `(path, mode, id)` entry list (paths
/// are `/`-joined, relative to the root) and returns the root tree id. The
/// entries are sorted by path internally, so any order is accepted. This is the
/// tree-construction primitive shared by `write-tree` and the merge machinery.
pub fn write_tree_from_entries<D: ObjectDatabase>(
    odb: &D,
    mut entries: Vec<(Vec<u8>, FileMode, ObjectId)>,
) -> Result<ObjectId> {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    build(odb, &entries)
}

/// Recursively builds one tree from `entries` (paths relative to this tree),
/// writing it and any subtrees, and returns this tree's id.
fn build<D: ObjectDatabase>(
    odb: &D,
    entries: &[(Vec<u8>, FileMode, ObjectId)],
) -> Result<ObjectId> {
    let mut tree_entries: Vec<TreeEntry> = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let (path, mode, id) = &entries[i];
        match path.iter().position(|&b| b == b'/') {
            None => {
                // A leaf file at this level.
                tree_entries.push(TreeEntry {
                    mode: *mode,
                    name: path.clone(),
                    id: *id,
                });
                i += 1;
            }
            Some(slash) => {
                // A subdirectory: gather every consecutive entry under it,
                // stripping the `dir/` prefix, then build that subtree.
                let dir = &path[..slash];
                let mut sub: Vec<(Vec<u8>, FileMode, ObjectId)> = Vec::new();
                while i < entries.len() {
                    let p = &entries[i].0;
                    if p.len() > slash && &p[..slash] == dir && p[slash] == b'/' {
                        sub.push((p[slash + 1..].to_vec(), entries[i].1, entries[i].2));
                        i += 1;
                    } else {
                        break;
                    }
                }
                let subtree = build(odb, &sub)?;
                tree_entries.push(TreeEntry {
                    mode: FileMode::Tree,
                    name: dir.to_vec(),
                    id: subtree,
                });
            }
        }
    }

    let tree = Tree {
        entries: tree_entries,
    };
    odb.write(ObjectType::Tree, &tree.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::IndexEntry;
    use crate::odb::MemoryOdb;
    use crate::oid::HashAlgo;

    fn entry(path: &[u8], id: ObjectId) -> IndexEntry {
        IndexEntry {
            ctime: (0, 0),
            mtime: (0, 0),
            dev: 0,
            ino: 0,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: 0,
            id,
            stage: 0,
            assume_valid: false,
            path: path.to_vec(),
        }
    }

    #[test]
    fn builds_nested_tree() {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let blob = odb.write(ObjectType::Blob, b"x").unwrap();

        let mut index = Index::new(HashAlgo::Sha1);
        index.entries.push(entry(b"README", blob));
        index.entries.push(entry(b"src/main.rs", blob));
        index.entries.push(entry(b"src/lib.rs", blob));

        let root_id = write_tree_from_index(&odb, &index).unwrap();

        // Root has README (blob) and src (tree).
        let root = match odb.read_object(&root_id).unwrap() {
            crate::object::Object::Tree(t) => t,
            _ => panic!("root is not a tree"),
        };
        assert_eq!(root.entries.len(), 2);
        let src = root.get(b"src").expect("src entry");
        assert_eq!(src.mode, FileMode::Tree);

        // The src subtree has both files.
        let sub = match odb.read_object(&src.id).unwrap() {
            crate::object::Object::Tree(t) => t,
            _ => panic!("src is not a tree"),
        };
        assert_eq!(sub.entries.len(), 2);
        assert!(sub.get(b"main.rs").is_some());
        assert!(sub.get(b"lib.rs").is_some());
    }
}
