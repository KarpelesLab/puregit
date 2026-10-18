//! libgit2 writes -> puregit reads.
//!
//! Each test builds a repository (or a pack) with libgit2 through `git2`, then
//! opens it with puregit and checks that puregit sees exactly what libgit2
//! wrote: object ids, raw object bytes, parsed fields, refs, the index, config,
//! reflogs, packs, history walks, merge bases and tree diffs.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use puregit::object::{FileMode, Object};
use puregit::refs::Reference;
use puregit::walk::{self, TreeChange};
use puregit::{HashAlgo, ObjectId};
use puregit_interop_libgit2::*;

fn pg_open(path: &Path) -> puregit::Repository {
    puregit::Repository::open(path).expect("puregit open")
}

/// A spread of blob contents: empty, text, CRLF, binary with NULs, non-UTF-8,
/// and a large blob that spans many zlib blocks.
fn sample_blobs() -> Vec<Vec<u8>> {
    let mut large = Vec::new();
    for i in 0..20_000u32 {
        large.extend_from_slice(format!("line {i} {}\n", i.wrapping_mul(2654435761)).as_bytes());
    }
    vec![
        Vec::new(),
        b"hello\n".to_vec(),
        b"no trailing newline".to_vec(),
        b"crlf\r\nline\r\n".to_vec(),
        vec![0, 1, 2, 3, 255, 254, 0, 0, 10, 13],
        b"latin1 \xe9\xe8\n".to_vec(),
        large,
    ]
}

#[test]
fn objects_trees_commits_tags() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);

    // Blobs written directly.
    let blob_ids: Vec<git2::Oid> = sample_blobs().iter().map(|b| g2.blob(b).unwrap()).collect();

    // A tree exercising every mode and git's tree sort order (a subtree sorts
    // as if its name ended in '/': "a" (dir) after "a-b" and "a.b" but before
    // "a0"), plus spaces, UTF-8 and non-UTF-8 names.
    let gitlink_target = blob_ids[1].to_string(); // any id works for a gitlink
    let files: Vec<FileSpec<'_>> = vec![
        ("a-b", 0o100644, b"dash\n"),
        ("a.b", 0o100644, b"dot\n"),
        ("a/inner.txt", 0o100644, b"inner\n"),
        ("a/deeper/x.sh", 0o100755, b"#!/bin/sh\necho hi\n"),
        ("a0", 0o100644, b"zero\n"),
        ("link", 0o120000, b"a/inner.txt"),
        ("sub module", 0o160000, gitlink_target.as_bytes()),
        ("unicode-\u{00e9}\u{4e2d}.txt", 0o100644, b"utf8\n"),
        ("empty", 0o100644, b""),
    ];
    let tree1 = g2_tree(&g2, &files);

    // A non-UTF-8 file name, inserted through a raw treebuilder.
    let mut tb = g2.treebuilder(Some(&g2.find_tree(tree1).unwrap())).unwrap();
    let raw_name: &[u8] = b"latin1-\xe9.bin";
    tb.insert(raw_name, blob_ids[4], 0o100644).unwrap();
    let tree2 = tb.write().unwrap();

    // Commits: root, child, a second branch, a merge, and an octopus merge,
    // with assorted timezones (including negative and half-hour offsets).
    let sig_a = g2_sig(1_600_000_000, 330);
    let sig_b = g2_sig(1_600_000_100, -480);
    let t1 = g2.find_tree(tree1).unwrap();
    let t2 = g2.find_tree(tree2).unwrap();
    let root = g2
        .commit(Some("HEAD"), &sig_a, &sig_b, "root commit\n", &t1, &[])
        .unwrap();
    let root_c = g2.find_commit(root).unwrap();
    let child = g2
        .commit(
            Some("HEAD"),
            &sig_b,
            &sig_a,
            "child\n\nWith a body.\nAnd unicode: \u{00e9}\n",
            &t2,
            &[&root_c],
        )
        .unwrap();
    let side = g2
        .commit(None, &sig_a, &sig_a, "side", &t1, &[&root_c])
        .unwrap();
    let third = g2
        .commit(None, &sig_b, &sig_b, "third\n", &t2, &[&root_c])
        .unwrap();
    let child_c = g2.find_commit(child).unwrap();
    let side_c = g2.find_commit(side).unwrap();
    let third_c = g2.find_commit(third).unwrap();
    let merge = g2
        .commit(
            Some("HEAD"),
            &sig_a,
            &sig_a,
            "Merge branch 'side'\n",
            &t2,
            &[&child_c, &side_c],
        )
        .unwrap();
    let octopus = g2
        .commit(
            None,
            &sig_a,
            &sig_b,
            "octopus\n",
            &t2,
            &[&child_c, &side_c, &third_c],
        )
        .unwrap();

    // A signed commit (libgit2 inserts the `gpgsig` header) and a commit
    // carrying an `encoding` header, written as raw bytes.
    let buf = g2
        .commit_create_buffer(&sig_a, &sig_a, "signed\n", &t1, &[&root_c])
        .unwrap();
    let armor =
        "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n=abcd\n-----END PGP SIGNATURE-----";
    let signed = g2
        .commit_signed(buf.as_str().unwrap(), armor, None)
        .unwrap();
    let encoded_raw = format!(
        "tree {tree1}\nparent {root}\nauthor A U Thor <a@example.com> 1600000000 +0000\n\
         committer C O Mitter <c@example.com> 1600000000 +0000\nencoding ISO-8859-1\n\n\
         caf\u{e9} in latin1? no, utf8\n"
    );
    let encoded = g2
        .odb()
        .unwrap()
        .write(git2::ObjectType::Commit, encoded_raw.as_bytes())
        .unwrap();

    // Annotated tags of a commit, a tree, a blob, and of another tag; plus a
    // lightweight tag.
    let tag_commit = g2
        .tag(
            "v1.0",
            &g2.find_object(merge, None).unwrap(),
            &sig_b,
            "release 1.0\n",
            false,
        )
        .unwrap();
    let tag_tree = g2
        .tag(
            "tree-tag",
            &g2.find_object(tree1, None).unwrap(),
            &sig_a,
            "a tree\n",
            false,
        )
        .unwrap();
    let tag_blob = g2
        .tag(
            "blob-tag",
            &g2.find_object(blob_ids[2], None).unwrap(),
            &sig_a,
            "",
            false,
        )
        .unwrap();
    let tag_tag = g2
        .tag(
            "tag-of-tag",
            &g2.find_object(tag_commit, None).unwrap(),
            &sig_a,
            "nested\n",
            false,
        )
        .unwrap();
    g2.tag_lightweight("light", &g2.find_object(child, None).unwrap(), false)
        .unwrap();

    // --- puregit's view --------------------------------------------------
    let pg = pg_open(dir.path());
    assert_eq!(pg.algo(), HashAlgo::Sha1);

    // Every object: same type, same bytes, same hash, byte-exact re-serialize.
    let n = assert_pg_reads_all(&g2, &pg);
    assert!(n >= 20, "only {n} objects");

    // The loose object enumeration agrees with libgit2's odb.
    let g2_ids: BTreeSet<ObjectId> = g2_all_oids(&g2).into_iter().map(pg_oid).collect();
    let pg_ids: BTreeSet<ObjectId> = pg.loose_object_ids().unwrap().into_iter().collect();
    assert_eq!(pg_ids, g2_ids);

    // Trees: entry-by-entry equality (order, mode, name, id).
    for tid in [tree1, tree2] {
        let g2_tree = g2.find_tree(tid).unwrap();
        let Object::Tree(pg_tree) = pg.read_object(&pg_oid(tid)).unwrap() else {
            panic!("not a tree")
        };
        let g2_entries: Vec<(i32, Vec<u8>, ObjectId)> = g2_tree
            .iter()
            .map(|e| (e.filemode(), e.name_bytes().to_vec(), pg_oid(e.id())))
            .collect();
        let pg_entries: Vec<(i32, Vec<u8>, ObjectId)> = pg_tree
            .entries
            .iter()
            .map(|e| (mode_bits(e.mode), e.name.clone(), e.id))
            .collect();
        assert_eq!(pg_entries, g2_entries, "tree {tid}");
    }
    // Spot-check modes puregit decoded.
    let Object::Tree(t) = pg.read_object(&pg_oid(tree1)).unwrap() else {
        panic!()
    };
    assert_eq!(t.get(b"link").unwrap().mode, FileMode::Symlink);
    assert_eq!(t.get(b"sub module").unwrap().mode, FileMode::Gitlink);
    assert_eq!(t.get(b"a").unwrap().mode, FileMode::Tree);

    // Commits: tree, parents (in order), identities, times, tz, message.
    for cid in [root, child, side, merge, octopus, signed, encoded] {
        let gc = g2.find_commit(cid).unwrap();
        let Object::Commit(pc) = pg.read_object(&pg_oid(cid)).unwrap() else {
            panic!("not a commit")
        };
        assert_eq!(pc.tree, pg_oid(gc.tree_id()));
        let gp: Vec<ObjectId> = gc.parent_ids().map(pg_oid).collect();
        assert_eq!(pc.parents, gp, "parents of {cid}");
        for (ps, gs) in [(&pc.author, gc.author()), (&pc.committer, gc.committer())] {
            assert_eq!(ps.name, gs.name_bytes());
            assert_eq!(ps.email, gs.email_bytes());
            assert_eq!(ps.time, gs.when().seconds());
            assert_eq!(ps.tz, tz_string(gs.when().offset_minutes()).into_bytes());
        }
        assert_eq!(pc.message, gc.message_raw_bytes(), "message of {cid}");
    }
    // The signature puregit extracts is the one libgit2 stored, and the signed
    // payload is what libgit2 says was signed.
    let Object::Commit(pc) = pg.read_object(&pg_oid(signed)).unwrap() else {
        panic!()
    };
    let (g2_sig_buf, g2_payload) = g2.extract_signature(&signed, None).unwrap();
    // libgit2 hands the armor back without the final newline git stores
    // (puregit keeps it, as git's own parser does); the armor is otherwise
    // identical.
    let pg_armor = pc.signature().unwrap();
    assert_eq!(pg_armor.strip_suffix(b"\n").unwrap(), &*g2_sig_buf);
    assert_eq!(pc.signed_payload(), &*g2_payload);
    let Object::Commit(pc) = pg.read_object(&pg_oid(encoded)).unwrap() else {
        panic!()
    };
    assert_eq!(pc.extra_headers, b"encoding ISO-8859-1\n");

    // Tags: target, target type, name, tagger, message.
    for tid in [tag_commit, tag_tree, tag_blob, tag_tag] {
        let gt = g2.find_tag(tid).unwrap();
        let Object::Tag(pt) = pg.read_object(&pg_oid(tid)).unwrap() else {
            panic!("not a tag")
        };
        assert_eq!(pt.object, pg_oid(gt.target_id()));
        assert_eq!(pt.object_type, pg_type(gt.target_type().unwrap()));
        assert_eq!(pt.name, gt.name_bytes());
        let gs = gt.tagger().unwrap();
        let ps = pt.tagger.as_ref().unwrap();
        assert_eq!(ps.name, gs.name_bytes());
        assert_eq!(ps.time, gs.when().seconds());
        assert_eq!(pt.message, gt.message_bytes().unwrap_or(b""));
    }

    // HEAD resolution and the ref listing.
    assert_eq!(pg.head_id().unwrap(), pg_oid(merge));
    let refs = pg.refs().list().unwrap();
    assert_eq!(refs["refs/heads/main"], pg_oid(merge));
    assert_eq!(refs["refs/tags/v1.0"], pg_oid(tag_commit));
    assert_eq!(refs["refs/tags/light"], pg_oid(child));
}

#[test]
fn refs_symbolic_and_packed() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let tree = g2_tree(&g2, &[("f", 0o100644, b"1\n")]);
    let c1 = g2_commit(&g2, tree, &[], 1_000, "one\n");
    let c2 = g2_commit(&g2, tree, &[c1], 2_000, "two\n");
    let c3 = g2_commit(&g2, tree, &[c2], 3_000, "three\n");

    g2.reference("refs/heads/main", c3, true, "init").unwrap();
    g2.reference("refs/heads/feature/deep/name", c2, true, "x")
        .unwrap();
    g2.reference("refs/remotes/origin/main", c1, true, "x")
        .unwrap();
    g2.reference_symbolic(
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
        true,
        "x",
    )
    .unwrap();
    let sig = g2_sig(4_000, 60);
    let annotated = g2
        .tag(
            "v2",
            &g2.find_object(c2, None).unwrap(),
            &sig,
            "two\n",
            false,
        )
        .unwrap();
    g2.tag_lightweight("v1", &g2.find_object(c1, None).unwrap(), false)
        .unwrap();
    g2.reference("refs/notes/commits", c1, true, "x").unwrap();

    // Snapshot libgit2's resolved view of every ref.
    let snapshot = |g2: &git2::Repository| -> BTreeMap<String, ObjectId> {
        g2.references()
            .unwrap()
            .map(|r| r.unwrap())
            .map(|r| {
                let name = r.name().unwrap().to_string();
                let id = r.resolve().unwrap().target().unwrap();
                (name, pg_oid(id))
            })
            .collect()
    };

    // Loose refs.
    let pg = pg_open(dir.path());
    assert_eq!(pg.refs().list().unwrap(), snapshot(&g2));
    assert_eq!(
        pg.refs().lookup("refs/remotes/origin/HEAD").unwrap(),
        Reference::Symbolic("refs/remotes/origin/main".into())
    );
    assert_eq!(
        pg.head().unwrap(),
        Reference::Symbolic("refs/heads/main".into())
    );

    // Pack every ref (libgit2 writes `packed-refs` with peeled tags and
    // removes the loose files).
    g2.refdb_compress().unwrap();
    assert!(dir.path().join(".git/packed-refs").is_file());
    assert!(!dir.path().join(".git/refs/heads/main").exists());
    let pg = pg_open(dir.path());
    assert_eq!(pg.refs().list().unwrap(), snapshot(&g2));
    for name in [
        "refs/heads/main",
        "refs/tags/v2",
        "refs/heads/feature/deep/name",
    ] {
        let g2_id = g2.refname_to_id(name).unwrap();
        assert_eq!(pg.refs().resolve(name).unwrap(), pg_oid(g2_id), "{name}");
    }
    // Peeled annotated tag.
    let packed = pg.refs().packed().unwrap();
    let v2 = packed.iter().find(|p| p.name == "refs/tags/v2").unwrap();
    assert_eq!(v2.id, pg_oid(annotated));
    assert_eq!(v2.peeled, Some(pg_oid(c2)));
    // A lightweight tag carries no peel line.
    let v1 = packed.iter().find(|p| p.name == "refs/tags/v1").unwrap();
    assert_eq!(v1.peeled, None);
    // Symbolic refs stay loose (packed-refs cannot hold them).
    assert_eq!(
        pg.refs().resolve("refs/remotes/origin/HEAD").unwrap(),
        pg_oid(c1)
    );

    // A loose ref written after packing shadows the packed one, and a ref
    // libgit2 deletes from packed-refs is gone for puregit too.
    g2.reference("refs/heads/main", c1, true, "rewind").unwrap();
    g2.find_reference("refs/notes/commits")
        .unwrap()
        .delete()
        .unwrap();
    let pg = pg_open(dir.path());
    assert_eq!(pg.refs().resolve("refs/heads/main").unwrap(), pg_oid(c1));
    assert!(pg.refs().resolve("refs/notes/commits").is_err());
    assert_eq!(pg.refs().list().unwrap(), snapshot(&g2));
}

/// libgit2's index entry flag bits (`git_index_entry`).
const STAGE_SHIFT: u16 = 12;
const INTENT_TO_ADD: u16 = 1 << 13;
const SKIP_WORKTREE: u16 = 1 << 14;

fn g2_entry(path: &str, mode: u32, id: git2::Oid, seed: u32) -> git2::IndexEntry {
    git2::IndexEntry {
        ctime: git2::IndexTime::new(1_600_000_000 + seed as i32, seed * 3),
        mtime: git2::IndexTime::new(1_600_000_500 + seed as i32, seed * 7),
        dev: 100 + seed,
        ino: 2000 + seed,
        mode,
        uid: 1000 + seed,
        gid: 50 + seed,
        file_size: 10 * seed,
        id,
        flags: 0,
        flags_extended: 0,
        path: path.as_bytes().to_vec(),
    }
}

/// libgit2's view of the index file as it is on disk (a fresh read, not the
/// repository's cached in-memory index).
fn disk_index(work: &Path) -> git2::Index {
    git2::Index::open(&work.join(".git/index")).unwrap()
}

/// The format version recorded in the on-disk index header.
fn disk_index_version(work: &Path) -> u32 {
    let raw = std::fs::read(work.join(".git/index")).unwrap();
    u32::from_be_bytes(raw[4..8].try_into().unwrap())
}

/// Compares every field of libgit2's index entries with puregit's parse of
/// the same file, in file order.
fn assert_index_matches(g2_index: &git2::Index, pg_index: &puregit::index::Index) {
    let g2_entries: Vec<git2::IndexEntry> = g2_index.iter().collect();
    assert_eq!(pg_index.entries.len(), g2_entries.len(), "entry count");
    for (p, g) in pg_index.entries.iter().zip(&g2_entries) {
        let path = String::from_utf8_lossy(&g.path);
        assert_eq!(p.path, g.path);
        assert_eq!(p.mode, g.mode, "{path}: mode");
        assert_eq!(p.id, pg_oid(g.id), "{path}: id");
        assert_eq!(
            p.stage as u16,
            (g.flags >> STAGE_SHIFT) & 3,
            "{path}: stage"
        );
        assert_eq!(
            p.assume_valid,
            g.flags & 0x8000 != 0,
            "{path}: assume-valid"
        );
        assert_eq!(p.ctime, (g.ctime.seconds() as u32, g.ctime.nanoseconds()));
        assert_eq!(p.mtime, (g.mtime.seconds() as u32, g.mtime.nanoseconds()));
        assert_eq!(
            (p.dev, p.ino, p.uid, p.gid, p.size),
            (g.dev, g.ino, g.uid, g.gid, g.file_size),
            "{path}: stat"
        );
    }
}

#[test]
fn index_entries_stages_and_stat_data() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let work = dir.path();

    // Real files staged through the worktree (libgit2 fills in stat data).
    write_file(work, "README.md", b"# readme\n");
    write_file(work, "src/lib.rs", b"pub fn f() {}\n");
    write_file(work, "bin/run.sh", b"#!/bin/sh\n");
    set_executable(&work.join("bin/run.sh"), true);
    let mut index = g2.index().unwrap();
    for p in ["README.md", "src/lib.rs", "bin/run.sh"] {
        index.add_path(Path::new(p)).unwrap();
    }

    // Synthetic entries with every mode and distinctive stat fields.
    let blob = g2.blob(b"synthetic\n").unwrap();
    let link = g2.blob(b"README.md").unwrap();
    index.add(&g2_entry("z/exec", 0o100755, blob, 1)).unwrap();
    index.add(&g2_entry("z/link", 0o120000, link, 2)).unwrap();
    index.add(&g2_entry("z/sub", 0o160000, blob, 3)).unwrap();
    let mut assumed = g2_entry("z/assumed", 0o100644, blob, 4);
    assumed.flags |= 0x8000;
    index.add(&assumed).unwrap();
    // A path longer than the 12-bit name-length field (0xFFF).
    let long_path = format!("long/{}", "x".repeat(5000));
    index.add(&g2_entry(&long_path, 0o100644, blob, 5)).unwrap();

    // A conflict: stages 1, 2 and 3 for one path.
    for (stage, content, mode) in [
        (1u16, &b"base\n"[..], 0o100644),
        (2, b"ours\n", 0o100644),
        (3, b"theirs\n", 0o100755),
    ] {
        let mut e = g2_entry(
            "conflicted.txt",
            mode,
            g2.blob(content).unwrap(),
            5 + stage as u32,
        );
        e.flags |= stage << STAGE_SHIFT;
        index.add(&e).unwrap();
    }
    // A cache-tree extension cannot be written while conflicts exist; write
    // the file with entries only.
    index.write().unwrap();

    let pg = pg_open(work);
    let pg_index = pg.index().unwrap();
    assert_eq!(pg_index.version, disk_index_version(work));
    assert_index_matches(&disk_index(work), &pg_index);
    let stages: Vec<u8> = pg_index
        .entries
        .iter()
        .filter(|e| e.path == b"conflicted.txt")
        .map(|e| e.stage)
        .collect();
    assert_eq!(stages, [1, 2, 3]);
    if exec_bits_supported() {
        assert_eq!(pg_index.get(b"bin/run.sh").unwrap().mode, 0o100755);
    }

    // puregit's own serialization of the parsed index is byte-identical to
    // libgit2's file (same entries, same padding, same extensions, same
    // checksum).
    let on_disk = std::fs::read(work.join(".git/index")).unwrap();
    assert_eq!(pg_index.serialize(), on_disk);
}

#[test]
fn index_with_cache_tree_and_tree_from_index() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let work = dir.path();
    for (p, c) in [
        ("a.txt", "a\n"),
        ("dir/b.txt", "b\n"),
        ("dir/sub/c.txt", "c\n"),
        ("dir-x", "dx\n"),
        ("e", "e\n"),
    ] {
        write_file(work, p, c.as_bytes());
    }
    let mut index = g2.index().unwrap();
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    // write_tree populates libgit2's cache-tree, which then lands in the
    // index file as a TREE extension.
    let g2_tree_id = index.write_tree().unwrap();
    index.write().unwrap();

    let pg = pg_open(work);
    let pg_index = pg.index().unwrap();
    assert_index_matches(&disk_index(dir.path()), &pg_index);
    // puregit builds the same tree from the same index.
    let pg_tree_id = puregit::tree_builder::write_tree_from_index(pg.objects(), &pg_index).unwrap();
    assert_eq!(pg_tree_id, pg_oid(g2_tree_id));
    // ...and keeps the TREE extension verbatim when re-serializing unchanged.
    assert_eq!(
        pg_index.serialize(),
        std::fs::read(work.join(".git/index")).unwrap()
    );
}

#[test]
fn index_extended_flags_v3() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let blob = g2.blob(b"x\n").unwrap();
    let mut index = g2.index().unwrap();
    index.add(&g2_entry("plain", 0o100644, blob, 1)).unwrap();
    let mut ita = g2_entry("intent", 0o100644, blob, 2);
    ita.flags_extended |= INTENT_TO_ADD;
    index.add(&ita).unwrap();
    let mut skip = g2_entry("skipped", 0o100644, blob, 3);
    skip.flags_extended |= SKIP_WORKTREE;
    index.add(&skip).unwrap();
    index.write().unwrap();
    // Extended flags force index format version 3 on disk.
    assert_eq!(disk_index_version(dir.path()), 3);

    let pg = pg_open(dir.path());
    let pg_index = pg.index().unwrap();
    assert_eq!(pg_index.version, 3);
    assert_index_matches(&disk_index(dir.path()), &pg_index);
    // Re-serialized unchanged, the file must be identical: the extended flags
    // (intent-to-add, skip-worktree) must survive a puregit round-trip.
    assert_eq!(
        pg_index.serialize(),
        std::fs::read(dir.path().join(".git/index")).unwrap()
    );
}

#[test]
fn index_version_4() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let blob = g2.blob(b"x\n").unwrap();
    let mut index = g2.index().unwrap();
    for (i, p) in [
        "dir/file-a",
        "dir/file-b",
        "dir/sub/deep-1",
        "dir/sub/deep-2",
        "other",
    ]
    .iter()
    .enumerate()
    {
        index.add(&g2_entry(p, 0o100644, blob, i as u32)).unwrap();
    }
    index.set_version(4).unwrap();
    index.write().unwrap();

    let pg = pg_open(dir.path());
    let pg_index = pg
        .index()
        .expect("puregit reads a v4 (path-compressed) index");
    assert_eq!(pg_index.version, 4);
    assert_index_matches(&disk_index(dir.path()), &pg_index);
    assert_eq!(
        pg_index.serialize(),
        std::fs::read(dir.path().join(".git/index")).unwrap()
    );
}

#[test]
fn config_values() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let values: &[(&str, &str)] = &[
        ("interop.plain", "plain"),
        ("interop.words", "two words"),
        ("interop.padded", "  leading and trailing  "),
        ("interop.hash", "has # hash"),
        ("interop.semi", "semi ; colon"),
        ("interop.quote", "say \"hi\""),
        ("interop.backslash", "C:\\Users\\tester\\repo"),
        ("interop.tab", "a\tb"),
        ("interop.newline", "line1\nline2"),
        ("interop.empty", ""),
        ("interop.unicode", "caf\u{e9} \u{4e2d}"),
        ("interop.url", "https://example.com/a#frag;x"),
        ("Interop.MixedCase", "key case folds"),
        ("remote.Origin.Dots.url", "subsection with dots and case"),
        ("branch.feature/x.merge", "refs/heads/feature/x"),
    ];
    {
        let mut cfg = g2
            .config()
            .unwrap()
            .open_level(git2::ConfigLevel::Local)
            .unwrap();
        for (k, v) in values {
            cfg.set_str(k, v).unwrap();
        }
        cfg.set_bool("interop.yes", true).unwrap();
        cfg.set_bool("interop.no", false).unwrap();
        cfg.set_i64("interop.big", 1_234_567_890_123).unwrap();
        cfg.set_i32("interop.negative", -42).unwrap();
        cfg.set_multivar("interop.multi", "^$", "first").unwrap();
        cfg.set_multivar("interop.multi", "^$", "second").unwrap();
        cfg.set_multivar("interop.multi", "^$", "third value")
            .unwrap();
    }
    let g2cfg = g2
        .config()
        .unwrap()
        .open_level(git2::ConfigLevel::Local)
        .unwrap();
    let pg = pg_open(dir.path());
    let pgcfg = pg.config().unwrap();

    // Splits "section.sub.section.name" the way git does: first and last dots.
    fn split(key: &str) -> (&str, Option<&str>, &str) {
        let first = key.find('.').unwrap();
        let last = key.rfind('.').unwrap();
        let sub = (first != last).then(|| &key[first + 1..last]);
        (&key[..first], sub, &key[last + 1..])
    }
    for (k, v) in values {
        let (s, ss, n) = split(k);
        assert_eq!(g2cfg.get_string(k).unwrap(), *v, "libgit2 {k}");
        assert_eq!(pgcfg.get(s, ss, n), Some(*v), "puregit {k}");
    }
    assert_eq!(pgcfg.get_bool("interop", None, "yes"), Some(true));
    assert_eq!(pgcfg.get_bool("interop", None, "no"), Some(false));
    assert_eq!(pgcfg.get("interop", None, "big"), Some("1234567890123"));
    assert_eq!(pgcfg.get("interop", None, "negative"), Some("-42"));
    assert_eq!(
        pgcfg.get_all("interop", None, "multi"),
        ["first", "second", "third value"]
    );
    // The values libgit2's init wrote are visible too.
    assert_eq!(pgcfg.get_bool("core", None, "bare"), Some(false));
    assert_eq!(pgcfg.get_bool("core", None, "autocrlf"), Some(false));
}

#[test]
fn reflogs_written_by_libgit2_and_expired_by_puregit() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let tree = g2_tree(&g2, &[("f", 0o100644, b"x\n")]);
    let c1 = g2_commit(&g2, tree, &[], 1_000, "c1\n");
    let c2 = g2_commit(&g2, tree, &[c1], 2_000, "c2\n");
    let c3 = g2_commit(&g2, tree, &[c2], 3_000, "c3\n");
    g2.reference("refs/heads/main", c3, true, "seed").unwrap();

    // A reflog with fixed timestamps (libgit2 appends with the given
    // committer, so the times are deterministic).
    let mut log = g2.reflog("refs/heads/main").unwrap();
    while !log.is_empty() {
        log.remove(0, false).unwrap();
    }
    log.append(c1, &g2_sig(1_000, 0), Some("commit (initial): c1"))
        .unwrap();
    log.append(c2, &g2_sig(2_000, 120), Some("commit: c2"))
        .unwrap();
    log.append(c3, &g2_sig(3_000, -60), Some("commit: c3"))
        .unwrap();
    log.write().unwrap();

    let pg = pg_open(dir.path());
    // puregit parses each line's timestamp: dropping everything before 2500
    // removes exactly the first two entries.
    let removed = pg.reflog_expire("refs/heads/main", 2_500).unwrap();
    assert_eq!(removed, 2);

    // libgit2 still reads the rewritten log, with the surviving entry intact.
    let log = g2.reflog("refs/heads/main").unwrap();
    assert_eq!(log.len(), 1);
    let e = log.get(0).unwrap();
    assert_eq!(e.id_new(), c3);
    assert_eq!(e.id_old(), c2);
    assert_eq!(e.committer().when().seconds(), 3_000);
    assert_eq!(e.committer().when().offset_minutes(), -60);
    assert_eq!(e.message(), Ok(Some("commit: c3")));
}

/// A history of many similar versions of a large file, so that libgit2's
/// packbuilder produces OFS_DELTA chains.
fn deltifiable_history(g2: &git2::Repository, versions: usize) -> Vec<git2::Oid> {
    let mut lines: Vec<String> = (0..400).map(|i| format!("line number {i}\n")).collect();
    let mut parents = Vec::new();
    let mut commits = Vec::new();
    for v in 0..versions {
        lines[(v * 37) % 400] = format!("changed in version {v}\n");
        lines.push(format!("appended {v}\n"));
        let content: String = lines.concat();
        let tree = g2_tree(
            g2,
            &[
                ("big.txt", 0o100644, content.as_bytes()),
                ("docs/notes.md", 0o100644, format!("v{v}\n").as_bytes()),
                ("static.bin", 0o100644, &[7u8; 3000]),
            ],
        );
        let c = g2_commit(g2, tree, &parents, 10_000 + v as i64, &format!("v{v}\n"));
        parents = vec![c];
        commits.push(c);
    }
    g2.reference("refs/heads/main", *commits.last().unwrap(), true, "x")
        .unwrap();
    commits
}

fn g2_pack_of(g2: &git2::Repository) -> Vec<u8> {
    let mut walk = g2.revwalk().unwrap();
    walk.push_ref("refs/heads/main").unwrap();
    let mut pb = g2.packbuilder().unwrap();
    pb.insert_walk(&mut walk).unwrap();
    let mut buf = git2::Buf::new();
    pb.write_buf(&mut buf).unwrap();
    buf.to_vec()
}

#[test]
fn packbuilder_pack_read_by_puregit() {
    let src_dir = tmp();
    let src = g2_init(src_dir.path(), HashAlgo::Sha1);
    deltifiable_history(&src, 12);
    let pack = g2_pack_of(&src);
    let raw_total: usize = g2_all_oids(&src)
        .iter()
        .map(|id| src.odb().unwrap().read(*id).unwrap().len())
        .sum();
    assert!(
        pack.len() * 4 < raw_total,
        "libgit2's pack should be deltified ({} vs {raw_total} bytes)",
        pack.len()
    );

    // 1. puregit parses and explodes the pack stream itself.
    let pg_dir = tmp();
    let pg = pg_init(pg_dir.path(), HashAlgo::Sha1);
    let parsed = puregit::pack::Pack::new(pack.clone(), HashAlgo::Sha1).unwrap();
    assert_eq!(parsed.object_count() as usize, g2_all_oids(&src).len());
    let written = pg.ingest_pack(&pack).unwrap();
    assert_eq!(written.len(), g2_all_oids(&src).len());
    assert_pg_reads_all(&src, &pg);

    // 2. libgit2 stores the pack (+ its own .idx) in a fresh repository; puregit
    //    then reads every object from that packed-only store, resolving deltas.
    let dst_dir = tmp();
    let dst = g2_init(dst_dir.path(), HashAlgo::Sha1);
    {
        let odb = dst.odb().unwrap();
        let mut deltas = 0usize;
        let mut pw = odb.packwriter().unwrap();
        pw.progress(|p| {
            deltas = p.total_deltas();
            true
        });
        pw.write_all(&pack).unwrap();
        pw.commit().unwrap();
        drop(pw);
        assert!(deltas > 0, "pack should contain deltas");
    }
    let pg = pg_open(dst_dir.path());
    assert!(pg.loose_object_ids().unwrap().is_empty());
    assert_eq!(pg.objects().pack_count(), 1);
    assert_pg_reads_all(&src, &pg);

    // puregit agrees with libgit2's .idx: verify_pack accepts the pair.
    let pack_dir = dst_dir.path().join(".git/objects/pack");
    let idx_path = std::fs::read_dir(&pack_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "idx"))
        .unwrap();
    let idx_bytes = std::fs::read(&idx_path).unwrap();
    let pack_bytes = std::fs::read(idx_path.with_extension("pack")).unwrap();
    let idx = puregit::pack::PackIndex::parse(HashAlgo::Sha1, &idx_bytes).unwrap();
    assert_eq!(idx.len(), g2_all_oids(&src).len());
    let no_external = |id: &ObjectId| -> puregit::Result<(puregit::ObjectType, Vec<u8>)> {
        panic!("libgit2's pack is self-contained, yet {id} was requested")
    };
    let report =
        puregit::pack::verify_pack(&pack_bytes, &idx_bytes, HashAlgo::Sha1, &no_external).unwrap();
    assert!(report.is_ok(), "puregit verify_pack on libgit2's pack");
}

/// The commit graph used by the walk / merge-base / diff tests:
///
/// ```text
///   R(1) - A1(2) - A2(3) - A3(4) ------------- M(10) = merge(A3, B1)
///     \                                       /
///      \------------------------------ B1(9)
///   X(11) = merge(R, A1)       (first parent is the *older* common ancestor)
/// ```
struct Dag {
    r: git2::Oid,
    a1: git2::Oid,
    a2: git2::Oid,
    a3: git2::Oid,
    b1: git2::Oid,
    m: git2::Oid,
    x: git2::Oid,
}

fn build_dag(g2: &git2::Repository) -> Dag {
    let t_r = g2_tree(
        g2,
        &[
            ("keep.txt", 0o100644, b"keep\n"),
            ("mod.txt", 0o100644, b"one\n"),
            ("gone.txt", 0o100644, b"bye\n"),
            ("mode.sh", 0o100644, b"echo\n"),
            ("type", 0o100644, b"regular\n"),
            ("becomes-dir", 0o100644, b"file\n"),
            ("dir/inner.txt", 0o100644, b"inner\n"),
        ],
    );
    let t_a1 = g2_tree(
        g2,
        &[
            ("keep.txt", 0o100644, b"keep\n"),
            ("mod.txt", 0o100644, b"two\n"),
            ("mode.sh", 0o100755, b"echo\n"),
            ("type", 0o120000, b"keep.txt"),
            ("becomes-dir/now.txt", 0o100644, b"file\n"),
            ("dir/inner.txt", 0o100644, b"inner changed\n"),
            ("dir/new.txt", 0o100644, b"new\n"),
            ("added.txt", 0o100644, b"added\n"),
        ],
    );
    let t_a2 = g2_tree(
        g2,
        &[
            ("keep.txt", 0o100644, b"keep\n"),
            ("mod.txt", 0o100644, b"three\n"),
            ("added.txt", 0o100644, b"added\n"),
        ],
    );
    let t_b1 = g2_tree(
        g2,
        &[
            ("keep.txt", 0o100644, b"keep\n"),
            ("mod.txt", 0o100644, b"one\n"),
            ("side.txt", 0o100644, b"side\n"),
        ],
    );
    let r = g2_commit(g2, t_r, &[], 1, "R\n");
    let a1 = g2_commit(g2, t_a1, &[r], 2, "A1\n");
    let a2 = g2_commit(g2, t_a2, &[a1], 3, "A2\n");
    let a3 = g2_commit(g2, t_a2, &[a2], 4, "A3\n");
    let b1 = g2_commit(g2, t_b1, &[r], 9, "B1\n");
    let m = g2_commit(g2, t_a2, &[a3, b1], 10, "M\n");
    let x = g2_commit(g2, t_r, &[r, a1], 11, "X\n");
    g2.reference("refs/heads/main", m, true, "x").unwrap();
    g2.reference("refs/heads/x", x, true, "x").unwrap();
    Dag {
        r,
        a1,
        a2,
        a3,
        b1,
        m,
        x,
    }
}

fn g2_walk(g2: &git2::Repository, tips: &[git2::Oid], sort: git2::Sort) -> Vec<ObjectId> {
    let mut walk = g2.revwalk().unwrap();
    walk.set_sorting(sort).unwrap();
    for t in tips {
        walk.push(*t).unwrap();
    }
    walk.map(|id| pg_oid(id.unwrap())).collect()
}

fn pg_walk(pg: &puregit::Repository, tips: &[ObjectId]) -> Vec<ObjectId> {
    walk::RevWalk::new(pg.objects(), tips)
        .map(|r| r.unwrap().0)
        .collect()
}

/// Every commit appears before all of its parents.
fn assert_topological(pg: &puregit::Repository, order: &[ObjectId]) {
    let pos: BTreeMap<ObjectId, usize> = order.iter().enumerate().map(|(i, c)| (*c, i)).collect();
    for c in order {
        let Object::Commit(commit) = pg.read_object(c).unwrap() else {
            panic!()
        };
        for p in &commit.parents {
            if let Some(pp) = pos.get(p) {
                assert!(pos[c] < *pp, "{c} must come before its parent {p}");
            }
        }
    }
}

#[test]
fn revwalk_order_matches_libgit2() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let d = build_dag(&g2);
    let pg = pg_open(dir.path());

    for tips in [vec![d.m], vec![d.x], vec![d.m, d.x], vec![d.a3, d.b1]] {
        let g2_time = g2_walk(&g2, &tips, git2::Sort::TIME);
        let g2_topo = g2_walk(&g2, &tips, git2::Sort::TOPOLOGICAL | git2::Sort::TIME);
        let pg_tips: Vec<ObjectId> = tips.iter().map(|t| pg_oid(*t)).collect();
        let pg_order = pg_walk(&pg, &pg_tips);
        // Same commit set as libgit2.
        let a: BTreeSet<_> = pg_order.iter().collect();
        let b: BTreeSet<_> = g2_topo.iter().collect();
        assert_eq!(a, b, "walk set from {tips:?}");
        assert_eq!(pg_order.len(), g2_topo.len(), "no duplicates");
        // With strictly increasing commit times, git's default (date) order is
        // also topological; puregit must produce exactly libgit2's TIME order.
        assert_eq!(pg_order, g2_time, "walk order from {tips:?}");
        assert_topological(&pg, &pg_order);
    }
}

#[test]
fn merge_base_and_ancestry_match_libgit2() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let d = build_dag(&g2);
    let pg = pg_open(dir.path());
    let all = [d.r, d.a1, d.a2, d.a3, d.b1, d.m, d.x];
    for &a in &all {
        for &b in &all {
            let g2_base = g2.merge_base(a, b).ok().map(pg_oid);
            let pg_base = walk::merge_base(pg.objects(), &pg_oid(a), &pg_oid(b)).unwrap();
            assert_eq!(pg_base, g2_base, "merge-base({a}, {b})");
            let g2_anc = a == b || g2.graph_descendant_of(b, a).unwrap();
            let pg_anc = walk::is_ancestor(pg.objects(), &pg_oid(a), &pg_oid(b)).unwrap();
            assert_eq!(pg_anc, g2_anc, "is {a} an ancestor of {b}");
        }
    }
}

/// libgit2's name-status diff between two trees, as puregit models it.
fn g2_name_status(g2: &git2::Repository, a: git2::Oid, b: git2::Oid) -> Vec<(Vec<u8>, TreeChange)> {
    let ta = g2.find_commit(a).unwrap().tree().unwrap();
    let tb = g2.find_commit(b).unwrap().tree().unwrap();
    let mut opts = git2::DiffOptions::new();
    // A mode-class change (file <-> symlink) is one "modified" path for
    // puregit; ask libgit2 for typechange records instead of delete+add.
    opts.include_typechange(true);
    let diff = g2
        .diff_tree_to_tree(Some(&ta), Some(&tb), Some(&mut opts))
        .unwrap();
    let mut out: Vec<(Vec<u8>, TreeChange)> = diff
        .deltas()
        .map(|d| {
            let (path, change) = match d.status() {
                git2::Delta::Added => (d.new_file().path_bytes(), TreeChange::Added),
                git2::Delta::Deleted => (d.old_file().path_bytes(), TreeChange::Deleted),
                git2::Delta::Modified | git2::Delta::Typechange => {
                    (d.new_file().path_bytes(), TreeChange::Modified)
                }
                other => panic!("unexpected delta {other:?}"),
            };
            (path.unwrap().to_vec(), change)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn tree_diff_matches_libgit2() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let d = build_dag(&g2);
    let pg = pg_open(dir.path());
    let tree_of = |c: git2::Oid| pg_oid(g2.find_commit(c).unwrap().tree_id());
    let pairs = [
        (d.r, d.a1),
        (d.a1, d.r),
        (d.a1, d.a2),
        (d.r, d.b1),
        (d.b1, d.m),
        (d.r, d.r),
    ];
    for (a, b) in pairs {
        let expected = g2_name_status(&g2, a, b);
        let mut got: Vec<(Vec<u8>, TreeChange)> =
            walk::diff_trees(pg.objects(), Some(&tree_of(a)), Some(&tree_of(b)))
                .unwrap()
                .into_iter()
                .map(|e| (e.path, e.change))
                .collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got, expected, "diff {a}..{b}");
    }
}

#[test]
fn tree_merge_matches_libgit2() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let body: String = (0..30).map(|i| format!("line {i}\n")).collect();
    let ours_body = body.replace("line 2\n", "line 2 (ours)\n");
    let theirs_body = body.replace("line 25\n", "line 25 (theirs)\n");
    let conflict_ours = body.replace("line 10\n", "line 10 OURS\n");
    let conflict_theirs = body.replace("line 10\n", "line 10 THEIRS\n");

    let base = g2_tree(
        &g2,
        &[
            ("shared.txt", 0o100644, body.as_bytes()),
            ("only-ours-changes", 0o100644, b"base\n"),
            ("deleted-by-theirs", 0o100644, b"bye\n"),
            ("conflict.txt", 0o100644, body.as_bytes()),
        ],
    );
    let ours = g2_tree(
        &g2,
        &[
            ("shared.txt", 0o100644, ours_body.as_bytes()),
            ("only-ours-changes", 0o100644, b"ours\n"),
            ("deleted-by-theirs", 0o100644, b"bye\n"),
            ("added-by-ours", 0o100644, b"new ours\n"),
            ("conflict.txt", 0o100644, conflict_ours.as_bytes()),
        ],
    );
    let theirs = g2_tree(
        &g2,
        &[
            ("shared.txt", 0o100644, theirs_body.as_bytes()),
            ("only-ours-changes", 0o100644, b"base\n"),
            ("added-by-theirs/x", 0o100644, b"new theirs\n"),
            ("conflict.txt", 0o100644, conflict_theirs.as_bytes()),
        ],
    );
    let pg = pg_open(dir.path());
    let g2_merge = |with_conflict: bool| {
        let strip = |t: git2::Oid| {
            let mut tb = g2.treebuilder(Some(&g2.find_tree(t).unwrap())).unwrap();
            if !with_conflict {
                tb.remove("conflict.txt").unwrap();
            }
            tb.write().unwrap()
        };
        let (b, o, t) = (strip(base), strip(ours), strip(theirs));
        let mut idx = g2
            .merge_trees(
                &g2.find_tree(b).unwrap(),
                &g2.find_tree(o).unwrap(),
                &g2.find_tree(t).unwrap(),
                None,
            )
            .unwrap();
        (b, o, t, idx.has_conflicts(), {
            if idx.has_conflicts() {
                let mut paths: Vec<Vec<u8>> = idx
                    .conflicts()
                    .unwrap()
                    .map(|c| c.unwrap().our.unwrap().path)
                    .collect();
                paths.sort();
                Err(paths)
            } else {
                Ok(idx.write_tree_to(&g2).unwrap())
            }
        })
    };

    // Clean merge: identical merged tree.
    let (b, o, t, conflicted, result) = g2_merge(false);
    assert!(!conflicted);
    let pg_result =
        puregit::merge::merge_trees(pg.objects(), Some(&pg_oid(b)), &pg_oid(o), &pg_oid(t))
            .unwrap();
    assert!(pg_result.conflicts.is_empty());
    assert_eq!(pg_result.tree, pg_oid(result.unwrap()));

    // Conflicting merge: the same conflicted paths.
    let (b, o, t, conflicted, result) = g2_merge(true);
    assert!(conflicted);
    let pg_result =
        puregit::merge::merge_trees(pg.objects(), Some(&pg_oid(b)), &pg_oid(o), &pg_oid(t))
            .unwrap();
    let mut pg_conflicts = pg_result.conflicts.clone();
    pg_conflicts.sort();
    assert_eq!(pg_conflicts, result.unwrap_err());
}

#[test]
fn status_of_libgit2_worktree() {
    // A worktree committed and staged by libgit2: puregit's status agrees with
    // libgit2's on staged, unstaged and untracked paths.
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let work = dir.path();
    for (p, c) in [
        ("tracked.txt", "v1\n"),
        ("dir/a.txt", "a\n"),
        ("to-delete.txt", "x\n"),
        ("to-stage.txt", "s1\n"),
    ] {
        write_file(work, p, c.as_bytes());
    }
    let mut index = g2.index().unwrap();
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree = index.write_tree().unwrap();
    let sig = g2_sig(1_000, 0);
    g2.commit(
        Some("HEAD"),
        &sig,
        &sig,
        "init\n",
        &g2.find_tree(tree).unwrap(),
        &[],
    )
    .unwrap();

    write_file(work, "tracked.txt", b"v2 changed\n");
    std::fs::remove_file(work.join("to-delete.txt")).unwrap();
    write_file(work, "to-stage.txt", b"s2\n");
    write_file(work, "new-staged.txt", b"n\n");
    write_file(work, "untracked.txt", b"u\n");
    let mut index = g2.index().unwrap();
    index.add_path(Path::new("to-stage.txt")).unwrap();
    index.add_path(Path::new("new-staged.txt")).unwrap();
    index.write().unwrap();

    let pg = pg_open(work);
    let st = puregit::status::status(&pg).unwrap();
    let mut staged: Vec<(String, puregit::status::Change)> = st
        .staged
        .iter()
        .map(|(p, c)| (String::from_utf8_lossy(p).into_owned(), *c))
        .collect();
    staged.sort();
    let mut unstaged: Vec<(String, puregit::status::Change)> = st
        .unstaged
        .iter()
        .map(|(p, c)| (String::from_utf8_lossy(p).into_owned(), *c))
        .collect();
    unstaged.sort();
    let mut untracked: Vec<String> = st
        .untracked
        .iter()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    untracked.sort();

    // libgit2's view.
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    let mut g_staged = Vec::new();
    let mut g_unstaged = Vec::new();
    let mut g_untracked = Vec::new();
    use puregit::status::Change;
    for e in g2.statuses(Some(&mut opts)).unwrap().iter() {
        let p = e.path().unwrap().to_string();
        let s = e.status();
        if s.contains(git2::Status::INDEX_NEW) {
            g_staged.push((p.clone(), Change::Added));
        }
        if s.contains(git2::Status::INDEX_MODIFIED) {
            g_staged.push((p.clone(), Change::Modified));
        }
        if s.contains(git2::Status::INDEX_DELETED) {
            g_staged.push((p.clone(), Change::Deleted));
        }
        if s.contains(git2::Status::WT_MODIFIED) {
            g_unstaged.push((p.clone(), Change::Modified));
        }
        if s.contains(git2::Status::WT_DELETED) {
            g_unstaged.push((p.clone(), Change::Deleted));
        }
        if s.contains(git2::Status::WT_NEW) {
            g_untracked.push(p.clone());
        }
    }
    g_staged.sort();
    g_unstaged.sort();
    g_untracked.sort();
    assert_eq!(staged, g_staged, "staged");
    assert_eq!(unstaged, g_unstaged, "unstaged");
    assert_eq!(untracked, g_untracked, "untracked");
}

#[test]
fn bare_repository_and_commit_graph_independent_reads() {
    // A bare repository created by libgit2 opens bare in puregit, with the
    // same HEAD and objects.
    let dir = tmp();
    let g2 = git2::Repository::init_opts(
        dir.path(),
        git2::RepositoryInitOptions::new()
            .bare(true)
            .initial_head("trunk"),
    )
    .unwrap();
    let tree = g2_tree(&g2, &[("f", 0o100644, b"bare\n")]);
    let c = g2_commit(&g2, tree, &[], 5, "bare\n");
    g2.reference("refs/heads/trunk", c, true, "x").unwrap();
    let pg = pg_open(dir.path());
    assert!(pg.work_tree().is_none());
    assert_eq!(pg.head_id().unwrap(), pg_oid(c));
    assert_pg_reads_all(&g2, &pg);
}
