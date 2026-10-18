//! puregit writes -> libgit2 reads.
//!
//! Each test produces repository state with puregit's API — objects, refs,
//! the index, config, reflogs, packs (+ idx, bitmap, multi-pack-index,
//! commit-graph), merges — and then opens it with libgit2, which must find and
//! parse everything and agree on ids and content.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use puregit::object::{Object, Tag};
use puregit::refs::Reference;
use puregit::walk;
use puregit::{HashAlgo, ObjectId, ObjectType};
use puregit_interop_libgit2::*;

fn g2_open(path: &Path) -> git2::Repository {
    hermetic();
    git2::Repository::open(path).expect("libgit2 open")
}

/// Writes a representative object graph with puregit and returns every id.
fn write_graph(pg: &puregit::Repository) -> (Vec<ObjectId>, BTreeMap<&'static str, ObjectId>) {
    let mut ids = Vec::new();
    let mut named = BTreeMap::new();
    let mut large = Vec::new();
    for i in 0..20_000u32 {
        large.extend_from_slice(format!("row {i}\n").as_bytes());
    }
    for blob in [
        &b""[..],
        b"hello\n",
        b"\x00\x01binary\xff",
        b"crlf\r\n",
        &large,
    ] {
        ids.push(pg.write_object(ObjectType::Blob, blob).unwrap());
    }
    let gitlink = ids[1].to_hex();
    let t1 = pg_tree(
        pg,
        &[
            ("a-b", 0o100644, b"dash\n"),
            ("a.b", 0o100644, b"dot\n"),
            ("a/inner.txt", 0o100644, b"inner\n"),
            ("a/deeper/x.sh", 0o100755, b"#!/bin/sh\n"),
            ("a0", 0o100644, b"zero\n"),
            ("link", 0o120000, b"a/inner.txt"),
            ("sub module", 0o160000, gitlink.as_bytes()),
            ("unicode-\u{00e9}.txt", 0o100644, b"utf8\n"),
        ],
    );
    let t2 = pg_tree(pg, &[("only", 0o100644, b"other\n")]);
    let root = pg_commit(pg, t1, &[], 1_600_000_000, "root\n");
    let child = pg_commit(pg, t2, &[root], 1_600_000_100, "child\n\nbody\n");
    let side = pg_commit(pg, t1, &[root], 1_600_000_050, "side");
    let merge = pg_commit(pg, t2, &[child, side], 1_600_000_200, "merge\n");
    let octo = pg_commit(pg, t1, &[child, side, root], 1_600_000_300, "octopus\n");
    // A commit with a non-UTC timezone and an extra header.
    let tz = puregit::object::Commit {
        tree: t1,
        parents: vec![merge],
        author: pg_sig(1_600_000_400, -330),
        committer: pg_sig(1_600_000_401, 545),
        extra_headers: b"encoding ISO-8859-1\n".to_vec(),
        message: b"tz\n".to_vec(),
    };
    let tz = pg
        .write_object(ObjectType::Commit, &tz.serialize())
        .unwrap();
    let tag = Tag {
        object: merge,
        object_type: ObjectType::Commit,
        name: b"v1.0".to_vec(),
        tagger: Some(pg_sig(1_600_000_500, 60)),
        message: b"release\n".to_vec(),
    };
    let tag = pg.write_object(ObjectType::Tag, &tag.serialize()).unwrap();
    let tag_of_tree = Tag {
        object: t2,
        object_type: ObjectType::Tree,
        name: b"tree-tag".to_vec(),
        tagger: Some(pg_sig(1_600_000_600, 0)),
        message: b"".to_vec(),
    };
    let tag_of_tree = pg
        .write_object(ObjectType::Tag, &tag_of_tree.serialize())
        .unwrap();
    ids.extend([t1, t2, root, child, side, merge, octo, tz, tag, tag_of_tree]);
    named.extend([
        ("t1", t1),
        ("root", root),
        ("child", child),
        ("side", side),
        ("merge", merge),
        ("octo", octo),
        ("tz", tz),
        ("tag", tag),
        ("tag_of_tree", tag_of_tree),
    ]);
    (ids, named)
}

#[test]
fn objects_and_refs() {
    let dir = tmp();
    let pg = pg_init(dir.path(), HashAlgo::Sha1);
    let (ids, n) = write_graph(&pg);
    let refs = pg.refs();
    refs.update("refs/heads/main", &Reference::Direct(n["tz"]))
        .unwrap();
    refs.update("refs/heads/topic/deep", &Reference::Direct(n["side"]))
        .unwrap();
    refs.update("refs/tags/v1.0", &Reference::Direct(n["tag"]))
        .unwrap();
    refs.update("refs/tags/tree-tag", &Reference::Direct(n["tag_of_tree"]))
        .unwrap();
    refs.update(
        "refs/remotes/origin/HEAD",
        &Reference::Symbolic("refs/heads/main".into()),
    )
    .unwrap();

    let g2 = g2_open(dir.path());
    assert!(!g2.is_bare());
    assert_eq!(g2.object_format(), git2::ObjectFormat::Sha1);
    assert_g2_reads(&g2, &pg, &ids);

    // libgit2 enumerates exactly the objects puregit wrote.
    let g2_ids: BTreeSet<ObjectId> = g2_all_oids(&g2).into_iter().map(pg_oid).collect();
    let pg_ids: BTreeSet<ObjectId> = pg.loose_object_ids().unwrap().into_iter().collect();
    assert_eq!(g2_ids, pg_ids);

    // Parsed fields agree.
    for cid in ["root", "child", "merge", "octo", "tz"] {
        let id = n[cid];
        let gc = g2.find_commit(g2_oid(&id)).unwrap();
        let Object::Commit(pc) = pg.read_object(&id).unwrap() else {
            panic!()
        };
        assert_eq!(pg_oid(gc.tree_id()), pc.tree);
        assert_eq!(gc.parent_ids().map(pg_oid).collect::<Vec<_>>(), pc.parents);
        assert_eq!(gc.message_raw_bytes(), pc.message);
        assert_eq!(gc.author().when().seconds(), pc.author.time);
        assert_eq!(
            tz_string(gc.author().when().offset_minutes()).into_bytes(),
            pc.author.tz
        );
        assert_eq!(
            tz_string(gc.committer().when().offset_minutes()).into_bytes(),
            pc.committer.tz
        );
    }
    let gc = g2.find_commit(g2_oid(&n["tz"])).unwrap();
    assert_eq!(gc.message_encoding().unwrap(), Some("ISO-8859-1"));
    let tree = g2.find_tree(g2_oid(&n["t1"])).unwrap();
    let modes: BTreeMap<String, i32> = tree
        .iter()
        .map(|e| (e.name().unwrap().to_string(), e.filemode()))
        .collect();
    assert_eq!(modes["link"], 0o120000);
    assert_eq!(modes["sub module"], 0o160000);
    assert_eq!(modes["a"], 0o040000);
    let names: Vec<String> = tree.iter().map(|e| e.name().unwrap().to_string()).collect();
    assert_eq!(
        names,
        [
            "a-b",
            "a.b",
            "a",
            "a0",
            "link",
            "sub module",
            "unicode-\u{00e9}.txt"
        ]
    );
    let gt = g2.find_tag(g2_oid(&n["tag"])).unwrap();
    assert_eq!(gt.name().unwrap(), "v1.0");
    assert_eq!(gt.target_id(), g2_oid(&n["merge"]));
    assert_eq!(gt.message().unwrap(), Some("release\n"));
    assert_eq!(gt.tagger().unwrap().when().offset_minutes(), 60);

    // Refs: libgit2 resolves every ref puregit wrote, symbolic ones included.
    let g2_refs: BTreeMap<String, ObjectId> = g2
        .references()
        .unwrap()
        .map(|r| r.unwrap())
        .map(|r| {
            (
                r.name().unwrap().to_string(),
                pg_oid(r.resolve().unwrap().target().unwrap()),
            )
        })
        .collect();
    assert_eq!(g2_refs, pg.refs().list().unwrap());
    let origin_head = g2.find_reference("refs/remotes/origin/HEAD").unwrap();
    assert_eq!(
        origin_head.symbolic_target().unwrap(),
        Some("refs/heads/main")
    );
    assert_eq!(g2.head().unwrap().name().unwrap(), "refs/heads/main");
    assert_eq!(
        pg_oid(g2.head().unwrap().peel_to_commit().unwrap().id()),
        n["tz"]
    );
    // Tag peeling across puregit-written objects.
    let peeled = g2
        .revparse_single("v1.0^{commit}")
        .unwrap()
        .peel_to_commit()
        .unwrap();
    assert_eq!(pg_oid(peeled.id()), n["merge"]);
}

fn sig(t: i64) -> puregit::object::Signature {
    pg_sig(t, 0)
}

/// Asserts libgit2's on-disk view of the index equals puregit's, field by
/// field (paths, modes, ids, stages, flags, stat data).
fn assert_index_agrees(work: &Path, pg: &puregit::Repository) {
    let g2_index = git2::Index::open(&work.join(".git/index")).unwrap();
    let pg_index = pg.index().unwrap();
    let g: Vec<git2::IndexEntry> = g2_index.iter().collect();
    assert_eq!(g.len(), pg_index.entries.len());
    for (g, p) in g.iter().zip(&pg_index.entries) {
        assert_eq!(g.path, p.path);
        assert_eq!(g.mode, p.mode);
        assert_eq!(pg_oid(g.id), p.id);
        assert_eq!(((g.flags >> 12) & 3) as u8, p.stage);
        assert_eq!(g.file_size, p.size);
        assert_eq!(g.mtime.seconds() as u32, p.mtime.0);
        assert_eq!(g.mtime.nanoseconds(), p.mtime.1);
    }
}

#[test]
fn porcelain_add_commit_branch_checkout() {
    let dir = tmp();
    let work = dir.path();
    let pg = pg_init(work, HashAlgo::Sha1);
    write_file(work, "README.md", b"# hi\n");
    write_file(work, "src/main.rs", b"fn main() {}\n");
    write_file(work, "src/nested/deep.txt", b"deep\n");
    write_file(work, "tool.sh", b"#!/bin/sh\n");
    set_executable(&work.join("tool.sh"), true);
    for p in ["README.md", "src/main.rs", "src/nested/deep.txt", "tool.sh"] {
        pg.add_path(p).unwrap();
    }
    let c1 = pg.commit(b"first\n", sig(1_000), sig(1_000)).unwrap();
    write_file(work, "README.md", b"# hi again\n");
    pg.add_path("README.md").unwrap();
    let c2 = pg.commit(b"second\n", sig(2_000), sig(2_000)).unwrap();
    pg.create_branch("feature", Some(c1)).unwrap();

    let g2 = g2_open(work);
    assert_eq!(pg_oid(g2.head().unwrap().target().unwrap()), c2);
    assert_index_agrees(work, &pg);
    if exec_bits_supported() {
        let idx = git2::Index::open(&work.join(".git/index")).unwrap();
        assert_eq!(
            idx.get_path(Path::new("tool.sh"), 0).unwrap().mode,
            0o100755
        );
    }

    // libgit2 builds the identical tree from puregit's index.
    let mut idx = git2::Index::open(&work.join(".git/index")).unwrap();
    let tree = idx.write_tree_to(&g2).unwrap();
    assert_eq!(
        pg_oid(tree),
        pg_oid(g2.find_commit(g2_oid(&c2)).unwrap().tree_id())
    );

    // A clean worktree for libgit2 too (it trusts or re-hashes the stat data
    // puregit stored, and must find nothing changed).
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true);
    let statuses = g2.statuses(Some(&mut opts)).unwrap();
    let dirty: Vec<String> = statuses
        .iter()
        .map(|e| format!("{:?} {}", e.status(), e.path().unwrap()))
        .collect();
    assert!(dirty.is_empty(), "libgit2 sees changes: {dirty:?}");

    // Reflogs puregit appended are readable by libgit2.
    let log = g2.reflog("refs/heads/main").unwrap();
    assert_eq!(log.len(), 2);
    // Newest first.
    assert_eq!(pg_oid(log.get(0).unwrap().id_new()), c2);
    assert_eq!(pg_oid(log.get(0).unwrap().id_old()), c1);
    assert_eq!(log.get(0).unwrap().message(), Ok(Some("commit: second")));
    assert!(log.get(1).unwrap().id_old().is_zero());
    let head_log = g2.reflog("HEAD").unwrap();
    assert_eq!(head_log.len(), 2);
    let feature_log = g2.reflog("refs/heads/feature").unwrap();
    assert_eq!(feature_log.len(), 1);
    assert_eq!(pg_oid(feature_log.get(0).unwrap().id_new()), c1);

    // Checkout of the other branch: HEAD, index and worktree follow, and
    // libgit2 again sees a clean status.
    pg.checkout("feature").unwrap();
    let g2 = g2_open(work);
    assert_eq!(g2.head().unwrap().name().unwrap(), "refs/heads/feature");
    assert_index_agrees(work, &pg);
    let statuses = g2.statuses(Some(&mut opts)).unwrap();
    assert_eq!(statuses.len(), 0, "clean after puregit checkout");
    assert_eq!(std::fs::read(work.join("README.md")).unwrap(), b"# hi\n");
    let head_log = g2.reflog("HEAD").unwrap();
    assert_eq!(
        head_log.get(0).unwrap().message(),
        Ok(Some("checkout: moving from main to feature"))
    );
}

#[test]
fn puregit_status_matches_libgit2() {
    let dir = tmp();
    let work = dir.path();
    let pg = pg_init(work, HashAlgo::Sha1);
    for (p, c) in [
        ("keep.txt", "k\n"),
        ("modify.txt", "m1\n"),
        ("delete.txt", "d\n"),
        ("stage-mod.txt", "s1\n"),
        ("dir/a.txt", "a\n"),
    ] {
        write_file(work, p, c.as_bytes());
        pg.add_path(p).unwrap();
    }
    write_file(work, "will-be-exec.sh", b"echo\n");
    pg.add_path("will-be-exec.sh").unwrap();
    #[cfg(unix)]
    {
        // Symlinks staged by puregit (to a file, a directory, nowhere) are
        // links for libgit2 too, and clean for both.
        std::os::unix::fs::symlink("keep.txt", work.join("file-link")).unwrap();
        std::os::unix::fs::symlink("dir", work.join("dir-link")).unwrap();
        std::os::unix::fs::symlink("nowhere", work.join("dangling")).unwrap();
        for l in ["file-link", "dir-link", "dangling"] {
            pg.add_path(l).unwrap();
        }
    }
    pg.commit(b"base\n", sig(1), sig(1)).unwrap();
    if symlinks_supported() {
        let g2 = g2_open(work);
        let idx = git2::Index::open(&work.join(".git/index")).unwrap();
        for l in ["file-link", "dir-link", "dangling"] {
            let e = idx.get_path(Path::new(l), 0).unwrap();
            assert_eq!(e.mode, 0o120000, "{l}");
            let target = g2.find_blob(e.id).unwrap();
            assert_eq!(
                std::fs::read_link(work.join(l))
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .as_bytes(),
                target.content()
            );
        }
    }
    // chmod +x is a modification for both (where there are exec bits).
    set_executable(&work.join("will-be-exec.sh"), true);
    write_file(work, "modify.txt", b"m2 longer\n");
    std::fs::remove_file(work.join("delete.txt")).unwrap();
    write_file(work, "stage-mod.txt", b"s2\n");
    pg.add_path("stage-mod.txt").unwrap();
    write_file(work, "new-staged.txt", b"n\n");
    pg.add_path("new-staged.txt").unwrap();
    write_file(work, "dir/untracked.txt", b"u\n");

    use puregit::status::Change;
    let st = puregit::status::status(&pg).unwrap();
    let fmt = |v: &[(Vec<u8>, Change)]| -> Vec<(String, Change)> {
        let mut v: Vec<(String, Change)> = v
            .iter()
            .map(|(p, c)| (String::from_utf8_lossy(p).into_owned(), *c))
            .collect();
        v.sort();
        v
    };
    let g2 = g2_open(work);
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    let (mut gs, mut gu, mut gn) = (Vec::new(), Vec::new(), Vec::new());
    for e in g2.statuses(Some(&mut opts)).unwrap().iter() {
        let p = e.path().unwrap().to_string();
        let s = e.status();
        for (flag, list, ch) in [
            (git2::Status::INDEX_NEW, 0, Change::Added),
            (git2::Status::INDEX_MODIFIED, 0, Change::Modified),
            (git2::Status::INDEX_DELETED, 0, Change::Deleted),
            (git2::Status::WT_MODIFIED, 1, Change::Modified),
            (git2::Status::WT_DELETED, 1, Change::Deleted),
        ] {
            if s.contains(flag) {
                if list == 0 {
                    gs.push((p.clone(), ch));
                } else {
                    gu.push((p.clone(), ch));
                }
            }
        }
        if s.contains(git2::Status::WT_NEW) {
            gn.push(p.clone());
        }
    }
    gs.sort();
    gu.sort();
    gn.sort();
    assert_eq!(fmt(&st.staged), gs, "staged");
    assert_eq!(fmt(&st.unstaged), gu, "unstaged");
    if exec_bits_supported() {
        assert!(gu.contains(&("will-be-exec.sh".to_string(), Change::Modified)));
    }
    let mut untracked: Vec<String> = st
        .untracked
        .iter()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    untracked.sort();
    assert_eq!(untracked, gn, "untracked");
}

#[test]
fn puregit_add_invalidates_libgit2_cache_tree() {
    // libgit2 commits through its index, which stores a cache-tree (TREE
    // extension). puregit then stages a modification: the index it writes back
    // must not carry a stale cache-tree, or libgit2 (and git) would build the
    // *old* tree from it.
    let dir = tmp();
    let work = dir.path();
    let g2 = g2_init(work, HashAlgo::Sha1);
    write_file(work, "a.txt", b"one\n");
    write_file(work, "dir/b.txt", b"two\n");
    let mut idx = g2.index().unwrap();
    idx.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    let tree = idx.write_tree().unwrap();
    idx.write().unwrap();
    let s = g2_sig(1, 0);
    g2.commit(
        Some("HEAD"),
        &s,
        &s,
        "c\n",
        &g2.find_tree(tree).unwrap(),
        &[],
    )
    .unwrap();
    let raw = std::fs::read(work.join(".git/index")).unwrap();
    assert!(
        raw.windows(4).any(|w| w == b"TREE"),
        "libgit2 should have written a cache-tree"
    );

    let pg = puregit::Repository::open(work).unwrap();
    write_file(work, "dir/b.txt", b"two, modified\n");
    pg.add_path("dir/b.txt").unwrap();
    let expected =
        puregit::tree_builder::write_tree_from_index(pg.objects(), &pg.index().unwrap()).unwrap();
    assert_ne!(pg_oid(tree), expected);

    let g2 = g2_open(work);
    let mut idx = git2::Index::open(&work.join(".git/index")).unwrap();
    let g2_tree = idx.write_tree_to(&g2).unwrap();
    assert_eq!(pg_oid(g2_tree), expected, "libgit2 used a stale cache-tree");
}

#[test]
fn puregit_rewrites_index_keeping_extended_flags() {
    // libgit2 writes intent-to-add / skip-worktree entries (index v3); after
    // puregit stages an unrelated file, libgit2 must still see those flags.
    let dir = tmp();
    let work = dir.path();
    let g2 = g2_init(work, HashAlgo::Sha1);
    let blob = g2.blob(b"").unwrap();
    let mut idx = g2.index().unwrap();
    for (path, ext) in [("intent.txt", 1u16 << 13), ("sparse.txt", 1 << 14)] {
        idx.add(&git2::IndexEntry {
            ctime: git2::IndexTime::new(0, 0),
            mtime: git2::IndexTime::new(0, 0),
            dev: 0,
            ino: 0,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            file_size: 0,
            id: blob,
            flags: 0,
            flags_extended: ext,
            path: path.as_bytes().to_vec(),
        })
        .unwrap();
    }
    idx.write().unwrap();

    let pg = puregit::Repository::open(work).unwrap();
    write_file(work, "other.txt", b"other\n");
    pg.add_path("other.txt").unwrap();

    let idx = git2::Index::open(&work.join(".git/index")).unwrap();
    let flags: BTreeMap<String, u16> = idx
        .iter()
        .map(|e| (String::from_utf8(e.path).unwrap(), e.flags_extended))
        .collect();
    assert_eq!(
        flags["intent.txt"] & (1 << 13),
        1 << 13,
        "intent-to-add lost"
    );
    assert_eq!(
        flags["sparse.txt"] & (1 << 14),
        1 << 14,
        "skip-worktree lost"
    );
    assert_eq!(flags["other.txt"], 0);
}

/// Builds a history of many similar versions of a big file with puregit.
fn pg_history(pg: &puregit::Repository, versions: usize) -> Vec<ObjectId> {
    let mut lines: Vec<String> = (0..300).map(|i| format!("line {i}\n")).collect();
    let mut parents = Vec::new();
    let mut commits = Vec::new();
    for v in 0..versions {
        lines[(v * 13) % 300] = format!("edited in {v}\n");
        let content = lines.concat();
        let tree = pg_tree(
            pg,
            &[
                ("big.txt", 0o100644, content.as_bytes()),
                ("v.txt", 0o100644, format!("{v}\n").as_bytes()),
            ],
        );
        let c = pg_commit(pg, tree, &parents, 5_000 + v as i64, &format!("v{v}\n"));
        parents = vec![c];
        commits.push(c);
    }
    pg.refs()
        .update(
            "refs/heads/main",
            &Reference::Direct(*commits.last().unwrap()),
        )
        .unwrap();
    commits
}

fn pack_files(work: &Path, ext: &str) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(work.join(".git/objects/pack"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == ext))
        .collect();
    v.sort();
    v
}

#[test]
fn puregit_pack_and_idx_accepted_by_libgit2() {
    let dir = tmp();
    let work = dir.path();
    let mut pg = pg_init(work, HashAlgo::Sha1);
    let commits = pg_history(&pg, 10);
    let all: Vec<ObjectId> = pg.loose_object_ids().unwrap();
    let packed = pg.repack().unwrap();
    assert_eq!(packed, all.len());
    assert!(pg.loose_object_ids().unwrap().is_empty());

    // libgit2 reads every (deltified) object from puregit's pack via its idx.
    let g2 = g2_open(work);
    assert_g2_reads(&g2, &pg, &all);
    assert_eq!(g2_all_oids(&g2).len(), all.len());

    // History is walkable by libgit2.
    let mut walk = g2.revwalk().unwrap();
    walk.push_head().unwrap();
    assert_eq!(walk.count(), commits.len());

    // libgit2's indexer re-indexes puregit's pack (verifying every object and
    // delta) and produces a byte-identical .idx.
    let pack_path = pack_files(work, "pack").remove(0);
    let pack = std::fs::read(&pack_path).unwrap();
    let our_idx = std::fs::read(pack_path.with_extension("idx")).unwrap();
    let out = tmp();
    let mut indexer = git2::Indexer::new(None, out.path(), 0, true).unwrap();
    let mut deltas = 0;
    indexer.progress(|p| {
        deltas = p.total_deltas();
        true
    });
    indexer.write_all(&pack).unwrap();
    let name = indexer.commit().unwrap();
    assert!(deltas > 0, "puregit's pack should contain deltas");
    assert_eq!(
        pack_path.file_stem().unwrap().to_str().unwrap(),
        format!("pack-{name}")
    );
    let their_idx = std::fs::read(out.path().join(format!("pack-{name}.idx"))).unwrap();
    assert_eq!(our_idx, their_idx, "puregit's .idx differs from libgit2's");
}

#[test]
fn thin_and_ref_delta_pack_ingested_by_libgit2() {
    // A pack whose objects REF_DELTA against bases the receiver already has
    // (a thin pack, as a fetch/push sends): libgit2's packwriter must complete
    // it against its own object database.
    let base_dir = tmp();
    let pg = pg_init(base_dir.path(), HashAlgo::Sha1);
    let base_body: String = (0..500).map(|i| format!("base line {i}\n")).collect();
    let new_body = base_body.replace("base line 250\n", "changed line 250\n");
    let base_blob = pg
        .write_object(ObjectType::Blob, base_body.as_bytes())
        .unwrap();

    let mut w = puregit::pack::PackWriter::new(HashAlgo::Sha1);
    w.add_external_base(ObjectType::Blob, base_body.as_bytes());
    let new_blob = w.add(ObjectType::Blob, new_body.as_bytes());
    let out = w.finish().unwrap();
    assert!(out.pack.len() < 200, "thin pack should hold just a delta");

    let g2_dir = tmp();
    let g2 = g2_init(g2_dir.path(), HashAlgo::Sha1);
    g2.blob(base_body.as_bytes()).unwrap();
    assert_eq!(pg_oid(g2.blob(base_body.as_bytes()).unwrap()), base_blob);
    let odb = g2.odb().unwrap();
    let mut pw = odb.packwriter().unwrap();
    pw.write_all(&out.pack).unwrap();
    pw.commit().unwrap();
    drop(pw);
    let obj = odb.read(g2_oid(&new_blob)).unwrap();
    assert_eq!(obj.data(), new_body.as_bytes());
}

#[test]
fn bitmap_midx_and_commit_graph_tolerated_by_libgit2() {
    let dir = tmp();
    let work = dir.path();
    let mut pg = pg_init(work, HashAlgo::Sha1);
    let first = pg_history(&pg, 4);
    // Pack 1 with a bitmap + reverse index.
    pg.repack_with_bitmap().unwrap();
    assert_eq!(pack_files(work, "bitmap").len(), 1);
    assert_eq!(pack_files(work, "rev").len(), 1);
    // Pack 2: more history on top, packed from loose objects.
    let tree = pg_tree(&pg, &[("more", 0o100644, b"more\n")]);
    let tip = pg_commit(&pg, tree, &[*first.last().unwrap()], 9_000, "more\n");
    pg.refs()
        .update("refs/heads/main", &Reference::Direct(tip))
        .unwrap();
    pg.repack().unwrap();
    assert_eq!(pack_files(work, "pack").len(), 2);
    // A multi-pack-index over both packs and a commit-graph.
    assert_eq!(pg.write_multi_pack_index().unwrap(), 2);
    let graphed = pg.write_commit_graph().unwrap();
    assert_eq!(graphed, first.len() + 1);
    let mut cfg = pg.config().unwrap();
    cfg.set("core", None, "commitGraph", "true");
    cfg.set("core", None, "multiPackIndex", "true");
    pg.write_config(&cfg).unwrap();

    let g2 = g2_open(work);
    let mut all = Vec::new();
    for c in walk::RevWalk::new(pg.objects(), &[tip]) {
        all.push(c.unwrap().0);
    }
    let reachable = walk::reachable_objects(pg.objects(), &[tip]).unwrap();
    let reachable: Vec<ObjectId> = reachable.into_iter().collect();
    assert_g2_reads(&g2, &pg, &reachable);
    // libgit2 walks (with the commit-graph enabled) the same history.
    let mut walk = g2.revwalk().unwrap();
    walk.set_sorting(git2::Sort::TIME).unwrap();
    walk.push(g2_oid(&tip)).unwrap();
    let g2_order: Vec<ObjectId> = walk.map(|r| pg_oid(r.unwrap())).collect();
    assert_eq!(g2_order, all);
    assert_eq!(
        pg_oid(g2.merge_base(g2_oid(&tip), g2_oid(&first[1])).unwrap()),
        first[1]
    );
}

#[test]
fn config_written_by_puregit() {
    let dir = tmp();
    let pg = pg_init(dir.path(), HashAlgo::Sha1);
    let values: &[(&str, Option<&str>, &str, &str)] = &[
        ("interop", None, "plain", "plain"),
        ("interop", None, "words", "two words"),
        ("interop", None, "padded", "  padded  "),
        ("interop", None, "hash", "has # hash"),
        ("interop", None, "semi", "semi ; colon"),
        ("interop", None, "quote", "say \"hi\""),
        ("interop", None, "backslash", "C:\\Users\\tester"),
        ("interop", None, "tab", "a\tb"),
        ("interop", None, "newline", "l1\nl2"),
        ("interop", None, "empty", ""),
        ("interop", None, "unicode", "caf\u{e9}"),
        ("remote", Some("origin"), "url", "https://example.com/r.git"),
        ("remote", Some("Weird \"Name\" \\ x"), "url", "x"),
        ("branch", Some("feature/x"), "merge", "refs/heads/feature/x"),
    ];
    let mut cfg = pg.config().unwrap();
    for (s, ss, n, v) in values {
        cfg.set(s, *ss, n, v);
    }
    pg.write_config(&cfg).unwrap();

    let g2 = g2_open(dir.path());
    let gcfg = g2
        .config()
        .unwrap()
        .open_level(git2::ConfigLevel::Local)
        .unwrap();
    for (s, ss, n, v) in values {
        let key = match ss {
            Some(ss) => format!("{s}.{ss}.{n}"),
            None => format!("{s}.{n}"),
        };
        assert_eq!(gcfg.get_string(&key).ok().as_deref(), Some(*v), "{key}");
    }
    assert!(!gcfg.get_bool("core.bare").unwrap());
    // And puregit reads back what it wrote.
    let back = pg.config().unwrap();
    for (s, ss, n, v) in values {
        assert_eq!(back.get(s, *ss, n), Some(*v), "puregit {s}.{n}");
    }
}

#[test]
fn packed_refs_rewritten_by_puregit() {
    let dir = tmp();
    let g2 = g2_init(dir.path(), HashAlgo::Sha1);
    let tree = g2_tree(&g2, &[("f", 0o100644, b"x\n")]);
    let c1 = g2_commit(&g2, tree, &[], 1, "1\n");
    let c2 = g2_commit(&g2, tree, &[c1], 2, "2\n");
    g2.reference("refs/heads/main", c2, true, "x").unwrap();
    g2.reference("refs/heads/doomed", c1, true, "x").unwrap();
    let s = g2_sig(3, 0);
    let tag = g2
        .tag("v1", &g2.find_object(c1, None).unwrap(), &s, "t\n", false)
        .unwrap();
    g2.refdb_compress().unwrap();
    // Close libgit2's handle first: it may keep packed-refs memory-mapped,
    // and Windows refuses to rewrite a mapped file.
    drop(g2);

    let pg = puregit::Repository::open(dir.path()).unwrap();
    pg.refs().delete("refs/heads/doomed").unwrap();
    // puregit also adds a loose ref next to the packed ones.
    pg.refs()
        .update("refs/heads/new", &Reference::Direct(pg_oid(c1)))
        .unwrap();

    let g2 = g2_open(dir.path());
    assert!(g2.find_reference("refs/heads/doomed").is_err());
    assert_eq!(g2.refname_to_id("refs/heads/main").unwrap(), c2);
    assert_eq!(g2.refname_to_id("refs/heads/new").unwrap(), c1);
    let v1 = g2.find_reference("refs/tags/v1").unwrap();
    assert_eq!(v1.target(), Some(tag));
    assert_eq!(v1.peel_to_commit().unwrap().id(), c1);
    let names: BTreeSet<String> = g2
        .references()
        .unwrap()
        .map(|r| r.unwrap().name().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        ["refs/heads/main", "refs/heads/new", "refs/tags/v1"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    );
}

#[test]
fn puregit_merge_commit_matches_libgit2_merge() {
    let dir = tmp();
    let work = dir.path();
    let pg = pg_init(work, HashAlgo::Sha1);
    let body: String = (0..20).map(|i| format!("l{i}\n")).collect();
    write_file(work, "shared.txt", body.as_bytes());
    write_file(work, "base.txt", b"base\n");
    pg.add_path("shared.txt").unwrap();
    pg.add_path("base.txt").unwrap();
    let base = pg.commit(b"base\n", sig(10), sig(10)).unwrap();
    pg.create_branch("other", None).unwrap();

    write_file(
        work,
        "shared.txt",
        body.replace("l1\n", "l1 ours\n").as_bytes(),
    );
    write_file(work, "ours.txt", b"ours\n");
    pg.add_path("shared.txt").unwrap();
    pg.add_path("ours.txt").unwrap();
    let ours = pg.commit(b"ours\n", sig(20), sig(20)).unwrap();

    pg.checkout("other").unwrap();
    write_file(
        work,
        "shared.txt",
        body.replace("l18\n", "l18 theirs\n").as_bytes(),
    );
    write_file(work, "theirs.txt", b"theirs\n");
    pg.add_path("shared.txt").unwrap();
    pg.add_path("theirs.txt").unwrap();
    let theirs = pg.commit(b"theirs\n", sig(30), sig(30)).unwrap();
    pg.checkout("main").unwrap();

    let outcome = pg
        .merge(&theirs, sig(40), sig(40), b"merge other\n")
        .unwrap();
    let puregit::merge::MergeOutcome::Merged(m) = outcome else {
        panic!("expected a merge commit, got {outcome:?}")
    };

    let g2 = g2_open(work);
    let gm = g2.find_commit(g2_oid(&m)).unwrap();
    assert_eq!(
        gm.parent_ids().map(pg_oid).collect::<Vec<_>>(),
        [ours, theirs]
    );
    assert_eq!(
        pg_oid(g2.merge_base(g2_oid(&ours), g2_oid(&theirs)).unwrap()),
        base
    );
    // libgit2's own three-way merge of the same trees gives the same tree.
    let t = |id: &ObjectId| g2.find_commit(g2_oid(id)).unwrap().tree().unwrap();
    let mut idx = g2
        .merge_trees(&t(&base), &t(&ours), &t(&theirs), None)
        .unwrap();
    assert!(!idx.has_conflicts());
    assert_eq!(
        pg_oid(idx.write_tree_to(&g2).unwrap()),
        pg_oid(gm.tree_id())
    );
    assert_eq!(pg.head_id().unwrap(), m);
    assert_eq!(pg_oid(g2.head().unwrap().target().unwrap()), m);
    // The worktree and the index follow the merge: libgit2 sees nothing
    // staged or modified.
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true);
    let dirty: Vec<String> = g2
        .statuses(Some(&mut opts))
        .unwrap()
        .iter()
        .map(|e| format!("{:?} {}", e.status(), e.path().unwrap()))
        .collect();
    assert!(
        dirty.is_empty(),
        "libgit2 sees changes after merge: {dirty:?}"
    );
    assert!(puregit::status::status(&pg).unwrap().is_clean());
}

#[test]
fn libgit2_diff_of_puregit_commits() {
    let dir = tmp();
    let pg = pg_init(dir.path(), HashAlgo::Sha1);
    let t1 = pg_tree(
        &pg,
        &[
            ("same", 0o100644, b"s\n"),
            ("mod", 0o100644, b"1\n"),
            ("del", 0o100644, b"d\n"),
            ("x/y", 0o100644, b"y\n"),
            ("exec", 0o100644, b"e\n"),
        ],
    );
    let t2 = pg_tree(
        &pg,
        &[
            ("same", 0o100644, b"s\n"),
            ("mod", 0o100644, b"2\n"),
            ("x/y", 0o100644, b"y2\n"),
            ("x/z", 0o100644, b"z\n"),
            ("exec", 0o100755, b"e\n"),
            ("added", 0o100644, b"a\n"),
        ],
    );
    let g2 = g2_open(dir.path());
    let diff = g2
        .diff_tree_to_tree(
            Some(&g2.find_tree(g2_oid(&t1)).unwrap()),
            Some(&g2.find_tree(g2_oid(&t2)).unwrap()),
            None,
        )
        .unwrap();
    let mut g: Vec<(String, char)> = diff
        .deltas()
        .map(|d| {
            let f = if d.status() == git2::Delta::Deleted {
                d.old_file()
            } else {
                d.new_file()
            };
            let c = match d.status() {
                git2::Delta::Added => 'A',
                git2::Delta::Deleted => 'D',
                git2::Delta::Modified => 'M',
                other => panic!("{other:?}"),
            };
            (f.path().unwrap().to_str().unwrap().replace('\\', "/"), c)
        })
        .collect();
    g.sort();
    let mut p: Vec<(String, char)> = walk::diff_trees(pg.objects(), Some(&t1), Some(&t2))
        .unwrap()
        .into_iter()
        .map(|e| {
            let c = match e.change {
                walk::TreeChange::Added => 'A',
                walk::TreeChange::Deleted => 'D',
                walk::TreeChange::Modified => 'M',
            };
            (String::from_utf8(e.path).unwrap(), c)
        })
        .collect();
    p.sort();
    assert_eq!(p, g);
}
