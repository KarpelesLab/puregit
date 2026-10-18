//! SHA-256 repositories, both directions.
//!
//! libgit2's SHA-256 object format is experimental and only compiled in with
//! `GIT_EXPERIMENTAL_SHA256` — which the harness enables through git2's
//! `unstable-sha256` feature on the vendored build. These tests cover objects,
//! refs, the index (whose checksum is SHA-256 too) and packs.

use std::io::Write;
use std::path::Path;

use puregit::object::Object;
use puregit::refs::Reference;
use puregit::{HashAlgo, ObjectId, ObjectType};
use puregit_interop_libgit2::*;

fn g2_open(path: &Path) -> git2::Repository {
    hermetic();
    git2::Repository::open(path).expect("libgit2 open")
}

#[test]
fn libgit2_sha256_repo_read_by_puregit() {
    let dir = tmp();
    let work = dir.path();
    let g2 = g2_init(work, HashAlgo::Sha256);
    assert_eq!(g2.object_format(), git2::ObjectFormat::Sha256);

    write_file(work, "a.txt", b"alpha\n");
    write_file(work, "dir/b.txt", b"beta\n");
    let mut index = g2.index().unwrap();
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree = index.write_tree().unwrap();
    assert_eq!(tree.as_bytes().len(), 32);
    let s = g2_sig(1_700_000_000, 120);
    let tree_obj = g2.find_tree(tree).unwrap();
    let c1 = g2
        .commit(Some("HEAD"), &s, &s, "first sha256\n", &tree_obj, &[])
        .unwrap();
    let c1_obj = g2.find_commit(c1).unwrap();
    let side = g2
        .commit(None, &s, &s, "side\n", &tree_obj, &[&c1_obj])
        .unwrap();
    let c2 = g2
        .commit(
            Some("HEAD"),
            &s,
            &s,
            "merge\n",
            &tree_obj,
            &[&c1_obj, &g2.find_commit(side).unwrap()],
        )
        .unwrap();
    let tag = g2
        .tag("v1", &g2.find_object(c2, None).unwrap(), &s, "tag\n", false)
        .unwrap();

    let pg = puregit::Repository::open(work).unwrap();
    assert_eq!(pg.algo(), HashAlgo::Sha256);
    assert_pg_reads_all(&g2, &pg);
    assert_eq!(pg.head_id().unwrap(), pg_oid(c2));
    assert_eq!(pg.refs().resolve("refs/tags/v1").unwrap(), pg_oid(tag));
    let Object::Commit(pc) = pg.read_object(&pg_oid(c2)).unwrap() else {
        panic!()
    };
    assert_eq!(pc.parents, [pg_oid(c1), pg_oid(side)]);
    assert_eq!(pc.tree, pg_oid(tree));

    // The SHA-256 index (32-byte ids, SHA-256 trailer).
    let pg_index = pg.index().unwrap();
    let g2_index =
        git2::Index::open_ext(&work.join(".git/index"), git2::ObjectFormat::Sha256).unwrap();
    let g: Vec<(Vec<u8>, ObjectId)> = g2_index.iter().map(|e| (e.path, pg_oid(e.id))).collect();
    let p: Vec<(Vec<u8>, ObjectId)> = pg_index
        .entries
        .iter()
        .map(|e| (e.path.clone(), e.id))
        .collect();
    assert_eq!(p, g);
    assert_eq!(
        pg_index.serialize(),
        std::fs::read(work.join(".git/index")).unwrap()
    );
    // The status is clean for puregit as it is for libgit2.
    assert!(puregit::status::status(&pg).unwrap().is_clean());

    // A SHA-256 pack built by libgit2, read by puregit.
    let mut walk = g2.revwalk().unwrap();
    walk.push_head().unwrap();
    let mut pb = g2.packbuilder().unwrap();
    pb.insert_walk(&mut walk).unwrap();
    pb.insert_object(tag, None).unwrap();
    let mut buf = git2::Buf::new();
    pb.write_buf(&mut buf).unwrap();
    let other = tmp();
    let pg2 = pg_init(other.path(), HashAlgo::Sha256);
    let written = pg2.ingest_pack(&buf).unwrap();
    assert_eq!(written.len(), g2_all_oids(&g2).len());
    assert_pg_reads_all(&g2, &pg2);
}

#[test]
fn puregit_sha256_repo_read_by_libgit2() {
    let dir = tmp();
    let work = dir.path();
    let mut pg = pg_init(work, HashAlgo::Sha256);
    write_file(work, "a.txt", b"alpha\n");
    write_file(work, "sub/b.txt", b"beta\n");
    pg.add_path("a.txt").unwrap();
    pg.add_path("sub/b.txt").unwrap();
    let c1 = pg.commit(b"one\n", pg_sig(1, 0), pg_sig(1, 0)).unwrap();
    write_file(work, "a.txt", b"alpha 2\n");
    pg.add_path("a.txt").unwrap();
    let c2 = pg.commit(b"two\n", pg_sig(2, 60), pg_sig(2, 60)).unwrap();
    let tag = puregit::object::Tag {
        object: c2,
        object_type: ObjectType::Commit,
        name: b"v2".to_vec(),
        tagger: Some(pg_sig(3, 0)),
        message: b"two\n".to_vec(),
    };
    let tag = pg.write_object(ObjectType::Tag, &tag.serialize()).unwrap();
    pg.refs()
        .update("refs/tags/v2", &Reference::Direct(tag))
        .unwrap();
    assert_eq!(c2.as_bytes().len(), 32);
    let loose = pg.loose_object_ids().unwrap();

    let g2 = g2_open(work);
    assert_eq!(g2.object_format(), git2::ObjectFormat::Sha256);
    assert_g2_reads(&g2, &pg, &loose);
    assert_eq!(pg_oid(g2.head().unwrap().target().unwrap()), c2);
    let gc = g2.find_commit(g2_oid(&c2)).unwrap();
    assert_eq!(gc.parent_ids().map(pg_oid).collect::<Vec<_>>(), [c1]);
    assert_eq!(g2.find_tag(g2_oid(&tag)).unwrap().target_id(), g2_oid(&c2));
    // libgit2 reads puregit's SHA-256 index and finds the worktree clean.
    let g2_index =
        git2::Index::open_ext(&work.join(".git/index"), git2::ObjectFormat::Sha256).unwrap();
    assert_eq!(g2_index.len(), 2);
    let statuses = g2.statuses(None).unwrap();
    assert_eq!(statuses.len(), 0);
    let mut walk = g2.revwalk().unwrap();
    walk.push_head().unwrap();
    let order: Vec<ObjectId> = walk.map(|r| pg_oid(r.unwrap())).collect();
    assert_eq!(order, [c2, c1]);

    // A SHA-256 pack + idx written by puregit: libgit2 reads every object, and
    // its indexer produces the identical .idx.
    pg.repack().unwrap();
    let g2 = g2_open(work);
    assert_g2_reads(&g2, &pg, &loose);
    let pack_path = std::fs::read_dir(work.join(".git/objects/pack"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "pack"))
        .unwrap();
    let out = tmp();
    let mut indexer =
        git2::Indexer::new_ext(None, out.path(), 0, true, git2::ObjectFormat::Sha256).unwrap();
    indexer
        .write_all(&std::fs::read(&pack_path).unwrap())
        .unwrap();
    let name = indexer.commit().unwrap();
    assert_eq!(
        std::fs::read(out.path().join(format!("pack-{name}.idx"))).unwrap(),
        std::fs::read(pack_path.with_extension("idx")).unwrap(),
        "SHA-256 .idx differs from libgit2's"
    );
}
