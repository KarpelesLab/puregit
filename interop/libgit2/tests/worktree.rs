//! Working trees materialized by one library and inspected by the other:
//! file contents, executable bits and symlinks, judged clean by both sides'
//! status. Exec-bit and symlink sub-checks run only where the platform has
//! them (not on Windows).

use std::path::Path;

use puregit::{HashAlgo, ObjectId};
use puregit_interop_libgit2::*;

fn g2_dirty(g2: &git2::Repository) -> Vec<String> {
    let mut opts = git2::StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    g2.statuses(Some(&mut opts))
        .unwrap()
        .iter()
        .map(|e| format!("{:?} {}", e.status(), e.path().unwrap()))
        .collect()
}

/// A tree with a regular file, an executable, a nested file and (where the
/// platform supports it) a symlink.
fn files() -> Vec<FileSpec<'static>> {
    let mut v: Vec<FileSpec<'static>> = vec![
        ("README", 0o100644, b"readme\n"),
        ("bin/tool", 0o100755, b"#!/bin/sh\necho tool\n"),
        ("src/deep/file.txt", 0o100644, b"deep\n"),
    ];
    if symlinks_supported() {
        v.push(("link-to-readme", 0o120000, b"README"));
        v.push(("dir-link", 0o120000, b"src/deep"));
    }
    v
}

fn assert_materialized(work: &Path, version: &str) {
    assert_eq!(
        std::fs::read(work.join("src/deep/file.txt")).unwrap(),
        b"deep\n"
    );
    assert_eq!(
        std::fs::read_to_string(work.join("README")).unwrap(),
        format!("readme{version}\n")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(work.join("bin/tool"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "bin/tool must be executable");
        let mode = std::fs::metadata(work.join("README"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0, "README must not be executable");
        let link = std::fs::read_link(work.join("link-to-readme")).unwrap();
        assert_eq!(link, Path::new("README"));
        assert!(
            std::fs::symlink_metadata(work.join("dir-link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

/// Two commits of `files()` differing in README, built with libgit2, on
/// branches `main` (v1) and `next` (v2).
fn g2_two_branches(g2: &git2::Repository) -> (git2::Oid, git2::Oid) {
    let mut v1 = files();
    v1[0].2 = b"readme\n";
    let t1 = g2_tree(g2, &v1);
    let mut v2 = files();
    v2[0].2 = b"readme2\n";
    let t2 = g2_tree(g2, &v2);
    let c1 = g2_commit(g2, t1, &[], 1, "v1\n");
    let c2 = g2_commit(g2, t2, &[c1], 2, "v2\n");
    g2.reference("refs/heads/main", c1, true, "x").unwrap();
    g2.reference("refs/heads/next", c2, true, "x").unwrap();
    (c1, c2)
}

#[test]
fn puregit_checks_out_libgit2_commits() {
    let dir = tmp();
    let work = dir.path();
    let g2 = g2_init(work, HashAlgo::Sha1);
    let (_c1, c2) = g2_two_branches(&g2);

    // libgit2 materializes `main` first, so the worktree already holds the
    // files (and symlinks) puregit's checkout must replace.
    let mut co = git2::build::CheckoutBuilder::new();
    co.force();
    g2.checkout_head(Some(&mut co)).unwrap();
    assert!(g2_dirty(&g2).is_empty());

    let pg = puregit::Repository::open(work).unwrap();
    pg.checkout("next").unwrap();
    assert_materialized(work, "2");
    assert_eq!(pg.head_id().unwrap(), pg_oid(c2));
    assert!(puregit::status::status(&pg).unwrap().is_clean());

    let g2 = git2::Repository::open(work).unwrap();
    assert_eq!(g2.head().unwrap().name().unwrap(), "refs/heads/next");
    let dirty = g2_dirty(&g2);
    assert!(dirty.is_empty(), "libgit2 sees changes: {dirty:?}");

    // And back again, over puregit's own checkout.
    pg.checkout("main").unwrap();
    assert_materialized(work, "");
    let dirty = g2_dirty(&git2::Repository::open(work).unwrap());
    assert!(dirty.is_empty(), "libgit2 sees changes: {dirty:?}");
}

#[test]
fn puregit_checkout_and_reset_remove_files_the_target_lacks() {
    let dir = tmp();
    let work = dir.path();
    let g2 = g2_init(work, HashAlgo::Sha1);
    let full = g2_tree(
        &g2,
        &[
            ("keep.txt", 0o100644, b"keep\n"),
            ("gone.txt", 0o100644, b"gone\n"),
            ("olddir/a.txt", 0o100644, b"a\n"),
            ("olddir/deeper/b.txt", 0o100644, b"b\n"),
        ],
    );
    let slim = g2_tree(&g2, &[("keep.txt", 0o100644, b"keep\n")]);
    let c_full = g2_commit(&g2, full, &[], 1, "full\n");
    let c_slim = g2_commit(&g2, slim, &[c_full], 2, "slim\n");
    g2.reference("refs/heads/main", c_full, true, "x").unwrap();
    g2.reference("refs/heads/slim", c_slim, true, "x").unwrap();
    let mut co = git2::build::CheckoutBuilder::new();
    co.force();
    g2.checkout_head(Some(&mut co)).unwrap();
    // An untracked file must survive (git only removes tracked files).
    write_file(work, "olddir/untracked.txt", b"mine\n");

    let pg = puregit::Repository::open(work).unwrap();
    pg.checkout("slim").unwrap();
    assert!(!work.join("gone.txt").exists());
    assert!(!work.join("olddir/a.txt").exists());
    assert!(!work.join("olddir/deeper").exists(), "emptied dirs go too");
    assert!(work.join("olddir/untracked.txt").exists());
    std::fs::remove_file(work.join("olddir/untracked.txt")).unwrap();
    let dirty = g2_dirty(&git2::Repository::open(work).unwrap());
    assert!(dirty.is_empty(), "libgit2 sees changes: {dirty:?}");

    // Back to the full tree, then reset --hard to the slim one.
    pg.checkout("main").unwrap();
    assert!(work.join("olddir/deeper/b.txt").exists());
    pg.reset(puregit::repository::ResetMode::Hard, &pg_oid(c_slim))
        .unwrap();
    assert!(!work.join("gone.txt").exists());
    assert!(!work.join("olddir").exists());
    let dirty = g2_dirty(&git2::Repository::open(work).unwrap());
    assert!(dirty.is_empty(), "libgit2 sees changes: {dirty:?}");
}

#[test]
fn libgit2_checks_out_puregit_commits() {
    let dir = tmp();
    let work = dir.path();
    let pg = pg_init(work, HashAlgo::Sha1);
    let mut v1 = files();
    v1[0].2 = b"readme\n";
    let mut v2 = files();
    v2[0].2 = b"readme2\n";
    let t1 = pg_tree(&pg, &v1);
    let t2 = pg_tree(&pg, &v2);
    let c1 = pg_commit(&pg, t1, &[], 1, "v1\n");
    let c2: ObjectId = pg_commit(&pg, t2, &[c1], 2, "v2\n");
    pg.refs()
        .update("refs/heads/main", &puregit::refs::Reference::Direct(c2))
        .unwrap();
    pg.refs()
        .update("refs/heads/old", &puregit::refs::Reference::Direct(c1))
        .unwrap();

    let g2 = git2::Repository::open(work).unwrap();
    let mut co = git2::build::CheckoutBuilder::new();
    co.force();
    g2.checkout_head(Some(&mut co)).unwrap();
    assert_materialized(work, "2");
    assert!(g2_dirty(&g2).is_empty());

    // puregit agrees the worktree libgit2 wrote (and the index it wrote) is
    // clean, and its index matches libgit2's entry for entry.
    let pg = puregit::Repository::open(work).unwrap();
    let st = puregit::status::status(&pg).unwrap();
    assert!(st.is_clean(), "puregit status: {st:?}");
    let idx = pg.index().unwrap();
    let g2_idx = git2::Index::open(&work.join(".git/index")).unwrap();
    let ours: Vec<(Vec<u8>, u32, ObjectId)> = idx
        .entries
        .iter()
        .map(|e| (e.path.clone(), e.mode, e.id))
        .collect();
    let theirs: Vec<(Vec<u8>, u32, ObjectId)> = g2_idx
        .iter()
        .map(|e| (e.path, e.mode, pg_oid(e.id)))
        .collect();
    assert_eq!(ours, theirs);
    if exec_bits_supported() {
        assert_eq!(idx.get(b"bin/tool").unwrap().mode, 0o100755);
    }
    if symlinks_supported() {
        assert_eq!(idx.get(b"link-to-readme").unwrap().mode, 0o120000);
    }

    // puregit then resets hard onto the older commit over libgit2's worktree.
    pg.reset(puregit::repository::ResetMode::Hard, &c1).unwrap();
    assert_materialized(work, "");
    let dirty = g2_dirty(&git2::Repository::open(work).unwrap());
    assert!(dirty.is_empty(), "libgit2 sees changes: {dirty:?}");
}
