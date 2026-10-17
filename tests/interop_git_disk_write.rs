//! On-disk interop, direction **puregit writes → git reads**.
//!
//! Objects, trees, commits (merges, octopus), tags, refs, the index, packs
//! (with deltas), bitmaps, commit-graphs and multi-pack-indexes are produced
//! through puregit's API, then judged by the real `git` CLI: `git fsck
//! --strict --full` must be silent, and `git cat-file`, `git log`, `git
//! ls-files`, `git status`, `git verify-pack`, `git index-pack`, `git
//! commit-graph verify`, `git multi-pack-index verify` and `git rev-list
//! --test-bitmap` must agree exactly with what puregit wrote. SHA-1 and
//! SHA-256 throughout.
//!
//! The reverse direction lives in `interop_git_disk.rs`.

#![cfg(feature = "std")]

#[path = "interop_git_disk_support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use puregit::object::{Commit, FileMode, Object, ObjectType, Signature, Tag, Tree, TreeEntry};
use puregit::odb::ObjectDatabase;
use puregit::refs::Reference;
use puregit::{HashAlgo, ObjectId, Repository};

use support::{EPOCH, Git, TempDir, oid};

fn sig(name: &str, t: i64, tz: &str) -> Signature {
    Signature {
        name: name.as_bytes().to_vec(),
        email: format!("{}@example.com", name.to_lowercase().replace(' ', ".")).into_bytes(),
        time: t,
        tz: tz.as_bytes().to_vec(),
    }
}

/// Everything puregit wrote, for later comparison.
struct Written {
    /// id → (type, payload)
    objects: BTreeMap<ObjectId, (ObjectType, Vec<u8>)>,
    /// ref name → id
    refs: BTreeMap<String, ObjectId>,
    /// main's history, newest first (distinct dates).
    main_log: Vec<ObjectId>,
}

struct Writer<'a> {
    repo: &'a Repository,
    w: Written,
}

impl Writer<'_> {
    fn put(&mut self, ty: ObjectType, payload: &[u8]) -> ObjectId {
        let id = self.repo.write_object(ty, payload).unwrap();
        self.w.objects.insert(id, (ty, payload.to_vec()));
        id
    }
    fn blob(&mut self, content: &[u8]) -> ObjectId {
        self.put(ObjectType::Blob, content)
    }
    fn tree(&mut self, entries: Vec<(FileMode, &str, ObjectId)>) -> ObjectId {
        let t = Tree {
            entries: entries
                .into_iter()
                .map(|(mode, name, id)| TreeEntry {
                    mode,
                    name: name.as_bytes().to_vec(),
                    id,
                })
                .collect(),
        };
        self.put(ObjectType::Tree, &t.serialize())
    }
    fn commit(&mut self, tree: ObjectId, parents: Vec<ObjectId>, n: i64, msg: &str) -> ObjectId {
        let c = Commit {
            tree,
            parents,
            author: sig("A U Thor", EPOCH + n * 60, "+0530"),
            committer: sig("C O Mitter", EPOCH + n * 60 + 7, "-0700"),
            extra_headers: Vec::new(),
            message: msg.as_bytes().to_vec(),
        };
        self.put(ObjectType::Commit, &c.serialize())
    }
    fn tag(&mut self, target: ObjectId, ty: ObjectType, name: &str, n: i64) -> ObjectId {
        let t = Tag {
            object: target,
            object_type: ty,
            name: name.as_bytes().to_vec(),
            tagger: Some(sig("T Agger", EPOCH + n * 60, "+0000")),
            message: format!("tag {name}\n").into_bytes(),
        };
        self.put(ObjectType::Tag, &t.serialize())
    }
    fn set_ref(&mut self, name: &str, id: ObjectId) {
        self.repo
            .refs()
            .update(name, &Reference::Direct(id))
            .unwrap();
        self.w.refs.insert(name.to_string(), id);
    }
}

/// Writes a history with every object shape through puregit's object API.
fn write_rich_history(repo: &Repository) -> Written {
    let mut w = Writer {
        repo,
        w: Written {
            objects: BTreeMap::new(),
            refs: BTreeMap::new(),
            main_log: Vec::new(),
        },
    };
    use FileMode::*;
    let empty = w.blob(b"");
    let hello = w.blob(b"hello\n");
    let all_bytes: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let binary = w.blob(&all_bytes);
    let big = w.blob(&support::noise(1 << 20, 99));
    let script = w.blob(b"#!/bin/sh\necho hi\n");
    let link = w.blob(b"README.md");
    let deep = w.blob(b"deep\n");
    let no_nl = w.blob(b"no newline at end");

    let d = w.tree(vec![(Regular, "deep.txt", deep)]);
    let c_dir = w.tree(vec![(Tree, "d", d), (Regular, "c.txt", hello)]);
    let b_dir = w.tree(vec![(Tree, "c", c_dir)]);
    // Names chosen to exercise git's tree order: "a-b" < "a.c" < "a/" < "a0".
    let root1 = w.tree(vec![
        (Regular, "README.md", hello),
        (Regular, "empty", empty),
        (Regular, "binary.bin", binary),
        (Executable, "script.sh", script),
        (Symlink, "link", link),
        (Tree, "a", b_dir),
        (Regular, "a-b", hello),
        (Regular, "a.c", no_nl),
        (Regular, "a0", hello),
        (Regular, "file with spaces.txt", hello),
        (Regular, "h\u{e9}llo w\u{f6}rld \u{2713}.txt", hello),
    ]);
    let c1 = w.commit(root1, vec![], 1, "initial\n");
    let root2 = w.tree(vec![
        (Regular, "README.md", hello),
        (Regular, "big.bin", big),
        (Tree, "a", b_dir),
        (Executable, "script.sh", script),
    ]);
    let c2 = w.commit(root2, vec![c1], 2, "second\n\nwith a body\n");
    let side_blob = w.blob(b"side\n");
    let root3 = w.tree(vec![(Regular, "README.md", side_blob), (Tree, "a", b_dir)]);
    let c3 = w.commit(root3, vec![c1], 3, "side branch\n");
    let m = w.commit(root2, vec![c2, c3], 4, "Merge side\n");
    let o1 = w.commit(root1, vec![c3], 5, "o1\n");
    let o2 = w.commit(root3, vec![c2], 6, "o2\n");
    let octo = w.commit(root2, vec![m, o1, o2], 7, "Octopus \u{2014} unicode\n");
    let tip = w.commit(root2, vec![octo], 8, "tip\n");
    w.w.main_log = vec![tip, octo, o2, o1, m, c3, c2, c1];

    let v1 = w.tag(tip, ObjectType::Commit, "v1", 9);
    let nested = w.tag(v1, ObjectType::Tag, "nested", 10);
    let tree_tag = w.tag(root1, ObjectType::Tree, "tree-tag", 11);
    let blob_tag = w.tag(hello, ObjectType::Blob, "blob-tag", 12);

    w.set_ref("refs/heads/main", tip);
    w.set_ref("refs/heads/side", c3);
    w.set_ref("refs/heads/nested/branch/name", o1);
    w.set_ref("refs/tags/v1", v1);
    w.set_ref("refs/tags/nested", nested);
    w.set_ref("refs/tags/tree-tag", tree_tag);
    w.set_ref("refs/tags/blob-tag", blob_tag);
    w.set_ref("refs/tags/light", c2);
    w.w
}

/// git agrees with everything in `written`, byte for byte.
fn assert_git_reads(git: &Git, dir: &Path, algo: HashAlgo, written: &Written) {
    git.assert_fsck_clean(dir);
    assert_eq!(
        git.line(dir, &["rev-parse", "--show-object-format"]),
        algo.name()
    );

    let ids: Vec<String> = written.objects.keys().map(|id| id.to_hex()).collect();
    let theirs = git.cat_batch(dir, &ids);
    for (id, (ty, payload)) in &written.objects {
        let (gty, gcontent) = &theirs[&id.to_hex()];
        assert_eq!(gty, ty, "type of {id}");
        assert_eq!(gcontent, payload, "content of {id}");
    }

    // Trees are canonical: git's own mktree over the listing reproduces them.
    for (id, (ty, _)) in &written.objects {
        if *ty == ObjectType::Tree {
            let listing = git.run(dir, &["ls-tree", "-z", &id.to_hex()]);
            let again = git.run_stdin(dir, &["mktree", "-z"], &listing);
            assert_eq!(
                oid(algo, &String::from_utf8_lossy(&again)),
                *id,
                "mktree {id}"
            );
        }
    }

    for (name, id) in &written.refs {
        assert_eq!(git.rev_parse(dir, algo, name), *id, "rev-parse {name}");
    }
    let log: Vec<ObjectId> = git
        .run_str(dir, &["log", "--format=%H", "main"])
        .lines()
        .map(|l| oid(algo, l))
        .collect();
    assert_eq!(log, written.main_log, "git log main");

    let repo = Repository::open(dir).unwrap();
    let tips: Vec<ObjectId> = written.refs.values().copied().collect();
    let reach: BTreeSet<String> = puregit::walk::reachable_objects(repo.objects(), &tips)
        .unwrap()
        .iter()
        .map(|id| id.to_hex())
        .collect();
    assert_eq!(reach, git.rev_list_objects_all(dir), "reachable objects");
}

#[test]
fn objects_refs_and_history_pass_git_fsck() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-objects");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        let repo = Repository::init_with(&dir, algo).unwrap();
        let written = write_rich_history(&repo);
        assert_git_reads(&git, &dir, algo, &written);
        // HEAD → main as written by puregit's init.
        assert_eq!(git.line(&dir, &["symbolic-ref", "HEAD"]), "refs/heads/main");
        assert_eq!(
            git.line(&dir, &["rev-parse", "--is-bare-repository"]),
            "false"
        );
    }
}

#[test]
fn loose_repack_and_pack_writer_output_verified_by_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-repack");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        let mut repo = Repository::init_with(&dir, algo).unwrap();
        let written = write_rich_history(&repo);
        let n = repo.repack().unwrap();
        assert_eq!(n, written.objects.len());
        assert_git_reads(&git, &dir, algo, &written);
        let counts = git.run_str(&dir, &["count-objects", "-v"]);
        assert!(counts.contains("\ncount: 0\n") || counts.starts_with("count: 0\n"));
        assert!(counts.contains(&format!("in-pack: {n}\n")), "{counts}");
        verify_packs_with_git(&git, &dir, algo, false);
    }
}

/// Runs `git verify-pack -v` on every pack and checks `git index-pack`
/// regenerates each `.idx` byte-for-byte. Returns the number of deltified
/// objects git saw.
fn verify_packs_with_git(git: &Git, dir: &Path, algo: HashAlgo, expect_deltas: bool) -> usize {
    let pack_dir = dir.join(".git/objects/pack");
    let mut deltas = 0;
    let mut packs = 0;
    for e in std::fs::read_dir(&pack_dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".pack") else {
            continue;
        };
        packs += 1;
        let idx_path = pack_dir.join(format!("{stem}.idx"));
        let out = git.run_str(dir, &["verify-pack", "-v", idx_path.to_str().unwrap()]);
        for line in out.lines() {
            // "<oid> <type> <size> <packed> <offset> <depth> <base>" for deltas.
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() == 7 && fields[0].len() == algo.hex_len() {
                deltas += 1;
            }
        }
        let regen = dir.join(".git").join(format!("regen-{stem}.idx"));
        let fmt = format!("--object-format={}", algo.name());
        git.run(
            dir,
            &[
                "index-pack",
                &fmt,
                "-o",
                regen.to_str().unwrap(),
                pack_dir.join(&name).to_str().unwrap(),
            ],
        );
        let ours = std::fs::read(&idx_path).unwrap();
        let theirs = std::fs::read(&regen).unwrap();
        assert!(ours == theirs, "{stem}.idx differs from git index-pack's");
        std::fs::remove_file(&regen).unwrap();
    }
    assert!(packs > 0, "no packs to verify");
    if expect_deltas {
        assert!(deltas > 0, "git saw no deltas in puregit's packs");
    }
    deltas
}

#[test]
fn pack_writer_deltas_verified_by_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-pack");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        let mut repo = Repository::init_with(&dir, algo).unwrap();

        // Twenty revisions of a growing file: prime delta material.
        let mut writer = puregit::pack::PackWriter::new(algo);
        let mut objects = BTreeMap::new();
        let mut parent: Option<ObjectId> = None;
        let mut body = support::text_body(2000, "rev");
        for i in 0..20 {
            body.extend_from_slice(format!("change {i}\n").as_bytes());
            let blob = writer.add(ObjectType::Blob, &body);
            objects.insert(blob, (ObjectType::Blob, body.clone()));
            let t = Tree {
                entries: vec![TreeEntry {
                    mode: FileMode::Regular,
                    name: b"file.txt".to_vec(),
                    id: blob,
                }],
            };
            let tree = writer.add(ObjectType::Tree, &t.serialize());
            objects.insert(tree, (ObjectType::Tree, t.serialize()));
            let c = Commit {
                tree,
                parents: parent.into_iter().collect(),
                author: sig("A", EPOCH + i, "+0000"),
                committer: sig("C", EPOCH + i, "+0000"),
                extra_headers: Vec::new(),
                message: format!("rev {i}\n").into_bytes(),
            };
            let id = writer.add(ObjectType::Commit, &c.serialize());
            objects.insert(id, (ObjectType::Commit, c.serialize()));
            parent = Some(id);
        }
        let out = writer.finish().unwrap();
        repo.write_pack(&out).unwrap();
        repo.reload_odb().unwrap();
        repo.refs()
            .update("refs/heads/main", &Reference::Direct(parent.unwrap()))
            .unwrap();

        git.assert_fsck_clean(&dir);
        verify_packs_with_git(&git, &dir, algo, true);
        let ids: Vec<String> = objects.keys().map(|id| id.to_hex()).collect();
        let theirs = git.cat_batch(&dir, &ids);
        for (id, (ty, payload)) in &objects {
            assert_eq!(
                &theirs[&id.to_hex()],
                &(*ty, payload.clone()),
                "object {id}"
            );
        }
        assert_eq!(
            git.line(&dir, &["rev-list", "--count", "main"]),
            "20",
            "history length"
        );
    }
}

#[test]
fn commit_graph_and_multi_pack_index_verified_by_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-cg-midx");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        let mut repo = Repository::init_with(&dir, algo).unwrap();
        let written = write_rich_history(&repo);
        repo.repack().unwrap();
        // A second pack on top.
        let blob = repo.write_object(ObjectType::Blob, b"more\n").unwrap();
        let t = Tree {
            entries: vec![TreeEntry {
                mode: FileMode::Regular,
                name: b"more.txt".to_vec(),
                id: blob,
            }],
        };
        let tree = repo.write_object(ObjectType::Tree, &t.serialize()).unwrap();
        let c = Commit {
            tree,
            parents: vec![written.main_log[0]],
            author: sig("A", EPOCH + 10_000, "+0000"),
            committer: sig("C", EPOCH + 10_000, "+0000"),
            extra_headers: Vec::new(),
            message: b"more\n".to_vec(),
        };
        let more = repo
            .write_object(ObjectType::Commit, &c.serialize())
            .unwrap();
        repo.refs()
            .update("refs/heads/main", &Reference::Direct(more))
            .unwrap();
        repo.repack().unwrap();

        assert_eq!(repo.write_multi_pack_index().unwrap(), 2);
        git.run(&dir, &["multi-pack-index", "verify", "--no-progress"]);

        // The history includes an octopus merge (EDGE chunk).
        let n = repo.write_commit_graph().unwrap();
        assert_eq!(n, written.main_log.len() + 1);
        git.run(&dir, &["commit-graph", "verify", "--no-progress"]);
        // git actually uses the graph and agrees on history.
        let log = git.run_str(
            &dir,
            &[
                "-c",
                "core.commitGraph=true",
                "log",
                "--format=%H %P",
                "main",
            ],
        );
        let expected: Vec<String> = std::iter::once(more)
            .chain(written.main_log.iter().copied())
            .map(|id| {
                let Object::Commit(c) = repo.read_object(&id).unwrap() else {
                    panic!()
                };
                let parents: Vec<String> = c.parents.iter().map(|p| p.to_hex()).collect();
                format!("{} {}", id.to_hex(), parents.join(" "))
                    .trim_end()
                    .to_string()
            })
            .collect();
        let got: Vec<String> = log.lines().map(|l| l.trim_end().to_string()).collect();
        assert_eq!(got, expected);
        git.assert_fsck_clean(&dir);
    }
}

#[test]
fn bitmap_and_reverse_index_verified_by_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-bitmap");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        let mut repo = Repository::init_with(&dir, algo).unwrap();
        let written = write_rich_history(&repo);
        let n = repo.repack_with_bitmap().unwrap();
        assert_eq!(n, git.rev_list_objects_all(&dir).len());
        git.assert_fsck_clean(&dir);
        verify_packs_with_git(&git, &dir, algo, false);
        let tip = written.main_log[0].to_hex();
        // `--test-bitmap` reports on stderr and fails on any mismatch.
        let out = git.output(&dir, &["rev-list", "--test-bitmap", &tip]);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success() && text.contains("OK!"),
            "test-bitmap: {text}"
        );
        // A bitmap-driven object listing matches the plain traversal.
        let with: BTreeSet<String> = git
            .run_str(
                &dir,
                &["rev-list", "--use-bitmap-index", "--objects", "--all"],
            )
            .lines()
            .map(|l| l.split(' ').next().unwrap().to_string())
            .collect();
        assert_eq!(with, git.rev_list_objects_all(&dir));
        let count = git.line(&dir, &["rev-list", "--use-bitmap-index", "--count", "main"]);
        assert_eq!(count, written.main_log.len().to_string());
    }
}

// ---------------------------------------------------------------------------
// Index and working tree.
// ---------------------------------------------------------------------------

/// `git ls-files --stage -z` as (mode, id, stage, path).
fn ls_stage(git: &Git, dir: &Path) -> Vec<(u32, String, u8, Vec<u8>)> {
    support::split_nul(&git.run(dir, &["ls-files", "--stage", "-z"]))
        .into_iter()
        .map(|rec| {
            let tab = rec.iter().position(|&b| b == b'\t').unwrap();
            let meta = String::from_utf8(rec[..tab].to_vec()).unwrap();
            let mut it = meta.split(' ');
            (
                u32::from_str_radix(it.next().unwrap(), 8).unwrap(),
                it.next().unwrap().to_string(),
                it.next().unwrap().parse().unwrap(),
                rec[tab + 1..].to_vec(),
            )
        })
        .collect()
}

fn pure_stage(repo: &Repository) -> Vec<(u32, String, u8, Vec<u8>)> {
    let mut v: Vec<_> = repo
        .index()
        .unwrap()
        .entries
        .iter()
        .map(|e| (e.mode, e.id.to_hex(), e.stage, e.path.clone()))
        .collect();
    v.sort_by(|a, b| a.3.cmp(&b.3).then(a.2.cmp(&b.2)));
    v
}

fn git_status_lines(git: &Git, dir: &Path) -> Vec<String> {
    support::split_nul(&git.run(
        dir,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    ))
    .into_iter()
    .map(|r| String::from_utf8_lossy(&r).into_owned())
    .collect()
}

fn write_worktree(dir: &Path) -> Vec<&'static str> {
    let files: Vec<(&str, &[u8])> = vec![
        ("README.md", b"hello\n"),
        ("empty", b""),
        ("crlf.txt", b"windows\r\nendings\r\n"),
        ("dir with space/file name.txt", b"spaces\n"),
        (
            "unicode/h\u{e9}llo \u{2713}.txt",
            "unicode \u{1f980}\n".as_bytes(),
        ),
        ("a/b/c/deep.txt", b"deep\n"),
        ("a-b", b"x\n"),
        ("a.c", b"y\n"),
        ("bin/tool.sh", b"#!/bin/sh\necho tool\n"),
    ];
    for (p, c) in &files {
        support::write(&dir.join(p), c);
    }
    support::set_exec(&dir.join("bin/tool.sh"), true);
    let mut paths: Vec<&str> = files.iter().map(|(p, _)| *p).collect();
    if support::symlinks_supported() {
        support::make_symlink("README.md", &dir.join("link"));
        paths.push("link");
    }
    paths
}

#[test]
fn porcelain_add_commit_is_clean_for_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-porcelain");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        let repo = Repository::init_with(&dir, algo).unwrap();
        for p in write_worktree(&dir) {
            repo.add_path(p).unwrap();
        }
        assert_eq!(pure_stage(&repo), ls_stage(&git, &dir), "index after add");
        let c1 = repo
            .commit(
                b"first\n",
                sig("A", EPOCH, "+0000"),
                sig("C", EPOCH, "+0000"),
            )
            .unwrap();
        git.assert_fsck_clean(&dir);
        assert_eq!(git_status_lines(&git, &dir), Vec::<String>::new());
        git.run(&dir, &["diff-index", "--cached", "--exit-code", "HEAD"]);
        let Object::Commit(c) = repo.read_object(&c1).unwrap() else {
            panic!()
        };
        assert_eq!(git.rev_parse(&dir, algo, "HEAD^{tree}"), c.tree);
        assert_eq!(
            oid(algo, &git.line(&dir, &["write-tree"])),
            c.tree,
            "git write-tree over puregit's index"
        );
        if cfg!(unix) {
            let tool = git.run_str(&dir, &["ls-tree", "HEAD", "bin/tool.sh"]);
            assert!(tool.starts_with("100755 "), "{tool}");
        }
        if support::symlinks_supported() {
            let l = git.run_str(&dir, &["ls-tree", "HEAD", "link"]);
            assert!(l.starts_with("120000 "), "{l}");
            assert_eq!(
                git.run(&dir, &["cat-file", "blob", "HEAD:link"]),
                b"README.md"
            );
        }

        // Second commit: modify, remove, rename.
        support::write(&dir.join("README.md"), b"hello again\n");
        repo.add_path("README.md").unwrap();
        repo.remove_path("empty").unwrap();
        repo.mv("a.c", "moved/a.c").unwrap();
        let c2 = repo
            .commit(
                b"second\n",
                sig("A", EPOCH + 60, "+0000"),
                sig("C", EPOCH + 60, "+0000"),
            )
            .unwrap();
        git.assert_fsck_clean(&dir);
        assert_eq!(git_status_lines(&git, &dir), Vec::<String>::new());
        assert_eq!(
            pure_stage(&repo),
            ls_stage(&git, &dir),
            "index after commit 2"
        );
        let log: Vec<ObjectId> = git
            .run_str(&dir, &["log", "--format=%H"])
            .lines()
            .map(|l| oid(algo, l))
            .collect();
        assert_eq!(log, vec![c2, c1]);
        let names = git.run_str(
            &dir,
            &[
                "diff-tree",
                "-r",
                "--no-renames",
                "--name-status",
                "HEAD~1",
                "HEAD",
            ],
        );
        let mut names: Vec<&str> = names.lines().collect();
        names.sort();
        assert_eq!(
            names,
            vec!["A\tmoved/a.c", "D\ta.c", "D\tempty", "M\tREADME.md"]
        );
        // The reflog puregit wrote parses for git.
        let reflog = git.run_str(&dir, &["reflog", "show", "--format=%H", "refs/heads/main"]);
        let reflog: Vec<ObjectId> = reflog.lines().map(|l| oid(algo, l)).collect();
        assert_eq!(reflog, vec![c2, c1]);

        // An index written as v4 by puregit reads identically.
        let mut index = repo.index().unwrap();
        index.version = 4;
        repo.write_index(&index).unwrap();
        assert_eq!(
            &std::fs::read(dir.join(".git/index")).unwrap()[4..8],
            &4u32.to_be_bytes()
        );
        assert_eq!(pure_stage(&repo), ls_stage(&git, &dir), "v4 index");
        assert_eq!(git_status_lines(&git, &dir), Vec::<String>::new());
    }
}

#[test]
fn puregit_add_on_git_index_keeps_cache_tree_honest() {
    // git's index carries a cache-tree (TREE extension) after a commit. When
    // puregit stages a change it must not leave that cache claiming the old
    // tree, or `git commit` would record stale content.
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-cache-tree");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        git.init(&dir, algo);
        support::write(&dir.join("a/b/c/deep.txt"), b"v1\n");
        support::write(&dir.join("top.txt"), b"top\n");
        git.commit_all(&dir, "base");
        let idx = std::fs::read(dir.join(".git/index")).unwrap();
        assert!(
            idx.windows(4).any(|w| w == b"TREE"),
            "git wrote no cache-tree"
        );

        support::write(&dir.join("a/b/c/deep.txt"), b"v2\n");
        let repo = Repository::open(&dir).unwrap();
        repo.add_path("a/b/c/deep.txt").unwrap();
        let ours =
            puregit::tree_builder::write_tree_from_index(repo.objects(), &repo.index().unwrap())
                .unwrap();
        let theirs = oid(algo, &git.line(&dir, &["write-tree"]));
        assert_eq!(theirs, ours, "git write-tree after puregit add");
        git.commit_staged(&dir, "change deep");
        assert_eq!(git.run(&dir, &["show", "HEAD:a/b/c/deep.txt"]), b"v2\n");
        assert_eq!(git_status_lines(&git, &dir), Vec::<String>::new());
    }
}

#[test]
fn branches_refs_and_checkout_read_by_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-refs");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        let repo = Repository::init_with(&dir, algo).unwrap();
        let written = write_rich_history(&repo);
        // Materialize main so the work tree matches HEAD.
        repo.reset(puregit::repository::ResetMode::Hard, &written.main_log[0])
            .unwrap();
        assert_eq!(git_status_lines(&git, &dir), Vec::<String>::new());

        // A branch made and checked out by puregit.
        repo.create_branch("feature", Some(written.main_log[3]))
            .unwrap();
        repo.checkout("feature").unwrap();
        assert_eq!(git.line(&dir, &["branch", "--show-current"]), "feature");
        assert_eq!(git.rev_parse(&dir, algo, "HEAD"), written.main_log[3]);
        assert_eq!(git_status_lines(&git, &dir), Vec::<String>::new());

        // Packed by git, then deleted / updated / symref'd by puregit.
        git.run(&dir, &["pack-refs", "--all", "--prune"]);
        repo.refs().delete("refs/heads/side").unwrap();
        repo.refs()
            .update("refs/heads/main", &Reference::Direct(written.main_log[1]))
            .unwrap();
        repo.refs()
            .update(
                "refs/remotes/origin/HEAD",
                &Reference::Symbolic("refs/heads/main".into()),
            )
            .unwrap();
        let refs = git.run_str(&dir, &["for-each-ref", "--format=%(refname) %(objectname)"]);
        assert!(!refs.contains("refs/heads/side "), "{refs}");
        assert_eq!(git.rev_parse(&dir, algo, "main"), written.main_log[1]);
        assert_eq!(
            git.line(&dir, &["symbolic-ref", "refs/remotes/origin/HEAD"]),
            "refs/heads/main"
        );
        assert_eq!(git.rev_parse(&dir, algo, "v1^{}"), written.main_log[0]);
        assert_eq!(git.rev_parse(&dir, algo, "nested^{}"), written.main_log[0]);
        git.assert_fsck_clean(&dir);
    }
}

#[test]
fn puregit_merge_matches_git_merge_tree() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("write-merge");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        git.init(&dir, algo);
        support::write(&dir.join("shared.txt"), &support::text_body(20, "base"));
        support::write(&dir.join("keep.txt"), b"keep\n");
        git.commit_all(&dir, "base");
        // The merge-base trap: `side` merges main's first commit with --no-ff,
        // so a breadth-first base search from it would stop at "base".
        git.run(&dir, &["checkout", "-q", "-b", "side"]);
        let mut lines = support::text_body(20, "base");
        lines.extend_from_slice(b"side appends\n");
        support::write(&dir.join("shared.txt"), &lines);
        support::write(&dir.join("side-only.txt"), b"side\n");
        git.commit_all(&dir, "side work");
        git.run(&dir, &["checkout", "-q", "main"]);
        let mut main_lines = b"main prepends\n".to_vec();
        main_lines.extend_from_slice(&support::text_body(20, "base"));
        support::write(&dir.join("shared.txt"), &main_lines);
        support::write(&dir.join("main-only.txt"), b"main\n");
        git.commit_all(&dir, "main work");

        let repo = Repository::open(&dir).unwrap();
        let theirs = git.rev_parse(&dir, algo, "side");
        let outcome = repo
            .merge(
                &theirs,
                sig("A", EPOCH + 9_000, "+0000"),
                sig("C", EPOCH + 9_000, "+0000"),
                b"Merge side\n",
            )
            .unwrap();
        let puregit::merge::MergeOutcome::Merged(m) = outcome else {
            panic!("expected a merge commit, got {outcome:?}")
        };
        git.assert_fsck_clean(&dir);
        assert_eq!(
            git.line(&dir, &["log", "-1", "--format=%P", "HEAD"]),
            format!(
                "{} {}",
                git.line(&dir, &["rev-parse", "HEAD~1"]),
                theirs.to_hex()
            )
        );
        assert_eq!(git.rev_parse(&dir, algo, "HEAD"), m);
        assert_eq!(git_status_lines(&git, &dir), Vec::<String>::new());
        let merged = git.run(&dir, &["show", "HEAD:shared.txt"]);
        let mut want = b"main prepends\n".to_vec();
        want.extend_from_slice(&support::text_body(20, "base"));
        want.extend_from_slice(b"side appends\n");
        assert_eq!(merged, want);

        // git's own merge of the same two commits yields the same tree.
        let out = git.output(&dir, &["merge-tree", "--write-tree", "HEAD~1", "side"]);
        if out.status.success() {
            let tree = String::from_utf8_lossy(&out.stdout);
            let tree = oid(algo, tree.lines().next().unwrap());
            assert_eq!(git.rev_parse(&dir, algo, "HEAD^{tree}"), tree, "merge-tree");
        } else {
            eprintln!("git merge-tree --write-tree unavailable; skipping tree comparison");
        }
    }
}

/// Sanity: the odb trait objects written above are visible to puregit too
/// (guards the test fixtures themselves).
#[test]
fn fixture_round_trips_through_puregit() {
    let tmp = TempDir::new("write-fixture");
    for algo in support::ALGOS {
        let dir = tmp.join(algo.name());
        let repo = Repository::init_with(&dir, algo).unwrap();
        let written = write_rich_history(&repo);
        for (id, (ty, payload)) in &written.objects {
            assert_eq!(&repo.objects().read(id).unwrap(), &(*ty, payload.clone()));
        }
    }
}
