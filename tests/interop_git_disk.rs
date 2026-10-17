//! On-disk interop, direction **git writes → puregit reads**.
//!
//! Repositories are built with the real `git` CLI (merges, octopus merges,
//! annotated/lightweight/nested tags, nested trees, executable files, symlinks,
//! empty/large blobs, unicode and space-containing names; SHA-1 and SHA-256),
//! then every structure puregit reads is checked for *exact* agreement with
//! git's own view: object ids and bytes, refs (loose and packed), packs (OFS and
//! REF deltas, deep chains, bitmaps, multi-pack-index, commit-graph), the index
//! (versions 2/3/4, conflict stages, extended flags), revision walking, status,
//! merge bases and tree diffs.
//!
//! The reverse direction lives in `interop_git_disk_write.rs`.

#![cfg(feature = "std")]

#[path = "interop_git_disk_support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use puregit::index::Index;
use puregit::object::Object;
use puregit::odb::ObjectDatabase;
use puregit::{HashAlgo, ObjectId, Repository};

use support::{Git, TempDir, oid};

// ---------------------------------------------------------------------------
// Fixture: a feature-rich repository built entirely by git.
// ---------------------------------------------------------------------------

/// Builds a repository exercising most object/tree shapes. Symlinks and the
/// executable bit are recorded through `git update-index` so the *objects* are
/// identical on every platform; the working tree mirrors them where possible.
fn build_rich_repo(git: &Git, dir: &Path, algo: HashAlgo) {
    use support::write;
    git.init(dir, algo);

    // -- commit 1: assorted shapes ------------------------------------------
    write(&dir.join("README.md"), b"hello\n");
    write(&dir.join("empty.txt"), b"");
    write(&dir.join("dir with space/file name.txt"), b"spaces\n");
    write(
        &dir.join("unicode/h\u{e9}llo w\u{f6}rld \u{2713}.txt"),
        "unicode \u{1f980}\n".as_bytes(),
    );
    write(&dir.join("a/b/c/d/deep.txt"), b"deep\n");
    write(&dir.join("a/b/sibling.txt"), b"sibling\n");
    write(&dir.join("a-b"), b"sorts before a/\n");
    write(&dir.join("a.c"), b"sorts between\n");
    write(&dir.join("bin/script.sh"), b"#!/bin/sh\necho hi\n");
    write(&dir.join("big.bin"), &support::noise(300_000, 7));
    write(&dir.join("big.txt"), &support::text_body(4000, "v1"));
    write(&dir.join("no-newline"), b"no trailing newline");
    write(&dir.join("crlf.txt"), b"windows\r\nline endings\r\n");
    git.run(dir, &["add", "-A"]);
    git.run(dir, &["update-index", "--chmod=+x", "bin/script.sh"]);
    support::set_exec(&dir.join("bin/script.sh"), true);
    // A symlink: blob holding the target, staged with mode 120000.
    let target = git.hash_object_w(dir, b"README.md");
    git.run(
        dir,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{target},link-to-readme"),
        ],
    );
    if support::symlinks_supported() {
        support::make_symlink("README.md", &dir.join("link-to-readme"));
    }
    git.commit_staged(dir, "initial: assorted tree shapes");

    // -- commit 2: delta-friendly edits --------------------------------------
    let mut big = support::text_body(4000, "v1");
    big.extend_from_slice(b"appended in v2\n");
    write(&dir.join("big.txt"), &big);
    let mut bin = support::noise(300_000, 7);
    bin[1000] ^= 0xff;
    write(&dir.join("big.bin"), &bin);
    write(&dir.join("a/b/c/new.txt"), b"new\n");
    git.commit_all(dir, "second: edits\n\nWith a body paragraph.\n");

    // -- a topic branch merged with --no-ff ----------------------------------
    git.run(dir, &["checkout", "-q", "-b", "feature/topic"]);
    write(&dir.join("topic.txt"), b"topic work\n");
    git.commit_all(dir, "topic: add file");
    write(&dir.join("topic.txt"), b"topic work, revised\n");
    git.commit_all(dir, "topic: revise");
    git.run(dir, &["checkout", "-q", "main"]);
    write(&dir.join("main-only.txt"), b"main side\n");
    git.commit_all(dir, "main: diverge");
    git.tick();
    git.run(
        dir,
        &[
            "merge",
            "-q",
            "--no-ff",
            "-m",
            "Merge feature/topic",
            "feature/topic",
        ],
    );

    // -- an octopus merge -----------------------------------------------------
    for b in ["oct1", "oct2", "oct3"] {
        git.run(dir, &["checkout", "-q", "-b", b, "main"]);
        write(&dir.join(format!("{b}.txt")), b.as_bytes());
        git.commit_all(dir, &format!("{b}: add"));
    }
    git.run(dir, &["checkout", "-q", "main"]);
    git.tick();
    git.run(
        dir,
        &[
            "merge", "-q", "--no-ff", "-m", "Octopus", "oct1", "oct2", "oct3",
        ],
    );

    // -- tags ----------------------------------------------------------------
    git.tick();
    git.run(dir, &["tag", "-a", "v1.0", "-m", "release 1.0"]);
    git.run(dir, &["tag", "light", "HEAD~1"]);
    git.tick();
    git.run(
        dir,
        &["tag", "-a", "nested", "v1.0", "-m", "a tag of a tag"],
    );
    let tree = git.line(dir, &["rev-parse", "HEAD^{tree}"]);
    git.run(dir, &["tag", "-a", "tree-tag", &tree, "-m", "tags a tree"]);
    let blob = git.line(dir, &["rev-parse", "HEAD:README.md"]);
    git.run(dir, &["tag", "-a", "blob-tag", &blob, "-m", "tags a blob"]);

    // -- a final commit with an empty tree diff and odd message --------------
    git.tick();
    git.run(
        dir,
        &[
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "empty commit \u{2014} unicode message",
        ],
    );
    // A symbolic ref below refs/ (as a clone has for origin/HEAD).
    git.run(dir, &["update-ref", "refs/remotes/origin/main", "main"]);
    git.run(
        dir,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );
}

// ---------------------------------------------------------------------------
// Shared verification.
// ---------------------------------------------------------------------------

/// Every object git has is read by puregit with identical type and bytes; the
/// typed parse re-serializes byte-for-byte; the id re-hashes; and puregit's
/// reachability from the refs equals `git rev-list --objects --all`.
fn assert_objects_match(git: &Git, dir: &Path, algo: HashAlgo) {
    let repo = Repository::open(dir).expect("puregit opens git repo");
    assert_eq!(repo.algo(), algo);
    let all = git.all_objects(dir);
    assert!(!all.is_empty());
    for (hex, (ty, content)) in &all {
        let id = oid(algo, hex);
        assert!(repo.objects().contains(&id), "puregit lacks {hex}");
        let (pty, payload) = repo
            .objects()
            .read(&id)
            .unwrap_or_else(|e| panic!("puregit cannot read {hex}: {e:?}"));
        assert_eq!(pty, *ty, "type of {hex}");
        assert_eq!(&payload, content, "content of {hex}");
        assert_eq!(
            puregit::hash::hash_object(algo, pty, &payload),
            id,
            "re-hash of {hex}"
        );
        let parsed = Object::parse(algo, pty, &payload)
            .unwrap_or_else(|e| panic!("puregit cannot parse {ty} {hex}: {e:?}"));
        assert_eq!(&parsed.payload(), content, "re-serialization of {ty} {hex}");
    }

    // Reachability closure from every ref (and HEAD).
    let mut tips: Vec<ObjectId> = repo.refs().list().unwrap().into_values().collect();
    tips.push(repo.head_id().unwrap());
    let reach: BTreeSet<String> = puregit::walk::reachable_objects(repo.objects(), &tips)
        .unwrap()
        .iter()
        .map(|id| id.to_hex())
        .collect();
    assert_eq!(reach, git.rev_list_objects_all(dir));
}

/// puregit's refs agree with `git for-each-ref` / `git rev-parse`, including
/// `HEAD`'s symbolic target and (when packed) the peeled values.
fn assert_refs_match(git: &Git, dir: &Path, algo: HashAlgo) {
    let repo = Repository::open(dir).unwrap();
    let git_refs: BTreeMap<String, ObjectId> = git
        .run_str(dir, &["for-each-ref", "--format=%(refname) %(objectname)"])
        .lines()
        .map(|l| {
            let (name, id) = l.split_once(' ').unwrap();
            (name.to_string(), oid(algo, id))
        })
        .collect();
    let ours = repo.refs().list().unwrap();
    assert_eq!(ours, git_refs, "ref listing");
    for (name, id) in &git_refs {
        assert_eq!(repo.refs().resolve(name).unwrap(), *id, "resolve {name}");
    }
    assert_eq!(
        repo.head().unwrap(),
        puregit::refs::Reference::Symbolic(git.line(dir, &["symbolic-ref", "HEAD"]))
    );
    assert_eq!(repo.head_id().unwrap(), git.rev_parse(dir, algo, "HEAD"));

    // Peeled entries in packed-refs must be the fully-peeled target.
    for p in repo.refs().packed().unwrap() {
        let peeled = git.rev_parse(dir, algo, &format!("{}^{{}}", p.id));
        match p.peeled {
            Some(x) => assert_eq!(x, peeled, "peel of {}", p.name),
            None => assert_eq!(p.id, peeled, "{} is not a tag yet has no peel", p.name),
        }
    }
}

/// Raw pack-entry type tags of every object in every pack of `dir`, as a
/// histogram (1..=4 base types, 6 OFS_DELTA, 7 REF_DELTA).
fn pack_entry_types(dir: &Path, algo: HashAlgo) -> BTreeMap<u8, usize> {
    let mut hist = BTreeMap::new();
    let pack_dir = dir.join(".git/objects/pack");
    for e in std::fs::read_dir(&pack_dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".idx") else {
            continue;
        };
        let idx = puregit::pack::PackIndex::parse(algo, &std::fs::read(e.path()).unwrap()).unwrap();
        let pack = std::fs::read(pack_dir.join(format!("{stem}.pack"))).unwrap();
        for row in 0..idx.len() {
            let off = idx.offset_at(row).unwrap() as usize;
            *hist.entry((pack[off] >> 4) & 7).or_insert(0) += 1;
        }
    }
    hist
}

fn count_loose(dir: &Path) -> usize {
    let mut n = 0;
    for e in std::fs::read_dir(dir.join(".git/objects"))
        .unwrap()
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
            n += std::fs::read_dir(e.path()).unwrap().count();
        }
    }
    n
}

fn pack_count(dir: &Path) -> usize {
    std::fs::read_dir(dir.join(".git/objects/pack"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".pack"))
        .count()
}

// ---------------------------------------------------------------------------
// Objects and refs.
// ---------------------------------------------------------------------------

#[test]
fn loose_objects_and_refs_match_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-loose");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        assert!(count_loose(&dir) > 0);
        assert_eq!(pack_count(&dir), 0);
        assert_objects_match(&git, &dir, algo);
        assert_refs_match(&git, &dir, algo);

        // Specific shapes resolve as git says.
        let repo = Repository::open(&dir).unwrap();
        let head = repo.head_id().unwrap();
        let Object::Commit(c) = repo.read_object(&head).unwrap() else {
            panic!("HEAD is not a commit")
        };
        let Object::Commit(octo) = repo.read_object(&c.parents[0]).unwrap() else {
            panic!()
        };
        assert_eq!(octo.parents.len(), 4, "octopus merge has four parents");
        let flat = puregit::walk::flatten_tree(repo.objects(), &c.tree).unwrap();
        use puregit::object::FileMode;
        assert_eq!(flat[&b"link-to-readme"[..]].0, FileMode::Symlink);
        assert_eq!(flat[&b"bin/script.sh"[..]].0, FileMode::Executable);
        assert_eq!(flat[&b"README.md"[..]].0, FileMode::Regular);
        let ls_tree = git.run(&dir, &["ls-tree", "-r", "-z", "HEAD"]);
        let git_flat: BTreeMap<Vec<u8>, (String, ObjectId)> = support::split_nul(&ls_tree)
            .into_iter()
            .map(|rec| {
                let tab = rec.iter().position(|&b| b == b'\t').unwrap();
                let meta = String::from_utf8(rec[..tab].to_vec()).unwrap();
                let mut it = meta.split(' ');
                let mode = it.next().unwrap().to_string();
                let _ty = it.next();
                let id = oid(algo, it.next().unwrap());
                (rec[tab + 1..].to_vec(), (mode, id))
            })
            .collect();
        let ours: BTreeMap<Vec<u8>, (String, ObjectId)> = flat
            .into_iter()
            .map(|(p, (m, id))| (p, (m.as_octal().to_string(), id)))
            .collect();
        assert_eq!(ours, git_flat, "flattened HEAD tree vs ls-tree -r");
    }
}

#[test]
fn packed_refs_match_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-packed-refs");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        git.run(&dir, &["pack-refs", "--all", "--prune"]);
        assert!(dir.join(".git/packed-refs").exists());
        assert!(!dir.join(".git/refs/tags/v1.0").exists());
        assert_refs_match(&git, &dir, algo);
        let repo = Repository::open(&dir).unwrap();
        let packed = repo.refs().packed().unwrap();
        assert!(
            packed
                .iter()
                .any(|p| p.name == "refs/tags/nested" && p.peeled.is_some())
        );

        // A loose ref written after packing shadows the packed one (git's
        // precedence), as both tools agree.
        git.run(&dir, &["update-ref", "refs/heads/feature/topic", "main"]);
        assert_refs_match(&git, &dir, algo);
    }
}

// ---------------------------------------------------------------------------
// Packs.
// ---------------------------------------------------------------------------

#[test]
fn gc_packs_with_ofs_deltas_read_back() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-gc");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        git.run(&dir, &["gc", "-q", "--prune=now"]);
        assert_eq!(count_loose(&dir), 0, "gc left loose objects");
        let types = pack_entry_types(&dir, algo);
        assert!(
            types.get(&6).copied().unwrap_or(0) > 0,
            "no OFS deltas: {types:?}"
        );
        assert_eq!(types.get(&7), None, "unexpected REF deltas");
        assert_objects_match(&git, &dir, algo);
        assert_refs_match(&git, &dir, algo);
    }
}

#[test]
fn zlib_levels_and_cruft_packs_read_back() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-zlib-cruft");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        // Loose objects at the extremes of zlib's levels (0 = stored blocks).
        for level in ["0", "1", "9"] {
            let cfg = format!("core.looseCompression={level}");
            let body = support::text_body(300, &format!("level {level}"));
            let id = String::from_utf8(git.run_stdin(
                &dir,
                &["-c", &cfg, "hash-object", "-w", "--stdin"],
                &body,
            ))
            .unwrap();
            let repo = Repository::open(&dir).unwrap();
            let (_, payload) = repo.objects().read(&oid(algo, &id)).unwrap();
            assert_eq!(payload, body, "loose object at level {level}");
        }
        assert_objects_match(&git, &dir, algo);

        // Unreachable objects go to a cruft pack (with its .mtimes file);
        // the main pack is stored without compression.
        git.run(
            &dir,
            &[
                "-c",
                "pack.compression=0",
                "gc",
                "-q",
                "--cruft",
                "--prune=1.year.ago",
            ],
        );
        assert!(
            std::fs::read_dir(dir.join(".git/objects/pack"))
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".mtimes")),
            "git wrote no cruft pack"
        );
        assert_eq!(count_loose(&dir), 0);
        assert_objects_match(&git, &dir, algo);
    }
}

#[test]
fn repack_with_ref_deltas_reads_back() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-refdelta");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        git.run(
            &dir,
            &[
                "-c",
                "repack.useDeltaBaseOffset=false",
                "repack",
                "-q",
                "-adf",
            ],
        );
        let types = pack_entry_types(&dir, algo);
        assert!(
            types.get(&7).copied().unwrap_or(0) > 0,
            "no REF deltas: {types:?}"
        );
        assert_eq!(types.get(&6), None, "unexpected OFS deltas");
        assert_objects_match(&git, &dir, algo);
    }
}

/// Builds a long linear history of one slowly-growing file so an aggressive
/// repack produces delta chains far deeper than git's default of 50.
fn build_deep_history(git: &Git, dir: &Path, algo: HashAlgo, versions: usize) {
    git.init(dir, algo);
    // Each revision rewrites a few lines in a different region, so version k
    // is most similar to k±1 and git chains the deltas one after another.
    let mut lines: Vec<String> = (0..1000)
        .map(|i| format!("base line {i:05}: the quick brown fox\n"))
        .collect();
    for i in 0..versions {
        for k in 0..10 {
            let j = (i * 37 + k * 101) % lines.len();
            lines[j] = format!("rev {i} changed line {j} {k}\n");
        }
        support::write(&dir.join("grow.txt"), lines.concat().as_bytes());
        git.run(dir, &["add", "grow.txt"]);
        git.tick();
        git.run(dir, &["commit", "-q", "-m", &format!("rev {i}")]);
    }
}

/// The longest delta chain `git verify-pack -v` reports for the packs in `dir`.
fn max_chain(git: &Git, dir: &Path) -> usize {
    let mut max = 0;
    for e in std::fs::read_dir(dir.join(".git/objects/pack"))
        .unwrap()
        .flatten()
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "idx") {
            let out = git.run_str(dir, &["verify-pack", "-v", p.to_str().unwrap()]);
            for line in out.lines() {
                if let Some(rest) = line.strip_prefix("chain length = ") {
                    let n: usize = rest.split(':').next().unwrap().trim().parse().unwrap();
                    max = max.max(n);
                }
            }
        }
    }
    max
}

#[test]
fn deep_ofs_delta_chains_read_back() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-deep-ofs");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_deep_history(&git, &dir, algo, 120);
        git.run(
            &dir,
            &["repack", "-q", "-adf", "--depth=250", "--window=250"],
        );
        let depth = max_chain(&git, &dir);
        assert!(depth > 60, "expected a deep chain, got {depth}");
        assert_objects_match(&git, &dir, algo);
    }
}

#[test]
fn deep_ref_delta_chains_read_back() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-deep-ref");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_deep_history(&git, &dir, algo, 120);
        git.run(
            &dir,
            &[
                "-c",
                "repack.useDeltaBaseOffset=false",
                "repack",
                "-q",
                "-adf",
                "--depth=250",
                "--window=250",
            ],
        );
        let depth = max_chain(&git, &dir);
        assert!(depth > 60, "expected a deep chain, got {depth}");
        assert!(pack_entry_types(&dir, algo).get(&7).copied().unwrap_or(0) > 0);
        assert_objects_match(&git, &dir, algo);
    }
}

#[test]
fn bitmap_midx_and_commit_graph_from_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-midx");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        // One full pack with a bitmap…
        git.run(&dir, &["repack", "-q", "-adb"]);
        assert!(
            std::fs::read_dir(dir.join(".git/objects/pack"))
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".bitmap"))
        );
        // …then two incremental packs on top.
        for round in 0..2 {
            support::write(
                &dir.join(format!("inc{round}.txt")),
                &support::text_body(50, "inc"),
            );
            git.commit_all(&dir, &format!("incremental {round}"));
            git.run(&dir, &["repack", "-q", "-d"]);
        }
        assert_eq!(pack_count(&dir), 3);
        git.run(&dir, &["multi-pack-index", "write"]);
        git.run(
            &dir,
            &["commit-graph", "write", "--reachable", "--no-progress"],
        );
        assert_objects_match(&git, &dir, algo);

        // The MIDX maps every object to a pack/offset that pack's own .idx
        // agrees with.
        let pack_dir = dir.join(".git/objects/pack");
        let midx = puregit::multi_pack_index::MultiPackIndex::parse(
            algo,
            &std::fs::read(pack_dir.join("multi-pack-index")).unwrap(),
        )
        .unwrap();
        assert_eq!(midx.pack_names().len(), 3);
        let mut idxs = BTreeMap::new();
        for name in midx.pack_names() {
            let bytes = std::fs::read(pack_dir.join(name)).unwrap();
            idxs.insert(
                name.clone(),
                puregit::pack::PackIndex::parse(algo, &bytes).unwrap(),
            );
        }
        let mut packed = BTreeSet::new();
        for idx in idxs.values() {
            for row in 0..idx.len() {
                packed.insert(idx.id_at(row).unwrap());
            }
        }
        assert_eq!(midx.len(), packed.len());
        for id in &packed {
            let (pack, off) = midx.find(id).unwrap_or_else(|| panic!("midx lacks {id}"));
            assert_eq!(
                idxs[pack].offset_of(id).map(|o| o as u64),
                Some(off),
                "midx offset of {id}"
            );
        }

        // The commit-graph records exactly git's parents, trees and
        // topological levels.
        let cg = puregit::commit_graph::CommitGraph::parse(
            algo,
            &std::fs::read(dir.join(".git/objects/info/commit-graph")).unwrap(),
        )
        .unwrap();
        let repo = Repository::open(&dir).unwrap();
        let commits: Vec<String> = git
            .run_str(&dir, &["rev-list", "--all"])
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(cg.len(), commits.len());
        let mut levels: BTreeMap<ObjectId, u32> = BTreeMap::new();
        // rev-list --reverse --topo-order yields parents before children.
        for hex in git
            .run_str(&dir, &["rev-list", "--all", "--topo-order", "--reverse"])
            .lines()
        {
            let id = oid(algo, hex);
            let Object::Commit(c) = repo.read_object(&id).unwrap() else {
                panic!()
            };
            let level = 1 + c.parents.iter().map(|p| levels[p]).max().unwrap_or(0);
            levels.insert(id, level);
            let pos = cg
                .position_of(&id)
                .unwrap_or_else(|| panic!("graph lacks {hex}"));
            assert_eq!(cg.id_at(pos), Some(id));
            assert_eq!(cg.tree_at(pos), Some(c.tree), "tree of {hex}");
            assert_eq!(cg.parents_at(pos), c.parents, "parents of {hex}");
            assert_eq!(cg.generation_at(pos), level, "level of {hex}");
            assert_eq!(
                cg.commit_time_at(pos),
                c.committer.time as u64,
                "date of {hex}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The index.
// ---------------------------------------------------------------------------

/// One `git ls-files --stage --debug -z` record.
#[derive(Debug, PartialEq, Eq)]
struct LsEntry {
    path: Vec<u8>,
    mode: u32,
    id: String,
    stage: u8,
    ctime: (u32, u32),
    mtime: (u32, u32),
    dev: u32,
    ino: u32,
    uid: u32,
    gid: u32,
    size: u32,
}

fn ls_files_debug(git: &Git, dir: &Path) -> Vec<LsEntry> {
    let out = git.run(dir, &["ls-files", "--stage", "--debug", "-z"]);
    let mut rest = &out[..];
    let mut v = Vec::new();
    while !rest.is_empty() {
        let nul = rest.iter().position(|&b| b == 0).unwrap();
        let rec = &rest[..nul];
        rest = &rest[nul + 1..];
        let tab = rec.iter().position(|&b| b == b'\t').unwrap();
        let meta = String::from_utf8(rec[..tab].to_vec()).unwrap();
        let mut it = meta.split(' ');
        let mode = u32::from_str_radix(it.next().unwrap(), 8).unwrap();
        let id = it.next().unwrap().to_string();
        let stage: u8 = it.next().unwrap().parse().unwrap();
        // Five debug lines follow, each newline-terminated.
        let mut fields = BTreeMap::new();
        for _ in 0..5 {
            let nl = rest.iter().position(|&b| b == b'\n').unwrap();
            let line = String::from_utf8(rest[..nl].to_vec()).unwrap();
            rest = &rest[nl + 1..];
            for part in line.trim().split('\t') {
                let (k, val) = part.split_once(": ").unwrap();
                fields.insert(k.trim().to_string(), val.trim().to_string());
            }
        }
        let pair = |s: &str| {
            let (a, b) = s.split_once(':').unwrap();
            (a.parse().unwrap(), b.parse().unwrap())
        };
        v.push(LsEntry {
            path: rec[tab + 1..].to_vec(),
            mode,
            id,
            stage,
            ctime: pair(&fields["ctime"]),
            mtime: pair(&fields["mtime"]),
            dev: fields["dev"].parse().unwrap(),
            ino: fields["ino"].parse().unwrap(),
            uid: fields["uid"].parse().unwrap(),
            gid: fields["gid"].parse().unwrap(),
            size: fields["size"].parse().unwrap(),
        });
    }
    v
}

fn index_as_ls(index: &Index) -> Vec<LsEntry> {
    index
        .entries
        .iter()
        .map(|e| LsEntry {
            path: e.path.clone(),
            mode: e.mode,
            id: e.id.to_hex(),
            stage: e.stage,
            ctime: e.ctime,
            mtime: e.mtime,
            dev: e.dev,
            ino: e.ino,
            uid: e.uid,
            gid: e.gid,
            size: e.size,
        })
        .collect()
}

/// Byte equality with a readable failure (first differing offset).
fn assert_same_bytes(ours: &[u8], theirs: &[u8], what: &str) {
    if ours != theirs {
        let at = ours
            .iter()
            .zip(theirs)
            .position(|(a, b)| a != b)
            .unwrap_or(ours.len().min(theirs.len()));
        panic!(
            "{what}: puregit's bytes differ from git's at offset {at} (lengths {} vs {})\n ours: {:02x?}\n git:  {:02x?}",
            ours.len(),
            theirs.len(),
            &ours[at.saturating_sub(8)..(at + 24).min(ours.len())],
            &theirs[at.saturating_sub(8)..(at + 24).min(theirs.len())],
        );
    }
}

fn read_index(dir: &Path, algo: HashAlgo) -> (Vec<u8>, Index) {
    let bytes = std::fs::read(dir.join(".git/index")).unwrap();
    let index = Index::parse(algo, &bytes)
        .unwrap_or_else(|e| panic!("puregit cannot parse git's index: {e:?}"));
    (bytes, index)
}

/// Parses git's index, compares every entry with `ls-files --debug`, and
/// checks that serializing it back reproduces git's file byte-for-byte.
fn assert_index_matches(git: &Git, dir: &Path, algo: HashAlgo, version: u32) {
    let (bytes, index) = read_index(dir, algo);
    // git demotes v3 to v2 when no entry needs the extended flags.
    let on_disk = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    assert!(on_disk == version || (version == 3 && on_disk == 2));
    assert_eq!(index.version, on_disk);
    assert_eq!(index_as_ls(&index), ls_files_debug(git, dir));
    assert_same_bytes(
        &index.serialize(),
        &bytes,
        &format!("index v{on_disk} round-trip"),
    );
}

#[test]
fn index_versions_2_3_4_match_ls_files() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-index");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        // Some staged-but-uncommitted state too.
        support::write(&dir.join("staged-new.txt"), b"staged\n");
        support::write(&dir.join("a/b/c/d/deep.txt"), b"deep, modified\n");
        git.run(&dir, &["add", "staged-new.txt", "a/b/c/d/deep.txt"]);
        for version in [2u32, 3, 4, 2] {
            git.run(
                &dir,
                &["update-index", &format!("--index-version={version}")],
            );
            assert_index_matches(&git, &dir, algo, version);
        }
    }
}

#[test]
fn index_extended_flags_round_trip() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-index-ext");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        support::write(&dir.join("intent.txt"), b"intent to add\n");
        git.run(&dir, &["add", "-N", "intent.txt"]);
        git.run(&dir, &["update-index", "--skip-worktree", "README.md"]);
        for version in [3u32, 4] {
            git.run(
                &dir,
                &["update-index", &format!("--index-version={version}")],
            );
            assert_index_matches(&git, &dir, algo, version);
            let tags_before = git.run_str(&dir, &["ls-files", "-t", "--stage"]);
            // Write puregit's serialization back and let git read it.
            let (_, index) = read_index(&dir, algo);
            std::fs::write(dir.join(".git/index"), index.serialize()).unwrap();
            assert_eq!(
                git.run_str(&dir, &["ls-files", "-t", "--stage"]),
                tags_before
            );
        }
    }
}

#[test]
fn index_with_conflict_stages_matches_ls_files() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-index-conflict");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        git.init(&dir, algo);
        support::write(&dir.join("f.txt"), b"base\n");
        support::write(&dir.join("other.txt"), b"other\n");
        git.commit_all(&dir, "base");
        git.run(&dir, &["checkout", "-q", "-b", "side"]);
        support::write(&dir.join("f.txt"), b"side\n");
        git.commit_all(&dir, "side");
        git.run(&dir, &["checkout", "-q", "main"]);
        support::write(&dir.join("f.txt"), b"main\n");
        git.commit_all(&dir, "main");
        let out = git.output(&dir, &["merge", "-q", "side"]);
        assert!(!out.status.success(), "merge was expected to conflict");
        assert_index_matches(&git, &dir, algo, 2);
        let (_, index) = read_index(&dir, algo);
        let stages: Vec<u8> = index
            .entries
            .iter()
            .filter(|e| e.path == b"f.txt")
            .map(|e| e.stage)
            .collect();
        assert_eq!(stages, vec![1, 2, 3]);
    }
}

#[test]
fn index_with_skip_hash_is_accepted() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-index-skiphash");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        git.init(&dir, algo);
        support::write(&dir.join("f.txt"), b"x\n");
        git.run(&dir, &["-c", "index.skipHash=true", "add", "f.txt"]);
        let bytes = std::fs::read(dir.join(".git/index")).unwrap();
        let tail = &bytes[bytes.len() - algo.raw_len()..];
        if tail.iter().any(|&b| b != 0) {
            // This git predates index.skipHash; nothing to check.
            continue;
        }
        let index = Index::parse(algo, &bytes).expect("skip-hash index");
        assert_eq!(index_as_ls(&index), ls_files_debug(&git, &dir));
    }
}

// ---------------------------------------------------------------------------
// History: revwalk, merge-base, tree diff.
// ---------------------------------------------------------------------------

fn peel_to_commit(repo: &Repository, mut id: ObjectId) -> Option<ObjectId> {
    loop {
        match repo.read_object(&id).ok()? {
            Object::Commit(_) => return Some(id),
            Object::Tag(t) => id = t.object,
            _ => return None,
        }
    }
}

#[test]
fn revwalk_order_matches_rev_list() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-revwalk");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        // A long side branch merged with a short one, so breadth-first and
        // date order disagree.
        git.run(&dir, &["checkout", "-q", "-b", "long", "main~2"]);
        for i in 0..4 {
            support::write(&dir.join("long.txt"), format!("{i}\n").as_bytes());
            git.commit_all(&dir, &format!("long {i}"));
        }
        git.run(&dir, &["checkout", "-q", "main"]);
        git.tick();
        git.run(
            &dir,
            &["merge", "-q", "--no-ff", "-m", "merge long", "long"],
        );

        let repo = Repository::open(&dir).unwrap();
        let walk = |tips: &[ObjectId]| -> Vec<String> {
            puregit::walk::RevWalk::new(repo.objects(), tips)
                .map(|r| r.unwrap().0.to_hex())
                .collect()
        };
        let git_list = |args: &[&str]| -> Vec<String> {
            let mut a = vec!["rev-list"];
            a.extend_from_slice(args);
            git.run_str(&dir, &a).lines().map(String::from).collect()
        };

        assert_eq!(walk(&[repo.head_id().unwrap()]), git_list(&["HEAD"]));
        let topic = repo.refs().resolve("refs/heads/feature/topic").unwrap();
        assert_eq!(walk(&[topic]), git_list(&["feature/topic"]));

        // Every ref at once (tags peeled to their commits).
        let mut tips = Vec::new();
        for id in repo.refs().list().unwrap().into_values() {
            if let Some(c) = peel_to_commit(&repo, id)
                && !tips.contains(&c)
            {
                tips.push(c);
            }
        }
        let ours = walk(&tips);
        let theirs = git_list(&["--all"]);
        assert_eq!(ours, theirs, "rev-list --all order");
    }
}

#[test]
fn merge_base_matches_git() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-merge-base");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        git.init(&dir, algo);
        let commit = |name: &str| {
            support::write(&dir.join(format!("{name}.txt")), name.as_bytes());
            git.commit_all(&dir, name);
        };
        // o -- a1 -- a2            (main)
        //  \     \
        //   `---- m                (x: merge of o-side and a1)
        commit("o");
        commit("a1");
        git.run(&dir, &["checkout", "-q", "-b", "x", "main~1"]);
        git.tick();
        git.run(&dir, &["merge", "-q", "--no-ff", "-m", "m", "main"]);
        git.run(&dir, &["checkout", "-q", "main"]);
        commit("a2");
        // A criss-cross: p and q each merge the other's parent.
        git.run(&dir, &["checkout", "-q", "-b", "p", "main"]);
        commit("p1");
        git.run(&dir, &["checkout", "-q", "-b", "q", "main"]);
        commit("q1");
        git.run(&dir, &["checkout", "-q", "p"]);
        git.tick();
        git.run(&dir, &["merge", "-q", "--no-ff", "-m", "p merges q1", "q"]);
        git.run(&dir, &["checkout", "-q", "q"]);
        git.tick();
        git.run(
            &dir,
            &["merge", "-q", "--no-ff", "-m", "q merges p1", "p~1"],
        );
        commit("q2");
        git.run(&dir, &["checkout", "-q", "p"]);
        commit("p2");
        // An unrelated root.
        git.run(&dir, &["checkout", "-q", "--orphan", "orphan"]);
        git.run(&dir, &["rm", "-q", "-rf", "."]);
        commit("lonely");

        let repo = Repository::open(&dir).unwrap();
        let refs = [
            "main", "x", "p", "q", "orphan", "main~1", "x^2", "p~1", "q~2",
        ];
        for a in refs {
            for b in refs {
                let ia = git.rev_parse(&dir, algo, a);
                let ib = git.rev_parse(&dir, algo, b);
                let ours = puregit::walk::merge_base(repo.objects(), &ia, &ib).unwrap();
                let out = git.output(&dir, &["merge-base", "--all", a, b]);
                let all: BTreeSet<ObjectId> = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(|l| oid(algo, l))
                    .collect();
                match ours {
                    None => assert!(all.is_empty(), "merge-base {a} {b}: git found {all:?}"),
                    Some(id) => assert!(
                        all.contains(&id),
                        "merge-base {a} {b}: puregit {id} not among git's {all:?}"
                    ),
                }
                if all.len() == 1 {
                    let single = git.rev_parse(&dir, algo, &git.line(&dir, &["merge-base", a, b]));
                    assert_eq!(ours, Some(single), "merge-base {a} {b}");
                }
                let anc = git
                    .output(&dir, &["merge-base", "--is-ancestor", a, b])
                    .status
                    .success();
                assert_eq!(
                    puregit::walk::is_ancestor(repo.objects(), &ia, &ib).unwrap(),
                    anc,
                    "is-ancestor {a} {b}"
                );
            }
        }
    }
}

#[test]
fn tree_diff_matches_diff_tree() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-diff-tree");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        // A commit with a type change (file → directory), a mode change, a
        // deletion, and a symlink retarget.
        std::fs::remove_file(dir.join("a.c")).unwrap();
        support::write(&dir.join("a.c/inner.txt"), b"now a dir\n");
        std::fs::remove_file(dir.join("empty.txt")).unwrap();
        git.run(&dir, &["add", "-A"]);
        git.run(&dir, &["update-index", "--chmod=-x", "bin/script.sh"]);
        let target = git.hash_object_w(&dir, b"empty.txt");
        git.run(
            &dir,
            &[
                "update-index",
                "--cacheinfo",
                &format!("120000,{target},link-to-readme"),
            ],
        );
        git.commit_staged(&dir, "reshape");

        let repo = Repository::open(&dir).unwrap();
        let commits: Vec<String> = git
            .run_str(&dir, &["rev-list", "--all"])
            .lines()
            .map(String::from)
            .collect();
        let tree_of = |c: &str| git.rev_parse(&dir, algo, &format!("{c}^{{tree}}"));
        let mut pairs: Vec<(Option<String>, String)> = Vec::new();
        for c in &commits {
            pairs.push((None, c.clone()));
        }
        for w in commits.windows(2) {
            pairs.push((Some(w[1].clone()), w[0].clone()));
            pairs.push((Some(w[0].clone()), w[1].clone()));
        }
        pairs.push((Some(commits[commits.len() - 1].clone()), commits[0].clone()));
        for (old, new) in pairs {
            let empty;
            let old_arg = match &old {
                Some(o) => o.as_str(),
                None => {
                    empty = git.line(&dir, &["hash-object", "-t", "tree", "-w", "--stdin"]);
                    empty.as_str()
                }
            };
            let out = git.run(
                &dir,
                &[
                    "diff-tree",
                    "-r",
                    "-z",
                    "--no-renames",
                    "--name-status",
                    old_arg,
                    &new,
                ],
            );
            let recs = support::split_nul(&out);
            let mut theirs = Vec::new();
            for pair in recs.chunks(2) {
                let st = match &pair[0][..] {
                    b"A" => "A",
                    b"D" => "D",
                    b"M" | b"T" => "M",
                    other => panic!("unexpected status {other:?}"),
                };
                theirs.push((pair[1].clone(), st));
            }
            theirs.sort();
            let old_tree = old.as_deref().map(tree_of);
            let ours: Vec<(Vec<u8>, &str)> =
                puregit::walk::diff_trees(repo.objects(), old_tree.as_ref(), Some(&tree_of(&new)))
                    .unwrap()
                    .into_iter()
                    .map(|e| {
                        let st = match e.change {
                            puregit::walk::TreeChange::Added => "A",
                            puregit::walk::TreeChange::Deleted => "D",
                            puregit::walk::TreeChange::Modified => "M",
                        };
                        (e.path, st)
                    })
                    .collect();
            assert_eq!(ours, theirs, "diff-tree {old_arg} {new}");
        }
    }
}

// ---------------------------------------------------------------------------
// Status.
// ---------------------------------------------------------------------------

/// `git status --porcelain=v1` as `path → "XY"`.
fn git_status(git: &Git, dir: &Path) -> BTreeMap<Vec<u8>, String> {
    let out = git.run(
        dir,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--no-renames",
            "--ignored=no",
        ],
    );
    support::split_nul(&out)
        .into_iter()
        .map(|rec| {
            (
                rec[3..].to_vec(),
                String::from_utf8(rec[..2].to_vec()).unwrap(),
            )
        })
        .collect()
}

/// puregit's status rendered in the same `path → "XY"` shape.
fn pure_status(dir: &Path) -> BTreeMap<Vec<u8>, String> {
    use puregit::status::Change;
    let repo = Repository::open(dir).unwrap();
    let st = puregit::status::status(&repo).unwrap();
    let mut map: BTreeMap<Vec<u8>, [char; 2]> = BTreeMap::new();
    let ch = |c: Change| match c {
        Change::Added => 'A',
        Change::Modified => 'M',
        Change::Deleted => 'D',
    };
    for (p, c) in st.staged {
        map.entry(p).or_insert([' ', ' '])[0] = ch(c);
    }
    for (p, c) in st.unstaged {
        map.entry(p).or_insert([' ', ' '])[1] = ch(c);
    }
    let mut out: BTreeMap<Vec<u8>, String> = map
        .into_iter()
        .map(|(p, xy)| (p, xy.iter().collect()))
        .collect();
    for p in st.untracked {
        out.insert(p, "??".to_string());
    }
    out
}

#[test]
fn status_matches_git_porcelain() {
    require_git!();
    for algo in support::ALGOS {
        let tmp = TempDir::new("read-status");
        let git = Git::new(&tmp);
        let dir = tmp.join("repo");
        build_rich_repo(&git, &dir, algo);
        if !support::symlinks_supported() {
            // The fixture's symlink has no working-tree counterpart here;
            // drop it so both tools start from a clean tree.
            git.run(&dir, &["rm", "-q", "--cached", "link-to-readme"]);
            git.commit_staged(&dir, "drop symlink");
        }
        assert_eq!(git_status(&git, &dir), BTreeMap::new(), "fixture is clean");
        assert_eq!(
            pure_status(&dir),
            BTreeMap::new(),
            "puregit sees a clean tree"
        );

        support::write(&dir.join(".gitignore"), b"*.log\nbuild/\n");
        git.commit_all(&dir, "ignore rules");
        // Unstaged modification.
        support::write(&dir.join("README.md"), b"hello, changed\n");
        // Staged modification, then modified again.
        support::write(&dir.join("big.txt"), b"rewritten\n");
        git.run(&dir, &["add", "big.txt"]);
        support::write(&dir.join("big.txt"), b"rewritten twice\n");
        // Staged addition; staged addition then deleted from disk.
        support::write(&dir.join("added.txt"), b"added\n");
        support::write(&dir.join("added-then-gone.txt"), b"gone\n");
        git.run(&dir, &["add", "added.txt", "added-then-gone.txt"]);
        std::fs::remove_file(dir.join("added-then-gone.txt")).unwrap();
        // Unstaged deletion; staged deletion; untracked after `rm --cached`.
        std::fs::remove_file(dir.join("empty.txt")).unwrap();
        git.run(&dir, &["rm", "-q", "a/b/sibling.txt"]);
        git.run(&dir, &["rm", "-q", "--cached", "no-newline"]);
        // Untracked files, nested; ignored files.
        support::write(&dir.join("untracked.txt"), b"u\n");
        support::write(&dir.join("new dir/deeper/u2.txt"), b"u2\n");
        support::write(&dir.join("debug.log"), b"ignored\n");
        support::write(&dir.join("build/out.o"), b"ignored\n");
        // Staged mode change (git records it; the content is unchanged).
        git.run(&dir, &["update-index", "--chmod=+x", "README.md"]);
        support::set_exec(&dir.join("README.md"), true);
        // Intent-to-add.
        support::write(&dir.join("intent.txt"), b"later\n");
        git.run(&dir, &["add", "-N", "intent.txt"]);
        // Work-tree-only mode change and symlink retarget (where the
        // platform can express them).
        if cfg!(unix) {
            support::set_exec(&dir.join("crlf.txt"), true);
        }
        if support::symlinks_supported() {
            std::fs::remove_file(dir.join("link-to-readme")).unwrap();
            support::make_symlink("a.c", &dir.join("link-to-readme"));
        }

        let theirs = git_status(&git, &dir);
        assert!(theirs.len() > 8, "scenario produced {theirs:?}");
        assert_eq!(pure_status(&dir), theirs);
    }
}
