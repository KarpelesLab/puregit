//! CLI parity: mutating commands. Each command runs with real `git` in one copy
//! of the fixture and with `puregit` in another; the resulting repository state
//! (HEAD, refs, index, work-tree status — all read back with real git) must be
//! identical, and object ids must match exactly since inputs and timestamps
//! are pinned. Also covers cross-tool round trips (`git fsck --strict` clean).
//!
//! Skips (with a notice) when `git` is not on `PATH`, unless
//! `PUREGIT_REQUIRE_GIT=1`.

#![cfg(all(feature = "std", feature = "client"))]

#[path = "interop_cli_support/mod.rs"]
mod support;

use std::path::Path;

use support::{Ctx, Tool, write};

macro_rules! ctx {
    ($label:expr) => {
        match Ctx::new($label) {
            Some(c) => c,
            None => return,
        }
    };
}

/// Asserts the two repositories are in the same state.
fn same_state(ctx: &Ctx, g: &Path, p: &Path) {
    let (a, b) = (ctx.state(g), ctx.state(p));
    assert_eq!(a, b, "repository state differs (left: git, right: puregit)");
}

/// Asserts real git writes the same tree from both indexes.
fn same_tree(ctx: &Ctx, g: &Path, p: &Path) {
    assert_eq!(
        ctx.git_ok(g, &["write-tree"]),
        ctx.git_ok(p, &["write-tree"]),
        "git write-tree differs on the puregit-written index"
    );
}

/// Reads a work-tree file (for content comparisons).
fn read(dir: &Path, rel: &str) -> Option<Vec<u8>> {
    std::fs::read(dir.join(rel)).ok()
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

#[test]
fn init_layouts() {
    let ctx = ctx!("init");
    for (name, extra) in [
        ("plain", &[][..]),
        ("bare", &["--bare"][..]),
        ("sha256", &["--object-format=sha256"][..]),
        ("branch", &["-b", "trunk"][..]),
        ("initial", &["--initial-branch=dev"][..]),
    ] {
        let g = ctx.dir(&format!("init-{name}-git"));
        let p = ctx.dir(&format!("init-{name}-pure"));
        let mut args = vec!["init"];
        args.extend_from_slice(extra);
        args.push("repo");
        let (a, b) = ctx.both(&g, &p, &args);
        assert_eq!(a.code, b.code, "{args:?}: {}", b.err());
        // "Initialized empty Git repository in <abs>/repo/[.git/]" — the
        // absolute prefix differs between the two directories.
        // Compare what follows each tool's own directory name, so differing
        // spellings of the temp root (symlinks, 8.3 names) do not matter.
        let tail = |o: &support::Out, base: &Path| {
            let s = o.out().replace('\\', "/");
            let marker = format!("/{}/", base.file_name().unwrap().to_string_lossy());
            match (
                s.find("Initialized empty Git repository in "),
                s.find(&marker),
            ) {
                (Some(0), Some(i)) => format!("<prefix>{}", &s[i + marker.len()..]),
                _ => s,
            }
        };
        assert_eq!(tail(&a, &g), tail(&b, &p), "init stdout for {args:?}");
        let (gr, pr) = (g.join("repo"), p.join("repo"));
        for q in [
            &["rev-parse", "--is-bare-repository"][..],
            &["rev-parse", "--show-object-format"],
            &["symbolic-ref", "HEAD"],
            &["config", "core.bare"],
            &["config", "core.repositoryformatversion"],
            &["config", "extensions.objectformat"],
        ] {
            let (x, y) = (ctx.git(&gr, q), ctx.git(&pr, q));
            assert_eq!(
                (x.code, x.out()),
                (y.code, y.out()),
                "{name}: git {q:?} differs"
            );
        }
        ctx.fsck_clean(&pr);
    }
    // Quiet init prints nothing.
    let g = ctx.dir("init-q-git");
    let p = ctx.dir("init-q-pure");
    ctx.same(&g, &p, &["init", "-q", "repo"]);
    // Re-initialising an existing repository succeeds.
    let (a, b) = ctx.both(&g, &p, &["init", "-q", "repo"]);
    assert_eq!((a.code, b.code), (0, 0), "{}", b.err());
}

// ---------------------------------------------------------------------------
// add / rm / mv / commit
// ---------------------------------------------------------------------------

#[test]
fn add_and_commit_match_object_ids() {
    let ctx = ctx!("add-commit");
    let (g, p) = ctx.pair("ac");
    for d in [&g, &p] {
        write(d, "a.txt", "hello\nworld\nagain\n");
        write(d, "new dir/n\u{e9}w.txt", "new\n");
        write(d, "dir/sub/e.txt", "e\n");
        write(d, "ignored.log", "x\n");
        std::fs::remove_file(d.join("dir/b.txt")).unwrap();
    }
    for args in [
        &["add", "a.txt"][..],
        &["add", "new dir"],
        &["add", "dir/b.txt"],
        &["add", "dir"],
    ] {
        let (a, b) = ctx.both(&g, &p, args);
        assert_eq!(
            (a.code, a.out()),
            (b.code, b.out()),
            "{args:?}: {}",
            b.err()
        );
    }
    same_state(&ctx, &g, &p);
    // The index puregit wrote must not carry a stale cache-tree: real git
    // writing a tree from it must agree with git's own index.
    same_tree(&ctx, &g, &p);
    let (a, b) = ctx.both(&g, &p, &["commit", "-m", "puregit parity"]);
    assert_eq!(a.code, b.code, "{}", b.err());
    // First line: "[main <short>] <subject>".
    assert_eq!(a.out().lines().next(), b.out().lines().next());
    same_state(&ctx, &g, &p);
    ctx.fsck_clean(&p);
    // A second commit after `add .` (whole tree), with a multi-line message.
    for d in [&g, &p] {
        write(d, "z.txt", "z\n");
        write(d, "a.txt", "rewritten\n");
    }
    ctx.same(&g, &p, &["add", "."]);
    let (a, b) = ctx.both(
        &g,
        &p,
        &["commit", "-q", "-m", "subject", "-m", "body text"],
    );
    assert_eq!((a.code, a.out()), (b.code, b.out()), "{}", b.err());
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["cat-file", "commit", "HEAD"]);
    ctx.fsck_clean(&p);
}

#[test]
fn add_all_flag() {
    let ctx = ctx!("add-all");
    let (g, p) = ctx.pair("aa");
    for d in [&g, &p] {
        write(d, "a.txt", "changed\n");
        write(d, "brand/new.txt", "new\n");
        std::fs::remove_file(d.join("f.txt")).unwrap();
    }
    ctx.same(&g, &p, &["add", "-A"]);
    same_state(&ctx, &g, &p);
}

#[test]
fn commit_nothing_to_commit() {
    let ctx = ctx!("commit-nothing");
    let (g, p) = ctx.pair("cn");
    let (a, b) = ctx.both(&g, &p, &["commit", "-m", "nothing"]);
    assert_eq!(a.code, b.code, "{}{}", b.out(), b.err());
    same_state(&ctx, &g, &p);
}

#[test]
fn commit_root_and_detached() {
    let ctx = ctx!("commit-root");
    let g = ctx.dir("root-git");
    let p = ctx.dir("root-pure");
    ctx.git_init(&g, &[]);
    ctx.git_init(&p, &[]);
    for d in [&g, &p] {
        write(d, "one.txt", "1\n");
    }
    ctx.same(&g, &p, &["add", "one.txt"]);
    let (a, b) = ctx.both(&g, &p, &["commit", "-m", "root"]);
    assert_eq!(a.code, b.code, "{}", b.err());
    assert_eq!(a.out().lines().next(), b.out().lines().next());
    same_state(&ctx, &g, &p);
    // Commit on a detached HEAD moves HEAD only.
    for d in [&g, &p] {
        ctx.git_ok(d, &["checkout", "-q", "--detach"]);
        write(d, "two.txt", "2\n");
        ctx.git_ok(d, &["add", "two.txt"]);
    }
    let (a, b) = ctx.both(&g, &p, &["commit", "-m", "detached"]);
    assert_eq!(a.code, b.code, "{}", b.err());
    assert_eq!(a.out().lines().next(), b.out().lines().next());
    same_state(&ctx, &g, &p);
    ctx.fsck_clean(&p);
}

#[test]
fn rm_and_mv() {
    let ctx = ctx!("rm-mv");
    let (g, p) = ctx.pair("rm");
    ctx.same(&g, &p, &["rm", "a.txt"]);
    ctx.same(&g, &p, &["rm", "--cached", "sp ace.txt"]);
    ctx.same(&g, &p, &["rm", "-q", "dir/d.txt"]);
    ctx.same(&g, &p, &["mv", "dir/b.txt", "moved.txt"]);
    ctx.same(&g, &p, &["mv", "f.txt", "dir/sub/f2.txt"]);
    same_state(&ctx, &g, &p);
    assert_eq!(read(&g, "moved.txt"), read(&p, "moved.txt"));
    assert!(read(&p, "a.txt").is_none());
    assert!(read(&p, "sp ace.txt").is_some());
    same_tree(&ctx, &g, &p);
    ctx.same(&g, &p, &["commit", "-q", "-m", "rm and mv"]);
    same_state(&ctx, &g, &p);
    // Errors with git's wording.
    ctx.same_err(&g, &p, &["rm", "a.txt"]);
    ctx.same_err(&g, &p, &["mv", "nope", "x"]);
}

#[test]
#[ignore = "puregit status has no rename detection (git reports `R  old -> new`)"]
fn status_after_mv_shows_rename() {
    let ctx = ctx!("status-rename");
    let (g, p) = ctx.pair("sr");
    for d in [&g, &p] {
        ctx.git_ok(d, &["mv", "a.txt", "b.txt"]);
    }
    ctx.same(&g, &p, &["status", "--porcelain"]);
}

// ---------------------------------------------------------------------------
// branch / tag / checkout / switch / reset
// ---------------------------------------------------------------------------

#[test]
fn branch_create_delete() {
    let ctx = ctx!("branch");
    let (g, p) = ctx.pair("br");
    ctx.same(&g, &p, &["branch", "topic"]);
    ctx.same(&g, &p, &["branch", "old", "HEAD~2"]);
    ctx.same(&g, &p, &["branch", "fromtag", "v1"]);
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["branch"]);
    ctx.same(&g, &p, &["branch", "-d", "topic"]);
    ctx.same(&g, &p, &["branch", "-D", "old"]);
    same_state(&ctx, &g, &p);
    ctx.same_err(&g, &p, &["branch", "-d", "nope"]);
}

#[test]
fn tag_create_delete() {
    let ctx = ctx!("tag");
    let (g, p) = ctx.pair("tag");
    ctx.same(&g, &p, &["tag", "light"]);
    ctx.same(&g, &p, &["tag", "light2", "HEAD~2"]);
    ctx.same(&g, &p, &["tag", "-a", "ann", "-m", "an annotated tag"]);
    ctx.same(
        &g,
        &p,
        &["tag", "-m", "implicit annotate", "ann2", "feature"],
    );
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["cat-file", "-p", "ann"]);
    ctx.same(&g, &p, &["tag"]);
    ctx.same(&g, &p, &["tag", "-d", "light"]);
    same_state(&ctx, &g, &p);
    ctx.same_err(&g, &p, &["tag", "ann"]);
    ctx.fsck_clean(&p);
}

#[test]
fn checkout_and_switch() {
    let ctx = ctx!("checkout");
    let (g, p) = ctx.pair("co");
    let (a, b) = ctx.both(&g, &p, &["checkout", "feature"]);
    assert_eq!((a.code, a.out(), a.err()), (b.code, b.out(), b.err()));
    same_state(&ctx, &g, &p);
    // Files present only on main must be gone from the work tree.
    assert_eq!(read(&g, "dir/sub/c.txt"), read(&p, "dir/sub/c.txt"));
    let (a, b) = ctx.both(&g, &p, &["checkout", "-b", "newbranch"]);
    assert_eq!((a.code, a.err()), (b.code, b.err()));
    same_state(&ctx, &g, &p);
    let (a, b) = ctx.both(&g, &p, &["switch", "main"]);
    assert_eq!((a.code, a.err()), (b.code, b.err()));
    same_state(&ctx, &g, &p);
    let (a, b) = ctx.both(&g, &p, &["switch", "-c", "made-by-switch", "v1"]);
    assert_eq!(a.code, b.code, "{}", b.err());
    same_state(&ctx, &g, &p);
    assert_eq!(read(&g, "f.txt"), read(&p, "f.txt"));
    assert_eq!(read(&g, "dir/d.txt"), read(&p, "dir/d.txt"));
    // Detached checkouts.
    let (a, b) = ctx.both(&g, &p, &["checkout", "--detach", "main"]);
    assert_eq!(a.code, b.code, "{}", b.err());
    same_state(&ctx, &g, &p);
    let (a, b) = ctx.both(&g, &p, &["checkout", "v1"]);
    assert_eq!(a.code, b.code, "{}", b.err());
    same_state(&ctx, &g, &p);
    let (a, b) = ctx.both(&g, &p, &["switch", "--detach", "feature~1"]);
    assert_eq!(a.code, b.code, "{}", b.err());
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["branch"]);
}

#[test]
fn reset_modes() {
    let ctx = ctx!("reset");
    let (g, p) = ctx.pair("rs");
    for d in [&g, &p] {
        write(d, "a.txt", "dirty\n");
        write(d, "dir/b.txt", "staged\n");
        ctx.git_ok(d, &["add", "dir/b.txt"]);
    }
    ctx.same(&g, &p, &["reset", "--soft", "HEAD~1"]);
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["reset"]);
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["reset", "--mixed", "feature"]);
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["reset", "--hard", "v1"]);
    same_state(&ctx, &g, &p);
    assert_eq!(read(&g, "a.txt"), read(&p, "a.txt"));
    assert_eq!(read(&g, "dir/d.txt"), read(&p, "dir/d.txt"));
    ctx.same(&g, &p, &["reset", "-q", "--hard", "main"]);
    same_state(&ctx, &g, &p);
}

// ---------------------------------------------------------------------------
// config (write)
// ---------------------------------------------------------------------------

#[test]
fn config_set() {
    let ctx = ctx!("config-set");
    let (g, p) = ctx.pair("cs");
    ctx.same(&g, &p, &["config", "user.name", "Some Body"]);
    ctx.same(&g, &p, &["config", "branch.main.remote", "origin"]);
    ctx.same(&g, &p, &["config", "core.bare", "false"]);
    for q in ["user.name", "branch.main.remote", "core.bare"] {
        let (a, b) = (ctx.git(&g, &["config", q]), ctx.git(&p, &["config", q]));
        assert_eq!(a.out(), b.out(), "{q}");
    }
    ctx.same(&g, &p, &["config", "--unset", "user.name"]);
    let (a, b) = (
        ctx.git(&g, &["config", "user.name"]),
        ctx.git(&p, &["config", "user.name"]),
    );
    assert_eq!((a.code, b.code), (1, 1));
}

// ---------------------------------------------------------------------------
// clone (local only) / unpack-objects
// ---------------------------------------------------------------------------

#[test]
fn clone_local_path_and_file_url() {
    let ctx = ctx!("clone");
    let fx = ctx.fixture().to_path_buf();
    let src = fx.display().to_string();
    let url = file_url(&fx);
    for (name, from) in [("path", src.as_str()), ("url", url.as_str())] {
        let g = ctx.dir(&format!("clone-{name}-git"));
        let p = ctx.dir(&format!("clone-{name}-pure"));
        let (a, b) = ctx.both(&g, &p, &["clone", "-q", from, "dst"]);
        assert_eq!((a.code, a.out()), (b.code, b.out()), "{}", b.err());
        let (gd, pd) = (g.join("dst"), p.join("dst"));
        same_state(&ctx, &gd, &pd);
        for q in [
            &["config", "remote.origin.url"][..],
            &["config", "remote.origin.fetch"],
            &["config", "branch.main.remote"],
            &["config", "branch.main.merge"],
            &["rev-parse", "--abbrev-ref", "origin/HEAD"],
        ] {
            let (x, y) = (ctx.git(&gd, q), ctx.git(&pd, q));
            assert_eq!((x.code, x.out()), (y.code, y.out()), "{q:?}");
        }
        assert_eq!(read(&gd, "a.txt"), read(&pd, "a.txt"));
        ctx.fsck_clean(&pd);
        // The clone is fully usable by git.
        ctx.git_ok(&pd, &["log", "--oneline", "origin/feature"]);
    }
}

#[test]
fn clone_default_directory_name() {
    let ctx = ctx!("clone-name");
    let fx = ctx.fixture().to_path_buf();
    let g = ctx.dir("cn-git");
    let p = ctx.dir("cn-pure");
    let (a, b) = ctx.both(&g, &p, &["clone", "-q", &fx.display().to_string()]);
    assert_eq!(a.code, b.code, "{}", b.err());
    same_state(&ctx, &g.join("fixture"), &p.join("fixture"));
}

#[test]
fn clone_bare() {
    let ctx = ctx!("clone-bare");
    let fx = ctx.fixture().to_path_buf();
    let g = ctx.dir("cb-git");
    let p = ctx.dir("cb-pure");
    let (a, b) = ctx.both(
        &g,
        &p,
        &["clone", "-q", "--bare", &fx.display().to_string(), "b.git"],
    );
    assert_eq!(a.code, b.code, "{}", b.err());
    let (gd, pd) = (g.join("b.git"), p.join("b.git"));
    for q in [
        &["for-each-ref", "--format=%(refname) %(objectname)"][..],
        &["symbolic-ref", "HEAD"],
        &["rev-parse", "--is-bare-repository"],
    ] {
        let (x, y) = (ctx.git(&gd, q), ctx.git(&pd, q));
        assert_eq!((x.code, x.out()), (y.code, y.out()), "{q:?}");
    }
    ctx.fsck_clean(&pd);
}

fn file_url(path: &Path) -> String {
    let s = path.display().to_string().replace('\\', "/");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

#[test]
fn unpack_objects_from_stdin() {
    let ctx = ctx!("unpack");
    let fx = ctx.fixture().to_path_buf();
    // Build a pack of everything reachable from main with real git.
    let revs = ctx.git_ok(&fx, &["rev-list", "--objects", "--all"]);
    let ids: String = revs
        .lines()
        .map(|l| l.split(' ').next().unwrap().to_string() + "\n")
        .collect();
    let pack = ctx.run_full(
        Tool::Git,
        &fx,
        &["pack-objects", "--stdout"],
        Some(ids.as_bytes()),
        &[],
    );
    assert!(pack.ok(), "{}", pack.err());
    let g = ctx.dir("up-git");
    let p = ctx.dir("up-pure");
    ctx.git_init(&g, &[]);
    ctx.git_init(&p, &[]);
    let (a, b) = ctx.both_stdin(&g, &p, &["unpack-objects", "-q"], &pack.stdout);
    support::assert_same(&["unpack-objects"], &a, &b);
    let list = |d: &Path| {
        ctx.git_ok(
            d,
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            ],
        )
    };
    assert_eq!(list(&g), list(&p));
}

// ---------------------------------------------------------------------------
// Cross-tool round trips
// ---------------------------------------------------------------------------

#[test]
fn round_trip_puregit_repo_read_by_git() {
    let ctx = ctx!("rt-pure-to-git");
    let g = ctx.dir("rt1-git");
    let p = ctx.dir("rt1-pure");
    // Same history built by each tool from scratch.
    ctx.git_ok(&g, &["init", "-q"]);
    ctx.pure_ok(&p, &["init", "-q"]);
    for d in [&g, &p] {
        ctx.git_ok(d, &["config", "core.autocrlf", "false"]);
    }
    let steps: &[&[(&str, &str)]] = &[
        &[
            ("a.txt", "a\n"),
            ("d/e/f.txt", "deep\n"),
            ("sp ace.txt", "s\n"),
        ],
        &[("a.txt", "a2\n"), ("b.txt", "b\n")],
        &[("d/e/f.txt", "deeper\n")],
    ];
    for (i, files) in steps.iter().enumerate() {
        let date = format!("{} +0200", 1_600_000_000 + i * 3600);
        for d in [&g, &p] {
            for (f, c) in *files {
                write(d, f, c);
            }
        }
        for (tool, d) in [(Tool::Git, &g), (Tool::Pure, &p)] {
            let o = ctx.run(tool, d, &["add", "."]);
            assert!(o.ok(), "{tool:?} add: {}", o.err());
            let o = ctx.run_full(
                tool,
                d,
                &["commit", "-q", "-m", &format!("step {i}")],
                None,
                &[("GIT_AUTHOR_DATE", &date), ("GIT_COMMITTER_DATE", &date)],
            );
            assert!(o.ok(), "{tool:?} commit: {}", o.err());
        }
    }
    same_state(&ctx, &g, &p);
    ctx.fsck_clean(&p);
    assert_eq!(
        ctx.git_ok(&g, &["log", "--format=%H %T %an %ad"]),
        ctx.git_ok(&p, &["log", "--format=%H %T %an %ad"])
    );
    // Git can keep working in the puregit repository, and puregit can read it.
    write(&p, "after.txt", "git was here\n");
    ctx.git_ok(&p, &["add", "after.txt"]);
    ctx.git_ok(&p, &["commit", "-q", "-m", "by git"]);
    ctx.git_ok(&p, &["gc", "-q"]);
    assert_eq!(
        ctx.pure_ok(&p, &["rev-parse", "HEAD"]),
        ctx.git_ok(&p, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        ctx.pure_ok(&p, &["log", "--format=%H %s"]),
        ctx.git_ok(&p, &["log", "--format=%H %s"])
    );
    assert_eq!(
        ctx.pure_ok(&p, &["status", "--porcelain"]),
        ctx.git_ok(&p, &["status", "--porcelain"])
    );
}

#[test]
fn round_trip_git_repo_mutated_by_puregit() {
    let ctx = ctx!("rt-git-to-pure");
    let (g, p) = ctx.pair("rt2");
    // Pack the repositories first so puregit works against packs + packed-refs.
    for d in [&g, &p] {
        ctx.git_ok(d, &["gc", "-q"]);
    }
    for d in [&g, &p] {
        write(d, "dir/sub/c.txt", "rewritten by both\n");
        write(d, "added.txt", "added\n");
    }
    for (tool, d) in [(Tool::Git, &g), (Tool::Pure, &p)] {
        for args in [
            &["add", "dir/sub/c.txt", "added.txt"][..],
            &["rm", "-q", "uni-\u{e9}.txt"],
            &["commit", "-q", "-m", "mutated"],
            &["tag", "-a", "-m", "after mutation", "v3"],
            &["branch", "side", "HEAD~2"],
        ] {
            let o = ctx.run(tool, d, args);
            assert!(o.ok(), "{tool:?} {args:?}: {}", o.err());
        }
    }
    same_state(&ctx, &g, &p);
    ctx.fsck_clean(&p);
    assert_eq!(
        ctx.git_ok(&g, &["cat-file", "tag", "v3"]),
        ctx.git_ok(&p, &["cat-file", "tag", "v3"])
    );
}

#[test]
fn sha256_repository() {
    let ctx = ctx!("sha256");
    let g = ctx.dir("s256-git");
    let p = ctx.dir("s256-pure");
    ctx.git_ok(&g, &["init", "-q", "--object-format=sha256"]);
    let o = ctx.pure(&p, &["init", "-q", "--object-format=sha256"]);
    assert!(o.ok(), "{}", o.err());
    for d in [&g, &p] {
        ctx.pin_config(d);
        write(d, "a.txt", "sha256 content\n");
        write(d, "sub/b.txt", "b\n");
    }
    ctx.same(&g, &p, &["hash-object", "a.txt"]);
    ctx.same(&g, &p, &["add", "a.txt", "sub/b.txt"]);
    ctx.same(&g, &p, &["write-tree"]);
    let (a, b) = ctx.both(&g, &p, &["commit", "-q", "-m", "sha256 commit"]);
    assert_eq!((a.code, a.out()), (b.code, b.out()), "{}", b.err());
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["rev-parse", "HEAD", "HEAD^{tree}", "HEAD:a.txt"]);
    ctx.same(&g, &p, &["cat-file", "-p", "HEAD"]);
    ctx.same(&g, &p, &["ls-tree", "-r", "HEAD"]);
    ctx.same(&g, &p, &["log", "--oneline"]);
    ctx.same(&g, &p, &["tag", "-a", "t", "-m", "sha256 tag"]);
    same_state(&ctx, &g, &p);
    ctx.fsck_clean(&p);
}

#[test]
fn unicode_and_space_paths() {
    let ctx = ctx!("unicode");
    let (g, p) = ctx.pair("uni");
    let names = [
        "\u{65e5}\u{672c}\u{8a9e}.txt",
        "with space/and more.txt",
        "\u{e9}t\u{e9}/\u{f1}.md",
        "emoji-\u{1f600}.txt",
    ];
    for d in [&g, &p] {
        for n in names {
            write(d, n, &format!("{n}\n"));
        }
    }
    for (tool, d) in [(Tool::Git, &g), (Tool::Pure, &p)] {
        let mut args = vec!["add"];
        args.extend(names);
        let o = ctx.run(tool, d, &args);
        assert!(o.ok(), "{tool:?}: {}", o.err());
        let o = ctx.run(tool, d, &["commit", "-q", "-m", "unicode \u{2713}"]);
        assert!(o.ok(), "{tool:?}: {}", o.err());
    }
    same_state(&ctx, &g, &p);
    ctx.same(&g, &p, &["ls-tree", "-r", "-z", "HEAD"]);
    ctx.same(&g, &p, &["ls-files", "-z"]);
    ctx.same(&g, &p, &["log", "--format=%s", "-1"]);
    ctx.fsck_clean(&p);
}
