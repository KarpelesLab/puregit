//! CLI parity: read-only commands, run with the real `git` and with the built
//! `puregit` binary against copies of the same fixture repository, comparing
//! stdout, exit status and (where git's wording is stable) stderr.
//!
//! Skips (with a notice) when `git` is not on `PATH`, unless
//! `PUREGIT_REQUIRE_GIT=1`.

#![cfg(all(feature = "std", feature = "client"))]

#[path = "interop_cli_support/mod.rs"]
mod support;

use support::{Ctx, Tool, write};

macro_rules! ctx {
    ($label:expr) => {
        match Ctx::new($label) {
            Some(c) => c,
            None => return,
        }
    };
}

// ---------------------------------------------------------------------------
// Meta: version / help / unknown commands
// ---------------------------------------------------------------------------

#[test]
fn version_and_help_exit_codes() {
    let ctx = ctx!("meta");
    let d = ctx.dir("meta");
    for args in [
        &["--version"][..],
        &["version"],
        &["help"],
        &["--help"],
        &[],
        &["frobnicate"],
        &["--frobnicate"],
    ] {
        let (g, p) = ctx.both(&d, &d, args);
        assert_eq!(
            g.code,
            p.code,
            "exit code differs for {args:?}: git {} ({}), puregit {} ({})",
            g.code,
            g.err(),
            p.code,
            p.err()
        );
    }
    // `--version` prints a single "<name> version <x>"-shaped line.
    let p = ctx.pure(&d, &["--version"]);
    assert!(p.out().contains("version"), "{}", p.out());
    // The unknown-command headline is git's exact wording.
    let (g, p) = ctx.both(&d, &d, &["frobnicate"]);
    assert_eq!(g.err_line(), p.err_line());
}

// ---------------------------------------------------------------------------
// hash-object
// ---------------------------------------------------------------------------

#[test]
fn hash_object() {
    let ctx = ctx!("hash-object");
    let (g, p) = ctx.pair("ho");
    for d in [&g, &p] {
        write(d, "new.txt", "brand new\n");
        write(d, "other.txt", "");
    }
    ctx.same(&g, &p, &["hash-object", "a.txt"]);
    ctx.same(&g, &p, &["hash-object", "new.txt", "other.txt"]);
    ctx.same(&g, &p, &["hash-object", "-t", "blob", "new.txt"]);
    ctx.same(&g, &p, &["hash-object", "sp ace.txt", "uni-\u{e9}.txt"]);
    let (a, b) = ctx.both_stdin(&g, &p, &["hash-object", "--stdin"], b"from stdin\n");
    support::assert_same(&["hash-object", "--stdin"], &a, &b);
    let (a, b) = ctx.both_stdin(&g, &p, &["hash-object", "-w", "--stdin"], b"stored\n");
    support::assert_same(&["hash-object", "-w", "--stdin"], &a, &b);
    let id = a.out().trim().to_string();
    assert!(
        ctx.git(&p, &["cat-file", "-e", &id]).ok(),
        "-w did not store"
    );

    // `-w` writes a loose object real git can read back.
    let (a, _) = ctx.same(&g, &p, &["hash-object", "-w", "new.txt"]);
    let id = a.out().trim().to_string();
    assert_eq!(ctx.git_ok(&p, &["cat-file", "-p", &id]), "brand new\n");

    // A tree payload hashed with `-t tree` (no `-w`, so no validation needed).
    let tree = ctx.git_ok(&g, &["cat-file", "tree", "HEAD^{tree}"]);
    let raw = ctx.git(&g, &["cat-file", "tree", "HEAD^{tree}"]).stdout;
    assert!(!tree.is_empty());
    let (a, b) = ctx.both_stdin(&g, &p, &["hash-object", "-t", "tree", "--stdin"], &raw);
    support::assert_same(&["hash-object", "-t", "tree", "--stdin"], &a, &b);

    // Missing file: fatal.
    let (a, b) = ctx.both(&g, &p, &["hash-object", "no-such-file"]);
    assert_eq!(a.code, b.code, "{} / {}", a.err(), b.err());
}

// ---------------------------------------------------------------------------
// cat-file
// ---------------------------------------------------------------------------

#[test]
fn cat_file_type_size_pretty() {
    let ctx = ctx!("cat-file");
    let (g, p) = ctx.pair("cf");
    let head = ctx.git_ok(&g, &["rev-parse", "HEAD"]).trim().to_string();
    let short = &head[..7];
    for spec in [
        "HEAD",
        "HEAD^{tree}",
        "HEAD:a.txt",
        "HEAD:dir",
        "HEAD:script.sh",
        "v1",
        "v2",
        "main",
        "feature~1",
        head.as_str(),
        short,
    ] {
        for flag in ["-t", "-s", "-p"] {
            ctx.same(&g, &p, &["cat-file", flag, spec]);
        }
        ctx.same(&g, &p, &["cat-file", "-e", spec]);
    }
    // `cat-file <type> <obj>` prints the raw payload.
    ctx.same(&g, &p, &["cat-file", "blob", "HEAD:a.txt"]);
    ctx.same(&g, &p, &["cat-file", "commit", "HEAD"]);
    ctx.same(&g, &p, &["cat-file", "tree", "HEAD^{tree}"]);
    ctx.same(&g, &p, &["cat-file", "tag", "v2"]);

    // Unknown objects: `-e` exits 1 quietly; `-t` is fatal with git's wording.
    ctx.same(&g, &p, &["cat-file", "-e", "nope"]);
    ctx.same(&g, &p, &["cat-file", "-e", &"1".repeat(40)]);
    ctx.same_err(&g, &p, &["cat-file", "-t", "nope"]);
    ctx.same_err(&g, &p, &["cat-file", "-p", "HEAD:no-such-path"]);
    // Usage errors.
    let (a, b) = ctx.both(&g, &p, &["cat-file"]);
    assert_eq!((a.code, b.code), (129, 129), "{}", b.err());
    let (a, b) = ctx.both(&g, &p, &["cat-file", "-t"]);
    assert_eq!(a.code, b.code, "{}", b.err());
}

#[test]
fn cat_file_batch() {
    let ctx = ctx!("cat-file-batch");
    let (g, p) = ctx.pair("cfb");
    let head = ctx.git_ok(&g, &["rev-parse", "HEAD"]);
    let input = format!(
        "HEAD\nHEAD:a.txt\nv2\nnope\n{}\nHEAD^{{tree}}\nfeature\n{head}",
        "2".repeat(40)
    );
    for mode in ["--batch", "--batch-check"] {
        let (a, b) = ctx.both_stdin(&g, &p, &["cat-file", mode], input.as_bytes());
        support::assert_same(&["cat-file", mode], &a, &b);
    }
    // A custom batch-check format.
    let fmt = "--batch-check=%(objectname) %(objecttype) %(objectsize)";
    let (a, b) = ctx.both_stdin(&g, &p, &["cat-file", fmt], input.as_bytes());
    support::assert_same(&["cat-file", fmt], &a, &b);
}

// ---------------------------------------------------------------------------
// rev-parse and revision syntax
// ---------------------------------------------------------------------------

#[test]
fn rev_parse_revisions() {
    let ctx = ctx!("rev-parse");
    let (g, p) = ctx.pair("rp");
    let head = ctx.git_ok(&g, &["rev-parse", "HEAD"]).trim().to_string();
    let tree = ctx
        .git_ok(&g, &["rev-parse", "HEAD^{tree}"])
        .trim()
        .to_string();
    for spec in [
        "HEAD",
        "@",
        "main",
        "heads/main",
        "refs/heads/main",
        "feature",
        "v1",
        "v2",
        "tags/v2",
        "v2^{}",
        "v2^{commit}",
        "v2^{tree}",
        "v2^0",
        "HEAD^",
        "HEAD^1",
        "HEAD^2",
        "HEAD^^",
        "HEAD~",
        "HEAD~1",
        "HEAD~2",
        "HEAD~3",
        "HEAD^2~1",
        "HEAD~1^{tree}",
        "HEAD^{commit}",
        "HEAD^{tree}",
        "HEAD:a.txt",
        "HEAD:dir",
        "HEAD:dir/sub/c.txt",
        "HEAD:sp ace.txt",
        "HEAD:uni-\u{e9}.txt",
        "v1:a.txt",
        "HEAD~2:dir/b.txt",
        ":a.txt",
        ":0:a.txt",
        ":dir/b.txt",
        &head,
        &head[..7],
        &head[..12],
        &tree,
        &tree[..8],
    ] {
        ctx.same(&g, &p, &["rev-parse", spec]);
        ctx.same(&g, &p, &["rev-parse", "--verify", spec]);
    }
    // Several arguments at once, one line each.
    ctx.same(&g, &p, &["rev-parse", "HEAD", "v1", "feature"]);
    // Abbreviation.
    ctx.same(&g, &p, &["rev-parse", "--short", "HEAD"]);
    ctx.same(&g, &p, &["rev-parse", "--short=10", "HEAD"]);
    ctx.same(&g, &p, &["rev-parse", "--short", "v1"]);
    // Symbolic names.
    ctx.same(&g, &p, &["rev-parse", "--abbrev-ref", "HEAD"]);
    ctx.same(&g, &p, &["rev-parse", "--symbolic-full-name", "HEAD"]);
    ctx.same(&g, &p, &["rev-parse", "--symbolic-full-name", "feature"]);
    // Repository queries.
    ctx.same(&g, &p, &["rev-parse", "--git-dir"]);
    ctx.same(&g, &p, &["rev-parse", "--is-inside-work-tree"]);
    ctx.same(&g, &p, &["rev-parse", "--is-bare-repository"]);
}

#[test]
fn rev_parse_reflog_syntax() {
    let ctx = ctx!("rev-parse-reflog");
    let (g, p) = ctx.pair("rpr");
    for spec in ["HEAD@{0}", "HEAD@{1}", "main@{0}", "main@{1}", "@{0}"] {
        ctx.same(&g, &p, &["rev-parse", spec]);
    }
}

#[test]
fn rev_parse_errors() {
    let ctx = ctx!("rev-parse-errors");
    let (g, p) = ctx.pair("rpe");
    // An unknown name echoes the argument on stdout and dies with 128.
    ctx.same_err(&g, &p, &["rev-parse", "nope"]);
    ctx.same_err(&g, &p, &["rev-parse", "--verify", "nope"]);
    ctx.same(&g, &p, &["rev-parse", "--verify", "--quiet", "nope"]);
    ctx.same(&g, &p, &["rev-parse", "-q", "--verify", "nope"]);
    ctx.same_err(&g, &p, &["rev-parse", "HEAD~10"]);
    ctx.same_err(&g, &p, &["rev-parse", "HEAD^3"]);
    ctx.same(&g, &p, &["rev-parse", "--verify", "HEAD:no-such-file"]);
    ctx.same_err(&g, &p, &["rev-parse", "--verify", "HEAD", "v1"]);
    // Outside any repository.
    let out = ctx.dir("not-a-repo");
    ctx.same_err(&out, &out, &["rev-parse", "HEAD"]);
}

#[test]
fn rev_parse_packed_repository() {
    // The same lookups against a fully packed repository with packed refs.
    let ctx = ctx!("rev-parse-packed");
    let (g, p) = ctx.pair("rpp");
    for d in [&g, &p] {
        ctx.git_ok(d, &["repack", "-adq"]);
        ctx.git_ok(d, &["pack-refs", "--all"]);
        ctx.git_ok(d, &["prune-packed"]);
    }
    let head = ctx.git_ok(&g, &["rev-parse", "HEAD"]).trim().to_string();
    for spec in [
        "HEAD",
        "feature",
        "v1",
        "v2",
        "v2^{}",
        "HEAD^2",
        "HEAD~3:a.txt",
        &head[..7],
    ] {
        ctx.same(&g, &p, &["rev-parse", spec]);
    }
    for flag in ["-t", "-s", "-p"] {
        ctx.same(&g, &p, &["cat-file", flag, "v2"]);
        ctx.same(&g, &p, &["cat-file", flag, "HEAD:dir/sub/c.txt"]);
    }
    ctx.same(&g, &p, &["log", "--format=%H %s"]);
    ctx.same(&g, &p, &["ls-tree", "-r", "HEAD"]);
    ctx.same(&g, &p, &["tag"]);
    ctx.same(&g, &p, &["branch"]);
}

// ---------------------------------------------------------------------------
// ls-tree / ls-files / write-tree
// ---------------------------------------------------------------------------

#[test]
fn ls_tree() {
    let ctx = ctx!("ls-tree");
    let (g, p) = ctx.pair("lt");
    let tree = ctx
        .git_ok(&g, &["rev-parse", "HEAD^{tree}"])
        .trim()
        .to_string();
    for args in [
        &["ls-tree", "HEAD"][..],
        &["ls-tree", "main"],
        &["ls-tree", &tree],
        &["ls-tree", "HEAD:dir"],
        &["ls-tree", "v1"],
        &["ls-tree", "v2"],
        &["ls-tree", "-r", "HEAD"],
        &["ls-tree", "-r", "-t", "HEAD"],
        &["ls-tree", "-d", "HEAD"],
        &["ls-tree", "--name-only", "HEAD"],
        &["ls-tree", "-r", "--name-only", "HEAD"],
        &["ls-tree", "--name-only", "-r", "HEAD~3"],
    ] {
        ctx.same(&g, &p, args);
    }
    ctx.same_err(&g, &p, &["ls-tree", "nope"]);
}

#[test]
fn ls_files() {
    let ctx = ctx!("ls-files");
    let (g, p) = ctx.pair("lf");
    ctx.same(&g, &p, &["ls-files"]);
    ctx.same(&g, &p, &["ls-files", "-s"]);
    ctx.same(&g, &p, &["ls-files", "--stage"]);
    ctx.same(&g, &p, &["ls-files", "-z"]);
    // After staging a change and a removal.
    for d in [&g, &p] {
        write(d, "a.txt", "changed\n");
        write(d, "zz new.txt", "new\n");
        ctx.git_ok(d, &["add", "a.txt", "zz new.txt"]);
        ctx.git_ok(d, &["rm", "-q", "--cached", "dir/b.txt"]);
    }
    ctx.same(&g, &p, &["ls-files", "-s"]);
    ctx.same(&g, &p, &["ls-files"]);
}

#[test]
fn write_tree() {
    let ctx = ctx!("write-tree");
    let (g, p) = ctx.pair("wt");
    ctx.same(&g, &p, &["write-tree"]);
    for d in [&g, &p] {
        write(d, "a.txt", "changed\n");
        write(d, "new/deep/file.txt", "deep\n");
        ctx.git_ok(d, &["add", "a.txt", "new/deep/file.txt"]);
        ctx.git_ok(d, &["rm", "-q", "--cached", "dir/sub/c.txt"]);
    }
    let (a, _) = ctx.same(&g, &p, &["write-tree"]);
    // The tree puregit wrote is a real, readable object.
    let id = a.out().trim().to_string();
    assert_eq!(ctx.git_ok(&p, &["cat-file", "-t", &id]), "tree\n");
    ctx.fsck_clean(&p);
}

// ---------------------------------------------------------------------------
// log / show
// ---------------------------------------------------------------------------

#[test]
fn log_formats() {
    let ctx = ctx!("log");
    let (g, p) = ctx.pair("log");
    for args in [
        &["log"][..],
        &["log", "--oneline"],
        &["log", "--format=%H %T %P"],
        &["log", "--pretty=format:%h %t %p %s"],
        &["log", "--format=%an <%ae> %at | %cn <%ce> %ct"],
        &["log", "--format=%s%n%b--"],
        &["log", "-n", "2", "--oneline"],
        &["log", "-2", "--format=%H"],
        &["log", "--max-count=3", "--format=%H"],
        &["log", "--oneline", "feature"],
        &["log", "--oneline", "v1"],
        &["log", "--oneline", "HEAD~1"],
        &["log", "--format=%H", "HEAD^2"],
        &["log", "--pretty=oneline"],
        &["log", "--format=%h %d %s"],
        &["log", "feature", "-1"],
    ] {
        ctx.same(&g, &p, args);
    }
}

#[test]
fn log_raw_and_medium_dates() {
    // The medium (default) date format across time zones.
    let ctx = ctx!("log-tz");
    let (g, p) = ctx.pair("logtz");
    for (i, tz) in ["+0530", "-0800", "+1400"].iter().enumerate() {
        let date = format!("{} {tz}", 1_234_567_890 + i * 86_400 * 40);
        for d in [&g, &p] {
            write(d, "a.txt", &format!("tz {tz}\n"));
            ctx.git_ok(d, &["add", "a.txt"]);
            ctx.git_ok_env(
                d,
                &["commit", "-q", "-m", &format!("tz {tz}")],
                &[("GIT_AUTHOR_DATE", &date), ("GIT_COMMITTER_DATE", &date)],
            );
        }
    }
    ctx.same(&g, &p, &["log", "-3"]);
    ctx.same(&g, &p, &["log", "-3", "--format=%ad|%cd|%ai|%ci"]);
}

#[test]
fn show_objects() {
    let ctx = ctx!("show");
    let (g, p) = ctx.pair("show");
    for spec in [
        "HEAD~1",
        "HEAD~2",
        "HEAD~3",
        "feature",
        "HEAD:a.txt",
        "v1:sp ace.txt",
    ] {
        ctx.same(&g, &p, &["show", spec]);
    }
}

#[test]
fn show_tag_and_tree() {
    let ctx = ctx!("show-tag");
    let (g, p) = ctx.pair("showtag");
    ctx.same(&g, &p, &["show", "v2"]);
    ctx.same(&g, &p, &["show", "HEAD^{tree}"]);
}

#[test]
fn show_clean_merge_commit() {
    // A clean merge has an empty dense combined diff; puregit does not render
    // non-empty combined diffs (it refuses rather than printing a wrong one).
    let ctx = ctx!("show-merge");
    let (g, p) = ctx.pair("showm");
    ctx.same(&g, &p, &["show", "HEAD"]);
}

// ---------------------------------------------------------------------------
// diff / diff-tree / merge-base
// ---------------------------------------------------------------------------

#[test]
fn diff_tree() {
    let ctx = ctx!("diff-tree");
    let (g, p) = ctx.pair("dt");
    for args in [
        &["diff-tree", "HEAD~3", "HEAD~2"][..],
        &["diff-tree", "-r", "HEAD~3", "HEAD~2"],
        &["diff-tree", "-r", "HEAD~3", "HEAD"],
        &["diff-tree", "--name-status", "-r", "HEAD~3", "HEAD"],
        &["diff-tree", "-r", "--name-only", "HEAD~3", "HEAD"],
        &["diff-tree", "--name-only", "HEAD~3", "HEAD"],
        &["diff-tree", "-r", "HEAD", "HEAD~3"],
        &["diff-tree", "-r", "v1", "feature"],
        &["diff-tree", "HEAD^{tree}", "HEAD~1^{tree}"],
        &["diff-tree", "-r", "HEAD", "HEAD"],
    ] {
        ctx.same(&g, &p, args);
    }
}

#[test]
fn diff_commits_and_cached() {
    let ctx = ctx!("diff-commits");
    let (g, p) = ctx.pair("dc");
    for args in [
        &["diff", "HEAD~3", "HEAD~2"][..],
        &["diff", "HEAD~2", "HEAD~1"],
        &["diff", "HEAD~3", "HEAD"],
        &["diff", "HEAD", "HEAD~3"],
        &["diff", "--name-only", "HEAD~3", "HEAD"],
        &["diff", "--name-status", "HEAD~3", "HEAD"],
        &["diff", "--cached"],
        &["diff"],
    ] {
        ctx.same(&g, &p, args);
    }
    for d in [&g, &p] {
        write(d, "a.txt", "hello\nthere\nworld\n");
        write(d, "brand.txt", "new file\n");
        ctx.git_ok(d, &["add", "a.txt", "brand.txt"]);
        ctx.git_ok(d, &["rm", "-q", "--cached", "dir/d.txt"]);
    }
    ctx.same(&g, &p, &["diff", "--cached"]);
    ctx.same(&g, &p, &["diff", "--cached", "--name-status"]);
    ctx.same(&g, &p, &["diff", "--cached", "--exit-code"]);
    ctx.same(&g, &p, &["diff", "--cached", "--quiet"]);
    ctx.same(&g, &p, &["diff", "--cached", "HEAD~2"]);
}

#[test]
fn diff_worktree() {
    let ctx = ctx!("diff-wt");
    let (g, p) = ctx.pair("dw");
    ctx.same(&g, &p, &["diff", "--exit-code"]);
    for d in [&g, &p] {
        write(
            d,
            "dir/sub/c.txt",
            "c1\nc2 changed\nc3\nc4 edited\nc5\nc6\nc7\nc8\nc9 changed\nc10\nc11\n",
        );
        write(d, "a.txt", "hello\nworld");
        std::fs::remove_file(d.join("dir/b.txt")).unwrap();
        write(d, "sp ace.txt", "more space\n");
        write(d, "untracked.txt", "ignored by diff\n");
    }
    ctx.same(&g, &p, &["diff"]);
    ctx.same(&g, &p, &["diff", "--name-only"]);
    ctx.same(&g, &p, &["diff", "--name-status"]);
    ctx.same(&g, &p, &["diff", "--exit-code"]);
    ctx.same(&g, &p, &["diff", "--quiet"]);
}

#[test]
fn diff_unicode_path_header() {
    let ctx = ctx!("diff-unicode");
    let (g, p) = ctx.pair("du");
    for d in [&g, &p] {
        write(d, "uni-\u{e9}.txt", "changed\n");
    }
    ctx.same(&g, &p, &["diff"]);
}

#[test]
fn merge_base() {
    let ctx = ctx!("merge-base");
    let (g, p) = ctx.pair("mb");
    ctx.same(&g, &p, &["merge-base", "main", "feature"]);
    ctx.same(&g, &p, &["merge-base", "HEAD~1", "feature"]);
    ctx.same(&g, &p, &["merge-base", "v1", "v2"]);
    ctx.same(&g, &p, &["merge-base", "--is-ancestor", "v1", "HEAD"]);
    ctx.same(&g, &p, &["merge-base", "--is-ancestor", "HEAD", "v1"]);
    ctx.same(&g, &p, &["merge-base", "--is-ancestor", "feature", "main"]);
    ctx.same(
        &g,
        &p,
        &["merge-base", "--is-ancestor", "HEAD~1", "feature"],
    );
    let (a, b) = ctx.both(&g, &p, &["merge-base", "HEAD"]);
    assert_eq!((a.code, b.code), (129, 129), "{}", b.err());
    ctx.same(&g, &p, &["merge-base", "HEAD", "nope"]);
}

// ---------------------------------------------------------------------------
// status / branch / tag / config listings
// ---------------------------------------------------------------------------

#[test]
fn status_porcelain() {
    let ctx = ctx!("status");
    let (g, p) = ctx.pair("st");
    ctx.same(&g, &p, &["status", "--porcelain"]);
    for d in [&g, &p] {
        write(d, "a.txt", "modified then staged\n");
        ctx.git_ok(d, &["add", "a.txt"]);
        write(d, "a.txt", "modified again\n");
        write(d, "dir/b.txt", "unstaged\n");
        std::fs::remove_file(d.join("dir/d.txt")).unwrap();
        write(d, "staged-new.txt", "x\n");
        ctx.git_ok(d, &["add", "staged-new.txt"]);
        ctx.git_ok(d, &["rm", "-q", "--cached", "f.txt"]);
        write(d, "untracked file.txt", "u\n");
        write(d, "newdir/one.txt", "1\n");
        write(d, "newdir/two/three.txt", "3\n");
        write(d, "dir/sub/new.txt", "n\n");
        write(d, "debug.log", "ignored\n");
        write(d, "build/out.bin", "ignored\n");
    }
    ctx.same(&g, &p, &["status", "--porcelain"]);
    ctx.same(&g, &p, &["status", "-s"]);
    ctx.same(&g, &p, &["status", "--short"]);
    ctx.same(&g, &p, &["status", "--porcelain", "-uall"]);
    ctx.same(&g, &p, &["status", "--porcelain", "--untracked-files=no"]);
}

#[test]
fn status_porcelain_unicode_untracked() {
    let ctx = ctx!("status-unicode");
    let (g, p) = ctx.pair("stu");
    for d in [&g, &p] {
        write(d, "caf\u{e9}.txt", "u\n");
    }
    ctx.same(&g, &p, &["status", "--porcelain"]);
}

#[test]
#[ignore = "puregit's long-form `status` output is not git's"]
fn status_long_format() {
    let ctx = ctx!("status-long");
    let (g, p) = ctx.pair("stl");
    for d in [&g, &p] {
        write(d, "a.txt", "x\n");
    }
    ctx.same(&g, &p, &["status"]);
}

#[test]
fn branch_and_tag_listing() {
    let ctx = ctx!("listing");
    let (g, p) = ctx.pair("ls");
    ctx.same(&g, &p, &["branch"]);
    ctx.same(&g, &p, &["branch", "--list"]);
    ctx.same(&g, &p, &["tag"]);
    ctx.same(&g, &p, &["tag", "-l"]);
    ctx.same(&g, &p, &["branch", "--show-current"]);
    // Detached HEAD.
    for d in [&g, &p] {
        ctx.git_ok(d, &["checkout", "-q", "--detach", "HEAD~1"]);
    }
    ctx.same(&g, &p, &["branch"]);
    ctx.same(&g, &p, &["branch", "--show-current"]);
}

#[test]
fn config_get() {
    let ctx = ctx!("config");
    let (g, p) = ctx.pair("cfg");
    for d in [&g, &p] {
        ctx.git_ok(d, &["config", "user.name", "Config Person"]);
        ctx.git_ok(d, &["config", "remote.origin.url", "/some/where"]);
        ctx.git_ok(
            d,
            &["config", "--add", "remote.origin.fetch", "+refs/a:refs/b"],
        );
        ctx.git_ok(
            d,
            &["config", "--add", "remote.origin.fetch", "+refs/c:refs/d"],
        );
    }
    ctx.same(&g, &p, &["config", "user.name"]);
    ctx.same(&g, &p, &["config", "--get", "user.name"]);
    ctx.same(&g, &p, &["config", "core.bare"]);
    ctx.same(&g, &p, &["config", "remote.origin.url"]);
    ctx.same(&g, &p, &["config", "--get-all", "remote.origin.fetch"]);
    ctx.same(&g, &p, &["config", "Core.Bare"]);
    // Missing key: exit 1, no output.
    ctx.same(&g, &p, &["config", "no.such"]);
    ctx.same(&g, &p, &["config", "--get", "user.nothing"]);
}

// ---------------------------------------------------------------------------
// fsck / misc
// ---------------------------------------------------------------------------

#[test]
fn fsck_clean_and_dangling() {
    let ctx = ctx!("fsck");
    let (g, p) = ctx.pair("fsck");
    ctx.same(&g, &p, &["fsck"]);
    for d in [&g, &p] {
        let o = ctx.run_full(
            Tool::Git,
            d,
            &["hash-object", "-w", "--stdin"],
            Some(b"dangle\n"),
            &[],
        );
        assert!(o.ok());
    }
    ctx.same(&g, &p, &["fsck"]);
}

#[test]
fn fsck_detects_corruption() {
    let ctx = ctx!("fsck-corrupt");
    let (g, p) = ctx.pair("fsckc");
    let blob = ctx
        .git_ok(&g, &["rev-parse", "HEAD:a.txt"])
        .trim()
        .to_string();
    for d in [&g, &p] {
        let path = d.join(".git/objects").join(&blob[..2]).join(&blob[2..]);
        // Loose objects are read-only; make it writable, then truncate it.
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(&path, perm).unwrap();
        std::fs::write(&path, b"garbage").unwrap();
    }
    let (a, b) = ctx.both(&g, &p, &["fsck"]);
    assert_ne!(a.code, 0, "git fsck should fail");
    assert_ne!(b.code, 0, "puregit fsck should fail: {}", b.out());
}

#[test]
fn subdirectory_discovery() {
    // Commands run from a subdirectory find the repository above them.
    let ctx = ctx!("subdir");
    let (g, p) = ctx.pair("sub");
    let (gs, ps) = (g.join("dir/sub"), p.join("dir/sub"));
    ctx.same(&gs, &ps, &["rev-parse", "HEAD"]);
    ctx.same(&gs, &ps, &["cat-file", "-p", "HEAD:a.txt"]);
    ctx.same(&gs, &ps, &["log", "--oneline"]);
    ctx.same(&gs, &ps, &["rev-parse", "--is-inside-work-tree"]);
}

#[test]
#[ignore = "pathspecs relative to a subdirectory (ls-files/status prefix) are not implemented"]
fn subdirectory_relative_paths() {
    let ctx = ctx!("subdir-rel");
    let (g, p) = ctx.pair("subr");
    let (gs, ps) = (g.join("dir"), p.join("dir"));
    ctx.same(&gs, &ps, &["ls-files"]);
    ctx.same(&gs, &ps, &["rev-parse", "--show-prefix"]);
}

#[test]
fn empty_repository() {
    let ctx = ctx!("empty");
    let g = ctx.dir("empty-git");
    let p = ctx.dir("empty-pure");
    ctx.git_init(&g, &[]);
    ctx.git_init(&p, &[]);
    ctx.same(&g, &p, &["status", "--porcelain"]);
    ctx.same(&g, &p, &["ls-files"]);
    ctx.same(&g, &p, &["branch"]);
    ctx.same(&g, &p, &["tag"]);
    ctx.same(&g, &p, &["rev-parse", "--abbrev-ref", "HEAD"]);
    ctx.same(&g, &p, &["rev-parse", "--symbolic-full-name", "HEAD"]);
    ctx.same(&g, &p, &["rev-parse", "--verify", "-q", "HEAD"]);
    ctx.same_err(&g, &p, &["rev-parse", "HEAD"]);
    ctx.same_err(&g, &p, &["log"]);
    ctx.same(&g, &p, &["fsck"]);
    ctx.same(&g, &p, &["write-tree"]);
}

#[test]
fn usage_and_fatal_exit_codes() {
    let ctx = ctx!("exit-codes");
    let (g, p) = ctx.pair("ec");
    // Usage errors (129).
    for args in [
        &["ls-files", "--bogus"][..],
        &["log", "--bogus-flag"],
        &["cat-file", "-q", "HEAD"],
        &["merge-base"],
    ] {
        let (a, b) = ctx.both(&g, &p, args);
        assert_eq!(
            a.code,
            b.code,
            "{args:?}: git {} / puregit {}: {}",
            a.code,
            b.code,
            b.err()
        );
    }
    // Fatal errors (128) with git's wording.
    for args in [
        &["cat-file", "-p", "nope"][..],
        &["ls-tree", "nope"],
        &["log", "nope"],
        &["show", "nope"],
        &["rm", "nope.txt"],
        &["add", "nope.txt"],
        &["reset", "nope"],
        &["tag", "v1"],
        &["branch", "feature"],
        &["branch", "bad..name"],
    ] {
        ctx.same_err(&g, &p, args);
    }
    // `checkout`/`switch` of an unknown name.
    let (a, b) = ctx.both(&g, &p, &["checkout", "nope"]);
    assert_eq!((a.code, a.err_line()), (b.code, b.err_line()));
    let (a, b) = ctx.both(&g, &p, &["switch", "nope"]);
    assert_eq!(a.code, b.code, "{}", b.err());
}
