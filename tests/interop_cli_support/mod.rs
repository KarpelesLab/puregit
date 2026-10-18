//! Shared harness for the `interop_cli*` test binaries: runs the same command
//! with the real `git` and with the built `puregit` binary under an identical,
//! hermetic environment, and compares the results.
//!
//! This directory has no `main.rs`, so Cargo does not build it as a test target
//! of its own; each `tests/interop_cli*.rs` pulls it in with `#[path]`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Fixed identity and clock for both tools, so object ids are reproducible.
pub const NAME: &str = "A U Thor";
pub const EMAIL: &str = "author@example.com";
pub const DATE: &str = "1700000000 +0000";

/// The `-c` overrides passed to real git on every invocation.
const GIT_OVERRIDES: &[&str] = &[
    "-c",
    "core.autocrlf=false",
    "-c",
    "init.defaultBranch=main",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "tag.gpgsign=false",
    "-c",
    "gc.auto=0",
    "-c",
    "advice.detachedHead=false",
    "-c",
    "core.pager=cat",
];

/// The repository-level config written into every fixture (so puregit, which
/// does not take `-c`, sees the same settings real git gets on its command line).
const REPO_CONFIG: &[(&str, &str)] = &[
    ("core.autocrlf", "false"),
    ("commit.gpgsign", "false"),
    ("tag.gpgsign", "false"),
    ("gc.auto", "0"),
];

/// Which binary to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    /// The real `git` from `PATH`.
    Git,
    /// The `puregit` binary built from this crate.
    Pure,
}

/// The captured result of one command.
#[derive(Clone, Debug)]
pub struct Out {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Out {
    pub fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
    /// The first line of stderr (git's wording for the headline message).
    pub fn err_line(&self) -> String {
        self.err().lines().next().unwrap_or("").to_string()
    }
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// A temporary directory removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> TempDir {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "puregit-cli-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        // Canonicalize so both tools see the same spelling of the path (macOS
        // `/var` vs `/private/var`); keep the plain form on Windows, where
        // canonicalize yields a `\\?\` verbatim path git does not print.
        #[cfg(not(windows))]
        let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
        TempDir(dir)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Whether a working `git` is on `PATH`.
pub fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A per-test context: a temp root with a hermetic `HOME` and an empty global
/// config file. `None` (after printing a skip notice) when git is missing,
/// unless `PUREGIT_REQUIRE_GIT=1`, in which case a missing git is a failure.
pub struct Ctx {
    tmp: TempDir,
    home: PathBuf,
    global: PathBuf,
    fixture: std::cell::OnceCell<PathBuf>,
}

impl Ctx {
    pub fn new(label: &str) -> Option<Ctx> {
        if !git_available() {
            if std::env::var("PUREGIT_REQUIRE_GIT").as_deref() == Ok("1") {
                panic!("git is not on PATH but PUREGIT_REQUIRE_GIT=1");
            }
            eprintln!("skipping {label}: `git` not found on PATH");
            return None;
        }
        let tmp = TempDir::new(label);
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let global = home.join("gitconfig");
        std::fs::write(&global, b"").unwrap();
        Some(Ctx {
            tmp,
            home,
            global,
            fixture: std::cell::OnceCell::new(),
        })
    }

    pub fn root(&self) -> &Path {
        self.tmp.path()
    }

    /// A fresh, empty directory under the temp root.
    pub fn dir(&self, name: &str) -> PathBuf {
        let d = self.root().join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Runs `tool` in `dir` with `args`, optional stdin bytes, and extra env.
    pub fn run_full(
        &self,
        tool: Tool,
        dir: &Path,
        args: &[&str],
        stdin: Option<&[u8]>,
        env: &[(&str, &str)],
    ) -> Out {
        let mut cmd = match tool {
            Tool::Git => {
                let mut c = Command::new("git");
                c.args(GIT_OVERRIDES);
                c
            }
            Tool::Pure => Command::new(env!("CARGO_BIN_EXE_puregit")),
        };
        cmd.args(args).current_dir(dir);
        // Scrub any inherited git environment, then pin a hermetic one.
        for (k, _) in std::env::vars_os() {
            if let Some(k) = k.to_str()
                && k.starts_with("GIT_")
            {
                cmd.env_remove(k);
            }
        }
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.global)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("xdg"))
            .env("GIT_AUTHOR_NAME", NAME)
            .env("GIT_AUTHOR_EMAIL", EMAIL)
            .env("GIT_AUTHOR_DATE", DATE)
            .env("GIT_COMMITTER_NAME", NAME)
            .env("GIT_COMMITTER_EMAIL", EMAIL)
            .env("GIT_COMMITTER_DATE", DATE)
            .env("GIT_PAGER", "cat")
            .env("PAGER", "cat")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ADVICE", "0")
            .env("GIT_CEILING_DIRECTORIES", self.root())
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("TZ", "UTC");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {tool:?} {args:?}: {e}"));
        let writer = stdin.map(|bytes| {
            let mut pipe = child.stdin.take().unwrap();
            let bytes = bytes.to_vec();
            std::thread::spawn(move || {
                use std::io::Write;
                let _ = pipe.write_all(&bytes);
            })
        });
        let output = child.wait_with_output().unwrap();
        if let Some(w) = writer {
            let _ = w.join();
        }
        Out {
            code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }

    pub fn run(&self, tool: Tool, dir: &Path, args: &[&str]) -> Out {
        self.run_full(tool, dir, args, None, &[])
    }

    pub fn git(&self, dir: &Path, args: &[&str]) -> Out {
        self.run(Tool::Git, dir, args)
    }

    pub fn pure(&self, dir: &Path, args: &[&str]) -> Out {
        self.run(Tool::Pure, dir, args)
    }

    /// Runs real git and asserts success, returning stdout.
    pub fn git_ok(&self, dir: &Path, args: &[&str]) -> String {
        let o = self.git(dir, args);
        assert!(o.ok(), "git {args:?} failed ({}): {}", o.code, o.err());
        o.out()
    }

    /// Like [`git_ok`] with an extra environment (e.g. a per-commit date).
    pub fn git_ok_env(&self, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
        let o = self.run_full(Tool::Git, dir, args, None, env);
        assert!(o.ok(), "git {args:?} failed ({}): {}", o.code, o.err());
        o.out()
    }

    /// Runs puregit and asserts success, returning stdout.
    pub fn pure_ok(&self, dir: &Path, args: &[&str]) -> String {
        let o = self.pure(dir, args);
        assert!(
            o.ok(),
            "puregit {args:?} failed ({}): {}{}",
            o.code,
            o.out(),
            o.err()
        );
        o.out()
    }

    /// Initialises `dir` as an empty repo with real git and pins the
    /// repository-level config both tools should see.
    pub fn git_init(&self, dir: &Path, extra: &[&str]) {
        let mut args = vec!["init", "-q"];
        args.extend_from_slice(extra);
        self.git_ok(dir, &args);
        self.pin_config(dir);
    }

    /// Writes the hermetic settings into `dir`'s repository config.
    pub fn pin_config(&self, dir: &Path) {
        for (k, v) in REPO_CONFIG {
            self.git_ok(dir, &["config", k, v]);
        }
    }

    /// The shared fixture repository (built once per context with real git).
    ///
    /// History (each commit at a distinct fixed date):
    ///
    /// ```text
    ///   c1 (v1) ── c2 ── c3 ──────── M (main, HEAD)
    ///                └── c4 (feature) ┘
    /// ```
    /// with `v2` an annotated tag on `c3`, an executable `script.sh`, a
    /// `.gitignore`, and paths containing a space and non-ASCII characters.
    pub fn fixture(&self) -> &Path {
        self.fixture.get_or_init(|| {
            let fx = self.root().join("fixture");
            std::fs::create_dir_all(&fx).unwrap();
            self.git_init(&fx, &[]);
            let at = |n: u32| format!("{} +0000", 1_700_000_000u64 + u64::from(n) * 100);
            let commit = |msg: &str, n: u32| {
                let d = at(n);
                self.git_ok_env(
                    &fx,
                    &["commit", "-q", "-m", msg],
                    &[("GIT_AUTHOR_DATE", &d), ("GIT_COMMITTER_DATE", &d)],
                );
            };
            write(&fx, "a.txt", "hello\n");
            write(&fx, "dir/b.txt", "b\n");
            write(
                &fx,
                "dir/sub/c.txt",
                "c1\nc2\nc3\nc4\nc5\nc6\nc7\nc8\nc9\nc10\n",
            );
            write(&fx, "sp ace.txt", "space\n");
            write(&fx, "uni-\u{e9}.txt", "unicode\n");
            write(&fx, "script.sh", "#!/bin/sh\necho hi\n");
            write(&fx, ".gitignore", "*.log\nbuild/\n");
            set_exec(&fx.join("script.sh"));
            self.git_ok(&fx, &["add", "-A"]);
            self.git_ok(&fx, &["update-index", "--chmod=+x", "script.sh"]);
            commit("initial", 1);
            self.git_ok(&fx, &["tag", "v1"]);

            write(&fx, "a.txt", "hello\nworld\n");
            write(&fx, "dir/d.txt", "d\n");
            self.git_ok(&fx, &["add", "-A"]);
            commit("second\n\nWith a body line.", 2);
            self.git_ok(&fx, &["branch", "feature"]);

            write(
                &fx,
                "dir/sub/c.txt",
                "c1\nc2 changed\nc3\nc4\nc5\nc6\nc7\nc8\nc9 changed\nc10\n",
            );
            self.git_ok(&fx, &["add", "-A"]);
            commit("third on main", 3);
            let d = at(6);
            self.git_ok_env(
                &fx,
                &["tag", "-a", "v2", "-m", "version two"],
                &[("GIT_COMMITTER_DATE", &d)],
            );

            self.git_ok(&fx, &["checkout", "-q", "feature"]);
            write(&fx, "f.txt", "feature\n");
            self.git_ok(&fx, &["add", "-A"]);
            commit("feature work", 4);
            self.git_ok(&fx, &["checkout", "-q", "main"]);
            let d = at(5);
            self.git_ok_env(
                &fx,
                &["merge", "-q", "--no-ff", "-m", "merge feature", "feature"],
                &[("GIT_AUTHOR_DATE", &d), ("GIT_COMMITTER_DATE", &d)],
            );
            fx
        })
    }

    /// A fresh copy of the fixture at `<root>/<name>`.
    pub fn copy(&self, name: &str) -> PathBuf {
        let dst = self.root().join(name);
        let _ = std::fs::remove_dir_all(&dst);
        copy_dir(self.fixture(), &dst);
        dst
    }

    /// Two fresh fixture copies: one for git, one for puregit.
    pub fn pair(&self, name: &str) -> (PathBuf, PathBuf) {
        (
            self.copy(&format!("{name}-git")),
            self.copy(&format!("{name}-pure")),
        )
    }

    /// A snapshot of a repository's state, read with real git: HEAD (symbolic
    /// and resolved), all refs, the index, and the work-tree status.
    pub fn state(&self, dir: &Path) -> String {
        let mut s = String::new();
        for args in [
            &["symbolic-ref", "-q", "HEAD"][..],
            &["rev-parse", "-q", "--verify", "HEAD"],
            &["for-each-ref", "--format=%(refname) %(objectname)"],
            &["ls-files", "-s"],
            &["status", "--porcelain", "--untracked-files=all"],
        ] {
            let o = self.git(dir, args);
            s.push_str(&format!("$ git {}\n{}", args.join(" "), o.out()));
        }
        s
    }

    /// Asserts `git fsck --strict` is clean on `dir`.
    pub fn fsck_clean(&self, dir: &Path) {
        let o = self.git(dir, &["fsck", "--strict", "--no-dangling"]);
        assert!(
            o.ok(),
            "git fsck --strict failed in {}:\n{}{}",
            dir.display(),
            o.out(),
            o.err()
        );
    }

    /// Runs `args` with git in `g` and puregit in `p` and returns both.
    pub fn both(&self, g: &Path, p: &Path, args: &[&str]) -> (Out, Out) {
        (self.git(g, args), self.pure(p, args))
    }

    /// Runs `args` (with stdin) with git in `g` and puregit in `p`.
    pub fn both_stdin(&self, g: &Path, p: &Path, args: &[&str], stdin: &[u8]) -> (Out, Out) {
        (
            self.run_full(Tool::Git, g, args, Some(stdin), &[]),
            self.run_full(Tool::Pure, p, args, Some(stdin), &[]),
        )
    }

    /// Runs `args` with both tools and asserts identical stdout and exit code.
    pub fn same(&self, g: &Path, p: &Path, args: &[&str]) -> (Out, Out) {
        let (a, b) = self.both(g, p, args);
        assert_same(args, &a, &b);
        (a, b)
    }

    /// Like [`same`], additionally requiring the first stderr line to match.
    pub fn same_err(&self, g: &Path, p: &Path, args: &[&str]) -> (Out, Out) {
        let (a, b) = self.same(g, p, args);
        assert_eq!(
            a.err_line(),
            b.err_line(),
            "stderr headline differs for {args:?}\n git: {}\npure: {}",
            a.err(),
            b.err()
        );
        (a, b)
    }
}

/// Asserts two outcomes have identical stdout and exit code.
pub fn assert_same(args: &[&str], git: &Out, pure: &Out) {
    assert!(
        git.code == pure.code && git.stdout == pure.stdout,
        "mismatch for {args:?}\n--- git (exit {}) stdout:\n{}\n--- git stderr:\n{}\n--- puregit (exit {}) stdout:\n{}\n--- puregit stderr:\n{}",
        git.code,
        git.out(),
        git.err(),
        pure.code,
        pure.out(),
        pure.err()
    );
}

/// Writes `content` to `dir/rel`, creating parent directories.
pub fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, content).unwrap();
}

/// Marks a file executable (no-op where the platform has no exec bit).
pub fn set_exec(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Recursively copies a directory tree (files keep their permissions).
pub fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir(&entry.path(), &to);
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}
