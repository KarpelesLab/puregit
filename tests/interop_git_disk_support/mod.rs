//! Hermetic helpers for the on-disk interop tests against the real `git` CLI.
//!
//! Shared (via `#[path]`) by `tests/interop_git_disk*.rs` only. Every `git`
//! invocation runs with the user's and the system's configuration masked
//! (`GIT_CONFIG_NOSYSTEM`, a private empty `GIT_CONFIG_GLOBAL`, `HOME` inside
//! the scratch directory), fixed identities, a deterministic clock, and the
//! `-c` overrides that make the on-disk output reproducible on every platform.
//!
//! When `git` is not on `PATH` the tests print a skip notice and pass, unless
//! `PUREGIT_REQUIRE_GIT=1` is set (CI), in which case they fail loudly.

#![allow(dead_code)]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use puregit::object::ObjectType;
use puregit::{HashAlgo, ObjectId};

/// Returns early from the calling test when `git` is unavailable (see
/// [`git_available`]).
#[macro_export]
macro_rules! require_git {
    () => {
        if !support::git_available() {
            return;
        }
    };
}

/// Whether the real `git` binary is runnable. Prints a skip notice when it is
/// not — or panics if `PUREGIT_REQUIRE_GIT=1` demands it.
pub fn git_available() -> bool {
    let ok = Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        if std::env::var("PUREGIT_REQUIRE_GIT").as_deref() == Ok("1") {
            panic!("`git` is not on PATH but PUREGIT_REQUIRE_GIT=1 requires it");
        }
        eprintln!("skipping: `git` not found on PATH (set PUREGIT_REQUIRE_GIT=1 to fail instead)");
    }
    ok
}

/// A unique scratch directory, removed (recursively) on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "puregit-interop-{tag}-{}-{n}-{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        // Canonicalize so paths compare equal to what git reports (macOS
        // `/var` → `/private/var`). Not on Windows, where it yields a
        // verbatim `\\?\C:\…` path that git does not accept everywhere.
        if cfg!(unix) {
            TempDir(std::fs::canonicalize(&dir).unwrap_or(dir))
        } else {
            TempDir(dir)
        }
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if std::fs::remove_dir_all(&self.0).is_err() {
            // git marks pack/idx and loose objects read-only; Windows refuses
            // to delete read-only files, so clear the bit and retry.
            make_writable(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn make_writable(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            make_writable(&p);
        } else if let Ok(md) = std::fs::metadata(&p) {
            let mut perm = md.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            let _ = std::fs::set_permissions(&p, perm);
        }
    }
}

/// Configuration forced onto every `git` invocation.
const CONFIG: &[&str] = &[
    "core.autocrlf=false",
    "core.eol=lf",
    "core.safecrlf=false",
    "core.fsmonitor=false",
    "core.quotepath=false",
    "init.defaultBranch=main",
    "commit.gpgsign=false",
    "tag.gpgsign=false",
    "gc.auto=0",
    "maintenance.auto=false",
    "safe.directory=*",
    "advice.detachedHead=false",
    "merge.renames=false",
    "diff.renames=false",
    "status.renames=false",
];

/// Base epoch for the deterministic clock (2023-11-14).
pub const EPOCH: i64 = 1_700_000_000;

/// A hermetic `git` runner with a deterministic, advancing clock.
pub struct Git {
    home: PathBuf,
    global: PathBuf,
    now: Cell<i64>,
}

impl Git {
    /// A runner whose `HOME` and global config live under `scratch`.
    pub fn new(scratch: &TempDir) -> Git {
        let home = scratch.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let global = home.join("gitconfig");
        std::fs::write(&global, b"").unwrap();
        Git {
            home,
            global,
            now: Cell::new(EPOCH),
        }
    }

    /// The current clock value (seconds), used for author/committer dates.
    pub fn now(&self) -> i64 {
        self.now.get()
    }

    /// Advances the clock by one minute and returns the new time.
    pub fn tick(&self) -> i64 {
        self.now.set(self.now.get() + 60);
        self.now.get()
    }

    fn command(&self, cwd: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(cwd);
        for var in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
            "GIT_NAMESPACE",
            "GIT_CEILING_DIRECTORIES",
            "GIT_CONFIG",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
            "GIT_DEFAULT_HASH",
            "GIT_TRACE",
            "XDG_CONFIG_HOME",
        ] {
            cmd.env_remove(var);
        }
        let date = format!("{} +0000", self.now.get());
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.global)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("GIT_AUTHOR_NAME", "A U Thor")
            .env("GIT_AUTHOR_EMAIL", "author@example.com")
            .env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_NAME", "C O Mitter")
            .env("GIT_COMMITTER_EMAIL", "committer@example.com")
            .env("GIT_COMMITTER_DATE", &date)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_PAGER", "cat")
            .env("PAGER", "cat")
            .env("GIT_EDITOR", "true")
            .env("LC_ALL", "C")
            .env("LANG", "C");
        for c in CONFIG {
            cmd.arg("-c").arg(c);
        }
        if !symlinks_supported() {
            // Where no symlink can be created, git keeps a 120000 entry whose
            // work-tree file holds the target (as Git for Windows does).
            cmd.arg("-c").arg("core.symlinks=false");
        }
        cmd.args(args);
        cmd
    }

    /// Runs `git args…` in `cwd`, returning the raw output (any exit status).
    pub fn output(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command(cwd, args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn git")
    }

    /// Runs `git args…` in `cwd`, panicking (with stderr) on failure; returns
    /// stdout.
    pub fn run(&self, cwd: &Path, args: &[&str]) -> Vec<u8> {
        let out = self.output(cwd, args);
        assert!(
            out.status.success(),
            "git {args:?} failed in {}: {}\n{}",
            cwd.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    /// [`run`](Self::run), returning stdout as a string (lossy).
    pub fn run_str(&self, cwd: &Path, args: &[&str]) -> String {
        String::from_utf8_lossy(&self.run(cwd, args)).into_owned()
    }

    /// [`run_str`](Self::run_str), trimmed of surrounding whitespace.
    pub fn line(&self, cwd: &Path, args: &[&str]) -> String {
        self.run_str(cwd, args).trim().to_string()
    }

    /// Runs `git args…` feeding `input` on stdin; panics on failure.
    pub fn run_stdin(&self, cwd: &Path, args: &[&str], input: &[u8]) -> Vec<u8> {
        let mut child = self
            .command(cwd, args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn git");
        {
            let mut stdin = child.stdin.take().unwrap();
            // A writer thread avoids a pipe deadlock on large inputs.
            let input = input.to_vec();
            let h = std::thread::spawn(move || {
                let _ = stdin.write_all(&input);
            });
            let out = child.wait_with_output().expect("wait git");
            let _ = h.join();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
            out.stdout
        }
    }

    /// `git init` (non-bare) with the given object format.
    pub fn init(&self, dir: &Path, algo: HashAlgo) {
        std::fs::create_dir_all(dir).unwrap();
        let fmt = format!("--object-format={}", algo.name());
        self.run(dir, &["init", "-q", &fmt]);
    }

    /// Stages everything and commits with `msg` at the next clock tick;
    /// returns the new commit id (hex).
    pub fn commit_all(&self, dir: &Path, msg: &str) -> String {
        self.tick();
        self.run(dir, &["add", "-A"]);
        self.run(dir, &["commit", "-q", "--allow-empty", "-m", msg]);
        self.line(dir, &["rev-parse", "HEAD"])
    }

    /// Commits whatever is staged (no `add`).
    pub fn commit_staged(&self, dir: &Path, msg: &str) -> String {
        self.tick();
        self.run(dir, &["commit", "-q", "--allow-empty", "-m", msg]);
        self.line(dir, &["rev-parse", "HEAD"])
    }

    /// `git rev-parse <rev>` as an [`ObjectId`].
    pub fn rev_parse(&self, dir: &Path, algo: HashAlgo, rev: &str) -> ObjectId {
        oid(algo, &self.line(dir, &["rev-parse", "--verify", rev]))
    }

    /// Writes `content` as a blob with `git hash-object -w`, returning its id.
    pub fn hash_object_w(&self, dir: &Path, content: &[u8]) -> String {
        String::from_utf8(self.run_stdin(dir, &["hash-object", "-w", "--stdin"], content))
            .unwrap()
            .trim()
            .to_string()
    }

    /// Every object in the repository, via `git cat-file --batch-all-objects
    /// --batch`: hex id → (type, content).
    pub fn all_objects(&self, dir: &Path) -> BTreeMap<String, (ObjectType, Vec<u8>)> {
        let out = self.run(dir, &["cat-file", "--batch-all-objects", "--batch"]);
        parse_batch(&out)
    }

    /// The `(type, content)` of the given objects via `git cat-file --batch`.
    pub fn cat_batch(&self, dir: &Path, ids: &[String]) -> BTreeMap<String, (ObjectType, Vec<u8>)> {
        let mut input = String::new();
        for id in ids {
            input.push_str(id);
            input.push('\n');
        }
        parse_batch(&self.run_stdin(dir, &["cat-file", "--batch"], input.as_bytes()))
    }

    /// The set of objects `git rev-list --objects --all` reports.
    pub fn rev_list_objects_all(&self, dir: &Path) -> BTreeSet<String> {
        self.run_str(dir, &["rev-list", "--objects", "--all"])
            .lines()
            .map(|l| l.split(' ').next().unwrap().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Asserts `git fsck --strict --full` is clean: success and no
    /// diagnostics at all (no warnings, no dangling notes).
    pub fn assert_fsck_clean(&self, dir: &Path) {
        let out = self.output(
            dir,
            &[
                "fsck",
                "--strict",
                "--full",
                "--no-dangling",
                "--no-progress",
            ],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.trim().is_empty() && stderr.trim().is_empty(),
            "git fsck --strict --full is not clean in {}:\nstatus: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            dir.display(),
            out.status
        );
    }
}

/// Parses `git cat-file --batch` output.
pub fn parse_batch(mut out: &[u8]) -> BTreeMap<String, (ObjectType, Vec<u8>)> {
    let mut map = BTreeMap::new();
    while !out.is_empty() {
        let nl = out.iter().position(|&b| b == b'\n').expect("batch header");
        let header = std::str::from_utf8(&out[..nl]).unwrap();
        let mut parts = header.split(' ');
        let id = parts.next().unwrap().to_string();
        let ty = parts.next().unwrap();
        assert_ne!(ty, "missing", "cat-file reports {id} missing");
        let size: usize = parts.next().unwrap().parse().unwrap();
        let content = out[nl + 1..nl + 1 + size].to_vec();
        assert_eq!(out[nl + 1 + size], b'\n');
        out = &out[nl + 2 + size..];
        map.insert(id, (ObjectType::from_str(ty).unwrap(), content));
    }
    map
}

/// Parses a hex id under `algo`, panicking on malformed input.
pub fn oid(algo: HashAlgo, hex: &str) -> ObjectId {
    ObjectId::from_hex(algo, hex.trim()).unwrap_or_else(|e| panic!("bad oid {hex:?}: {e:?}"))
}

/// Writes a file (creating parent directories).
pub fn write(path: &Path, content: &[u8]) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// Deterministic pseudo-random bytes (xorshift), for incompressible blobs.
pub fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    seed |= 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// A compressible, delta-friendly text body: `lines` numbered lines.
pub fn text_body(lines: usize, tag: &str) -> Vec<u8> {
    let mut s = String::new();
    for i in 0..lines {
        s.push_str(&format!(
            "{tag} line {i:05}: the quick brown fox jumps over the lazy dog\n"
        ));
    }
    s.into_bytes()
}

/// Whether symbolic links can be created in the working tree on this host.
pub fn symlinks_supported() -> bool {
    cfg!(unix)
}

/// Creates a working-tree symlink `link` → `target` (Unix only).
#[cfg(unix)]
pub fn make_symlink(target: &str, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(not(unix))]
pub fn make_symlink(_target: &str, _link: &Path) {
    unreachable!("symlinks are only created on Unix");
}

/// Puts the work-tree counterpart of a 120000 entry at `link`: a real symlink
/// where supported, else a plain file holding `target` — what git checks out
/// with `core.symlinks=false`.
pub fn place_link(target: &str, link: &Path) {
    if symlinks_supported() {
        make_symlink(target, link);
    } else {
        write(link, target.as_bytes());
    }
}

/// Sets or clears the executable bit on a working-tree file (Unix only; a
/// no-op elsewhere).
pub fn set_exec(path: &Path, exec: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        let mode = perm.mode();
        perm.set_mode(if exec { mode | 0o111 } else { mode & !0o111 });
        std::fs::set_permissions(path, perm).unwrap();
    }
    #[cfg(not(unix))]
    {
        let _ = (path, exec);
    }
}

/// Splits NUL-terminated output into its records (dropping the final empty).
pub fn split_nul(out: &[u8]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = out.split(|&b| b == 0).map(|s| s.to_vec()).collect();
    if v.last().is_some_and(|l| l.is_empty()) {
        v.pop();
    }
    v
}

/// The algorithms every format-sensitive test is run under.
pub const ALGOS: [HashAlgo; 2] = [HashAlgo::Sha1, HashAlgo::Sha256];
