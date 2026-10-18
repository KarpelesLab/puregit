//! Shared helpers for the `interop_git_protocol*` wire-protocol interop tests.
//!
//! Included by path from `tests/interop_git_protocol_server.rs` and
//! `tests/interop_git_protocol_client.rs` (it lives in a subdirectory so cargo
//! does not compile it as a test target of its own). Std only.
//!
//! Everything here is hermetic: git runs with no system/global config, `HOME`
//! inside a per-test temp dir, fixed identities and dates, and only loopback
//! sockets. Every spawned process and server thread is killed/joined on drop,
//! and every socket and child wait is bounded by a timeout so a protocol hang
//! fails the test in seconds instead of wedging CI.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long any single git command may run before it is killed.
pub const CMD_TIMEOUT: Duration = Duration::from_secs(60);
/// Socket read/write timeout for the in-test servers and stream transports.
pub const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// Base timestamp for generated commits (2023-11-14).
pub const BASE_TIME: i64 = 1_700_000_000;
/// Seconds between successive generated commits (one day).
pub const DAY: i64 = 86_400;

// ---------------------------------------------------------------------------
// git availability
// ---------------------------------------------------------------------------

/// Whether a usable `git` is on `PATH`. When it is not, prints a skip message
/// and returns `false` — unless `PUREGIT_REQUIRE_GIT=1`, in which case it
/// panics so CI cannot silently skip the suite.
pub fn git_available() -> bool {
    let ok = Command::new("git")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        if std::env::var("PUREGIT_REQUIRE_GIT").as_deref() == Ok("1") {
            panic!("`git` is not on PATH but PUREGIT_REQUIRE_GIT=1");
        }
        eprintln!("SKIP: `git` is not on PATH; skipping wire-protocol interop test");
    }
    ok
}

/// Returns early from the calling test when git is unavailable.
macro_rules! require_git {
    () => {
        if !support::git_available() {
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// temp dirs
// ---------------------------------------------------------------------------

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A uniquely-named temp directory, removed (recursively) on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    /// Creates a fresh directory under the system temp dir.
    pub fn new(tag: &str) -> TempDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "pg-proto-{tag}-{}-{n}-{nanos:x}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Windows may briefly hold handles of just-exited children; retry.
        for _ in 0..20 {
            if std::fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

// ---------------------------------------------------------------------------
// processes with timeouts
// ---------------------------------------------------------------------------

/// Runs `cmd` to completion (stdin closed, stdout/stderr captured), killing it
/// and panicking if it outlives `timeout`.
pub fn run_with_timeout(mut cmd: Command, timeout: Duration, what: &str) -> Output {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let t_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let status = wait_with_deadline(&mut child, timeout)
        .unwrap_or_else(|| panic!("TIMEOUT after {timeout:?}: {what}"));
    Output {
        status,
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
    }
}

/// Waits for `child`, killing it after `timeout` (returning `None` then).
pub fn wait_with_deadline(
    child: &mut Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ---------------------------------------------------------------------------
// hermetic git environment
// ---------------------------------------------------------------------------

/// Server-side git configuration applied to every git process through
/// `GIT_CONFIG_COUNT` (so it reaches `upload-pack`/`receive-pack` children of
/// `git daemon` and `git http-backend` as well).
const SERVER_CONFIG: &[(&str, &str)] = &[
    ("uploadpack.allowFilter", "true"),
    ("uploadpack.allowAnySHA1InWant", "true"),
    ("http.receivepack", "true"),
    ("receive.denyCurrentBranch", "ignore"),
    ("core.autocrlf", "false"),
    ("init.defaultBranch", "main"),
    ("commit.gpgsign", "false"),
    ("tag.gpgsign", "false"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("fetch.writeCommitGraph", "false"),
    ("protocol.allow", "always"),
    ("advice.detachedHead", "false"),
    ("safe.directory", "*"),
];

/// A hermetic git environment rooted in its own temp dir.
pub struct GitEnv {
    root: TempDir,
    home: PathBuf,
    global_config: PathBuf,
}

impl GitEnv {
    /// Creates a new environment (temp root, empty `HOME`, empty global
    /// config).
    pub fn new(tag: &str) -> GitEnv {
        let root = TempDir::new(tag);
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let global_config = home.join("gitconfig");
        std::fs::write(&global_config, b"").unwrap();
        GitEnv {
            root,
            home,
            global_config,
        }
    }

    /// The temp root; repositories are created beneath it.
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// A path under the root.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    /// Applies the hermetic environment to `cmd`.
    pub fn apply(&self, cmd: &mut Command) {
        for var in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
            "GIT_PROTOCOL",
            "GIT_TRACE",
            "GIT_TRACE_PACKET",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_EXEC_PATH",
            "GIT_TEMPLATE_DIR",
            "GIT_CEILING_DIRECTORIES",
            "GIT_CONFIG",
            "GIT_CONFIG_PARAMETERS",
            "GIT_DEFAULT_HASH",
            "GIT_PROXY_COMMAND",
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "all_proxy",
        ] {
            cmd.env_remove(var);
        }
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "Interop Tester")
            .env("GIT_AUTHOR_EMAIL", "tester@example.com")
            .env("GIT_COMMITTER_NAME", "Interop Tester")
            .env("GIT_COMMITTER_EMAIL", "tester@example.com")
            .env("GIT_AUTHOR_DATE", format!("{BASE_TIME} +0000"))
            .env("GIT_COMMITTER_DATE", format!("{BASE_TIME} +0000"))
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("NO_PROXY", "*")
            .env("no_proxy", "*")
            .env("GIT_CONFIG_COUNT", SERVER_CONFIG.len().to_string());
        for (i, (k, v)) in SERVER_CONFIG.iter().enumerate() {
            cmd.env(format!("GIT_CONFIG_KEY_{i}"), k)
                .env(format!("GIT_CONFIG_VALUE_{i}"), v);
        }
    }

    /// A `git` command in `cwd` with the hermetic environment applied.
    pub fn cmd(&self, cwd: &Path) -> Command {
        let mut cmd = Command::new("git");
        self.apply(&mut cmd);
        cmd.current_dir(cwd);
        cmd.args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "gc.auto=0",
        ]);
        cmd
    }

    /// Runs `git <args>` in `cwd`, returning the raw output (any status).
    pub fn try_git(&self, cwd: &Path, args: &[&str]) -> Output {
        self.try_git_env(cwd, args, &[])
    }

    /// Like [`try_git`](Self::try_git) with extra environment variables.
    pub fn try_git_env(&self, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = self.cmd(cwd);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        run_with_timeout(cmd, CMD_TIMEOUT, &format!("git {}", args.join(" ")))
    }

    /// Runs `git <args>` in `cwd`, panicking (with stderr) on failure;
    /// returns stdout with trailing whitespace trimmed.
    pub fn git(&self, cwd: &Path, args: &[&str]) -> String {
        self.git_env(cwd, args, &[])
    }

    /// Like [`git`](Self::git) with extra environment variables.
    pub fn git_env(&self, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
        let out = self.try_git_env(cwd, args, env);
        if !out.status.success() {
            panic!(
                "git {} (in {}) failed: {}\nstdout:\n{}\nstderr:\n{}",
                args.join(" "),
                cwd.display(),
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        String::from_utf8_lossy(&out.stdout).trim_end().to_string()
    }

    /// Commits whatever is staged in work tree `dir` with a deterministic
    /// date `BASE_TIME + n * DAY`, returning the new commit id.
    pub fn commit_at(&self, dir: &Path, msg: &str, n: i64) -> String {
        let date = format!("{} +0000", BASE_TIME + n * DAY);
        self.git_env(
            dir,
            &["commit", "-q", "--allow-empty", "-m", msg],
            &[("GIT_AUTHOR_DATE", &date), ("GIT_COMMITTER_DATE", &date)],
        );
        self.git(dir, &["rev-parse", "HEAD"])
    }

    /// Writes `content` to `rel` in work tree `dir` (creating parent dirs) and
    /// stages it.
    pub fn write_and_add(&self, dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content.as_bytes()).unwrap();
        self.git(dir, &["add", "--", rel]);
    }

    /// `git for-each-ref` (`<oid> <refname>` per line, sorted by refname) of
    /// the repository at `git_dir`, optionally limited to `pattern`.
    pub fn refs(&self, repo: &Path, pattern: Option<&str>) -> BTreeMap<String, String> {
        let mut args = vec!["for-each-ref", "--format=%(refname) %(objectname)"];
        if let Some(p) = pattern {
            args.push(p);
        }
        parse_ref_lines(&self.git(repo, &args))
    }

    /// `git rev-parse <rev>` in `repo`.
    pub fn rev_parse(&self, repo: &Path, rev: &str) -> String {
        self.git(repo, &["rev-parse", "--verify", "-q", rev])
    }

    /// Runs `git fsck --strict` on `repo`, panicking with its output unless it
    /// is clean (exit 0 and no `error`/`missing`/`broken` lines).
    pub fn fsck(&self, repo: &Path, what: &str) {
        let out = self.try_git(
            repo,
            &["fsck", "--strict", "--no-progress", "--no-dangling"],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let dirty = stdout
            .lines()
            .chain(stderr.lines())
            .any(|l| l.contains("error") || l.starts_with("missing") || l.contains("broken"));
        assert!(
            out.status.success() && !dirty,
            "git fsck --strict failed for {what} ({}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
            repo.display()
        );
    }

    /// Whether this git can create SHA-256 repositories.
    pub fn supports_sha256(&self) -> bool {
        let probe = self.path(&format!(
            "sha256-probe-{}",
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let out = self.try_git(
            self.root(),
            &[
                "init",
                "-q",
                "--bare",
                "--object-format=sha256",
                probe.to_str().unwrap(),
            ],
        );
        let _ = std::fs::remove_dir_all(&probe);
        out.status.success()
    }

    /// `git ls-remote <url>` with `protocol.version=<v>`, parsed to
    /// `name → oid`.
    pub fn ls_remote(&self, url: &str, version: u8) -> BTreeMap<String, String> {
        let pv = format!("protocol.version={version}");
        let out = self.git(self.root(), &["-c", &pv, "ls-remote", url]);
        let mut map = BTreeMap::new();
        for line in out.lines() {
            if let Some((oid, name)) = line.split_once('\t') {
                map.insert(name.to_string(), oid.to_string());
            }
        }
        map
    }
}

/// Parses `refname oid` lines into a map.
pub fn parse_ref_lines(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if let Some((name, oid)) = line.split_once(' ') {
            map.insert(name.to_string(), oid.to_string());
        }
    }
    map
}

/// The object format names exercised: always SHA-1, plus SHA-256 when git
/// supports it.
pub fn algos(env: &GitEnv) -> Vec<&'static str> {
    if env.supports_sha256() {
        vec!["sha1", "sha256"]
    } else {
        eprintln!("NOTE: this git cannot create SHA-256 repositories; SHA-1 only");
        vec!["sha1"]
    }
}

// ---------------------------------------------------------------------------
// fixture repositories
// ---------------------------------------------------------------------------

/// A bare "server" repository.
pub struct Fixture {
    /// The bare repository the server side serves.
    pub bare: PathBuf,
    /// Number of commits authored so far on `main` (for dates).
    pub commits: i64,
}

/// Appends one fast-import `data` block.
fn fi_data(out: &mut String, text: &str) {
    out.push_str(&format!("data {}\n{text}\n", text.len()));
}

/// Appends a fast-import commit of `files` to `refname`, dated
/// `BASE_TIME + day * DAY`, optionally starting from `from`.
fn fi_commit(
    out: &mut String,
    refname: &str,
    mark: Option<i64>,
    day: i64,
    msg: &str,
    from: Option<&str>,
    files: &[(String, String)],
) {
    let when = BASE_TIME + day * DAY;
    out.push_str(&format!("commit {refname}\n"));
    if let Some(m) = mark {
        out.push_str(&format!("mark :{m}\n"));
    }
    out.push_str(&format!(
        "author Interop Tester <tester@example.com> {when} +0000\n\
         committer Interop Tester <tester@example.com> {when} +0000\n"
    ));
    fi_data(out, msg);
    if let Some(f) = from {
        out.push_str(&format!("from {f}\n"));
    }
    for (path, content) in files {
        out.push_str(&format!("M 100644 inline {path}\n"));
        fi_data(out, content);
    }
    out.push('\n');
}

/// The files commit `i` of a fixture touches: a modified README, a new
/// nested file, and a big file that deltas well.
fn fixture_files(i: i64) -> Vec<(String, String)> {
    let mut big = String::new();
    for line in 0..200 {
        big.push_str(&format!("line {line} of the shared big file\n"));
    }
    big.push_str(&format!("tail {i}\n"));
    vec![
        ("README.md".into(), format!("readme revision {i}\n")),
        (
            format!("src/dir{}/file{i}.txt", i % 4),
            format!("file {i}\n{}\n", "x".repeat((i as usize) * 7)),
        ),
        ("docs/big.txt".into(), big),
    ]
}

/// Feeds a fast-import stream to the repository at `dir` — one process for a
/// whole history, which keeps fixture setup fast where process spawns are
/// slow (Windows).
pub fn fast_import(env: &GitEnv, dir: &Path, stream: &str) {
    let mut cmd = env.cmd(dir);
    cmd.args(["fast-import", "--quiet", "--done"]);
    let mut input = stream.to_string();
    input.push_str("done\n");
    let out = run_with_input(cmd, input.as_bytes(), CMD_TIMEOUT, "git fast-import");
    assert!(
        out.status.success(),
        "git fast-import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Creates `<root>/<name>` (bare, `object_format`) holding `n` (≥ 3) commits
/// on `main` touching nested files, a `feature` branch, a lightweight tag
/// `v-light` and an annotated tag `v1.0`.
pub fn make_fixture(env: &GitEnv, name: &str, object_format: &str, n: i64) -> Fixture {
    assert!(n >= 3);
    let bare = env.path(name);
    let fmt = format!("--object-format={object_format}");
    env.git(
        env.root(),
        &["init", "-q", "--bare", &fmt, bare.to_str().unwrap()],
    );
    let mut s = String::new();
    for i in 1..=n {
        fi_commit(
            &mut s,
            "refs/heads/main",
            Some(i),
            i,
            &format!("commit {i}"),
            None,
            &fixture_files(i),
        );
    }
    // A side branch forked a few commits back, with its own commit.
    let fork = if n > 3 { n - 3 } else { n };
    fi_commit(
        &mut s,
        "refs/heads/feature",
        None,
        n + 1,
        "feature commit",
        Some(&format!(":{fork}")),
        &[("feature/notes.txt".into(), "feature work\n".into())],
    );
    s.push_str(&format!("reset refs/tags/v-light\nfrom :{}\n\n", n - 1));
    s.push_str(&format!(
        "tag v1.0\nfrom :{}\ntagger Interop Tester <tester@example.com> {} +0000\n",
        n - 2,
        BASE_TIME + (n + 1) * DAY
    ));
    fi_data(&mut s, "release 1.0");
    fast_import(env, &bare, &s);
    env.git(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    Fixture {
        bare,
        commits: n + 1,
    }
}

/// Adds `k` commits to the fixture's `main`; returns the new tip.
pub fn advance_main(env: &GitEnv, fx: &mut Fixture, k: usize) -> String {
    let mut s = String::new();
    for j in 0..k {
        fx.commits += 1;
        let i = fx.commits;
        let from = (j == 0).then_some("refs/heads/main^0");
        fi_commit(
            &mut s,
            "refs/heads/main",
            None,
            i,
            &format!("commit {i}"),
            from,
            &fixture_files(i),
        );
    }
    fast_import(env, &fx.bare, &s);
    env.rev_parse(&fx.bare, "refs/heads/main")
}

/// Creates `n` commits on a new branch `refname` of the repository at `dir`,
/// starting from `from` (each changes `local.txt`), without touching its work
/// tree. Dated from day `day0`.
pub fn local_commits(env: &GitEnv, dir: &Path, refname: &str, from: &str, n: i64, day0: i64) {
    let mut s = String::new();
    for i in 0..n {
        fi_commit(
            &mut s,
            refname,
            None,
            day0 + i,
            &format!("local {i}"),
            (i == 0).then_some(from),
            &[("local.txt".into(), format!("local {i}\n"))],
        );
    }
    fast_import(env, dir, &s);
}

/// Runs `cmd` with `input` on stdin (stdout/stderr captured), killing it and
/// panicking if it outlives `timeout`.
pub fn run_with_input(mut cmd: Command, input: &[u8], timeout: Duration, what: &str) -> Output {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let t_in = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let t_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let status = wait_with_deadline(&mut child, timeout)
        .unwrap_or_else(|| panic!("TIMEOUT after {timeout:?}: {what}"));
    let _ = t_in.join();
    Output {
        status,
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
    }
}
// ---------------------------------------------------------------------------
// gzip (git gzips large upload-pack POST bodies)
// ---------------------------------------------------------------------------

/// Decodes a gzip member (RFC 1952) using the raw-deflate decoder of the
/// `compcol` crate puregit already depends on.
pub fn gunzip(data: &[u8]) -> Vec<u8> {
    assert!(data.len() >= 18 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8);
    let flags = data[3];
    let mut off = 10;
    if flags & 0x04 != 0 {
        let xlen = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2 + xlen;
    }
    for bit in [0x08, 0x10] {
        if flags & bit != 0 {
            while data[off] != 0 {
                off += 1;
            }
            off += 1;
        }
    }
    if flags & 0x02 != 0 {
        off += 2;
    }
    let body = &data[off..data.len() - 8];
    let out = compcol::vec::decompress_to_vec::<compcol::deflate::Deflate>(body)
        .expect("gunzip request body");
    let isize = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
    assert_eq!(out.len() as u32, isize, "gzip ISIZE mismatch");
    out
}

// ---------------------------------------------------------------------------
// a tiny threaded HTTP/1.1 server
// ---------------------------------------------------------------------------

/// A parsed HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The verb.
    pub method: String,
    /// The path (percent-encoding left as-is), without the query.
    pub path: String,
    /// The raw query string (no `?`).
    pub query: String,
    /// Headers in arrival order.
    pub headers: Vec<(String, String)>,
    /// The de-chunked body (still content-encoded, if it was).
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An HTTP response to send.
pub struct HttpReply {
    /// Status code.
    pub status: u16,
    /// Extra headers (`Content-Length`/`Connection` are added).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

type Handler = dyn Fn(&HttpRequest) -> HttpReply + Send + Sync;

/// A loopback HTTP server running `handler` for each request on its own
/// thread; stops and joins everything on drop.
pub struct HttpServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    /// Requests served, for assertions/debugging.
    pub log: Arc<Mutex<Vec<String>>>,
}

impl HttpServer {
    /// Binds `127.0.0.1:0` and starts serving.
    pub fn start(handler: Arc<Handler>) -> HttpServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind http");
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let log = Arc::new(Mutex::new(Vec::new()));
        let (stop2, log2) = (stop.clone(), log.clone());
        let thread = std::thread::spawn(move || {
            // Each live connection's thread, plus a handle to its socket so an
            // idle keep-alive connection can be shut down when the server stops.
            let mut conns: Vec<(JoinHandle<()>, Option<TcpStream>)> = Vec::new();
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let h = handler.clone();
                        let l = log2.clone();
                        let peer = stream.try_clone().ok();
                        conns.push((
                            std::thread::spawn(move || serve_http_conn(stream, &*h, &l)),
                            peer,
                        ));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
                conns.retain(|(c, _)| !c.is_finished());
            }
            for (c, peer) in conns {
                if let Some(peer) = peer {
                    let _ = peer.shutdown(Shutdown::Both);
                }
                let _ = c.join();
            }
        });
        HttpServer {
            addr,
            stop,
            thread: Some(thread),
            log,
        }
    }

    /// `http://127.0.0.1:<port>/<path>`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}/{}", self.addr, path.trim_start_matches('/'))
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve_http_conn(stream: TcpStream, handler: &Handler, log: &Mutex<Vec<String>>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_nodelay(true);
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    // Serve requests until the peer closes (keep-alive), one at a time.
    loop {
        let req = match read_http_request(&mut reader, &mut writer) {
            Some(r) => r,
            None => return,
        };
        let reply = handler(&req);
        log.lock().unwrap().push(format!(
            "{} {}?{} -> {} (gp={:?})",
            req.method,
            req.path,
            req.query,
            reply.status,
            req.header("Git-Protocol")
        ));
        let mut head = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status));
        for (k, v) in &reply.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
        head.push_str("Connection: keep-alive\r\n\r\n");
        if writer.write_all(head.as_bytes()).is_err()
            || writer.write_all(&reply.body).is_err()
            || writer.flush().is_err()
        {
            return;
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

fn read_http_request(
    reader: &mut BufReader<TcpStream>,
    writer: &mut TcpStream,
) -> Option<HttpRequest> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).ok()? == 0 {
            return None;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut req = HttpRequest {
        method,
        path,
        query,
        headers,
        body: Vec::new(),
    };
    if req
        .header("Expect")
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    {
        writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").ok()?;
        writer.flush().ok()?;
    }
    if req
        .header("Transfer-Encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).ok()?;
            let size_hex = size_line.trim().split(';').next()?.trim().to_string();
            let size = usize::from_str_radix(&size_hex, 16).ok()?;
            if size == 0 {
                // Trailers until an empty line.
                loop {
                    let mut t = String::new();
                    reader.read_line(&mut t).ok()?;
                    if t.trim().is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk).ok()?;
            req.body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).ok()?;
        }
    } else if let Some(len) = req.header("Content-Length") {
        let len: usize = len.parse().ok()?;
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).ok()?;
        req.body = body;
    }
    Some(req)
}

// ---------------------------------------------------------------------------
// git daemon / git http-backend (real git servers)
// ---------------------------------------------------------------------------

/// Picks a free loopback port (bind `:0`, read it, release it).
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running `git daemon` serving `base_path`; killed on drop.
pub struct GitDaemon {
    child: Child,
    /// The listening port.
    pub port: u16,
}

impl GitDaemon {
    /// Starts `git daemon --export-all --enable=receive-pack` on a free
    /// loopback port. Returns `None` (with a SKIP message) if the platform's
    /// git cannot run a daemon.
    pub fn start(env: &GitEnv, base_path: &Path) -> Option<GitDaemon> {
        for _attempt in 0..2 {
            let port = free_port();
            let mut cmd = Command::new("git");
            env.apply(&mut cmd);
            cmd.current_dir(base_path)
                .arg("daemon")
                .arg("--export-all")
                .arg("--reuseaddr")
                .arg("--informative-errors")
                .arg("--enable=receive-pack")
                .arg(format!("--base-path={}", base_path.display()))
                .arg(format!("--port={port}"))
                .arg("--listen=127.0.0.1")
                .arg(base_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("SKIP: cannot spawn `git daemon`: {e}");
                    return None;
                }
            };
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(Some(status)) = child.try_wait() {
                    eprintln!("note: `git daemon` exited early ({status}); retrying");
                    break;
                }
                if TcpStream::connect_timeout(
                    &SocketAddr::from(([127, 0, 0, 1], port)),
                    Duration::from_millis(200),
                )
                .is_ok()
                {
                    return Some(GitDaemon { child, port });
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        eprintln!("SKIP: `git daemon` is unavailable on this platform");
        None
    }

    /// `git://127.0.0.1:<port>/<name>`.
    pub fn url(&self, name: &str) -> String {
        format!("git://127.0.0.1:{}/{}", self.port, name)
    }
}

impl Drop for GitDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How the `git http-backend` shim treats the client's `Git-Protocol` header.
#[derive(Clone, Debug)]
pub enum ProtocolOverride {
    /// Forward whatever the client sent.
    PassThrough,
    /// Replace it (an empty string drops it, forcing v0).
    Force(String),
}

/// `git http-backend` behind a minimal HTTP→CGI shim.
pub struct GitHttpBackend {
    server: HttpServer,
}

impl GitHttpBackend {
    /// Whether `git http-backend` runs here at all.
    pub fn available(env: &GitEnv) -> bool {
        // Probed once per test binary: spawning is slow on Windows.
        static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *AVAILABLE.get_or_init(|| Self::probe(env))
    }

    fn probe(env: &GitEnv) -> bool {
        let mut cmd = Command::new("git");
        env.apply(&mut cmd);
        cmd.arg("http-backend")
            .env("REQUEST_METHOD", "GET")
            .env("PATH_INFO", "/nonexistent/info/refs")
            .env("QUERY_STRING", "")
            .env("GIT_PROJECT_ROOT", env.root());
        let out = run_with_timeout(cmd, Duration::from_secs(30), "git http-backend probe");
        let ok = String::from_utf8_lossy(&out.stdout).contains("Status:")
            || String::from_utf8_lossy(&out.stdout).contains("Content-Type");
        if !ok {
            eprintln!(
                "SKIP: `git http-backend` is unavailable: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        ok
    }

    /// Serves every repository under `project_root`.
    pub fn start(env: &GitEnv, project_root: &Path, proto: ProtocolOverride) -> GitHttpBackend {
        // Capture the hermetic environment once, as (key, value) pairs.
        let mut template = Command::new("git");
        env.apply(&mut template);
        let envs: Vec<(String, Option<String>)> = template
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let root = project_root.to_path_buf();
        let handler = move |req: &HttpRequest| -> HttpReply {
            let mut cmd = Command::new("git");
            for (k, v) in &envs {
                match v {
                    Some(v) => cmd.env(k, v),
                    None => cmd.env_remove(k),
                };
            }
            cmd.arg("http-backend")
                .env("GIT_PROJECT_ROOT", &root)
                .env("GIT_HTTP_EXPORT_ALL", "1")
                .env("REQUEST_METHOD", &req.method)
                .env("PATH_INFO", &req.path)
                .env("QUERY_STRING", &req.query)
                .env("CONTENT_LENGTH", req.body.len().to_string())
                .env("REMOTE_USER", "tester")
                .env("REMOTE_ADDR", "127.0.0.1")
                .env("SERVER_PROTOCOL", "HTTP/1.1")
                .env("GATEWAY_INTERFACE", "CGI/1.1")
                .env_remove("HTTP_GIT_PROTOCOL")
                .env_remove("HTTP_CONTENT_ENCODING");
            if let Some(ct) = req.header("Content-Type") {
                cmd.env("CONTENT_TYPE", ct);
            }
            if let Some(ce) = req.header("Content-Encoding") {
                cmd.env("HTTP_CONTENT_ENCODING", ce);
            }
            let gp = match &proto {
                ProtocolOverride::PassThrough => req.header("Git-Protocol").map(str::to_string),
                ProtocolOverride::Force(v) if v.is_empty() => None,
                ProtocolOverride::Force(v) => Some(v.clone()),
            };
            if let Some(gp) = gp {
                cmd.env("HTTP_GIT_PROTOCOL", gp);
            }
            run_cgi(cmd, &req.body)
        };
        GitHttpBackend {
            server: HttpServer::start(Arc::new(handler)),
        }
    }

    /// `http://127.0.0.1:<port>/<name>`.
    pub fn url(&self, name: &str) -> String {
        self.server.url(name)
    }

    /// The request log.
    pub fn log(&self) -> Vec<String> {
        self.server.log.lock().unwrap().clone()
    }
}

/// Runs one CGI request: pipes `body` to stdin, parses the CGI header block
/// from stdout (translating `Status:`), and returns the reply.
fn run_cgi(mut cmd: Command, body: &[u8]) -> HttpReply {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return HttpReply {
                status: 500,
                headers: vec![],
                body: format!("spawn http-backend: {e}").into_bytes(),
            };
        }
    };
    let mut stdin = child.stdin.take().unwrap();
    let body = body.to_vec();
    let t_in = std::thread::spawn(move || {
        let _ = stdin.write_all(&body);
    });
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let t_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let status = wait_with_deadline(&mut child, CMD_TIMEOUT);
    let _ = t_in.join();
    let raw = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    if status.is_none() {
        return HttpReply {
            status: 500,
            headers: vec![],
            body: b"http-backend timed out".to_vec(),
        };
    }
    if !stderr.is_empty() {
        eprintln!("http-backend stderr: {}", String::from_utf8_lossy(&stderr));
    }
    // Split the CGI header block from the body.
    let (head_end, sep) = match find(&raw, b"\r\n\r\n") {
        Some(i) => (i, 4),
        None => match find(&raw, b"\n\n") {
            Some(i) => (i, 2),
            None => (raw.len(), 0),
        },
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut reply = HttpReply {
        status: 200,
        headers: vec![],
        body: raw[(head_end + sep).min(raw.len())..].to_vec(),
    };
    for line in head.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("Status") {
            reply.status = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(500);
        } else if !k.eq_ignore_ascii_case("Content-Length") {
            reply.headers.push((k.to_string(), v.to_string()));
        }
    }
    reply
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// pkt-line helpers for raw stream transports
// ---------------------------------------------------------------------------

/// Encodes one pkt-line data packet.
pub fn pkt(data: &[u8]) -> Vec<u8> {
    let mut v = format!("{:04x}", data.len() + 4).into_bytes();
    v.extend_from_slice(data);
    v
}

/// Reads one raw pkt-line (length prefix included) from `r`.
pub fn read_raw_pkt<R: Read + ?Sized>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = usize::from_str_radix(std::str::from_utf8(&len).unwrap_or("zz"), 16)
        .map_err(|_| std::io::Error::other("bad pkt-line length"))?;
    let mut raw = len.to_vec();
    if n > 4 {
        let mut body = vec![0u8; n - 4];
        r.read_exact(&mut body)?;
        raw.extend_from_slice(&body);
    }
    Ok(raw)
}

/// Reads raw pkt-lines up to and including the first flush (`0000`).
pub fn read_until_flush<R: Read + ?Sized>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let raw = read_raw_pkt(r)?;
        let flush = raw == b"0000";
        out.extend_from_slice(&raw);
        if flush {
            return Ok(out);
        }
    }
}

/// A `file://` URL for a local path (forces git's pack transport rather than
/// the local-clone shortcut), correct on Windows drive paths too.
pub fn file_url(p: &Path) -> String {
    let s = p.display().to_string().replace('\\', "/");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

/// Half-closes the write side of a TCP stream (best effort).
pub fn shutdown_write(s: &TcpStream) {
    let _ = s.shutdown(Shutdown::Write);
}
