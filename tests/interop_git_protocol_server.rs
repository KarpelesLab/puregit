//! Wire-protocol interop: **puregit server ↔ real `git` client**.
//!
//! puregit's `git://` daemon handler and its smart-HTTP handler are served on
//! loopback ephemeral ports from in-process threads, and the real `git` CLI
//! drives clone / fetch / ls-remote / push / shallow / partial clone against
//! them with `protocol.version` 0, 1 and 2, for SHA-1 and SHA-256 repositories.
//! Every result is checked with `git fsck --strict` and by comparing refs and
//! object ids between both sides (and, for shallow clones, against the same
//! operation served by git itself over `file://`).
//!
//! Skips (with a message) when `git` is not on `PATH`, unless
//! `PUREGIT_REQUIRE_GIT=1`.

#![cfg(feature = "server")]

#[macro_use]
#[path = "interop_git_protocol/support.rs"]
mod support;

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use puregit::Repository;
use puregit::server::http::{ServerConfig, handle_http_with_version};
use puregit::transport::Service;

use support::*;

const VERSIONS: [u8; 3] = [0, 1, 2];

// ---------------------------------------------------------------------------
// puregit servers
// ---------------------------------------------------------------------------

/// Opens the repository a request path names (`/<name>/…`) under `root`.
fn open_under(root: &Path, request_path: &str) -> Option<Repository> {
    let name = request_path.trim_start_matches('/').split('/').next()?;
    if name.is_empty() || name.contains("..") {
        return None;
    }
    let dir = root.join(name);
    if !dir.is_dir() {
        return None;
    }
    Repository::open(&dir).ok()
}

/// puregit's smart-HTTP handler behind the in-test HTTP server.
struct PuregitHttp {
    server: HttpServer,
}

impl PuregitHttp {
    fn start(root: &Path) -> PuregitHttp {
        let root = root.to_path_buf();
        let handler = move |req: &HttpRequest| -> HttpReply {
            let Some(repo) = open_under(&root, &req.path) else {
                return HttpReply {
                    status: 404,
                    headers: vec![],
                    body: b"no such repository".to_vec(),
                };
            };
            let body = if req
                .header("Content-Encoding")
                .is_some_and(|v| v.eq_ignore_ascii_case("gzip"))
            {
                gunzip(&req.body)
            } else {
                req.body.clone()
            };
            let resp = handle_http_with_version(
                &repo,
                &ServerConfig::default(),
                &req.method,
                &req.path,
                &req.query,
                &body,
                req.header("Git-Protocol").unwrap_or(""),
            );
            HttpReply {
                status: resp.status,
                headers: vec![
                    ("Content-Type".into(), resp.content_type),
                    ("Cache-Control".into(), "no-cache".into()),
                ],
                body: resp.body,
            }
        };
        PuregitHttp {
            server: HttpServer::start(Arc::new(handler)),
        }
    }

    fn url(&self, name: &str) -> String {
        self.server.url(name)
    }
}

/// A stream that replays an already-consumed prefix before reading on.
struct Replay<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: std::io::Read> std::io::Read for Replay<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = buf.len().min(self.prefix.len() - self.pos);
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl<S: std::io::Write> std::io::Write for Replay<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// puregit's `git://` daemon handler on a loopback port.
///
/// `git-upload-pack` requests go to `server::daemon::serve_upload_pack`.
/// puregit's `Daemon` deliberately refuses `git-receive-pack` (anonymous
/// `git://` push), so pushes are served by composing the daemon request parser
/// with `server::serve_ssh_receive_pack` — the same stream-level receive-pack
/// handler, minus the SSH channel.
struct PuregitDaemon {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PuregitDaemon {
    fn start(root: &Path) -> PuregitDaemon {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let root = root.to_path_buf();
        let thread = std::thread::spawn(move || {
            let mut conns: Vec<JoinHandle<()>> = Vec::new();
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let root = root.clone();
                        conns.push(std::thread::spawn(move || serve_daemon_conn(stream, &root)));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
                conns.retain(|c| !c.is_finished());
            }
            for c in conns {
                let _ = c.join();
            }
        });
        PuregitDaemon {
            addr,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self, name: &str) -> String {
        format!("git://{}/{}", self.addr, name)
    }
}

impl Drop for PuregitDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve_daemon_conn(mut stream: TcpStream, root: &Path) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let Ok(first) = read_raw_pkt(&mut stream) else {
        return;
    };
    let Ok(req) = puregit::server::daemon::parse_request(&first[4..]) else {
        return;
    };
    let resolve = |p: &str| open_under(root, p);
    let result = match req.service {
        Service::UploadPack => puregit::server::daemon::serve_upload_pack(
            Replay {
                prefix: first,
                pos: 0,
                inner: stream,
            },
            resolve,
        ),
        Service::ReceivePack => puregit::server::serve_ssh_receive_pack(
            &format!("git-receive-pack '{}'", req.path),
            stream,
            resolve,
            &|_| Ok(()),
        ),
    };
    if let Err(e) = result {
        eprintln!("puregit daemon: {:?} {}: {e}", req.service, req.path);
    }
}

/// Which puregit server a test drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Daemon,
    Http,
}

/// A running puregit server of either kind, rooted at a directory.
enum Server {
    Daemon(PuregitDaemon),
    Http(PuregitHttp),
}

impl Server {
    fn start(kind: Kind, root: &Path) -> Server {
        match kind {
            Kind::Daemon => Server::Daemon(PuregitDaemon::start(root)),
            Kind::Http => Server::Http(PuregitHttp::start(root)),
        }
    }

    fn url(&self, name: &str) -> String {
        match self {
            Server::Daemon(d) => d.url(name),
            Server::Http(h) => h.url(name),
        }
    }
}

// ---------------------------------------------------------------------------
// verification helpers
// ---------------------------------------------------------------------------

fn pv(v: u8) -> String {
    format!("protocol.version={v}")
}

/// Maps a clone's `refs/remotes/origin/*` back to `refs/heads/*`.
fn remote_branches(env: &GitEnv, clone: &Path) -> BTreeMap<String, String> {
    env.refs(clone, Some("refs/remotes/origin/"))
        .into_iter()
        .filter(|(k, _)| k != "refs/remotes/origin/HEAD")
        .map(|(k, v)| (k.replacen("refs/remotes/origin/", "refs/heads/", 1), v))
        .collect()
}

/// Asserts a (full, non-mirror) clone mirrors `bare`: every branch as a
/// remote-tracking ref, every tag, `HEAD`, and a clean `fsck --strict`.
fn assert_clone_matches(env: &GitEnv, bare: &Path, clone: &Path, ctx: &str) {
    assert_eq!(
        remote_branches(env, clone),
        env.refs(bare, Some("refs/heads/")),
        "{ctx}: remote-tracking branches differ from the server's branches"
    );
    assert_eq!(
        env.refs(clone, Some("refs/tags/")),
        env.refs(bare, Some("refs/tags/")),
        "{ctx}: tags differ"
    );
    assert_eq!(
        env.rev_parse(clone, "HEAD"),
        env.rev_parse(bare, "HEAD"),
        "{ctx}: HEAD differs"
    );
    assert_eq!(
        env.git(clone, &["symbolic-ref", "HEAD"]),
        "refs/heads/main",
        "{ctx}: checked-out branch"
    );
    env.fsck(clone, ctx);
}

/// Asserts (from git's packet trace of an `ls-remote`) that the server
/// answered in protocol version `v`.
fn assert_protocol_version(env: &GitEnv, url: &str, v: u8, ctx: &str) {
    let out = env.try_git_env(
        env.root(),
        &["-c", &pv(v), "ls-remote", url],
        &[("GIT_TRACE_PACKET", "1")],
    );
    assert!(out.status.success(), "{ctx}: traced ls-remote failed");
    let trace = String::from_utf8_lossy(&out.stderr);
    let said = |n: u8| {
        trace
            .lines()
            .any(|l| l.contains("< version ") && l.trim_end().ends_with(&format!("version {n}")))
    };
    match v {
        0 => assert!(
            !said(1) && !said(2),
            "{ctx}: server announced a version for v0"
        ),
        n => assert!(
            said(n),
            "{ctx}: server did not answer in protocol v{n}:\n{trace}"
        ),
    }
}

/// The set of `(algo, version)` combinations.
fn matrix(env: &GitEnv) -> Vec<(&'static str, u8)> {
    let mut out = Vec::new();
    for algo in algos(env) {
        for v in VERSIONS {
            out.push((algo, v));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// scenarios
// ---------------------------------------------------------------------------

/// ls-remote, clone, incremental fetch, and a fetch whose client holds lots of
/// unrelated local history (multi-round `have` negotiation).
fn scenario_clone_fetch(kind: Kind) {
    require_git!();
    let env = GitEnv::new(&format!("srv-clone-{kind:?}"));
    let server = Server::start(kind, env.root());
    for (algo, v) in matrix(&env) {
        let ctx = format!("{kind:?} {algo} v{v}");
        let name = format!("cf-{algo}-v{v}.git");
        let mut fx = make_fixture(&env, &name, algo, 20);
        let url = server.url(&name);

        // ls-remote lists exactly the server's refs (+HEAD); peeled entries,
        // when present, must name the tag's target.
        let listed = env.ls_remote(&url, v);
        let mut expect = env.refs(&fx.bare, None);
        expect.insert("HEAD".into(), env.rev_parse(&fx.bare, "HEAD"));
        let unpeeled: BTreeMap<String, String> = listed
            .iter()
            .filter(|(k, _)| !k.ends_with("^{}"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assert_eq!(unpeeled, expect, "{ctx}: ls-remote");
        for (k, oid) in listed.iter().filter(|(k, _)| k.ends_with("^{}")) {
            assert_eq!(
                oid,
                &env.rev_parse(&fx.bare, k),
                "{ctx}: ls-remote peeled {k}"
            );
        }

        // The server really speaks the requested protocol version.
        assert_protocol_version(&env, &url, v, &ctx);

        // Clone.
        let clone = env.path(&format!("cf-{algo}-v{v}-clone"));
        env.git(
            env.root(),
            &["-c", &pv(v), "clone", "-q", &url, clone.to_str().unwrap()],
        );
        assert_clone_matches(&env, &fx.bare, &clone, &format!("{ctx} clone"));
        assert_eq!(
            env.git(&clone, &["rev-parse", "--show-object-format"]),
            algo,
            "{ctx}: object format of the clone"
        );

        // Incremental fetch after new commits on the server.
        let tip = advance_main(&env, &mut fx, 3);
        env.git(&clone, &["-c", &pv(v), "fetch", "-q", "origin"]);
        assert_eq!(
            env.rev_parse(&clone, "refs/remotes/origin/main"),
            tip,
            "{ctx}: incremental fetch"
        );
        assert_eq!(
            remote_branches(&env, &clone),
            env.refs(&fx.bare, Some("refs/heads/")),
            "{ctx}: incremental fetch refs"
        );
        env.fsck(&clone, &format!("{ctx} incremental fetch"));

        // A client with lots of local-only history: many `have`s the server
        // does not know, forcing several negotiation rounds.
        local_commits(
            &env,
            &clone,
            "refs/heads/local-work",
            "refs/heads/main^0",
            40,
            500,
        );
        let tip = advance_main(&env, &mut fx, 2);
        env.git(&clone, &["-c", &pv(v), "fetch", "-q", "origin"]);
        assert_eq!(
            env.rev_parse(&clone, "refs/remotes/origin/main"),
            tip,
            "{ctx}: negotiated fetch"
        );
        assert_eq!(
            remote_branches(&env, &clone),
            env.refs(&fx.bare, Some("refs/heads/")),
            "{ctx}: negotiated fetch refs"
        );
        env.fsck(&clone, &format!("{ctx} negotiated fetch"));

        // A mirror clone copies every ref verbatim.
        let mirror = env.path(&format!("cf-{algo}-v{v}-mirror.git"));
        env.git(
            env.root(),
            &[
                "-c",
                &pv(v),
                "clone",
                "-q",
                "--mirror",
                &url,
                mirror.to_str().unwrap(),
            ],
        );
        assert_eq!(
            env.refs(&mirror, None),
            env.refs(&fx.bare, None),
            "{ctx}: mirror clone refs"
        );
        env.fsck(&mirror, &format!("{ctx} mirror"));
        env.fsck(&fx.bare, &format!("{ctx} server"));
    }
}

/// Push: create/update/delete branches, push tags, and non-fast-forward
/// rejection; `--atomic` all-or-nothing.
fn scenario_push(kind: Kind) {
    require_git!();
    let env = GitEnv::new(&format!("srv-push-{kind:?}"));
    let server = Server::start(kind, env.root());
    for (algo, v) in matrix(&env) {
        let ctx = format!("{kind:?} {algo} v{v}");
        let name = format!("p-{algo}-v{v}.git");
        let fx = make_fixture(&env, &name, algo, 6);
        let url = server.url(&name);
        let clone = env.path(&format!("p-{algo}-v{v}-clone"));
        env.git(
            env.root(),
            &["-c", &pv(v), "clone", "-q", &url, clone.to_str().unwrap()],
        );
        let push = |args: &[&str]| -> std::process::Output {
            let pvs = pv(v);
            let mut full = vec!["-c", pvs.as_str(), "push", "--porcelain", "origin"];
            full.extend_from_slice(args);
            env.try_git(&clone, &full)
        };
        let ok = |args: &[&str], what: &str| {
            let out = push(args);
            assert!(
                out.status.success(),
                "{ctx}: push {what} failed:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        };

        // Create a branch.
        ok(&["HEAD:refs/heads/topic"], "create");
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/heads/topic"),
            env.rev_parse(&clone, "HEAD"),
            "{ctx}: created branch"
        );

        // Fast-forward main with new objects (including a modified big blob
        // the client may send as a thin delta).
        for i in 0..3 {
            env.write_and_add(
                &clone,
                "docs/big.txt",
                &format!("{}\nchange {i}\n", "y".repeat(3000)),
            );
            env.write_and_add(&clone, &format!("pushed/{i}.txt"), &format!("pushed {i}\n"));
            env.commit_at(&clone, &format!("pushed {i}"), 100 + i);
        }
        ok(&["main"], "fast-forward");
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/heads/main"),
            env.rev_parse(&clone, "HEAD"),
            "{ctx}: fast-forward"
        );
        env.fsck(&fx.bare, &format!("{ctx} after ff push"));

        // Push an annotated tag and a lightweight tag.
        env.git(&clone, &["tag", "-a", "-m", "pushed tag", "v2.0"]);
        env.git(&clone, &["tag", "light2", "HEAD~1"]);
        ok(&["v2.0", "light2"], "tags");
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/tags/v2.0"),
            env.rev_parse(&clone, "refs/tags/v2.0"),
            "{ctx}: annotated tag"
        );
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/tags/light2"),
            env.rev_parse(&clone, "refs/tags/light2"),
            "{ctx}: lightweight tag"
        );

        // Delete a branch.
        ok(&[":refs/heads/topic"], "delete");
        assert!(
            !env.refs(&fx.bare, Some("refs/heads/"))
                .contains_key("refs/heads/topic"),
            "{ctx}: deleted branch still present"
        );

        // Non-fast-forward: refused by the client without --force, and by
        // the server (which does not allow non-fast-forward branch updates)
        // even with --force; the server's ref must not move either way.
        let before = env.rev_parse(&fx.bare, "refs/heads/main");
        env.git(&clone, &["checkout", "-q", "-b", "diverged", "HEAD~2"]);
        env.write_and_add(&clone, "diverged.txt", "diverged\n");
        env.commit_at(&clone, "diverged", 200);
        let out = push(&["diverged:main"]);
        assert!(!out.status.success(), "{ctx}: non-ff push must fail");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("rejected")
                || String::from_utf8_lossy(&out.stderr).contains("rejected"),
            "{ctx}: non-ff push not reported as rejected"
        );
        let out = push(&["--force", "diverged:main"]);
        assert!(
            !out.status.success(),
            "{ctx}: forced non-ff push must be refused"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("!\tdiverged:refs/heads/main") || stdout.contains("[remote rejected]"),
            "{ctx}: forced non-ff not reported as a remote rejection:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/heads/main"),
            before,
            "{ctx}: server ref moved"
        );

        // Atomic push: one good and one bad update ⇒ nothing applied; two good
        // updates ⇒ both applied.
        let out = push(&[
            "--atomic",
            "--force",
            "HEAD:refs/heads/atomic-a",
            "diverged:main",
        ]);
        assert!(
            !out.status.success(),
            "{ctx}: atomic push with a bad update must fail"
        );
        assert!(
            !env.refs(&fx.bare, Some("refs/heads/"))
                .contains_key("refs/heads/atomic-a"),
            "{ctx}: atomic push partially applied"
        );
        assert_eq!(env.rev_parse(&fx.bare, "refs/heads/main"), before);
        ok(
            &[
                "--atomic",
                "HEAD:refs/heads/atomic-a",
                "HEAD~1:refs/heads/atomic-b",
            ],
            "atomic",
        );
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/heads/atomic-a"),
            env.rev_parse(&clone, "HEAD")
        );
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/heads/atomic-b"),
            env.rev_parse(&clone, "HEAD~1")
        );

        env.fsck(&fx.bare, &format!("{ctx} server after pushes"));
        // A fresh clone from the server sees exactly what was pushed.
        let check = env.path(&format!("p-{algo}-v{v}-check"));
        env.git(
            env.root(),
            &["-c", &pv(v), "clone", "-q", &url, check.to_str().unwrap()],
        );
        assert_clone_matches(&env, &fx.bare, &check, &format!("{ctx} re-clone"));
    }
}

/// The `.git/shallow` boundary of a repository (sorted), empty if none.
fn shallow_file(repo: &Path) -> Vec<String> {
    let p = repo.join(".git").join("shallow");
    let mut v: Vec<String> = std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    v.sort();
    v
}

/// `git rev-list --all` of a repository (sorted).
fn all_commits(env: &GitEnv, repo: &Path) -> Vec<String> {
    let mut v: Vec<String> = env
        .git(repo, &["rev-list", "--all"])
        .lines()
        .map(str::to_string)
        .collect();
    v.sort();
    v
}

/// Shallow clone (`--depth`, `--shallow-since`) and `--deepen`, compared
/// against the same operations served by git itself over `file://`.
fn scenario_shallow(kind: Kind) {
    require_git!();
    let env = GitEnv::new(&format!("srv-shallow-{kind:?}"));
    let server = Server::start(kind, env.root());
    for (algo, v) in matrix(&env) {
        let ctx = format!("{kind:?} {algo} v{v}");
        let name = format!("s-{algo}-v{v}.git");
        let fx = make_fixture(&env, &name, algo, 12);
        let url = server.url(&name);
        let oracle_url = file_url(&fx.bare);

        type Step<'a> = (&'a str, Vec<&'a str>);
        let since = format!("--shallow-since={}", BASE_TIME + 8 * DAY);
        let cases: Vec<(&str, Vec<&str>, Vec<Step<'_>>)> = vec![
            (
                "depth1",
                vec!["--depth", "1"],
                vec![
                    ("deepen2", vec!["--deepen=2"]),
                    ("depth5", vec!["--depth=5"]),
                ],
            ),
            (
                "depth3-nosingle",
                vec!["--depth", "3", "--no-single-branch"],
                vec![],
            ),
            ("since", vec![since.as_str()], vec![]),
            ("exclude", vec!["--shallow-exclude=v1.0"], vec![]),
        ];
        for (case, args, steps) in cases {
            let ctx = format!("{ctx} {case}");
            let ours = env.path(&format!("s-{algo}-v{v}-{case}-pg"));
            let theirs = env.path(&format!("s-{algo}-v{v}-{case}-git"));
            for (u, dest) in [(&url, &ours), (&oracle_url, &theirs)] {
                let mut a = vec!["-c", "protocol.allow=always"];
                let pvs = pv(v);
                a.extend_from_slice(&["-c", &pvs, "clone", "-q"]);
                a.extend_from_slice(&args);
                a.push(u);
                a.push(dest.to_str().unwrap());
                env.git(env.root(), &a);
            }
            let compare = |step: &str| {
                assert_eq!(
                    shallow_file(&ours),
                    shallow_file(&theirs),
                    "{ctx} {step}: shallow boundary differs from git's\nours:\n{}\ngit's:\n{}",
                    env.git(&ours, &["log", "--oneline", "--decorate", "--all"]),
                    env.git(&theirs, &["log", "--oneline", "--decorate", "--all"]),
                );
                assert!(!shallow_file(&ours).is_empty(), "{ctx} {step}: not shallow");
                assert_eq!(
                    all_commits(&env, &ours),
                    all_commits(&env, &theirs),
                    "{ctx} {step}: commit set differs from git's"
                );
                assert_eq!(
                    env.refs(&ours, None),
                    env.refs(&theirs, None),
                    "{ctx} {step}: refs differ from git's"
                );
                env.fsck(&ours, &format!("{ctx} {step}"));
            };
            compare("clone");
            for (step, sargs) in steps {
                for dest in [&ours, &theirs] {
                    let pvs = pv(v);
                    let mut a = vec!["-c", pvs.as_str(), "fetch", "-q"];
                    a.extend_from_slice(&sargs);
                    a.push("origin");
                    env.git(dest, &a);
                }
                compare(step);
            }
            // Unshallow restores the full history.
            env.git(
                &ours,
                &["-c", &pv(v), "fetch", "-q", "--unshallow", "origin"],
            );
            assert!(
                shallow_file(&ours).is_empty(),
                "{ctx}: still shallow after --unshallow"
            );
            env.fsck(&ours, &format!("{ctx} unshallow"));
            assert_eq!(
                env.git(&ours, &["rev-list", "--count", "HEAD"]),
                env.git(&fx.bare, &["rev-list", "--count", "HEAD"]),
                "{ctx}: unshallowed history length"
            );
        }
    }
}

/// Partial clone (`--filter=blob:none`, `--filter=tree:0`) followed by a
/// checkout that lazily fetches the missing objects from the promisor remote.
fn scenario_partial(kind: Kind) {
    require_git!();
    let env = GitEnv::new(&format!("srv-partial-{kind:?}"));
    let server = Server::start(kind, env.root());
    for (algo, v) in matrix(&env) {
        let name = format!("pc-{algo}-v{v}.git");
        let fx = make_fixture(&env, &name, algo, 8);
        let url = server.url(&name);
        for filter in ["blob:none", "tree:0"] {
            let ctx = format!("{kind:?} {algo} v{v} {filter}");
            let dest = env.path(&format!("pc-{algo}-v{v}-{}", filter.replace(':', "-")));
            let farg = format!("--filter={filter}");
            env.git(
                env.root(),
                &[
                    "-c",
                    &pv(v),
                    "clone",
                    "-q",
                    "--no-checkout",
                    &farg,
                    &url,
                    dest.to_str().unwrap(),
                ],
            );
            assert_eq!(
                env.git(&dest, &["config", "remote.origin.promisor"]),
                "true",
                "{ctx}: not a promisor clone"
            );
            let missing_before = env
                .git(
                    &dest,
                    &["rev-list", "--objects", "--all", "--missing=print"],
                )
                .lines()
                .filter(|l| l.starts_with('?'))
                .count();
            assert!(
                missing_before > 0,
                "{ctx}: the server ignored the filter (no objects omitted)"
            );
            // Commits are all present.
            assert_eq!(
                remote_branches(&env, &dest),
                env.refs(&fx.bare, Some("refs/heads/")),
                "{ctx}: branches"
            );

            // Checkout lazily fetches what HEAD's tree needs.
            env.git(&dest, &["-c", &pv(v), "checkout", "-q", "main"]);
            let tree_listing = env.git(&dest, &["ls-tree", "-r", "HEAD"]);
            assert_eq!(
                tree_listing,
                env.git(&fx.bare, &["ls-tree", "-r", "HEAD"]),
                "{ctx}: checked-out tree"
            );
            for line in tree_listing.lines() {
                let (meta, path) = line.split_once('\t').unwrap();
                let oid = meta.split_whitespace().nth(2).unwrap();
                let on_disk = std::fs::read(dest.join(path)).unwrap();
                let want = env.git(&fx.bare, &["cat-file", "blob", oid]);
                assert_eq!(
                    String::from_utf8_lossy(&on_disk).trim_end(),
                    want,
                    "{ctx}: worktree file {path}"
                );
            }
            assert_eq!(
                env.git(&dest, &["status", "--porcelain"]),
                "",
                "{ctx}: status"
            );
            env.fsck(&dest, &ctx);
            // Lazily fetching an old blob by name also works.
            let old_blob = env.rev_parse(&fx.bare, "HEAD~5:README.md");
            assert_eq!(
                env.git(&dest, &["-c", &pv(v), "cat-file", "-p", &old_blob]),
                env.git(&fx.bare, &["cat-file", "-p", &old_blob]),
                "{ctx}: lazy fetch of an old blob"
            );
        }
    }
}

#[test]
fn daemon_clone_fetch_ls_remote() {
    scenario_clone_fetch(Kind::Daemon);
}

#[test]
fn http_clone_fetch_ls_remote() {
    scenario_clone_fetch(Kind::Http);
}

#[test]
fn daemon_push() {
    scenario_push(Kind::Daemon);
}

#[test]
fn http_push() {
    scenario_push(Kind::Http);
}

#[test]
fn daemon_shallow() {
    scenario_shallow(Kind::Daemon);
}

#[test]
fn http_shallow() {
    scenario_shallow(Kind::Http);
}

#[test]
fn daemon_partial_clone() {
    scenario_partial(Kind::Daemon);
}

#[test]
fn http_partial_clone() {
    scenario_partial(Kind::Http);
}

/// Sanity check of the harness itself: the oracle `git http-backend` shim and
/// `git daemon` serve the same fixture, so a failure above is attributable to
/// puregit rather than to the test plumbing.
#[test]
fn harness_git_servers_work() {
    require_git!();
    let env = GitEnv::new("srv-harness");
    let fx = make_fixture(&env, "h.git", "sha1", 3);
    if GitHttpBackend::available(&env) {
        let backend = GitHttpBackend::start(&env, env.root(), ProtocolOverride::PassThrough);
        let dest = env.path("h-http");
        env.git(
            env.root(),
            &["clone", "-q", &backend.url("h.git"), dest.to_str().unwrap()],
        );
        assert_clone_matches(&env, &fx.bare, &dest, "git http-backend");
    }
    if let Some(d) = GitDaemon::start(&env, env.root()) {
        let dest = env.path("h-daemon");
        env.git(
            env.root(),
            &["clone", "-q", &d.url("h.git"), dest.to_str().unwrap()],
        );
        assert_clone_matches(&env, &fx.bare, &dest, "git daemon");
    }
}
