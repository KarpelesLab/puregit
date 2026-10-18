//! Wire-protocol interop: **real `git` server ↔ puregit client**.
//!
//! Repositories are served by `git http-backend` (behind a minimal in-test
//! HTTP→CGI shim), by `git daemon`, and by spawned `git upload-pack` /
//! `git receive-pack` processes (the file/"local" pack transport), all on
//! loopback. puregit's client porcelain (`clone`, `fetch_update`,
//! `fetch_negotiated`, `push`, shallow and filtered fetches with promisor
//! backfill) drives them for protocol v0, v1 and (over HTTP) v2, for SHA-1 and
//! SHA-256 repositories, and every result is verified with `git fsck --strict`
//! and exact ref/object-id comparisons against the serving repository.
//!
//! puregit has no `git://` or file-transport client of its own; the
//! `StreamTransport` below frames those byte streams (connect, request line /
//! process spawn, read-to-EOF) and delegates everything else — advertisement
//! parsing, negotiation, pack ingest, ref updates, push commands and
//! report-status — to puregit.
//!
//! SSH is not exercised: puregit's SSH client needs an SSH server, and neither
//! a hermetic one (puressh's server is not a dependency) nor a local `sshd`
//! is available portably.
//!
//! Skips (with a message) when `git` is not on `PATH`, unless
//! `PUREGIT_REQUIRE_GIT=1`.

#![cfg(all(feature = "client", feature = "std"))]

#[macro_use]
#[path = "interop_git_protocol/support.rs"]
mod support;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use puregit::oid::HashAlgo;
use puregit::protocol::{RefAdvertisement, pktline};
use puregit::transport::{Service, Transport};
use puregit::{ObjectId, Repository, client};

use support::*;

// ---------------------------------------------------------------------------
// a git:// / spawned-process byte-stream transport for puregit's client
// ---------------------------------------------------------------------------

/// Where a [`StreamTransport`] connects.
#[derive(Clone)]
enum Endpoint {
    /// `git daemon` on 127.0.0.1:`port`, repository `/<name>`.
    Daemon { port: u16, name: String },
    /// `git upload-pack` / `git receive-pack` spawned on a local directory.
    Spawn { dir: PathBuf },
}

/// An open connection.
enum Conn {
    Tcp(TcpStream),
    Child {
        child: Child,
        stdin: Option<ChildStdin>,
        stdout: ChildStdout,
    },
}

impl Conn {
    fn reader(&mut self) -> &mut dyn Read {
        match self {
            Conn::Tcp(s) => s,
            Conn::Child { stdout, .. } => stdout,
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.write_all(bytes),
            Conn::Child { stdin, .. } => stdin
                .as_mut()
                .ok_or_else(|| std::io::Error::other("stdin closed"))?
                .write_all(bytes),
        }
    }

    /// Signals end-of-request (half-close / close stdin).
    fn finish_writing(&mut self) {
        match self {
            Conn::Tcp(s) => shutdown_write(s),
            Conn::Child { stdin, .. } => drop(stdin.take()),
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let Conn::Child { child, stdin, .. } = self {
            drop(stdin.take());
            if wait_with_deadline(child, Duration::from_secs(20)).is_none() {
                eprintln!("note: killed a lingering git pack process");
            }
        }
    }
}

/// A smart-protocol (v0/v1) transport over a raw byte stream, for puregit's
/// client: `git://` (`git daemon`) or a spawned `git upload-pack` /
/// `git receive-pack` (the file transport).
struct StreamTransport<'a> {
    env: &'a GitEnv,
    endpoint: Endpoint,
    /// Wire protocol version requested (0 or 1).
    version: u8,
    algo: HashAlgo,
    conn: Option<Conn>,
    /// Whether the open connection still owes the server a request.
    pending: bool,
}

impl<'a> StreamTransport<'a> {
    fn new(env: &'a GitEnv, endpoint: Endpoint, version: u8) -> Self {
        StreamTransport {
            env,
            endpoint,
            version,
            algo: HashAlgo::Sha1,
            conn: None,
            pending: false,
        }
    }

    fn close(&mut self) {
        if let Some(mut conn) = self.conn.take() {
            if self.pending {
                // Tell an upload-pack we want nothing (a lone flush).
                let _ = conn.write_all(b"0000");
            }
            conn.finish_writing();
            let mut sink = Vec::new();
            let _ = conn.reader().read_to_end(&mut sink);
        }
        self.pending = false;
    }

    fn connect(&self, service: Service) -> puregit::Result<Conn> {
        let io = |e: std::io::Error| puregit::Error::Io(e.to_string());
        match &self.endpoint {
            Endpoint::Daemon { port, name } => {
                let s = TcpStream::connect(("127.0.0.1", *port)).map_err(io)?;
                s.set_read_timeout(Some(IO_TIMEOUT)).map_err(io)?;
                s.set_write_timeout(Some(IO_TIMEOUT)).map_err(io)?;
                let mut line = format!("{} /{name}\0host=127.0.0.1\0", service.name()).into_bytes();
                if self.version > 0 {
                    line.extend_from_slice(format!("\0version={}\0", self.version).as_bytes());
                }
                let mut conn = Conn::Tcp(s);
                conn.write_all(&pkt(&line)).map_err(io)?;
                Ok(conn)
            }
            Endpoint::Spawn { dir } => {
                let mut cmd = Command::new("git");
                self.env.apply(&mut cmd);
                cmd.arg(service.name().trim_start_matches("git-"))
                    .arg(dir)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit());
                if self.version > 0 {
                    cmd.env("GIT_PROTOCOL", format!("version={}", self.version));
                }
                let mut child = cmd.spawn().map_err(io)?;
                let stdin = child.stdin.take();
                let stdout = child.stdout.take().unwrap();
                Ok(Conn::Child {
                    child,
                    stdin,
                    stdout,
                })
            }
        }
    }
}

impl Drop for StreamTransport<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

impl Transport for StreamTransport<'_> {
    fn discover(&mut self, service: Service) -> puregit::Result<RefAdvertisement> {
        self.close();
        let mut conn = self.connect(service)?;
        let raw = read_until_flush(conn.reader()).map_err(|e| puregit::Error::Io(e.to_string()))?;
        let packets = pktline::decode_all(&raw)?;
        let advert = RefAdvertisement::parse(self.algo, &packets)?;
        self.algo = advert.object_format;
        self.conn = Some(conn);
        self.pending = true;
        Ok(advert)
    }

    fn exchange(&mut self, _service: Service, request: &[u8]) -> puregit::Result<Vec<u8>> {
        let io = |e: std::io::Error| puregit::Error::Io(e.to_string());
        let mut conn = self
            .conn
            .take()
            .ok_or_else(|| puregit::Error::Protocol("exchange before discover".into()))?;
        self.pending = false;
        conn.write_all(request).map_err(io)?;
        conn.finish_writing();
        let mut response = Vec::new();
        conn.reader().read_to_end(&mut response).map_err(io)?;
        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// servers under test
// ---------------------------------------------------------------------------

/// Which real git server a test drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Http,
    Daemon,
    File,
}

/// A running git server (or none, for the spawned file transport).
// Without the `http` feature the HTTP variant is constructed but never used.
#[cfg_attr(not(feature = "http"), allow(dead_code))]
enum Server {
    Http(GitHttpBackend),
    Daemon(GitDaemon),
    File,
}

impl Server {
    /// Starts the server for `kind`/`version`, or `None` (with a SKIP message)
    /// if this platform's git cannot provide it.
    fn start(env: &GitEnv, kind: Kind, version: u8) -> Option<Server> {
        match kind {
            Kind::Http => {
                if !GitHttpBackend::available(env) {
                    return None;
                }
                // puregit's HTTP client always offers v2; the shim pins the
                // version git sees.
                let proto = match version {
                    0 => ProtocolOverride::Force(String::new()),
                    1 => ProtocolOverride::Force("version=1".into()),
                    _ => ProtocolOverride::PassThrough,
                };
                Some(Server::Http(GitHttpBackend::start(env, env.root(), proto)))
            }
            Kind::Daemon => GitDaemon::start(env, env.root()).map(Server::Daemon),
            Kind::File => Some(Server::File),
        }
    }

    /// A fresh puregit transport to repository `name` (under the env root).
    fn transport<'a>(&self, env: &'a GitEnv, name: &str, version: u8) -> Box<dyn Transport + 'a> {
        match self {
            #[cfg(feature = "http")]
            Server::Http(b) => Box::new(puregit::transport::http::HttpTransport::new(
                b.url(name),
                HashAlgo::Sha1,
            )),
            #[cfg(not(feature = "http"))]
            Server::Http(_) => unreachable!("http tests need the `http` feature"),
            Server::Daemon(d) => Box::new(StreamTransport::new(
                env,
                Endpoint::Daemon {
                    port: d.port,
                    name: name.to_string(),
                },
                version,
            )),
            Server::File => Box::new(StreamTransport::new(
                env,
                Endpoint::Spawn {
                    dir: env.path(name),
                },
                version,
            )),
        }
    }
}

/// The protocol versions exercised per transport (puregit's stream client
/// speaks v0/v1; its HTTP client also v2).
fn versions(kind: Kind) -> &'static [u8] {
    match kind {
        Kind::Http => &[0, 1, 2],
        Kind::Daemon | Kind::File => &[0, 1],
    }
}

// ---------------------------------------------------------------------------
// verification helpers
// ---------------------------------------------------------------------------

fn remote_branches(env: &GitEnv, clone: &Path) -> BTreeMap<String, String> {
    env.refs(clone, Some("refs/remotes/origin/"))
        .into_iter()
        .filter(|(k, _)| k != "refs/remotes/origin/HEAD")
        .map(|(k, v)| (k.replacen("refs/remotes/origin/", "refs/heads/", 1), v))
        .collect()
}

fn hex(id: &ObjectId) -> String {
    id.to_hex()
}

/// Asserts a puregit clone mirrors `bare` exactly and is fsck-clean.
fn assert_clone_matches(env: &GitEnv, bare: &Path, clone: &Path, algo: &str, ctx: &str) {
    assert_eq!(
        env.git(clone, &["rev-parse", "--show-object-format"]),
        algo,
        "{ctx}: object format"
    );
    assert_eq!(
        remote_branches(env, clone),
        env.refs(bare, Some("refs/heads/")),
        "{ctx}: remote-tracking branches"
    );
    assert_eq!(
        env.refs(clone, Some("refs/tags/")),
        env.refs(bare, Some("refs/tags/")),
        "{ctx}: tags"
    );
    assert_eq!(
        env.git(clone, &["symbolic-ref", "HEAD"]),
        "refs/heads/main",
        "{ctx}: HEAD branch"
    );
    assert_eq!(
        env.rev_parse(clone, "HEAD"),
        env.rev_parse(bare, "HEAD"),
        "{ctx}: HEAD commit"
    );
    assert_eq!(
        env.git(clone, &["status", "--porcelain"]),
        "",
        "{ctx}: work tree / index not clean after clone"
    );
    env.fsck(clone, ctx);
}

/// The `(algo, version)` matrix for `kind`.
fn matrix(env: &GitEnv, kind: Kind) -> Vec<(&'static str, u8)> {
    let mut out = Vec::new();
    for algo in algos(env) {
        for &v in versions(kind) {
            out.push((algo, v));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// scenarios
// ---------------------------------------------------------------------------

/// clone, fetch (incremental, with prune), and — over stateless HTTP — the
/// multi-round negotiated fetch.
fn scenario_clone_fetch(kind: Kind) {
    require_git!();
    let env = GitEnv::new(&format!("cli-clone-{kind:?}"));
    for (algo, v) in matrix(&env, kind) {
        let Some(server) = Server::start(&env, kind, v) else {
            return;
        };
        let ctx = format!("{kind:?} {algo} v{v}");
        let name = format!("c-{algo}-v{v}.git");
        let mut fx = make_fixture(&env, &name, algo, 20);

        let dest = env.path(&format!("c-{algo}-v{v}-clone"));
        let mut t = server.transport(&env, &name, v);
        let repo = client::clone(&dest, &mut *t)
            .unwrap_or_else(|e| panic!("{ctx}: puregit clone failed: {e}"));
        assert_eq!(repo.algo().name(), algo, "{ctx}: clone hash algorithm");
        drop(repo);
        assert_clone_matches(&env, &fx.bare, &dest, algo, &format!("{ctx} clone"));

        // Incremental fetch, plus a branch deleted on the server (pruned).
        let tip = advance_main(&env, &mut fx, 3);
        env.git(&fx.bare, &["branch", "-D", "feature"]);
        let mut repo = Repository::open(&dest).unwrap();
        let mut t = server.transport(&env, &name, v);
        let got = client::fetch_update(&mut repo, &mut *t, "origin", true)
            .unwrap_or_else(|e| panic!("{ctx}: puregit fetch failed: {e}"));
        assert!(got > 0, "{ctx}: fetch received nothing");
        drop(repo);
        assert_eq!(
            env.rev_parse(&dest, "refs/remotes/origin/main"),
            tip,
            "{ctx}: fetched tip"
        );
        assert_eq!(
            remote_branches(&env, &dest),
            env.refs(&fx.bare, Some("refs/heads/")),
            "{ctx}: refs after fetch --prune"
        );
        env.fsck(&dest, &format!("{ctx} fetch"));

        // A no-op fetch transfers nothing and changes nothing.
        let mut repo = Repository::open(&dest).unwrap();
        let mut t = server.transport(&env, &name, v);
        let got = client::fetch_update(&mut repo, &mut *t, "origin", false).unwrap();
        assert_eq!(got, 0, "{ctx}: up-to-date fetch received objects");
        drop(repo);

        // Multi-round negotiation (stateless request/response shape — HTTP).
        if kind == Kind::Http {
            env.git(&dest, &["checkout", "-q", "-b", "local"]);
            for i in 0..40 {
                env.write_and_add(&dest, "local.txt", &format!("local {i}\n"));
                env.commit_at(&dest, &format!("local {i}"), 900 + i);
            }
            let tip = advance_main(&env, &mut fx, 2);
            let mut repo = Repository::open(&dest).unwrap();
            let mut t = server.transport(&env, &name, v);
            let out = client::fetch_negotiated(&mut repo, &mut *t)
                .unwrap_or_else(|e| panic!("{ctx}: negotiated fetch failed: {e}"));
            assert!(
                out.received_objects > 0,
                "{ctx}: negotiated fetch got nothing"
            );
            let main = out
                .refs
                .iter()
                .find(|r| r.name == "refs/heads/main")
                .expect("main advertised");
            assert_eq!(hex(&main.id), tip, "{ctx}: negotiated advertisement");
            assert!(repo.objects_contains(&main.id), "{ctx}: tip not fetched");
            repo.refs()
                .update(
                    "refs/remotes/origin/main",
                    &puregit::refs::Reference::Direct(main.id),
                )
                .unwrap();
            drop(repo);
            env.fsck(&dest, &format!("{ctx} negotiated fetch"));
        }
        env.fsck(&fx.bare, &format!("{ctx} server"));
    }
}

trait ContainsExt {
    fn objects_contains(&self, id: &ObjectId) -> bool;
}

impl ContainsExt for Repository {
    fn objects_contains(&self, id: &ObjectId) -> bool {
        use puregit::odb::ObjectDatabase;
        self.objects().contains(id)
    }
}

/// push: fast-forward, create a branch, and non-fast-forward rejection.
fn scenario_push(kind: Kind) {
    require_git!();
    let env = GitEnv::new(&format!("cli-push-{kind:?}"));
    for (algo, v) in matrix(&env, kind) {
        let Some(server) = Server::start(&env, kind, v) else {
            return;
        };
        let ctx = format!("{kind:?} {algo} v{v}");
        let name = format!("p-{algo}-v{v}.git");
        let fx = make_fixture(&env, &name, algo, 5);
        let dest = env.path(&format!("p-{algo}-v{v}-clone"));
        // Start from a git-made clone so the push is puregit's alone.
        env.git(
            env.root(),
            &["clone", "-q", &file_url(&fx.bare), dest.to_str().unwrap()],
        );

        // Fast-forward main with new objects, including a modified big blob.
        for i in 0..3 {
            env.write_and_add(
                &dest,
                "docs/big.txt",
                &format!("{}\nedit {i}\n", "z".repeat(4000)),
            );
            env.write_and_add(&dest, &format!("new/{i}.txt"), &format!("new {i}\n"));
            env.commit_at(&dest, &format!("local {i}"), 300 + i);
        }
        let push = |local: &str, remote: &str| {
            let repo = Repository::open(&dest).unwrap();
            let mut t = server.transport(&env, &name, v);
            client::push(&repo, &mut *t, local, remote)
                .unwrap_or_else(|e| panic!("{ctx}: puregit push {local}:{remote} failed: {e}"))
        };
        let report = push("refs/heads/main", "refs/heads/main");
        assert!(report.is_ok(), "{ctx}: ff push rejected: {report:?}");
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/heads/main"),
            env.rev_parse(&dest, "HEAD"),
            "{ctx}: server main after push"
        );
        env.fsck(&fx.bare, &format!("{ctx} after ff push"));

        // Create a new branch.
        let report = push("refs/heads/main", "refs/heads/pg-branch");
        assert!(report.is_ok(), "{ctx}: create push rejected: {report:?}");
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/heads/pg-branch"),
            env.rev_parse(&dest, "HEAD"),
            "{ctx}: created branch"
        );

        // Pushing what the server already has is a no-op success.
        let report = push("refs/heads/main", "refs/heads/main");
        assert!(report.is_ok(), "{ctx}: up-to-date push: {report:?}");

        // Non-fast-forward: git's receive-pack refuses it; nothing moves.
        let before = env.rev_parse(&fx.bare, "refs/heads/main");
        env.git(&dest, &["checkout", "-q", "-b", "diverged", "HEAD~2"]);
        env.write_and_add(&dest, "diverged.txt", "diverged\n");
        env.commit_at(&dest, "diverged", 400);
        env.git(&fx.bare, &["config", "receive.denyNonFastForwards", "true"]);
        let report = push("refs/heads/diverged", "refs/heads/main");
        assert!(!report.is_ok(), "{ctx}: non-ff push accepted: {report:?}");
        assert!(report.unpack.is_ok(), "{ctx}: unpack failed: {report:?}");
        assert_eq!(report.refs.len(), 1, "{ctx}: {report:?}");
        assert!(report.refs[0].result.is_err(), "{ctx}: {report:?}");
        assert_eq!(
            env.rev_parse(&fx.bare, "refs/heads/main"),
            before,
            "{ctx}: ref moved"
        );
        env.fsck(&fx.bare, &format!("{ctx} after pushes"));
    }
}

/// Shallow clone and deepen, compared against git fetching the same refs at
/// the same depth over `file://`.
fn scenario_shallow(kind: Kind) {
    require_git!();
    let env = GitEnv::new(&format!("cli-shallow-{kind:?}"));
    for (algo, v) in matrix(&env, kind) {
        let Some(server) = Server::start(&env, kind, v) else {
            return;
        };
        let ctx = format!("{kind:?} {algo} v{v}");
        let name = format!("s-{algo}-v{v}.git");
        let fx = make_fixture(&env, &name, algo, 10);

        let ours = env.path(&format!("s-{algo}-v{v}-pg"));
        let mut t = server.transport(&env, &name, v);
        let repo = client::clone_with_depth(&ours, &mut *t, Some(1))
            .unwrap_or_else(|e| panic!("{ctx}: shallow clone failed: {e}"));
        drop(repo);

        // git, asked for the very same refs at the same depth.
        let theirs = env.path(&format!("s-{algo}-v{v}-git"));
        let fmt = format!("--object-format={algo}");
        env.git(env.root(), &["init", "-q", &fmt, theirs.to_str().unwrap()]);
        let fetch_oracle = |depth: &str| {
            env.git(
                &theirs,
                &[
                    "fetch",
                    "-q",
                    "--no-tags",
                    depth,
                    &file_url(&fx.bare),
                    "+refs/heads/*:refs/remotes/origin/*",
                    "+refs/tags/*:refs/tags/*",
                ],
            );
        };
        fetch_oracle("--depth=1");
        let compare = |step: &str| {
            let sf = |r: &Path| {
                let mut v: Vec<String> = std::fs::read_to_string(r.join(".git/shallow"))
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_string)
                    .collect();
                v.sort();
                v
            };
            assert_eq!(sf(&ours), sf(&theirs), "{ctx} {step}: shallow boundary");
            assert!(!sf(&ours).is_empty(), "{ctx} {step}: not shallow");
            let commits = |r: &Path| {
                let mut v: Vec<String> = env
                    .git(r, &["rev-list", "--all"])
                    .lines()
                    .map(str::to_string)
                    .collect();
                v.sort();
                v
            };
            assert_eq!(commits(&ours), commits(&theirs), "{ctx} {step}: commits");
            assert_eq!(
                env.refs(&ours, Some("refs/remotes/")),
                env.refs(&theirs, Some("refs/remotes/")),
                "{ctx} {step}: refs"
            );
            env.fsck(&ours, &format!("{ctx} {step}"));
        };
        compare("depth 1");

        let mut repo = Repository::open(&ours).unwrap();
        let mut t = server.transport(&env, &name, v);
        client::fetch_with_depth(&mut repo, &mut *t, Some(3))
            .unwrap_or_else(|e| panic!("{ctx}: deepen failed: {e}"));
        drop(repo);
        fetch_oracle("--depth=3");
        compare("deepen to 3");
    }
}

/// Partial clone (`blob:none`, `tree:0`) and the promisor backfill that
/// materializes a work tree.
fn scenario_partial(kind: Kind) {
    require_git!();
    let env = GitEnv::new(&format!("cli-partial-{kind:?}"));
    for (algo, v) in matrix(&env, kind) {
        let Some(server) = Server::start(&env, kind, v) else {
            return;
        };
        let name = format!("f-{algo}-v{v}.git");
        let fx = make_fixture(&env, &name, algo, 6);
        let hash = if algo == "sha256" {
            HashAlgo::Sha256
        } else {
            HashAlgo::Sha1
        };
        for filter in ["blob:none", "tree:0"] {
            let ctx = format!("{kind:?} {algo} v{v} {filter}");
            let dest = env.path(&format!("f-{algo}-v{v}-{}", filter.replace(':', "-")));
            let mut repo = Repository::init_with(&dest, hash).unwrap();
            let mut t = server.transport(&env, &name, v);
            client::fetch_with_filter(&mut repo, &mut *t, Some(filter.to_string()))
                .unwrap_or_else(|e| panic!("{ctx}: filtered fetch failed: {e}"));
            let main_hex = env.rev_parse(&fx.bare, "refs/heads/main");
            let main = ObjectId::from_hex(hash, &main_hex).unwrap();
            assert!(repo.objects_contains(&main), "{ctx}: commit missing");
            let tree_hex = env.rev_parse(&fx.bare, "refs/heads/main^{tree}");
            let tree = ObjectId::from_hex(hash, &tree_hex).unwrap();
            let blob_hex = env.rev_parse(&fx.bare, "refs/heads/main:README.md");
            let blob = ObjectId::from_hex(hash, &blob_hex).unwrap();
            assert!(
                !repo.objects_contains(&blob),
                "{ctx}: filter ignored (blob sent)"
            );
            if filter == "tree:0" {
                assert!(
                    !repo.objects_contains(&tree),
                    "{ctx}: filter ignored (tree sent)"
                );
            }

            // Backfill + checkout into a separate directory.
            let work = env.path(&format!("f-{algo}-v{v}-{}-wt", filter.replace(':', "-")));
            let mut t = server.transport(&env, &name, v);
            client::checkout_tree(&mut repo, &mut *t, &tree, &work)
                .unwrap_or_else(|e| panic!("{ctx}: promisor checkout failed: {e}"));
            for line in env.git(&fx.bare, &["ls-tree", "-r", "main"]).lines() {
                let (meta, path) = line.split_once('\t').unwrap();
                let oid = meta.split_whitespace().nth(2).unwrap();
                let id = ObjectId::from_hex(hash, oid).unwrap();
                assert!(repo.objects_contains(&id), "{ctx}: {path} not backfilled");
                let on_disk = std::fs::read(work.join(path)).unwrap();
                let want = env.git(&fx.bare, &["cat-file", "blob", oid]);
                assert_eq!(
                    String::from_utf8_lossy(&on_disk).trim_end(),
                    want,
                    "{ctx}: {path} content"
                );
            }
            // Every object the main tree reaches is now present and valid.
            repo.refs()
                .update("refs/heads/main", &puregit::refs::Reference::Direct(main))
                .unwrap();
            drop(repo);
            let listing = env.git(&dest, &["ls-tree", "-r", "-t", "main"]);
            assert_eq!(
                listing,
                env.git(&fx.bare, &["ls-tree", "-r", "-t", "main"]),
                "{ctx}: backfilled tree listing"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(feature = "http")]
#[test]
fn http_clone_fetch() {
    scenario_clone_fetch(Kind::Http);
}

#[cfg(feature = "http")]
#[test]
fn http_push() {
    scenario_push(Kind::Http);
}

#[cfg(feature = "http")]
#[test]
fn http_shallow() {
    scenario_shallow(Kind::Http);
}

#[cfg(feature = "http")]
#[test]
fn http_partial_clone() {
    scenario_partial(Kind::Http);
}

#[test]
fn daemon_clone_fetch() {
    scenario_clone_fetch(Kind::Daemon);
}

#[test]
fn daemon_push() {
    scenario_push(Kind::Daemon);
}

#[test]
fn daemon_shallow() {
    scenario_shallow(Kind::Daemon);
}

#[test]
fn daemon_partial_clone() {
    scenario_partial(Kind::Daemon);
}

#[test]
fn file_clone_fetch() {
    scenario_clone_fetch(Kind::File);
}

#[test]
fn file_push() {
    scenario_push(Kind::File);
}

#[test]
fn file_shallow() {
    scenario_shallow(Kind::File);
}

#[test]
fn file_partial_clone() {
    scenario_partial(Kind::File);
}
