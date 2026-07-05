//! Server side — `upload-pack` and `receive-pack` request handlers.
//!
//! The server is the mirror image of the client: given a [`Repository`], it
//! produces the ref advertisement a client reads, then answers the client's
//! negotiation by building a pack ([`upload_pack`], serving fetch/clone) or by
//! applying ref updates from a received pack ([`receive_pack`], accepting push).
//!
//! Like the client, the protocol logic is transport-agnostic and sans-IO: a
//! handler consumes the request pkt-lines and emits response pkt-lines, and the
//! same handler is reused whether it is driven over HTTP (a CGI-style endpoint)
//! or over an SSH `exec` channel. The advertisement builder is implemented;
//! pack generation and ref-update application are built out on the roadmap.

pub mod daemon;
pub mod http;
pub mod lfs;

use alloc::vec::Vec;

use crate::error::Result;
use crate::odb::ObjectDatabase;
use crate::oid::{HashAlgo, ObjectId};
use crate::protocol::pktline::{self, Packet};
use crate::repository::Repository;
use crate::transport::Service;

/// Upper bound on client-held objects offered as thin-pack `REF_DELTA` bases
/// when serving a fetch, bounding the delta search on a large repository.
const THIN_PACK_BASE_CAP: usize = 2000;

/// Builds the v0/v1 reference advertisement a client reads first.
///
/// Emits one pkt-line per ref (`"<oid> <name>"`, with the capabilities appended
/// after a NUL on the first line), terminated by a flush. An empty repository
/// advertises the `capabilities^{}` placeholder so the capability list still
/// reaches the client.
pub fn advertise_refs(
    repo: &Repository,
    service: Service,
    capabilities: &[&str],
) -> Result<Vec<u8>> {
    let refs = repo.refs().list()?;
    let mut out = Vec::new();
    // Advertise `object-format` for a SHA-256 repository so the client parses the
    // 64-hex ids and initializes its clone with the right algorithm. SHA-1 (the
    // default) is left implicit for backward compatibility with plain v0/v1
    // clients that predate the capability.
    let mut caps = capabilities.join(" ");
    if repo.algo() == HashAlgo::Sha256 {
        if !caps.is_empty() {
            caps.push(' ');
        }
        caps.push_str("object-format=sha256");
    }
    let mut first = true;

    // HEAD is advertised first when it resolves.
    if let Ok(head) = repo.head_id() {
        emit_ref(&mut out, &mut first, &head, "HEAD", &caps)?;
    }
    for (name, id) in &refs {
        emit_ref(&mut out, &mut first, id, name, &caps)?;
    }

    if first {
        // No refs at all: advertise the capabilities placeholder.
        let zero = ObjectId::zero(repo.algo());
        let line = alloc::format!("{} capabilities^{{}}\0{}\n", zero.to_hex(), caps);
        out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
    }

    out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
    let _ = service; // v0/v1 advertisement shape is the same for both services
    Ok(out)
}

/// Emits one advertised ref line, attaching the capability list (after a NUL)
/// to the first line only.
fn emit_ref(
    out: &mut Vec<u8>,
    first: &mut bool,
    id: &ObjectId,
    name: &str,
    caps: &str,
) -> Result<()> {
    let line = if *first {
        *first = false;
        alloc::format!("{} {}\0{}\n", id.to_hex(), name, caps)
    } else {
        alloc::format!("{} {}\n", id.to_hex(), name)
    };
    out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
    Ok(())
}

/// Serves a `git-upload-pack` request: given the client's `want`/`have`
/// pkt-line request, computes the objects to send, builds a packfile, and
/// returns the response bytes (`NAK` line followed by the raw pack).
///
/// This is the single-round v0/v1 flow (the client sends `done` immediately, as
/// in a clone or a simple fetch): the server acknowledges with `NAK` and sends a
/// pack of everything reachable from the wants and not from the haves. Multi-
/// round `have` negotiation, sideband progress, and shallow support are
/// roadmap refinements.
pub fn upload_pack(repo: &Repository, request: &[u8]) -> Result<Vec<u8>> {
    use crate::pack::PackWriter;
    use crate::protocol::FetchRequest;
    use crate::protocol::pktline;

    let packets = pktline::decode_all(request)?;
    let req = FetchRequest::parse(repo.algo(), &packets)?;
    if req.wants.is_empty() {
        return Err(crate::error::Error::Protocol(
            "upload-pack: request has no wants".into(),
        ));
    }

    let to_send = crate::walk::objects_to_send(repo.objects(), &req.wants, &req.haves)?;

    let mut writer = PackWriter::new(repo.algo());
    for id in &to_send {
        let (ty, payload) = repo.objects().read(id)?;
        writer.add(ty, &payload);
    }
    // When the client offered `thin-pack`, delta the response against objects it
    // already has (reachable from its `have`s), which it resolves from its own
    // store — a smaller "thin" response. Bounded to keep pack building cheap.
    if req.capabilities.has("thin-pack") && !req.haves.is_empty() {
        let have_closure = crate::walk::reachable_objects(repo.objects(), &req.haves)?;
        for id in have_closure.iter().take(THIN_PACK_BASE_CAP) {
            if let Ok((ty, payload)) = repo.objects().read(id) {
                writer.add_external_base(ty, &payload);
            }
        }
    }
    let pack = writer.finish()?;

    let mut response = pktline::encode_data(b"NAK\n")?;
    response.extend_from_slice(&pack.pack);
    Ok(response)
}

/// Serves a git SSH `exec` of `git-upload-pack '<path>'` over a bidirectional
/// channel: resolves the repository from the command's path, advertises refs,
/// reads the client's `want`/`have` negotiation through `done`, and writes the
/// pack. This is the server-side SSH entry point — wire it into any SSH server's
/// exec handler, passing the channel as `stream` and a path→repo `resolve`.
///
/// `resolve` returning `None` (or a non-upload-pack command) yields an error;
/// the caller decides how to signal it on the channel.
pub fn serve_ssh_upload_pack<S, F>(command: &str, mut stream: S, resolve: F) -> Result<()>
where
    S: std::io::Read + std::io::Write,
    F: FnOnce(&str) -> Option<Repository>,
{
    let (service, path) = parse_ssh_command(command)?;
    if service != Service::UploadPack {
        return Err(crate::error::Error::Protocol(
            "ssh: only git-upload-pack is served here".into(),
        ));
    }
    let repo = resolve(&path).ok_or_else(|| {
        crate::error::Error::Io(alloc::format!("ssh: repository {path:?} not found"))
    })?;

    let advert = advertise_refs(&repo, service, &["ofs-delta", "thin-pack"])?;
    stream
        .write_all(&advert)
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;

    let request = daemon::read_until_done(&mut stream)?;
    if request.is_empty() {
        return Ok(()); // client hung up without wanting anything
    }
    let response = upload_pack(&repo, &request)?;
    stream
        .write_all(&response)
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| crate::error::Error::Io(e.to_string()))
}

/// Parses a git SSH exec command (`git-upload-pack '<path>'` /
/// `git-receive-pack '<path>'`) into the service and the POSIX-single-quoted
/// repository path the client sent.
fn parse_ssh_command(command: &str) -> Result<(Service, alloc::string::String)> {
    let command = command.trim();
    let (service, rest) = if let Some(r) = command.strip_prefix("git-upload-pack") {
        (Service::UploadPack, r)
    } else if let Some(r) = command.strip_prefix("git-receive-pack") {
        (Service::ReceivePack, r)
    } else {
        return Err(crate::error::Error::Protocol(alloc::format!(
            "ssh: unsupported command {command:?}"
        )));
    };
    Ok((service, unquote_posix(rest.trim())))
}

/// Reverses the POSIX single-quote escaping the SSH client applies to the path
/// (`'…'` with `'\''` for an embedded quote). An unquoted argument is returned
/// verbatim.
fn unquote_posix(s: &str) -> alloc::string::String {
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        s[1..s.len() - 1].replace("'\\''", "'")
    } else {
        s.to_string()
    }
}

/// Serves a `git-receive-pack` request (accepts a push): parses the ref-update
/// command list, ingests the received pack, applies the updates after checking
/// each command's precondition, and returns the report-status pkt-lines.
///
/// Preconditions enforced: a create (`old` = zero) requires the ref to be
/// absent; an update requires the ref to equal `old` and (for branches) to be a
/// fast-forward; a deletion (`new` = zero) requires the ref to equal `old`.
///
/// This applies every well-formed update; use [`receive_pack_with`] to install
/// an access-policy hook (the server-side equivalent of a `pre-receive`/`update`
/// hook) that can reject individual updates.
pub fn receive_pack(repo: &Repository, request: &[u8]) -> Result<Vec<u8>> {
    receive_pack_with(repo, request, &|_| Ok(()))
}

/// A pre-receive/update access-policy hook: given a proposed ref-update command,
/// returns `Ok(())` to allow it or `Err(reason)` to reject it. A rejected update
/// is not applied and is reported to the client as `ng <ref> <reason>`.
pub type UpdateHook<'a> =
    dyn Fn(&crate::protocol::RefUpdateCommand) -> core::result::Result<(), String> + 'a;

/// A post-receive notification: called once, after all updates are applied, with
/// the `(ref name, result)` outcome of each. Runs only when the pack unpacked;
/// its return value does not affect the report already sent to the client (it is
/// for side effects — CI triggers, mirror pushes, notifications).
pub type PostReceiveHook<'a> =
    dyn Fn(&[(alloc::string::String, core::result::Result<(), String>)]) + 'a;

/// Like [`receive_pack`], but consults `hook` before applying each ref update so
/// an embedder can enforce access control (branch protection, auth, quotas, …)
/// without reimplementing the pack ingest / precondition logic.
pub fn receive_pack_with(
    repo: &Repository,
    request: &[u8],
    hook: &UpdateHook<'_>,
) -> Result<Vec<u8>> {
    receive_pack_with_hooks(repo, request, hook, &|_| {})
}

/// Like [`receive_pack_with`], but also invokes `post` after the updates are
/// applied (the server-side `post-receive` hook).
pub fn receive_pack_with_hooks(
    repo: &Repository,
    request: &[u8],
    hook: &UpdateHook<'_>,
    post: &PostReceiveHook<'_>,
) -> Result<Vec<u8>> {
    use crate::protocol::{PushRequest, RefStatus, ReportStatus};

    // Split the command section (pkt-lines up to the first flush) from the pack.
    let (command_bytes, pack_start) = split_at_flush(request)?;
    let packets = pktline::decode_all(command_bytes)?;
    let req = PushRequest::parse(repo.algo(), &packets)?;

    // Ingest the packfile if one was sent (a delete-only push has none).
    let pack = &request[pack_start..];
    let unpack = if pack.starts_with(b"PACK") {
        match repo.ingest_pack(pack) {
            Ok(_) => Ok(()),
            Err(e) => Err(alloc::format!("{e}")),
        }
    } else {
        Ok(())
    };

    // Apply each command, recording its outcome. The hook runs first and can
    // veto an update before any precondition check or ref write.
    let mut statuses = Vec::new();
    for cmd in &req.commands {
        let result = if unpack.is_err() {
            Err("unpacker error".to_string())
        } else if let Err(reason) = hook(cmd) {
            Err(reason)
        } else {
            apply_command(repo, cmd)
        };
        statuses.push(RefStatus::new(cmd.name.clone(), result));
    }

    // Post-receive: notify of the applied outcomes (only if the pack unpacked).
    if unpack.is_ok() {
        let outcomes: Vec<(alloc::string::String, core::result::Result<(), String>)> = statuses
            .iter()
            .map(|s| (s.name.clone(), s.result.clone()))
            .collect();
        post(&outcomes);
    }

    ReportStatus {
        unpack,
        refs: statuses,
    }
    .encode()
}

/// Applies one ref-update command after checking its precondition.
fn apply_command(
    repo: &Repository,
    cmd: &crate::protocol::RefUpdateCommand,
) -> core::result::Result<(), String> {
    use crate::refs::Reference;

    if cmd.new.is_zero() {
        // Deletion: require the ref to currently match `old` (zero ⇒ no check).
        if !cmd.old.is_zero() {
            match repo.refs().resolve(&cmd.name).ok() {
                Some(cur) if cur == cmd.old => {}
                Some(_) => return Err("stale info".to_string()),
                None => return Err("ref does not exist".to_string()),
            }
        }
        return repo
            .refs()
            .delete(&cmd.name)
            .map_err(|e| alloc::format!("{e}"));
    }
    // The new object must have arrived in the pack (or already exist).
    if !repo.objects().contains(&cmd.new) {
        return Err("missing necessary objects".to_string());
    }

    let current = repo.refs().resolve(&cmd.name).ok();
    match (cmd.old.is_zero(), current) {
        (true, Some(_)) => return Err("ref already exists".to_string()),
        (true, None) => {}
        (false, Some(cur)) if cur == cmd.old => {
            // The update must be a fast-forward: new must descend from old.
            // (Branch refs only; tag/other refs are not ancestry-checked here.)
            if cmd.name.starts_with("refs/heads/") {
                let ff = crate::walk::is_ancestor(repo.objects(), &cmd.old, &cmd.new)
                    .map_err(|e| alloc::format!("{e}"))?;
                if !ff {
                    return Err("non-fast-forward".to_string());
                }
            }
        }
        (false, Some(_)) => return Err("stale info".to_string()),
        (false, None) => return Err("stale info".to_string()),
    }

    repo.refs()
        .update(&cmd.name, &Reference::Direct(cmd.new))
        .map_err(|e| alloc::format!("{e}"))
}

/// Splits a receive-pack request into `(command_section_bytes, pack_offset)` at
/// the first flush packet that ends the command list.
fn split_at_flush(request: &[u8]) -> Result<(&[u8], usize)> {
    let mut off = 0;
    loop {
        match pktline::decode(&request[off..])? {
            Some((Packet::Flush, n)) => {
                let end = off + n;
                return Ok((&request[..end], end));
            }
            Some((_, n)) => off += n,
            None => {
                return Err(crate::error::Error::Protocol(
                    "receive-pack: command list not flush-terminated".into(),
                ));
            }
        }
    }
}

/// An in-process [`Transport`](crate::transport::Transport) that serves a local
/// [`Repository`] directly through the server handlers — no socket involved.
///
/// This is the loopback transport: it lets the full client/server protocol
/// stack (discovery, negotiation, pack build, pack ingest) be driven and tested
/// end to end without a network, and is a useful building block for embedding a
/// server in-process. The HTTP and SSH transports are the same handlers with
/// real byte movement in front.
pub struct LocalTransport<'a> {
    remote: &'a Repository,
    /// Capabilities the served advertisement announces.
    capabilities: Vec<&'static str>,
}

impl<'a> LocalTransport<'a> {
    /// Creates a loopback transport serving `remote`.
    pub fn new(remote: &'a Repository) -> Self {
        LocalTransport {
            remote,
            capabilities: alloc::vec!["ofs-delta", "report-status", "thin-pack"],
        }
    }
}

impl crate::transport::Transport for LocalTransport<'_> {
    fn discover(&mut self, service: Service) -> Result<crate::protocol::RefAdvertisement> {
        let bytes = advertise_refs(self.remote, service, &self.capabilities)?;
        let packets = pktline::decode_all(&bytes)?;
        crate::protocol::RefAdvertisement::parse(self.remote.algo(), &packets)
    }

    fn exchange(&mut self, service: Service, request: &[u8]) -> Result<Vec<u8>> {
        match service {
            Service::UploadPack => upload_pack(self.remote, request),
            Service::ReceivePack => receive_pack(self.remote, request),
        }
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::object::{Object, Signature};
    use crate::oid::HashAlgo;

    fn sig() -> Signature {
        Signature {
            name: b"Tester".to_vec(),
            email: b"t@example.com".to_vec(),
            time: 1_700_000_000,
            tz: b"+0000".to_vec(),
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-srv-{name}-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn loopback_clone_round_trip() {
        // Build a remote repo with two commits.
        let remote_dir = scratch("remote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("a.txt"), b"hello\n").unwrap();
        std::fs::create_dir_all(remote_dir.join("src")).unwrap();
        std::fs::write(remote_dir.join("src/main.rs"), b"fn main() {}\n").unwrap();
        remote.add_path("a.txt").unwrap();
        remote.add_path("src/main.rs").unwrap();
        remote.commit(b"first\n", sig(), sig()).unwrap();
        std::fs::write(remote_dir.join("a.txt"), b"hello\nworld\n").unwrap();
        remote.add_path("a.txt").unwrap();
        let tip = remote.commit(b"second\n", sig(), sig()).unwrap();

        // Clone it through the in-process transport.
        let dest_dir = scratch("clone");
        let mut transport = LocalTransport::new(&remote);
        let cloned = crate::client::clone(&dest_dir, &mut transport).unwrap();

        // The clone has the tip commit and the full reachable object graph.
        assert_eq!(cloned.algo(), HashAlgo::Sha1);
        assert_eq!(cloned.head_id().unwrap(), tip);
        assert!(cloned.objects().contains(&tip));
        // The remote branch was mapped to a remote-tracking ref.
        assert_eq!(
            cloned.refs().resolve("refs/remotes/origin/main").unwrap(),
            tip
        );

        // The working tree was checked out.
        assert_eq!(
            std::fs::read(dest_dir.join("a.txt")).unwrap(),
            b"hello\nworld\n"
        );
        assert_eq!(
            std::fs::read(dest_dir.join("src/main.rs")).unwrap(),
            b"fn main() {}\n"
        );

        // The cloned commit matches the remote's, byte for byte.
        match cloned.read_object(&tip).unwrap() {
            Object::Commit(c) => assert_eq!(c.summary(), b"second"),
            _ => panic!("tip is not a commit"),
        }

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn loopback_push_round_trip() {
        // A local repo with one commit on main.
        let local_dir = scratch("pushlocal");
        let local = Repository::init(&local_dir).unwrap();
        std::fs::write(local_dir.join("f.txt"), b"content\n").unwrap();
        local.add_path("f.txt").unwrap();
        let tip = local.commit(b"only\n", sig(), sig()).unwrap();

        // An empty bare-ish remote to receive the push.
        let remote_dir = scratch("pushremote");
        let remote = Repository::init(&remote_dir).unwrap();

        // Push local main -> remote refs/heads/main.
        let mut transport = LocalTransport::new(&remote);
        let report =
            crate::client::push(&local, &mut transport, "refs/heads/main", "refs/heads/main")
                .unwrap();
        assert!(report.is_ok(), "push report not ok: {report:?}");

        // Reopen the remote and verify the ref and objects landed.
        let remote2 = Repository::open(&remote_dir).unwrap();
        assert_eq!(remote2.refs().resolve("refs/heads/main").unwrap(), tip);
        assert!(remote2.objects().contains(&tip));
        match remote2.read_object(&tip).unwrap() {
            Object::Commit(c) => assert_eq!(c.summary(), b"only"),
            _ => panic!("pushed tip is not a commit"),
        }

        // A second push of the same ref is a no-op "already up to date".
        let mut t2 = LocalTransport::new(&remote2);
        let report2 =
            crate::client::push(&local, &mut t2, "refs/heads/main", "refs/heads/main").unwrap();
        assert!(report2.is_ok());

        let _ = std::fs::remove_dir_all(&local_dir);
        let _ = std::fs::remove_dir_all(&remote_dir);
    }

    #[test]
    fn clone_adopts_remote_sha256_object_format() {
        // A SHA-256 remote must be cloned as SHA-256: advertise_refs offers
        // object-format=sha256 and clone initializes the destination with it.
        let remote_dir = scratch("sha256remote");
        let remote = Repository::init_with(&remote_dir, HashAlgo::Sha256).unwrap();
        std::fs::write(remote_dir.join("a.txt"), b"hello sha256\n").unwrap();
        remote.add_path("a.txt").unwrap();
        let tip = remote.commit(b"c\n", sig(), sig()).unwrap();
        assert_eq!(remote.algo(), HashAlgo::Sha256);
        assert_eq!(tip.to_hex().len(), 64);

        let dest_dir = scratch("sha256clone");
        let mut transport = LocalTransport::new(&remote);
        let cloned = crate::client::clone(&dest_dir, &mut transport).unwrap();

        assert_eq!(cloned.algo(), HashAlgo::Sha256);
        assert_eq!(cloned.head_id().unwrap(), tip);
        assert!(cloned.objects().contains(&tip));

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn ssh_upload_pack_serves_a_clone() {
        use crate::protocol::FetchRequest;

        let dir = scratch("sshserve");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hi\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let tip = repo.commit(b"c\n", sig(), sig()).unwrap();

        // The client's upload-pack request: want the tip, no haves, done.
        let request = FetchRequest {
            wants: alloc::vec![tip],
            ..Default::default()
        }
        .encode()
        .unwrap();

        // A bidirectional in-memory channel: the handler reads the request and
        // writes the advertisement + pack into `output`.
        struct Pipe {
            input: std::io::Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl std::io::Read for Pipe {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                std::io::Read::read(&mut self.input, b)
            }
        }
        impl std::io::Write for Pipe {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.output.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut pipe = Pipe {
            input: std::io::Cursor::new(request),
            output: Vec::new(),
        };

        serve_ssh_upload_pack("git-upload-pack '/srv/repo'", &mut pipe, |_path| {
            Repository::open(&dir).ok()
        })
        .unwrap();

        // The response ends with NAK + the pack. Locate PACK, explode it, and
        // confirm it carries the tip commit.
        let pack_pos = pipe
            .output
            .windows(4)
            .position(|w| w == b"PACK")
            .expect("response contains a pack");
        // A full clone pack needs no external bases, so the resolver never fires.
        let objs = crate::pack::explode_pack(
            &pipe.output[pack_pos..],
            HashAlgo::Sha1,
            &|id: &ObjectId| {
                Err(crate::error::Error::NotFound(
                    crate::error::ObjectKindHint::Object(id.to_hex()),
                ))
            },
        )
        .unwrap();
        assert!(objs.iter().any(|(id, _, _)| *id == tip));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn thin_pack_fetch_resolves_against_local_objects() {
        // Remote with a first commit.
        let remote_dir = scratch("thinremote");
        let remote = Repository::init(&remote_dir).unwrap();
        let big = alloc::vec![b'a'; 5000];
        std::fs::write(remote_dir.join("f.bin"), &big).unwrap();
        remote.add_path("f.bin").unwrap();
        remote.commit(b"first\n", sig(), sig()).unwrap();

        // Clone it (the client now has the first commit's objects).
        let dest_dir = scratch("thinclone");
        let mut t1 = LocalTransport::new(&remote);
        let mut local = crate::client::clone(&dest_dir, &mut t1).unwrap();

        // Remote makes a second commit with a *similar* large file.
        let mut big2 = big.clone();
        big2[2500] = b'b';
        std::fs::write(remote_dir.join("f.bin"), &big2).unwrap();
        remote.add_path("f.bin").unwrap();
        let tip2 = remote.commit(b"second\n", sig(), sig()).unwrap();

        // Fetch the update: the server may REF_DELTA the new blob against the
        // one the client already has (thin pack); the client must resolve it
        // against its own store and end up with the new objects intact.
        let mut t2 = LocalTransport::new(&remote);
        let got = crate::client::fetch_update(&mut local, &mut t2, "origin", false).unwrap();
        assert!(got >= 1);
        assert!(local.objects().contains(&tip2));
        match local.read_object(&tip2).unwrap() {
            Object::Commit(c) => {
                let tree = match local.read_object(&c.tree).unwrap() {
                    Object::Tree(t) => t,
                    _ => panic!("not a tree"),
                };
                let blob_id = tree.get(b"f.bin").unwrap().id;
                match local.read_object(&blob_id).unwrap() {
                    Object::Blob(b) => assert_eq!(b, big2),
                    _ => panic!("not a blob"),
                }
            }
            _ => panic!("tip2 not a commit"),
        }

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn fetch_update_prunes_deleted_remote_branches() {
        // Remote with two branches.
        let remote_dir = scratch("pruneremote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("a.txt"), b"x\n").unwrap();
        remote.add_path("a.txt").unwrap();
        remote.commit(b"c\n", sig(), sig()).unwrap();
        remote.create_branch("feature", None).unwrap();

        // Clone maps both branches to refs/remotes/origin/*.
        let dest_dir = scratch("pruneclone");
        let mut transport = LocalTransport::new(&remote);
        let mut local = crate::client::clone(&dest_dir, &mut transport).unwrap();
        assert!(local.refs().resolve("refs/remotes/origin/feature").is_ok());

        // Delete the branch on the remote, then fetch --prune.
        remote.refs().delete("refs/heads/feature").unwrap();
        let mut t2 = LocalTransport::new(&remote);
        crate::client::fetch_update(&mut local, &mut t2, "origin", true).unwrap();

        // The stale tracking ref is gone; the surviving one remains.
        assert!(local.refs().resolve("refs/remotes/origin/feature").is_err());
        assert!(local.refs().resolve("refs/remotes/origin/main").is_ok());

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn receive_pack_hook_can_reject_updates() {
        use crate::odb::ObjectDatabase;
        use crate::pack::PackWriter;
        use crate::protocol::{PushRequest, RefUpdateCommand, ReportStatus};

        // A source repo with one commit, and an empty destination to receive it.
        let src_dir = scratch("hooksrc");
        let src = Repository::init(&src_dir).unwrap();
        std::fs::write(src_dir.join("a.txt"), b"x\n").unwrap();
        src.add_path("a.txt").unwrap();
        let tip = src.commit(b"c\n", sig(), sig()).unwrap();

        let dst_dir = scratch("hookdst");
        let dst = Repository::init(&dst_dir).unwrap();

        // Build a receive-pack request: create refs/heads/main = tip, with a pack
        // of everything reachable from it.
        let objs = crate::walk::reachable_objects(src.objects(), &[tip]).unwrap();
        let mut w = PackWriter::new(dst.algo());
        for id in &objs {
            let (ty, p) = src.objects().read(id).unwrap();
            w.add(ty, &p);
        }
        let pack = w.finish().unwrap();
        let mut request = PushRequest {
            commands: alloc::vec![RefUpdateCommand {
                old: ObjectId::zero(dst.algo()),
                new: tip,
                name: "refs/heads/main".into(),
            }],
            ..Default::default()
        };
        request.capabilities.add_flag("report-status");
        let mut bytes = request.encode().unwrap();
        bytes.extend_from_slice(&pack.pack);

        // A hook that rejects everything: the update is reported `ng` and the ref
        // is not created.
        let response =
            receive_pack_with(&dst, &bytes, &|_| Err("blocked by policy".to_string())).unwrap();
        let report = ReportStatus::parse(&pktline::decode_all(&response).unwrap()).unwrap();
        assert!(!report.is_ok());
        assert!(
            report
                .refs
                .iter()
                .any(|r| matches!(&r.result, Err(e) if e.contains("blocked by policy")))
        );
        assert!(dst.refs().resolve("refs/heads/main").is_err());

        // With an allowing pre-hook the same request succeeds, and the
        // post-receive hook observes the applied update.
        let notified = core::cell::RefCell::new(Vec::new());
        let post = |outcomes: &[(alloc::string::String, core::result::Result<(), String>)]| {
            notified.borrow_mut().extend_from_slice(outcomes);
        };
        let response = receive_pack_with_hooks(&dst, &bytes, &|_| Ok(()), &post).unwrap();
        let report = ReportStatus::parse(&pktline::decode_all(&response).unwrap()).unwrap();
        assert!(report.is_ok());
        assert_eq!(dst.refs().resolve("refs/heads/main").unwrap(), tip);
        let seen = notified.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "refs/heads/main");
        assert!(seen[0].1.is_ok());

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    #[test]
    fn push_rejects_non_fast_forward() {
        // Remote already has a commit on main.
        let remote_dir = scratch("ffremote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("a.txt"), b"remote\n").unwrap();
        remote.add_path("a.txt").unwrap();
        remote.commit(b"remote work\n", sig(), sig()).unwrap();

        // Local has a divergent commit on main (different root, not a descendant).
        let local_dir = scratch("fflocal");
        let local = Repository::init(&local_dir).unwrap();
        std::fs::write(local_dir.join("b.txt"), b"local\n").unwrap();
        local.add_path("b.txt").unwrap();
        local.commit(b"local work\n", sig(), sig()).unwrap();

        let mut transport = LocalTransport::new(&remote);
        let report =
            crate::client::push(&local, &mut transport, "refs/heads/main", "refs/heads/main")
                .unwrap();
        // The ref update must be rejected as non-fast-forward.
        assert!(!report.is_ok());
        assert!(
            report
                .refs
                .iter()
                .any(|r| matches!(&r.result, Err(e) if e.contains("fast-forward")))
        );

        let _ = std::fs::remove_dir_all(&local_dir);
        let _ = std::fs::remove_dir_all(&remote_dir);
    }
}
