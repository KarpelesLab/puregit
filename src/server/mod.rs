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

pub mod http;

use alloc::vec::Vec;

use crate::error::Result;
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;
use crate::protocol::pktline::{self, Packet};
use crate::repository::Repository;
use crate::transport::Service;

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
    let caps = capabilities.join(" ");
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
    let pack = writer.finish()?;

    let mut response = pktline::encode_data(b"NAK\n")?;
    response.extend_from_slice(&pack.pack);
    Ok(response)
}

/// Serves a `git-receive-pack` request (accepts a push): parses the ref-update
/// command list, ingests the received pack, applies the updates after checking
/// each command's precondition, and returns the report-status pkt-lines.
///
/// Preconditions enforced: a create (`old` = zero) requires the ref to be
/// absent; an update requires the ref to equal `old` and (for branches) to be a
/// fast-forward; a deletion (`new` = zero) requires the ref to equal `old`.
/// Pre-receive/update hooks are a roadmap refinement.
pub fn receive_pack(repo: &Repository, request: &[u8]) -> Result<Vec<u8>> {
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

    // Apply each command, recording its outcome.
    let mut statuses = Vec::new();
    for cmd in &req.commands {
        let result = if unpack.is_err() {
            Err("unpacker error".to_string())
        } else {
            apply_command(repo, cmd)
        };
        statuses.push(RefStatus {
            name: cmd.name.clone(),
            result,
        });
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
            capabilities: alloc::vec!["ofs-delta"],
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
