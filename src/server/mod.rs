//! Server side — `upload-pack` and `receive-pack` request handlers.
//!
//! The server is the mirror image of the client: given a [`Repository`], it
//! produces the ref advertisement a client reads, then answers the client's
//! negotiation by building a pack ([`upload-pack`](UploadPack), serving
//! fetch/clone) or by applying ref updates from a received pack
//! ([`receive-pack`](ReceivePack), accepting push).
//!
//! Like the client, the protocol logic is transport-agnostic and sans-IO: a
//! handler consumes the request pkt-lines and emits response pkt-lines, and the
//! same handler is reused whether it is driven over HTTP (a CGI-style endpoint)
//! or over an SSH `exec` channel. The advertisement builder is implemented;
//! pack generation and ref-update application are built out on the roadmap.

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

/// `git-receive-pack` handler state (accepts push). Built out on the roadmap:
/// parse the ref-update command list, index and ingest the received pack,
/// apply the updates under lock, and emit the report-status.
#[non_exhaustive]
pub struct ReceivePack;

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
            Service::ReceivePack => Err(crate::error::Error::Unsupported(
                "receive-pack handler not yet implemented".into(),
            )),
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
}
