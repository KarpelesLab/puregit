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

/// `git-upload-pack` handler state (serves fetch/clone). Built out on the
/// roadmap: parse the client's `want`/`have` lines, run the
/// have-negotiation, and stream a (thin) pack of the wanted history.
#[non_exhaustive]
pub struct UploadPack;

/// `git-receive-pack` handler state (accepts push). Built out on the roadmap:
/// parse the ref-update command list, index and ingest the received pack,
/// apply the updates under lock, and emit the report-status.
#[non_exhaustive]
pub struct ReceivePack;
