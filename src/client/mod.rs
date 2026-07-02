//! Client porcelain — fetch and clone over a [`Transport`].
//!
//! This drives the sans-IO [`crate::protocol`] negotiation against a concrete
//! [`Transport`] (HTTP, SSH, or the in-process local transport) and applies the
//! result to a local [`Repository`]: discover the remote's refs, ask for the
//! objects we lack, ingest the returned pack, and report what was advertised so
//! the caller can update refs.
//!
//! Today this implements the single-round fetch (send all wants and our current
//! haves, then `done`) that a clone and a simple fetch use. Multi-round `have`
//! negotiation, refspec mapping, pruning, and tag-following are roadmap
//! refinements; [`clone`] composes `init` + `fetch` + ref setup + checkout.

use alloc::vec::Vec;
use std::path::Path;

use crate::error::{Error, Result};
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;
use crate::protocol::{AdvertisedRef, FetchRequest, pktline};
use crate::refs::Reference;
use crate::repository::Repository;
use crate::transport::{Service, Transport};

/// What a [`fetch`] retrieved: the remote's advertised refs and how many objects
/// were ingested.
#[derive(Debug, Clone)]
pub struct FetchOutcome {
    /// Every ref the remote advertised (name → id), for the caller to map into
    /// local refs (e.g. remote-tracking branches, or a clone's refs).
    pub refs: Vec<AdvertisedRef>,
    /// The number of objects received and stored.
    pub received_objects: usize,
}

/// Fetches missing objects for the remote's advertised refs into `repo`.
///
/// Discovers the remote refs, requests every advertised id the local object
/// store lacks (bounded by the ids we already have), ingests the returned pack,
/// and returns the advertisement. Does **not** update any refs — the caller
/// decides how to map remote refs onto local ones (see [`clone`]).
pub fn fetch(repo: &mut Repository, transport: &mut dyn Transport) -> Result<FetchOutcome> {
    let advert = transport.discover(Service::UploadPack)?;

    let wants: Vec<ObjectId> = advert
        .refs
        .iter()
        .filter(|r| !r.id.is_zero() && !repo.objects().contains(&r.id))
        .map(|r| r.id)
        .collect();

    if wants.is_empty() {
        return Ok(FetchOutcome {
            refs: advert.refs,
            received_objects: 0,
        });
    }

    let haves: Vec<ObjectId> = repo.refs().list()?.into_values().collect();

    let mut req = FetchRequest {
        wants,
        haves,
        ..Default::default()
    };
    // Advertise the capabilities we can honor on receive. The server side is
    // lenient about these today; they document intent and forward-compat.
    req.capabilities.add_flag("ofs-delta");
    req.capabilities
        .add_value("object-format", repo.algo().name());

    let request = req.encode()?;
    let response = transport.exchange(Service::UploadPack, &request)?;
    let pack = strip_to_pack(&response)?;

    let ids = repo.ingest_pack(pack)?;
    repo.reload_odb()?;

    Ok(FetchOutcome {
        refs: advert.refs,
        received_objects: ids.len(),
    })
}

/// Clones the remote into a new repository at `dest`.
///
/// Initializes `dest`, fetches all objects, writes the remote's refs under
/// `refs/heads/*` (and `refs/remotes/origin/*` is left to a later refspec
/// layer), points `HEAD`/the default branch at the remote's `HEAD`, and checks
/// out the working tree.
pub fn clone(dest: impl AsRef<Path>, transport: &mut dyn Transport) -> Result<Repository> {
    let mut repo = Repository::init(dest.as_ref())?;
    let outcome = fetch(&mut repo, transport)?;

    // Determine the remote HEAD's target id (the ref it points at), to set our
    // default branch. The minimal advertisement carries HEAD as a ref entry.
    let head_id = outcome.refs.iter().find(|r| r.name == "HEAD").map(|r| r.id);

    // Write every advertised branch/tag as a local ref.
    for r in &outcome.refs {
        if r.name == "HEAD" || r.id.is_zero() {
            continue;
        }
        if r.name.starts_with("refs/") {
            repo.refs().update(&r.name, &Reference::Direct(r.id))?;
        }
    }

    // Point the checked-out branch at the remote HEAD commit and check it out.
    if let Some(id) = head_id {
        // Prefer the branch whose tip equals HEAD; else default to refs/heads/main.
        let branch = outcome
            .refs
            .iter()
            .find(|r| r.id == id && r.name.starts_with("refs/heads/"))
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "refs/heads/main".into());

        repo.refs()
            .update("HEAD", &Reference::Symbolic(branch.clone()))?;
        repo.refs().update(&branch, &Reference::Direct(id))?;

        if let Some(work) = repo.work_tree() {
            let work = work.to_path_buf();
            if let crate::object::Object::Commit(commit) = repo.read_object(&id)? {
                crate::worktree::checkout_tree(&repo, &commit.tree, &work)?;
            }
        }
    }

    Ok(repo)
}

/// Pushes a local ref to the remote.
///
/// Discovers the remote's current refs, builds the ref-update command (creating
/// or fast-forwarding `remote_ref` to the tip of `local_ref`), packs every
/// object the remote lacks, sends the command list plus the pack, and returns
/// the parsed report-status.
pub fn push(
    repo: &Repository,
    transport: &mut dyn Transport,
    local_ref: &str,
    remote_ref: &str,
) -> Result<crate::protocol::ReportStatus> {
    use crate::pack::PackWriter;
    use crate::protocol::{PushRequest, RefUpdateCommand};

    let new = repo.refs().resolve(local_ref)?;

    // The remote's current value for the target ref (zero ⇒ it doesn't exist).
    let advert = transport.discover(Service::ReceivePack)?;
    let old = advert
        .refs
        .iter()
        .find(|r| r.name == remote_ref)
        .map(|r| r.id)
        .unwrap_or_else(|| ObjectId::zero(repo.algo()));

    if old == new {
        // Already up to date — report success without sending a pack.
        return Ok(crate::protocol::ReportStatus {
            unpack: Ok(()),
            refs: alloc::vec![crate::protocol::RefStatus {
                name: remote_ref.into(),
                result: Ok(()),
            }],
        });
    }

    // Objects the remote needs: reachable from `new`, minus what it already has.
    let remote_haves: Vec<ObjectId> = advert
        .refs
        .iter()
        .filter(|r| !r.id.is_zero())
        .map(|r| r.id)
        .collect();
    let to_send = crate::walk::objects_to_send(repo.objects(), &[new], &remote_haves)?;

    let mut writer = PackWriter::new(repo.algo());
    for id in &to_send {
        let (ty, payload) = repo.objects().read(id)?;
        writer.add(ty, &payload);
    }
    let pack = writer.finish()?;

    let mut request = PushRequest {
        commands: alloc::vec![RefUpdateCommand {
            old,
            new,
            name: remote_ref.into(),
        }],
        ..Default::default()
    };
    request.capabilities.add_flag("report-status");
    request
        .capabilities
        .add_value("object-format", repo.algo().name());

    let mut bytes = request.encode()?;
    bytes.extend_from_slice(&pack.pack);

    let response = transport.exchange(Service::ReceivePack, &bytes)?;
    // The report-status comes from an untrusted server; cap the packet count so
    // a flood of tiny pkt-lines cannot force an unbounded allocation (B2).
    let packets = pktline::decode_all_bounded(&response, pktline::MAX_PACKETS)?;
    crate::protocol::ReportStatus::parse(&packets)
}

/// The maximum number of pre-pack pkt-lines [`strip_to_pack`] will scan before
/// giving up. A legitimate upload-pack response precedes the packfile with only
/// a handful of `NAK`/`ACK` (and possibly a few sideband/progress) lines; a
/// hostile server can instead precede the pack with an enormous run of such
/// lines to waste our time (a DoS amplifier — finding B3). This cap, together
/// with the transport's total-response byte cap (finding B1), bounds the work.
const MAX_PREPACK_PKTLINES: usize = 65_536;

/// Skips the leading acknowledgment pkt-lines (`NAK`/`ACK …`) of an upload-pack
/// response and returns the raw packfile that follows (it starts with `PACK`).
///
/// At most [`MAX_PREPACK_PKTLINES`] pre-pack lines are scanned; a response that
/// buries the pack behind more than that is rejected rather than scanned
/// indefinitely.
fn strip_to_pack(response: &[u8]) -> Result<&[u8]> {
    let mut off = 0;
    let mut scanned = 0usize;
    loop {
        if response[off..].starts_with(b"PACK") {
            return Ok(&response[off..]);
        }
        if scanned >= MAX_PREPACK_PKTLINES {
            return Err(Error::Protocol(
                "upload-pack response: too many pre-pack pkt-lines".into(),
            ));
        }
        match pktline::decode(&response[off..])? {
            Some((_, n)) => off += n,
            None => break,
        }
        scanned += 1;
        if off >= response.len() {
            break;
        }
    }
    Err(Error::Protocol(
        "upload-pack response contained no packfile".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_to_pack_finds_pack_after_acks() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&pktline::encode_data(b"NAK\n").unwrap());
        buf.extend_from_slice(b"PACKrest");
        let pack = strip_to_pack(&buf).unwrap();
        assert_eq!(pack, b"PACKrest");
    }

    #[test]
    fn strip_to_pack_stops_after_scan_limit() {
        // A response of many tiny pkt-lines and no PACK must be rejected once the
        // scan limit is reached, not scanned to exhaustion. Build a hair over the
        // limit's worth of minimal 4-byte "0004" empty-data lines.
        let mut buf = Vec::new();
        for _ in 0..(MAX_PREPACK_PKTLINES + 10) {
            // A 4-byte pkt-line with an empty payload ("0004").
            buf.extend_from_slice(&pktline::encode_data(b"").unwrap());
        }
        let err = strip_to_pack(&buf).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
        assert!(alloc::format!("{err}").contains("too many pre-pack"));
    }
}
