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

/// Upper bound on the number of receiver-held objects offered as thin-pack
/// `REF_DELTA` bases when pushing. Bounds the delta search so a push against a
/// large remote stays cheap; a modified object usually deltas well against a
/// recent base, so a generous cap captures nearly all the benefit.
const MAX_THIN_PACK_BASES: usize = 2000;

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
    fetch_with_depth(repo, transport, None)
}

/// Like [`fetch`], but truncates history to `depth` commits per ref (a shallow
/// clone/fetch) when `depth` is `Some`.
///
/// The server's shallow boundary is recorded in `.git/shallow` so later history
/// walks stop there rather than erroring on the deliberately-absent parents. A
/// `depth` of `None` is an ordinary full fetch.
pub fn fetch_with_depth(
    repo: &mut Repository,
    transport: &mut dyn Transport,
    depth: Option<u32>,
) -> Result<FetchOutcome> {
    do_fetch(repo, transport, depth, None)
}

/// Like [`fetch`], but requests an object `filter` (a partial clone, e.g.
/// `blob:none`): the server omits the filtered objects and the caller fetches
/// them lazily later via [`fetch_objects`]. `None` is an ordinary full fetch.
pub fn fetch_with_filter(
    repo: &mut Repository,
    transport: &mut dyn Transport,
    filter: Option<String>,
) -> Result<FetchOutcome> {
    do_fetch(repo, transport, None, filter)
}

/// The shared fetch driver behind [`fetch`], [`fetch_with_depth`], and
/// [`fetch_with_filter`].
fn do_fetch(
    repo: &mut Repository,
    transport: &mut dyn Transport,
    depth: Option<u32>,
    filter: Option<String>,
) -> Result<FetchOutcome> {
    let advert = transport.discover(Service::UploadPack)?;

    // Deepening an existing shallow repository re-requests the same tips it
    // already holds (to receive their now-missing ancestors), so a shallow
    // deepen wants every advertised ref even when present; an ordinary fetch
    // wants only the refs it lacks.
    let deepening = depth.is_some() && !repo.shallow()?.is_empty();
    let wants: Vec<ObjectId> = advert
        .refs
        .iter()
        .filter(|r| !r.id.is_zero() && (deepening || !repo.objects().contains(&r.id)))
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
        deepen: depth,
        // When deepening an already-shallow repository, tell the server our
        // current boundary so it does not re-send what we have.
        shallows: repo.shallow()?,
        filter,
        ..Default::default()
    };
    // Request only capabilities the server actually advertised (the negotiated
    // intersection of our preferences with its offer), then echo our
    // object-format so a SHA-256 exchange is unambiguous.
    req.capabilities = advert.capabilities.negotiate_flags(&[
        "ofs-delta",
        "multi_ack",
        "side-band-64k",
        "thin-pack",
    ]);
    req.capabilities
        .add_value("object-format", repo.algo().name());

    let sideband = req.capabilities.has("side-band-64k");
    let request = req.encode()?;
    let response = transport.exchange(Service::UploadPack, &request)?;

    // A shallow fetch's response carries `shallow`/`unshallow` updates before the
    // pack (raw pkt-lines, independent of sideband); apply them to the boundary.
    if depth.is_some() {
        let (add, remove) = parse_shallow_updates(repo.algo(), &response)?;
        let mut boundary: alloc::collections::BTreeSet<ObjectId> =
            repo.shallow()?.into_iter().collect();
        boundary.extend(add);
        for oid in &remove {
            boundary.remove(oid);
        }
        repo.write_shallow(&boundary.into_iter().collect::<Vec<_>>())?;
    }

    // When we negotiated `side-band-64k`, the pack arrives multiplexed on
    // channel 1 and must be demuxed; otherwise it follows the `NAK` line raw.
    let pack = if sideband {
        demux_sideband_pack(&response)?
    } else {
        strip_to_pack(&response)?.to_vec()
    };

    let ids = repo.ingest_pack(&pack)?;
    repo.reload_odb()?;

    Ok(FetchOutcome {
        refs: advert.refs,
        received_objects: ids.len(),
    })
}

/// Fetches a specific set of objects by id and ingests them — the on-demand
/// backfill a partial (promisor) clone uses to obtain the objects its `filter`
/// omitted.
///
/// Objects already present are dropped from the request; the server sends an
/// explicitly-wanted object even when it is reachable from a `have` (so a blob a
/// filtered clone lacks is retrievable). Returns the number of objects received.
pub fn fetch_objects(
    repo: &mut Repository,
    transport: &mut dyn Transport,
    wants: &[ObjectId],
) -> Result<usize> {
    let wanted: Vec<ObjectId> = wants
        .iter()
        .copied()
        .filter(|id| !repo.objects().contains(id))
        .collect();
    if wanted.is_empty() {
        return Ok(0);
    }

    let advert = transport.discover(Service::UploadPack)?;
    let haves: Vec<ObjectId> = repo.refs().list()?.into_values().collect();
    let mut req = FetchRequest {
        wants: wanted,
        haves,
        ..Default::default()
    };
    req.capabilities =
        advert
            .capabilities
            .negotiate_flags(&["ofs-delta", "side-band-64k", "thin-pack"]);
    req.capabilities
        .add_value("object-format", repo.algo().name());

    let sideband = req.capabilities.has("side-band-64k");
    let response = transport.exchange(Service::UploadPack, &req.encode()?)?;
    let pack = if sideband {
        demux_sideband_pack(&response)?
    } else {
        strip_to_pack(&response)?.to_vec()
    };
    let ids = repo.ingest_pack(&pack)?;
    repo.reload_odb()?;
    Ok(ids.len())
}

/// An upper bound on backfill rounds, so a server that keeps failing to deliver
/// a requested object cannot spin the promisor loop forever.
const MAX_BACKFILL_ROUNDS: usize = 64;

/// Backfills every object reachable from tree `tree_id` that the local
/// (partial/promisor) clone is missing, fetching them from `transport` in
/// batched rounds until the tree's closure is complete. Returns the total number
/// of objects received.
///
/// A `--filter` clone omits some objects (e.g. every blob under `blob:none`);
/// this walks the tree as far as the present objects allow, fetches the missing
/// ones ([`walk::missing_tree_objects`](crate::walk::missing_tree_objects) →
/// [`fetch_objects`]), and repeats — so a newly-arrived subtree's own children
/// are discovered on the next round. Each round transfers a whole batch, not one
/// object at a time. Used by [`checkout_tree`] to materialize a partial clone's
/// working tree.
pub fn backfill_tree(
    repo: &mut Repository,
    transport: &mut dyn Transport,
    tree_id: &ObjectId,
) -> Result<usize> {
    let mut total = 0;
    for _ in 0..MAX_BACKFILL_ROUNDS {
        let missing = crate::walk::missing_tree_objects(repo.objects(), tree_id)?;
        if missing.is_empty() {
            return Ok(total);
        }
        let received = fetch_objects(repo, transport, &missing)?;
        if received == 0 {
            // The server delivered none of the requested objects — it cannot
            // satisfy the closure, so stop rather than loop forever.
            return Err(Error::Protocol(
                "promisor backfill: remote did not provide the missing objects".into(),
            ));
        }
        total += received;
    }
    Err(Error::Protocol(
        "promisor backfill: exceeded the round limit".into(),
    ))
}

/// Checks out tree `tree_id` into `dest`, transparently backfilling any object
/// the (partial/promisor) clone is missing from `transport` first — so a
/// `--filter`ed working tree materializes without an explicit backfill call.
///
/// Equivalent to [`backfill_tree`] followed by
/// [`worktree::checkout_tree`](crate::worktree::checkout_tree); on a complete
/// (non-partial) clone the backfill is a no-op and this is a plain checkout.
pub fn checkout_tree(
    repo: &mut Repository,
    transport: &mut dyn Transport,
    tree_id: &ObjectId,
    dest: &Path,
) -> Result<()> {
    backfill_tree(repo, transport, tree_id)?;
    crate::worktree::checkout_tree(repo, tree_id, dest)
}

/// Scans the leading pkt-lines of an upload-pack response for the
/// `shallow <oid>` / `unshallow <oid>` boundary updates (which precede the
/// `NAK`/pack), returning `(added, removed)` and stopping at the pack.
fn parse_shallow_updates(
    algo: crate::oid::HashAlgo,
    response: &[u8],
) -> Result<(Vec<ObjectId>, Vec<ObjectId>)> {
    let (mut add, mut remove) = (Vec::new(), Vec::new());
    let mut off = 0;
    let mut scanned = 0usize;
    while off < response.len() && scanned < MAX_PREPACK_PKTLINES {
        if response[off..].starts_with(b"PACK") {
            break;
        }
        match pktline::decode(&response[off..])? {
            Some((pktline::Packet::Data(d), n)) => {
                if let Some(rest) = d.strip_prefix(b"shallow ") {
                    add.push(parse_oid_line(algo, rest)?);
                } else if let Some(rest) = d.strip_prefix(b"unshallow ") {
                    remove.push(parse_oid_line(algo, rest)?);
                }
                off += n;
            }
            Some((_, n)) => off += n,
            None => break,
        }
        scanned += 1;
    }
    Ok((add, remove))
}

/// Parses an object id from a `shallow`/`unshallow` line's trailing bytes.
fn parse_oid_line(algo: crate::oid::HashAlgo, rest: &[u8]) -> Result<ObjectId> {
    let text =
        core::str::from_utf8(rest).map_err(|_| Error::Protocol("shallow: non-utf8".into()))?;
    ObjectId::from_hex(algo, text.trim())
}

/// Fetches from a remote and updates its remote-tracking refs.
///
/// Discovers and fetches missing objects, then maps each advertised branch to
/// `refs/remotes/<remote>/*` (per the standard fetch refspec) and copies tags to
/// `refs/tags/*`. When `prune` is set, remote-tracking refs under
/// `refs/remotes/<remote>/` that the remote no longer advertises are deleted
/// (`git fetch --prune`). Returns the number of objects received.
pub fn fetch_update(
    repo: &mut Repository,
    transport: &mut dyn Transport,
    remote: &str,
    prune: bool,
) -> Result<usize> {
    let outcome = fetch(repo, transport)?;
    let refspec = crate::remote::Remote::default_fetch(remote);

    // The set of remote-tracking refs the advertisement justifies keeping.
    let mut wanted: alloc::collections::BTreeSet<alloc::string::String> =
        alloc::collections::BTreeSet::new();
    for r in &outcome.refs {
        if r.name == "HEAD" || r.id.is_zero() {
            continue;
        }
        if let Some(tracking) = refspec.dst_for(&r.name) {
            repo.refs().update(&tracking, &Reference::Direct(r.id))?;
            wanted.insert(tracking);
        } else if r.name.starts_with("refs/tags/") {
            repo.refs().update(&r.name, &Reference::Direct(r.id))?;
        }
    }

    if prune {
        let prefix = alloc::format!("refs/remotes/{remote}/");
        let stale: Vec<alloc::string::String> = repo
            .refs()
            .list()?
            .into_keys()
            .filter(|name| name.starts_with(&prefix) && !wanted.contains(name))
            .collect();
        for name in stale {
            repo.refs().delete(&name)?;
        }
    }

    Ok(outcome.received_objects)
}

/// Clones the remote into a new repository at `dest`.
///
/// Initializes `dest`, fetches all objects, maps the remote's branches to
/// remote-tracking refs (`refs/remotes/origin/*`) and copies its tags, points
/// `HEAD`/the default branch at the remote's `HEAD`, and checks out the working
/// tree.
pub fn clone(dest: impl AsRef<Path>, transport: &mut dyn Transport) -> Result<Repository> {
    clone_with_depth(dest, transport, None)
}

/// Like [`clone`], but performs a shallow clone truncated to `depth` commits when
/// `depth` is `Some` (the equivalent of `git clone --depth`).
pub fn clone_with_depth(
    dest: impl AsRef<Path>,
    transport: &mut dyn Transport,
    depth: Option<u32>,
) -> Result<Repository> {
    // Peek the advertisement to learn the remote's object format, so the clone
    // is initialized with the matching algorithm (a SHA-256 remote is cloned as
    // SHA-256). `fetch` re-discovers below; the extra round-trip is acceptable
    // for a one-time clone.
    let algo = transport.discover(Service::UploadPack)?.object_format;
    let mut repo = Repository::init_with(dest.as_ref(), algo)?;
    let outcome = fetch_with_depth(&mut repo, transport, depth)?;

    // Determine the remote HEAD's target id (the ref it points at), to set our
    // default branch. The minimal advertisement carries HEAD as a ref entry.
    let head_id = outcome.refs.iter().find(|r| r.name == "HEAD").map(|r| r.id);

    // Apply the standard fetch layout: branches → refs/remotes/origin/*, tags
    // copied under refs/tags/* (the local refs/heads/<default> is created below
    // for the checked-out branch only).
    let origin_fetch = crate::remote::Remote::default_fetch("origin");
    for r in &outcome.refs {
        if r.name == "HEAD" || r.id.is_zero() {
            continue;
        }
        if let Some(tracking) = origin_fetch.dst_for(&r.name) {
            repo.refs().update(&tracking, &Reference::Direct(r.id))?;
        } else if r.name.starts_with("refs/tags/") {
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
            refs: alloc::vec![crate::protocol::RefStatus::new(remote_ref.into(), Ok(()))],
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
    // Thin pack: offer the objects the remote already has (reachable from its
    // advertised refs) as REF_DELTA bases, so a modified blob/tree can be sent
    // as a delta against the version the remote holds. Bounded so pack building
    // stays cheap; the receiver resolves these bases from its own store.
    if !remote_haves.is_empty() {
        let have_closure = crate::walk::reachable_objects(repo.objects(), &remote_haves)?;
        for id in have_closure.iter().take(MAX_THIN_PACK_BASES) {
            if let Ok((ty, payload)) = repo.objects().read(id) {
                writer.add_external_base(ty, &payload);
            }
        }
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
    // Ask for report-status only if the server offered it, and prefer
    // report-status-v2 when available.
    request.capabilities =
        advert
            .capabilities
            .negotiate_flags(&["report-status-v2", "report-status", "ofs-delta"]);
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

/// Demultiplexes a `side-band-64k` upload-pack response into the raw packfile.
///
/// The response is a sequence of pkt-lines: negotiation lines (`NAK`/`ACK`, which
/// never begin with a band byte) are skipped, then each remaining data packet
/// carries a leading band byte — `1` pack data, `2` progress (discarded), `3` a
/// fatal error (surfaced). The stream ends at the flush-pkt. The concatenated
/// band-1 payloads are the packfile.
fn demux_sideband_pack(response: &[u8]) -> Result<Vec<u8>> {
    use crate::protocol::pktline::Packet;
    let mut off = 0;
    let mut pack = Vec::new();
    while off < response.len() {
        let (packet, n) = match pktline::decode(&response[off..])? {
            Some(pair) => pair,
            None => break,
        };
        if n == 0 {
            break; // defensive: never spin on a zero-length advance
        }
        off += n;
        match packet {
            Packet::Data(payload) => match payload.first() {
                Some(1) => pack.extend_from_slice(&payload[1..]),
                Some(2) => {} // progress on channel 2 — nothing to display here
                Some(3) => {
                    return Err(Error::Protocol(alloc::format!(
                        "upload-pack sideband error: {}",
                        alloc::string::String::from_utf8_lossy(&payload[1..])
                    )));
                }
                // A pre-pack negotiation line (NAK/ACK) or an empty packet.
                _ => {}
            },
            // A flush terminates the stream — but an *early* flush is only a
            // section separator (e.g. after the `shallow` boundary), so ignore
            // it until pack data has begun.
            Packet::Flush if !pack.is_empty() => break,
            _ => {}
        }
    }
    if !pack.starts_with(b"PACK") {
        return Err(Error::Protocol(
            "upload-pack sideband response contained no packfile".into(),
        ));
    }
    Ok(pack)
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
