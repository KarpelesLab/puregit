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
use crate::refs::RefStore;
use crate::repository::Repository;
use crate::transport::Service;
use crate::vfs::Vfs;

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
    advertise_refs_over(repo.objects(), repo.refs(), service, capabilities)
}

/// The storage-generic form of [`advertise_refs`]: builds the advertisement from
/// any [`ObjectDatabase`] (for the hash algorithm) and [`RefStore`], so a server
/// can advertise an in-memory, remote, or otherwise custom backend — not only an
/// on-disk [`Repository`]. The concrete handler delegates here.
pub fn advertise_refs_over<D, V>(
    odb: &D,
    refs: &RefStore<V>,
    service: Service,
    capabilities: &[&str],
) -> Result<Vec<u8>>
where
    D: ObjectDatabase,
    V: Vfs,
{
    let listed = refs.list()?;
    let mut out = Vec::new();
    // Advertise `object-format` for a SHA-256 repository so the client parses the
    // 64-hex ids and initializes its clone with the right algorithm. SHA-1 (the
    // default) is left implicit for backward compatibility with plain v0/v1
    // clients that predate the capability.
    let mut caps = capabilities.join(" ");
    if odb.algo() == HashAlgo::Sha256 {
        if !caps.is_empty() {
            caps.push(' ');
        }
        caps.push_str("object-format=sha256");
    }
    let mut first = true;

    // HEAD is advertised first when it resolves.
    if let Ok(head) = refs.resolve("HEAD") {
        emit_ref(&mut out, &mut first, &head, "HEAD", &caps)?;
    }
    for (name, id) in &listed {
        emit_ref(&mut out, &mut first, id, name, &caps)?;
    }

    if first {
        // No refs at all: advertise the capabilities placeholder.
        let zero = ObjectId::zero(odb.algo());
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
    upload_pack_over(repo.objects(), request)
}

/// The `have`-acknowledgment mode a v0/v1 fetch negotiated, derived from the
/// capabilities on the client's first `want` line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AckMode {
    /// No multi-ack capability: the client sends `done` at once and the server
    /// answers `NAK` then the pack (no incremental acknowledgments).
    Single,
    /// `multi_ack`: each common object is acknowledged `ACK <oid> continue`
    /// during negotiation.
    Multi,
    /// `multi_ack_detailed`: as `multi_ack`, but with `common`/`ready` suffixes
    /// so the client learns when the server can build the pack.
    Detailed,
}

impl AckMode {
    /// Selects the richest mode both sides support (detailed ▷ multi ▷ single).
    fn from_caps(caps: &crate::protocol::Capabilities) -> Self {
        if caps.has("multi_ack_detailed") {
            AckMode::Detailed
        } else if caps.has("multi_ack") {
            AckMode::Multi
        } else {
            AckMode::Single
        }
    }
}

/// Emits the acknowledgment lines for a negotiation round (a `have` batch with
/// no `done`): one `ACK` per object the server also holds (a *common* object),
/// or a single `NAK` when none are common. Under `multi_ack_detailed` the last
/// common object is flagged `ready` (the server can build the pack now), which
/// tells the client to stop negotiating and send `done`.
fn encode_negotiation_acks<D: ObjectDatabase>(
    out: &mut Vec<u8>,
    odb: &D,
    haves: &[ObjectId],
    mode: AckMode,
) -> Result<()> {
    let common: Vec<&ObjectId> = haves.iter().filter(|h| odb.contains(h)).collect();
    if common.is_empty() {
        out.extend_from_slice(&pktline::encode_data(b"NAK\n")?);
        return Ok(());
    }
    for (i, oid) in common.iter().enumerate() {
        let last = i == common.len() - 1;
        let line = match mode {
            AckMode::Detailed if last => alloc::format!("ACK {} ready\n", oid.to_hex()),
            AckMode::Detailed => alloc::format!("ACK {} common\n", oid.to_hex()),
            AckMode::Multi => alloc::format!("ACK {} continue\n", oid.to_hex()),
            // Original single-ack: the first common object is acknowledged plain.
            AckMode::Single => alloc::format!("ACK {}\n", oid.to_hex()),
        };
        out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
    }
    Ok(())
}

/// The storage-generic form of [`upload_pack`]: serves a fetch from any
/// [`ObjectDatabase`], so a custom / in-memory object store can be served
/// directly. The concrete handler delegates here.
pub fn upload_pack_over<D: ObjectDatabase>(odb: &D, request: &[u8]) -> Result<Vec<u8>> {
    use crate::pack::PackWriter;
    use crate::protocol::FetchRequest;
    use crate::protocol::pktline;

    let algo = odb.algo();
    let packets = pktline::decode_all(request)?;
    let req = FetchRequest::parse(algo, &packets)?;
    if req.wants.is_empty() {
        return Err(crate::error::Error::Protocol(
            "upload-pack: request has no wants".into(),
        ));
    }

    let mut response = Vec::new();

    // A `deepen` request is a shallow fetch: truncate history to the requested
    // depth, announce the new shallow boundary, then pack only those objects.
    let to_send = if let Some(depth) = req.deepen {
        let client_shallow: alloc::collections::BTreeSet<ObjectId> =
            req.shallows.iter().copied().collect();
        let plan = plan_deepen(odb, &req.wants, depth, &client_shallow)?;
        for oid in &plan.shallow {
            response.extend_from_slice(&pktline::encode_data(
                alloc::format!("shallow {}\n", oid.to_hex()).as_bytes(),
            )?);
        }
        for oid in &plan.unshallow {
            response.extend_from_slice(&pktline::encode_data(
                alloc::format!("unshallow {}\n", oid.to_hex()).as_bytes(),
            )?);
        }
        // A flush terminates the shallow section, before the ack/pack.
        response.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        // Stateless-HTTP shallow probe: the client sends `deepen` with no `done`
        // first, expecting only the shallow boundary; the pack comes on the
        // follow-up request that carries `done`. Answer the probe and stop.
        if !req.done {
            return Ok(response);
        }
        plan.objects
    } else {
        // Multi-round `have` negotiation: a request that is still negotiating
        // (it carries `have`s but no `done`) is answered with acknowledgments
        // only — the pack waits for the `done` request. The single-round client
        // (clone / simple fetch) sends `done` immediately and skips this.
        if !req.done {
            encode_negotiation_acks(
                &mut response,
                odb,
                &req.haves,
                AckMode::from_caps(&req.capabilities),
            )?;
            return Ok(response);
        }
        let mut set = crate::walk::objects_to_send(odb, &req.wants, &req.haves)?;
        // Always send the explicitly-wanted objects, even when they are also
        // reachable from a `have`: a promisor client re-requests a specific
        // filtered-out blob it already reaches through the commit it holds, and
        // the standard closure would otherwise exclude it and send nothing.
        set.extend(req.wants.iter().copied());
        set
    };

    // A partial-clone `filter` omits objects (e.g. all blobs) *found by
    // traversal* — but never an object the client explicitly `want`ed, which is
    // exactly how a promisor client lazily re-fetches a filtered-out blob (it
    // re-sends the filter yet names the blob in a `want`).
    let filter = crate::object_filter::from_spec(req.filter.as_deref());
    let wanted: alloc::collections::BTreeSet<ObjectId> = req.wants.iter().copied().collect();
    let mut writer = PackWriter::new(algo);
    for id in &to_send {
        let (ty, payload) = odb.read(id)?;
        if ty == crate::object::ObjectType::Blob
            && !filter.keeps_blob(payload.len())
            && !wanted.contains(id)
        {
            continue;
        }
        writer.add(ty, &payload);
    }
    // When the client offered `thin-pack`, delta the response against objects it
    // already has (reachable from its `have`s), which it resolves from its own
    // store — a smaller "thin" response. Bounded to keep pack building cheap.
    //
    // Never for a shallow (`deepen`) client: its `have`s do *not* imply it holds
    // everything reachable from them (its history is truncated at the shallow
    // boundary), so a delta against such a base would be unresolvable.
    if req.capabilities.has("thin-pack") && !req.haves.is_empty() && req.deepen.is_none() {
        let have_closure = crate::walk::reachable_objects(odb, &req.haves)?;
        for id in have_closure.iter().take(THIN_PACK_BASE_CAP) {
            if let Ok((ty, payload)) = odb.read(id) {
                writer.add_external_base(ty, &payload);
            }
        }
    }
    let pack = writer.finish()?;

    // The pre-pack acknowledgment: on `done`, acknowledge the most-recent object
    // the client offered that we also hold (`ACK <oid>`), so a negotiating client
    // learns a common base was found; `NAK` when nothing was common (e.g. a
    // clone). Either way the pack that follows already excludes the haves'
    // closure, so this line is informational — but git warns "no common commits"
    // without it.
    let last_common = req.haves.iter().rev().find(|h| odb.contains(h));
    match last_common {
        Some(oid) => response.extend_from_slice(&pktline::encode_data(
            alloc::format!("ACK {}\n", oid.to_hex()).as_bytes(),
        )?),
        None => response.extend_from_slice(&pktline::encode_data(b"NAK\n")?),
    }
    if req.capabilities.has("side-band-64k") {
        // Multiplex the pack over sideband channel 1, as git does when the
        // client offers `side-band-64k`: the pack is split into pkt-lines each
        // prefixed with the band byte `1`, and the stream ends with a flush.
        // (Channel 2 carries human-readable progress and channel 3 errors; we
        // send neither, only the pack itself.)
        encode_sideband_pack(&mut response, &pack.pack)?;
        response.extend_from_slice(&pktline::encode_control(&Packet::Flush));
    } else {
        response.extend_from_slice(&pack.pack);
    }
    Ok(response)
}

/// Builds the protocol-v2 capability advertisement for `repo` (the greeting a v2
/// client reads before issuing `ls-refs`/`fetch`).
pub fn v2_capability_advertisement(repo: &Repository) -> Result<Vec<u8>> {
    crate::protocol::v2::capability_advertisement(repo.algo())
}

/// Serves one protocol-v2 upload-pack command (`ls-refs` or `fetch`) against
/// `repo`, returning the response pkt-lines. This is the v2 counterpart of
/// [`upload_pack`]; the HTTP handler dispatches here when the client negotiated
/// `Git-Protocol: version=2`.
pub fn serve_v2_upload_pack(repo: &Repository, request: &[u8]) -> Result<Vec<u8>> {
    use crate::protocol::v2;

    let packets = pktline::decode_all(request)?;
    let command = v2::Command::parse(&packets)?;
    match command.name.as_str() {
        "ls-refs" => v2::encode_ls_refs_response(&command, &v2_ref_list(repo)?),
        "fetch" => v2_fetch(repo, &command),
        other => Err(crate::error::Error::Protocol(alloc::format!(
            "v2: unsupported command {other:?}"
        ))),
    }
}

/// Builds the `(name, id, symref-target, peeled)` tuples `ls-refs` advertises:
/// `HEAD` (with its symbolic target) followed by every ref, annotated tags
/// carrying their peeled commit.
fn v2_ref_list(repo: &Repository) -> Result<Vec<crate::protocol::v2::LsRef>> {
    use crate::refs::Reference;
    let mut out = Vec::new();
    if let (Ok(Reference::Symbolic(target)), Ok(id)) =
        (repo.refs().lookup("HEAD"), repo.refs().resolve("HEAD"))
    {
        out.push(("HEAD".to_string(), id, Some(target), peel_tag(repo, &id)));
    }
    for (name, id) in repo.refs().list()? {
        let peeled = peel_tag(repo, &id);
        out.push((name, id, None, peeled));
    }
    Ok(out)
}

/// Follows a chain of annotated tags to the underlying non-tag object, returning
/// it only if `id` was itself a tag (so a plain ref yields `None`).
fn peel_tag(repo: &Repository, id: &ObjectId) -> Option<ObjectId> {
    use crate::object::Object;
    let mut cur = *id;
    while let Ok(Object::Tag(tag)) = repo.read_object(&cur) {
        cur = tag.object;
    }
    (cur != *id).then_some(cur)
}

/// Serves a v2 `fetch` command: negotiates (single round — the client sends
/// `done` for a clone/simple fetch), builds the pack, and frames it in the v2
/// `packfile` section over sideband.
fn v2_fetch(repo: &Repository, command: &crate::protocol::v2::Command) -> Result<Vec<u8>> {
    use crate::protocol::v2;

    let mut args = v2::FetchArgs::parse(repo.algo(), command)?;

    // `ref-in-want`: resolve each `want-ref <name>` to an id, echo it in a
    // `wanted-refs` section, and add it to the want set.
    let mut wanted_refs: Vec<(ObjectId, alloc::string::String)> = Vec::new();
    for name in &args.want_refs {
        if let Ok(id) = repo.refs().resolve(name) {
            wanted_refs.push((id, name.clone()));
            args.wants.push(id);
        }
    }

    if args.wants.is_empty() {
        return Err(crate::error::Error::Protocol(
            "v2 fetch: request has no wants".into(),
        ));
    }

    let filter = crate::object_filter::from_spec(args.filter.as_deref());
    let wanted: alloc::collections::BTreeSet<ObjectId> = args.wants.iter().copied().collect();

    // The object set plus any shallow/unshallow boundary. A `deepen` request is a
    // shallow fetch (or a deepening of an existing shallow clone); otherwise it is
    // an ordinary fetch.
    let plan = if let Some(depth) = args.deepen {
        let client_shallow: alloc::collections::BTreeSet<ObjectId> =
            args.shallows.iter().copied().collect();
        plan_deepen(repo.objects(), &args.wants, depth, &client_shallow)?
    } else {
        let mut objects = crate::walk::objects_to_send(repo.objects(), &args.wants, &args.haves)?;
        // Explicitly-wanted objects are always sent (a promisor blob re-fetch —
        // see `upload_pack_over`).
        objects.extend(args.wants.iter().copied());
        DeepenPlan {
            objects,
            shallow: Vec::new(),
            unshallow: Vec::new(),
        }
    };

    let pack = build_pack(repo, &plan.objects, filter, &wanted)?;

    // Without `done` the client is still negotiating and expects an
    // `acknowledgments` section (with `ready`, since we complete in one round)
    // before the pack; a `done` clone gets the pack directly.
    let ack_section = if args.done {
        None
    } else {
        let common: Vec<ObjectId> = args
            .haves
            .iter()
            .filter(|h| repo.objects().contains(h))
            .copied()
            .collect();
        Some(common)
    };
    v2::encode_fetch_sections(
        ack_section.as_deref(),
        &plan.shallow,
        &plan.unshallow,
        &wanted_refs,
        &pack,
    )
}

/// The object set and shallow-boundary changes for a (possibly deepening)
/// shallow fetch.
struct DeepenPlan {
    objects: alloc::collections::BTreeSet<ObjectId>,
    /// New `shallow <oid>` boundary lines to announce.
    shallow: Vec<ObjectId>,
    /// `unshallow <oid>` lines: commits that were shallow but now have their
    /// history, so the client removes them from its boundary.
    unshallow: Vec<ObjectId>,
}

/// Plans a shallow/deepen fetch: the objects to send and how the shallow
/// boundary changes.
///
/// For an initial shallow clone (`client_shallow` empty) this is a depth-limited
/// walk. For deepening an existing shallow clone, it walks the new depth, sends
/// only the objects the client's current (shallow) view lacks, announces any new
/// boundary, and `unshallow`s the old boundary commits whose parents are now
/// included.
fn plan_deepen<D: crate::odb::ObjectDatabase>(
    odb: &D,
    wants: &[ObjectId],
    depth: u32,
    client_shallow: &alloc::collections::BTreeSet<ObjectId>,
) -> Result<DeepenPlan> {
    let empty = alloc::collections::BTreeSet::new();
    let target = crate::walk::shallow_objects_to_send(odb, wants, depth, &empty)?;

    if client_shallow.is_empty() {
        return Ok(DeepenPlan {
            objects: target.objects,
            shallow: target.shallow.into_iter().collect(),
            unshallow: Vec::new(),
        });
    }

    // What the client already has: its truncated view, bounded at its current
    // shallow commits.
    let have = crate::walk::shallow_objects_to_send(odb, wants, u32::MAX, client_shallow)?;
    let objects = target.objects.difference(&have.objects).copied().collect();
    let shallow = target.shallow.difference(client_shallow).copied().collect();
    let unshallow = client_shallow
        .iter()
        .filter(|c| target.objects.contains(c) && !target.shallow.contains(c))
        .copied()
        .collect();
    Ok(DeepenPlan {
        objects,
        shallow,
        unshallow,
    })
}

/// Builds a packfile from `ids`, omitting blobs the partial-clone `filter`
/// excludes — except any object in `wanted`, which is always included (a
/// promisor client explicitly re-requests a filtered-out blob).
fn build_pack(
    repo: &Repository,
    ids: &alloc::collections::BTreeSet<ObjectId>,
    filter: crate::object_filter::ObjectFilter,
    wanted: &alloc::collections::BTreeSet<ObjectId>,
) -> Result<Vec<u8>> {
    use crate::pack::PackWriter;
    let mut writer = PackWriter::new(repo.algo());
    for id in ids {
        let (ty, payload) = repo.objects().read(id)?;
        if ty == crate::object::ObjectType::Blob
            && !filter.keeps_blob(payload.len())
            && !wanted.contains(id)
        {
            continue;
        }
        writer.add(ty, &payload);
    }
    Ok(writer.finish()?.pack)
}

/// The band byte marking pack data in a `side-band-64k` stream (channel 1).
const SIDEBAND_PACK: u8 = 1;

/// The largest pack payload carried in one `side-band-64k` pkt-line: the max
/// pkt-line length, less the 4-byte length prefix and the 1-byte band marker.
const SIDEBAND_MAX_PAYLOAD: usize = crate::protocol::pktline::MAX_PKTLINE_LEN - 4 - 1;

/// Appends `pack` to `out` as a series of sideband channel-1 pkt-lines. Each
/// line is `[band=1][chunk]`, chunked to fit [`SIDEBAND_MAX_PAYLOAD`].
fn encode_sideband_pack(out: &mut Vec<u8>, pack: &[u8]) -> Result<()> {
    use crate::protocol::pktline;
    for chunk in pack.chunks(SIDEBAND_MAX_PAYLOAD) {
        let mut line = Vec::with_capacity(chunk.len() + 1);
        line.push(SIDEBAND_PACK);
        line.extend_from_slice(chunk);
        out.extend_from_slice(&pktline::encode_data(&line)?);
    }
    Ok(())
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

    let advert = advertise_refs(
        &repo,
        service,
        &[
            "multi_ack_detailed",
            "multi_ack",
            "ofs-delta",
            "thin-pack",
            "side-band-64k",
        ],
    )?;
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

/// Serves a git SSH `exec` of `git-receive-pack '<path>'` over a bidirectional
/// channel: resolves the repository, advertises its refs, reads the client's
/// ref-update command list and (unless the push is delete-only) the packfile,
/// applies the updates, and writes the report-status. This is the push mirror of
/// [`serve_ssh_upload_pack`] — wire it into any SSH server's exec handler.
///
/// Access control is delegated to `hook`, the same `pre-receive`/`update` policy
/// hook [`receive_pack_with`] takes: it can reject individual updates (returning
/// `ng <ref> <reason>` to the client) without the handler reimplementing the
/// ingest or precondition logic. Pass `&|_| Ok(())` to accept every well-formed
/// update.
///
/// `resolve` returning `None` (or a non-receive-pack command) yields an error;
/// the caller decides how to signal it on the channel.
pub fn serve_ssh_receive_pack<S, F>(
    command: &str,
    mut stream: S,
    resolve: F,
    hook: &UpdateHook<'_>,
) -> Result<()>
where
    S: std::io::Read + std::io::Write,
    F: FnOnce(&str) -> Option<Repository>,
{
    let (service, path) = parse_ssh_command(command)?;
    if service != Service::ReceivePack {
        return Err(crate::error::Error::Protocol(
            "ssh: only git-receive-pack is served here".into(),
        ));
    }
    let repo = resolve(&path).ok_or_else(|| {
        crate::error::Error::Io(alloc::format!("ssh: repository {path:?} not found"))
    })?;

    let advert = advertise_refs(
        &repo,
        service,
        &["report-status", "delete-refs", "ofs-delta"],
    )?;
    stream
        .write_all(&advert)
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;

    let request = read_receive_request(&mut stream, repo.algo())?;
    if request.is_empty() {
        return Ok(()); // client sent a flush with no commands — nothing to do
    }
    let response = receive_pack_with(&repo, &request, hook)?;
    stream
        .write_all(&response)
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| crate::error::Error::Io(e.to_string()))
}

/// The largest packfile the streaming SSH `receive-pack` reader will accept, a
/// backstop against an endless push consuming memory without bound.
const MAX_RECEIVE_PACK_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Reads a `receive-pack` request off a stream: the ref-update command pkt-lines
/// through their terminating flush, then — unless every command is a deletion —
/// the packfile that follows. The returned buffer is exactly what
/// [`receive_pack_with`] parses (commands + flush + pack).
///
/// The command list is flush-terminated, so it reads cleanly; the packfile is
/// not, so [`read_full_pack`] delimits it by walking its frames. A delete-only
/// push carries no pack, and reading one would block forever waiting for bytes
/// the client will never send — so the commands are parsed first to decide.
fn read_receive_request<S: std::io::Read>(
    stream: &mut S,
    algo: crate::oid::HashAlgo,
) -> Result<Vec<u8>> {
    use crate::protocol::PushRequest;

    // 1. The command list: raw pkt-lines up to and including the flush-pkt.
    let mut buf = Vec::new();
    let mut packets = 0usize;
    // EOF (an `Err` from `read_pktline`) ends the list — the client hung up with
    // an empty or truncated command section.
    while let Ok((packet, raw)) = daemon::read_pktline(stream) {
        packets += 1;
        if packets > 100_000 {
            return Err(crate::error::Error::Protocol(
                "ssh: receive-pack command count exceeded".into(),
            ));
        }
        buf.extend_from_slice(&raw);
        if matches!(packet, Packet::Flush) {
            break;
        }
    }
    if buf.is_empty() {
        return Ok(buf);
    }

    // 2. Decide whether a pack follows: any create/update (non-zero `new`) means
    //    the client will send one; a delete-only push sends none.
    let (command_bytes, _) = split_at_flush(&buf)?;
    let req = PushRequest::parse(algo, &pktline::decode_all(command_bytes)?)?;
    let expects_pack = req.commands.iter().any(|c| !c.new.is_zero());
    if expects_pack {
        read_full_pack(stream, algo, &mut buf)?;
    }
    Ok(buf)
}

/// Appends a complete packfile read from `stream` onto `buf`, delimiting it by
/// walking its frames (the pack has no on-wire terminator). Reads in chunks,
/// retrying the frame walk as more bytes arrive, and stops the instant the last
/// object and trailing checksum are present — so it never blocks waiting past the
/// pack for bytes the client will not send.
fn read_full_pack<S: std::io::Read>(
    stream: &mut S,
    algo: crate::oid::HashAlgo,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let start = buf.len();
    let id_len = algo.raw_len();
    let mut chunk = [0u8; 65536];

    // Ensure the 12-byte header is present, then read the declared object count.
    fill_to(stream, buf, start + 12, &mut chunk)?;
    if &buf[start..start + 4] != b"PACK" {
        return Err(crate::error::Error::Pack("ssh: expected a packfile".into()));
    }
    let count = u32::from_be_bytes([
        buf[start + 8],
        buf[start + 9],
        buf[start + 10],
        buf[start + 11],
    ]);

    // Walk each frame, reading more bytes whenever the current one is truncated.
    let mut off = 12usize; // relative to `start`
    let mut parsed = 0u32;
    while parsed < count {
        match crate::pack::pack_frame_end(&buf[start..], off, algo) {
            Ok(end) => {
                off = end;
                parsed += 1;
            }
            Err(_) => {
                // Truncated (or not yet valid): pull in more bytes and retry the
                // same frame. A genuinely corrupt pack fails once EOF is reached.
                read_more(stream, buf, &mut chunk)?;
            }
        }
    }

    // The trailing checksum follows the last object.
    fill_to(stream, buf, start + off + id_len, &mut chunk)?;
    buf.truncate(start + off + id_len);
    Ok(())
}

/// Reads from `stream` until `buf` holds at least `target` bytes (or errors on a
/// premature EOF / the size cap).
fn fill_to<S: std::io::Read>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    target: usize,
    chunk: &mut [u8],
) -> Result<()> {
    while buf.len() < target {
        read_more(stream, buf, chunk)?;
    }
    Ok(())
}

/// Reads one chunk from `stream` onto `buf`, erroring on EOF or the size cap.
fn read_more<S: std::io::Read>(stream: &mut S, buf: &mut Vec<u8>, chunk: &mut [u8]) -> Result<()> {
    if buf.len() > MAX_RECEIVE_PACK_BYTES {
        return Err(crate::error::Error::Pack(
            "ssh: receive-pack packfile too large".into(),
        ));
    }
    let n = stream
        .read(chunk)
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;
    if n == 0 {
        return Err(crate::error::Error::Pack(
            "ssh: receive-pack packfile truncated".into(),
        ));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
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
    receive_pack_over(repo.objects(), repo.refs(), request, hook, post)
}

/// The storage-generic form of [`receive_pack_with_hooks`]: accepts a push into
/// any [`ObjectDatabase`] + [`RefStore`], so a custom / in-memory backend can be
/// served. Ingests the pack into `odb`, applies the ref updates to `refs` (with
/// the same preconditions and access-policy `hook`), and returns report-status.
/// The concrete handlers delegate here.
pub fn receive_pack_over<D, V>(
    odb: &D,
    refs: &RefStore<V>,
    request: &[u8],
    hook: &UpdateHook<'_>,
    post: &PostReceiveHook<'_>,
) -> Result<Vec<u8>>
where
    D: ObjectDatabase,
    V: Vfs,
{
    use crate::protocol::{PushRequest, RefStatus, ReportStatus};

    // Split the command section (pkt-lines up to the first flush) from the pack.
    let (command_bytes, pack_start) = split_at_flush(request)?;
    let packets = pktline::decode_all(command_bytes)?;
    let req = PushRequest::parse(odb.algo(), &packets)?;

    // Ingest the packfile if one was sent (a delete-only push has none).
    let pack = &request[pack_start..];
    let unpack = if pack.starts_with(b"PACK") {
        match ingest_into(odb, pack) {
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
            apply_command(odb, refs, cmd)
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

/// Explodes a received packfile and writes every object into `odb`, returning
/// their ids — the storage-generic core of `Repository::ingest_pack`. `REF_DELTA`
/// bases are resolved against `odb` itself (so a thin pack whose bases the
/// receiver already holds resolves).
fn ingest_into<D: ObjectDatabase>(odb: &D, pack: &[u8]) -> Result<Vec<ObjectId>> {
    let resolver = |id: &ObjectId| odb.read(id);
    let objects = crate::pack::explode_pack(pack, odb.algo(), &resolver)?;
    let mut written = Vec::with_capacity(objects.len());
    for (_, ty, payload) in &objects {
        written.push(odb.write(*ty, payload)?);
    }
    Ok(written)
}

/// Applies one ref-update command to `refs` after checking its precondition
/// against `odb` (object presence, fast-forward ancestry).
fn apply_command<D, V>(
    odb: &D,
    refs: &RefStore<V>,
    cmd: &crate::protocol::RefUpdateCommand,
) -> core::result::Result<(), String>
where
    D: ObjectDatabase,
    V: Vfs,
{
    use crate::refs::Reference;

    if cmd.new.is_zero() {
        // Deletion: require the ref to currently match `old` (zero ⇒ no check).
        if !cmd.old.is_zero() {
            match refs.resolve(&cmd.name).ok() {
                Some(cur) if cur == cmd.old => {}
                Some(_) => return Err("stale info".to_string()),
                None => return Err("ref does not exist".to_string()),
            }
        }
        return refs.delete(&cmd.name).map_err(|e| alloc::format!("{e}"));
    }
    // The new object must have arrived in the pack (or already exist).
    if !odb.contains(&cmd.new) {
        return Err("missing necessary objects".to_string());
    }

    let current = refs.resolve(&cmd.name).ok();
    match (cmd.old.is_zero(), current) {
        (true, Some(_)) => return Err("ref already exists".to_string()),
        (true, None) => {}
        (false, Some(cur)) if cur == cmd.old => {
            // The update must be a fast-forward: new must descend from old.
            // (Branch refs only; tag/other refs are not ancestry-checked here.)
            if cmd.name.starts_with("refs/heads/") {
                let ff = crate::walk::is_ancestor(odb, &cmd.old, &cmd.new)
                    .map_err(|e| alloc::format!("{e}"))?;
                if !ff {
                    return Err("non-fast-forward".to_string());
                }
            }
        }
        (false, Some(_)) => return Err("stale info".to_string()),
        (false, None) => return Err("stale info".to_string()),
    }

    refs.update(&cmd.name, &Reference::Direct(cmd.new))
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
            capabilities: alloc::vec!["ofs-delta", "report-status", "thin-pack", "side-band-64k"],
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
    fn plan_deepen_extends_boundary_and_unshallows() {
        use alloc::collections::BTreeSet;

        // A three-commit chain c1 → c2 → c3.
        let dir = scratch("deepen-plan");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("f"), b"1\n").unwrap();
        repo.add_path("f").unwrap();
        let c1 = repo.commit(b"c1\n", sig(), sig()).unwrap();
        std::fs::write(dir.join("f"), b"2\n").unwrap();
        repo.add_path("f").unwrap();
        let c2 = repo.commit(b"c2\n", sig(), sig()).unwrap();
        std::fs::write(dir.join("f"), b"3\n").unwrap();
        repo.add_path("f").unwrap();
        let c3 = repo.commit(b"c3\n", sig(), sig()).unwrap();

        // Initial shallow clone to depth 1: only c3, boundary at c3.
        let p1 = plan_deepen(repo.objects(), &[c3], 1, &BTreeSet::new()).unwrap();
        assert!(p1.objects.contains(&c3) && !p1.objects.contains(&c2));
        assert_eq!(p1.shallow, alloc::vec![c3]);
        assert!(p1.unshallow.is_empty());

        // Deepen that clone to depth 2: send c2, move the boundary to c2, and
        // unshallow c3 (its parent is now present).
        let client_shallow = BTreeSet::from([c3]);
        let p2 = plan_deepen(repo.objects(), &[c3], 2, &client_shallow).unwrap();
        assert!(p2.objects.contains(&c2), "the newly-reached commit is sent");
        assert!(!p2.objects.contains(&c3), "the client already has c3");
        assert!(!p2.objects.contains(&c1), "c1 is still beyond depth 2");
        assert_eq!(p2.shallow, alloc::vec![c2]);
        assert_eq!(p2.unshallow, alloc::vec![c3]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loopback_deepen_extends_a_shallow_clone() {
        // A remote with a three-commit chain.
        let remote_dir = scratch("deepen-remote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"1\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let c1 = remote.commit(b"c1\n", sig(), sig()).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"2\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let c2 = remote.commit(b"c2\n", sig(), sig()).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"3\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let tip = remote.commit(b"c3\n", sig(), sig()).unwrap();

        // Shallow-clone to depth 1: only the tip, boundary at the tip.
        let dest = scratch("deepen-clone");
        let mut transport = LocalTransport::new(&remote);
        let mut cloned = crate::client::clone_with_depth(&dest, &mut transport, Some(1)).unwrap();
        assert!(cloned.objects().contains(&tip) && !cloned.objects().contains(&c2));
        assert_eq!(cloned.shallow().unwrap(), alloc::vec![tip]);

        // Deepen to depth 2: fetch c2, move the boundary to c2 (the tip is
        // unshallowed).
        let mut transport = LocalTransport::new(&remote);
        crate::client::fetch_with_depth(&mut cloned, &mut transport, Some(2)).unwrap();
        assert!(cloned.objects().contains(&c2), "the deeper commit arrived");
        assert!(!cloned.objects().contains(&c1), "still beyond depth 2");
        assert_eq!(cloned.shallow().unwrap(), alloc::vec![c2]);

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn loopback_partial_clone_then_backfill() {
        use crate::object::{Object, ObjectType};

        // A remote with a commit whose tree references a blob.
        let remote_dir = scratch("partial-remote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"blob contents here\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let tip = remote.commit(b"c\n", sig(), sig()).unwrap();
        let blob = crate::walk::reachable_objects(remote.objects(), &[tip])
            .unwrap()
            .into_iter()
            .find(|id| matches!(remote.objects().read(id), Ok((ObjectType::Blob, _))))
            .unwrap();

        // A partial fetch with `blob:none`: the commit and tree arrive, the blob
        // does not.
        let dest = scratch("partial-clone");
        let mut repo = Repository::init(&dest).unwrap();
        let mut transport = LocalTransport::new(&remote);
        crate::client::fetch_with_filter(&mut repo, &mut transport, Some("blob:none".into()))
            .unwrap();
        assert!(repo.objects().contains(&tip));
        assert!(!repo.objects().contains(&blob), "blob:none omits the blob");

        // Backfilling the blob on demand retrieves it with the right content.
        let mut transport = LocalTransport::new(&remote);
        let received = crate::client::fetch_objects(&mut repo, &mut transport, &[blob]).unwrap();
        assert_eq!(received, 1);
        assert!(repo.objects().contains(&blob));
        match repo.read_object(&blob).unwrap() {
            Object::Blob(b) => assert_eq!(b, b"blob contents here\n"),
            _ => panic!("not a blob"),
        }

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn loopback_partial_clone_transparent_checkout() {
        use crate::object::Object;

        // A remote whose tree spans a top-level file and a subdirectory, so the
        // backfill must recurse through a subtree to reach every blob.
        let remote_dir = scratch("promisor-remote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("top.txt"), b"top level\n").unwrap();
        std::fs::create_dir_all(remote_dir.join("sub")).unwrap();
        std::fs::write(remote_dir.join("sub/inner.txt"), b"nested content\n").unwrap();
        remote.add_path("top.txt").unwrap();
        remote.add_path("sub/inner.txt").unwrap();
        let tip = remote.commit(b"c\n", sig(), sig()).unwrap();
        let tree = match remote.read_object(&tip).unwrap() {
            Object::Commit(c) => c.tree,
            _ => panic!("tip is not a commit"),
        };

        // Partial-clone with `blob:none`: commit and both trees arrive, no blobs.
        let dest = scratch("promisor-clone");
        let mut repo = Repository::init(&dest).unwrap();
        let mut transport = LocalTransport::new(&remote);
        crate::client::fetch_with_filter(&mut repo, &mut transport, Some("blob:none".into()))
            .unwrap();
        // Every blob is missing at this point.
        let missing = crate::walk::missing_tree_objects(repo.objects(), &tree).unwrap();
        assert_eq!(missing.len(), 2, "both blobs are absent after blob:none");

        // A transparent checkout backfills the blobs and materializes the tree.
        let mut transport = LocalTransport::new(&remote);
        crate::client::checkout_tree(&mut repo, &mut transport, &tree, &dest).unwrap();

        assert_eq!(std::fs::read(dest.join("top.txt")).unwrap(), b"top level\n");
        assert_eq!(
            std::fs::read(dest.join("sub/inner.txt")).unwrap(),
            b"nested content\n"
        );
        // The closure is now complete locally.
        assert!(
            crate::walk::missing_tree_objects(repo.objects(), &tree)
                .unwrap()
                .is_empty()
        );

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn loopback_multi_round_negotiation_fetches_new_commits() {
        // A remote with two commits; a client cloned at that state.
        let remote_dir = scratch("negotiate-remote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"one\n").unwrap();
        remote.add_path("f.txt").unwrap();
        remote.commit(b"one\n", sig(), sig()).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"two\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let c2 = remote.commit(b"two\n", sig(), sig()).unwrap();

        let dest = scratch("negotiate-clone");
        let mut transport = LocalTransport::new(&remote);
        let mut repo = crate::client::clone(&dest, &mut transport).unwrap();
        assert!(repo.objects().contains(&c2));

        // The remote advances by one commit.
        std::fs::write(remote_dir.join("f.txt"), b"three\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let c3 = remote.commit(b"three\n", sig(), sig()).unwrap();

        // A multi-round negotiated fetch: the client offers c2 as a `have`, the
        // server acknowledges it common/ready, and only c3's objects arrive.
        let mut transport = LocalTransport::new(&remote);
        let before = crate::walk::reachable_objects(repo.objects(), &[c2])
            .unwrap()
            .len();
        let outcome = crate::client::fetch_negotiated(&mut repo, &mut transport).unwrap();
        assert!(repo.objects().contains(&c3), "the new commit arrived");
        // The pack carried only the delta (the new commit, its tree, its blob) —
        // far fewer than the full closure, since c2 was recognized as common.
        assert!(
            outcome.received_objects < before,
            "negotiation truncated the pack to the new objects ({} received, {} already present)",
            outcome.received_objects,
            before
        );
        assert_eq!(outcome.received_objects, 3, "new commit + tree + blob");

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn loopback_shallow_clone_truncates_history() {
        // A remote with three linear commits.
        let remote_dir = scratch("shallow-remote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"one\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let c1 = remote.commit(b"one\n", sig(), sig()).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"two\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let c2 = remote.commit(b"two\n", sig(), sig()).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"three\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let tip = remote.commit(b"three\n", sig(), sig()).unwrap();

        // Shallow-clone to depth 1 through the in-process transport.
        let dest = scratch("shallow-clone");
        let mut transport = LocalTransport::new(&remote);
        let cloned = crate::client::clone_with_depth(&dest, &mut transport, Some(1)).unwrap();

        // Only the tip is present; the older history is truncated.
        assert!(cloned.objects().contains(&tip));
        assert!(!cloned.objects().contains(&c2));
        assert!(!cloned.objects().contains(&c1));
        // The shallow boundary was recorded at the tip.
        assert_eq!(cloned.shallow().unwrap(), alloc::vec![tip]);

        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&dest);
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
    fn partial_clone_filter_omits_blobs_but_keeps_wanted_ones() {
        use crate::object::ObjectType;
        use crate::protocol::{Capabilities, FetchRequest};

        // A remote with a commit whose tree references a blob.
        let remote_dir = scratch("filter");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"file contents\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let tip = remote.commit(b"only\n", sig(), sig()).unwrap();
        // The blob id (the only blob reachable from the tip).
        let blob = crate::walk::reachable_objects(remote.objects(), &[tip])
            .unwrap()
            .into_iter()
            .find(|id| matches!(remote.objects().read(id), Ok((ObjectType::Blob, _))))
            .unwrap();

        // Helper: explode an upload-pack response's pack and collect object types.
        let explode = |resp: &[u8]| {
            let at = resp.windows(4).position(|w| w == b"PACK").unwrap();
            let resolver = |id: &crate::oid::ObjectId| remote.objects().read(id);
            crate::pack::explode_pack(&resp[at..], remote.algo(), &resolver).unwrap()
        };

        // A `blob:none` fetch of the tip: the pack carries the commit and tree
        // but no blob.
        let mut req = FetchRequest {
            wants: alloc::vec![tip],
            ..Default::default()
        };
        req.filter = Some("blob:none".into());
        let resp = upload_pack(&remote, &req.encode().unwrap()).unwrap();
        let types: Vec<ObjectType> = explode(&resp).iter().map(|(_, t, _)| *t).collect();
        assert!(types.contains(&ObjectType::Commit));
        assert!(types.contains(&ObjectType::Tree));
        assert!(
            !types.contains(&ObjectType::Blob),
            "blob:none must omit blobs"
        );

        // A promisor re-fetch: the same filter, but the blob is explicitly wanted
        // — it must be sent despite the filter.
        let mut req2 = FetchRequest {
            wants: alloc::vec![blob],
            haves: alloc::vec![tip],
            ..Default::default()
        };
        req2.filter = Some("blob:none".into());
        req2.capabilities = Capabilities::new();
        let resp2 = upload_pack(&remote, &req2.encode().unwrap()).unwrap();
        assert!(
            explode(&resp2)
                .iter()
                .any(|(id, ty, _)| *ty == ObjectType::Blob && *id == blob),
            "an explicitly-wanted blob must be sent even under blob:none"
        );

        let _ = std::fs::remove_dir_all(&remote_dir);
    }

    #[test]
    fn upload_pack_acknowledges_common_haves_in_a_negotiation_round() {
        use crate::protocol::{Capabilities, FetchRequest};

        let remote_dir = scratch("ack-remote");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"x\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let tip = remote.commit(b"c\n", sig(), sig()).unwrap();

        // A negotiation round (no `done`) offering the tip as a `have`: the
        // server holds it, so it acknowledges it `ready` and sends no pack.
        let req = FetchRequest {
            wants: alloc::vec![tip],
            haves: alloc::vec![tip],
            capabilities: Capabilities::parse("multi_ack_detailed"),
            ..Default::default()
        };
        let resp = upload_pack(&remote, &req.encode_negotiation().unwrap()).unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.contains(&alloc::format!("ACK {} ready", tip.to_hex())),
            "the common have is acknowledged ready: {text:?}"
        );
        assert!(
            !resp.windows(4).any(|w| w == b"PACK"),
            "a negotiation round sends no pack"
        );

        // A negotiation round offering only an unknown object: no common → NAK.
        let unknown = ObjectId::from_hex(remote.algo(), &"3".repeat(40)).unwrap();
        let req = FetchRequest {
            wants: alloc::vec![tip],
            haves: alloc::vec![unknown],
            capabilities: Capabilities::parse("multi_ack_detailed"),
            ..Default::default()
        };
        let resp = upload_pack(&remote, &req.encode_negotiation().unwrap()).unwrap();
        assert!(
            String::from_utf8_lossy(&resp).contains("NAK"),
            "no common object yields NAK"
        );
        assert!(!resp.windows(4).any(|w| w == b"PACK"));

        let _ = std::fs::remove_dir_all(&remote_dir);
    }

    #[test]
    fn upload_pack_multiplexes_over_sideband_when_offered() {
        use crate::protocol::pktline::{self, Packet};
        use crate::protocol::{Capabilities, FetchRequest};

        // A remote with one commit.
        let remote_dir = scratch("sideband");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"hi\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let tip = remote.commit(b"only\n", sig(), sig()).unwrap();

        // Build a want for the tip, once with side-band-64k and once without.
        let base = FetchRequest {
            wants: alloc::vec![tip],
            haves: Vec::new(),
            ..Default::default()
        };
        let mut sb = base.clone();
        sb.capabilities = Capabilities::new();
        sb.capabilities.add_flag("side-band-64k");

        // Without sideband: NAK line then the raw pack begins with "PACK".
        let plain = upload_pack(&remote, &base.encode().unwrap()).unwrap();
        let (first, n) = pktline::decode(&plain).unwrap().unwrap();
        assert_eq!(first, Packet::Data(b"NAK\n".to_vec()));
        assert!(plain[n..].starts_with(b"PACK"), "raw pack after NAK");

        // With sideband: every post-NAK data packet is band 1, and demuxing the
        // channel-1 payloads reconstructs the same packfile, terminated by flush.
        let muxed = upload_pack(&remote, &sb.encode().unwrap()).unwrap();
        let mut off = pktline::decode(&muxed).unwrap().unwrap().1; // skip NAK
        let mut pack = Vec::new();
        let mut saw_flush = false;
        while off < muxed.len() {
            let (packet, adv) = pktline::decode(&muxed[off..]).unwrap().unwrap();
            off += adv;
            match packet {
                Packet::Data(p) => {
                    assert_eq!(p.first(), Some(&1u8), "pack must ride channel 1");
                    pack.extend_from_slice(&p[1..]);
                }
                Packet::Flush => {
                    saw_flush = true;
                    break;
                }
                other => panic!("unexpected packet: {other:?}"),
            }
        }
        assert!(saw_flush, "sideband stream ends with a flush");
        assert!(pack.starts_with(b"PACK"), "demuxed bytes are a packfile");
        assert_eq!(pack, plain[n..], "sideband and raw packs are identical");

        let _ = std::fs::remove_dir_all(&remote_dir);
    }

    /// A bidirectional in-memory channel standing in for an SSH exec channel:
    /// reads drain a preloaded request, writes accumulate the server's output.
    struct MockChannel {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        /// Max bytes returned per read (0 ⇒ unlimited); a small value forces the
        /// pack to arrive in fragments, exercising the frame-walk retry loop.
        chunk_limit: usize,
    }

    impl MockChannel {
        fn new(input: Vec<u8>) -> Self {
            MockChannel {
                input: std::io::Cursor::new(input),
                output: Vec::new(),
                chunk_limit: 0,
            }
        }
    }

    impl std::io::Read for MockChannel {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.chunk_limit == 0 {
                std::io::Read::read(&mut self.input, buf)
            } else {
                let cap = self.chunk_limit.min(buf.len());
                std::io::Read::read(&mut self.input, &mut buf[..cap])
            }
        }
    }

    impl std::io::Write for MockChannel {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Encodes a `git-receive-pack` request (command list + flush, then the pack
    /// for any create/update) exactly as the client transmits it.
    fn encode_push_request(
        local: &Repository,
        commands: Vec<crate::protocol::RefUpdateCommand>,
        remote_haves: &[crate::oid::ObjectId],
    ) -> Vec<u8> {
        use crate::pack::PackWriter;
        use crate::protocol::PushRequest;

        let wants: Vec<crate::oid::ObjectId> = commands
            .iter()
            .filter(|c| !c.new.is_zero())
            .map(|c| c.new)
            .collect();
        let mut request = PushRequest {
            commands,
            ..Default::default()
        };
        request.capabilities.add_flag("report-status");
        let mut bytes = request.encode().unwrap();

        if !wants.is_empty() {
            let to_send =
                crate::walk::objects_to_send(local.objects(), &wants, remote_haves).unwrap();
            let mut writer = PackWriter::new(local.algo());
            for id in &to_send {
                let (ty, payload) = local.objects().read(id).unwrap();
                writer.add(ty, &payload);
            }
            bytes.extend_from_slice(&writer.finish().unwrap().pack);
        }
        bytes
    }

    #[test]
    fn v2_ref_in_want_resolves_and_echoes_the_ref() {
        use crate::protocol::v2;

        let remote_dir = scratch("refinwant");
        let remote = Repository::init(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("f.txt"), b"x\n").unwrap();
        remote.add_path("f.txt").unwrap();
        let tip = remote.commit(b"c\n", sig(), sig()).unwrap();

        // A v2 fetch that names the ref by name rather than by oid.
        let request = v2::encode_command(
            "fetch",
            &[],
            &["want-ref refs/heads/main".to_string(), "done".to_string()],
        )
        .unwrap();
        let response = serve_v2_upload_pack(&remote, &request).unwrap();
        let text = String::from_utf8_lossy(&response);

        // The response carries a wanted-refs section resolving the name to tip,
        // and the packfile that satisfies it.
        assert!(text.contains("wanted-refs"), "wanted-refs section present");
        assert!(
            text.contains(&alloc::format!("{} refs/heads/main", tip.to_hex())),
            "the ref resolves to its tip"
        );
        assert!(response.windows(4).any(|w| w == b"PACK"), "pack present");

        let _ = std::fs::remove_dir_all(&remote_dir);
    }

    #[test]
    fn serves_fetch_from_a_non_repository_backend() {
        use crate::odb::MemoryOdb;
        use crate::protocol::{FetchRequest, RefAdvertisement};
        use crate::refs::Reference;
        use crate::vfs::StdFs;

        // Build a real object graph on disk, then stage it into an in-memory
        // object store paired with a *separate* on-disk ref store — a split a
        // concrete `Repository` (one `Vfs` for both) can't express, proving the
        // handlers are generic over storage.
        let src_dir = scratch("generic-src");
        let src = Repository::init(&src_dir).unwrap();
        std::fs::write(src_dir.join("a.txt"), b"alpha\n").unwrap();
        src.add_path("a.txt").unwrap();
        let tip = src.commit(b"only\n", sig(), sig()).unwrap();

        let mem = MemoryOdb::new(src.algo());
        for id in crate::walk::reachable_objects(src.objects(), &[tip]).unwrap() {
            let (ty, payload) = src.objects().read(&id).unwrap();
            mem.write(ty, &payload).unwrap();
        }

        let refs_dir = scratch("generic-refs");
        let refs = RefStore::new(StdFs::new(&refs_dir), src.algo());
        refs.update("refs/heads/main", &Reference::Direct(tip))
            .unwrap();
        refs.update("HEAD", &Reference::Symbolic("refs/heads/main".into()))
            .unwrap();

        // Advertise over the generic surface: HEAD and the branch resolve to tip.
        let advert_bytes =
            advertise_refs_over(&mem, &refs, Service::UploadPack, &["ofs-delta"]).unwrap();
        let advert =
            RefAdvertisement::parse(mem.algo(), &pktline::decode_all(&advert_bytes).unwrap())
                .unwrap();
        assert!(
            advert
                .refs
                .iter()
                .any(|r| r.name == "refs/heads/main" && r.id == tip),
            "advertisement must list the branch at tip"
        );

        // Serve a fetch for the tip; the returned pack carries the whole graph.
        let req = FetchRequest {
            wants: alloc::vec![tip],
            haves: Vec::new(),
            ..Default::default()
        };
        let response = upload_pack_over(&mem, &req.encode().unwrap()).unwrap();
        // The response is a `NAK` pkt-line followed by the raw pack (no sideband
        // was negotiated); locate the packfile after it.
        let pack_at = response
            .windows(4)
            .position(|w| w == b"PACK")
            .expect("response contains a packfile");
        let pack = &response[pack_at..];
        let resolver = |id: &crate::oid::ObjectId| mem.read(id);
        let exploded = crate::pack::explode_pack(pack, mem.algo(), &resolver).unwrap();
        assert!(
            exploded.iter().any(|(id, _, _)| *id == tip),
            "served pack must contain the requested commit"
        );

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&refs_dir);
    }

    #[test]
    fn ssh_receive_pack_applies_a_push() {
        use crate::protocol::RefUpdateCommand;

        // A local repo with one commit; an empty remote to receive it.
        let local_dir = scratch("sshpush-local");
        let local = Repository::init(&local_dir).unwrap();
        std::fs::write(local_dir.join("f.txt"), b"content\n").unwrap();
        local.add_path("f.txt").unwrap();
        let tip = local.commit(b"only\n", sig(), sig()).unwrap();

        let remote_dir = scratch("sshpush-remote");
        Repository::init(&remote_dir).unwrap();

        // The client bytes for `create refs/heads/main -> tip`, with the pack.
        let request = encode_push_request(
            &local,
            alloc::vec![RefUpdateCommand {
                old: crate::oid::ObjectId::zero(local.algo()),
                new: tip,
                name: "refs/heads/main".into(),
            }],
            &[],
        );

        // Drive the SSH receive-pack handler over the mock channel.
        let remote_path = remote_dir.clone();
        let mut ch = MockChannel::new(request);
        serve_ssh_receive_pack(
            "git-receive-pack 'repo.git'",
            &mut ch,
            |_path| Some(Repository::open(&remote_path).unwrap()),
            &|_| Ok(()),
        )
        .unwrap();

        // The report acknowledges the ref, and the ref + objects landed.
        assert!(
            ch.output.windows(3).any(|w| w == b"ok "),
            "report-status should contain an ok line: {:?}",
            String::from_utf8_lossy(&ch.output)
        );
        let remote = Repository::open(&remote_dir).unwrap();
        assert_eq!(remote.refs().resolve("refs/heads/main").unwrap(), tip);
        assert!(remote.objects().contains(&tip));

        let _ = std::fs::remove_dir_all(&local_dir);
        let _ = std::fs::remove_dir_all(&remote_dir);
    }

    #[test]
    fn ssh_receive_pack_reassembles_a_fragmented_pack() {
        use crate::protocol::RefUpdateCommand;

        // A local repo with several files across two commits, so the pack holds
        // multiple objects (blobs, trees, commits) and is comfortably larger than
        // the tiny per-read chunk the mock will hand out.
        let local_dir = scratch("sshfrag-local");
        let local = Repository::init(&local_dir).unwrap();
        for i in 0..8 {
            std::fs::write(
                local_dir.join(alloc::format!("f{i}.txt")),
                alloc::format!("payload number {i}, padded for bulk ----------\n").repeat(4),
            )
            .unwrap();
            local.add_path(&alloc::format!("f{i}.txt")).unwrap();
        }
        local.commit(b"bulk one\n", sig(), sig()).unwrap();
        std::fs::write(local_dir.join("f0.txt"), b"changed\n").unwrap();
        local.add_path("f0.txt").unwrap();
        let tip = local.commit(b"bulk two\n", sig(), sig()).unwrap();

        let remote_dir = scratch("sshfrag-remote");
        Repository::init(&remote_dir).unwrap();

        let request = encode_push_request(
            &local,
            alloc::vec![RefUpdateCommand {
                old: crate::oid::ObjectId::zero(local.algo()),
                new: tip,
                name: "refs/heads/main".into(),
            }],
            &[],
        );
        // Deliver the whole request 7 bytes at a time: the pack spans many reads,
        // so `read_full_pack` must retry each frame until enough bytes arrive.
        let remote_path = remote_dir.clone();
        let mut ch = MockChannel::new(request);
        ch.chunk_limit = 7;
        serve_ssh_receive_pack(
            "git-receive-pack 'repo.git'",
            &mut ch,
            |_path| Some(Repository::open(&remote_path).unwrap()),
            &|_| Ok(()),
        )
        .unwrap();

        let remote = Repository::open(&remote_dir).unwrap();
        assert_eq!(remote.refs().resolve("refs/heads/main").unwrap(), tip);
        assert!(remote.objects().contains(&tip));

        let _ = std::fs::remove_dir_all(&local_dir);
        let _ = std::fs::remove_dir_all(&remote_dir);
    }

    #[test]
    fn ssh_receive_pack_handles_delete_only_push_without_a_pack() {
        use crate::protocol::RefUpdateCommand;
        use crate::refs::Reference;

        // A remote with a branch to delete.
        let local_dir = scratch("sshdel-local");
        let local = Repository::init(&local_dir).unwrap();
        std::fs::write(local_dir.join("f.txt"), b"x\n").unwrap();
        local.add_path("f.txt").unwrap();
        let tip = local.commit(b"c\n", sig(), sig()).unwrap();

        let remote_dir = scratch("sshdel-remote");
        let remote = Repository::init(&remote_dir).unwrap();
        remote
            .refs()
            .update("refs/heads/doomed", &Reference::Direct(tip))
            .unwrap();

        // A delete-only request carries no pack; the reader must not block
        // waiting for one. The mock EOFs after the command list.
        let request = encode_push_request(
            &local,
            alloc::vec![RefUpdateCommand {
                old: tip,
                new: crate::oid::ObjectId::zero(local.algo()),
                name: "refs/heads/doomed".into(),
            }],
            &[],
        );
        let remote_path = remote_dir.clone();
        let mut ch = MockChannel::new(request);
        serve_ssh_receive_pack(
            "git-receive-pack 'repo.git'",
            &mut ch,
            |_path| Some(Repository::open(&remote_path).unwrap()),
            &|_| Ok(()),
        )
        .unwrap();

        let remote = Repository::open(&remote_dir).unwrap();
        assert!(remote.refs().resolve("refs/heads/doomed").is_err());

        let _ = std::fs::remove_dir_all(&local_dir);
        let _ = std::fs::remove_dir_all(&remote_dir);
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
