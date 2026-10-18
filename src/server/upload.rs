//! upload-pack internals shared by every server frontend.
//!
//! The same three pieces serve a fetch whether it arrives as one stateless
//! request (smart HTTP) or as a live conversation (`git://`, SSH):
//!
//! - [`Negotiator`] — the v0/v1 `have` acknowledgment state machine, matching
//!   `git upload-pack`'s `multi_ack` / `multi_ack_detailed` / single-ACK
//!   output line for line;
//! - [`plan`] — the object set to send, including every shallow flavour
//!   (`deepen <n>`, `deepen-relative`, `deepen-since`, `deepen-not`) with the
//!   resulting `shallow` / `unshallow` boundary updates;
//! - [`build_pack`] / [`encode_pack_stream`] — the filtered (partial clone),
//!   optionally thin packfile and its sideband framing.
//!
//! [`serve_session`] drives a whole stateful v0/v1 conversation over a stream.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::object::{Commit, ObjectType, Tag};
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;
use crate::protocol::pktline::{self, Packet};
use crate::protocol::{Capabilities, FetchRequest};

use super::daemon::{MAX_NEGOTIATION_BYTES, MAX_NEGOTIATION_PACKETS};

/// The v0/v1 `upload-pack` capabilities every puregit server frontend
/// advertises (`object-format`, `symref` and `agent` are added per repository
/// by the advertisement builder).
pub const UPLOAD_PACK_CAPABILITIES: &[&str] = &[
    "multi_ack",
    "thin-pack",
    "side-band",
    "side-band-64k",
    "ofs-delta",
    "shallow",
    "deepen-since",
    "deepen-not",
    "deepen-relative",
    "no-progress",
    "allow-tip-sha1-in-want",
    "allow-reachable-sha1-in-want",
    "multi_ack_detailed",
    "include-tag",
    "filter",
];

/// The ref-store access an upload-pack session needs beyond the object store:
/// resolving `deepen-not` names and listing tags for `include-tag`.
pub(crate) trait RefView {
    /// Resolves a (possibly abbreviated) ref name to its id.
    fn resolve(&self, name: &str) -> Option<ObjectId>;
    /// The ids `refs/tags/*` point at.
    fn tags(&self) -> Vec<ObjectId>;
}

/// A [`RefView`] with no refs (a bare object store being served).
pub(crate) struct NoRefs;

impl RefView for NoRefs {
    fn resolve(&self, _name: &str) -> Option<ObjectId> {
        None
    }
    fn tags(&self) -> Vec<ObjectId> {
        Vec::new()
    }
}

/// Upper bound on client-held objects offered as thin-pack `REF_DELTA` bases
/// when serving a fetch, bounding the delta search on a large repository.
const THIN_PACK_BASE_CAP: usize = 2000;

/// Upper bound on commits visited when deciding whether the server can give
/// up negotiating (`ready`); beyond it the server simply keeps negotiating.
const GIVE_UP_WALK_CAP: usize = 100_000;

/// The `have`-acknowledgment mode a v0/v1 fetch negotiated, derived from the
/// capabilities on the client's first `want` line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AckMode {
    /// No multi-ack capability: only the first common object is acknowledged.
    Single,
    /// `multi_ack`: each common object is acknowledged `ACK <oid> continue`.
    Multi,
    /// `multi_ack_detailed`: `ACK <oid> common`, plus `ACK <oid> ready` once
    /// the server can build the pack.
    Detailed,
}

impl AckMode {
    /// Selects the richest mode the client requested (detailed ▷ multi ▷ single).
    pub(crate) fn from_caps(caps: &Capabilities) -> Self {
        if caps.has("multi_ack_detailed") {
            AckMode::Detailed
        } else if caps.has("multi_ack") {
            AckMode::Multi
        } else {
            AckMode::Single
        }
    }
}

/// The server half of v0/v1 `have` negotiation, mirroring
/// `upload-pack.c:get_common_commits`: feed it each `have`, each flush, and the
/// final `done`, and it appends exactly the `ACK`/`NAK` lines git would send.
pub(crate) struct Negotiator<'a, D: ObjectDatabase> {
    odb: &'a D,
    wants: &'a [ObjectId],
    mode: AckMode,
    /// Every common object the client announced, in order (git's `have_obj`).
    common: Vec<ObjectId>,
    common_set: BTreeSet<ObjectId>,
    /// Whether this round saw a common / an unknown `have`.
    got_common: bool,
    got_other: bool,
}

impl<'a, D: ObjectDatabase> Negotiator<'a, D> {
    /// Starts a negotiation for `wants` under `mode`.
    pub(crate) fn new(odb: &'a D, wants: &'a [ObjectId], mode: AckMode) -> Self {
        Negotiator {
            odb,
            wants,
            mode,
            common: Vec::new(),
            common_set: BTreeSet::new(),
            got_common: false,
            got_other: false,
        }
    }

    /// The common objects found so far (the client's usable `have`s).
    pub(crate) fn common(&self) -> &[ObjectId] {
        &self.common
    }

    /// Processes one `have <oid>` line.
    pub(crate) fn have(&mut self, oid: ObjectId, out: &mut Vec<u8>) -> Result<()> {
        if !self.odb.contains(&oid) {
            self.got_other = true;
            return Ok(());
        }
        self.got_common = true;
        if self.common_set.insert(oid) {
            self.common.push(oid);
        }
        let line = match self.mode {
            AckMode::Detailed => Some(alloc::format!("ACK {} common\n", oid.to_hex())),
            AckMode::Multi => Some(alloc::format!("ACK {} continue\n", oid.to_hex())),
            AckMode::Single if self.common.len() == 1 => {
                Some(alloc::format!("ACK {}\n", oid.to_hex()))
            }
            AckMode::Single => None,
        };
        if let Some(line) = line {
            out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
        }
        Ok(())
    }

    /// Processes the flush that ends a negotiation round.
    pub(crate) fn flush(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if self.mode == AckMode::Detailed
            && self.got_common
            && !self.got_other
            && ok_to_give_up(self.odb, self.wants, &self.common_set)?
            && let Some(last) = self.common.last()
        {
            out.extend_from_slice(&pktline::encode_data(
                alloc::format!("ACK {} ready\n", last.to_hex()).as_bytes(),
            )?);
        }
        if self.common.is_empty() || self.mode != AckMode::Single {
            out.extend_from_slice(&pktline::encode_data(b"NAK\n")?);
        }
        self.got_common = false;
        self.got_other = false;
        Ok(())
    }

    /// Processes `done`: the final acknowledgment before the pack.
    pub(crate) fn done(&mut self, out: &mut Vec<u8>) -> Result<()> {
        match self.common.last() {
            Some(last) => {
                if self.mode != AckMode::Single {
                    out.extend_from_slice(&pktline::encode_data(
                        alloc::format!("ACK {}\n", last.to_hex()).as_bytes(),
                    )?);
                }
            }
            None => out.extend_from_slice(&pktline::encode_data(b"NAK\n")?),
        }
        Ok(())
    }
}

/// Whether every wanted commit reaches a `common` object, so the server can
/// build a minimal pack now (git's `ok_to_give_up`). Non-commit wants are
/// considered satisfied, as in git; with nothing common it is never ready.
pub(crate) fn ok_to_give_up<D: ObjectDatabase>(
    odb: &D,
    wants: &[ObjectId],
    common: &BTreeSet<ObjectId>,
) -> Result<bool> {
    if common.is_empty() {
        return Ok(false);
    }
    for want in wants {
        let Some(start) = peel_to_commit(odb, want)? else {
            continue;
        };
        if !reaches_any(odb, &start, common)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Follows tags from `id` to a commit; `None` if it ends at a non-commit or a
/// missing object.
fn peel_to_commit<D: ObjectDatabase>(odb: &D, id: &ObjectId) -> Result<Option<ObjectId>> {
    let mut cur = *id;
    for _ in 0..64 {
        let (ty, payload) = match odb.read(&cur) {
            Ok(v) => v,
            Err(Error::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        match ty {
            ObjectType::Commit => return Ok(Some(cur)),
            ObjectType::Tag => cur = Tag::parse(odb.algo(), &payload)?.object,
            _ => return Ok(None),
        }
    }
    Ok(None)
}

/// Whether `start` or one of its ancestors is in `targets` (bounded walk).
fn reaches_any<D: ObjectDatabase>(
    odb: &D,
    start: &ObjectId,
    targets: &BTreeSet<ObjectId>,
) -> Result<bool> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([*start]);
    while let Some(id) = queue.pop_front() {
        if targets.contains(&id) {
            return Ok(true);
        }
        if !seen.insert(id) || seen.len() > GIVE_UP_WALK_CAP {
            continue;
        }
        if let Some(commit) = read_commit(odb, &id)? {
            queue.extend(commit.parents);
        }
    }
    Ok(false)
}

/// Reads and parses a commit, `None` if it is missing or not a commit.
fn read_commit<D: ObjectDatabase>(odb: &D, id: &ObjectId) -> Result<Option<Commit>> {
    match odb.read_typed(id, ObjectType::Commit) {
        Ok(payload) => Ok(Some(Commit::parse(odb.algo(), &payload)?)),
        Err(Error::NotFound(_)) | Err(Error::UnexpectedType { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The shallow-related arguments of a fetch.
#[derive(Debug, Clone, Default)]
pub(crate) struct Deepen {
    /// `deepen <n>`.
    pub depth: Option<u32>,
    /// `deepen-since <timestamp>`.
    pub since: Option<i64>,
    /// `deepen-not <ref>` (repeatable).
    pub not: Vec<String>,
    /// `deepen-relative`: `depth` counts from the client's current boundary.
    pub relative: bool,
}

impl Deepen {
    /// Whether the request changes the shallow boundary at all.
    pub(crate) fn is_active(&self) -> bool {
        self.depth.is_some() || self.since.is_some() || !self.not.is_empty()
    }

    /// The deepen arguments of a v0/v1 request.
    pub(crate) fn from_request(req: &FetchRequest) -> Self {
        Deepen {
            depth: req.deepen,
            since: req.deepen_since,
            not: req.deepen_not.clone(),
            relative: req.deepen_relative,
        }
    }
}

/// What a fetch request asks for, independent of protocol version.
pub(crate) struct Want<'a> {
    pub wants: &'a [ObjectId],
    pub haves: &'a [ObjectId],
    pub client_shallow: &'a [ObjectId],
    pub deepen: &'a Deepen,
}

/// The planned response to a fetch: the objects to pack, the objects the
/// client provably holds (usable as thin-pack bases), and the shallow
/// boundary changes to announce.
pub(crate) struct Plan {
    pub objects: BTreeSet<ObjectId>,
    pub client_has: BTreeSet<ObjectId>,
    pub shallow: Vec<ObjectId>,
    pub unshallow: Vec<ObjectId>,
}

/// Plans a fetch response. `refs` resolves `deepen-not` ref names.
///
/// The client's holdings are the closure of its (known) `have`s, cut at its
/// shallow boundary — a shallow client does *not* hold the history behind its
/// boundary even though the server does, so nothing from there may be assumed.
/// Explicitly wanted objects are always sent (a promisor client re-fetches a
/// filtered-out object it already reaches).
pub(crate) fn plan<D: ObjectDatabase>(odb: &D, refs: &dyn RefView, req: &Want<'_>) -> Result<Plan> {
    let client_shallow: BTreeSet<ObjectId> = req.client_shallow.iter().copied().collect();
    let haves: Vec<ObjectId> = req
        .haves
        .iter()
        .copied()
        .filter(|h| odb.contains(h))
        .collect();
    let client_has = if client_shallow.is_empty() {
        crate::walk::reachable_objects(odb, &haves)?
    } else {
        let mut view =
            crate::walk::shallow_objects_to_send(odb, &haves, u32::MAX, &client_shallow)?.objects;
        // `shallow_objects_to_send` keeps an unknown root id; only real
        // objects count as held.
        view.retain(|id| odb.contains(id));
        view
    };

    if !req.deepen.is_active() {
        let mut objects = crate::walk::reachable_objects_excluding(odb, req.wants, &client_has)?;
        objects.extend(req.wants.iter().filter(|w| !req.haves.contains(w)).copied());
        return Ok(Plan {
            objects,
            client_has,
            shallow: Vec::new(),
            unshallow: Vec::new(),
        });
    }

    // 1. Which commits the client will hold afterwards, and the new boundary.
    let mut extra: BTreeSet<ObjectId> = BTreeSet::new();
    let mut tips: Vec<ObjectId> = Vec::new();
    for want in req.wants {
        collect_tip(odb, want, &mut tips, &mut extra)?;
    }
    let (included, boundary) = match (req.deepen.depth, req.deepen.relative) {
        (Some(depth), false) => depth_walk(odb, &tips, depth)?,
        (Some(depth), true) => {
            let starts: Vec<ObjectId> = client_shallow
                .iter()
                .copied()
                .filter(|c| odb.contains(c))
                .collect();
            let (_, new_boundary) = depth_walk(odb, &starts, depth.saturating_add(1))?;
            walk_until(odb, &tips, &new_boundary)?
        }
        (None, _) => rev_list_walk(odb, refs, &tips, req.deepen)?,
    };

    // 2. Their trees, plus any non-commit wants, minus what the client holds.
    let mut roots: Vec<ObjectId> = Vec::new();
    for c in &included {
        if let Some(commit) = read_commit(odb, c)? {
            roots.push(commit.tree);
        }
    }
    let mut objects = crate::walk::reachable_objects_excluding(odb, &roots, &client_has)?;
    for c in &included {
        if !client_has.contains(c) {
            objects.insert(*c);
        }
    }
    for e in &extra {
        if !client_has.contains(e) {
            objects.extend(crate::walk::reachable_objects_excluding(
                odb,
                &[*e],
                &client_has,
            )?);
        }
    }
    objects.extend(req.wants.iter().filter(|w| !req.haves.contains(w)).copied());

    let shallow = boundary
        .iter()
        .filter(|c| !client_shallow.contains(c))
        .copied()
        .collect();
    let unshallow = req
        .client_shallow
        .iter()
        .filter(|c| included.contains(c) && !boundary.contains(c))
        .copied()
        .collect();
    Ok(Plan {
        objects,
        client_has,
        shallow,
        unshallow,
    })
}

/// Resolves a want to the commit the shallow walk starts from: tags are
/// peeled (the tag objects themselves go to `extra`), a commit is a tip, and
/// a tree/blob want is sent as-is (`extra`).
fn collect_tip<D: ObjectDatabase>(
    odb: &D,
    want: &ObjectId,
    tips: &mut Vec<ObjectId>,
    extra: &mut BTreeSet<ObjectId>,
) -> Result<()> {
    let mut cur = *want;
    for _ in 0..64 {
        let (ty, payload) = match odb.read(&cur) {
            Ok(v) => v,
            Err(Error::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        match ty {
            ObjectType::Commit => {
                tips.push(cur);
                return Ok(());
            }
            ObjectType::Tag => {
                extra.insert(cur);
                cur = Tag::parse(odb.algo(), &payload)?.object;
            }
            _ => {
                extra.insert(cur);
                return Ok(());
            }
        }
    }
    Ok(())
}

/// `get_shallow_commits`: breadth-first from `tips`, each commit at its
/// shallowest depth (tips are depth 1); commits at `depth` form the boundary
/// and their parents are not walked. Returns `(included, boundary)`.
fn depth_walk<D: ObjectDatabase>(
    odb: &D,
    tips: &[ObjectId],
    depth: u32,
) -> Result<(BTreeSet<ObjectId>, BTreeSet<ObjectId>)> {
    let depth = depth.max(1);
    let mut best: BTreeMap<ObjectId, u32> = BTreeMap::new();
    let mut queue: VecDeque<(ObjectId, u32)> = tips.iter().map(|t| (*t, 1)).collect();
    while let Some((id, d)) = queue.pop_front() {
        if best.get(&id).is_some_and(|&prev| prev <= d) {
            continue;
        }
        let Some(commit) = read_commit(odb, &id)? else {
            continue;
        };
        best.insert(id, d);
        if d < depth {
            for p in commit.parents {
                queue.push_back((p, d + 1));
            }
        }
    }
    let included: BTreeSet<ObjectId> = best.keys().copied().collect();
    let boundary = best
        .iter()
        .filter(|&(_, &d)| d >= depth)
        .map(|(id, _)| *id)
        .collect();
    Ok((included, boundary))
}

/// Walks the history of `tips`, not descending past `stop` commits (which
/// are themselves included). Returns `(included, stop ∩ included)`.
fn walk_until<D: ObjectDatabase>(
    odb: &D,
    tips: &[ObjectId],
    stop: &BTreeSet<ObjectId>,
) -> Result<(BTreeSet<ObjectId>, BTreeSet<ObjectId>)> {
    let mut included = BTreeSet::new();
    let mut boundary = BTreeSet::new();
    let mut stack: Vec<ObjectId> = tips.to_vec();
    while let Some(id) = stack.pop() {
        if included.contains(&id) {
            continue;
        }
        let Some(commit) = read_commit(odb, &id)? else {
            continue;
        };
        included.insert(id);
        if stop.contains(&id) {
            boundary.insert(id);
            continue;
        }
        stack.extend(commit.parents);
    }
    Ok((included, boundary))
}

/// `deepen-since` / `deepen-not` (git's `deepen_by_rev_list`): the commits of
/// `rev-list --max-age=<since> <tips> --not <refs>`; the boundary is every
/// such commit with a parent outside the set.
fn rev_list_walk<D: ObjectDatabase>(
    odb: &D,
    refs: &dyn RefView,
    tips: &[ObjectId],
    deepen: &Deepen,
) -> Result<(BTreeSet<ObjectId>, BTreeSet<ObjectId>)> {
    // Everything reachable from a `deepen-not` ref is excluded.
    let mut not_roots = Vec::new();
    for name in &deepen.not {
        let id = refs
            .resolve(name)
            .ok_or_else(|| Error::Protocol(alloc::format!("deepen-not: {name} is not a ref")))?;
        if let Some(c) = peel_to_commit(odb, &id)? {
            not_roots.push(c);
        }
    }
    let excluded = commit_ancestry(odb, &not_roots)?;

    let mut included = BTreeSet::new();
    let mut parents_of: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
    let mut stack: Vec<ObjectId> = tips.to_vec();
    while let Some(id) = stack.pop() {
        if included.contains(&id) || excluded.contains(&id) {
            continue;
        }
        let Some(commit) = read_commit(odb, &id)? else {
            continue;
        };
        if deepen
            .since
            .is_some_and(|since| commit.committer.time < since)
        {
            continue;
        }
        included.insert(id);
        stack.extend(commit.parents.iter().copied());
        parents_of.insert(id, commit.parents);
    }
    if included.is_empty() {
        return Err(Error::Protocol(
            "no commits selected for shallow requests".to_string(),
        ));
    }
    let boundary = parents_of
        .iter()
        .filter(|(_, parents)| parents.iter().any(|p| !included.contains(p)))
        .map(|(id, _)| *id)
        .collect();
    Ok((included, boundary))
}

/// Every commit reachable from `roots` (inclusive).
fn commit_ancestry<D: ObjectDatabase>(odb: &D, roots: &[ObjectId]) -> Result<BTreeSet<ObjectId>> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<ObjectId> = roots.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(commit) = read_commit(odb, &id)? {
            stack.extend(commit.parents);
        }
    }
    Ok(seen)
}

/// `include-tag`: adds every annotated tag (and tag chain) under `refs/tags/`
/// whose peeled target is being sent, so the client gets the tags that now
/// point into its history without a second fetch — as `git pack-objects
/// --include-tag` does.
pub(crate) fn include_tags<D: ObjectDatabase>(
    odb: &D,
    refs: &dyn RefView,
    plan: &mut Plan,
) -> Result<()> {
    for tag in refs.tags() {
        let mut chain = Vec::new();
        let mut cur = tag;
        for _ in 0..64 {
            match odb.read(&cur) {
                Ok((ObjectType::Tag, payload)) => {
                    chain.push(cur);
                    cur = Tag::parse(odb.algo(), &payload)?.object;
                }
                _ => break,
            }
        }
        if !chain.is_empty() && plan.objects.contains(&cur) {
            for t in chain {
                if !plan.client_has.contains(&t) {
                    plan.objects.insert(t);
                }
            }
        }
    }
    Ok(())
}

/// Builds the response packfile for `plan`, omitting what the partial-clone
/// `filter` excludes — except explicitly `wanted` objects, which are always
/// sent. With `thin`, objects the client holds are offered as delta bases.
pub(crate) fn build_pack<D: ObjectDatabase>(
    odb: &D,
    plan: &Plan,
    filter: Option<&str>,
    wanted: &[ObjectId],
    thin: bool,
) -> Result<Vec<u8>> {
    use crate::pack::PackWriter;
    let filter = crate::object_filter::from_spec(filter);
    let wanted: BTreeSet<ObjectId> = wanted.iter().copied().collect();
    let mut writer = PackWriter::new(odb.algo());
    for id in &plan.objects {
        let (ty, payload) = odb.read(id)?;
        if !wanted.contains(id) && !filter.keeps(ty, payload.len()) {
            continue;
        }
        writer.add(ty, &payload);
    }
    if thin {
        for id in plan.client_has.iter().take(THIN_PACK_BASE_CAP) {
            if let Ok((ty, payload)) = odb.read(id) {
                writer.add_external_base(ty, &payload);
            }
        }
    }
    Ok(writer.finish()?.pack)
}

/// Appends `pack` to `out` as the v0/v1 response body: multiplexed over
/// sideband channel 1 (ending with a flush) when the client asked for
/// `side-band-64k` / `side-band`, raw otherwise.
pub(crate) fn encode_pack_stream(
    out: &mut Vec<u8>,
    caps: &Capabilities,
    pack: &[u8],
) -> Result<()> {
    let max = if caps.has("side-band-64k") {
        pktline::MAX_PKTLINE_LEN - 5
    } else if caps.has("side-band") {
        1000 - 5
    } else {
        out.extend_from_slice(pack);
        return Ok(());
    };
    for chunk in pack.chunks(max) {
        let mut line = Vec::with_capacity(chunk.len() + 1);
        line.push(1);
        line.extend_from_slice(chunk);
        out.extend_from_slice(&pktline::encode_data(&line)?);
    }
    out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
    Ok(())
}

/// Appends the v0/v1 shallow section (`shallow`/`unshallow` lines + flush).
pub(crate) fn encode_shallow_section(out: &mut Vec<u8>, plan: &Plan) -> Result<()> {
    for oid in &plan.shallow {
        out.extend_from_slice(&pktline::encode_data(
            alloc::format!("shallow {}\n", oid.to_hex()).as_bytes(),
        )?);
    }
    for oid in &plan.unshallow {
        out.extend_from_slice(&pktline::encode_data(
            alloc::format!("unshallow {}\n", oid.to_hex()).as_bytes(),
        )?);
    }
    out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
    Ok(())
}

/// Serves one stateless (smart-HTTP) v0/v1 upload-pack request.
///
/// The request carries the want section, then the `have`s of this round,
/// ended either by a flush (a negotiation round: answered with
/// acknowledgments only) or by `done` (answered with the final ACK/NAK and the
/// pack). A deepen request is answered with the shallow section first, every
/// round, as git does.
pub(crate) fn serve_stateless<D: ObjectDatabase>(
    odb: &D,
    refs: &dyn RefView,
    request: &[u8],
) -> Result<Vec<u8>> {
    let packets = pktline::decode_all(request)?;
    // Split the want section (up to the first flush) from the have section.
    let want_end = packets
        .iter()
        .position(|p| matches!(p, Packet::Flush))
        .map_or(packets.len(), |i| i + 1);
    let req = FetchRequest::parse(odb.algo(), &packets[..want_end])?;
    if req.wants.is_empty() {
        return Err(Error::Protocol("upload-pack: request has no wants".into()));
    }
    let deepen = Deepen::from_request(&req);
    let mut out = Vec::new();
    let want = Want {
        wants: &req.wants,
        haves: &[],
        client_shallow: &req.shallows,
        deepen: &deepen,
    };
    if deepen.is_active() {
        let p = plan(odb, refs, &want)?;
        encode_shallow_section(&mut out, &p)?;
    }

    let mut neg = Negotiator::new(odb, &req.wants, AckMode::from_caps(&req.capabilities));
    let mut done = false;
    let mut saw_round = false;
    for packet in &packets[want_end..] {
        match packet {
            Packet::Data(d) => {
                let line = trim_newline(d);
                if let Some(hex) = line.strip_prefix(b"have ") {
                    let hex = core::str::from_utf8(hex)
                        .map_err(|_| Error::Protocol("have: non-utf8".into()))?;
                    neg.have(ObjectId::from_hex(odb.algo(), hex.trim())?, &mut out)?;
                    saw_round = true;
                } else if line == b"done" {
                    done = true;
                    break;
                }
            }
            Packet::Flush => {
                neg.flush(&mut out)?;
                saw_round = false;
            }
            _ => {}
        }
    }
    if !done {
        // A negotiation round (or the stateless shallow probe) ends here.
        if saw_round {
            neg.flush(&mut out)?;
        }
        return Ok(out);
    }
    neg.done(&mut out)?;
    let want = Want {
        haves: neg.common(),
        ..want
    };
    let mut p = plan(odb, refs, &want)?;
    if req.capabilities.has("include-tag") {
        include_tags(odb, refs, &mut p)?;
    }
    let thin = req.capabilities.has("thin-pack");
    let pack = build_pack(odb, &p, req.filter.as_deref(), &req.wants, thin)?;
    encode_pack_stream(&mut out, &req.capabilities, &pack)?;
    Ok(out)
}

/// Serves a whole stateful v0/v1 upload-pack conversation (`git://`, SSH,
/// a pipe) after the ref advertisement has been written: reads the want
/// section, answers a deepen request with the shallow section immediately,
/// acknowledges each `have` round as it arrives, and on `done` sends the pack.
/// A client that hangs up (or sends only a flush) without wanting anything
/// ends the session cleanly.
pub(crate) fn serve_session<S, D>(stream: &mut S, odb: &D, refs: &dyn RefView) -> Result<()>
where
    S: std::io::Read + std::io::Write,
    D: ObjectDatabase,
{
    // 1. The want section, through its flush.
    let mut want_bytes = Vec::new();
    loop {
        let (packet, raw) = match super::daemon::read_pktline(stream) {
            Ok(v) => v,
            Err(_) => return Ok(()), // hung up without a request
        };
        if want_bytes.len() + raw.len() > MAX_NEGOTIATION_BYTES {
            return Err(Error::Protocol(
                "upload-pack: want section too large".into(),
            ));
        }
        want_bytes.extend_from_slice(&raw);
        if matches!(packet, Packet::Flush) {
            break;
        }
    }
    let req = FetchRequest::parse(odb.algo(), &pktline::decode_all(&want_bytes)?)?;
    if req.wants.is_empty() {
        return Ok(()); // "nothing to fetch": a lone flush
    }
    let deepen = Deepen::from_request(&req);
    let mut want = Want {
        wants: &req.wants,
        haves: &[],
        client_shallow: &req.shallows,
        deepen: &deepen,
    };
    if deepen.is_active() {
        let mut out = Vec::new();
        encode_shallow_section(&mut out, &plan(odb, refs, &want)?)?;
        write_all(stream, &out)?;
    }

    // 2. `have` rounds until `done`.
    let mut neg = Negotiator::new(odb, &req.wants, AckMode::from_caps(&req.capabilities));
    let (mut packets, mut bytes) = (0usize, 0usize);
    loop {
        let (packet, raw) = match super::daemon::read_pktline(stream) {
            Ok(v) => v,
            Err(_) => return Ok(()), // the client gave up (e.g. nothing new)
        };
        packets += 1;
        bytes += raw.len();
        if packets > MAX_NEGOTIATION_PACKETS || bytes > MAX_NEGOTIATION_BYTES {
            return Err(Error::Protocol("upload-pack: negotiation too long".into()));
        }
        let mut out = Vec::new();
        match packet {
            Packet::Data(d) => {
                let line = trim_newline(&d);
                if let Some(hex) = line.strip_prefix(b"have ") {
                    let hex = core::str::from_utf8(hex)
                        .map_err(|_| Error::Protocol("have: non-utf8".into()))?;
                    neg.have(ObjectId::from_hex(odb.algo(), hex.trim())?, &mut out)?;
                } else if line == b"done" {
                    neg.done(&mut out)?;
                    write_all(stream, &out)?;
                    break;
                } else {
                    return Err(Error::Protocol(alloc::format!(
                        "upload-pack: unexpected line {:?}",
                        String::from_utf8_lossy(line)
                    )));
                }
            }
            Packet::Flush => neg.flush(&mut out)?,
            _ => {}
        }
        if !out.is_empty() {
            write_all(stream, &out)?;
        }
    }

    // 3. The pack.
    let common = neg.common().to_vec();
    want.haves = &common;
    let mut p = plan(odb, refs, &want)?;
    if req.capabilities.has("include-tag") {
        include_tags(odb, refs, &mut p)?;
    }
    let thin = req.capabilities.has("thin-pack");
    let pack = build_pack(odb, &p, req.filter.as_deref(), &req.wants, thin)?;
    let mut out = Vec::new();
    encode_pack_stream(&mut out, &req.capabilities, &pack)?;
    write_all(stream, &out)
}

fn write_all<S: std::io::Write>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(bytes)
        .and_then(|_| stream.flush())
        .map_err(|e| Error::Io(e.to_string()))
}

fn trim_newline(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::odb::MemoryOdb;
    use crate::oid::HashAlgo;

    /// A linear history of `n` commits (oldest first) in a fresh store.
    fn chain(n: usize) -> (MemoryOdb, Vec<ObjectId>) {
        let odb = MemoryOdb::new(HashAlgo::Sha1);
        let tree = odb.write(ObjectType::Tree, b"").unwrap();
        let mut ids: Vec<ObjectId> = Vec::new();
        for i in 0..n {
            let mut body = alloc::format!("tree {}\n", tree.to_hex());
            if let Some(p) = ids.last() {
                body.push_str(&alloc::format!("parent {}\n", p.to_hex()));
            }
            body.push_str(&alloc::format!(
                "author A <a@e> {i} +0000\ncommitter A <a@e> {i} +0000\n\nc{i}\n"
            ));
            ids.push(odb.write(ObjectType::Commit, body.as_bytes()).unwrap());
        }
        (odb, ids)
    }

    fn lines(out: &[u8]) -> Vec<String> {
        pktline::decode_all(out)
            .unwrap()
            .into_iter()
            .filter_map(|p| match p {
                Packet::Data(d) => Some(String::from_utf8_lossy(trim_newline(&d)).into_owned()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn negotiator_matches_git_ack_modes() {
        let (odb, ids) = chain(3);
        let unknown = ObjectId::from_hex(HashAlgo::Sha1, &"7".repeat(40)).unwrap();
        let tip = [ids[2]];
        let (a, b) = (ids[0].to_hex(), ids[1].to_hex());

        // multi_ack_detailed: `common` per known have; `ready` + NAK at the
        // flush once every want reaches a common commit; final `ACK` at done.
        let mut out = Vec::new();
        let mut n = Negotiator::new(&odb, &tip, AckMode::Detailed);
        n.have(ids[1], &mut out).unwrap();
        n.have(ids[0], &mut out).unwrap();
        n.flush(&mut out).unwrap();
        n.done(&mut out).unwrap();
        assert_eq!(
            lines(&out),
            [
                alloc::format!("ACK {b} common"),
                alloc::format!("ACK {a} common"),
                alloc::format!("ACK {a} ready"),
                "NAK".into(),
                alloc::format!("ACK {a}"),
            ]
        );

        // An unknown have in the round withholds `ready`.
        let mut out = Vec::new();
        let mut n = Negotiator::new(&odb, &tip, AckMode::Detailed);
        n.have(unknown, &mut out).unwrap();
        n.have(ids[1], &mut out).unwrap();
        n.flush(&mut out).unwrap();
        assert_eq!(
            lines(&out),
            [alloc::format!("ACK {b} common"), "NAK".into()]
        );

        // multi_ack: `continue`, NAK after every flush.
        let mut out = Vec::new();
        let mut n = Negotiator::new(&odb, &tip, AckMode::Multi);
        n.have(ids[1], &mut out).unwrap();
        n.flush(&mut out).unwrap();
        n.done(&mut out).unwrap();
        assert_eq!(
            lines(&out),
            [
                alloc::format!("ACK {b} continue"),
                "NAK".into(),
                alloc::format!("ACK {b}")
            ]
        );

        // Single ACK: only the first common object, nothing more after it.
        let mut out = Vec::new();
        let mut n = Negotiator::new(&odb, &tip, AckMode::Single);
        n.have(unknown, &mut out).unwrap();
        n.flush(&mut out).unwrap();
        n.have(ids[1], &mut out).unwrap();
        n.have(ids[0], &mut out).unwrap();
        n.flush(&mut out).unwrap();
        n.done(&mut out).unwrap();
        assert_eq!(lines(&out), ["NAK".to_string(), alloc::format!("ACK {b}")]);

        // Nothing in common at all: NAK at done.
        let mut out = Vec::new();
        Negotiator::new(&odb, &tip, AckMode::Detailed)
            .done(&mut out)
            .unwrap();
        assert_eq!(lines(&out), ["NAK"]);
    }

    #[test]
    fn plan_deepen_since_and_not() {
        // Commit i is committed at time i.
        let (odb, ids) = chain(6);
        struct Refs(ObjectId);
        impl RefView for Refs {
            fn resolve(&self, name: &str) -> Option<ObjectId> {
                (name == "old").then_some(self.0)
            }
            fn tags(&self) -> Vec<ObjectId> {
                Vec::new()
            }
        }
        let refs = Refs(ids[2]);
        let run = |deepen: Deepen| {
            plan(
                &odb,
                &refs,
                &Want {
                    wants: &[ids[5]],
                    haves: &[],
                    client_shallow: &[],
                    deepen: &deepen,
                },
            )
        };

        // since 3: commits 3..=5, boundary at 3.
        let p = run(Deepen {
            since: Some(3),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(p.shallow, [ids[3]]);
        assert!(p.objects.contains(&ids[3]) && !p.objects.contains(&ids[2]));

        // not `old` (commit 2): commits 3..=5 again.
        let p = run(Deepen {
            not: alloc::vec!["old".into()],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(p.shallow, [ids[3]]);

        // An unresolvable deepen-not name is an error, as in git.
        assert!(
            run(Deepen {
                not: alloc::vec!["nope".into()],
                ..Default::default()
            })
            .is_err()
        );

        // Excluding everything selects no commits: an error, as in git.
        assert!(
            run(Deepen {
                since: Some(100),
                ..Default::default()
            })
            .is_err()
        );
    }
}
