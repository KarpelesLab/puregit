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

/// Skips the leading acknowledgment pkt-lines (`NAK`/`ACK …`) of an upload-pack
/// response and returns the raw packfile that follows (it starts with `PACK`).
fn strip_to_pack(response: &[u8]) -> Result<&[u8]> {
    let mut off = 0;
    loop {
        if response[off..].starts_with(b"PACK") {
            return Ok(&response[off..]);
        }
        match pktline::decode(&response[off..])? {
            Some((_, n)) => off += n,
            None => break,
        }
        if off >= response.len() {
            break;
        }
    }
    Err(Error::Protocol(
        "upload-pack response contained no packfile".into(),
    ))
}
