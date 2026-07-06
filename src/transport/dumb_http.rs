//! Dumb-HTTP fetch fallback.
//!
//! A "dumb" HTTP server has no `git-upload-pack` CGI — it just serves the files
//! under a repository's `objects/` and `info/` directories statically (as
//! produced by `git update-server-info`). There is no negotiation and no
//! server-built pack: the client reads the ref list from `info/refs`, then walks
//! the object graph itself, fetching each object over plain `GET`s — loose
//! objects at `objects/<xx>/<rest>` and, for what has been packed,
//! `objects/pack/*.idx` + `*.pack` enumerated in `objects/info/packs`.
//!
//! This module models the remote object store as a lazily-fetching
//! [`ObjectDatabase`] (`DumbHttpOdb`): once the store
//! can answer `read`, the ordinary
//! [`objects_to_send`](crate::walk::objects_to_send) walk and
//! [`PackWriter`](crate::pack::PackWriter) synthesise exactly the pack a smart
//! server would have returned, so the client's clone/fetch path is unchanged.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::error::{Error, ObjectKindHint, Result};
use crate::object::{ObjectType, parse_loose};
use crate::odb::ObjectDatabase;
use crate::oid::{HashAlgo, ObjectId};
use crate::pack::{Pack, PackIndex};
use crate::protocol::{AdvertisedRef, Capabilities, RefAdvertisement};

/// The largest loose object this fallback will inflate, a guard against a
/// hostile server declaring an enormous decompressed size.
const MAX_LOOSE_OBJECT: usize = 512 * 1024 * 1024;

/// The HTTP configuration a dumb fetch needs, copied from the transport so the
/// object store can issue its own `GET`s with the same auth and redirect policy.
#[derive(Clone)]
pub(crate) struct DumbConfig {
    pub base_url: String,
    pub algo: HashAlgo,
    pub auth: Option<String>,
    pub follow_redirects: bool,
    pub max_redirects: u32,
}

impl DumbConfig {
    /// Issues a `GET` for `url`, returning `Ok(Some(body))` on `200`, `Ok(None)`
    /// on `404` (so a caller can fall through to another location), or an error
    /// for any other status / transport failure.
    fn get(&self, url: &str) -> Result<Option<Vec<u8>>> {
        let mut req = rsurl::Request::new("GET", url)
            .map_err(|e| Error::Io(e.to_string()))?
            .header("User-Agent", concat!("puregit/", env!("CARGO_PKG_VERSION")))
            .follow_redirects(self.follow_redirects)
            .max_redirs(self.max_redirects);
        if let Some(auth) = &self.auth {
            req = req.header("Authorization", auth);
        }
        let response = req.send().map_err(|e| Error::Io(e.to_string()))?;
        match response.status {
            200 => Ok(Some(response.body)),
            404 => Ok(None),
            other => Err(Error::Protocol(alloc::format!(
                "dumb http: GET {url} returned HTTP {other}"
            ))),
        }
    }
}

/// Builds the ref advertisement from a dumb server: the `info/refs` listing
/// plus the symbolic `HEAD`, mapped to the same [`RefAdvertisement`] a smart
/// server would produce (with an empty capability set).
pub(crate) fn discover(cfg: &DumbConfig, info_refs: &[u8]) -> Result<RefAdvertisement> {
    let text = core::str::from_utf8(info_refs)
        .map_err(|_| Error::Protocol("dumb http: info/refs is not utf-8".into()))?;

    let mut refs = parse_info_refs(cfg.algo, text);
    let by_name: BTreeMap<String, ObjectId> = refs.iter().map(|r| (r.name.clone(), r.id)).collect();

    // Resolve HEAD's symref target to an oid so the clone knows the default
    // branch. A missing/unreadable HEAD simply omits it.
    if let Some(body) = cfg.get(&alloc::format!("{}/HEAD", cfg.base_url))?
        && let Ok(text) = core::str::from_utf8(&body)
        && let Some(target) = text.trim().strip_prefix("ref: ")
        && let Some(id) = by_name.get(target.trim())
    {
        refs.insert(
            0,
            AdvertisedRef {
                name: "HEAD".into(),
                id: *id,
            },
        );
    }

    Ok(RefAdvertisement {
        refs,
        capabilities: Capabilities::new(),
        object_format: cfg.algo,
    })
}

/// Parses a dumb `info/refs` body into advertised refs.
///
/// Each line is `<hex-oid>\t<refname>`. Peeled tag lines (`<name>^{}`) are
/// redundant with the tag object itself (which is listed separately) and are
/// dropped; malformed lines are skipped.
fn parse_info_refs(algo: HashAlgo, text: &str) -> Vec<AdvertisedRef> {
    let mut refs = Vec::new();
    for line in text.lines() {
        let Some((hex, name)) = line.split_once('\t') else {
            continue;
        };
        let name = name.trim();
        if name.ends_with("^{}") {
            continue;
        }
        let Ok(id) = ObjectId::from_hex(algo, hex.trim()) else {
            continue;
        };
        refs.push(AdvertisedRef {
            name: name.to_string(),
            id,
        });
    }
    refs
}

/// One packfile fetched from a dumb server: its index and bytes.
struct LoadedPack {
    index: PackIndex,
    pack: Pack,
}

/// A remote object store served over dumb HTTP, fetching objects lazily.
///
/// Reads consult an in-memory cache, then the loose location, then every pack
/// listed in `objects/info/packs` (loaded on first miss). `write` is
/// unsupported — a dumb fetch is read-only.
pub(crate) struct DumbHttpOdb {
    cfg: DumbConfig,
    cache: RefCell<BTreeMap<ObjectId, (ObjectType, Vec<u8>)>>,
    packs: RefCell<Option<Vec<Rc<LoadedPack>>>>,
}

impl DumbHttpOdb {
    pub(crate) fn new(cfg: DumbConfig) -> Self {
        DumbHttpOdb {
            cfg,
            cache: RefCell::new(BTreeMap::new()),
            packs: RefCell::new(None),
        }
    }

    /// Fetches a loose object, if present, returning its parsed `(type, bytes)`.
    fn read_loose(&self, id: &ObjectId) -> Result<Option<(ObjectType, Vec<u8>)>> {
        let hex = id.to_hex();
        let url = alloc::format!("{}/objects/{}/{}", self.cfg.base_url, &hex[..2], &hex[2..]);
        let Some(body) = self.cfg.get(&url)? else {
            return Ok(None);
        };
        let raw = crate::compress::inflate_capped(&body, MAX_LOOSE_OBJECT)?;
        let (ty, payload) = parse_loose(&raw)?;
        Ok(Some((ty, payload.to_vec())))
    }

    /// Loads every pack advertised in `objects/info/packs`, once.
    fn ensure_packs(&self) -> Result<()> {
        if self.packs.borrow().is_some() {
            return Ok(());
        }
        let mut loaded = Vec::new();
        let list_url = alloc::format!("{}/objects/info/packs", self.cfg.base_url);
        if let Some(body) = self.cfg.get(&list_url)? {
            let text = core::str::from_utf8(&body).unwrap_or("");
            for line in text.lines() {
                // Lines look like `P pack-<hash>.pack`.
                let Some(name) = line.trim().strip_prefix("P ") else {
                    continue;
                };
                let name = name.trim();
                let Some(stem) = name.strip_suffix(".pack") else {
                    continue;
                };
                let idx_url = alloc::format!("{}/objects/pack/{stem}.idx", self.cfg.base_url);
                let pack_url = alloc::format!("{}/objects/pack/{name}", self.cfg.base_url);
                if let (Some(idx), Some(pk)) = (self.cfg.get(&idx_url)?, self.cfg.get(&pack_url)?) {
                    let index = PackIndex::parse(self.cfg.algo, &idx)?;
                    let pack = Pack::new(pk, self.cfg.algo)?;
                    loaded.push(Rc::new(LoadedPack { index, pack }));
                }
            }
        }
        *self.packs.borrow_mut() = Some(loaded);
        Ok(())
    }
}

impl ObjectDatabase for DumbHttpOdb {
    fn algo(&self) -> HashAlgo {
        self.cfg.algo
    }

    fn contains(&self, id: &ObjectId) -> bool {
        self.read(id).is_ok()
    }

    fn read(&self, id: &ObjectId) -> Result<(ObjectType, Vec<u8>)> {
        if let Some(obj) = self.cache.borrow().get(id) {
            return Ok(obj.clone());
        }
        if let Some(obj) = self.read_loose(id)? {
            self.cache.borrow_mut().insert(*id, obj.clone());
            return Ok(obj);
        }
        // Packed: locate the object in a loaded pack, then read it *after*
        // dropping the borrow — `read_at` re-enters `read` to resolve a delta
        // base, which would double-borrow `packs`. The `Rc` makes the handoff
        // cheap.
        self.ensure_packs()?;
        let candidate = {
            let packs = self.packs.borrow();
            packs
                .as_ref()
                .expect("packs loaded")
                .iter()
                .find_map(|lp| lp.index.offset_of(id).map(|off| (Rc::clone(lp), off)))
        };
        if let Some((lp, off)) = candidate {
            let resolver = |base: &ObjectId| self.read(base);
            let obj = lp.pack.read_at(off, &resolver)?;
            self.cache.borrow_mut().insert(*id, obj.clone());
            return Ok(obj);
        }
        Err(Error::NotFound(ObjectKindHint::Object(id.to_hex())))
    }

    fn write(&self, _ty: ObjectType, _payload: &[u8]) -> Result<ObjectId> {
        Err(Error::Unsupported(
            "dumb http: object store is read-only".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_info_refs_lines_and_skips_peeled_and_junk() {
        let oid = "1".repeat(40);
        let text = alloc::format!(
            "{oid}\trefs/heads/main\n\
             {oid}\trefs/tags/v1\n\
             {oid}\trefs/tags/v1^{{}}\n\
             garbage-with-no-tab\n\
             nothex\trefs/heads/bad\n"
        );
        let refs = parse_info_refs(HashAlgo::Sha1, &text);
        let names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
        // The two real refs are kept; the peeled `^{}` line, the tab-less line,
        // and the non-hex oid are all dropped.
        assert_eq!(names, ["refs/heads/main", "refs/tags/v1"]);
        assert!(
            refs.iter()
                .all(|r| r.id == ObjectId::from_hex(HashAlgo::Sha1, &oid).unwrap())
        );
    }
}
