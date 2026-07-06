//! A framework-agnostic smart-HTTP request handler.
//!
//! [`handle_http`] maps the three smart-HTTP endpoints onto the transport-
//! agnostic [`advertise_refs`] / [`upload_pack`] / [`receive_pack`] handlers,
//! returning a plain `(status, content-type, body)` so it can be
//! served by any HTTP stack (a CGI shim, a `std::net` loop, or an async
//! framework) without this crate depending on one.
//!
//! Routes handled (relative to the repository's URL path):
//! - `GET  …/info/refs?service=git-upload-pack|git-receive-pack`
//! - `POST …/git-upload-pack`
//! - `POST …/git-receive-pack`
//!
//! Authentication and authorization are the caller's responsibility — wrap this
//! handler and reject `git-receive-pack` (push) for unauthenticated clients, as
//! a real server does. As defense in depth this handler also carries a
//! [`ServerConfig`] with an explicit request-body size cap and per-service
//! enable flags, so a deployment that forgets an external wrapper still fails
//! safe rather than accepting unbounded pushes.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::protocol::pktline;
use crate::repository::Repository;
use crate::transport::Service;

use super::{advertise_refs, receive_pack, upload_pack};

/// The default cap on a smart-HTTP request body, in bytes.
///
/// Sized generously enough for ordinary interactive fetch/push negotiations and
/// small packs while still bounding the memory a single request can force the
/// server to buffer. Deployments serving large pushes should raise
/// [`ServerConfig::max_body`] explicitly.
pub const DEFAULT_MAX_BODY: usize = 64 * 1024 * 1024;

/// Configuration and access-control policy for the smart-HTTP handler.
///
/// Constructed via [`ServerConfig::default`], which is **read-write** to
/// preserve the historical behaviour of [`handle_http`] (both fetch and push
/// enabled). Callers that want a safe read-only deployment should start from
/// [`ServerConfig::read_only`] instead, which disables `git-receive-pack`
/// (push) up front. All requests are additionally bounded by [`Self::max_body`].
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    /// Maximum accepted request-body size in bytes; larger bodies are rejected
    /// with `413` before any processing. Defaults to [`DEFAULT_MAX_BODY`].
    pub max_body: usize,
    /// Whether `POST …/git-upload-pack` (fetch/clone) is served. Defaults to
    /// `true`.
    pub allow_upload: bool,
    /// Whether `POST …/git-receive-pack` (push) is served. When `false` a push
    /// is rejected with `403` before dispatch. Defaults to `true` for backward
    /// compatibility; set it to `false` (or use [`Self::read_only`]) for a
    /// read-only server.
    pub allow_receive: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        // Backward-compatible default: both services enabled (the historical
        // behaviour of `handle_http`), but with the body cap now enforced.
        ServerConfig {
            max_body: DEFAULT_MAX_BODY,
            allow_upload: true,
            allow_receive: true,
        }
    }
}

impl ServerConfig {
    /// A safe read-only policy: fetch/clone enabled, push (`git-receive-pack`)
    /// disabled, with the default body cap.
    pub fn read_only() -> Self {
        ServerConfig {
            allow_receive: false,
            ..ServerConfig::default()
        }
    }
}

/// A minimal HTTP response: status, `Content-Type`, and body bytes.
pub struct HttpResponse {
    /// HTTP status code (200, 404, 400, …).
    pub status: u16,
    /// The `Content-Type` header value.
    pub content_type: String,
    /// The response body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn text(status: u16, msg: &str) -> Self {
        HttpResponse {
            status,
            content_type: "text/plain".to_string(),
            body: msg.as_bytes().to_vec(),
        }
    }
}

/// Handles one smart-HTTP request against `repo` using the default
/// [`ServerConfig`] (both services enabled, [`DEFAULT_MAX_BODY`] cap).
///
/// `method` is the HTTP verb (`GET`/`POST`), `path` is the request path (only
/// its suffix is inspected, so any repository prefix is fine), `query` is the
/// raw query string (without `?`), and `body` is the request body (empty for
/// GET). Service selection comes from the path suffix and, for discovery, the
/// `service=` query parameter.
///
/// This is a thin wrapper over [`handle_http_with`]; use that directly to serve
/// a read-only repository or to change the body cap.
pub fn handle_http(
    repo: &Repository,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> HttpResponse {
    handle_http_with(repo, &ServerConfig::default(), method, path, query, body)
}

/// Handles one smart-HTTP request against `repo` under an explicit
/// [`ServerConfig`].
///
/// Enforces, in order: the [`ServerConfig::max_body`] cap on POST bodies
/// (rejecting oversized requests with `413` before any parsing), and the
/// per-service enable flags (rejecting a disabled service with `403` before
/// dispatch). Otherwise identical to [`handle_http`].
pub fn handle_http_with(
    repo: &Repository,
    config: &ServerConfig,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> HttpResponse {
    // No `Git-Protocol` header ⇒ v0/v1 (the historical behaviour).
    handle_http_with_version(repo, config, method, path, query, body, "")
}

/// Like [`handle_http_with`], but also given the request's `Git-Protocol` header
/// value so protocol **v2** can be served.
///
/// When `git_protocol` requests `version=2`, discovery returns the v2 capability
/// advertisement and `POST …/git-upload-pack` is dispatched as a v2 command
/// (`ls-refs`/`fetch`). Pass `""` (or a value without `version=2`) for v0/v1.
/// A server behind a real HTTP stack should forward the `Git-Protocol` header
/// here; one that never sets it keeps the v0/v1 behaviour.
pub fn handle_http_with_version(
    repo: &Repository,
    config: &ServerConfig,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    git_protocol: &str,
) -> HttpResponse {
    let path = path.trim_end_matches('/');
    let v2 = git_protocol.split(':').any(|p| p.trim() == "version=2");

    if method.eq_ignore_ascii_case("GET") && path.ends_with("/info/refs") {
        let service = match service_from_query(query) {
            Some(s) => s,
            None => return HttpResponse::text(400, "missing or unknown service"),
        };
        // Reflect the access-control policy in discovery too: a disabled
        // service is advertised as forbidden rather than probeable.
        if !service_allowed(config, service) {
            return HttpResponse::text(403, "service not enabled");
        }
        // v2 discovery is a capability advertisement (only upload-pack speaks v2
        // here; a v2 push still uses receive-pack's v0/v1 advertisement).
        if v2 && service == Service::UploadPack {
            return v2_advertise(repo);
        }
        return info_refs(repo, service);
    }

    if method.eq_ignore_ascii_case("POST") {
        let service = if path.ends_with("/git-upload-pack") {
            Some(Service::UploadPack)
        } else if path.ends_with("/git-receive-pack") {
            Some(Service::ReceivePack)
        } else {
            None
        };
        if let Some(service) = service {
            // Reject a disabled service before touching the body, so a
            // read-only server never processes a push.
            if !service_allowed(config, service) {
                return HttpResponse::text(403, "service not enabled");
            }
            // Bound the body we are willing to buffer/process.
            if body.len() > config.max_body {
                return HttpResponse::text(413, "request body too large");
            }
            if v2 && service == Service::UploadPack {
                return v2_service_result(repo, body);
            }
            return service_result(repo, service, body);
        }
    }

    HttpResponse::text(404, "not found")
}

/// The v2 capability advertisement response (GET `info/refs` under v2).
fn v2_advertise(repo: &Repository) -> HttpResponse {
    match super::v2_capability_advertisement(repo) {
        Ok(body) => HttpResponse {
            status: 200,
            content_type: "application/x-git-upload-pack-advertisement".to_string(),
            body,
        },
        Err(_) => HttpResponse::text(500, "internal error"),
    }
}

/// Runs a v2 upload-pack command POST (`ls-refs`/`fetch`) and wraps the result.
fn v2_service_result(repo: &Repository, body: &[u8]) -> HttpResponse {
    match super::serve_v2_upload_pack(repo, body) {
        Ok(out) => HttpResponse {
            status: 200,
            content_type: "application/x-git-upload-pack-result".to_string(),
            body: out,
        },
        Err(_) => HttpResponse::text(500, "internal error"),
    }
}

/// Whether `config` permits `service` to be served.
fn service_allowed(config: &ServerConfig, service: Service) -> bool {
    match service {
        Service::UploadPack => config.allow_upload,
        Service::ReceivePack => config.allow_receive,
    }
}

/// Builds the `info/refs` smart advertisement: the `# service=…` banner
/// pkt-line and a flush, then the ref advertisement.
fn info_refs(repo: &Repository, service: Service) -> HttpResponse {
    let banner = alloc::format!("# service={}\n", service.name());
    // On error, return a generic message: the underlying `Error::to_string()`
    // can embed OS error text and server filesystem paths, which must not reach
    // an untrusted client (C5).
    let mut body = match pktline::encode_data(banner.as_bytes()) {
        Ok(b) => b,
        Err(_) => return HttpResponse::text(500, "internal error"),
    };
    body.extend_from_slice(&pktline::encode_control(&pktline::Packet::Flush));

    // Advertise service-appropriate capabilities. `upload-pack` (fetch) can
    // serve thin packs; `receive-pack` (push) must advertise `report-status` so
    // the client requests — and then parses — the push report the handler emits,
    // and `delete-refs` so branch deletions are accepted. Without `report-status`
    // real git treats a push as failed even though it applied.
    let caps: &[&str] = match service {
        Service::UploadPack => &["ofs-delta", "thin-pack", "side-band-64k", "shallow"],
        Service::ReceivePack => &["report-status", "delete-refs", "ofs-delta"],
    };
    match advertise_refs(repo, service, caps) {
        Ok(adv) => body.extend_from_slice(&adv),
        Err(_) => return HttpResponse::text(500, "internal error"),
    }

    HttpResponse {
        status: 200,
        content_type: alloc::format!("application/x-{}-advertisement", service.name()),
        body,
    }
}

/// Runs a service POST (upload-pack or receive-pack) and wraps the result.
fn service_result(repo: &Repository, service: Service, body: &[u8]) -> HttpResponse {
    let result = match service {
        Service::UploadPack => upload_pack(repo, body),
        Service::ReceivePack => receive_pack(repo, body),
    };
    match result {
        Ok(out) => HttpResponse {
            status: 200,
            content_type: alloc::format!("application/x-{}-result", service.name()),
            body: out,
        },
        // Do not leak internal error detail (paths/OS text) to the client (C5).
        Err(_) => HttpResponse::text(500, "internal error"),
    }
}

/// Parses the `service=` parameter from a raw query string.
fn service_from_query(query: &str) -> Option<Service> {
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("service=") {
            return match v {
                "git-upload-pack" => Some(Service::UploadPack),
                "git-receive-pack" => Some(Service::ReceivePack),
                _ => None,
            };
        }
    }
    None
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::object::Signature;
    use crate::odb::ObjectDatabase;

    fn sig() -> Signature {
        Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 0,
            tz: b"+0000".to_vec(),
        }
    }

    #[test]
    fn info_refs_advertises_service_appropriate_capabilities() {
        // Regression: `receive-pack` must advertise `report-status` (real git
        // treats a push as failed without it, even though it applied), and
        // `upload-pack` advertises `thin-pack`. Verified against real git 2.51.
        let dir = std::env::temp_dir().join(alloc::format!("puregit-caps-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x\n").unwrap();
        repo.add_path("a.txt").unwrap();
        repo.commit(b"c\n", sig(), sig()).unwrap();

        let up = handle_http(&repo, "GET", "/info/refs", "service=git-upload-pack", &[]);
        assert!(
            up.body.windows(9).any(|w| w == b"thin-pack"),
            "upload-pack advert should offer thin-pack"
        );

        let rp = handle_http(&repo, "GET", "/info/refs", "service=git-receive-pack", &[]);
        assert!(
            rp.body.windows(13).any(|w| w == b"report-status"),
            "receive-pack advert must offer report-status"
        );
        assert!(
            rp.body.windows(11).any(|w| w == b"delete-refs"),
            "receive-pack advert should offer delete-refs"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn http_info_refs_and_upload_pack_round_trip() {
        // Remote repo with a commit.
        let dir = std::env::temp_dir().join(alloc::format!("puregit-http-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let remote = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        remote.add_path("a.txt").unwrap();
        let tip = remote.commit(b"c\n", sig(), sig()).unwrap();

        // GET info/refs?service=git-upload-pack → advertisement carrying the tip.
        let adv = handle_http(
            &remote,
            "GET",
            "/repo.git/info/refs",
            "service=git-upload-pack",
            &[],
        );
        assert_eq!(adv.status, 200);
        assert_eq!(
            adv.content_type,
            "application/x-git-upload-pack-advertisement"
        );
        let packets = pktline::decode_all(&adv.body).unwrap();
        // First packet is the "# service=…" banner.
        assert!(matches!(&packets[0], pktline::Packet::Data(d) if d.starts_with(b"# service=")));

        // POST git-upload-pack with a want for the tip → NAK + pack.
        let mut req = crate::protocol::FetchRequest::default();
        req.wants.push(tip);
        let request = req.encode().unwrap();
        let resp = handle_http(&remote, "POST", "/repo.git/git-upload-pack", "", &request);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/x-git-upload-pack-result");

        // The pack in the response ingests into a fresh repo and yields the tip.
        let pack_off = resp.body.windows(4).position(|w| w == b"PACK").unwrap();
        let dest = std::env::temp_dir().join(alloc::format!("puregit-http-dst-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let mut clone = Repository::init(&dest).unwrap();
        clone.ingest_pack(&resp.body[pack_off..]).unwrap();
        clone.reload_odb().unwrap();
        assert!(clone.objects().contains(&tip));

        // An unknown route is a 404.
        assert_eq!(handle_http(&remote, "GET", "/nope", "", &[]).status, 404);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn oversized_body_is_rejected_413() {
        // A tiny repo suffices; the body cap is checked before any processing.
        let dir = std::env::temp_dir().join(alloc::format!("puregit-http-cap-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();

        let config = ServerConfig {
            max_body: 16,
            ..ServerConfig::default()
        };
        let big = alloc::vec![b'x'; 17];
        let resp = handle_http_with(&repo, &config, "POST", "/r.git/git-upload-pack", "", &big);
        assert_eq!(resp.status, 413);
        // A body at the limit is accepted past the cap check (it then fails to
        // parse as a request, but crucially not with 413).
        let ok = alloc::vec![b'x'; 16];
        let resp2 = handle_http_with(&repo, &config, "POST", "/r.git/git-upload-pack", "", &ok);
        assert_ne!(resp2.status, 413);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_receive_pack_is_forbidden_403() {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-http-ro-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();

        let config = ServerConfig::read_only();
        // Push is rejected with 403, before any body processing.
        let resp = handle_http_with(
            &repo,
            &config,
            "POST",
            "/r.git/git-receive-pack",
            "",
            b"anything",
        );
        assert_eq!(resp.status, 403);
        // Discovery for the disabled service is also forbidden.
        let disc = handle_http_with(
            &repo,
            &config,
            "GET",
            "/r.git/info/refs",
            "service=git-receive-pack",
            &[],
        );
        assert_eq!(disc.status, 403);
        // Read-only fetch still works.
        let up = handle_http_with(
            &repo,
            &config,
            "GET",
            "/r.git/info/refs",
            "service=git-upload-pack",
            &[],
        );
        assert_eq!(up.status, 200);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn error_500_body_leaks_no_path_detail() {
        // A malformed upload-pack body makes `upload_pack` return an error; the
        // 500 response body must be the generic message, not the error string.
        let dir = std::env::temp_dir().join(alloc::format!("puregit-http-500-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();

        // Bytes that decode as pkt-lines but carry no valid want → protocol error.
        let resp = handle_http(&repo, "POST", "/r.git/git-upload-pack", "", b"0009junk");
        assert_eq!(resp.status, 500);
        let body = core::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, "internal error");
        assert!(!body.contains('/'));
        assert!(!body.contains("error:"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
