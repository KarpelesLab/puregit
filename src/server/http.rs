//! A framework-agnostic smart-HTTP request handler.
//!
//! [`handle_http`] maps the three smart-HTTP endpoints onto the transport-
//! agnostic [`advertise_refs`](super::advertise_refs) /
//! [`upload_pack`](super::upload_pack) / [`receive_pack`](super::receive_pack)
//! handlers, returning a plain `(status, content-type, body)` so it can be
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
//! a real server does.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::protocol::pktline;
use crate::repository::Repository;
use crate::transport::Service;

use super::{advertise_refs, receive_pack, upload_pack};

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

/// Handles one smart-HTTP request against `repo`.
///
/// `method` is the HTTP verb (`GET`/`POST`), `path` is the request path (only
/// its suffix is inspected, so any repository prefix is fine), `query` is the
/// raw query string (without `?`), and `body` is the request body (empty for
/// GET). Service selection comes from the path suffix and, for discovery, the
/// `service=` query parameter.
pub fn handle_http(
    repo: &Repository,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> HttpResponse {
    let path = path.trim_end_matches('/');

    if method.eq_ignore_ascii_case("GET") && path.ends_with("/info/refs") {
        let service = match service_from_query(query) {
            Some(s) => s,
            None => return HttpResponse::text(400, "missing or unknown service"),
        };
        return info_refs(repo, service);
    }

    if method.eq_ignore_ascii_case("POST") {
        if path.ends_with("/git-upload-pack") {
            return service_result(repo, Service::UploadPack, body);
        }
        if path.ends_with("/git-receive-pack") {
            return service_result(repo, Service::ReceivePack, body);
        }
    }

    HttpResponse::text(404, "not found")
}

/// Builds the `info/refs` smart advertisement: the `# service=…` banner
/// pkt-line and a flush, then the ref advertisement.
fn info_refs(repo: &Repository, service: Service) -> HttpResponse {
    let banner = alloc::format!("# service={}\n", service.name());
    let mut body = match pktline::encode_data(banner.as_bytes()) {
        Ok(b) => b,
        Err(e) => return HttpResponse::text(500, &e.to_string()),
    };
    body.extend_from_slice(&pktline::encode_control(&pktline::Packet::Flush));

    match advertise_refs(repo, service, &["ofs-delta"]) {
        Ok(adv) => body.extend_from_slice(&adv),
        Err(e) => return HttpResponse::text(500, &e.to_string()),
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
        Err(e) => HttpResponse::text(500, &e.to_string()),
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
}
