//! Smart-HTTP(S) transport over [`rsurl`].
//!
//! Git's smart-HTTP protocol is two phases against a base URL `<repo>`:
//!
//! 1. **Ref discovery** — `GET <repo>/info/refs?service=git-upload-pack`, whose
//!    body is the service announcement (`# service=…\n`, a flush, then the v0/v1
//!    ref advertisement) or a v2 capability advertisement.
//! 2. **Service** — `POST <repo>/git-upload-pack` (or `git-receive-pack`) with
//!    `Content-Type: application/x-git-<service>-request`, the pkt-line request
//!    body, and the pack/report-status in the response.
//!
//! This module wires that onto the pure-Rust [`rsurl`] HTTP client. The request
//! shaping and response parsing are sans-IO ([`crate::protocol`]); this type
//! owns only the HTTP round-trips and the smart-HTTP envelope.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::HashAlgo;
use crate::protocol::RefAdvertisement;
use crate::protocol::pktline::{self, Packet};

use super::{Service, Transport};

/// A smart-HTTP(S) transport bound to a remote repository URL.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    base_url: String,
    algo: HashAlgo,
}

impl HttpTransport {
    /// Creates a transport for the repository at `base_url` (e.g.
    /// `https://github.com/owner/repo.git`).
    pub fn new(base_url: impl Into<String>, algo: HashAlgo) -> Self {
        HttpTransport {
            base_url: base_url.into(),
            algo,
        }
    }

    /// The `info/refs` discovery URL for a service.
    fn info_refs_url(&self, service: Service) -> String {
        alloc::format!(
            "{}/info/refs?service={}",
            self.base_url.trim_end_matches('/'),
            service.name()
        )
    }

    /// The service endpoint URL (the POST target).
    fn service_url(&self, service: Service) -> String {
        alloc::format!("{}/{}", self.base_url.trim_end_matches('/'), service.name())
    }
}

impl Transport for HttpTransport {
    fn discover(&mut self, service: Service) -> Result<RefAdvertisement> {
        let url = self.info_refs_url(service);
        let response = rsurl::Request::new("GET", &url)
            .map_err(map_rsurl_err)?
            .header("User-Agent", USER_AGENT)
            .header("Accept", "*/*")
            .send()
            .map_err(map_rsurl_err)?;

        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "info/refs returned HTTP {}",
                response.status
            )));
        }
        parse_smart_advertisement(self.algo, &response.body)
    }

    fn exchange(&mut self, service: Service, request: &[u8]) -> Result<Vec<u8>> {
        let url = self.service_url(service);
        let content_type = alloc::format!("application/x-{}-request", service.name());
        let accept = alloc::format!("application/x-{}-result", service.name());

        let response = rsurl::Request::new("POST", &url)
            .map_err(map_rsurl_err)?
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", &content_type)
            .header("Accept", &accept)
            .body(request.to_vec())
            .send()
            .map_err(map_rsurl_err)?;

        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "{} returned HTTP {}",
                service.name(),
                response.status
            )));
        }
        Ok(response.body)
    }
}

const USER_AGENT: &str = concat!("puregit/", env!("CARGO_PKG_VERSION"));

/// Parses a smart-HTTP `info/refs` advertisement body.
///
/// The smart response is prefixed with a service-announcement pkt-line
/// (`# service=git-upload-pack\n`) and a flush before the real v0/v1 ref
/// advertisement. This strips that prefix and parses the remainder. A dumb-HTTP
/// server (no service banner) is rejected with a clear error rather than
/// mis-parsed.
fn parse_smart_advertisement(algo: HashAlgo, body: &[u8]) -> Result<RefAdvertisement> {
    let packets = pktline::decode_all(body)?;

    let is_service_banner = matches!(
        packets.first(),
        Some(Packet::Data(d)) if d.starts_with(b"# service=")
    );
    if !is_service_banner {
        return Err(Error::Protocol(
            "info/refs: not a smart-HTTP advertisement (dumb HTTP unsupported)".into(),
        ));
    }

    // Skip the banner line and the flush that follows it.
    let mut start = 1;
    if matches!(packets.get(start), Some(Packet::Flush)) {
        start += 1;
    }
    RefAdvertisement::parse(algo, &packets[start..])
}

fn map_rsurl_err(e: rsurl::Error) -> Error {
    Error::Io(e.to_string())
}
