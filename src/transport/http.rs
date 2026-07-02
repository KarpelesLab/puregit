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
    ///
    /// `base_url` is the untrusted clone URL and is later interpolated into
    /// request URLs. It is validated on first use (in
    /// [`discover`](Transport::discover) / [`exchange`](Transport::exchange))
    /// rather than here, so this constructor stays infallible: the check
    /// requires an `http://` or `https://` scheme and rejects any control
    /// character (including CR, LF, and NUL) that could otherwise smuggle a
    /// second header or a confused request. TLS-certificate verification and
    /// redirect handling are the responsibility of the underlying `rsurl`
    /// client (finding B7); this layer does not weaken either.
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
        validate_base_url(&self.base_url)?;
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
        validate_base_url(&self.base_url)?;
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

/// Validates an untrusted clone `base_url` (finding B6).
///
/// Requires an `http://` or `https://` scheme (a `file://`, `javascript:`, or
/// scheme-relative URL is refused rather than delegated to `rsurl`) and rejects
/// any ASCII/Unicode control character. In particular CR and LF, if allowed
/// into a URL that is later interpolated into a request line, could split the
/// request or inject a header; NUL similarly has no place in a URL. This is a
/// deliberately minimal check — full URL parsing and the TLS/redirect policy
/// stay with `rsurl`.
fn validate_base_url(base_url: &str) -> Result<()> {
    let is_http = base_url.starts_with("http://") || base_url.starts_with("https://");
    if !is_http {
        return Err(Error::Protocol(
            "http url: scheme must be http:// or https://".into(),
        ));
    }
    if base_url.chars().any(|c| c.is_control()) {
        return Err(Error::Protocol(
            "http url: contains control characters (CR/LF/NUL)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_http_and_https() {
        assert!(validate_base_url("https://example.com/r.git").is_ok());
        assert!(validate_base_url("http://example.com/r.git").is_ok());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(validate_base_url("file:///etc/passwd").is_err());
        assert!(validate_base_url("ftp://example.com/r.git").is_err());
        assert!(validate_base_url("//example.com/r.git").is_err());
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_base_url("https://example.com/r.git\r\nHost: evil").is_err());
        assert!(validate_base_url("https://example.com/\nr.git").is_err());
        assert!(validate_base_url("https://example.com/\0r.git").is_err());
    }

    #[test]
    fn discover_rejects_bad_base_url() {
        // A non-http scheme is caught at first use even though `new` is infallible.
        let mut t = HttpTransport::new("file:///etc/passwd", HashAlgo::Sha1);
        assert!(matches!(
            t.discover(Service::UploadPack),
            Err(Error::Protocol(_))
        ));
    }
}
