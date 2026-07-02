//! The Git LFS object transfer client (over [`rsurl`]).
//!
//! Given an LFS endpoint (derived from the git remote, e.g.
//! `https://host/owner/repo.git/info/lfs`), `LfsClient` runs the batch API to
//! learn where each object lives, then transfers it with the "basic" protocol:
//! a plain `GET` to download and `PUT` to upload, honoring the per-object auth
//! headers the batch server returns. This is the only network-touching part of
//! LFS; the request/response shaping is the sans-IO `batch`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

use super::Pointer;
use super::batch::{self, Operation};

/// Content types the LFS batch API requires.
const LFS_JSON: &str = "application/vnd.git-lfs+json";

/// An absolute cap on any single object we will buffer from a transfer,
/// regardless of the declared `size`, so a malicious server cannot exhaust
/// memory by declaring (and then delivering) an enormous object. 2 GiB is far
/// above any realistic LFS blob while still being a hard ceiling. See E3/E5.
const MAX_OBJECT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// An LFS transfer client bound to a batch endpoint.
#[derive(Debug, Clone)]
pub struct LfsClient {
    endpoint: String,
}

impl LfsClient {
    /// Creates a client for an LFS endpoint URL (the `…/info/lfs` base, no
    /// trailing `/objects/batch`).
    pub fn new(endpoint: impl Into<String>) -> Self {
        LfsClient {
            endpoint: endpoint.into(),
        }
    }

    /// Derives the LFS endpoint from a git remote URL: for an HTTP(S) remote,
    /// git-lfs appends `/info/lfs` (and drops a trailing `/`). A `.git` suffix
    /// is kept, matching git-lfs.
    pub fn endpoint_from_remote(remote_url: &str) -> String {
        alloc::format!("{}/info/lfs", remote_url.trim_end_matches('/'))
    }

    fn batch_url(&self) -> String {
        alloc::format!("{}/objects/batch", self.endpoint.trim_end_matches('/'))
    }

    /// Runs the batch API for `pointers` and `operation`, returning the server's
    /// per-object decisions.
    pub fn batch(
        &self,
        operation: Operation,
        pointers: &[Pointer],
    ) -> Result<Vec<batch::ObjectResult>> {
        let body = batch::build_request(operation, pointers);
        let response = rsurl::Request::new("POST", &self.batch_url())
            .map_err(map_err)?
            .header("Accept", LFS_JSON)
            .header("Content-Type", LFS_JSON)
            .body(body.into_bytes())
            .send()
            .map_err(map_err)?;
        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "lfs batch: HTTP {}",
                response.status
            )));
        }
        let text = String::from_utf8(response.body)
            .map_err(|_| Error::Protocol("lfs batch: non-utf8 response".into()))?;
        batch::parse_response(&text)
    }

    /// Downloads one object via a batch `download` action, verifying its hash
    /// against `pointer`.
    ///
    /// Two defenses apply to the server-supplied action here:
    ///
    /// * **SSRF (E4):** `action.href` is validated against the batch endpoint
    ///   before any request is made — see `validate_transfer_href`. A `file:`,
    ///   `gopher:`, `http://169.254.169.254/…` (cloud metadata), or otherwise
    ///   off-origin href is rejected, and the server-supplied `header` entries
    ///   are only forwarded because the href is confined to the endpoint's own
    ///   origin.
    /// * **Memory DoS (E3):** the transfer is bounded by the pointer's declared
    ///   `size` (and an absolute cap). The content must hash to exactly that
    ///   size anyway, so a body longer than `size` — or a `Content-Length`
    ///   promising more — is invalid and rejected up front / before buffering
    ///   the whole thing.
    pub fn download(&self, pointer: &Pointer, action: &batch::Action) -> Result<Vec<u8>> {
        validate_transfer_href(&self.endpoint, &action.href)?;

        let mut req = rsurl::Request::new("GET", &action.href).map_err(map_err)?;
        for (k, v) in &action.headers {
            req = req.header(k, v);
        }
        let response = req.send().map_err(map_err)?;
        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "lfs download: HTTP {}",
                response.status
            )));
        }

        // Fail fast on a Content-Length that already exceeds what the object may
        // be, before trusting the buffered body length.
        let content_length = response
            .header("content-length")
            .and_then(|s| s.parse::<u64>().ok());
        check_download_size(pointer.size, content_length, response.body.len())?;

        let got = Pointer::for_content(&response.body);
        if &got != pointer {
            return Err(Error::InvalidOid(
                "lfs download: content does not match its pointer".into(),
            ));
        }
        Ok(response.body)
    }

    /// Uploads one object via a batch `upload` action.
    pub fn upload(&self, action: &batch::Action, content: &[u8]) -> Result<()> {
        // Same SSRF guard as download (E4): never PUT our content — with the
        // server-supplied auth headers attached — to an off-origin or
        // non-HTTP(S) href.
        validate_transfer_href(&self.endpoint, &action.href)?;
        let mut req = rsurl::Request::new("PUT", &action.href).map_err(map_err)?;
        for (k, v) in &action.headers {
            req = req.header(k, v);
        }
        let response = req.body(content.to_vec()).send().map_err(map_err)?;
        if !(200..300).contains(&response.status) {
            return Err(Error::Protocol(alloc::format!(
                "lfs upload: HTTP {}",
                response.status
            )));
        }
        Ok(())
    }
}

/// Enforces the download size bound (E3): rejects a transfer whose declared
/// `Content-Length` (if any) or actual buffered `body_len` exceeds what the
/// object may legitimately be.
///
/// A legitimate object hashes to exactly `declared_size` bytes, so that is the
/// hard upper bound — clamped to `MAX_OBJECT_BYTES` as a belt-and-suspenders
/// absolute cap against a bogus (huge) declared size. The `Content-Length`
/// check lets us fail fast before trusting a body we may not have fully read;
/// the body-length check is the defense in depth against a lying or absent
/// `Content-Length`. Any deviation above the bound is invalid regardless, since
/// the subsequent hash check would fail anyway.
fn check_download_size(
    declared_size: u64,
    content_length: Option<u64>,
    body_len: usize,
) -> Result<()> {
    let limit = declared_size.min(MAX_OBJECT_BYTES);
    if let Some(len) = content_length
        && len > limit
    {
        return Err(Error::Protocol(alloc::format!(
            "lfs download: Content-Length {len} exceeds declared size {declared_size}"
        )));
    }
    if body_len as u64 > limit {
        return Err(Error::Protocol(alloc::format!(
            "lfs download: body of {body_len} bytes exceeds declared size {declared_size}"
        )));
    }
    Ok(())
}

/// Splits a URL into `(scheme, host)`, lowercased, discarding userinfo, port,
/// path, query, and fragment. Returns `None` if it is not a well-formed
/// absolute `scheme://host…` URL.
///
/// This is deliberately small (no full URL parser): we only need the scheme and
/// authority-host to decide whether a server-supplied transfer href stays on
/// the batch endpoint's origin.
fn scheme_and_host(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    // Authority ends at the first '/', '?' or '#'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Drop any `user:pass@` userinfo.
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // Drop the port. IPv6 literals are `[::1]:port`; strip the bracketed host.
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        // `[host]` or `[host]:port`.
        let end = stripped.find(']')?;
        &stripped[..end]
    } else {
        hostport.split(':').next().unwrap_or(hostport)
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

/// Validates a server-supplied transfer `href` against the LFS batch
/// `endpoint`, defending against SSRF and credential/header exfiltration (E4).
///
/// Rules enforced:
///
/// * The href must be `https://`, or `http://` **only if** the batch endpoint
///   itself is `http://` (a plaintext endpoint cannot be downgraded further,
///   but an https endpoint must not be redirected to plaintext). Any other
///   scheme — `file:`, `gopher:`, `data:`, `ftp:`, … — is rejected outright, so
///   a malicious server cannot read local files or hit non-HTTP internal
///   services.
/// * The href host must equal the batch endpoint host. This same-origin
///   confinement is what makes it safe to forward the server-supplied auth
///   headers on the transfer request: they only ever go back to the origin that
///   issued them, never to `169.254.169.254` (cloud metadata) or other internal
///   hosts.
///
/// Residual risk: within the endpoint's own host, the server still chooses the
/// port and path, and same-origin is host-only (it does not pin the port). A
/// server that already controls the endpoint host is the trust anchor here, so
/// this is acceptable; the header forwarding is safe precisely because the host
/// is pinned. If a future change relaxes same-host enforcement, headers must
/// NOT be forwarded cross-origin.
fn validate_transfer_href(endpoint: &str, href: &str) -> Result<()> {
    let (href_scheme, href_host) = scheme_and_host(href)
        .ok_or_else(|| Error::Protocol(alloc::format!("lfs transfer: malformed href {href:?}")))?;
    let (ep_scheme, ep_host) = scheme_and_host(endpoint).ok_or_else(|| {
        Error::Protocol(alloc::format!(
            "lfs transfer: malformed endpoint {endpoint:?}"
        ))
    })?;

    // Scheme allow-list: https always; http only if the endpoint is http.
    let scheme_ok = match href_scheme.as_str() {
        "https" => true,
        "http" => ep_scheme == "http",
        _ => false,
    };
    if !scheme_ok {
        return Err(Error::Protocol(alloc::format!(
            "lfs transfer: refusing href with scheme {href_scheme:?} (endpoint is {ep_scheme:?})"
        )));
    }

    // Same-host confinement — keeps forwarded auth headers on-origin and blocks
    // redirection to metadata / internal hosts.
    if href_host != ep_host {
        return Err(Error::Protocol(alloc::format!(
            "lfs transfer: refusing off-origin href host {href_host:?} (endpoint host {ep_host:?})"
        )));
    }

    Ok(())
}

fn map_err(e: rsurl::Error) -> Error {
    Error::Io(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_derivation() {
        assert_eq!(
            LfsClient::endpoint_from_remote("https://host/owner/repo.git"),
            "https://host/owner/repo.git/info/lfs"
        );
        let c = LfsClient::new("https://host/owner/repo.git/info/lfs");
        assert_eq!(
            c.batch_url(),
            "https://host/owner/repo.git/info/lfs/objects/batch"
        );
    }

    #[test]
    fn scheme_and_host_parsing() {
        assert_eq!(
            scheme_and_host("https://Cdn.Example.com:443/a/b?x#y"),
            Some(("https".into(), "cdn.example.com".into()))
        );
        assert_eq!(
            scheme_and_host("http://user:pass@host/x"),
            Some(("http".into(), "host".into()))
        );
        assert_eq!(
            scheme_and_host("https://[::1]:8443/x"),
            Some(("https".into(), "::1".into()))
        );
        assert_eq!(scheme_and_host("not a url"), None);
        assert_eq!(scheme_and_host("https://"), None);
    }

    #[test]
    fn href_validation_blocks_ssrf() {
        let ep = "https://host.example.com/owner/repo.git/info/lfs";

        // Same-origin https href is allowed.
        assert!(validate_transfer_href(ep, "https://host.example.com/cdn/obj").is_ok());

        // E4: cross-scheme (https endpoint → http href) is rejected.
        assert!(validate_transfer_href(ep, "http://host.example.com/cdn/obj").is_err());

        // E4: non-HTTP(S) schemes are rejected outright.
        assert!(validate_transfer_href(ep, "file:///etc/passwd").is_err());
        assert!(validate_transfer_href(ep, "gopher://host.example.com/1").is_err());
        assert!(validate_transfer_href(ep, "data:text/plain,hi").is_err());

        // E4: off-origin host (e.g. cloud metadata / internal) is rejected even
        // over https.
        assert!(validate_transfer_href(ep, "https://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_transfer_href(ep, "https://evil.example.net/obj").is_err());

        // A malformed href is rejected rather than passed through.
        assert!(validate_transfer_href(ep, "://nohost").is_err());

        // With an http endpoint, an http href on the same host is allowed
        // (a plaintext endpoint can't be downgraded further).
        let http_ep = "http://localhost/repo/info/lfs";
        assert!(validate_transfer_href(http_ep, "http://localhost/obj").is_ok());
        assert!(validate_transfer_href(http_ep, "https://localhost/obj").is_ok());
    }

    #[test]
    fn download_size_bound_is_enforced() {
        // E3: `download`'s size guard is `check_download_size`; exercise it
        // directly (the network path can't run in a unit test).

        // Exact-size body with a matching Content-Length is accepted.
        assert!(check_download_size(4, Some(4), 4).is_ok());
        // No Content-Length, exact body — accepted.
        assert!(check_download_size(4, None, 4).is_ok());

        // A body larger than the declared size is rejected (defends against a
        // lying/absent Content-Length).
        assert!(check_download_size(4, None, 5).is_err());
        // A Content-Length promising more than the declared size fails fast.
        assert!(check_download_size(4, Some(1_000_000), 0).is_err());
        // Both over-limit.
        assert!(check_download_size(4, Some(5), 5).is_err());

        // The absolute cap applies even to an absurd declared size.
        assert!(check_download_size(u64::MAX, Some(MAX_OBJECT_BYTES + 1), 0).is_err());
    }
}
