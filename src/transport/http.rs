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

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::HashAlgo;
use crate::protocol::RefAdvertisement;

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
        let _url = self.info_refs_url(service);
        let _algo = self.algo;
        // TODO: GET _url via rsurl, strip the "# service=…\n" banner + flush,
        // decode the remaining pkt-lines, and hand them to
        // RefAdvertisement::parse(self.algo, …).
        let _ = RefAdvertisement::parse(self.algo, &[]);
        Err(Error::Unsupported(
            "smart-HTTP transport: discover() not yet implemented".into(),
        ))
    }

    fn exchange(&mut self, service: Service, request: &[u8]) -> Result<Vec<u8>> {
        let _url = self.service_url(service);
        let _ = request;
        // TODO: POST _url with Content-Type
        // application/x-<service>-request and the pkt-line body via rsurl;
        // demultiplex the sideband and return the pack / report-status bytes.
        Err(Error::Unsupported(
            "smart-HTTP transport: exchange() not yet implemented".into(),
        ))
    }
}
