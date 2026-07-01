//! The Git LFS object transfer client (over [`rsurl`]).
//!
//! Given an LFS endpoint (derived from the git remote, e.g.
//! `https://host/owner/repo.git/info/lfs`), [`LfsClient`] runs the batch API to
//! learn where each object lives, then transfers it with the "basic" protocol:
//! a plain `GET` to download and `PUT` to upload, honoring the per-object auth
//! headers the batch server returns. This is the only network-touching part of
//! LFS; the request/response shaping is the sans-IO [`super::batch`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

use super::Pointer;
use super::batch::{self, Operation};

/// Content types the LFS batch API requires.
const LFS_JSON: &str = "application/vnd.git-lfs+json";

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
    pub fn download(&self, pointer: &Pointer, action: &batch::Action) -> Result<Vec<u8>> {
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
}
