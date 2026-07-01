//! The Git LFS batch API request/response, sans-IO.
//!
//! Before transferring objects, an LFS client asks the server's batch endpoint
//! (`POST <lfs-url>/objects/batch`) which objects it may up/download and where.
//! This module builds that JSON request and parses the response into typed
//! actions — the byte transforms; the HTTP round-trip lives in
//! [`super::transfer`] (behind the `http` feature), so this part is testable
//! without a network.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

use super::Pointer;
use super::json::{self, Json};

/// Which side of a transfer the batch request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Fetching objects from the server.
    Download,
    /// Sending objects to the server.
    Upload,
}

impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Operation::Download => "download",
            Operation::Upload => "upload",
        }
    }
}

/// A transfer action for one object: where to send/get it and which headers to
/// attach (the server may hand back a signed CDN URL with auth headers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The URL to `GET` (download) or `PUT` (upload).
    pub href: String,
    /// Headers to include on the transfer request.
    pub headers: Vec<(String, String)>,
}

/// The batch server's decision for one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectResult {
    /// The object's SHA-256 (hex).
    pub oid: String,
    /// Its size in bytes.
    pub size: u64,
    /// The download action, if the server offers one.
    pub download: Option<Action>,
    /// The upload action, if the server wants the object (absent ⇒ already
    /// present server-side, nothing to upload).
    pub upload: Option<Action>,
    /// A per-object error message, if the server reported one.
    pub error: Option<String>,
}

/// Builds the batch-request JSON for `pointers` under `operation`.
pub fn build_request(operation: Operation, pointers: &[Pointer]) -> String {
    let mut out = String::new();
    out.push_str("{\"operation\":");
    out.push_str(&json::escape(operation.as_str()));
    out.push_str(",\"transfers\":[\"basic\"],\"objects\":[");
    for (i, p) in pointers.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"oid\":");
        out.push_str(&json::escape(&p.oid));
        out.push_str(",\"size\":");
        out.push_str(&p.size.to_string());
        out.push('}');
    }
    out.push_str("]}");
    out
}

/// Parses a batch-response body into per-object results.
pub fn parse_response(body: &str) -> Result<Vec<ObjectResult>> {
    let root = Json::parse(body)?;
    let objects = root
        .get("objects")
        .and_then(Json::as_array)
        .ok_or_else(|| Error::Protocol("lfs batch: no objects array".into()))?;

    let mut results = Vec::with_capacity(objects.len());
    for obj in objects {
        let oid = obj
            .get("oid")
            .and_then(Json::as_str)
            .ok_or_else(|| Error::Protocol("lfs batch: object missing oid".into()))?
            .to_string();
        let size = obj.get("size").and_then(Json::as_u64).unwrap_or(0);

        let error = obj
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Json::as_str)
            .map(String::from);

        let actions = obj.get("actions");
        let download = actions
            .and_then(|a| a.get("download"))
            .and_then(parse_action);
        let upload = actions.and_then(|a| a.get("upload")).and_then(parse_action);

        results.push(ObjectResult {
            oid,
            size,
            download,
            upload,
            error,
        });
    }
    Ok(results)
}

fn parse_action(action: &Json) -> Option<Action> {
    let href = action.get("href").and_then(Json::as_str)?.to_string();
    let mut headers = Vec::new();
    if let Some(Json::Obj(pairs)) = action.get("header") {
        for (k, v) in pairs {
            if let Some(v) = v.as_str() {
                headers.push((k.clone(), v.to_string()));
            }
        }
    }
    Some(Action { href, headers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_download_request() {
        let p = Pointer {
            oid: "abc".into(),
            size: 42,
        };
        let req = build_request(Operation::Download, &[p]);
        assert!(req.contains("\"operation\":\"download\""));
        assert!(req.contains("\"transfers\":[\"basic\"]"));
        assert!(req.contains("\"oid\":\"abc\""));
        assert!(req.contains("\"size\":42"));
    }

    #[test]
    fn parses_download_and_error() {
        let body = r#"{
            "objects": [
                {"oid":"a1","size":10,"actions":{"download":{"href":"https://x/a1","header":{"Authorization":"Bearer t"}}}},
                {"oid":"b2","size":20,"error":{"code":404,"message":"not found"}}
            ]
        }"#;
        let results = parse_response(body).unwrap();
        assert_eq!(results.len(), 2);

        let a = &results[0];
        assert_eq!(a.oid, "a1");
        assert_eq!(a.size, 10);
        let d = a.download.as_ref().unwrap();
        assert_eq!(d.href, "https://x/a1");
        assert_eq!(
            d.headers,
            alloc::vec![("Authorization".to_string(), "Bearer t".to_string())]
        );

        let b = &results[1];
        assert_eq!(b.error.as_deref(), Some("not found"));
        assert!(b.download.is_none());
    }
}
