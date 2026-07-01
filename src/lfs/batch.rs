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

/// Parses a batch *request* body (the server side of [`build_request`]) into
/// its operation and the requested objects.
pub fn parse_request(body: &str) -> Result<(Operation, Vec<Pointer>)> {
    let root = Json::parse(body)?;
    let operation = match root.get("operation").and_then(Json::as_str) {
        Some("download") => Operation::Download,
        Some("upload") => Operation::Upload,
        _ => {
            return Err(Error::Protocol(
                "lfs batch: missing/unknown operation".into(),
            ));
        }
    };
    let mut pointers = Vec::new();
    if let Some(objects) = root.get("objects").and_then(Json::as_array) {
        for obj in objects {
            let oid = obj
                .get("oid")
                .and_then(Json::as_str)
                .ok_or_else(|| Error::Protocol("lfs batch: object missing oid".into()))?;
            let size = obj.get("size").and_then(Json::as_u64).unwrap_or(0);
            pointers.push(Pointer {
                oid: oid.to_string(),
                size,
            });
        }
    }
    Ok((operation, pointers))
}

/// Serializes per-object results into a batch *response* body (the server side
/// of [`parse_response`]).
pub fn build_response(results: &[ObjectResult]) -> String {
    let mut out = String::new();
    out.push_str("{\"transfer\":\"basic\",\"objects\":[");
    for (i, r) in results.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"oid\":");
        out.push_str(&json::escape(&r.oid));
        out.push_str(",\"size\":");
        out.push_str(&r.size.to_string());
        if let Some(msg) = &r.error {
            out.push_str(",\"error\":{\"code\":404,\"message\":");
            out.push_str(&json::escape(msg));
            out.push('}');
        } else {
            let mut actions = String::new();
            if let Some(a) = &r.download {
                actions.push_str("\"download\":");
                actions.push_str(&action_json(a));
            }
            if let Some(a) = &r.upload {
                if !actions.is_empty() {
                    actions.push(',');
                }
                actions.push_str("\"upload\":");
                actions.push_str(&action_json(a));
            }
            if !actions.is_empty() {
                out.push_str(",\"actions\":{");
                out.push_str(&actions);
                out.push('}');
            }
        }
        out.push('}');
    }
    out.push_str("]}");
    out
}

fn action_json(action: &Action) -> String {
    let mut s = String::new();
    s.push_str("{\"href\":");
    s.push_str(&json::escape(&action.href));
    if !action.headers.is_empty() {
        s.push_str(",\"header\":{");
        for (i, (k, v)) in action.headers.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json::escape(k));
            s.push(':');
            s.push_str(&json::escape(v));
        }
        s.push('}');
    }
    s.push('}');
    s
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

    #[test]
    fn request_and_response_roundtrip() {
        // Request round-trips through build → parse.
        let ps = alloc::vec![
            Pointer {
                oid: "a1".into(),
                size: 10
            },
            Pointer {
                oid: "b2".into(),
                size: 20
            },
        ];
        let (op, back) = parse_request(&build_request(Operation::Upload, &ps)).unwrap();
        assert_eq!(op, Operation::Upload);
        assert_eq!(back, ps);

        // Response round-trips through build → parse (download action + error).
        let results = alloc::vec![
            ObjectResult {
                oid: "a1".into(),
                size: 10,
                download: Some(Action {
                    href: "https://x/a1".into(),
                    headers: alloc::vec![("Authorization".into(), "Bearer t".into())],
                }),
                upload: None,
                error: None,
            },
            ObjectResult {
                oid: "b2".into(),
                size: 20,
                download: None,
                upload: None,
                error: Some("nope".into()),
            },
        ];
        let parsed = parse_response(&build_response(&results)).unwrap();
        assert_eq!(parsed, results);
    }
}
