//! A framework-agnostic Git LFS server handler.
//!
//! Mirrors [`super::http`] for the LFS transfer API: [`handle_lfs_http`] routes
//! the LFS endpoints onto a [`LfsStore`] and returns a plain [`HttpResponse`],
//! so any HTTP stack can serve LFS objects for a repository.
//!
//! Routes (relative to the repository's LFS base URL):
//! - `POST …/info/lfs/objects/batch` — the batch API (download/upload actions).
//! - `GET  …/lfs/<oid>` — download an object's content.
//! - `PUT  …/lfs/<oid>` — upload an object's content.
//!
//! Object transfer URLs are built from `base_url` (the externally reachable
//! `…/info/lfs` base), so the batch response points clients back at this
//! handler. Auth/authorization is the caller's responsibility.

use alloc::string::ToString;

use crate::lfs::batch::{self, Action, ObjectResult, Operation};
use crate::lfs::{LfsStore, Pointer};
use crate::vfs::Vfs;

use super::http::HttpResponse;

/// Handles one LFS HTTP request against `store`. `base_url` is the externally
/// reachable `…/info/lfs` base used to build object transfer URLs.
pub fn handle_lfs_http<V: Vfs>(
    store: &LfsStore<V>,
    method: &str,
    path: &str,
    base_url: &str,
    body: &[u8],
) -> HttpResponse {
    let path = path.trim_end_matches('/');

    if method.eq_ignore_ascii_case("POST") && path.ends_with("/objects/batch") {
        return handle_batch(store, base_url, body);
    }
    // Object transfer URLs are `<base>/lfs/<oid>`.
    if let Some(oid) = path.rsplit_once("/lfs/").map(|(_, o)| o) {
        if method.eq_ignore_ascii_case("GET") {
            return handle_download(store, oid);
        }
        if method.eq_ignore_ascii_case("PUT") {
            return handle_upload(store, oid, body);
        }
    }
    http_text(404, "not found")
}

/// Serves the batch API: for each requested object decide the transfer action.
fn handle_batch<V: Vfs>(store: &LfsStore<V>, base_url: &str, body: &[u8]) -> HttpResponse {
    let body = match core::str::from_utf8(body) {
        Ok(b) => b,
        Err(_) => return http_text(400, "non-utf8 body"),
    };
    let (operation, pointers) = match batch::parse_request(body) {
        Ok(v) => v,
        Err(e) => return http_text(400, &e.to_string()),
    };

    let base = base_url.trim_end_matches('/');
    let mut results = alloc::vec::Vec::with_capacity(pointers.len());
    for p in pointers {
        let href = alloc::format!("{base}/lfs/{}", p.oid);
        let (download, upload, error) = match operation {
            Operation::Download => {
                if store.contains(&p.oid) {
                    (Some(action(href)), None, None)
                } else {
                    (None, None, Some("object not found".to_string()))
                }
            }
            Operation::Upload => {
                if store.contains(&p.oid) {
                    (None, None, None) // already present — no upload needed
                } else {
                    (None, Some(action(href)), None)
                }
            }
        };
        results.push(ObjectResult {
            oid: p.oid,
            size: p.size,
            download,
            upload,
            error,
        });
    }

    HttpResponse {
        status: 200,
        content_type: "application/vnd.git-lfs+json".into(),
        body: batch::build_response(&results).into_bytes(),
    }
}

fn handle_download<V: Vfs>(store: &LfsStore<V>, oid: &str) -> HttpResponse {
    match store.read(oid) {
        Ok(content) => HttpResponse {
            status: 200,
            content_type: "application/octet-stream".into(),
            body: content,
        },
        Err(_) => http_text(404, "object not found"),
    }
}

fn handle_upload<V: Vfs>(store: &LfsStore<V>, oid: &str, body: &[u8]) -> HttpResponse {
    let pointer = Pointer::for_content(body);
    if pointer.oid != oid {
        return http_text(422, "uploaded content does not match oid");
    }
    match store.write_verified(&pointer, body) {
        Ok(()) => http_text(200, "ok"),
        Err(e) => http_text(500, &e.to_string()),
    }
}

fn action(href: alloc::string::String) -> Action {
    Action {
        href,
        headers: alloc::vec::Vec::new(),
    }
}

fn http_text(status: u16, msg: &str) -> HttpResponse {
    HttpResponse {
        status,
        content_type: "text/plain".into(),
        body: msg.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::StdFs;

    #[test]
    fn batch_download_and_object_transfer() {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-lfssrv-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = LfsStore::new(StdFs::new(&dir));

        let content = b"the large object bytes";
        let pointer = store.write(content).unwrap();

        // Batch download → an action href pointing back at this handler.
        let req = batch::build_request(Operation::Download, core::slice::from_ref(&pointer));
        let resp = handle_lfs_http(
            &store,
            "POST",
            "/r.git/info/lfs/objects/batch",
            "https://host/r.git/info/lfs",
            req.as_bytes(),
        );
        assert_eq!(resp.status, 200);
        let results = batch::parse_response(core::str::from_utf8(&resp.body).unwrap()).unwrap();
        let href = &results[0].download.as_ref().unwrap().href;
        assert_eq!(
            href,
            &alloc::format!("https://host/r.git/info/lfs/lfs/{}", pointer.oid)
        );

        // GET that href's path → the object bytes.
        let get = handle_lfs_http(&store, "GET", href, "https://host/r.git/info/lfs", &[]);
        assert_eq!(get.status, 200);
        assert_eq!(get.body, content);

        // Uploading a new object via PUT stores it.
        let new = b"a brand new object";
        let new_ptr = Pointer::for_content(new);
        let put_path = alloc::format!("/r.git/info/lfs/lfs/{}", new_ptr.oid);
        let put = handle_lfs_http(&store, "PUT", &put_path, "https://host", new);
        assert_eq!(put.status, 200);
        assert!(store.contains(&new_ptr.oid));

        // A download for a missing object reports an error, not an action.
        let missing = Pointer {
            oid: "00".repeat(32),
            size: 1,
        };
        let req2 = batch::build_request(Operation::Download, core::slice::from_ref(&missing));
        let resp2 = handle_lfs_http(
            &store,
            "POST",
            "/x/objects/batch",
            "https://host",
            req2.as_bytes(),
        );
        let r2 = batch::parse_response(core::str::from_utf8(&resp2.body).unwrap()).unwrap();
        assert!(r2[0].error.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pull_smudges_worktree_from_lfs_server() {
        use crate::repository::Repository;

        // "Server side": a store holding the real content of a tracked file.
        let srv_dir =
            std::env::temp_dir().join(alloc::format!("puregit-lfspull-srv-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&srv_dir);
        std::fs::create_dir_all(&srv_dir).unwrap();
        let server_store = LfsStore::new(StdFs::new(&srv_dir));
        let real: alloc::vec::Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        let pointer = server_store.write(&real).unwrap();

        // "Client side": a fresh repo whose working tree holds only the pointer
        // (as it would just after a clone that skipped LFS content).
        let cli_dir =
            std::env::temp_dir().join(alloc::format!("puregit-lfspull-cli-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&cli_dir);
        std::fs::create_dir_all(&cli_dir).unwrap();
        let repo = Repository::init(&cli_dir).unwrap();
        std::fs::write(cli_dir.join("asset.bin"), pointer.serialize()).unwrap();
        // Stage the pointer file so it is in the index (bypassing the clean
        // filter, which is not configured here).
        {
            let id = repo
                .write_object(crate::object::ObjectType::Blob, &pointer.serialize())
                .unwrap();
            let mut idx = repo.index().unwrap();
            idx.entries.push(crate::index::IndexEntry {
                ctime: (0, 0),
                mtime: (0, 0),
                dev: 0,
                ino: 0,
                mode: 0o100644,
                uid: 0,
                gid: 0,
                size: 0,
                id,
                stage: 0,
                assume_valid: false,
                path: b"asset.bin".to_vec(),
            });
            repo.write_index(&idx).unwrap();
        }

        // The fetch callback drives the LFS transfer protocol against the server
        // handler (batch → download), entirely in-process.
        let fetch = |p: &Pointer| -> crate::error::Result<alloc::vec::Vec<u8>> {
            let req = batch::build_request(Operation::Download, core::slice::from_ref(p));
            let resp = handle_lfs_http(
                &server_store,
                "POST",
                "/info/lfs/objects/batch",
                "http://srv/info/lfs",
                req.as_bytes(),
            );
            let results = batch::parse_response(core::str::from_utf8(&resp.body).unwrap()).unwrap();
            let action = results[0]
                .download
                .as_ref()
                .ok_or_else(|| crate::error::Error::Protocol("no download action".into()))?;
            let get = handle_lfs_http(
                &server_store,
                "GET",
                &action.href,
                "http://srv/info/lfs",
                &[],
            );
            Ok(get.body)
        };

        let n = repo.lfs_smudge_worktree(fetch).unwrap();
        assert_eq!(n, 1);
        // The pointer file is now the real content, and the client store has it.
        assert_eq!(std::fs::read(cli_dir.join("asset.bin")).unwrap(), real);
        assert!(repo.lfs_store().contains(&pointer.oid));

        let _ = std::fs::remove_dir_all(&srv_dir);
        let _ = std::fs::remove_dir_all(&cli_dir);
    }
}
