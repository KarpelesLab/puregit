//! Drives puregit's libgit2-shaped C ABI (feature `ffi`) and prints what it
//! sees, one fact per line, for `tests/ffi_parity.rs` to compare with
//! libgit2's answers on the same repository.
//!
//! Usage: `puregit-interop-ffi-probe <repo> [ref:<name>]... [obj:<hex>]...`
//!
//! Output lines (all ids in lowercase hex, byte strings hex-encoded):
//!
//! ```text
//! open <code>
//! head <code> <id>
//! ref <name> <code> <id>
//! obj <hex> <code> <type>
//! blob <hex> <size> <content-hex>
//! commit <hex> <tree> <parent-count> [<parent>...] <message-hex>
//! ```
//!
//! The functions are called through their exported `extern "C"` symbols —
//! exactly what a C program linking puregit's staticlib/cdylib would call.

use std::ffi::{CStr, CString, c_char};
use std::ptr;

use puregit::ffi::{self, git_object};
use puregit::repository::Repository;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn id_from(buf: &[c_char]) -> String {
    // SAFETY: the FFI writes a NUL-terminated string into `buf` on success.
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: probe <repo> [ref:<name>|obj:<hex>]...");
    let c_path = CString::new(path).unwrap();
    let mut repo: *mut Repository = ptr::null_mut();
    // SAFETY: valid out pointer and NUL-terminated path.
    let rc = unsafe { ffi::git_repository_open(&mut repo, c_path.as_ptr()) };
    println!("open {rc}");
    if rc != ffi::GIT_OK {
        return;
    }

    let mut buf = [0 as c_char; ffi::GIT_OID_HEXSZ + 1];
    // SAFETY: `buf` is large enough for any object id plus NUL.
    let rc = unsafe { ffi::git_repository_head_id(buf.as_mut_ptr(), buf.len(), repo) };
    println!(
        "head {rc} {}",
        if rc == 0 { id_from(&buf) } else { "-".into() }
    );

    for arg in args {
        if let Some(name) = arg.strip_prefix("ref:") {
            let c_name = CString::new(name).unwrap();
            let mut buf = [0 as c_char; ffi::GIT_OID_HEXSZ + 1];
            // SAFETY: as above; `c_name` is NUL-terminated.
            let rc = unsafe {
                ffi::git_reference_name_to_id(buf.as_mut_ptr(), buf.len(), repo, c_name.as_ptr())
            };
            let id = if rc == 0 { id_from(&buf) } else { "-".into() };
            println!("ref {name} {rc} {id}");
        } else if let Some(oid) = arg.strip_prefix("obj:") {
            let c_oid = CString::new(oid).unwrap();
            let mut obj: *mut git_object = ptr::null_mut();
            // SAFETY: valid out pointer, repository and NUL-terminated hex.
            let rc = unsafe { ffi::git_object_lookup(&mut obj, repo, c_oid.as_ptr()) };
            if rc != 0 {
                println!("obj {oid} {rc} -");
                continue;
            }
            // SAFETY: `obj` is a live object returned by git_object_lookup.
            unsafe {
                let ty = ffi::git_object_type(obj);
                let mut idbuf = [0 as c_char; ffi::GIT_OID_HEXSZ + 1];
                assert_eq!(ffi::git_object_id(idbuf.as_mut_ptr(), idbuf.len(), obj), 0);
                assert_eq!(id_from(&idbuf), oid, "git_object_id round-trip");
                println!("obj {oid} {rc} {ty}");
                if ty == ffi::GIT_OBJECT_BLOB {
                    let size = ffi::git_blob_rawsize(obj);
                    let data = ffi::git_blob_rawcontent(obj);
                    let content = if size == 0 {
                        &[][..]
                    } else {
                        std::slice::from_raw_parts(data, size)
                    };
                    println!("blob {oid} {size} {}", hex(content));
                } else if ty == ffi::GIT_OBJECT_COMMIT {
                    let mut tree = [0 as c_char; ffi::GIT_OID_HEXSZ + 1];
                    assert_eq!(
                        ffi::git_commit_tree_id(tree.as_mut_ptr(), tree.len(), obj),
                        0
                    );
                    let n = ffi::git_commit_parentcount(obj);
                    let mut line = format!("commit {oid} {} {n}", id_from(&tree));
                    for i in 0..n {
                        let mut p = [0 as c_char; ffi::GIT_OID_HEXSZ + 1];
                        assert_eq!(
                            ffi::git_commit_parent_id(p.as_mut_ptr(), p.len(), obj, i),
                            0
                        );
                        line.push(' ');
                        line.push_str(&id_from(&p));
                    }
                    let msg = CStr::from_ptr(ffi::git_commit_message(obj)).to_bytes();
                    line.push(' ');
                    line.push_str(&hex(msg));
                    println!("{line}");
                }
                ffi::git_object_free(obj);
            }
        }
    }
    // SAFETY: `repo` came from git_repository_open and is freed once.
    unsafe { ffi::git_repository_free(repo) };
}
