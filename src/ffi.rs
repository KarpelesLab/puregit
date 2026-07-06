//! A C ABI (`libgit2`-shaped) surface for reading repositories from C.
//!
//! This module exposes a small, `libgit2`-flavoured set of `extern "C"` entry
//! points so a C (or any FFI-capable) program can open a repository and read its
//! refs and objects without the C toolchain the rest of the stack forbids —
//! puregit is pure Rust, and so is anything linking this surface.
//!
//! Conventions, following `libgit2`:
//!
//! - Functions return a `c_int` status: `0` ([`GIT_OK`]) on success, a negative
//!   code on failure. [`git_error_last`] returns the message for the most recent
//!   failure on the calling thread.
//! - Object ids cross the boundary as NUL-terminated hex strings. An out-param
//!   `(buf, len)` receives one; [`GIT_OID_HEXSZ`]` + 1` bytes always suffice.
//! - Handles (`*mut Repository`, `*mut git_object`) are opaque and owned by the
//!   caller, who must release each with the matching `_free`.
//! - Borrowed pointers returned by accessors (blob content, commit message) stay
//!   valid until the owning object is freed.
//!
//! Entry points are wrapped so a Rust panic can never unwind across the FFI
//! boundary (which would be undefined behaviour); a caught panic becomes
//! [`GIT_ERROR`].
//!
//! This is the one module permitted `unsafe`: a C ABI cannot be expressed
//! without raw pointers and `extern "C"`. Every `unsafe` here is a documented
//! pointer-validity contract at the boundary; the rest of the crate stays safe.

#![allow(unsafe_code)]
// `git_object` follows the C/`libgit2` naming, not Rust's `CamelCase`.
#![allow(non_camel_case_types)]

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ffi::{c_char, c_int, c_uint};
use core::ptr;
use std::ffi::{CStr, CString};

use crate::object::{Commit, Object, ObjectType};
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;
use crate::repository::Repository;

/// Success.
pub const GIT_OK: c_int = 0;
/// A generic error; see [`git_error_last`].
pub const GIT_ERROR: c_int = -1;
/// The requested object or reference does not exist.
pub const GIT_ENOTFOUND: c_int = -3;
/// A supplied argument was invalid (null pointer, bad UTF-8, buffer too small).
pub const GIT_EINVALID: c_int = -6;

/// `git_object_t`: an object's type (matches `libgit2`'s numbering).
pub const GIT_OBJECT_COMMIT: c_int = 1;
/// A tree object.
pub const GIT_OBJECT_TREE: c_int = 2;
/// A blob object.
pub const GIT_OBJECT_BLOB: c_int = 3;
/// A tag object.
pub const GIT_OBJECT_TAG: c_int = 4;

/// The number of hex characters in a SHA-256 object id — the largest id, so
/// `GIT_OID_HEXSZ + 1` bytes hold any id's hex string plus its NUL terminator.
pub const GIT_OID_HEXSZ: usize = 64;

thread_local! {
    /// The most recent error message on this thread (see [`git_error_last`]).
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Records `msg` as this thread's last error and returns `code`.
fn fail(code: c_int, msg: impl Into<String>) -> c_int {
    let text = msg.into();
    let c = CString::new(text).unwrap_or_default();
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(c));
    code
}

/// Runs an FFI body, converting any panic into [`GIT_ERROR`] so unwinding never
/// crosses the C boundary.
fn guard(f: impl FnOnce() -> c_int + core::panic::UnwindSafe) -> c_int {
    match std::panic::catch_unwind(f) {
        Ok(code) => code,
        Err(_) => fail(GIT_ERROR, "puregit: internal panic"),
    }
}

/// Returns the message for the calling thread's most recent failure, or `NULL`
/// if none. The pointer is valid until the next puregit call on this thread.
///
/// # Safety
/// The returned pointer must not be freed or used after the next call.
#[unsafe(no_mangle)]
pub extern "C" fn git_error_last() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ref().map_or(ptr::null(), |c| c.as_ptr()))
}

/// Borrows a `&str` from a C string pointer, or `None` if null / not UTF-8.
///
/// # Safety
/// `p` must be null or point to a valid NUL-terminated string.
unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

/// Writes `hex` and a NUL into the caller's `(buf, len)`, or errors if the
/// buffer is null or too small.
///
/// # Safety
/// `buf` must be null or point to at least `len` writable bytes.
unsafe fn write_hex(buf: *mut c_char, len: usize, hex: &str) -> c_int {
    if buf.is_null() {
        return fail(GIT_EINVALID, "output buffer is null");
    }
    if len < hex.len() + 1 {
        return fail(GIT_EINVALID, "output buffer too small for object id");
    }
    unsafe {
        ptr::copy_nonoverlapping(hex.as_ptr(), buf.cast::<u8>(), hex.len());
        *buf.add(hex.len()) = 0;
    }
    GIT_OK
}

/// Returns the puregit implementation version as a NUL-terminated string.
#[unsafe(no_mangle)]
pub extern "C" fn git_libgit2_version_string() -> *const c_char {
    // A 'static NUL-terminated build constant; safe to hand out indefinitely.
    concat!("puregit ", env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Opens an existing repository at `path`. On success `*out` owns a handle that
/// must be released with [`git_repository_free`].
///
/// # Safety
/// `out` must be a valid pointer to a `*mut Repository`; `path` a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_repository_open(
    out: *mut *mut Repository,
    path: *const c_char,
) -> c_int {
    guard(|| {
        if out.is_null() {
            return fail(GIT_EINVALID, "out pointer is null");
        }
        let Some(path) = (unsafe { cstr(path) }) else {
            return fail(GIT_EINVALID, "path is null or not utf-8");
        };
        match Repository::open(path) {
            Ok(repo) => {
                unsafe { *out = Box::into_raw(Box::new(repo)) };
                GIT_OK
            }
            Err(e) => fail(GIT_ENOTFOUND, format!("open {path}: {e}")),
        }
    })
}

/// Creates (or reinitialises) a repository at `path`. `is_bare` is currently
/// advisory — puregit initialises a standard repository. On success `*out` owns
/// a handle to be released with [`git_repository_free`].
///
/// # Safety
/// `out` must be valid; `path` a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_repository_init(
    out: *mut *mut Repository,
    path: *const c_char,
    _is_bare: c_uint,
) -> c_int {
    guard(|| {
        if out.is_null() {
            return fail(GIT_EINVALID, "out pointer is null");
        }
        let Some(path) = (unsafe { cstr(path) }) else {
            return fail(GIT_EINVALID, "path is null or not utf-8");
        };
        match Repository::init(path) {
            Ok(repo) => {
                unsafe { *out = Box::into_raw(Box::new(repo)) };
                GIT_OK
            }
            Err(e) => fail(GIT_ERROR, format!("init {path}: {e}")),
        }
    })
}

/// Frees a repository handle. A null pointer is ignored.
///
/// # Safety
/// `repo` must be a handle from [`git_repository_open`]/[`git_repository_init`]
/// that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_repository_free(repo: *mut Repository) {
    if !repo.is_null() {
        drop(unsafe { Box::from_raw(repo) });
    }
}

/// Writes the object id `HEAD` resolves to into `(buf, len)` as a hex string.
///
/// # Safety
/// `repo` must be a live handle; `buf` must point to `len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_repository_head_id(
    buf: *mut c_char,
    len: usize,
    repo: *mut Repository,
) -> c_int {
    guard(|| {
        let Some(repo) = (unsafe { repo.as_ref() }) else {
            return fail(GIT_EINVALID, "repository is null");
        };
        match repo.head_id() {
            Ok(id) => unsafe { write_hex(buf, len, &id.to_hex()) },
            Err(e) => fail(GIT_ENOTFOUND, format!("HEAD: {e}")),
        }
    })
}

/// Resolves reference `name` to an object id, written into `(buf, len)` as hex.
///
/// # Safety
/// `repo` must be live; `buf` must point to `len` writable bytes; `name` a valid
/// C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_reference_name_to_id(
    buf: *mut c_char,
    len: usize,
    repo: *mut Repository,
    name: *const c_char,
) -> c_int {
    guard(|| {
        let Some(repo) = (unsafe { repo.as_ref() }) else {
            return fail(GIT_EINVALID, "repository is null");
        };
        let Some(name) = (unsafe { cstr(name) }) else {
            return fail(GIT_EINVALID, "reference name is null or not utf-8");
        };
        match repo.refs().resolve(name) {
            Ok(id) => unsafe { write_hex(buf, len, &id.to_hex()) },
            Err(e) => fail(GIT_ENOTFOUND, format!("resolve {name}: {e}")),
        }
    })
}

/// An object read out of the store, owned by the caller.
///
/// Holds the raw payload (for [`git_blob_rawcontent`]) and, for a commit, its
/// pre-rendered message and parent/tree ids so accessor pointers stay stable for
/// the object's lifetime.
pub struct git_object {
    id: ObjectId,
    ty: ObjectType,
    payload: Vec<u8>,
    commit_message: Option<CString>,
    commit_tree: Option<ObjectId>,
    commit_parents: Vec<ObjectId>,
}

/// Looks up the object named by the hex id `oid_hex`. On success `*out` owns a
/// handle to be released with [`git_object_free`].
///
/// # Safety
/// `out` and `repo` must be valid; `oid_hex` a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_object_lookup(
    out: *mut *mut git_object,
    repo: *mut Repository,
    oid_hex: *const c_char,
) -> c_int {
    guard(|| {
        if out.is_null() {
            return fail(GIT_EINVALID, "out pointer is null");
        }
        let Some(repo) = (unsafe { repo.as_ref() }) else {
            return fail(GIT_EINVALID, "repository is null");
        };
        let Some(hex) = (unsafe { cstr(oid_hex) }) else {
            return fail(GIT_EINVALID, "oid is null or not utf-8");
        };
        let id = match ObjectId::from_hex(repo.algo(), hex) {
            Ok(id) => id,
            Err(e) => return fail(GIT_EINVALID, format!("bad oid {hex}: {e}")),
        };
        let (ty, payload) = match repo.objects().read(&id) {
            Ok(o) => o,
            Err(e) => return fail(GIT_ENOTFOUND, format!("lookup {hex}: {e}")),
        };

        // For a commit, pre-render the fields the accessors expose so their
        // returned pointers remain valid for the object's whole lifetime.
        let (mut msg, mut tree, mut parents) = (None, None, Vec::new());
        if ty == ObjectType::Commit
            && let Ok(Object::Commit(Commit {
                tree: t,
                parents: p,
                message,
                ..
            })) = Object::parse(repo.algo(), ty, &payload)
        {
            msg = Some(CString::new(message).unwrap_or_default());
            tree = Some(t);
            parents = p;
        }

        let obj = Box::new(git_object {
            id,
            ty,
            payload,
            commit_message: msg,
            commit_tree: tree,
            commit_parents: parents,
        });
        unsafe { *out = Box::into_raw(obj) };
        GIT_OK
    })
}

/// Returns the object's `git_object_t` type constant, or `GIT_ERROR` if null.
///
/// # Safety
/// `obj` must be a live handle or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_object_type(obj: *const git_object) -> c_int {
    let Some(obj) = (unsafe { obj.as_ref() }) else {
        return GIT_ERROR;
    };
    match obj.ty {
        ObjectType::Commit => GIT_OBJECT_COMMIT,
        ObjectType::Tree => GIT_OBJECT_TREE,
        ObjectType::Blob => GIT_OBJECT_BLOB,
        ObjectType::Tag => GIT_OBJECT_TAG,
    }
}

/// Writes the object's own id into `(buf, len)` as a hex string.
///
/// # Safety
/// `obj` must be live; `buf` must point to `len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_object_id(
    buf: *mut c_char,
    len: usize,
    obj: *const git_object,
) -> c_int {
    let Some(obj) = (unsafe { obj.as_ref() }) else {
        return fail(GIT_EINVALID, "object is null");
    };
    unsafe { write_hex(buf, len, &obj.id.to_hex()) }
}

/// Frees an object handle. A null pointer is ignored.
///
/// # Safety
/// `obj` must be a handle from [`git_object_lookup`] not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_object_free(obj: *mut git_object) {
    if !obj.is_null() {
        drop(unsafe { Box::from_raw(obj) });
    }
}

/// Returns a pointer to a blob's raw bytes (see [`git_blob_rawsize`]), valid
/// until the object is freed, or `NULL` if the object is not a blob.
///
/// # Safety
/// `obj` must be a live handle or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_blob_rawcontent(obj: *const git_object) -> *const u8 {
    match unsafe { obj.as_ref() } {
        Some(o) if o.ty == ObjectType::Blob => o.payload.as_ptr(),
        _ => ptr::null(),
    }
}

/// Returns a blob's size in bytes, or `0` if the object is not a blob.
///
/// # Safety
/// `obj` must be a live handle or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_blob_rawsize(obj: *const git_object) -> usize {
    match unsafe { obj.as_ref() } {
        Some(o) if o.ty == ObjectType::Blob => o.payload.len(),
        _ => 0,
    }
}

/// Returns a commit's message as a NUL-terminated string, valid until the object
/// is freed, or `NULL` if the object is not a commit.
///
/// # Safety
/// `obj` must be a live handle or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_commit_message(obj: *const git_object) -> *const c_char {
    match unsafe { obj.as_ref() } {
        Some(o) => o
            .commit_message
            .as_ref()
            .map_or(ptr::null(), |m| m.as_ptr()),
        None => ptr::null(),
    }
}

/// Writes a commit's tree id into `(buf, len)` as hex.
///
/// # Safety
/// `obj` must be live; `buf` must point to `len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_commit_tree_id(
    buf: *mut c_char,
    len: usize,
    obj: *const git_object,
) -> c_int {
    let Some(obj) = (unsafe { obj.as_ref() }) else {
        return fail(GIT_EINVALID, "object is null");
    };
    match &obj.commit_tree {
        Some(id) => unsafe { write_hex(buf, len, &id.to_hex()) },
        None => fail(GIT_EINVALID, "object is not a commit"),
    }
}

/// Returns the number of parents of a commit (`0` if not a commit).
///
/// # Safety
/// `obj` must be a live handle or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_commit_parentcount(obj: *const git_object) -> usize {
    match unsafe { obj.as_ref() } {
        Some(o) => o.commit_parents.len(),
        None => 0,
    }
}

/// Writes the id of a commit's `n`-th parent into `(buf, len)` as hex.
///
/// # Safety
/// `obj` must be live; `buf` must point to `len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn git_commit_parent_id(
    buf: *mut c_char,
    len: usize,
    obj: *const git_object,
    n: usize,
) -> c_int {
    let Some(obj) = (unsafe { obj.as_ref() }) else {
        return fail(GIT_EINVALID, "object is null");
    };
    match obj.commit_parents.get(n) {
        Some(id) => unsafe { write_hex(buf, len, &id.to_hex()) },
        None => fail(GIT_EINVALID, "parent index out of range"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the C entry points the way a C caller would — through raw
    /// pointers and out-params — without a C compiler.
    #[test]
    fn c_surface_reads_a_repository() {
        use crate::object::Signature;

        let dir = std::env::temp_dir().join(format!("puregit-ffi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = CString::new(dir.to_str().unwrap()).unwrap();

        // init
        let mut repo: *mut Repository = ptr::null_mut();
        assert_eq!(
            unsafe { git_repository_init(&mut repo, path.as_ptr(), 0) },
            GIT_OK
        );
        assert!(!repo.is_null());

        // Stage a commit through the Rust API (the C surface here is read-only).
        {
            let r = unsafe { &*repo };
            std::fs::write(dir.join("a.txt"), b"hello ffi\n").unwrap();
            r.add_path("a.txt").unwrap();
            let sig = Signature {
                name: b"T".to_vec(),
                email: b"t@e".to_vec(),
                time: 1_700_000_000,
                tz: b"+0000".to_vec(),
            };
            r.commit(b"ffi commit\n", sig.clone(), sig).unwrap();
        }

        // HEAD id via the C surface.
        let mut buf = [0i8; GIT_OID_HEXSZ + 1];
        assert_eq!(
            unsafe { git_repository_head_id(buf.as_mut_ptr(), buf.len(), repo) },
            GIT_OK
        );
        let head_hex = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(head_hex.len(), 40);

        // refs/heads/main resolves to the same id.
        let name = CString::new("refs/heads/main").unwrap();
        let mut buf2 = [0i8; GIT_OID_HEXSZ + 1];
        assert_eq!(
            unsafe { git_reference_name_to_id(buf2.as_mut_ptr(), buf2.len(), repo, name.as_ptr()) },
            GIT_OK
        );
        assert_eq!(
            unsafe { CStr::from_ptr(buf2.as_ptr()) }.to_str().unwrap(),
            head_hex
        );

        // Look the commit up, check its type and message.
        let head_c = CString::new(head_hex.clone()).unwrap();
        let mut obj: *mut git_object = ptr::null_mut();
        assert_eq!(
            unsafe { git_object_lookup(&mut obj, repo, head_c.as_ptr()) },
            GIT_OK
        );
        assert_eq!(unsafe { git_object_type(obj) }, GIT_OBJECT_COMMIT);
        let msg = unsafe { CStr::from_ptr(git_commit_message(obj)) }
            .to_str()
            .unwrap();
        assert_eq!(msg, "ffi commit\n");
        assert_eq!(unsafe { git_commit_parentcount(obj) }, 0);

        // The commit's tree, looked up as an object, is a tree.
        let mut tree_hex = [0i8; GIT_OID_HEXSZ + 1];
        assert_eq!(
            unsafe { git_commit_tree_id(tree_hex.as_mut_ptr(), tree_hex.len(), obj) },
            GIT_OK
        );
        let mut tree_obj: *mut git_object = ptr::null_mut();
        assert_eq!(
            unsafe {
                git_object_lookup(
                    &mut tree_obj,
                    repo,
                    CStr::from_ptr(tree_hex.as_ptr()).as_ptr(),
                )
            },
            GIT_OK
        );
        assert_eq!(unsafe { git_object_type(tree_obj) }, GIT_OBJECT_TREE);

        // A missing object reports GIT_ENOTFOUND and sets the last error.
        let bogus = CString::new("0".repeat(40)).unwrap();
        let mut missing: *mut git_object = ptr::null_mut();
        assert_eq!(
            unsafe { git_object_lookup(&mut missing, repo, bogus.as_ptr()) },
            GIT_ENOTFOUND
        );
        assert!(!git_error_last().is_null());

        unsafe {
            git_object_free(tree_obj);
            git_object_free(obj);
            git_repository_free(repo);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
