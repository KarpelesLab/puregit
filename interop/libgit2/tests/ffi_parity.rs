//! FFI parity: puregit's libgit2-shaped C ABI versus libgit2 itself.
//!
//! puregit's `ffi` feature exports `extern "C"` functions named after libgit2's
//! (`git_repository_open`, `git_object_lookup`, `git_blob_rawcontent`,
//! `git_commit_message`, ...). Those exported symbols would clash with the
//! vendored libgit2 in one binary, so puregit's side runs in a separate process:
//! the `ffi-probe` workspace member (built here on demand, into its own target
//! directory) calls the puregit functions and prints the results; this test
//! calls the same-named libgit2 functions through `libgit2-sys` on the same
//! repository and compares.
//!
//! Where puregit's signatures deliberately differ (ids are passed as hex
//! strings instead of `git_oid` structs, `git_repository_head_id` is a
//! convenience with no libgit2 twin), the libgit2 side uses the equivalent
//! call (`git_reference_name_to_id(.., "HEAD")`).

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::OnceLock;

use libgit2_sys as raw;
use puregit::HashAlgo;
use puregit_interop_libgit2::*;

/// Builds the probe once per test process and returns its path.
fn probe() -> &'static Path {
    static PROBE: OnceLock<PathBuf> = OnceLock::new();
    PROBE.get_or_init(|| {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        // A separate target directory: the outer `cargo test` holds the lock
        // on the main one while tests run, and the probe is built with a
        // different puregit feature set (`ffi`) anyway.
        let target_dir = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| manifest_dir.join("target"))
            .join("ffi-probe");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(cargo)
            .args([
                "build",
                "--quiet",
                "--offline",
                "--locked",
                "--manifest-path",
            ])
            .arg(manifest_dir.join("ffi-probe/Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .status()
            .expect("run cargo to build the ffi probe");
        assert!(status.success(), "building the ffi probe failed");
        let exe = format!("puregit-interop-ffi-probe{}", std::env::consts::EXE_SUFFIX);
        let path = target_dir.join("debug").join(exe);
        assert!(path.is_file(), "probe not found at {}", path.display());
        path
    })
}

/// Runs the probe on `repo` with the given queries; returns its output lines.
fn run_probe(repo: &Path, queries: &[String]) -> Vec<String> {
    let out = Command::new(probe())
        .arg(repo)
        .args(queries)
        .output()
        .expect("run ffi probe");
    assert!(
        out.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn oid_hex(id: *const raw::git_oid) -> String {
    let mut buf = [0 as c_char; 65];
    // SAFETY: `id` points at a live git_oid; `buf` holds 64 hex digits + NUL.
    unsafe {
        raw::git_oid_tostr(buf.as_mut_ptr(), buf.len(), id);
        CStr::from_ptr(buf.as_ptr()).to_str().unwrap().to_owned()
    }
}

/// libgit2's answers to the same queries, produced with the raw C functions
/// that puregit's FFI mirrors, in the probe's output format.
fn libgit2_answers(
    repo_path: &Path,
    queries: &[String],
    ids: &BTreeMap<String, git2::Oid>,
) -> Vec<String> {
    raw::init();
    let mut out = Vec::new();
    let c_path = CString::new(repo_path.to_str().unwrap()).unwrap();
    let mut repo: *mut raw::git_repository = ptr::null_mut();
    // SAFETY: plain libgit2 calls on valid pointers; every object is freed.
    unsafe {
        let rc = raw::git_repository_open(&mut repo, c_path.as_ptr());
        out.push(format!("open {rc}"));
        assert_eq!(rc, 0);

        let name_to_id = |name: &str| -> (i32, String) {
            let c = CString::new(name).unwrap();
            let mut oid: raw::git_oid = std::mem::zeroed();
            let rc = raw::git_reference_name_to_id(&mut oid, repo, c.as_ptr());
            (rc, if rc == 0 { oid_hex(&oid) } else { "-".into() })
        };
        let (rc, id) = name_to_id("HEAD");
        out.push(format!("head {rc} {id}"));

        for q in queries {
            if let Some(name) = q.strip_prefix("ref:") {
                let (rc, id) = name_to_id(name);
                out.push(format!("ref {name} {rc} {id}"));
            } else if let Some(hexid) = q.strip_prefix("obj:") {
                let oid = ids[hexid];
                // git2::Oid is a #[repr(C)] wrapper around the raw git_oid.
                let raw_oid = &oid as *const git2::Oid as *const raw::git_oid;
                let mut obj: *mut raw::git_object = ptr::null_mut();
                let rc = raw::git_object_lookup(&mut obj, repo, raw_oid, raw::GIT_OBJECT_ANY);
                if rc != 0 {
                    out.push(format!("obj {hexid} {rc} -"));
                    continue;
                }
                let ty = raw::git_object_type(obj);
                out.push(format!("obj {hexid} {rc} {ty}"));
                if ty == raw::GIT_OBJECT_BLOB {
                    let blob = obj as *const raw::git_blob;
                    let size = raw::git_blob_rawsize(blob) as usize;
                    let data = raw::git_blob_rawcontent(blob) as *const u8;
                    let content = if size == 0 {
                        &[][..]
                    } else {
                        std::slice::from_raw_parts(data, size)
                    };
                    out.push(format!("blob {hexid} {size} {}", hex(content)));
                } else if ty == raw::GIT_OBJECT_COMMIT {
                    let commit = obj as *const raw::git_commit;
                    let n = raw::git_commit_parentcount(commit);
                    let mut line = format!(
                        "commit {hexid} {} {n}",
                        oid_hex(raw::git_commit_tree_id(commit))
                    );
                    for i in 0..n {
                        line.push(' ');
                        line.push_str(&oid_hex(raw::git_commit_parent_id(commit, i)));
                    }
                    let msg = CStr::from_ptr(raw::git_commit_message(commit)).to_bytes();
                    line.push(' ');
                    line.push_str(&hex(msg));
                    out.push(line);
                }
                raw::git_object_free(obj);
            }
        }
        raw::git_repository_free(repo);
    }
    out
}

fn check_parity(algo: HashAlgo) {
    let dir = tmp();
    let work = dir.path();
    let g2 = g2_init(work, algo);
    let tree = g2_tree(
        &g2,
        &[
            ("a.txt", 0o100644, b"alpha\n"),
            ("bin", 0o100644, &[0, 1, 2, 0, 255]),
            ("empty", 0o100644, b""),
            ("dir/x", 0o100755, b"x\n"),
        ],
    );
    let c1 = g2_commit(&g2, tree, &[], 1, "first\n\nwith a body\n");
    let c2 = g2_commit(&g2, tree, &[c1], 2, "second\n");
    let c3 = g2_commit(&g2, tree, &[c1], 3, "side\n");
    let m = g2_commit(&g2, tree, &[c2, c3], 4, "merge \u{e9}\n");
    g2.reference("refs/heads/main", m, true, "x").unwrap();
    g2.reference("refs/heads/side", c3, true, "x").unwrap();
    let s = g2_sig(5, 0);
    let tag = g2
        .tag("v1", &g2.find_object(c2, None).unwrap(), &s, "t\n", false)
        .unwrap();
    g2.reference_symbolic("refs/remotes/origin/HEAD", "refs/heads/side", true, "x")
        .unwrap();

    let mut ids: BTreeMap<String, git2::Oid> = BTreeMap::new();
    for id in g2_all_oids(&g2) {
        ids.insert(id.to_string(), id);
    }
    // A well-formed id that does not exist.
    let missing = if algo == HashAlgo::Sha1 {
        "1".repeat(40)
    } else {
        "1".repeat(64)
    };
    ids.insert(
        missing.clone(),
        git2::Oid::from_str_ext(&missing, format_of(algo)).unwrap(),
    );
    assert!(ids.contains_key(&tag.to_string()));

    let mut queries: Vec<String> = [
        "refs/heads/main",
        "refs/heads/side",
        "refs/tags/v1",
        "refs/remotes/origin/HEAD",
        "refs/heads/does-not-exist",
    ]
    .iter()
    .map(|r| format!("ref:{r}"))
    .collect();
    queries.extend(ids.keys().map(|k| format!("obj:{k}")));

    let ours = run_probe(work, &queries);
    let theirs = libgit2_answers(work, &queries, &ids);
    // open + head + one line per query, plus blob/commit detail lines.
    assert!(ours.len() > queries.len() + 2, "probe output: {ours:?}");
    assert_eq!(ours, theirs);
}

#[test]
fn ffi_parity_sha1() {
    check_parity(HashAlgo::Sha1);
}

#[test]
fn ffi_parity_sha256() {
    check_parity(HashAlgo::Sha256);
}
