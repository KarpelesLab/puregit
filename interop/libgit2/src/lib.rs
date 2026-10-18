//! Shared helpers for the puregit <-> libgit2 interop tests.
//!
//! Everything here exists to keep the tests *hermetic*: libgit2 must never read
//! the developer's (or the CI runner's) global/system git configuration, every
//! repository lives in a fresh temporary directory, and every signature carries
//! a fixed name, email, timestamp and timezone so object ids are reproducible.

use std::path::Path;
use std::sync::Once;

use git2::{ConfigLevel, ObjectFormat, RepositoryInitOptions};
use puregit::{HashAlgo, ObjectId};

pub use tempfile::TempDir;

static HERMETIC: Once = Once::new();

/// Points libgit2's global, XDG, system and ProgramData config search paths at
/// an empty directory (once per process), so no user or machine configuration
/// (`init.defaultBranch`, `core.autocrlf`, `user.*`, hooks paths, ...) leaks
/// into a test. Called by every constructor below.
pub fn hermetic() {
    HERMETIC.call_once(|| {
        // A process-lifetime empty directory: leaked on purpose (the search
        // path must stay valid for as long as libgit2 may consult it).
        let dir = tempfile::Builder::new()
            .prefix("puregit-interop-noconfig-")
            .tempdir()
            .expect("create empty config dir")
            .keep();
        for level in [
            ConfigLevel::System,
            ConfigLevel::XDG,
            ConfigLevel::Global,
            ConfigLevel::ProgramData,
        ] {
            // SAFETY: libgit2 options are process-global; this runs exactly
            // once (guarded by `Once`) before any repository is opened.
            unsafe { git2::opts::set_search_path(level, &dir) }.expect("set config search path");
        }
        // The temp dirs created below may be owned differently from what
        // libgit2 expects on some CI images; ownership checks are irrelevant
        // for throwaway test repositories.
        // SAFETY: as above, process-global and set once.
        unsafe { git2::opts::set_verify_owner_validation(false) }.expect("disable owner check");
    });
}

/// A fresh temporary directory.
pub fn tmp() -> TempDir {
    hermetic();
    tempfile::Builder::new()
        .prefix("puregit-interop-")
        .tempdir()
        .expect("create temp dir")
}

/// The libgit2 object format matching a puregit hash algorithm.
pub fn format_of(algo: HashAlgo) -> ObjectFormat {
    match algo {
        HashAlgo::Sha1 => ObjectFormat::Sha1,
        HashAlgo::Sha256 => ObjectFormat::Sha256,
    }
}

/// Initializes a non-bare libgit2 repository at `path` with `HEAD ->
/// refs/heads/main`, `core.autocrlf=false` and a fixed `user.*` identity.
pub fn g2_init(path: &Path, algo: HashAlgo) -> git2::Repository {
    hermetic();
    let mut opts = RepositoryInitOptions::new();
    opts.initial_head("main")
        .object_format(format_of(algo))
        .no_reinit(true);
    let repo = git2::Repository::init_opts(path, &opts).expect("libgit2 init");
    {
        let mut cfg = repo.config().expect("config");
        cfg.set_bool("core.autocrlf", false).unwrap();
        cfg.set_str("user.name", "Interop Tester").unwrap();
        cfg.set_str("user.email", "interop@example.com").unwrap();
    }
    repo
}

/// Initializes a puregit repository at `path` (HEAD -> refs/heads/main) and
/// pins `core.autocrlf=false` plus a fixed `user.*` identity in its config.
pub fn pg_init(path: &Path, algo: HashAlgo) -> puregit::Repository {
    hermetic();
    let repo = puregit::Repository::init_with(path, algo).expect("puregit init");
    let mut cfg = repo.config().unwrap();
    cfg.set("core", None, "autocrlf", "false");
    cfg.set("user", None, "name", "Interop Tester");
    cfg.set("user", None, "email", "interop@example.com");
    repo.write_config(&cfg).unwrap();
    repo
}

/// A libgit2 signature with a fixed identity at `time` (seconds) and `offset`
/// (minutes east of UTC).
pub fn g2_sig(time: i64, offset_minutes: i32) -> git2::Signature<'static> {
    git2::Signature::new(
        "Interop Tester",
        "interop@example.com",
        &git2::Time::new(time, offset_minutes),
    )
    .unwrap()
}

/// Formats a timezone offset in minutes the way git writes it (`+0530`).
pub fn tz_string(offset_minutes: i32) -> String {
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let m = offset_minutes.abs();
    format!("{sign}{:02}{:02}", m / 60, m % 60)
}

/// A puregit signature equal to [`g2_sig`] with the same arguments.
pub fn pg_sig(time: i64, offset_minutes: i32) -> puregit::object::Signature {
    puregit::object::Signature {
        name: b"Interop Tester".to_vec(),
        email: b"interop@example.com".to_vec(),
        time,
        tz: tz_string(offset_minutes).into_bytes(),
    }
}

/// Converts a libgit2 object id to puregit's.
pub fn pg_oid(id: git2::Oid) -> ObjectId {
    let algo = match id.as_bytes().len() {
        20 => HashAlgo::Sha1,
        32 => HashAlgo::Sha256,
        n => panic!("unexpected oid length {n}"),
    };
    ObjectId::from_bytes(algo, id.as_bytes()).unwrap()
}

/// Converts a puregit object id to libgit2's.
pub fn g2_oid(id: &ObjectId) -> git2::Oid {
    git2::Oid::from_bytes(id.as_bytes()).unwrap()
}

/// puregit's object type for a libgit2 one (blob/tree/commit/tag only).
pub fn pg_type(kind: git2::ObjectType) -> puregit::ObjectType {
    match kind {
        git2::ObjectType::Blob => puregit::ObjectType::Blob,
        git2::ObjectType::Tree => puregit::ObjectType::Tree,
        git2::ObjectType::Commit => puregit::ObjectType::Commit,
        git2::ObjectType::Tag => puregit::ObjectType::Tag,
        other => panic!("not a concrete object type: {other:?}"),
    }
}

/// Every object id in a libgit2 object database, sorted.
pub fn g2_all_oids(repo: &git2::Repository) -> Vec<git2::Oid> {
    let odb = repo.odb().unwrap();
    let mut out = Vec::new();
    odb.foreach(|id| {
        out.push(*id);
        true
    })
    .unwrap();
    out.sort();
    out.dedup();
    out
}

/// Asserts that puregit reads every object libgit2 knows about with the same
/// type and byte-identical content, and that puregit's hash of that content is
/// the object's id. Returns how many objects were compared.
pub fn assert_pg_reads_all(g2: &git2::Repository, pg: &puregit::Repository) -> usize {
    use puregit::odb::ObjectDatabase;
    let odb = g2.odb().unwrap();
    let ids = g2_all_oids(g2);
    for id in &ids {
        let obj = odb.read(*id).unwrap();
        let pid = pg_oid(*id);
        let (ty, payload) = pg
            .objects()
            .read(&pid)
            .unwrap_or_else(|e| panic!("puregit cannot read {pid}: {e}"));
        assert_eq!(ty, pg_type(obj.kind()), "type of {pid}");
        assert_eq!(payload, obj.data(), "content of {pid}");
        assert_eq!(
            puregit::hash::hash_object(pg.algo(), ty, &payload),
            pid,
            "puregit hash of {pid}"
        );
        // The typed parse must succeed for every kind, and re-serializing the
        // parsed object must reproduce libgit2's bytes exactly.
        let parsed = puregit::Object::parse(pg.algo(), ty, &payload)
            .unwrap_or_else(|e| panic!("puregit cannot parse {pid}: {e}"));
        assert_eq!(parsed.payload(), payload, "re-serialized {pid}");
    }
    ids.len()
}

/// Asserts that libgit2 reads every given puregit object with the same type
/// and byte-identical content.
pub fn assert_g2_reads(g2: &git2::Repository, pg: &puregit::Repository, ids: &[ObjectId]) {
    use puregit::odb::ObjectDatabase;
    let odb = g2.odb().unwrap();
    for id in ids {
        let (ty, payload) = pg.objects().read(id).unwrap();
        let obj = odb
            .read(g2_oid(id))
            .unwrap_or_else(|e| panic!("libgit2 cannot read {id}: {e}"));
        assert_eq!(pg_type(obj.kind()), ty, "type of {id}");
        assert_eq!(obj.data(), payload.as_slice(), "content of {id}");
        // libgit2's full object parser must accept it too.
        g2.find_object(g2_oid(id), None)
            .unwrap_or_else(|e| panic!("libgit2 cannot parse {id}: {e}"));
    }
}

/// The raw stat mode git stores for a tree entry mode.
pub fn mode_bits(mode: puregit::object::FileMode) -> i32 {
    use puregit::object::FileMode;
    match mode {
        FileMode::Tree => 0o040000,
        FileMode::Regular => 0o100644,
        FileMode::Executable => 0o100755,
        FileMode::Symlink => 0o120000,
        FileMode::Gitlink => 0o160000,
    }
}

/// Whether the platform can create symlinks without special privileges.
pub fn symlinks_supported() -> bool {
    cfg!(unix)
}

/// Whether the platform has POSIX executable bits.
pub fn exec_bits_supported() -> bool {
    cfg!(unix)
}

/// Writes `content` to `root/rel`, creating parent directories.
pub fn write_file(root: &Path, rel: &str, content: &[u8]) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, content).unwrap();
}

/// Sets or clears the executable bit of a file (no-op without POSIX modes).
pub fn set_executable(path: &Path, exec: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(if exec { 0o755 } else { 0o644 });
        std::fs::set_permissions(path, perm).unwrap();
    }
    #[cfg(not(unix))]
    {
        let _ = (path, exec);
    }
}

/// One file of a tree spec: `(slash-separated path, git mode, content)`. For a
/// gitlink (`0o160000`) the content is the hex id of the referenced commit.
pub type FileSpec<'a> = (&'a str, i32, &'a [u8]);

/// Builds (with libgit2) the nested tree for a flat list of files and returns
/// its id. Blobs are written to the repository's object database.
pub fn g2_tree(repo: &git2::Repository, files: &[FileSpec<'_>]) -> git2::Oid {
    type Flat<'a> = Vec<(Vec<&'a str>, i32, &'a [u8])>;
    fn build(repo: &git2::Repository, files: &Flat<'_>) -> git2::Oid {
        use std::collections::BTreeMap;
        let mut tb = repo.treebuilder(None).unwrap();
        let mut subdirs: BTreeMap<&str, Flat<'_>> = BTreeMap::new();
        for (parts, mode, content) in files {
            if parts.len() == 1 {
                let id = if *mode == 0o160000 {
                    git2::Oid::from_str_ext(
                        std::str::from_utf8(content).unwrap(),
                        repo.object_format(),
                    )
                    .unwrap()
                } else {
                    repo.blob(content).unwrap()
                };
                tb.insert(parts[0], id, *mode).unwrap();
            } else {
                subdirs
                    .entry(parts[0])
                    .or_default()
                    .push((parts[1..].to_vec(), *mode, content));
            }
        }
        for (name, sub) in subdirs {
            let id = build(repo, &sub);
            tb.insert(name, id, 0o040000).unwrap();
        }
        tb.write().unwrap()
    }
    let split: Flat<'_> = files
        .iter()
        .map(|(p, m, c)| (p.split('/').collect(), *m, *c))
        .collect();
    build(repo, &split)
}

/// Creates a commit (with libgit2) of `tree` on top of `parents` at a fixed
/// time, without moving any ref. Returns the commit id.
pub fn g2_commit(
    repo: &git2::Repository,
    tree: git2::Oid,
    parents: &[git2::Oid],
    time: i64,
    message: &str,
) -> git2::Oid {
    let tree = repo.find_tree(tree).unwrap();
    let parents: Vec<git2::Commit<'_>> = parents
        .iter()
        .map(|p| repo.find_commit(*p).unwrap())
        .collect();
    let parent_refs: Vec<&git2::Commit<'_>> = parents.iter().collect();
    let sig = g2_sig(time, 0);
    repo.commit(None, &sig, &sig, message, &tree, &parent_refs)
        .unwrap()
}

/// Builds the same nested tree with puregit's object model and returns its id.
pub fn pg_tree(repo: &puregit::Repository, files: &[FileSpec<'_>]) -> ObjectId {
    use puregit::object::{FileMode, Tree, TreeEntry};
    use std::collections::BTreeMap;
    type Flat<'a> = Vec<(Vec<&'a str>, i32, &'a [u8])>;
    fn mode_of(bits: i32) -> FileMode {
        FileMode::from_mode_bits(bits as u32).unwrap()
    }
    fn build(repo: &puregit::Repository, files: &Flat<'_>) -> ObjectId {
        let mut tree = Tree::default();
        let mut subdirs: BTreeMap<&str, Flat<'_>> = BTreeMap::new();
        for (parts, mode, content) in files {
            if parts.len() == 1 {
                let id = if *mode == 0o160000 {
                    ObjectId::from_hex(repo.algo(), std::str::from_utf8(content).unwrap()).unwrap()
                } else {
                    repo.write_object(puregit::ObjectType::Blob, content)
                        .unwrap()
                };
                tree.entries.push(TreeEntry {
                    mode: mode_of(*mode),
                    name: parts[0].as_bytes().to_vec(),
                    id,
                });
            } else {
                subdirs
                    .entry(parts[0])
                    .or_default()
                    .push((parts[1..].to_vec(), *mode, content));
            }
        }
        for (name, sub) in subdirs {
            let id = build(repo, &sub);
            tree.entries.push(TreeEntry {
                mode: FileMode::Tree,
                name: name.as_bytes().to_vec(),
                id,
            });
        }
        repo.write_object(puregit::ObjectType::Tree, &tree.serialize())
            .unwrap()
    }
    let split: Flat<'_> = files
        .iter()
        .map(|(p, m, c)| (p.split('/').collect(), *m, *c))
        .collect();
    build(repo, &split)
}

/// Creates a commit with puregit's object model (no ref is moved).
pub fn pg_commit(
    repo: &puregit::Repository,
    tree: ObjectId,
    parents: &[ObjectId],
    time: i64,
    message: &str,
) -> ObjectId {
    let c = puregit::object::Commit {
        tree,
        parents: parents.to_vec(),
        author: pg_sig(time, 0),
        committer: pg_sig(time, 0),
        extra_headers: Vec::new(),
        message: message.as_bytes().to_vec(),
    };
    repo.write_object(puregit::ObjectType::Commit, &c.serialize())
        .unwrap()
}
