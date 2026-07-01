//! The on-disk repository — the std-level entry point.
//!
//! [`Repository`] wires the [`crate::odb`] loose store, the [`crate::refs`]
//! store, the [`crate::config`] file, and the [`crate::index`] together over a
//! [`crate::vfs::StdFs`] rooted at the git directory. It is the type most
//! callers start from: [`Repository::init`] creates a new repository and
//! [`Repository::open`] discovers an existing one.
//!
//! Today this provides repository creation/discovery, object read/write, ref
//! resolution (including `HEAD`), and config/index access. Higher-level
//! porcelain (commit, checkout, status, fetch/push) builds on these and lands
//! incrementally — see the roadmap.

use alloc::string::{String, ToString};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::index::Index;
use crate::object::{Object, ObjectType};
use crate::odb::{CombinedOdb, ObjectDatabase};
use crate::oid::{HashAlgo, ObjectId};
use crate::refs::{RefStore, Reference};
use crate::vfs::{StdFs, Vfs};

/// An opened git repository.
pub struct Repository {
    /// Absolute path to the git directory (the `.git` dir, or the repo root for
    /// a bare repo).
    git_dir: PathBuf,
    /// Absolute path to the working tree root, if this is not a bare repo.
    work_tree: Option<PathBuf>,
    algo: HashAlgo,
    odb: CombinedOdb<StdFs>,
    refs: RefStore<StdFs>,
}

impl Repository {
    /// Initializes a new repository at `path`.
    ///
    /// Creates `path/.git` with the standard layout (`objects/`, `refs/heads`,
    /// `refs/tags`, a default `config`, and a `HEAD` pointing at
    /// `refs/heads/main`). The repository uses SHA-1 object names; pass
    /// [`Repository::init_with`] to choose SHA-256.
    pub fn init(path: impl AsRef<Path>) -> Result<Self> {
        Self::init_with(path, HashAlgo::Sha1)
    }

    /// Initializes a new repository with an explicit hash algorithm.
    pub fn init_with(path: impl AsRef<Path>, algo: HashAlgo) -> Result<Self> {
        let work_tree = path.as_ref().to_path_buf();
        let git_dir = work_tree.join(".git");
        let fs = StdFs::new(&git_dir);

        fs.create_dir_all("objects/pack")?;
        fs.create_dir_all("objects/info")?;
        fs.create_dir_all("refs/heads")?;
        fs.create_dir_all("refs/tags")?;

        let mut config = Config::new();
        config.set(
            "core",
            None,
            "repositoryformatversion",
            if algo == HashAlgo::Sha256 { "1" } else { "0" },
        );
        config.set("core", None, "filemode", "true");
        config.set("core", None, "bare", "false");
        if algo == HashAlgo::Sha256 {
            // The extensions.objectformat marker required by SHA-256 repos.
            config.set("extensions", None, "objectformat", "sha256");
        }
        fs.write("config", config.serialize().as_bytes())?;
        fs.write("HEAD", b"ref: refs/heads/main\n")?;

        Self::assemble(git_dir, Some(work_tree), algo)
    }

    /// Opens an existing repository by discovering the git directory at or above
    /// `path`.
    ///
    /// Ascends from `path` toward the filesystem root: the first directory with
    /// a `.git` subdirectory becomes the work tree (its `.git` the git
    /// directory). If `path` itself looks like a bare git directory (has `HEAD`
    /// and `objects/`), it is opened bare. This mirrors `git`'s discovery, so
    /// commands work from any subdirectory of a repository.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let start = path.as_ref();

        // Walk up looking for `<dir>/.git`.
        let mut cur = Some(start);
        while let Some(dir) = cur {
            let dot_git = dir.join(".git");
            if dot_git.is_dir() {
                let algo = detect_algo(&dot_git)?;
                return Self::assemble(dot_git, Some(dir.to_path_buf()), algo);
            }
            cur = dir.parent();
        }

        // Otherwise accept `path` itself as a bare repository.
        if start.join("HEAD").is_file() && start.join("objects").is_dir() {
            let algo = detect_algo(start)?;
            return Self::assemble(start.to_path_buf(), None, algo);
        }

        Err(Error::Io(alloc::format!(
            "no git repository found at {}",
            start.display()
        )))
    }

    fn assemble(git_dir: PathBuf, work_tree: Option<PathBuf>, algo: HashAlgo) -> Result<Self> {
        let odb = CombinedOdb::open(StdFs::new(git_dir.join("objects")), algo)?;
        let refs = RefStore::new(StdFs::new(&git_dir), algo);
        Ok(Repository {
            git_dir,
            work_tree,
            algo,
            odb,
            refs,
        })
    }

    /// Reloads the object database, picking up packs added since `open`.
    ///
    /// [`CombinedOdb`] loads packfiles eagerly at open time, so a pack written
    /// after this repository was opened (e.g. by a just-completed fetch) is not
    /// visible until the store is rebuilt. Call this after ingesting a pack.
    pub fn reload_odb(&mut self) -> Result<()> {
        self.odb = CombinedOdb::open(StdFs::new(self.git_dir.join("objects")), self.algo)?;
        Ok(())
    }

    /// The git directory path.
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    /// The working-tree root, or `None` for a bare repository.
    pub fn work_tree(&self) -> Option<&Path> {
        self.work_tree.as_deref()
    }

    /// The repository's object hash algorithm.
    pub fn algo(&self) -> HashAlgo {
        self.algo
    }

    /// The object database (loose + packed; reads consult both, writes land
    /// as loose objects).
    pub fn objects(&self) -> &CombinedOdb<StdFs> {
        &self.odb
    }

    /// The reference store.
    pub fn refs(&self) -> &RefStore<StdFs> {
        &self.refs
    }

    /// Reads and parses an object by id.
    pub fn read_object(&self, id: &ObjectId) -> Result<Object> {
        self.odb.read_object(id)
    }

    /// Writes an object, returning its id.
    pub fn write_object(&self, ty: ObjectType, payload: &[u8]) -> Result<ObjectId> {
        self.odb.write(ty, payload)
    }

    /// Resolves `HEAD` to a commit id (following the symbolic ref). Returns
    /// [`Error::NotFound`] on an unborn branch (HEAD points at a ref that does
    /// not exist yet).
    pub fn head_id(&self) -> Result<ObjectId> {
        self.refs.resolve("HEAD")
    }

    /// Reads `HEAD` itself (typically the symbolic ref to the current branch).
    pub fn head(&self) -> Result<Reference> {
        self.refs.lookup("HEAD")
    }

    /// Loads the repository configuration (`.git/config`).
    pub fn config(&self) -> Result<Config> {
        let fs = StdFs::new(&self.git_dir);
        match fs.read("config") {
            Ok(bytes) => Config::parse(
                core::str::from_utf8(&bytes)
                    .map_err(|_| Error::Config("config is not valid utf-8".into()))?,
            ),
            Err(_) => Ok(Config::new()),
        }
    }

    /// Writes the repository configuration back to `.git/config`.
    pub fn write_config(&self, config: &Config) -> Result<()> {
        let fs = StdFs::new(&self.git_dir);
        fs.write("config", config.serialize().as_bytes())
    }

    /// Loads the staging index (`.git/index`), or an empty index if absent.
    pub fn index(&self) -> Result<Index> {
        let fs = StdFs::new(&self.git_dir);
        if !fs.exists("index") {
            return Ok(Index::new(self.algo));
        }
        let bytes = fs.read("index")?;
        Index::parse(self.algo, &bytes)
    }

    /// Writes the staging index back to `.git/index`.
    pub fn write_index(&self, index: &Index) -> Result<()> {
        let fs = StdFs::new(&self.git_dir);
        fs.write("index", &index.serialize())
    }

    /// Writes a generated pack and its index into `objects/pack/`.
    ///
    /// The two files are stored as `pack-<hash>.pack` / `pack-<hash>.idx`, where
    /// `<hash>` is the pack trailer hash from [`crate::pack::PackOutput`]. Call
    /// [`Repository::reload_odb`] afterwards to make the packed objects visible
    /// to this handle's object database.
    pub fn write_pack(&self, output: &crate::pack::PackOutput) -> Result<()> {
        let fs = StdFs::new(self.git_dir.join("objects"));
        let stem = alloc::format!("pack/pack-{}", output.hash.to_hex());
        fs.write(&alloc::format!("{stem}.pack"), &output.pack)?;
        fs.write(&alloc::format!("{stem}.idx"), &output.idx)?;
        Ok(())
    }

    /// Enumerates the ids of all loose objects (`objects/ab/cdef…`).
    pub fn loose_object_ids(&self) -> Result<alloc::vec::Vec<ObjectId>> {
        let objects_dir = self.git_dir.join("objects");
        let mut ids = alloc::vec::Vec::new();
        let hex_len = self.algo.hex_len();

        let read = match std::fs::read_dir(&objects_dir) {
            Ok(r) => r,
            Err(_) => return Ok(ids),
        };
        for sub in read {
            let sub = sub?;
            let name = sub.file_name().to_string_lossy().into_owned();
            // Object subdirs are exactly two hex chars; skip pack/, info/, etc.
            if name.len() != 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            for obj in std::fs::read_dir(sub.path())? {
                let obj = obj?;
                let rest = obj.file_name().to_string_lossy().into_owned();
                if rest.len() + 2 != hex_len || !rest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    continue;
                }
                let hex = alloc::format!("{name}{rest}");
                if let Ok(id) = ObjectId::from_hex(self.algo, &hex) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    /// Packs every loose object into a single packfile and removes the loose
    /// copies (the core of `git gc` / `git repack -d`). Returns the number of
    /// objects packed.
    ///
    /// Objects already in existing packs are left as-is; only loose objects are
    /// consolidated. Delta compression on write is a later optimization, so the
    /// pack is larger than git's but valid and readable by git.
    pub fn repack(&mut self) -> Result<usize> {
        let ids = self.loose_object_ids()?;
        if ids.is_empty() {
            return Ok(0);
        }

        let mut writer = crate::pack::PackWriter::new(self.algo);
        for id in &ids {
            let (ty, payload) = self.odb.read(id)?;
            writer.add(ty, &payload);
        }
        let out = writer.finish()?;
        self.write_pack(&out)?;

        // The objects are now in the pack; remove the loose copies.
        let objects_dir = self.git_dir.join("objects");
        for id in &ids {
            let hex = id.to_hex();
            let path = objects_dir.join(&hex[..2]).join(&hex[2..]);
            let _ = std::fs::remove_file(path);
        }

        self.reload_odb()?;
        Ok(ids.len())
    }

    /// Ingests a received packfile by exploding it into loose objects.
    ///
    /// Decodes every object (resolving deltas, including `REF_DELTA` bases this
    /// repository already has for a thin pack) and writes each as a loose
    /// object. Returns the ids written. This is the simplest correct ingest
    /// path used by clone/fetch; storing the pack verbatim with a generated
    /// index is a later optimization.
    pub fn ingest_pack(&self, pack: &[u8]) -> Result<alloc::vec::Vec<ObjectId>> {
        let resolver = |id: &ObjectId| self.odb.read(id);
        let objects = crate::pack::explode_pack(pack, self.algo, &resolver)?;
        let mut written = alloc::vec::Vec::with_capacity(objects.len());
        for (_, ty, payload) in &objects {
            written.push(self.odb.write(*ty, payload)?);
        }
        Ok(written)
    }

    // ---- branches & checkout -----------------------------------------------

    /// Creates a branch `refs/heads/<name>` pointing at `target` (or `HEAD` if
    /// `target` is `None`). Errors if the branch already exists.
    pub fn create_branch(&self, name: &str, target: Option<ObjectId>) -> Result<()> {
        let full = alloc::format!("refs/heads/{name}");
        if self.refs.lookup(&full).is_ok() {
            return Err(Error::Reference(alloc::format!(
                "branch {name} already exists"
            )));
        }
        let id = match target {
            Some(id) => id,
            None => self.head_id()?,
        };
        self.refs.update(&full, &Reference::Direct(id))
    }

    /// Checks out a branch: points `HEAD` at it, materializes its tree into the
    /// working tree, and rebuilds the index to match. Requires a non-bare repo.
    ///
    /// This is a simple, destructive checkout (it overwrites working-tree files
    /// from the target tree); a dirty-tree safety check and partial updates are
    /// roadmap refinements.
    pub fn checkout(&self, name: &str) -> Result<()> {
        let full = alloc::format!("refs/heads/{name}");
        let commit_id = self.refs.resolve(&full)?;
        let commit = match self.read_object(&commit_id)? {
            Object::Commit(c) => c,
            _ => return Err(Error::Parse("checkout: ref is not a commit".into())),
        };

        let work = self
            .work_tree
            .as_ref()
            .ok_or_else(|| Error::Io("checkout: bare repository has no work tree".into()))?
            .clone();

        crate::worktree::checkout_tree(self, &commit.tree, &work)?;
        self.rebuild_index_from_tree(&commit.tree)?;
        self.refs.update("HEAD", &Reference::Symbolic(full))?;
        Ok(())
    }

    /// Rebuilds the index to exactly mirror a tree (used by checkout). Stat
    /// fields are zeroed; git refreshes them on the next status that stats the
    /// files.
    fn rebuild_index_from_tree(&self, tree_id: &ObjectId) -> Result<()> {
        let flat = crate::walk::flatten_tree(&self.odb, tree_id)?;
        let mut index = Index::new(self.algo);
        for (path, (mode, id)) in flat {
            index.entries.push(crate::index::IndexEntry {
                ctime: (0, 0),
                mtime: (0, 0),
                dev: 0,
                ino: 0,
                mode: mode_bits(mode),
                uid: 0,
                gid: 0,
                size: 0,
                id,
                stage: 0,
                assume_valid: false,
                path,
            });
        }
        self.write_index(&index)
    }

    // ---- local porcelain ---------------------------------------------------

    /// Stages a working-tree file into the index: reads it, writes its blob to
    /// the object store, and inserts/updates the matching index entry (stat
    /// metadata is captured where the platform exposes it). `rel_path` is
    /// relative to the working-tree root; requires a non-bare repository.
    pub fn add_path(&self, rel_path: &str) -> Result<ObjectId> {
        let work = self
            .work_tree
            .as_ref()
            .ok_or_else(|| Error::Io("cannot add: bare repository has no work tree".into()))?;
        let full = work.join(rel_path);

        // `git add` of a file removed from the work tree stages its deletion.
        let content = match std::fs::read(&full) {
            Ok(c) => c,
            Err(_) => {
                let mut index = self.index()?;
                index.entries.retain(|e| e.path != rel_path.as_bytes());
                self.write_index(&index)?;
                return Ok(ObjectId::zero(self.algo));
            }
        };
        // If the path is LFS-tracked, run the clean filter: store the real
        // content in the LFS store and commit the small pointer blob instead.
        let blob_bytes = if self.lfs_attributes()?.is_lfs(rel_path.as_bytes()) {
            self.lfs_clean(&content)?
        } else {
            content
        };
        let id = self.odb.write(ObjectType::Blob, &blob_bytes)?;

        let entry = build_index_entry(&full, rel_path.as_bytes(), id)?;
        let mut index = self.index()?;
        index.entries.retain(|e| e.path != rel_path.as_bytes());
        index.entries.push(entry);
        self.write_index(&index)?;
        Ok(id)
    }

    // ---- Git LFS ------------------------------------------------------------

    /// The local LFS object store (`<git-dir>/lfs/objects/`).
    pub fn lfs_store(&self) -> crate::lfs::LfsStore<StdFs> {
        crate::lfs::LfsStore::new(StdFs::new(self.git_dir.join("lfs")))
    }

    /// Loads the LFS rules from the working tree's `.gitattributes` (empty for a
    /// bare repo or when the file is absent).
    pub fn lfs_attributes(&self) -> Result<crate::lfs::attributes::Attributes> {
        let Some(work) = &self.work_tree else {
            return Ok(crate::lfs::attributes::Attributes::default());
        };
        match std::fs::read_to_string(work.join(".gitattributes")) {
            Ok(text) => Ok(crate::lfs::attributes::Attributes::parse(&text)),
            Err(_) => Ok(crate::lfs::attributes::Attributes::default()),
        }
    }

    /// The clean filter: stores `content` in the LFS store and returns the
    /// pointer blob bytes that stand in for it in git.
    pub fn lfs_clean(&self, content: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        let pointer = self.lfs_store().write(content)?;
        Ok(pointer.serialize())
    }

    /// The smudge filter: if `blob` is an LFS pointer whose object is in the
    /// local LFS store, returns the real content; otherwise returns `blob`
    /// unchanged (an un-fetched pointer stays a pointer until `lfs fetch`).
    pub fn lfs_smudge(&self, blob: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        if crate::lfs::Pointer::is_pointer(blob)
            && let Ok(pointer) = crate::lfs::Pointer::parse(blob)
        {
            let store = self.lfs_store();
            if store.contains(&pointer.oid) {
                return store.read(&pointer.oid);
            }
        }
        Ok(blob.to_vec())
    }

    /// Materializes every LFS-pointer file in the working tree to its real
    /// content (the `git lfs pull` / smudge-after-clone step).
    ///
    /// For each index entry whose working-tree file is an LFS pointer: if the
    /// object is missing from the local store it is obtained via `fetch` and
    /// stored (hash-verified), then the working-tree file is rewritten with the
    /// content. `fetch` is the transfer callback — the HTTP `LfsClient`, or any
    /// closure. Returns the number of files smudged.
    pub fn lfs_smudge_worktree<F>(&self, mut fetch: F) -> Result<usize>
    where
        F: FnMut(&crate::lfs::Pointer) -> Result<alloc::vec::Vec<u8>>,
    {
        use crate::lfs::Pointer;
        let work = self
            .work_tree
            .as_ref()
            .ok_or_else(|| Error::Io("lfs pull: bare repository has no work tree".into()))?
            .clone();
        let store = self.lfs_store();
        let index = self.index()?;
        let mut count = 0;

        for entry in &index.entries {
            if entry.stage != 0 {
                continue;
            }
            let Ok(rel) = core::str::from_utf8(&entry.path) else {
                continue;
            };
            let full = work.join(rel);
            let Ok(bytes) = std::fs::read(&full) else {
                continue;
            };
            if !Pointer::is_pointer(&bytes) {
                continue;
            }
            let Ok(pointer) = Pointer::parse(&bytes) else {
                continue;
            };

            if !store.contains(&pointer.oid) {
                let content = fetch(&pointer)?;
                store.write_verified(&pointer, &content)?;
            }
            let content = store.read(&pointer.oid)?;
            std::fs::write(&full, &content)?;
            count += 1;
        }
        Ok(count)
    }

    /// Registers an LFS tracking pattern by appending it to `.gitattributes`
    /// (the equivalent of `git lfs track <pattern>`). Idempotent.
    pub fn lfs_track(&self, pattern: &str) -> Result<()> {
        let work = self
            .work_tree
            .as_ref()
            .ok_or_else(|| Error::Io("lfs track: bare repository has no work tree".into()))?;
        let path = work.join(".gitattributes");
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let line = alloc::format!("{pattern} filter=lfs diff=lfs merge=lfs -text");
        if existing.lines().any(|l| l.trim() == line) {
            return Ok(());
        }
        let mut out = existing;
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&line);
        out.push('\n');
        std::fs::write(&path, out)?;
        Ok(())
    }

    /// Removes a path from the index and the working tree (`git rm`). It is not
    /// an error for the working-tree file to be already gone.
    pub fn remove_path(&self, rel_path: &str) -> Result<()> {
        let mut index = self.index()?;
        let before = index.entries.len();
        index.entries.retain(|e| e.path != rel_path.as_bytes());
        if index.entries.len() == before {
            return Err(Error::Io(alloc::format!(
                "pathspec '{rel_path}' did not match any tracked file"
            )));
        }
        self.write_index(&index)?;
        if let Some(work) = &self.work_tree {
            let _ = std::fs::remove_file(work.join(rel_path));
        }
        Ok(())
    }

    /// Creates a commit from the current index and advances the current branch.
    ///
    /// Builds the tree from the staged index, uses the resolved `HEAD` (if any)
    /// as the sole parent, writes the commit object, and updates the ref that
    /// `HEAD` points at (creating it for an unborn branch). Returns the new
    /// commit id.
    pub fn commit(
        &self,
        message: &[u8],
        author: crate::object::Signature,
        committer: crate::object::Signature,
    ) -> Result<ObjectId> {
        let tree = crate::tree_builder::write_tree_from_index(&self.odb, &self.index()?)?;

        let mut parents = alloc::vec::Vec::new();
        if let Ok(parent) = self.head_id() {
            parents.push(parent);
        }

        let commit = crate::object::Commit {
            tree,
            parents,
            author,
            committer,
            extra_headers: alloc::vec::Vec::new(),
            message: message.to_vec(),
        };
        let id = self.odb.write(ObjectType::Commit, &commit.serialize())?;
        self.update_current_branch(&id)?;
        Ok(id)
    }

    /// Points the branch that `HEAD` references at `id`. If `HEAD` is detached
    /// (a direct ref), updates `HEAD` itself.
    pub fn update_current_branch(&self, id: &ObjectId) -> Result<()> {
        match self.head()? {
            Reference::Symbolic(branch) => self.refs.update(&branch, &Reference::Direct(*id)),
            Reference::Direct(_) => self.refs.update("HEAD", &Reference::Direct(*id)),
        }
    }
}

/// Builds an index entry for a freshly-staged file, capturing stat metadata
/// where the platform exposes it (full on Unix; size/mode only elsewhere).
fn build_index_entry(full: &Path, rel: &[u8], id: ObjectId) -> Result<crate::index::IndexEntry> {
    let meta = std::fs::metadata(full)?;
    let size = meta.len().min(u32::MAX as u64) as u32;
    let (ctime, mtime, dev, ino, mode, uid, gid) = stat_fields(&meta);
    Ok(crate::index::IndexEntry {
        ctime,
        mtime,
        dev,
        ino,
        mode,
        uid,
        gid,
        size,
        id,
        stage: 0,
        assume_valid: false,
        path: rel.to_vec(),
    })
}

#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn stat_fields(meta: &std::fs::Metadata) -> ((u32, u32), (u32, u32), u32, u32, u32, u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let exec = meta.mode() & 0o111 != 0;
    let git_mode = if exec { 0o100755 } else { 0o100644 };
    (
        (meta.ctime() as u32, meta.ctime_nsec() as u32),
        (meta.mtime() as u32, meta.mtime_nsec() as u32),
        meta.dev() as u32,
        meta.ino() as u32,
        git_mode,
        meta.uid(),
        meta.gid(),
    )
}

#[cfg(not(unix))]
fn stat_fields(_meta: &std::fs::Metadata) -> ((u32, u32), (u32, u32), u32, u32, u32, u32, u32) {
    // Non-Unix: git stores a normalized regular-file mode and leaves the
    // platform-specific stat fields zero (they only feed the racy-clean check).
    ((0, 0), (0, 0), 0, 0, 0o100644, 0, 0)
}

/// The raw stat/index mode bits for a tree [`FileMode`].
fn mode_bits(mode: crate::object::tree::FileMode) -> u32 {
    use crate::object::tree::FileMode;
    match mode {
        FileMode::Tree => 0o040000,
        FileMode::Regular => 0o100644,
        FileMode::Executable => 0o100755,
        FileMode::Symlink => 0o120000,
        FileMode::Gitlink => 0o160000,
    }
}

/// Determines a repository's object format from its config
/// (`extensions.objectformat`), defaulting to SHA-1.
fn detect_algo(git_dir: &Path) -> Result<HashAlgo> {
    let fs = StdFs::new(git_dir);
    let bytes = match fs.read("config") {
        Ok(b) => b,
        Err(_) => return Ok(HashAlgo::Sha1),
    };
    let text = String::from_utf8_lossy(&bytes).to_string();
    let cfg = Config::parse(&text)?;
    match cfg.get("extensions", None, "objectformat") {
        Some("sha256") => Ok(HashAlgo::Sha256),
        _ => Ok(HashAlgo::Sha1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(alloc::format!("puregit-repo-{name}-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn init_open_roundtrip() {
        let dir = scratch("init");
        let repo = Repository::init(&dir).unwrap();
        assert_eq!(repo.algo(), HashAlgo::Sha1);

        // HEAD is the symbolic ref to main.
        match repo.head().unwrap() {
            Reference::Symbolic(t) => assert_eq!(t, "refs/heads/main"),
            _ => panic!("expected symbolic HEAD"),
        }

        // Write a blob and read it back.
        let id = repo.write_object(ObjectType::Blob, b"hello\n").unwrap();
        let obj = repo.read_object(&id).unwrap();
        assert_eq!(obj, Object::Blob(b"hello\n".to_vec()));

        // Reopen and find the same object.
        let repo2 = Repository::open(&dir).unwrap();
        assert!(repo2.objects().contains(&id));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_discovers_from_subdirectory() {
        let dir = scratch("discover");
        let repo = Repository::init(&dir).unwrap();
        let id = repo.write_object(ObjectType::Blob, b"hi\n").unwrap();

        // A nested subdirectory.
        let sub = dir.join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();

        // Opening from the subdirectory finds the repo above it.
        let found = Repository::open(&sub).unwrap();
        assert_eq!(found.work_tree().unwrap(), dir.as_path());
        assert!(found.objects().contains(&id));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sha256_repo() {
        let dir = scratch("sha256");
        let repo = Repository::init_with(&dir, HashAlgo::Sha256).unwrap();
        assert_eq!(repo.algo(), HashAlgo::Sha256);
        let repo2 = Repository::open(&dir).unwrap();
        assert_eq!(repo2.algo(), HashAlgo::Sha256);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn sig() -> crate::object::Signature {
        crate::object::Signature {
            name: b"Tester".to_vec(),
            email: b"t@example.com".to_vec(),
            time: 1_700_000_000,
            tz: b"+0000".to_vec(),
        }
    }

    #[test]
    fn add_commit_log_cycle() {
        let dir = scratch("commit");
        let repo = Repository::init(&dir).unwrap();

        // Stage two files (one nested) and commit.
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/main.rs"), b"fn main() {}\n").unwrap();
        repo.add_path("a.txt").unwrap();
        repo.add_path("src/main.rs").unwrap();

        let c1 = repo.commit(b"first\n", sig(), sig()).unwrap();
        assert_eq!(repo.head_id().unwrap(), c1);

        // The branch ref now points at the commit.
        assert_eq!(repo.refs().resolve("refs/heads/main").unwrap(), c1);

        // A second commit has the first as its parent.
        std::fs::write(dir.join("a.txt"), b"hello\nworld\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let c2 = repo.commit(b"second\n", sig(), sig()).unwrap();

        let commit2 = match repo.read_object(&c2).unwrap() {
            Object::Commit(c) => c,
            _ => panic!("not a commit"),
        };
        assert_eq!(commit2.parents, alloc::vec![c1]);

        // History walks back through both commits.
        let history: alloc::vec::Vec<_> = crate::walk::RevWalk::new(repo.objects(), &[c2])
            .map(|r| r.unwrap().0)
            .collect();
        assert_eq!(history, alloc::vec![c2, c1]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_stages_deletion_and_rm() {
        let dir = scratch("rm");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"a\n").unwrap();
        std::fs::write(dir.join("b.txt"), b"b\n").unwrap();
        repo.add_path("a.txt").unwrap();
        repo.add_path("b.txt").unwrap();
        assert_eq!(repo.index().unwrap().entries.len(), 2);

        // Deleting the file then `add`-ing stages the removal.
        std::fs::remove_file(dir.join("a.txt")).unwrap();
        repo.add_path("a.txt").unwrap();
        let idx = repo.index().unwrap();
        assert_eq!(idx.entries.len(), 1);
        assert!(idx.get(b"a.txt").is_none());

        // `rm` removes from the index and the work tree.
        repo.remove_path("b.txt").unwrap();
        assert_eq!(repo.index().unwrap().entries.len(), 0);
        assert!(!dir.join("b.txt").exists());
        // Removing an untracked path errors.
        assert!(repo.remove_path("nope.txt").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lfs_clean_store_smudge_cycle() {
        use crate::lfs::Pointer;

        let dir = scratch("lfs");
        let repo = Repository::init(&dir).unwrap();
        repo.lfs_track("*.bin").unwrap();

        // A "large" binary file (bigger than a pointer).
        let big: alloc::vec::Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
        std::fs::write(dir.join("asset.bin"), &big).unwrap();

        // add runs the clean filter: the committed blob is a pointer, the real
        // content lands in the LFS store.
        repo.add_path("asset.bin").unwrap();
        let idx = repo.index().unwrap();
        let entry = idx.get(b"asset.bin").unwrap();
        let (_, blob) = repo.objects().read(&entry.id).unwrap();
        assert!(
            Pointer::is_pointer(&blob),
            "committed blob should be a pointer"
        );
        let pointer = Pointer::parse(&blob).unwrap();
        assert_eq!(pointer, Pointer::for_content(&big));
        assert!(repo.lfs_store().contains(&pointer.oid));

        // The pointer blob is tiny; the real content is stored out of band.
        assert!(blob.len() < 200);

        // The smudge filter restores the real content from the local store.
        assert_eq!(repo.lfs_smudge(&blob).unwrap(), big);

        // A non-tracked file is stored inline (no pointer).
        std::fs::write(dir.join("notes.txt"), b"plain\n").unwrap();
        repo.add_path("notes.txt").unwrap();
        let (_, txt) = repo
            .objects()
            .read(&repo.index().unwrap().get(b"notes.txt").unwrap().id)
            .unwrap();
        assert_eq!(txt, b"plain\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repack_consolidates_loose_objects() {
        let dir = scratch("repack");
        let mut repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let tip = repo.commit(b"c\n", sig(), sig()).unwrap();

        let loose_before = repo.loose_object_ids().unwrap().len();
        assert!(loose_before >= 3); // blob + tree + commit

        let packed = repo.repack().unwrap();
        assert_eq!(packed, loose_before);

        // The loose objects are gone, but everything still reads (from the pack).
        assert_eq!(repo.loose_object_ids().unwrap().len(), 0);
        assert!(repo.objects().pack_count() >= 1);
        assert!(repo.objects().contains(&tip));
        match repo.read_object(&tip).unwrap() {
            Object::Commit(c) => assert_eq!(c.summary(), b"c"),
            _ => panic!("tip not a commit after repack"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
