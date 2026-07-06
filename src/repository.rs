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

/// How far [`Repository::reset`] resets — matching `git reset`'s three modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetMode {
    /// Move the branch ref only; leave the index and working tree as they are.
    Soft,
    /// Move the branch and reset the index to the target tree (git's default);
    /// the working tree is untouched.
    Mixed,
    /// Move the branch, reset the index, and overwrite the working tree with the
    /// target tree, discarding local modifications.
    Hard,
}

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

    /// Records the shallow boundary in `.git/shallow` (the commits whose parents
    /// are intentionally absent in a shallow clone), or removes the file when the
    /// boundary is empty (the repository is complete). Reading these ids back
    /// bounds later history walks so a missing parent is not an error.
    pub fn write_shallow(&self, oids: &[ObjectId]) -> Result<()> {
        let fs = StdFs::new(&self.git_dir);
        if oids.is_empty() {
            let _ = fs.remove_file("shallow");
            return Ok(());
        }
        let mut body = alloc::string::String::new();
        for id in oids {
            body.push_str(&id.to_hex());
            body.push('\n');
        }
        fs.write("shallow", body.as_bytes())
    }

    /// Reads the shallow boundary from `.git/shallow` (empty if the file is
    /// absent — the repository is complete).
    pub fn shallow(&self) -> Result<alloc::vec::Vec<ObjectId>> {
        let fs = StdFs::new(&self.git_dir);
        let Ok(bytes) = fs.read("shallow") else {
            return Ok(alloc::vec::Vec::new());
        };
        let text =
            core::str::from_utf8(&bytes).map_err(|_| Error::Parse("shallow: not utf-8".into()))?;
        let mut out = alloc::vec::Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.is_empty() {
                out.push(ObjectId::from_hex(self.algo, line)?);
            }
        }
        Ok(out)
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

    /// Reads a tree object recursively into the index, replacing its contents
    /// (`git read-tree`). Every non-tree entry is staged at stage 0 with the
    /// tree's mode and blob id; the stat fields (`ctime`/`mtime`/`dev`/… /`size`)
    /// are left zero — git fills them on a later refresh — so a following
    /// `status` re-hashes each path rather than trusting a bogus cached stat.
    pub fn read_tree(&self, tree_id: &ObjectId) -> Result<()> {
        self.write_index(&self.index_from_tree(tree_id)?)
    }

    /// Builds an [`Index`] mirroring a tree (stage-0 entries, zeroed stat
    /// fields). Shared by [`read_tree`](Self::read_tree) and worktree setup.
    fn index_from_tree(&self, tree_id: &ObjectId) -> Result<Index> {
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
        Ok(index)
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
        for id in &ids {
            let _ = std::fs::remove_file(self.loose_path(id));
        }

        self.reload_odb()?;
        Ok(ids.len())
    }

    /// Repacks **every object reachable from every ref** into one packfile and
    /// writes a reachability `.bitmap` and its `.rev` alongside it (the core of
    /// `git repack -adb`). Returns the number of objects packed.
    ///
    /// Unlike [`repack`](Self::repack), which consolidates only loose objects,
    /// this gathers the full reachable closure into a single pack so the bitmap
    /// covers a closed object set — the shape a bitmap requires. Loose copies of
    /// the packed objects are then removed. The bitmap and reverse index are the
    /// git-compatible ones from [`crate::pack::bitmap`].
    pub fn repack_with_bitmap(&mut self) -> Result<usize> {
        let tips: alloc::vec::Vec<ObjectId> = self.refs.list()?.into_values().collect();
        if tips.is_empty() {
            return Ok(0);
        }
        let reachable = crate::walk::reachable_objects(&self.odb, &tips)?;
        if reachable.is_empty() {
            return Ok(0);
        }

        let mut writer = crate::pack::PackWriter::new(self.algo);
        let mut commits = alloc::vec::Vec::new();
        for id in &reachable {
            let (ty, payload) = self.odb.read(id)?;
            if ty == crate::object::ObjectType::Commit {
                commits.push(*id);
            }
            writer.add(ty, &payload);
        }
        let out = writer.finish()?;
        self.write_pack(&out)?;

        // Write the bitmap and its reverse index next to the pack.
        let idx = crate::pack::PackIndex::parse(self.algo, &out.idx)?;
        let bitmap = crate::pack::bitmap::write_bitmap(&self.odb, &idx, &out.hash, &commits)?;
        let rev = crate::pack::bitmap::write_reverse_index(&idx, &out.hash)?;
        let fs = StdFs::new(self.git_dir.join("objects"));
        let stem = alloc::format!("pack/pack-{}", out.hash.to_hex());
        fs.write(&alloc::format!("{stem}.bitmap"), &bitmap)?;
        fs.write(&alloc::format!("{stem}.rev"), &rev)?;

        // The packed objects' loose copies are now redundant.
        for id in &reachable {
            let _ = std::fs::remove_file(self.loose_path(id));
        }

        self.reload_odb()?;
        Ok(reachable.len())
    }

    /// Writes a commit-graph (`objects/info/commit-graph`) covering every commit
    /// reachable from the refs and `HEAD`, returning the number of commits
    /// indexed. Annotated tags are peeled to their commit; the graph is a
    /// parent-closed set (BFS follows parents), so it is a valid full graph.
    pub fn write_commit_graph(&self) -> Result<usize> {
        use alloc::collections::{BTreeSet, VecDeque};

        let mut roots: alloc::vec::Vec<ObjectId> = alloc::vec::Vec::new();
        if let Ok(h) = self.head_id() {
            roots.push(h);
        }
        for (_name, id) in self.refs.list()? {
            roots.push(id);
        }

        let mut commits = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut queue: VecDeque<ObjectId> = roots.into_iter().collect();
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) {
                continue;
            }
            match self.read_object(&id) {
                Ok(Object::Commit(c)) => {
                    commits.insert(id);
                    for p in c.parents {
                        queue.push_back(p);
                    }
                }
                Ok(Object::Tag(t)) => queue.push_back(t.object),
                _ => {} // a tree/blob tip is not a commit
            }
        }
        if commits.is_empty() {
            return Ok(0);
        }
        let commits: alloc::vec::Vec<ObjectId> = commits.into_iter().collect();
        let bytes = crate::commit_graph::write_commit_graph(&self.odb, &commits)?;
        let fs = StdFs::new(self.git_dir.join("objects"));
        fs.create_dir_all("info")?;
        fs.write("info/commit-graph", &bytes)?;
        Ok(commits.len())
    }

    /// Writes a multi-pack-index (`objects/pack/multi-pack-index`) covering every
    /// `.idx` in `objects/pack/`, returning the number of packs indexed (0 if
    /// there are none). The MIDX lets a repository with many packs resolve an
    /// object in one lookup.
    pub fn write_multi_pack_index(&self) -> Result<usize> {
        let pack_dir = self.git_dir.join("objects").join("pack");
        let mut names: alloc::vec::Vec<String> = alloc::vec::Vec::new();
        if let Ok(entries) = std::fs::read_dir(&pack_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".idx") {
                    names.push(name);
                }
            }
        }
        if names.is_empty() {
            return Ok(0);
        }
        names.sort();

        // Parse each idx and pair it with its file name.
        let mut parsed = alloc::vec::Vec::with_capacity(names.len());
        for name in &names {
            let bytes = std::fs::read(pack_dir.join(name)).map_err(|e| Error::Io(e.to_string()))?;
            parsed.push(crate::pack::PackIndex::parse(self.algo, &bytes)?);
        }
        let packs: alloc::vec::Vec<(String, &crate::pack::PackIndex)> =
            names.iter().cloned().zip(parsed.iter()).collect();

        let bytes = crate::multi_pack_index::write_multi_pack_index(self.algo, &packs)?;
        let fs = StdFs::new(&pack_dir);
        fs.write("multi-pack-index", &bytes)?;
        Ok(names.len())
    }

    /// The on-disk path of a loose object (`objects/ab/cdef…`).
    fn loose_path(&self, id: &ObjectId) -> PathBuf {
        let hex = id.to_hex();
        self.git_dir.join("objects").join(&hex[..2]).join(&hex[2..])
    }

    /// Removes unreachable loose objects (`git prune`), returning the count.
    ///
    /// Reachability is computed from the refs, `HEAD`, and the index (the same
    /// roots as [`crate::fsck`]); every loose object not reachable from them is
    /// deleted. Packed objects are left untouched. Unlike git there is no
    /// grace period — all dangling loose objects are removed immediately, so do
    /// not run this concurrently with an operation staging new objects.
    pub fn prune(&mut self) -> Result<usize> {
        let dangling = crate::fsck::fsck(self)?.dangling;
        for id in &dangling {
            let _ = std::fs::remove_file(self.loose_path(id));
        }
        if !dangling.is_empty() {
            self.reload_odb()?;
        }
        Ok(dangling.len())
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
        self.refs.update(&full, &Reference::Direct(id))?;
        self.write_reflog(
            &full,
            &ObjectId::zero(self.algo),
            &id,
            &alloc::format!("branch: Created from {}", id.to_hex()),
        );
        Ok(())
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

        // Capture where HEAD was, for the reflog "moving from X to Y" entry.
        let old_commit = self.head_id().unwrap_or_else(|_| ObjectId::zero(self.algo));
        let from = match self.head() {
            Ok(Reference::Symbolic(b)) => b.strip_prefix("refs/heads/").unwrap_or(&b).to_string(),
            _ => old_commit.to_hex(),
        };

        crate::worktree::checkout_tree(self, &commit.tree, &work)?;
        self.read_tree(&commit.tree)?;
        self.refs.update("HEAD", &Reference::Symbolic(full))?;
        self.write_reflog(
            "HEAD",
            &old_commit,
            &commit_id,
            &alloc::format!("checkout: moving from {from} to {name}"),
        );
        Ok(())
    }

    /// Adds a linked worktree at `path` checked out at `commit` (detached),
    /// creating git's linked-worktree layout so `git worktree list` (real git)
    /// recognizes it: `.git/worktrees/<name>/{HEAD,commondir,gitdir,index}` and a
    /// `<path>/.git` file pointing back. Requires a non-bare repository.
    pub fn add_worktree(&self, path: &Path, commit: &ObjectId) -> Result<()> {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::Io("worktree: could not derive a name from the path".into()))?
            .to_string();
        let io = |e: std::io::Error| Error::Io(e.to_string());
        // Absolute paths are required in the link files so git can resolve them
        // from either the main repo or the linked worktree.
        let common_git = std::fs::canonicalize(&self.git_dir).map_err(io)?;
        let wt_git = common_git.join("worktrees").join(&name);
        if wt_git.exists() {
            return Err(Error::Io(alloc::format!(
                "worktree {name:?} already exists"
            )));
        }
        let commit_obj = match self.read_object(commit)? {
            Object::Commit(c) => c,
            other => {
                return Err(Error::UnexpectedType {
                    expected: ObjectType::Commit,
                    actual: other.object_type(),
                });
            }
        };

        std::fs::create_dir_all(&wt_git).map_err(io)?;
        std::fs::create_dir_all(path).map_err(io)?;
        let wt_dotgit = std::fs::canonicalize(path).map_err(io)?.join(".git");

        // Detached HEAD at the commit; commondir points back to the main git dir.
        std::fs::write(wt_git.join("HEAD"), alloc::format!("{}\n", commit.to_hex())).map_err(io)?;
        std::fs::write(wt_git.join("commondir"), b"../..\n").map_err(io)?;
        std::fs::write(
            wt_git.join("gitdir"),
            alloc::format!("{}\n", wt_dotgit.display()),
        )
        .map_err(io)?;
        // The linked working tree's `.git` pointer file (absolute).
        std::fs::write(&wt_dotgit, alloc::format!("gitdir: {}\n", wt_git.display())).map_err(io)?;

        // Materialize the tree and write the worktree's own index.
        crate::worktree::checkout_tree(self, &commit_obj.tree, path)?;
        let index = self.index_from_tree(&commit_obj.tree)?;
        std::fs::write(wt_git.join("index"), index.serialize()).map_err(io)?;
        Ok(())
    }

    /// Lists the linked worktrees (name → checked-out commit), read from
    /// `.git/worktrees/*/HEAD`. Does not include the main working tree.
    pub fn worktrees(&self) -> Result<alloc::vec::Vec<(String, ObjectId)>> {
        let dir = self.git_dir.join("worktrees");
        let mut out = alloc::vec::Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let head = entry.path().join("HEAD");
                if let Ok(bytes) = std::fs::read(&head)
                    && let Ok(reference) = crate::refs::Reference::parse(self.algo, &bytes)
                {
                    // Resolve HEAD (a direct id or a symref) against the shared refs.
                    let id = match reference {
                        Reference::Direct(id) => Some(id),
                        Reference::Symbolic(t) => self.refs.resolve(&t).ok(),
                    };
                    if let Some(id) = id {
                        out.push((name, id));
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Resets the current branch to `target`, and — depending on `mode` — the
    /// index and working tree with it (`git reset`).
    ///
    /// - [`ResetMode::Soft`] moves the branch ref only; the index and worktree
    ///   are left as they are (the changes become "staged" relative to the new
    ///   `HEAD`).
    /// - [`ResetMode::Mixed`] (git's default) also resets the index to
    ///   `target`'s tree, so nothing is staged; the worktree is untouched.
    /// - [`ResetMode::Hard`] additionally materializes `target`'s tree into the
    ///   working tree, discarding local modifications. Requires a non-bare repo.
    pub fn reset(&self, mode: ResetMode, target: &ObjectId) -> Result<()> {
        let commit = match self.read_object(target)? {
            Object::Commit(c) => c,
            other => {
                return Err(Error::UnexpectedType {
                    expected: ObjectType::Commit,
                    actual: other.object_type(),
                });
            }
        };

        let old = self.head_id().unwrap_or_else(|_| ObjectId::zero(self.algo));
        self.update_current_branch(target)?;
        if let Ok(Reference::Symbolic(branch)) = self.head() {
            self.write_reflog(
                &branch,
                &old,
                target,
                &alloc::format!("reset: moving to {}", target.to_hex()),
            );
        }
        if mode == ResetMode::Soft {
            return Ok(());
        }
        if mode == ResetMode::Hard {
            let work = self
                .work_tree
                .as_ref()
                .ok_or_else(|| Error::Io("reset --hard: bare repository has no work tree".into()))?
                .clone();
            crate::worktree::checkout_tree(self, &commit.tree, &work)?;
        }
        // Both mixed and hard reset the index to the target tree.
        self.read_tree(&commit.tree)
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
            // Defense in depth (D4): `Index::parse` already rejects unsafe
            // paths, but re-validate here before joining onto the work tree so
            // this write sink is safe even if reached with an unvalidated
            // path. Skip anything that is not a safe relative path.
            if !crate::index::is_safe_index_path(&entry.path) {
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

    /// Renames a tracked file in both the working tree and the index (`git mv`).
    ///
    /// `src` must be tracked at stage 0 and `dst` must not already be tracked.
    /// The working-tree file is moved (creating destination directories) and the
    /// index entry is re-pathed, preserving its blob id and mode — no re-hash.
    /// Both paths are relative to the work-tree root and `dst` is validated
    /// against path traversal.
    pub fn mv(&self, src: &str, dst: &str) -> Result<()> {
        let work = self
            .work_tree
            .as_ref()
            .ok_or_else(|| Error::Io("cannot mv: bare repository has no work tree".into()))?;

        let mut index = self.index()?;
        if !index
            .entries
            .iter()
            .any(|e| e.stage == 0 && e.path == src.as_bytes())
        {
            return Err(Error::Io(alloc::format!(
                "mv: '{src}' is not under version control"
            )));
        }
        if index
            .entries
            .iter()
            .any(|e| e.stage == 0 && e.path == dst.as_bytes())
        {
            return Err(Error::Io(alloc::format!(
                "mv: destination '{dst}' already exists in the index"
            )));
        }
        if !crate::index::is_safe_index_path(dst.as_bytes()) {
            return Err(Error::Io(alloc::format!(
                "mv: unsafe destination path '{dst}'"
            )));
        }

        let dst_full = work.join(dst);
        if let Some(parent) = dst_full.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        std::fs::rename(work.join(src), &dst_full).map_err(|e| Error::Io(e.to_string()))?;

        for e in &mut index.entries {
            if e.stage == 0 && e.path == src.as_bytes() {
                e.path = dst.as_bytes().to_vec();
            }
        }
        self.write_index(&index)
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
        let old = self.head_id().unwrap_or_else(|_| ObjectId::zero(self.algo));
        let id = self.odb.write(ObjectType::Commit, &commit.serialize())?;
        self.update_current_branch(&id)?;
        // Reflog: "commit: <summary>" on the branch (mirrored to HEAD).
        let summary = String::from_utf8_lossy(commit_summary(message));
        if let Ok(Reference::Symbolic(branch)) = self.head() {
            self.write_reflog(&branch, &old, &id, &alloc::format!("commit: {summary}"));
        }
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

    /// A committer signature from `user.name`/`user.email` in config (falling
    /// back to placeholders) stamped with the current wall-clock time in UTC.
    /// Used for reflog entries and as a default author/committer identity.
    pub fn signature_now(&self) -> crate::object::Signature {
        use std::time::{SystemTime, UNIX_EPOCH};
        let cfg = self.config().unwrap_or_else(|_| Config::new());
        let name = cfg
            .get("user", None, "name")
            .unwrap_or("puregit")
            .to_string();
        let email = cfg
            .get("user", None, "email")
            .unwrap_or("puregit@localhost")
            .to_string();
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        crate::object::Signature {
            name: name.into_bytes(),
            email: email.into_bytes(),
            time,
            tz: b"+0000".to_vec(),
        }
    }

    /// Appends a reflog entry for `refname` (`logs/<refname>`), and mirrors it to
    /// `logs/HEAD` when `refname` is the branch `HEAD` currently points at — so
    /// `git reflog` (which reads `logs/HEAD`) shows commits/resets on the current
    /// branch. Best-effort: a reflog write failure never fails the ref update.
    pub fn write_reflog(&self, refname: &str, old: &ObjectId, new: &ObjectId, message: &str) {
        let sig = self.signature_now();
        let line = alloc::format!(
            "{} {} {} <{}> {} {}\t{}\n",
            old.to_hex(),
            new.to_hex(),
            String::from_utf8_lossy(&sig.name),
            String::from_utf8_lossy(&sig.email),
            sig.time,
            String::from_utf8_lossy(&sig.tz),
            message,
        );
        let _ = self.append_log_file(refname, &line);
        if refname != "HEAD"
            && let Ok(Reference::Symbolic(head_branch)) = self.head()
            && head_branch == refname
        {
            let _ = self.append_log_file("HEAD", &line);
        }
    }

    /// Expires reflog entries for `refname` older than `expire_before` (a Unix
    /// timestamp), rewriting `logs/<refname>` with only the entries at or after
    /// the cutoff. Returns how many entries were dropped (0 if there is no log).
    /// This is `git reflog expire`'s core: prune stale history so unreachable
    /// objects it pinned can later be `gc`'d.
    pub fn reflog_expire(&self, refname: &str, expire_before: i64) -> Result<usize> {
        let path = self.git_dir.join("logs").join(refname);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Ok(0),
        };
        let mut kept = String::new();
        let mut removed = 0usize;
        for line in content.lines() {
            // A reflog line is "<old> <new> <ident> <email> <time> <tz>\t<msg>";
            // the two whitespace tokens before the TAB are <time> <tz>.
            let time = line
                .split_once('\t')
                .and_then(|(meta, _)| meta.rsplit(' ').nth(1))
                .and_then(|t| t.parse::<i64>().ok())
                .unwrap_or(i64::MAX); // unparseable → keep (fail safe)
            if time >= expire_before {
                kept.push_str(line);
                kept.push('\n');
            } else {
                removed += 1;
            }
        }
        std::fs::write(&path, kept).map_err(|e| Error::Io(e.to_string()))?;
        Ok(removed)
    }

    /// Appends one raw line to `logs/<refname>`, creating parent directories.
    fn append_log_file(&self, refname: &str, line: &str) -> Result<()> {
        use std::io::Write;
        let path = self.git_dir.join("logs").join(refname);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Error::Io(e.to_string()))?;
        f.write_all(line.as_bytes())
            .map_err(|e| Error::Io(e.to_string()))
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
#[allow(clippy::type_complexity)]
fn stat_fields(_meta: &std::fs::Metadata) -> ((u32, u32), (u32, u32), u32, u32, u32, u32, u32) {
    // Non-Unix: git stores a normalized regular-file mode and leaves the
    // platform-specific stat fields zero (they only feed the racy-clean check).
    ((0, 0), (0, 0), 0, 0, 0o100644, 0, 0)
}

/// The first line of a commit message (its summary), for reflog entries.
fn commit_summary(message: &[u8]) -> &[u8] {
    match message.iter().position(|&b| b == b'\n') {
        Some(nl) => &message[..nl],
        None => message,
    }
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
    fn repack_with_bitmap_produces_a_valid_bitmap() {
        let dir = scratch("bitmap");
        let mut repo = Repository::init(&dir).unwrap();
        for i in 0..4 {
            std::fs::write(dir.join("f.txt"), alloc::format!("line {i}\n")).unwrap();
            repo.add_path("f.txt").unwrap();
            repo.commit(alloc::format!("c{i}\n").as_bytes(), sig(), sig())
                .unwrap();
        }

        let packed = repo.repack_with_bitmap().unwrap();
        assert!(packed >= 8); // 4 commits + trees + blobs

        // The pack, its index, the bitmap, and the reverse index all landed.
        let pack_dir = repo.git_dir().join("objects/pack");
        let has = |ext: &str| {
            std::fs::read_dir(&pack_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().ends_with(ext))
        };
        assert!(has(".pack") && has(".idx") && has(".bitmap") && has(".rev"));

        // The bitmap parses: BITM header with one entry per commit, then four
        // type bitmaps.
        let bm_path = std::fs::read_dir(&pack_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().ends_with(".bitmap"))
            .unwrap()
            .path();
        let bm = std::fs::read(&bm_path).unwrap();
        assert_eq!(&bm[..4], b"BITM");
        assert_eq!(u32::from_be_bytes([bm[8], bm[9], bm[10], bm[11]]), 4); // 4 commits
        let mut off = 12 + HashAlgo::Sha1.raw_len();
        for _ in 0..4 {
            let (_, n) = crate::pack::ewah::Ewah::from_bytes(&bm[off..]).unwrap();
            off += n;
        }

        // Objects are still readable after the loose copies were removed.
        assert!(repo.objects().contains(&repo.head_id().unwrap()));
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
    fn read_tree_roundtrips_the_index() {
        // Build a repo with a nested tree, capture its index, write the tree,
        // then read that tree back into a fresh index and compare.
        let dir = scratch("readtree");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"aaa\n").unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/b.txt"), b"bbb\n").unwrap();
        repo.add_path("a.txt").unwrap();
        repo.add_path("sub/b.txt").unwrap();
        let tree =
            crate::tree_builder::write_tree_from_index(repo.objects(), &repo.index().unwrap())
                .unwrap();

        // Read the tree into the index; the staged (path, mode, id) set must
        // match what write-tree consumed, across the subdirectory boundary.
        repo.read_tree(&tree).unwrap();
        let idx = repo.index().unwrap();
        let mut got: Vec<(Vec<u8>, u32, ObjectId)> = idx
            .entries
            .iter()
            .map(|e| (e.path.clone(), e.mode, e.id))
            .collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, b"a.txt");
        assert_eq!(got[0].1, 0o100644);
        assert_eq!(got[1].0, b"sub/b.txt");
        // Re-writing the tree from the read-back index yields the same tree id.
        let tree2 = crate::tree_builder::write_tree_from_index(repo.objects(), &idx).unwrap();
        assert_eq!(tree, tree2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mv_renames_tracked_file() {
        let dir = scratch("mv");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hi\n").unwrap();
        repo.add_path("a.txt").unwrap();

        repo.mv("a.txt", "sub/b.txt").unwrap();
        assert!(!dir.join("a.txt").exists());
        assert_eq!(std::fs::read(dir.join("sub/b.txt")).unwrap(), b"hi\n");
        let idx = repo.index().unwrap();
        assert!(idx.get(b"sub/b.txt").is_some());
        assert!(idx.get(b"a.txt").is_none());

        // Moving an untracked path is rejected.
        std::fs::write(dir.join("c.txt"), b"x").unwrap();
        assert!(repo.mv("c.txt", "d.txt").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_mixed_and_hard() {
        let dir = scratch("reset");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"v1\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let c1 = repo.commit(b"c1\n", sig(), sig()).unwrap();
        let c1_tree = match repo.read_object(&c1).unwrap() {
            Object::Commit(c) => c.tree,
            _ => panic!("c1 not a commit"),
        };

        // Stage a change so the index diverges from c1.
        std::fs::write(dir.join("a.txt"), b"v2\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let staged =
            crate::tree_builder::write_tree_from_index(repo.objects(), &repo.index().unwrap())
                .unwrap();
        assert_ne!(staged, c1_tree);

        // --mixed resets the index back to c1 but leaves the worktree file.
        repo.reset(ResetMode::Mixed, &c1).unwrap();
        let idx_tree =
            crate::tree_builder::write_tree_from_index(repo.objects(), &repo.index().unwrap())
                .unwrap();
        assert_eq!(idx_tree, c1_tree);
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"v2\n");

        // --hard restores the worktree to c1 as well.
        std::fs::write(dir.join("a.txt"), b"v2\n").unwrap();
        repo.add_path("a.txt").unwrap();
        repo.reset(ResetMode::Hard, &c1).unwrap();
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"v1\n");
        assert_eq!(repo.head_id().unwrap(), c1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reflog_expire_drops_old_entries() {
        let dir = scratch("reflogexpire");
        let repo = Repository::init(&dir).unwrap();
        // Two hand-written reflog entries: one old (time 1000), one new (2000).
        let zero = ObjectId::zero(HashAlgo::Sha1).to_hex();
        std::fs::create_dir_all(dir.join(".git/logs")).unwrap();
        std::fs::write(
            dir.join(".git/logs/HEAD"),
            alloc::format!(
                "{zero} {zero} T <t@e> 1000 +0000\told\n{zero} {zero} T <t@e> 2000 +0000\tnew\n"
            ),
        )
        .unwrap();

        // Expire everything before t=1500: the old entry goes, the new stays.
        let removed = repo.reflog_expire("HEAD", 1500).unwrap();
        assert_eq!(removed, 1);
        let after = std::fs::read_to_string(dir.join(".git/logs/HEAD")).unwrap();
        assert!(!after.contains("\told"));
        assert!(after.contains("\tnew"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn worktree_add_and_list() {
        let dir = scratch("wtmain");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hi\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let tip = repo.commit(b"c\n", sig(), sig()).unwrap();

        let wt_path = std::env::temp_dir().join(alloc::format!("puregit-linked-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&wt_path);
        repo.add_worktree(&wt_path, &tip).unwrap();

        // The tree was checked out and the linked-worktree files were created.
        assert_eq!(std::fs::read(wt_path.join("a.txt")).unwrap(), b"hi\n");
        assert!(
            std::fs::read_to_string(wt_path.join(".git"))
                .unwrap()
                .starts_with("gitdir: ")
        );
        let name = wt_path.file_name().unwrap().to_str().unwrap();
        assert!(
            dir.join(alloc::format!(".git/worktrees/{name}/HEAD"))
                .exists()
        );
        assert!(
            dir.join(alloc::format!(".git/worktrees/{name}/index"))
                .exists()
        );

        // worktrees() lists it, resolving HEAD to the tip.
        assert!(repo.worktrees().unwrap().iter().any(|(_n, id)| *id == tip));
        // Re-adding the same worktree fails.
        assert!(repo.add_worktree(&wt_path, &tip).is_err());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&wt_path);
    }

    #[test]
    fn ref_update_uses_a_lockfile() {
        let dir = scratch("reflock");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let tip = repo.commit(b"c\n", sig(), sig()).unwrap();

        // A held lockfile blocks an update of that ref.
        std::fs::create_dir_all(dir.join(".git/refs/heads")).unwrap();
        std::fs::write(dir.join(".git/refs/heads/locked.lock"), b"held").unwrap();
        assert!(
            repo.refs()
                .update("refs/heads/locked", &Reference::Direct(tip))
                .is_err()
        );

        // A normal update succeeds and leaves no `.lock` artifact behind.
        repo.create_branch("clean", None).unwrap();
        assert_eq!(repo.refs().resolve("refs/heads/clean").unwrap(), tip);
        assert!(!dir.join(".git/refs/heads/clean.lock").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_a_packed_ref() {
        let dir = scratch("packeddel");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let tip = repo.commit(b"c\n", sig(), sig()).unwrap();

        // Simulate a packed ref: write refs/tags/v1 into packed-refs and ensure
        // no loose file exists for it.
        let packed = alloc::format!(
            "# pack-refs with: peeled fully-peeled sorted \n{} refs/tags/v1\n",
            tip.to_hex()
        );
        std::fs::write(dir.join(".git/packed-refs"), packed).unwrap();
        assert_eq!(repo.refs().resolve("refs/tags/v1").unwrap(), tip);

        // Deleting it must remove it from packed-refs (not just the missing loose
        // file), so it does not resurrect.
        repo.refs().delete("refs/tags/v1").unwrap();
        assert!(repo.refs().resolve("refs/tags/v1").is_err());
        let after = std::fs::read_to_string(dir.join(".git/packed-refs")).unwrap();
        assert!(!after.contains("refs/tags/v1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_and_reset_write_reflog() {
        let dir = scratch("reflog");
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"v1\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let c1 = repo.commit(b"first\n", sig(), sig()).unwrap();
        std::fs::write(dir.join("a.txt"), b"v2\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let c2 = repo.commit(b"second\n", sig(), sig()).unwrap();
        repo.reset(ResetMode::Soft, &c1).unwrap();

        // logs/HEAD records both commits and the reset, oldest-first.
        let head_log = std::fs::read_to_string(dir.join(".git/logs/HEAD")).unwrap();
        let lines: Vec<&str> = head_log.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("commit: first"));
        assert!(lines[0].starts_with(&alloc::format!(
            "{} {}",
            ObjectId::zero(HashAlgo::Sha1).to_hex(),
            c1.to_hex()
        )));
        assert!(lines[1].contains("commit: second"));
        assert!(lines[2].contains(&alloc::format!("reset: moving to {}", c1.to_hex())));
        // The branch's own log mirrors the same entries.
        let branch_log = std::fs::read_to_string(dir.join(".git/logs/refs/heads/main")).unwrap();
        assert_eq!(branch_log.lines().count(), 3);
        // The reset moved HEAD back to c1 (not c2).
        assert_eq!(repo.head_id().unwrap(), c1);
        let _ = c2;

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_removes_only_unreachable_loose_objects() {
        let dir = scratch("prune");
        let mut repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        repo.add_path("a.txt").unwrap();
        let tip = repo.commit(b"c\n", sig(), sig()).unwrap();

        // A stray, unreferenced blob is prunable; the committed graph is not.
        let stray = repo
            .write_object(ObjectType::Blob, b"unreferenced\n")
            .unwrap();
        assert!(repo.objects().contains(&stray));

        let removed = repo.prune().unwrap();
        assert_eq!(removed, 1);
        assert!(!repo.objects().contains(&stray));
        // Everything reachable from HEAD survives.
        assert!(repo.objects().contains(&tip));
        assert!(crate::fsck::fsck(&repo).unwrap().dangling.is_empty());

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
