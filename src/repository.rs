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
use crate::odb::{LooseOdb, ObjectDatabase};
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
    odb: LooseOdb<StdFs>,
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

        Ok(Self::assemble(git_dir, Some(work_tree), algo))
    }

    /// Opens an existing repository by discovering the git directory at or above
    /// `path`.
    ///
    /// If `path/.git` is a directory, that is the git directory and `path` is
    /// the work tree. Otherwise, if `path` itself looks like a git directory
    /// (has `HEAD` and `objects/`), it is treated as a bare repository. Parent
    /// directories are not yet walked (on the roadmap).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let dot_git = path.join(".git");
        let (git_dir, work_tree) = if dot_git.is_dir() {
            (dot_git, Some(path.to_path_buf()))
        } else if path.join("HEAD").is_file() && path.join("objects").is_dir() {
            (path.to_path_buf(), None)
        } else {
            return Err(Error::Io(alloc::format!(
                "no git repository found at {}",
                path.display()
            )));
        };

        let algo = detect_algo(&git_dir)?;
        Ok(Self::assemble(git_dir, work_tree, algo))
    }

    fn assemble(git_dir: PathBuf, work_tree: Option<PathBuf>, algo: HashAlgo) -> Self {
        let odb = LooseOdb::new(StdFs::new(git_dir.join("objects")), algo);
        let refs = RefStore::new(StdFs::new(&git_dir), algo);
        Repository {
            git_dir,
            work_tree,
            algo,
            odb,
            refs,
        }
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

    /// The loose object database (read/write objects).
    pub fn objects(&self) -> &LooseOdb<StdFs> {
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
    fn sha256_repo() {
        let dir = scratch("sha256");
        let repo = Repository::init_with(&dir, HashAlgo::Sha256).unwrap();
        assert_eq!(repo.algo(), HashAlgo::Sha256);
        let repo2 = Repository::open(&dir).unwrap();
        assert_eq!(repo2.algo(), HashAlgo::Sha256);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
