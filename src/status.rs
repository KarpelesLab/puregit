//! Working-tree status — comparing `HEAD`, the index, and the working tree.
//!
//! [`status`] computes the three-way comparison `git status` reports:
//!
//! - **staged** — the index versus the `HEAD` tree (what a commit would record).
//! - **unstaged** — the working tree versus the index (changes not yet `add`ed).
//! - **untracked** — files in the working tree absent from the index.
//!
//! Paths are raw bytes relative to the working-tree root. Untracked paths are
//! filtered through the repository's ignore rules (a root `.gitignore` plus
//! `.git/info/exclude`; see [`crate::ignore`]). Per-directory nested
//! `.gitignore` files and rename detection are roadmap refinements.

use alloc::vec::Vec;
use std::path::Path;

use crate::error::{Error, Result};
use crate::hash::hash_object;
use crate::object::tree::FileMode;
use crate::object::{Object, ObjectType};
use crate::oid::ObjectId;
use crate::repository::Repository;

/// How a path changed between two of the three states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    /// Present on the newer side, absent on the older.
    Added,
    /// Present on both with differing content.
    Modified,
    /// Absent on the newer side, present on the older.
    Deleted,
}

/// The result of [`status`]: staged, unstaged, and untracked path lists.
#[derive(Debug, Clone, Default)]
pub struct Status {
    /// Index versus `HEAD` (staged for the next commit).
    pub staged: Vec<(Vec<u8>, Change)>,
    /// Working tree versus index (not yet staged).
    pub unstaged: Vec<(Vec<u8>, Change)>,
    /// Working-tree paths not in the index.
    pub untracked: Vec<Vec<u8>>,
}

impl Status {
    /// Whether the working tree and index are clean relative to `HEAD`.
    pub fn is_clean(&self) -> bool {
        self.staged.is_empty() && self.unstaged.is_empty() && self.untracked.is_empty()
    }
}

/// Computes the working-tree status of `repo` (requires a non-bare repository).
pub fn status(repo: &Repository) -> Result<Status> {
    use alloc::collections::{BTreeMap, BTreeSet};

    let work = repo
        .work_tree()
        .ok_or_else(|| Error::Io("status: bare repository has no work tree".into()))?
        .to_path_buf();

    // HEAD tree, flattened to path → (mode, id) (empty on an unborn branch).
    let head_map: BTreeMap<Vec<u8>, (FileMode, ObjectId)> = match repo.head_id() {
        Ok(commit_id) => {
            let commit = match repo.read_object(&commit_id)? {
                Object::Commit(c) => c,
                _ => return Err(Error::Parse("HEAD is not a commit".into())),
            };
            crate::walk::flatten_tree(repo.objects(), &commit.tree)?
        }
        Err(_) => BTreeMap::new(),
    };

    // Index (stage 0), path → entry. Every stage counts as tracked.
    let index = repo.index()?;
    let index_map: BTreeMap<Vec<u8>, &crate::index::IndexEntry> = index
        .entries
        .iter()
        .filter(|e| e.stage == 0)
        .map(|e| (e.path.clone(), e))
        .collect();
    let tracked: BTreeSet<&[u8]> = index.entries.iter().map(|e| &e.path[..]).collect();

    // Staged: index vs HEAD — the content *or* the mode (e.g. a staged
    // `chmod +x`) differing counts. An intent-to-add entry (`git add -N`) is
    // a placeholder, not staged content: git reports it as added in the work
    // tree instead.
    let mut staged = Vec::new();
    for (path, e) in &index_map {
        if is_intent_to_add(e) {
            continue;
        }
        let mode = FileMode::from_mode_bits(e.mode)?;
        match head_map.get(path) {
            None => staged.push((path.clone(), Change::Added)),
            Some(&(h_mode, h_id)) if h_id != e.id || h_mode != mode => {
                staged.push((path.clone(), Change::Modified))
            }
            Some(_) => {}
        }
    }
    for path in head_map.keys() {
        if !tracked.contains(&path[..]) {
            staged.push((path.clone(), Change::Deleted));
        }
    }

    // Working-tree files, relative paths.
    let mut worktree_files = BTreeSet::new();
    collect_files(&work, &work, &mut worktree_files)?;
    let filemode = repo
        .config()
        .ok()
        .and_then(|c| c.get("core", None, "filemode").map(|v| v != "false"))
        .unwrap_or(cfg!(unix));

    // Unstaged: index vs working tree.
    let mut unstaged = Vec::new();
    for (path, e) in &index_map {
        // Defense in depth (D4): `Index::parse` rejects unsafe paths, but
        // re-validate before joining so a stray unvalidated path can never
        // redirect this read outside the work tree.
        if !crate::index::is_safe_index_path(path) {
            continue;
        }
        // A gitlink (submodule) is a directory with its own repository;
        // its state is not part of this tree's status.
        if e.mode & 0o170000 == 0o160000 {
            continue;
        }
        let full = join_rel(&work, path);
        match worktree_blob(&full) {
            None => unstaged.push((path.clone(), Change::Deleted)),
            Some(_) if is_intent_to_add(e) => unstaged.push((path.clone(), Change::Added)),
            Some((wt_mode, content)) => {
                let index_mode = FileMode::from_mode_bits(e.mode)?;
                let wt_id = hash_object(repo.algo(), ObjectType::Blob, &content);
                if wt_id != e.id || !modes_agree(index_mode, wt_mode, filemode) {
                    unstaged.push((path.clone(), Change::Modified));
                }
            }
        }
    }

    // Untracked: working-tree files not in the index and not ignored. (Tracked
    // paths are never untracked, so an ignore rule never hides them.)
    let ignore = load_ignore(repo, &work);
    let mut untracked = Vec::new();
    for path in &worktree_files {
        if !tracked.contains(&path[..]) && !ignore.is_ignored(path) {
            untracked.push(path.clone());
        }
    }

    staged.sort();
    unstaged.sort();
    untracked.sort();
    Ok(Status {
        staged,
        unstaged,
        untracked,
    })
}

/// Whether an index entry is an intent-to-add placeholder (`git add -N`).
fn is_intent_to_add(e: &crate::index::IndexEntry) -> bool {
    e.extended_flags & crate::index::EXT_INTENT_TO_ADD != 0
}

/// Reads a working-tree path the way git would stage it: a symlink yields its
/// *target* (not the file it points at) with [`FileMode::Symlink`]; a regular
/// file yields its content with its executable bit. `None` if the path is
/// missing or is not a file/symlink (e.g. replaced by a directory).
fn worktree_blob(full: &Path) -> Option<(FileMode, Vec<u8>)> {
    let meta = std::fs::symlink_metadata(full).ok()?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = std::fs::read_link(full).ok()?;
        return Some((
            FileMode::Symlink,
            crate::worktree::link_target_bytes(&target),
        ));
    }
    if !ft.is_file() {
        return None;
    }
    let content = std::fs::read(full).ok()?;
    Some((crate::worktree::file_mode_of(&meta), content))
}

/// Whether the index mode and the working-tree file's mode agree, as git
/// judges it: the executable bit only counts when `core.filemode` is on, and
/// on a platform without symlinks a symlink is checked out as a plain file
/// holding the target.
fn modes_agree(index: FileMode, worktree: FileMode, filemode: bool) -> bool {
    use FileMode::*;
    match (index, worktree) {
        (Symlink, Symlink) => true,
        (Symlink, _) => !cfg!(unix),
        (_, Symlink) => false,
        (a, b) => !filemode || a == b,
    }
}

/// Loads the repository's ignore rules:`.git/info/exclude` first, then the
/// work-tree root `.gitignore` (so a root rule can override an exclude). Missing
/// files are simply skipped.
fn load_ignore(repo: &Repository, work: &Path) -> crate::ignore::Ignore {
    let mut ignore = crate::ignore::Ignore::new();
    if let Ok(bytes) = std::fs::read(repo.git_dir().join("info").join("exclude")) {
        ignore.add_bytes(&bytes);
    }
    if let Ok(bytes) = std::fs::read(work.join(".gitignore")) {
        ignore.add_bytes(&bytes);
    }
    ignore
}

/// Recursively collects working-tree file paths (relative to `root`), skipping
/// the `.git` directory.
fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut alloc::collections::BTreeSet<Vec<u8>>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files(root, &path, out)?;
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.insert(path_to_bytes(rel));
        }
    }
    Ok(())
}

/// Joins a raw byte path (relative) onto the work-tree root.
fn join_rel(root: &Path, rel: &[u8]) -> std::path::PathBuf {
    let s = String::from_utf8_lossy(rel);
    root.join(s.as_ref())
}

#[cfg(unix)]
fn path_to_bytes(p: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_to_bytes(p: &Path) -> Vec<u8> {
    // On non-Unix, normalize separators to `/` to match git's path form.
    p.to_string_lossy().replace('\\', "/").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Signature;

    fn sig() -> Signature {
        Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 0,
            tz: b"+0000".to_vec(),
        }
    }

    #[test]
    fn reports_staged_unstaged_untracked() {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-status-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();

        // Commit one file.
        std::fs::write(dir.join("committed.txt"), b"v1\n").unwrap();
        repo.add_path("committed.txt").unwrap();
        repo.commit(b"c\n", sig(), sig()).unwrap();
        assert!(status(&repo).unwrap().is_clean());

        // Modify the committed file in the working tree (unstaged).
        std::fs::write(dir.join("committed.txt"), b"v2\n").unwrap();
        // Stage a brand-new file (staged add).
        std::fs::write(dir.join("staged.txt"), b"new\n").unwrap();
        repo.add_path("staged.txt").unwrap();
        // Leave an untracked file.
        std::fs::write(dir.join("untracked.txt"), b"loose\n").unwrap();

        let st = status(&repo).unwrap();
        assert!(
            st.staged
                .iter()
                .any(|(p, c)| p == b"staged.txt" && *c == Change::Added)
        );
        assert!(
            st.unstaged
                .iter()
                .any(|(p, c)| p == b"committed.txt" && *c == Change::Modified)
        );
        assert!(st.untracked.iter().any(|p| p == b"untracked.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gitignore_filters_untracked() {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-status-ign-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();

        std::fs::write(dir.join(".gitignore"), b"*.log\nbuild/\n").unwrap();
        std::fs::write(dir.join("keep.txt"), b"k\n").unwrap();
        std::fs::write(dir.join("debug.log"), b"noise\n").unwrap();
        std::fs::create_dir_all(dir.join("build")).unwrap();
        std::fs::write(dir.join("build/out.bin"), b"art\n").unwrap();

        let st = status(&repo).unwrap();
        // The ignored files are absent; the real untracked ones remain.
        assert!(st.untracked.iter().any(|p| p == b"keep.txt"));
        assert!(st.untracked.iter().any(|p| p == b".gitignore"));
        assert!(!st.untracked.iter().any(|p| p == b"debug.log"));
        assert!(!st.untracked.iter().any(|p| p == b"build/out.bin"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staged_mode_change_and_intent_to_add() {
        let dir =
            std::env::temp_dir().join(alloc::format!("puregit-status-mode-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("tool.sh"), b"echo\n").unwrap();
        repo.add_path("tool.sh").unwrap();
        repo.commit(b"c\n", sig(), sig()).unwrap();

        // Stage only a mode change (content identical).
        let mut index = repo.index().unwrap();
        index.entries[0].mode = 0o100755;
        // And an intent-to-add placeholder for a new file.
        std::fs::write(dir.join("later.txt"), b"later\n").unwrap();
        let mut ita = index.entries[0].clone();
        ita.path = b"later.txt".to_vec();
        ita.mode = 0o100644;
        ita.id = hash_object(repo.algo(), ObjectType::Blob, b"");
        ita.extended_flags = crate::index::EXT_INTENT_TO_ADD;
        index.entries.push(ita);
        repo.write_index(&index).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.join("tool.sh");
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm).unwrap();
        }

        let st = status(&repo).unwrap();
        assert_eq!(
            st.staged,
            alloc::vec![(b"tool.sh".to_vec(), Change::Modified)]
        );
        // git: " A later.txt" — added in the work tree, nothing staged.
        assert_eq!(
            st.unstaged,
            alloc::vec![(b"later.txt".to_vec(), Change::Added)]
        );
        assert!(st.untracked.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_staged_and_compared_as_links() {
        let dir =
            std::env::temp_dir().join(alloc::format!("puregit-status-link-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("target.txt"), b"content\n").unwrap();
        std::os::unix::fs::symlink("target.txt", dir.join("link")).unwrap();
        repo.add_path("target.txt").unwrap();
        let id = repo.add_path("link").unwrap();
        // The blob is the link text, the mode 120000.
        assert_eq!(
            id,
            hash_object(repo.algo(), ObjectType::Blob, b"target.txt")
        );
        assert_eq!(repo.index().unwrap().get(b"link").unwrap().mode, 0o120000);
        repo.commit(b"c\n", sig(), sig()).unwrap();
        assert!(status(&repo).unwrap().is_clean());

        // Editing the target does not modify the link; retargeting does.
        std::fs::write(dir.join("target.txt"), b"changed\n").unwrap();
        let st = status(&repo).unwrap();
        assert_eq!(
            st.unstaged,
            alloc::vec![(b"target.txt".to_vec(), Change::Modified)]
        );
        std::fs::remove_file(dir.join("link")).unwrap();
        std::os::unix::fs::symlink("elsewhere", dir.join("link")).unwrap();
        let st = status(&repo).unwrap();
        assert!(st.unstaged.contains(&(b"link".to_vec(), Change::Modified)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
