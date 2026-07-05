//! Object-graph integrity checking (`git fsck`).
//!
//! [`fsck`] verifies a repository's connectivity and object well-formedness: it
//! walks every object reachable from the refs, `HEAD`, and the index, and for
//! each one confirms the object is present, readable (loose objects are
//! re-hashed by the object store on read, so a content/​id mismatch surfaces as
//! an unreadable object), and parses as its declared type. Anything missing or
//! malformed is collected into the [`Report`] rather than aborting the walk, so
//! a single fsck run surfaces every problem at once.
//!
//! It also lists **dangling** loose objects — objects on disk that no ref, the
//! index, or reachable history points at (candidates for `gc`). Objects that
//! live only inside a packfile are not enumerated for dangling detection, so the
//! dangling list covers loose objects only.

use alloc::collections::BTreeSet;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::object::tree::FileMode;
use crate::object::{Commit, ObjectType, Tag, Tree};
use crate::odb::ObjectDatabase;
use crate::oid::ObjectId;
use crate::repository::Repository;

/// A single integrity problem: an object that is referenced but missing, or
/// present but malformed.
#[derive(Debug, Clone)]
pub struct Problem {
    /// The problematic object's id.
    pub id: ObjectId,
    /// The object that referenced it, if any (`None` for a root ref target).
    pub referenced_by: Option<ObjectId>,
    /// A human-readable description (`missing object`, `malformed tree: …`, …).
    pub message: String,
}

/// The result of an [`fsck`] run.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Count of reachable objects that read and parsed cleanly.
    pub checked: usize,
    /// Missing or malformed reachable objects.
    pub problems: Vec<Problem>,
    /// Loose objects unreachable from any ref, the index, or history.
    pub dangling: Vec<ObjectId>,
}

impl Report {
    /// Whether the repository is intact (no missing or malformed objects).
    /// Dangling objects are not failures — they are merely reported.
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Checks the integrity of `repo`'s object graph. See the module docs.
pub fn fsck(repo: &Repository) -> Result<Report> {
    let odb = repo.objects();

    // Roots: HEAD (if born), every ref, and every staged index blob (so a
    // staged-but-uncommitted object is not flagged dangling, matching git).
    let mut roots: Vec<ObjectId> = Vec::new();
    if let Ok(head) = repo.head_id() {
        roots.push(head);
    }
    for (_name, id) in repo.refs().list()? {
        roots.push(id);
    }
    for entry in &repo.index()?.entries {
        roots.push(entry.id);
    }

    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    let mut checked = 0usize;

    let mut queue: VecDeque<(ObjectId, Option<ObjectId>)> =
        roots.iter().map(|id| (*id, None)).collect();
    while let Some((id, parent)) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let (ty, payload) = match odb.read(&id) {
            Ok(v) => v,
            Err(Error::NotFound(_)) => {
                problems.push(Problem {
                    id,
                    referenced_by: parent,
                    message: "missing object".into(),
                });
                continue;
            }
            Err(e) => {
                problems.push(Problem {
                    id,
                    referenced_by: parent,
                    message: alloc::format!("unreadable object: {e}"),
                });
                continue;
            }
        };
        checked += 1;

        // Parse the object and enqueue what it references. A parse failure is a
        // recorded problem, not a hard error.
        match ty {
            ObjectType::Commit => match Commit::parse(odb.algo(), &payload) {
                Ok(c) => {
                    queue.push_back((c.tree, Some(id)));
                    for p in c.parents {
                        queue.push_back((p, Some(id)));
                    }
                }
                Err(e) => problems.push(malformed(id, parent, "commit", e)),
            },
            ObjectType::Tree => match Tree::parse(odb.algo(), &payload) {
                Ok(t) => {
                    for entry in t.entries {
                        // Gitlink entries name commits in another repository and
                        // are expected to be absent locally.
                        if entry.mode != FileMode::Gitlink {
                            queue.push_back((entry.id, Some(id)));
                        }
                    }
                }
                Err(e) => problems.push(malformed(id, parent, "tree", e)),
            },
            ObjectType::Tag => match Tag::parse(odb.algo(), &payload) {
                Ok(t) => queue.push_back((t.object, Some(id))),
                Err(e) => problems.push(malformed(id, parent, "tag", e)),
            },
            ObjectType::Blob => {}
        }
    }

    // Dangling loose objects: on disk but unreachable (packed objects are not
    // enumerated here).
    let mut dangling = Vec::new();
    for id in repo.loose_object_ids()? {
        if !seen.contains(&id) {
            dangling.push(id);
        }
    }
    dangling.sort();

    Ok(Report {
        checked,
        problems,
        dangling,
    })
}

fn malformed(id: ObjectId, referenced_by: Option<ObjectId>, kind: &str, e: Error) -> Problem {
    Problem {
        id,
        referenced_by,
        message: alloc::format!("malformed {kind}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectType, Signature};

    fn sig() -> Signature {
        Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 0,
            tz: b"+0000".to_vec(),
        }
    }

    #[test]
    fn clean_repo_passes_and_flags_dangling() {
        let dir = std::env::temp_dir().join(alloc::format!("puregit-fsck-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repository::init(&dir).unwrap();

        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        repo.add_path("a.txt").unwrap();
        repo.commit(b"c\n", sig(), sig()).unwrap();

        // A committed, fully-connected repo is intact with nothing dangling.
        let r = fsck(&repo).unwrap();
        assert!(r.is_ok(), "unexpected problems: {:?}", r.problems);
        assert!(r.checked >= 3); // blob + tree + commit
        assert!(r.dangling.is_empty());

        // Writing a stray, unreferenced blob makes it dangling (but not an error).
        let stray = repo
            .write_object(ObjectType::Blob, b"nobody points here\n")
            .unwrap();
        let r = fsck(&repo).unwrap();
        assert!(r.is_ok());
        assert!(r.dangling.contains(&stray));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
