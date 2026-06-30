//! `git` — a thin command-line front end over the puregit library.
//!
//! This is intentionally minimal while the library grows: it wires a handful of
//! plumbing/porcelain commands to the crate's public API so the engine can be
//! exercised end to end. Commands are added as the corresponding library
//! capability lands; unimplemented ones print a clear message rather than
//! pretending to succeed.

use std::path::PathBuf;
use std::process::ExitCode;

use puregit::Repository;
use puregit::object::ObjectType;
use puregit::oid::{HashAlgo, ObjectId};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let result = match command.as_str() {
        "init" => cmd_init(&args[1..]),
        "hash-object" => cmd_hash_object(&args[1..]),
        "cat-file" => cmd_cat_file(&args[1..]),
        "rev-parse" => cmd_rev_parse(&args[1..]),
        "add" => cmd_add(&args[1..]),
        "write-tree" => cmd_write_tree(&args[1..]),
        "commit" => cmd_commit(&args[1..]),
        "log" => cmd_log(&args[1..]),
        "status" => cmd_status(&args[1..]),
        "branch" => cmd_branch(&args[1..]),
        "checkout" => cmd_checkout(&args[1..]),
        "gc" | "repack" => cmd_gc(&args[1..]),
        "merge-base" => cmd_merge_base(&args[1..]),
        "unpack-objects" => cmd_unpack_objects(&args[1..]),
        "clone" => cmd_clone(&args[1..]),
        "--version" | "version" => {
            println!("puregit {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
usage: git <command> [<args>]

commands:
    init [<dir>]                 create an empty repository
    hash-object [-w] <file>      compute an object id (and optionally store it)
    cat-file -t|-p|-s <oid>      show an object's type, contents, or size
    rev-parse <ref>             resolve a ref to an object id
    add <file>...               stage working-tree files into the index
    write-tree                  write the index out as a tree, print its id
    commit -m <msg>             commit the staged index
    log                         show commit history from HEAD
    status                      show working-tree status
    branch <name>               create a branch at HEAD
    checkout <branch>           switch to a branch (updates the work tree)
    gc                          pack loose objects and prune them
    merge-base <a> <b>          print the best common ancestor of two commits
    unpack-objects <pack>       explode a packfile into loose objects
    clone <url> [<dir>]         clone a remote repository (http/https)
    version                     print the puregit version";

fn cmd_init(args: &[String]) -> Result<(), String> {
    let dir = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let repo = Repository::init(&dir).map_err(|e| e.to_string())?;
    println!(
        "Initialized empty Git repository in {}",
        repo.git_dir().display()
    );
    Ok(())
}

fn cmd_hash_object(args: &[String]) -> Result<(), String> {
    let mut write = false;
    let mut file = None;
    for arg in args {
        match arg.as_str() {
            "-w" => write = true,
            other => file = Some(other.to_string()),
        }
    }
    let file = file.ok_or("hash-object: missing <file>")?;
    let content = std::fs::read(&file).map_err(|e| format!("reading {file}: {e}"))?;

    if write {
        let repo = open_here()?;
        let id = repo
            .write_object(ObjectType::Blob, &content)
            .map_err(|e| e.to_string())?;
        println!("{id}");
    } else {
        let id = puregit::hash::hash_object(HashAlgo::Sha1, ObjectType::Blob, &content);
        println!("{id}");
    }
    Ok(())
}

fn cmd_cat_file(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("cat-file: usage: cat-file -t|-p|-s <oid>".into());
    }
    let flag = &args[0];
    let repo = open_here()?;
    let id = ObjectId::from_hex(repo.algo(), &args[1]).map_err(|e| e.to_string())?;
    let (ty, payload) = repo.objects_read(&id).map_err(|e| e.to_string())?;

    match flag.as_str() {
        "-t" => println!("{ty}"),
        "-s" => println!("{}", payload.len()),
        "-p" => {
            use std::io::Write;
            std::io::stdout()
                .write_all(&payload)
                .map_err(|e| e.to_string())?;
        }
        other => return Err(format!("cat-file: unknown flag '{other}'")),
    }
    Ok(())
}

fn cmd_rev_parse(args: &[String]) -> Result<(), String> {
    let name = args.first().ok_or("rev-parse: missing <ref>")?;
    let repo = open_here()?;
    let id = repo.refs().resolve(name).map_err(|e| e.to_string())?;
    println!("{id}");
    Ok(())
}

fn cmd_add(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("add: nothing specified".into());
    }
    let repo = open_here()?;
    for path in args {
        repo.add_path(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn cmd_write_tree(_args: &[String]) -> Result<(), String> {
    use puregit::tree_builder::write_tree_from_index;
    let repo = open_here()?;
    let index = repo.index().map_err(|e| e.to_string())?;
    let id = write_tree_from_index(repo.objects(), &index).map_err(|e| e.to_string())?;
    println!("{id}");
    Ok(())
}

fn cmd_commit(args: &[String]) -> Result<(), String> {
    // Minimal flag parsing: `-m <message>`.
    let mut message = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-m" {
            message = args.get(i + 1).cloned();
            i += 2;
        } else {
            i += 1;
        }
    }
    let message = message.ok_or("commit: -m <message> is required")?;

    let repo = open_here()?;
    let who = signature_now(&repo)?;
    let mut body = message.into_bytes();
    body.push(b'\n');
    let id = repo
        .commit(&body, who.clone(), who)
        .map_err(|e| e.to_string())?;
    println!("committed {id}");
    Ok(())
}

fn cmd_log(_args: &[String]) -> Result<(), String> {
    use puregit::walk::RevWalk;
    let repo = open_here()?;
    let head = match repo.head_id() {
        Ok(h) => h,
        Err(_) => return Err("log: HEAD does not point at any commit yet".into()),
    };
    for item in RevWalk::new(repo.objects(), &[head]) {
        let (id, commit) = item.map_err(|e| e.to_string())?;
        let summary = String::from_utf8_lossy(commit.summary());
        let author = String::from_utf8_lossy(&commit.author.name);
        println!("commit {id}");
        println!("Author: {author}");
        println!("\n    {summary}\n");
    }
    Ok(())
}

/// Builds an author/committer signature from `user.name`/`user.email` in config
/// (falling back to the `GIT_AUTHOR_*` env vars, then placeholders) stamped with
/// the current wall-clock time in UTC.
fn signature_now(repo: &Repository) -> Result<puregit::object::Signature, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let cfg = repo.config().map_err(|e| e.to_string())?;
    let name = cfg
        .get("user", None, "name")
        .map(String::from)
        .or_else(|| std::env::var("GIT_AUTHOR_NAME").ok())
        .unwrap_or_else(|| "puregit".into());
    let email = cfg
        .get("user", None, "email")
        .map(String::from)
        .or_else(|| std::env::var("GIT_AUTHOR_EMAIL").ok())
        .unwrap_or_else(|| "puregit@localhost".into());
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(puregit::object::Signature {
        name: name.into_bytes(),
        email: email.into_bytes(),
        time,
        tz: b"+0000".to_vec(),
    })
}

fn cmd_clone(args: &[String]) -> Result<(), String> {
    let url = args.first().ok_or("clone: missing <url>")?;
    let dir = match args.get(1) {
        Some(d) => d.clone(),
        None => dir_from_url(url),
    };

    if url.starts_with("http://") || url.starts_with("https://") {
        return clone_http(url, &dir);
    }
    if url.starts_with("ssh://") || is_scp_like(url) {
        return clone_ssh(url, &dir);
    }
    Err(format!("clone: unsupported URL scheme in '{url}'"))
}

/// Whether `url` looks like an scp-style SSH target (`user@host:path`) rather
/// than a local path — i.e. it has a `:` before any `/`.
fn is_scp_like(url: &str) -> bool {
    match (url.find(':'), url.find('/')) {
        (Some(colon), Some(slash)) => colon < slash,
        (Some(_), None) => true,
        _ => false,
    }
}

#[cfg(feature = "ssh")]
fn clone_ssh(url: &str, dir: &str) -> Result<(), String> {
    use puregit::oid::HashAlgo;
    use puregit::transport::ssh::SshTransport;
    let mut transport = SshTransport::from_url(url, HashAlgo::Sha1).map_err(|e| e.to_string())?;
    if let Ok(pw) = std::env::var("GIT_SSH_PASSWORD") {
        transport = transport.with_password(pw);
    } else if let Ok(key) = std::env::var("GIT_SSH_KEY") {
        transport = transport.with_key(key, std::env::var("GIT_SSH_KEY_PASSPHRASE").ok());
    }
    let repo = puregit::client::clone(dir, &mut transport).map_err(|e| e.to_string())?;
    println!(
        "Cloned into '{}' (HEAD {})",
        dir,
        repo.head_id()
            .map(|h| h.to_hex_short(8))
            .unwrap_or_else(|_| "unborn".into())
    );
    Ok(())
}

#[cfg(not(feature = "ssh"))]
fn clone_ssh(_url: &str, _dir: &str) -> Result<(), String> {
    Err("clone: this build lacks the `ssh` feature".into())
}

#[cfg(feature = "http")]
fn clone_http(url: &str, dir: &str) -> Result<(), String> {
    use puregit::oid::HashAlgo;
    use puregit::transport::http::HttpTransport;
    let mut transport = HttpTransport::new(url.to_string(), HashAlgo::Sha1);
    let repo = puregit::client::clone(dir, &mut transport).map_err(|e| e.to_string())?;
    println!(
        "Cloned into '{}' (HEAD {})",
        dir,
        repo.head_id()
            .map(|h| h.to_hex_short(8))
            .unwrap_or_else(|_| "unborn".into())
    );
    Ok(())
}

#[cfg(not(feature = "http"))]
fn clone_http(_url: &str, _dir: &str) -> Result<(), String> {
    Err("clone: this build lacks the `http` feature".into())
}

/// Derives a directory name from a clone URL (last path segment, sans `.git`).
fn dir_from_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("repo");
    last.strip_suffix(".git").unwrap_or(last).to_string()
}

fn cmd_status(_args: &[String]) -> Result<(), String> {
    use puregit::status::{Change, status};
    let repo = open_here()?;
    let st = status(&repo).map_err(|e| e.to_string())?;
    if st.is_clean() {
        println!("nothing to commit, working tree clean");
        return Ok(());
    }
    let show = |label: &str, items: &[(Vec<u8>, Change)]| {
        if !items.is_empty() {
            println!("{label}:");
            for (path, change) in items {
                let tag = match change {
                    Change::Added => "new file",
                    Change::Modified => "modified",
                    Change::Deleted => "deleted",
                };
                println!("\t{tag}:   {}", String::from_utf8_lossy(path));
            }
        }
    };
    show("Changes to be committed", &st.staged);
    show("Changes not staged for commit", &st.unstaged);
    if !st.untracked.is_empty() {
        println!("Untracked files:");
        for path in &st.untracked {
            println!("\t{}", String::from_utf8_lossy(path));
        }
    }
    Ok(())
}

fn cmd_branch(args: &[String]) -> Result<(), String> {
    let repo = open_here()?;
    match args.first() {
        None => {
            // List branches, marking the current one.
            let current = repo.head().ok();
            for (name, _) in repo.refs().list().map_err(|e| e.to_string())? {
                if let Some(short) = name.strip_prefix("refs/heads/") {
                    let marker = matches!(&current, Some(puregit::refs::Reference::Symbolic(t)) if t == &name);
                    println!("{} {short}", if marker { "*" } else { " " });
                }
            }
            Ok(())
        }
        Some(name) => repo.create_branch(name, None).map_err(|e| e.to_string()),
    }
}

fn cmd_checkout(args: &[String]) -> Result<(), String> {
    let name = args.first().ok_or("checkout: missing <branch>")?;
    let repo = open_here()?;
    repo.checkout(name).map_err(|e| e.to_string())?;
    println!("Switched to branch '{name}'");
    Ok(())
}

fn cmd_merge_base(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("merge-base: usage: merge-base <commit> <commit>".into());
    }
    let repo = open_here()?;
    let a = repo
        .refs()
        .resolve(&args[0])
        .or_else(|_| ObjectId::from_hex(repo.algo(), &args[0]).map_err(|e| e.to_string()))?;
    let b = repo
        .refs()
        .resolve(&args[1])
        .or_else(|_| ObjectId::from_hex(repo.algo(), &args[1]).map_err(|e| e.to_string()))?;
    match puregit::walk::merge_base(repo.objects(), &a, &b).map_err(|e| e.to_string())? {
        Some(base) => {
            println!("{base}");
            Ok(())
        }
        None => Err("no merge base".into()),
    }
}

fn cmd_gc(_args: &[String]) -> Result<(), String> {
    let mut repo = open_here()?;
    let n = repo.repack().map_err(|e| e.to_string())?;
    println!("Packed {n} loose object(s).");
    Ok(())
}

fn cmd_unpack_objects(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("unpack-objects: missing <packfile>")?;
    let pack = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    let repo = open_here()?;
    let ids = repo.ingest_pack(&pack).map_err(|e| e.to_string())?;
    eprintln!("Unpacked {} objects.", ids.len());
    Ok(())
}

fn open_here() -> Result<Repository, String> {
    Repository::open(".").map_err(|e| e.to_string())
}

// Small extension trait shim so `cat-file` can read the raw (type, payload)
// without importing the ObjectDatabase trait at the call site.
trait ObjectsReadExt {
    fn objects_read(&self, id: &ObjectId) -> puregit::Result<(ObjectType, Vec<u8>)>;
}
impl ObjectsReadExt for Repository {
    fn objects_read(&self, id: &ObjectId) -> puregit::Result<(ObjectType, Vec<u8>)> {
        use puregit::odb::ObjectDatabase;
        self.objects().read(id)
    }
}
