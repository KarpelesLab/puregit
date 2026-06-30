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
        "unpack-objects" => cmd_unpack_objects(&args[1..]),
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
    unpack-objects <pack>       explode a packfile into loose objects
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
