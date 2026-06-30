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
