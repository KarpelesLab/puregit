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
        "rm" => cmd_rm(&args[1..]),
        "mv" => cmd_mv(&args[1..]),
        "write-tree" => cmd_write_tree(&args[1..]),
        "read-tree" => cmd_read_tree(&args[1..]),
        "mktree" => cmd_mktree(&args[1..]),
        "commit-tree" => cmd_commit_tree(&args[1..]),
        "commit" => cmd_commit(&args[1..]),
        "log" => cmd_log(&args[1..]),
        "reflog" => cmd_reflog(&args[1..]),
        "show" => cmd_show(&args[1..]),
        "status" => cmd_status(&args[1..]),
        "branch" => cmd_branch(&args[1..]),
        "checkout" => cmd_checkout(&args[1..]),
        "reset" => cmd_reset(&args[1..]),
        "gc" | "repack" => cmd_gc(&args[1..]),
        "fsck" => cmd_fsck(&args[1..]),
        "prune" => cmd_prune(&args[1..]),
        "commit-graph" => cmd_commit_graph(&args[1..]),
        "multi-pack-index" => cmd_multi_pack_index(&args[1..]),
        "merge-base" => cmd_merge_base(&args[1..]),
        "merge" => cmd_merge(&args[1..]),
        "lfs" => cmd_lfs(&args[1..]),
        "tag" => cmd_tag(&args[1..]),
        "ls-tree" => cmd_ls_tree(&args[1..]),
        "diff-tree" => cmd_diff_tree(&args[1..]),
        "diff" => cmd_diff(&args[1..]),
        "unpack-objects" => cmd_unpack_objects(&args[1..]),
        "verify-pack" => cmd_verify_pack(&args[1..]),
        "clone" => cmd_clone(&args[1..]),
        "completion" => cmd_completion(&args[1..]),
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
    cat-file --batch            print type/size/contents for oids read on stdin
    rev-parse <ref>             resolve a ref to an object id
    add <file>...               stage working-tree files (or deletions)
    rm <file>...                remove files from the index and work tree
    mv <source> <dest>          move/rename a tracked file
    write-tree                  write the index out as a tree, print its id
    read-tree <tree-ish>        load a tree into the index (replacing it)
    mktree                      read `ls-tree` lines from stdin, write a tree
    commit-tree <tree> [-p <parent>]... [-m <msg>]
                                create a commit object, print its id
    commit -m <msg>             commit the staged index
    log                         show commit history from HEAD
    reflog [<ref>]              show the update log of a ref (default HEAD)
    show [<object>]             show a commit (with patch), tag, tree, or blob
    status                      show working-tree status
    branch <name>               create a branch at HEAD
    checkout <branch>           switch to a branch (updates the work tree)
    reset [--soft|--mixed|--hard] [<commit>]
                                move HEAD (and index/work tree) to a commit
    gc                          pack loose objects and prune them
    fsck                        verify object connectivity and integrity
    prune                       delete unreachable loose objects
    commit-graph write|verify   write or verify the commit-graph cache
    multi-pack-index write|verify  write or verify the multi-pack-index
    merge-base <a> <b>          print the best common ancestor of two commits
    merge <branch>              merge a branch into the current branch
    lfs track <pattern>         track a path pattern with Git LFS
    lfs ls-files                list LFS-pointer files in the index
    lfs pull                    download LFS objects for the current checkout
    tag <name> [<commit>]       create a lightweight tag (or list tags)
    ls-tree <tree-ish>          list the entries of a tree
    diff-tree <a> <b>           name-status diff between two commits/trees
    diff                        unified diff of the work tree vs the index
    unpack-objects <pack>       explode a packfile into loose objects
    verify-pack <pack>          check a packfile against its .idx
    clone <url> [<dir>]         clone a remote repository (http/https)
    completion [bash]           print a shell completion script
    version                     print the puregit version";

/// The subcommands offered for shell completion (kept in sync with `main`'s
/// dispatch and `USAGE`).
const SUBCOMMANDS: &[&str] = &[
    "init",
    "hash-object",
    "cat-file",
    "rev-parse",
    "add",
    "rm",
    "mv",
    "write-tree",
    "read-tree",
    "mktree",
    "commit-tree",
    "commit",
    "log",
    "reflog",
    "show",
    "status",
    "branch",
    "checkout",
    "reset",
    "gc",
    "repack",
    "fsck",
    "prune",
    "merge-base",
    "merge",
    "lfs",
    "tag",
    "ls-tree",
    "diff-tree",
    "diff",
    "unpack-objects",
    "verify-pack",
    "clone",
    "completion",
    "version",
];

/// `completion [bash]` — print a shell completion script for this `git` binary.
/// Only bash is supported today; source the output (e.g. from `~/.bashrc`).
fn cmd_completion(args: &[String]) -> Result<(), String> {
    let shell = args.first().map(String::as_str).unwrap_or("bash");
    if shell != "bash" {
        return Err(format!(
            "completion: unsupported shell '{shell}' (try 'bash')"
        ));
    }
    let words = SUBCOMMANDS.join(" ");
    // A minimal completion: complete the first argument against the subcommand
    // list; leave later words to the filesystem default.
    println!(
        "_puregit_git() {{\n  \
           local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  \
           if [ \"$COMP_CWORD\" -eq 1 ]; then\n    \
             COMPREPLY=( $(compgen -W \"{words}\" -- \"$cur\") )\n  \
           fi\n\
         }}\n\
         complete -o default -F _puregit_git git"
    );
    Ok(())
}

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
    if args.first().map(String::as_str) == Some("--batch") {
        return cmd_cat_file_batch();
    }
    if args.len() < 2 {
        return Err("cat-file: usage: cat-file -t|-p|-s <oid> | --batch".into());
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

/// `cat-file --batch` — read object names on stdin (one per line) and, for each,
/// print `<oid> SP <type> SP <size> LF` followed by the raw contents and a LF.
/// An unresolvable name prints `<name> missing`, matching git.
fn cmd_cat_file_batch() -> Result<(), String> {
    use std::io::{BufRead, Write};

    let repo = open_here()?;
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let rev = line.trim();
        if rev.is_empty() {
            continue;
        }
        let resolved = repo
            .refs()
            .resolve(rev)
            .or_else(|_| ObjectId::from_hex(repo.algo(), rev).map_err(|e| e.to_string()))
            .ok()
            .and_then(|id| repo.objects_read(&id).ok().map(|(ty, p)| (id, ty, p)));
        match resolved {
            Some((id, ty, payload)) => {
                writeln!(out, "{id} {ty} {}", payload.len()).map_err(|e| e.to_string())?;
                out.write_all(&payload).map_err(|e| e.to_string())?;
                out.write_all(b"\n").map_err(|e| e.to_string())?;
            }
            None => {
                writeln!(out, "{rev} missing").map_err(|e| e.to_string())?;
            }
        }
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

fn cmd_rm(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("rm: nothing specified".into());
    }
    let repo = open_here()?;
    for path in args {
        repo.remove_path(path).map_err(|e| e.to_string())?;
        println!("rm '{path}'");
    }
    Ok(())
}

fn cmd_mv(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("mv: usage: mv <source> <dest>".into());
    }
    let repo = open_here()?;
    repo.mv(&args[0], &args[1]).map_err(|e| e.to_string())
}

fn cmd_write_tree(_args: &[String]) -> Result<(), String> {
    use puregit::tree_builder::write_tree_from_index;
    let repo = open_here()?;
    let index = repo.index().map_err(|e| e.to_string())?;
    let id = write_tree_from_index(repo.objects(), &index).map_err(|e| e.to_string())?;
    println!("{id}");
    Ok(())
}

/// `read-tree <tree-ish>` — resolve a tree/commit and load its tree into the
/// index, replacing the current staged contents.
fn cmd_read_tree(args: &[String]) -> Result<(), String> {
    use puregit::object::Object;
    let rev = args.first().ok_or("read-tree: missing <tree-ish>")?;
    let repo = open_here()?;
    let id = repo
        .refs()
        .resolve(rev)
        .or_else(|_| ObjectId::from_hex(repo.algo(), rev).map_err(|e| e.to_string()))?;
    let tree = match repo.read_object(&id).map_err(|e| e.to_string())? {
        Object::Commit(c) => c.tree,
        Object::Tree(_) => id,
        other => {
            return Err(format!(
                "read-tree: {} is not a tree or commit",
                other.object_type()
            ));
        }
    };
    repo.read_tree(&tree).map_err(|e| e.to_string())
}

/// `mktree` — read `ls-tree`-style lines from stdin and write a single tree
/// object, printing its id. Each line is `<mode> SP <type> SP <sha> TAB <name>`
/// (the `<type>` column is accepted but ignored; the mode determines the entry
/// kind). Entries are canonically sorted by `Tree::serialize`, so the input
/// order does not matter.
fn cmd_mktree(_args: &[String]) -> Result<(), String> {
    use puregit::object::tree::FileMode;
    use puregit::object::{Tree, TreeEntry};
    use std::io::Read;

    let repo = open_here()?;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("mktree: reading stdin: {e}"))?;

    let mut entries = Vec::new();
    for line in input.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Split "<mode> <type> <sha>\t<name>": the name is after the TAB, the
        // three space-separated fields are before it.
        let (meta, name) = line
            .split_once('\t')
            .ok_or_else(|| format!("mktree: no TAB before name in: {line}"))?;
        let mut fields = meta.split_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| format!("mktree: missing mode in: {line}"))?;
        let _kind = fields.next(); // "blob"/"tree"/"commit" — informational.
        let sha = fields
            .next()
            .ok_or_else(|| format!("mktree: missing sha in: {line}"))?;

        entries.push(TreeEntry {
            mode: FileMode::from_octal(mode.as_bytes()).map_err(|e| e.to_string())?,
            name: name.as_bytes().to_vec(),
            id: ObjectId::from_hex(repo.algo(), sha).map_err(|e| e.to_string())?,
        });
    }

    let id = repo
        .write_object(ObjectType::Tree, &Tree { entries }.serialize())
        .map_err(|e| e.to_string())?;
    println!("{id}");
    Ok(())
}

/// `commit-tree <tree> [-p <parent>]... [-m <msg>]` — create a commit object for
/// an existing tree and print its id, without touching `HEAD` or the index.
/// The message comes from `-m` (repeatable, joined by blank lines) or, if none
/// is given, from stdin.
fn cmd_commit_tree(args: &[String]) -> Result<(), String> {
    use puregit::object::{Commit, Object};
    use std::io::Read;

    let mut tree_arg = None;
    let mut parents_hex = Vec::new();
    let mut messages = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                let p = args.get(i + 1).ok_or("commit-tree: -p needs a <parent>")?;
                parents_hex.push(p.clone());
                i += 2;
            }
            "-m" => {
                let m = args.get(i + 1).ok_or("commit-tree: -m needs a <message>")?;
                messages.push(m.clone());
                i += 2;
            }
            other => {
                if tree_arg.is_some() {
                    return Err(format!("commit-tree: unexpected argument '{other}'"));
                }
                tree_arg = Some(other.to_string());
                i += 1;
            }
        }
    }
    let tree_arg = tree_arg.ok_or("commit-tree: missing <tree>")?;

    let repo = open_here()?;
    let tree = ObjectId::from_hex(repo.algo(), &tree_arg).map_err(|e| e.to_string())?;
    // Validate the id names a tree so a typo fails loudly rather than producing
    // a dangling commit.
    match repo.read_object(&tree).map_err(|e| e.to_string())? {
        Object::Tree(_) => {}
        other => {
            return Err(format!(
                "commit-tree: {tree} is a {}, not a tree",
                other.object_type()
            ));
        }
    }

    let mut parents = Vec::new();
    for p in &parents_hex {
        parents.push(ObjectId::from_hex(repo.algo(), p).map_err(|e| e.to_string())?);
    }

    let mut message = if messages.is_empty() {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("commit-tree: reading stdin: {e}"))?;
        buf
    } else {
        messages.join("\n\n")
    };
    if !message.ends_with('\n') {
        message.push('\n');
    }

    let who = signature_now(&repo)?;
    let commit = Commit {
        tree,
        parents,
        author: who.clone(),
        committer: who,
        extra_headers: Vec::new(),
        message: message.into_bytes(),
    };
    let id = repo
        .write_object(ObjectType::Commit, &commit.serialize())
        .map_err(|e| e.to_string())?;
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

/// `show [<object>]` (default `HEAD`) — display an object. A commit prints its
/// header and message followed by a unified patch against its first parent; a
/// tag prints its header and then shows the object it points at; a tree lists
/// its entries; a blob prints its raw contents.
fn cmd_show(args: &[String]) -> Result<(), String> {
    let rev = args.first().map(String::as_str).unwrap_or("HEAD");
    let repo = open_here()?;
    let id = repo
        .refs()
        .resolve(rev)
        .or_else(|_| ObjectId::from_hex(repo.algo(), rev).map_err(|e| e.to_string()))?;
    show_object(&repo, &id)
}

/// Renders one object for `show`, recursing through a tag to its target.
fn show_object(repo: &Repository, id: &ObjectId) -> Result<(), String> {
    use puregit::object::Object;
    use std::io::Write;

    match repo.read_object(id).map_err(|e| e.to_string())? {
        Object::Commit(c) => {
            println!("commit {id}");
            println!(
                "Author: {} <{}>",
                String::from_utf8_lossy(&c.author.name),
                String::from_utf8_lossy(&c.author.email)
            );
            println!();
            for line in String::from_utf8_lossy(&c.message).lines() {
                println!("    {line}");
            }
            println!();

            // Unified patch against the first parent (an empty tree for a root
            // commit), built from flattened path → blob maps of both trees.
            let new_map =
                puregit::walk::flatten_tree(repo.objects(), &c.tree).map_err(|e| e.to_string())?;
            let mut old_map = std::collections::BTreeMap::new();
            if let Some(parent) = c.parents.first()
                && let Object::Commit(pc) = repo.read_object(parent).map_err(|e| e.to_string())?
            {
                old_map = puregit::walk::flatten_tree(repo.objects(), &pc.tree)
                    .map_err(|e| e.to_string())?;
            }
            print_patch(repo, &old_map, &new_map)
        }
        Object::Tag(t) => {
            println!("tag {}", String::from_utf8_lossy(&t.name));
            if let Some(tagger) = &t.tagger {
                println!(
                    "Tagger: {} <{}>",
                    String::from_utf8_lossy(&tagger.name),
                    String::from_utf8_lossy(&tagger.email)
                );
            }
            println!();
            for line in String::from_utf8_lossy(&t.message).lines() {
                println!("{line}");
            }
            println!();
            // Show the object the tag points at (a commit, usually).
            show_object(repo, &t.object)
        }
        Object::Tree(t) => {
            for entry in &t.entries {
                let kind = if entry.mode.is_tree() { "tree" } else { "blob" };
                println!(
                    "{:0>6} {} {}\t{}",
                    entry.mode.as_octal(),
                    kind,
                    entry.id,
                    String::from_utf8_lossy(&entry.name)
                );
            }
            Ok(())
        }
        Object::Blob(bytes) => std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| e.to_string()),
    }
}

/// Prints a `git show`-style unified patch between two flattened trees.
fn print_patch(
    repo: &Repository,
    old: &std::collections::BTreeMap<Vec<u8>, (puregit::object::FileMode, ObjectId)>,
    new: &std::collections::BTreeMap<Vec<u8>, (puregit::object::FileMode, ObjectId)>,
) -> Result<(), String> {
    use puregit::object::FileMode;

    // The union of paths, in sorted order (both maps are already ordered).
    let mut paths: Vec<&Vec<u8>> = old.keys().chain(new.keys()).collect();
    paths.sort();
    paths.dedup();

    for path in paths {
        let o = old.get(path);
        let n = new.get(path);
        if o.map(|(_, i)| i) == n.map(|(_, i)| i) {
            continue; // unchanged (same blob id)
        }
        let name = String::from_utf8_lossy(path);
        // Submodule (gitlink) entries have no local blob to diff; note the id
        // change and move on.
        let is_gitlink =
            |e: Option<&(FileMode, ObjectId)>| matches!(e, Some((FileMode::Gitlink, _)));
        if is_gitlink(o) || is_gitlink(n) {
            println!("Submodule {name} changed");
            continue;
        }
        let read = |e: Option<&(FileMode, ObjectId)>| -> Result<Vec<u8>, String> {
            match e {
                Some((_, id)) => repo
                    .objects_read(id)
                    .map(|(_, p)| p)
                    .map_err(|err| err.to_string()),
                None => Ok(Vec::new()),
            }
        };
        let old_bytes = read(o)?;
        let new_bytes = read(n)?;
        println!("diff --git a/{name} b/{name}");
        let patch = puregit::diff::unified(
            &old_bytes,
            &new_bytes,
            &format!("a/{name}"),
            &format!("b/{name}"),
            3,
        );
        print!("{patch}");
    }
    Ok(())
}

/// `reflog [<ref>]` — print a ref's update log; `reflog expire [--expire=<secs>]
/// [<ref>]` — drop entries older than `<secs>` ago (default 90 days).
fn cmd_reflog(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("expire") {
        return cmd_reflog_expire(&args[1..]);
    }
    let refname = args.first().map(String::as_str).unwrap_or("HEAD");
    let repo = open_here()?;
    let path = repo.git_dir().join("logs").join(refname);
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    // Entries are appended oldest-first; git numbers them newest-first as @{0}.
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().rev().enumerate() {
        let Some((meta, message)) = line.split_once('\t') else {
            continue;
        };
        // meta = "<old> <new> <name> <email> <time> <tz>"; we want <new>.
        let new = meta.split_whitespace().nth(1).unwrap_or("");
        let short = &new[..new.len().min(8)];
        println!("{short} {refname}@{{{i}}}: {message}");
    }
    Ok(())
}

/// `reflog expire [--expire=<seconds>] [<ref>]` — drop entries in `logs/<ref>`
/// older than `<seconds>` ago (default 90 days), matching `git reflog expire`.
fn cmd_reflog_expire(args: &[String]) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seconds: i64 = 90 * 24 * 60 * 60; // 90 days
    let mut refname = "HEAD".to_string();
    for arg in args {
        if let Some(v) = arg.strip_prefix("--expire=") {
            seconds = v
                .parse()
                .map_err(|_| format!("reflog expire: bad --expire value {v:?}"))?;
        } else {
            refname = arg.clone();
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let repo = open_here()?;
    let removed = repo
        .reflog_expire(&refname, now - seconds)
        .map_err(|e| e.to_string())?;
    eprintln!(
        "reflog expire: dropped {removed} entr{}",
        if removed == 1 { "y" } else { "ies" }
    );
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
    write_origin_config(&repo, url)?;
    Ok(())
}

/// Records `[remote "origin"]` (URL + default fetch refspec) in a freshly cloned
/// repository's config, so later fetches and `git lfs pull` know the origin.
#[cfg(any(feature = "http", feature = "ssh"))]
fn write_origin_config(repo: &Repository, url: &str) -> Result<(), String> {
    use puregit::refs::Reference;

    let mut cfg = repo.config().map_err(|e| e.to_string())?;
    cfg.set("remote", Some("origin"), "url", url);
    cfg.set(
        "remote",
        Some("origin"),
        "fetch",
        &puregit::remote::Remote::default_fetch("origin").to_string_form(),
    );
    // Set the checked-out branch to track origin's matching branch.
    if let Ok(Reference::Symbolic(head_ref)) = repo.head()
        && let Some(branch) = head_ref.strip_prefix("refs/heads/")
    {
        cfg.set("branch", Some(branch), "remote", "origin");
        cfg.set("branch", Some(branch), "merge", &head_ref);
    }
    repo.write_config(&cfg).map_err(|e| e.to_string())
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

    // Record the origin URL + default fetch refspec so `git lfs pull` and
    // future fetches know the origin.
    write_origin_config(&repo, url)?;

    // Best-effort: fetch any LFS objects the checkout left as pointers.
    match cmd_lfs_pull(&repo) {
        Ok(()) => {}
        Err(e) => eprintln!("warning: lfs pull skipped: {e}"),
    }
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

fn cmd_status(args: &[String]) -> Result<(), String> {
    use puregit::status::{Change, status};
    let repo = open_here()?;
    let st = status(&repo).map_err(|e| e.to_string())?;

    if args
        .iter()
        .any(|a| a == "--porcelain" || a == "-s" || a == "--short")
    {
        return status_porcelain(&st);
    }

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

/// `status --porcelain` (v1) — one `XY SP <path>` line per changed path, sorted
/// by path. `X` is the index-vs-`HEAD` (staged) state and `Y` the worktree-vs-
/// index (unstaged) state; each is `A`/`M`/`D` or a space when unchanged on that
/// side. Untracked paths are `??`. This is the stable, script-friendly format.
fn status_porcelain(st: &puregit::status::Status) -> Result<(), String> {
    use puregit::status::Change;
    use std::collections::BTreeMap;

    let code = |c: &Change| match c {
        Change::Added => 'A',
        Change::Modified => 'M',
        Change::Deleted => 'D',
    };
    // path -> (staged col, unstaged col), both defaulting to space (unchanged).
    let mut rows: BTreeMap<&[u8], (char, char)> = BTreeMap::new();
    for (path, change) in &st.staged {
        rows.entry(path).or_insert((' ', ' ')).0 = code(change);
    }
    for (path, change) in &st.unstaged {
        rows.entry(path).or_insert((' ', ' ')).1 = code(change);
    }
    for path in &st.untracked {
        rows.insert(path, ('?', '?'));
    }
    for (path, (x, y)) in &rows {
        println!("{x}{y} {}", String::from_utf8_lossy(path));
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

/// `reset [--soft|--mixed|--hard] [<commit>]` — move the current branch to
/// `<commit>` (default `HEAD`); `--mixed` (default) also resets the index,
/// `--hard` also overwrites the working tree, `--soft` moves the ref only.
fn cmd_reset(args: &[String]) -> Result<(), String> {
    use puregit::repository::ResetMode;

    let mut mode = ResetMode::Mixed;
    let mut target = None;
    for arg in args {
        match arg.as_str() {
            "--soft" => mode = ResetMode::Soft,
            "--mixed" => mode = ResetMode::Mixed,
            "--hard" => mode = ResetMode::Hard,
            other if other.starts_with('-') => {
                return Err(format!("reset: unknown option '{other}'"));
            }
            other => target = Some(other.to_string()),
        }
    }
    let target = target.unwrap_or_else(|| "HEAD".to_string());

    let repo = open_here()?;
    let commit = repo
        .refs()
        .resolve(&target)
        .or_else(|_| ObjectId::from_hex(repo.algo(), &target).map_err(|e| e.to_string()))?;
    repo.reset(mode, &commit).map_err(|e| e.to_string())?;
    let label = match mode {
        ResetMode::Soft => "soft",
        ResetMode::Mixed => "mixed",
        ResetMode::Hard => "hard",
    };
    println!("HEAD is now at {} ({label} reset)", commit.to_hex_short(8));
    Ok(())
}

fn cmd_tag(args: &[String]) -> Result<(), String> {
    let repo = open_here()?;
    match args.first() {
        None => {
            // List tags.
            for (name, _) in repo.refs().list().map_err(|e| e.to_string())? {
                if let Some(short) = name.strip_prefix("refs/tags/") {
                    println!("{short}");
                }
            }
            Ok(())
        }
        Some(name) => {
            let target = match args.get(1) {
                Some(rev) => repo
                    .refs()
                    .resolve(rev)
                    .or_else(|_| ObjectId::from_hex(repo.algo(), rev).map_err(|e| e.to_string()))?,
                None => repo.head_id().map_err(|e| e.to_string())?,
            };
            let full = format!("refs/tags/{name}");
            if repo.refs().lookup(&full).is_ok() {
                return Err(format!("tag '{name}' already exists"));
            }
            repo.refs()
                .update(&full, &puregit::refs::Reference::Direct(target))
                .map_err(|e| e.to_string())
        }
    }
}

fn cmd_ls_tree(args: &[String]) -> Result<(), String> {
    use puregit::object::Object;
    let rev = args.first().ok_or("ls-tree: missing <tree-ish>")?;
    let repo = open_here()?;
    let id = repo
        .refs()
        .resolve(rev)
        .or_else(|_| ObjectId::from_hex(repo.algo(), rev).map_err(|e| e.to_string()))?;

    // Resolve a commit to its tree; accept a tree id directly.
    let tree = match repo.read_object(&id).map_err(|e| e.to_string())? {
        Object::Commit(c) => match repo.read_object(&c.tree).map_err(|e| e.to_string())? {
            Object::Tree(t) => t,
            _ => return Err("ls-tree: commit tree is not a tree".into()),
        },
        Object::Tree(t) => t,
        other => {
            return Err(format!(
                "ls-tree: {} is not a tree or commit",
                other.object_type()
            ));
        }
    };

    for entry in &tree.entries {
        let kind = if entry.mode == puregit::object::tree::FileMode::Tree {
            "tree"
        } else {
            "blob"
        };
        // git pads the mode to six octal digits (e.g. 040000 for a subtree).
        println!(
            "{:0>6} {} {}\t{}",
            entry.mode.as_octal(),
            kind,
            entry.id,
            String::from_utf8_lossy(&entry.name)
        );
    }
    Ok(())
}

fn cmd_diff(_args: &[String]) -> Result<(), String> {
    use puregit::object::Object;
    let repo = open_here()?;
    let work = repo
        .work_tree()
        .ok_or("diff: bare repository has no work tree")?
        .to_path_buf();
    let index = repo.index().map_err(|e| e.to_string())?;

    for entry in &index.entries {
        if entry.stage != 0 {
            continue;
        }
        let path = String::from_utf8_lossy(&entry.path).into_owned();
        // An empty buffer represents a file deleted from the work tree.
        let wt = std::fs::read(work.join(&path)).unwrap_or_default();
        // The staged blob content.
        let staged = match repo.read_object(&entry.id).map_err(|e| e.to_string())? {
            Object::Blob(b) => b,
            _ => continue,
        };
        if wt == staged {
            continue;
        }
        let d = puregit::diff::unified(&staged, &wt, &format!("a/{path}"), &format!("b/{path}"), 3);
        print!("{d}");
    }
    Ok(())
}

fn cmd_diff_tree(args: &[String]) -> Result<(), String> {
    use puregit::object::Object;
    use puregit::walk::{TreeChange, diff_trees};
    if args.len() < 2 {
        return Err("diff-tree: usage: diff-tree <a> <b>".into());
    }
    let repo = open_here()?;

    // Resolve a commit/tree-ish argument to a tree id.
    let to_tree = |rev: &str| -> Result<ObjectId, String> {
        let id = repo
            .refs()
            .resolve(rev)
            .or_else(|_| ObjectId::from_hex(repo.algo(), rev).map_err(|e| e.to_string()))?;
        match repo.read_object(&id).map_err(|e| e.to_string())? {
            Object::Commit(c) => Ok(c.tree),
            Object::Tree(_) => Ok(id),
            other => Err(format!(
                "diff-tree: {} is not a tree or commit",
                other.object_type()
            )),
        }
    };
    let a = to_tree(&args[0])?;
    let b = to_tree(&args[1])?;

    for entry in diff_trees(repo.objects(), Some(&a), Some(&b)).map_err(|e| e.to_string())? {
        let tag = match entry.change {
            TreeChange::Added => 'A',
            TreeChange::Modified => 'M',
            TreeChange::Deleted => 'D',
        };
        println!("{tag}\t{}", String::from_utf8_lossy(&entry.path));
    }
    Ok(())
}

fn cmd_lfs(args: &[String]) -> Result<(), String> {
    use puregit::lfs::Pointer;
    let sub = args.first().map(String::as_str).unwrap_or("");
    let repo = open_here()?;
    match sub {
        "track" => {
            let pattern = args.get(1).ok_or("lfs track: missing <pattern>")?;
            repo.lfs_track(pattern).map_err(|e| e.to_string())?;
            println!("Tracking \"{pattern}\"");
            Ok(())
        }
        "ls-files" => {
            use puregit::odb::ObjectDatabase;
            let index = repo.index().map_err(|e| e.to_string())?;
            for entry in &index.entries {
                if entry.stage != 0 {
                    continue;
                }
                if let Ok((_, blob)) = repo.objects().read(&entry.id)
                    && let Ok(ptr) = Pointer::parse(&blob)
                {
                    println!(
                        "{} * {}",
                        &ptr.oid[..10],
                        String::from_utf8_lossy(&entry.path)
                    );
                }
            }
            Ok(())
        }
        "pull" => cmd_lfs_pull(&repo),
        other => Err(format!(
            "lfs: unknown subcommand '{other}' (try track|ls-files|pull)"
        )),
    }
}

#[cfg(feature = "http")]
fn cmd_lfs_pull(repo: &Repository) -> Result<(), String> {
    use puregit::lfs::batch::Operation;
    use puregit::lfs::transfer::LfsClient;

    let url = repo
        .config()
        .map_err(|e| e.to_string())?
        .get("remote", Some("origin"), "url")
        .map(String::from)
        .ok_or("lfs pull: no remote.origin.url configured")?;
    let client = LfsClient::new(LfsClient::endpoint_from_remote(&url));

    let n = repo
        .lfs_smudge_worktree(|p| {
            let results = client.batch(Operation::Download, std::slice::from_ref(p))?;
            let action = results
                .first()
                .and_then(|r| r.download.as_ref())
                .ok_or_else(|| puregit::Error::Protocol("lfs pull: no download action".into()))?;
            client.download(p, action)
        })
        .map_err(|e| e.to_string())?;
    println!("Downloaded {n} LFS object(s).");
    Ok(())
}

#[cfg(not(feature = "http"))]
fn cmd_lfs_pull(_repo: &Repository) -> Result<(), String> {
    Err("lfs pull: this build lacks the `http` feature".into())
}

fn cmd_merge(args: &[String]) -> Result<(), String> {
    use puregit::merge::MergeOutcome;
    let branch = args.first().ok_or("merge: missing <branch>")?;
    let repo = open_here()?;
    let their = repo
        .refs()
        .resolve(&format!("refs/heads/{branch}"))
        .or_else(|_| repo.refs().resolve(branch))
        .or_else(|_| ObjectId::from_hex(repo.algo(), branch).map_err(|e| e.to_string()))?;

    let who = signature_now(&repo)?;
    let msg = format!("Merge branch '{branch}'\n");
    match repo
        .merge(&their, who.clone(), who, msg.as_bytes())
        .map_err(|e| e.to_string())?
    {
        MergeOutcome::AlreadyUpToDate => println!("Already up to date."),
        MergeOutcome::FastForward(id) => println!("Fast-forward to {}", id.to_hex_short(8)),
        MergeOutcome::Merged(id) => println!(
            "Merge made by the 'three-way' strategy: {}",
            id.to_hex_short(8)
        ),
        MergeOutcome::Conflicts(paths) => {
            println!("Automatic merge failed; fix conflicts and then commit the result:");
            for p in paths {
                println!("\tboth modified: {}", String::from_utf8_lossy(&p));
            }
            return Err("merge conflicts".into());
        }
    }
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

/// `fsck` — verify object connectivity and integrity. Prints each missing or
/// malformed object and each dangling loose object, and exits non-zero if any
/// integrity problem (not merely dangling) was found.
fn cmd_fsck(_args: &[String]) -> Result<(), String> {
    let repo = open_here()?;
    let report = puregit::fsck::fsck(&repo).map_err(|e| e.to_string())?;

    for p in &report.problems {
        match &p.referenced_by {
            Some(parent) => println!("{} ({}, referenced by {parent})", p.message, p.id),
            None => println!("{} ({})", p.message, p.id),
        }
    }
    for id in &report.dangling {
        println!("dangling object {id}");
    }
    if report.is_ok() {
        eprintln!(
            "fsck: {} object(s) checked, no problems found",
            report.checked
        );
        Ok(())
    } else {
        Err(format!(
            "{} integrity problem(s) found",
            report.problems.len()
        ))
    }
}

/// `commit-graph write|verify` — write the `objects/info/commit-graph` cache
/// (covering all commits reachable from refs/HEAD) or parse-and-verify it.
fn cmd_commit_graph(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("write");
    let repo = open_here()?;
    match sub {
        "write" => {
            let n = repo.write_commit_graph().map_err(|e| e.to_string())?;
            eprintln!("commit-graph: wrote {n} commit(s)");
            Ok(())
        }
        "verify" => {
            let path = repo.git_dir().join("objects/info/commit-graph");
            let data = std::fs::read(&path).map_err(|e| format!("reading commit-graph: {e}"))?;
            let g = puregit::commit_graph::CommitGraph::parse(repo.algo(), &data)
                .map_err(|e| e.to_string())?;
            eprintln!("commit-graph: OK, {} commit(s)", g.len());
            Ok(())
        }
        other => Err(format!("commit-graph: unknown subcommand '{other}'")),
    }
}

/// `multi-pack-index write|verify` — write `objects/pack/multi-pack-index`
/// covering every `.idx`, or parse-and-verify it.
fn cmd_multi_pack_index(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("write");
    let repo = open_here()?;
    match sub {
        "write" => {
            let n = repo.write_multi_pack_index().map_err(|e| e.to_string())?;
            eprintln!("multi-pack-index: wrote an index over {n} pack(s)");
            Ok(())
        }
        "verify" => {
            let path = repo.git_dir().join("objects/pack/multi-pack-index");
            let data =
                std::fs::read(&path).map_err(|e| format!("reading multi-pack-index: {e}"))?;
            let m = puregit::multi_pack_index::MultiPackIndex::parse(repo.algo(), &data)
                .map_err(|e| e.to_string())?;
            eprintln!(
                "multi-pack-index: OK, {} object(s) over {} pack(s)",
                m.len(),
                m.pack_names().len()
            );
            Ok(())
        }
        other => Err(format!("multi-pack-index: unknown subcommand '{other}'")),
    }
}

fn cmd_prune(_args: &[String]) -> Result<(), String> {
    let mut repo = open_here()?;
    let n = repo.prune().map_err(|e| e.to_string())?;
    println!("Pruned {n} unreachable loose object(s).");
    Ok(())
}

/// `verify-pack <packfile>` — validate a pack against its `.idx`. The index path
/// is derived by swapping the `.pack` suffix for `.idx`. Runs in a repository so
/// bases of a thin pack can be resolved from the object store.
fn cmd_verify_pack(args: &[String]) -> Result<(), String> {
    let pack_path = args.first().ok_or("verify-pack: missing <packfile>")?;
    let idx_path = match pack_path.strip_suffix(".pack") {
        Some(stem) => format!("{stem}.idx"),
        None => format!("{pack_path}.idx"),
    };
    let pack = std::fs::read(pack_path).map_err(|e| format!("reading {pack_path}: {e}"))?;
    let idx = std::fs::read(&idx_path).map_err(|e| format!("reading {idx_path}: {e}"))?;

    use puregit::odb::ObjectDatabase;
    let repo = open_here()?;
    let resolver = |id: &ObjectId| repo.objects().read(id);
    let v = puregit::pack::verify_pack(&pack, &idx, repo.algo(), &resolver)
        .map_err(|e| e.to_string())?;

    for p in &v.problems {
        println!("{p}");
    }
    if v.is_ok() {
        eprintln!("verify-pack: {} object(s) ok", v.objects);
        Ok(())
    } else {
        Err(format!("{} problem(s) found", v.problems.len()))
    }
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
