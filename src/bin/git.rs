//! `git` — a thin command-line front end over the puregit library.
//!
//! This wires the plumbing/porcelain commands to the crate's public API so the
//! engine can be exercised end to end. Output formats, exit codes and the
//! wording of common errors follow real git (`tests/interop_cli*.rs` compares
//! the two side by side); unimplemented options are rejected as usage errors
//! rather than silently ignored.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use puregit::Repository;
use puregit::object::{Commit, FileMode, Object, ObjectType, Signature, Tag, Tree};
use puregit::odb::ObjectDatabase;
use puregit::oid::{HashAlgo, ObjectId};
use puregit::refs::Reference;

// ---------------------------------------------------------------------------
// Errors and exit codes
// ---------------------------------------------------------------------------

/// How a command failed, which decides the message prefix and the exit code
/// (git: 128 for a fatal error, 129 for a usage error).
#[derive(Debug)]
enum Fail {
    /// `fatal: <msg>`, exit 128.
    Fatal(String),
    /// A usage message printed verbatim, exit 129.
    Usage(String),
    /// A message printed verbatim (if non-empty) with an explicit exit code.
    Code(u8, String),
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Fatal(s)
    }
}

impl From<&str> for Fail {
    fn from(s: &str) -> Self {
        Fail::Fatal(s.to_string())
    }
}

impl From<puregit::Error> for Fail {
    fn from(e: puregit::Error) -> Self {
        Fail::Fatal(e.to_string())
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        Fail::Fatal(e.to_string())
    }
}

type CmdResult = Result<(), Fail>;

/// A usage error for `cmd` (git prints `usage: git <cmd> ...` and exits 129).
fn usage(cmd: &str, synopsis: &str) -> Fail {
    Fail::Usage(format!("usage: git {cmd} {synopsis}"))
}

/// An unknown option for `cmd`, in git's wording.
fn unknown_option(cmd: &str, opt: &str, synopsis: &str) -> Fail {
    let name = opt.trim_start_matches('-');
    let what = if opt.starts_with("--") {
        format!("error: unknown option `{name}'")
    } else {
        format!("error: unknown switch `{name}'")
    };
    Fail::Usage(format!("{what}\nusage: git {cmd} {synopsis}"))
}

/// Writes bytes to stdout (ignoring a closed pipe).
fn emit(bytes: &[u8]) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(bytes);
    let _ = out.flush();
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        println!("{USAGE}");
        // Bare `git` prints its usage and exits 1.
        return ExitCode::from(1);
    };

    // Meta commands short-circuit with their own exit codes.
    match command.as_str() {
        "--version" | "-v" | "version" => {
            println!("puregit version {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        "--help" | "-h" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        "help" => return cmd_help(&args[1..]),
        _ => {}
    }

    let rest = &args[1..];
    let result = match command.as_str() {
        "init" => cmd_init(rest),
        "hash-object" => cmd_hash_object(rest),
        "cat-file" => cmd_cat_file(rest),
        "rev-parse" => cmd_rev_parse(rest),
        "add" => cmd_add(rest),
        "rm" => cmd_rm(rest),
        "mv" => cmd_mv(rest),
        "write-tree" => cmd_write_tree(rest),
        "read-tree" => cmd_read_tree(rest),
        "mktree" => cmd_mktree(rest),
        "commit-tree" => cmd_commit_tree(rest),
        "commit" => cmd_commit(rest),
        "log" => cmd_log(rest),
        "reflog" => cmd_reflog(rest),
        "show" => cmd_show(rest),
        "status" => cmd_status(rest),
        "branch" => cmd_branch(rest),
        "checkout" => cmd_checkout(rest),
        "switch" => cmd_switch(rest),
        "reset" => cmd_reset(rest),
        "config" => cmd_config(rest),
        "ls-files" => cmd_ls_files(rest),
        "gc" | "repack" => cmd_gc(rest),
        "fsck" => cmd_fsck(rest),
        "prune" => cmd_prune(rest),
        "commit-graph" => cmd_commit_graph(rest),
        "multi-pack-index" => cmd_multi_pack_index(rest),
        "worktree" => cmd_worktree(rest),
        "merge-base" => cmd_merge_base(rest),
        "merge" => cmd_merge(rest),
        "lfs" => cmd_lfs(rest),
        "tag" => cmd_tag(rest),
        "ls-tree" => cmd_ls_tree(rest),
        "diff-tree" => cmd_diff_tree(rest),
        "diff" => cmd_diff(rest),
        "unpack-objects" => cmd_unpack_objects(rest),
        "verify-pack" => cmd_verify_pack(rest),
        "clone" => cmd_clone(rest),
        "completion" => cmd_completion(rest),
        other if other.starts_with('-') => {
            eprintln!("unknown option: {other}");
            eprintln!("{USAGE}");
            return ExitCode::from(129);
        }
        other => {
            eprintln!("git: '{other}' is not a git command. See 'git --help'.");
            // git returns 1 for an unknown command (distinct from a usage error).
            return ExitCode::from(1);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Fatal(msg)) => {
            eprintln!("fatal: {msg}");
            ExitCode::from(128)
        }
        Err(Fail::Usage(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(129)
        }
        Err(Fail::Code(code, msg)) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            ExitCode::from(code)
        }
    }
}

const USAGE: &str = "\
usage: git <command> [<args>]

commands:
    init [--bare] [-b <branch>] [--object-format=<fmt>] [<dir>]
                                create an empty repository
    hash-object [-w] [-t <type>] [--stdin] <file>...
                                compute an object id (and optionally store it)
    cat-file -t|-p|-s|-e <object>  show an object's type, contents, or size
    cat-file --batch[-check]    print type/size[/contents] for names on stdin
    rev-parse <rev>...          resolve revisions to object ids
    add <pathspec>...           stage working-tree files (or deletions)
    rm [--cached] <file>...     remove files from the index and work tree
    mv <source> <dest>          move/rename a tracked file
    write-tree                  write the index out as a tree, print its id
    read-tree <tree-ish>        load a tree into the index (replacing it)
    mktree                      read `ls-tree` lines from stdin, write a tree
    commit-tree <tree> [-p <parent>]... [-m <msg>]
                                create a commit object, print its id
    commit -m <msg>             commit the staged index
    log [<rev>] [-n <n>] [--oneline] [--format=<fmt>]
                                show commit history
    reflog [<ref>]              show the update log of a ref (default HEAD)
    show [<object>]             show a commit (with patch), tag, tree, or blob
    status [--porcelain]        show working-tree status
    branch [-d] [<name> [<start>]]  list, create, or delete branches
    checkout [-b <new>] <branch>|<commit>
                                switch branches or detach HEAD
    switch [-c <new>] <branch>  switch branches
    reset [--soft|--mixed|--hard] [<commit>]
                                move HEAD (and index/work tree) to a commit
    config <key> [<value>]      get or set a repository config value
    ls-files [-s]               list the files in the index
    gc                          pack loose objects and prune them
    fsck                        verify object connectivity and integrity
    prune                       delete unreachable loose objects
    commit-graph write|verify   write or verify the commit-graph cache
    multi-pack-index write|verify  write or verify the multi-pack-index
    worktree add <path> [<commit>] | list   manage linked worktrees
    merge-base <a> <b>          print the best common ancestor of two commits
    merge <branch>              merge a branch into the current branch
    lfs track <pattern>         track a path pattern with Git LFS
    lfs ls-files                list LFS-pointer files in the index
    lfs pull                    download LFS objects for the current checkout
    tag [-a] [-m <msg>] [-d] <name> [<commit>]
                                create, delete, or list tags
    ls-tree [-r] [-t] [-d] [--name-only] <tree-ish>
                                list the entries of a tree
    diff-tree [-r] [--name-only|--name-status] <a> <b>
                                compare two trees
    diff [--cached] [<commit> [<commit>]]
                                unified diff of the work tree, index, or commits
    unpack-objects [<pack>]     explode a packfile (default: stdin) into objects
    verify-pack <pack>          check a packfile against its .idx
    clone <url> [<dir>]         clone a repository (local path, file://, http(s), ssh)
    completion [bash]           print a shell completion script
    version                     print the puregit version";

/// Handles `git help [--man] [<command>]`.
///
/// `--man` writes a roff-formatted `git.1` man page to stdout (pipe it to a file
/// under a `man1/` directory to install it); `git help <command>` prints that
/// command's usage line from [`USAGE`]; bare `git help` prints the full usage.
fn cmd_help(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("--man") => {
            print!("{}", manpage());
            ExitCode::SUCCESS
        }
        Some(topic) => {
            // Print the usage line(s) whose command column names this topic.
            let mut printed = false;
            for line in USAGE.lines() {
                // `split_whitespace` already skips the leading indentation.
                if line.split_whitespace().next().is_some_and(|w| w == topic) {
                    println!("{}", line.trim_start());
                    printed = true;
                }
            }
            if !printed {
                eprintln!("No manual entry for git{topic}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        None => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
    }
}

/// Renders the `git.1` man page as roff.
///
/// Pure-Rust and dependency-free: the command table is derived from [`USAGE`], so
/// the page stays in sync with the implemented subcommands, and the EXIT STATUS
/// section documents the git-compatible codes `main` returns.
fn manpage() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let mut out = String::new();
    // Header: title, manual section 1, and the source/version footer.
    out.push_str(&format!(
        ".TH PUREGIT 1 \"\" \"puregit {version}\" \"puregit Manual\"\n"
    ));
    out.push_str(".SH NAME\n");
    out.push_str("puregit \\- pure-Rust git command-line front end\n");
    out.push_str(".SH SYNOPSIS\n");
    out.push_str(".B puregit\n");
    out.push_str(".I command\n");
    out.push_str("[\\fIargs\\fR]\n");
    out.push_str(".SH DESCRIPTION\n");
    out.push_str(
        "A minimal git command-line interface over the pure-Rust puregit library. \
It maintains repositories and clones, fetches, and pushes over HTTP and SSH \
without any C toolchain.\n",
    );
    out.push_str(".SH COMMANDS\n");
    // Each usage line becomes a tagged paragraph: the command column is the tag,
    // the rest is the description.
    for line in USAGE.lines() {
        let trimmed = line.trim_start();
        // Skip the header, the "commands:" label, and blank lines.
        if trimmed.is_empty() || trimmed.starts_with("usage:") || trimmed == "commands:" {
            continue;
        }
        // A continuation line (a wrapped synopsis) has no command column.
        if !line.starts_with("    ") || line.starts_with("     ") {
            continue;
        }
        // Split the synopsis (the command column) from its description at the
        // first run of two or more spaces, so only the synopsis is bold.
        let (synopsis, description) = match trimmed.find("  ") {
            Some(i) => (trimmed[..i].trim_end(), trimmed[i..].trim_start()),
            None => (trimmed, ""),
        };
        out.push_str(".TP\n.B ");
        out.push_str(&roff_escape(synopsis));
        out.push('\n');
        if !description.is_empty() {
            out.push_str(&roff_escape(description));
            out.push('\n');
        }
    }
    out.push_str(".SH EXIT STATUS\n");
    out.push_str(".TP\n.B 0\nSuccess.\n");
    out.push_str(
        ".TP\n.B 1\nA controlled negative result \\(em \
\\fBdiff \\-\\-exit\\-code\\fR found changes, or \
\\fBmerge\\-base \\-\\-is\\-ancestor\\fR was false \\(em or an unknown command.\n",
    );
    out.push_str(".TP\n.B 128\nA fatal error (the operation could not be performed).\n");
    out.push_str(".TP\n.B 129\nA usage error (invalid arguments).\n");
    out.push_str(".SH SEE ALSO\n");
    out.push_str(".BR git (1)\n");
    out
}

/// Escapes a string for a roff line: backslashes (roff's escape introducer) are
/// doubled and a leading control character (`.`/`'`) is neutralised so the text
/// is never taken for a request.
fn roff_escape(s: &str) -> String {
    let mut out = s.replace('\\', "\\\\");
    if out.starts_with('.') || out.starts_with('\'') {
        out.insert_str(0, "\\&");
    }
    out
}

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
    "switch",
    "reset",
    "config",
    "ls-files",
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
fn cmd_completion(args: &[String]) -> CmdResult {
    let shell = args.first().map(String::as_str).unwrap_or("bash");
    if shell != "bash" {
        return Err(format!("completion: unsupported shell '{shell}' (try 'bash')").into());
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

// ---------------------------------------------------------------------------
// Repository discovery and small helpers
// ---------------------------------------------------------------------------

/// Opens the repository containing the current directory (searching upward).
fn open_here() -> Result<Repository, Fail> {
    let cwd = std::env::current_dir()?;
    Repository::open(&cwd).map_err(|_| {
        Fail::Fatal("not a git repository (or any of the parent directories): .git".into())
    })
}

/// The work tree, or a fatal error in a bare repository.
fn work_tree(repo: &Repository, what: &str) -> Result<PathBuf, Fail> {
    repo.work_tree().map(Path::to_path_buf).ok_or_else(|| {
        Fail::Fatal(format!(
            "this operation must be run in a work tree ({what})"
        ))
    })
}

/// Reads an object's raw `(type, payload)`.
fn read_raw(repo: &Repository, id: &ObjectId) -> puregit::Result<(ObjectType, Vec<u8>)> {
    repo.objects().read(id)
}

/// Reads and parses a commit.
fn read_commit(repo: &Repository, id: &ObjectId) -> Result<Commit, Fail> {
    match repo.read_object(id)? {
        Object::Commit(c) => Ok(c),
        other => Err(Fail::Fatal(format!(
            "object {id} is a {}, not a commit",
            other.object_type()
        ))),
    }
}

/// The current branch's full ref name, if `HEAD` is symbolic.
fn head_branch(repo: &Repository) -> Option<String> {
    match repo.refs().lookup("HEAD") {
        Ok(Reference::Symbolic(t)) => Some(t),
        _ => None,
    }
}

/// git's `core.quotePath` C-style quoting: a path containing control
/// characters, `"`, `\`, or non-ASCII bytes is wrapped in double quotes with
/// those bytes escaped (octal for non-ASCII). Anything else is printed as is.
fn quote_path(p: &[u8]) -> String {
    let needs = p
        .iter()
        .any(|&b| b < 0x20 || b == b'"' || b == b'\\' || b >= 0x7f);
    if !needs {
        return String::from_utf8_lossy(p).into_owned();
    }
    let mut s = String::from("\"");
    for &b in p {
        match b {
            0x07 => s.push_str("\\a"),
            0x08 => s.push_str("\\b"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            0x0b => s.push_str("\\v"),
            0x0c => s.push_str("\\f"),
            b'\r' => s.push_str("\\r"),
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\{b:03o}")),
        }
    }
    s.push('"');
    s
}

/// `quote_path` that also quotes a path containing a space (what `status`
/// short/porcelain output does).
fn quote_path_sp(p: &[u8]) -> String {
    if p.contains(&b' ')
        && !p
            .iter()
            .any(|&b| b < 0x20 || b == b'"' || b == b'\\' || b >= 0x7f)
    {
        return format!("\"{}\"", String::from_utf8_lossy(p));
    }
    quote_path(p)
}

/// `quote_path` for `<prefix><path>` (diff headers quote the whole label).
fn quote_prefixed(prefix: &str, p: &[u8]) -> String {
    let mut full = prefix.as_bytes().to_vec();
    full.extend_from_slice(p);
    quote_path(&full)
}

/// A tree entry's numeric git mode.
fn mode_num(mode: FileMode) -> u32 {
    match mode {
        FileMode::Tree => 0o040000,
        FileMode::Regular => 0o100644,
        FileMode::Executable => 0o100755,
        FileMode::Symlink => 0o120000,
        FileMode::Gitlink => 0o160000,
    }
}

/// The `ls-tree` object type column for a mode.
fn mode_kind(mode: FileMode) -> &'static str {
    match mode {
        FileMode::Tree => "tree",
        FileMode::Gitlink => "commit",
        _ => "blob",
    }
}

// ---------------------------------------------------------------------------
// Object enumeration and abbreviation
// ---------------------------------------------------------------------------

/// Every object id in the repository (loose and packed), sorted.
fn all_object_ids(repo: &Repository) -> Vec<ObjectId> {
    let mut ids: BTreeSet<ObjectId> = repo
        .loose_object_ids()
        .unwrap_or_default()
        .into_iter()
        .collect();
    if let Ok(rd) = std::fs::read_dir(repo.git_dir().join("objects").join("pack")) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("idx") {
                continue;
            }
            if let Ok(data) = std::fs::read(&p)
                && let Ok(idx) = puregit::pack::PackIndex::parse(repo.algo(), &data)
            {
                for row in 0..idx.len() {
                    if let Some(id) = idx.id_at(row) {
                        ids.insert(id);
                    }
                }
            }
        }
    }
    ids.into_iter().collect()
}

thread_local! {
    static ALL_HEX: std::cell::OnceCell<Vec<String>> = const { std::cell::OnceCell::new() };
}

/// The shortest unique abbreviation of `id`, at least `min` hex digits (git's
/// default is 7).
fn abbrev_len(repo: &Repository, id: &ObjectId, min: usize) -> String {
    let hex = id.to_hex();
    let min = min.clamp(4, hex.len());
    ALL_HEX.with(|cell| {
        let all = cell.get_or_init(|| all_object_ids(repo).iter().map(|i| i.to_hex()).collect());
        let mut len = min;
        while len < hex.len() {
            let prefix = &hex[..len];
            if !all.iter().any(|h| h != &hex && h.starts_with(prefix)) {
                break;
            }
            len += 1;
        }
        hex[..len].to_string()
    })
}

fn abbrev(repo: &Repository, id: &ObjectId) -> String {
    abbrev_len(repo, id, 7)
}

// ---------------------------------------------------------------------------
// Revision parsing
// ---------------------------------------------------------------------------

/// Why a revision did not resolve.
#[derive(Debug)]
enum RevErr {
    /// Not a valid name for any object.
    Unknown,
    /// `<rev>:<path>` where the path is not in the tree.
    PathNotInTree { path: String, rev: String },
    /// `:<path>` where the path is not in the index.
    PathNotInIndex(String),
    /// A short hex prefix matching several objects.
    Ambiguous(String),
}

impl RevErr {
    /// The fatal message git prints for `spec` failing in a context that wants
    /// a single object (cat-file, ls-tree, merge-base, ...).
    fn object_message(&self, spec: &str) -> String {
        match self {
            RevErr::PathNotInTree { path, rev } => {
                format!("path '{path}' does not exist in '{rev}'")
            }
            RevErr::PathNotInIndex(path) => {
                format!("path '{path}' does not exist (neither on disk nor in the index)")
            }
            RevErr::Ambiguous(p) => format!("short object ID {p} is ambiguous"),
            RevErr::Unknown => format!("Not a valid object name {spec}"),
        }
    }

    /// The fatal message for a revision argument (log, show, rev-parse, reset).
    fn rev_message(&self, spec: &str) -> String {
        match self {
            RevErr::Unknown => format!(
                "ambiguous argument '{spec}': unknown revision or path not in the working tree.\n\
                 Use '--' to separate paths from revisions, like this:\n\
                 'git <command> [<revision>...] -- [<file>...]'"
            ),
            other => other.object_message(spec),
        }
    }
}

/// Whether `s` is plausible as (part of) a ref name we may look up on disk.
fn safe_ref_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.contains("..")
        && !s.contains('\\')
        && !s.contains("//")
        && s.bytes().all(|b| b > 0x20 && b != 0x7f && b != b':')
}

/// git's ref DWIM: the full ref name and id that `name` refers to.
fn dwim_ref(repo: &Repository, name: &str) -> Option<(String, ObjectId)> {
    if !safe_ref_name(name) {
        return None;
    }
    let mut candidates = Vec::new();
    if name == "HEAD"
        || name.starts_with("refs/")
        || name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
    {
        candidates.push(name.to_string());
    }
    for rule in ["refs/", "refs/tags/", "refs/heads/", "refs/remotes/"] {
        candidates.push(format!("{rule}{name}"));
    }
    candidates.push(format!("refs/remotes/{name}/HEAD"));
    for c in candidates {
        if c != "HEAD" && !puregit::refs::is_valid_ref_name(&c) {
            continue;
        }
        if let Ok(id) = repo.refs().resolve(&c) {
            return Some((c, id));
        }
    }
    None
}

/// Like [`dwim_ref`] but returns the ref name even when it is an unborn symref
/// target (used for `--symbolic-full-name`).
fn dwim_ref_name(repo: &Repository, name: &str) -> Option<String> {
    dwim_ref(repo, name).map(|(n, _)| n)
}

/// Resolves the base of a revision (before any `~`/`^` suffix).
fn resolve_base(repo: &Repository, base: &str) -> Result<ObjectId, RevErr> {
    let algo = repo.algo();
    // `<ref>@{<n>}`: the n-th prior value from the ref's reflog.
    if let Some(at) = base.find("@{")
        && base.ends_with('}')
    {
        let name = &base[..at];
        let sel = &base[at + 2..base.len() - 1];
        let n: usize = sel.parse().map_err(|_| RevErr::Unknown)?;
        let refname = match name {
            "" => head_branch(repo).unwrap_or_else(|| "HEAD".into()),
            "HEAD" | "@" => "HEAD".into(),
            other => dwim_ref(repo, other).ok_or(RevErr::Unknown)?.0,
        };
        if !safe_ref_name(&refname) {
            return Err(RevErr::Unknown);
        }
        let log = std::fs::read_to_string(repo.git_dir().join("logs").join(&refname))
            .map_err(|_| RevErr::Unknown)?;
        let lines: Vec<&str> = log.lines().filter(|l| !l.is_empty()).collect();
        let line = lines
            .len()
            .checked_sub(n + 1)
            .and_then(|i| lines.get(i))
            .ok_or(RevErr::Unknown)?;
        let new = line.split(' ').nth(1).ok_or(RevErr::Unknown)?;
        return ObjectId::from_hex(algo, new).map_err(|_| RevErr::Unknown);
    }
    let base = if base == "@" { "HEAD" } else { base };
    let is_hex = !base.is_empty() && base.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex
        && base.len() == algo.hex_len()
        && let Ok(id) = ObjectId::from_hex(algo, &base.to_ascii_lowercase())
    {
        return Ok(id);
    }
    if let Some((_, id)) = dwim_ref(repo, base) {
        return Ok(id);
    }
    if is_hex && base.len() >= 4 && base.len() < algo.hex_len() {
        let prefix = base.to_ascii_lowercase();
        let matches: Vec<ObjectId> = all_object_ids(repo)
            .into_iter()
            .filter(|id| id.to_hex().starts_with(&prefix))
            .collect();
        return match matches.len() {
            1 => Ok(matches[0]),
            0 => Err(RevErr::Unknown),
            _ => Err(RevErr::Ambiguous(base.to_string())),
        };
    }
    Err(RevErr::Unknown)
}

/// Peels `id` until it is an object of type `want` (tags are dereferenced,
/// commits yield their tree), or fails.
fn peel_to(repo: &Repository, mut id: ObjectId, want: ObjectType) -> Result<ObjectId, RevErr> {
    loop {
        let obj = repo.read_object(&id).map_err(|_| RevErr::Unknown)?;
        if obj.object_type() == want {
            return Ok(id);
        }
        match obj {
            Object::Tag(t) => id = t.object,
            Object::Commit(c) if want == ObjectType::Tree => return Ok(c.tree),
            _ => return Err(RevErr::Unknown),
        }
    }
}

/// Dereferences tags until a non-tag object.
fn peel_tags(repo: &Repository, mut id: ObjectId) -> Result<ObjectId, RevErr> {
    loop {
        match repo.read_object(&id).map_err(|_| RevErr::Unknown)? {
            Object::Tag(t) => id = t.object,
            _ => return Ok(id),
        }
    }
}

/// Looks up `path` (slash-separated) inside the tree `tree`.
fn tree_lookup(repo: &Repository, tree: ObjectId, path: &str) -> Option<(FileMode, ObjectId)> {
    let mut cur = (FileMode::Tree, tree);
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        if cur.0 != FileMode::Tree {
            return None;
        }
        let t = match repo.read_object(&cur.1).ok()? {
            Object::Tree(t) => t,
            _ => return None,
        };
        let e = t.get(comp.as_bytes())?;
        cur = (e.mode, e.id);
    }
    Some(cur)
}

/// Resolves a git revision expression to an object id: full or abbreviated
/// hex, ref names (with git's DWIM rules), `@`, `<ref>@{n}`, the `~<n>`,
/// `^<n>`, `^{<type>}` and `^{}` suffixes, `<rev>:<path>` and `:[<n>:]<path>`.
fn resolve(repo: &Repository, spec: &str) -> Result<ObjectId, RevErr> {
    if let Some(rest) = spec.strip_prefix(':') {
        let (stage, path) = match rest.split_once(':') {
            Some((n, p)) if n.len() == 1 && n.as_bytes()[0].is_ascii_digit() => {
                (n.as_bytes()[0] - b'0', p)
            }
            _ => (0, rest),
        };
        let index = repo.index().map_err(|_| RevErr::Unknown)?;
        return index
            .entries
            .iter()
            .find(|e| e.stage == stage && e.path == path.as_bytes())
            .map(|e| e.id)
            .ok_or_else(|| RevErr::PathNotInIndex(path.to_string()));
    }
    if let Some((rev, path)) = spec.split_once(':') {
        let id = resolve(repo, rev)?;
        let tree = peel_to(repo, id, ObjectType::Tree)?;
        return tree_lookup(repo, tree, path)
            .map(|(_, id)| id)
            .ok_or_else(|| RevErr::PathNotInTree {
                path: path.to_string(),
                rev: rev.to_string(),
            });
    }
    // Split the base name from the navigation suffixes.
    let base_end = spec.find(['^', '~']).unwrap_or(spec.len());
    let mut id = resolve_base(repo, &spec[..base_end])?;
    let mut rest = &spec[base_end..];
    let digits = |s: &str| s.bytes().take_while(u8::is_ascii_digit).count();
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix("^{") {
            let close = r.find('}').ok_or(RevErr::Unknown)?;
            id = match &r[..close] {
                "" => peel_tags(repo, id)?,
                "object" => id,
                "commit" => peel_to(repo, id, ObjectType::Commit)?,
                "tree" => peel_to(repo, id, ObjectType::Tree)?,
                "blob" => peel_to(repo, id, ObjectType::Blob)?,
                "tag" => peel_to(repo, id, ObjectType::Tag)?,
                _ => return Err(RevErr::Unknown),
            };
            rest = &r[close + 1..];
        } else if let Some(r) = rest.strip_prefix('^') {
            let n_len = digits(r);
            let n: usize = if n_len == 0 {
                1
            } else {
                r[..n_len].parse().map_err(|_| RevErr::Unknown)?
            };
            let cid = peel_to(repo, id, ObjectType::Commit)?;
            id = if n == 0 {
                cid
            } else {
                let c = read_commit(repo, &cid).map_err(|_| RevErr::Unknown)?;
                *c.parents.get(n - 1).ok_or(RevErr::Unknown)?
            };
            rest = &r[n_len..];
        } else if let Some(r) = rest.strip_prefix('~') {
            let n_len = digits(r);
            let n: usize = if n_len == 0 {
                1
            } else {
                r[..n_len].parse().map_err(|_| RevErr::Unknown)?
            };
            id = peel_to(repo, id, ObjectType::Commit)?;
            for _ in 0..n {
                let c = read_commit(repo, &id).map_err(|_| RevErr::Unknown)?;
                id = *c.parents.first().ok_or(RevErr::Unknown)?;
            }
            rest = &r[n_len..];
        } else {
            return Err(RevErr::Unknown);
        }
    }
    Ok(id)
}

/// Resolves `spec` for a command that needs an existing object.
fn resolve_object(repo: &Repository, spec: &str) -> Result<ObjectId, Fail> {
    let id = resolve(repo, spec).map_err(|e| Fail::Fatal(e.object_message(spec)))?;
    if !repo.objects().contains(&id) {
        return Err(Fail::Fatal(RevErr::Unknown.object_message(spec)));
    }
    Ok(id)
}

/// Resolves `spec` as a revision argument (git's "ambiguous argument" error).
fn resolve_rev(repo: &Repository, spec: &str) -> Result<ObjectId, Fail> {
    resolve(repo, spec).map_err(|e| Fail::Fatal(e.rev_message(spec)))
}

/// Resolves `spec` to a commit id (peeling tags).
fn resolve_commit(repo: &Repository, spec: &str) -> Result<ObjectId, Fail> {
    let id = resolve_rev(repo, spec)?;
    peel_to(repo, id, ObjectType::Commit).map_err(|_| Fail::Fatal(format!("{spec}: not a commit")))
}

/// Resolves `spec` to a tree id (peeling tags and commits).
fn resolve_tree(repo: &Repository, spec: &str) -> Result<ObjectId, Fail> {
    let id = resolve_object(repo, spec)?;
    peel_to(repo, id, ObjectType::Tree).map_err(|_| Fail::Fatal("not a tree object".into()))
}

// ---------------------------------------------------------------------------
// Identities and dates
// ---------------------------------------------------------------------------

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date for a day count since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parses a `+hhmm`/`-hhmm` offset into seconds east of UTC.
fn tz_offset(tz: &[u8]) -> i64 {
    let s = std::str::from_utf8(tz).unwrap_or("+0000");
    let (sign, digits) = match s.as_bytes().first() {
        Some(b'-') => (-1, &s[1..]),
        Some(b'+') => (1, &s[1..]),
        _ => (1, s),
    };
    let n: i64 = digits.parse().unwrap_or(0);
    sign * ((n / 100) * 3600 + (n % 100) * 60)
}

/// Splits `time` (UTC seconds) shifted into `tz` into calendar fields:
/// (year, month, day, hour, minute, second, weekday with Sunday = 0).
fn local_fields(time: i64, tz: &[u8]) -> (i64, u32, u32, u32, u32, u32, u32) {
    let t = time + tz_offset(tz);
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let wd = (days + 4).rem_euclid(7) as u32;
    (
        y,
        m,
        d,
        (secs / 3600) as u32,
        ((secs % 3600) / 60) as u32,
        (secs % 60) as u32,
        wd,
    )
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// git's default date format: `Tue Nov 14 22:13:20 2023 +0000`.
fn fmt_date(sig: &Signature) -> String {
    let (y, mo, d, h, mi, s, wd) = local_fields(sig.time, &sig.tz);
    format!(
        "{} {} {d} {h:02}:{mi:02}:{s:02} {y} {}",
        WEEKDAYS[wd as usize],
        MONTHS[(mo - 1) as usize],
        String::from_utf8_lossy(&sig.tz)
    )
}

/// git's ISO-like date format: `2023-11-14 22:13:20 +0000`.
fn fmt_date_iso(sig: &Signature) -> String {
    let (y, mo, d, h, mi, s, _) = local_fields(sig.time, &sig.tz);
    format!(
        "{y}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} {}",
        String::from_utf8_lossy(&sig.tz)
    )
}

/// Parses a `GIT_*_DATE` value: git's raw `<seconds> <tz>` (optionally with a
/// leading `@`) or ISO 8601 `YYYY-MM-DD[T ]HH:MM:SS [<tz>]`.
fn parse_date(s: &str) -> Option<(i64, Vec<u8>)> {
    let s = s.trim();
    let valid_tz = |tz: &str| {
        tz.len() == 5
            && matches!(tz.as_bytes()[0], b'+' | b'-')
            && tz[1..].bytes().all(|b| b.is_ascii_digit())
    };
    let raw = s.strip_prefix('@').unwrap_or(s);
    let mut parts = raw.split_whitespace();
    if let Some(secs) = parts.next()
        && let Ok(secs) = secs.parse::<i64>()
    {
        let tz = parts.next().unwrap_or("+0000");
        if parts.next().is_none() && valid_tz(tz) {
            return Some((secs, tz.as_bytes().to_vec()));
        }
        return None;
    }
    // ISO 8601.
    let (date, rest) = s.split_at(s.find(['T', ' '])?);
    let rest = rest[1..].trim();
    let (time, tz) = match rest.split_once(' ') {
        Some((t, z)) => (t, z.trim()),
        None => (rest, "+0000"),
    };
    let tz = if tz == "Z" { "+0000" } else { tz };
    if !valid_tz(tz) {
        return None;
    }
    let mut dp = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, mo, d) = (dp.next()??, dp.next()??, dp.next()??);
    let mut tp = time.split(':').map(|p| p.parse::<i64>().ok());
    let (h, mi) = (tp.next()??, tp.next()??);
    let sec = tp.next().flatten().unwrap_or(0);
    let local = days_from_civil(y, mo as u32, d as u32) * 86_400 + h * 3600 + mi * 60 + sec;
    Some((local - tz_offset(tz.as_bytes()), tz.as_bytes().to_vec()))
}

/// Builds the author (`role = "AUTHOR"`) or committer (`"COMMITTER"`) identity
/// the way git does: `GIT_<role>_NAME`/`_EMAIL`/`_DATE` from the environment
/// win, then `user.name`/`user.email` from config; the date defaults to now.
fn ident(repo: &Repository, role: &str) -> Result<Signature, Fail> {
    let cfg = repo.config()?;
    let name = std::env::var(format!("GIT_{role}_NAME"))
        .ok()
        .or_else(|| cfg.get("user", None, "name").map(String::from))
        .unwrap_or_else(|| "puregit".into());
    let email = std::env::var(format!("GIT_{role}_EMAIL"))
        .ok()
        .or_else(|| cfg.get("user", None, "email").map(String::from))
        .unwrap_or_else(|| "puregit@localhost".into());
    let (time, tz) = match std::env::var(format!("GIT_{role}_DATE")) {
        Ok(v) if !v.is_empty() => {
            parse_date(&v).ok_or_else(|| Fail::Fatal(format!("invalid date format: {v}")))?
        }
        _ => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            (now, b"+0000".to_vec())
        }
    };
    Ok(Signature {
        name: name.into_bytes(),
        email: email.into_bytes(),
        time,
        tz,
    })
}

/// git's commit-message cleanup for `-m`: paragraphs joined by a blank line,
/// trailing whitespace stripped, surrounding blank lines dropped, one final LF.
fn clean_message(paragraphs: &[String]) -> Vec<u8> {
    let joined = paragraphs.join("\n\n");
    let mut lines: Vec<&str> = joined.lines().map(str::trim_end).collect();
    // Collapse runs of blank lines and trim leading/trailing ones.
    let mut out: Vec<&str> = Vec::new();
    for l in lines.drain(..) {
        if l.is_empty() && out.last().is_none_or(|p: &&str| p.is_empty()) {
            continue;
        }
        out.push(l);
    }
    while out.last() == Some(&"") {
        out.pop();
    }
    let mut s = out.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    s.into_bytes()
}

// ---------------------------------------------------------------------------
// init / clone
// ---------------------------------------------------------------------------

fn cmd_init(args: &[String]) -> CmdResult {
    const SYN: &str = "init [-q | --quiet] [--bare] [--object-format=<format>] [-b <branch-name> | --initial-branch=<branch-name>] [<directory>]";
    let mut quiet = false;
    let mut bare = false;
    let mut algo = HashAlgo::Sha1;
    let mut branch: Option<String> = None;
    let mut dir: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-q" | "--quiet" => quiet = true,
            "--bare" => bare = true,
            "-b" | "--initial-branch" => {
                i += 1;
                branch = Some(args.get(i).ok_or_else(|| usage("init", SYN))?.clone());
            }
            _ if a.starts_with("--initial-branch=") => {
                branch = Some(a["--initial-branch=".len()..].to_string());
            }
            _ if a.starts_with("--object-format=") => {
                algo = match &a["--object-format=".len()..] {
                    "sha1" => HashAlgo::Sha1,
                    "sha256" => HashAlgo::Sha256,
                    other => return Err(format!("unknown hash algorithm '{other}'").into()),
                };
            }
            _ if a.starts_with('-') => return Err(unknown_option("init", a, SYN)),
            _ => {
                if dir.is_some() {
                    return Err(usage("init", SYN));
                }
                dir = Some(a.to_string());
            }
        }
        i += 1;
    }
    let cwd = std::env::current_dir()?;
    let target = match &dir {
        Some(d) => cwd.join(d),
        None => cwd.clone(),
    };
    let git_dir = if bare {
        target.clone()
    } else {
        target.join(".git")
    };
    let shown = format!("{}{}", git_dir.display(), std::path::MAIN_SEPARATOR);

    if git_dir.join("HEAD").is_file() {
        if !quiet {
            println!("Reinitialized existing Git repository in {shown}");
        }
        return Ok(());
    }
    if let Some(b) = &branch
        && !puregit::refs::is_valid_ref_name(&format!("refs/heads/{b}"))
    {
        return Err(format!("invalid initial branch name: '{b}'").into());
    }
    if bare {
        init_bare(&target, algo)?;
    } else {
        Repository::init_with(&target, algo)?;
    }
    let b = branch.unwrap_or_else(|| "main".into());
    std::fs::write(git_dir.join("HEAD"), format!("ref: refs/heads/{b}\n"))?;
    if !quiet {
        println!("Initialized empty Git repository in {shown}");
    }
    Ok(())
}

/// Creates a bare repository layout at `dir`.
fn init_bare(dir: &Path, algo: HashAlgo) -> CmdResult {
    for sub in ["objects/pack", "objects/info", "refs/heads", "refs/tags"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    let mut cfg = puregit::config::Config::new();
    let version = if algo == HashAlgo::Sha256 { "1" } else { "0" };
    cfg.set("core", None, "repositoryformatversion", version);
    cfg.set("core", None, "filemode", "true");
    cfg.set("core", None, "bare", "true");
    if algo == HashAlgo::Sha256 {
        cfg.set("extensions", None, "objectformat", "sha256");
    }
    std::fs::write(dir.join("config"), cfg.serialize())?;
    std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n")?;
    Ok(())
}

fn cmd_clone(args: &[String]) -> CmdResult {
    const SYN: &str = "clone [<options>] [--] <repo> [<dir>]";
    let mut quiet = false;
    let mut bare = false;
    let mut positional = Vec::new();
    for a in args {
        match a.as_str() {
            "-q" | "--quiet" => quiet = true,
            "--bare" => bare = true,
            "--" => {}
            s if s.starts_with('-') => return Err(unknown_option("clone", s, SYN)),
            s => positional.push(s.to_string()),
        }
    }
    let url = positional.first().ok_or_else(|| {
        Fail::Usage(format!(
            "fatal: You must specify a repository to clone.\n\nusage: git {SYN}"
        ))
    })?;
    let dir = match positional.get(1) {
        Some(d) => d.clone(),
        None => {
            let name = dir_from_url(url);
            if bare { format!("{name}.git") } else { name }
        }
    };

    if let Some(path) = local_clone_source(url) {
        return clone_local(url, &path, &dir, bare, quiet);
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return clone_http(url, &dir);
    }
    if url.starts_with("ssh://") || is_scp_like(url) {
        return clone_ssh(url, &dir);
    }
    Err(format!("repository '{url}' does not exist").into())
}

/// The local repository path a clone URL names (`file://` or a plain path to
/// an existing repository), if any.
fn local_clone_source(url: &str) -> Option<PathBuf> {
    let path = match url.strip_prefix("file://") {
        Some(rest) => {
            // `file:///C:/x` on Windows: drop the slash before the drive letter.
            let b = rest.as_bytes();
            if cfg!(windows) && b.len() > 2 && b[0] == b'/' && b[2] == b':' {
                PathBuf::from(&rest[1..])
            } else {
                PathBuf::from(rest)
            }
        }
        None => PathBuf::from(url),
    };
    if path.join(".git").is_dir() || (path.join("HEAD").is_file() && path.join("objects").is_dir())
    {
        Some(path)
    } else {
        None
    }
}

/// Copies every file under `src` into `dst` (creating directories).
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        let ty = e.file_type()?;
        if ty.is_dir() {
            copy_tree(&e.path(), &to)?;
        } else if ty.is_file() {
            std::fs::copy(e.path(), &to)?;
        }
    }
    Ok(())
}

/// Clones a repository on the local filesystem: copies the object store,
/// maps the source's branches to `refs/remotes/origin/*` (or mirrors them for
/// `--bare`), copies tags, records the origin, and checks out the source's
/// current branch.
fn clone_local(url: &str, src: &Path, dir: &str, bare: bool, quiet: bool) -> CmdResult {
    let source = Repository::open(src)
        .map_err(|_| Fail::Fatal(format!("repository '{url}' does not exist")))?;
    let dest = std::env::current_dir()?.join(dir);
    if dest.exists()
        && std::fs::read_dir(&dest)
            .map(|mut d| d.next().is_some())
            .unwrap_or(true)
    {
        return Err(format!(
            "destination path '{dir}' already exists and is not an empty directory."
        )
        .into());
    }
    if !quiet {
        eprintln!(
            "Cloning into {}'{dir}'...",
            if bare { "bare repository " } else { "" }
        );
    }
    let git_dir = if bare {
        init_bare(&dest, source.algo())?;
        dest.clone()
    } else {
        Repository::init_with(&dest, source.algo())?;
        dest.join(".git")
    };
    copy_tree(&source.git_dir().join("objects"), &git_dir.join("objects"))?;
    let repo = Repository::open(&dest)?;

    let src_head = match source.refs().lookup("HEAD") {
        Ok(Reference::Symbolic(t)) => Some(t),
        _ => None,
    };
    let refs = source.refs().list()?;
    for (name, id) in &refs {
        let target = if let Some(b) = name.strip_prefix("refs/heads/") {
            if bare {
                name.clone()
            } else {
                format!("refs/remotes/origin/{b}")
            }
        } else if name.starts_with("refs/tags/") {
            name.clone()
        } else {
            continue;
        };
        repo.refs().update(&target, &Reference::Direct(*id))?;
    }

    // Like git, record a plain local path as an absolute path. Git for
    // Windows keeps the platform's `\` separators here.
    let stored_url = if url.starts_with("file://") {
        url.to_string()
    } else {
        std::env::current_dir()?.join(src).display().to_string()
    };
    let mut cfg = repo.config()?;
    cfg.set("remote", Some("origin"), "url", &stored_url);
    if !bare {
        cfg.set(
            "remote",
            Some("origin"),
            "fetch",
            "+refs/heads/*:refs/remotes/origin/*",
        );
    }
    let branch = src_head
        .as_deref()
        .and_then(|h| h.strip_prefix("refs/heads/"))
        .filter(|b| refs.contains_key(&format!("refs/heads/{b}")))
        .map(String::from);
    if let Some(b) = &branch {
        std::fs::write(git_dir.join("HEAD"), format!("ref: refs/heads/{b}\n"))?;
        if !bare {
            cfg.set("branch", Some(b), "remote", "origin");
            cfg.set("branch", Some(b), "merge", &format!("refs/heads/{b}"));
            repo.refs().update(
                "refs/remotes/origin/HEAD",
                &Reference::Symbolic(format!("refs/remotes/origin/{b}")),
            )?;
        }
    }
    repo.write_config(&cfg)?;

    if let Some(b) = &branch
        && !bare
    {
        let id = refs[&format!("refs/heads/{b}")];
        repo.refs()
            .update(&format!("refs/heads/{b}"), &Reference::Direct(id))?;
        let commit = read_commit(&repo, &id)?;
        puregit::worktree::checkout_tree(&repo, &commit.tree, &dest)?;
        repo.read_tree(&commit.tree)?;
    }
    Ok(())
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
fn clone_ssh(url: &str, dir: &str) -> CmdResult {
    use puregit::transport::ssh::SshTransport;
    let mut transport = SshTransport::from_url(url, HashAlgo::Sha1)?;
    if let Ok(pw) = std::env::var("GIT_SSH_PASSWORD") {
        transport = transport.with_password(pw);
    } else if let Ok(key) = std::env::var("GIT_SSH_KEY") {
        transport = transport.with_key(key, std::env::var("GIT_SSH_KEY_PASSPHRASE").ok());
    }
    let repo = puregit::client::clone(dir, &mut transport)?;
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
fn write_origin_config(repo: &Repository, url: &str) -> CmdResult {
    let mut cfg = repo.config()?;
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
    repo.write_config(&cfg)?;
    Ok(())
}

#[cfg(not(feature = "ssh"))]
fn clone_ssh(_url: &str, _dir: &str) -> CmdResult {
    Err("clone: this build lacks the `ssh` feature".into())
}

#[cfg(feature = "http")]
fn clone_http(url: &str, dir: &str) -> CmdResult {
    use puregit::transport::http::HttpTransport;
    let mut transport = HttpTransport::new(url.to_string(), HashAlgo::Sha1);
    let repo = puregit::client::clone(dir, &mut transport)?;
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
        Err(Fail::Fatal(e) | Fail::Usage(e) | Fail::Code(_, e)) => {
            eprintln!("warning: lfs pull skipped: {e}")
        }
    }
    Ok(())
}

#[cfg(not(feature = "http"))]
fn clone_http(_url: &str, _dir: &str) -> CmdResult {
    Err("clone: this build lacks the `http` feature".into())
}

/// Derives a directory name from a clone URL (last path segment, sans `.git`).
fn dir_from_url(url: &str) -> String {
    let trimmed = url.trim_end_matches(['/', '\\']);
    let trimmed = trimmed.strip_suffix("/.git").unwrap_or(trimmed);
    let last = trimmed.rsplit(['/', '\\']).next().unwrap_or("repo");
    last.strip_suffix(".git").unwrap_or(last).to_string()
}

// ---------------------------------------------------------------------------
// hash-object / cat-file
// ---------------------------------------------------------------------------

fn cmd_hash_object(args: &[String]) -> CmdResult {
    const SYN: &str = "hash-object [-t <type>] [-w] [--stdin] [--] <file>...";
    let mut write = false;
    let mut stdin = false;
    let mut ty = ObjectType::Blob;
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-w" => write = true,
            "--stdin" => stdin = true,
            "--literally" | "--no-filters" | "--" => {}
            "-t" => {
                i += 1;
                let t = args.get(i).ok_or_else(|| usage("hash-object", SYN))?;
                ty = ObjectType::from_str(t)
                    .map_err(|_| Fail::Fatal(format!("invalid object type \"{t}\"")))?;
            }
            s if s.starts_with('-') => return Err(unknown_option("hash-object", s, SYN)),
            s => files.push(s.to_string()),
        }
        i += 1;
    }
    let repo = open_here().ok();
    if write && repo.is_none() {
        return Err(open_here().err().unwrap());
    }
    let algo = repo.as_ref().map(|r| r.algo()).unwrap_or(HashAlgo::Sha1);
    let mut inputs = Vec::new();
    if stdin {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
        inputs.push(buf);
    }
    for f in &files {
        inputs.push(std::fs::read(f).map_err(|_| {
            Fail::Fatal(format!(
                "could not open '{f}' for reading: No such file or directory"
            ))
        })?);
    }
    let mut out = String::new();
    for content in inputs {
        // A non-blob payload must parse as that type (git's validation).
        if ty != ObjectType::Blob {
            Object::parse(algo, ty, &content).map_err(|_| Fail::Fatal(format!("corrupt {ty}")))?;
        }
        let id = match (&repo, write) {
            (Some(r), true) => r.write_object(ty, &content)?,
            _ => puregit::hash::hash_object(algo, ty, &content),
        };
        out.push_str(&format!("{id}\n"));
    }
    emit(out.as_bytes());
    Ok(())
}

/// The `ls-tree`-style lines for a tree (used by `cat-file -p` and `ls-tree`).
fn tree_lines(tree: &Tree) -> String {
    let mut s = String::new();
    for e in &tree.entries {
        s.push_str(&format!(
            "{:06o} {} {}\t{}\n",
            mode_num(e.mode),
            mode_kind(e.mode),
            e.id,
            quote_path(&e.name)
        ));
    }
    s
}

fn cmd_cat_file(args: &[String]) -> CmdResult {
    const SYN: &str = "cat-file <type> <object>\n   or: git cat-file (-e | -p) <object>\n   or: git cat-file (-t | -s) <object>\n   or: git cat-file (--batch | --batch-check) [--batch-all-objects]";
    let mut flag: Option<&str> = None;
    let mut batch: Option<(bool, Option<String>)> = None;
    let mut positional = Vec::new();
    for a in args {
        match a.as_str() {
            "-t" | "-s" | "-p" | "-e" => flag = Some(a.as_str()),
            "--batch" => batch = Some((true, None)),
            "--batch-check" => batch = Some((false, None)),
            s if s.starts_with("--batch=") => batch = Some((true, Some(s[8..].to_string()))),
            s if s.starts_with("--batch-check=") => {
                batch = Some((false, Some(s["--batch-check=".len()..].to_string())))
            }
            s if s.starts_with('-') => return Err(unknown_option("cat-file", s, SYN)),
            s => positional.push(s),
        }
    }
    if let Some((contents, fmt)) = batch {
        if !positional.is_empty() || flag.is_some() {
            return Err(usage("cat-file", SYN));
        }
        return cat_file_batch(contents, fmt.as_deref());
    }
    let (flag, spec) = match (flag, positional.as_slice()) {
        (Some(f), [spec]) => (f, *spec),
        (None, [ty, spec]) => (*ty, *spec),
        _ => return Err(usage("cat-file", SYN)),
    };
    let repo = open_here()?;
    if flag == "-e" {
        return match resolve(&repo, spec) {
            Ok(id) if repo.objects().contains(&id) => Ok(()),
            Ok(_) => Err(Fail::Code(1, String::new())),
            Err(e) => Err(Fail::Fatal(e.object_message(spec))),
        };
    }
    let id = resolve_object(&repo, spec)?;
    let (ty, payload) = read_raw(&repo, &id)?;
    match flag {
        "-t" => println!("{ty}"),
        "-s" => println!("{}", payload.len()),
        "-p" => match ty {
            ObjectType::Tree => emit(tree_lines(&Tree::parse(repo.algo(), &payload)?).as_bytes()),
            _ => emit(&payload),
        },
        want => {
            let want_ty = ObjectType::from_str(want)
                .map_err(|_| Fail::Fatal(format!("invalid object type \"{want}\"")))?;
            let peeled = peel_to(&repo, id, want_ty)
                .map_err(|_| Fail::Fatal(format!("git cat-file {spec}: bad file")))?;
            let (_, payload) = read_raw(&repo, &peeled)?;
            emit(&payload);
        }
    }
    Ok(())
}

/// `cat-file --batch[=<fmt>]` / `--batch-check[=<fmt>]`: for each name on
/// stdin print `<oid> <type> <size>` (or the custom format), followed for
/// `--batch` by the contents and a LF. Unresolvable names print
/// `<name> missing`.
fn cat_file_batch(contents: bool, fmt: Option<&str>) -> CmdResult {
    use std::io::BufRead;
    let repo = open_here()?;
    let fmt = fmt.unwrap_or("%(objectname) %(objecttype) %(objectsize)");
    let mut out = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        let name = line.trim_end_matches('\r');
        let found = resolve(&repo, name)
            .ok()
            .and_then(|id| read_raw(&repo, &id).ok().map(|(ty, p)| (id, ty, p)));
        match found {
            Some((id, ty, payload)) => {
                let header = fmt
                    .replace("%(objectname)", &id.to_hex())
                    .replace("%(objecttype)", ty.as_str())
                    .replace("%(objectsize)", &payload.len().to_string())
                    .replace("%(rest)", "");
                out.extend_from_slice(header.as_bytes());
                out.push(b'\n');
                if contents {
                    out.extend_from_slice(&payload);
                    out.push(b'\n');
                }
            }
            None => out.extend_from_slice(format!("{name} missing\n").as_bytes()),
        }
    }
    emit(&out);
    Ok(())
}

// ---------------------------------------------------------------------------
// rev-parse
// ---------------------------------------------------------------------------

fn cmd_rev_parse(args: &[String]) -> CmdResult {
    let mut verify = false;
    let mut quiet = false;
    let mut short: Option<usize> = None;
    let mut abbrev_ref = false;
    let mut full_name = false;
    let mut out = String::new();
    let mut revs = Vec::new();
    let repo = open_here();

    for a in args {
        match a.as_str() {
            "--verify" => verify = true,
            "-q" | "--quiet" => quiet = true,
            "--short" => short = Some(7),
            "--abbrev-ref" => abbrev_ref = true,
            "--symbolic-full-name" => full_name = true,
            "--git-dir" => {
                let r = repo.as_ref().map_err(|_| open_here().err().unwrap())?;
                let cwd = std::env::current_dir()?;
                let gd = r.git_dir();
                let shown = match gd.strip_prefix(&cwd) {
                    Ok(rel) if !rel.as_os_str().is_empty() => rel.display().to_string(),
                    Ok(_) => ".".into(),
                    Err(_) => gd.display().to_string(),
                };
                out.push_str(&format!("{shown}\n"));
            }
            "--is-inside-work-tree" => {
                let r = repo.as_ref().map_err(|_| open_here().err().unwrap())?;
                out.push_str(if r.work_tree().is_some() {
                    "true\n"
                } else {
                    "false\n"
                });
            }
            "--is-bare-repository" => {
                let r = repo.as_ref().map_err(|_| open_here().err().unwrap())?;
                out.push_str(if r.work_tree().is_some() {
                    "false\n"
                } else {
                    "true\n"
                });
            }
            "--show-object-format" => {
                let r = repo.as_ref().map_err(|_| open_here().err().unwrap())?;
                out.push_str(&format!("{}\n", r.algo().name()));
            }
            s if s.starts_with("--short=") => {
                let n: usize = s[8..]
                    .parse()
                    .map_err(|_| Fail::Fatal(format!("bad --short value: {}", &s[8..])))?;
                short = Some(n);
            }
            s if s.starts_with("--") => {
                return Err(Fail::Fatal(format!("unknown option {s}")));
            }
            s => revs.push(s.to_string()),
        }
    }
    if short.is_some() && !verify && revs.len() <= 1 {
        // `--short` implies `--verify`.
        verify = true;
    }
    if revs.is_empty() {
        if verify {
            if quiet {
                return Err(Fail::Code(1, String::new()));
            }
            return Err("Needed a single revision".into());
        }
        emit(out.as_bytes());
        return Ok(());
    }
    let repo = repo?;
    if verify && revs.len() > 1 {
        return Err("Needed a single revision".into());
    }
    for spec in &revs {
        if abbrev_ref || full_name {
            let base = spec.as_str();
            let full = if base == "HEAD" || base == "@" {
                // An unborn HEAD does not resolve, so it has no name either.
                match (repo.refs().lookup("HEAD"), repo.head_id()) {
                    (_, Err(_)) => None,
                    (Ok(Reference::Symbolic(t)), _) => Some(t),
                    _ => Some("HEAD".to_string()),
                }
            } else {
                dwim_ref_name(&repo, base)
            };
            match full {
                Some(f) => {
                    let shown = if abbrev_ref {
                        shorten_ref(&f)
                    } else if f == "HEAD" {
                        // A detached HEAD has no symbolic full name.
                        continue;
                    } else {
                        f
                    };
                    out.push_str(&format!("{shown}\n"));
                }
                None => {
                    out.push_str(&format!("{spec}\n"));
                    emit(out.as_bytes());
                    return Err(RevErr::Unknown.rev_message(spec).into());
                }
            }
            continue;
        }
        match resolve(&repo, spec) {
            Ok(id) if !verify || repo.objects().contains(&id) => {
                let shown = match short {
                    Some(n) => abbrev_len(&repo, &id, n),
                    None => id.to_hex(),
                };
                out.push_str(&format!("{shown}\n"));
            }
            other => {
                emit(out.as_bytes());
                if verify {
                    if quiet {
                        return Err(Fail::Code(1, String::new()));
                    }
                    return Err(match other {
                        Err(e @ RevErr::PathNotInTree { .. }) => e.object_message(spec),
                        _ => "Needed a single revision".into(),
                    }
                    .into());
                }
                // git echoes the unresolvable argument (taking it for a path).
                println!("{spec}");
                let msg = match other {
                    Err(e) => e.rev_message(spec),
                    Ok(_) => RevErr::Unknown.rev_message(spec),
                };
                return Err(msg.into());
            }
        }
    }
    emit(out.as_bytes());
    Ok(())
}

/// The shortest unambiguous display form of a full ref name.
fn shorten_ref(full: &str) -> String {
    for p in ["refs/heads/", "refs/tags/", "refs/remotes/"] {
        if let Some(s) = full.strip_prefix(p) {
            return s.to_string();
        }
    }
    full.strip_prefix("refs/").unwrap_or(full).to_string()
}

// ---------------------------------------------------------------------------
// Index manipulation: add / rm / mv / ls-files / write-tree / read-tree
// ---------------------------------------------------------------------------

/// Normalises a user-supplied pathspec (relative to the work tree root) into
/// git's `/`-separated form, without a trailing slash; `.` becomes empty.
fn norm_pathspec(p: &str) -> String {
    let p = p.replace('\\', "/");
    let p = p.trim_start_matches("./").trim_end_matches('/');
    if p == "." {
        String::new()
    } else {
        p.to_string()
    }
}

/// Whether `path` is `spec` itself or lies under the directory `spec`.
fn under(path: &[u8], spec: &str) -> bool {
    spec.is_empty()
        || path == spec.as_bytes()
        || (path.starts_with(spec.as_bytes()) && path.get(spec.len()) == Some(&b'/'))
}

fn cmd_add(args: &[String]) -> CmdResult {
    const SYN: &str = "add [<options>] [--] <pathspec>...";
    let mut all = false;
    let mut specs = Vec::new();
    for a in args {
        match a.as_str() {
            "-A" | "--all" => all = true,
            "--" => {}
            s if s.starts_with('-') => return Err(unknown_option("add", s, SYN)),
            s => specs.push(norm_pathspec(s)),
        }
    }
    if specs.is_empty() && !all {
        println!("Nothing specified, nothing added.");
        return Ok(());
    }
    if all && specs.is_empty() {
        specs.push(String::new());
    }
    let repo = open_here()?;
    let work = work_tree(&repo, "add")?;
    let st = puregit::status::status(&repo)?;
    let index = repo.index()?;
    // Candidate paths: changed tracked files plus untracked, unignored files.
    let mut changed: BTreeSet<Vec<u8>> = st.unstaged.iter().map(|(p, _)| p.clone()).collect();
    changed.extend(st.untracked.iter().cloned());

    let mut todo: BTreeSet<Vec<u8>> = BTreeSet::new();
    for spec in &specs {
        let matched_index = index.entries.iter().any(|e| under(&e.path, spec));
        let on_disk = spec.is_empty() || work.join(spec).exists();
        if !matched_index && !on_disk {
            return Err(format!("pathspec '{spec}' did not match any files").into());
        }
        if !spec.is_empty() && work.join(spec).is_file() {
            todo.insert(spec.as_bytes().to_vec());
            continue;
        }
        for p in &changed {
            if under(p, spec) {
                todo.insert(p.clone());
            }
        }
    }
    for p in todo {
        let p = String::from_utf8_lossy(&p).into_owned();
        repo.add_path(&p)?;
    }
    Ok(())
}

fn cmd_rm(args: &[String]) -> CmdResult {
    const SYN: &str = "rm [<options>] [--] <file>...";
    let mut cached = false;
    let mut quiet = false;
    let mut specs = Vec::new();
    for a in args {
        match a.as_str() {
            "--cached" => cached = true,
            "-q" | "--quiet" => quiet = true,
            "-f" | "--force" | "--" => {}
            s if s.starts_with('-') => return Err(unknown_option("rm", s, SYN)),
            s => specs.push(norm_pathspec(s)),
        }
    }
    if specs.is_empty() {
        return Err(usage("rm", SYN));
    }
    let repo = open_here()?;
    let mut index = repo.index()?;
    for s in &specs {
        if !index.entries.iter().any(|e| e.path == s.as_bytes()) {
            return Err(format!("pathspec '{s}' did not match any files").into());
        }
    }
    let mut out = String::new();
    for s in &specs {
        index.entries.retain(|e| e.path != s.as_bytes());
        if !quiet {
            out.push_str(&format!("rm '{s}'\n"));
        }
    }
    repo.write_index(&index)?;
    if !cached && let Some(work) = repo.work_tree() {
        for s in &specs {
            let full = work.join(s);
            let _ = std::fs::remove_file(&full);
            remove_empty_parents(work, &full);
        }
    }
    emit(out.as_bytes());
    Ok(())
}

/// Whether an index path is a safe, relative, `/`-separated path (no empty,
/// `.`, `..` or `.git` components) that may be joined onto the work tree.
fn safe_rel_path(p: &[u8]) -> bool {
    !p.is_empty()
        && p.split(|&b| b == b'/').all(|c| {
            !c.is_empty()
                && c != b"."
                && c != b".."
                && !c.eq_ignore_ascii_case(b".git")
                && !c.contains(&b'\\')
                && !(cfg!(windows) && c.contains(&b':'))
        })
}

/// Removes now-empty directories between `path` and the work-tree root.
fn remove_empty_parents(root: &Path, path: &Path) {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if dir == root || !dir.starts_with(root) || std::fs::remove_dir(dir).is_err() {
            break;
        }
        cur = dir.parent();
    }
}

fn cmd_mv(args: &[String]) -> CmdResult {
    const SYN: &str = "mv [<options>] <source>... <destination>";
    let positional: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|s| norm_pathspec(s))
        .collect();
    if let Some(bad) = args.iter().find(|a| a.starts_with('-') && *a != "--") {
        return Err(unknown_option("mv", bad, SYN));
    }
    if positional.len() != 2 {
        return Err(usage("mv", SYN));
    }
    let (src, dst) = (&positional[0], &positional[1]);
    let repo = open_here()?;
    let work = work_tree(&repo, "mv")?;
    let index = repo.index()?;
    if !index.entries.iter().any(|e| e.path == src.as_bytes()) {
        let why = if work.join(src).exists() {
            "not under version control"
        } else {
            "bad source"
        };
        return Err(format!("{why}, source={src}, destination={dst}").into());
    }
    // `mv file dir/` moves into an existing directory.
    let dst = if work.join(dst).is_dir() {
        let name = src.rsplit('/').next().unwrap_or(src);
        format!("{}/{name}", dst.trim_end_matches('/'))
    } else {
        dst.clone()
    };
    if work.join(&dst).exists() {
        return Err(format!("destination exists, source={src}, destination={dst}").into());
    }
    repo.mv(src, &dst)?;
    remove_empty_parents(&work, &work.join(src));
    Ok(())
}

fn cmd_ls_files(args: &[String]) -> CmdResult {
    const SYN: &str = "ls-files [<options>] [<file>...]";
    let mut stage = false;
    let mut nul = false;
    for a in args {
        match a.as_str() {
            "-s" | "--stage" => stage = true,
            "-z" => nul = true,
            "-c" | "--cached" => {}
            s => return Err(unknown_option("ls-files", s, SYN)),
        }
    }
    let repo = open_here()?;
    let mut index = repo.index()?;
    index
        .entries
        .sort_by(|a, b| a.path.cmp(&b.path).then(a.stage.cmp(&b.stage)));
    let mut out = Vec::new();
    for e in &index.entries {
        let name = if nul {
            String::from_utf8_lossy(&e.path).into_owned()
        } else {
            quote_path(&e.path)
        };
        if stage {
            out.extend_from_slice(format!("{:06o} {} {}\t", e.mode, e.id, e.stage).as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(if nul { 0 } else { b'\n' });
    }
    emit(&out);
    Ok(())
}

fn cmd_write_tree(args: &[String]) -> CmdResult {
    use puregit::tree_builder::write_tree_from_index;
    if let Some(a) = args.first() {
        return Err(unknown_option(
            "write-tree",
            a,
            "write-tree [--missing-ok] [--prefix=<prefix>/]",
        ));
    }
    let repo = open_here()?;
    let index = repo.index()?;
    let id = write_tree_from_index(repo.objects(), &index)?;
    println!("{id}");
    Ok(())
}

/// `read-tree <tree-ish>` — resolve a tree/commit and load its tree into the
/// index, replacing the current staged contents.
fn cmd_read_tree(args: &[String]) -> CmdResult {
    let rev = args
        .first()
        .ok_or_else(|| usage("read-tree", "<tree-ish>"))?;
    let repo = open_here()?;
    let tree = resolve_tree(&repo, rev)?;
    repo.read_tree(&tree)?;
    Ok(())
}

/// `mktree` — read `ls-tree`-style lines from stdin and write a single tree
/// object, printing its id. Each line is `<mode> SP <type> SP <sha> TAB <name>`
/// (the `<type>` column is accepted but ignored; the mode determines the entry
/// kind). Entries are canonically sorted by `Tree::serialize`, so the input
/// order does not matter.
fn cmd_mktree(_args: &[String]) -> CmdResult {
    use puregit::object::TreeEntry;
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
            mode: FileMode::from_octal(mode.as_bytes())?,
            name: name.as_bytes().to_vec(),
            id: ObjectId::from_hex(repo.algo(), sha)?,
        });
    }

    let id = repo.write_object(ObjectType::Tree, &Tree { entries }.serialize())?;
    println!("{id}");
    Ok(())
}

/// `commit-tree <tree> [-p <parent>]... [-m <msg>]` — create a commit object for
/// an existing tree and print its id, without touching `HEAD` or the index.
/// The message comes from `-m` (repeatable, joined by blank lines) or, if none
/// is given, from stdin.
fn cmd_commit_tree(args: &[String]) -> CmdResult {
    use std::io::Read;
    const SYN: &str = "commit-tree <tree> [(-p <parent>)...] [(-m <message>)...]";

    let mut tree_arg = None;
    let mut parents_spec = Vec::new();
    let mut messages = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                let p = args.get(i + 1).ok_or_else(|| usage("commit-tree", SYN))?;
                parents_spec.push(p.clone());
                i += 2;
            }
            "-m" => {
                let m = args.get(i + 1).ok_or_else(|| usage("commit-tree", SYN))?;
                messages.push(m.clone());
                i += 2;
            }
            other => {
                if tree_arg.is_some() {
                    return Err(usage("commit-tree", SYN));
                }
                tree_arg = Some(other.to_string());
                i += 1;
            }
        }
    }
    let tree_arg = tree_arg.ok_or_else(|| usage("commit-tree", SYN))?;

    let repo = open_here()?;
    let tree = resolve_tree(&repo, &tree_arg)?;
    let mut parents = Vec::new();
    for p in &parents_spec {
        parents.push(resolve_commit(&repo, p)?);
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

    let commit = Commit {
        tree,
        parents,
        author: ident(&repo, "AUTHOR")?,
        committer: ident(&repo, "COMMITTER")?,
        extra_headers: Vec::new(),
        message: message.into_bytes(),
    };
    let id = repo.write_object(ObjectType::Commit, &commit.serialize())?;
    println!("{id}");
    Ok(())
}

fn cmd_commit(args: &[String]) -> CmdResult {
    const SYN: &str = "commit [-q] [--allow-empty] [-a] -m <msg>...";
    let mut messages = Vec::new();
    let mut quiet = false;
    let mut allow_empty = false;
    let mut all = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--message" => {
                messages.push(args.get(i + 1).ok_or_else(|| usage("commit", SYN))?.clone());
                i += 1;
            }
            s if s.starts_with("--message=") => messages.push(s[10..].to_string()),
            s if s.starts_with("-m") && s.len() > 2 => messages.push(s[2..].to_string()),
            "-q" | "--quiet" => quiet = true,
            "--allow-empty" => allow_empty = true,
            "-a" | "--all" => all = true,
            s => return Err(unknown_option("commit", s, SYN)),
        }
        i += 1;
    }
    if messages.is_empty() {
        return Err(Fail::Usage(format!(
            "error: puregit commit requires -m <message>\nusage: git {SYN}"
        )));
    }

    let repo = open_here()?;
    if all {
        let st = puregit::status::status(&repo)?;
        for (p, _) in &st.unstaged {
            repo.add_path(&String::from_utf8_lossy(p))?;
        }
    }
    let index = repo.index()?;
    let tree = puregit::tree_builder::write_tree_from_index(repo.objects(), &index)?;
    let parent = repo.head_id().ok();
    let parent_tree = match &parent {
        Some(p) => Some(read_commit(&repo, p)?.tree),
        None => None,
    };
    if !allow_empty && (parent_tree == Some(tree) || (parent.is_none() && index.entries.is_empty()))
    {
        let branch =
            head_branch(&repo).and_then(|b| b.strip_prefix("refs/heads/").map(String::from));
        let mut msg = match &branch {
            Some(b) => format!("On branch {b}\n"),
            None => "HEAD detached\n".to_string(),
        };
        msg.push_str("nothing to commit, working tree clean\n");
        emit(msg.as_bytes());
        return Err(Fail::Code(1, String::new()));
    }

    let message = clean_message(&messages);
    let author = ident(&repo, "AUTHOR")?;
    let committer = ident(&repo, "COMMITTER")?;
    let id = repo.commit(&message, author, committer)?;
    if !quiet {
        let label = match head_branch(&repo) {
            Some(b) => b.strip_prefix("refs/heads/").unwrap_or(&b).to_string(),
            None => "detached HEAD".to_string(),
        };
        let root = if parent.is_none() {
            " (root-commit)"
        } else {
            ""
        };
        let subject = subject_of(&message);
        let mut out = format!("[{label}{root} {}] {subject}\n", abbrev(&repo, &id));
        out.push_str(&diffstat_summary(&repo, parent_tree.as_ref(), &tree)?);
        emit(out.as_bytes());
    }
    Ok(())
}

/// The ` N files changed, X insertions(+), Y deletions(-)` line (plus
/// create/delete mode lines) that `git commit` prints.
fn diffstat_summary(
    repo: &Repository,
    old: Option<&ObjectId>,
    new: &ObjectId,
) -> Result<String, Fail> {
    let old_map = match old {
        Some(t) => puregit::walk::flatten_tree(repo.objects(), t)?,
        None => BTreeMap::new(),
    };
    let new_map = puregit::walk::flatten_tree(repo.objects(), new)?;
    let (mut files, mut ins, mut del) = (0usize, 0usize, 0usize);
    let mut modes = String::new();
    let paths: BTreeSet<&Vec<u8>> = old_map.keys().chain(new_map.keys()).collect();
    for p in paths {
        let (o, n) = (old_map.get(p), new_map.get(p));
        if o == n {
            continue;
        }
        files += 1;
        let read = |e: Option<&(FileMode, ObjectId)>| -> Vec<u8> {
            e.and_then(|(_, id)| read_raw(repo, id).ok())
                .map(|(_, b)| b)
                .unwrap_or_default()
        };
        let (ob, nb) = (read(o), read(n));
        if !is_binary(&ob) && !is_binary(&nb) {
            let (a, d) = line_counts(&ob, &nb);
            ins += a;
            del += d;
        }
        match (o, n) {
            (None, Some((m, _))) => modes.push_str(&format!(
                " create mode {:o} {}\n",
                mode_num(*m),
                quote_path(p)
            )),
            (Some((m, _)), None) => modes.push_str(&format!(
                " delete mode {:o} {}\n",
                mode_num(*m),
                quote_path(p)
            )),
            _ => {}
        }
    }
    let mut s = format!(" {files} file{} changed", if files == 1 { "" } else { "s" });
    if ins > 0 || (ins == 0 && del == 0) {
        s.push_str(&format!(
            ", {ins} insertion{}(+)",
            if ins == 1 { "" } else { "s" }
        ));
    }
    if del > 0 {
        s.push_str(&format!(
            ", {del} deletion{}(-)",
            if del == 1 { "" } else { "s" }
        ));
    }
    s.push('\n');
    s.push_str(&modes);
    Ok(s)
}

/// (insertions, deletions) between two texts, from the unified diff.
fn line_counts(old: &[u8], new: &[u8]) -> (usize, usize) {
    let d = puregit::diff::unified(old, new, "a", "b", 0);
    let mut ins = 0;
    let mut del = 0;
    for l in d.lines().skip(2) {
        if l.starts_with('+') {
            ins += 1;
        } else if l.starts_with('-') {
            del += 1;
        }
    }
    (ins, del)
}

// ---------------------------------------------------------------------------
// log / show
// ---------------------------------------------------------------------------

/// The subject (`%s`): the first paragraph of a message, lines joined by a space.
fn subject_of(msg: &[u8]) -> String {
    let text = String::from_utf8_lossy(msg);
    let mut parts = Vec::new();
    for l in text.lines().skip_while(|l| l.trim().is_empty()) {
        if l.trim().is_empty() {
            break;
        }
        parts.push(l.trim_end().to_string());
    }
    parts.join(" ")
}

/// The body (`%b`): everything after the subject paragraph.
fn body_of(msg: &[u8]) -> String {
    let text = String::from_utf8_lossy(msg);
    let mut lines = text.lines().skip_while(|l| l.trim().is_empty());
    for l in lines.by_ref() {
        if l.trim().is_empty() {
            break;
        }
    }
    let rest: Vec<&str> = lines.skip_while(|l| l.trim().is_empty()).collect();
    let mut s = String::new();
    for l in rest {
        s.push_str(l);
        s.push('\n');
    }
    s
}

/// Ref decorations, keyed by the decorated object, in git's display order.
struct Decorations {
    by_id: BTreeMap<ObjectId, Vec<String>>,
}

impl Decorations {
    fn load(repo: &Repository) -> Decorations {
        let mut by_id: BTreeMap<ObjectId, Vec<String>> = BTreeMap::new();
        let head = repo.refs().lookup("HEAD").ok();
        let head_branch = match &head {
            Some(Reference::Symbolic(t)) => Some(t.clone()),
            _ => None,
        };
        let refs = repo.refs().list().unwrap_or_default();
        // git prepends each decoration, so later refs (in sorted order) show
        // first; HEAD is added last and therefore leads.
        for (name, id) in refs.iter().rev() {
            if Some(name) == head_branch.as_ref() {
                continue;
            }
            let (label, is_tag) = if let Some(t) = name.strip_prefix("refs/tags/") {
                (format!("tag: {t}"), true)
            } else if let Some(h) = name.strip_prefix("refs/heads/") {
                (h.to_string(), false)
            } else if let Some(r) = name.strip_prefix("refs/remotes/") {
                (r.to_string(), false)
            } else {
                (name.clone(), false)
            };
            by_id.entry(*id).or_default().push(label.clone());
            if is_tag {
                let mut cur = *id;
                while let Ok(Object::Tag(t)) = repo.read_object(&cur) {
                    cur = t.object;
                    by_id.entry(cur).or_default().push(label.clone());
                }
            }
        }
        if let Ok(head_id) = repo.head_id() {
            let label = match &head_branch {
                Some(b) => format!("HEAD -> {}", shorten_ref(b)),
                None => "HEAD".to_string(),
            };
            by_id.entry(head_id).or_default().insert(0, label);
        }
        Decorations { by_id }
    }

    fn get(&self, id: &ObjectId) -> Option<String> {
        self.by_id.get(id).map(|v| v.join(", "))
    }
}

/// A `log`/`show` output format.
enum Pretty {
    Medium,
    Oneline,
    /// `--pretty=oneline`: full hash and subject.
    FullOneline,
    /// A user format; `terminator` is true for `tformat:`/`--format=`.
    Format {
        template: String,
        terminator: bool,
    },
}

/// Expands a `--format` template for one commit.
fn expand_format(
    repo: &Repository,
    id: &ObjectId,
    c: &Commit,
    template: &str,
    decor: &Decorations,
) -> String {
    let mut out = String::new();
    let mut chars = template.char_indices().peekable();
    let rest_from = |i: usize| &template[i..];
    while let Some((i, ch)) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        let r = rest_from(i + 1);
        let (rep, len): (String, usize) = if r.starts_with('%') {
            ("%".into(), 1)
        } else if r.starts_with('n') {
            ("\n".into(), 1)
        } else if r.starts_with('H') {
            (id.to_hex(), 1)
        } else if r.starts_with('h') {
            (abbrev(repo, id), 1)
        } else if r.starts_with('T') {
            (c.tree.to_hex(), 1)
        } else if r.starts_with('t') {
            (abbrev(repo, &c.tree), 1)
        } else if r.starts_with('P') {
            (
                c.parents
                    .iter()
                    .map(|p| p.to_hex())
                    .collect::<Vec<_>>()
                    .join(" "),
                1,
            )
        } else if r.starts_with('p') {
            (
                c.parents
                    .iter()
                    .map(|p| abbrev(repo, p))
                    .collect::<Vec<_>>()
                    .join(" "),
                1,
            )
        } else if r.starts_with('s') {
            (subject_of(&c.message), 1)
        } else if r.starts_with('b') {
            (body_of(&c.message), 1)
        } else if r.starts_with('B') {
            (String::from_utf8_lossy(&c.message).into_owned(), 1)
        } else if r.starts_with('d') {
            (
                decor.get(id).map(|d| format!(" ({d})")).unwrap_or_default(),
                1,
            )
        } else if r.starts_with('D') {
            (decor.get(id).unwrap_or_default(), 1)
        } else if let Some(who) = r
            .strip_prefix('a')
            .map(|_| &c.author)
            .or_else(|| r.strip_prefix('c').map(|_| &c.committer))
        {
            let rest = &r[1..];
            match rest.chars().next() {
                Some('n') => (String::from_utf8_lossy(&who.name).into_owned(), 2),
                Some('e') => (String::from_utf8_lossy(&who.email).into_owned(), 2),
                Some('t') => (who.time.to_string(), 2),
                Some('d') => (fmt_date(who), 2),
                Some('i') => (fmt_date_iso(who), 2),
                _ => (format!("%{}", &r[..1]), 1),
            }
        } else {
            ("%".into(), 0)
        };
        out.push_str(&rep);
        for _ in 0..len {
            chars.next();
        }
    }
    out
}

/// Renders one commit in the given format (without the inter-commit separator).
fn render_commit(
    repo: &Repository,
    id: &ObjectId,
    c: &Commit,
    pretty: &Pretty,
    decor: &Decorations,
) -> String {
    match pretty {
        Pretty::Oneline => format!("{} {}\n", abbrev(repo, id), subject_of(&c.message)),
        Pretty::FullOneline => format!("{id} {}\n", subject_of(&c.message)),
        Pretty::Format { template, .. } => expand_format(repo, id, c, template, decor),
        Pretty::Medium => {
            let mut s = format!("commit {id}\n");
            if c.parents.len() > 1 {
                let ps: Vec<String> = c.parents.iter().map(|p| abbrev(repo, p)).collect();
                s.push_str(&format!("Merge: {}\n", ps.join(" ")));
            }
            s.push_str(&format!(
                "Author: {} <{}>\nDate:   {}\n\n",
                String::from_utf8_lossy(&c.author.name),
                String::from_utf8_lossy(&c.author.email),
                fmt_date(&c.author)
            ));
            s.push_str(&indent_message(&c.message));
            s
        }
    }
}

/// A commit message indented by four spaces (git's medium format), with
/// leading and trailing blank lines dropped.
fn indent_message(msg: &[u8]) -> String {
    let text = String::from_utf8_lossy(msg);
    let lines: Vec<&str> = text.lines().skip_while(|l| l.trim().is_empty()).collect();
    let end = lines
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map_or(0, |i| i + 1);
    let mut s = String::new();
    for l in &lines[..end] {
        s.push_str("    ");
        s.push_str(l);
        s.push('\n');
    }
    s
}

/// Commits reachable from `tips`, newest first by committer date (git's
/// default order: a date-ordered queue with first-seen tie-breaking).
fn walk_by_date(repo: &Repository, tips: &[ObjectId]) -> Result<Vec<(ObjectId, Commit)>, Fail> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut heap = BinaryHeap::new();
    let mut pending: BTreeMap<ObjectId, Commit> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut seq = 0u64;
    for t in tips {
        if seen.insert(*t) {
            let c = read_commit(repo, t)?;
            heap.push((c.committer.time, Reverse(seq), *t));
            pending.insert(*t, c);
            seq += 1;
        }
    }
    let mut out = Vec::new();
    while let Some((_, _, id)) = heap.pop() {
        let Some(c) = pending.remove(&id) else {
            continue;
        };
        for p in &c.parents {
            if seen.insert(*p) {
                // A missing parent (e.g. a shallow boundary) ends that line.
                if let Ok(Object::Commit(pc)) = repo.read_object(p) {
                    heap.push((pc.committer.time, Reverse(seq), *p));
                    pending.insert(*p, pc);
                    seq += 1;
                }
            }
        }
        out.push((id, c));
    }
    Ok(out)
}

/// Parses a `--pretty=`/`--format=` value.
fn parse_pretty(v: &str, is_format_flag: bool) -> Result<Pretty, Fail> {
    if let Some(t) = v.strip_prefix("format:") {
        return Ok(Pretty::Format {
            template: t.to_string(),
            terminator: false,
        });
    }
    if let Some(t) = v.strip_prefix("tformat:") {
        return Ok(Pretty::Format {
            template: t.to_string(),
            terminator: true,
        });
    }
    match v {
        "medium" => Ok(Pretty::Medium),
        "oneline" => Ok(Pretty::FullOneline),
        _ if is_format_flag || v.contains('%') => Ok(Pretty::Format {
            template: v.to_string(),
            terminator: true,
        }),
        other => Err(Fail::Fatal(format!("invalid --pretty format: {other}"))),
    }
}

fn cmd_log(args: &[String]) -> CmdResult {
    let mut pretty = Pretty::Medium;
    let mut max: Option<usize> = None;
    let mut revs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--oneline" => pretty = Pretty::Oneline,
            "-n" | "--max-count" => {
                i += 1;
                let v = args.get(i).ok_or("switch `n' requires a value")?;
                max = Some(
                    v.parse()
                        .map_err(|_| Fail::Fatal(format!("'{v}': not an integer")))?,
                );
            }
            "--" => break,
            _ if a.starts_with("--max-count=") => {
                max = Some(
                    a[12..]
                        .parse()
                        .map_err(|_| Fail::Fatal(format!("'{a}': not an integer")))?,
                );
            }
            _ if a.starts_with("--pretty=") => pretty = parse_pretty(&a[9..], false)?,
            _ if a.starts_with("--format=") => pretty = parse_pretty(&a[9..], true)?,
            _ if a.starts_with('-')
                && a.len() > 1
                && a[1..].bytes().all(|b| b.is_ascii_digit()) =>
            {
                max = Some(a[1..].parse().unwrap_or(0));
            }
            _ if a.starts_with("-n")
                && a[2..].bytes().all(|b| b.is_ascii_digit())
                && a.len() > 2 =>
            {
                max = Some(a[2..].parse().unwrap_or(0));
            }
            _ if a.starts_with('-') => {
                return Err(Fail::Fatal(format!("unrecognized argument: {a}")));
            }
            _ => revs.push(a.to_string()),
        }
        i += 1;
    }
    let repo = open_here()?;
    let mut tips = Vec::new();
    if revs.is_empty() {
        match repo.head_id() {
            Ok(h) => tips.push(h),
            Err(_) => {
                let b = head_branch(&repo).unwrap_or_else(|| "HEAD".into());
                return Err(format!(
                    "your current branch '{}' does not have any commits yet",
                    shorten_ref(&b)
                )
                .into());
            }
        }
    }
    for r in &revs {
        tips.push(resolve_commit(&repo, r)?);
    }
    let decor = Decorations::load(&repo);
    let commits = walk_by_date(&repo, &tips)?;
    let limit = max.unwrap_or(usize::MAX);
    let mut out = String::new();
    for (n, (id, c)) in commits.iter().take(limit).enumerate() {
        let body = render_commit(&repo, id, c, &pretty, &decor);
        match &pretty {
            Pretty::Medium if n > 0 => out.push('\n'),
            Pretty::Format {
                terminator: false, ..
            } if n > 0 => out.push('\n'),
            _ => {}
        }
        out.push_str(&body);
        if let Pretty::Format {
            terminator: true, ..
        } = pretty
        {
            out.push('\n');
        }
    }
    emit(out.as_bytes());
    Ok(())
}

/// `show [<object>...]` (default `HEAD`) — display objects. A commit prints its
/// header and message followed by a patch against its parent; a tag prints its
/// header and then the object it points at; a tree lists its entry names; a
/// blob prints its raw contents.
fn cmd_show(args: &[String]) -> CmdResult {
    let mut specs: Vec<String> = Vec::new();
    for a in args {
        if a.starts_with('-') {
            return Err(Fail::Fatal(format!("unrecognized argument: {a}")));
        }
        specs.push(a.clone());
    }
    if specs.is_empty() {
        specs.push("HEAD".into());
    }
    let repo = open_here()?;
    let mut out = String::new();
    for (n, spec) in specs.iter().enumerate() {
        let id = resolve_rev(&repo, spec)?;
        if n > 0 {
            out.push('\n');
        }
        show_object(&repo, spec, &id, &mut out)?;
    }
    emit(out.as_bytes());
    Ok(())
}

/// Renders one object for `show`, recursing through a tag to its target.
fn show_object(repo: &Repository, spec: &str, id: &ObjectId, out: &mut String) -> CmdResult {
    match repo.read_object(id)? {
        Object::Commit(c) => {
            let decor = Decorations {
                by_id: BTreeMap::new(),
            };
            out.push_str(&render_commit(repo, id, &c, &Pretty::Medium, &decor));
            let patch = commit_patch(repo, &c)?;
            // git separates a merge's header from its (here empty) combined
            // diff with a blank line even when there is nothing to show.
            if !patch.is_empty() || c.parents.len() > 1 {
                out.push('\n');
                out.push_str(&patch);
            }
            Ok(())
        }
        Object::Tag(t) => {
            out.push_str(&format!("tag {}\n", String::from_utf8_lossy(&t.name)));
            if let Some(tagger) = &t.tagger {
                out.push_str(&format!(
                    "Tagger: {} <{}>\nDate:   {}\n",
                    String::from_utf8_lossy(&tagger.name),
                    String::from_utf8_lossy(&tagger.email),
                    fmt_date(tagger)
                ));
            }
            out.push('\n');
            out.push_str(&String::from_utf8_lossy(&t.message));
            out.push('\n');
            show_object(repo, spec, &t.object, out)
        }
        Object::Tree(t) => {
            out.push_str(&format!("tree {spec}\n\n"));
            for e in &t.entries {
                out.push_str(&String::from_utf8_lossy(&e.name));
                if e.mode == FileMode::Tree {
                    out.push('/');
                }
                out.push('\n');
            }
            Ok(())
        }
        Object::Blob(bytes) => {
            out.push_str(&String::from_utf8_lossy(&bytes));
            Ok(())
        }
    }
}

/// The patch `show` prints for a commit: against its parent (or the empty tree
/// for a root). For a merge, only paths differing from every parent are
/// candidates (git's dense combined diff); a clean merge prints nothing.
fn commit_patch(repo: &Repository, c: &Commit) -> Result<String, Fail> {
    let new_map = puregit::walk::flatten_tree(repo.objects(), &c.tree)?;
    if c.parents.len() > 1 {
        for (path, entry) in &new_map {
            let mut differs_from_all = true;
            for p in &c.parents {
                let pt = read_commit(repo, p)?.tree;
                let pm = puregit::walk::flatten_tree(repo.objects(), &pt)?;
                if pm.get(path) == Some(entry) {
                    differs_from_all = false;
                }
            }
            if differs_from_all {
                return Err("combined diffs of merge commits are not supported".into());
            }
        }
        return Ok(String::new());
    }
    let old_map = match c.parents.first() {
        Some(p) => puregit::walk::flatten_tree(repo.objects(), &read_commit(repo, p)?.tree)?,
        None => BTreeMap::new(),
    };
    let entries = map_diff(&old_map, &new_map);
    let mut out = String::new();
    for (path, o, n) in entries {
        out.push_str(&file_patch(
            repo,
            &path,
            o.map(side_of),
            n.map(side_of),
            None,
        )?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Diff machinery
// ---------------------------------------------------------------------------

/// One side of a file diff: its mode and blob id.
type Side = (u32, ObjectId);

/// A changed path for `diff`: (path, old side, new side, new work-tree
/// content when the new side is not in the object store).
type Change = (Vec<u8>, Option<Side>, Option<Side>, Option<Vec<u8>>);

fn side_of(e: (FileMode, ObjectId)) -> Side {
    (mode_num(e.0), e.1)
}

/// The changed paths between two flattened trees, with each side's entry.
#[allow(clippy::type_complexity)]
fn map_diff(
    old: &BTreeMap<Vec<u8>, (FileMode, ObjectId)>,
    new: &BTreeMap<Vec<u8>, (FileMode, ObjectId)>,
) -> Vec<(
    Vec<u8>,
    Option<(FileMode, ObjectId)>,
    Option<(FileMode, ObjectId)>,
)> {
    let paths: BTreeSet<&Vec<u8>> = old.keys().chain(new.keys()).collect();
    let mut out = Vec::new();
    for p in paths {
        let (o, n) = (old.get(p).copied(), new.get(p).copied());
        if o != n {
            out.push((p.clone(), o, n));
        }
    }
    out
}

/// Whether a buffer looks binary (a NUL in the first 8000 bytes, as git checks).
fn is_binary(b: &[u8]) -> bool {
    b.iter().take(8000).any(|&c| c == 0)
}

/// git's default "function name" for a hunk header: the nearest line above the
/// hunk that starts with a letter, `_` or `$` (trailing space trimmed, at most
/// 80 bytes).
fn func_context(old_lines: &[&[u8]], before: usize) -> Option<String> {
    for l in old_lines[..before.min(old_lines.len())].iter().rev() {
        if let Some(&c) = l.first()
            && (c.is_ascii_alphabetic() || c == b'_' || c == b'$')
        {
            let mut t: &[u8] = l;
            if t.len() > 80 {
                t = &t[..80];
            }
            while let Some((last, rest)) = t.split_last() {
                if last.is_ascii_whitespace() {
                    t = rest;
                } else {
                    break;
                }
            }
            return Some(String::from_utf8_lossy(t).into_owned());
        }
    }
    None
}

/// The hunks of a unified diff (everything after the `---`/`+++` lines), with
/// git's function-context suffix added to each `@@` header.
fn hunks(old: &[u8], new: &[u8]) -> String {
    let d = puregit::diff::unified(old, new, "a", "b", 3);
    let old_lines: Vec<&[u8]> = old.split_inclusive(|&b| b == b'\n').collect();
    let mut out = String::new();
    for line in d.split_inclusive('\n').skip(2) {
        if let Some(rest) = line.strip_prefix("@@ -")
            && let Some(end) = rest.find(" @@")
        {
            let range = rest.split(' ').next().unwrap_or("");
            let (start, count) = match range.split_once(',') {
                Some((s, c)) => (
                    s.parse::<usize>().unwrap_or(0),
                    c.parse::<usize>().unwrap_or(0),
                ),
                None => (range.parse::<usize>().unwrap_or(0), 1),
            };
            // 0-based index of the first old line in the hunk.
            let s1 = if count == 0 {
                start
            } else {
                start.saturating_sub(1)
            };
            out.push_str("@@ -");
            out.push_str(&rest[..end + 3]);
            if let Some(f) = func_context(&old_lines, s1) {
                out.push(' ');
                out.push_str(&f);
            }
            out.push('\n');
            continue;
        }
        out.push_str(line);
    }
    out
}

/// A git-style patch for one path. `new_bytes` overrides reading the new side
/// from the object store (used for work-tree content).
fn file_patch(
    repo: &Repository,
    path: &[u8],
    old: Option<Side>,
    new: Option<Side>,
    new_bytes: Option<&[u8]>,
) -> Result<String, Fail> {
    let read = |s: Option<Side>| -> Result<Vec<u8>, Fail> {
        match s {
            Some((_, id)) => Ok(read_raw(repo, &id)?.1),
            None => Ok(Vec::new()),
        }
    };
    let ob = read(old)?;
    let nb = match new_bytes {
        Some(b) => b.to_vec(),
        None => read(new)?,
    };
    let a = quote_prefixed("a/", path);
    let b = quote_prefixed("b/", path);
    let mut s = format!("diff --git {a} {b}\n");
    let zero = "0".repeat(7);
    let short = |side: Option<Side>| side.map_or(zero.clone(), |(_, id)| abbrev(repo, &id));
    match (old, new) {
        (None, Some((m, _))) => s.push_str(&format!(
            "new file mode {m:o}\nindex {zero}..{}\n",
            short(new)
        )),
        (Some((m, _)), None) => s.push_str(&format!(
            "deleted file mode {m:o}\nindex {}..{zero}\n",
            short(old)
        )),
        (Some((om, oid)), Some((nm, nid))) => {
            if om != nm {
                s.push_str(&format!("old mode {om:o}\nnew mode {nm:o}\n"));
            }
            if oid != nid {
                if om == nm {
                    s.push_str(&format!("index {}..{} {om:o}\n", short(old), short(new)));
                } else {
                    s.push_str(&format!("index {}..{}\n", short(old), short(new)));
                }
            }
        }
        (None, None) => return Ok(String::new()),
    }
    if old.map(|o| o.1) == new.map(|n| n.1) {
        return Ok(s);
    }
    // git appends a TAB to a `---`/`+++` file label containing a space.
    let tab = |l: &str| {
        if l != "/dev/null" && path.contains(&b' ') {
            "\t"
        } else {
            ""
        }
    };
    let la = if old.is_some() {
        a.clone()
    } else {
        "/dev/null".into()
    };
    let lb = if new.is_some() {
        b.clone()
    } else {
        "/dev/null".into()
    };
    if is_binary(&ob) || is_binary(&nb) {
        s.push_str(&format!("Binary files {la} and {lb} differ\n"));
        return Ok(s);
    }
    if ob.is_empty() && nb.is_empty() {
        return Ok(s);
    }
    s.push_str(&format!("--- {la}{}\n+++ {lb}{}\n", tab(&la), tab(&lb)));
    s.push_str(&hunks(&ob, &nb));
    Ok(s)
}

/// How `diff`/`diff-tree` print the list of changes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DiffOut {
    Patch,
    NameOnly,
    NameStatus,
}

fn status_letter(o: bool, n: bool) -> char {
    match (o, n) {
        (false, true) => 'A',
        (true, false) => 'D',
        _ => 'M',
    }
}

fn cmd_diff(args: &[String]) -> CmdResult {
    let mut quiet = false;
    let mut exit_code = false;
    let mut cached = false;
    let mut mode = DiffOut::Patch;
    let mut revs = Vec::new();
    for a in args {
        match a.as_str() {
            "--quiet" => quiet = true,
            "--exit-code" => exit_code = true,
            "--cached" | "--staged" => cached = true,
            "--name-only" => mode = DiffOut::NameOnly,
            "--name-status" => mode = DiffOut::NameStatus,
            "-p" | "--patch" => mode = DiffOut::Patch,
            "--" => {}
            s if s.starts_with('-') => {
                return Err(Fail::Usage(format!("error: invalid option: {s}")));
            }
            s => revs.push(s.to_string()),
        }
    }
    let exit_code = exit_code || quiet;
    let repo = open_here()?;

    // (path, old side, new side, new content override)
    let mut changes: Vec<Change> = Vec::new();
    let tree_map = |id: &ObjectId| puregit::walk::flatten_tree(repo.objects(), id);
    if cached || revs.len() == 2 {
        let (old_map, new_map) = if revs.len() == 2 {
            (
                tree_map(&resolve_tree(&repo, &revs[0])?)?,
                tree_map(&resolve_tree(&repo, &revs[1])?)?,
            )
        } else {
            let base = match revs.first() {
                Some(r) => tree_map(&resolve_tree(&repo, r)?)?,
                None => match repo.head_id() {
                    Ok(h) => tree_map(&read_commit(&repo, &h)?.tree)?,
                    Err(_) => BTreeMap::new(),
                },
            };
            let index = repo.index()?;
            let idx: BTreeMap<Vec<u8>, (FileMode, ObjectId)> = index
                .entries
                .iter()
                .filter(|e| e.stage == 0)
                .map(|e| {
                    (
                        e.path.clone(),
                        (
                            FileMode::from_mode_bits(e.mode).unwrap_or(FileMode::Regular),
                            e.id,
                        ),
                    )
                })
                .collect();
            (base, idx)
        };
        for (p, o, n) in map_diff(&old_map, &new_map) {
            changes.push((p, o.map(side_of), n.map(side_of), None));
        }
    } else if revs.is_empty() {
        let work = work_tree(&repo, "diff")?;
        let mut index = repo.index()?;
        index.entries.sort_by(|a, b| a.path.cmp(&b.path));
        for e in index.entries.iter().filter(|e| e.stage == 0) {
            let path = String::from_utf8_lossy(&e.path).into_owned();
            let old: Side = (e.mode, e.id);
            match std::fs::read(work.join(&path)) {
                Err(_) => changes.push((e.path.clone(), Some(old), None, None)),
                Ok(content) => {
                    let id = puregit::hash::hash_object(repo.algo(), ObjectType::Blob, &content);
                    if id != e.id {
                        changes.push((
                            e.path.clone(),
                            Some(old),
                            Some((e.mode, id)),
                            Some(content),
                        ));
                    }
                }
            }
        }
    } else {
        return Err("diff against the work tree for a commit is not supported".into());
    }

    if !quiet {
        let mut out = String::new();
        for (path, o, n, content) in &changes {
            match mode {
                DiffOut::NameOnly => out.push_str(&format!("{}\n", quote_path(path))),
                DiffOut::NameStatus => out.push_str(&format!(
                    "{}\t{}\n",
                    status_letter(o.is_some(), n.is_some()),
                    quote_path(path)
                )),
                DiffOut::Patch => {
                    out.push_str(&file_patch(&repo, path, *o, *n, content.as_deref())?)
                }
            }
        }
        emit(out.as_bytes());
    }
    if exit_code && !changes.is_empty() {
        return Err(Fail::Code(1, String::new()));
    }
    Ok(())
}

fn cmd_diff_tree(args: &[String]) -> CmdResult {
    const SYN: &str = "diff-tree [-r] [--name-only | --name-status] <tree-ish> <tree-ish>";
    let mut recursive = false;
    let mut mode = DiffOut::Patch; // Patch here means the raw format.
    let mut revs = Vec::new();
    for a in args {
        match a.as_str() {
            "-r" => recursive = true,
            "--name-only" => mode = DiffOut::NameOnly,
            "--name-status" => mode = DiffOut::NameStatus,
            s if s.starts_with('-') => return Err(unknown_option("diff-tree", s, SYN)),
            s => revs.push(s.to_string()),
        }
    }
    if revs.len() != 2 {
        return Err(usage("diff-tree", SYN));
    }
    let repo = open_here()?;
    let a = resolve_tree(&repo, &revs[0])?;
    let b = resolve_tree(&repo, &revs[1])?;
    let (old_map, new_map) = if recursive {
        (
            puregit::walk::flatten_tree(repo.objects(), &a)?,
            puregit::walk::flatten_tree(repo.objects(), &b)?,
        )
    } else {
        let top = |id: &ObjectId| -> Result<BTreeMap<Vec<u8>, (FileMode, ObjectId)>, Fail> {
            match repo.read_object(id)? {
                Object::Tree(t) => Ok(t
                    .entries
                    .into_iter()
                    .map(|e| (e.name, (e.mode, e.id)))
                    .collect()),
                _ => Err("not a tree".into()),
            }
        };
        (top(&a)?, top(&b)?)
    };
    let zero = ObjectId::zero(repo.algo());
    let mut out = String::new();
    for (path, o, n) in map_diff(&old_map, &new_map) {
        let letter = status_letter(o.is_some(), n.is_some());
        let name = quote_path(&path);
        match mode {
            DiffOut::NameOnly => out.push_str(&format!("{name}\n")),
            DiffOut::NameStatus => out.push_str(&format!("{letter}\t{name}\n")),
            DiffOut::Patch => {
                let (om, oid) = o.map_or((0, zero), side_of);
                let (nm, nid) = n.map_or((0, zero), side_of);
                out.push_str(&format!(
                    ":{om:06o} {nm:06o} {oid} {nid} {letter}\t{name}\n"
                ));
            }
        }
    }
    emit(out.as_bytes());
    Ok(())
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn cmd_status(args: &[String]) -> CmdResult {
    use puregit::status::Change;
    const SYN: &str = "status [<options>] [--] [<pathspec>...]";
    let mut short = false;
    let mut untracked = "normal";
    for a in args {
        match a.as_str() {
            "--porcelain" | "--porcelain=v1" | "-s" | "--short" => short = true,
            "-u" | "-uall" | "--untracked-files" => untracked = "all",
            "-uno" => untracked = "no",
            "-unormal" => untracked = "normal",
            s if s.starts_with("--untracked-files=") => {
                untracked = match &s[18..] {
                    "all" => "all",
                    "no" => "no",
                    "normal" => "normal",
                    v => return Err(format!("Invalid untracked files mode '{v}'").into()),
                }
            }
            s => return Err(unknown_option("status", s, SYN)),
        }
    }
    let repo = open_here()?;
    let st = puregit::status::status(&repo)?;

    if !short {
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
                    println!("\t{tag}:   {}", quote_path(path));
                }
            }
        };
        show("Changes to be committed", &st.staged);
        show("Changes not staged for commit", &st.unstaged);
        if !st.untracked.is_empty() {
            println!("Untracked files:");
            for path in &st.untracked {
                println!("\t{}", quote_path(path));
            }
        }
        return Ok(());
    }

    // `XY <path>` lines for tracked paths (sorted), then `?? <path>` lines.
    let code = |c: &Change| match c {
        Change::Added => 'A',
        Change::Modified => 'M',
        Change::Deleted => 'D',
    };
    let mut rows: BTreeMap<&[u8], (char, char)> = BTreeMap::new();
    for (path, change) in &st.staged {
        rows.entry(path).or_insert((' ', ' ')).0 = code(change);
    }
    for (path, change) in &st.unstaged {
        rows.entry(path).or_insert((' ', ' ')).1 = code(change);
    }
    let mut out = String::new();
    for (path, (x, y)) in &rows {
        out.push_str(&format!("{x}{y} {}\n", quote_path_sp(path)));
    }
    if untracked != "no" {
        let index = repo.index()?;
        let tracked_dirs: BTreeSet<Vec<u8>> = index
            .entries
            .iter()
            .flat_map(|e| {
                let p = &e.path;
                p.iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'/')
                    .map(|(i, _)| p[..i].to_vec())
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut shown: BTreeSet<Vec<u8>> = BTreeSet::new();
        for p in &st.untracked {
            let mut entry = p.clone();
            if untracked == "normal" {
                // Collapse to the outermost directory holding no tracked files.
                for (i, b) in p.iter().enumerate() {
                    if *b == b'/' && !tracked_dirs.contains(&p[..i]) {
                        entry = p[..=i].to_vec();
                        break;
                    }
                }
            }
            shown.insert(entry);
        }
        for p in shown {
            out.push_str(&format!("?? {}\n", quote_path_sp(&p)));
        }
    }
    emit(out.as_bytes());
    Ok(())
}

// ---------------------------------------------------------------------------
// branch / checkout / switch / reset / tag
// ---------------------------------------------------------------------------

/// Where a detached `HEAD` came from, read from the `HEAD` reflog the way
/// `git branch`/`git status` do: `(at|from, label)`.
fn detached_label(repo: &Repository, head: &ObjectId) -> Option<String> {
    let log = std::fs::read_to_string(repo.git_dir().join("logs").join("HEAD")).ok()?;
    for line in log.lines().rev() {
        let (meta, msg) = line.split_once('\t')?;
        let Some(rest) = msg.strip_prefix("checkout: moving from ") else {
            continue;
        };
        let (_, to) = rest.rsplit_once(" to ")?;
        let noid = ObjectId::from_hex(repo.algo(), meta.split(' ').nth(1)?).ok()?;
        let from = match dwim_ref(repo, to) {
            Some((name, id))
                if id == noid || peel_to(repo, id, ObjectType::Commit).ok() == Some(noid) =>
            {
                let n = name
                    .strip_prefix("refs/tags/")
                    .or_else(|| name.strip_prefix("refs/remotes/"))
                    .unwrap_or(&name);
                n.to_string()
            }
            _ => abbrev(repo, &noid),
        };
        let at = if *head == noid { "at" } else { "from" };
        return Some(format!("HEAD detached {at} {from}"));
    }
    None
}

fn cmd_branch(args: &[String]) -> CmdResult {
    const SYN: &str = "branch [<options>] [-l] [<pattern>...]\n   or: git branch [<options>] <branch-name> [<start-point>]\n   or: git branch [<options>] (-d | -D) <branch-name>...";
    let mut delete: Option<bool> = None; // Some(force)
    let mut list = false;
    let mut show_current = false;
    let mut positional = Vec::new();
    for a in args {
        match a.as_str() {
            "-d" | "--delete" => delete = Some(false),
            "-D" => delete = Some(true),
            "-l" | "--list" => list = true,
            "--show-current" => show_current = true,
            s if s.starts_with('-') => return Err(unknown_option("branch", s, SYN)),
            s => positional.push(s.to_string()),
        }
    }
    let repo = open_here()?;
    if show_current {
        if let Some(b) = head_branch(&repo) {
            println!("{}", b.strip_prefix("refs/heads/").unwrap_or(&b));
        }
        return Ok(());
    }
    if let Some(force) = delete {
        if positional.is_empty() {
            return Err("branch name required".into());
        }
        let mut out = String::new();
        let head = repo.head_id().ok();
        for name in &positional {
            let full = format!("refs/heads/{name}");
            let id = repo
                .refs()
                .resolve(&full)
                .map_err(|_| Fail::Code(1, format!("error: branch '{name}' not found")))?;
            if head_branch(&repo).as_deref() == Some(full.as_str()) {
                return Err(Fail::Code(
                    1,
                    format!("error: cannot delete branch '{name}' used by worktree"),
                ));
            }
            if !force
                && let Some(h) = head
                && !puregit::walk::is_ancestor(repo.objects(), &id, &h)?
            {
                return Err(Fail::Code(
                    1,
                    format!(
                        "error: the branch '{name}' is not fully merged\nhint: If you are sure you want to delete it, run 'git branch -D {name}'"
                    ),
                ));
            }
            repo.refs().delete(&full)?;
            let _ = std::fs::remove_file(repo.git_dir().join("logs").join(&full));
            out.push_str(&format!(
                "Deleted branch {name} (was {}).\n",
                abbrev(&repo, &id)
            ));
        }
        emit(out.as_bytes());
        return Ok(());
    }
    if positional.is_empty() || list {
        let mut out = String::new();
        let current = head_branch(&repo);
        if current.is_none()
            && let Ok(h) = repo.head_id()
        {
            let label = detached_label(&repo, &h).unwrap_or_else(|| "no branch".into());
            out.push_str(&format!("* ({label})\n"));
        }
        for (name, _) in repo.refs().list()? {
            if let Some(short) = name.strip_prefix("refs/heads/") {
                let mark = if current.as_deref() == Some(name.as_str()) {
                    '*'
                } else {
                    ' '
                };
                out.push_str(&format!("{mark} {short}\n"));
            }
        }
        emit(out.as_bytes());
        return Ok(());
    }
    if positional.len() > 2 {
        return Err(usage("branch", SYN));
    }
    let name = &positional[0];
    if !puregit::refs::is_valid_ref_name(&format!("refs/heads/{name}")) || name.starts_with('-') {
        return Err(format!("'{name}' is not a valid branch name").into());
    }
    if repo.refs().lookup(&format!("refs/heads/{name}")).is_ok() {
        return Err(format!("a branch named '{name}' already exists").into());
    }
    let start = match positional.get(1) {
        Some(s) => resolve_commit(&repo, s)
            .map_err(|_| Fail::Fatal(format!("not a valid object name: '{s}'")))?,
        None => repo
            .head_id()
            .map_err(|_| Fail::Fatal("not a valid object name: 'HEAD'".into()))?,
    };
    repo.create_branch(name, Some(start))?;
    Ok(())
}

/// Moves `HEAD` to `target` (a branch ref or a detached commit) and makes the
/// index and work tree match the target commit. Tracked files absent from the
/// target are removed.
fn switch_head(
    repo: &Repository,
    new_head: Reference,
    commit_id: &ObjectId,
    to_label: &str,
) -> CmdResult {
    let work = work_tree(repo, "checkout")?;
    let commit = read_commit(repo, commit_id)?;
    let new_map = puregit::walk::flatten_tree(repo.objects(), &commit.tree)?;
    let index = repo.index()?;
    for e in &index.entries {
        if !new_map.contains_key(&e.path) && safe_rel_path(&e.path) {
            let full = work.join(String::from_utf8_lossy(&e.path).as_ref());
            if std::fs::remove_file(&full).is_ok() {
                remove_empty_parents(&work, &full);
            }
        }
    }
    puregit::worktree::checkout_tree(repo, &commit.tree, &work)?;
    repo.read_tree(&commit.tree)?;

    let old = repo
        .head_id()
        .unwrap_or_else(|_| ObjectId::zero(repo.algo()));
    let from = match head_branch(repo) {
        Some(b) => shorten_ref(&b),
        None => old.to_hex(),
    };
    repo.refs().update("HEAD", &new_head)?;
    append_head_log(
        repo,
        &old,
        commit_id,
        &format!("checkout: moving from {from} to {to_label}"),
    )?;
    Ok(())
}

/// Appends an entry to `logs/HEAD` (git's reflog for `HEAD`).
fn append_head_log(repo: &Repository, old: &ObjectId, new: &ObjectId, msg: &str) -> CmdResult {
    let who = ident(repo, "COMMITTER")?;
    let line = format!(
        "{} {} {} <{}> {} {}\t{msg}\n",
        old.to_hex(),
        new.to_hex(),
        String::from_utf8_lossy(&who.name),
        String::from_utf8_lossy(&who.email),
        who.time,
        String::from_utf8_lossy(&who.tz),
    );
    let dir = repo.git_dir().join("logs");
    std::fs::create_dir_all(&dir)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("HEAD"))?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

/// The "<abbrev> <subject>" description of a commit.
fn one_line(repo: &Repository, id: &ObjectId) -> String {
    let subject = read_commit(repo, id)
        .map(|c| subject_of(&c.message))
        .unwrap_or_default();
    format!("{} {subject}", abbrev(repo, id))
}

/// Switches to an existing branch, printing git's messages to stderr.
fn switch_branch(repo: &Repository, name: &str, quiet: bool) -> CmdResult {
    let full = format!("refs/heads/{name}");
    let id = repo.refs().resolve(&full)?;
    let was_detached = head_branch(repo).is_none();
    let current = head_branch(repo);
    let prev = repo.head_id().ok();
    switch_head(repo, Reference::Symbolic(full.clone()), &id, name)?;
    if !quiet {
        if current.as_deref() == Some(full.as_str()) {
            eprintln!("Already on '{name}'");
        } else {
            if was_detached && let Some(p) = prev {
                eprintln!("Previous HEAD position was {}", one_line(repo, &p));
            }
            eprintln!("Switched to branch '{name}'");
        }
    }
    Ok(())
}

/// Detaches `HEAD` at `spec`, printing git's messages to stderr.
fn switch_detached(repo: &Repository, spec: &str, quiet: bool) -> CmdResult {
    let id = resolve_commit(repo, spec)?;
    let was_detached = head_branch(repo).is_none();
    let prev = repo.head_id().ok();
    switch_head(repo, Reference::Direct(id), &id, spec)?;
    if !quiet {
        if was_detached
            && let Some(p) = prev
            && p != id
        {
            eprintln!("Previous HEAD position was {}", one_line(repo, &p));
        }
        eprintln!("HEAD is now at {}", one_line(repo, &id));
    }
    Ok(())
}

/// Creates branch `name` at `start` (default `HEAD`) and switches to it.
fn switch_new(repo: &Repository, name: &str, start: Option<&str>, quiet: bool) -> CmdResult {
    if !puregit::refs::is_valid_ref_name(&format!("refs/heads/{name}")) {
        return Err(format!("'{name}' is not a valid branch name").into());
    }
    if repo.refs().lookup(&format!("refs/heads/{name}")).is_ok() {
        return Err(format!("a branch named '{name}' already exists").into());
    }
    let id = match start {
        Some(s) => resolve_commit(repo, s)?,
        None => repo.head_id()?,
    };
    repo.create_branch(name, Some(id))?;
    switch_head(
        repo,
        Reference::Symbolic(format!("refs/heads/{name}")),
        &id,
        name,
    )?;
    if !quiet {
        eprintln!("Switched to a new branch '{name}'");
    }
    Ok(())
}

fn cmd_checkout(args: &[String]) -> CmdResult {
    const SYN: &str =
        "checkout [<options>] <branch>\n   or: git checkout [<options>] [<branch>] -- <file>...";
    let mut quiet = false;
    let mut detach = false;
    let mut new_branch: Option<String> = None;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-q" | "--quiet" => quiet = true,
            "--detach" => detach = true,
            "-b" => {
                i += 1;
                new_branch = Some(args.get(i).ok_or_else(|| usage("checkout", SYN))?.clone());
            }
            s if s.starts_with('-') => return Err(unknown_option("checkout", s, SYN)),
            s => positional.push(s.to_string()),
        }
        i += 1;
    }
    let repo = open_here()?;
    if let Some(nb) = new_branch {
        return switch_new(&repo, &nb, positional.first().map(String::as_str), quiet);
    }
    let target = positional.first().cloned();
    if detach {
        return switch_detached(&repo, target.as_deref().unwrap_or("HEAD"), quiet);
    }
    let Some(target) = target else {
        return Ok(());
    };
    if repo.refs().lookup(&format!("refs/heads/{target}")).is_ok() {
        return switch_branch(&repo, &target, quiet);
    }
    if resolve(&repo, &target).is_ok_and(|id| peel_to(&repo, id, ObjectType::Commit).is_ok()) {
        return switch_detached(&repo, &target, quiet);
    }
    Err(Fail::Code(
        1,
        format!("error: pathspec '{target}' did not match any file(s) known to git"),
    ))
}

fn cmd_switch(args: &[String]) -> CmdResult {
    const SYN: &str = "switch [<options>] [<branch>]";
    let mut quiet = false;
    let mut detach = false;
    let mut create: Option<String> = None;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-q" | "--quiet" => quiet = true,
            "-d" | "--detach" => detach = true,
            "-c" | "--create" => {
                i += 1;
                create = Some(args.get(i).ok_or_else(|| usage("switch", SYN))?.clone());
            }
            s if s.starts_with('-') => return Err(unknown_option("switch", s, SYN)),
            s => positional.push(s.to_string()),
        }
        i += 1;
    }
    let repo = open_here()?;
    if let Some(nb) = create {
        return switch_new(&repo, &nb, positional.first().map(String::as_str), quiet);
    }
    let target = positional
        .first()
        .cloned()
        .ok_or_else(|| Fail::Fatal("missing branch or commit argument".into()))?;
    if detach {
        return switch_detached(&repo, &target, quiet);
    }
    if repo.refs().lookup(&format!("refs/heads/{target}")).is_ok() {
        return switch_branch(&repo, &target, quiet);
    }
    if resolve(&repo, &target).is_ok() {
        return Err(format!("a branch is expected, got '{target}'").into());
    }
    Err(format!("invalid reference: {target}").into())
}

/// `reset [--soft|--mixed|--hard] [-q] [<commit>]` — move the current branch to
/// `<commit>` (default `HEAD`); `--mixed` (default) also resets the index,
/// `--hard` also overwrites the working tree, `--soft` moves the ref only.
fn cmd_reset(args: &[String]) -> CmdResult {
    use puregit::repository::ResetMode;
    const SYN: &str = "reset [--mixed | --soft | --hard] [-q] [<commit>]";

    let mut mode = ResetMode::Mixed;
    let mut quiet = false;
    let mut target = None;
    for arg in args {
        match arg.as_str() {
            "--soft" => mode = ResetMode::Soft,
            "--mixed" => mode = ResetMode::Mixed,
            "--hard" => mode = ResetMode::Hard,
            "-q" | "--quiet" => quiet = true,
            other if other.starts_with('-') => return Err(unknown_option("reset", other, SYN)),
            other => target = Some(other.to_string()),
        }
    }
    let target = target.unwrap_or_else(|| "HEAD".to_string());

    let repo = open_here()?;
    let commit = resolve_commit(&repo, &target)?;
    repo.reset(mode, &commit)?;
    if quiet {
        return Ok(());
    }
    match mode {
        ResetMode::Hard => println!("HEAD is now at {}", one_line(&repo, &commit)),
        ResetMode::Mixed => {
            let st = puregit::status::status(&repo)?;
            if !st.unstaged.is_empty() {
                let mut out = String::from("Unstaged changes after reset:\n");
                for (p, c) in &st.unstaged {
                    let l = match c {
                        puregit::status::Change::Deleted => 'D',
                        _ => 'M',
                    };
                    out.push_str(&format!("{l}\t{}\n", quote_path(p)));
                }
                emit(out.as_bytes());
            }
        }
        ResetMode::Soft => {}
    }
    Ok(())
}

fn cmd_tag(args: &[String]) -> CmdResult {
    const SYN: &str = "tag [-a] [-f] [-m <msg>] <tagname> [<commit>]\n   or: git tag -d <tagname>...\n   or: git tag -l [<pattern>...]";
    let mut annotate = false;
    let mut delete = false;
    let mut force = false;
    let mut list = false;
    let mut messages = Vec::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-a" | "--annotate" => annotate = true,
            "-d" | "--delete" => delete = true,
            "-f" | "--force" => force = true,
            "-l" | "--list" => list = true,
            "-m" | "--message" => {
                i += 1;
                messages.push(args.get(i).ok_or_else(|| usage("tag", SYN))?.clone());
            }
            s if s.starts_with('-') => return Err(unknown_option("tag", s, SYN)),
            s => positional.push(s.to_string()),
        }
        i += 1;
    }
    let repo = open_here()?;
    if delete {
        let mut out = String::new();
        for name in &positional {
            let full = format!("refs/tags/{name}");
            let id = repo
                .refs()
                .resolve(&full)
                .map_err(|_| Fail::Code(1, format!("error: tag '{name}' not found.")))?;
            repo.refs().delete(&full)?;
            out.push_str(&format!(
                "Deleted tag '{name}' (was {})\n",
                abbrev(&repo, &id)
            ));
        }
        emit(out.as_bytes());
        return Ok(());
    }
    if positional.is_empty() || list {
        let mut out = String::new();
        for (name, _) in repo.refs().list()? {
            if let Some(short) = name.strip_prefix("refs/tags/") {
                out.push_str(&format!("{short}\n"));
            }
        }
        emit(out.as_bytes());
        return Ok(());
    }
    if positional.len() > 2 {
        return Err(usage("tag", SYN));
    }
    let name = &positional[0];
    let full = format!("refs/tags/{name}");
    if !puregit::refs::is_valid_ref_name(&full) {
        return Err(format!("'{name}' is not a valid tag name.").into());
    }
    if !force && repo.refs().lookup(&full).is_ok() {
        return Err(format!("tag '{name}' already exists").into());
    }
    let target = match positional.get(1) {
        Some(rev) => resolve_object(&repo, rev)?,
        None => repo
            .head_id()
            .map_err(|_| Fail::Fatal("Failed to resolve 'HEAD' as a valid ref.".into()))?,
    };
    let id = if annotate || !messages.is_empty() {
        if messages.is_empty() {
            return Err("puregit tag -a requires -m <message>".into());
        }
        let (ty, _) = read_raw(&repo, &target)?;
        let tag = Tag {
            object: target,
            object_type: ty,
            name: name.as_bytes().to_vec(),
            tagger: Some(ident(&repo, "COMMITTER")?),
            message: clean_message(&messages),
        };
        repo.write_object(ObjectType::Tag, &tag.serialize())?
    } else {
        target
    };
    repo.refs().update(&full, &Reference::Direct(id))?;
    Ok(())
}

fn cmd_ls_tree(args: &[String]) -> CmdResult {
    const SYN: &str = "ls-tree [<options>] <tree-ish> [<path>...]";
    let mut recursive = false;
    let mut show_trees = false;
    let mut only_trees = false;
    let mut name_only = false;
    let mut nul = false;
    let mut positional = Vec::new();
    for a in args {
        match a.as_str() {
            "-r" => recursive = true,
            "-t" => show_trees = true,
            "-d" => only_trees = true,
            "-z" => nul = true,
            "--name-only" | "--name-status" => name_only = true,
            s if s.starts_with('-') => return Err(unknown_option("ls-tree", s, SYN)),
            s => positional.push(s.to_string()),
        }
    }
    let [rev] = positional.as_slice() else {
        return Err(usage("ls-tree", SYN));
    };
    let repo = open_here()?;
    let id = resolve_object(&repo, rev)?;
    let tree = peel_to(&repo, id, ObjectType::Tree)
        .map_err(|_| Fail::Fatal("not a tree object".into()))?;
    let mut out = Vec::new();
    ls_tree_into(
        &repo,
        &tree,
        b"",
        &LsTreeOpts {
            recursive,
            show_trees,
            only_trees,
            name_only,
            nul,
        },
        &mut out,
    )?;
    emit(&out);
    Ok(())
}

struct LsTreeOpts {
    recursive: bool,
    show_trees: bool,
    only_trees: bool,
    name_only: bool,
    nul: bool,
}

fn ls_tree_into(
    repo: &Repository,
    tree: &ObjectId,
    prefix: &[u8],
    o: &LsTreeOpts,
    out: &mut Vec<u8>,
) -> CmdResult {
    let t = match repo.read_object(tree)? {
        Object::Tree(t) => t,
        _ => return Err("not a tree object".into()),
    };
    for e in &t.entries {
        let mut path = prefix.to_vec();
        path.extend_from_slice(&e.name);
        let is_tree = e.mode == FileMode::Tree;
        let descend = is_tree && o.recursive && !o.only_trees;
        let show = if o.only_trees {
            is_tree
        } else {
            !descend || o.show_trees
        };
        if show {
            let name = if o.nul {
                String::from_utf8_lossy(&path).into_owned()
            } else {
                quote_path(&path)
            };
            if !o.name_only {
                out.extend_from_slice(
                    format!("{:06o} {} {}\t", mode_num(e.mode), mode_kind(e.mode), e.id).as_bytes(),
                );
            }
            out.extend_from_slice(name.as_bytes());
            out.push(if o.nul { 0 } else { b'\n' });
        }
        if descend {
            let mut sub = path.clone();
            sub.push(b'/');
            ls_tree_into(repo, &e.id, &sub, o, out)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

/// Splits `section[.subsection].name` into its parts.
fn split_key(key: &str) -> Result<(String, Option<String>, String), Fail> {
    let first = key.find('.');
    let last = key.rfind('.');
    match (first, last) {
        (Some(f), Some(l)) if f > 0 && l + 1 < key.len() => {
            let section = key[..f].to_string();
            let name = key[l + 1..].to_string();
            let sub = if f == l {
                None
            } else {
                Some(key[f + 1..l].to_string())
            };
            Ok((section, sub, name))
        }
        _ => Err(Fail::Code(
            1,
            format!("error: key does not contain a section: {key}"),
        )),
    }
}

fn cmd_config(args: &[String]) -> CmdResult {
    const SYN: &str = "config [<options>] <name> [<value>]";
    let mut action = "auto";
    let mut positional = Vec::new();
    for a in args {
        match a.as_str() {
            "--get" => action = "get",
            "--get-all" => action = "get-all",
            "--unset" => action = "unset",
            "--add" => action = "add",
            "--local" => {}
            s if s.starts_with('-') => return Err(unknown_option("config", s, SYN)),
            s => positional.push(s.to_string()),
        }
    }
    let repo = open_here()?;
    let mut cfg = repo.config()?;
    let key = positional.first().ok_or_else(|| usage("config", SYN))?;
    let (section, sub, name) = split_key(key)?;
    let action = match (action, positional.len()) {
        ("auto", 1) => "get",
        ("auto", 2) => "set",
        (a, _) => a,
    };
    match action {
        "get" | "get-all" => {
            let values = cfg.get_all(&section, sub.as_deref(), &name);
            if values.is_empty() {
                return Err(Fail::Code(1, String::new()));
            }
            let mut out = String::new();
            if action == "get" {
                out.push_str(values[values.len() - 1]);
                out.push('\n');
            } else {
                for v in values {
                    out.push_str(v);
                    out.push('\n');
                }
            }
            emit(out.as_bytes());
            Ok(())
        }
        "set" => {
            let value = positional.get(1).ok_or_else(|| usage("config", SYN))?;
            cfg.set(&section, sub.as_deref(), &name, value);
            repo.write_config(&cfg)?;
            Ok(())
        }
        "unset" => {
            if cfg.get(&section, sub.as_deref(), &name).is_none() {
                return Err(Fail::Code(5, String::new()));
            }
            // Rebuild without the key (Config has no removal API).
            let text = cfg.serialize();
            let mut kept = puregit::config::Config::new();
            for (s, ss, n, v) in config_entries(&text) {
                let same = s.eq_ignore_ascii_case(&section)
                    && ss.as_deref() == sub.as_deref()
                    && n.eq_ignore_ascii_case(&name);
                if !same {
                    kept_push(&mut kept, &s, ss.as_deref(), &n, &v);
                }
            }
            repo.write_config(&kept)?;
            Ok(())
        }
        _ => Err(usage("config", SYN)),
    }
}

/// Appends a value to a config without replacing existing ones.
fn kept_push(cfg: &mut puregit::config::Config, s: &str, ss: Option<&str>, n: &str, v: &str) {
    let existing: Vec<String> = cfg
        .get_all(s, ss, n)
        .into_iter()
        .map(String::from)
        .collect();
    if existing.is_empty() {
        cfg.set(s, ss, n, v);
    } else {
        // Multi-valued: re-set by serializing through text.
        let mut text = cfg.serialize();
        let header = match ss {
            Some(sub) => format!("[{s} \"{sub}\"]\n"),
            None => format!("[{s}]\n"),
        };
        text.push_str(&header);
        text.push_str(&format!("\t{n} = {v}\n"));
        if let Ok(c) = puregit::config::Config::parse(&text) {
            *cfg = c;
        }
    }
}

/// The `(section, subsection, name, value)` entries of serialized config text.
fn config_entries(text: &str) -> Vec<(String, Option<String>, String, String)> {
    let mut out = Vec::new();
    let mut cur: Option<(String, Option<String>)> = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some(h) = l.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            cur = Some(match h.split_once(' ') {
                Some((s, ss)) => (s.to_string(), Some(ss.trim().trim_matches('"').to_string())),
                None => (h.to_string(), None),
            });
        } else if let (Some((s, ss)), Some((n, v))) = (&cur, l.split_once('=')) {
            out.push((
                s.clone(),
                ss.clone(),
                n.trim().to_string(),
                v.trim().to_string(),
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// History: reflog / merge / merge-base
// ---------------------------------------------------------------------------

/// `reflog [<ref>]` — print a ref's update log; `reflog expire [--expire=<secs>]
/// [<ref>]` — drop entries older than `<secs>` ago (default 90 days).
fn cmd_reflog(args: &[String]) -> CmdResult {
    if args.first().map(String::as_str) == Some("expire") {
        return cmd_reflog_expire(&args[1..]);
    }
    let refname = args.first().map(String::as_str).unwrap_or("HEAD");
    let repo = open_here()?;
    let full = if refname == "HEAD" {
        "HEAD".to_string()
    } else {
        dwim_ref_name(&repo, refname).unwrap_or_else(|| refname.to_string())
    };
    if !safe_ref_name(&full) {
        return Err(format!("invalid ref name '{refname}'").into());
    }
    let path = repo.git_dir().join("logs").join(&full);
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    // Entries are appended oldest-first; git numbers them newest-first as @{0}.
    let lines: Vec<&str> = content.lines().collect();
    let mut out = String::new();
    for (i, line) in lines.iter().rev().enumerate() {
        let Some((meta, message)) = line.split_once('\t') else {
            continue;
        };
        let new = meta.split_whitespace().nth(1).unwrap_or("");
        let short = match ObjectId::from_hex(repo.algo(), new) {
            Ok(id) => abbrev(&repo, &id),
            Err(_) => new.to_string(),
        };
        out.push_str(&format!("{short} {refname}@{{{i}}}: {message}\n"));
    }
    emit(out.as_bytes());
    Ok(())
}

/// `reflog expire [--expire=<seconds>] [<ref>]` — drop entries in `logs/<ref>`
/// older than `<seconds>` ago (default 90 days), matching `git reflog expire`.
fn cmd_reflog_expire(args: &[String]) -> CmdResult {
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
    let removed = repo.reflog_expire(&refname, now - seconds)?;
    eprintln!(
        "reflog expire: dropped {removed} entr{}",
        if removed == 1 { "y" } else { "ies" }
    );
    Ok(())
}

fn cmd_merge(args: &[String]) -> CmdResult {
    use puregit::merge::MergeOutcome;
    let branch = args.first().ok_or_else(|| usage("merge", "<branch>"))?;
    let repo = open_here()?;
    let their = resolve_commit(&repo, branch)?;

    let msg = format!("Merge branch '{branch}'\n");
    match repo.merge(
        &their,
        ident(&repo, "AUTHOR")?,
        ident(&repo, "COMMITTER")?,
        msg.as_bytes(),
    )? {
        MergeOutcome::AlreadyUpToDate => println!("Already up to date."),
        MergeOutcome::FastForward(id) => println!("Fast-forward to {}", abbrev(&repo, &id)),
        MergeOutcome::Merged(id) => println!(
            "Merge made by the 'three-way' strategy: {}",
            abbrev(&repo, &id)
        ),
        MergeOutcome::Conflicts(paths) => {
            let mut out = String::new();
            for p in paths {
                out.push_str(&format!(
                    "CONFLICT (content): Merge conflict in {}\n",
                    quote_path(&p)
                ));
            }
            out.push_str("Automatic merge failed; fix conflicts and then commit the result.\n");
            emit(out.as_bytes());
            return Err(Fail::Code(1, String::new()));
        }
    }
    Ok(())
}

fn cmd_merge_base(args: &[String]) -> CmdResult {
    const SYN: &str = "merge-base [-a | --all] <commit> <commit>...\n   or: git merge-base --is-ancestor <commit> <commit>";
    let mut is_ancestor = false;
    let mut positional = Vec::new();
    for a in args {
        match a.as_str() {
            "--is-ancestor" => is_ancestor = true,
            s if s.starts_with('-') => return Err(unknown_option("merge-base", s, SYN)),
            s => positional.push(s.to_string()),
        }
    }
    if positional.len() != 2 {
        return Err(usage("merge-base", SYN));
    }
    let repo = open_here()?;
    let resolve_c = |spec: &str| -> Result<ObjectId, Fail> {
        let id = resolve_object(&repo, spec)?;
        peel_to(&repo, id, ObjectType::Commit)
            .map_err(|_| Fail::Fatal(format!("Not a valid commit name {spec}")))
    };
    let a = resolve_c(&positional[0])?;
    let b = resolve_c(&positional[1])?;

    if is_ancestor {
        // `--is-ancestor <a> <b>`: exit 0 if a is an ancestor of b, else 1 —
        // no output, matching git.
        return if puregit::walk::is_ancestor(repo.objects(), &a, &b)? {
            Ok(())
        } else {
            Err(Fail::Code(1, String::new()))
        };
    }

    match puregit::walk::merge_base(repo.objects(), &a, &b)? {
        Some(base) => {
            println!("{base}");
            Ok(())
        }
        // git prints nothing and exits 1 when there is no common ancestor.
        None => Err(Fail::Code(1, String::new())),
    }
}

// ---------------------------------------------------------------------------
// LFS
// ---------------------------------------------------------------------------

fn cmd_lfs(args: &[String]) -> CmdResult {
    use puregit::lfs::Pointer;
    let sub = args.first().map(String::as_str).unwrap_or("");
    let repo = open_here()?;
    match sub {
        "track" => {
            let pattern = args.get(1).ok_or("lfs track: missing <pattern>")?;
            repo.lfs_track(pattern)?;
            println!("Tracking \"{pattern}\"");
            Ok(())
        }
        "ls-files" => {
            let index = repo.index()?;
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
        other => Err(format!("lfs: unknown subcommand '{other}' (try track|ls-files|pull)").into()),
    }
}

#[cfg(feature = "http")]
fn cmd_lfs_pull(repo: &Repository) -> CmdResult {
    use puregit::lfs::batch::Operation;
    use puregit::lfs::transfer::LfsClient;

    let url = repo
        .config()?
        .get("remote", Some("origin"), "url")
        .map(String::from)
        .ok_or("lfs pull: no remote.origin.url configured")?;
    let client = LfsClient::new(LfsClient::endpoint_from_remote(&url));

    let n = repo.lfs_smudge_worktree(|p| {
        let results = client.batch(Operation::Download, std::slice::from_ref(p))?;
        let action = results
            .first()
            .and_then(|r| r.download.as_ref())
            .ok_or_else(|| puregit::Error::Protocol("lfs pull: no download action".into()))?;
        client.download(p, action)
    })?;
    println!("Downloaded {n} LFS object(s).");
    Ok(())
}

#[cfg(not(feature = "http"))]
fn cmd_lfs_pull(_repo: &Repository) -> CmdResult {
    Err("lfs pull: this build lacks the `http` feature".into())
}

// ---------------------------------------------------------------------------
// Maintenance: gc / fsck / prune / commit-graph / multi-pack-index / worktree
// ---------------------------------------------------------------------------

fn cmd_gc(_args: &[String]) -> CmdResult {
    let mut repo = open_here()?;
    let n = repo.repack()?;
    println!("Packed {n} loose object(s).");
    Ok(())
}

/// `fsck` — verify object connectivity and integrity. Prints each missing or
/// malformed object and each dangling loose object (`dangling <type> <id>`,
/// as git does), and exits non-zero if any integrity problem (not merely
/// dangling) was found.
fn cmd_fsck(_args: &[String]) -> CmdResult {
    let repo = open_here()?;
    let report = puregit::fsck::fsck(&repo)?;

    let mut out = String::new();
    for p in &report.problems {
        match &p.referenced_by {
            Some(parent) => out.push_str(&format!(
                "{} ({}, referenced by {parent})\n",
                p.message, p.id
            )),
            None => out.push_str(&format!("{} ({})\n", p.message, p.id)),
        }
    }
    for id in &report.dangling {
        let ty = read_raw(&repo, id)
            .map(|(t, _)| t.as_str())
            .unwrap_or("object");
        out.push_str(&format!("dangling {ty} {id}\n"));
    }
    emit(out.as_bytes());
    if report.is_ok() {
        Ok(())
    } else {
        Err(Fail::Code(
            2,
            format!(
                "error: {} integrity problem(s) found",
                report.problems.len()
            ),
        ))
    }
}

/// `commit-graph write|verify` — write the `objects/info/commit-graph` cache
/// (covering all commits reachable from refs/HEAD) or parse-and-verify it.
fn cmd_commit_graph(args: &[String]) -> CmdResult {
    let sub = args.first().map(String::as_str).unwrap_or("write");
    let repo = open_here()?;
    match sub {
        "write" => {
            let n = repo.write_commit_graph()?;
            eprintln!("commit-graph: wrote {n} commit(s)");
            Ok(())
        }
        "verify" => {
            let path = repo.git_dir().join("objects/info/commit-graph");
            let data = std::fs::read(&path).map_err(|e| format!("reading commit-graph: {e}"))?;
            let g = puregit::commit_graph::CommitGraph::parse(repo.algo(), &data)?;
            eprintln!("commit-graph: OK, {} commit(s)", g.len());
            Ok(())
        }
        other => Err(format!("commit-graph: unknown subcommand '{other}'").into()),
    }
}

/// `multi-pack-index write|verify` — write `objects/pack/multi-pack-index`
/// covering every `.idx`, or parse-and-verify it.
fn cmd_multi_pack_index(args: &[String]) -> CmdResult {
    let sub = args.first().map(String::as_str).unwrap_or("write");
    let repo = open_here()?;
    match sub {
        "write" => {
            let n = repo.write_multi_pack_index()?;
            eprintln!("multi-pack-index: wrote an index over {n} pack(s)");
            Ok(())
        }
        "verify" => {
            let path = repo.git_dir().join("objects/pack/multi-pack-index");
            let data =
                std::fs::read(&path).map_err(|e| format!("reading multi-pack-index: {e}"))?;
            let m = puregit::multi_pack_index::MultiPackIndex::parse(repo.algo(), &data)?;
            eprintln!(
                "multi-pack-index: OK, {} object(s) over {} pack(s)",
                m.len(),
                m.pack_names().len()
            );
            Ok(())
        }
        other => Err(format!("multi-pack-index: unknown subcommand '{other}'").into()),
    }
}

/// `worktree add <path> [<commit>]` — create a linked worktree checked out at
/// `<commit>` (default `HEAD`); `worktree list` — list linked worktrees.
fn cmd_worktree(args: &[String]) -> CmdResult {
    let repo = open_here()?;
    match args.first().map(String::as_str) {
        Some("add") => {
            let path = args.get(1).ok_or("worktree add: missing <path>")?;
            let commit = match args.get(2) {
                Some(rev) => resolve_commit(&repo, rev)?,
                None => repo.head_id()?,
            };
            repo.add_worktree(Path::new(path), &commit)?;
            println!("Prepared worktree at {path} ({})", abbrev(&repo, &commit));
            Ok(())
        }
        Some("list") | None => {
            // The main working tree first, then the linked ones.
            if let (Some(work), Ok(head)) = (repo.work_tree(), repo.head_id()) {
                println!("{}  {}", work.display(), abbrev(&repo, &head));
            }
            for (name, id) in repo.worktrees()? {
                println!("worktrees/{name}  {}", abbrev(&repo, &id));
            }
            Ok(())
        }
        Some(other) => Err(format!("worktree: unknown subcommand '{other}'").into()),
    }
}

fn cmd_prune(_args: &[String]) -> CmdResult {
    let mut repo = open_here()?;
    let n = repo.prune()?;
    println!("Pruned {n} unreachable loose object(s).");
    Ok(())
}

/// `verify-pack <packfile>` — validate a pack against its `.idx`. The index path
/// is derived by swapping the `.pack` suffix for `.idx`. Runs in a repository so
/// bases of a thin pack can be resolved from the object store.
fn cmd_verify_pack(args: &[String]) -> CmdResult {
    let pack_path = args
        .first()
        .ok_or_else(|| usage("verify-pack", "<pack>.idx..."))?;
    let pack_path = match pack_path.strip_suffix(".idx") {
        Some(stem) => format!("{stem}.pack"),
        None => pack_path.clone(),
    };
    let idx_path = match pack_path.strip_suffix(".pack") {
        Some(stem) => format!("{stem}.idx"),
        None => format!("{pack_path}.idx"),
    };
    let pack = std::fs::read(&pack_path).map_err(|e| format!("reading {pack_path}: {e}"))?;
    let idx = std::fs::read(&idx_path).map_err(|e| format!("reading {idx_path}: {e}"))?;

    let repo = open_here()?;
    let resolver = |id: &ObjectId| repo.objects().read(id);
    let v = puregit::pack::verify_pack(&pack, &idx, repo.algo(), &resolver)?;

    for p in &v.problems {
        println!("{p}");
    }
    if v.is_ok() {
        eprintln!("verify-pack: {} object(s) ok", v.objects);
        Ok(())
    } else {
        Err(format!("{} problem(s) found", v.problems.len()).into())
    }
}

/// `unpack-objects [-q] [<pack>]` — explode a packfile into loose objects. Like
/// git, the pack is read from stdin; a path argument is accepted as a
/// convenience.
fn cmd_unpack_objects(args: &[String]) -> CmdResult {
    let mut quiet = false;
    let mut path = None;
    for a in args {
        match a.as_str() {
            "-q" => quiet = true,
            "-n" | "--strict" => {}
            s if s.starts_with('-') => {
                return Err(usage("unpack-objects", "[-n] [-q] [-r] [--strict]"));
            }
            s => path = Some(s.to_string()),
        }
    }
    let pack = match &path {
        Some(p) => std::fs::read(p).map_err(|e| format!("reading {p}: {e}"))?,
        None => {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
            buf
        }
    };
    let repo = open_here()?;
    let ids = repo.ingest_pack(&pack)?;
    if !quiet {
        eprintln!("Unpacking objects: 100% ({0}/{0}), done.", ids.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roff_escapes_backslashes_and_leading_control() {
        assert_eq!(roff_escape("a\\b"), "a\\\\b");
        // A line starting with a roff control char is neutralised with \&.
        assert_eq!(roff_escape(".hidden"), "\\&.hidden");
        assert_eq!(roff_escape("'quote"), "\\&'quote");
        assert_eq!(roff_escape("plain"), "plain");
    }

    #[test]
    fn manpage_has_required_roff_sections() {
        let man = manpage();
        assert!(man.starts_with(".TH PUREGIT 1 "));
        for section in [
            ".SH NAME",
            ".SH SYNOPSIS",
            ".SH DESCRIPTION",
            ".SH COMMANDS",
            ".SH EXIT STATUS",
        ] {
            assert!(man.contains(section), "man page missing {section}");
        }
        // The command table is derived from USAGE, so a known command appears.
        assert!(man.contains(".B init"));
        // Exit-status parity is documented.
        assert!(man.contains(".B 128"));
        assert!(man.contains(".B 129"));
    }

    #[test]
    fn dates_round_trip() {
        let (t, tz) = parse_date("2005-04-07T22:13:13 +0200").unwrap();
        assert_eq!((t, tz.as_slice()), (1_112_904_793, b"+0200".as_slice()));
        assert_eq!(parse_date("@1700000000 +0000").unwrap().0, 1_700_000_000);
        let sig = Signature {
            name: vec![],
            email: vec![],
            time: 1_700_000_000,
            tz: b"+0000".to_vec(),
        };
        assert_eq!(fmt_date(&sig), "Tue Nov 14 22:13:20 2023 +0000");
        assert_eq!(fmt_date_iso(&sig), "2023-11-14 22:13:20 +0000");
    }

    #[test]
    fn quoting_matches_git() {
        assert_eq!(quote_path(b"plain name.txt"), "plain name.txt");
        assert_eq!(quote_path("caf\u{e9}".as_bytes()), "\"caf\\303\\251\"");
        assert_eq!(quote_path(b"a\"b\\c\td"), "\"a\\\"b\\\\c\\td\"");
    }

    #[test]
    fn message_cleanup() {
        assert_eq!(
            clean_message(&["subject".into(), "body  ".into()]),
            b"subject\n\nbody\n"
        );
        assert_eq!(clean_message(&["\n\nx\n\n\n".into()]), b"x\n");
    }
}
