# puregit

A pure-Rust implementation of git, written from scratch in the spirit of
`libgit2` — the object model, packfiles, references, the staging index, and the
*smart* transfer protocol, as both a **client and a server**, over **HTTP and
SSH**.

puregit is built on the same first-party, no-C-toolchain foundation as its
sibling crates:

- **[`purecrypto`](https://crates.io/crates/purecrypto)** — SHA-1 / SHA-256 for
  object names (and, later, commit/tag signing).
- **[`compcol`](https://crates.io/crates/compcol)** — zlib for loose objects and
  packfiles.
- **[`puressh`](../puressh)** — the SSH transport.
- **[`rsurl`](../rsurl)** — the HTTP(S) transport.

There is **no C in the dependency tree** and **no `*-sys` crate** — the whole
stack compiles with nothing but a Rust toolchain.

## Design: a `no_std` core and a `std` shell

The crate is split so the engine that manipulates git data is portable and the
parts that touch a socket, a clock, or the real filesystem are isolated behind
features:

```
┌─────────────────────────────────────────────────────────────┐
│ std shell (feature `std`)                                    │
│   vfs::StdFs · Repository · worktree · transport::{http,ssh} │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ no_std + alloc core                                          │
│   oid · hash · object · odb · pack · refs · index · config   │
│   protocol (pkt-line · capabilities · fetch/push negotiation)│
└─────────────────────────────────────────────────────────────┘
```

The core is `#![no_std]` (with `alloc`); it never names `std`. Filesystem
access goes through the [`Vfs`](src/vfs/mod.rs) trait, so the same repository
logic runs over the real disk ([`StdFs`](src/vfs/std_impl.rs)), an in-memory
store, or any custom backend. The wire protocols are **sans-IO** — the
negotiation layer transforms byte buffers and the transport owns the socket,
the same architecture as `puressh` and `rsurl`.

## What works today

**puregit clones real repositories from GitHub over HTTPS**, and round-trips
clone / fetch / push over an in-process transport — the object engine,
protocol, client, and server all work end to end and are byte-compatible with
canonical git (puregit-created history passes `git fsck`; a real GitHub clone
matches git's HEAD, history, and checkout exactly).

- **Object engine** — SHA-1 / SHA-256 ids; blob/tree/commit/tag parse +
  serialize (signed commits and annotated tags round-trip byte-for-byte); the
  combined loose + packed object database with delta resolution across backends.
- **Packfiles** — read (random access + delta chains, v2 `.idx`), write
  (`PackWriter` + `.idx` generation), and ingest a received pack with no index
  (`explode_pack`) — verified against real `git repack` output.
- **Reachability** — object-graph closure, the fetch/push object set, and a
  commit `RevWalk`.
- **References / index / config** — loose + `packed-refs` + symrefs; the `DIRC`
  v2/v3 index with `write-tree`; the `.git/config` INI format.
- **Local porcelain** — `init`, `add`, `commit`, `log`, working-tree checkout.
- **Networking** — smart-HTTP(S) over `rsurl` (clones GitHub) and SSH over
  `puressh` (password auth today); client `fetch`/`clone`/`push` and server
  `upload-pack`/`receive-pack` driving the sans-IO protocol core.
- **`git` CLI** — `init`, `hash-object`, `cat-file`, `rev-parse`, `add`,
  `write-tree`, `commit`, `log`, `unpack-objects`, `clone`.

The long tail — SSH key/agent auth, multi-round negotiation + sideband,
protocol v2, more porcelain (`status`/`branch`/`checkout`/`diff`/`merge`), and
maintenance (`repack`/`gc`) — is the focus of the [roadmap](ROADMAP.md).

## Usage

```rust
use puregit::{Repository, object::ObjectType};

let repo = Repository::init("/tmp/demo")?;
let id = repo.write_object(ObjectType::Blob, b"hello\n")?;
println!("{id}"); // ce013625030ba8dba906f756967f9e9ca394464a
let blob = repo.read_object(&id)?;
# Ok::<(), puregit::Error>(())
```

```console
$ git init demo && cd demo
$ printf 'hello\n' > a.txt
$ git add a.txt && git commit -m "first commit"
committed 9b2c8e…
$ git log

# clone a real repository over HTTPS (pure-Rust TLS, no C):
$ git clone https://github.com/octocat/Hello-World.git
Cloned into 'Hello-World' (HEAD 7fd1a60b)
```

## Features

| Feature   | Default | Description                                              |
|-----------|:-------:|----------------------------------------------------------|
| `std`     |   ✓     | Standard library: `StdFs`, `Repository`, worktree, I/O   |
| `client`  |   ✓     | Client-side porcelain/plumbing (local + fetch/push driver)|
| `server`  |         | `upload-pack` / `receive-pack` request handlers          |
| `http`    |         | Smart-HTTP(S) transport over `rsurl`                      |
| `ssh`     |         | SSH transport over `puressh`                             |

Build the `no_std` core with `--no-default-features` (an allocator is still
required). `--features full` turns on everything.

## License

Licensed under either of MIT or Apache-2.0 at your option.
