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

The local object engine is functional end to end:

- **Object ids** — SHA-1 and SHA-256, hex/binary, with the well-known
  empty-blob / `hello\n` vectors covered by tests.
- **Objects** — blob, tree, commit, and tag parsing and serialization
  (round-tripping signed commits and annotated tags byte-for-byte).
- **Object database** — loose objects (`objects/ab/cdef…`, zlib) over the VFS,
  plus an in-memory backend; integrity-checked on read.
- **Packfiles** — `.pack` random access with full `OFS_DELTA` / `REF_DELTA`
  resolution, and v2 `.idx` id→offset lookup.
- **References** — name validation, loose + `packed-refs`, symbolic-ref
  resolution, and a VFS-backed store.
- **Index** — the `DIRC` v2/v3 staging index, read and written with checksum
  verification.
- **Config** — the `.git/config` (INI) format.
- **Protocol** — pkt-line framing, the capability set, ref-advertisement
  parsing, and the `want`/`have` fetch request builder.
- **Repository** — `init`/`open`, object read/write, `HEAD` resolution, config
  and index access, and working-tree checkout of a tree.
- **`git` CLI** — `init`, `hash-object [-w]`, `cat-file -t|-p|-s`, `rev-parse`.

The HTTP/SSH transports and the fetch/push/clone porcelain and server handlers
are scaffolded behind their feature flags and are the focus of the
[roadmap](ROADMAP.md).

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
$ git hash-object -w a.txt
ce013625030ba8dba906f756967f9e9ca394464a
$ git cat-file -p ce013625030ba8dba906f756967f9e9ca394464a
hello
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
