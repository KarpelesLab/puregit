# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2](https://github.com/KarpelesLab/puregit/compare/v0.0.1...v0.0.2) - 2026-10-18

### Fixed

- *(transport)* retry reads/requests interrupted by a signal (EINTR)
- *(client)* clone writes the index; filter cap; HTTP v2 push/sha256/deepen
- *(server)* git-compatible upload-pack negotiation, shallow, include-tag, atomic
- *(protocol)* parse v1/peeled adverts, deepen-since/not/relative, v2 unshallow
- *(cli)* keep Windows separators in a local clone's origin URL
- *(init)* write core.symlinks=false off Unix
- *(config)* read and write git's value quoting and escapes
- *(cli)* make the puregit CLI output and exit codes git-compatible
- *(diff)* emit git's hunk header ranges
- *(worktree)* checkout/reset --hard/merge keep index and work tree in sync
- *(status,add)* stage symlinks as links, compare modes, honor intent-to-add
- *(commit-graph)* git's generation/date bit layout and octopus EDGE parents
- *(walk)* pick the best merge base and walk history in git's date order
- *(index)* read/write v4, keep extended flags, honor skipHash, drop stale cache-tree
- *(pack)* resolve delta chains iteratively and accept git's deep chains

### Other

- *(interop)* faster fixtures, no TCP half-close, skip git daemon client on Windows
- *(interop)* wire-protocol interop against the real git CLI
- *(interop)* model symlinks the Git for Windows way off Unix
- exclude interop/ from the published package
- run the libgit2 interop harness on Linux, macOS and Windows
- *(interop)* libgit2 interop harness in interop/libgit2
- *(interop)* CLI parity tests against the real git binary
- *(interop)* on-disk format interop against the real git CLI, both directions
- require git for interop tests
- relicense under MIT only
- add CI, crates.io, docs.rs and license badges
- keep test fixtures byte-exact on Windows

### Added

- Initial scaffold of the pure-Rust git engine.
  - `no_std + alloc` core: object ids (SHA-1/SHA-256), the blob/tree/commit/tag
    object model, loose + in-memory object databases, zlib compression over
    `compcol`, packfile reading with `OFS_DELTA`/`REF_DELTA` resolution and v2
    `.idx` lookup, references (loose + `packed-refs` + symrefs), the `DIRC`
    staging index, the git config parser, and the sans-IO smart protocol
    (pkt-line, capabilities, ref advertisement, fetch request).
  - `std` shell: the `Vfs` trait and its `StdFs` backend, `Repository`
    (`init`/`open`, object I/O, `HEAD`, config/index), and worktree checkout.
  - Feature-gated scaffolds for the HTTP (`rsurl`) and SSH (`puressh`)
    transports and the `upload-pack`/`receive-pack` server handlers.
  - A `puregit` CLI (git-compatible front end) with `init`, `hash-object`, `cat-file`, and `rev-parse`.
- Project `README.md` and a milestone-based `ROADMAP.md`.
- Combined loose + packed object database with cross-backend delta resolution;
  reachability/`RevWalk`; pack writing (`PackWriter` + `.idx`) and pack ingest
  (`explode_pack`); `write-tree` from the index.
- Local porcelain: `Repository::add_path` / `commit`, and CLI `add` /
  `write-tree` / `commit` / `log` / `unpack-objects`. Output is byte-compatible
  with canonical git (passes `git fsck`).
- Smart transfer protocol: `upload_pack` and `receive_pack` server handlers, a
  client `fetch` / `clone` / `push`, and an in-process `LocalTransport`.
- Smart-HTTP(S) transport over `rsurl` — clones real repositories from GitHub
  over HTTPS (pure-Rust TLS). CLI `git clone <url>`.
- SSH transport over `puressh` (single owned exec channel; strict
  `known_hosts`; password auth). CLI `clone` routes `ssh://` and scp-style URLs.
- Fixed an `inflate_capped` infinite loop (compcol's capped decoder spins at the
  exact-size cap with trailing pack bytes); reimplemented with a bounded
  scratch-buffer loop, plus `inflate_exact` for packfile iteration.
