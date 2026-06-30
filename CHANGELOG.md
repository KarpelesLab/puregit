# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  - A `git` CLI with `init`, `hash-object`, `cat-file`, and `rev-parse`.
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
