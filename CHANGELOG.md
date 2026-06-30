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
