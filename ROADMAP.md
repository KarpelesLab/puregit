# puregit roadmap

The goal: a pure-Rust git that can **maintain a repository**, **fetch/clone and
push** as a client, and **serve** fetch and push as a server, over both **HTTP**
and **SSH** — keeping the defining constraints intact.

**Invariants (never traded away):**

- **No C toolchain / no `*-sys` crates.** Pure-Rust dependencies only
  (`purecrypto`, `compcol`, `puressh`, `rsurl`). This is the whole point of the
  stack and gates every dependency decision.
- **`no_std + alloc` core.** The object/pack/ref/protocol engine never names
  `std`. Filesystem and network live behind the `std` feature and the [`Vfs`]
  trait; the wire protocols stay sans-IO.
- **Correctness verified against real git.** Object ids, pack/index decoding,
  index checksums, and ref formats are checked against git's own output and
  byte-for-byte round-trips. CI gate: build (default, `no_std`, `full`),
  `clippy -D warnings`, `fmt`, doc, and tests.

---

## Status

The core arc — clone / fetch / push / serve over HTTP, SSH, and `git://`, the
full local workflow (`add`/`rm`/`commit`/`status`/`branch`/`checkout`/`merge`/
`diff`/`gc`), and Git LFS — is implemented and validated against canonical git
(puregit-created history passes `git fsck`; a real `git clone` from GitHub over
pure-Rust TLS matches git byte-for-byte). **This roadmap tracks the remaining
work only** — everything below is planned (⬜).

---

## Milestone 3 — Smart protocol core (sans-IO)

- **v0/v1 negotiation — done.**

  **v0/v1 multi-round negotiation is done** — both ACK modes (`multi_ack`,
  `multi_ack_detailed`). The server advertises them and answers a negotiation
  round (a `have` batch with no `done`) with `ACK <oid> common`/`ready` (detailed)
  or `ACK <oid> continue` (multi_ack), or `NAK` when nothing is common, deferring
  the pack to the `done` request — which now acknowledges the last common object
  (`ACK <oid>`) so a negotiating peer records the common base. The client drives
  it (`client::fetch_negotiated`): it offers local history in `have` batches until
  the server signals `ready`, then finishes with `done`. Verified end to end:
  real `git fetch` (incremental, over both the `git://` daemon and smart-HTTP)
  finds the common commits and pulls only the delta, `git fsck` clean; a puregit
  loopback fetch truncates the pack to the new objects; a wire-format test pins
  the `ACK`/`NAK` output. The plain single-round `fetch` (all ref tips as `have`
  + `done`) stays the default — already optimal when the haves are just the tips.

  `side-band-64k` demuxing and `shallow`/`deepen` **serving**
  are done — the client negotiates sideband and reassembles a multiplexed pack,
  and the server answers a `deepen` request (v0/v1 and v2) with the shallow
  boundary and a depth-truncated pack: a real `git clone --depth N` from puregit
  (both protocols) produces a correct shallow repository that passes `git fsck`.
  Client-side shallow (puregit issuing `--depth` and writing `.git/shallow`) is
  done (see M8).
- ⬜ **Protocol v2 — remaining advanced features**: `packfile-uris` (offload
  pack download to URLs) and multi-round v2 negotiation. `filter` (partial clone)
  and `ref-in-want` are done — the v2 server advertises `fetch=shallow filter
  ref-in-want`, resolves each `want-ref <name>` to its id, and echoes a
  `wanted-refs` section before the pack. The core v2 path is done (see below).

  **Protocol v2 is implemented, client and server** (`protocol::v2`). Server:
  `serve_v2_upload_pack` handles `ls-refs` (with `symrefs`/`peel`/`ref-prefix`)
  and `fetch` (single-round `done`, plus an `acknowledgments` round), framing the
  pack in the v2 `packfile` section over sideband; the HTTP handler serves the v2
  capability advertisement and dispatch on `Git-Protocol: version=2`. Client: the
  HTTP transport offers `version=2` at discovery, and on a v2 server drives
  `ls-refs` then `fetch`, demuxing the `packfile` section — transparently, so
  `clone`/`fetch` are unchanged. Verified end to end: a real
  `git -c protocol.version=2 clone` from puregit passes `git fsck`, the puregit
  client clones a puregit v2 server over HTTP, and v0/v1 peers still work.


## Milestone 8 — Repository maintenance

  **Transparent promisor fetch is done**: `client::backfill_tree` scans a tree
  for the objects a partial clone is missing
  ([`walk::missing_tree_objects`](src/walk.rs) — descending only as far as the
  present objects allow, so a newly-fetched subtree's children surface on the
  next round), fetches them in batched rounds via `fetch_objects`, and repeats
  until the closure is complete; `client::checkout_tree` wires that ahead of the
  worktree materialization, so a `--filter`ed clone checks out with no explicit
  backfill call. The transport stays a caller-supplied parameter — the sans-IO
  core holds no network handle. Verified by a loopback test: a `blob:none`
  partial clone (spanning a subdirectory) checks out to the correct working tree
  with every blob auto-fetched, plus a `no_std` unit test of the missing-object
  scan across nested subtrees.

  The client half of partial clone is otherwise done: `fetch_with_filter` issues
  a `--filter` fetch (the server omits the filtered objects), and `fetch_objects`
  backfills specific objects on demand — the server sends an explicitly-wanted
  object even when it is reachable from a `have`. Verified by a loopback test: a
  `blob:none` fetch omits the blob, and `fetch_objects` retrieves it with the
  correct content.

  **Deepen / unshallow is done** (client and server, v0/v1 and v2). The server
  plans a deepen against the client's current shallow boundary — sending only the
  newly-reached objects, announcing the new boundary, and `unshallow`ing commits
  whose ancestors now arrive — and never offers a thin-pack base a shallow client
  cannot resolve. The client applies the `shallow`/`unshallow` updates to
  `.git/shallow` and re-requests the tips when deepening. Verified: a real
  `git fetch --unshallow` of a puregit `--depth 1` clone restores full history
  (`is-shallow-repository` false, `git fsck` clean), and a hermetic loopback test
  covers a puregit client deepening depth 1 → 2.

  **Serving partial (`filter`) clones is done**: the server parses `filter`
  (`blob:none`, `blob:limit=<n>`), advertises it (v0/v1 `filter`, v2
  `fetch=filter`), and omits the filtered blobs from the pack — while always
  sending an *explicitly-wanted* object, so a promisor client's lazy blob
  re-fetch (which re-sends the filter yet names the blob) is served. Verified end
  to end: a real `git clone --filter=blob:none` from puregit produces a promisor
  clone whose checkout lazily fetches the blobs and passes `git fsck`.

  **Client-side shallow clone is done**: `clone_with_depth` / `fetch_with_depth`
  send `deepen <n>`, record the server's boundary in `.git/shallow`
  ([`Repository::write_shallow`]/[`shallow`](src/repository.rs)), and ingest the
  truncated pack — over v0/v1 and v2 alike. Verified: a puregit `--depth 1` clone
  of a puregit server produces a repository real `git` recognises as shallow
  (`is-shallow-repository` true, one commit, `git fsck` clean); a hermetic
  loopback test confirms the older history is truncated. Serving shallow clones
  is done (M3); alternates and worktrees are done.

  **Reachability bitmaps are done**: `pack::ewah` (an EWAH codec validated
  byte-identical to git) and `pack::bitmap` write a git-compatible reachability
  `.bitmap` and its `.rev`, and `Repository::repack_with_bitmap` packs the full
  reachable closure and emits them. Verified end to end: `git rev-list
  --test-bitmap HEAD` reports `OK!` — verifying every entry — on a repository
  puregit built and bitmapped, across linear and merge histories, `git fsck`
  clean.

## Milestone 9 — Compatibility & ecosystem polish

- ⬜ **PGP — remaining**: keyring management (puregit deliberately manages no
  keyring — the caller supplies the key to [`verify_pgp`] and
  [`sign_pgp_ed25519`]). OpenPGP **EdDSA**, **RSA**, and **ECDSA** *verification*
  and OpenPGP EdDSA *signature creation* are done.

  **Signing/verification are otherwise done** (`signing` feature):
  - *OpenPGP EdDSA, RSA & ECDSA verify* — `verify_pgp` de-armors the block,
    parses the v4 OpenPGP signature packet and its MPIs, rebuilds the signed
    digest, and checks it with `purecrypto` — Ed25519 for EdDSA, PKCS#1 v1.5
    (SHA-256/512) for RSA, and NIST P-256/384/521 for ECDSA. Verified against
    real `git commit -S` GnuPG Ed25519, RSA-2048, **and** ECDSA (nistp256)
    signatures (tamper and wrong-key rejected); committed fixtures keep all
    three green.
  - *OpenPGP EdDSA sign* — `sign_pgp_ed25519` / `sign_commit_pgp_ed25519` build
    a v4 binary-document signature packet (creation-time + issuer subpackets,
    MPI-encoded R/S, CRC-24 armor) a private key never leaves puregit for.
    Verified end to end: a puregit-signed commit passes real `git verify-commit`
    (`Good signature`), and a hermetic round-trip test signs then re-verifies
    through `verify_pgp`.
  - *SSH sign & verify* — both Ed25519:
  - *Verify* — `verify_ssh` parses the `SSHSIG` structure, reconstructs the exact
    signed bytes ([`Commit::signed_payload`] strips the `gpgsig` header;
    [`Tag::signed_payload`] drops the trailing block), and checks it with
    `purecrypto` Ed25519 over SHA-256/512. Verified against real
    `git commit -S` / `git tag -s` signatures for commits and tags.
  - *Sign* — `sign_ssh_ed25519` / `sign_commit_ssh` produce a `gpgsig` armor a
    private key never leaves puregit for. Verified end to end: a puregit-created
    signature is accepted by real `ssh-keygen -Y verify`, and a puregit-signed
    commit passes real `git verify-commit` (`Good "git" signature`).

  The **C ABI** (`ffi` feature) is done: a `libgit2`-shaped `extern "C"` surface
  (`git_repository_open`/`init`/`free`, `git_repository_head_id`,
  `git_reference_name_to_id`, `git_object_lookup`/`type`/`id`/`free`,
  `git_blob_rawcontent`/`rawsize`, `git_commit_message`/`tree_id`/`parentcount`/
  `parent_id`, thread-local `git_error_last`), panic-guarded at the boundary and
  built explicitly as a staticlib/cdylib (`cargo rustc --features ffi
  --crate-type staticlib`). The default `crate-type` stays `["lib"]` and the
  crate keeps `forbid(unsafe_code)` unless `ffi` is enabled, which confines the
  `unsafe` to that one audited module. Verified by linking a C program against
  the staticlib and reading a real-git repository through it.

---

## Suggested ordering (dependency-aware)

1. **M1** delta compression on write — unblocks thin packs and smaller pushes,
   and feeds M6/M7 pack building and M8 repack.
2. **M3** multi-round `have` negotiation + sideband-64k, then **protocol v2** —
   sans-IO, testable without a transport.
3. **M6/M7** thin packs + server-side sideband progress once delta-on-write lands.
4. **M2** ref lockfiles + reflogs, `read-tree`/`reset`/`mv`, gitignore, and
   symlink/gitlink materialization — independent of transport.
5. **M4/M5** HTTP auth + dumb fallback; SSH ssh-agent + `known_hosts`.
6. **M8 maintenance** (`commit-graph`, MIDX, fsck, bitmaps) and **M9 polish**
   (`object-format` negotiation, `show`/`cat-file --batch`, C ABI, signing) —
   ongoing.

## Out of scope / caveats (under the no-C invariant)

- **libgit2/git C plug-ins, credential helpers as C libraries** — not
  applicable; credential callbacks are pure-Rust.
- **GSSAPI/Kerberos SSH auth** — no pure-Rust GSSAPI today (same caveat as
  `rsurl`/`puressh`); key and password auth work, agent auth is planned (M5).
- **Bitmap index v2 / reachability bitmaps** — large; a stretch goal in M8.

[`Vfs`]: src/vfs/mod.rs
[`ObjectDatabase`]: src/odb/mod.rs
[`transport::http`]: src/transport/http.rs
[`transport::ssh`]: src/transport/ssh.rs
[`server`]: src/server/mod.rs
