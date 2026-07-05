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

## Milestone 1 — Object engine completeness

- ⬜ **Delta compression on write** — deltify objects when serializing a `.pack`
  (packs are currently emitted undeltified); unblocks thin packs and smaller
  pushes/repacks.
- ⬜ **fsck-style validation** — connectivity and object well-formedness (a native
  `fsck`; see also M8).

## Milestone 2 — Refs, index & worktree porcelain

- ⬜ **Atomic ref updates** — loose-ref lockfiles (`*.lock`), reflogs, and the
  `packed-refs` rewrite path.
- ⬜ **Index ↔ worktree** — `mv` and gitignore matching.
- ⬜ **`read-tree`** — read a tree object into the index.
- ⬜ **`reset`, plus symlink and gitlink materialization** — currently recognized
  but rejected via `Error::Unsupported`, not written to the worktree.

## Milestone 3 — Smart protocol core (sans-IO)

- ⬜ **v0/v1 negotiation** — multi-round `have` negotiation with all ACK modes
  (`multi_ack`, `multi_ack_detailed`), `shallow`/`deepen`, and sideband-64k
  demuxing (`multi_ack` is advertised as a capability but not yet driven).
- ⬜ **Protocol v2** — `command=ls-refs` and `command=fetch` framing, `ref-in-want`,
  `packfile-uris`; the preferred path for new servers.
- ⬜ **`report-status-v2`** — the richer push-report format.
- ⬜ **Capability negotiation policy** — negotiate `thin-pack`, `side-band-64k`,
  `agent`, `object-format` consistently from both peers' advertised lists.

## Milestone 4 — HTTP transport (client) — feature `http`

Over `rsurl` ([`transport::http`]).

- ⬜ **Auth & redirects** — Basic/Bearer via `rsurl`, credential callbacks, `.git`
  suffix and redirect handling, dumb-HTTP fallback (read-only). (Base-URL
  scheme/CRLF validation is in place; cert/redirect policy is `rsurl`'s.)
- ⬜ **Protocol-v2 detection** — select v2 vs v0/v1 at discovery (with M3).

## Milestone 5 — SSH transport (client) — feature `ssh`

Over `puressh` ([`transport::ssh`]).

- ⬜ **Host keys & auth** — ssh-agent auth, `known_hosts` verification, and
  `~/.ssh/config`-style host/user/port resolution (password + public-key auth
  already work).

## Milestone 6 — Client porcelain — feature `client`

- ⬜ **fetch refinements** — remote-tracking ref update conventions, `--prune`,
  and tag-following.
- ⬜ **Thin packs on push** — build and emit thin packs (depends on M1
  delta-on-write).
- ⬜ **Remotes & refspecs** — `[remote]`/`[branch]` config and general refspec
  matching (explicit-refspec push/fetch and fast-forward rules already work).

## Milestone 7 — Server handlers — feature `server`

The mirror image, transport-agnostic ([`server`]).

- ⬜ **upload-pack refinements** — thin packs and sideband progress.
- ⬜ **receive-pack refinements** — ref-update locking and hooks.
- ⬜ **Server-side SSH `exec` entry point** — reuse the same handlers over an SSH
  channel (the HTTP handler and `git://` daemon already ship).
- ⬜ **Access policy hooks** — pre-receive/update/post-receive callbacks. (Per-
  service enable flags and body/negotiation size caps are already in place.)
- ⬜ **Pluggable storage backend** — let the server serve from any
  [`Vfs`]/[`ObjectDatabase`] implementation, not just the on-disk `StdFs`.
  Today `advertise_refs`/`upload_pack`/`receive_pack`, the HTTP handler, and the
  `git://` daemon all take a concrete `Repository` (`odb: CombinedOdb<StdFs>`,
  `refs: RefStore<StdFs>`), so a custom / in-memory / remote object store can't
  be served without first staging it to a real git directory. The lower layers
  (`CombinedOdb<V>`, `RefStore<V>`, `LooseOdb<V>`) are already generic over
  `V: Vfs`; make `Repository` and the server entry points generic too — or add a
  handler surface over `&impl ObjectDatabase` + `&RefStore<V>`. (Transport,
  request routing, and access control are *already* pluggable: the handlers are
  sans-IO and the daemon takes a `resolve: Fn(&str) -> Option<Repository>`
  closure — this item is only about the object/ref **storage** backend.)

## Milestone 8 — Repository maintenance

- ⬜ **Reachability bitmaps** — for repack/gc (stretch).
- ⬜ **`commit-graph`** and **multi-pack-index** for fast traversal.
- ⬜ **prune / reflog expire**, **fsck**, **verify-pack**.
- ⬜ **worktrees**, **shallow/partial clone** maintenance, **alternates**.

## Milestone 9 — Compatibility & ecosystem polish

- ⬜ **SHA-256 on the wire** — `object-format` negotiation and interop edges (the
  object format is already modeled throughout: ids, loose, packs, index).
- ⬜ **CLI breadth** — `git status --porcelain` machine-readable output.
- ⬜ **C ABI** (`ffi` feature) — a `libgit2`-shaped surface for drop-in linking
  (as in the sibling crates), built explicitly.
- ⬜ **Signing/verification** — SSH and PGP commit/tag signatures via `purecrypto`
  (`gpgsig` headers are already preserved on round-trip).
- ⬜ Man pages, shell completions, exit-code parity.

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
