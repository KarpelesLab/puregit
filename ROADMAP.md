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

- ⬜ **v0/v1 negotiation** — multi-round `have` negotiation with all ACK modes
  (`multi_ack`, `multi_ack_detailed`) and `shallow`/`deepen` (`multi_ack` is
  advertised as a capability but not yet driven). `side-band-64k` demuxing is
  done — the client negotiates it and reassembles a multiplexed pack.
- ⬜ **Protocol v2** — `command=ls-refs` and `command=fetch` framing, `ref-in-want`,
  `packfile-uris`; the preferred path for new servers.

## Milestone 4 — HTTP transport (client) — feature `http`

Over `rsurl` ([`transport::http`]).

- ⬜ **Dumb-HTTP fallback** — fetch loose objects and packs directly when a
  server has no smart-HTTP service. (401-challenge credential callbacks
  [`with_credential_callback`] and same-host redirect following are done —
  verified end to end against an auth-protected server: an anonymous clone gets
  a `401`, the callback supplies credentials, and the retry succeeds. Preemptive
  Basic auth [`with_basic_auth`] and raw `Authorization` [`with_authorization`]
  were already in place.)
- ⬜ **Protocol-v2 detection** — select v2 vs v0/v1 at discovery (with M3).

## Milestone 5 — SSH transport (client) — feature `ssh`

Over `puressh` ([`transport::ssh`]).

- ⬜ **Host keys & auth** — ssh-agent auth, `known_hosts` verification, and
  `~/.ssh/config`-style host/user/port resolution (password + public-key auth
  already work).

## Milestone 8 — Repository maintenance

- ⬜ **Reachability bitmaps** — for repack/gc (stretch).
- ⬜ **shallow/partial clone** maintenance (depends on the M3 `shallow`/`deepen`
  protocol). Alternates and worktrees are done.

## Milestone 9 — Compatibility & ecosystem polish

- ⬜ **C ABI** (`ffi` feature) — a `libgit2`-shaped surface for drop-in linking
  (as in the sibling crates), built explicitly.
- ⬜ **Signing/verification** — SSH and PGP commit/tag signatures via `purecrypto`
  (`gpgsig` headers are already preserved on round-trip).

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
