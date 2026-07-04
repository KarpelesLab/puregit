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

Status legend: ✅ done · 🚧 in progress · ⬜ planned.

---

## Where we are today

**puregit clones real repositories from GitHub over HTTPS** and round-trips
clone/fetch/push over an in-process transport — the full object engine,
protocol, client, and server are working end to end. Validated against the
reference implementation: puregit-created history passes `git fsck`, and a
real `git clone https://github.com/octocat/Hello-World.git` produces a repo
whose HEAD, history, and checkout match git exactly (pure-Rust TLS, no C).

Delivered (all CI-gate-clean):

- ✅ **Object ids** — SHA-1 + SHA-256, hex/binary, ordering, null id.
- ✅ **Object model** — blob/tree/commit/tag parse + serialize, including
  continuation-header (`gpgsig`) preservation and tree-sort canonicalization.
- ✅ **Object database** — loose (zlib over the VFS, integrity-checked),
  in-memory, and the **combined loose + packed** store that resolves delta
  chains across every backend.
- ✅ **Packfiles** — `.pack` random access, `OFS_DELTA` + `REF_DELTA` chains,
  the delta codec, v2 `.idx` read **and write**, the **`PackWriter`**, and
  **`explode_pack`** (ingest a received pack with no index). Verified against
  real `git repack` output.
- ✅ **Reachability** — `reachable_objects`, `objects_to_send` (the fetch/push
  object set), and a `RevWalk` commit iterator.
- ✅ **References** — name validation, loose + `packed-refs`, symref resolution,
  a VFS-backed store, and the server advertisement builder.
- ✅ **Index** — `DIRC` v2/v3 read/write with checksum, extension preservation,
  and **`write-tree`** (build nested trees from the index).
- ✅ **Config** — INI parse/serialize with section/subsection/bool semantics.
- ✅ **Protocol** — pkt-line, capabilities, ref-advertisement parse/build,
  fetch request encode/parse, push command list + report-status encode/parse.
- ✅ **Repository / worktree** — `init`/`open`, object I/O, `HEAD`, config/index,
  **`add`**, **`commit`**, **`status`**, **`branch`**, **`checkout`**, tree
  checkout, **`ingest_pack`**, **`repack`/`gc`**.
- ✅ **History** — **`is_ancestor`**, **`merge_base`**, **`diff_trees`**
  (name-status), textual unified **`diff`**, and a **three-way `merge`**
  (diff3 content merge + tree merge + merge commits, conflict detection).
- ✅ **Client** — **`fetch`** and **`clone`** over any transport.
- ✅ **Server** — **`upload_pack`** (single-round) and **`receive_pack`** (push
  with create/update/delete preconditions and **fast-forward enforcement**);
  an in-process `LocalTransport`; a framework-agnostic **smart-HTTP handler**
  (`server::http`); and a **`git://` daemon** (`server::daemon`) over TCP.
- ✅ **Transports** — **smart-HTTP(S)** over `rsurl` (clones real GitHub repos)
  and **SSH** over `puressh` (password + public-key auth; agent pending).
- ✅ **Git LFS** — end to end: pointer format, local `lfs/objects` store,
  `.gitattributes` tracking, clean/smudge filters (wired into `add`/checkout),
  a dependency-free JSON reader, the batch API + basic object transfer over
  HTTP (client **and** a framework-agnostic server handler), and auto-pull on
  `clone` (`git lfs pull`). Pointers are byte-compatible with `git lfs`.
- ✅ **CLI** — `init`, `hash-object`, `cat-file`, `rev-parse`, `add`, `rm`,
  `write-tree`, `commit`, `log`, `status`, `branch`, `checkout`, `gc`,
  `merge-base`, `merge`, `tag`, `ls-tree`, `diff-tree`, `diff`, `lfs`,
  `unpack-objects`, `clone`.

**Remaining** (the long tail — optimizations, conveniences, and hard-to-test-
offline items): SSH ssh-agent auth, multi-round `have` negotiation +
sideband-64k, protocol v2, delta compression on write, pre-receive/update
hooks, reflogs, and advanced maintenance (`commit-graph`, multi-pack-index),
plus a `libgit2`-shaped C ABI and commit/tag signing. The full core arc —
clone/fetch/push/serve over HTTP, SSH, and `git://`, and the complete local
workflow (`add`/`rm`/`commit`/`status`/`branch`/`checkout`/`merge`/`diff`/`gc`)
— is implemented and validated against canonical git.

---

## Milestone 1 — Object engine completeness (keystone) — ✅ core done

The local store underneath everything else. Delivered; the remainder is
refinement (delta-on-write, a couple of plumbing commands, fsck).

- 🚧 **Pack writing** — serialize objects into a `.pack` and compute its `.idx`
  (`PackWriter` + v2 `.idx` write ✅). Needed to *send* data (push, the server's
  fetch response) and to repack. Remaining: **delta compression on write** (packs
  are currently emitted undeltified).
- ✅ **Combined ODB** — a backend that consults loose objects and every pack
  index, with a `REF_DELTA`/`OFS_DELTA` resolver, so `Repository` reads packed
  history transparently.
- ✅ **Object enumeration & reachability** — `reachable_objects`,
  `objects_to_send` (the negotiation/packing object set), and a `RevWalk`.
- 🚧 **`hash-object` for all types, `mktree`, `commit-tree`** plumbing —
  `hash-object` ✅ and `commit-tree`-equivalent logic drives `commit`; standalone
  `mktree`/`commit-tree` CLI verbs are the remainder.
- ⬜ **fsck-style validation** — connectivity and object well-formedness. (puregit
  output already passes real `git fsck`; a native `fsck` is pending — see M8.)

**Delivers:** the ability to produce packs and read packed repos — unblocks all
transport work. **Effort: L.**

## Milestone 2 — Refs, index & worktree porcelain — 🚧 mostly done

Turning the plumbing into the everyday local operations.

- 🚧 **Atomic ref updates** — non-fast-forward detection ✅ (`is_ancestor`, and
  the server enforces it on push); loose + `packed-refs` **read** ✅. Remaining:
  loose-ref lockfiles (`*.lock`), reflogs, and the `packed-refs` rewrite path.
- 🚧 **Index ↔ worktree** — `add` (stat + hash + stage) ✅, `status` (worktree vs
  index vs `HEAD`) ✅, `rm` ✅. Remaining: `mv` and gitignore matching.
- 🚧 **Tree building** — write the index out as tree objects (`write-tree`) ✅.
  Remaining: read a tree into the index (`read-tree`).
- 🚧 **commit / checkout / reset** — the staging→commit→checkout cycle ✅.
  Remaining: `reset`, plus symlink and gitlink materialization (currently
  recognized but rejected via `Error::Unsupported`, not written).
- ✅ **Diff** — blob and tree diffs, textual unified output + name-status.

**Delivers:** a usable local git. **Effort: XL.**

## Milestone 3 — Smart protocol core (sans-IO) — 🚧 v0/v1 single-round done

The negotiation state machines the transports drive, transport-agnostic.

- 🚧 **Protocol v0/v1** — advertisement parse/build ✅, fetch request ✅, and the
  single-round (`want`…`done`) flow ✅. Remaining: multi-round `have` negotiation
  with all ACK modes (`multi_ack`, `multi_ack_detailed`), `shallow`/`deepen`, and
  sideband-64k demuxing (`multi_ack` is advertised as a capability but not yet
  driven).
- ⬜ **Protocol v2** — `command=ls-refs` and `command=fetch` framing, `ref-in-want`,
  `packfile-uris`; the preferred path for new servers.
- ✅ **receive-pack (push) request** — the `<old> <new> <ref>` command list, the
  pushed pack, and `report-status` parsing/encoding. (`report-status-v2` pending.)
- 🚧 **Capability negotiation policy** — pkt-line + capability parse/build ✅ and a
  fixed client/server set (`ofs-delta`…). Remaining: negotiating `thin-pack`,
  `side-band-64k`, `agent`, `object-format` consistently from both peers' lists.

**Delivers:** everything the client/server need above the socket. **Effort: L.**

## Milestone 4 — HTTP transport (client) — feature `http` — 🚧 clones real repos

Smart-HTTP(S) over `rsurl` ([`transport::http`]). Clones real GitHub repos today.

- ✅ **Discovery** — `GET info/refs?service=…`, strip the `# service=` banner,
  decode the advertisement (v0/v1). (v2 detection pending with M3.)
- ✅ **Service POST** — `POST git-upload-pack` / `git-receive-pack` with the
  correct `Content-Type`, request + response bodies.
- ⬜ **Auth & redirects** — Basic/Bearer via `rsurl`, credential callbacks,
  `.git` suffix and redirect handling, dumb-HTTP fallback (read-only). (base-URL
  scheme/CRLF validation is in place; cert/redirect policy is `rsurl`'s.)

**Delivers:** `clone`/`fetch`/`push` over HTTPS. **Effort: M.**

## Milestone 5 — SSH transport (client) — feature `ssh` — 🚧 working

Over `puressh` ([`transport::ssh`]).

- ✅ **Exec channel** — connect, `exec git-upload-pack '<path>'` /
  `git-receive-pack` (POSIX-quoted path), and pump pkt-lines over the channel.
- 🚧 **Host keys & auth** — password + public-key auth ✅. Remaining: ssh-agent
  auth, `known_hosts` verification, and `~/.ssh/config`-style host/user/port
  resolution.
- ✅ **`ssh://` and `scp`-style `user@host:path`** URL parsing into a transport
  (with host/user/path validation); the `git://` daemon is M7.

**Delivers:** `clone`/`fetch`/`push` over SSH. **Effort: M.**

## Milestone 6 — Client porcelain (clone / fetch / push) — feature `client` — 🚧 core done

Drive the M3 negotiation over an M4/M5 transport against the M1 ODB.

- ✅ **clone** — discover, negotiate a full fetch, ingest the received pack, write
  refs + `HEAD`, check out the worktree (with LFS auto-pull).
- 🚧 **fetch** — negotiation from local `have`s ✅. Remaining: remote-tracking ref
  update conventions, `--prune`, and tag-following.
- 🚧 **push** — compute the objects to send, build a pack, send the command list,
  apply `report-status` ✅ (fast-forward enforced). Remaining: **thin** packs.
- 🚧 **Remotes & refspecs** — fast-forward rules ✅ and explicit-refspec push/fetch.
  Remaining: `[remote]`/`[branch]` config and general refspec matching.

**Delivers:** the headline client commands. **Effort: L.**

## Milestone 7 — Server handlers — feature `server` — 🚧 serving fetch + push

The mirror image, transport-agnostic ([`server`]). Advertisement builder ✅.

- 🚧 **upload-pack** — parse `want`/`have`, run reachability, build the response
  pack ✅ (single-round). Remaining: **thin** packs and sideband progress.
- 🚧 **receive-pack** — parse the command list, ingest + validate the pushed pack,
  apply ref updates with create/update/delete preconditions + fast-forward
  enforcement, emit `report-status` ✅. Remaining: ref-update **locking** and hooks.
- 🚧 **Endpoints** — a framework-agnostic HTTP handler ✅ and a `git://` daemon
  listener ✅. Remaining: a server-side SSH `exec` entry point reusing the same
  handlers.
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

**Delivers:** serve fetch and push. **Effort: L.**

## Milestone 8 — Repository maintenance — 🚧 repack/gc done

- 🚧 **repack / gc** — combine loose objects into a pack and prune ✅. Remaining:
  reachability **bitmaps** (stretch) and delta-compressed repacking (M1).
- ⬜ **`commit-graph`** and **multi-pack-index** for fast traversal.
- ⬜ **prune / reflog expire**, **fsck**, **verify-pack**.
- ⬜ **worktrees**, **shallow/partial clone** maintenance, **alternates**.

**Delivers:** keep a repository healthy at scale. **Effort: M–L.**

## Milestone 9 — Compatibility & ecosystem polish — 🚧 ongoing

- 🚧 **SHA-256 end to end** — the object format is modeled throughout (ids,
  loose, packs, index) ✅. Remaining: `object-format` negotiation on the wire and
  interop edges.
- 🚧 **CLI breadth** — `log`, `branch`, `tag`, `merge`/`merge-base`, `ls-tree`,
  `ls-files`, `diff`/`diff-tree`, `status` ✅. Remaining: `show`,
  `cat-file --batch`, and porcelain status output.
- ⬜ **C ABI** (`ffi` feature) — a `libgit2`-shaped surface for drop-in linking
  (as in the sibling crates), built explicitly.
- ⬜ **Signing/verification** — SSH and PGP commit/tag signatures via
  `purecrypto` (`gpgsig` headers are already preserved on round-trip).
- ⬜ Man pages, shell completions, exit-code parity.

**Effort: ongoing.**

---

## Suggested ordering (dependency-aware)

The core arc is delivered in this dependency order: **M1** object engine → **M3**
v0/v1 protocol → **M4 HTTP** → **M6 clone/fetch/push** → **M5 SSH** → **M7 server**
(HTTP endpoint + `git://` daemon), with **M2** worktree porcelain as parallel work.
Remaining work, dependency-ordered:

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
  `rsurl`/`puressh`); key, password, and agent auth are supported.
- **Bitmap index v2 / reachability bitmaps** — large; a stretch goal in M8.

[`Vfs`]: src/vfs/mod.rs
[`ObjectDatabase`]: src/odb/mod.rs
[`transport::http`]: src/transport/http.rs
[`transport::ssh`]: src/transport/ssh.rs
[`server`]: src/server/mod.rs
