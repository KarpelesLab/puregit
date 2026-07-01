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

## Milestone 1 — Object engine completeness (keystone)

The local store underneath everything else. Mostly ✅; the remainder:

- ⬜ **Pack writing** — serialize objects into a `.pack` (with delta
  compression) and compute its `.idx`. Needed to *send* data (push, and the
  server's fetch response) and to repack.
- ⬜ **Combined ODB** — a backend that consults loose objects and every pack
  index, with a thin-pack-aware `REF_DELTA` resolver, so `Repository` reads
  packed history transparently. (Loose + single-pack pieces exist; this ties
  them together.)
- ⬜ **Object enumeration & reachability** — walk commits/trees to compute the
  closure of "what objects does X reach", the core of negotiation and packing.
- ⬜ **`hash-object` for all types, `mktree`, `commit-tree`** plumbing.
- ⬜ **fsck-style validation** — connectivity and object well-formedness.

**Delivers:** the ability to produce packs and read packed repos — unblocks all
transport work. **Effort: L.**

## Milestone 2 — Refs, index & worktree porcelain

Turning the plumbing into the everyday local operations.

- ⬜ **Atomic ref updates** — loose-ref lockfiles (`*.lock`), reflogs, and the
  `packed-refs` rewrite path; non-fast-forward detection.
- ⬜ **Index ↔ worktree** — `add` (stat + hash + stage), `status` (worktree vs
  index vs `HEAD`), `rm`, `mv`; gitignore matching.
- ⬜ **Tree building** — write the index out as tree objects (`write-tree`) and
  read a tree into the index (`read-tree`).
- ⬜ **commit / checkout / reset** — the staging→commit→checkout cycle, plus
  symlink and gitlink materialization (currently rejected, not written).
- ⬜ **Diff** — blob and tree diffs (Myers), text + name-status output.

**Delivers:** a usable local git. **Effort: XL.**

## Milestone 3 — Smart protocol core (sans-IO)

The negotiation state machines the transports drive, transport-agnostic.

- 🚧 **Protocol v0/v1** — advertisement parse ✅ and fetch request ✅; remaining:
  the multi-round `have` negotiation with all ACK modes (`multi_ack`,
  `multi_ack_detailed`), `shallow`/`deepen`, and sideband-64k demuxing.
- ⬜ **Protocol v2** — `command=ls-refs` and `command=fetch` framing, `ref-in-want`,
  `packfile-uris`; the preferred path for new servers.
- ⬜ **receive-pack (push) request** — the `<old> <new> <ref>` command list,
  the pushed pack, and `report-status` / `report-status-v2` parsing.
- ⬜ **Capability negotiation policy** — pick `ofs-delta`, `thin-pack`,
  `side-band-64k`, `agent`, `object-format` consistently on both sides.

**Delivers:** everything the client/server need above the socket. **Effort: L.**

## Milestone 4 — HTTP transport (client) — feature `http`

Smart-HTTP(S) over `rsurl`. Scaffolded ([`transport::http`]).

- ⬜ **Discovery** — `GET info/refs?service=…`, strip the `# service=` banner,
  decode the advertisement; detect v2 vs v0/v1.
- ⬜ **Service POST** — `POST git-upload-pack` / `git-receive-pack` with the
  correct `Content-Type`, streaming request and response bodies.
- ⬜ **Auth & redirects** — Basic/Bearer via `rsurl`, credential callbacks,
  `.git` suffix and redirect handling, dumb-HTTP fallback (read-only).

**Delivers:** `clone`/`fetch`/`push` over HTTPS. **Effort: M.**

## Milestone 5 — SSH transport (client) — feature `ssh`

Over `puressh`. Scaffolded ([`transport::ssh`]).

- ⬜ **Exec channel** — connect, `exec git-upload-pack '<path>'` /
  `git-receive-pack`, and pump pkt-lines over the channel stdio.
- ⬜ **Host keys & auth** — `known_hosts` verification and key/agent auth via
  `puressh`; `~/.ssh/config`-style host/user/port resolution.
- ⬜ **`ssh://`, `scp`-style `user@host:path`, and `git://` (daemon)** URL
  parsing into a transport.

**Delivers:** `clone`/`fetch`/`push` over SSH. **Effort: M.**

## Milestone 6 — Client porcelain (clone / fetch / push) — feature `client`

Drive the M3 negotiation over an M4/M5 transport against the M1 ODB.

- ⬜ **clone** — discover, negotiate a full fetch, index the received pack, write
  refs + `HEAD`, check out the worktree.
- ⬜ **fetch** — incremental negotiation from local `have`s, update
  remote-tracking refs, `--prune`, tags.
- ⬜ **push** — compute the objects to send, build a (thin) pack, send the
  command list, apply `report-status`.
- ⬜ **Remotes & refspecs** — `[remote]`/`[branch]` config, refspec matching,
  fast-forward rules.

**Delivers:** the headline client commands. **Effort: L.**

## Milestone 7 — Server handlers — feature `server`

The mirror image, transport-agnostic ([`server`]). Advertisement builder ✅.

- ⬜ **upload-pack** — parse `want`/`have`, run reachability, build and stream
  the (thin) response pack with sideband progress.
- ⬜ **receive-pack** — parse the command list, ingest + validate the pushed
  pack, apply ref updates under lock with hooks, emit `report-status`.
- ⬜ **Endpoints** — an HTTP handler (CGI-shaped, for any server framework) and
  an SSH `exec` entry point reusing the same handlers; a minimal `git://`
  daemon listener.
- ⬜ **Access policy hooks** — pre-receive/update/post-receive callbacks.

**Delivers:** serve fetch and push. **Effort: L.**

## Milestone 8 — Repository maintenance

- ⬜ **repack / gc** — combine loose objects and small packs, prune unreachable
  objects, write bitmaps (stretch).
- ⬜ **`commit-graph`** and **multi-pack-index** for fast traversal.
- ⬜ **prune / reflog expire**, **fsck**, **verify-pack**.
- ⬜ **worktrees**, **shallow/partial clone** maintenance, **alternates**.

**Delivers:** keep a repository healthy at scale. **Effort: M–L.**

## Milestone 9 — Compatibility & ecosystem polish

- ⬜ **SHA-256 end to end** — the object format is modeled throughout; finish the
  transition bits (`object-format` negotiation, interop edges).
- ⬜ **CLI breadth** — `log`, `show`, `branch`, `tag`, `merge`/`merge-base`,
  `ls-tree`, `ls-files`, `cat-file --batch`, porcelain status output.
- ⬜ **C ABI** (`ffi` feature) — a `libgit2`-shaped surface for drop-in linking
  (as in the sibling crates), built explicitly.
- ⬜ **Signing/verification** — SSH and PGP commit/tag signatures via
  `purecrypto`.
- ⬜ Man pages, shell completions, exit-code parity.

**Effort: ongoing.**

---

## Suggested ordering (dependency-aware)

1. **M1** pack writing + combined ODB + reachability — unblocks everything.
2. **M3** protocol core in parallel (sans-IO, no transport needed to test).
3. **M4 HTTP** then **M6 clone/fetch** (HTTP is the easiest to test against
   public repos), then **push**.
4. **M5 SSH** reusing the M6 porcelain.
5. **M7 server** once M1+M3 are solid; HTTP endpoint first, then SSH, then daemon.
6. **M2 worktree porcelain** as steady parallel work — independent of transport.
7. **M8 maintenance** and **M9 polish** ongoing.

## Out of scope / caveats (under the no-C invariant)

- **libgit2/git C plug-ins, credential helpers as C libraries** — not
  applicable; credential callbacks are pure-Rust.
- **GSSAPI/Kerberos SSH auth** — no pure-Rust GSSAPI today (same caveat as
  `rsurl`/`puressh`); key, password, and agent auth are supported.
- **Bitmap index v2 / reachability bitmaps** — large; a stretch goal in M8.

[`Vfs`]: src/vfs/mod.rs
[`transport::http`]: src/transport/http.rs
[`transport::ssh`]: src/transport/ssh.rs
[`server`]: src/server/mod.rs
