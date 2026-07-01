#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

//! puregit — a pure-Rust implementation of git.
//!
//! In the spirit of `libgit2`, but written from scratch in safe Rust and built
//! on [`purecrypto`] for hashing and [`compcol`] for zlib, with no foreign code
//! in the dependency tree. The crate covers the full local object engine, the
//! packfile format, references, the staging index, and the *smart* transport
//! used by `git fetch`/`git push` — as both a client and a server, over HTTP
//! and SSH.
//!
//! # Layering
//!
//! The library is deliberately split into a `no_std + alloc` **core** and a
//! `std` **shell**:
//!
//! ```text
//!  ┌───────────────────────────────────────────────────────────────┐
//!  │ std shell (feature `std`)                                      │
//!  │   vfs::StdFs · Repository · worktree · transport::{http,ssh}   │
//!  └───────────────────────────────────────────────────────────────┘
//!  ┌───────────────────────────────────────────────────────────────┐
//!  │ no_std + alloc core                                            │
//!  │   oid · hash · object · odb · pack · refs · index · config     │
//!  │   protocol (pkt-line, capabilities, fetch/push negotiation)    │
//!  └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! Nothing in the core names `std`: it transforms byte buffers and is driven by
//! the caller's I/O. The [`vfs`] trait abstracts the filesystem so the same
//! repository logic runs over the real disk ([`vfs::StdFs`], feature `std`), an
//! in-memory store, or any custom backend.
//!
//! # Sans-IO transport
//!
//! Like the sibling `puressh`/`rsurl` crates, the wire protocols are *sans-IO*:
//! the [`protocol`] negotiation drivers consume inbound bytes and produce
//! outbound frames and events, while the caller owns the socket and the clock.
//! Two transport frontends drive that one core — `transport::http` (feature
//! `http`, over `rsurl`) and `transport::ssh` (feature `ssh`, over
//! `puressh`) — sharing all protocol logic.
//!
//! # Module map
//!
//! Core (always built):
//! - [`error`]    — the crate-wide [`Error`] / [`Result`] types.
//! - [`oid`]      — [`ObjectId`], git's SHA-1 / SHA-256 content name.
//! - [`hash`]     — compute an [`ObjectId`] from object bytes.
//! - [`object`]   — the object model: blob, [`tree`](object::tree),
//!   [`commit`](object::commit), [`tag`](object::tag); loose-object framing.
//! - [`odb`]      — the [`ObjectDatabase`](odb::ObjectDatabase) trait and the
//!   loose-object backend.
//! - [`pack`]     — packfile parsing/writing and delta resolution.
//! - [`refs`]     — reference names, the ref store, packed-refs, symrefs.
//! - [`index`]    — the staging index (`.git/index`).
//! - [`config`]   — the git config (`.git/config`) parser.
//! - [`protocol`] — pkt-line framing, capabilities, and the sans-IO
//!   fetch/push negotiation state machines.
//!
//! Shell (feature `std`):
//! - [`vfs`]        — the filesystem abstraction and its std backend.
//! - [`repository`] — [`Repository`], the on-disk repo tying it all together.
//! - [`worktree`]   — working-tree checkout, status, and diff.
//! - `transport`  — the HTTP and SSH smart-transport frontends (features
//!   `http` / `ssh`).
//! - `server`     — `upload-pack` / `receive-pack` request handlers
//!   (feature `server`).
//!
//! [`purecrypto`]: https://crates.io/crates/purecrypto
//! [`compcol`]: https://crates.io/crates/compcol

extern crate alloc;

// ---- core (no_std + alloc) -------------------------------------------------

pub mod compress;
pub mod config;
pub mod diff;
pub mod error;
pub mod hash;
pub mod index;
pub mod object;
pub mod odb;
pub mod oid;
pub mod pack;
pub mod protocol;
pub mod refs;
pub mod tree_builder;
pub mod vfs;
pub mod walk;

// ---- std shell -------------------------------------------------------------

#[cfg(feature = "std")]
pub mod merge;
#[cfg(feature = "std")]
pub mod repository;
#[cfg(feature = "std")]
pub mod status;
#[cfg(feature = "std")]
pub mod worktree;

#[cfg(any(
    feature = "client",
    feature = "http",
    feature = "ssh",
    feature = "server"
))]
pub mod transport;

#[cfg(all(feature = "client", feature = "std"))]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

// ---- re-exports ------------------------------------------------------------

pub use crate::error::{Error, Result};
pub use crate::object::{Object, ObjectType};
pub use crate::oid::{HashAlgo, ObjectId};

#[cfg(feature = "std")]
pub use crate::repository::Repository;
