//! Git LFS (Large File Storage) support.
//!
//! Git LFS keeps large files out of the packfile by committing a small *pointer*
//! blob in their place and storing the real content separately — locally under
//! `.git/lfs/objects/` and, for sharing, on an LFS server. puregit implements
//! this the same pure-Rust way as everything else: SHA-256 content addressing
//! via [`purecrypto`], the local store over the [`crate::vfs`] trait, and the
//! LFS transfer API over [`rsurl`] (behind the `http` feature).
//!
//! Layers:
//! - [`Pointer`] — the pointer-file format (parse / serialize / detect), core
//!   and `no_std`.
//! - [`LfsStore`] — the local content-addressed object store (`lfs/objects/…`).
//! - [`attributes`] — `.gitattributes` matching to decide which paths are LFS.
//!
//! The clean (file → pointer) and smudge (pointer → file) filters, and the
//! batch-API transfer, are wired into [`crate::repository`] and the HTTP
//! transport respectively.

pub mod attributes;
pub mod batch;
pub mod json;
mod pointer;
mod store;

pub use pointer::Pointer;
pub use store::LfsStore;

/// The LFS object transfer client (batch API + basic transfer over HTTP).
#[cfg(feature = "http")]
pub mod transfer;
