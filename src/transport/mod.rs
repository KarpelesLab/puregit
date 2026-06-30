//! Transports — moving smart-protocol bytes to and from a remote.
//!
//! The [`protocol`](crate::protocol) layer is sans-IO: it builds requests and
//! parses responses but never touches a socket. A [`Transport`] is the I/O
//! frontend that connects to a remote and exchanges the two service streams git
//! defines:
//!
//! - **`git-upload-pack`** — serves a fetch/clone: the client reads the ref
//!   advertisement, sends its `want`/`have` negotiation, and receives a pack.
//! - **`git-receive-pack`** — accepts a push: the client reads the
//!   advertisement, sends its ref-update commands and a pack, and reads the
//!   report-status.
//!
//! Two implementations ship behind features:
//! - [`http`] (feature `http`) — smart HTTP(S) over [`rsurl`].
//! - [`ssh`] (feature `ssh`) — runs the pack programs on a remote over
//!   [`puressh`].
//!
//! Both are being built out; the trait and the connection plumbing are defined
//! here so the client porcelain can be written against the interface.

use alloc::vec::Vec;

use crate::error::Result;
use crate::protocol::RefAdvertisement;

/// Which pack service a transport request targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// `git-upload-pack` — the fetch/clone server.
    UploadPack,
    /// `git-receive-pack` — the push server.
    ReceivePack,
}

impl Service {
    /// The service's wire name, used in the smart-HTTP URL and SSH command.
    pub const fn name(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }
}

/// A connection to a remote repository over some concrete transport.
///
/// The lifecycle is: [`Transport::discover`] to read the ref advertisement,
/// then [`Transport::exchange`] to send the negotiation/command stream and read
/// the response (the pack, or the report-status). A single connection serves one
/// service; stateless transports (HTTP) reconnect per call internally.
pub trait Transport {
    /// Fetches the ref advertisement for `service` from the remote.
    fn discover(&mut self, service: Service) -> Result<RefAdvertisement>;

    /// Sends `request` (pkt-line bytes from the protocol layer) for `service`
    /// and returns the raw response bytes (the sideband-demuxed pack for a
    /// fetch, or the report-status for a push).
    fn exchange(&mut self, service: Service, request: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "ssh")]
pub mod ssh;
