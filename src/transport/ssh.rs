//! SSH transport over [`puressh`].
//!
//! Over SSH, git runs the pack program on the remote host and speaks the
//! pkt-line protocol over the channel's stdio. The client opens a session,
//! requests an `exec` of `git-upload-pack '<path>'` (or `git-receive-pack`),
//! then reads the ref advertisement and exchanges the negotiation exactly as in
//! every other transport — there is no info/refs envelope, the advertisement is
//! simply the first thing the program writes.
//!
//! This module connects with the pure-Rust [`puressh`] client and drives that
//! exec stream. The protocol handling is shared sans-IO code
//! ([`crate::protocol`]); this type owns the SSH session and the exec channel.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::HashAlgo;
use crate::protocol::RefAdvertisement;

use super::{Service, Transport};

/// An SSH transport: host/user/path plus the repository's hash algorithm.
#[derive(Debug, Clone)]
pub struct SshTransport {
    /// The remote host (and optional `:port`).
    host: String,
    /// The login user.
    user: String,
    /// The repository path on the remote, as passed to the pack program.
    path: String,
    algo: HashAlgo,
}

impl SshTransport {
    /// Creates an SSH transport for `user@host:path`.
    pub fn new(
        user: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
        algo: HashAlgo,
    ) -> Self {
        SshTransport {
            user: user.into(),
            host: host.into(),
            path: path.into(),
            algo,
        }
    }

    /// The exec command line run on the remote for a service, e.g.
    /// `git-upload-pack 'group/repo.git'`.
    fn exec_command(&self, service: Service) -> String {
        alloc::format!("{} '{}'", service.name(), self.path)
    }
}

impl Transport for SshTransport {
    fn discover(&mut self, service: Service) -> Result<RefAdvertisement> {
        let _cmd = self.exec_command(service);
        let _ = (&self.user, &self.host);
        // TODO: connect via puressh, exec _cmd, read pkt-lines from the channel
        // until the first flush, and parse via RefAdvertisement::parse(self.algo, …).
        let _ = RefAdvertisement::parse(self.algo, &[]);
        Err(Error::Unsupported(
            "SSH transport: discover() not yet implemented".into(),
        ))
    }

    fn exchange(&mut self, service: Service, request: &[u8]) -> Result<Vec<u8>> {
        let _cmd = self.exec_command(service);
        let _ = request;
        // TODO: write the pkt-line request to the exec channel's stdin and read
        // the pack / report-status from stdout.
        Err(Error::Unsupported(
            "SSH transport: exchange() not yet implemented".into(),
        ))
    }
}
