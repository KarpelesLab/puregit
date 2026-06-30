//! SSH transport over [`puressh`].
//!
//! Over SSH, git runs the pack program on the remote and speaks the pkt-line
//! protocol over the channel's stdio. Unlike HTTP (two stateless requests),
//! the whole conversation — ref advertisement *and* negotiation — happens on a
//! single `exec` channel, so this transport opens that channel in
//! [`discover`](Transport::discover) and keeps it open for the following
//! [`exchange`](Transport::exchange).
//!
//! The channel is an owned [`OwnedChannelStream`](puressh::shared::OwnedChannelStream)
//! (a `Read + Write`) obtained from a [`SharedClient`](puressh::shared::SharedClient),
//! so the transport can hold the connection and the stream together without a
//! self-referential borrow.
//!
//! Authentication: password auth is wired today (set it with
//! [`SshTransport::with_password`]). Public-key and ssh-agent auth — the common
//! case for git over SSH — are the next step; they need a live server to verify
//! and are tracked in the roadmap.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use puressh::client::{Client, Config};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;
use puressh::shared::{OwnedChannelStream, SharedClient};

use crate::error::{Error, Result};
use crate::oid::HashAlgo;
use crate::protocol::RefAdvertisement;
use crate::protocol::pktline::{self, Packet};

use super::{Service, Transport};

/// An SSH transport: connection coordinates plus the repository's hash algorithm.
pub struct SshTransport {
    host: String,
    port: u16,
    user: String,
    path: String,
    algo: HashAlgo,
    password: Option<String>,
    /// An explicit private-key file (OpenSSH PEM) and optional passphrase.
    key: Option<(std::path::PathBuf, Option<String>)>,
    /// The live connection, opened lazily on the first `discover`.
    shared: Option<SharedClient>,
    /// The exec channel for the in-flight conversation.
    stream: Option<OwnedChannelStream>,
    /// Which service the open channel is running.
    service: Option<Service>,
}

impl SshTransport {
    /// Creates an SSH transport for `user@host:port` serving repository `path`.
    pub fn new(
        user: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        path: impl Into<String>,
        algo: HashAlgo,
    ) -> Self {
        SshTransport {
            host: host.into(),
            port,
            user: user.into(),
            path: path.into(),
            algo,
            password: None,
            key: None,
            shared: None,
            stream: None,
            service: None,
        }
    }

    /// Parses an `ssh://[user@]host[:port]/path` or scp-style
    /// `[user@]host:path` URL into a transport. The default user is `git` and
    /// the default port 22.
    pub fn from_url(url: &str, algo: HashAlgo) -> Result<Self> {
        let (user, host, port, path) = parse_ssh_url(url)?;
        Ok(SshTransport::new(user, host, port, path, algo))
    }

    /// Sets a password for password authentication.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Sets an explicit private-key file (OpenSSH PEM) and optional passphrase
    /// for public-key authentication.
    pub fn with_key(
        mut self,
        path: impl Into<std::path::PathBuf>,
        passphrase: Option<String>,
    ) -> Self {
        self.key = Some((path.into(), passphrase));
        self
    }

    /// The command run on the remote for a service, e.g.
    /// `git-upload-pack 'group/repo.git'`.
    fn exec_command(&self, service: Service) -> String {
        alloc::format!("{} '{}'", service.name(), self.path)
    }

    /// Builds the SSH client config with strict host-key verification against
    /// the user's `~/.ssh/known_hosts` (an absent file yields an empty store, so
    /// an unknown host is rejected rather than blindly trusted).
    fn ssh_config(&self) -> Config {
        let known = std::env::var("HOME")
            .ok()
            .map(|home| std::path::PathBuf::from(home).join(".ssh/known_hosts"))
            .and_then(|path| KnownHosts::load(path).ok())
            .unwrap_or_default();
        Config::with_known_hosts(Arc::new(Mutex::new(known)))
    }

    /// Connects and authenticates if not already connected.
    fn ensure_connected(&mut self) -> Result<()> {
        if self.shared.is_some() {
            return Ok(());
        }
        let mut client = Client::connect_to_host(&self.host, self.port, self.ssh_config())
            .map_err(map_ssh_err)?;

        // Auth order: explicit password, then public key (explicit file or the
        // default ~/.ssh/id_* keys). ssh-agent auth is a roadmap item.
        if let Some(pw) = &self.password {
            client
                .authenticate_password(&self.user, pw)
                .map_err(map_ssh_err)?;
        } else if let Some(host_key) = self.load_private_key()? {
            client
                .authenticate_publickey(&self.user, host_key)
                .map_err(map_ssh_err)?;
        } else {
            return Err(Error::Unsupported(
                "SSH transport: no usable credential — set a password (with_password), a key \
                 (with_key), or place an unencrypted OpenSSH key at ~/.ssh/id_ed25519 \
                 (ssh-agent auth is on the roadmap)"
                    .into(),
            ));
        }

        self.shared = Some(SharedClient::from(client));
        Ok(())
    }

    /// Loads a private key for public-key auth: the explicitly configured key
    /// if set, otherwise the first parseable default key under `~/.ssh`.
    fn load_private_key(
        &self,
    ) -> Result<Option<alloc::boxed::Box<dyn puressh::hostkey::HostKey + Send>>> {
        if let Some((path, passphrase)) = &self.key {
            let pem = std::fs::read_to_string(path).map_err(|e| {
                Error::Io(alloc::format!("reading ssh key {}: {e}", path.display()))
            })?;
            let key = PrivateKey::parse_openssh_pem(&pem, passphrase.as_deref().map(str::as_bytes))
                .map_err(map_ssh_err)?;
            return Ok(Some(key.into_host_key().map_err(map_ssh_err)?));
        }

        // Fall back to the conventional default unencrypted keys.
        if let Ok(home) = std::env::var("HOME") {
            for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                let path = std::path::PathBuf::from(&home).join(".ssh").join(name);
                let Ok(pem) = std::fs::read_to_string(&path) else {
                    continue;
                };
                // Skip keys we can't parse unencrypted (e.g. passphrase-protected).
                if let Ok(key) = PrivateKey::parse_openssh_pem(&pem, None)
                    && let Ok(hk) = key.into_host_key()
                {
                    return Ok(Some(hk));
                }
            }
        }
        Ok(None)
    }

    /// Opens the exec channel for `service` and returns the advertisement bytes
    /// read up to the first flush.
    fn open_service(&mut self, service: Service) -> Result<Vec<u8>> {
        self.ensure_connected()?;
        let cmd = self.exec_command(service);
        let shared = self.shared.as_ref().expect("connected");
        let stream = shared.exec_stream(&cmd).map_err(map_ssh_err)?;
        self.stream = Some(stream);
        self.service = Some(service);
        // The server writes the advertisement immediately; read up to its flush.
        read_until_flush(self.stream.as_mut().unwrap())
    }
}

impl Transport for SshTransport {
    fn discover(&mut self, service: Service) -> Result<RefAdvertisement> {
        let advert = self.open_service(service)?;
        let packets = pktline::decode_all(&advert)?;
        RefAdvertisement::parse(self.algo, &packets)
    }

    fn exchange(&mut self, service: Service, request: &[u8]) -> Result<Vec<u8>> {
        // The channel opened in discover() is reused for the negotiation.
        if self.service != Some(service) || self.stream.is_none() {
            self.open_service(service)?;
        }
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| Error::Protocol("ssh: no open channel".into()))?;
        stream
            .write_all(request)
            .map_err(|e| Error::Io(e.to_string()))?;
        stream.flush().map_err(|e| Error::Io(e.to_string()))?;

        // Read the whole response (the server closes the channel after the pack
        // / report-status).
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| Error::Io(e.to_string()))?;
        Ok(response)
    }
}

/// Reads pkt-lines from `stream` until (and including) the first flush packet,
/// returning the bytes read. Used to bound the ref advertisement read.
fn read_until_flush(stream: &mut OwnedChannelStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        // Try to find a flush in what we already have.
        if let Some(end) = scan_for_flush(&buf)? {
            // Keep reading is unnecessary; return through the flush.
            return Ok(buf[..end].to_vec());
        }
        let n = stream
            .read(&mut scratch)
            .map_err(|e| Error::Io(e.to_string()))?;
        if n == 0 {
            // EOF before a flush — return what we have (parser will validate).
            return Ok(buf);
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

/// Returns the byte offset just past the first flush pkt-line in `buf`, or
/// `None` if no complete flush has been seen yet.
fn scan_for_flush(buf: &[u8]) -> Result<Option<usize>> {
    let mut off = 0;
    loop {
        match pktline::decode(&buf[off..])? {
            Some((Packet::Flush, n)) => return Ok(Some(off + n)),
            Some((_, n)) => off += n,
            None => return Ok(None),
        }
        if off >= buf.len() {
            return Ok(None);
        }
    }
}

/// Parses an SSH git URL into `(user, host, port, path)`.
fn parse_ssh_url(url: &str) -> Result<(String, String, u16, String)> {
    if let Some(rest) = url.strip_prefix("ssh://") {
        // ssh://[user@]host[:port]/path
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, alloc::format!("/{p}")),
            None => (rest, String::from("/")),
        };
        let (user, hostport) = match authority.split_once('@') {
            Some((u, h)) => (u.to_string(), h),
            None => ("git".to_string(), authority),
        };
        let (host, port) = match hostport.split_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse()
                    .map_err(|_| Error::Protocol("ssh url: bad port".into()))?,
            ),
            None => (hostport.to_string(), 22),
        };
        Ok((user, host, port, path))
    } else if let Some((authority, path)) = url.split_once(':') {
        // scp-style [user@]host:path
        let (user, host) = match authority.split_once('@') {
            Some((u, h)) => (u.to_string(), h.to_string()),
            None => ("git".to_string(), authority.to_string()),
        };
        Ok((user, host, 22, path.to_string()))
    } else {
        Err(Error::Protocol(alloc::format!("not an ssh url: {url}")))
    }
}

fn map_ssh_err(e: puressh::Error) -> Error {
    Error::Io(alloc::format!("ssh: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ssh_scheme_url() {
        let (u, h, p, path) = parse_ssh_url("ssh://git@example.com:2222/group/repo.git").unwrap();
        assert_eq!(u, "git");
        assert_eq!(h, "example.com");
        assert_eq!(p, 2222);
        assert_eq!(path, "/group/repo.git");
    }

    #[test]
    fn parse_scp_style_url() {
        let (u, h, p, path) = parse_ssh_url("git@github.com:owner/repo.git").unwrap();
        assert_eq!(u, "git");
        assert_eq!(h, "github.com");
        assert_eq!(p, 22);
        assert_eq!(path, "owner/repo.git");
    }

    #[test]
    fn exec_command_quotes_path() {
        let t = SshTransport::new("git", "h", 22, "a/b.git", HashAlgo::Sha1);
        assert_eq!(
            t.exec_command(Service::UploadPack),
            "git-upload-pack 'a/b.git'"
        );
    }
}
