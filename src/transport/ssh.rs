//! SSH transport over [`puressh`].
//!
//! Over SSH, git runs the pack program on the remote and speaks the pkt-line
//! protocol over the channel's stdio. Unlike HTTP (two stateless requests),
//! the whole conversation — ref advertisement *and* negotiation — happens on a
//! single `exec` channel, so this transport opens that channel in
//! [`discover`](Transport::discover) and keeps it open for the following
//! [`exchange`](Transport::exchange).
//!
//! The channel is an owned `puressh::shared::OwnedChannelStream` (a `Read +
//! Write`) obtained from a `puressh::shared::SharedClient`, so the transport can
//! hold the connection and the stream together without a self-referential
//! borrow.
//!
//! Authentication: password ([`SshTransport::with_password`]), public-key
//! ([`SshTransport::with_key`], or the default `~/.ssh/id_*`), and **ssh-agent**
//! (identities from `$SSH_AUTH_SOCK`, signed without the key ever leaving the
//! agent). Host keys are checked against `~/.ssh/known_hosts`, and
//! [`SshTransport::from_url`] resolves the host alias through `~/.ssh/config`
//! (`HostName`/`User`/`Port`/`IdentityFile`).

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

/// The maximum number of bytes we will buffer while reading the ref
/// advertisement (up to the first flush). The advertisement is sent by an
/// *untrusted* server; without a cap a peer that never sends a flush but keeps
/// streaming data would grow this buffer without bound (a memory DoS) and never
/// return. 128 MiB is far larger than any real advertisement.
const MAX_ADVERTISEMENT_BYTES: usize = 128 * 1024 * 1024;

/// The maximum number of bytes we will buffer for a full `exchange` response
/// (the pack plus any sideband/ack framing). Bounds the memory a malicious
/// server can make us allocate; 2 GiB comfortably exceeds any pack we would
/// realistically clone over a single channel while still refusing to grow
/// without limit.
const MAX_EXCHANGE_BYTES: usize = 2 * 1024 * 1024 * 1024;

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
        let mut transport = SshTransport::new(user, host, port, path, algo);
        // Resolve the host alias through `~/.ssh/config`, as ssh/git do.
        if let Some(text) = read_ssh_config() {
            transport.apply_config(&text, url);
        }
        Ok(transport)
    }

    /// Applies `~/.ssh/config` settings for this transport's host alias, given
    /// the raw `url` (used to tell which fields the URL set explicitly — those
    /// take precedence over the config).
    ///
    /// `HostName` rewrites the host (unless it fails validation); `User`/`Port`
    /// fill in only what the URL left at its default; `IdentityFile` supplies a
    /// key when none was set explicitly.
    fn apply_config(&mut self, config_text: &str, url: &str) {
        let cfg = super::ssh_config::resolve(config_text, &self.host);
        if let Some(hostname) = cfg.hostname
            && validate_host(&hostname).is_ok()
        {
            self.host = hostname;
        }
        if !url_has_explicit_user(url)
            && let Some(user) = cfg.user
            && validate_user(&user).is_ok()
        {
            self.user = user;
        }
        if !url_has_explicit_port(url)
            && let Some(port) = cfg.port
        {
            self.port = port;
        }
        if self.key.is_none()
            && let Some(identity) = cfg.identity_file
        {
            self.key = Some((expand_tilde(&identity), None));
        }
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
    ///
    /// The remote runs this through its login shell, so `self.path` (which comes
    /// verbatim from the clone URL and is therefore *untrusted*) is wrapped in
    /// POSIX single quotes with any embedded single quote correctly escaped by
    /// [`shell_single_quote`]. Without that escaping a path such as
    /// `foo';id;'` would break out of the quotes and inject an arbitrary command
    /// on the remote. `service.name()` is a compile-time constant and needs no
    /// escaping. A leading `-` is neutralized inside the quotes (it is data, not
    /// an option) and rejected earlier by [`parse_ssh_url`].
    fn exec_command(&self, service: Service) -> String {
        alloc::format!("{} {}", service.name(), shell_single_quote(&self.path))
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

        // Auth order: an explicit password, else the ssh-agent's identities
        // (git's default preference), then an explicit or default key file.
        if let Some(pw) = &self.password {
            client
                .authenticate_password(&self.user, pw)
                .map_err(map_ssh_err)?;
        } else {
            let mut creds = agent_credentials();
            if let Some(host_key) = self.load_private_key()? {
                creds.push(puressh::auth::ClientCredential::PublicKey(host_key));
            }
            if creds.is_empty() {
                return Err(Error::Unsupported(
                    "SSH transport: no usable credential — set a password (with_password), a key \
                     (with_key), place an unencrypted OpenSSH key at ~/.ssh/id_ed25519, or run an \
                     ssh-agent holding your key"
                        .into(),
                ));
            }
            client
                .authenticate(&self.user, creds)
                .map_err(map_ssh_err)?;
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
        let packets = pktline::decode_all_bounded(&advert, pktline::MAX_PACKETS)?;
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
        // / report-status), enforcing a running cap so a server that keeps
        // streaming without ever closing the channel cannot exhaust memory.
        read_capped(stream, MAX_EXCHANGE_BYTES)
    }
}

/// `Read::read`, retried while it fails with [`std::io::ErrorKind::Interrupted`]
/// (`EINTR`), which `std::io::Read` leaves to the caller.
fn read_retrying(stream: &mut OwnedChannelStream, buf: &mut [u8]) -> Result<usize> {
    loop {
        match stream.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            other => return other.map_err(|e| Error::Io(e.to_string())),
        }
    }
}

/// Reads from `stream` to EOF in bounded chunks, returning [`Error::Protocol`]
/// as soon as the accumulated length would exceed `max`. This replaces
/// `read_to_end`, whose only bound is available memory, for reads of untrusted
/// server responses.
fn read_capped(stream: &mut OwnedChannelStream, max: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        let n = read_retrying(stream, &mut scratch)?;
        if n == 0 {
            return Ok(buf);
        }
        if buf.len() + n > max {
            return Err(Error::Protocol("ssh: response exceeded size limit".into()));
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

/// Reads pkt-lines from `stream` until (and including) the first flush packet,
/// returning the bytes read. Used to bound the ref advertisement read.
///
/// The accumulated buffer is capped at [`MAX_ADVERTISEMENT_BYTES`]: a malicious
/// server that never emits a flush but keeps streaming data would otherwise
/// grow this buffer without bound (and never return). Exceeding the cap yields
/// [`Error::Protocol`].
fn read_until_flush(stream: &mut OwnedChannelStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        // Try to find a flush in what we already have.
        if let Some(end) = scan_for_flush(&buf)? {
            // Keep reading is unnecessary; return through the flush.
            return Ok(buf[..end].to_vec());
        }
        let n = read_retrying(stream, &mut scratch)?;
        if n == 0 {
            // EOF before a flush — return what we have (parser will validate).
            return Ok(buf);
        }
        if buf.len() + n > MAX_ADVERTISEMENT_BYTES {
            return Err(Error::Protocol(
                "ssh: advertisement exceeded size limit (no flush)".into(),
            ));
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

/// Wraps `s` in POSIX single quotes, escaping any embedded single quote as
/// `'\''` (close-quote, escaped literal quote, reopen-quote). The result is a
/// single shell word that reproduces `s` verbatim, so no metacharacter it
/// contains can be interpreted by the remote shell.
///
/// This is the standard argument-injection defense for building a command line
/// out of untrusted data (finding B4): even `foo';id;'` becomes the harmless
/// literal word `'foo'\''id;'\'''`.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Validates a host token parsed from an SSH URL (finding B5).
///
/// The host is passed to `Client::connect_to_host`, so it must be a plausible
/// hostname or IP literal: non-empty, no leading `-` (which some resolvers or
/// downstream tools could treat as an option), and free of whitespace, control
/// characters, and NUL. This is deliberately conservative rather than a full
/// RFC 1123 / IP-literal grammar.
fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(Error::Protocol("ssh url: empty host".into()));
    }
    if host.starts_with('-') {
        return Err(Error::Protocol("ssh url: host starts with '-'".into()));
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\0')
    {
        return Err(Error::Protocol(
            "ssh url: host contains whitespace or control characters".into(),
        ));
    }
    Ok(())
}

/// Validates a user token parsed from an SSH URL (finding B5). The user is used
/// for authentication only, but a leading `-`, whitespace, control character,
/// NUL, or `@`/`:` (which would indicate a mis-parse) is rejected as
/// implausible.
fn validate_user(user: &str) -> Result<()> {
    if user.is_empty() {
        return Err(Error::Protocol("ssh url: empty user".into()));
    }
    if user.starts_with('-') {
        return Err(Error::Protocol("ssh url: user starts with '-'".into()));
    }
    if user
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\0' || c == '@' || c == ':')
    {
        return Err(Error::Protocol(
            "ssh url: user contains invalid characters".into(),
        ));
    }
    Ok(())
}

/// Validates the repository path parsed from an SSH URL. The path is escaped
/// before it reaches the remote shell (see [`shell_single_quote`]), so command
/// injection is already prevented; here we additionally reject control
/// characters and NUL (which have no place in a path and can confuse the remote
/// git), and a leading `-` so the path can never be mistaken for an option.
fn validate_path(path: &str) -> Result<()> {
    if path.chars().any(|c| c.is_control() || c == '\0') {
        return Err(Error::Protocol(
            "ssh url: path contains control characters".into(),
        ));
    }
    // A path starting with '-' could be read as an option by the remote git;
    // legitimate repository paths do not start with a dash (ssh:// paths begin
    // with '/', scp-style paths are repository names).
    if path.starts_with('-') {
        return Err(Error::Protocol("ssh url: path starts with '-'".into()));
    }
    Ok(())
}

/// Parses an SSH git URL into `(user, host, port, path)`, validating the host,
/// user, and path (findings B4/B5) before returning them.
/// Collects public-key credentials from the running ssh-agent (via
/// `$SSH_AUTH_SOCK`), one per identity it holds. Returns an empty vector when no
/// agent is reachable — the caller then falls back to key files.
///
/// Each credential signs through the agent (the private key never leaves it),
/// exactly as `ssh`/`git` do. ssh-agent uses a Unix-domain socket, so this is a
/// no-op on non-Unix platforms.
#[cfg(unix)]
fn agent_credentials() -> Vec<puressh::auth::ClientCredential> {
    use puressh::agent::{Agent, AgentHostKey};

    let agent = match Agent::connect_env() {
        Ok(Some(a)) => a,
        _ => return Vec::new(),
    };
    let agent = Arc::new(Mutex::new(agent));
    let identities = match agent.lock() {
        Ok(mut a) => a.identities().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    identities
        .into_iter()
        .filter_map(|id| {
            AgentHostKey::from_identity(Arc::clone(&agent), id.key_blob)
                .ok()
                .map(|hk| puressh::auth::ClientCredential::PublicKey(alloc::boxed::Box::new(hk)))
        })
        .collect()
}

/// No ssh-agent on non-Unix platforms (it speaks over a Unix socket).
#[cfg(not(unix))]
fn agent_credentials() -> Vec<puressh::auth::ClientCredential> {
    Vec::new()
}

/// Reads `~/.ssh/config`, or `None` if `$HOME` is unset or the file is absent.
fn read_ssh_config() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    std::fs::read_to_string(std::path::PathBuf::from(home).join(".ssh/config")).ok()
}

/// Expands a leading `~/` in a path to `$HOME`.
fn expand_tilde(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return std::path::PathBuf::from(home).join(rest);
    }
    std::path::PathBuf::from(path)
}

/// The authority component of an ssh URL (before the path).
fn url_authority(url: &str) -> &str {
    if let Some(rest) = url.strip_prefix("ssh://") {
        rest.split('/').next().unwrap_or(rest)
    } else {
        url.split_once(':').map(|(a, _)| a).unwrap_or(url)
    }
}

/// Whether the URL names a user explicitly (`user@…`), so `~/.ssh/config`'s
/// `User` must not override it.
fn url_has_explicit_user(url: &str) -> bool {
    url_authority(url).contains('@')
}

/// Whether the URL names a port explicitly (only possible in `ssh://…:port`),
/// so `~/.ssh/config`'s `Port` must not override it.
fn url_has_explicit_port(url: &str) -> bool {
    if !url.starts_with("ssh://") {
        return false; // scp-style has no port field
    }
    let authority = url_authority(url);
    let hostpart = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    hostpart.contains(':')
}

fn parse_ssh_url(url: &str) -> Result<(String, String, u16, String)> {
    let (user, host, port, path) = if let Some(rest) = url.strip_prefix("ssh://") {
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
        (user, host, port, path)
    } else if let Some((authority, path)) = url.split_once(':') {
        // scp-style [user@]host:path
        let (user, host) = match authority.split_once('@') {
            Some((u, h)) => (u.to_string(), h.to_string()),
            None => ("git".to_string(), authority.to_string()),
        };
        (user, host, 22, path.to_string())
    } else {
        return Err(Error::Protocol(alloc::format!("not an ssh url: {url}")));
    };

    validate_user(&user)?;
    validate_host(&host)?;
    validate_path(&path)?;
    Ok((user, host, port, path))
}

fn map_ssh_err(e: puressh::Error) -> Error {
    Error::Io(alloc::format!("ssh: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config_resolves_alias_and_respects_explicit_url_fields() {
        let cfg =
            "Host gh\n  HostName github.com\n  User git\n  Port 2222\n  IdentityFile /keys/id_gh\n";

        // A bare alias picks up HostName, User, Port, and IdentityFile.
        let mut t = SshTransport::new("git", "gh", 22, "/r.git", HashAlgo::Sha1);
        t.apply_config(cfg, "gh:/r.git");
        assert_eq!(t.host, "github.com");
        assert_eq!(t.user, "git");
        assert_eq!(t.port, 2222);
        assert_eq!(
            t.key.as_ref().map(|(p, _)| p.as_path()),
            Some("/keys/id_gh".as_ref())
        );

        // An explicit user and port in the URL are kept; only HostName applies.
        let mut t2 = SshTransport::new("alice", "gh", 2000, "/r.git", HashAlgo::Sha1);
        t2.apply_config(cfg, "ssh://alice@gh:2000/r.git");
        assert_eq!(t2.host, "github.com");
        assert_eq!(t2.user, "alice");
        assert_eq!(t2.port, 2000);
    }

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

    #[test]
    fn shell_single_quote_escapes_injection() {
        // A path attempting to break out of the single quotes is neutralized:
        // every embedded quote becomes '\'' and the whole thing stays one word.
        assert_eq!(shell_single_quote("a/b.git"), "'a/b.git'");
        assert_eq!(shell_single_quote("foo';id;'"), "'foo'\\'';id;'\\'''");
        // No unescaped single quote can appear inside the body.
        let q = shell_single_quote("x'y");
        assert_eq!(q, "'x'\\''y'");
    }

    #[test]
    fn parse_ssh_url_rejects_injection_path() {
        // Even though the path is escaped, an ssh:// path can never start with a
        // bare '-' after the leading '/', but a control char / NUL is rejected.
        assert!(parse_ssh_url("ssh://git@example.com/foo\0bar").is_err());
        // scp-style path is not forced to start with '/', so a leading '-' path
        // is rejected as a would-be option.
        assert!(parse_ssh_url("git@example.com:-oProxyCommand=x").is_err());
    }

    #[test]
    fn parse_ssh_url_rejects_bad_host() {
        // Empty host.
        assert!(parse_ssh_url("ssh://git@/repo.git").is_err());
        // Host starting with '-'.
        assert!(parse_ssh_url("ssh://git@-h/repo.git").is_err());
        // Host with an embedded space (via scp-style, before the ':').
        assert!(parse_ssh_url("git@bad host:repo.git").is_err());
        // A legitimate URL still parses.
        assert!(parse_ssh_url("ssh://git@example.com:22/repo.git").is_ok());
    }
}
