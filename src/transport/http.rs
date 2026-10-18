//! Smart-HTTP(S) transport over [`rsurl`].
//!
//! Git's smart-HTTP protocol is two phases against a base URL `<repo>`:
//!
//! 1. **Ref discovery** — `GET <repo>/info/refs?service=git-upload-pack`, whose
//!    body is the service announcement (`# service=…\n`, a flush, then the v0/v1
//!    ref advertisement) or a v2 capability advertisement.
//! 2. **Service** — `POST <repo>/git-upload-pack` (or `git-receive-pack`) with
//!    `Content-Type: application/x-git-<service>-request`, the pkt-line request
//!    body, and the pack/report-status in the response.
//!
//! This module wires that onto the pure-Rust [`rsurl`] HTTP client. The request
//! shaping and response parsing are sans-IO ([`crate::protocol`]); this type
//! owns only the HTTP round-trips and the smart-HTTP envelope.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::HashAlgo;
use crate::protocol::RefAdvertisement;
use crate::protocol::pktline::{self, Packet};

use super::dumb_http::{self, DumbConfig, DumbHttpOdb};
use super::{Service, Transport};

/// A server's `401` authentication demand, handed to a credential callback.
///
/// The callback inspects it (the failing URL and, if the server sent a
/// `WWW-Authenticate` header, its scheme and `realm`) and returns the
/// `(username, password)` to retry with — or `None` to give up.
#[derive(Debug, Clone)]
pub struct AuthChallenge {
    /// The URL whose request was refused with `401`.
    pub url: String,
    /// The authentication scheme the server named (e.g. `Basic`), lowercased;
    /// empty if it sent no parseable `WWW-Authenticate` header.
    pub scheme: String,
    /// The `realm="…"` from the `WWW-Authenticate` header, if present.
    pub realm: Option<String>,
}

/// A credential callback: given a [`AuthChallenge`], returns the
/// `(username, password)` to authenticate with, or `None` to stop.
type CredentialFn = Arc<dyn Fn(&AuthChallenge) -> Option<(String, String)>>;

/// A smart-HTTP(S) transport bound to a remote repository URL.
#[derive(Clone)]
pub struct HttpTransport {
    base_url: String,
    algo: HashAlgo,
    /// A pre-built `Authorization` header value (e.g. `Basic <base64>`), sent on
    /// every request when set. `None` for anonymous access. Populated preemptively
    /// by [`with_basic_auth`](Self::with_basic_auth) or, on a `401`, by the
    /// credential callback.
    auth: Option<String>,
    /// Invoked on a `401` to obtain credentials and retry (git's credential-helper
    /// equivalent). `None` disables the challenge-response flow.
    credential: Option<CredentialFn>,
    /// Whether to follow `3xx` redirects (default on, as git does). Cross-host
    /// redirects never carry the `Authorization` header (`rsurl`'s secure
    /// default), so credentials are not leaked to a redirect target.
    follow_redirects: bool,
    /// Cap on redirect hops.
    max_redirects: u32,
    /// The base URL discovery was redirected to, if any: a `GET info/refs` that
    /// follows a redirect must send the subsequent `POST` to the *redirected*
    /// base, not the original (git's behaviour). Set in [`discover`] and only
    /// when the redirect stayed on the same host, so a hostile redirect cannot
    /// steer an authenticated `POST` to a third party.
    effective_base: Option<String>,
    /// Set by [`discover`] when the server has no smart-HTTP service and the
    /// dumb-HTTP fallback was used: a subsequent fetch synthesises the pack by
    /// walking objects over plain `GET`s instead of `POST`ing to a service.
    dumb: bool,
    /// Set by [`discover`] when the server advertised protocol v2: a subsequent
    /// fetch drives the v2 `fetch` command instead of a v0/v1 upload-pack request.
    v2: bool,
    /// Set by [`discover`] when the v2 server advertised `packfile-uris`: the
    /// fetch then offers `packfile-uris https` and downloads any pack the server
    /// offloads to a URL (verified against the announced hash).
    v2_packfile_uris: bool,
    /// The features of the v2 server's `fetch` command (`shallow`, `filter`,
    /// …), surfaced to the client as their v0/v1 capability names.
    v2_fetch_features: Vec<String>,
}

impl HttpTransport {
    /// Creates a transport for the repository at `base_url` (e.g.
    /// `https://github.com/owner/repo.git`).
    ///
    /// `base_url` is the untrusted clone URL and is later interpolated into
    /// request URLs. It is validated on first use (in
    /// [`discover`](Transport::discover) / [`exchange`](Transport::exchange))
    /// rather than here, so this constructor stays infallible: the check
    /// requires an `http://` or `https://` scheme and rejects any control
    /// character (including CR, LF, and NUL) that could otherwise smuggle a
    /// second header or a confused request. TLS-certificate verification stays
    /// with the underlying `rsurl` client (finding B7); this layer does not
    /// weaken it, and follows redirects without leaking credentials cross-host.
    pub fn new(base_url: impl Into<String>, algo: HashAlgo) -> Self {
        HttpTransport {
            base_url: base_url.into(),
            algo,
            auth: None,
            credential: None,
            follow_redirects: true,
            max_redirects: 10,
            effective_base: None,
            dumb: false,
            v2: false,
            v2_packfile_uris: false,
            v2_fetch_features: Vec::new(),
        }
    }

    /// Authenticates every request with HTTP Basic auth (`user:password`,
    /// base64-encoded). For a token-based host, pass the token as the password
    /// (and any non-empty username, e.g. the token itself or `x-access-token`).
    /// The credential is sent preemptively on each request.
    pub fn with_basic_auth(mut self, user: &str, password: &str) -> Self {
        self.auth = Some(basic_auth_header(user, password));
        self
    }

    /// Sets a raw `Authorization` header value (e.g. `Bearer <token>`), sent
    /// preemptively on every request.
    pub fn with_authorization(mut self, value: impl Into<String>) -> Self {
        self.auth = Some(value.into());
        self
    }

    /// Installs a credential callback invoked when a request is refused with
    /// `401`: it receives the [`AuthChallenge`] and returns the
    /// `(username, password)` to retry once with (cached for later requests), or
    /// `None` to surface the `401`. This is the pure-Rust analogue of a git
    /// credential helper — prompt a user, read a token store, etc.
    pub fn with_credential_callback<F>(mut self, f: F) -> Self
    where
        F: Fn(&AuthChallenge) -> Option<(String, String)> + 'static,
    {
        self.credential = Some(Arc::new(f));
        self
    }

    /// Enables or disables following `3xx` redirects (default enabled).
    pub fn with_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// The base URL to build request URLs from — the redirected base once
    /// discovery has found one, else the configured base.
    fn active_base(&self) -> &str {
        self.effective_base.as_deref().unwrap_or(&self.base_url)
    }

    /// The `info/refs` discovery URL for a service.
    fn info_refs_url(&self, service: Service) -> String {
        alloc::format!(
            "{}/info/refs?service={}",
            self.active_base().trim_end_matches('/'),
            service.name()
        )
    }

    /// The service endpoint URL (the POST target).
    fn service_url(&self, service: Service) -> String {
        alloc::format!(
            "{}/{}",
            self.active_base().trim_end_matches('/'),
            service.name()
        )
    }

    /// Issues one request (no `401` retry), applying the current auth header,
    /// redirect policy, and any extra headers.
    fn send_once(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<rsurl::Response> {
        let mut req = rsurl::Request::new(method, url)
            .map_err(map_rsurl_err)?
            .header("User-Agent", USER_AGENT)
            .follow_redirects(self.follow_redirects)
            .max_redirs(self.max_redirects);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        if let Some(auth) = &self.auth {
            req = req.header("Authorization", auth);
        }
        if let Some(body) = body {
            req = req.body(body.to_vec());
        }
        req.send().map_err(map_rsurl_err)
    }

    /// Issues a request, and on a `401` consults the credential callback once:
    /// if it yields credentials they are cached in `auth` and the request is
    /// retried. Returns the final response (which the caller checks for `200`).
    fn request(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<rsurl::Response> {
        let response = self.send_once(method, url, headers, body)?;
        if response.status != 401 {
            return Ok(response);
        }
        let Some(callback) = self.credential.clone() else {
            return Ok(response);
        };
        let challenge = parse_auth_challenge(url, &response.headers);
        let Some((user, password)) = callback(&challenge) else {
            return Ok(response);
        };
        self.auth = Some(basic_auth_header(&user, &password));
        self.send_once(method, url, headers, body)
    }
}

impl core::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately never print `auth`: it holds Basic/Bearer credentials.
        f.debug_struct("HttpTransport")
            .field("base_url", &self.base_url)
            .field("algo", &self.algo)
            .field("authenticated", &self.auth.is_some())
            .field("has_credential_callback", &self.credential.is_some())
            .field("follow_redirects", &self.follow_redirects)
            .finish()
    }
}

impl Transport for HttpTransport {
    fn discover(&mut self, service: Service) -> Result<RefAdvertisement> {
        validate_base_url(&self.base_url)?;
        let url = self.info_refs_url(service);
        // Offer protocol v2 for fetches; the server ignores the header if it
        // only speaks v0/v1. Like git's own client, never for a push: there is
        // no v2 `receive-pack`, and a server honouring the header would answer
        // without the `# service=` banner (looking like dumb HTTP).
        let headers: &[(&str, &str)] = match service {
            Service::UploadPack => &[("Accept", "*/*"), ("Git-Protocol", "version=2")],
            Service::ReceivePack => &[("Accept", "*/*")],
        };
        let response = self.request("GET", &url, headers, None)?;

        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "info/refs returned HTTP {}",
                response.status
            )));
        }
        // If discovery was redirected (on the same host), send later requests to
        // the redirected base — git rebases the service URL onto it.
        self.rebase_after_redirect(&response.final_url);

        // Prefer v2 when the server advertised it (upload-pack only); otherwise
        // parse a v0/v1 smart advertisement, and failing that fall back to dumb.
        if service == Service::UploadPack
            && let Ok(packets) = pktline::decode_all(&response.body)
            && let Ok(caps) = crate::protocol::v2::parse_capability_advertisement(&packets)
        {
            self.v2 = true;
            self.dumb = false;
            // Note whether the server offers `packfile-uris` (a `fetch=…`
            // capability value), so the fetch can offer to download offloaded
            // packs.
            self.v2_packfile_uris = caps.iter().any(|c| {
                c.strip_prefix("fetch=")
                    .is_some_and(|v| v.split(' ').any(|w| w == "packfile-uris"))
            });
            // A v2 server names its hash in the capabilities (there is no ref
            // advertisement to carry it), e.g. `object-format=sha256`.
            if let Some(algo) = caps
                .iter()
                .find_map(|c| c.strip_prefix("object-format="))
                .and_then(|n| match n {
                    "sha1" => Some(HashAlgo::Sha1),
                    "sha256" => Some(HashAlgo::Sha256),
                    _ => None,
                })
            {
                self.algo = algo;
            }
            self.v2_fetch_features = caps
                .iter()
                .find_map(|c| c.strip_prefix("fetch="))
                .map(|v| v.split(' ').map(str::to_string).collect())
                .unwrap_or_default();
            return self.v2_ls_refs();
        }
        self.v2 = false;

        match parse_smart_advertisement(self.algo, &response.body) {
            Ok(advert) => {
                self.dumb = false;
                Ok(advert)
            }
            // No smart-HTTP service banner: the body is a dumb `info/refs`
            // listing. Fall back to the dumb protocol (fetch objects directly).
            Err(_) => {
                self.dumb = true;
                dumb_http::discover(&self.dumb_config(), &response.body)
            }
        }
    }

    fn exchange(&mut self, service: Service, request: &[u8]) -> Result<Vec<u8>> {
        validate_base_url(&self.base_url)?;
        if self.dumb {
            return self.dumb_exchange(service, request);
        }
        if self.v2 && service == Service::UploadPack {
            return self.v2_fetch(request);
        }
        let url = self.service_url(service);
        let content_type = alloc::format!("application/x-{}-request", service.name());
        let accept = alloc::format!("application/x-{}-result", service.name());

        let response = self.request(
            "POST",
            &url,
            &[("Content-Type", &content_type), ("Accept", &accept)],
            Some(request),
        )?;

        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "{} returned HTTP {}",
                service.name(),
                response.status
            )));
        }
        Ok(response.body)
    }
}

impl HttpTransport {
    /// Snapshots the HTTP settings a dumb fetch needs (the active base URL, hash
    /// algorithm, resolved auth, and redirect policy).
    fn dumb_config(&self) -> DumbConfig {
        DumbConfig {
            base_url: self.active_base().trim_end_matches('/').to_string(),
            algo: self.algo,
            auth: self.auth.clone(),
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
        }
    }

    /// Serves a fetch from a dumb server by walking the object graph over plain
    /// `GET`s and packing the closure — the pack a smart `upload-pack` would have
    /// built. Push (`receive-pack`) is unsupported: dumb HTTP is read-only.
    fn dumb_exchange(&self, service: Service, request: &[u8]) -> Result<Vec<u8>> {
        use crate::pack::PackWriter;
        use crate::protocol::FetchRequest;

        if service != Service::UploadPack {
            return Err(Error::Unsupported(
                "dumb http: server is read-only (push needs smart HTTP)".into(),
            ));
        }
        let packets = pktline::decode_all(request)?;
        let req = FetchRequest::parse(self.algo, &packets)?;
        if req.wants.is_empty() {
            return Err(Error::Protocol("dumb http: fetch has no wants".into()));
        }

        let odb = DumbHttpOdb::new(self.dumb_config());
        let to_send = crate::walk::objects_to_send(&odb, &req.wants, &req.haves)?;
        let mut writer = PackWriter::new(self.algo);
        for id in &to_send {
            let (ty, payload) = crate::odb::ObjectDatabase::read(&odb, id)?;
            writer.add(ty, &payload);
        }
        let pack = writer.finish()?;

        // The client's non-sideband path expects a `NAK` line then the raw pack.
        let mut response = pktline::encode_data(b"NAK\n")?;
        response.extend_from_slice(&pack.pack);
        Ok(response)
    }

    /// The capability lines echoed on every v2 command (git includes the object
    /// format so a SHA-256 exchange is unambiguous).
    fn v2_command_caps(&self) -> Vec<String> {
        alloc::vec![alloc::format!("object-format={}", self.algo.name())]
    }

    /// Runs the v2 `ls-refs` command to build the ref advertisement (v2 discovery
    /// only announces capabilities, not refs).
    fn v2_ls_refs(&mut self) -> Result<RefAdvertisement> {
        use crate::protocol::v2;
        let args = alloc::vec![
            "peel".to_string(),
            "symrefs".to_string(),
            "unborn".to_string(),
            "ref-prefix HEAD".to_string(),
            "ref-prefix refs/".to_string(),
        ];
        let body = v2::encode_command("ls-refs", &self.v2_command_caps(), &args)?;
        let url = self.service_url(Service::UploadPack);
        let response = self.request(
            "POST",
            &url,
            &[
                ("Content-Type", "application/x-git-upload-pack-request"),
                ("Accept", "application/x-git-upload-pack-result"),
                ("Git-Protocol", "version=2"),
            ],
            Some(&body),
        )?;
        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "v2 ls-refs returned HTTP {}",
                response.status
            )));
        }
        let refs = v2::parse_ls_refs_response(self.algo, &pktline::decode_all(&response.body)?)?;
        // Surface the v2 `fetch` features under their v0/v1 capability names
        // so the client can gate shallow/filter requests uniformly. (Sideband
        // and the like stay off: `v2_fetch` hands back a plain `NAK` + pack.)
        let mut capabilities = crate::protocol::Capabilities::new();
        capabilities.add_flag("ofs-delta");
        for feature in &self.v2_fetch_features {
            match feature.as_str() {
                "shallow" => {
                    for c in ["shallow", "deepen-since", "deepen-not", "deepen-relative"] {
                        capabilities.add_flag(c);
                    }
                }
                "filter" => capabilities.add_flag("filter"),
                _ => {}
            }
        }
        Ok(RefAdvertisement {
            refs,
            capabilities,
            object_format: self.algo,
        })
    }

    /// Serves a fetch by translating the v0-style request into a v2 `fetch`
    /// command, then demuxing the `packfile` section back into a `NAK`+pack the
    /// client's v0 ingest path expects.
    fn v2_fetch(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        use crate::protocol::{FetchRequest, v2};

        let packets = pktline::decode_all(request)?;
        let req = FetchRequest::parse(self.algo, &packets)?;
        let mut args = Vec::new();
        for w in &req.wants {
            args.push(alloc::format!("want {}", w.to_hex()));
        }
        for h in &req.haves {
            args.push(alloc::format!("have {}", h.to_hex()));
        }
        for s in &req.shallows {
            args.push(alloc::format!("shallow {}", s.to_hex()));
        }
        if let Some(depth) = req.deepen {
            args.push(alloc::format!("deepen {depth}"));
        }
        if let Some(since) = req.deepen_since {
            args.push(alloc::format!("deepen-since {since}"));
        }
        for name in &req.deepen_not {
            args.push(alloc::format!("deepen-not {name}"));
        }
        if req.deepen_relative {
            args.push("deepen-relative".to_string());
        }
        if let Some(filter) = &req.filter {
            args.push(alloc::format!("filter {filter}"));
        }
        if req.capabilities.has("thin-pack") {
            args.push("thin-pack".to_string());
        }
        args.push("ofs-delta".to_string());
        // Offer to download packs the server offloads to URLs (only over
        // `https`, so an offloaded pack cannot be fetched over cleartext).
        if self.v2_packfile_uris {
            args.push("packfile-uris https".to_string());
        }
        // A v0 request ending in `done` asks for the pack; one ending in a
        // flush is a negotiation round, answered with acknowledgments only.
        if req.done {
            args.push("done".to_string());
        }

        let body = v2::encode_command("fetch", &self.v2_command_caps(), &args)?;
        let url = self.service_url(Service::UploadPack);
        let response = self.request(
            "POST",
            &url,
            &[
                ("Content-Type", "application/x-git-upload-pack-request"),
                ("Accept", "application/x-git-upload-pack-result"),
                ("Git-Protocol", "version=2"),
            ],
            Some(&body),
        )?;
        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "v2 fetch returned HTTP {}",
                response.status
            )));
        }
        if !req.done {
            return v2_acks_as_v0(self.algo, &response.body);
        }
        let resp =
            v2::parse_fetch_response_sections(self.algo, &pktline::decode_all(&response.body)?)?;
        let (uris, pack) = (resp.packfile_uris, resp.pack);
        // Hand the client a v0-shaped response: any `shallow` / `unshallow`
        // boundary lines, then the `NAK` line, then the raw pack — so the
        // client parses the shallow set and the pack uniformly across
        // protocols.
        let mut out = Vec::new();
        for oid in &resp.shallow {
            out.extend_from_slice(&pktline::encode_data(
                alloc::format!("shallow {}\n", oid.to_hex()).as_bytes(),
            )?);
        }
        for oid in &resp.unshallow {
            out.extend_from_slice(&pktline::encode_data(
                alloc::format!("unshallow {}\n", oid.to_hex()).as_bytes(),
            )?);
        }
        out.extend_from_slice(&pktline::encode_data(b"NAK\n")?);
        out.extend_from_slice(&pack);
        // Download each offloaded pack and append it after the inline pack; the
        // client's ingest decodes the concatenated packfiles in sequence.
        for (hash, uri) in &uris {
            out.extend_from_slice(&self.download_packfile_uri(hash, uri)?);
        }
        Ok(out)
    }

    /// Downloads a `packfile-uris` pack from `uri` and verifies it against the
    /// server-announced `hash`.
    ///
    /// Security: the URI comes from the server, so it is constrained — only
    /// `https` is accepted (no cleartext, no `file://`/other schemes), and the
    /// downloaded bytes are checked to be a real packfile whose SHA-1 content
    /// hash equals the announced `hash`, so a tampered or substituted pack is
    /// rejected before ingestion.
    fn download_packfile_uri(&mut self, hash: &str, uri: &str) -> Result<Vec<u8>> {
        if !uri.starts_with("https://") {
            return Err(Error::Protocol(alloc::format!(
                "packfile-uris: refusing non-https uri {uri:?}"
            )));
        }
        let response = self.request("GET", uri, &[("Accept", "*/*")], None)?;
        if response.status != 200 {
            return Err(Error::Protocol(alloc::format!(
                "packfile-uris: {uri} returned HTTP {}",
                response.status
            )));
        }
        verify_downloaded_pack(self.algo, hash, response.body)
    }

    /// After a redirected `info/refs`, adopts the redirected base URL for later
    /// requests — but only when the redirect stayed on the original host (a
    /// scheme upgrade or path change), so an authenticated `POST` is never
    /// steered to a third-party host. `final_url` is empty when no redirect
    /// occurred (or on transport paths that don't report it), in which case the
    /// configured base is kept.
    fn rebase_after_redirect(&mut self, final_url: &str) {
        let Some(base) = base_from_info_refs(final_url) else {
            return;
        };
        if validate_base_url(&base).is_err() {
            return;
        }
        if url_host(&base) != url_host(&self.base_url) {
            return; // cross-host redirect: do not carry requests (or auth) over
        }
        if base != self.base_url {
            self.effective_base = Some(base);
        }
    }
}

/// Translates the `acknowledgments` section of a v2 `fetch` response (a
/// negotiation round) into the v0 `multi_ack_detailed` lines the client's
/// negotiation loop reads: `ACK <oid> common` per common object, `ACK <oid>
/// ready` when the server is ready, then `NAK`. Any packfile the server sent
/// along with `ready` is dropped; the client asks for it with `done` next.
fn v2_acks_as_v0(algo: HashAlgo, body: &[u8]) -> Result<Vec<u8>> {
    let mut common = Vec::new();
    let mut ready = false;
    for packet in pktline::decode_all_bounded(body, pktline::MAX_PACKETS)? {
        let line = match &packet {
            Packet::Data(d) => d.strip_suffix(b"\n").unwrap_or(d),
            // The acknowledgments section ends at the first delim/flush.
            _ => break,
        };
        if let Some(hex) = line.strip_prefix(b"ACK ") {
            let hex = core::str::from_utf8(hex)
                .map_err(|_| Error::Protocol("v2 acknowledgments: non-utf8".into()))?;
            common.push(crate::oid::ObjectId::from_hex(algo, hex.trim())?);
        } else if line == b"ready" {
            ready = true;
        }
    }
    let mut out = Vec::new();
    for oid in &common {
        out.extend_from_slice(&pktline::encode_data(
            alloc::format!("ACK {} common\n", oid.to_hex()).as_bytes(),
        )?);
    }
    if ready && let Some(last) = common.last() {
        out.extend_from_slice(&pktline::encode_data(
            alloc::format!("ACK {} ready\n", last.to_hex()).as_bytes(),
        )?);
    }
    out.extend_from_slice(&pktline::encode_data(b"NAK\n")?);
    Ok(out)
}

const USER_AGENT: &str = concat!("puregit/", env!("CARGO_PKG_VERSION"));

/// Builds a Basic `Authorization` header value from a username and password.
fn basic_auth_header(user: &str, password: &str) -> String {
    let raw = alloc::format!("{user}:{password}");
    alloc::format!("Basic {}", base64_encode(raw.as_bytes()))
}

/// Parses a `401`'s `WWW-Authenticate` header into an [`AuthChallenge`].
///
/// The header looks like `Basic realm="Git"`; this extracts the scheme
/// (lowercased) and the quoted `realm`. Header lookup is case-insensitive. A
/// missing or unparseable header still yields a challenge (empty scheme, no
/// realm) so the callback runs — some servers omit it.
fn parse_auth_challenge(url: &str, headers: &[(String, String)]) -> AuthChallenge {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("www-authenticate"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let scheme = value
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let realm = value.find("realm=").and_then(|i| {
        let after = &value[i + "realm=".len()..];
        let after = after.trim_start_matches('"');
        after.split('"').next().map(|s| s.to_string())
    });
    AuthChallenge {
        url: url.to_string(),
        scheme,
        realm,
    }
}

/// Derives the smart-HTTP base URL from a (possibly redirected) `info/refs` URL
/// by stripping the `/info/refs` path and any query string. Returns `None` when
/// `final_url` is empty or does not look like an `info/refs` URL.
fn base_from_info_refs(final_url: &str) -> Option<String> {
    if final_url.is_empty() {
        return None;
    }
    let path = final_url.split(['?', '#']).next().unwrap_or(final_url);
    path.strip_suffix("/info/refs").map(|s| s.to_string())
}

/// Extracts the `host[:port]` authority from an `http(s)` URL, for a same-host
/// redirect check. Returns `None` for a non-`http(s)` URL.
fn url_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    Some(rest.split(['/', '?', '#']).next().unwrap_or(rest))
}

/// Standard base64 encoding (RFC 4648, with `=` padding), for the Basic-auth
/// credential. Small and self-contained to avoid pulling in a dependency.
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Parses a smart-HTTP `info/refs` advertisement body.
///
/// The smart response is prefixed with a service-announcement pkt-line
/// (`# service=git-upload-pack\n`) and a flush before the real v0/v1 ref
/// advertisement. This strips that prefix and parses the remainder. A dumb-HTTP
/// server (no service banner) is rejected with a clear error rather than
/// mis-parsed.
fn parse_smart_advertisement(algo: HashAlgo, body: &[u8]) -> Result<RefAdvertisement> {
    let packets = pktline::decode_all(body)?;

    let is_service_banner = matches!(
        packets.first(),
        Some(Packet::Data(d)) if d.starts_with(b"# service=")
    );
    if !is_service_banner {
        return Err(Error::Protocol(
            "info/refs: not a smart-HTTP advertisement (dumb HTTP unsupported)".into(),
        ));
    }

    // Skip the banner line and the flush that follows it.
    let mut start = 1;
    if matches!(packets.get(start), Some(Packet::Flush)) {
        start += 1;
    }
    RefAdvertisement::parse(algo, &packets[start..])
}

fn map_rsurl_err(e: rsurl::Error) -> Error {
    Error::Io(e.to_string())
}

/// Checks a downloaded `packfile-uris` pack `body` before ingestion, returning
/// the verified bytes.
///
/// Two layers: (1) the pack must be well-formed and **self-consistent** — its
/// trailing checksum must equal the digest of its own body, which catches any
/// corruption or truncation in transit (this is unambiguous and always
/// enforced); (2) the server-announced `hash` must match the pack, accepting
/// either convention seen in the wild — the pack's trailing checksum (its name)
/// or the digest of the whole file — so a substituted pack is rejected without
/// false-rejecting a valid one over a hash-convention disagreement. Object-level
/// integrity is additionally guaranteed at ingest time, where every object is
/// content-addressed.
fn verify_downloaded_pack(algo: HashAlgo, hash: &str, body: Vec<u8>) -> Result<Vec<u8>> {
    let id_len = algo.raw_len();
    if body.len() < 12 + id_len || &body[..4] != b"PACK" {
        return Err(Error::Protocol(
            "packfile-uris: downloaded object is not a packfile".into(),
        ));
    }
    // (1) Self-consistency: the trailer is the digest of everything before it.
    let split = body.len() - id_len;
    let trailer = to_hex(&crate::hash::hash_bytes(algo, &body[..split]));
    let announced_trailer = to_hex(&body[split..]);
    if trailer != announced_trailer {
        return Err(Error::Protocol(
            "packfile-uris: pack checksum is not self-consistent (corrupt download)".into(),
        ));
    }
    // (2) Bind to the advertisement: the announced hash names the pack by its
    // trailing checksum, or (some servers) by the whole-file digest.
    let whole = to_hex(&crate::hash::hash_bytes(algo, &body));
    if !hash.eq_ignore_ascii_case(&trailer) && !hash.eq_ignore_ascii_case(&whole) {
        return Err(Error::Protocol(alloc::format!(
            "packfile-uris: announced hash {hash} matches neither the pack checksum nor its file digest"
        )));
    }
    Ok(body)
}

/// Lower-case hex encoding of `bytes` (for comparing a `packfile-uris` digest).
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Validates an untrusted clone `base_url` (finding B6).
///
/// Requires an `http://` or `https://` scheme (a `file://`, `javascript:`, or
/// scheme-relative URL is refused rather than delegated to `rsurl`) and rejects
/// any ASCII/Unicode control character. In particular CR and LF, if allowed
/// into a URL that is later interpolated into a request line, could split the
/// request or inject a header; NUL similarly has no place in a URL. This is a
/// deliberately minimal check — full URL parsing and the TLS/redirect policy
/// stay with `rsurl`.
fn validate_base_url(base_url: &str) -> Result<()> {
    let is_http = base_url.starts_with("http://") || base_url.starts_with("https://");
    if !is_http {
        return Err(Error::Protocol(
            "http url: scheme must be http:// or https://".into(),
        ));
    }
    if base_url.chars().any(|c| c.is_control()) {
        return Err(Error::Protocol(
            "http url: contains control characters (CR/LF/NUL)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // The classic Basic-auth example from RFC 7617.
        assert_eq!(
            base64_encode(b"Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn basic_auth_sets_authorization_header_value() {
        let t = HttpTransport::new("https://example.com/r.git", HashAlgo::Sha1)
            .with_basic_auth("user", "pass");
        assert_eq!(t.auth.as_deref(), Some("Basic dXNlcjpwYXNz"));
    }

    #[test]
    fn accepts_http_and_https() {
        assert!(validate_base_url("https://example.com/r.git").is_ok());
        assert!(validate_base_url("http://example.com/r.git").is_ok());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(validate_base_url("file:///etc/passwd").is_err());
        assert!(validate_base_url("ftp://example.com/r.git").is_err());
        assert!(validate_base_url("//example.com/r.git").is_err());
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_base_url("https://example.com/r.git\r\nHost: evil").is_err());
        assert!(validate_base_url("https://example.com/\nr.git").is_err());
        assert!(validate_base_url("https://example.com/\0r.git").is_err());
    }

    #[test]
    fn parses_www_authenticate_scheme_and_realm() {
        let headers = alloc::vec![(
            "WWW-Authenticate".to_string(),
            "Basic realm=\"Git Access\"".to_string(),
        )];
        let ch = parse_auth_challenge("https://h/r.git/info/refs", &headers);
        assert_eq!(ch.scheme, "basic");
        assert_eq!(ch.realm.as_deref(), Some("Git Access"));
        assert_eq!(ch.url, "https://h/r.git/info/refs");

        // A missing header still yields a (blank) challenge so the callback runs.
        let ch = parse_auth_challenge("https://h/r.git", &[]);
        assert_eq!(ch.scheme, "");
        assert!(ch.realm.is_none());
    }

    #[test]
    fn derives_base_from_redirected_info_refs() {
        assert_eq!(
            base_from_info_refs("https://new/r.git/info/refs?service=git-upload-pack").as_deref(),
            Some("https://new/r.git")
        );
        assert_eq!(base_from_info_refs(""), None);
        assert_eq!(
            base_from_info_refs("https://new/r.git/git-upload-pack"),
            None
        );
    }

    #[test]
    fn same_host_check_ignores_scheme_and_path() {
        assert_eq!(url_host("http://h:8080/a"), url_host("https://h:8080/b"));
        assert_ne!(url_host("https://h/a"), url_host("https://evil/a"));
        assert_eq!(url_host("ftp://h/a"), None);
    }

    #[test]
    fn rebases_only_on_same_host_redirect() {
        // A same-host scheme upgrade rebases the base URL...
        let mut t = HttpTransport::new("http://h/r.git", HashAlgo::Sha1);
        t.rebase_after_redirect("https://h/r.git/info/refs?service=git-upload-pack");
        assert_eq!(t.active_base(), "https://h/r.git");

        // ...but a cross-host redirect is ignored, keeping the original base so no
        // authenticated request follows the redirect to a third party.
        let mut t = HttpTransport::new("https://h/r.git", HashAlgo::Sha1).with_basic_auth("u", "p");
        t.rebase_after_redirect("https://evil/r.git/info/refs");
        assert_eq!(t.active_base(), "https://h/r.git");
    }

    #[test]
    fn debug_does_not_leak_credentials() {
        let t =
            HttpTransport::new("https://h/r.git", HashAlgo::Sha1).with_basic_auth("u", "sekret");
        let shown = alloc::format!("{t:?}");
        assert!(!shown.contains("sekret"));
        assert!(!shown.contains("dXNlcg")); // nor the base64 of the credential
        assert!(shown.contains("authenticated: true"));
    }

    #[test]
    fn discover_rejects_bad_base_url() {
        // A non-http scheme is caught at first use even though `new` is infallible.
        let mut t = HttpTransport::new("file:///etc/passwd", HashAlgo::Sha1);
        assert!(matches!(
            t.discover(Service::UploadPack),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn packfile_uri_download_refuses_non_https() {
        // A server-supplied `packfile-uris` target that is not https is rejected
        // before any network access (no cleartext / `file://` offloading).
        let mut t = HttpTransport::new("https://example/r.git", HashAlgo::Sha1);
        for uri in [
            "http://cdn.example/p.pack",
            "file:///etc/passwd",
            "ftp://cdn.example/p.pack",
        ] {
            assert!(
                matches!(
                    t.download_packfile_uri("abcd", uri),
                    Err(Error::Protocol(_))
                ),
                "must refuse {uri}"
            );
        }
    }

    #[test]
    fn downloaded_pack_is_verified_against_the_announced_hash() {
        // A minimal but valid empty packfile (PACK, version 2, 0 objects) with a
        // self-consistent trailing checksum over its 12-byte body.
        let header = alloc::vec![b'P', b'A', b'C', b'K', 0, 0, 0, 2, 0, 0, 0, 0];
        let checksum = crate::hash::hash_bytes(HashAlgo::Sha1, &header);
        let mut pack = header.clone();
        pack.extend_from_slice(&checksum);
        let by_checksum = to_hex(&checksum); // the pack's trailing checksum (its name)
        let by_file = to_hex(&crate::hash::hash_bytes(HashAlgo::Sha1, &pack)); // whole-file digest

        // Either hash convention is accepted…
        assert_eq!(
            verify_downloaded_pack(HashAlgo::Sha1, &by_checksum, pack.clone()).unwrap(),
            pack
        );
        assert!(verify_downloaded_pack(HashAlgo::Sha1, &by_file, pack.clone()).is_ok());
        // …a wrong hash is rejected…
        assert!(verify_downloaded_pack(HashAlgo::Sha1, &"0".repeat(40), pack.clone()).is_err());
        // …non-pack content is rejected…
        assert!(
            verify_downloaded_pack(HashAlgo::Sha1, &by_checksum, b"not a pack".to_vec()).is_err()
        );
        // …and a pack whose trailer does not match its body (corruption) is
        // rejected even if the announced hash "matches" the corrupt file digest.
        let mut corrupt = header;
        corrupt.extend_from_slice(&[0u8; 20]); // wrong trailer
        let corrupt_file = to_hex(&crate::hash::hash_bytes(HashAlgo::Sha1, &corrupt));
        assert!(verify_downloaded_pack(HashAlgo::Sha1, &corrupt_file, corrupt).is_err());
    }

    #[test]
    fn v2_acknowledgments_translate_to_v0_negotiation_lines() {
        let a = "a".repeat(40);
        let mut body = Vec::new();
        for line in ["acknowledgments\n", &alloc::format!("ACK {a}\n"), "ready\n"] {
            body.extend_from_slice(&pktline::encode_data(line.as_bytes()).unwrap());
        }
        body.extend_from_slice(&pktline::encode_control(&Packet::Delim));
        body.extend_from_slice(&pktline::encode_data(b"packfile\n").unwrap());
        body.extend_from_slice(&pktline::encode_data(b"\x01PACK").unwrap());
        body.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        let out = v2_acks_as_v0(HashAlgo::Sha1, &body).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains(&alloc::format!("ACK {a} common")));
        assert!(text.contains(&alloc::format!("ACK {a} ready")));
        assert!(text.ends_with("NAK\n"));
        assert!(
            !text.contains("PACK"),
            "the pack of a negotiation round is dropped"
        );

        // Nothing common, not ready: just NAK.
        let mut body = pktline::encode_data(b"acknowledgments\n").unwrap();
        body.extend_from_slice(&pktline::encode_data(b"NAK\n").unwrap());
        body.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        let out = v2_acks_as_v0(HashAlgo::Sha1, &body).unwrap();
        assert_eq!(out, pktline::encode_data(b"NAK\n").unwrap());
    }
}
