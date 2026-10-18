//! A minimal `git://` daemon (the git-native transport).
//!
//! The git protocol used by `git://` URLs is the simplest transport: the client
//! connects, sends a single pkt-line request
//! (`git-upload-pack /path\0host=…\0`), and the server then speaks the same
//! upload-pack conversation as every other transport over the raw socket —
//! advertise refs, read the `want`/`have` negotiation, send the pack.
//!
//! [`serve_upload_pack`] handles one connection over any `Read + Write`, so it
//! works on a `TcpStream` or an in-memory pipe; [`Daemon`] binds a
//! [`TcpListener`] and serves connections. Only the read-only `git-upload-pack`
//! service is offered — anonymous `git://` push is virtually never enabled, and
//! `git-receive-pack` is rejected.

use alloc::string::String;
use alloc::vec::Vec;
use std::io::{Read, Write};
use std::net::{TcpListener, ToSocketAddrs};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::protocol::pktline::{self, Packet};
use crate::repository::Repository;
use crate::transport::Service;

use super::serve_upload_pack_stream;

/// Upper bound on the total bytes accepted during the `want`/`have`
/// negotiation before a `done` line. A legitimate negotiation is a handful of
/// KiB; this cap (a few MiB) bounds the memory a client can force the daemon to
/// buffer while streaming `have` lines without ever sending `done`.
pub(crate) const MAX_NEGOTIATION_BYTES: usize = 4 * 1024 * 1024;

/// Upper bound on the number of pkt-lines accepted during the negotiation,
/// bounding CPU as well as memory for a client that streams many tiny packets.
pub(crate) const MAX_NEGOTIATION_PACKETS: usize = 100_000;

/// Default per-read timeout applied to accepted daemon connections, so a
/// slowloris client that opens a socket and stalls cannot pin a serving thread
/// indefinitely.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The parsed first line of a git-daemon request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonRequest {
    /// The requested service (`git-upload-pack` / `git-receive-pack`).
    pub service: Service,
    /// The repository path the client asked for.
    pub path: String,
    /// The `host=` extra parameter, if the client sent one (virtual hosting).
    pub host: Option<String>,
    /// The wire protocol version the client asked for with a `version=<n>`
    /// extra parameter (after the double NUL); `0` when absent.
    pub protocol_version: u8,
}

/// Parses a git-daemon request line: `"<service> <path>\0host=<host>\0…"`.
pub fn parse_request(line: &[u8]) -> Result<DaemonRequest> {
    // Strip a trailing NUL run; split extras on NUL.
    let mut parts = line.split(|&b| b == 0);
    let head = parts
        .next()
        .ok_or_else(|| Error::Protocol("daemon: empty request".into()))?;
    let text = core::str::from_utf8(head)
        .map_err(|_| Error::Protocol("daemon: non-utf8 request".into()))?;
    let (service, path) = text
        .split_once(' ')
        .ok_or_else(|| Error::Protocol("daemon: malformed request line".into()))?;
    let service = match service {
        "git-upload-pack" => Service::UploadPack,
        "git-receive-pack" => Service::ReceivePack,
        other => {
            return Err(Error::Protocol(alloc::format!(
                "daemon: unknown service {other}"
            )));
        }
    };
    let mut host = None;
    let mut protocol_version = 0;
    for extra in parts {
        if let Some(h) = extra.strip_prefix(b"host=") {
            host = core::str::from_utf8(h).ok().map(String::from);
        } else if let Some(v) = extra.strip_prefix(b"version=") {
            // Unknown versions fall back to v0, as git's own daemon does.
            protocol_version = match v {
                b"1" => 1,
                b"2" => 2,
                _ => 0,
            };
        }
    }
    Ok(DaemonRequest {
        service,
        path: path.to_string(),
        host,
        protocol_version,
    })
}

/// Serves a single git-daemon connection for the `git-upload-pack` service.
///
/// Reads the request line, resolves the repository with `resolve` (given the
/// requested path), advertises refs, negotiates round by round as the client
/// sends its `have`s (`multi_ack_detailed`, shallow and filter requests
/// included), and writes the pack after `done` — see
/// [`serve_upload_pack_stream`]. `resolve` returning `None` sends a git `ERR`
/// line and closes.
pub fn serve_upload_pack<S, F>(mut stream: S, resolve: F) -> Result<()>
where
    S: Read + Write,
    F: FnOnce(&str) -> Option<Repository>,
{
    let (packet, _raw) = read_pktline(&mut stream)?;
    let line = match packet {
        Packet::Data(d) => d,
        _ => return Err(Error::Protocol("daemon: expected a request line".into())),
    };
    let req = parse_request(&line)?;

    if req.service != Service::UploadPack {
        write_err(&mut stream, "service not enabled")?;
        return Ok(());
    }
    let repo = match resolve(&req.path) {
        Some(r) => r,
        None => {
            write_err(&mut stream, "repository not found")?;
            return Ok(());
        }
    };

    serve_upload_pack_stream(&repo, &mut stream, req.protocol_version)
}

/// A blocking `git://` daemon over a [`TcpListener`].
pub struct Daemon {
    listener: TcpListener,
}

impl Daemon {
    /// Binds the daemon to `addr` (e.g. `"127.0.0.1:9418"`, git's default port).
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let listener = TcpListener::bind(addr).map_err(|e| Error::Io(e.to_string()))?;
        Ok(Daemon { listener })
    }

    /// The local address the daemon is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| Error::Io(e.to_string()))
    }

    /// Accepts and serves connections forever, resolving each request's path to
    /// a repository with `resolve` (cloned per connection). Errors on a single
    /// connection are logged-and-skipped rather than stopping the daemon.
    pub fn serve<F>(&self, resolve: F) -> Result<()>
    where
        F: Fn(&str) -> Option<Repository>,
    {
        for stream in self.listener.incoming() {
            match stream {
                Ok(s) => {
                    // Apply a read timeout so a stalled (slowloris) client cannot
                    // hold a serving thread forever. Best-effort: if the platform
                    // rejects it we still serve, bounded by the negotiation caps.
                    let _ = s.set_read_timeout(Some(READ_TIMEOUT));
                    let _ = serve_upload_pack(s, |p| resolve(p));
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

/// Reads one pkt-line from a stream, returning the packet and its raw bytes.
pub(crate) fn read_pktline<S: Read>(stream: &mut S) -> Result<(Packet, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    read_exact(stream, &mut len_buf)?;
    let mut raw = len_buf.to_vec();
    // Reuse the decoder for the length semantics.
    match pktline::decode(&len_buf)? {
        Some((Packet::Flush, _)) => Ok((Packet::Flush, raw)),
        Some((Packet::Delim, _)) => Ok((Packet::Delim, raw)),
        Some((Packet::ResponseEnd, _)) => Ok((Packet::ResponseEnd, raw)),
        _ => {
            // Data line: parse the hex length and read the remainder.
            let total = parse_hex4(&len_buf)?;
            if total < 4 {
                return Err(Error::Protocol("daemon: bad pkt-line length".into()));
            }
            let mut payload = alloc::vec![0u8; total - 4];
            read_exact(stream, &mut payload)?;
            raw.extend_from_slice(&payload);
            Ok((Packet::Data(payload), raw))
        }
    }
}

fn write_err<S: Write>(stream: &mut S, msg: &str) -> Result<()> {
    let line = alloc::format!("ERR {msg}");
    let pkt = pktline::encode_data(line.as_bytes())?;
    stream
        .write_all(&pkt)
        .map_err(|e| Error::Io(e.to_string()))?;
    stream.flush().map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

fn read_exact<S: Read>(stream: &mut S, buf: &mut [u8]) -> Result<()> {
    stream.read_exact(buf).map_err(|e| Error::Io(e.to_string()))
}

fn parse_hex4(b: &[u8]) -> Result<usize> {
    let mut v = 0usize;
    for &c in &b[..4] {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return Err(Error::Protocol("daemon: non-hex pkt-line length".into())),
        };
        v = (v << 4) | d as usize;
    }
    Ok(v)
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::object::Signature;
    use crate::odb::ObjectDatabase;
    use std::net::TcpStream;

    fn sig() -> Signature {
        Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 0,
            tz: b"+0000".to_vec(),
        }
    }

    #[test]
    fn oversized_negotiation_is_rejected() {
        use crate::odb::MemoryOdb;

        // A want, then an endless stream of `have` lines and never a `done`:
        // the session must reject it once the byte cap is crossed rather than
        // read (and acknowledge) forever.
        struct Pipe {
            input: std::io::Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl Read for Pipe {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.input.read(b)
            }
        }
        impl Write for Pipe {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.output.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let odb = MemoryOdb::new(crate::oid::HashAlgo::Sha1);
        let mut input =
            pktline::encode_data(b"want 1111111111111111111111111111111111111111\n").unwrap();
        input.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        let have =
            pktline::encode_data(b"have 2222222222222222222222222222222222222222\n").unwrap();
        while input.len() <= 2 * MAX_NEGOTIATION_BYTES {
            input.extend_from_slice(&have);
        }
        let mut pipe = Pipe {
            input: std::io::Cursor::new(input),
            output: Vec::new(),
        };
        let err =
            crate::server::upload::serve_session(&mut pipe, &odb, &crate::server::upload::NoRefs)
                .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn parses_request_line() {
        let req = parse_request(b"git-upload-pack /group/repo.git\0host=example.com\0").unwrap();
        assert_eq!(req.service, Service::UploadPack);
        assert_eq!(req.path, "/group/repo.git");
        assert_eq!(req.host.as_deref(), Some("example.com"));
        assert_eq!(req.protocol_version, 0);

        // Protocol v2 is requested with an extra parameter after a double NUL.
        let req =
            parse_request(b"git-upload-pack /r.git\0host=example.com\0\0version=2\0").unwrap();
        assert_eq!(req.path, "/r.git");
        assert_eq!(req.protocol_version, 2);
    }

    #[test]
    fn daemon_serves_a_clone_over_tcp() {
        // A remote repo with one commit.
        let dir = std::env::temp_dir().join(alloc::format!("puregit-daemon-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let remote = Repository::init(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        remote.add_path("a.txt").unwrap();
        let tip = remote.commit(b"c\n", sig(), sig()).unwrap();

        // Bind an ephemeral port and serve exactly one connection in a thread.
        let daemon = Daemon::bind("127.0.0.1:0").unwrap();
        let addr = daemon.local_addr().unwrap();
        let dir2 = dir.clone();
        let handle = std::thread::spawn(move || {
            if let Some(Ok(stream)) = daemon.listener.incoming().next() {
                let _ = serve_upload_pack(stream, |_path| Repository::open(&dir2).ok());
            }
        });

        // Act as the client: send the request line, read the advertisement,
        // send the want/done, read NAK + pack.
        let mut sock = TcpStream::connect(addr).unwrap();
        let req = pktline::encode_data(b"git-upload-pack /r\0host=localhost\0").unwrap();
        sock.write_all(&req).unwrap();

        let advert = read_until_flush(&mut sock);
        let packets = pktline::decode_all(&advert).unwrap();
        let parsed =
            crate::protocol::RefAdvertisement::parse(crate::oid::HashAlgo::Sha1, &packets).unwrap();
        assert!(parsed.refs.iter().any(|r| r.id == tip));

        let mut fetch = crate::protocol::FetchRequest::default();
        fetch.wants.push(tip);
        sock.write_all(&fetch.encode().unwrap()).unwrap();

        let mut response = Vec::new();
        sock.read_to_end(&mut response).unwrap();
        let pack_off = response.windows(4).position(|w| w == b"PACK").unwrap();

        let dest =
            std::env::temp_dir().join(alloc::format!("puregit-daemon-dst-{}", core::line!()));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let mut clone = Repository::init(&dest).unwrap();
        clone.ingest_pack(&response[pack_off..]).unwrap();
        clone.reload_odb().unwrap();
        assert!(clone.objects().contains(&tip));

        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    /// Reads pkt-lines until the first flush (for the test client).
    fn read_until_flush(sock: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        loop {
            let (packet, raw) = read_pktline(sock).unwrap();
            buf.extend_from_slice(&raw);
            if packet == Packet::Flush {
                return buf;
            }
        }
    }
}
