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

use crate::error::{Error, Result};
use crate::protocol::pktline::{self, Packet};
use crate::repository::Repository;
use crate::transport::Service;

use super::{advertise_refs, upload_pack};

/// The parsed first line of a git-daemon request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonRequest {
    /// The requested service (`git-upload-pack` / `git-receive-pack`).
    pub service: Service,
    /// The repository path the client asked for.
    pub path: String,
    /// The `host=` extra parameter, if the client sent one (virtual hosting).
    pub host: Option<String>,
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
    for extra in parts {
        if let Some(h) = extra.strip_prefix(b"host=") {
            host = core::str::from_utf8(h).ok().map(String::from);
        }
    }
    Ok(DaemonRequest {
        service,
        path: path.to_string(),
        host,
    })
}

/// Serves a single git-daemon connection for the `git-upload-pack` service.
///
/// Reads the request line, resolves the repository with `resolve` (given the
/// requested path), advertises refs, reads the `want`/`have` negotiation through
/// the client's `done`, and writes the pack. `resolve` returning `None` sends a
/// git `ERR` line and closes.
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

    // Advertise refs, then read the negotiation up to `done`, then send the pack.
    let advert = advertise_refs(&repo, Service::UploadPack, &["ofs-delta"])?;
    stream
        .write_all(&advert)
        .map_err(|e| Error::Io(e.to_string()))?;
    stream.flush().map_err(|e| Error::Io(e.to_string()))?;

    let request = read_until_done(&mut stream)?;
    if request.is_empty() {
        return Ok(()); // client hung up without wanting anything
    }
    let response = upload_pack(&repo, &request)?;
    stream
        .write_all(&response)
        .map_err(|e| Error::Io(e.to_string()))?;
    stream.flush().map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
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
                    let _ = serve_upload_pack(s, |p| resolve(p));
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

/// Reads one pkt-line from a stream, returning the packet and its raw bytes.
fn read_pktline<S: Read>(stream: &mut S) -> Result<(Packet, Vec<u8>)> {
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

/// Reads pkt-lines (accumulating their raw bytes) until a `done` line, so the
/// accumulated buffer can be handed to [`upload_pack`].
fn read_until_done<S: Read>(stream: &mut S) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        let (packet, raw) = match read_pktline(stream) {
            Ok(v) => v,
            Err(_) => return Ok(buf), // EOF / client closed
        };
        buf.extend_from_slice(&raw);
        if let Packet::Data(d) = &packet
            && (d == b"done\n" || d == b"done")
        {
            return Ok(buf);
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
    fn parses_request_line() {
        let req = parse_request(b"git-upload-pack /group/repo.git\0host=example.com\0").unwrap();
        assert_eq!(req.service, Service::UploadPack);
        assert_eq!(req.path, "/group/repo.git");
        assert_eq!(req.host.as_deref(), Some("example.com"));
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
