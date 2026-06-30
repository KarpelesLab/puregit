//! The smart transfer protocol: ref advertisement and fetch/push negotiation.
//!
//! This module is *sans-IO*. It parses what a peer sends (the ref
//! advertisement) and builds what we send (the `want`/`have` negotiation and
//! the push commands), as pure byte transforms over [`pktline`] frames. The
//! actual byte movement belongs to a transport (the transport layer).
//!
//! Coverage today:
//! - [`pktline`] — packet framing (complete).
//! - [`capabilities`] — the capability set (complete).
//! - [`RefAdvertisement`] — parsing the v0/v1 reference advertisement.
//! - [`FetchRequest`] — building the `want`/`have`/`done` upload-pack request.
//!
//! On the roadmap: the protocol-v2 command framing (`command=fetch`,
//! `command=ls-refs`), the full multi-round `have` negotiation state machine
//! with the various `ACK`/`NAK` ack-modes, and the receive-pack (push) command
//! list with report-status parsing.

pub mod capabilities;
pub mod pktline;

pub use capabilities::Capabilities;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::{HashAlgo, ObjectId};

use pktline::Packet;

/// One advertised reference: a name and the id it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisedRef {
    /// The full ref name (e.g. `refs/heads/main`), or `HEAD`.
    pub name: String,
    /// The object id it currently resolves to.
    pub id: ObjectId,
}

/// A parsed v0/v1 reference advertisement: the server's refs plus the
/// capabilities it offered (carried after a NUL on the first ref line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefAdvertisement {
    /// The advertised refs, in the order received.
    pub refs: Vec<AdvertisedRef>,
    /// The capabilities advertised alongside the first ref.
    pub capabilities: Capabilities,
}

impl RefAdvertisement {
    /// Parses a v0/v1 advertisement from its decoded packets.
    ///
    /// The first data line is `"<oid> <name>\0<capabilities>"`; subsequent lines
    /// are `"<oid> <name>"`, terminated by a flush. An empty repository
    /// advertises a single capabilities line with the null id and the magic
    /// name `capabilities^{}`.
    pub fn parse(algo: HashAlgo, packets: &[Packet]) -> Result<Self> {
        let mut refs = Vec::new();
        let mut capabilities = Capabilities::new();
        let mut first = true;

        for packet in packets {
            let line = match packet {
                Packet::Data(d) => d,
                Packet::Flush => break,
                _ => continue,
            };
            let line = trim_trailing_newline(line);

            // The first line may carry "\0<caps>".
            let (ref_part, caps_part) = if first {
                match line.iter().position(|&b| b == 0) {
                    Some(nul) => (&line[..nul], Some(&line[nul + 1..])),
                    None => (line, None),
                }
            } else {
                (line, None)
            };
            first = false;

            if let Some(caps) = caps_part {
                let caps = core::str::from_utf8(caps)
                    .map_err(|_| Error::Protocol("advert: non-utf8 capabilities".into()))?;
                capabilities = Capabilities::parse(caps);
            }

            let text = core::str::from_utf8(ref_part)
                .map_err(|_| Error::Protocol("advert: non-utf8 ref line".into()))?;
            let (oid, name) = text
                .split_once(' ')
                .ok_or_else(|| Error::Protocol("advert: malformed ref line".into()))?;

            // Skip the "capabilities^{}" placeholder of an empty repo.
            if name == "capabilities^{}" {
                continue;
            }
            refs.push(AdvertisedRef {
                name: name.to_string(),
                id: ObjectId::from_hex(algo, oid)?,
            });
        }

        Ok(RefAdvertisement { refs, capabilities })
    }
}

/// Builds the client's upload-pack request: the `want` lines (the first
/// carrying the negotiated capabilities), the `have` lines we already possess,
/// and the terminating `done`.
///
/// This is the v0/v1 request shape; protocol v2's `command=fetch` framing is a
/// separate builder on the roadmap.
#[derive(Debug, Clone, Default)]
pub struct FetchRequest {
    /// Object ids we want the server to send.
    pub wants: Vec<ObjectId>,
    /// Object ids we already have (to bound the pack the server builds).
    pub haves: Vec<ObjectId>,
    /// Capabilities to request on the first `want` line.
    pub capabilities: Capabilities,
}

impl FetchRequest {
    /// Encodes the request to pkt-line bytes ready to send to the server.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.wants.is_empty() {
            return Err(Error::Protocol("fetch: no wants".into()));
        }
        let mut out = Vec::new();
        for (i, want) in self.wants.iter().enumerate() {
            let line = if i == 0 {
                let caps = self.capabilities.to_wire();
                if caps.is_empty() {
                    alloc::format!("want {}\n", want.to_hex())
                } else {
                    alloc::format!("want {} {}\n", want.to_hex(), caps)
                }
            } else {
                alloc::format!("want {}\n", want.to_hex())
            };
            out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
        }
        // End the want section.
        out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        for have in &self.haves {
            let line = alloc::format!("have {}\n", have.to_hex());
            out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
        }
        out.extend_from_slice(&pktline::encode_data(b"done\n")?);
        Ok(out)
    }

    /// Parses an upload-pack request (the server side of [`FetchRequest::encode`])
    /// from its decoded packets: `want <oid> [caps]` lines, then `have <oid>`
    /// lines, then `done`. The capabilities on the first `want` are captured.
    pub fn parse(algo: HashAlgo, packets: &[Packet]) -> Result<Self> {
        let mut req = FetchRequest::default();
        let mut first_want = true;
        for packet in packets {
            let line = match packet {
                Packet::Data(d) => trim_trailing_newline(d),
                _ => continue,
            };
            if let Some(rest) = line.strip_prefix(b"want ") {
                let text = core::str::from_utf8(rest)
                    .map_err(|_| Error::Protocol("want: non-utf8".into()))?;
                let (oid, caps) = match text.split_once(' ') {
                    Some((o, c)) => (o, Some(c)),
                    None => (text, None),
                };
                req.wants.push(ObjectId::from_hex(algo, oid.trim())?);
                if first_want {
                    if let Some(c) = caps {
                        req.capabilities = Capabilities::parse(c);
                    }
                    first_want = false;
                }
            } else if let Some(rest) = line.strip_prefix(b"have ") {
                let text = core::str::from_utf8(rest)
                    .map_err(|_| Error::Protocol("have: non-utf8".into()))?;
                req.haves.push(ObjectId::from_hex(algo, text.trim())?);
            }
            // `done` and anything else is ignored here.
        }
        Ok(req)
    }
}

/// A single ref-update command in a push: move `name` from `old` to `new`.
///
/// A zero `old` means "create" (the ref must not exist); a zero `new` means
/// "delete". Otherwise the server requires the ref to currently equal `old`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdateCommand {
    /// The ref's expected current id (zero ⇒ the ref must be created).
    pub old: ObjectId,
    /// The id to set the ref to (zero ⇒ delete the ref).
    pub new: ObjectId,
    /// The full ref name being updated.
    pub name: String,
}

/// The command section of a `git-receive-pack` (push) request: the ref updates
/// plus the capabilities. The packfile that follows is handled separately by
/// the transport (the client appends it; the server splits it off).
#[derive(Debug, Clone, Default)]
pub struct PushRequest {
    /// The ref updates to apply.
    pub commands: Vec<RefUpdateCommand>,
    /// Capabilities requested on the first command line.
    pub capabilities: Capabilities,
}

impl PushRequest {
    /// Encodes the command section to pkt-lines, terminated by a flush. The
    /// caller appends the packfile bytes after this.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.commands.is_empty() {
            return Err(Error::Protocol("push: no commands".into()));
        }
        let mut out = Vec::new();
        for (i, c) in self.commands.iter().enumerate() {
            let base = alloc::format!("{} {} {}", c.old.to_hex(), c.new.to_hex(), c.name);
            let line = if i == 0 {
                let caps = self.capabilities.to_wire();
                if caps.is_empty() {
                    alloc::format!("{base}\n")
                } else {
                    // Capabilities follow a NUL after the first command.
                    let mut v = base.into_bytes();
                    v.push(0);
                    v.extend_from_slice(caps.as_bytes());
                    v.push(b'\n');
                    out.extend_from_slice(&pktline::encode_data(&v)?);
                    continue;
                }
            } else {
                alloc::format!("{base}\n")
            };
            out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
        }
        out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        Ok(out)
    }

    /// Parses the command section from decoded packets (stops at the flush).
    pub fn parse(algo: HashAlgo, packets: &[Packet]) -> Result<Self> {
        let mut req = PushRequest::default();
        let mut first = true;
        for packet in packets {
            let line = match packet {
                Packet::Data(d) => trim_trailing_newline(d),
                Packet::Flush => break,
                _ => continue,
            };
            // The first line may carry "\0<caps>".
            let (cmd_part, caps_part) = if first {
                match line.iter().position(|&b| b == 0) {
                    Some(nul) => (&line[..nul], Some(&line[nul + 1..])),
                    None => (line, None),
                }
            } else {
                (line, None)
            };
            first = false;
            if let Some(caps) = caps_part {
                let caps = core::str::from_utf8(caps)
                    .map_err(|_| Error::Protocol("push: non-utf8 caps".into()))?;
                req.capabilities = Capabilities::parse(caps);
            }
            let text = core::str::from_utf8(cmd_part)
                .map_err(|_| Error::Protocol("push: non-utf8 command".into()))?;
            let mut parts = text.split(' ');
            let old = parts
                .next()
                .ok_or_else(|| Error::Protocol("push: missing old id".into()))?;
            let new = parts
                .next()
                .ok_or_else(|| Error::Protocol("push: missing new id".into()))?;
            let name = parts
                .next()
                .ok_or_else(|| Error::Protocol("push: missing ref name".into()))?;
            req.commands.push(RefUpdateCommand {
                old: ObjectId::from_hex(algo, old)?,
                new: ObjectId::from_hex(algo, new)?,
                name: name.to_string(),
            });
        }
        Ok(req)
    }
}

/// One line of a push report-status: whether a ref update succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefStatus {
    /// The ref name.
    pub name: String,
    /// `Ok(())` for `ok`, `Err(reason)` for `ng <reason>`.
    pub result: core::result::Result<(), String>,
}

/// A parsed push report-status: the overall unpack result and per-ref results.
#[derive(Debug, Clone)]
pub struct ReportStatus {
    /// `Ok(())` if the server unpacked the pack, else the `unpack` error text.
    pub unpack: core::result::Result<(), String>,
    /// Per-ref outcomes.
    pub refs: Vec<RefStatus>,
}

impl ReportStatus {
    /// Encodes a report-status to pkt-lines (server side), terminated by flush.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let unpack_line = match &self.unpack {
            Ok(()) => "unpack ok\n".into(),
            Err(e) => alloc::format!("unpack {e}\n"),
        };
        out.extend_from_slice(&pktline::encode_data(unpack_line.as_bytes())?);
        for r in &self.refs {
            let line = match &r.result {
                Ok(()) => alloc::format!("ok {}\n", r.name),
                Err(reason) => alloc::format!("ng {} {}\n", r.name, reason),
            };
            out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
        }
        out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        Ok(out)
    }

    /// Parses a report-status from decoded packets (client side).
    pub fn parse(packets: &[Packet]) -> Result<Self> {
        let mut unpack = Err("no unpack status".to_string());
        let mut refs = Vec::new();
        for packet in packets {
            let line = match packet {
                Packet::Data(d) => trim_trailing_newline(d),
                _ => continue,
            };
            let text = core::str::from_utf8(line)
                .map_err(|_| Error::Protocol("report-status: non-utf8".into()))?;
            if let Some(rest) = text.strip_prefix("unpack ") {
                unpack = if rest == "ok" {
                    Ok(())
                } else {
                    Err(rest.to_string())
                };
            } else if let Some(name) = text.strip_prefix("ok ") {
                refs.push(RefStatus {
                    name: name.to_string(),
                    result: Ok(()),
                });
            } else if let Some(rest) = text.strip_prefix("ng ") {
                let (name, reason) = rest.split_once(' ').unwrap_or((rest, ""));
                refs.push(RefStatus {
                    name: name.to_string(),
                    result: Err(reason.to_string()),
                });
            }
        }
        Ok(ReportStatus { unpack, refs })
    }

    /// Whether the whole push succeeded (unpack ok and every ref ok).
    pub fn is_ok(&self) -> bool {
        self.unpack.is_ok() && self.refs.iter().all(|r| r.result.is_ok())
    }
}

fn trim_trailing_newline(line: &[u8]) -> &[u8] {
    match line.last() {
        Some(b'\n') => &line[..line.len() - 1],
        _ => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_advertisement() {
        let id1 = "1111111111111111111111111111111111111111";
        let id2 = "2222222222222222222222222222222222222222";
        let mut buf = Vec::new();
        let first = alloc::format!("{id1} HEAD\0multi_ack ofs-delta agent=git/test\n");
        buf.extend_from_slice(&pktline::encode_data(first.as_bytes()).unwrap());
        let second = alloc::format!("{id2} refs/heads/main\n");
        buf.extend_from_slice(&pktline::encode_data(second.as_bytes()).unwrap());
        buf.extend_from_slice(&pktline::encode_control(&Packet::Flush));

        let packets = pktline::decode_all(&buf).unwrap();
        let advert = RefAdvertisement::parse(HashAlgo::Sha1, &packets).unwrap();
        assert_eq!(advert.refs.len(), 2);
        assert_eq!(advert.refs[0].name, "HEAD");
        assert_eq!(advert.refs[1].name, "refs/heads/main");
        assert!(advert.capabilities.has("ofs-delta"));
        assert_eq!(advert.capabilities.get("agent"), Some("git/test"));
    }

    #[test]
    fn build_fetch_request() {
        let want =
            ObjectId::from_hex(HashAlgo::Sha1, "1111111111111111111111111111111111111111").unwrap();
        let have =
            ObjectId::from_hex(HashAlgo::Sha1, "2222222222222222222222222222222222222222").unwrap();
        let mut req = FetchRequest::default();
        req.wants.push(want);
        req.haves.push(have);
        req.capabilities.add_flag("ofs-delta");
        let bytes = req.encode().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("want 1111111111111111111111111111111111111111 ofs-delta"));
        assert!(text.contains("have 2222222222222222222222222222222222222222"));
        assert!(text.contains("done"));
    }
}
