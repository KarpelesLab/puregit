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
