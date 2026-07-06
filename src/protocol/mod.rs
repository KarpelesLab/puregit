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
pub mod v2;

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

/// The maximum number of refs we will accept from a single advertisement.
///
/// Each advertised ref allocates a `String` for its name plus an [`ObjectId`],
/// and the advertisement comes from an *untrusted* server. A peer advertising
/// millions of refs would otherwise force an unbounded allocation (a memory
/// DoS). A quarter-million refs is far beyond any real repository (the largest
/// public monorepos advertise on the order of tens of thousands) yet still
/// blocks a flood.
pub const MAX_ADVERTISED_REFS: usize = 262_144;

/// A parsed v0/v1 reference advertisement: the server's refs plus the
/// capabilities it offered (carried after a NUL on the first ref line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefAdvertisement {
    /// The advertised refs, in the order received.
    pub refs: Vec<AdvertisedRef>,
    /// The capabilities advertised alongside the first ref.
    pub capabilities: Capabilities,
    /// The object format the advertised ids use, taken from the
    /// `object-format` capability when present (else the algorithm the caller
    /// assumed). A clone should initialize its repository with this so a
    /// SHA-256 remote is cloned as SHA-256.
    pub object_format: HashAlgo,
}

impl RefAdvertisement {
    /// Parses a v0/v1 advertisement from its decoded packets.
    ///
    /// The first data line is `"<oid> <name>\0<capabilities>"`; subsequent lines
    /// are `"<oid> <name>"`, terminated by a flush. An empty repository
    /// advertises a single capabilities line with the null id and the magic
    /// name `capabilities^{}`.
    ///
    /// The number of refs is capped at [`MAX_ADVERTISED_REFS`]; a server
    /// advertising more is rejected with [`Error::Protocol`] rather than allowed
    /// to drive an unbounded allocation. The transport separately bounds the
    /// total byte count and packet count of the advertisement it hands us.
    pub fn parse(algo: HashAlgo, packets: &[Packet]) -> Result<Self> {
        let mut refs = Vec::new();
        let mut capabilities = Capabilities::new();
        let mut first = true;
        // The ids are parsed with `algo` unless the advertisement declares a
        // different `object-format`, in which case that wins (a SHA-256 remote
        // sends 64-hex ids that would not parse as SHA-1).
        let mut effective_algo = algo;

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
                if let Some(detected) = capabilities.object_format() {
                    effective_algo = detected;
                }
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
            if refs.len() >= MAX_ADVERTISED_REFS {
                return Err(Error::Protocol("advert: too many refs".into()));
            }
            refs.push(AdvertisedRef {
                name: name.to_string(),
                id: ObjectId::from_hex(effective_algo, oid)?,
            });
        }

        Ok(RefAdvertisement {
            refs,
            capabilities,
            object_format: effective_algo,
        })
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
    /// A `deepen <n>` request: truncate history to `n` commits per want (a
    /// shallow clone). `None` requests full history.
    pub deepen: Option<u32>,
    /// The client's existing shallow boundary (`shallow <oid>` lines), sent when
    /// deepening an already-shallow repository. Empty for an initial clone.
    pub shallows: Vec<ObjectId>,
    /// Whether the request ended with `done`. In the stateless-HTTP shallow flow
    /// the client first probes (no `done`) to learn the shallow boundary, then
    /// repeats with `done` to receive the pack — so a `deepen` request without
    /// `done` must be answered with the shallow list alone.
    pub done: bool,
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
        // Shallow boundary and depth requests belong in the want section,
        // before its terminating flush.
        for shallow in &self.shallows {
            let line = alloc::format!("shallow {}\n", shallow.to_hex());
            out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
        }
        if let Some(depth) = self.deepen {
            out.extend_from_slice(&pktline::encode_data(
                alloc::format!("deepen {depth}\n").as_bytes(),
            )?);
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
            } else if let Some(rest) = line.strip_prefix(b"shallow ") {
                let text = core::str::from_utf8(rest)
                    .map_err(|_| Error::Protocol("shallow: non-utf8".into()))?;
                req.shallows.push(ObjectId::from_hex(algo, text.trim())?);
            } else if let Some(rest) = line.strip_prefix(b"deepen ") {
                let text = core::str::from_utf8(rest)
                    .map_err(|_| Error::Protocol("deepen: non-utf8".into()))?;
                req.deepen = Some(
                    text.trim()
                        .parse()
                        .map_err(|_| Error::Protocol("deepen: invalid depth".into()))?,
                );
            } else if line == b"done" {
                req.done = true;
            }
            // Anything else is ignored here.
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
    /// `report-status-v2` option lines attached to this ref, as `(key, value)`
    /// pairs (e.g. `("old-oid", "…")`, `("new-oid", "…")`, `("forced-update",
    /// "")`). Empty for the v1 format.
    pub options: Vec<(String, String)>,
}

impl RefStatus {
    /// A v1 ref status with no options.
    pub fn new(name: String, result: core::result::Result<(), String>) -> Self {
        RefStatus {
            name,
            result,
            options: Vec::new(),
        }
    }
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
                refs.push(RefStatus::new(name.to_string(), Ok(())));
            } else if let Some(rest) = text.strip_prefix("ng ") {
                let (name, reason) = rest.split_once(' ').unwrap_or((rest, ""));
                refs.push(RefStatus::new(name.to_string(), Err(reason.to_string())));
            }
        }
        Ok(ReportStatus { unpack, refs })
    }

    /// Encodes a `report-status-v2` (server side): the same `unpack`/`ok`/`ng`
    /// lines as v1, but each ref status may be followed by `option <key> <value>`
    /// lines carrying extra detail (`old-oid`, `new-oid`, `ref`, `forced-update`,
    /// …). Negotiated via the `report-status-v2` capability.
    pub fn encode_v2(&self) -> Result<Vec<u8>> {
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
            for (key, value) in &r.options {
                let opt = if value.is_empty() {
                    alloc::format!("option {key}\n")
                } else {
                    alloc::format!("option {key} {value}\n")
                };
                out.extend_from_slice(&pktline::encode_data(opt.as_bytes())?);
            }
        }
        out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        Ok(out)
    }

    /// Parses a `report-status-v2` (client side): like [`ReportStatus::parse`],
    /// but `option …` lines are attached to the most recent ref status.
    pub fn parse_v2(packets: &[Packet]) -> Result<Self> {
        let mut unpack = Err("no unpack status".to_string());
        let mut refs: Vec<RefStatus> = Vec::new();
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
                refs.push(RefStatus::new(name.to_string(), Ok(())));
            } else if let Some(rest) = text.strip_prefix("ng ") {
                let (name, reason) = rest.split_once(' ').unwrap_or((rest, ""));
                refs.push(RefStatus::new(name.to_string(), Err(reason.to_string())));
            } else if let Some(opt) = text.strip_prefix("option ") {
                // Attach to the ref status the option follows.
                if let Some(last) = refs.last_mut() {
                    let (key, value) = opt.split_once(' ').unwrap_or((opt, ""));
                    last.options.push((key.to_string(), value.to_string()));
                } else {
                    return Err(Error::Protocol(
                        "report-status-v2: option before any ref status".into(),
                    ));
                }
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
    fn parse_detects_sha256_object_format() {
        // A SHA-256 advertisement (64-hex ids) parsed while *assuming* SHA-1:
        // the `object-format=sha256` capability must override the assumption so
        // the id parses and the detected format is reported.
        let id = "a".repeat(64);
        let mut buf = Vec::new();
        let first = alloc::format!("{id} HEAD\0object-format=sha256 ofs-delta\n");
        buf.extend_from_slice(&pktline::encode_data(first.as_bytes()).unwrap());
        buf.extend_from_slice(&pktline::encode_control(&Packet::Flush));
        let packets = pktline::decode_all(&buf).unwrap();

        let adv = RefAdvertisement::parse(HashAlgo::Sha1, &packets).unwrap();
        assert_eq!(adv.object_format, HashAlgo::Sha256);
        assert_eq!(adv.refs.len(), 1);
        assert_eq!(adv.refs[0].name, "HEAD");
        assert_eq!(adv.refs[0].id.to_hex(), id);
    }

    #[test]
    fn report_status_v2_round_trips_options() {
        let report = ReportStatus {
            unpack: Ok(()),
            refs: alloc::vec![
                RefStatus {
                    name: "refs/heads/main".into(),
                    result: Ok(()),
                    options: alloc::vec![
                        (
                            "old-oid".into(),
                            "1111111111111111111111111111111111111111".into()
                        ),
                        (
                            "new-oid".into(),
                            "2222222222222222222222222222222222222222".into()
                        ),
                        ("forced-update".into(), String::new()),
                    ],
                },
                RefStatus::new("refs/heads/dev".into(), Err("non-fast-forward".into())),
            ],
        };

        let wire = report.encode_v2().unwrap();
        let packets = pktline::decode_all(&wire).unwrap();
        let back = ReportStatus::parse_v2(&packets).unwrap();

        assert!(back.unpack.is_ok());
        assert_eq!(back.refs.len(), 2);
        assert_eq!(back.refs[0].name, "refs/heads/main");
        assert!(back.refs[0].result.is_ok());
        assert_eq!(back.refs[0].options.len(), 3);
        assert_eq!(
            back.refs[0].options[0],
            (
                "old-oid".into(),
                "1111111111111111111111111111111111111111".into()
            )
        );
        assert_eq!(
            back.refs[0].options[2],
            ("forced-update".into(), String::new())
        );
        assert_eq!(back.refs[1].result, Err("non-fast-forward".into()));
        assert!(back.refs[1].options.is_empty());
        assert!(!back.is_ok());
    }

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
    fn advertisement_ref_cap_rejected() {
        // Build an advertisement whose ref count exceeds a small local cap by
        // parsing packets directly and asserting the constant-driven guard. We
        // exercise the guard with a tiny synthetic run rather than materializing
        // MAX_ADVERTISED_REFS refs (which would be wasteful); the cap value is a
        // public constant so we verify the guard fires at the boundary using a
        // handful of refs and the same code path.
        let id = "1111111111111111111111111111111111111111";
        let mut packets = Vec::new();
        // First line carries caps; then many plain ref lines.
        let n = MAX_ADVERTISED_REFS + 2;
        packets.push(Packet::Data(
            alloc::format!("{id} refs/heads/b0\0ofs-delta\n").into_bytes(),
        ));
        for i in 1..n {
            packets.push(Packet::Data(
                alloc::format!("{id} refs/heads/b{i}\n").into_bytes(),
            ));
        }
        packets.push(Packet::Flush);
        let err = RefAdvertisement::parse(HashAlgo::Sha1, &packets).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
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
