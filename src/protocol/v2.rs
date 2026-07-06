//! Git wire protocol **version 2** (the command-oriented protocol).
//!
//! Where v0/v1 begins every connection with a full ref advertisement, v2 begins
//! with a *capability* advertisement and then runs discrete commands the client
//! names: `ls-refs` (enumerate refs) and `fetch` (negotiate and receive a pack).
//! This module implements the server half — the framing a v2 client (including
//! real `git`) drives — as sans-IO functions over decoded pkt-lines.
//!
//! A v2 request is a `command=<name>` pkt-line, then a delim-pkt (`0001`), then
//! argument pkt-lines, then a flush. Responses are pkt-line sections; the fetch
//! response's `packfile` section multiplexes the pack over sideband channel 1.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::oid::{HashAlgo, ObjectId};

use super::pktline::{self, Packet};

/// The largest pack payload carried in one `side-band-64k` pkt-line (max line
/// length less the 4-byte length prefix and the 1-byte band marker).
const SIDEBAND_MAX_PAYLOAD: usize = pktline::MAX_PKTLINE_LEN - 4 - 1;

/// A ref as `ls-refs` advertises it: its `(name, id, symref-target, peeled)` —
/// where `symref-target` is the target of a symbolic ref (e.g. `HEAD`) and
/// `peeled` is the commit an annotated tag dereferences to, each present only
/// when applicable.
pub type LsRef = (String, ObjectId, Option<String>, Option<ObjectId>);

/// The agent string this implementation advertises.
const AGENT: &str = concat!("puregit/", env!("CARGO_PKG_VERSION"));

/// Builds the v2 capability advertisement — the response to `GET
/// info/refs?service=git-upload-pack` when the client sent `Git-Protocol:
/// version=2`, and the greeting on a stateful v2 connection.
///
/// It announces protocol version 2 and the commands/capabilities this server
/// supports: `ls-refs` and a basic `fetch` (no shallow/filter), plus the agent
/// and object-format.
pub fn capability_advertisement(algo: HashAlgo) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&pktline::encode_data(b"version 2\n")?);
    out.extend_from_slice(&pktline::encode_data(
        alloc::format!("agent={AGENT}\n").as_bytes(),
    )?);
    out.extend_from_slice(&pktline::encode_data(b"ls-refs=unborn\n")?);
    out.extend_from_slice(&pktline::encode_data(b"fetch\n")?);
    out.extend_from_slice(&pktline::encode_data(
        alloc::format!("object-format={}\n", algo.name()).as_bytes(),
    )?);
    out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
    Ok(out)
}

/// A parsed v2 command request: the command name and its argument lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The command name from the `command=<name>` line (e.g. `ls-refs`).
    pub name: String,
    /// The capability lines that preceded the delimiter (e.g. `object-format`,
    /// `agent`).
    pub capabilities: Vec<String>,
    /// The argument lines after the delimiter, trimmed of their trailing newline.
    pub args: Vec<String>,
}

impl Command {
    /// Parses a v2 request: `command=<name>` and capability lines, a delim-pkt,
    /// then argument lines, terminated by a flush.
    pub fn parse(packets: &[Packet]) -> Result<Self> {
        let mut name = None;
        let mut capabilities = Vec::new();
        let mut args = Vec::new();
        let mut after_delim = false;

        for packet in packets {
            match packet {
                Packet::Delim => after_delim = true,
                Packet::Flush => break,
                Packet::Data(d) => {
                    let line = trim_newline(d);
                    let text = String::from_utf8_lossy(line).to_string();
                    if after_delim {
                        args.push(text);
                    } else if let Some(cmd) = text.strip_prefix("command=") {
                        name = Some(cmd.to_string());
                    } else {
                        capabilities.push(text);
                    }
                }
                Packet::ResponseEnd => break,
            }
        }

        Ok(Command {
            name: name.ok_or_else(|| Error::Protocol("v2: request has no command".into()))?,
            capabilities,
            args,
        })
    }

    /// Whether an argument line equal to `arg` is present.
    pub fn has_arg(&self, arg: &str) -> bool {
        self.args.iter().any(|a| a == arg)
    }
}

/// Builds the `ls-refs` response: one `"<oid> <name>"` line per ref (with
/// `symref-target:` / `peeled:` attributes when requested), terminated by a
/// flush.
///
/// `refs` are `(name, id, symref_target, peeled)` tuples. `symref_target` is the
/// target a symbolic ref points at (only emitted when the client asked for
/// `symrefs`); `peeled` is the commit an annotated tag dereferences to (only
/// emitted when the client asked to `peel`). Only refs whose name starts with one
/// of the request's `ref-prefix` args are included (all, if none given).
pub fn encode_ls_refs_response(command: &Command, refs: &[LsRef]) -> Result<Vec<u8>> {
    let want_symrefs = command.has_arg("symrefs");
    let want_peel = command.has_arg("peel");
    let prefixes: Vec<&str> = command
        .args
        .iter()
        .filter_map(|a| a.strip_prefix("ref-prefix "))
        .collect();

    let mut out = Vec::new();
    for (name, id, symref, peeled) in refs {
        if !prefixes.is_empty() && !prefixes.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let mut line = alloc::format!("{} {name}", id.to_hex());
        if want_symrefs && let Some(target) = symref {
            line.push_str(&alloc::format!(" symref-target:{target}"));
        }
        if want_peel && let Some(p) = peeled {
            line.push_str(&alloc::format!(" peeled:{}", p.to_hex()));
        }
        line.push('\n');
        out.extend_from_slice(&pktline::encode_data(line.as_bytes())?);
    }
    out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
    Ok(out)
}

/// The parsed arguments of a v2 `fetch` command.
#[derive(Debug, Clone, Default)]
pub struct FetchArgs {
    /// Object ids the client wants (`want <oid>` lines).
    pub wants: Vec<ObjectId>,
    /// Object ids the client already has (`have <oid>` lines).
    pub haves: Vec<ObjectId>,
    /// Whether the client sent `done` (negotiation is over; send the pack).
    pub done: bool,
    /// Whether the client offered `thin-pack`.
    pub thin_pack: bool,
    /// Whether the client asked for `no-progress`.
    pub no_progress: bool,
}

impl FetchArgs {
    /// Parses the argument lines of a `fetch` [`Command`].
    pub fn parse(algo: HashAlgo, command: &Command) -> Result<Self> {
        let mut args = FetchArgs::default();
        for line in &command.args {
            if let Some(oid) = line.strip_prefix("want ") {
                args.wants.push(ObjectId::from_hex(algo, oid.trim())?);
            } else if let Some(oid) = line.strip_prefix("have ") {
                args.haves.push(ObjectId::from_hex(algo, oid.trim())?);
            } else if line == "done" {
                args.done = true;
            } else if line == "thin-pack" {
                args.thin_pack = true;
            } else if line == "no-progress" {
                args.no_progress = true;
            }
            // Unknown args (ofs-delta, include-tag, …) are accepted and ignored.
        }
        Ok(args)
    }
}

/// Wraps a built `pack` in the v2 `fetch` response: an `acknowledgments` section
/// is omitted (the client sent `done`), and the `packfile` section carries the
/// pack multiplexed over sideband channel 1, ended by a flush.
pub fn encode_fetch_response(pack: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // The packfile section header, then sideband-framed pack data (band 1).
    out.extend_from_slice(&pktline::encode_data(b"packfile\n")?);
    for chunk in pack.chunks(SIDEBAND_MAX_PAYLOAD) {
        let mut line = Vec::with_capacity(chunk.len() + 1);
        line.push(1); // sideband channel 1: pack data
        line.extend_from_slice(chunk);
        out.extend_from_slice(&pktline::encode_data(&line)?);
    }
    out.extend_from_slice(&pktline::encode_control(&Packet::Flush));
    Ok(out)
}

/// Strips a single trailing `\n` from a line, if present.
fn trim_newline(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\n") {
        Some(rest) => rest,
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_advertisement_announces_v2_and_commands() {
        let bytes = capability_advertisement(HashAlgo::Sha1).unwrap();
        let packets = pktline::decode_all(&bytes).unwrap();
        let lines: Vec<String> = packets
            .iter()
            .filter_map(|p| match p {
                Packet::Data(d) => Some(String::from_utf8_lossy(trim_newline(d)).to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(lines[0], "version 2");
        assert!(lines.iter().any(|l| l == "ls-refs=unborn"));
        assert!(lines.iter().any(|l| l == "fetch"));
        assert!(lines.iter().any(|l| l == "object-format=sha1"));
    }

    #[test]
    fn parses_a_command_with_caps_and_args() {
        let mut req = Vec::new();
        req.extend(pktline::encode_data(b"command=fetch\n").unwrap());
        req.extend(pktline::encode_data(b"object-format=sha1\n").unwrap());
        req.extend(pktline::encode_control(&Packet::Delim));
        req.extend(
            pktline::encode_data(b"want 1111111111111111111111111111111111111111\n").unwrap(),
        );
        req.extend(pktline::encode_data(b"done\n").unwrap());
        req.extend(pktline::encode_control(&Packet::Flush));

        let cmd = Command::parse(&pktline::decode_all(&req).unwrap()).unwrap();
        assert_eq!(cmd.name, "fetch");
        assert!(cmd.capabilities.iter().any(|c| c == "object-format=sha1"));
        assert!(cmd.has_arg("done"));

        let args = FetchArgs::parse(HashAlgo::Sha1, &cmd).unwrap();
        assert_eq!(args.wants.len(), 1);
        assert!(args.done);
    }

    #[test]
    fn ls_refs_filters_by_prefix_and_adds_attrs() {
        let mut req = Vec::new();
        req.extend(pktline::encode_data(b"command=ls-refs\n").unwrap());
        req.extend(pktline::encode_control(&Packet::Delim));
        req.extend(pktline::encode_data(b"symrefs\n").unwrap());
        req.extend(pktline::encode_data(b"ref-prefix refs/heads/\n").unwrap());
        req.extend(pktline::encode_control(&Packet::Flush));
        let cmd = Command::parse(&pktline::decode_all(&req).unwrap()).unwrap();

        let id = ObjectId::from_hex(HashAlgo::Sha1, &"a".repeat(40)).unwrap();
        let refs = alloc::vec![
            (
                "HEAD".to_string(),
                id,
                Some("refs/heads/main".to_string()),
                None
            ),
            ("refs/heads/main".to_string(), id, None, None),
            ("refs/tags/v1".to_string(), id, None, None),
        ];
        let resp = encode_ls_refs_response(&cmd, &refs).unwrap();
        let text = String::from_utf8_lossy(&resp);
        // HEAD is filtered out (doesn't match refs/heads/ prefix); main is kept;
        // the tag is filtered out.
        assert!(text.contains("refs/heads/main"));
        assert!(!text.contains("refs/tags/v1"));
        assert!(!text.contains("HEAD"));
    }

    #[test]
    fn fetch_response_wraps_pack_in_sideband() {
        let resp = encode_fetch_response(b"PACKDATA").unwrap();
        let packets = pktline::decode_all(&resp).unwrap();
        // First a "packfile" header line, then a band-1 data line carrying it.
        assert_eq!(packets[0], Packet::Data(b"packfile\n".to_vec()));
        match &packets[1] {
            Packet::Data(d) => {
                assert_eq!(d[0], 1);
                assert_eq!(&d[1..], b"PACKDATA");
            }
            other => panic!("expected sideband data, got {other:?}"),
        }
        assert_eq!(packets.last(), Some(&Packet::Flush));
    }
}
