//! pkt-line framing — the packet format underlying every git transport.
//!
//! Git's smart protocol frames every message as a *pkt-line*: a four-character
//! hexadecimal length prefix followed by that many bytes (the length *includes*
//! the four-byte prefix). Three short lengths are special control packets:
//!
//! - `0000` — **flush-pkt**, a section terminator.
//! - `0001` — **delim-pkt**, a section separator (protocol v2).
//! - `0002` — **response-end-pkt** (protocol v2 stateless sideband).
//!
//! A normal data line carries 1..=65516 payload bytes (the maximum line length
//! is 65520 including the prefix). This module encodes and decodes that framing
//! without any I/O — the transports feed it bytes.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// The maximum total length of a pkt-line, including the 4-byte prefix.
pub const MAX_PKTLINE_LEN: usize = 65520;

/// A decoded pkt-line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// A data packet carrying a payload (without the length prefix).
    Data(Vec<u8>),
    /// `0000` — flush.
    Flush,
    /// `0001` — section delimiter (v2).
    Delim,
    /// `0002` — response end (v2).
    ResponseEnd,
}

/// Encodes a data payload as a pkt-line (prefix + payload). Errors if the
/// payload would exceed [`MAX_PKTLINE_LEN`].
pub fn encode_data(payload: &[u8]) -> Result<Vec<u8>> {
    let total = payload.len() + 4;
    if total > MAX_PKTLINE_LEN {
        return Err(Error::Protocol("pkt-line: payload too long".into()));
    }
    let mut out = Vec::with_capacity(total);
    write_len_prefix(&mut out, total as u16);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Encodes a control packet (flush / delim / response-end).
pub fn encode_control(packet: &Packet) -> Vec<u8> {
    let bytes: &[u8; 4] = match packet {
        Packet::Flush => b"0000",
        Packet::Delim => b"0001",
        Packet::ResponseEnd => b"0002",
        Packet::Data(_) => unreachable!("use encode_data for data packets"),
    };
    bytes.to_vec()
}

/// Encodes any [`Packet`].
pub fn encode(packet: &Packet) -> Result<Vec<u8>> {
    match packet {
        Packet::Data(p) => encode_data(p),
        other => Ok(encode_control(other)),
    }
}

/// Decodes a single pkt-line from the front of `input`, returning the packet
/// and the number of bytes consumed. Returns `Ok(None)` if `input` does not yet
/// contain a complete pkt-line (the caller should read more and retry).
pub fn decode(input: &[u8]) -> Result<Option<(Packet, usize)>> {
    if input.len() < 4 {
        return Ok(None);
    }
    let len = parse_len_prefix(&input[..4])?;
    match len {
        0 => Ok(Some((Packet::Flush, 4))),
        1 => Ok(Some((Packet::Delim, 4))),
        2 => Ok(Some((Packet::ResponseEnd, 4))),
        3 => Err(Error::Protocol("pkt-line: invalid length 3".into())),
        n => {
            let n = n as usize;
            if !(4..=MAX_PKTLINE_LEN).contains(&n) {
                return Err(Error::Protocol("pkt-line: length out of range".into()));
            }
            if input.len() < n {
                return Ok(None); // incomplete
            }
            Ok(Some((Packet::Data(input[4..n].to_vec()), n)))
        }
    }
}

/// Decodes a complete buffer into all of its packets. Errors if the buffer ends
/// mid-packet.
pub fn decode_all(mut input: &[u8]) -> Result<Vec<Packet>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        match decode(input)? {
            Some((packet, consumed)) => {
                out.push(packet);
                input = &input[consumed..];
            }
            None => return Err(Error::Protocol("pkt-line: trailing partial packet".into())),
        }
    }
    Ok(out)
}

fn write_len_prefix(out: &mut Vec<u8>, len: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[((len >> 12) & 0xf) as usize]);
    out.push(HEX[((len >> 8) & 0xf) as usize]);
    out.push(HEX[((len >> 4) & 0xf) as usize]);
    out.push(HEX[(len & 0xf) as usize]);
}

fn parse_len_prefix(b: &[u8]) -> Result<u16> {
    let mut v = 0u16;
    for &c in &b[..4] {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return Err(Error::Protocol("pkt-line: non-hex length prefix".into())),
        };
        v = (v << 4) | d as u16;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_roundtrip() {
        let line = encode_data(b"want abc\n").unwrap();
        // "0010" = 16 = 4 + 12? payload "want abc\n" is 9 bytes → total 13 = 0x0d.
        assert_eq!(&line[..4], b"000d");
        let (pkt, n) = decode(&line).unwrap().unwrap();
        assert_eq!(n, line.len());
        assert_eq!(pkt, Packet::Data(b"want abc\n".to_vec()));
    }

    #[test]
    fn control_packets() {
        assert_eq!(decode(b"0000").unwrap().unwrap().0, Packet::Flush);
        assert_eq!(decode(b"0001").unwrap().unwrap().0, Packet::Delim);
        assert_eq!(decode(b"0002").unwrap().unwrap().0, Packet::ResponseEnd);
    }

    #[test]
    fn incomplete_returns_none() {
        assert_eq!(decode(b"00").unwrap(), None);
        assert_eq!(decode(b"000d").unwrap(), None); // header says 13, only 4 present
    }

    #[test]
    fn decode_all_stream() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_data(b"line1").unwrap());
        buf.extend_from_slice(&encode_data(b"line2").unwrap());
        buf.extend_from_slice(&encode_control(&Packet::Flush));
        let pkts = decode_all(&buf).unwrap();
        assert_eq!(pkts.len(), 3);
        assert_eq!(pkts[2], Packet::Flush);
    }
}
