//! zlib (RFC 1950) compression, the on-disk encoding for git data.
//!
//! Both loose objects and the object contents inside a packfile are stored as
//! zlib streams. These are thin one-shot wrappers over [`compcol`]'s pure-Rust
//! `zlib` codec, mapping its errors into [`crate::Error`].
//!
//! The capped [`inflate_capped`] variant is the one object/pack code should
//! prefer: a loose object header declares its uncompressed size, so we can
//! bound the output and refuse a corrupt or hostile stream that would otherwise
//! decompress without limit.

use alloc::vec::Vec;
use compcol::zlib::Zlib;

use crate::error::{Error, Result};

/// Compresses `data` into a zlib stream (default compression level).
pub fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    Ok(compcol::vec::compress_to_vec::<Zlib>(data)?)
}

/// Decompresses a complete zlib stream with no explicit output bound.
///
/// Prefer [`inflate_capped`] wherever the expected size is known (it always is
/// for git objects, which prefix their uncompressed length).
pub fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    Ok(compcol::vec::decompress_to_vec::<Zlib>(data)?)
}

/// Decompresses a zlib stream, refusing to produce more than `max` bytes.
///
/// Used by the loose-object and packfile readers, which know the declared
/// uncompressed size up front: a stream that tries to exceed it is corrupt (or
/// malicious) and is rejected rather than allowed to exhaust memory. `data` may
/// contain trailing bytes after the zlib stream (a packfile object is followed
/// by more objects and the pack checksum); decoding stops cleanly at the stream
/// end and ignores them.
///
/// This drives the streaming decoder over a fixed scratch buffer and enforces
/// `max` against the accumulated output itself, rather than delegating the
/// bound to the codec. That deliberately avoids `compcol`'s
/// `decompress_to_vec_capped`, whose budgeted decoder spins forever when the
/// decoded size meets the cap exactly while the stream trailer (or following
/// pack bytes) is still unconsumed — the common case for a packed object, whose
/// cap is its exact declared size.
pub fn inflate_capped(data: &[u8], max: usize) -> Result<Vec<u8>> {
    inflate_counted(data, max).map(|(out, _consumed)| out)
}

/// Decompresses one zlib stream and returns the output plus the *exact*
/// compressed length, suitable for packfile iteration.
///
/// Packfile objects are stored back-to-back with no length prefix, so after
/// decoding one object the next begins at `object_offset + header_len +
/// compressed_len`. The underlying decoder ([`inflate_counted`]) may report a
/// few extra lookahead bytes past the true stream end when trailing data
/// follows (it pulls bytes into its bit buffer), so this recovers the exact end
/// by shrinking the input until it no longer decodes to the same output. The
/// over-read is only a handful of bytes, so this costs a small, bounded number
/// of re-inflations.
pub fn inflate_exact(data: &[u8], max: usize) -> Result<(Vec<u8>, usize)> {
    let (out, over) = inflate_counted(data, max)?;
    // The true compressed length is the smallest prefix that still decodes to
    // the same bytes. Shrink down from the (possibly over-reported) length;
    // the over-read is tiny, so cap the search to stay cheap and bounded.
    const MAX_OVERREAD: usize = 64;
    let floor = over.saturating_sub(MAX_OVERREAD);
    let mut exact = over;
    let mut len = over;
    while len > floor && len > 0 {
        let cand = len - 1;
        match inflate_counted(&data[..cand], max) {
            Ok((o, _)) if o == out => {
                exact = cand;
                len = cand;
            }
            _ => break,
        }
    }
    Ok((out, exact))
}

/// Like [`inflate_capped`], but also returns how many bytes of `data` the
/// decoder consumed. The count may include a few lookahead bytes past the true
/// zlib stream end when trailing data is present; use [`inflate_exact`] when the
/// precise compressed length is required (packfile iteration).
pub fn inflate_counted(data: &[u8], max: usize) -> Result<(Vec<u8>, usize)> {
    use compcol::zlib::Decoder as ZlibDecoder;
    use compcol::{Decoder, Status};

    let mut dec = ZlibDecoder::new();
    let mut out = Vec::new();
    // A real (non-empty) scratch buffer means `OutputFull` always reflects a
    // full *scratch* — guaranteeing forward progress — never an exhausted
    // budget that would stall.
    let mut scratch = [0u8; 16 * 1024];

    let mut consumed = 0usize;
    loop {
        let (progress, status) = dec
            .decode(&data[consumed..], &mut scratch)
            .map_err(map_err)?;
        out.extend_from_slice(&scratch[..progress.written]);
        consumed += progress.consumed;
        if out.len() > max {
            return Err(Error::Compression("inflate exceeded declared size".into()));
        }
        match status {
            Status::StreamEnd => return Ok((out, consumed)),
            Status::InputEmpty => break,
            Status::OutputFull => {
                // `OutputFull` with forward progress means our scratch filled —
                // drain and continue. `OutputFull` with *no* progress is how the
                // zlib decoder signals it has finished the stream (and will not
                // consume the trailing pack bytes): stop and flush via finish().
                if progress.written == 0 && progress.consumed == 0 {
                    break;
                }
            }
        }
    }
    // Flush: the decoder must now report the stream end. A non-end status with
    // nothing left to write means the input was truncated mid-stream.
    loop {
        let (progress, status) = dec.finish(&mut scratch).map_err(map_err)?;
        out.extend_from_slice(&scratch[..progress.written]);
        if out.len() > max {
            return Err(Error::Compression("inflate exceeded declared size".into()));
        }
        match status {
            Status::StreamEnd => return Ok((out, consumed)),
            _ if progress.written == 0 => {
                return Err(Error::Compression("truncated zlib stream".into()));
            }
            _ => continue,
        }
    }
}

fn map_err(e: compcol::Error) -> Error {
    use alloc::format;
    Error::Compression(format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let msg = b"the quick brown fox jumps over the lazy dog";
        let z = deflate(msg).unwrap();
        assert_eq!(inflate(&z).unwrap(), msg);
        assert_eq!(inflate_capped(&z, msg.len()).unwrap(), msg);
    }

    #[test]
    fn cap_is_enforced() {
        let z = deflate(&[7u8; 4096]).unwrap();
        assert!(inflate_capped(&z, 16).is_err());
    }

    // Regression: a packed object is decoded with a cap equal to its exact
    // declared size, and its zlib stream is followed by trailing bytes (the
    // next object + the pack checksum). The exact-cap-with-trailer case must
    // terminate, not spin. The empty payload (cap 0) is the sharpest version.
    #[test]
    fn exact_cap_with_trailing_bytes() {
        for payload in [&b""[..], &b"hello\n"[..], &[9u8; 5000][..]] {
            let mut z = deflate(payload).unwrap();
            z.extend_from_slice(b"TRAILING-PACK-BYTES-AND-CHECKSUM");
            let got = inflate_capped(&z, payload.len()).unwrap();
            assert_eq!(got, payload, "exact-cap decode for len {}", payload.len());
        }
    }

    #[test]
    fn over_cap_by_one_is_rejected() {
        let z = deflate(b"hello\n").unwrap();
        assert!(inflate_capped(&z, 5).is_err()); // declares 5, stream yields 6
    }

    // A scratch-buffer-sized output (forcing several real `OutputFull` drains)
    // must still decode correctly and not be confused with the no-progress
    // "done" signal.
    #[test]
    fn large_output_drains_correctly() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut z = deflate(&payload).unwrap();
        z.extend_from_slice(b"TRAILER");
        assert_eq!(inflate_capped(&z, payload.len()).unwrap(), payload);
    }

    // inflate_exact must report the exact compressed stream length even with
    // trailing bytes present (packfile iteration relies on it to locate the next
    // object). The empty payload is the sharp case where the raw decoder
    // over-reads its bit buffer past the stream end.
    #[test]
    fn inflate_exact_reports_true_length() {
        for payload in [&b""[..], &b"hi\n"[..], &[5u8; 1000][..], &[0u8; 70_000][..]] {
            let stream = deflate(payload).unwrap();
            let exact = stream.len();

            let (out, n) = inflate_exact(&stream, payload.len()).unwrap();
            assert_eq!(out, payload);
            assert_eq!(n, exact, "no-trailer exact for len {}", payload.len());

            let mut with_trailer = stream.clone();
            with_trailer.extend_from_slice(b"NEXTOBJECTHEADER....");
            let (out2, n2) = inflate_exact(&with_trailer, payload.len()).unwrap();
            assert_eq!(out2, payload);
            assert_eq!(n2, exact, "with-trailer exact for len {}", payload.len());
        }
    }
}
