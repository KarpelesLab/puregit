//! EWAH bitmap compression — the encoding git's reachability `.bitmap` uses.
//!
//! EWAH (Enhanced Word-Aligned Hybrid) is a run-length compression for bitmaps
//! built from 64-bit words. The stream alternates *run-length words* (RLWs) —
//! each describing a run of identical "clean" words (all-zero or all-one) plus a
//! count of *literal* words that follow — with those literal words. Long stretches
//! of empty (or full) bitmap collapse to a single RLW, which is exactly the shape
//! a reachability bitmap has.
//!
//! The on-disk layout git uses (all integers big-endian):
//!
//! ```text
//! uint32  bit_size        number of meaningful bits
//! uint32  word_count      number of 64-bit words that follow
//! uint64  words[word_count]
//! uint32  rlw_position    word index of the final RLW
//! ```
//!
//! This module encodes a plain bit vector to that form and decodes it back, so a
//! bitmap round-trips byte-for-byte with git's reader.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// The bit width of one word.
const WORD_BITS: usize = 64;

/// An EWAH-compressed bitmap plus the number of meaningful bits it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ewah {
    /// The number of meaningful bits (the uncompressed length).
    pub bit_size: usize,
    /// The compressed 64-bit words (RLWs interleaved with literals).
    words: Vec<u64>,
    /// Word index of the last RLW written.
    rlw_position: usize,
}

impl Ewah {
    /// Compresses a bitmap given as its raw 64-bit words and its meaningful bit
    /// length. Trailing all-zero words beyond `bit_size` are still compressed.
    pub fn compress(bits: &[u64], bit_size: usize) -> Self {
        let mut words: Vec<u64> = Vec::new();
        let mut rlw_position = 0;
        let mut i = 0;
        while i < bits.len() {
            // A run of identical clean words (all 0x0 or all ~0).
            let clean_val = if bits[i] == 0 {
                Some(false)
            } else if bits[i] == u64::MAX {
                Some(true)
            } else {
                None
            };

            if let Some(bit) = clean_val {
                let target = if bit { u64::MAX } else { 0 };
                let start = i;
                while i < bits.len() && bits[i] == target {
                    i += 1;
                }
                let run_len = (i - start) as u64;
                // Count the literal words that immediately follow this run.
                let lit_start = i;
                while i < bits.len() && bits[i] != 0 && bits[i] != u64::MAX {
                    i += 1;
                }
                let literals = &bits[lit_start..i];
                rlw_position = words.len();
                words.push(make_rlw(bit, run_len, literals.len() as u64));
                words.extend_from_slice(literals);
            } else {
                // A literal not preceded by a clean run: emit an empty run RLW.
                let lit_start = i;
                while i < bits.len() && bits[i] != 0 && bits[i] != u64::MAX {
                    i += 1;
                }
                let literals = &bits[lit_start..i];
                rlw_position = words.len();
                words.push(make_rlw(false, 0, literals.len() as u64));
                words.extend_from_slice(literals);
            }
        }
        if words.is_empty() {
            // An all-empty bitmap is a single empty RLW.
            words.push(make_rlw(false, 0, 0));
        }
        Ewah {
            bit_size,
            words,
            rlw_position,
        }
    }

    /// Compresses a bitmap given as the sorted positions of its set bits.
    pub fn from_set_bits(set: &[usize], bit_size: usize) -> Self {
        let word_len = bit_size.div_ceil(WORD_BITS);
        let mut words = alloc::vec![0u64; word_len];
        for &b in set {
            if b < bit_size {
                words[b / WORD_BITS] |= 1u64 << (b % WORD_BITS);
            }
        }
        Ewah::compress(&words, bit_size)
    }

    /// Serializes to git's on-disk EWAH layout (big-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.words.len() * 8);
        out.extend_from_slice(&(self.bit_size as u32).to_be_bytes());
        out.extend_from_slice(&(self.words.len() as u32).to_be_bytes());
        for w in &self.words {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out.extend_from_slice(&(self.rlw_position as u32).to_be_bytes());
        out
    }

    /// Parses git's on-disk EWAH layout, returning the bitmap and the number of
    /// bytes consumed.
    pub fn from_bytes(data: &[u8]) -> Result<(Ewah, usize)> {
        if data.len() < 8 {
            return Err(Error::Parse("ewah: truncated header".into()));
        }
        let bit_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let word_count = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let end = 8 + word_count * 8;
        if data.len() < end + 4 {
            return Err(Error::Parse("ewah: truncated words".into()));
        }
        let mut words = Vec::with_capacity(word_count);
        for chunk in data[8..end].as_chunks::<8>().0 {
            words.push(u64::from_be_bytes(*chunk));
        }
        let rlw_position =
            u32::from_be_bytes([data[end], data[end + 1], data[end + 2], data[end + 3]]) as usize;
        Ok((
            Ewah {
                bit_size,
                words,
                rlw_position,
            },
            end + 4,
        ))
    }

    /// Decompresses back to the raw 64-bit words of the bitmap.
    pub fn decompress(&self) -> Vec<u64> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.words.len() {
            let rlw = self.words[i];
            i += 1;
            let (bit, run_len, literals) = split_rlw(rlw);
            let fill = if bit { u64::MAX } else { 0 };
            for _ in 0..run_len {
                out.push(fill);
            }
            for _ in 0..literals {
                if i < self.words.len() {
                    out.push(self.words[i]);
                    i += 1;
                }
            }
        }
        out
    }

    /// Returns the positions of the set bits (bounded by `bit_size`).
    pub fn set_bits(&self) -> Vec<usize> {
        let mut out = Vec::new();
        for (wi, word) in self.decompress().iter().enumerate() {
            if *word == 0 {
                continue;
            }
            for b in 0..WORD_BITS {
                let pos = wi * WORD_BITS + b;
                if pos >= self.bit_size {
                    return out;
                }
                if word & (1u64 << b) != 0 {
                    out.push(pos);
                }
            }
        }
        out
    }
}

/// Packs a run-length word: `bit` = the clean run's value, `run_len` clean words,
/// then `literals` literal words.
fn make_rlw(bit: bool, run_len: u64, literals: u64) -> u64 {
    (bit as u64) | (run_len << 1) | (literals << 33)
}

/// Unpacks a run-length word into `(clean bit, clean word count, literal count)`.
fn split_rlw(rlw: u64) -> (bool, u64, u64) {
    let bit = rlw & 1 != 0;
    let run_len = (rlw >> 1) & 0xFFFF_FFFF;
    let literals = (rlw >> 33) & 0x7FFF_FFFF;
    (bit, run_len, literals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(set: &[usize], bit_size: usize) {
        let ewah = Ewah::from_set_bits(set, bit_size);
        // Wire round-trip.
        let bytes = ewah.to_bytes();
        let (parsed, n) = Ewah::from_bytes(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(parsed, ewah);
        // Semantic round-trip.
        assert_eq!(parsed.set_bits(), set);
    }

    #[test]
    fn empty_bitmap() {
        roundtrip(&[], 0);
        roundtrip(&[], 200);
    }

    #[test]
    fn sparse_bits() {
        roundtrip(&[0], 1);
        roundtrip(&[3, 5, 63], 64);
        roundtrip(&[0, 64, 128, 200], 256);
    }

    #[test]
    fn long_runs_compress() {
        // A single bit far out — the leading empty words become one RLW.
        let ewah = Ewah::from_set_bits(&[10_000], 10_001);
        // Far fewer than 157 words (10001/64) thanks to the run-length word.
        assert!(ewah.to_bytes().len() < 64, "long empty run must compress");
        assert_eq!(ewah.set_bits(), alloc::vec![10_000]);
    }

    #[test]
    fn all_ones_run() {
        // Every bit in three words set: compresses to a full run.
        let set: Vec<usize> = (0..192).collect();
        roundtrip(&set, 192);
        let ewah = Ewah::from_set_bits(&set, 192);
        assert!(ewah.to_bytes().len() < 40, "a full run must compress");
    }

    #[test]
    fn mixed_runs_and_literals() {
        // Empty run, a literal word, a full run, a literal.
        let mut set: Vec<usize> = alloc::vec![70]; // literal in word 1
        set.extend(128..192); // full word 2
        set.push(260); // literal in word 4
        set.sort_unstable();
        roundtrip(&set, 320);
    }
}
