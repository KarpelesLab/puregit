//! Textual line diffs (unified format).
//!
//! Given two byte buffers, [`unified`] produces a `git diff`-style unified diff:
//! the lines are compared by an LCS (longest-common-subsequence) so the result
//! is a minimal-ish set of insertions and deletions, grouped into `@@ … @@`
//! hunks with surrounding context. This is the engine behind `git diff` for
//! file contents; it is `no_std` (operates on byte slices) and makes no
//! assumption that the input is UTF-8.
//!
//! The LCS is computed with the classic O(n·m) dynamic-programming table, which
//! is simple and exact; switching to Myers' O(nd) algorithm for very large
//! inputs is a possible later optimization.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// One line-level edit operation in a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// A line present in both sides (carried through).
    Equal,
    /// A line only in the old side.
    Delete,
    /// A line only in the new side.
    Insert,
}

/// Splits a buffer into lines, each *including* its trailing `\n` (the last line
/// has none if the input did not end in a newline).
fn split_lines(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            lines.push(&data[start..=i]);
            start = i + 1;
        }
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

/// Computes the line-level edit script between `old` and `new` via LCS.
/// Returns `(op, line)` pairs in output order.
fn line_ops<'a>(old: &[&'a [u8]], new: &[&'a [u8]]) -> Vec<(Op, &'a [u8])> {
    let (n, m) = (old.len(), new.len());
    // lcs[i][j] = length of the LCS of old[i..] and new[j..].
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old[i] == new[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut ops = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if old[i] == new[j] {
            ops.push((Op::Equal, old[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            ops.push((Op::Delete, old[i]));
            i += 1;
        } else {
            ops.push((Op::Insert, new[j]));
            j += 1;
        }
    }
    while i < n {
        ops.push((Op::Delete, old[i]));
        i += 1;
    }
    while j < m {
        ops.push((Op::Insert, new[j]));
        j += 1;
    }
    ops
}

/// Produces a unified diff of `old` vs `new` with `context` lines of context,
/// labeled `--- old_name` / `+++ new_name`. Returns an empty string when the
/// inputs are identical.
pub fn unified(old: &[u8], new: &[u8], old_name: &str, new_name: &str, context: usize) -> String {
    if old == new {
        return String::new();
    }
    let old_lines = split_lines(old);
    let new_lines = split_lines(new);
    let ops = line_ops(&old_lines, &new_lines);

    // Group the ops into hunks: runs of changes plus `context` equal lines
    // around them, merging hunks whose context windows overlap.
    let mut hunks: Vec<(usize, usize)> = Vec::new(); // (start, end) indices into ops
    let mut idx = 0;
    while idx < ops.len() {
        if ops[idx].0 == Op::Equal {
            idx += 1;
            continue;
        }
        // A change run begins; extend it to include changes separated by <=
        // 2*context equal lines.
        let mut start = idx;
        let mut equal_run = 0;
        let mut end = idx;
        let mut k = idx;
        while k < ops.len() {
            if ops[k].0 == Op::Equal {
                equal_run += 1;
                if equal_run > 2 * context {
                    break;
                }
            } else {
                equal_run = 0;
                end = k;
            }
            k += 1;
        }
        // Trim leading/trailing context to `context`.
        start = start.saturating_sub(context);
        let trail = (end + context + 1).min(ops.len());
        // Skip leading equals beyond context already handled by start clamp.
        let _ = &mut start;
        hunks.push((start, trail));
        idx = trail;
    }

    let mut out = String::new();
    out.push_str(&format!("--- {old_name}\n+++ {new_name}\n"));

    for (start, end) in hunks {
        // Compute the 1-based old/new line numbers at `start`.
        let (mut old_no, mut new_no) = (1usize, 1usize);
        for (op, _) in &ops[..start] {
            match op {
                Op::Equal => {
                    old_no += 1;
                    new_no += 1;
                }
                Op::Delete => old_no += 1,
                Op::Insert => new_no += 1,
            }
        }
        let (mut old_count, mut new_count) = (0usize, 0usize);
        for (op, _) in &ops[start..end] {
            match op {
                Op::Equal => {
                    old_count += 1;
                    new_count += 1;
                }
                Op::Delete => old_count += 1,
                Op::Insert => new_count += 1,
            }
        }
        out.push_str(&format!(
            "@@ -{old_no},{old_count} +{new_no},{new_count} @@\n"
        ));
        for (op, line) in &ops[start..end] {
            let prefix = match op {
                Op::Equal => ' ',
                Op::Delete => '-',
                Op::Insert => '+',
            };
            out.push(prefix);
            out.push_str(&String::from_utf8_lossy(line));
            if !line.ends_with(b"\n") {
                out.push('\n');
                out.push_str("\\ No newline at end of file\n");
            }
        }
    }
    out
}

/// The matched line-index pairs `(base_idx, other_idx)` of the LCS of `base`
/// and `other` — the lines that are unchanged between them, in order.
fn matches<'a>(base: &[&'a [u8]], other: &[&'a [u8]]) -> Vec<(usize, usize)> {
    let ops = line_ops(base, other);
    let mut pairs = Vec::new();
    let (mut bi, mut oi) = (0usize, 0usize);
    for (op, _) in ops {
        match op {
            Op::Equal => {
                pairs.push((bi, oi));
                bi += 1;
                oi += 1;
            }
            Op::Delete => bi += 1, // in base only
            Op::Insert => oi += 1, // in other only
        }
    }
    pairs
}

/// The result of a three-way line merge.
pub struct Merge3 {
    /// The merged bytes (with conflict markers where `conflicted` is true).
    pub merged: Vec<u8>,
    /// Whether any region conflicted (both sides changed the same base region
    /// differently).
    pub conflicted: bool,
}

/// Performs a three-way line merge of `ours` and `theirs` against their common
/// `base` (the diff3 algorithm). Regions changed on only one side are taken from
/// that side; regions changed identically on both are taken once; regions
/// changed differently on both are emitted as a conflict bracketed by
/// `<<<<<<< ours` / `=======` / `>>>>>>> theirs` markers.
pub fn merge3(base: &[u8], ours: &[u8], theirs: &[u8]) -> Merge3 {
    let base_l = split_lines(base);
    let ours_l = split_lines(ours);
    let theirs_l = split_lines(theirs);

    // base line index → matched index on each side (unchanged lines).
    let ours_of: alloc::collections::BTreeMap<usize, usize> =
        matches(&base_l, &ours_l).into_iter().collect();
    let theirs_of: alloc::collections::BTreeMap<usize, usize> =
        matches(&base_l, &theirs_l).into_iter().collect();

    // Anchors: base lines unchanged on BOTH sides, in order, plus a terminal
    // sentinel at the ends of all three sequences.
    let mut anchors: Vec<(usize, usize, usize)> = Vec::new();
    for (&bi, &oi) in &ours_of {
        if let Some(&ti) = theirs_of.get(&bi) {
            anchors.push((bi, oi, ti));
        }
    }
    anchors.push((base_l.len(), ours_l.len(), theirs_l.len()));

    let mut merged = Vec::new();
    let mut conflicted = false;
    let (mut pb, mut po, mut pt) = (0usize, 0usize, 0usize);

    for (bi, oi, ti) in anchors {
        let base_region = &base_l[pb..bi];
        let ours_region = &ours_l[po..oi];
        let theirs_region = &theirs_l[pt..ti];

        if ours_region == theirs_region {
            append_lines(&mut merged, ours_region);
        } else if ours_region == base_region {
            append_lines(&mut merged, theirs_region); // only theirs changed
        } else if theirs_region == base_region {
            append_lines(&mut merged, ours_region); // only ours changed
        } else {
            conflicted = true;
            merged.extend_from_slice(b"<<<<<<< ours\n");
            append_lines(&mut merged, ours_region);
            merged.extend_from_slice(b"=======\n");
            append_lines(&mut merged, theirs_region);
            merged.extend_from_slice(b">>>>>>> theirs\n");
        }

        // Emit the anchor line itself (skip the terminal sentinel).
        if bi < base_l.len() {
            merged.extend_from_slice(base_l[bi]);
        }
        pb = bi + 1;
        po = oi + 1;
        pt = ti + 1;
    }

    Merge3 { merged, conflicted }
}

fn append_lines(out: &mut Vec<u8>, lines: &[&[u8]]) {
    for l in lines {
        out.extend_from_slice(l);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_is_empty() {
        assert_eq!(unified(b"a\nb\n", b"a\nb\n", "x", "x", 3), "");
    }

    #[test]
    fn simple_change() {
        let old = b"one\ntwo\nthree\n";
        let new = b"one\nTWO\nthree\n";
        let d = unified(old, new, "a", "b", 3);
        assert!(d.contains("--- a\n+++ b\n"));
        assert!(d.contains("-two\n"));
        assert!(d.contains("+TWO\n"));
        assert!(d.contains(" one\n")); // context
        assert!(d.contains(" three\n"));
    }

    #[test]
    fn pure_insertion_and_deletion() {
        let d = unified(b"a\nc\n", b"a\nb\nc\n", "a", "b", 1);
        assert!(d.contains("+b\n"));
        let d2 = unified(b"a\nb\nc\n", b"a\nc\n", "a", "b", 1);
        assert!(d2.contains("-b\n"));
    }

    #[test]
    fn no_trailing_newline_marker() {
        let d = unified(b"a\n", b"a\nb", "a", "b", 3);
        assert!(d.contains("\\ No newline at end of file"));
    }

    #[test]
    fn merge_non_overlapping_changes() {
        // ours changes line 1, theirs changes line 3 — clean merge.
        let base = b"one\ntwo\nthree\n";
        let ours = b"ONE\ntwo\nthree\n";
        let theirs = b"one\ntwo\nTHREE\n";
        let m = merge3(base, ours, theirs);
        assert!(!m.conflicted);
        assert_eq!(m.merged, b"ONE\ntwo\nTHREE\n");
    }

    #[test]
    fn merge_same_change_both_sides() {
        let base = b"a\nb\n";
        let ours = b"a\nB\n";
        let theirs = b"a\nB\n";
        let m = merge3(base, ours, theirs);
        assert!(!m.conflicted);
        assert_eq!(m.merged, b"a\nB\n");
    }

    #[test]
    fn merge_conflict_both_change_same_line() {
        let base = b"a\nb\nc\n";
        let ours = b"a\nOURS\nc\n";
        let theirs = b"a\nTHEIRS\nc\n";
        let m = merge3(base, ours, theirs);
        assert!(m.conflicted);
        let s = String::from_utf8_lossy(&m.merged);
        assert!(s.contains("<<<<<<< ours\nOURS\n=======\nTHEIRS\n>>>>>>> theirs\n"));
        assert!(s.starts_with("a\n"));
        assert!(s.ends_with("c\n"));
    }
}
