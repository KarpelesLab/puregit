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
}
