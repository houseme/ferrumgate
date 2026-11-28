//! Port range arithmetic for the open-port view (WP-53 实施步骤 1): pure
//! parsing, merging, subtraction and counting. Ranges are inclusive on
//! both ends and always normalized (sorted, overlapping and adjacent
//! ranges merged), so the internal representation stays compact even for
//! the thousands of ports a module may register (conventions: the open
//! ports must be ranges, never individual ports).
//!
//! No I/O happens here; every function takes and returns plain data.

use std::fmt;

/// An inclusive port range `lo..=hi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    pub lo: u16,
    pub hi: u16,
}

impl Range {
    /// A single-port range.
    pub fn single(port: u16) -> Self {
        Self { lo: port, hi: port }
    }

    /// A range from `lo` to `hi`; a reversed pair is normalized.
    pub fn new(lo: u16, hi: u16) -> Self {
        Self {
            lo: lo.min(hi),
            hi: lo.max(hi),
        }
    }

    /// Number of ports inside the range.
    pub fn len(&self) -> usize {
        usize::from(self.hi - self.lo) + 1
    }

    /// Always at least one port.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether `port` falls inside the range.
    pub fn contains(&self, port: u16) -> bool {
        self.lo <= port && port <= self.hi
    }

    /// The ports of the range, ascending (bounded by the `u16` domain).
    pub fn ports(&self) -> impl Iterator<Item = u16> {
        self.lo..=self.hi
    }
}

impl fmt::Display for Range {
    /// `23` for a single port, `5900-5910` for a range (the port-list
    /// syntax the settings accept).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// Whether `text` parses as one port or one `lo-hi` range token.
fn parse_token(token: &str) -> Option<Range> {
    let token = token.trim();
    if let Some((lo, hi)) = token.split_once('-') {
        let lo: u16 = lo.trim().parse().ok()?;
        let hi: u16 = hi.trim().parse().ok()?;
        return Some(Range::new(lo, hi));
    }
    let port: u16 = token.parse().ok()?;
    Some(Range::single(port))
}

/// The tokens of `text` that are neither empty separators nor valid port
/// or range tokens (validation reports them; parsing skips them).
pub fn bad_tokens(text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for token in split_tokens(text) {
        if parse_token(&token).is_none() {
            bad.push(token);
        }
    }
    bad
}

/// Splits on commas, ASCII whitespace and newlines; empty items between
/// separators are skipped (unlike the strict listener parser, the trap
/// port list is a set and tolerates stray separators).
fn split_tokens(text: &str) -> Vec<String> {
    text.split([',', '，', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parses a port list such as `23,3389,5900-5910` (separators: commas,
/// whitespace, newlines) into normalized ranges. Invalid tokens are
/// skipped — [`bad_tokens`] surfaces them for validation; overlapping and
/// adjacent ranges are merged.
pub fn parse_ports(text: &str) -> Vec<Range> {
    let mut ranges = Vec::new();
    for token in split_tokens(text) {
        if let Some(range) = parse_token(&token) {
            ranges.push(range);
        }
    }
    merge(ranges)
}

/// Sorts and merges overlapping and adjacent ranges.
pub fn merge(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_by_key(|range| (range.lo, range.hi));
    let mut merged: Vec<Range> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            // Adjacent (hi + 1 == lo) or overlapping: extend in place.
            Some(last) if usize::from(last.hi) + 1 >= usize::from(range.lo) => {
                last.hi = last.hi.max(range.hi);
            }
            _ => merged.push(range),
        }
    }
    merged
}

/// Union of two normalized range lists.
pub fn union(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut all = a.to_vec();
    all.extend_from_slice(b);
    merge(all)
}

/// Splits `ranges` by the `remove` predicate: returns `(remaining,
/// removed)` as normalized ranges. Every port is visited once, so the
/// worst case stays bounded by the `u16` port space per call.
pub fn subtract(ranges: &[Range], remove: &dyn Fn(u16) -> bool) -> (Vec<Range>, Vec<Range>) {
    let mut remaining = Vec::new();
    let mut removed = Vec::new();
    for range in ranges {
        let mut kept_start: Option<u16> = None;
        let mut dropped_start: Option<u16> = None;
        for port in range.ports() {
            if remove(port) {
                if let Some(start) = kept_start.take() {
                    remaining.push(Range::new(start, port - 1));
                }
                if dropped_start.is_none() {
                    dropped_start = Some(port);
                }
            } else {
                if let Some(start) = dropped_start.take() {
                    removed.push(Range::new(start, port - 1));
                }
                if kept_start.is_none() {
                    kept_start = Some(port);
                }
            }
        }
        if let Some(start) = kept_start {
            remaining.push(Range::new(start, range.hi));
        }
        if let Some(start) = dropped_start {
            removed.push(Range::new(start, range.hi));
        }
    }
    (merge(remaining), merge(removed))
}

/// Total number of ports inside the ranges.
pub fn count(ranges: &[Range]) -> usize {
    ranges.iter().map(Range::len).sum()
}

/// Whether any range contains `port`.
pub fn contains(ranges: &[Range], port: u16) -> bool {
    ranges.iter().any(|range| range.contains(port))
}

/// Expands at most `cap` ports from the front of the normalized list and
/// re-merges them into ranges (the user-trap cap of 64 ports).
pub fn take_ports(ranges: &[Range], cap: usize) -> Vec<Range> {
    if cap == 0 {
        return Vec::new();
    }
    if count(ranges) <= cap {
        return ranges.to_vec();
    }
    let mut taken = Vec::new();
    let mut left = cap;
    for range in ranges {
        if left == 0 {
            break;
        }
        let hi = range.lo.saturating_add(left as u16 - 1).min(range.hi);
        taken.push(Range::new(range.lo, hi));
        left -= usize::from(hi) - usize::from(range.lo) + 1;
    }
    merge(taken)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(lo: u16, hi: u16) -> Range {
        Range::new(lo, hi)
    }

    #[test]
    fn range_parse_merges_adjacent() {
        assert_eq!(
            parse_ports("23,3389,5900-5910"),
            [r(23, 23), r(3389, 3389), r(5900, 5910)]
        );
        // Adjacent ranges and overlapping ranges merge.
        assert_eq!(parse_ports("5900-5911, 5912"), [r(5900, 5912)]);
        assert_eq!(parse_ports("100-200,150-160"), [r(100, 200)]);
        // Whitespace and newlines are separators too; stray separators and
        // invalid tokens are skipped.
        assert_eq!(
            parse_ports("23\n135,\t 1433"),
            [r(23, 23), r(135, 135), r(1433, 1433)]
        );
        assert_eq!(parse_ports(" , 23 ,, "), [r(23, 23)]);
        assert_eq!(parse_ports("23,bogus,65536x"), [r(23, 23)]);
        assert_eq!(parse_ports("65535"), [r(65535, 65535)]);
        assert_eq!(parse_ports("10-5"), [r(5, 10)], "reversed pairs normalize");
        assert!(parse_ports("").is_empty());
    }

    #[test]
    fn range_bad_tokens_reports_invalid_entries() {
        assert_eq!(
            bad_tokens("23,3389,abc,70000,8-4x"),
            ["abc", "70000", "8-4x"]
        );
        assert!(bad_tokens("23, 5900-5910").is_empty());
    }

    #[test]
    fn range_subtract_returns_remaining_and_removed() {
        let ranges = [r(10, 20), r(30, 32)];
        // Remove the middle of the first range: it splits in two.
        let (remaining, removed) = subtract(&ranges, &|p| (13..=18).contains(&p));
        assert_eq!(remaining, [r(10, 12), r(19, 20), r(30, 32)]);
        assert_eq!(removed, [r(13, 18)]);
        // Remove everything.
        let (remaining, removed) = subtract(&ranges, &|_| true);
        assert!(remaining.is_empty());
        assert_eq!(removed, [r(10, 20), r(30, 32)]);
        // Remove nothing.
        let (remaining, removed) = subtract(&ranges, &|_| false);
        assert_eq!(remaining, [r(10, 20), r(30, 32)]);
        assert!(removed.is_empty());
    }

    #[test]
    fn range_count_and_contains_match_expansion() {
        let ranges = [r(23, 23), r(5900, 5910)];
        assert_eq!(count(&ranges), 12);
        assert!(contains(&ranges, 5903));
        assert!(!contains(&ranges, 24));
        assert_eq!(count(&[]), 0);
        assert_eq!(count(&[r(0, u16::MAX)]), 65536);
    }

    #[test]
    fn range_union_merges_both_sides() {
        assert_eq!(union(&[r(1, 5)], &[r(6, 9)]), [r(1, 9)]);
        assert_eq!(union(&[], &[r(2, 3)]), [r(2, 3)]);
        assert_eq!(union(&[r(9, 9)], &[r(1, 2)]), [r(1, 2), r(9, 9)]);
    }

    #[test]
    fn range_take_ports_caps_expansion() {
        assert_eq!(take_ports(&[r(10, 15), r(20, 25)], 3), [r(10, 12)]);
        assert_eq!(
            take_ports(&[r(10, 15), r(20, 25)], 9),
            [r(10, 15), r(20, 22)]
        );
        assert_eq!(
            take_ports(&[r(10, 15), r(20, 25)], 100),
            [r(10, 15), r(20, 25)],
            "under the cap the list is untouched"
        );
        assert_eq!(take_ports(&[r(10, 15)], 0).len(), 0);
    }

    #[test]
    fn range_display_uses_port_list_syntax() {
        assert_eq!(Range::single(23).to_string(), "23");
        assert_eq!(r(5900, 5910).to_string(), "5900-5910");
    }
}
