//! Literal keyword extraction prefilter for `@rx` rules (WP-55 step E9).
//!
//! Extracts required literal byte substrings from a regex pattern so subjects
//! that cannot possibly match are rejected in a fast byte scan before invoking
//! the regex engine.

/// A sound literal prefilter for a regex pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefilter {
    /// Subject must contain AT LEAST ONE of these byte literals.
    /// (Single element for non-alternating patterns; one per branch for
    /// top-level `A|B|C` alternations when every branch has a required literal.)
    literals: Vec<Box<[u8]>>,
    case_insensitive: bool,
}

impl Prefilter {
    /// Attempts to extract a sound literal prefilter from `pattern`.
    /// Returns `None` when no useful literal (length >= 2) can be proven
    /// required across all branches.
    pub fn from_regex(pattern: &str) -> Option<Self> {
        let (ci, body) = strip_leading_flags(pattern);
        let branches = split_top_level_alternation(body);
        if branches.is_empty() || branches.len() > 32 {
            return None;
        }

        let mut literals = Vec::with_capacity(branches.len());
        for branch in branches {
            let lit = longest_required_literal(branch)?;
            if lit.len() < 2 {
                return None;
            }
            let bytes: Vec<u8> = if ci {
                lit.as_bytes().iter().map(u8::to_ascii_lowercase).collect()
            } else {
                lit.into_bytes()
            };
            literals.push(bytes.into_boxed_slice());
        }

        Some(Self {
            literals,
            case_insensitive: ci,
        })
    }

    /// Extracted literal needles (for inspection and testing).
    pub fn literals(&self) -> &[Box<[u8]>] {
        &self.literals
    }

    /// Fast necessary-condition check: returns `false` only when the regex is
    /// guaranteed not to match `haystack`.
    pub fn might_match(&self, haystack: &[u8]) -> bool {
        if self.case_insensitive {
            self.literals
                .iter()
                .any(|lit| ci_contains_lower_needle(haystack, lit))
        } else {
            self.literals
                .iter()
                .any(|lit| contains_bytes(haystack, lit))
        }
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

fn ci_contains_lower_needle(haystack: &[u8], lower_needle: &[u8]) -> bool {
    if lower_needle.is_empty() {
        return true;
    }
    if lower_needle.len() > haystack.len() {
        return false;
    }
    let first = lower_needle[0];
    let last_start = haystack.len() - lower_needle.len();
    let mut i = 0;
    while i <= last_start {
        if haystack[i].to_ascii_lowercase() == first
            && haystack[i..i + lower_needle.len()]
                .iter()
                .zip(lower_needle.iter())
                .all(|(h, n)| h.to_ascii_lowercase() == *n)
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Strips leading inline flag groups like `(?i)`, `(?is)`, `(?m)`.
fn strip_leading_flags(mut pattern: &str) -> (bool, &str) {
    let mut ci = false;
    while let Some(rest) = pattern.strip_prefix("(?") {
        let Some(close) = rest.find(')') else { break };
        let flags = &rest[..close];
        // Only strip pure flag setters (not `(?i:...)`, `(?:...)`, `(?=...)`).
        if !flags.is_empty()
            && flags
                .bytes()
                .all(|b| matches!(b, b'i' | b'm' | b's' | b'x' | b'U' | b'-'))
        {
            let mut neg = false;
            for b in flags.bytes() {
                match b {
                    b'-' => neg = true,
                    b'i' => ci = !neg,
                    _ => {}
                }
            }
            pattern = &rest[close + 1..];
        } else {
            break;
        }
    }
    // Also handle top-level `(?i:...)` wrapping the whole pattern.
    if let Some(inner) = strip_wrapping_group(pattern) {
        if pattern.starts_with("(?i:") {
            ci = true;
            return (ci, inner);
        }
        if pattern.starts_with("(?:") {
            return (ci, inner);
        }
    }
    (ci, pattern)
}

fn strip_wrapping_group(pattern: &str) -> Option<&str> {
    let start = if pattern.starts_with("(?i:") {
        4
    } else if pattern.starts_with("(?:") {
        3
    } else {
        return None;
    };
    if !pattern.ends_with(')') {
        return None;
    }
    // Verify the opening `(` matches the final `)`.
    let bytes = pattern.as_bytes();
    let mut depth = 0usize;
    let mut in_class = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if in_class {
            if b == b']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'[' => in_class = true,
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && i + 1 != bytes.len() {
                    return None;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if depth == 0 {
        Some(&pattern[start..pattern.len() - 1])
    } else {
        None
    }
}

fn split_top_level_alternation(pattern: &str) -> Vec<&str> {
    let bytes = pattern.as_bytes();
    let mut branches = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut in_class = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if in_class {
            if b == b']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'[' => in_class = true,
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'|' if depth == 0 => {
                branches.push(&pattern[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    branches.push(&pattern[start..]);
    branches
}

/// Finds the longest contiguous literal string required in one concatenation
/// branch (no top-level `|`).
fn longest_required_literal(branch: &str) -> Option<String> {
    let bytes = branch.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut cur = String::new();
    let mut best = String::new();

    let flush = |cur: &mut String, best: &mut String| {
        if cur.len() > best.len() {
            *best = std::mem::take(cur);
        } else {
            cur.clear();
        }
    };

    while i < len {
        let b = bytes[i];
        match b {
            // Anchors don't emit chars, don't break required status (but break
            // contiguity only if mid-literal).
            b'^' | b'$' => {
                flush(&mut cur, &mut best);
                i += 1;
            }
            b'.' => {
                flush(&mut cur, &mut best);
                i = skip_quantifier(bytes, i + 1);
            }
            b'[' => {
                flush(&mut cur, &mut best);
                i += 1;
                if i < len && bytes[i] == b'^' {
                    i += 1;
                }
                if i < len && bytes[i] == b']' {
                    i += 1;
                }
                while i < len {
                    if bytes[i] == b'\\' && i + 1 < len {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b']' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                i = skip_quantifier(bytes, i);
            }
            b'(' => {
                flush(&mut cur, &mut best);
                // Find matching `)`.
                let mut depth = 1usize;
                let mut in_class = false;
                let mut j = i + 1;
                while j < len && depth > 0 {
                    let c = bytes[j];
                    if c == b'\\' && j + 1 < len {
                        j += 2;
                        continue;
                    }
                    if in_class {
                        if c == b']' {
                            in_class = false;
                        }
                        j += 1;
                        continue;
                    }
                    match c {
                        b'[' => in_class = true,
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                let after = skip_quantifier(bytes, j);
                let optional = is_optional_quantifier(&bytes[j..after]);
                // If group is non-optional and has no `|`, extract literal inside it.
                if !optional && j > i + 1 {
                    let mut inner_start = i + 1;
                    let inner_end = j - 1;
                    let mut extractable = true;
                    if branch[inner_start..inner_end].starts_with("?:") {
                        inner_start += 2;
                    } else if branch[inner_start..inner_end].starts_with('?') {
                        // Lookaround or inline flag: don't extract from inside.
                        extractable = false;
                    }
                    if extractable {
                        let inner = &branch[inner_start..inner_end];
                        let sub_branches = split_top_level_alternation(inner);
                        if sub_branches.len() == 1
                            && let Some(sub_lit) = longest_required_literal(sub_branches[0])
                            && sub_lit.len() > best.len()
                        {
                            best = sub_lit;
                        }
                    }
                }
                i = after;
            }
            b'\\' => {
                if i + 1 >= len {
                    break;
                }
                let next = bytes[i + 1];
                let after_esc = i + 2;
                let after_q = skip_quantifier(bytes, after_esc);
                let optional = is_optional_quantifier(&bytes[after_esc..after_q]);
                // Escaped punctuation/metacharacters are literal bytes;
                // character class shorthands (`\d`, `\w`, `\s`, `\b`, `\x`, ...)
                // break the literal run.
                let is_literal_esc = !next.is_ascii_alphanumeric();
                if is_literal_esc && !optional {
                    cur.push(next as char);
                    if after_q > after_esc {
                        // Repeated literal (`\++`): still at least 1 copy, flush after.
                        flush(&mut cur, &mut best);
                    }
                } else {
                    flush(&mut cur, &mut best);
                }
                i = after_q;
            }
            b'*' | b'+' | b'?' | b'{' | b')' => {
                // Unexpected stray quantifier: break cleanly.
                flush(&mut cur, &mut best);
                i += 1;
            }
            _ => {
                let ch = branch[i..].chars().next().expect("valid utf-8");
                let next_i = i + ch.len_utf8();
                let after_q = skip_quantifier(bytes, next_i);
                let optional = is_optional_quantifier(&bytes[next_i..after_q]);
                if optional {
                    flush(&mut cur, &mut best);
                } else {
                    cur.push(ch);
                    if after_q > next_i {
                        flush(&mut cur, &mut best);
                    }
                }
                i = after_q;
            }
        }
    }

    flush(&mut cur, &mut best);
    if best.is_empty() { None } else { Some(best) }
}

fn skip_quantifier(bytes: &[u8], mut i: usize) -> usize {
    if i >= bytes.len() {
        return i;
    }
    match bytes[i] {
        b'*' | b'+' | b'?' => {
            i += 1;
            if i < bytes.len() && bytes[i] == b'?' {
                i += 1;
            }
        }
        b'{' => {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b',') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'}' {
                i = j + 1;
                if i < bytes.len() && bytes[i] == b'?' {
                    i += 1;
                }
            }
        }
        _ => {}
    }
    i
}

fn is_optional_quantifier(q: &[u8]) -> bool {
    if q.is_empty() {
        return false;
    }
    match q[0] {
        b'?' | b'*' => true,
        b'{' => {
            // `{0,...}` or `{0}` is optional.
            q.len() >= 2 && q[1] == b'0' && (q.len() == 2 || q[2] == b',' || q[2] == b'}')
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_literals_from_single_and_alternated_patterns() {
        let pf = Prefilter::from_regex(r"(?i)\bunion\s+select\b").expect("extracts literal");
        assert!(pf.might_match(b"1 UNION SELECT 1"));
        assert!(!pf.might_match(b"hello world"));

        let alt = Prefilter::from_regex(r"(?i)select|union|drop\s+table").expect("alt literals");
        assert!(alt.might_match(b"DROP TABLE x"));
        assert!(!alt.might_match(b"normal request path"));

        assert!(Prefilter::from_regex(r"^[0-9]+$").is_none());
    }
}
