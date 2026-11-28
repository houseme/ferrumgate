//! Version parsing, comparison, `git describe` normalization, and GitHub
//! security advisory range matching.

use std::cmp::Ordering;

/// A parsed semantic version with up to four numeric segments and an optional
/// pre-release suffix.
///
/// Missing fourth segments are normalized to `0`, so `v0.5.4` and `v0.5.4.0`
/// compare equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedVersion {
    pub nums: [u32; 4],
    pub pre: String,
}

/// Parses a strict release version: optional leading `v`/`V`, 3 to 4 numeric
/// dot-separated segments, optional `-prerelease`, optional `+build` (ignored).
pub fn parse_version(s: &str) -> Option<ParsedVersion> {
    parse_version_segments(s, 3, 4)
}

/// Parses a version allowing 2 to 4 numeric segments (used in GitHub security
/// advisories where ranges may specify `major.minor` such as `< 0.6`).
pub fn parse_loose_version(s: &str) -> Option<ParsedVersion> {
    parse_version_segments(s, 2, 4)
}

fn parse_version_segments(s: &str, min_segs: usize, max_segs: usize) -> Option<ParsedVersion> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let s = s
        .strip_prefix('v')
        .or_else(|| s.strip_prefix('V'))
        .unwrap_or(s);
    // Strip +build metadata first.
    let s = match s.split_once('+') {
        Some((before, build)) => {
            if build.is_empty() {
                return None;
            }
            before
        }
        None => s,
    };
    let (core, pre) = match s.split_once('-') {
        Some((core, pre)) => {
            if pre.is_empty() {
                return None;
            }
            (core, pre.to_owned())
        }
        None => (s, String::new()),
    };

    let mut nums = [0u32; 4];
    let mut count = 0usize;
    for part in core.split('.') {
        if count >= max_segs || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        nums[count] = part.parse::<u32>().ok()?;
        count += 1;
    }
    if count < min_segs {
        return None;
    }
    Some(ParsedVersion { nums, pre })
}

/// Compares two parsed versions.
///
/// Numeric segments are compared lexicographically. When numeric segments are
/// equal, a release (empty `pre`) is newer than a pre-release, and two
/// pre-releases are compared lexicographically as strings.
pub fn compare_version(a: &ParsedVersion, b: &ParsedVersion) -> Ordering {
    match a.nums.cmp(&b.nums) {
        Ordering::Equal => match (a.pre.is_empty(), b.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => a.pre.cmp(&b.pre),
        },
        ord => ord,
    }
}

/// Normalizes `git describe` output (`v0.6.3-5-gabc1234`, `v0.6.3-dirty`,
/// `v0.6.3-5-gabc1234-dirty`) back to the underlying tag so builds ahead of a
/// tag are not mistaken for pre-releases of that tag.
pub fn release_base(current: &str) -> &str {
    let trimmed = current.trim();
    let without_dirty = trimmed
        .strip_suffix("-dirty")
        .filter(|base| !base.is_empty())
        .unwrap_or(trimmed);

    if let Some((before_g, hex)) = without_dirty.rsplit_once("-g")
        && hex.len() >= 4
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
        && let Some((tag, commits)) = before_g.rsplit_once('-')
        && !tag.is_empty()
        && !commits.is_empty()
        && commits.bytes().all(|b| b.is_ascii_digit())
    {
        return tag;
    }
    without_dirty
}

/// Returns `true` if `a` is strictly newer than `b`. Unparseable versions
/// return `false`.
pub fn version_newer(a: &str, b: &str) -> bool {
    match (
        parse_version(release_base(a)),
        parse_version(release_base(b)),
    ) {
        (Some(va), Some(vb)) => compare_version(&va, &vb) == Ordering::Greater,
        _ => false,
    }
}

/// Returns `true` if both `a` and `b` parse as release versions after
/// normalizing `git describe` suffixes.
pub fn version_comparable(a: &str, b: &str) -> bool {
    parse_version(release_base(a)).is_some() && parse_version(release_base(b)).is_some()
}

/// Evaluates whether `v` satisfies a GitHub Security Advisory version range
/// string (comma-separated constraints such as `"<= 0.6.0.4"` or
/// `">= 0.5.0, < 0.6.1"`).
///
/// Returns `(matched, parsed)` where `parsed` is `false` if the range is empty
/// or contains any unrecognized operator or unparseable version.
pub fn version_in_range(v: &ParsedVersion, range: &str) -> (bool, bool) {
    let range = range.trim();
    if range.is_empty() {
        return (false, false);
    }
    let mut matched = true;
    for raw_clause in range.split(',') {
        let clause = raw_clause.trim();
        if clause.is_empty() {
            return (false, false);
        }
        let (op, ver_str) = if let Some(rest) = clause.strip_prefix("<=") {
            ("<=", rest)
        } else if let Some(rest) = clause.strip_prefix(">=") {
            (">=", rest)
        } else if let Some(rest) = clause.strip_prefix("==") {
            ("=", rest)
        } else if let Some(rest) = clause.strip_prefix('<') {
            ("<", rest)
        } else if let Some(rest) = clause.strip_prefix('>') {
            (">", rest)
        } else if let Some(rest) = clause.strip_prefix('=') {
            ("=", rest)
        } else {
            ("=", clause)
        };

        let Some(bound) = parse_loose_version(ver_str.trim()) else {
            return (false, false);
        };
        let ord = compare_version(v, &bound);
        let ok = match op {
            "<=" => matches!(ord, Ordering::Less | Ordering::Equal),
            ">=" => matches!(ord, Ordering::Greater | Ordering::Equal),
            "<" => ord == Ordering::Less,
            ">" => ord == Ordering::Greater,
            "=" => ord == Ordering::Equal,
            _ => return (false, false),
        };
        matched &= ok;
    }
    (matched, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_newer_and_comparable() {
        // Basic 3-segment and 4-segment normalization.
        assert!(!version_newer("v0.5.4", "v0.5.4.0"));
        assert!(!version_newer("v0.5.4.0", "v0.5.4"));
        assert!(version_newer("v0.5.4.1", "v0.5.4"));
        assert!(version_newer("v0.6.0", "v0.5.9.9"));
        assert!(version_newer("1.0.0", "0.9.9"));
        assert!(!version_newer("v0.5.3", "v0.5.4"));

        // Release vs pre-release and build metadata.
        assert!(version_newer("v1.0.0", "v1.0.0-rc.1"));
        assert!(!version_newer("v1.0.0-rc.1", "v1.0.0"));
        assert!(version_newer("v1.0.0-rc.2", "v1.0.0-rc.1"));
        assert!(!version_newer("v1.0.0+build1", "v1.0.0+build2"));

        // git describe forms compare by base tag.
        assert_eq!(release_base("v0.6.3-5-gabc1234"), "v0.6.3");
        assert_eq!(release_base("v0.6.3-5-gabc1234-dirty"), "v0.6.3");
        assert_eq!(release_base("v0.6.3-dirty"), "v0.6.3");
        assert_eq!(release_base("v0.6.3-rc.1-2-gdeadbeef"), "v0.6.3-rc.1");
        assert_eq!(release_base("v0.6.3-rc.1"), "v0.6.3-rc.1");
        assert!(!version_newer("v0.6.3", "v0.6.3-5-gabc1234"));
        assert!(!version_newer("v0.6.3", "v0.6.3-dirty"));
        assert!(version_newer("v0.6.4", "v0.6.3-5-gabc1234-dirty"));

        // Unparseable / dev builds.
        assert!(!version_comparable("v0.6.0", "dev"));
        assert!(!version_comparable("dev", "v0.6.0"));
        assert!(!version_newer("v0.6.0", "dev"));
        assert!(!version_comparable("v0.6", "v0.6.0"));
        assert!(version_comparable("v0.6.0", "v0.6.3-5-gabc1234"));
        assert!(parse_version("v0.6.0-").is_none());
        assert!(parse_version("v0.6.0+").is_none());
        assert!(parse_version("1.2.3.4.5").is_none());
    }

    #[test]
    fn version_in_range_github_notation() {
        let v = parse_version("v0.6.0.4").unwrap();
        assert_eq!(version_in_range(&v, "<= 0.6.0.4"), (true, true));
        assert_eq!(version_in_range(&v, "< 0.6.0.4"), (false, true));
        assert_eq!(version_in_range(&v, ">= 0.5.0, < 0.6.1"), (true, true));
        assert_eq!(version_in_range(&v, ">= 0.6.1, < 0.7.0"), (false, true));
        assert_eq!(version_in_range(&v, "= 0.6.0.4"), (true, true));
        assert_eq!(version_in_range(&v, "== 0.6.0.4"), (true, true));
        assert_eq!(version_in_range(&v, "0.6.0.4"), (true, true));
        assert_eq!(version_in_range(&v, "> 0.5, <= 0.7"), (true, true));
        assert_eq!(version_in_range(&v, ">= 0.6.0, <= 0.6.0.4"), (true, true));

        // Pre-release comparisons inside ranges.
        let rc = parse_version("v0.6.0-rc.1").unwrap();
        assert_eq!(version_in_range(&rc, "< 0.6.0"), (true, true));
        assert_eq!(version_in_range(&rc, ">= 0.6.0"), (false, true));

        // Invalid / unparseable ranges.
        assert_eq!(version_in_range(&v, ""), (false, false));
        assert_eq!(version_in_range(&v, "   "), (false, false));
        assert_eq!(version_in_range(&v, "<= 0.6.0, "), (false, false));
        assert_eq!(version_in_range(&v, "!= 0.6.0"), (false, false));
        assert_eq!(version_in_range(&v, "all versions"), (false, false));
    }
}
