//! Path-prefix routing rules ("locations") for reverse-proxy sites
//! (WP-22 §3.3 按路径后端).
//!
//! A `proxy` site may carry `locations[]`: rules that send requests whose
//! path starts with a given prefix to a dedicated set of backends. This
//! module implements the matching and prefix-stripping semantics from the
//! plan:
//!
//! - prefixes match at path-segment boundaries: `/api` matches `/api`,
//!   `/api/x` and `/api/`, but not `/apix`; a trailing `/` on the prefix is
//!   not significant;
//! - the longest prefix wins ([`Locations`] keeps rules sorted by prefix
//!   length descending);
//! - the path is cleaned (`//` merged, `.` / `..` resolved) before matching
//!   and stripping; a trailing `/` on the request path is preserved;
//! - dot-segments that would escape above the prefix are rejected — HTTP 400
//!   in production, `None` from [`strip_prefix`] here.

use std::borrow::Cow;

/// A path-prefix routing rule.
#[derive(Clone, Debug)]
pub struct LocationRule {
    pub prefix: String,
    pub strip: bool,
    /// Empty → use the site's backends.
    pub targets: Vec<String>,
    /// Extra request headers (same-name overrides).
    pub headers: Vec<(String, String)>,
}

/// Location rules sorted by prefix length descending (longest match wins).
#[derive(Clone, Debug)]
pub struct Locations {
    rules: Vec<LocationRule>,
}

impl Locations {
    /// Sorts rules by prefix length descending at construction.
    pub fn new(mut rules: Vec<LocationRule>) -> Self {
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.prefix.len()));
        Self { rules }
    }

    /// Finds the longest-prefix match. `/api` and `/api/` both match `/api`
    /// and `/api/x`, not `/apix`.
    ///
    /// The path is cleaned before matching. Escaping dot-segments clamp at
    /// the root here; the request pipeline must reject them with 400
    /// beforehand (see [`strip_prefix`], which reports them).
    pub fn dispatch(&self, path: &str) -> Option<&LocationRule> {
        let cleaned = clean_path(path);
        self.rules
            .iter()
            .find(|rule| matches_prefix(&cleaned, &rule.prefix))
    }
}

/// Normalizes a path: merges `//`, resolves `.` and `..` segments. Cannot
/// escape via dot-segments: a `..` above the root is clamped, so the result
/// always stays under `/`. A trailing `/` is preserved; the result is empty
/// only for empty input, which becomes `/`.
///
/// ```text
/// clean_path("//a/./b/../c") == "/a/c"
/// clean_path("/api/users/")  == "/api/users/"
/// clean_path("/a/../../b")   == "/b"     // clamped; strip_prefix rejects it
/// ```
pub fn clean_path(path: &str) -> Cow<'_, str> {
    if is_canonical(path) {
        return Cow::Borrowed(path);
    }
    Cow::Owned(resolve(path).path)
}

/// Strips a prefix at a path-segment boundary; preserves a trailing slash.
///
/// Returns `None` if the path doesn't start with the prefix or if a
/// dot-segment would escape above the root (`/api/../../secret`).
/// A path that merely leaves the prefix (`/api/../secret`) fails the match
/// instead. The path *is* the prefix → `Some("")`; a trailing `/` on the
/// prefix behaves the same (`/api/` also matches the bare path `/api`).
///
/// The path is cleaned before matching. The returned slice borrows from
/// `path`; when the input itself is not canonical, its tail can still
/// contain redundant separators (`/api/x//y` → `/x//y`) — pass a
/// pre-cleaned path (see [`clean_path`]) if the remainder must be
/// normalized too.
pub fn strip_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let Resolved {
        path: cleaned,
        escaped,
        seg_starts,
    } = resolve(path);
    if escaped {
        return None;
    }
    let keep = prefix_match_len(&cleaned, prefix)?;
    if keep == cleaned.len() {
        // The path is exactly the prefix: nothing remains.
        return Some("");
    }
    // The remainder in canonical form starts with '/'. Map that boundary
    // back into the input: the '/' immediately before kept segment number
    // `n`, where `n` counts segments before the boundary.
    let n = cleaned[..keep].matches('/').count();
    let boundary = if n < seg_starts.len() {
        let off = seg_starts[n];
        if off > 0 && path.as_bytes()[off - 1] == b'/' {
            off - 1
        } else {
            off
        }
    } else {
        // The remainder is the trailing '/' of a directory-style path.
        debug_assert!(path.ends_with('/'));
        path.len() - 1
    };
    Some(&path[boundary..])
}

/// Byte offset of each kept segment within the input, plus the cleaned path.
struct Resolved {
    path: String,
    /// True when a `..` segment popped past the root (it is clamped).
    escaped: bool,
    seg_starts: Vec<usize>,
}

/// Collapses `//`, drops `.` segments and resolves `..` segments (clamping
/// above the root, flagged as [`Resolved::escaped`]). Preserves a trailing
/// `/` (except on the bare root).
fn resolve(path: &str) -> Resolved {
    let mut segs: Vec<&str> = Vec::new();
    let mut seg_starts: Vec<usize> = Vec::new();
    let mut escaped = false;
    // Segment boundaries are ASCII '/', so offsets stay on char boundaries.
    let mut cursor = 0usize;
    for seg in path.split('/') {
        let start = cursor;
        cursor = start + seg.len() + 1; // skip the separating '/'
        match seg {
            "" | "." => {}
            ".." => {
                if segs.pop().is_none() {
                    escaped = true;
                } else {
                    seg_starts.pop();
                }
            }
            s => {
                segs.push(s);
                seg_starts.push(start);
            }
        }
    }
    let mut out = String::with_capacity(path.len() + 1);
    for seg in &segs {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    if path.ends_with('/') && out != "/" {
        out.push('/');
    }
    Resolved {
        path: out,
        escaped,
        seg_starts,
    }
}

/// True when `path` is already in [`resolve`] output form.
fn is_canonical(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let body = &path[1..];
    if body.is_empty() {
        return true; // "/"
    }
    if body.ends_with('/') {
        return false; // a trailing slash is canonical only on the root
    }
    body.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Number of leading bytes of `cleaned` covered by `prefix`, when the
/// prefix matches at a segment boundary. A trailing `/` on the prefix is
/// not significant; the root prefix matches every path and strips nothing.
fn prefix_match_len(cleaned: &str, prefix: &str) -> Option<usize> {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return Some(0);
    }
    if cleaned == prefix {
        return Some(prefix.len());
    }
    let rest = cleaned.strip_prefix(prefix)?;
    rest.starts_with('/').then_some(prefix.len())
}

/// Whether `prefix` matches the already-cleaned `cleaned` at a segment
/// boundary.
fn matches_prefix(cleaned: &str, prefix: &str) -> bool {
    prefix_match_len(cleaned, prefix).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(prefix: &str) -> LocationRule {
        LocationRule {
            prefix: prefix.to_owned(),
            strip: false,
            targets: Vec::new(),
            headers: Vec::new(),
        }
    }

    #[test]
    fn dispatch_longest_prefix_wins() {
        // Inserted shortest-first: Locations must sort so the longer wins.
        let locs = Locations::new(vec![rule("/api"), rule("/api/v2")]);
        assert_eq!(locs.dispatch("/api/v2/users").unwrap().prefix, "/api/v2");
        assert_eq!(locs.dispatch("/api/users").unwrap().prefix, "/api");
        assert_eq!(locs.dispatch("/api").unwrap().prefix, "/api");
    }

    #[test]
    fn dispatch_segment_boundary() {
        let locs = Locations::new(vec![rule("/api"), rule("/api/v2")]);
        assert!(locs.dispatch("/api").is_some());
        assert!(locs.dispatch("/api/x").is_some());
        assert!(locs.dispatch("/api/").is_some());
        // Trailing slash on the prefix is not significant.
        assert!(locs.dispatch("/apix").is_none());
        let slashed = Locations::new(vec![rule("/api/")]);
        assert!(slashed.dispatch("/api").is_some());
        assert!(slashed.dispatch("/api/x").is_some());
        assert!(slashed.dispatch("/apix").is_none());
        // Unclean paths are normalized before matching.
        assert_eq!(
            locs.dispatch("//api/./v2/users").map(|r| r.prefix.as_str()),
            Some("/api/v2")
        );
    }

    #[test]
    fn clean_path_resolves_dot_segments() {
        assert_eq!(clean_path("//a/./b/../c"), "/a/c");
        assert_eq!(clean_path("/a/../../b"), "/b"); // clamped, no escape
        assert_eq!(clean_path("/api/users/"), "/api/users/");
        assert_eq!(clean_path("/"), "/");
        assert_eq!(clean_path("/x//y///z"), "/x/y/z");
        // Escape above the root is detected by strip_prefix.
        assert_eq!(strip_prefix("/a/../../b", "/a"), None);
    }

    #[test]
    fn strip_prefix_preserves_trailing_slash() {
        assert_eq!(strip_prefix("/api/users/", "/api"), Some("/users/"));
        assert_eq!(strip_prefix("/api/users/", "/api/"), Some("/users/"));
        assert_eq!(strip_prefix("/api/", "/api"), Some("/"));
        assert_eq!(strip_prefix("/api", "/api"), Some(""));
        assert_eq!(strip_prefix("/api", "/api/"), Some(""));
        assert_eq!(strip_prefix("/api/x", "/api"), Some("/x"));
        assert_eq!(strip_prefix("/apix", "/api"), None);
        assert_eq!(strip_prefix("/x", "/api"), None);
        // Root prefix matches everything and strips nothing.
        assert_eq!(strip_prefix("/x/y", "/"), Some("/x/y"));
    }

    #[test]
    fn strip_prefix_rejects_escape() {
        // Leaves the prefix: fails the match itself.
        assert_eq!(strip_prefix("/api/../secret", "/api"), None);
        // Pops past the root: genuine escape, rejected outright.
        assert_eq!(strip_prefix("/api/../../secret", "/api"), None);
        // Clamped dot-segments cannot sneak back under the prefix.
        assert_eq!(strip_prefix("/api/../../api/x", "/api"), None);
        // Inside-prefix dot-segments are fine.
        assert_eq!(strip_prefix("/api/v2/../users", "/api"), Some("/users"));
    }

    #[test]
    fn locations_empty_returns_none() {
        let locs = Locations::new(Vec::new());
        assert!(locs.dispatch("/").is_none());
        assert!(locs.dispatch("/api/v2/users").is_none());
    }
}
