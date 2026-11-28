//! Web path rules (WP-52 §3.3): one rule per line; `~` marks a regex
//! (RE2 syntax, not auto-anchored), everything else is a glob where `*`
//! matches any character including `/`, compared case-insensitively over
//! the whole path. Globs are evaluated as segmented prefix / infix /
//! suffix comparisons — never through a regex — so the cost is linear in
//! the path length.

use regex::Regex;

/// FerrumGate protection: the maximum path length that still participates
/// in matching; longer paths contribute their head and tail halves only
/// (prefix and suffix rules keep working, middle-only patterns do not).
pub const MAX_PATH_MATCH_BYTES: usize = 4096;
/// FerrumGate protection: path rules per jail.
pub const MAX_PATH_RULES: usize = 128;
/// FerrumGate protection: bytes per path rule line.
pub const MAX_PATH_RULE_BYTES: usize = 2048;

/// One compiled path rule.
#[derive(Clone, Debug)]
pub enum PathRule {
    /// A `~`-prefixed RE2 regex, matched unanchored and case-sensitive.
    Regex(Regex),
    /// A glob split at every `*` into lowercase segments; the first is a
    /// prefix, the last a suffix, the middle ones must appear in order.
    Glob(Vec<String>),
}

/// Every compile error of a path-rule block, one message per bad line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathRuleError {
    pub errors: Vec<String>,
}

impl IntoIterator for PathRuleError {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.errors.into_iter()
    }
}

impl std::fmt::Display for PathRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.errors.join("; "))
    }
}

/// Compiles a multi-line path-rule block (rules or exclusions).
pub fn compile_paths(text: &str) -> Result<Vec<PathRule>, PathRuleError> {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() > MAX_PATH_RULES {
        errors.push(format!("at most {MAX_PATH_RULES} path rules per jail"));
        return Err(PathRuleError { errors });
    }
    for (index, line) in lines.iter().enumerate() {
        if line.len() > MAX_PATH_RULE_BYTES {
            errors.push(format!(
                "path rule {index} exceeds {MAX_PATH_RULE_BYTES} bytes"
            ));
            continue;
        }
        if let Some(pattern) = line.strip_prefix('~') {
            match Regex::new(pattern) {
                Ok(regex) => rules.push(PathRule::Regex(regex)),
                Err(error) => errors.push(format!("path rule {index}: {error}")),
            }
        } else {
            rules.push(PathRule::Glob(
                line.to_lowercase().split('*').map(str::to_owned).collect(),
            ));
        }
    }
    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(PathRuleError { errors })
    }
}

/// Whether the request path hits any rule. Both the raw path and the
/// normalized one are tested, so `//.env` and `/a/../.env` cannot dodge a
/// `*/.env` rule.
pub fn path_matches(rules: &[PathRule], raw_path: &str, normalized_path: &str) -> bool {
    let raw = clamp_path_pair(raw_path);
    let normalized = clamp_path_pair(normalized_path);
    if raw_path == normalized_path {
        rules.iter().any(|rule| rule_matches(rule, &raw))
    } else {
        rules
            .iter()
            .any(|rule| rule_matches(rule, &raw) || rule_matches(rule, &normalized))
    }
}

fn rule_matches(rule: &PathRule, path: &str) -> bool {
    match rule {
        PathRule::Regex(regex) => regex.is_match(path),
        PathRule::Glob(segments) => glob_matches(segments, path),
    }
}

/// Glob semantics: `segments` comes from splitting the lowercase pattern
/// at `*`. With a single segment the whole path must equal it; otherwise
/// the path must start with the first segment, end with the last, and
/// contain the middle ones in order.
fn glob_matches(segments: &[String], path: &str) -> bool {
    let path = path.to_lowercase();
    let (first, last) = match segments {
        [only] => return path == *only,
        [first, .., last] => (first, last),
        [] => return true,
    };
    let Some(rest) = path.strip_prefix(first.as_str()) else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(last.as_str()) else {
        return false;
    };
    let mut cursor = rest;
    for segment in &segments[1..segments.len() - 1] {
        match cursor.find(segment.as_str()) {
            Some(position) => cursor = &cursor[position + segment.len()..],
            None => return false,
        }
    }
    true
}

/// Normalizes a request path: collapses duplicate slashes, resolves `.` /
/// `..` segments, keeps the trailing slash. A leading `..` beyond the
/// root and the query string handling are the reporter's concern — the
/// guard only needs a canonical form that defeats trivial bypasses.
pub fn normalize_path(raw: &str) -> String {
    let path = raw.split('?').next().unwrap_or(raw);
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut normalized = format!("/{}", parts.join("/"));
    if path.ends_with('/') && normalized != "/" {
        normalized.push('/');
    }
    normalized
}

/// Long paths only contribute their head and tail halves (each half of
/// [`MAX_PATH_MATCH_BYTES`]); prefix and suffix rules keep matching,
/// middle-only rules do not. Short paths pass through unchanged.
pub fn clamp_path_pair(path: &str) -> String {
    if path.len() <= MAX_PATH_MATCH_BYTES {
        return path.to_owned();
    }
    let half = MAX_PATH_MATCH_BYTES / 2;
    let mut clamped = String::with_capacity(MAX_PATH_MATCH_BYTES);
    clamped.push_str(&path[..half]);
    clamped.push_str(&path[path.len() - half..]);
    clamped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(text: &str) -> Vec<PathRule> {
        compile_paths(text).expect("compile")
    }

    #[test]
    fn path_glob_matches_across_slashes_case_insensitive() {
        let rules = compile("*/.env\n/WP-LOGIN.php\n*.sql");
        assert!(path_matches(&rules, "/.env", "/.env"));
        assert!(path_matches(&rules, "/api/.env", "/api/.env"));
        assert!(path_matches(&rules, "/wp-login.php", "/wp-login.php"));
        assert!(path_matches(&rules, "/WP-LOGIN.PHP", "/wp-login.php"));
        assert!(path_matches(&rules, "/backup/db.SQL", "/backup/db.sql"));
        // `.env.local` is a different file from `/.env`; the decoy
        // preset's companion `*/.env.*` rule covers it.
        assert!(!path_matches(
            &rules,
            "/deep/nested/.env.local",
            "/deep/nested/.env.local"
        ));
        let with_wildcard = compile("*/.env.*");
        assert!(path_matches(
            &with_wildcard,
            "/deep/nested/.env.local",
            "/deep/nested/.env.local"
        ));
        assert!(!path_matches(&rules, "/env", "/env"));
        assert!(!path_matches(&rules, "/api/env", "/api/env"));
    }

    #[test]
    fn path_glob_full_match_requires_exact_ends() {
        // `*` spans slashes, but the pattern must still cover the whole
        // path: `/.git` does not match `/.git/config`...
        let rules = compile("*/.git");
        assert!(!path_matches(&rules, "/.git/config", "/.git/config"));
        // ...while the preset's `*/.git/*` companion does.
        let rules = compile("*/.git/*");
        assert!(path_matches(&rules, "/.git/config", "/.git/config"));
        assert!(path_matches(&rules, "/.git/", "/.git/"));
    }

    #[test]
    fn path_regex_unanchored() {
        let rules = compile("~debug\n~^/api/v[0-9]+/admin");
        assert!(path_matches(&rules, "/x/debug/1", "/x/debug/1"));
        assert!(!path_matches(&rules, "/x/dbg/1", "/x/dbg/1"));
        assert!(path_matches(
            &rules,
            "/api/v2/admin/users",
            "/api/v2/admin/users"
        ));
        assert!(!path_matches(&rules, "/api/admin", "/api/admin"));
        // Regexes keep their own case sensitivity.
        let rules = compile("~Debug");
        assert!(!path_matches(&rules, "/debug", "/debug"));
    }

    #[test]
    fn path_checked_raw_and_normalized() {
        let rules = compile("*/.env\n*/.git/config");
        // Double slashes and dot segments cannot bypass the rules.
        assert!(path_matches(
            &rules,
            "//.env",
            normalize_path("//.env").as_str()
        ));
        assert!(path_matches(
            &rules,
            "/a/../.env",
            normalize_path("/a/../.env").as_str()
        ));
        assert!(path_matches(
            &rules,
            "/x/./y/../../.git/config",
            normalize_path("/x/./y/../../.git/config").as_str()
        ));
        assert!(!path_matches(&rules, "/.envx", "/.envx"));
    }

    #[test]
    fn path_normalize_resolves_dot_segments() {
        assert_eq!(normalize_path("//.env"), "/.env");
        assert_eq!(normalize_path("/a/../.env"), "/.env");
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
        assert_eq!(normalize_path("/a/b/"), "/a/b/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/../../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn path_long_input_uses_head_and_tail() {
        // A prefix/suffix rule still matches an oversized path; a
        // middle-only rule does not (that is the point of the clamp).
        let prefix_suffix = compile("*/start*end");
        let mut long = String::from("/start");
        long.push_str(&"x".repeat(MAX_PATH_MATCH_BYTES * 2));
        long.push_str("end");
        assert!(path_matches(&prefix_suffix, &long, &long));
        let middle = compile("~middle");
        assert!(!path_matches(&middle, &long, &long));
        // Short paths are untouched.
        assert_eq!(clamp_path_pair("/.env"), "/.env");
    }

    #[test]
    fn path_compile_reports_bad_rules_and_caps() {
        let error = compile_paths("~(unclosed").expect_err("bad regex");
        assert_eq!(error.errors.len(), 1);
        assert!(error.errors[0].starts_with("path rule 0"));

        let too_many = "~a\n".repeat(MAX_PATH_RULES + 1);
        let error = compile_paths(&too_many).expect_err("too many rules");
        assert!(error.errors[0].contains("at most"));

        let oversized = format!("~a{}", "b".repeat(MAX_PATH_RULE_BYTES));
        let error = compile_paths(&oversized).expect_err("oversized rule");
        assert!(error.errors[0].contains("exceeds"));
    }
}
