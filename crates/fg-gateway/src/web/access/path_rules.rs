//! Path rules (WP-26): per-prefix overrides for auth and IP control,
//! longest prefix wins, matched on segment boundaries after
//! normalization (`.`/`..`/duplicate slashes collapse).
#![allow(dead_code)]

/// The auth override on a rule: inherit the site's setting, or force
/// off/on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthRule {
    #[default]
    Inherit,
    Off,
    On,
}

#[derive(Clone, Debug, Default)]
pub struct PathRule {
    /// Starts with `/`; matched on segment boundaries (`/admin` matches
    /// `/admin/x`, not `/administrator`).
    pub prefix: String,
    pub auth: AuthRule,
    /// IP-list override keys (empty = inherit the site lists).
    pub ip_list: Vec<String>,
}

/// Normalizes a request path: resolves `.` and `..`, collapses duplicate
/// slashes, and keeps a trailing slash off the match.
pub fn normalize(path: &str) -> String {
    let (path, _trailing) = match path.strip_suffix('/') {
        Some(stripped) if stripped.len() > 1 => (stripped, true),
        _ => (path, false),
    };
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    if segments.is_empty() {
        return "/".to_owned();
    }
    format!("/{}", segments.join("/"))
}

/// Does `path` sit under `rule_prefix` on segment boundaries?
pub fn matches(rule_prefix: &str, normalized: &str) -> bool {
    let prefix = normalize(rule_prefix);
    if prefix == "/" {
        return true;
    }
    normalized == prefix || normalized.starts_with(&format!("{prefix}/"))
}

/// The most specific rule covering the path (longest prefix wins; ties
/// keep the first).
pub fn select<'a>(rules: &'a [PathRule], normalized: &str) -> Option<&'a PathRule> {
    rules
        .iter()
        .filter(|rule| matches(&rule.prefix, normalized))
        .max_by_key(|rule| normalize(&rule.prefix).len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_resolves_dots_and_duplicates() {
        assert_eq!(normalize("/a/../b"), "/b");
        assert_eq!(normalize("/a//b///c"), "/a/b/c");
        assert_eq!(normalize("/a/b/../../c"), "/c");
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize("/x/"), "/x");
    }

    #[test]
    fn segment_boundary_matching() {
        assert!(matches("/admin", "/admin"));
        assert!(matches("/admin", "/admin/users"));
        assert!(!matches("/admin", "/administrator"));
        assert!(matches("/", "/anything"));
    }

    #[test]
    fn longest_prefix_wins() {
        let rules = vec![
            PathRule {
                prefix: "/admin".to_owned(),
                auth: AuthRule::On,
                ip_list: Vec::new(),
            },
            PathRule {
                prefix: "/admin/secret".to_owned(),
                auth: AuthRule::Off,
                ip_list: Vec::new(),
            },
        ];
        assert_eq!(
            select(&rules, &normalize("/admin/secret/keys")).map(|rule| rule.prefix.as_str()),
            Some("/admin/secret")
        );
        assert_eq!(
            select(&rules, &normalize("/admin/dash")).map(|rule| rule.prefix.as_str()),
            Some("/admin")
        );
        assert!(select(&rules, &normalize("/public")).is_none());
    }
}
