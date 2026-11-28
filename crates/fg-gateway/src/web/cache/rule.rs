//! Per-path cache rules (WP-27): validation, path normalization, segment-prefix
//! and linear-time wildcard matching, and specificity precedence.

use std::{collections::HashSet, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum number of per-path cache rules allowed on a single site.
pub const MAX_CACHE_RULES: usize = 200;

/// Maximum cache TTL (30 days).
pub const MAX_CACHE_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// Per-path cache rule overriding the site default caching behavior.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheRule {
    /// Leading `/`, no whitespace/`?`/`#`/`%`/`//`/`.`/`..`, unique per site,
    /// case-sensitive.
    pub path: String,
    /// When `true`, matching paths neither read from nor write to the cache.
    pub no_cache: bool,
    /// Rule-specific TTL (`0..=30d`); `None` (or 0 seconds) inherits the site TTL.
    #[serde(default, with = "opt_duration_secs")]
    pub ttl: Option<Duration>,
    /// Force-cache: ignores backend `no-store`, `no-cache`, and `max-age`,
    /// while still respecting `private`, `Set-Cookie`, and `Vary: *`.
    #[serde(rename = "override")]
    pub override_: bool,
}

mod opt_duration_secs {
    use super::*;

    pub fn serialize<S: Serializer>(val: &Option<Duration>, ser: S) -> Result<S::Ok, S::Error> {
        let secs = val.map_or(0, |d| d.as_secs());
        ser.serialize_u64(secs)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Duration>, D::Error> {
        let secs = Option::<u64>::deserialize(de)?.unwrap_or(0);
        if secs == 0 {
            Ok(None)
        } else {
            Ok(Some(Duration::from_secs(secs)))
        }
    }
}

/// Validates a single rule path string (used both for site config validation
/// and the cache purge endpoint).
pub fn validate_rule_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err("cache rule path must start with '/'".to_owned());
    }
    if path.contains("//") {
        return Err("cache rule path must not contain consecutive '/'".to_owned());
    }
    if path.chars().any(char::is_whitespace) {
        return Err("cache rule path must not contain whitespace".to_owned());
    }
    for forbidden in ['?', '#', '%'] {
        if path.contains(forbidden) {
            return Err(format!("cache rule path must not contain '{forbidden}'"));
        }
    }
    for seg in path.split('/') {
        if seg == "." || seg == ".." {
            return Err("cache rule path must not contain '.' or '..' segments".to_owned());
        }
    }
    Ok(())
}

/// Validates a site's cache rules against WP-27 constraints:
/// - At most 200 rules
/// - Valid path syntax and unique per site (case-sensitive)
/// - TTL within `0..=30 days`
/// - When `override_` is enabled (and not `no_cache`), at least one of the
///   rule TTL or site TTL must be > 0.
pub fn validate_rules(rules: &[CacheRule], site_ttl: Duration) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if rules.len() > MAX_CACHE_RULES {
        errors.push(format!(
            "too many cache rules: {} exceeds maximum {}",
            rules.len(),
            MAX_CACHE_RULES
        ));
    }
    let mut seen: HashSet<&str> = HashSet::with_capacity(rules.len());
    for (idx, rule) in rules.iter().enumerate() {
        if let Err(msg) = validate_rule_path(&rule.path) {
            errors.push(format!("rules[{idx}].path: {msg}"));
        } else if !seen.insert(rule.path.as_str()) {
            errors.push(format!(
                "rules[{idx}].path: duplicate cache rule path '{}'",
                rule.path
            ));
        }
        if let Some(ttl) = rule.ttl
            && ttl > MAX_CACHE_TTL
        {
            errors.push(format!(
                "rules[{idx}].ttl: exceeds maximum {} seconds",
                MAX_CACHE_TTL.as_secs()
            ));
        }
        if rule.override_ && !rule.no_cache {
            let effective_rule_ttl = rule.ttl.unwrap_or(Duration::ZERO);
            if effective_rule_ttl.is_zero() && site_ttl.is_zero() {
                errors.push(format!(
                    "rules[{idx}].override: requires a non-zero rule or site TTL"
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Normalizes a request path (Go `path.Clean` semantics): resolves `.` and `..`,
/// collapses duplicate slashes, ensures a leading `/`, and strips any trailing
/// slash except for `"/"`.
pub fn normalize_path(path: &str) -> String {
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

/// Linear-time greedy-backtracking wildcard matcher (`*` matches zero or more
/// of any character, including `/`).
///
/// Worst-case time complexity is `O(len(pattern) * len(text))` with `O(1)`
/// extra space — never degenerates exponentially on crafted inputs.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let s = text.as_bytes();
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut match_si = 0usize;

    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            match_si = si;
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            match_si += 1;
            si = match_si;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Matches a validated rule pattern against a *normalized* request path.
///
/// - Without `*`: segment-prefix match (`"/api"` matches `"/api"` and
///   `"/api/x"`, not `"/apix"`; `"/"` matches everything).
/// - With `*`: full-path wildcard match via [`wildcard_match`].
pub fn match_rule_path(pattern: &str, normalized_path: &str) -> bool {
    if pattern.contains('*') {
        return wildcard_match(pattern, normalized_path);
    }
    let clean_pat = normalize_path(pattern);
    if clean_pat == "/" {
        return true;
    }
    normalized_path == clean_pat
        || normalized_path
            .strip_prefix(clean_pat.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Rule specificity score: number of non-`*` characters in the rule path.
fn specificity(pattern: &str) -> usize {
    pattern.chars().filter(|&c| c != '*').count()
}

/// Selects the highest-precedence matching rule for `raw_path`.
///
/// Normalizes `raw_path` first. More specific rules (more non-`*` characters)
/// win; ties preserve configuration order (earlier rule wins).
pub fn select_rule<'a>(rules: &'a [CacheRule], raw_path: &str) -> Option<&'a CacheRule> {
    let normalized = normalize_path(raw_path);
    let mut best: Option<(&'a CacheRule, usize)> = None;
    for rule in rules {
        if match_rule_path(&rule.path, &normalized) {
            let score = specificity(&rule.path);
            if best.is_none_or(|(_, best_score)| score > best_score) {
                best = Some((rule, score));
            }
        }
    }
    best.map(|(r, _)| r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn rule(path: &str) -> CacheRule {
        CacheRule {
            path: path.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn cache_rule_matching_and_precedence() {
        // Segment prefix: /api matches /api and /api/x, not /apix.
        assert!(match_rule_path("/api", "/api"));
        assert!(match_rule_path("/api", "/api/x"));
        assert!(!match_rule_path("/api", "/apix"));
        assert!(match_rule_path("/", "/anything/here"));

        // Wildcard matches across `/`.
        assert!(match_rule_path(
            "/api/products/*",
            "/api/products/1/details"
        ));
        assert!(match_rule_path("/static/*.js", "/static/sub/app.js"));
        assert!(!match_rule_path("/static/*.js", "/static/app.css"));

        // Normalization before matching.
        assert_eq!(normalize_path("//api"), "/api");
        assert_eq!(normalize_path("/x/../api"), "/api");
        assert_eq!(normalize_path("/a/b/../../api/v1/"), "/api/v1");

        // Precedence: more non-'*' chars wins; tie keeps config order.
        let rules = vec![
            CacheRule {
                path: "/".to_owned(),
                no_cache: true,
                ..Default::default()
            },
            CacheRule {
                path: "/static/*".to_owned(),
                ttl: Some(Duration::from_secs(60)),
                ..Default::default()
            },
            CacheRule {
                path: "/static/*.js".to_owned(),
                ttl: Some(Duration::from_secs(300)),
                ..Default::default()
            },
            // Same specificity (8 non-'*' chars) as `/static/*`: earlier wins.
            CacheRule {
                path: "/static/*".to_owned(),
                ttl: Some(Duration::from_secs(999)),
                ..Default::default()
            },
        ];

        assert_eq!(
            select_rule(&rules, "//static/sub/../app.js")
                .and_then(|r| r.ttl)
                .map(|d| d.as_secs()),
            Some(300)
        );
        assert_eq!(
            select_rule(&rules, "/static/app.css")
                .and_then(|r| r.ttl)
                .map(|d| d.as_secs()),
            Some(60)
        );
        assert!(select_rule(&rules, "/other").unwrap().no_cache);

        // Tie between two distinct patterns with identical non-'*' length:
        // `/a/*/c` (5) vs `/a/b/*` (5) on `/a/b/c` -> first in config order wins.
        let tie_rules = vec![
            CacheRule {
                path: "/a/*/c".to_owned(),
                ttl: Some(Duration::from_secs(10)),
                ..Default::default()
            },
            CacheRule {
                path: "/a/b/*".to_owned(),
                ttl: Some(Duration::from_secs(20)),
                ..Default::default()
            },
        ];
        assert_eq!(
            select_rule(&tie_rules, "/a/b/c")
                .and_then(|r| r.ttl)
                .map(|d| d.as_secs()),
            Some(10)
        );
    }

    #[test]
    fn cache_wildcard_match_is_linear() {
        // Adversarial backtracking input that blows up naive recursive matchers.
        let pattern = format!("/{}b", "a*".repeat(40));
        let input = format!("/{}", "a".repeat(20_000));
        let start = Instant::now();
        assert!(!wildcard_match(&pattern, &input));
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "wildcard match took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn rule_validation_enforces_constraints() {
        assert!(validate_rule_path("/api/v1").is_ok());
        assert!(validate_rule_path("/static/*.js").is_ok());
        assert!(validate_rule_path("api").is_err());
        assert!(validate_rule_path("/a b").is_err());
        assert!(validate_rule_path("/a?b").is_err());
        assert!(validate_rule_path("/a#b").is_err());
        assert!(validate_rule_path("/a%20b").is_err());
        assert!(validate_rule_path("/a//b").is_err());
        assert!(validate_rule_path("/a/./b").is_err());
        assert!(validate_rule_path("/a/../b").is_err());

        // Duplicates rejected.
        let dup = vec![rule("/api"), rule("/api")];
        assert!(validate_rules(&dup, Duration::from_secs(60)).is_err());

        // > 200 rules rejected.
        let many: Vec<CacheRule> = (0..=MAX_CACHE_RULES)
            .map(|i| rule(&format!("/p{i}")))
            .collect();
        assert!(validate_rules(&many, Duration::from_secs(60)).is_err());

        // override requires non-zero TTL on rule or site.
        let bad_override = vec![CacheRule {
            path: "/force".to_owned(),
            override_: true,
            ..Default::default()
        }];
        assert!(validate_rules(&bad_override, Duration::ZERO).is_err());
        assert!(validate_rules(&bad_override, Duration::from_secs(10)).is_ok());
    }
}
