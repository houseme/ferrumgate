//! Path rewrites and redirects (WP-23 step 10): ordered regex rules, the
//! first match wins. A rule is either an internal rewrite (`to` starts
//! with `/`) or a redirect (`redirect` is 301/302/307/308, 302 default;
//! the original query string is preserved and `{host}` expands).
#![allow(dead_code)]

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteError {
    BadRegex(String),
    BadTarget(String),
    BadCode(u16),
}

impl std::fmt::Display for RewriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRegex(pattern) => write!(f, "重写 pattern 不是合法正则：{pattern}"),
            Self::BadTarget(target) => write!(f, "内部重写目标必须以 / 开头：{target}"),
            Self::BadCode(code) => write!(f, "重定向码只允许 301/302/307/308：{code}"),
        }
    }
}

impl std::error::Error for RewriteError {}

/// One compiled rewrite rule.
pub struct Rewrite {
    pub pattern: Regex,
    pub to: String,
    /// None = internal rewrite (`to` starts with `/`); Some(301|302|307|308)
    /// = redirect that runs before authentication.
    pub redirect: Option<u16>,
}

/// Splits `path_and_query` into its path part and the raw query string
/// (without the `?`). Rules only ever match against the path; the query
/// is carried over verbatim.
fn split_path_query(path_and_query: &str) -> (&str, Option<&str>) {
    match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    }
}

impl Rewrite {
    pub fn compile(pattern: &str, to: &str, redirect: Option<u16>) -> Result<Self, RewriteError> {
        let pattern =
            Regex::new(pattern).map_err(|_| RewriteError::BadRegex(pattern.to_owned()))?;
        match redirect {
            // Internal rewrite: target must be an origin-form path.
            None => {
                if !to.starts_with('/') {
                    return Err(RewriteError::BadTarget(to.to_owned()));
                }
            }
            // Redirect: only permanent/temporary/keeper-preserving codes.
            Some(code) => {
                if !matches!(code, 301 | 302 | 307 | 308) {
                    return Err(RewriteError::BadCode(code));
                }
            }
        }
        Ok(Self {
            pattern,
            to: to.to_owned(),
            redirect,
        })
    }

    /// Applies this rule to `path_and_query`. Returns [`Outcome::None`]
    /// when the pattern does not match.
    pub fn apply(&self, path_and_query: &str, host: &str) -> Outcome {
        let (path, query) = split_path_query(path_and_query);
        if !self.pattern.is_match(path) {
            return Outcome::None;
        }
        match self.redirect {
            // Internal rewrite: substitute the path (`$1..$N` backrefs via
            // regex replace semantics) and re-attach the original query.
            None => {
                let new_path = self
                    .pattern
                    .replace_all(path, self.to.as_str())
                    .into_owned();
                match query {
                    Some(q) => Outcome::Rewritten(format!("{new_path}?{q}")),
                    None => Outcome::Rewritten(new_path),
                }
            }
            // Redirect: expand `{host}`, then append the original query to
            // the target (`?` if it has none, `&` if it already has one).
            Some(code) => {
                let mut target = self.to.replace("{host}", host);
                if let Some(q) = query {
                    let sep = if target.contains('?') { '&' } else { '?' };
                    target.push(sep);
                    target.push_str(q);
                }
                Outcome::Redirect { target, code }
            }
        }
    }
}

/// The result of the first matching rule for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No rule matched; the request proceeds untouched.
    None,
    /// Internal rewrite: the new origin-form path (query preserved).
    Rewritten(String),
    /// Redirect: target URL (query preserved, `{host}` expanded) + code.
    Redirect { target: String, code: u16 },
}

/// Applies the rules in order; the first match wins.
pub fn apply_all(rewrites: &[Rewrite], path_and_query: &str, host: &str) -> Outcome {
    for rewrite in rewrites {
        let outcome = rewrite.apply(path_and_query, host);
        if outcome != Outcome::None {
            return outcome;
        }
    }
    Outcome::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_first_match_wins() {
        let rules = [
            Rewrite::compile("^/api/(.*)", "/v2/$1", None).unwrap(),
            Rewrite::compile("^/api/users$", "/v3/users", None).unwrap(),
        ];
        // The first rule matches, so the second never runs even though it
        // would also match this path.
        assert_eq!(
            apply_all(&rules, "/api/users?x=1", "example.com"),
            Outcome::Rewritten("/v2/users?x=1".to_owned())
        );
        // Ordered semantics: swapping the rules changes the winner.
        let rules_flipped = [
            Rewrite::compile("^/api/users$", "/v3/users", None).unwrap(),
            Rewrite::compile("^/api/(.*)", "/v2/$1", None).unwrap(),
        ];
        assert_eq!(
            apply_all(&rules_flipped, "/api/users?x=1", "example.com"),
            Outcome::Rewritten("/v3/users?x=1".to_owned())
        );
    }

    #[test]
    fn internal_rewrite_captures() {
        let rule = Rewrite::compile("/api/(.*)", "/v2/$1", None).unwrap();
        assert_eq!(
            rule.apply("/api/users?x=1", "example.com"),
            Outcome::Rewritten("/v2/users?x=1".to_owned())
        );
        // No query on the request: the result must not gain a trailing `?`.
        assert_eq!(
            rule.apply("/api/users", "example.com"),
            Outcome::Rewritten("/v2/users".to_owned())
        );
    }

    #[test]
    fn redirect_preserves_query_and_expands_host() {
        for code in [301u16, 302, 307, 308] {
            let rule = Rewrite::compile("/old(.*)", "https://{host}/new", Some(code)).unwrap();
            assert_eq!(
                rule.apply("/old?a=b", "example.com"),
                Outcome::Redirect {
                    target: "https://example.com/new?a=b".to_owned(),
                    code
                }
            );
        }
        // No query on the request: the target is used as-is.
        let rule = Rewrite::compile("/old(.*)", "https://{host}/new", Some(302)).unwrap();
        assert_eq!(
            rule.apply("/old", "example.com"),
            Outcome::Redirect {
                target: "https://example.com/new".to_owned(),
                code: 302
            }
        );
        // A target that already carries a query gets `&` appended.
        let rule = Rewrite::compile("/old(.*)", "https://{host}/new?keep=1", Some(308)).unwrap();
        assert_eq!(
            rule.apply("/old?a=b", "example.com"),
            Outcome::Redirect {
                target: "https://example.com/new?keep=1&a=b".to_owned(),
                code: 308
            }
        );
    }

    #[test]
    fn compile_rejects() {
        // Invalid regex, and the error carries the original pattern text.
        match Rewrite::compile("([", "/v2", None) {
            Err(RewriteError::BadRegex(pattern)) => assert_eq!(pattern, "(["),
            _ => panic!("expected BadRegex for invalid pattern"),
        }
        // Internal rewrite target must start with `/`.
        assert!(matches!(
            Rewrite::compile("/api/(.*)", "https://example.com/v2", None),
            Err(RewriteError::BadTarget(_))
        ));
        // Redirect code must be 301/302/307/308.
        assert!(matches!(
            Rewrite::compile("/old", "https://example.com", Some(300)),
            Err(RewriteError::BadCode(300))
        ));
        assert!(matches!(
            Rewrite::compile("/old", "https://example.com", Some(303)),
            Err(RewriteError::BadCode(303))
        ));
    }

    #[test]
    fn no_match_returns_none() {
        let rewrite = Rewrite::compile("^/api/", "/v2", None).unwrap();
        assert_eq!(rewrite.apply("/other?x=1", "example.com"), Outcome::None);
        let redirect = Rewrite::compile("^/old", "https://{host}/new", Some(302)).unwrap();
        assert_eq!(redirect.apply("/new?x=1", "example.com"), Outcome::None);
        // `apply_all` with no rules at all.
        assert_eq!(apply_all(&[], "/api/users", "example.com"), Outcome::None);
    }
}
