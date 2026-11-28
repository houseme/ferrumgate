//! The authentication scope (WP-25): with `authOptional` on, only path
//! rules marked as requiring auth authenticate — everything else is
//! public. Forward auth cannot combine with basic/web auth.
#![allow(dead_code)]

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthScope {
    pub auth_optional: bool,
}

impl AuthScope {
    /// Does this request path require authentication? With authOptional
    /// off every path requires it (the legacy behavior); with it on only
    /// paths whose rule says so.
    pub fn requires_auth(&self, rule_requires: Option<bool>) -> bool {
        if self.auth_optional {
            rule_requires.unwrap_or(false)
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_auth_optional_every_path_requires_auth() {
        let scope = AuthScope {
            auth_optional: false,
        };
        assert!(scope.requires_auth(None));
        assert!(scope.requires_auth(Some(true)));
        assert!(scope.requires_auth(Some(false)));
    }

    #[test]
    fn with_auth_optional_only_marked_rules_require_auth() {
        let scope = AuthScope {
            auth_optional: true,
        };
        // No rule, or a public rule: the path is open.
        assert!(!scope.requires_auth(None));
        assert!(!scope.requires_auth(Some(false)));
        // A rule marked "must authenticate".
        assert!(scope.requires_auth(Some(true)));
    }
}
