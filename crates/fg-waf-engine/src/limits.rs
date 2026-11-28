//! Centralized limits for the WAF rule engine (WP-55 §3.4 and the batch
//! scope note "上限集中": rule count, regex size and the body inspection
//! size live here; every validation in `compile` and every clamping in
//! `EngineConfig` references these constants only).

/// Maximum number of rules in one rule set (FerrumGate's own cap; upstream
/// sets none, the engine needs a bound so compilation stays linear).
pub const MAX_RULES: usize = 512;
/// Maximum length of a rule id.
pub const MAX_RULE_ID_LEN: usize = 64;
/// Maximum length of a rule display name.
pub const MAX_RULE_NAME_LEN: usize = 128;
/// Maximum length of a rule set display name.
pub const MAX_RULE_SET_NAME_LEN: usize = 128;
/// Maximum length of a rule message (shown in hit logs).
pub const MAX_RULE_MESSAGE_LEN: usize = 512;
/// Maximum number of tags per rule.
pub const MAX_TAGS_PER_RULE: usize = 16;
/// Maximum length of one tag.
pub const MAX_TAG_LEN: usize = 64;
/// Maximum nesting depth of a condition matcher (`all` / `any` / `not`).
pub const MAX_CONDITION_DEPTH: usize = 8;
/// Maximum number of IP / CIDR entries in one `ipIn` condition.
pub const MAX_IP_ENTRIES: usize = 1024;
/// Maximum length of a header name in a `header` condition.
pub const MAX_HEADER_NAME_LEN: usize = 256;
/// Maximum length of a regex pattern (source text, in bytes).
pub const MAX_REGEX_PATTERN_LEN: usize = 4096;
/// Maximum size of one compiled regex program (`regex` crate
/// `RegexBuilder::size_limit`).
pub const MAX_COMPILED_REGEX_BYTES: usize = 1 << 20;
/// Default body inspection size: 12.5 MiB = 13_107_200 bytes (WP-55 §3.4,
/// upstream default "12.5 MB", binary MB as upstream Go computes it).
pub const DEFAULT_BODY_INSPECT_LIMIT: usize = 13_107_200;
/// Maximum body inspection size: 1024 MiB (WP-55 §3.4).
pub const MAX_BODY_INSPECT_LIMIT: usize = 1024 * 1024 * 1024;
/// Status code used by deny rules when the rule does not set one.
pub const DEFAULT_DENY_STATUS: u16 = 403;
/// Smallest status a deny rule may set.
pub const MIN_DENY_STATUS: u16 = 400;
/// Largest status a deny rule may set.
pub const MAX_DENY_STATUS: u16 = 599;
/// The only rule set format version understood by this engine.
pub const SUPPORTED_RULE_SET_VERSION: u32 = 1;

/// Engine-wide configuration knobs. Every size is normalized through
/// [`EngineConfig::clamped`] so the limits above stay the single source
/// of truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    /// Body bytes the engine inspects per request (WP-55 §3.4: default
    /// 12.5 MB, configurable up to 1024 MB). A longer body excerpt is
    /// truncated for matching; 0 selects the default.
    pub body_inspect_limit: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            body_inspect_limit: DEFAULT_BODY_INSPECT_LIMIT,
        }
    }
}

impl EngineConfig {
    /// Normalizes a configured limit: 0 falls back to the default and
    /// larger values clamp to [`MAX_BODY_INSPECT_LIMIT`].
    pub fn clamped(body_inspect_limit: usize) -> Self {
        Self {
            body_inspect_limit: if body_inspect_limit == 0 {
                DEFAULT_BODY_INSPECT_LIMIT
            } else {
                body_inspect_limit.min(MAX_BODY_INSPECT_LIMIT)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_limits_match_the_wp55_defaults() {
        // WP-55 §3.4: default 12.5 MB, configurable up to 1024 MB. The
        // checks are compile-time (all operands are constants); the test
        // keeps the invariants pinned to this file.
        const {
            assert!(MAX_BODY_INSPECT_LIMIT > DEFAULT_BODY_INSPECT_LIMIT);
            assert!(DEFAULT_BODY_INSPECT_LIMIT == 13_107_200);
            assert!(MAX_BODY_INSPECT_LIMIT == 1024 * 1024 * 1024);
        }
    }

    #[test]
    fn deny_status_range_is_a_valid_http_error_range() {
        const {
            assert!(MIN_DENY_STATUS <= DEFAULT_DENY_STATUS);
            assert!(DEFAULT_DENY_STATUS <= MAX_DENY_STATUS);
            assert!(MIN_DENY_STATUS == 400);
            assert!(MAX_DENY_STATUS == 599);
            assert!(DEFAULT_DENY_STATUS == 403);
        }
    }

    #[test]
    fn config_zero_inspect_limit_falls_back_to_the_default() {
        assert_eq!(
            EngineConfig::clamped(0),
            EngineConfig {
                body_inspect_limit: DEFAULT_BODY_INSPECT_LIMIT
            }
        );
    }

    #[test]
    fn config_over_max_inspect_limit_clamps_to_the_ceiling() {
        assert_eq!(
            EngineConfig::clamped(MAX_BODY_INSPECT_LIMIT * 2),
            EngineConfig {
                body_inspect_limit: MAX_BODY_INSPECT_LIMIT
            }
        );
        assert_eq!(
            EngineConfig::clamped(64 * 1024 * 1024),
            EngineConfig {
                body_inspect_limit: 64 * 1024 * 1024
            }
        );
    }
}
