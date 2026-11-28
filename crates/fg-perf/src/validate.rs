//! Normalization and validation (WP-69 §3.3): pure functions over plain
//! data — no I/O, no network, no clock. `normalize` fills missing rule
//! defaults (upstream loads fill them too) and repairs values the clamps
//! can fix; `validate` collects every remaining problem instead of
//! stopping at the first.

use std::collections::HashSet;

use crate::model::{AlertRule, FileConfig, limits};

/// One collected problem: the offending field path and the reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

/// Fills missing defaults and repairs what the documented bounds can
/// repair (zero duration → default, zero `minRequests` → 20, non-finite
/// thresholds → 0); trims and de-duplicates the site scope.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    for rule in &mut config.rules {
        normalize_rule(rule);
    }
    config
}

/// Applies the per-rule normalization ([`normalize`]).
pub fn normalize_rule(rule: &mut AlertRule) {
    rule.key = rule.key.trim().to_lowercase();
    rule.name = rule.name.trim().to_owned();
    rule.group = rule.group.trim().to_owned();
    rule.remark = rule.remark.trim().to_owned();
    rule.duration_minutes = if rule.duration_minutes == 0 {
        limits::DEFAULT_DURATION_MINUTES
    } else {
        rule.duration_minutes
            .clamp(limits::DURATION_MIN_MINUTES, limits::DURATION_MAX_MINUTES)
    };
    if rule.min_requests == 0 {
        rule.min_requests = limits::DEFAULT_MIN_REQUESTS;
    }
    if !rule.threshold.is_finite() {
        rule.threshold = 0.0;
    }
    let mut seen_sites = HashSet::new();
    rule.sites = rule
        .sites
        .iter()
        .map(|site| site.trim().to_owned())
        .filter(|site| !site.is_empty() && seen_sites.insert(site.clone()))
        .take(limits::MAX_SITES_PER_RULE)
        .collect();
}

/// Collects every problem of an already normalized config; field paths
/// are prefixed `rules[i].`.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    if config.rules.len() > limits::MAX_RULES {
        problems.push(Problem {
            field: "rules".to_owned(),
            reason: format!(
                "at most {} rules are allowed (found {})",
                limits::MAX_RULES,
                config.rules.len()
            ),
        });
    }
    let mut seen_keys = HashSet::with_capacity(config.rules.len());
    for (index, rule) in config.rules.iter().enumerate() {
        let prefix = format!("rules[{index}].");
        if !valid_key(&rule.key) {
            problems.push(Problem {
                field: format!("{prefix}key"),
                reason: "the key must be 12 lowercase hex characters".to_owned(),
            });
        } else if !seen_keys.insert(rule.key.as_str()) {
            problems.push(Problem {
                field: format!("{prefix}key"),
                reason: "duplicate rule key".to_owned(),
            });
        }
        if rule.name.is_empty() {
            problems.push(Problem {
                field: format!("{prefix}name"),
                reason: "the name is required".to_owned(),
            });
        } else if rule.name.chars().count() > limits::NAME_MAX_CHARS {
            problems.push(Problem {
                field: format!("{prefix}name"),
                reason: format!(
                    "the name must have at most {} characters",
                    limits::NAME_MAX_CHARS
                ),
            });
        }
        if rule.group.chars().count() > limits::GROUP_MAX_CHARS {
            problems.push(Problem {
                field: format!("{prefix}group"),
                reason: format!(
                    "the group must have at most {} characters",
                    limits::GROUP_MAX_CHARS
                ),
            });
        }
        if !(limits::DURATION_MIN_MINUTES..=limits::DURATION_MAX_MINUTES)
            .contains(&rule.duration_minutes)
        {
            problems.push(Problem {
                field: format!("{prefix}durationMinutes"),
                reason: format!(
                    "the duration must be {}..={} minutes",
                    limits::DURATION_MIN_MINUTES,
                    limits::DURATION_MAX_MINUTES
                ),
            });
        }
        if !rule.threshold.is_finite() {
            problems.push(Problem {
                field: format!("{prefix}threshold"),
                reason: "the threshold must be a finite number".to_owned(),
            });
        }
    }
    problems
}

/// Whether `text` is a valid collection key: 12 lowercase hex characters
/// (6 random bytes, the fg-admin collection convention).
pub fn valid_key(text: &str) -> bool {
    text.len() == 12
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Generates a key unique within `existing`; the same shape the fg-admin
/// collections generate.
pub fn random_key(existing: &[AlertRule]) -> anyhow::Result<String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes[2..]).map_err(|_| anyhow::anyhow!("key generation failed"))?;
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
        if !existing.iter().any(|rule| rule.key == key) {
            return Ok(key);
        }
    }
    anyhow::bail!("unable to generate a unique rule key")
}

/// Whether replacing `a` with `b` changes the alert semantics (metric,
/// operator, threshold, duration, site scope or minimum requests). The
/// name, group, level and remark do not affect a running evaluation
/// (WP-69 §3.3.4); the enable switch is handled separately.
pub fn semantic_eq(a: &AlertRule, b: &AlertRule) -> bool {
    let same_sites = {
        let mut left = a.sites.clone();
        let mut right = b.sites.clone();
        left.sort();
        right.sort();
        left == right
    };
    a.metric == b.metric
        && a.op == b.op
        && a.threshold.to_bits() == b.threshold.to_bits()
        && a.duration_minutes == b.duration_minutes
        && a.min_requests == b.min_requests
        && same_sites
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CmpOp, Level, Metric};

    fn rule() -> AlertRule {
        AlertRule {
            key: "a1b2c3d4e5f6".to_owned(),
            name: "cpu".to_owned(),
            metric: Metric::HostCpu,
            op: CmpOp::Gt,
            threshold: 90.0,
            duration_minutes: 5,
            level: Level::Warn,
            ..AlertRule::default()
        }
    }

    #[test]
    fn validate_duration_1_to_1440_name_64() {
        let mut raw = FileConfig::default();
        let mut r0 = rule();
        r0.key = "a1b2c3d4e500".to_owned();
        r0.duration_minutes = 0;
        raw.rules.push(r0);
        let mut r1 = rule();
        r1.key = "a1b2c3d4e501".to_owned();
        r1.duration_minutes = 1441;
        raw.rules.push(r1);
        let raw_problems = validate(&raw);
        assert_eq!(raw_problems.len(), 2, "{raw_problems:?}");
        assert!(
            raw_problems
                .iter()
                .all(|problem| problem.field.ends_with("durationMinutes"))
        );

        let mut config = FileConfig::default();
        let mut too_short = rule();
        too_short.key = "a1b2c3d4e510".to_owned();
        too_short.duration_minutes = 0;
        config.rules.push(too_short);
        let mut too_long = rule();
        too_long.key = "a1b2c3d4e511".to_owned();
        too_long.duration_minutes = 1441;
        config.rules.push(too_long);
        let mut nameless = rule();
        nameless.key = "a1b2c3d4e512".to_owned();
        nameless.name = "  ".to_owned();
        config.rules.push(nameless);
        let mut long_name = rule();
        long_name.key = "a1b2c3d4e513".to_owned();
        long_name.name = "x".repeat(65);
        config.rules.push(long_name);
        let mut ok = rule();
        ok.key = "a1b2c3d4e514".to_owned();
        ok.duration_minutes = 1440;
        ok.name = "y".repeat(64);
        config.rules.push(ok);
        // Normalization repairs the zero duration and the 1441 clamp.
        let config = normalize(config);
        assert_eq!(config.rules[0].duration_minutes, 5);
        assert_eq!(
            config.rules[1].duration_minutes,
            limits::DURATION_MAX_MINUTES
        );
        let problems = validate(&config);
        // Only the name problems remain after normalization.
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems
                .iter()
                .all(|problem| problem.field.ends_with("name"))
        );
    }

    #[test]
    fn normalize_fills_missing_rule_defaults() {
        let mut config = FileConfig::default();
        config.rules.push(AlertRule {
            key: "a1b2c3d4e5f6".to_owned(),
            name: "cpu".to_owned(),
            duration_minutes: 0,
            min_requests: 0,
            threshold: f64::NAN,
            sites: vec![
                " a ".to_owned(),
                "".to_owned(),
                "b".to_owned(),
                "a".to_owned(),
            ],
            ..AlertRule::default()
        });
        let config = normalize(config);
        let rule = &config.rules[0];
        assert_eq!(rule.min_requests, limits::DEFAULT_MIN_REQUESTS);
        assert_eq!(rule.duration_minutes, limits::DEFAULT_DURATION_MINUTES);
        assert_eq!(rule.threshold, 0.0);
        assert_eq!(rule.sites, vec!["a".to_owned(), "b".to_owned()]);
        assert!(validate(&config).is_empty(), "normalized config is clean");
    }

    #[test]
    fn semantic_eq_ignores_display_fields() {
        let mut edited = rule();
        assert!(semantic_eq(&rule(), &edited), "identical rules");
        edited.name = "renamed".to_owned();
        edited.level = Level::Error;
        edited.remark = "note".to_owned();
        edited.group = "ops".to_owned();
        assert!(semantic_eq(&rule(), &edited), "display-only edits");
        for mut semantic in [
            AlertRule {
                metric: Metric::HostMem,
                ..rule()
            },
            AlertRule {
                threshold: 91.0,
                ..rule()
            },
            AlertRule {
                duration_minutes: 6,
                ..rule()
            },
            AlertRule {
                min_requests: 21,
                ..rule()
            },
            AlertRule {
                sites: vec!["a".to_owned()],
                ..rule()
            },
        ] {
            semantic.key = rule().key;
            semantic.name = rule().name;
            assert!(
                !semantic_eq(&rule(), &semantic),
                "{:?} changes semantics",
                { semantic.metric }
            );
        }
    }

    #[test]
    fn random_key_is_unique_12_hex() {
        let existing = vec![rule()];
        let key = random_key(&existing).expect("key");
        assert_eq!(key.len(), 12);
        assert!(valid_key(&key));
        assert_ne!(key, existing[0].key);
        assert!(!valid_key("A1B2C3D4E5F6"), "uppercase refused");
        assert!(!valid_key("short"));
        assert!(!valid_key("zzzzzzzzzzzz"));
    }
}
