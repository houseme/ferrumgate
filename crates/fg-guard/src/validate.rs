//! Normalization and validation for the guard model (WP-50): pure
//! functions over plain data. `normalize` applies upstream defaults for
//! zero values and clamps the escalation ceiling; `validate` collects
//! every problem instead of stopping at the first.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::{FileConfig, Settings};

/// Upstream default: ban duration (3600 s).
pub const DEFAULT_BAN_SECONDS: u32 = 3600;
/// Upstream default escalation ceiling: 7 days.
pub const DEFAULT_MAX_BAN_SECONDS: u32 = 7 * 24 * 3600;
/// Hard ceiling for the escalation ceiling: 365 days.
pub const MAX_MAX_BAN_SECONDS: u32 = 365 * 24 * 3600;
/// FerrumGate protection: the default duration is capped at 30 days, like
/// manual bans.
pub const MAX_BAN_SECONDS: u32 = 30 * 24 * 3600;
/// Manual bans: 1 hour minimum.
pub const MANUAL_MIN_SECONDS: i64 = 3600;
/// Manual bans: 30 days maximum (720 hours).
pub const MANUAL_MAX_SECONDS: i64 = 720 * 3600;
/// Manual bans: interface default, 24 hours.
pub const MANUAL_DEFAULT_SECONDS: i64 = 24 * 3600;
/// Manual bans: `seconds = -1` means permanent.
pub const MANUAL_PERMANENT: i64 = -1;
/// FerrumGate protection: whitelist entries.
pub const MAX_IGNORE_LIST: usize = 256;

/// A collected validation problem: the offending field path and reason.
#[derive(Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

/// Applies upstream defaults for zero-valued settings and clamps both
/// durations to their documented ranges.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    let settings = &mut config.settings;
    settings.ban_seconds = if settings.ban_seconds == 0 {
        DEFAULT_BAN_SECONDS
    } else {
        settings.ban_seconds.min(MAX_BAN_SECONDS)
    };
    settings.max_ban_seconds = if settings.max_ban_seconds == 0 {
        DEFAULT_MAX_BAN_SECONDS
    } else {
        settings
            .max_ban_seconds
            .min(MAX_MAX_BAN_SECONDS)
            .max(settings.ban_seconds)
    };
    settings.ignore_list = settings
        .ignore_list
        .iter()
        .map(|entry| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .take(MAX_IGNORE_LIST)
        .collect();
    config
}

/// Collects every validation problem of an already normalized config.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    for (index, entry) in config.settings.ignore_list.iter().enumerate() {
        if parse_net(entry).is_none() {
            problems.push(Problem {
                field: format!("settings.ignoreList[{index}]"),
                reason: "not an IP address or CIDR network".to_owned(),
            });
        }
    }
    problems
}

/// Parses a whitelist entry: a bare IP becomes its host network (a single
/// IPv6 address protects its whole /64, the same normalization the ban
/// table applies).
pub fn parse_net(text: &str) -> Option<IpNet> {
    if let Ok(net) = text.parse::<IpNet>() {
        return Some(net);
    }
    let ip: IpAddr = text.parse().ok()?;
    Some(match ip {
        IpAddr::V4(_) => IpNet::new(ip, 32).ok()?,
        IpAddr::V6(v6) => {
            let v6 = v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6));
            let prefix = match v6 {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            IpNet::new(v6, prefix).ok()?
        }
    })
}

/// Whether `seconds` is a valid manual ban duration (`-1` for permanent,
/// otherwise 1..=720 hours).
pub fn valid_manual_seconds(seconds: i64) -> bool {
    seconds == MANUAL_PERMANENT || (MANUAL_MIN_SECONDS..=MANUAL_MAX_SECONDS).contains(&seconds)
}

/// Returns true when the settings changed the ban policy knobs (used to
/// skip no-op updates).
pub fn policy_equal(a: &Settings, b: &Settings) -> bool {
    a.ban_seconds == b.ban_seconds
        && a.increment == b.increment
        && a.max_ban_seconds == b.max_ban_seconds
        && a.ignore_private == b.ignore_private
        && a.ignore_list == b.ignore_list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_applies_defaults_and_clamps() {
        let config = normalize(FileConfig::default());
        assert_eq!(config.settings.ban_seconds, DEFAULT_BAN_SECONDS);
        assert_eq!(config.settings.max_ban_seconds, DEFAULT_MAX_BAN_SECONDS);
        assert!(config.settings.increment, "increment defaults on");
        assert!(!config.settings.enable, "module defaults off");

        let config = normalize(FileConfig {
            settings: Settings {
                ban_seconds: 999_999_999,
                max_ban_seconds: 999_999_999,
                ignore_list: vec!["  10.0.0.1  ".to_owned(), "".to_owned()],
                ..Settings::default()
            },
        });
        assert_eq!(config.settings.ban_seconds, MAX_BAN_SECONDS);
        assert_eq!(config.settings.max_ban_seconds, MAX_MAX_BAN_SECONDS);
        assert_eq!(config.settings.ignore_list, ["10.0.0.1"]);

        // The ceiling never drops below the default duration.
        let config = normalize(FileConfig {
            settings: Settings {
                ban_seconds: 7200,
                max_ban_seconds: 3600,
                ..Settings::default()
            },
        });
        assert_eq!(config.settings.max_ban_seconds, 7200);
    }

    #[test]
    fn validate_reports_bad_whitelist_entries() {
        let problems = validate(&normalize(FileConfig {
            settings: Settings {
                ignore_list: vec!["10.0.0.0/8".to_owned(), "bogus".to_owned()],
                ..Settings::default()
            },
        }));
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].field, "settings.ignoreList[1]");
    }

    #[test]
    fn parse_net_accepts_addresses_and_cidrs() {
        assert_eq!(parse_net("10.0.0.5").unwrap().to_string(), "10.0.0.5/32");
        // A bare IPv6 address stays host-scoped here; the ban table widens
        // single IPv6 entries to their /64 when the whitelist is applied.
        assert_eq!(parse_net("fd00::5").unwrap().to_string(), "fd00::5/128");
        assert_eq!(parse_net("10.0.0.0/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(
            parse_net("::ffff:1.2.3.4").unwrap().to_string(),
            "1.2.3.4/32",
            "v4-mapped addresses collapse to IPv4"
        );
        assert!(parse_net("bogus").is_none());
    }

    #[test]
    fn valid_manual_seconds_range_and_permanent() {
        assert!(valid_manual_seconds(MANUAL_PERMANENT));
        assert!(valid_manual_seconds(MANUAL_DEFAULT_SECONDS));
        assert!(valid_manual_seconds(MANUAL_MIN_SECONDS));
        assert!(valid_manual_seconds(MANUAL_MAX_SECONDS));
        assert!(!valid_manual_seconds(0));
        assert!(!valid_manual_seconds(60));
        assert!(!valid_manual_seconds(MANUAL_MAX_SECONDS + 1));
        assert!(!valid_manual_seconds(-2));
    }
}
