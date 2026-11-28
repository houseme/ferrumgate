//! Normalization and validation for jail rules (WP-52 §3.2/§3.4): pure
//! functions over plain data. `normalize_jail` applies the upstream
//! defaults (`maxRetry` 5, `findTime` 600, `banTime` clamped to a year)
//! and trims the multi-line fields; `jail_problems` collects every
//! problem of an already normalized rule, including a full compile check
//! of the filter / ignore / path / kind fields.

use super::model::{Jail, MAX_FILTER_LINE_BYTES, MAX_FILTER_LINES, Source};
use crate::validate::Problem;

/// Upstream default threshold: 5 matches within the window.
pub const DEFAULT_MAX_RETRY: u32 = 5;
/// Upstream default window: 600 seconds.
pub const DEFAULT_FIND_TIME: u32 = 600;
/// Upstream default duration marker: 0 = module default.
pub const DEFAULT_BAN_TIME: i64 = 0;
/// Upstream permanent marker: -1 = never expires.
pub const PERMANENT_BAN_TIME: i64 = -1;
/// Upstream ceiling for a custom duration: 365 days.
pub const MAX_BAN_TIME: i64 = 365 * 24 * 3600;

/// The collection key contract, identical to the fg-admin collections
/// (short, URL-safe, not colliding with batch-style suffixes).
pub fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key != "batch-delete"
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Applies defaults and trims every multi-line field. `name` falls back
/// to the preset's display name, then the key, then the source tag, so a
/// hand-written rule never runs unnamed.
pub fn normalize_jail(mut jail: Jail) -> Jail {
    jail.key = jail.key.trim().to_owned();
    jail.name = jail.name.trim().to_owned();
    jail.group = jail.group.trim().to_owned();
    jail.preset = jail.preset.trim().to_owned();
    jail.remark = jail.remark.trim().to_owned();
    jail.target = trim_lines(&jail.target).join("\n");
    jail.filter = trim_lines(&jail.filter).join("\n");
    jail.ignore = trim_lines(&jail.ignore).join("\n");
    if jail.name.is_empty() {
        jail.name = preset_name(&jail.preset)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if jail.key.is_empty() {
                    jail.source.tag().to_owned()
                } else {
                    jail.key.clone()
                }
            });
    }
    if jail.ban_time > MAX_BAN_TIME {
        jail.ban_time = MAX_BAN_TIME;
    }
    jail
}

/// Collects every validation problem of an already normalized jail; the
/// field paths are relative to the jail (`key`, `filter`, `target`, …).
pub fn jail_problems(jail: &Jail) -> Vec<Problem> {
    let mut problems = Vec::new();
    if !valid_key(&jail.key) {
        problems.push(Problem {
            field: "key".to_owned(),
            reason: "must be 1..=64 letters, digits, dashes or underscores".to_owned(),
        });
    }
    if jail.name.is_empty() {
        problems.push(Problem {
            field: "name".to_owned(),
            reason: "a jail name is required".to_owned(),
        });
    }
    if jail.group.chars().count() > 64 {
        problems.push(Problem {
            field: "group".to_owned(),
            reason: "group name must have at most 64 characters".to_owned(),
        });
    }
    match jail.ban_time {
        PERMANENT_BAN_TIME | DEFAULT_BAN_TIME => {}
        seconds if seconds > 0 && seconds <= MAX_BAN_TIME => {}
        seconds if seconds > MAX_BAN_TIME => problems.push(Problem {
            field: "banTime".to_owned(),
            reason: "the custom duration must not exceed one year".to_owned(),
        }),
        seconds => problems.push(Problem {
            field: "banTime".to_owned(),
            reason: format!(
                "seconds must be -1 (permanent), 0 (default) or positive, got {seconds}"
            ),
        }),
    }
    if jail.max_retry > 100_000 {
        problems.push(Problem {
            field: "maxRetry".to_owned(),
            reason: "the threshold must not exceed 100000".to_owned(),
        });
    }
    if jail.find_time > 30 * 24 * 3600 {
        problems.push(Problem {
            field: "findTime".to_owned(),
            reason: "the window must not exceed 30 days".to_owned(),
        });
    }
    match jail.source {
        Source::File | Source::Journal | Source::Command | Source::Docker => {
            log_jail_problems(jail, &mut problems)
        }
        Source::Event => event_jail_problems(jail, &mut problems),
        Source::Web => web_jail_problems(jail, &mut problems),
        Source::Tls => tls_jail_problems(jail, &mut problems),
    }
    problems
}

/// Ban duration semantics shared by the engine: `0` = module default,
/// `-1` = permanent, `> 0` = custom seconds (already clamped).
pub fn ban_duration(ban_time: i64) -> (Option<std::time::Duration>, bool) {
    match ban_time {
        PERMANENT_BAN_TIME => (None, true),
        DEFAULT_BAN_TIME => (None, false),
        seconds => (
            Some(std::time::Duration::from_secs(seconds.max(1) as u64)),
            false,
        ),
    }
}

fn log_jail_problems(jail: &Jail, problems: &mut Vec<Problem>) {
    if jail.target.is_empty() {
        problems.push(Problem {
            field: "target".to_owned(),
            reason: format!("{} jails need at least one target line", jail.source.tag()),
        });
        return;
    }
    for (index, line) in jail.target.lines().enumerate() {
        match jail.source {
            Source::File => {
                if !line.starts_with('/') {
                    problems.push(Problem {
                        field: format!("target[{index}]"),
                        reason: "log paths must be absolute".to_owned(),
                    });
                }
            }
            Source::Journal => {
                if !line.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b'-')
                }) {
                    problems.push(Problem {
                        field: format!("target[{index}]"),
                        reason: "not a systemd unit name".to_owned(),
                    });
                }
            }
            Source::Docker => {
                if !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
                {
                    problems.push(Problem {
                        field: format!("target[{index}]"),
                        reason: "not a container name".to_owned(),
                    });
                }
            }
            Source::Command if line.len() > 4096 => {
                problems.push(Problem {
                    field: format!("target[{index}]"),
                    reason: "command must have at most 4096 characters".to_owned(),
                });
            }
            _ => {}
        }
    }
    filter_problems(jail, problems, true);
    if let Err(errors) = super::compile_ignore(&jail.ignore) {
        for error in errors {
            problems.push(Problem {
                field: "ignore".to_owned(),
                reason: error,
            });
        }
    }
}

fn event_jail_problems(jail: &Jail, problems: &mut Vec<Problem>) {
    if !super::model::EVENT_TARGETS.contains(&jail.target.as_str()) {
        problems.push(Problem {
            field: "target".to_owned(),
            reason: "event jails target one of the documented event kinds".to_owned(),
        });
    }
    if !jail.filter.is_empty() {
        problems.push(Problem {
            field: "filter".to_owned(),
            reason: "event sources carry their own source address; the filter stays empty"
                .to_owned(),
        });
    }
    if !jail.ignore.is_empty()
        && let Err(errors) = super::compile_ignore(&jail.ignore)
    {
        for error in errors {
            problems.push(Problem {
                field: "ignore".to_owned(),
                reason: error,
            });
        }
    }
}

fn web_jail_problems(jail: &Jail, problems: &mut Vec<Problem>) {
    // Paths: the doc allows an empty rule list (every path), but an
    // `anyStatus` jail with no path rule and no `unknownHost` would count
    // every single request of every visitor — refused at save time.
    if let Err(errors) = crate::webprobe::compile_paths(&jail.filter) {
        for error in errors {
            problems.push(Problem {
                field: "filter".to_owned(),
                reason: error,
            });
        }
    }
    if let Err(errors) = crate::webprobe::compile_paths(&jail.ignore) {
        for error in errors {
            problems.push(Problem {
                field: "ignore".to_owned(),
                reason: error,
            });
        }
    }
    if jail.any_status && jail.filter.is_empty() && !jail.unknown_host {
        problems.push(Problem {
            field: "anyStatus".to_owned(),
            reason: "counting every status of every path needs path rules or unknownHost"
                .to_owned(),
        });
    }
}

fn tls_jail_problems(jail: &Jail, problems: &mut Vec<Problem>) {
    if jail.target.lines().count() > 1 {
        problems.push(Problem {
            field: "target".to_owned(),
            reason: "a TLS jail watches one listener (empty = all)".to_owned(),
        });
    }
    let lines = super::split_lines(&jail.filter);
    if lines.is_empty() {
        problems.push(Problem {
            field: "filter".to_owned(),
            reason: "select at least one failure kind".to_owned(),
        });
    }
    for (index, line) in lines.iter().enumerate() {
        if crate::webprobe::TlsFailKind::from_tag(line).is_none() {
            problems.push(Problem {
                field: format!("filter[{index}]"),
                reason: format!("unknown failure kind \"{line}\""),
            });
        }
    }
}

fn filter_problems(jail: &Jail, problems: &mut Vec<Problem>, host_required: bool) {
    let lines = super::split_lines(&jail.filter);
    if lines.len() > MAX_FILTER_LINES {
        problems.push(Problem {
            field: "filter".to_owned(),
            reason: format!("at most {MAX_FILTER_LINES} filter lines"),
        });
        return;
    }
    if host_required && lines.is_empty() {
        problems.push(Problem {
            field: "filter".to_owned(),
            reason: "log jails need at least one filter line containing <HOST>".to_owned(),
        });
        return;
    }
    for (index, line) in lines.iter().enumerate() {
        if line.len() > MAX_FILTER_LINE_BYTES {
            problems.push(Problem {
                field: format!("filter[{index}]"),
                reason: format!("filter lines are capped at {MAX_FILTER_LINE_BYTES} bytes"),
            });
            continue;
        }
        if host_required && !line.contains("<HOST>") {
            problems.push(Problem {
                field: format!("filter[{index}]"),
                reason: "every filter line must contain <HOST>".to_owned(),
            });
            continue;
        }
        if let Err(errors) = super::compile_line(line) {
            for error in errors {
                problems.push(Problem {
                    field: format!("filter[{index}]"),
                    reason: error,
                });
            }
        }
    }
}

/// Splits a multi-line field into trimmed, non-empty lines.
pub fn split_field(text: &str) -> Vec<String> {
    trim_lines(text)
}

fn trim_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn preset_name(preset: &str) -> Option<&'static str> {
    crate::presets::PRESETS
        .iter()
        .find(|candidate| candidate.id == preset)
        .map(|preset| preset.jail.name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jail::model::Jail;

    fn base(source: Source) -> Jail {
        Jail {
            key: "aabbccddeeff".to_owned(),
            name: "test".to_owned(),
            enable: true,
            source,
            ..Jail::default()
        }
    }

    #[test]
    fn jail_defaults_filled_for_zero() {
        let jail = normalize_jail(Jail {
            key: "aabbccddeeff".to_owned(),
            source: Source::File,
            target: " /var/log/auth.log \n".to_owned(),
            filter: " Failed password .* from <HOST> ".to_owned(),
            ..Jail::default()
        });
        assert_eq!(jail.target, "/var/log/auth.log");
        assert_eq!(jail.filter, "Failed password .* from <HOST>");
        assert_eq!(jail.name, "aabbccddeeff", "the name falls back to the key");
        assert_eq!(jail.retries(), DEFAULT_MAX_RETRY);
        assert_eq!(jail.window(), DEFAULT_FIND_TIME);
        assert_eq!(jail.ban_time, DEFAULT_BAN_TIME);
        assert!(jail_problems(&jail).is_empty());
    }

    #[test]
    fn jail_name_falls_back_to_preset_display_name() {
        let jail = normalize_jail(Jail {
            key: "aabbccddeeff".to_owned(),
            preset: "sshd".to_owned(),
            source: Source::File,
            ..Jail::default()
        });
        assert_eq!(jail.name, "SSH");
    }

    #[test]
    fn jail_ban_time_semantics() {
        // 0 keeps the module default, -1 is permanent.
        assert_eq!(ban_duration(0), (None, false));
        assert_eq!(ban_duration(-1), (None, true));
        // A positive value carries its own duration.
        let (duration, permanent) = ban_duration(7200);
        assert_eq!(duration, Some(std::time::Duration::from_secs(7200)));
        assert!(!permanent);
        // Beyond the ceiling normalization clamps to one year.
        let jail = normalize_jail(Jail {
            ban_time: MAX_BAN_TIME + 1,
            ..base(Source::Event)
        });
        assert_eq!(jail.ban_time, MAX_BAN_TIME);
        // Below -1 is a validation problem, never silently permanent.
        let jail = normalize_jail(Jail {
            ban_time: -2,
            ..base(Source::Event)
        });
        assert_eq!(
            jail_problems(&jail)
                .into_iter()
                .filter(|problem| problem.field == "banTime")
                .count(),
            1
        );
    }

    #[test]
    fn filter_requires_host_placeholder() {
        let mut jail = base(Source::File);
        jail.target = "/var/log/auth.log".to_owned();
        jail.filter = "Failed password for .*".to_owned();
        let problems = jail_problems(&jail);
        assert!(
            problems
                .iter()
                .any(|problem| problem.reason.contains("<HOST>")),
            "{problems:?}"
        );

        // Event sources may leave the filter empty; a non-empty one is
        // dead configuration and refused.
        let mut jail = base(Source::Event);
        jail.target = "auth.failed".to_owned();
        assert!(jail_problems(&jail).is_empty());
        let mut event = base(Source::Event);
        event.target = "auth.failed".to_owned();
        event.filter = "from <HOST>".to_owned();
        assert!(
            jail_problems(&event)
                .iter()
                .any(|problem| problem.field == "filter")
        );
    }

    #[test]
    fn filter_compile_errors_are_collected() {
        let mut jail = base(Source::File);
        jail.target = "/var/log/auth.log".to_owned();
        jail.filter = "from (unclosed <HOST>".to_owned();
        let problems = jail_problems(&jail);
        assert!(problems.iter().any(|problem| problem.field == "filter[0]"));
    }

    #[test]
    fn jail_validates_targets_per_source() {
        let mut jail = base(Source::File);
        jail.target = "var/log/relative.log".to_owned();
        jail.filter = "from <HOST>".to_owned();
        assert!(
            jail_problems(&jail)
                .iter()
                .any(|problem| problem.field == "target[0]")
        );

        let mut journal = base(Source::Journal);
        journal.target = "ssh service".to_owned();
        journal.filter = "from <HOST>".to_owned();
        assert!(
            jail_problems(&journal)
                .iter()
                .any(|problem| problem.field == "target[0]")
        );

        let mut docker = base(Source::Docker);
        docker.target = "vault warden".to_owned();
        docker.filter = "from <HOST>".to_owned();
        assert!(
            jail_problems(&docker)
                .iter()
                .any(|problem| problem.field == "target[0]")
        );

        let mut event = base(Source::Event);
        event.target = "not.an.event".to_owned();
        assert!(
            jail_problems(&event)
                .iter()
                .any(|problem| problem.field == "target")
        );

        let mut tls = base(Source::Tls);
        tls.filter = "eof\nbogus".to_owned();
        assert!(
            jail_problems(&tls)
                .iter()
                .any(|problem| problem.field == "filter[1]")
        );
        tls.filter = String::new();
        assert!(
            jail_problems(&tls)
                .iter()
                .any(|problem| problem.field == "filter")
        );
    }

    #[test]
    fn web_any_status_requires_path_or_unknown_host() {
        let mut jail = base(Source::Web);
        jail.any_status = true;
        let problems = jail_problems(&jail);
        assert!(
            problems.iter().any(|problem| problem.field == "anyStatus"),
            "{problems:?}"
        );
        jail.unknown_host = true;
        assert!(jail_problems(&jail).is_empty());
        jail.unknown_host = false;
        jail.filter = "*/.env".to_owned();
        assert!(jail_problems(&jail).is_empty());
    }
}
