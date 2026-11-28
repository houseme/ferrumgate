//! The jail rule model (WP-52 §3.2): one `jails[]` entry of `guard.json`
//! describes a single "count matches within a window → ban" rule. JSON
//! field names follow upstream (camelCase).

use serde::{Deserialize, Serialize};

/// Where a jail takes its matches from (WP-52 §3.3 source table).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Log file(s); `target` lists one path per line.
    #[default]
    File,
    /// systemd journal; `target` lists service units.
    Journal,
    /// A command's standard output; `target` is one shell command.
    Command,
    /// Docker container logs via the docker module (`Deps.docker_follow`).
    Docker,
    /// Gately events (WP-16 event bus); `target` is one event type name.
    Event,
    /// Web path probe; `target` is a listener (empty = all), `filter` the
    /// path rules, `ignore` the excluded paths.
    Web,
    /// TLS handshake failures; `target` is a listener (empty = all),
    /// `filter` the selected failure kinds, one per line.
    Tls,
}

impl Source {
    /// The stable tag used on the wire and in error messages.
    pub fn tag(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Journal => "journal",
            Self::Command => "command",
            Self::Docker => "docker",
            Self::Event => "event",
            Self::Web => "web",
            Self::Tls => "tls",
        }
    }

    /// The sources that read lines and match them against `filter`.
    pub fn is_log(self) -> bool {
        matches!(
            self,
            Self::File | Self::Journal | Self::Command | Self::Docker
        )
    }
}

/// The event kinds that may serve as an `event` jail target; each must
/// carry the offending source IP (`fields["ip"]` or `args["ip"]` /
/// `args["addr"]`). WP-52 §3.3: UDP knock rejections are counted and
/// logged by WP-54 but never published, so they cannot serve here.
pub const EVENT_TARGETS: [&str; 4] = [
    "auth.failed",
    "waf.blocked",
    "knock.failed",
    "fileauth.failed",
];

/// One detection rule of the intrusion protection module. Defaults are
/// applied by [`crate::jail::validate::normalize`]; a hand-written config
/// never runs with zero values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Jail {
    /// The collection key (12 hex characters, generated on create/copy).
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub source: Source,
    /// The source parameter: file paths (one per line), service units,
    /// a shell command, a container name or an event type.
    pub target: String,
    /// The failure-record regexes, one per line, `<HOST>` marking the
    /// source address. Event sources may leave it empty; `web` jails use
    /// it for path rules (`~` prefix = regex, otherwise glob) and `tls`
    /// jails list failure kinds.
    pub filter: String,
    /// Excluded lines / paths, one per line; matches never count.
    pub ignore: String,
    /// Matches within `findTime` that trigger a ban; 0 → 5.
    pub max_retry: u32,
    /// The counting window in seconds; 0 → 600.
    pub find_time: u32,
    /// Ban duration: 0 = module default, -1 = permanent, > 0 = seconds
    /// (capped at one year by normalization).
    pub ban_time: i64,
    /// Web probe only: every status code counts, not just 404/444.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub any_status: bool,
    /// Web probe only: only count requests for a host that matched no
    /// site (unknown-domain scanning).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unknown_host: bool,
    /// The preset id the rule was created from; display only.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub preset: String,
    pub remark: String,
}

impl Jail {
    /// The effective threshold (`maxRetry` with the upstream default).
    pub fn retries(&self) -> u32 {
        if self.max_retry == 0 {
            crate::jail::validate::DEFAULT_MAX_RETRY
        } else {
            self.max_retry
        }
    }

    /// The effective window in seconds (`findTime` with the default).
    pub fn window(&self) -> u32 {
        if self.find_time == 0 {
            crate::jail::validate::DEFAULT_FIND_TIME
        } else {
            self.find_time
        }
    }
}

/// FerrumGate protection: filter/ignore lines per jail (upstream relies on
/// the 4 MiB request body; a per-rule cap keeps a runaway regex set from
/// dominating the hot path, WP-52 §8).
pub const MAX_FILTER_LINES: usize = 128;
/// FerrumGate protection: bytes per filter/ignore line.
pub const MAX_FILTER_LINE_BYTES: usize = 2048;
/// Upstream `maxTracked`: sources tracked per rule; the least recently
/// active one is evicted beyond it.
pub const MAX_TRACKED: usize = 50000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jail_source_tags_are_stable() {
        assert_eq!(Source::default(), Source::File);
        assert_eq!(Source::File.tag(), "file");
        assert_eq!(Source::Tls.tag(), "tls");
        assert!(Source::Journal.is_log());
        assert!(!Source::Event.is_log());
        assert!(!Source::Web.is_log());
    }

    #[test]
    fn jail_serde_uses_camel_case_and_rejects_unknown() {
        let jail: Jail = serde_json::from_str(
            r#"{"key":"aabbccddeeff","name":"SSH","group":"","enable":true,
                "source":"journal","target":"ssh.service","filter":"from <HOST>",
                "ignore":"","maxRetry":3,"findTime":120,"banTime":-1,"remark":"r"}"#,
        )
        .expect("parse");
        assert_eq!(jail.source, Source::Journal);
        assert_eq!(jail.max_retry, 3);
        assert_eq!(jail.ban_time, -1);
        assert!(!jail.any_status && !jail.unknown_host);
        assert!(serde_json::from_str::<Jail>(r#"{"bogus":1}"#).is_err());
    }

    #[test]
    fn jail_effective_retries_and_window_fill_zero() {
        let jail = Jail::default();
        assert_eq!(jail.retries(), 5);
        assert_eq!(jail.window(), 600);
        let jail = Jail {
            max_retry: 7,
            find_time: 30,
            ..Jail::default()
        };
        assert_eq!(jail.retries(), 7);
        assert_eq!(jail.window(), 30);
    }

    #[test]
    fn jail_event_targets_match_event_bus_kinds() {
        // Every documented event target must exist on the WP-16 bus so a
        // jail never waits for a kind that can never be published.
        let names: Vec<&str> = fg_core::events::KINDS
            .iter()
            .map(|info| info.name)
            .collect();
        for target in EVENT_TARGETS {
            assert!(names.contains(&target), "{target} is not a known kind");
        }
    }
}
