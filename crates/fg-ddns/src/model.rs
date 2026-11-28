//! The `ddns.json` model (WP-40 §3.2): module settings, tasks and their
//! records. JSON field names follow the upstream (camelCase); Rust fields
//! are snake_case with `default` + `deny_unknown_fields` everywhere, so
//! hand-edited files that miss fields load with defaults instead of
//! failing, and unknown keys are reported instead of silently dropped.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, de, ser};

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here).
pub mod limits {
    use std::time::Duration;

    /// Upstream `defaultInterval`: check period in seconds when unset.
    pub const INTERVAL_DEFAULT: u32 = 300;
    /// Upstream `minInterval`: floor for the check period, protecting the
    /// provider API. Never remove this to go "faster".
    pub const INTERVAL_MIN: u32 = 30;
    /// Upstream default for the forced sync period; `0` means "sync only
    /// when the address changed".
    pub const FORCE_INTERVAL_DEFAULT: u32 = 3600;
    /// Upstream `defaultTimeout`: per-request timeout in seconds when unset.
    pub const HTTP_TIMEOUT_DEFAULT: u32 = 20;
    /// FerrumGate protection: ceiling for the task HTTP timeout.
    pub const HTTP_TIMEOUT_MAX: u32 = 600;
    /// Upstream `startupDelay`: first round is delayed so startup network
    /// initialization is not hit.
    pub const STARTUP_DELAY: Duration = Duration::from_secs(10);
    /// URL IP queries: connect timeout before the total timeout applies.
    pub const IP_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
    /// FerrumGate protection: cap on how long a `command` source may run
    /// regardless of the task timeout.
    pub const COMMAND_TIMEOUT_MAX: Duration = Duration::from_secs(60);
    /// FerrumGate protection: cap on `command` output that is read.
    pub const COMMAND_OUTPUT_MAX_BYTES: usize = 64 * 1024;
    /// Webhook: timeout in seconds when unset.
    pub const WEBHOOK_TIMEOUT_DEFAULT: u32 = 10;
    /// FerrumGate protection: ceiling for the webhook timeout.
    pub const WEBHOOK_TIMEOUT_MAX: u32 = 60;
    /// Upstream: remark written to the provider, in characters.
    pub const REMARK_MAX_CHARS: usize = 100;
    /// Upstream: Aliyun remark cap (and its restricted charset).
    pub const REMARK_ALIDNS_MAX_CHARS: usize = 50;
    /// Upstream: proxied Cloudflare records are pinned to TTL 1 (auto).
    pub const TTL_CLOUDFLARE_PROXIED: u32 = 1;
    /// Callback template variable `{ttl}` falls back to this when 0.
    pub const TTL_CALLBACK_DEFAULT: u32 = 600;
    /// Failure backoff sequence: the n-th consecutive failure waits this
    /// long before the next attempt (last entry repeats); a success resets
    /// the counter. A rate limited provider error with `Retry-After` uses
    /// the larger of the two.
    pub const FAILURE_BACKOFF: [Duration; 4] = [
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(300),
        Duration::from_secs(900),
    ];
    /// Grace period for in-flight rounds when the module drains.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
    /// FerrumGate protection: records per task (upstream has no explicit
    /// cap; the 4 MiB request body bound is the only upstream limit).
    pub const RECORDS_MAX: usize = 1000;
    /// FerrumGate protection: batch-add line count per request.
    pub const BATCH_LINES_MAX: usize = 1000;
    /// FerrumGate protection: task name length.
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: group name length (same cap as the collection
    /// group endpoint).
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: task remark length.
    pub const REMARK_FIELD_MAX_CHARS: usize = 512;
    /// FerrumGate protection: URLs per URL source.
    pub const URLS_MAX: usize = 16;
    /// FerrumGate protection: webhook header lines.
    pub const WEBHOOK_HEADERS_MAX: usize = 32;
}

/// The module's configuration file (`ddns.json`).
pub const FILE_NAME: &str = "ddns";

/// A fresh item key: 12 lowercase hex characters from 6 random bytes —
/// the same shape the fg-admin collections generate. Callers retry on the
/// (practically unreachable) collision with an existing key.
pub fn new_key() -> String {
    let mut bytes = [0u8; 6];
    if getrandom::fill(&mut bytes).is_err() {
        // OS random source unavailable: fall back to a time-flavored value.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |duration| duration.as_nanos() as u64 | 1);
        bytes.copy_from_slice(nanos.to_le_bytes()[..6].try_into().expect("6 bytes"));
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `ddns.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FileConfig {
    pub settings: Settings,
    pub tasks: Vec<Task>,
}

/// Module settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    /// Module switch; disabled tasks are never checked nor synced.
    pub enable: bool,
    /// Default state of the "also delete the provider record" checkbox in
    /// the management UI (upstream default: unchecked).
    pub delete_remote: bool,
}

/// One DDNS task: two IP sources (IPv4/IPv6), a provider and the records
/// to keep in sync.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Task {
    pub key: String,
    pub name: String,
    pub enable: bool,
    pub group: String,
    /// IPv4 acquisition source.
    pub ipv4: IpSource,
    /// IPv6 acquisition source.
    pub ipv6: IpSource,
    /// Provider adapter name (`fg_dns::Meta::name`).
    pub provider: String,
    pub credentials: Credentials,
    pub records: Vec<Record>,
    /// Check period in seconds; 0 normalizes to 300, floor 30.
    pub interval: u32,
    /// Forced sync period in seconds; 0 normalizes to 3600. At runtime a
    /// zero value means "only sync when the address changed".
    pub force_interval: u32,
    /// Outbound request timeout in seconds; 0 normalizes to 20.
    pub http_timeout: u32,
    pub webhook: WebhookConfig,
    pub remark: String,
}

impl Task {
    /// The normalized check period as a [`std::time::Duration`].
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.interval.max(limits::INTERVAL_MIN)))
    }
}

/// Provider credentials. `id`/`secret` meaning per provider comes from the
/// provider [`fg_dns::Meta`] labels; everything else (access point, region
/// id, Cloudflare proxy state) lives in `extra`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Credentials {
    pub id: String,
    pub secret: String,
    pub extra: BTreeMap<String, String>,
}

/// One of the two IP acquisition sources of a task.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct IpSource {
    pub enable: bool,
    pub kind: IpSourceKind,
    /// Query services tried in order (`kind: url`).
    pub urls: Vec<String>,
    /// Network interface name (`kind: netInterface`).
    pub interface: String,
    /// Optional filter over the candidate addresses; when set it decides
    /// alone (a private address may be chosen on purpose).
    pub regex: String,
    /// Shell command whose stdout is scanned for an address
    /// (`kind: command`).
    pub command: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IpSourceKind {
    #[default]
    Url,
    NetInterface,
    Command,
}

/// One DNS record a task keeps in sync.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Record {
    pub key: String,
    pub enable: bool,
    /// Zone hosted at the provider, e.g. `example.com` (no trailing dot).
    pub zone: String,
    /// Owner name; the zone apex is `@`. Stored and sent lowercased.
    pub sub: String,
    pub typ: RecordType,
    /// Target value; supports `{ipv4Addr}`, `{ipv6Addr}` and
    /// `{STUN_规则名_PORT|IP|ADDR}` variables. Empty on A/AAAA defaults to
    /// the matching task address.
    pub value: String,
    /// 0 = provider default.
    pub ttl: u32,
    /// Resolver line, only meaningful for a few Chinese providers.
    pub line: String,
    /// Written to the provider on sync (when it supports remarks).
    pub remark: String,
    pub group: String,
}

/// Record types (WP-41). Serialized as the upper-case well-known strings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecordType {
    #[default]
    A,
    AAAA,
    CNAME,
    TXT,
    NS,
    MX,
    SRV,
    CAA,
}

impl RecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::MX => "MX",
            RecordType::SRV => "SRV",
            RecordType::CAA => "CAA",
        }
    }

    /// Case-insensitive parse; unknown names are rejected.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "CNAME" => Some(RecordType::CNAME),
            "TXT" => Some(RecordType::TXT),
            "NS" => Some(RecordType::NS),
            "MX" => Some(RecordType::MX),
            "SRV" => Some(RecordType::SRV),
            "CAA" => Some(RecordType::CAA),
            _ => None,
        }
    }
}

impl Serialize for RecordType {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RecordType {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        RecordType::parse(&text).ok_or_else(|| de::Error::custom(format!("未知记录类型 {text:?}")))
    }
}

/// Task webhook (`webhook` object): fired when the address changed or a
/// round failed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct WebhookConfig {
    pub enable: bool,
    pub url: String,
    /// GET | POST | PUT | PATCH | DELETE.
    pub method: String,
    /// Raw `Key: Value` header lines.
    pub headers: Vec<String>,
    /// Request body; `{…}` variables are substituted.
    pub body: String,
    /// The request counts as successful when the response body contains any
    /// one of these; empty list means 2xx is enough.
    pub success_content: Vec<String>,
    /// Timeout in seconds; 0 normalizes to 10.
    pub timeout: u32,
    /// Skip TLS certificate verification.
    pub insecure_skip_verify: bool,
    /// Proxy URL for this webhook (empty = direct).
    pub proxy: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_defaults_and_min_interval() {
        let file: FileConfig = serde_json::from_str(
            r#"{
                "settings": {"enable": true},
                "tasks": [{
                    "name": "home",
                    "provider": "cloudflare",
                    "records": [{"zone": "example.com", "sub": "Home"}]
                }]
            }"#,
        )
        .expect("parse");
        let task = &file.tasks[0];
        // All numeric defaults come from normalize; the raw parse keeps
        // zeros, unknown fields are rejected.
        assert_eq!(task.interval, 0);
        assert_eq!(task.force_interval, 0);
        assert_eq!(task.http_timeout, 0);
        assert_eq!(task.records[0].sub, "Home");
        assert_eq!(task.records[0].typ, RecordType::A);
        let (status, body) = serde_json::to_value(&file).map_or_else(
            |error| (false, error.to_string()),
            |value| (true, value.to_string()),
        );
        assert!(status, "{body}");
        assert!(body.contains("\"deleteRemote\""), "{body}");
        assert!(body.contains("\"ipv4\""), "{body}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let error = serde_json::from_str::<FileConfig>(r#"{"tasks": [], "nope": 1}"#)
            .expect_err("unknown field");
        assert!(error.to_string().contains("nope"), "{error}");
    }

    #[test]
    fn record_type_roundtrip_and_rejects_unknown() {
        for typ in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::TXT,
            RecordType::NS,
            RecordType::MX,
            RecordType::SRV,
            RecordType::CAA,
        ] {
            let text = serde_json::to_string(&typ).expect("serialize");
            let back: RecordType = serde_json::from_str(&text).expect("parse");
            assert_eq!(back, typ);
        }
        assert!(serde_json::from_str::<RecordType>(r#""PTR""#).is_err());
    }
}
