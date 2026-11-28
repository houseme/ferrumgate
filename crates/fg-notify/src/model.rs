//! The `notify.json` model (WP-68 §3.2): module settings, channels and
//! rules. JSON field names follow the upstream (camelCase); Rust fields are
//! snake_case with `default` + `deny_unknown_fields` everywhere, so
//! hand-edited files that miss fields load with defaults instead of
//! failing, and unknown keys are reported instead of silently dropped.
//!
//! [`ChannelConfig`] carries every channel kind's fields in one struct;
//! which fields matter is decided by [`Channel::kind`], and
//! `validate::validate` enforces the per-kind required fields. Secret
//! fields (tokens, keys, SMTP passwords, webhook URLs) are listed in
//! [`Channel::secret_fields`] and masked by the management API.

use serde::{Deserialize, Serialize};

use crate::validate;

/// The module's configuration file (`notify.json`).
pub const FILE_NAME: &str = "notify";

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here).
pub mod limits {
    use std::time::Duration;

    /// Upstream default retry count; `settings.retries` unset means this.
    pub const RETRIES_DEFAULT: u32 = 3;
    /// Upstream maximum retry count; `0` disables retries entirely.
    pub const RETRIES_MAX: u32 = 10;
    /// Upstream retry timeline: the n-th retry waits this long (the last
    /// entry repeats for retries beyond the table).
    pub const RETRY_DELAYS: [Duration; 3] = [
        Duration::from_secs(10),
        Duration::from_secs(30),
        Duration::from_secs(60),
    ];
    /// Upstream default pending retention in hours; `settings.pendingHours`
    /// unset means this.
    pub const PENDING_HOURS_DEFAULT: u32 = 24;
    /// Upstream maximum pending retention; `0` disables the pending queue.
    pub const PENDING_HOURS_MAX: u32 = 168;
    /// Upstream: pending messages kept per channel; the oldest is dropped
    /// beyond this.
    pub const PENDING_CAP_PER_CHANNEL: usize = 100;
    /// Upstream: backfill failure wait starts at one minute.
    pub const PENDING_BACKOFF_INITIAL: Duration = Duration::from_secs(60);
    /// Upstream: backfill failure wait doubles up to this ceiling.
    pub const PENDING_BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);
    /// The pending queue file below the config directory (`notify/`).
    pub const PENDING_FILE_NAME: &str = "pending.json";
    /// FerrumGate protection: channels per config.
    pub const CHANNELS_MAX: usize = 100;
    /// FerrumGate protection: rules per config.
    pub const RULES_MAX: usize = 100;
    /// FerrumGate protection: bounded "recent deliveries" list.
    pub const DELIVERIES_MAX: usize = 200;
    /// FerrumGate protection: bounded dedup window keys.
    pub const DEDUP_MAX: usize = 1024;
    /// FerrumGate protection: events in flight per channel send.
    pub const SEND_CONCURRENCY_MAX: usize = 8;
    /// Upstream default per-request timeout for HTTP channel sends.
    pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);
    /// FerrumGate protection: the whole SMTP conversation (greeting
    /// through QUIT) is bounded even when the server stalls.
    pub const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
    /// FerrumGate protection: entry name length (channels and rules).
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: group name length (same cap as the collection
    /// group endpoint).
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: remark length.
    pub const REMARK_MAX_CHARS: usize = 512;
    /// FerrumGate protection: message template length.
    pub const TEMPLATE_MAX_CHARS: usize = 4000;
    /// FerrumGate protection: event patterns per rule.
    pub const EVENTS_MAX: usize = 32;
    /// FerrumGate protection: silence window in minutes (one week).
    pub const SILENCE_WINDOW_MAX: u32 = 7 * 24 * 60;
    /// FerrumGate protection: SMTP recipients per channel.
    pub const EMAIL_RECIPIENTS_MAX: usize = 20;
    /// The default message template when a rule leaves it empty.
    pub const DEFAULT_TEMPLATE: &str = "{title}\n{message}";
    /// Upstream default SMTP port per security mode: implicit TLS uses the
    /// SMTPS port, everything else uses submission.
    pub const SMTP_PORT_SSL_DEFAULT: u16 = 465;
    pub const SMTP_PORT_DEFAULT: u16 = 587;
    /// Upstream default Bark API server.
    pub const BARK_SERVER_DEFAULT: &str = "https://api.day.app";
    /// Upstream default ntfy server.
    pub const NTFY_SERVER_DEFAULT: &str = "https://ntfy.sh";
}

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

/// `notify.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FileConfig {
    pub settings: Settings,
    pub channels: Vec<Channel>,
    pub rules: Vec<Rule>,
}

/// Module settings (WP-68 §3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    /// Notification language tag; empty = follow the server language.
    pub language: String,
    /// Server name shown in notification titles (multi-instance setups).
    pub server_name: String,
    /// Retry count per message, 0 to [`limits::RETRIES_MAX`]; `None` =
    /// [`limits::RETRIES_DEFAULT`].
    pub retries: Option<u32>,
    /// Pending retention in hours, 0 to [`limits::PENDING_HOURS_MAX`];
    /// `None` = [`limits::PENDING_HOURS_DEFAULT`], `0` = no pending queue.
    pub pending_hours: Option<u32>,
    /// Global proxy for channel sends.
    pub proxy: SettingsProxy,
}

impl Settings {
    /// The effective retry count (`None` → default).
    pub fn effective_retries(&self) -> u32 {
        self.retries.unwrap_or(limits::RETRIES_DEFAULT)
    }

    /// The effective pending retention in hours (`None` → default).
    pub fn effective_pending_hours(&self) -> u32 {
        self.pending_hours.unwrap_or(limits::PENDING_HOURS_DEFAULT)
    }
}

/// The notification settings' proxy choice (WP-68 §3.3): no proxy (HTTP
/// channels still follow `HTTPS_PROXY`/`NO_PROXY`), the global update
/// proxy, or a custom proxy URL.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SettingsProxy {
    #[default]
    None,
    UpdateProxy,
    Custom(String),
}

/// Per-channel proxy choice: follow the notification settings, force a
/// direct connection (environment proxies ignored too), use the global
/// update proxy, or a custom proxy URL that overrides the global choice.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChannelProxy {
    #[default]
    Follow,
    Direct,
    UpdateProxy,
    Custom(String),
}

/// One notification channel (WP-68 §3.3 table).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Channel {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub kind: ChannelKind,
    pub config: ChannelConfig,
    pub proxy: ChannelProxy,
    pub remark: String,
}

impl Channel {
    /// The config fields that carry secrets for this channel kind, as they
    /// appear in the serialized JSON (camelCase).
    pub fn secret_fields(&self) -> &'static [&'static str] {
        match self.kind {
            ChannelKind::Webhook => &["url"],
            ChannelKind::Telegram => &["token"],
            ChannelKind::Bark => &["deviceKey"],
            ChannelKind::Ntfy => &["token", "password"],
            ChannelKind::Gotify => &["token"],
            ChannelKind::Pushover => &["token", "user"],
            ChannelKind::Discord | ChannelKind::Slack => &["url"],
            ChannelKind::ServerChan => &["sendKey"],
            ChannelKind::PushPlus => &["token"],
            ChannelKind::WeCom => &["key"],
            ChannelKind::DingTalk => &["accessToken", "secret"],
            ChannelKind::Feishu => &["url", "secret"],
            ChannelKind::Email => &["password"],
        }
    }

    /// The channel's config as JSON with every secret field replaced by the
    /// `********` mask (fg-admin contract: masked output, merged input).
    pub fn masked_value(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).expect("channel serializes");
        if let Some(config) = value
            .get_mut("config")
            .and_then(serde_json::Value::as_object_mut)
        {
            for field in self.secret_fields() {
                config.insert(
                    (*field).to_owned(),
                    serde_json::Value::from(validate::SECRET_MASK),
                );
            }
        }
        value
    }
}

/// The 14 channel kinds (WP-68 §3.4), serialized as the lowercase names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelKind {
    #[default]
    #[serde(rename = "webhook")]
    Webhook,
    #[serde(rename = "telegram")]
    Telegram,
    #[serde(rename = "bark")]
    Bark,
    #[serde(rename = "ntfy")]
    Ntfy,
    #[serde(rename = "gotify")]
    Gotify,
    #[serde(rename = "pushover")]
    Pushover,
    #[serde(rename = "discord")]
    Discord,
    #[serde(rename = "slack")]
    Slack,
    #[serde(rename = "serverchan")]
    ServerChan,
    #[serde(rename = "pushplus")]
    PushPlus,
    #[serde(rename = "wecom")]
    WeCom,
    #[serde(rename = "dingtalk")]
    DingTalk,
    #[serde(rename = "feishu")]
    Feishu,
    #[serde(rename = "email")]
    Email,
}

impl ChannelKind {
    /// Every kind in registration order (the event-types endpoint and
    /// validation listing).
    pub const ALL: [ChannelKind; 14] = [
        ChannelKind::Webhook,
        ChannelKind::Telegram,
        ChannelKind::Bark,
        ChannelKind::Ntfy,
        ChannelKind::Gotify,
        ChannelKind::Pushover,
        ChannelKind::Discord,
        ChannelKind::Slack,
        ChannelKind::ServerChan,
        ChannelKind::PushPlus,
        ChannelKind::WeCom,
        ChannelKind::DingTalk,
        ChannelKind::Feishu,
        ChannelKind::Email,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Webhook => "webhook",
            ChannelKind::Telegram => "telegram",
            ChannelKind::Bark => "bark",
            ChannelKind::Ntfy => "ntfy",
            ChannelKind::Gotify => "gotify",
            ChannelKind::Pushover => "pushover",
            ChannelKind::Discord => "discord",
            ChannelKind::Slack => "slack",
            ChannelKind::ServerChan => "serverchan",
            ChannelKind::PushPlus => "pushplus",
            ChannelKind::WeCom => "wecom",
            ChannelKind::DingTalk => "dingtalk",
            ChannelKind::Feishu => "feishu",
            ChannelKind::Email => "email",
        }
    }

    /// Case-insensitive parse; unknown names are rejected.
    pub fn parse(text: &str) -> Option<Self> {
        ChannelKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str().eq_ignore_ascii_case(text.trim()))
    }

    /// Whether channel sends of this kind go through the HTTP proxy stack
    /// (everything except e-mail, which dials through its own tunnel).
    pub fn is_http(self) -> bool {
        !matches!(self, ChannelKind::Email)
    }
}

/// Per-kind channel configuration. Fields not used by the channel's kind
/// stay at their defaults; `validate` enforces the required ones.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ChannelConfig {
    // Webhook / Discord / Slack / Feishu (webhook URL).
    /// Webhook endpoint; secret for webhook, Discord, Slack and Feishu.
    pub url: String,
    /// Webhook HTTP method (default POST).
    pub method: String,
    /// Raw `Key: Value` header lines (webhook).
    pub headers: Vec<String>,
    /// Webhook request body template (`{var}` placeholders; empty = the
    /// default JSON envelope).
    pub body: String,
    /// Skip TLS certificate verification (webhook, email).
    pub insecure_skip_verify: bool,
    // Telegram / Gotify / Pushover / PushPlus / ntfy.
    /// Bot / application / access token.
    pub token: String,
    /// Telegram chat id.
    pub chat_id: String,
    // Bark.
    /// Bark device key.
    pub device_key: String,
    /// Custom Bark server (empty = the default API).
    pub server: String,
    // ntfy.
    /// Topic to publish to.
    pub topic: String,
    /// ntfy access token (alternative to username/password).
    pub username: String,
    /// Basic-auth password (ntfy) / SMTP password.
    pub password: String,
    // Pushover.
    /// Pushover user key.
    pub user: String,
    // Gotify / Pushover / ntfy share `server`; Bark/ntfy defaults live in
    // normalize.
    // ServerChan / WeCom.
    /// ServerChan SendKey.
    pub send_key: String,
    /// WeCom robot key.
    pub key: String,
    // DingTalk.
    /// DingTalk robot access token.
    pub access_token: String,
    // DingTalk / Feishu signing secret.
    pub secret: String,
    // Email (SMTP).
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    /// SMTP user (empty = no authentication).
    pub smtp_user: String,
    /// Sender address.
    pub from: String,
    /// Recipient addresses.
    pub to: Vec<String>,
}

/// SMTP transport security (WP-68 §3.3 e-mail row).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtpSecurity {
    /// Plain SMTP; STARTTLS is attempted when the server advertises it.
    #[default]
    #[serde(rename = "none")]
    None,
    /// STARTTLS is required (fail when unsupported).
    #[serde(rename = "starttls")]
    StartTls,
    /// Implicit TLS from the first byte.
    #[serde(rename = "ssl")]
    Ssl,
}

impl SmtpSecurity {
    pub fn as_str(self) -> &'static str {
        match self {
            SmtpSecurity::None => "none",
            SmtpSecurity::StartTls => "starttls",
            SmtpSecurity::Ssl => "ssl",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "none" | "" => Some(SmtpSecurity::None),
            "starttls" => Some(SmtpSecurity::StartTls),
            "ssl" => Some(SmtpSecurity::Ssl),
            _ => None,
        }
    }

    /// The port used when the configured port is 0.
    pub fn default_port(self) -> u16 {
        match self {
            SmtpSecurity::Ssl => limits::SMTP_PORT_SSL_DEFAULT,
            _ => limits::SMTP_PORT_DEFAULT,
        }
    }
}

/// One notification rule (WP-68 §3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Rule {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    /// Event type patterns with `*` wildcards (`ddns.*`, `*`).
    pub events: Vec<String>,
    /// The rule fires for events at this level or above.
    #[serde(with = "level_json")]
    pub min_level: fg_core::events::Level,
    /// Channel keys the matching events are pushed to.
    pub channels: Vec<String>,
    /// Optional dedup window (silence).
    pub silence: Option<Silence>,
    /// Message template (`{var}` placeholders; empty = the default).
    pub template: String,
    pub remark: String,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            key: String::new(),
            name: String::new(),
            group: String::new(),
            enable: false,
            events: Vec::new(),
            min_level: fg_core::events::Level::Info,
            channels: Vec::new(),
            silence: None,
            template: String::new(),
            remark: String::new(),
        }
    }
}

/// Silence settings: events whose rendered dedup key repeats inside the
/// window are dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Silence {
    /// Dedup key template over the event variables (e.g.
    /// `auth.failed:{sourceAddr}`); empty = the event kind.
    pub dedup_key: String,
    /// Window length in minutes (1 to [`limits::SILENCE_WINDOW_MAX`]).
    pub window_minutes: u32,
}

/// JSON (de)serialization for the fg-core event [`fg_core::events::Level`]
/// as the lowercase labels `info` / `warn` / `error`.
pub mod level_json {
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// The lowercase level label used in JSON and the API output.
    pub fn label(level: fg_core::events::Level) -> &'static str {
        match level {
            fg_core::events::Level::Info => "info",
            fg_core::events::Level::Warn => "warn",
            fg_core::events::Level::Error => "error",
        }
    }

    pub fn parse(text: &str) -> Option<fg_core::events::Level> {
        match text.trim().to_ascii_lowercase().as_str() {
            "info" => Some(fg_core::events::Level::Info),
            "warn" | "warning" => Some(fg_core::events::Level::Warn),
            "error" => Some(fg_core::events::Level::Error),
            _ => None,
        }
    }

    pub fn serialize<S: Serializer>(
        level: &fg_core::events::Level,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(label(*level))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<fg_core::events::Level, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse(&text).ok_or_else(|| de::Error::custom(format!("未知事件级别 {text:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_core::events::Level;

    #[test]
    fn file_config_defaults_and_camel_case_roundtrip() {
        let file: FileConfig = serde_json::from_str(
            r#"{
                "settings": {"serverName": "home"},
                "channels": [{
                    "name": "tg",
                    "kind": "telegram",
                    "config": {"token": "t", "chatId": "1"}
                }],
                "rules": [{
                    "name": "all",
                    "events": ["*"],
                    "minLevel": "warn",
                    "channels": ["abc"],
                    "silence": {"dedupKey": "", "windowMinutes": 5}
                }]
            }"#,
        )
        .expect("parse");
        assert_eq!(file.settings.server_name, "home");
        assert_eq!(file.channels[0].kind, ChannelKind::Telegram);
        assert_eq!(file.channels[0].config.chat_id, "1");
        assert_eq!(file.rules[0].min_level, Level::Warn);
        assert_eq!(
            file.rules[0]
                .silence
                .as_ref()
                .expect("silence")
                .window_minutes,
            5
        );
        let text = serde_json::to_string(&file).expect("serialize");
        assert!(text.contains("\"serverName\""), "{text}");
        assert!(text.contains("\"chatId\""), "{text}");
        assert!(text.contains("\"minLevel\":\"warn\""), "{text}");
        assert!(text.contains("\"windowMinutes\""), "{text}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let error = serde_json::from_str::<FileConfig>(r#"{"channels": [], "nope": 1}"#)
            .expect_err("unknown field");
        assert!(error.to_string().contains("nope"), "{error}");
        assert!(serde_json::from_str::<ChannelKind>(r#""pigeon""#).is_err());
    }

    #[test]
    fn settings_defaults_are_effective_values() {
        let settings = Settings::default();
        assert_eq!(settings.effective_retries(), limits::RETRIES_DEFAULT);
        assert_eq!(
            settings.effective_pending_hours(),
            limits::PENDING_HOURS_DEFAULT
        );
        let settings = Settings {
            retries: Some(0),
            pending_hours: Some(0),
            ..Settings::default()
        };
        assert_eq!(settings.effective_retries(), 0);
        assert_eq!(settings.effective_pending_hours(), 0);
    }

    #[test]
    fn channel_kind_parse_and_proxy_shapes() {
        for kind in ChannelKind::ALL {
            assert_eq!(ChannelKind::parse(kind.as_str()), Some(kind));
            assert_eq!(
                serde_json::to_string(&kind).expect("serialize"),
                format!("\"{}\"", kind.as_str())
            );
        }
        assert_eq!(ChannelKind::parse("Telegram"), Some(ChannelKind::Telegram));
        assert_eq!(ChannelKind::parse("nope"), None);
        assert_eq!(
            SmtpSecurity::parse("STARTTLS"),
            Some(SmtpSecurity::StartTls)
        );
        assert_eq!(SmtpSecurity::None.default_port(), limits::SMTP_PORT_DEFAULT);
        assert_eq!(
            SmtpSecurity::Ssl.default_port(),
            limits::SMTP_PORT_SSL_DEFAULT
        );
        let proxy: SettingsProxy =
            serde_json::from_str(r#"{"custom": "http://gate:8080"}"#).expect("parse");
        assert_eq!(proxy, SettingsProxy::Custom("http://gate:8080".into()));
        assert_eq!(
            serde_json::to_string(&ChannelProxy::Follow).expect("serialize"),
            "\"follow\""
        );
    }

    #[test]
    fn masked_value_covers_secret_fields_per_kind() {
        let mut channel = Channel {
            kind: ChannelKind::DingTalk,
            config: ChannelConfig {
                access_token: "tok".into(),
                secret: "sec".into(),
                ..ChannelConfig::default()
            },
            ..Channel::default()
        };
        let masked = channel.masked_value();
        assert_eq!(masked["config"]["accessToken"], validate::SECRET_MASK);
        assert_eq!(masked["config"]["secret"], validate::SECRET_MASK);
        channel.kind = ChannelKind::Email;
        let masked = channel.masked_value();
        assert_eq!(masked["config"]["password"], validate::SECRET_MASK);
        assert_eq!(masked["config"]["host"], "");
    }

    #[test]
    fn new_key_is_twelve_lowercase_hex_characters() {
        let key = new_key();
        assert_eq!(key.len(), 12);
        assert!(
            key.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }
}
