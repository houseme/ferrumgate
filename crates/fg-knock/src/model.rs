//! The knock.json model (WP-54 §3.2/§3.4): settings and the rule
//! collection (identities are saved as part of their rule). JSON field
//! names follow the upstream file (camelCase); Rust fields are snake_case
//! with `deny_unknown_fields` everywhere, and every ceiling or default
//! used by the module lives in [`limits`].

use serde::{Deserialize, Serialize};

pub use crate::spa::HmacType;

/// The module's configuration file (`knock.json`).
pub const CONFIG_NAME: &str = "knock";

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here). Values follow WP-54 §3.4 unless noted.
pub mod limits {
    use std::time::Duration;

    /// UDP knock port; 0 disables the UDP listener (TCP knocks arrive via
    /// protocol routing `submit` only).
    pub const UDP_PORT_DEFAULT: u16 = 62201;
    /// Message validity window `maxAge`, seconds (default / ceiling).
    pub const MAX_AGE_DEFAULT: u32 = 120;
    pub const MAX_AGE_MAX: u32 = 3600;
    /// Grant duration seconds: rule default, client ceiling default, and
    /// the hard ceiling for both `timeout` and `maxTimeout`.
    pub const TIMEOUT_DEFAULT: u32 = 30;
    pub const MAX_TIMEOUT_DEFAULT: u32 = 300;
    pub const DURATION_MAX: u32 = 86_400;
    /// Ports protected by one rule / requested by one packet.
    pub const RULE_PORTS_MAX: usize = 16;
    /// Identities per rule; total credentials across all enabled rules.
    pub const IDENTITIES_MAX: usize = 64;
    pub const TOTAL_KEYS_MAX: usize = 1024;
    /// Key material lengths: encryption 16–32 bytes, HMAC 16–128 bytes;
    /// generated keys use 32 / 64 bytes (same as `fwknop -k`).
    pub const ENC_KEY_MIN: usize = 16;
    pub const ENC_KEY_MAX: usize = 32;
    pub const HMAC_KEY_MIN: usize = 16;
    pub const HMAC_KEY_MAX: usize = 128;
    pub const GENERATED_ENC_KEY_BYTES: usize = 32;
    pub const GENERATED_HMAC_KEY_BYTES: usize = 64;
    /// Username length carried by a packet or pinned on a rule.
    pub const USERNAME_MAX_CHARS: usize = 64;
    /// `allowList` entries (knock-exempt networks).
    pub const ALLOW_LIST_MAX: usize = 64;
    /// Knock-exempt networks by default (`allowLan`): private, loopback,
    /// link-local — but not the CGNAT range 100.64.0.0/10.
    pub const ALLOW_LAN_DEFAULT: bool = true;
    /// Per-source knock rate: 10 packets per second per IPv4 /24 (IPv6
    /// /64), applied before any HMAC work (upstream, docs).
    pub const SOURCE_WINDOW_V4_PREFIX: u8 = 24;
    pub const SOURCE_WINDOW_V6_PREFIX: u8 = 64;
    pub const SOURCE_RATE_PER_SEC: u64 = 10;
    /// Global HMAC budget: packets consume `keys × ⌈len / 512⌉` units from
    /// a 20000 units/second bucket (upstream, docs).
    pub const GLOBAL_BUDGET_PER_SEC: u64 = 20_000;
    pub const BUDGET_UNIT_BYTES: usize = 512;
    /// Bound for the per-source limiter table (FerrumGate protection;
    /// full-token sources are evicted idlest-first).
    pub const RATE_SOURCES_MAX: usize = 65_536;
    /// In-memory replay cache bound (FerrumGate protection; the cache is
    /// cleared wholesale when full — knocks remain valid while unexpired).
    pub const REPLAY_CACHE_MAX: usize = 65_536;
    /// Invalid-authentication log summary cadence.
    pub const FAILED_SUMMARY_INTERVAL: Duration = Duration::from_secs(60);
    /// `knock.failed` event throttle per source; UDP never publishes.
    pub const FAILED_EVENT_THROTTLE: Duration = Duration::from_secs(5);
    /// Throttle table bound (oldest entries evicted first).
    pub const FAILED_THROTTLE_MAX: usize = 4096;
    /// Simultaneous grants kept in memory; over the limit expired grants
    /// are pruned first and new grants are then refused.
    pub const GRANTS_LIMIT: usize = 4096;
    /// Web-login grant ceilings (owned by the fg-core `knockgate`
    /// registry / WP-26; kept here so validation and the UI agree).
    pub const WEB_GRANTS_PER_USER_PER_RULE: usize = 16;
    pub const WEB_GRANT_ADDRS_MAX: usize = 8;
    /// Grace period for in-flight packet handling and close timers when
    /// the module drains.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
    /// Text caps for rule metadata (conventions §4, same as the other
    /// module collections).
    pub const NAME_MAX_CHARS: usize = 128;
    pub const GROUP_MAX_CHARS: usize = 64;
    pub const REMARK_MAX_CHARS: usize = 512;
}

/// knock.json: the settings block plus the rule collection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
    pub rules: Vec<Rule>,
}

/// Module settings (`settings` block of knock.json).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Settings {
    /// UDP knock port; `0` disables the UDP listener.
    pub port: u16,
    /// Sync firewall blocks for rules with `firewall` enabled (WP-51).
    pub auto_firewall: bool,
    /// Private / link-local / local-network addresses are knock-exempt
    /// (CGNAT 100.64.0.0/10 is not included).
    pub allow_lan: bool,
    /// Additional knock-exempt networks (IP or CIDR strings).
    pub allow_list: Vec<String>,
    /// Message validity window in seconds.
    pub max_age: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: limits::UDP_PORT_DEFAULT,
            auto_firewall: true,
            allow_lan: limits::ALLOW_LAN_DEFAULT,
            allow_list: Vec::new(),
            max_age: limits::MAX_AGE_DEFAULT,
        }
    }
}

/// One knock rule: the protected ports and the credentials accepted for
/// them. The shared key can be turned off so only identities authenticate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Rule {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    /// Ports a packet may request; every requested port must be listed.
    pub ports: Vec<Access>,
    /// Block these ports in the system firewall and admit knockers only
    /// (WP-51 syncs the grant into `inet gately_knock`).
    pub firewall: bool,
    /// Shared key material, base64 (16–32 / 16–128 decoded bytes).
    pub enc_key: String,
    pub hmac_key: String,
    pub hmac_type: HmacType,
    /// Grant duration seconds.
    pub timeout: u32,
    /// Ceiling for client-requested durations; `0` ignores the request.
    pub max_timeout: u32,
    /// When set, packets must carry this username.
    pub user: String,
    /// Reject `-s` packets that leave the address to the server.
    pub require_addr: bool,
    /// Per-identity credentials (saved with the rule).
    pub identities: Vec<Identity>,
    /// Accept only identity credentials (shared key disabled).
    pub shared_key_off: bool,
    /// One address per credential at a time; a new address revokes the
    /// credential's earlier knock grants.
    pub single_addr: bool,
    pub remark: String,
}

/// One identity inside a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub enable: bool,
    pub enc_key: String,
    pub hmac_key: String,
    pub remark: String,
}

/// A port in a rule or packet (`proto/port`); the single definition lives
/// in the spa layer and carries its own serde shape.
pub use crate::spa::{Access, Proto};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn settings_defaults_follow_wp54() {
        let settings = Settings::default();
        assert_eq!(settings.port, 62201);
        assert!(settings.auto_firewall);
        assert!(settings.allow_lan);
        assert_eq!(settings.max_age, 120);
        assert_eq!(Settings::default().allow_list, Vec::<String>::new());
    }

    #[test]
    fn file_config_roundtrips_camel_case_and_rejects_unknown() {
        let json = r#"{
            "settings": {"port": 62201, "autoFirewall": true, "allowLan": true,
                         "allowList": ["10.0.0.0/8"], "maxAge": 120},
            "rules": [{
                "key": "a1b2c3d4e5f6", "name": "ssh", "group": "", "enable": true,
                "ports": [{"proto": "tcp", "port": 22}],
                "firewall": true,
                "encKey": "YWJjZGVmZ2hpamtsbW5vcA==", "hmacKey": "aGVsbG8td29ybGQtZm9vLWJhcg==",
                "hmacType": "sha256",
                "timeout": 30, "maxTimeout": 300, "user": "", "requireAddr": false,
                "identities": [{"id": "id1", "name": "alice", "enable": true,
                                "encKey": "", "hmacKey": "", "remark": ""}],
                "sharedKeyOff": false, "singleAddr": false, "remark": ""
            }]
        }"#;
        let config: FileConfig = serde_json::from_str(json).expect("parses");
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].ports, vec![Access::new(Proto::Tcp, 22)]);
        assert_eq!(config.rules[0].identities.len(), 1);
        assert_eq!(config.rules[0].hmac_type, HmacType::Sha256);
        let text = serde_json::to_string(&config).unwrap();
        assert!(text.contains("\"maxAge\""));
        assert!(text.contains("\"encKey\""));
        assert!(text.contains("\"hmacType\":\"sha256\""));
        let stray = r#"{"settings": {"port": 1, "stray": true}, "rules": []}"#;
        assert!(serde_json::from_str::<FileConfig>(stray).is_err());
        let stray_rule = r#"{"settings": {"port": 1}, "rules": [{"key": "k", "nope": 1}]}"#;
        assert!(serde_json::from_str::<FileConfig>(stray_rule).is_err());
    }

    #[test]
    fn empty_file_is_the_default_config() {
        let config: FileConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config, FileConfig::default());
    }

    #[test]
    fn limits_match_wp54_table() {
        use limits::*;
        assert_eq!(UDP_PORT_DEFAULT, 62201);
        assert_eq!((MAX_AGE_DEFAULT, MAX_AGE_MAX), (120, 3600));
        assert_eq!(
            (TIMEOUT_DEFAULT, MAX_TIMEOUT_DEFAULT, DURATION_MAX),
            (30, 300, 86_400)
        );
        assert_eq!(RULE_PORTS_MAX, 16);
        assert_eq!((IDENTITIES_MAX, TOTAL_KEYS_MAX), (64, 1024));
        assert_eq!(
            (ENC_KEY_MIN, ENC_KEY_MAX, HMAC_KEY_MIN, HMAC_KEY_MAX),
            (16, 32, 16, 128)
        );
        assert_eq!(
            (GENERATED_ENC_KEY_BYTES, GENERATED_HMAC_KEY_BYTES),
            (32, 64)
        );
        assert_eq!(
            (
                SOURCE_RATE_PER_SEC,
                GLOBAL_BUDGET_PER_SEC,
                BUDGET_UNIT_BYTES
            ),
            (10, 20_000, 512)
        );
        assert_eq!(
            (FAILED_SUMMARY_INTERVAL, FAILED_EVENT_THROTTLE),
            (Duration::from_secs(60), Duration::from_secs(5))
        );
        assert_eq!((WEB_GRANTS_PER_USER_PER_RULE, WEB_GRANT_ADDRS_MAX), (16, 8));
    }
}
