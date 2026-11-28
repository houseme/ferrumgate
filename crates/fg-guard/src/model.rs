//! The `guard.json` model (WP-50 §3.3 / WP-52 §4 / WP-53 §4): the module
//! switch and the ban table policy knobs, the decoy port and port-scan
//! settings (`trap`, `scan`), plus the jail rules (`jails[]`, WP-52).

use serde::{Deserialize, Serialize};

use crate::jail::model::Jail;

/// The configuration file name in the config store (`guard.json`).
pub const FILE_NAME: &str = "guard";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
    /// The detection rules (WP-52 §4): `jails[]` of `guard.json`.
    pub jails: Vec<Jail>,
}

/// Module settings. JSON field names follow upstream (camelCase).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    /// Module switch; when off the table keeps serving reads but nothing
    /// new is persisted by the intrusion protection side.
    pub enable: bool,
    /// Mirror bans into nftables (WP-51); reserved here.
    pub firewall: bool,
    /// Default ban duration in seconds; 0 normalizes to
    /// [`crate::validate::DEFAULT_BAN_SECONDS`].
    pub ban_seconds: u32,
    /// Double the duration for repeat offenders inside 30 days.
    pub increment: bool,
    /// Escalation ceiling in seconds; 0 normalizes to
    /// [`crate::validate::DEFAULT_MAX_BAN_SECONDS`], clamped to
    /// [`crate::validate::MAX_MAX_BAN_SECONDS`] (365 days).
    pub max_ban_seconds: u32,
    /// Never auto ban private, loopback or link-local addresses.
    pub ignore_private: bool,
    /// Extra whitelist entries (IP or CIDR) on top of the built-in
    /// internal ranges and the local IPv6 networks.
    pub ignore_list: Vec<String>,
    /// Decoy ports (WP-53): `trap{enable,ports,banSeconds}`.
    pub trap: TrapSettings,
    /// Port scan detection (WP-53): `scan{enable,threshold,excludePorts,banSeconds,ipv6Strict}`.
    pub scan: ScanSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable: false,
            firewall: false,
            ban_seconds: 0,
            increment: true,
            max_ban_seconds: 0,
            ignore_private: false,
            ignore_list: Vec::new(),
            trap: TrapSettings::default(),
            scan: ScanSettings::default(),
        }
    }
}

/// Decoy port settings (`trap`, WP-53 §4). `ban_seconds` of `0` follows
/// the module default (`settings.banSeconds`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct TrapSettings {
    pub enable: bool,
    /// Comma / whitespace separated port list (`23,3389,5900-5910`); an
    /// empty value normalizes to [`crate::trap::DEFAULT_TRAP_PORTS`].
    pub ports: String,
    pub ban_seconds: u32,
}

/// Port scan settings (`scan`, WP-53 §4). `ban_seconds` of `0` follows
/// the module default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanSettings {
    pub enable: bool,
    /// Hits per one-minute window that trigger a ban; 0 normalizes to
    /// [`crate::scan::DEFAULT_SCAN_THRESHOLD`].
    pub threshold: u32,
    /// Extra ports treated as open (comma / whitespace separated) —
    /// e.g. ports forwarded by other firewall rules.
    pub exclude_ports: String,
    pub ban_seconds: u32,
    /// IPv6 strict mode: an IPv6 source touching any non-open port is
    /// banned on the first hit (TCP only, requires scan detection).
    pub ipv6_strict: bool,
}
