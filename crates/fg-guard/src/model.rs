//! The `guard.json` model (WP-50 §3.3 / WP-52 §4): the module switch and
//! the ban table policy knobs, plus the jail rules (`jails[]`, WP-52).
//! The trap / scan detectors land with WP-53 and extend this file later.

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
        }
    }
}
