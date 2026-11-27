//! Certificate module settings. `renewBeforeDays`/`shortLivedRenewHours`
//! of 0 mean "use the default"; `shortLivedRenewHours` above 80 clamps
//! to 80 (normalize in `crate::certs::validate`).
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Renewal settings; `enable = false` stops automatic issuance but keeps
/// serving existing certificates.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Settings {
    pub enable: bool,
    pub renew_before_days: u32,
    pub short_lived_renew_hours: u32,
    pub default_email: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable: true,
            renew_before_days: 30,
            short_lived_renew_hours: 24,
            default_email: String::new(),
        }
    }
}
