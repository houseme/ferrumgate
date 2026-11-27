//! `ssl.json` serde model (WP-31 step 1): settings, certificate entries
//! and ACME accounts. `mapping` and `deploys` are WP-33 placeholders.
#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// The full model surface is exported for the later WP-31 batches
// (sources, provider, routes); the unused ones quiet until then.
#[allow(unused_imports)]
pub use cert::{Cert, CertSource, Deploy, Mapping};
pub use settings::Settings;

pub mod account;
pub mod cert;
pub mod settings;

/// The `ssl.json` file: settings, certificate entries and ACME accounts
/// keyed by `directory_url + email`. Contains private keys — 0600, never
/// exported outside configuration backups.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
    pub certs: Vec<Cert>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub accounts: BTreeMap<String, account::Account>,
}
