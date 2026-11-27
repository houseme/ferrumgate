//! An ACME account as persisted in `ssl.json` (WP-31 step 1). The key is
//! `directory_url + email`.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// One ACME account: key material plus the server registration URL.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Account {
    pub email: String,
    pub directory_url: String,
    pub key_pem: String,
    pub registration: String,
}
