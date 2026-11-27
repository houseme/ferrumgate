//! One certificate entry in `ssl.json` (WP-31 step 1). PEM contents live
//! in the entry itself for acme/upload sources; the `file` source points
//! at paths that are re-read periodically; `fnos` follows the system
//! certificate registry. `mapping`/`deploys` are WP-33 placeholders.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Where a certificate's content comes from.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Cert {
    pub key: String,
    /// Filename material: validated `^[A-Za-z0-9*_.@-]+$`, `*` → `_`.
    pub remark: String,
    /// Display-only grouping.
    pub group: String,
    pub enable: bool,
    /// acme | upload | file | fnos.
    pub source: CertSource,
    /// ACME parameters (WP-32 gives this its full ssl.json shape and
    /// drives issuance; validation of these fields waits for it).
    pub acme: serde_json::Map<String, serde_json::Value>,
    /// `file` source: re-read every 30 minutes.
    pub cert_file: String,
    pub key_file: String,
    /// `fnos` source: the system domain to look up.
    pub fnos_domain: String,
    /// Stored content for acme/upload (full chain / key / issuer).
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer_pem: String,
    /// WP-33: certificate mapping and deploy targets.
    pub mapping: Mapping,
    pub deploys: Vec<Deploy>,
    pub updated_at: Option<SystemTime>,
    /// Profile used at issuance; differs from `acme.profile` → reissue.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub issued_profile: String,
}

/// Certificate content source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CertSource {
    #[default]
    Acme,
    Upload,
    File,
    FnOS,
}

/// WP-33 placeholder: mapping from domains to this certificate.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Mapping {}

/// WP-33 placeholder: one deploy target.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Deploy {
    pub key: String,
    pub enable: bool,
}
