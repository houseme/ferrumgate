//! The migration report types (WP-39 §3.2): every field mapping, default
//! change, drop and warning is recorded so the user can review exactly
//! what the tool decided.
#![allow(dead_code)]

use serde::Serialize;

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    /// Files written and their entry counts.
    pub files: Vec<(String, usize)>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldMap {
    pub from: String,
    pub to: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultChange {
    pub field: String,
    pub old_effective: String,
    pub new_effective: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DroppedField {
    pub field: String,
    pub reason_key: String,
    pub hint_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    pub field: String,
    pub message: String,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MigrateReport {
    pub summary: Summary,
    pub mapped: Vec<FieldMap>,
    pub defaults_changed: Vec<DefaultChange>,
    pub dropped: Vec<DroppedField>,
    pub warnings: Vec<Warning>,
}

/// The conversion output: new-model documents plus the report.
pub struct Converted {
    pub webservice: fg_gateway::web::model::FileConfig,
    pub ssl: fg_gateway::certs::model::FileConfig,
    pub portforward: fg_gateway::l4::portforward::model::FileConfig,
    /// The `ferrumgate.json` body carrying the legacy globals
    /// (disabledModules, shutdownTimeoutMs, upstreamCaFile).
    pub management: serde_json::Value,
    pub report: MigrateReport,
}

#[derive(Debug)]
pub enum MigrateError {
    NotYetImplemented,
    Invalid(String),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotYetImplemented => write!(f, "迁移转换尚未实现"),
            Self::Invalid(text) => write!(f, "无法迁移：{text}"),
        }
    }
}

impl std::error::Error for MigrateError {}
