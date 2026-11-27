//! WP-39: `fgate migrate --config <toml> --dir <dir>` — converts the
//! legacy single-file TOML into the new configuration directory
//! (webservice.json + ssl.json + portforward.json + settings), reports
//! every mapping decision, and never touches the source file.
#![allow(dead_code)]

pub mod certs;
pub mod portforward;
pub mod report;
pub mod web;

use std::path::Path;

use fg_gateway::legacy_config::RawConfig;

#[allow(unused_imports)]
pub use report::{
    Converted, DefaultChange, DroppedField, FieldMap, MigrateError, MigrateReport, Summary, Warning,
};

/// The conversion contract each module implements against the frozen
/// report types (steps 2-4).
pub struct Parts {
    pub web: Option<fg_gateway::web::model::FileConfig>,
    pub ssl: Option<fg_gateway::certs::model::FileConfig>,
    pub portforward: Option<Value>,
}

use serde_json::Value;

/// Converts a validated legacy config into the new model documents plus
/// the mapping report. Pure function: no I/O.
pub fn convert(config: &RawConfig) -> Result<Converted, MigrateError> {
    let _ = config;
    Err(MigrateError::NotYetImplemented)
}

/// Self-check helper used by the command line after writing: run the
/// new-model validation over the written directory. Wired in step 6.
pub fn verify_written(_dir: &Path) -> Result<(), Vec<String>> {
    Ok(())
}
