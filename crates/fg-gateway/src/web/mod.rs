//! The web service module (WP-20): listeners + sites model, validation,
//! and the site table. The legacy TOML `[[routes]]` path keeps serving
//! until WP-39 completes the migration.
#![allow(dead_code, unused_imports)]
pub(crate) mod legacy;

pub(crate) use legacy::Web;

pub mod domains;
pub mod model;

pub use domains::{Pattern, PatternError, capture, normalize_pattern};
pub use model::{FileConfig, Listener, Settings, Site};
