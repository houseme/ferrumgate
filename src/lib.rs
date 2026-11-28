//! Library surface of the `fgate` binary: modules the integration tests
//! and tooling reach directly (WP-38: Gately import; WP-39: TOML migration).
#![forbid(unsafe_code)]

pub mod import_gately;
pub mod migrate_toml;
