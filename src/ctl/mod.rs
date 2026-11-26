//! `fgate ctl`: drive the management API of a running instance over HTTP
//! with an API token.

pub mod client;
pub mod commands;
pub mod config;

pub use commands::{CtlOptions, run};
