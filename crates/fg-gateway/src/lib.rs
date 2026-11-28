//! FerrumGate data plane and configuration lifecycle.

#![forbid(unsafe_code)]

mod acme;
mod backend;
mod cert_deploy;
pub mod certs;
pub mod dir_config;
mod config;
mod dns01;
mod domains;
mod forward_metrics;
mod forward_ports;
mod health;
pub mod l4;
pub mod legacy_config;
mod proxy;
mod server;
mod site;
mod source_policy;
mod source_quota;
mod static_files;
mod tcp_forward;
mod tls;
mod udp_forward;
pub mod web;
mod websocket;

use std::path::Path;

pub use server::{ManagementReady, REGISTRY, serve, serve_with_management, serve_with_ready};

/// Load and validate the gateway configuration and referenced TLS material.
/// The path is the legacy TOML file or (WP-39) a configuration directory.
pub async fn check_config(path: &Path) -> anyhow::Result<()> {
    let config = if path.is_dir() {
        dir_config::load(path, std::sync::Arc::default()).await?
    } else {
        config::load(path, std::sync::Arc::default()).await?
    };
    server::REGISTRY.validate_disabled(&config.disabled_modules, false)
}
