//! FerrumGate data plane and configuration lifecycle.

#![forbid(unsafe_code)]

mod acme;
mod backend;
mod cert_deploy;
mod config;
mod dns01;
mod domains;
mod forward_metrics;
mod forward_ports;
mod health;
mod proxy;
mod server;
mod site;
mod source_policy;
mod source_quota;
mod static_files;
mod tcp_forward;
mod tls;
mod udp_forward;
mod websocket;

use std::path::Path;

pub use server::serve;

/// Load and validate the gateway configuration and referenced TLS material.
pub async fn check_config(path: &Path) -> anyhow::Result<()> {
    config::load(path, std::sync::Arc::new(acme::Managed::default()))
        .await
        .map(|_| ())
}
