//! FerrumGate data plane and configuration lifecycle.

#![forbid(unsafe_code)]

mod acme;
mod backend;
mod config;
mod domains;
mod health;
mod proxy;
mod server;
mod site;
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
