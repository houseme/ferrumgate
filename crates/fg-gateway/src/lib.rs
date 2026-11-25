//! FerrumGate data plane and configuration lifecycle.

#![forbid(unsafe_code)]

mod backend;
mod config;
mod health;
mod proxy;
mod server;
mod site;
mod tls;
mod websocket;

use std::path::Path;

pub use server::serve;

/// Load and validate the gateway configuration and referenced TLS material.
pub async fn check_config(path: &Path) -> anyhow::Result<()> {
    config::load(path).await.map(|_| ())
}
