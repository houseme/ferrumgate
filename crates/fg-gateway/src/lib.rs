//! FerrumGate data plane and configuration lifecycle.

#![forbid(unsafe_code)]

mod config;
mod proxy;
mod server;
mod tls;

use std::path::Path;

pub use server::serve;

/// Load and validate the gateway configuration and referenced TLS material.
pub async fn check_config(path: &Path) -> anyhow::Result<()> {
    config::load(path).await.map(|_| ())
}
