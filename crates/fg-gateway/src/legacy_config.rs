//! The legacy `schema_version = 1` TOML deserialization structures
//! (WP-39 step 1). Extracted from `config.rs` verbatim so the migration
//! tool (`migrate_toml`, WP-39) can consume the same shape the old load
//! path validated — the runtime keeps using these types unchanged until
//! the TOML path is removed.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::{
    acme::RawAcme,
    backend::RawBackend,
    health::RawHealthCheck,
    site::RawResponse,
    tcp_forward::RawForward,
    tls::CertificateFiles,
    udp_forward::RawUdpForward,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub schema_version: u32,
    #[serde(default)]
    pub disabled_modules: Vec<String>,
    #[serde(default)]
    pub server: Settings,
    #[serde(default)]
    pub routes: Vec<RawRoute>,
    #[serde(default)]
    pub tcp_forward: Vec<RawForward>,
    #[serde(default)]
    pub udp_forward: Vec<RawUdpForward>,
    #[serde(default)]
    pub certificates: Vec<CertificateFiles>,
    pub upstream_ca_file: Option<PathBuf>,
    pub acme: Option<RawAcme>,
}

/// The legacy `[server]` section. Field-for-field what the TOML accepted;
/// the new model maps these per site / global setting (see the WP-39
/// report's `mapped` / `defaults_changed` / `dropped` tables).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub listen: SocketAddr,
    pub metrics_listen: Option<SocketAddr>,
    pub http_enabled: bool,
    pub tls: bool,
    pub tls_handshake_timeout_ms: u64,
    pub max_connections: usize,
    pub header_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub response_header_timeout_ms: u64,
    pub connection_lifetime_ms: u64,
    pub shutdown_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            metrics_listen: None,
            http_enabled: true,
            tls: false,
            tls_handshake_timeout_ms: 5_000,
            max_connections: 1024,
            header_timeout_ms: 5_000,
            connect_timeout_ms: 2_000,
            response_header_timeout_ms: 30_000,
            connection_lifetime_ms: 300_000,
            shutdown_timeout_ms: 10_000,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRoute {
    pub host: String,
    pub path_prefix: Option<String>,
    pub upstream: Option<String>,
    #[serde(default)]
    pub backends: Vec<RawBackend>,
    #[serde(default)]
    pub websocket: bool,
    #[serde(default)]
    pub upstream_h2c: bool,
    pub health: Option<RawHealthCheck>,
    pub response: Option<RawResponse>,
}
