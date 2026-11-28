//! WP-39 step 8 prerequisite: assemble the runtime `Config` from the new
//! configuration directory — `ferrumgate.json` + `webservice.json` +
//! `ssl.json` (+ optional `portforward.json`). v1 serves the first
//! enabled listener (the shape `fgate migrate` produces); extra enabled
//! listeners are rejected until multi-listener serving lands.
#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::acme::Managed;
use crate::config::{Config, Settings as LegacySettings};
use crate::web::model::{FileConfig as WebFileConfig, Listener};

/// The management settings file (fg-core owns its schema).
type ManagementSettings = fg_core::settings::Settings;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DirDocuments {
    webservice: Option<WebFileConfig>,
}

impl Default for DirDocuments {
    fn default() -> Self {
        Self { webservice: None }
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("读取 {} 失败", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("解析 {} 失败", path.display()))
}

/// Assembles the runtime config from a configuration directory.
pub async fn load(dir: &Path, managed: Arc<Managed>) -> Result<Config> {
    ensure!(
        dir.is_dir(),
        "配置目录 {} 不存在或不是目录",
        dir.display()
    );
    let management: ManagementSettings = read_json(&dir.join("ferrumgate.json"))
        .context("读取 ferrumgate.json 失败")?;
    let documents: DirDocuments =
        read_json(&dir.join("webservice.json")).context("读取 webservice.json 失败")?;
    let webservice = documents.webservice.unwrap_or_default();

    let listener = first_enabled_listener(&webservice)?;
    let legacy_settings = derive_settings(&management, &listener);

    // The web model owns its certificates in ssl.json (WP-31); the TOML
    // certificate list is gone.
    let ssl_state = crate::certs::load(dir)
        .await
        .context("准备证书（ssl.json）失败")?;
    let tls = crate::tls::load(
        dir,
        listener.tls,
        Vec::new(),
        management.upstream_ca_file.is_empty().then_some(()).and(Option::None),
        std::iter::empty(),
        None,
        Some(ssl_state.provider()),
    )
    .await
    .context("编译 TLS 失败")?;

    let routes = crate::web::bridge::compile_routes(listener)
        .await
        .map_err(|errors| {
            anyhow::anyhow!("webservice.json 校验失败：{}", errors.join("；"))
        })?;

    let portforward = crate::config::load_portforward_json(dir).await?;
    let (tcp_forward, udp_forward) = portforward.unwrap_or_default();

    Ok(Config {
        disabled_modules: management.disabled_modules.clone(),
        settings: legacy_settings,
        routes,
        tls,
        acme: None,
        tcp_forward,
        udp_forward,
        certs: Arc::new(ssl_state),
    })
}

fn first_enabled_listener(webservice: &WebFileConfig) -> Result<&Listener> {
    let enabled: Vec<&Listener> = webservice
        .listeners
        .iter()
        .filter(|listener| listener.enable)
        .collect();
    ensure!(
        !enabled.is_empty(),
        "webservice.json 没有启用的监听器"
    );
    ensure!(
        enabled.len() == 1,
        "当前版本只支持一个启用的监听器（读到 {} 个）；其余监听器请先停用",
        enabled.len()
    );
    Ok(enabled[0])
}

/// Derives the legacy server settings the serving pipeline still
/// consumes; the new model fixes the protection values (5s handshake,
/// 30s header timeout) and takes limits from the management settings.
fn derive_settings(management: &ManagementSettings, listener: &Listener) -> LegacySettings {
    LegacySettings {
        listen: std::net::SocketAddr::new(
            listener
                .listen_ip
                .parse()
                .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
            listener.port,
        ),
        metrics_listen: None,
        http_enabled: webservice_enabled(management),
        tls: listener.tls,
        tls_handshake_timeout_ms: 5_000,
        max_connections: 1024,
        header_timeout_ms: 30_000,
        connect_timeout_ms: 10_000,
        response_header_timeout_ms: 30_000,
        connection_lifetime_ms: 0,
        shutdown_timeout_ms: management.shutdown_timeout_ms.max(0) as u64,
    }
}

fn webservice_enabled(_management: &ManagementSettings) -> bool {
    true
}
