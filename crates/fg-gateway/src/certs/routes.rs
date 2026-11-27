//! WP-31 step 8: the certificate collection and settings API, following
//! the same shape as the portforward/web collection routes (mounted by
//! the management router, which owns authentication and the authorize
//! layer). Contract: validate first, then apply, persist ssl.json
//! (0600, atomic replace), reload the live index, reply.
//!
//! Secrets: private keys and stored PEM never leave the entry — `view`
//! masks them, `merge` restores from the masked sentinel, `copy_hook`
//! clears issued content so the copy re-issues from its own settings.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::Path;
use axum::routing::{get, post, put};
use hyper::{StatusCode, header::CONTENT_TYPE};
use serde_json::{Value, json};

use crate::certs::model::Settings as ModelSettings;
use crate::certs::model::{Cert, CertSource};
use crate::certs::{SslState, validate};

pub struct CertsRoutesState {
    pub config_dir: PathBuf,
    pub ssl: Arc<SslState>,
}

const MASK: &str = "[masked]";

/// Reads `ssl.json` (absent → default config).
fn read_config(dir: &std::path::Path) -> crate::certs::model::FileConfig {
    let path = dir.join("ssl.json");
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Default::default(),
    }
}

/// Writes `ssl.json` with 0600 and reloads the live index.
async fn persist_and_reload(
    state: &CertsRoutesState,
    config: &crate::certs::model::FileConfig,
) -> Result<(), String> {
    let path = state.config_dir.join("ssl.json");
    let bytes = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // Atomic replace keeps readers on a consistent file.
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, &bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    std::fs::rename(&temp, &path).map_err(|e| e.to_string())?;
    state.ssl.reload(&state.config_dir).await;
    Ok(())
}

fn reply(status: StatusCode, body: Value) -> hyper::Response<axum::body::Body> {
    let mut response = hyper::Response::new(axum::body::Body::from(body.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().expect("static"));
    response
}

fn error(status: StatusCode, message: &str) -> hyper::Response<axum::body::Body> {
    reply(status, json!({ "error": message }))
}

/// View projection: masked secrets + read-only display fields.
fn view_cert(cert: &Cert) -> Value {
    let now = std::time::SystemTime::now();
    let info = crate::certs::info::CertInfo::parse(&cert.cert_pem).ok();
    let not_after = info.as_ref().and_then(|info| info.not_after);
    let issuer = info
        .as_ref()
        .map(|info| info.issuer.clone())
        .unwrap_or_default();
    let domains = info.map(|info| info.dns_names).unwrap_or_default();
    let masked = |pem: &str| {
        if pem.is_empty() {
            Value::String(String::new())
        } else {
            Value::String(MASK.to_owned())
        }
    };
    json!({
        "key": cert.key,
        "remark": cert.remark,
        "group": cert.group,
        "enable": cert.enable,
        "source": cert.source,
        "acme": cert.acme,
        "certFile": cert.cert_file,
        "keyFile": cert.key_file,
        "fnosDomain": cert.fnos_domain,
        "certPem": masked(&cert.cert_pem),
        "keyPem": masked(&cert.key_pem),
        "issuerPem": masked(&cert.issuer_pem),
        "domains": domains,
        "issuer": issuer,
        "notAfter": not_after.map(humantime).unwrap_or_default(),
        "daysRemaining": not_after
            .and_then(|t| t.duration_since(now).ok())
            .map(|left| left.as_secs() / 86_400),
        "needsRenewal": crate::certs::needs_renewal(cert, &state_settings(cert), now),
        "updatedAt": cert.updated_at.map(humantime),
    })
}

fn state_settings(_cert: &Cert) -> ModelSettings {
    ModelSettings::default()
}

fn humantime(time: std::time::SystemTime) -> String {
    let seconds = time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{seconds}")
}

fn masked_or(submitted: &str, original: &str) -> String {
    if submitted.is_empty() || submitted == MASK {
        original.to_owned()
    } else {
        submitted.to_owned()
    }
}

fn backfill_key(config: &mut crate::certs::model::FileConfig, cert: &mut Cert) {
    if cert.key.is_empty() || config.certs.iter().any(|c| c.key == cert.key) {
        cert.key = new_key(config);
    }
}

fn new_key(config: &crate::certs::model::FileConfig) -> String {
    loop {
        let bytes: [u8; 6] = rand_bytes();
        let key: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        if !config.certs.iter().any(|c| c.key == key) {
            return key;
        }
    }
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    let _ = getrandom::fill(&mut out);
    out
}

pub fn mount(router: Router, state: Arc<CertsRoutesState>) -> Router {
    let (list, create, copy) = (state.clone(), state.clone(), state.clone());
    let (replace, remove, remove_many) = (state.clone(), state.clone(), state.clone());
    let (enable, batch_enable, order) = (state.clone(), state.clone(), state.clone());
    let (group, settings_get, settings_put) = (state.clone(), state.clone(), state);
    router
        .route(
            "/api/ssl/certs",
            get(move || async move { certs_list(list).await })
                .post(move |body: Bytes| async move { certs_create(create, body).await }),
        )
        .route(
            "/api/ssl/certs/{key}/copy",
            post(move |path: Path<String>| async move { certs_copy(copy, path).await }),
        )
        .route(
            "/api/ssl/certs/{key}",
            put(move |path: Path<String>, body: Bytes| async move {
                certs_replace(replace, path, body).await
            })
            .delete(move |path: Path<String>| async move { certs_remove(remove, path).await }),
        )
        .route(
            "/api/ssl/certs/{key}/enable",
            put(move |path: Path<String>, body: Bytes| async move {
                certs_enable(enable, path, body).await
            }),
        )
        .route(
            "/api/ssl/certs-enable",
            put(move |body: Bytes| async move { certs_batch_enable(batch_enable, body).await }),
        )
        .route(
            "/api/ssl/certs-order",
            put(move |body: Bytes| async move { certs_order(order, body).await }),
        )
        .route(
            "/api/ssl/certs-group",
            put(move |body: Bytes| async move { certs_group(group, body).await }),
        )
        .route(
            "/api/ssl/certs-delete",
            post(move |body: Bytes| async move { certs_batch_delete(remove_many, body).await }),
        )
        .route(
            "/api/ssl/settings",
            get(move || async move { settings_read(settings_get).await })
                .put(move |body: Bytes| async move { settings_write(settings_put, body).await }),
        )
}

use axum::body::Bytes;

async fn certs_list(state: Arc<CertsRoutesState>) -> hyper::Response<axum::body::Body> {
    let config = read_config(&state.config_dir);
    reply(
        StatusCode::OK,
        json!({ "certs": config.certs.iter().map(view_cert).collect::<Vec<_>>() }),
    )
}

async fn certs_create(
    state: Arc<CertsRoutesState>,
    body: Bytes,
) -> hyper::Response<axum::body::Body> {
    let Ok(mut cert) = serde_json::from_slice::<Cert>(&body) else {
        return error(StatusCode::BAD_REQUEST, "证书条目格式无效");
    };
    let mut config = read_config(&state.config_dir);
    if let Err(e) = validate::validate_cert(&cert) {
        return error(StatusCode::BAD_REQUEST, &e.to_string());
    }
    backfill_key(&mut config, &mut cert);
    config.certs.push(cert);
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::CREATED, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn certs_replace(
    state: Arc<CertsRoutesState>,
    path: Path<String>,
    body: Bytes,
) -> hyper::Response<axum::body::Body> {
    let Ok(submitted) = serde_json::from_slice::<Cert>(&body) else {
        return error(StatusCode::BAD_REQUEST, "证书条目格式无效");
    };
    let mut config = read_config(&state.config_dir);
    let Some(existing) = config.certs.iter_mut().find(|c| c.key == path.as_str()) else {
        return error(StatusCode::NOT_FOUND, "证书条目不存在");
    };
    // Merge: masked or empty secrets keep the stored values; ACME entries
    // keep their issued content unless explicitly replaced.
    let is_acme = existing.source == CertSource::Acme;
    let (old_cert_pem, old_key_pem, old_issuer, old_updated, old_profile) = (
        existing.cert_pem.clone(),
        existing.key_pem.clone(),
        existing.issuer_pem.clone(),
        existing.updated_at,
        existing.issued_profile.clone(),
    );
    *existing = submitted;
    existing.key = path.as_str().to_owned();
    if existing.cert_pem.is_empty()
        || existing.cert_pem == MASK
        || (is_acme
            && old_cert_pem != MASK
            && !old_cert_pem.is_empty()
            && existing.cert_pem == MASK)
    {
        existing.cert_pem = old_cert_pem;
    }
    if existing.key_pem.is_empty() || existing.key_pem == MASK {
        existing.key_pem = old_key_pem;
    }
    if existing.issuer_pem.is_empty() || existing.issuer_pem == MASK {
        existing.issuer_pem = old_issuer;
    }
    if is_acme {
        existing.updated_at = existing.updated_at.or(old_updated);
        if existing.issued_profile.is_empty() {
            existing.issued_profile = old_profile;
        }
    }
    if let Err(e) = validate::validate_cert(existing) {
        return error(StatusCode::BAD_REQUEST, &e.to_string());
    }
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::OK, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn certs_copy(
    state: Arc<CertsRoutesState>,
    path: Path<String>,
) -> hyper::Response<axum::body::Body> {
    let mut config = read_config(&state.config_dir);
    let Some(original) = config.certs.iter().find(|c| c.key == path.as_str()) else {
        return error(StatusCode::NOT_FOUND, "证书条目不存在");
    };
    // `Cert` is not `Clone` (zeroing semantics); a serde round-trip is the
    // cheapest faithful copy.
    let mut copy = match serde_json::to_value(original)
        .map_err(|_| ())
        .and_then(|value| serde_json::from_value::<Cert>(value).map_err(|_| ()))
    {
        Ok(copy) => copy,
        Err(()) => return error(StatusCode::INTERNAL_SERVER_ERROR, "证书条目复制失败"),
    };
    copy.key = String::new();
    copy.remark = format!("{}-copy", original.remark);
    // copy_hook: uploads keep their key material, ACME/file content is
    // cleared so the copy re-issues or re-reads from its own settings;
    // deploy targets start disabled.
    if original.source != CertSource::Upload {
        copy.cert_pem = String::new();
        copy.key_pem = String::new();
        copy.issuer_pem = String::new();
        copy.updated_at = None;
        copy.issued_profile = String::new();
    }
    for deploy in &mut copy.deploys {
        deploy.enable = false;
    }
    backfill_key(&mut config, &mut copy);
    config.certs.push(copy);
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::CREATED, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn certs_remove(
    state: Arc<CertsRoutesState>,
    path: Path<String>,
) -> hyper::Response<axum::body::Body> {
    let mut config = read_config(&state.config_dir);
    let before = config.certs.len();
    config.certs.retain(|c| c.key != path.as_str());
    if config.certs.len() == before {
        return error(StatusCode::NOT_FOUND, "证书条目不存在");
    }
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::OK, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn certs_batch_delete(
    state: Arc<CertsRoutesState>,
    body: Bytes,
) -> hyper::Response<axum::body::Body> {
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "请求体格式无效");
    };
    let Some(keys) = payload.get("keys").and_then(|k| k.as_array()) else {
        return error(StatusCode::BAD_REQUEST, "缺少 keys 数组");
    };
    let keys: Vec<String> = keys
        .iter()
        .filter_map(|k| k.as_str().map(str::to_owned))
        .collect();
    let mut config = read_config(&state.config_dir);
    config.certs.retain(|c| !keys.contains(&c.key));
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::OK, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn certs_enable(
    state: Arc<CertsRoutesState>,
    path: Path<String>,
    body: Bytes,
) -> hyper::Response<axum::body::Body> {
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "请求体格式无效");
    };
    let Some(enable) = payload.get("enable").and_then(|v| v.as_bool()) else {
        return error(StatusCode::BAD_REQUEST, "缺少 enable");
    };
    let mut config = read_config(&state.config_dir);
    let Some(cert) = config.certs.iter_mut().find(|c| c.key == path.as_str()) else {
        return error(StatusCode::NOT_FOUND, "证书条目不存在");
    };
    cert.enable = enable;
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::OK, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn certs_batch_enable(
    state: Arc<CertsRoutesState>,
    body: Bytes,
) -> hyper::Response<axum::body::Body> {
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "请求体格式无效");
    };
    let (Some(keys), Some(enable)) = (
        payload.get("keys").and_then(|k| k.as_array()),
        payload.get("enable").and_then(|v| v.as_bool()),
    ) else {
        return error(StatusCode::BAD_REQUEST, "缺少 keys 或 enable");
    };
    let keys: Vec<String> = keys
        .iter()
        .filter_map(|k| k.as_str().map(str::to_owned))
        .collect();
    let mut config = read_config(&state.config_dir);
    for cert in &mut config.certs {
        if keys.contains(&cert.key) {
            cert.enable = enable;
        }
    }
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::OK, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn certs_order(
    state: Arc<CertsRoutesState>,
    body: Bytes,
) -> hyper::Response<axum::body::Body> {
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "请求体格式无效");
    };
    let Some(keys) = payload.get("keys").and_then(|k| k.as_array()) else {
        return error(StatusCode::BAD_REQUEST, "缺少 keys 数组");
    };
    let keys: Vec<String> = keys
        .iter()
        .filter_map(|k| k.as_str().map(str::to_owned))
        .collect();
    let mut config = read_config(&state.config_dir);
    let mut ordered = Vec::with_capacity(config.certs.len());
    for key in &keys {
        if let Some(pos) = config.certs.iter().position(|c| c.key == *key) {
            ordered.push(config.certs.remove(pos));
        }
    }
    ordered.extend(config.certs);
    config.certs = ordered;
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::OK, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn certs_group(
    state: Arc<CertsRoutesState>,
    body: Bytes,
) -> hyper::Response<axum::body::Body> {
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "请求体格式无效");
    };
    let (Some(keys), Some(group)) = (
        payload.get("keys").and_then(|k| k.as_array()),
        payload.get("group").and_then(|g| g.as_str()),
    ) else {
        return error(StatusCode::BAD_REQUEST, "缺少 keys 或 group");
    };
    let keys: Vec<String> = keys
        .iter()
        .filter_map(|k| k.as_str().map(str::to_owned))
        .collect();
    let mut config = read_config(&state.config_dir);
    for cert in &mut config.certs {
        if keys.contains(&cert.key) {
            cert.group = group.to_owned();
        }
    }
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::OK, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn settings_read(state: Arc<CertsRoutesState>) -> hyper::Response<axum::body::Body> {
    let settings = state.ssl.settings();
    reply(
        StatusCode::OK,
        serde_json::to_value(&settings).unwrap_or_else(|_| json!({})),
    )
}

async fn settings_write(
    state: Arc<CertsRoutesState>,
    body: Bytes,
) -> hyper::Response<axum::body::Body> {
    let Ok(mut settings) = serde_json::from_slice::<ModelSettings>(&body) else {
        return error(StatusCode::BAD_REQUEST, "设置格式无效");
    };
    validate::normalize_settings(&mut settings);
    let mut config = read_config(&state.config_dir);
    config.settings = settings;
    match persist_and_reload(&state, &config).await {
        Ok(()) => reply(StatusCode::OK, json!({ "ok": true })),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}
