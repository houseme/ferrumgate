//! Cloudflared management routes (WP-46 §4): the tunnel collection, the
//! remote ingress editor, program settings, the online install and the
//! reset — served with plain axum while mirroring the fg-admin contract
//! (JSON shapes, status codes, problem lists) exactly like the fg-cron /
//! fg-guard module routes do — this crate cannot depend on fg-admin.
//!
//! Endpoints (permission domain `cloudflared`; of the 27 upstream
//! operations the 4 generic log endpoints `GET|DELETE
//! /api/cloudflared/logs`, `GET /api/cloudflared/logs/export`,
//! `GET /api/cloudflared/logs/sources` are served by fg-admin and not
//! mounted here — the remaining 23 live in this module):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/cloudflared/tunnels` | — | `[TunnelView]` (masked) |
//! | POST | `/api/cloudflared/tunnels` | `Tunnel` | created `TunnelView` |
//! | POST | `/api/cloudflared/tunnels-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | PUT | `/api/cloudflared/tunnels-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/cloudflared/tunnels-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | PUT | `/api/cloudflared/tunnels-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/cloudflared/tunnels/{key}` | `Tunnel` | replaced `TunnelView` |
//! | DELETE | `/api/cloudflared/tunnels/{key}` | — | `{"removed":1}` |
//! | POST | `/api/cloudflared/tunnels/{key}/copy` | `Tunnel` | created `TunnelView` (fresh key, secrets from the source) |
//! | PUT | `/api/cloudflared/tunnels/{key}/enable` | `{"enable":bool}` | `{"ok":true}` (start / stop) |
//! | POST | `/api/cloudflared/tunnels/{key}/restart` | — | `{"ok":true}` |
//! | GET | `/api/cloudflared/tunnels/{key}/secrets` | — | `{"token":…,"apiToken":…}` |
//! | GET | `/api/cloudflared/tunnels/{key}/ingress` | — | [`ingress::IngressView`] |
//! | PUT | `/api/cloudflared/tunnels/{key}/ingress` | [`ingress::IngressUpdate`] | [`ingress::IngressView`] (`409` stale version / local-managed without `force`) |
//! | GET | `/api/cloudflared/settings` | — | `{"settings":…,"binary":…,"version":…,"error":…}` |
//! | PUT | `/api/cloudflared/settings` | `Settings` | `{"ok":true}` (restarts enabled tunnels) |
//! | GET | `/api/cloudflared/install` | — | install view |
//! | POST | `/api/cloudflared/install` | `{"version":…,"proxy":…}` | install view (`409` when busy) |
//! | POST | `/api/cloudflared/install/check` | — | install view (`409` while checking) |
//! | POST | `/api/cloudflared/install/rollback` | `{"id":…}` | install view (`404` unknown backup) |
//! | DELETE | `/api/cloudflared/install` | — | install view |
//! | DELETE | `/api/cloudflared/install/backups/{id}` | — | install view (`404` unknown backup) |
//! | POST | `/api/cloudflared/reset` | — | `{"ok":true}` |
//!
//! The settings endpoints are restricted to logged-in sessions by the
//! surrounding management router (fg-admin wiring), not here. Collection
//! mutations follow the fg-cron commit order: normalize → validate →
//! persist → publish → runtime effects (start / stop / restart); validation
//! problems are returned as `400` with the collected list. Secret fields
//! (`token`, `apiToken`) are masked with `********` in every response;
//! submitting the mask keeps the stored value. Authentication is NOT
//! performed here: [`mount`] routes rely on the management router's
//! authorize layer mapping `/api/cloudflared/…` (GET → `cloudflared:read`,
//! every mutation → `cloudflared:write`).

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{Mutex, RwLock};

use crate::{
    cf_api::{self, CfClient, FetchFn},
    ingress::{self, IngressView},
    model::{FileConfig, InstallConfig, Settings, Tunnel, TunnelKind, limits},
    token,
    tunnel::{PROGRAM, TunnelRuntime, tunnel_view},
    validate::{self, Problem},
};

/// Writes the whole [`FileConfig`] to `cloudflared.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the cloudflared management routes.
pub struct RoutesState {
    /// The live desired config (already normalized once loaded).
    pub config: Arc<RwLock<FileConfig>>,
    pub persist: PersistFn,
    /// The tunnel process runtime (start / stop / views).
    pub runtime: Arc<TunnelRuntime>,
    /// The cloudflared online installer (`bin/` shared with fg-proc).
    pub installer: Arc<fg_proc::Installer>,
    /// The download channel for the installer (from `Deps`, conventions §3.4).
    pub fetch: Option<fg_proc::HttpGetter>,
    /// The outbound channel for the Cloudflare API (from `Deps`).
    pub cf_http: FetchFn,
    /// API endpoint override (tests point it at a fake server; production
    /// uses [`limits::CF_ENDPOINT`]).
    pub cf_endpoint: String,
    /// Serializes the remote ingress read → version check → write so two
    /// concurrent saves cannot overwrite each other (upstream `ingressMu`).
    pub ingress_lock: Arc<Mutex<()>>,
    /// The latest-version cache for `POST /install/check` (upstream
    /// `LatestInfo`), plus the in-flight flag.
    pub latest: Arc<Mutex<Option<LatestInfo>>>,
    pub checking: Arc<AtomicBool>,
    /// The probed program version, cached per binary path (upstream
    /// `versionPath` / `version`).
    pub version_cache: Arc<std::sync::Mutex<Option<(PathBuf, String)>>>,
}

/// The result of a `check` (upstream `Latest`).
#[derive(Clone, Debug)]
pub struct LatestInfo {
    pub version: String,
    pub checked_at: std::time::SystemTime,
    pub has_update: bool,
}

/// The runtime effects a mutation asks for, run after the file is saved.
#[derive(Default)]
struct Effects {
    changed: bool,
    /// Tunnels to re-apply (start / restart with the new config).
    apply: Vec<Tunnel>,
    /// Tunnel keys whose processes must stop (removed / disabled).
    stop: Vec<String>,
    /// Restart every enabled tunnel (settings / binary changed).
    restart_all: bool,
    /// Stop every tunnel (reset).
    stop_all: bool,
}

type Change<T> = Result<(T, Effects), Failure>;

/// Adds all cloudflared management routes to `router`.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create) = (state.clone(), state.clone());
    let (replace, remove) = (state.clone(), state.clone());
    let (copy, enable) = (state.clone(), state.clone());
    let (restart, order) = (state.clone(), state.clone());
    let (batch_enable, group) = (state.clone(), state.clone());
    let (batch_delete, secrets) = (state.clone(), state.clone());
    let (ingress_get, ingress_put) = (state.clone(), state.clone());
    let (settings_get, settings_put) = (state.clone(), state.clone());
    let (install_view, install_start) = (state.clone(), state.clone());
    let (install_check, install_rollback) = (state.clone(), state.clone());
    let (install_uninstall, install_delete_backup) = (state.clone(), state.clone());
    let reset = state;
    router
        .route(
            "/api/cloudflared/tunnels",
            get(move || async move { tunnels_list(list).await })
                .post(move |body: Bytes| async move { tunnels_create(create, body).await }),
        )
        .route(
            "/api/cloudflared/tunnels/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    tunnels_update(replace, path, body).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    tunnels_delete(remove, path).await
                },
            ),
        )
        .route(
            "/api/cloudflared/tunnels/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    tunnels_copy(copy, path, body).await
                },
            ),
        )
        .route(
            "/api/cloudflared/tunnels/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    tunnels_enable(enable, path, body).await
                },
            ),
        )
        .route(
            "/api/cloudflared/tunnels/{key}/restart",
            post(
                move |path: Result<Path<String>, PathRejection>| async move {
                    tunnels_restart(restart, path).await
                },
            ),
        )
        .route(
            "/api/cloudflared/tunnels/{key}/secrets",
            get(
                move |path: Result<Path<String>, PathRejection>| async move {
                    tunnels_secrets(secrets, path).await
                },
            ),
        )
        .route(
            "/api/cloudflared/tunnels/{key}/ingress",
            get(
                move |path: Result<Path<String>, PathRejection>| async move {
                    ingress_read(ingress_get, path).await
                },
            )
            .put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    ingress_save(ingress_put, path, body).await
                },
            ),
        )
        .route(
            "/api/cloudflared/tunnels-delete",
            post(move |body: Bytes| async move { tunnels_batch_delete(batch_delete, body).await }),
        )
        .route(
            "/api/cloudflared/tunnels-enable",
            put(move |body: Bytes| async move { tunnels_batch_enable(batch_enable, body).await }),
        )
        .route(
            "/api/cloudflared/tunnels-group",
            put(move |body: Bytes| async move { tunnels_group(group, body).await }),
        )
        .route(
            "/api/cloudflared/tunnels-order",
            put(move |body: Bytes| async move { tunnels_order(order, body).await }),
        )
        .route(
            "/api/cloudflared/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
        .route(
            "/api/cloudflared/install",
            get(move || async move { install_status(install_view).await })
                .post(move |body: Bytes| async move {
                    install_start_install(install_start, body).await
                })
                .delete(move || async move { install_uninstall_program(install_uninstall).await }),
        )
        .route(
            "/api/cloudflared/install/check",
            post(move || async move { install_check_latest(install_check).await }),
        )
        .route(
            "/api/cloudflared/install/rollback",
            post(move |body: Bytes| async move {
                install_rollback_version(install_rollback, body).await
            }),
        )
        .route(
            "/api/cloudflared/install/backups/{id}",
            delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    install_remove_backup(install_delete_backup, path).await
                },
            ),
        )
        .route(
            "/api/cloudflared/reset",
            post(move || async move { reset_config(reset).await }),
        )
}

/// A failed mutation: a plain status/message pair shaped like the fg-admin
/// `ApiError` body, or the collected validation problems.
enum Failure {
    Api(StatusCode, String),
    Problems(Vec<Problem>),
}

impl From<Failure> for Response {
    fn from(failure: Failure) -> Response {
        match failure {
            Failure::Api(status, message) => {
                (status, Json(json!({ "error": message }))).into_response()
            }
            Failure::Problems(problems) => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid cloudflared configuration",
                    "problems": problems
                        .iter()
                        .map(|problem| json!({"field": problem.field, "reason": problem.reason}))
                        .collect::<Vec<_>>(),
                })),
            )
                .into_response(),
        }
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        self.into()
    }
}

fn internal() -> Failure {
    Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "configuration operation failed".into(),
    )
}

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body".into()).into_response()
}

fn bad_gateway(context: &str, error: impl std::fmt::Display) -> Failure {
    if context.is_empty() {
        Failure::Api(StatusCode::BAD_GATEWAY, error.to_string())
    } else {
        Failure::Api(StatusCode::BAD_GATEWAY, format!("{context}: {error}"))
    }
}

/// Serializes writers, applies the change to a candidate, persists the
/// normalized candidate before publishing it, and runs the runtime effects
/// afterwards (fg-admin `Collection::change` commit order: the file is
/// written first; a failed write leaves the desired state untouched).
#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: &RoutesState,
    change: impl FnOnce(&mut FileConfig) -> Change<T> + Send,
) -> Result<T, Response> {
    let (value, effects, settings) = {
        let mut guard = state.config.write().await;
        let mut candidate = guard.clone();
        let (value, effects) = change(&mut candidate).map_err(Response::from)?;
        let settings = candidate.settings.clone();
        if effects.changed {
            let persist = state.persist.clone();
            let saved = candidate.clone();
            tokio::task::spawn_blocking(move || persist(&saved))
                .await
                .map_err(|_| internal())?
                .map_err(|error| {
                    tracing::warn!(%error, "persisting cloudflared.json failed");
                    internal()
                })?;
            *guard = candidate;
        }
        (value, effects, settings)
    };
    if effects.changed {
        for tunnel in effects.apply {
            state.runtime.apply(&tunnel, &settings).await;
        }
        for key in effects.stop {
            state.runtime.stop_key(&key).await;
        }
        if effects.restart_all {
            let config = state.config.read().await.clone();
            state.runtime.restart_all(&config).await;
        }
        if effects.stop_all {
            state.runtime.stop_all().await;
        }
    }
    Ok(value)
}

/// Validates one tunnel in place (the collection endpoints validate the
/// edited item, not the whole file).
fn settle_tunnel(tunnel: &mut Tunnel) -> Result<(), Failure> {
    validate::normalize_tunnel(tunnel);
    let problems = validate::validate_tunnel(tunnel);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Failure::Problems(problems))
    }
}

fn item_key(path: Result<Path<String>, PathRejection>) -> Result<String, Failure> {
    match path {
        Ok(Path(key)) if valid_key(&key) => Ok(key),
        _ => Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "invalid item key".into(),
        )),
    }
}

/// Same key contract as the fg-admin collections: short, URL-safe, and not
/// colliding with batch-style path suffixes.
fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key != "batch-delete"
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn batch_keys(mut keys: Vec<String>) -> Result<Vec<String>, Failure> {
    if keys.is_empty() || keys.len() > 500 || !keys.iter().all(|key| valid_key(key)) {
        return Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    keys.retain(|key| seen.insert(key.clone()));
    Ok(keys)
}

fn locate(tunnels: &[Tunnel], key: &str) -> Result<usize, Failure> {
    tunnels
        .iter()
        .position(|tunnel| tunnel.key == key)
        .ok_or_else(|| Failure::Api(StatusCode::NOT_FOUND, "item not found".into()))
}

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found".into())
}

/// Maps requested keys (each once) onto tunnel positions; `None` when a key
/// is unknown or duplicated.
fn find_indices(tunnels: &[Tunnel], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: std::collections::HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, tunnel) in tunnels.iter().enumerate() {
        if let Some(slot) = slots.remove(tunnel.key.as_str()) {
            indices[slot] = index;
            if slots.is_empty() {
                break;
            }
        }
    }
    slots.is_empty().then_some(indices)
}

/// 12 lowercase hex characters, unique within the collection — the same
/// shape the fg-admin collections generate.
fn random_key(tunnels: &[Tunnel]) -> Result<String, Failure> {
    for _ in 0..8 {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes[2..]).map_err(|_| internal())?;
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
        if !tunnels.iter().any(|tunnel| tunnel.key == key) {
            return Ok(key);
        }
    }
    Err(internal())
}

/// Submits a masked secret: the placeholder keeps the previous value
/// (upstream `crud.KeepSecret`).
fn keep_secret(old: &str, updated: &mut Option<String>) {
    if updated.as_deref() == Some(limits::SECRET_MASK) {
        *updated = (!old.is_empty()).then(|| old.to_owned());
    }
}

fn keep_secret_string(old: &str, updated: &mut String) {
    if updated == limits::SECRET_MASK {
        *updated = old.to_owned();
    }
}

/// Replaces a candidate tunnel's masked secrets with the stored values
/// (upstream `Merge` on update, `Copy` on copy).
fn merge_secrets(old: &Tunnel, updated: &mut Tunnel) {
    keep_secret_string(&old.token, &mut updated.token);
    keep_secret(
        old.api_token.as_deref().unwrap_or_default(),
        &mut updated.api_token,
    );
}

// ---------------------------------------------------------------------------
// Tunnel collection
// ---------------------------------------------------------------------------

async fn tunnels_list(state: Arc<RoutesState>) -> Response {
    let guard = state.config.read().await;
    let config = validate::normalize(guard.clone());
    let views: Vec<serde_json::Value> = config
        .tunnels
        .iter()
        .map(|tunnel| tunnel_view(tunnel, &state.runtime))
        .collect();
    Json(views).into_response()
}

async fn tunnels_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(mut tunnel) = serde_json::from_slice::<Tunnel>(&body) else {
        return decode_error();
    };
    let runtime = Arc::clone(&state.runtime);
    match mutate(&state, move |config| {
        // A client-supplied valid unique key is kept; anything else gets a
        // generated one (fg-admin collection behavior on create).
        if !valid_key(&tunnel.key) || config.tunnels.iter().any(|row| row.key == tunnel.key) {
            tunnel.key = random_key(&config.tunnels)?;
        }
        settle_tunnel(&mut tunnel)?;
        if config.tunnels.len() >= limits::TUNNELS_MAX {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                format!("最多只能添加 {} 条隧道", limits::TUNNELS_MAX),
            ));
        }
        let mut effects = Effects {
            changed: true,
            ..Effects::default()
        };
        if tunnel.enable {
            effects.apply.push(tunnel.clone());
        }
        config.tunnels.push(tunnel.clone());
        let view = tunnel_view(&tunnel, &runtime);
        Ok((view, effects))
    })
    .await
    {
        Ok(view) => Json(view).into_response(),
        Err(response) => response,
    }
}

async fn tunnels_copy(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut tunnel) = serde_json::from_slice::<Tunnel>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let runtime = Arc::clone(&state.runtime);
    match mutate(&state, move |config| {
        let index = locate(&config.tunnels, &source)?;
        // Copies always receive a generated key; still-masked secrets
        // follow the template (upstream `Copy`).
        merge_secrets(&config.tunnels[index], &mut tunnel);
        tunnel.key = random_key(&config.tunnels)?;
        settle_tunnel(&mut tunnel)?;
        if config.tunnels.len() >= limits::TUNNELS_MAX {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                format!("最多只能添加 {} 条隧道", limits::TUNNELS_MAX),
            ));
        }
        let mut effects = Effects {
            changed: true,
            ..Effects::default()
        };
        if tunnel.enable {
            effects.apply.push(tunnel.clone());
        }
        config.tunnels.insert(index + 1, tunnel.clone());
        let view = tunnel_view(&tunnel, &runtime);
        Ok((view, effects))
    })
    .await
    {
        Ok(view) => Json(view).into_response(),
        Err(response) => response,
    }
}

async fn tunnels_update(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut tunnel) = serde_json::from_slice::<Tunnel>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let runtime = Arc::clone(&state.runtime);
    match mutate(&state, move |config| {
        let index = locate(&config.tunnels, &key)?;
        // The path key wins over the body key; masked secrets keep the
        // stored values (upstream `Merge`).
        tunnel.key = key.clone();
        merge_secrets(&config.tunnels[index], &mut tunnel);
        settle_tunnel(&mut tunnel)?;
        // Re-apply on every change: apply stops the previous process and
        // starts the new one (a disabled tunnel just stops).
        let effects = Effects {
            changed: true,
            apply: vec![tunnel.clone()],
            ..Effects::default()
        };
        config.tunnels[index] = tunnel.clone();
        let view = tunnel_view(&tunnel, &runtime);
        Ok((view, effects))
    })
    .await
    {
        Ok(view) => Json(view).into_response(),
        Err(response) => response,
    }
}

async fn tunnels_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(&state, move |config| {
        locate(&config.tunnels, &key)?;
        config.tunnels.retain(|tunnel| tunnel.key != key);
        let effects = Effects {
            changed: true,
            stop: vec![key],
            ..Effects::default()
        };
        Ok((Json(json!({ "removed": 1 })), effects))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn tunnels_enable(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(Enable { enable }) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.tunnels, &key)?;
        let tunnel = &mut config.tunnels[index];
        if tunnel.enable == enable {
            return Ok((Json(json!({ "ok": true })), Effects::default()));
        }
        tunnel.enable = enable;
        let mut effects = Effects {
            changed: true,
            ..Effects::default()
        };
        if enable {
            effects.apply.push(tunnel.clone());
        } else {
            effects.stop.push(key);
        }
        Ok((Json(json!({ "ok": true })), effects))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn tunnels_restart(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let (tunnel, settings) = {
        let guard = state.config.read().await;
        let Some(index) = guard.tunnels.iter().position(|tunnel| tunnel.key == key) else {
            return missing_item().into();
        };
        (guard.tunnels[index].clone(), guard.settings.clone())
    };
    state.runtime.apply(&tunnel, &settings).await;
    Json(json!({ "ok": true })).into_response()
}

async fn tunnels_secrets(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let guard = state.config.read().await;
    let Some(tunnel) = guard.tunnels.iter().find(|tunnel| tunnel.key == key) else {
        return missing_item().into();
    };
    Json(json!({
        "token": tunnel.token,
        "apiToken": tunnel.api_token.clone().unwrap_or_default(),
    }))
    .into_response()
}

async fn tunnels_batch_delete(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into();
    };
    match mutate(&state, move |config| {
        // Every requested key must exist, mirroring the fg-admin batch
        // delete: no partial removals.
        find_indices(&config.tunnels, &keys).ok_or_else(missing_item)?;
        let removed: std::collections::HashSet<_> = keys.iter().map(String::as_str).collect();
        config
            .tunnels
            .retain(|tunnel| !removed.contains(tunnel.key.as_str()));
        let count = keys.len();
        let effects = Effects {
            changed: true,
            stop: keys,
            ..Effects::default()
        };
        Ok((Json(json!({ "removed": count })), effects))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn tunnels_batch_enable(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(BatchEnable { keys, enable }) = serde_json::from_slice::<BatchEnable>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into();
    };
    match mutate(&state, move |config| {
        let indices = find_indices(&config.tunnels, &keys).ok_or_else(missing_item)?;
        let mut changed = Vec::new();
        for index in indices {
            let tunnel = &mut config.tunnels[index];
            if tunnel.enable != enable {
                tunnel.enable = enable;
                changed.push(tunnel.clone());
            }
        }
        let count = changed.len();
        let effects = Effects {
            changed: !changed.is_empty(),
            apply: if enable { changed } else { Vec::new() },
            stop: if enable { Vec::new() } else { keys },
            ..Effects::default()
        };
        Ok((Json(json!({ "changed": count })), effects))
    })
    .await
    {
        Ok(changed) => changed.into_response(),
        Err(response) => response,
    }
}

async fn tunnels_order(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        if keys.len() != config.tunnels.len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once".into(),
            ));
        }
        let Some(indices) = find_indices(&config.tunnels, &keys) else {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order contains an unknown or duplicate key".into(),
            ));
        };
        if indices.iter().enumerate().all(|(index, &old)| index == old) {
            return Ok((Json(json!({ "ok": true })), Effects::default()));
        }
        let mut destination = vec![0; indices.len()];
        for (new, old) in indices.into_iter().enumerate() {
            destination[old] = new;
        }
        for index in 0..destination.len() {
            while destination[index] != index {
                let new = destination[index];
                config.tunnels.swap(index, new);
                destination.swap(index, new);
            }
        }
        Ok((
            Json(json!({ "ok": true })),
            Effects {
                changed: true,
                ..Effects::default()
            },
        ))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn tunnels_group(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Group { keys, group }) = serde_json::from_slice::<Group>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into();
    };
    let name = group.trim().to_owned();
    if name.chars().count() > limits::GROUP_MAX_CHARS {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            format!("分组名称不能超过 {} 个字符", limits::GROUP_MAX_CHARS),
        )
        .into();
    }
    match mutate(&state, move |config| {
        let indices = find_indices(&config.tunnels, &keys).ok_or_else(missing_item)?;
        let mut changed = false;
        for index in indices {
            let field = &mut config.tunnels[index].group;
            if *field != name {
                field.clone_from(&name);
                changed = true;
            }
        }
        Ok((
            Json(json!({ "ok": true })),
            Effects {
                changed,
                ..Effects::default()
            },
        ))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let settings = validate::normalize(state.config.read().await.clone()).settings;
    let (binary, version, error) = match state.runtime.resolve(&settings) {
        Ok((_from, binary)) => {
            let version = probe_cached(&state, &binary).await;
            (
                binary.to_string_lossy().into_owned(),
                version,
                String::new(),
            )
        }
        Err(message) => (String::new(), String::new(), message),
    };
    Json(json!({
        "settings": settings,
        "binary": binary,
        "version": version,
        "error": error,
    }))
    .into_response()
}

/// Probes the binary version once per path (upstream caches the version
/// per `versionPath`; failures cache the empty string until the path
/// changes).
async fn probe_cached(state: &RoutesState, binary: &std::path::Path) -> String {
    {
        let cache = state.version_cache.lock().expect("version cache");
        if let Some((path, version)) = cache.as_ref()
            && path == binary
        {
            return version.clone();
        }
    }
    let args: Vec<std::ffi::OsString> = fg_proc::install::spec::CLOUDFLARED
        .version_args
        .iter()
        .map(Into::into)
        .collect();
    let version = fg_proc::supervise::probe(binary, &args)
        .await
        .unwrap_or_default();
    *state.version_cache.lock().expect("version cache") =
        Some((binary.to_path_buf(), version.clone()));
    version
}

async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<Settings>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        let mut settings = settings;
        validate::normalize_settings(&mut settings);
        if settings.program_path.chars().count() > limits::PROGRAM_PATH_MAX_CHARS {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                format!("程序路径最多 {} 个字符", limits::PROGRAM_PATH_MAX_CHARS),
            ));
        }
        config.settings = settings;
        Ok((
            Json(json!({ "ok": true })),
            Effects {
                changed: true,
                restart_all: true,
                ..Effects::default()
            },
        ))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

/// The install status view (upstream `binstall.View`).
async fn install_status(state: Arc<RoutesState>) -> Response {
    let proxy = state.config.read().await.install.proxy.clone();
    let latest = state.latest.lock().await.clone();
    Json(install_view(&state, latest, proxy)).into_response()
}

async fn install_start_install(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(InstallRequest { version, proxy }) = serde_json::from_slice::<InstallRequest>(&body)
    else {
        return decode_error();
    };
    let proxy = proxy.unwrap_or_default().trim().to_owned();
    let parsed_proxy = match (!proxy.is_empty()).then(|| fg_proc::ProxyUrl::parse(&proxy)) {
        Some(Ok(parsed)) => Some(parsed),
        Some(Err(message)) => {
            return Failure::Api(StatusCode::BAD_REQUEST, message).into_response();
        }
        None => None,
    };
    if proxy.chars().count() > limits::PROXY_MAX_CHARS {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            format!("下载代理最多 {} 个字符", limits::PROXY_MAX_CHARS),
        )
        .into_response();
    }
    // Persist the proxy when it changed (upstream `SetProxy`).
    if state.config.read().await.install.proxy != proxy {
        let proxy_text = proxy.clone();
        let result = mutate(&state, move |config| {
            config.install = InstallConfig { proxy: proxy_text };
            Ok((
                (),
                Effects {
                    changed: true,
                    ..Effects::default()
                },
            ))
        })
        .await;
        if let Err(response) = result {
            return response;
        }
    }
    let target = match version {
        Some(version) if !version.is_empty() => fg_proc::InstallTarget::Version(version),
        _ => fg_proc::InstallTarget::Latest,
    };
    // 安装完成后重启已启用的隧道（上游 OnChange）。
    let runtime = Arc::clone(&state.runtime);
    let config = Arc::clone(&state.config);
    let on_done: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let runtime = Arc::clone(&runtime);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            tracing::info!("cloudflared 安装完成，重启已启用的隧道");
            let snapshot = config.read().await.clone();
            runtime.restart_all(&snapshot).await;
        });
    });
    match state
        .installer
        .start(target, parsed_proxy, Some(on_done))
        .await
    {
        Ok(_) => {
            let latest = state.latest.lock().await.clone();
            Json(install_view(&state, latest, proxy)).into_response()
        }
        Err(fg_proc::InstallError::Busy) => {
            Failure::Api(StatusCode::CONFLICT, "已有安装、回滚或卸载在进行中".into())
                .into_response()
        }
        Err(error) => Failure::Api(StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn install_check_latest(state: Arc<RoutesState>) -> Response {
    // 查询与请求的生命周期脱钩：查询照常完成，进行中的重复检查返回冲突。
    if state
        .checking
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Failure::Api(StatusCode::CONFLICT, "正在检查更新，请稍候".into()).into_response();
    }
    let Some(fetch) = state.fetch.clone() else {
        state.checking.store(false, Ordering::SeqCst);
        return Failure::Api(
            StatusCode::BAD_GATEWAY,
            "下载通道未配置，无法检查更新".into(),
        )
        .into_response();
    };
    let result = fg_proc::install::select_release(
        state.installer.spec(),
        &fetch,
        None,
        &fg_proc::InstallTarget::Latest,
    )
    .await;
    state.checking.store(false, Ordering::SeqCst);
    let selected = match result {
        Ok(selected) => selected,
        Err(fg_proc::InstallError::Unsupported(_)) => {
            return Failure::Api(StatusCode::BAD_REQUEST, "上游没有当前平台的程序".into())
                .into_response();
        }
        Err(error) => return bad_gateway("检查更新失败", error).into(),
    };
    let info = LatestInfo {
        version: selected.version.clone(),
        checked_at: std::time::SystemTime::now(),
        has_update: state.installer.installed().as_ref().is_some_and(|current| {
            fg_proc::install::swap::version_newer(&selected.version, &current.version)
        }),
    };
    *state.latest.lock().await = Some(info);
    let proxy = state.config.read().await.install.proxy.clone();
    let latest = state.latest.lock().await.clone();
    Json(install_view(&state, latest, proxy)).into_response()
}

async fn install_rollback_version(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Rollback { id }) = serde_json::from_slice::<Rollback>(&body) else {
        return decode_error();
    };
    match state.installer.rollback_to(&id).await {
        Ok(_) => {
            // 文件路径不变：重启让隧道用新程序运行（上游 OnChange）。
            restart_all(&state).await;
            let proxy = state.config.read().await.install.proxy.clone();
            let latest = state.latest.lock().await.clone();
            Json(install_view(&state, latest, proxy)).into_response()
        }
        Err(fg_proc::InstallError::Busy) => {
            Failure::Api(StatusCode::CONFLICT, "已有安装、回滚或卸载在进行中".into())
                .into_response()
        }
        Err(fg_proc::InstallError::Resolve(message)) => {
            Failure::Api(StatusCode::NOT_FOUND, message).into_response()
        }
        Err(error) => {
            Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}

async fn install_uninstall_program(state: Arc<RoutesState>) -> Response {
    match state.installer.uninstall().await {
        Ok(()) => {
            // 程序没了：重启让已启用的隧道记录「找不到程序」。
            restart_all(&state).await;
            let proxy = state.config.read().await.install.proxy.clone();
            let latest = state.latest.lock().await.clone();
            Json(install_view(&state, latest, proxy)).into_response()
        }
        Err(fg_proc::InstallError::Busy) => {
            Failure::Api(StatusCode::CONFLICT, "已有安装、回滚或卸载在进行中".into())
                .into_response()
        }
        Err(fg_proc::InstallError::Resolve(message)) => {
            Failure::Api(StatusCode::NOT_FOUND, message).into_response()
        }
        Err(error) => {
            Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}

async fn install_remove_backup(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(Path(id)) = path else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let dir = fg_proc::install::swap::versions_dir(state.installer.bin_dir(), PROGRAM)
        .join(safe_dir_name(&id));
    if !dir.is_dir() {
        return missing_item().into();
    }
    let removal = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(dir))
        .await
        .map_err(|_| internal())
        .and_then(|result| {
            result.map_err(|error| {
                tracing::warn!(%error, "删除旧版本失败");
                internal()
            })
        });
    if let Err(failure) = removal {
        return failure.into();
    }
    let proxy = state.config.read().await.install.proxy.clone();
    let latest = state.latest.lock().await.clone();
    Json(install_view(&state, latest, proxy)).into_response()
}

/// Restarts every enabled tunnel with the published config.
async fn restart_all(state: &RoutesState) {
    let config = state.config.read().await.clone();
    state.runtime.restart_all(&config).await;
}

/// A backup directory name: only common version characters survive
/// (mirrors fg-proc `swap::safe_dir_name`, which is private there).
fn safe_dir_name(version: &str) -> String {
    let mut name: String = version
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name == ".." || name == "." {
        name = "_".to_owned();
    }
    name
}

/// The install view (upstream `binstall.View`).
fn install_view(
    state: &RoutesState,
    latest: Option<LatestInfo>,
    proxy: String,
) -> serde_json::Value {
    let installer = &state.installer;
    let installed = installer.installed();
    let installed_json = match &installed {
        Some(installed) => {
            let missing: Vec<&str> = if installer.main_path().is_file() {
                Vec::new()
            } else {
                vec![installer.spec().main_file()]
            };
            json!({
                "present": true,
                "version": installed.version,
                "at": crate::tunnel::rfc3339(installed.at),
                "missing": missing,
            })
        }
        None => json!({ "present": false, "version": "", "at": null, "missing": [] }),
    };
    let backups: Vec<serde_json::Value> = installer
        .backups()
        .iter()
        .map(|backup| {
            json!({
                "id": safe_dir_name(&backup.version),
                "version": backup.version,
                "savedAt": crate::tunnel::rfc3339(backup.at),
            })
        })
        .collect();
    let stage = installer.stage().borrow().clone();
    let mut view = json!({
        "state": serde_json::to_value(&stage).unwrap_or_else(|_| json!({"stage": "idle"})),
        "program": installer.spec().name,
        "files": installer.spec().files,
        "binDir": installer.bin_dir().to_string_lossy(),
        "mainPath": installer.main_path().to_string_lossy(),
        "installed": installed_json,
        "backups": backups,
        "proxy": proxy,
        "platform": fg_proc::Platform::current().as_str(),
        "unsupported": "",
    });
    if let Some(latest) = latest {
        view["latest"] = json!({
            "version": latest.version,
            "checkedAt": crate::tunnel::rfc3339(latest.checked_at),
            "hasUpdate": latest.has_update,
        });
    }
    view
}

// ---------------------------------------------------------------------------
// Ingress (remote rules)
// ---------------------------------------------------------------------------

/// Resolves a tunnel for ingress editing: token tunnel with an API token
/// whose tunnel token parses (upstream `ingressTarget`). Returns the API
/// token and the parsed tunnel identity.
fn ingress_target(config: &FileConfig, key: &str) -> Result<(String, token::TokenInfo), Failure> {
    let tunnel = config
        .tunnels
        .iter()
        .find(|tunnel| tunnel.key == key)
        .ok_or_else(missing_item)?;
    if tunnel.kind != TunnelKind::Token {
        return Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "只有令牌隧道可以编辑路由规则".into(),
        ));
    }
    let Some(api_token) = tunnel
        .api_token
        .as_deref()
        .filter(|token| !token.is_empty())
    else {
        return Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "请先在隧道设置中填写 Cloudflare API 令牌".into(),
        ));
    };
    let info = token::parse_token(&tunnel.token)
        .map_err(|error| Failure::Api(StatusCode::BAD_REQUEST, error.to_string()))?;
    Ok((api_token.to_owned(), info))
}

fn client_for(state: &RoutesState, api_token: &str) -> CfClient {
    CfClient::new(state.cf_endpoint.clone(), api_token, state.cf_http.clone())
}

async fn ingress_read(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let (client, info) = {
        let config = state.config.read().await;
        match ingress_target(&config, &key) {
            Ok((api_token, info)) => (client_for(&state, &api_token), info),
            Err(failure) => return failure.into(),
        }
    };
    let remote = match client.get_config(&info.account_tag, &info.tunnel_id).await {
        Ok(remote) => remote,
        Err(error) => return bad_gateway("读取路由规则失败", error).into(),
    };
    match ingress_view_from(&info, &remote) {
        Ok(view) => Json(view).into_response(),
        Err(message) => bad_gateway("", message).into(),
    }
}

fn ingress_view_from(
    info: &token::TokenInfo,
    remote: &cf_api::RemoteConfig,
) -> Result<IngressView, String> {
    let (rules, catch_all) = ingress::split_ingress(&remote.config)?;
    Ok(IngressView {
        tunnel_id: info.tunnel_id.clone(),
        version: remote.version,
        source: remote.source.clone(),
        rules,
        catch_all: catch_all.service,
        dns: Vec::new(),
    })
}

async fn ingress_save(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(update) = serde_json::from_slice::<ingress::IngressUpdate>(&body) else {
        return decode_error();
    };
    // 缺少 rules 字段时拒绝，避免只想改兜底规则的调用把全部规则清空。
    let Some(mut rules) = update.rules.clone() else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "缺少 rules 字段，清空全部规则请传空数组".into(),
        )
        .into();
    };
    if let Err(error) = ingress::normalize_rules(&mut rules) {
        return Failure::Api(StatusCode::BAD_REQUEST, error).into();
    }
    let catch_all_text = update
        .catch_all
        .as_ref()
        .map(|service| service.to_wire())
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| limits::DEFAULT_CATCH_ALL.to_owned());
    let catch_all_service =
        ingress::Service::parse(&ingress::normalize_service(catch_all_text.trim()));
    if let Err(error) = ingress::validate_typed_service(&catch_all_service) {
        return Failure::Api(StatusCode::BAD_REQUEST, format!("兜底规则: {error}")).into();
    }
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let (client, info) = {
        let config = state.config.read().await;
        match ingress_target(&config, &key) {
            Ok((api_token, info)) => (client_for(&state, &api_token), info),
            Err(failure) => return failure.into(),
        }
    };
    // 读取、核对版本、写入串行执行，避免两次并发保存互相覆盖。
    let _guard = state.ingress_lock.lock().await;
    let mut current = match client.get_config(&info.account_tag, &info.tunnel_id).await {
        Ok(current) => current,
        Err(error) => return bad_gateway("读取路由规则失败", error).into(),
    };
    if update.version != current.version {
        return Failure::Api(
            StatusCode::CONFLICT,
            format!(
                "路由规则已在其他地方修改（版本 {}，当前 {}），请刷新后重试",
                update.version, current.version
            ),
        )
        .into();
    }
    if current.source == "local" && !update.force {
        return Failure::Api(
            StatusCode::CONFLICT,
            "这条隧道由本地配置文件管理，写入远程配置会改变它的管理方式，确认后请带 force 重试"
                .to_owned(),
        )
        .into();
    }
    let (_, old_catch_all) = match ingress::split_ingress(&current.config) {
        Ok(split) => split,
        Err(message) => return bad_gateway("", message).into(),
    };
    // 兜底服务换成请求值，但沿用旧兜底的回源设置。
    let catch_all = ingress::Rule {
        hostname: String::new(),
        path: None,
        service: catch_all_service,
        origin_request: old_catch_all.origin_request.clone(),
    };
    current.config["ingress"] =
        serde_json::Value::Array(ingress::build_ingress(&rules, &catch_all));
    let saved = match client
        .put_config(&info.account_tag, &info.tunnel_id, &current.config)
        .await
    {
        Ok(saved) => saved,
        Err(error) => return bad_gateway("保存路由规则失败", error).into(),
    };
    let mut view = match ingress_view_from(&info, &saved) {
        Ok(view) => view,
        Err(message) => return bad_gateway("", message).into(),
    };
    if update.sync_dns {
        view.dns = client.sync_dns(&info, &rules).await;
        for result in &view.dns {
            match result.status {
                cf_api::DnsStatus::Created => tracing::info!(
                    tunnel = %info.tunnel_id,
                    hostname = %result.hostname,
                    "已创建 DNS 记录 CNAME {}.cfargotunnel.com",
                    info.tunnel_id
                ),
                cf_api::DnsStatus::Conflict => tracing::warn!(
                    hostname = %result.hostname,
                    existing = %result.existing.clone().unwrap_or_default(),
                    "已有 DNS 记录，未修改"
                ),
                cf_api::DnsStatus::Failed => tracing::warn!(
                    hostname = %result.hostname,
                    error = %result.error.clone().unwrap_or_default(),
                    "DNS 记录同步失败"
                ),
                cf_api::DnsStatus::Unchanged => {}
            }
        }
    }
    Json(view).into_response()
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

async fn reset_config(state: Arc<RoutesState>) -> Response {
    match mutate(&state, |config| {
        // 旧配置留在配置历史中；安装的程序不受影响。
        *config = FileConfig::default();
        Ok((
            Json(json!({ "ok": true })),
            Effects {
                changed: true,
                stop_all: true,
                ..Effects::default()
            },
        ))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keys {
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enable {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchEnable {
    keys: Vec<String>,
    #[serde(default)]
    enable: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Group {
    keys: Vec<String>,
    #[serde(default)]
    group: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallRequest {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    proxy: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Rollback {
    #[serde(default)]
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_dir_name_strips_unsafe_characters() {
        assert_eq!(safe_dir_name("2026.1.0"), "2026.1.0");
        assert_eq!(safe_dir_name("v1/2"), "v1_2");
        assert_eq!(safe_dir_name(".."), "_");
    }

    #[test]
    fn keep_secret_replaces_only_the_mask() {
        let mut updated = Some(limits::SECRET_MASK.to_owned());
        keep_secret("cf-api", &mut updated);
        assert_eq!(updated.as_deref(), Some("cf-api"));
        let mut updated = Some("new".to_owned());
        keep_secret("cf-api", &mut updated);
        assert_eq!(updated.as_deref(), Some("new"));
        let mut updated = None;
        keep_secret("cf-api", &mut updated);
        assert_eq!(updated, None);
        let mut updated = limits::SECRET_MASK.to_owned();
        keep_secret_string("tok", &mut updated);
        assert_eq!(updated, "tok");
        let mut updated = String::new();
        keep_secret_string("tok", &mut updated);
        assert_eq!(updated, "");
    }

    #[test]
    fn merge_secrets_fills_masked_fields_from_old() {
        let old = Tunnel {
            token: "tok".into(),
            api_token: Some("cf-api".into()),
            ..Tunnel::default()
        };
        let mut updated = Tunnel {
            token: limits::SECRET_MASK.into(),
            api_token: Some(limits::SECRET_MASK.into()),
            ..Tunnel::default()
        };
        merge_secrets(&old, &mut updated);
        assert_eq!(updated.token, "tok");
        assert_eq!(updated.api_token.as_deref(), Some("cf-api"));
    }

    #[test]
    fn valid_key_follows_collection_contract() {
        assert!(valid_key("abc123"));
        assert!(valid_key("a-b_c"));
        assert!(!valid_key(""));
        assert!(!valid_key("batch-delete"));
        assert!(!valid_key("a/b"));
        assert!(!valid_key("a.b"));
        assert!(!valid_key(&"x".repeat(65)));
    }

    #[test]
    fn batch_keys_reject_empty_and_over_500() {
        assert!(batch_keys(Vec::new()).is_err());
        assert!(batch_keys(vec!["".to_owned()]).is_err());
        let many: Vec<String> = (0..501).map(|index| format!("k{index}")).collect();
        assert!(batch_keys(many).is_err());
        assert_eq!(
            batch_keys(vec!["a".into(), "a".into()])
                .map(|mut keys| {
                    keys.sort();
                    keys
                })
                .unwrap_or_default(),
            vec!["a".to_owned()]
        );
    }
}
