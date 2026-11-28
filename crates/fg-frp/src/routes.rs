//! frp management routes (WP-44 §4): three collections — frpc instances
//! (`/api/frp/clients`), frps instances (`/api/frp/servers`), proxies
//! (`/api/frp/proxies`) — plus import, online install (WP-43), reset and
//! settings. Served with plain axum while mirroring the fg-admin
//! collection contract (JSON shapes, status codes, key handling, secret
//! masking) exactly like the fg-cron / fg-guard routes do — this module
//! cannot depend on fg-admin.
//!
//! Endpoints (permission domain `frp`; the 4 generic log endpoints
//! `GET|DELETE /api/frp/logs`, `GET /api/frp/logs/export`,
//! `GET /api/frp/logs/sources` are served by fg-admin and not mounted
//! here — 49 upstream operations minus those 4):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/frp/{clients,servers,proxies}` | — | `[View]` (masked secrets + read-only `status` / `urls`) |
//! | POST | `/api/frp/{…}` | entry | created view |
//! | POST | `/api/frp/{…}-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | PUT | `/api/frp/{…}-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/frp/{…}-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | PUT | `/api/frp/{…}-order` | `{"keys":[…]}` full list | `{"ok":true}` |
//! | PUT | `/api/frp/{…}/{key}` | entry (secrets merged) | replaced view |
//! | DELETE | `/api/frp/{…}/{key}` | — | `{"removed":1}` |
//! | POST | `/api/frp/{…}/{key}/copy` | entry template | created view (fresh key) |
//! | PUT | `/api/frp/{…}/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | GET | `/api/frp/{…}/{key}/secrets` | — | plaintext secret fields |
//! | POST | `/api/frp/clients/{key}/restart`, `/api/frp/servers/{key}/restart` | — | `{"ok":true}` |
//! | POST | `/api/frp/import` | `{"content","apply"?}` | preview, or `{"ok":true}` after apply |
//! | GET | `/api/frp/install` | — | `{"frpc":InstallView,"frps":InstallView}` |
//! | POST | `/api/frp/install` | `{"program","version"?}` | `{"ok":true}` (progress via GET) |
//! | POST | `/api/frp/install/check` | `{"program"?}` | per-program latest / installed |
//! | POST | `/api/frp/install/rollback` | `{"program","version"}` | `{"ok":true}` |
//! | DELETE | `/api/frp/install?program=…` | — | `{"ok":true}` |
//! | DELETE | `/api/frp/install/backups/{id}?program=…` | — | `{"ok":true}` |
//! | POST | `/api/frp/reset` | — | `{"ok":true}` |
//! | GET / PUT | `/api/frp/settings` | settings view | settings view |
//!
//! Every mutation runs normalize → validate → apply → persist →
//! `runtime.notify_change()`; validation problems return `400` with
//! `{"error":…,"problems":[{"field":…,"reason":…}]}`. Secret fields in
//! views are `********`; submitting `********` or an empty value keeps the
//! stored secret; the `secrets` endpoints return plaintext (write
//! permission enforced by the management router). Restarting is per
//! instance: the reconcile pass restarts only the instances whose rendered
//! config changed.
//!
//! Authentication is NOT performed here: routes are meant to be mounted
//! under the management router whose authorize layer maps `/api/frp/…` to
//! the `frp` domain (GET → `frp:read`, mutations → `frp:write`, with
//! `secrets` paths escalated to write by the sensitive-segment rule).

use std::sync::Arc;

use anyhow::Result;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, rejection::PathRejection, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use fg_proc::install::{self, swap};
use fg_proc::{InstallTarget, Installer, ProgramSpec, Stage};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;

use crate::{
    access_addr,
    import::{self, ImportMode, ImportPreview, ImportTarget},
    model::{
        Client, FileConfig, InstallConfig, Proxy, SECRET_MASK, Server, Settings, limits,
        secret_unchanged,
    },
    runtime::{InstanceStatus, Runtime},
    validate::{self, Problem},
};

/// Writes the whole [`FileConfig`] to `frp.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> Result<()> + Send + Sync>;

/// Shared state behind the frp management routes.
pub struct RoutesState {
    /// The live desired config (already normalized once loaded); the
    /// runtime reads this same handle.
    pub config: Arc<RwLock<FileConfig>>,
    pub persist: PersistFn,
    pub runtime: Arc<Runtime>,
    /// Managed-program infrastructure for the install endpoints.
    pub proc: Arc<fg_proc::Proc>,
    /// Download channel for `install/check` (the same one the assembler
    /// gave `Proc::open`); absent → check reports the missing channel.
    pub fetch: Option<install::HttpGetter>,
}

/// The three collection kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coll {
    Clients,
    Servers,
    Proxies,
}

/// Collection-entry behavior shared by the three collections.
trait Entry: Clone + DeserializeOwned + Serialize + Sized + PartialEq {
    fn key(&self) -> &str;
    fn set_key(&mut self, key: String);
    fn slice(config: &FileConfig) -> &Vec<Self>;
    fn slice_mut(config: &mut FileConfig) -> &mut Vec<Self>;
    /// The view clone: secrets masked, identity intact.
    fn masked(&self) -> Self;
    /// Incoming `********` / empty secrets keep the stored value.
    fn merge_secrets(&mut self, old: &Self);
    /// The plaintext secret fields (secrets endpoint).
    fn secrets_json(&self) -> Value;
    /// Enables / disables and regroups one entry.
    fn set_enable(&mut self, enable: bool);
    fn enable(&self) -> bool;
    fn group(&self) -> &str;
    fn set_group(&mut self, group: &str);
    /// Read-only extras for the view: process status / access URLs.
    fn extras(
        state: &RoutesState,
        config: &FileConfig,
        entry: &Self,
        status: Option<InstanceStatus>,
    ) -> Vec<(&'static str, Value)>;
}

fn mask(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        SECRET_MASK.to_owned()
    }
}

impl Entry for Client {
    fn key(&self) -> &str {
        &self.key
    }
    fn set_key(&mut self, key: String) {
        self.key = key;
    }
    fn slice(config: &FileConfig) -> &Vec<Self> {
        &config.clients
    }
    fn slice_mut(config: &mut FileConfig) -> &mut Vec<Self> {
        &mut config.clients
    }
    fn masked(&self) -> Self {
        let mut clone = self.clone();
        clone.token = mask(&self.token);
        clone
    }
    fn merge_secrets(&mut self, old: &Self) {
        if secret_unchanged(&self.token, &old.token) {
            self.token = old.token.clone();
        }
    }
    fn secrets_json(&self) -> Value {
        json!({ "token": self.token })
    }
    fn set_enable(&mut self, enable: bool) {
        self.enable = enable;
    }
    fn enable(&self) -> bool {
        self.enable
    }
    fn group(&self) -> &str {
        &self.group
    }
    fn set_group(&mut self, group: &str) {
        self.group = group.to_owned();
    }
    fn extras(
        _state: &RoutesState,
        _config: &FileConfig,
        entry: &Self,
        status: Option<InstanceStatus>,
    ) -> Vec<(&'static str, Value)> {
        let status = status.unwrap_or_else(|| InstanceStatus::zero("frpc", entry.key()));
        vec![(
            "status",
            serde_json::to_value(status).unwrap_or(Value::Null),
        )]
    }
}

impl Entry for Server {
    fn key(&self) -> &str {
        &self.key
    }
    fn set_key(&mut self, key: String) {
        self.key = key;
    }
    fn slice(config: &FileConfig) -> &Vec<Self> {
        &config.servers
    }
    fn slice_mut(config: &mut FileConfig) -> &mut Vec<Self> {
        &mut config.servers
    }
    fn masked(&self) -> Self {
        let mut clone = self.clone();
        clone.token = mask(&self.token);
        clone.dashboard_pwd = mask(&self.dashboard_pwd);
        clone
    }
    fn merge_secrets(&mut self, old: &Self) {
        if secret_unchanged(&self.token, &old.token) {
            self.token = old.token.clone();
        }
        if secret_unchanged(&self.dashboard_pwd, &old.dashboard_pwd) {
            self.dashboard_pwd = old.dashboard_pwd.clone();
        }
    }
    fn secrets_json(&self) -> Value {
        json!({ "token": self.token, "dashboardPwd": self.dashboard_pwd })
    }
    fn set_enable(&mut self, enable: bool) {
        self.enable = enable;
    }
    fn enable(&self) -> bool {
        self.enable
    }
    fn group(&self) -> &str {
        &self.group
    }
    fn set_group(&mut self, group: &str) {
        self.group = group.to_owned();
    }
    fn extras(
        _state: &RoutesState,
        _config: &FileConfig,
        entry: &Self,
        status: Option<InstanceStatus>,
    ) -> Vec<(&'static str, Value)> {
        let status = status.unwrap_or_else(|| InstanceStatus::zero("frps", entry.key()));
        vec![(
            "status",
            serde_json::to_value(status).unwrap_or(Value::Null),
        )]
    }
}

impl Entry for Proxy {
    fn key(&self) -> &str {
        &self.key
    }
    fn set_key(&mut self, key: String) {
        self.key = key;
    }
    fn slice(config: &FileConfig) -> &Vec<Self> {
        &config.proxies
    }
    fn slice_mut(config: &mut FileConfig) -> &mut Vec<Self> {
        &mut config.proxies
    }
    fn masked(&self) -> Self {
        let mut clone = self.clone();
        clone.secret_key = mask(&self.secret_key);
        clone
    }
    fn merge_secrets(&mut self, old: &Self) {
        if secret_unchanged(&self.secret_key, &old.secret_key) {
            self.secret_key = old.secret_key.clone();
        }
    }
    fn secrets_json(&self) -> Value {
        json!({ "secretKey": self.secret_key })
    }
    fn set_enable(&mut self, enable: bool) {
        self.enable = enable;
    }
    fn enable(&self) -> bool {
        self.enable
    }
    fn group(&self) -> &str {
        &self.group
    }
    fn set_group(&mut self, group: &str) {
        self.group = group.to_owned();
    }
    fn extras(
        _state: &RoutesState,
        config: &FileConfig,
        entry: &Self,
        _status: Option<InstanceStatus>,
    ) -> Vec<(&'static str, Value)> {
        // The visitor access addresses: the owning client's access block,
        // falling back to a local frps instance's vhost settings.
        let client = config
            .clients
            .iter()
            .find(|client| client.key == entry.client);
        let server_fallback = config.servers.iter().find(|server| server.enable);
        let urls = match client {
            Some(client) => access_addr::proxy_urls(entry, client, server_fallback),
            None => Vec::new(),
        };
        let urls: Vec<Value> = urls
            .iter()
            .map(|url| {
                json!({
                    "kind": match url.kind {
                        access_addr::UrlKind::Tcp => "tcp",
                        access_addr::UrlKind::Udp => "udp",
                        access_addr::UrlKind::Http => "http",
                        access_addr::UrlKind::Https => "https",
                    },
                    "display": url.display,
                    "full": url.full,
                })
            })
            .collect();
        vec![("urls", Value::Array(urls))]
    }
}

/// Dispatches one collection call to the generic implementation.
macro_rules! dispatch {
    ($state:expr, $coll:expr, $function:ident, $($argument:expr),*) => {
        match $coll {
            Coll::Clients => $function::<Client>($state, $($argument),*).await,
            Coll::Servers => $function::<Server>($state, $($argument),*).await,
            Coll::Proxies => $function::<Proxy>($state, $($argument),*).await,
        }
    };
}

// ---------------------------------------------------------------------------
// Mount
// ---------------------------------------------------------------------------

/// Adds the frp routes to `router` (no auth of its own — mounted under the
/// management router).
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    macro_rules! clone_state {
        ($($name:ident),*) => {
            $(let $name = Arc::clone(&state);)*
        };
    }

    let mut app = axum::Router::new();
    {
        clone_state!(
            list,
            create,
            update,
            delete,
            copy,
            enable,
            restart,
            secrets,
            batch_delete,
            batch_enable,
            group,
            order
        );
        app = app
            .route(
                "/api/frp/clients",
                get(move || async move { coll_list(list, Coll::Clients).await })
                    .post(move |body: Bytes| async move {
                        dispatch!(create, Coll::Clients, coll_create, body)
                    }),
            )
            .route(
                "/api/frp/clients/{key}",
                put(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(update, Coll::Clients, coll_update, path, body)
                    },
                )
                .delete(move |path: Result<Path<String>, PathRejection>| async move {
                    dispatch!(delete, Coll::Clients, coll_delete, path)
                }),
            )
            .route(
                "/api/frp/clients/{key}/copy",
                post(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(copy, Coll::Clients, coll_copy, path, body)
                    },
                ),
            )
            .route(
                "/api/frp/clients/{key}/enable",
                put(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(enable, Coll::Clients, coll_enable, path, body)
                    },
                ),
            )
            .route(
                "/api/frp/clients/{key}/restart",
                post(move |path: Result<Path<String>, PathRejection>| async move {
                    instance_restart(restart, "frpc", path).await
                }),
            )
            .route(
                "/api/frp/clients/{key}/secrets",
                get(move |path: Result<Path<String>, PathRejection>| async move {
                    dispatch!(secrets, Coll::Clients, coll_secrets, path)
                }),
            )
            .route(
                "/api/frp/clients-delete",
                post(move |body: Bytes| async move {
                    dispatch!(batch_delete, Coll::Clients, coll_batch_delete, body)
                }),
            )
            .route(
                "/api/frp/clients-enable",
                put(move |body: Bytes| async move {
                    dispatch!(batch_enable, Coll::Clients, coll_batch_enable, body)
                }),
            )
            .route(
                "/api/frp/clients-group",
                put(move |body: Bytes| async move {
                    dispatch!(group, Coll::Clients, coll_group, body)
                }),
            )
            .route(
                "/api/frp/clients-order",
                put(move |body: Bytes| async move {
                    dispatch!(order, Coll::Clients, coll_order, body)
                }),
            );
    }
    {
        clone_state!(
            list,
            create,
            update,
            delete,
            copy,
            enable,
            restart,
            secrets,
            batch_delete,
            batch_enable,
            group,
            order
        );
        app = app
            .route(
                "/api/frp/servers",
                get(move || async move { coll_list(list, Coll::Servers).await })
                    .post(move |body: Bytes| async move {
                        dispatch!(create, Coll::Servers, coll_create, body)
                    }),
            )
            .route(
                "/api/frp/servers/{key}",
                put(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(update, Coll::Servers, coll_update, path, body)
                    },
                )
                .delete(move |path: Result<Path<String>, PathRejection>| async move {
                    dispatch!(delete, Coll::Servers, coll_delete, path)
                }),
            )
            .route(
                "/api/frp/servers/{key}/copy",
                post(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(copy, Coll::Servers, coll_copy, path, body)
                    },
                ),
            )
            .route(
                "/api/frp/servers/{key}/enable",
                put(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(enable, Coll::Servers, coll_enable, path, body)
                    },
                ),
            )
            .route(
                "/api/frp/servers/{key}/restart",
                post(move |path: Result<Path<String>, PathRejection>| async move {
                    instance_restart(restart, "frps", path).await
                }),
            )
            .route(
                "/api/frp/servers/{key}/secrets",
                get(move |path: Result<Path<String>, PathRejection>| async move {
                    dispatch!(secrets, Coll::Servers, coll_secrets, path)
                }),
            )
            .route(
                "/api/frp/servers-delete",
                post(move |body: Bytes| async move {
                    dispatch!(batch_delete, Coll::Servers, coll_batch_delete, body)
                }),
            )
            .route(
                "/api/frp/servers-enable",
                put(move |body: Bytes| async move {
                    dispatch!(batch_enable, Coll::Servers, coll_batch_enable, body)
                }),
            )
            .route(
                "/api/frp/servers-group",
                put(move |body: Bytes| async move {
                    dispatch!(group, Coll::Servers, coll_group, body)
                }),
            )
            .route(
                "/api/frp/servers-order",
                put(move |body: Bytes| async move {
                    dispatch!(order, Coll::Servers, coll_order, body)
                }),
            );
    }
    {
        clone_state!(
            list,
            create,
            update,
            delete,
            copy,
            enable,
            secrets,
            batch_delete,
            batch_enable,
            group,
            order
        );
        app = app
            .route(
                "/api/frp/proxies",
                get(move || async move { coll_list(list, Coll::Proxies).await })
                    .post(move |body: Bytes| async move {
                        dispatch!(create, Coll::Proxies, coll_create, body)
                    }),
            )
            .route(
                "/api/frp/proxies/{key}",
                put(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(update, Coll::Proxies, coll_update, path, body)
                    },
                )
                .delete(move |path: Result<Path<String>, PathRejection>| async move {
                    dispatch!(delete, Coll::Proxies, coll_delete, path)
                }),
            )
            .route(
                "/api/frp/proxies/{key}/copy",
                post(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(copy, Coll::Proxies, coll_copy, path, body)
                    },
                ),
            )
            .route(
                "/api/frp/proxies/{key}/enable",
                put(
                    move |path: Result<Path<String>, PathRejection>,
                          body: Bytes| async move {
                        dispatch!(enable, Coll::Proxies, coll_enable, path, body)
                    },
                ),
            )
            .route(
                "/api/frp/proxies/{key}/secrets",
                get(move |path: Result<Path<String>, PathRejection>| async move {
                    dispatch!(secrets, Coll::Proxies, coll_secrets, path)
                }),
            )
            .route(
                "/api/frp/proxies-delete",
                post(move |body: Bytes| async move {
                    dispatch!(batch_delete, Coll::Proxies, coll_batch_delete, body)
                }),
            )
            .route(
                "/api/frp/proxies-enable",
                put(move |body: Bytes| async move {
                    dispatch!(batch_enable, Coll::Proxies, coll_batch_enable, body)
                }),
            )
            .route(
                "/api/frp/proxies-group",
                put(move |body: Bytes| async move {
                    dispatch!(group, Coll::Proxies, coll_group, body)
                }),
            )
            .route(
                "/api/frp/proxies-order",
                put(move |body: Bytes| async move {
                    dispatch!(order, Coll::Proxies, coll_order, body)
                }),
            );
    }
    {
        clone_state!(
            import_s,
            install_get,
            install_post,
            install_check,
            install_rollback,
            install_delete,
            backup_delete,
            reset_s,
            settings_get,
            settings_put
        );
        app = app
            .route(
                "/api/frp/import",
                post(move |body: Bytes| async move { import_route(import_s, body).await }),
            )
            .route(
                "/api/frp/install",
                get(move || async move { install_view(install_get).await })
                    .post(move |body: Bytes| async move { install_start(install_post, body).await })
                    .delete(move |query: Result<Query<ProgramQuery>, QueryRejection>| async move {
                        install_uninstall(install_delete, query).await
                    }),
            )
            .route(
                "/api/frp/install/check",
                post(move |body: Bytes| async move {
                    install_check_route(install_check, body).await
                }),
            )
            .route(
                "/api/frp/install/rollback",
                post(move |body: Bytes| async move {
                    install_rollback_route(install_rollback, body).await
                }),
            )
            .route(
                "/api/frp/install/backups/{id}",
                delete(
                    move |path: Result<Path<String>, PathRejection>,
                          query: Result<Query<ProgramQuery>, QueryRejection>| async move {
                        install_backup_delete(backup_delete, path, query).await
                    },
                ),
            )
            .route(
                "/api/frp/reset",
                post(move || async move { reset_route(reset_s).await }),
            )
            .route(
                "/api/frp/settings",
                get(move || async move { settings_view(settings_get).await })
                    .put(move |body: Bytes| async move {
                        settings_save(settings_put, body).await
                    }),
            );
    }
    router.merge(app)
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

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
                    "error": "invalid frp configuration",
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
        Response::from(self)
    }
}

type Change<T> = Result<(T, bool), Failure>;

/// Serializes writers, applies the change to a candidate, persists the
/// normalized candidate before publishing it, and notifies the runtime
/// afterwards (fg-admin `Collection::change` commit order: a failed write
/// leaves the desired state untouched).
#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: &RoutesState,
    change: impl FnOnce(&mut FileConfig) -> Change<T> + Send + 'static,
) -> Result<T, Response> {
    let mut guard = state.config.write().await;
    let mut candidate = guard.clone();
    let (value, changed) = change(&mut candidate).map_err(Response::from)?;
    if changed {
        let persist = state.persist.clone();
        let saved = candidate.clone();
        tokio::task::spawn_blocking(move || persist(&saved))
            .await
            .map_err(|_| internal())?
            .map_err(|error| {
                tracing::warn!(%error, "persisting frp.json failed");
                internal()
            })?;
        *guard = candidate;
        drop(guard);
        state.runtime.notify_change();
        return Ok(value);
    }
    drop(guard);
    Ok(value)
}

fn internal() -> Failure {
    Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "configuration operation failed".into(),
    )
}

/// Applies defaults and collects every validation problem.
fn settle(config: &mut FileConfig) -> Result<(), Failure> {
    *config = validate::normalize(std::mem::take(config));
    let problems = validate::validate(config);
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

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found".into())
}

fn locate<E: Entry>(config: &FileConfig, key: &str) -> Result<usize, Failure> {
    E::slice(config)
        .iter()
        .position(|entry| entry.key() == key)
        .ok_or_else(missing_item)
}

/// Maps requested keys (each once) onto entry positions; `None` when a key
/// is unknown or duplicated.
fn find_indices<E: Entry>(config: &FileConfig, keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: std::collections::HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, entry) in E::slice(config).iter().enumerate() {
        if let Some(slot) = slots.remove(entry.key()) {
            indices[slot] = index;
            if slots.is_empty() {
                break;
            }
        }
    }
    slots.is_empty().then_some(indices)
}

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body".into()).into_response()
}

/// Deserializes one entry from the request body, stripping the read-only
/// extras the list views embed (`status`, `urls`) so a client can echo a
/// view back as an update body.
#[allow(clippy::result_large_err)]
fn parse_entry<E: Entry>(body: &Bytes) -> Result<E, Response> {
    let mut value: Value =
        serde_json::from_slice(body).map_err(|_| decode_error().into_response())?;
    if let Some(object) = value.as_object_mut() {
        object.remove("status");
        object.remove("urls");
    }
    serde_json::from_value::<E>(value).map_err(|_| decode_error().into_response())
}

fn entry_view<E: Entry>(
    state: &RoutesState,
    config: &FileConfig,
    entry: &E,
    status: Option<InstanceStatus>,
) -> Value {
    let mut view = serde_json::to_value(entry.masked()).unwrap_or(Value::Null);
    if let Some(object) = view.as_object_mut() {
        for (name, extra) in E::extras(state, config, entry, status) {
            object.insert(name.to_owned(), extra);
        }
    }
    view
}

fn generated_key<E: Entry>(config: &FileConfig) -> Result<String, Failure> {
    let existing: Vec<&str> = E::slice(config).iter().map(|entry| entry.key()).collect();
    Ok(import::new_key(&existing))
}

// ---------------------------------------------------------------------------
// Collection handlers
// ---------------------------------------------------------------------------

async fn coll_list(state: Arc<RoutesState>, coll: Coll) -> Response {
    let statuses = state.runtime.status().await;
    let config = state.config.read().await;
    let lookup = |kind: &'static str, key: &str| {
        statuses
            .iter()
            .find(|status| status.kind == kind && status.key == key)
            .cloned()
    };
    let config_ref = &*config;
    let views: Vec<Value> = match coll {
        Coll::Clients => Client::slice(config_ref)
            .iter()
            .map(|entry| entry_view(&state, config_ref, entry, lookup("frpc", entry.key())))
            .collect(),
        Coll::Servers => Server::slice(config_ref)
            .iter()
            .map(|entry| entry_view(&state, config_ref, entry, lookup("frps", entry.key())))
            .collect(),
        Coll::Proxies => Proxy::slice(config_ref)
            .iter()
            .map(|entry| entry_view(&state, config_ref, entry, None))
            .collect(),
    };
    Json(views).into_response()
}

async fn coll_create<E: Entry + Send + 'static>(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(mut entry) = parse_entry::<E>(&body) else {
        return decode_error();
    };
    let closure_state = Arc::clone(&state);
    match mutate(&state, move |config| {
        // A valid unique client-supplied key is kept; anything else is
        // generated (fg-admin collection behavior on create).
        if !valid_key(entry.key()) || E::slice(config).iter().any(|row| row.key() == entry.key()) {
            let key = generated_key::<E>(config)?;
            entry.set_key(key);
        }
        E::slice_mut(config).push(entry.clone());
        settle(config)?;
        let created = E::slice(config).last().cloned().expect("just pushed");
        Ok((
            Json(entry_view(&closure_state, config, &created, None)).into_response(),
            true,
        ))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn coll_update<E: Entry + Send + 'static>(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut entry) = parse_entry::<E>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let closure_state = Arc::clone(&state);
    match mutate(&state, move |config| {
        let index = locate::<E>(config, &key)?;
        // The path key wins; incoming `********` / empty secrets keep the
        // stored values.
        let old = E::slice(config)[index].clone();
        entry.set_key(key);
        entry.merge_secrets(&old);
        E::slice_mut(config)[index] = entry.clone();
        settle(config)?;
        let replaced = E::slice(config)[index].clone();
        Ok((
            Json(entry_view(&closure_state, config, &replaced, None)).into_response(),
            true,
        ))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn coll_delete<E: Entry + Send + 'static>(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(&state, move |config| {
        let index = locate::<E>(config, &key)?;
        E::slice_mut(config).remove(index);
        // A deleted frpc takes its proxies with it (no orphans).
        if std::any::TypeId::of::<E>() == std::any::TypeId::of::<Client>() {
            config.proxies.retain(|proxy| proxy.client != key);
        }
        Ok((Json(json!({ "removed": 1 })).into_response(), true))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn coll_copy<E: Entry + Send + 'static>(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut entry) = parse_entry::<E>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let closure_state = Arc::clone(&state);
    match mutate(&state, move |config| {
        let index = locate::<E>(config, &source)?;
        // Copies always receive a generated key; the template only decides
        // the insertion position.
        let key = generated_key::<E>(config)?;
        entry.set_key(key);
        E::slice_mut(config).insert(index + 1, entry);
        settle(config)?;
        let created = E::slice(config)[index + 1].clone();
        Ok((
            Json(entry_view(&closure_state, config, &created, None)).into_response(),
            true,
        ))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn coll_enable<E: Entry + Send + 'static>(
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
        let index = locate::<E>(config, &key)?;
        let entry = &mut E::slice_mut(config)[index];
        let changed = entry.enable() != enable;
        entry.set_enable(enable);
        Ok((Json(json!({ "ok": true })).into_response(), changed))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn coll_secrets<E: Entry + Send + 'static>(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let config = state.config.read().await;
    match locate::<E>(&config, &key) {
        Ok(index) => Json(E::slice(&config)[index].secrets_json()).into_response(),
        Err(failure) => failure.into_response(),
    }
}

async fn coll_batch_delete<E: Entry + Send + 'static>(
    state: Arc<RoutesState>,
    body: Bytes,
) -> Response {
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
        // Every key must exist, mirroring fg-admin batch delete (no
        // partial removals).
        find_indices::<E>(config, &keys).ok_or_else(missing_item)?;
        let removed: std::collections::HashSet<_> = keys.iter().map(String::as_str).collect();
        E::slice_mut(config).retain(|entry| !removed.contains(entry.key()));
        let count = keys.len();
        Ok((Json(json!({ "removed": count })).into_response(), true))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn coll_batch_enable<E: Entry + Send + 'static>(
    state: Arc<RoutesState>,
    body: Bytes,
) -> Response {
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
        let indices = find_indices::<E>(config, &keys).ok_or_else(missing_item)?;
        let mut changed = 0;
        for index in indices {
            let entry = &mut E::slice_mut(config)[index];
            if entry.enable() != enable {
                entry.set_enable(enable);
                changed += 1;
            }
        }
        Ok((
            Json(json!({ "changed": changed })).into_response(),
            changed > 0,
        ))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn coll_group<E: Entry + Send + 'static>(state: Arc<RoutesState>, body: Bytes) -> Response {
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
            format!(
                "group name must have at most {} characters",
                limits::GROUP_MAX_CHARS
            ),
        )
        .into();
    }
    match mutate(&state, move |config| {
        let indices = find_indices::<E>(config, &keys).ok_or_else(missing_item)?;
        let mut changed = false;
        for index in indices {
            let entry = &mut E::slice_mut(config)[index];
            if entry.group() != name {
                entry.set_group(&name);
                changed = true;
            }
        }
        Ok((Json(json!({ "ok": true })).into_response(), changed))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn coll_order<E: Entry + Send + 'static>(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        if keys.len() != E::slice(config).len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once".into(),
            ));
        }
        let Some(indices) = find_indices::<E>(config, &keys) else {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order contains an unknown or duplicate key".into(),
            ));
        };
        let unchanged = indices.iter().enumerate().all(|(index, &old)| index == old);
        if unchanged {
            return Ok((Json(json!({ "ok": true })).into_response(), false));
        }
        let mut destination = vec![0; indices.len()];
        for (new, old) in indices.into_iter().enumerate() {
            destination[old] = new;
        }
        let entries = E::slice_mut(config);
        for index in 0..destination.len() {
            while destination[index] != index {
                let new = destination[index];
                entries.swap(index, new);
                destination.swap(index, new);
            }
        }
        Ok((Json(json!({ "ok": true })).into_response(), true))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn instance_restart(
    state: Arc<RoutesState>,
    kind: &'static str,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let exists = {
        let config = state.config.read().await;
        match kind {
            "frpc" => config.clients.iter().any(|client| client.key == key),
            _ => config.servers.iter().any(|server| server.key == key),
        }
    };
    if !exists {
        return missing_item().into();
    }
    match state.runtime.restart(kind, &key).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error) => Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into(),
    }
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportBody {
    content: String,
    /// Absent → preview only; present → import into the target.
    apply: Option<ImportApply>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportApply {
    /// `new` creates new (disabled) instances; otherwise the target frpc
    /// instance key.
    target: String,
    /// `append` (default) or `replace` for an existing target.
    mode: Option<String>,
}

async fn import_route(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<ImportBody>(&body) else {
        return decode_error();
    };
    let preview = match import::parse(&request.content) {
        Ok(preview) => preview,
        Err(error) => return Failure::Api(StatusCode::BAD_REQUEST, error).into_response(),
    };
    let Some(apply) = request.apply else {
        return Json(preview_json(&preview)).into_response();
    };
    let target = if apply.target == "new" {
        ImportTarget::New
    } else {
        let mode = match apply.mode.as_deref() {
            None | Some("append") => ImportMode::Append,
            Some("replace") => ImportMode::Replace,
            Some(other) => {
                return Failure::Api(StatusCode::BAD_REQUEST, format!("未知的导入模式：{other}"))
                    .into_response();
            }
        };
        ImportTarget::ExistingClient {
            key: apply.target.clone(),
            mode,
        }
    };
    match mutate(&state, move |config| {
        import::apply(preview, &target, config)
            .map_err(|error| Failure::Api(StatusCode::BAD_REQUEST, error))?;
        settle(config)?;
        Ok((Json(json!({ "ok": true })).into_response(), true))
    })
    .await
    {
        Ok(response) => response,
        Err(response) => response,
    }
}

/// The preview response: masked entries plus the ignored fields.
fn preview_json(preview: &ImportPreview) -> Value {
    json!({
        "clients": preview
            .clients
            .iter()
            .map(|client| {
                serde_json::to_value(Client {
                    token: mask(&client.token),
                    ..client.clone()
                })
                .unwrap_or(Value::Null)
            })
            .collect::<Vec<_>>(),
        "servers": preview
            .servers
            .iter()
            .map(|server| {
                serde_json::to_value(Server {
                    token: mask(&server.token),
                    dashboard_pwd: mask(&server.dashboard_pwd),
                    ..server.clone()
                })
                .unwrap_or(Value::Null)
            })
            .collect::<Vec<_>>(),
        "proxies": preview
            .proxies
            .iter()
            .map(|proxy| {
                serde_json::to_value(Proxy {
                    secret_key: mask(&proxy.secret_key),
                    ..proxy.clone()
                })
                .unwrap_or(Value::Null)
            })
            .collect::<Vec<_>>(),
        "ignored": preview.ignored,
    })
}

// ---------------------------------------------------------------------------
// Online install (WP-43)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Program {
    Frpc,
    Frps,
}

impl Program {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "frpc" => Some(Self::Frpc),
            "frps" => Some(Self::Frps),
            _ => None,
        }
    }
    fn spec(self) -> &'static ProgramSpec {
        match self {
            Self::Frpc => &install::FRPC,
            Self::Frps => &install::FRPS,
        }
    }
    fn name(self) -> &'static str {
        self.spec().name
    }
}

fn installer_of(state: &RoutesState, program: Program) -> Arc<Installer> {
    state.proc.installer(program.spec())
}

async fn install_view(state: Arc<RoutesState>) -> Response {
    let proxy = current_install_proxy(&state).await;
    Json(json!({
        "frpc": install_program_json(&state, Program::Frpc, proxy.as_ref()),
        "frps": install_program_json(&state, Program::Frps, proxy.as_ref()),
    }))
    .into_response()
}

async fn current_install_proxy(state: &Arc<RoutesState>) -> Option<install::ProxyUrl> {
    let config = state.config.read().await;
    if config.install.proxy.is_empty() {
        None
    } else {
        install::ProxyUrl::parse(&config.install.proxy).ok()
    }
}

fn install_program_json(
    state: &RoutesState,
    program: Program,
    proxy: Option<&install::ProxyUrl>,
) -> Value {
    let installer = installer_of(state, program);
    let stage: Stage = installer.stage().borrow().clone();
    let installed = installer.installed().map(|installed| {
        json!({
            "version": installed.version,
            "at": rfc3339(installed.at),
        })
    });
    let backups: Vec<Value> = installer
        .backups()
        .iter()
        .map(|backup| {
            json!({
                "version": backup.version,
                "at": rfc3339(backup.at),
            })
        })
        .collect();
    let resolved = state
        .proc
        .resolve(None, program.name())
        .map(|(from, _)| match from {
            fg_proc::ResolvedFrom::Configured => "settings",
            fg_proc::ResolvedFrom::BinDir => "bin",
            fg_proc::ResolvedFrom::Path => "path",
        });
    json!({
        "program": program.name(),
        "installed": installed,
        "backups": backups,
        "stage": stage,
        "resolved": resolved,
        "proxy": proxy.map(|proxy| proxy.as_str()),
    })
}

fn rfc3339(at: std::time::SystemTime) -> String {
    let at: time::OffsetDateTime = at.into();
    at.format(&Rfc3339).unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallBody {
    program: String,
    version: Option<String>,
}

async fn install_start(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<InstallBody>(&body) else {
        return decode_error();
    };
    let Some(program) = Program::parse(&request.program) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "program 需为 frpc 或 frps".into())
            .into_response();
    };
    let target = match request.version {
        Some(version) if !version.trim().is_empty() => InstallTarget::Version(version),
        _ => InstallTarget::Latest,
    };
    let proxy = current_install_proxy(&state).await;
    let installer = installer_of(&state, program);
    let runtime = Arc::clone(&state.runtime);
    let on_done: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        runtime.notify_change();
    });
    match installer.start(target, proxy, Some(on_done)).await {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(error) => install_error(error),
    }
}

fn install_error(error: fg_proc::InstallError) -> Response {
    let status = match &error {
        fg_proc::InstallError::Busy => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Failure::Api(status, error.to_string()).into_response()
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallCheckBody {
    program: Option<String>,
}

async fn install_check_route(state: Arc<RoutesState>, body: Bytes) -> Response {
    let request = if body.is_empty() {
        InstallCheckBody::default()
    } else {
        match serde_json::from_slice::<InstallCheckBody>(&body) {
            Ok(request) => request,
            Err(_) => return decode_error(),
        }
    };
    let programs: Vec<Program> = match request.program.as_deref().and_then(Program::parse) {
        Some(program) => vec![program],
        None => vec![Program::Frpc, Program::Frps],
    };
    let Some(fetch) = state.fetch.clone() else {
        return Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, "下载通道未配置".into())
            .into_response();
    };
    let proxy = current_install_proxy(&state).await;
    let mut result = serde_json::Map::new();
    for program in programs {
        let installer = installer_of(&state, program);
        let installed = installer.installed();
        let latest = install::select_release(
            program.spec(),
            &fetch,
            proxy.as_ref(),
            &InstallTarget::Latest,
        )
        .await;
        let entry = match (&installed, latest) {
            (Some(current), Ok(selected)) => json!({
                "installed": current.version,
                "latest": selected.version,
                "updateAvailable": swap::version_newer(&selected.version, &current.version),
            }),
            (Some(current), Err(error)) => json!({
                "installed": current.version,
                "error": error.to_string(),
            }),
            (None, Ok(selected)) => json!({ "installed": Value::Null, "latest": selected.version }),
            (None, Err(error)) => json!({ "error": error.to_string() }),
        };
        result.insert(program.name().to_owned(), entry);
    }
    Json(Value::Object(result)).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RollbackBody {
    program: String,
    version: String,
}

async fn install_rollback_route(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<RollbackBody>(&body) else {
        return decode_error();
    };
    let Some(program) = Program::parse(&request.program) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "program 需为 frpc 或 frps".into())
            .into_response();
    };
    let installer = installer_of(&state, program);
    match installer.rollback_to(request.version.trim()).await {
        Ok(installed) => {
            state.runtime.notify_change();
            Json(json!({ "ok": true, "version": installed.version })).into_response()
        }
        Err(error) => install_error(error),
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProgramQuery {
    program: Option<String>,
}

async fn install_uninstall(
    state: Arc<RoutesState>,
    query: Result<Query<ProgramQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = query else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid query".into()).into_response();
    };
    let Some(program) = params.program.as_deref().and_then(Program::parse) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "program 需为 frpc 或 frps".into())
            .into_response();
    };
    let installer = installer_of(&state, program);
    match installer.uninstall().await {
        Ok(()) => {
            state.runtime.notify_change();
            Json(json!({ "ok": true })).into_response()
        }
        Err(error) => install_error(error),
    }
}

async fn install_backup_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<ProgramQuery>, QueryRejection>,
) -> Response {
    let Ok(Path(id)) = path else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into_response();
    };
    let Ok(Query(params)) = query else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid query".into()).into_response();
    };
    let Some(program) = params.program.as_deref().and_then(Program::parse) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "program 需为 frpc 或 frps".into())
            .into_response();
    };
    let installer = installer_of(&state, program);
    let known = installer
        .backups()
        .iter()
        .any(|backup| swap::version_eq(&backup.version, id.trim()));
    if !known {
        return missing_item().into();
    }
    let dir = swap::versions_dir(installer.bin_dir(), program.name()).join(id.trim());
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing_item().into(),
        Err(error) => Failure::Api(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("删除备份失败：{error}"),
        )
        .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Reset and settings
// ---------------------------------------------------------------------------

async fn reset_route(state: Arc<RoutesState>) -> Response {
    match mutate(&state, move |config| {
        *config = FileConfig::default();
        Ok((Json(json!({ "ok": true })).into_response(), true))
    })
    .await
    {
        Ok(response) => {
            // The reconcile pass after the notify stops everything (nothing
            // is enabled in the default config).
            state.runtime.notify_change();
            response
        }
        Err(response) => response,
    }
}

/// The settings block served by GET / PUT `/api/frp/settings`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct SettingsView {
    pub frpc_path: String,
    pub frps_path: String,
    pub install: InstallConfig,
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    let view = SettingsView {
        frpc_path: config.settings.frpc_path.clone(),
        frps_path: config.settings.frps_path.clone(),
        install: config.install.clone(),
    };
    Json(view).into_response()
}

async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(view) = serde_json::from_slice::<SettingsView>(&body) else {
        return decode_error();
    };
    let changed = match mutate(&state, move |config| {
        let settings = Settings {
            frpc_path: view.frpc_path.trim().to_owned(),
            frps_path: view.frps_path.trim().to_owned(),
        };
        let changed = config.settings != settings || config.install != view.install;
        config.settings = settings;
        config.install = view.install.clone();
        settle(config)?;
        Ok((changed, changed))
    })
    .await
    {
        Ok(changed) => changed,
        Err(response) => return response,
    };
    if changed {
        // Program paths changed: stop everything; the next reconcile
        // starts the instances on the newly resolved binaries.
        state.runtime.stop_all().await;
        state.runtime.notify_change();
    }
    let config = state.config.read().await;
    let view = SettingsView {
        frpc_path: config.settings.frpc_path.clone(),
        frps_path: config.settings.frps_path.clone(),
        install: config.install.clone(),
    };
    Json(view).into_response()
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

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
#[serde(deny_unknown_fields)]
struct BatchEnable {
    keys: Vec<String>,
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    keys: Vec<String>,
    group: String,
}
