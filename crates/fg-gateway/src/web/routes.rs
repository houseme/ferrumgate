//! Web service management routes (WP-20 step 6): the listener collection
//! (with sites embedded) and the module settings, served with plain axum
//! while mirroring the fg-admin `Collection<T>` contract (JSON shapes,
//! status codes, key handling) — fg-gateway cannot depend on fg-admin, so
//! the shapes are reimplemented here against [`super::model::FileConfig`]
//! instead of `ConfigStore`.
//!
//! Endpoints (permission domain `webservice`; no module-level metrics
//! endpoint — those go through the global `GET /api/metrics`):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/webservice/listeners` | — | `[Listener]` (normalized) |
//! | POST | `/api/webservice/listeners` | `Listener` | created `Listener` |
//! | POST | `/api/webservice/listeners/{key}/copy` | `Listener` | created `Listener` (fresh key, inserted after the source) |
//! | PUT | `/api/webservice/listeners/{key}` | `Listener` | replaced `Listener` |
//! | DELETE | `/api/webservice/listeners/{key}` | — | `{"removed":1}` |
//! | PUT | `/api/webservice/listeners/{key}/enable` | `{"enable":bool}` | `{"ok":true}` (also sets every embedded site's `enable`) |
//! | PUT | `/api/webservice/listeners-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/webservice/listeners-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | POST | `/api/webservice/listeners-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | GET | `/api/webservice/settings` | — | normalized `Settings` |
//! | PUT | `/api/webservice/settings` | `Settings` | normalized `Settings` |
//!
//! Sites are embedded in their listener: they are read and edited
//! exclusively through the listener endpoints (there are no separate site
//! routes), and the enable toggles cascade to every embedded site.
//!
//! Every mutation runs normalize → validate → apply → persist → publish →
//! on_change; validation problems are returned as `400` with the collected
//! list (`{"error":…,"problems":[{"field":…,"reason":…}]}`), matching the
//! [`Problem`](super::validate::Problem) collector. A no-op mutation skips
//! persist and the on_change notification (batch enable reports the number
//! of changed listeners as `{"changed":N}`). Listener keys follow the
//! fg-admin collection convention: 12 lowercase hex characters generated on
//! create/copy; a client-supplied valid unique key is kept on create and
//! always regenerated on copy.
//!
//! Authentication is NOT performed here: [`mount`] routes are meant to be
//! mounted under the management router built in `src/bootstrap.rs`, whose
//! per-route `authorize` layer authenticates sessions/tokens and derives
//! the required scope from the path prefix — fg-admin's `scope::required`
//! maps `/api/webservice/…` to domain `webservice` automatically (first
//! path segment: GET → `webservice:read`, every mutation →
//! `webservice:write`). Mounted outside that router, callers must apply
//! their own authentication layers.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use super::model::{FileConfig, Listener, Settings};
use super::validate::{Problem, normalize, validate};

/// Writes the whole [`FileConfig`] to `webservice.json`.
pub type ListenerPersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the webservice management routes.
///
/// `config` is the live desired snapshot (already normalized once loaded).
/// `persist` writes the whole [`FileConfig`] to `webservice.json` and is
/// invoked with the normalized candidate before the snapshot is published;
/// `on_change` runs in commit order after a successful, changed mutation so
/// the runtime can recompile affected listeners.
pub struct ListenerRoutesState {
    pub config: Arc<RwLock<FileConfig>>,
    pub on_change: Arc<dyn Fn() + Send + Sync>,
    pub persist: ListenerPersistFn,
}

/// Adds the webservice listener collection and settings routes to `router`.
///
/// See the module docs for the endpoint contract and the authentication
/// assumption: the returned routes carry no auth of their own and rely on
/// the management router's authorize layer being applied to them.
pub fn mount(router: axum::Router, state: Arc<ListenerRoutesState>) -> axum::Router {
    let (list, create) = (state.clone(), state.clone());
    let (replace, remove) = (state.clone(), state.clone());
    let (copy, enable) = (state.clone(), state.clone());
    let (order, batch_enable) = (state.clone(), state.clone());
    let (batch_delete, settings_get) = (state.clone(), state.clone());
    let settings_put = state;
    router
        .route(
            "/api/webservice/listeners",
            get(move || async move { listeners_list(list).await })
                .post(move |body: Bytes| async move { listeners_create(create, body).await }),
        )
        .route(
            "/api/webservice/listeners/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    listeners_update(replace, path, body).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    listeners_delete(remove, path).await
                },
            ),
        )
        .route(
            "/api/webservice/listeners/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    listeners_copy(copy, path, body).await
                },
            ),
        )
        .route(
            "/api/webservice/listeners/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    listeners_enable(enable, path, body).await
                },
            ),
        )
        .route(
            "/api/webservice/listeners-order",
            put(move |body: Bytes| async move { listeners_order(order, body).await }),
        )
        .route(
            "/api/webservice/listeners-enable",
            put(move |body: Bytes| async move { listeners_batch_enable(batch_enable, body).await }),
        )
        .route(
            "/api/webservice/listeners-delete",
            post(
                move |body: Bytes| async move { listeners_batch_delete(batch_delete, body).await },
            ),
        )
        .route(
            "/api/webservice/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
}

/// A failed mutation: either a plain status/message pair shaped like the
/// fg-admin `ApiError` body, or the collected validation problems.
enum Failure {
    Api(StatusCode, &'static str),
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
                    "error": "invalid webservice configuration",
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

type Change<T> = Result<(T, bool), Failure>;

/// Serializes writers, applies the change to a candidate, persists the
/// normalized candidate before publishing it, and notifies afterwards.
///
/// Mirrors the fg-admin `Collection::change` commit order: the file is
/// written first and the in-memory snapshot only advances once the persist
/// hook succeeded, so a failed write leaves the desired state untouched.
#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: &ListenerRoutesState,
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
                tracing::warn!(%error, "persisting webservice.json failed");
                internal()
            })?;
        *guard = candidate;
        drop(guard);
        (state.on_change)();
        return Ok(value);
    }
    drop(guard);
    Ok(value)
}

fn internal() -> Response {
    Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "configuration operation failed",
    )
    .into_response()
}

/// Applies upstream defaults and collects every validation problem.
fn settle(config: &mut FileConfig) -> Result<(), Failure> {
    *config = normalize(std::mem::take(config));
    let problems = validate(config);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Failure::Problems(problems))
    }
}

fn item_key(path: Result<Path<String>, PathRejection>) -> Result<String, Failure> {
    match path {
        Ok(Path(key)) if valid_key(&key) => Ok(key),
        _ => Err(Failure::Api(StatusCode::BAD_REQUEST, "invalid item key")),
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
            "expected between 1 and 500 valid keys",
        ));
    }
    let mut seen = HashSet::with_capacity(keys.len());
    keys.retain(|key| seen.insert(key.clone()));
    Ok(keys)
}

fn locate(listeners: &[Listener], key: &str) -> Result<usize, Failure> {
    listeners
        .iter()
        .position(|listener| listener.key == key)
        .ok_or(Failure::Api(StatusCode::NOT_FOUND, "item not found"))
}

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found")
}

/// Maps requested keys (each once) onto listener positions; `None` when a
/// key is unknown or duplicated.
fn find_indices(listeners: &[Listener], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, listener) in listeners.iter().enumerate() {
        if let Some(slot) = slots.remove(listener.key.as_str()) {
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
fn random_key(listeners: &[Listener]) -> Result<String, Failure> {
    use ring::rand::SecureRandom;

    let random = ring::rand::SystemRandom::new();
    for _ in 0..8 {
        let mut bytes = [0; 8];
        if random.fill(&mut bytes[2..]).is_err() {
            continue;
        }
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
        if !listeners.iter().any(|listener| listener.key == key) {
            return Ok(key);
        }
    }
    Err(Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to generate a unique listener key",
    ))
}

async fn listeners_list(state: Arc<ListenerRoutesState>) -> Response {
    let guard = state.config.read().await;
    Json(normalize(guard.clone()).listeners).into_response()
}

async fn listeners_create(state: Arc<ListenerRoutesState>, body: Bytes) -> Response {
    let Ok(listener) = serde_json::from_slice::<Listener>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        let mut listener = listener;
        // A client-supplied valid unique key is kept; anything else gets a
        // generated one (fg-admin collection behavior on create).
        if !valid_key(&listener.key) || config.listeners.iter().any(|row| row.key == listener.key) {
            listener.key = random_key(&config.listeners)?;
        }
        config.listeners.push(listener);
        settle(config)?;
        let created = config.listeners.last().cloned().expect("just pushed");
        Ok((Json(created), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn listeners_copy(
    state: Arc<ListenerRoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut listener) = serde_json::from_slice::<Listener>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key").into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.listeners, &source)?;
        // Copies always receive a generated key (fg-admin collection
        // behavior): the template only determines the insertion position.
        listener.key = random_key(&config.listeners)?;
        config.listeners.insert(index + 1, listener);
        settle(config)?;
        let created = config.listeners[index + 1].clone();
        Ok((Json(created), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn listeners_update(
    state: Arc<ListenerRoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut listener) = serde_json::from_slice::<Listener>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key").into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.listeners, &key)?;
        listener.key = key.clone();
        config.listeners[index] = listener;
        settle(config)?;
        let replaced = config.listeners[index].clone();
        Ok((Json(replaced), true))
    })
    .await
    {
        Ok(replaced) => replaced.into_response(),
        Err(response) => response,
    }
}

async fn listeners_delete(
    state: Arc<ListenerRoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key").into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.listeners, &key)?;
        config.listeners.remove(index);
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn listeners_batch_delete(state: Arc<ListenerRoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys",
        )
        .into();
    };
    match mutate(&state, move |config| {
        // Every requested key must exist, mirroring the fg-admin batch
        // delete: no partial removals.
        find_indices(&config.listeners, &keys).ok_or_else(missing_item)?;
        let removed: HashSet<_> = keys.iter().map(String::as_str).collect();
        config
            .listeners
            .retain(|listener| !removed.contains(listener.key.as_str()));
        let count = keys.len();
        Ok((Json(json!({ "removed": count })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn listeners_enable(
    state: Arc<ListenerRoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(Enable { enable }) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key").into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.listeners, &key)?;
        let listener = &mut config.listeners[index];
        // The toggle cascades: every embedded site follows the listener.
        let mut changed = listener.enable != enable;
        listener.enable = enable;
        for site in &mut listener.sites {
            changed |= site.enable != enable;
            site.enable = enable;
        }
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn listeners_batch_enable(state: Arc<ListenerRoutesState>, body: Bytes) -> Response {
    let Ok(BatchEnable { keys, enable }) = serde_json::from_slice::<BatchEnable>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys",
        )
        .into();
    };
    match mutate(&state, move |config| {
        let indices = find_indices(&config.listeners, &keys).ok_or_else(missing_item)?;
        let mut changed = 0;
        for index in indices {
            // Same cascade as the single toggle; a listener counts as
            // changed when it or any embedded site flipped.
            let listener = &mut config.listeners[index];
            let mut touched = listener.enable != enable;
            listener.enable = enable;
            for site in &mut listener.sites {
                touched |= site.enable != enable;
                site.enable = enable;
            }
            if touched {
                changed += 1;
            }
        }
        Ok((Json(json!({ "changed": changed })), changed > 0))
    })
    .await
    {
        Ok(changed) => changed.into_response(),
        Err(response) => response,
    }
}

async fn listeners_order(state: Arc<ListenerRoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        if keys.len() != config.listeners.len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once",
            ));
        }
        let Some(indices) = find_indices(&config.listeners, &keys) else {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order contains an unknown or duplicate key",
            ));
        };
        let unchanged = indices.iter().enumerate().all(|(index, &old)| index == old);
        if unchanged {
            return Ok((Json(json!({ "ok": true })), false));
        }
        let mut destination = vec![0; indices.len()];
        for (new, old) in indices.into_iter().enumerate() {
            destination[old] = new;
        }
        for index in 0..destination.len() {
            while destination[index] != index {
                let new = destination[index];
                config.listeners.swap(index, new);
                destination.swap(index, new);
            }
        }
        Ok((Json(json!({ "ok": true })), true))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn settings_view(state: Arc<ListenerRoutesState>) -> Response {
    let guard = state.config.read().await;
    Json(normalize(guard.clone()).settings).into_response()
}

async fn settings_save(state: Arc<ListenerRoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<Settings>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        let previous = config.settings.clone();
        config.settings = settings;
        settle(config)?;
        let view = config.settings.clone();
        Ok((Json(view), config.settings != previous))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body").into_response()
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
#[serde(deny_unknown_fields)]
struct BatchEnable {
    keys: Vec<String>,
    enable: bool,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::web::Site;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use hyper::header::CONTENT_TYPE;
    use hyper_util::rt::TokioIo;

    /// A mounted router over a temp file, counting persist/on_change calls.
    /// `config` is exposed so tests can seed unnormalized state directly.
    struct Harness {
        addr: std::net::SocketAddr,
        persists: Arc<AtomicUsize>,
        changes: Arc<AtomicUsize>,
        last_saved: Arc<Mutex<Option<FileConfig>>>,
        config: Arc<RwLock<FileConfig>>,
        _dir: tempfile::TempDir,
    }

    async fn harness() -> Harness {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("webservice.json");
        let persists = Arc::new(AtomicUsize::new(0));
        let changes = Arc::new(AtomicUsize::new(0));
        let last_saved: Arc<Mutex<Option<FileConfig>>> = Arc::new(Mutex::new(None));
        let config = Arc::new(RwLock::new(FileConfig::default()));
        let (file, count_persist, slot) = (path.clone(), persists.clone(), last_saved.clone());
        let persist: ListenerPersistFn = Arc::new(move |config: &FileConfig| {
            let mut bytes = serde_json::to_vec_pretty(config)?;
            bytes.push(b'\n');
            std::fs::write(&file, &bytes)?;
            *slot.lock().expect("slot") = Some(config.clone());
            count_persist.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let count_change = changes.clone();
        let on_change: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            count_change.fetch_add(1, Ordering::SeqCst);
        });
        let state = Arc::new(ListenerRoutesState {
            config: config.clone(),
            on_change,
            persist,
        });
        let app = mount(axum::Router::new(), state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        Harness {
            addr,
            persists,
            changes,
            last_saved,
            config,
            _dir: dir,
        }
    }

    impl Harness {
        async fn send(
            &self,
            method: &str,
            path: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, serde_json::Value) {
            let stream = tokio::net::TcpStream::connect(self.addr)
                .await
                .expect("connect");
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .expect("handshake");
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let builder = hyper::Request::builder()
                .method(method)
                .uri(path)
                .header(CONTENT_TYPE, "application/json");
            let request = match body {
                Some(body) => builder.body(Body::from(body.to_string())).expect("body"),
                None => builder.body(Body::empty()).expect("body"),
            };
            let response = sender.send_request(request).await.expect("send");
            let status = response.status();
            let bytes = BodyExt::collect(response.into_body())
                .await
                .expect("collect")
                .to_bytes();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
            )
        }

        /// POSTs a listener; returns the created listener as JSON.
        async fn create(&self, listener: serde_json::Value) -> serde_json::Value {
            let (status, body) = self
                .send("POST", "/api/webservice/listeners", Some(listener))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }

        async fn keys(&self) -> Vec<String> {
            let (_, body) = self.send("GET", "/api/webservice/listeners", None).await;
            body.as_array()
                .expect("listeners array")
                .iter()
                .map(|listener| listener["key"].as_str().expect("key").to_owned())
                .collect()
        }
    }

    fn base_listener(key: &str) -> serde_json::Value {
        json!({
            "key": key,
            "name": key,
            "enable": false,
            "network": "tcp",
            "listenIp": "127.0.0.1",
            "port": 8443,
            "tls": false,
            "minTls": "",
            "plainHttp": false,
            "httpPort": "",
            "acceptProxyProtocol": false,
            "accessScheme": "",
            "accessPort": 0,
            "autoFirewall": false,
            "sites": [],
            "default": false,
            "remark": ""
        })
    }

    fn proxy_site(key: &str, domains: &[&str]) -> serde_json::Value {
        json!({
            "key": key,
            "enable": true,
            "domains": domains,
            "siteType": "proxy",
            "targets": ["http://127.0.0.1:9000"]
        })
    }

    fn is_generated_key(key: &str) -> bool {
        key.len() == 12
            && key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    #[tokio::test]
    async fn create_generates_key_and_lists() {
        let app = harness().await;
        let created = app.create(base_listener("")).await;
        assert!(
            is_generated_key(created["key"].as_str().expect("key")),
            "{created}"
        );
        assert_eq!(created["name"], "");
        let (status, listeners) = app.send("GET", "/api/webservice/listeners", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listeners[0]["key"], created["key"]);
        assert_eq!(listeners.as_array().expect("array").len(), 1);
        // A valid unique client key is kept; a duplicate one is regenerated.
        let kept = app.create(base_listener("edge")).await;
        assert_eq!(kept["key"], "edge");
        let clash = app.create(base_listener("edge")).await;
        let clash = clash["key"].as_str().expect("key");
        assert!(is_generated_key(clash) && clash != "edge", "{clash}");
        assert_eq!(app.persists.load(Ordering::SeqCst), 3);
        assert_eq!(app.changes.load(Ordering::SeqCst), 3);
        let saved = app.last_saved.lock().expect("slot").clone().expect("saved");
        assert_eq!(saved.listeners.len(), 3);
        assert!(
            saved
                .listeners
                .iter()
                .any(|listener| listener.key == "edge")
        );
    }

    #[tokio::test]
    async fn create_rejects_invalid_listener_with_collected_problems() {
        let app = harness().await;
        let (status, body) = app
            .send(
                "POST",
                "/api/webservice/listeners",
                Some(json!({"name": "broken"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let problems = body["problems"].as_array().expect("problems");
        assert!(!problems.is_empty(), "{body}");
        assert!(
            problems
                .iter()
                .any(|p| p["field"].as_str().expect("field").ends_with(".port"))
        );
        // An embedded site's problems carry their full path.
        let (status, body) = app
            .send(
                "POST",
                "/api/webservice/listeners",
                Some(json!({"port": 8443, "sites": [{"siteType": "proxy"}]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["problems"]
                .as_array()
                .expect("problems")
                .iter()
                .any(|p| p["field"].as_str().expect("field") == "listeners[0].sites[0].domains")
        );
        // Nothing was applied or persisted.
        assert!(app.keys().await.is_empty());
        assert_eq!(app.persists.load(Ordering::SeqCst), 0);
        assert_eq!(app.changes.load(Ordering::SeqCst), 0);
        let (status, body) = app
            .send(
                "POST",
                "/api/webservice/listeners",
                Some(json!({"port": "nope"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
    }

    #[tokio::test]
    async fn copy_inserts_after_source_with_fresh_key() {
        let app = harness().await;
        app.create(base_listener("a")).await;
        let mut template = base_listener("");
        template["name"] = json!("copied");
        template["port"] = json!(9443);
        let (status, created) = app
            .send(
                "POST",
                "/api/webservice/listeners/a/copy",
                Some(template.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let key = created["key"].as_str().expect("key");
        assert!(is_generated_key(key) && key != "a", "{created}");
        assert_eq!(created["name"], "copied");
        assert_eq!(created["port"], 9443);
        assert_eq!(app.keys().await, vec!["a".to_owned(), key.to_owned()]);
        assert_eq!(app.persists.load(Ordering::SeqCst), 2);
        let (status, _) = app
            .send(
                "POST",
                "/api/webservice/listeners/ghost/copy",
                Some(template),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_replaces_normalizes_and_rejects_invalid() {
        let app = harness().await;
        app.create(base_listener("web")).await;
        let mut replacement = base_listener("ignored");
        replacement["listenIp"] = json!("  10.0.0.10  ");
        replacement["sites"] = json!([{
            "key": "api",
            "domains": ["Example.COM.", "example.com", ""],
            "siteType": "proxy",
            "targets": ["http://127.0.0.1:9000"]
        }]);
        let (status, body) = app
            .send("PUT", "/api/webservice/listeners/web", Some(replacement))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["key"], "web");
        // The replacement is normalized before it is stored.
        assert_eq!(body["listenIp"], "10.0.0.10");
        assert_eq!(body["sites"][0]["domains"], json!(["example.com"]));
        assert_eq!(app.persists.load(Ordering::SeqCst), 2);
        // An invalid replacement (port 0, site missing domains and its
        // type field) is rejected wholesale.
        let before = app.persists.load(Ordering::SeqCst);
        let mut broken = base_listener("web");
        broken["port"] = json!(0);
        broken["sites"] = json!([{"siteType": "redirect"}]);
        let (status, body) = app
            .send("PUT", "/api/webservice/listeners/web", Some(broken))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let problems = body["problems"].as_array().expect("problems");
        assert!(
            problems
                .iter()
                .any(|p| p["field"].as_str().expect("field").ends_with(".port"))
        );
        assert!(problems.iter().any(|p| {
            p["field"]
                .as_str()
                .expect("field")
                .ends_with("sites[0].redirectTo")
        }));
        assert_eq!(app.persists.load(Ordering::SeqCst), before);
        let (status, listeners) = app.send("GET", "/api/webservice/listeners", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listeners[0]["port"], 8443);
        assert_eq!(listeners[0]["sites"][0]["key"], "api");
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/listeners/ghost",
                Some(base_listener("ghost")),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
    }

    #[tokio::test]
    async fn site_group_truncated_through_listener_update() {
        let app = harness().await;
        app.create(base_listener("web")).await;
        let mut replacement = base_listener("ignored");
        let mut site = proxy_site("api", &["api.test"]);
        site["siteType"] = json!("text");
        site["textBody"] = json!("hi");
        site["group"] = json!("x".repeat(70));
        replacement["sites"] = json!([site]);
        let (status, body) = app
            .send("PUT", "/api/webservice/listeners/web", Some(replacement))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // normalize truncates the embedded site's group to 64 characters.
        let group = body["sites"][0]["group"].as_str().expect("group");
        assert_eq!(group.chars().count(), 64);
        let saved = app.last_saved.lock().expect("slot").clone().expect("saved");
        assert_eq!(saved.listeners[0].sites[0].group.chars().count(), 64);
    }

    #[tokio::test]
    async fn delete_single_and_batch() {
        let app = harness().await;
        app.create(base_listener("a")).await;
        app.create(base_listener("b")).await;
        let (status, body) = app
            .send("DELETE", "/api/webservice/listeners/a", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["removed"], 1);
        let (status, body) = app
            .send(
                "POST",
                "/api/webservice/listeners-delete",
                Some(json!({"keys": ["b"]})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["removed"], 1);
        assert!(app.keys().await.is_empty());
        let (status, body) = app
            .send(
                "POST",
                "/api/webservice/listeners-delete",
                Some(json!({"keys": ["ghost"]})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
        let (status, _) = app
            .send(
                "POST",
                "/api/webservice/listeners-delete",
                Some(json!({"keys": []})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn enable_cascades_to_sites_single_and_batch() {
        let app = harness().await;
        let mut payload = base_listener("a");
        let mut off = proxy_site("s1", &["a.test"]);
        off["enable"] = json!(false);
        let mut redirect = json!({
            "key": "s2",
            "enable": true,
            "domains": ["b.test"],
            "siteType": "redirect",
            "redirectTo": "https://x.test"
        });
        redirect["enable"] = json!(true);
        payload["sites"] = json!([off, redirect]);
        app.create(payload).await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/listeners/a/enable",
                Some(json!({"enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        // The toggle cascaded to both embedded sites.
        let (_, listeners) = app.send("GET", "/api/webservice/listeners", None).await;
        let listener = &listeners[0];
        assert_eq!(listener["enable"], true);
        assert_eq!(listener["sites"][0]["enable"], true);
        assert_eq!(listener["sites"][1]["enable"], true);
        assert_eq!(app.persists.load(Ordering::SeqCst), 2);
        // Enabling again is a no-op: no persist, no on_change.
        let (status, _) = app
            .send(
                "PUT",
                "/api/webservice/listeners/a/enable",
                Some(json!({"enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(app.persists.load(Ordering::SeqCst), 2);
        // Batch enable counts changed listeners and cascades too.
        let mut payload = base_listener("b");
        payload["sites"] = json!([{
            "key": "s3",
            "enable": false,
            "domains": ["c.test"],
            "siteType": "text",
            "textBody": "hi"
        }]);
        app.create(payload).await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/listeners-enable",
                Some(json!({"keys": ["a", "b"], "enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["changed"], 1, "a was already on, b flipped");
        let (_, listeners) = app.send("GET", "/api/webservice/listeners", None).await;
        assert!(
            listeners
                .as_array()
                .expect("listeners")
                .iter()
                .all(|listener| listener["enable"] == true)
        );
        assert_eq!(app.persists.load(Ordering::SeqCst), 4);
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/listeners-enable",
                Some(json!({"keys": ["a", "b"], "enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["changed"], 0);
        assert_eq!(app.persists.load(Ordering::SeqCst), 4);
        let (status, _) = app
            .send(
                "PUT",
                "/api/webservice/listeners/ghost/enable",
                Some(json!({"enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = app
            .send(
                "PUT",
                "/api/webservice/listeners-enable",
                Some(json!({"keys": ["ghost"], "enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn order_requires_complete_list_and_persists() {
        let app = harness().await;
        for key in ["a", "b", "c"] {
            app.create(base_listener(key)).await;
        }
        let persists = app.persists.load(Ordering::SeqCst);
        // Identity order changes nothing.
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/listeners-order",
                Some(json!({"keys": ["a", "b", "c"]})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        assert_eq!(app.persists.load(Ordering::SeqCst), persists);
        // A rotation persists and reorders.
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/listeners-order",
                Some(json!({"keys": ["c", "a", "b"]})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(app.keys().await, vec!["c", "a", "b"]);
        assert_eq!(app.persists.load(Ordering::SeqCst), persists + 1);
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/listeners-order",
                Some(json!({"keys": ["c", "a"]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "order must include every item once");
        let (status, _) = app
            .send(
                "PUT",
                "/api/webservice/listeners-order",
                Some(json!({"keys": ["c", "a", "a"]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = app
            .send(
                "PUT",
                "/api/webservice/listeners-order",
                Some(json!({"keys": ["c", "a", "ghost"]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn settings_get_put_apply_defaults_and_skip_noop() {
        let app = harness().await;
        let (status, settings) = app.send("GET", "/api/webservice/settings", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(settings["enable"], false);
        assert_eq!(settings["responseHeaderTimeoutMs"], 30_000);
        let (status, settings) = app
            .send(
                "PUT",
                "/api/webservice/settings",
                Some(json!({"enable": true, "responseHeaderTimeoutMs": 15000})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{settings}");
        assert_eq!(settings["enable"], true);
        assert_eq!(settings["responseHeaderTimeoutMs"], 15000);
        let saved = app.last_saved.lock().expect("slot").clone().expect("saved");
        assert!(saved.settings.enable);
        assert_eq!(saved.settings.response_header_timeout_ms, 15000);
        assert_eq!(app.changes.load(Ordering::SeqCst), 1);
        // An identical PUT is a no-op: the response still echoes the
        // settings, but nothing is persisted or announced.
        let (status, settings) = app
            .send(
                "PUT",
                "/api/webservice/settings",
                Some(json!({"enable": true, "responseHeaderTimeoutMs": 15000})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{settings}");
        assert_eq!(app.persists.load(Ordering::SeqCst), 1);
        assert_eq!(app.changes.load(Ordering::SeqCst), 1);
        // Missing fields fall back to the per-field defaults; the saved
        // candidate carries the defaults too.
        let (status, settings) = app
            .send(
                "PUT",
                "/api/webservice/settings",
                Some(json!({"responseHeaderTimeoutMs": 5000})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{settings}");
        assert_eq!(
            settings["enable"], false,
            "missing enable falls back to the default"
        );
        assert_eq!(settings["responseHeaderTimeoutMs"], 5000);
        assert_eq!(app.persists.load(Ordering::SeqCst), 2);
        let saved = app.last_saved.lock().expect("slot").clone().expect("saved");
        assert!(!saved.settings.enable);
        assert_eq!(saved.settings.response_header_timeout_ms, 5000);
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/settings",
                Some(json!({"bogus_field": 1})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
    }

    #[tokio::test]
    async fn get_normalizes_stored_config() {
        let app = harness().await;
        // Seed messy state directly, bypassing the API's settle step.
        *app.config.write().await = FileConfig {
            settings: Settings::default(),
            listeners: vec![
                Listener {
                    key: "  web  ".to_string(),
                    name: "  Public  ".to_string(),
                    listen_ip: "  ".to_string(),
                    port: 8443,
                    sites: vec![Site {
                        key: " s1 ".to_string(),
                        name: "  api  ".to_string(),
                        group: "x".repeat(70),
                        domains: vec![
                            "Example.COM.".to_string(),
                            "example.com".to_string(),
                            String::new(),
                        ],
                        site_type: "proxy".to_string(),
                        targets: vec!["http://127.0.0.1:9000".to_string()],
                        ..Site::default()
                    }],
                    ..Listener::default()
                },
                Listener {
                    key: "dup".to_string(),
                    port: 9443,
                    ..Listener::default()
                },
                Listener {
                    key: "dup".to_string(),
                    port: 9444,
                    ..Listener::default()
                },
            ],
        };
        let (status, listeners) = app.send("GET", "/api/webservice/listeners", None).await;
        assert_eq!(status, StatusCode::OK);
        let listeners = listeners.as_array().expect("listeners");
        assert_eq!(listeners.len(), 3);
        let first = &listeners[0];
        assert_eq!(first["key"], "web");
        assert_eq!(first["name"], "Public");
        assert_eq!(first["listenIp"], "0.0.0.0");
        let site = &first["sites"][0];
        assert_eq!(site["key"], "s1");
        assert_eq!(site["name"], "api");
        assert_eq!(site["domains"], json!(["example.com"]));
        assert_eq!(site["group"].as_str().expect("group").chars().count(), 64);
        // Duplicate listener keys: the first is kept, the rest regenerated.
        assert_eq!(listeners[1]["key"], "dup");
        let regenerated = listeners[2]["key"].as_str().expect("key");
        assert!(
            is_generated_key(regenerated) && regenerated != "dup",
            "{regenerated}"
        );
        // A plain GET never persists.
        assert_eq!(app.persists.load(Ordering::SeqCst), 0);
        assert_eq!(app.changes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_json_body_and_item_key_are_bad_request() {
        let app = harness().await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/webservice/listeners-order",
                Some(json!({"nope": true})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid JSON body");
        let (status, body) = app
            .send("DELETE", "/api/webservice/listeners/bad%2Fkey!", None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid item key");
        let (status, body) = app
            .send(
                "POST",
                "/api/webservice/listeners/bad%2Fkey!/copy",
                Some(base_listener("")),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid item key");
    }
}
