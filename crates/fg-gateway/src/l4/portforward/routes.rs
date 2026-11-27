//! Portforward management routes (WP-34 §4): the rule collection and the
//! module settings, served with plain axum while mirroring the fg-admin
//! `Collection<T>` contract (JSON shapes, status codes, key handling) —
//! fg-gateway cannot depend on fg-admin, so the shapes are reimplemented
//! here against [`super::model::FileConfig`] instead of `ConfigStore`.
//!
//! Endpoints (permission domain `portforward`; no module-level metrics
//! endpoint — those go through the global `GET /api/metrics`):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/portforward/rules` | — | `[Rule]` (normalized) |
//! | POST | `/api/portforward/rules` | `Rule` | created `Rule` |
//! | POST | `/api/portforward/rules/{key}/copy` | `Rule` | created `Rule` (fresh key, inserted after the source) |
//! | PUT | `/api/portforward/rules/{key}` | `Rule` | replaced `Rule` |
//! | DELETE | `/api/portforward/rules/{key}` | — | `{"removed":1}` |
//! | PUT | `/api/portforward/rules/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | PUT | `/api/portforward/rules-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/portforward/rules-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/portforward/rules-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | POST | `/api/portforward/rules-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | GET | `/api/portforward/settings` | — | normalized `Settings` |
//! | PUT | `/api/portforward/settings` | `Settings` | normalized `Settings` |
//!
//! Every mutation runs normalize → validate → apply → persist → on_change;
//! validation problems are returned as `400` with the collected list
//! (`{"error":…,"problems":[{"field":…,"reason":…}]}`), matching the
//! [`Problem`](super::Problem) collector. Rule keys follow the fg-admin
//! collection convention: 12 lowercase hex characters generated on
//! create/copy; a client-supplied valid unique key is kept on create and
//! always regenerated on copy.
//!
//! Authentication is NOT performed here: [`mount`] routes are meant to be
//! mounted under the management router built in `src/bootstrap.rs`, whose
//! per-route `authorize` layer authenticates sessions/tokens and derives
//! the required scope from the path prefix — fg-admin's `scope::required`
//! maps `/api/portforward/…` to domain `portforward` automatically (first
//! path segment: GET → `portforward:read`, every mutation →
//! `portforward:write`). Mounted outside that router, callers must apply
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

use super::model::{FileConfig, Rule, Settings};
use super::validate::{normalize, validate};

/// Shared state behind the portforward management routes.
///
/// `config` is the live desired snapshot (already normalized once loaded).
/// `persist` writes the whole [`FileConfig`] to `portforward.json` and is
/// invoked with the normalized candidate before the snapshot is published;
/// `on_change` runs in commit order after a successful, changed mutation so
/// the runtime can recompile affected rules.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

pub struct RoutesState {
    pub config: Arc<RwLock<FileConfig>>,
    pub on_change: Arc<dyn Fn() + Send + Sync>,
    pub persist: PersistFn,
}

/// Adds the portforward collection and settings routes to `router`.
///
/// See the module docs for the endpoint contract and the authentication
/// assumption: the returned routes carry no auth of their own and rely on
/// the management router's authorize layer being applied to them.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create) = (state.clone(), state.clone());
    let (replace, remove) = (state.clone(), state.clone());
    let (copy, enable) = (state.clone(), state.clone());
    let (order, batch_enable) = (state.clone(), state.clone());
    let (group, batch_delete) = (state.clone(), state.clone());
    let (settings_get, settings_put) = (state.clone(), state);
    router
        .route(
            "/api/portforward/rules",
            get(move || async move { rules_list(list).await })
                .post(move |body: Bytes| async move { rules_create(create, body).await }),
        )
        .route(
            "/api/portforward/rules/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rules_update(replace, path, body).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    rules_delete(remove, path).await
                },
            ),
        )
        .route(
            "/api/portforward/rules/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rules_copy(copy, path, body).await
                },
            ),
        )
        .route(
            "/api/portforward/rules/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rules_enable(enable, path, body).await
                },
            ),
        )
        .route(
            "/api/portforward/rules-order",
            put(move |body: Bytes| async move { rules_order(order, body).await }),
        )
        .route(
            "/api/portforward/rules-enable",
            put(move |body: Bytes| async move { rules_batch_enable(batch_enable, body).await }),
        )
        .route(
            "/api/portforward/rules-group",
            put(move |body: Bytes| async move { rules_group(group, body).await }),
        )
        .route(
            "/api/portforward/rules-delete",
            post(move |body: Bytes| async move { rules_batch_delete(batch_delete, body).await }),
        )
        .route(
            "/api/portforward/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
}

/// A failed mutation: either a plain status/message pair shaped like the
/// fg-admin `ApiError` body, or the collected validation problems.
enum Failure {
    Api(StatusCode, &'static str),
    Problems(Vec<super::Problem>),
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
                    "error": "invalid portforward configuration",
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
                tracing::warn!(%error, "persisting portforward.json failed");
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

fn locate(rules: &[Rule], key: &str) -> Result<usize, Failure> {
    rules
        .iter()
        .position(|rule| rule.key == key)
        .ok_or(Failure::Api(StatusCode::NOT_FOUND, "item not found"))
}

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found")
}

/// Maps requested keys (each once) onto rule positions; `None` when a key
/// is unknown or duplicated.
fn find_indices(rules: &[Rule], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, rule) in rules.iter().enumerate() {
        if let Some(slot) = slots.remove(rule.key.as_str()) {
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
fn random_key(rules: &[Rule]) -> Result<String, Failure> {
    use ring::rand::SecureRandom;

    let random = ring::rand::SystemRandom::new();
    for _ in 0..8 {
        let mut bytes = [0; 8];
        if random.fill(&mut bytes[2..]).is_err() {
            continue;
        }
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
        if !rules.iter().any(|rule| rule.key == key) {
            return Ok(key);
        }
    }
    Err(Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to generate a unique rule key",
    ))
}

async fn rules_list(state: Arc<RoutesState>) -> Response {
    let guard = state.config.read().await;
    Json(normalize(guard.clone()).rules).into_response()
}

async fn rules_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(rule) = serde_json::from_slice::<Rule>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        let mut rule = rule;
        // A client-supplied valid unique key is kept; anything else gets a
        // generated one (fg-admin collection behavior on create).
        if !valid_key(&rule.key) || config.rules.iter().any(|row| row.key == rule.key) {
            rule.key = random_key(&config.rules)?;
        }
        config.rules.push(rule);
        settle(config)?;
        let created = config.rules.last().cloned().expect("just pushed");
        Ok((Json(created), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn rules_copy(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut rule) = serde_json::from_slice::<Rule>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key").into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.rules, &source)?;
        // Copies always receive a generated key (fg-admin collection
        // behavior): the template only determines the insertion position.
        rule.key = random_key(&config.rules)?;
        config.rules.insert(index + 1, rule);
        settle(config)?;
        let created = config.rules[index + 1].clone();
        Ok((Json(created), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn rules_update(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut rule) = serde_json::from_slice::<Rule>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key").into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.rules, &key)?;
        rule.key = key.clone();
        config.rules[index] = rule;
        settle(config)?;
        let replaced = config.rules[index].clone();
        Ok((Json(replaced), true))
    })
    .await
    {
        Ok(replaced) => replaced.into_response(),
        Err(response) => response,
    }
}

async fn rules_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key").into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.rules, &key)?;
        config.rules.remove(index);
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn rules_batch_delete(state: Arc<RoutesState>, body: Bytes) -> Response {
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
        find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let removed: HashSet<_> = keys.iter().map(String::as_str).collect();
        config
            .rules
            .retain(|rule| !removed.contains(rule.key.as_str()));
        let count = keys.len();
        Ok((Json(json!({ "removed": count })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn rules_enable(
    state: Arc<RoutesState>,
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
        let index = locate(&config.rules, &key)?;
        let rule = &mut config.rules[index];
        let changed = rule.enable != enable;
        rule.enable = enable;
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn rules_batch_enable(state: Arc<RoutesState>, body: Bytes) -> Response {
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
        let indices = find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let mut changed = 0;
        for index in indices {
            let rule = &mut config.rules[index];
            if rule.enable != enable {
                rule.enable = enable;
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

async fn rules_order(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        if keys.len() != config.rules.len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once",
            ));
        }
        let Some(indices) = find_indices(&config.rules, &keys) else {
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
                config.rules.swap(index, new);
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

async fn rules_group(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Group { keys, group }) = serde_json::from_slice::<Group>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys",
        )
        .into();
    };
    let name = group.trim().to_owned();
    if name.chars().count() > 64 {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "group name must have at most 64 characters",
        )
        .into();
    }
    match mutate(&state, move |config| {
        let indices = find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let mut changed = false;
        for index in indices {
            let field = &mut config.rules[index].group;
            if *field != name {
                field.clone_from(&name);
                changed = true;
            }
        }
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let guard = state.config.read().await;
    Json(normalize(guard.clone()).settings).into_response()
}

async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    keys: Vec<String>,
    group: String,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use hyper::header::CONTENT_TYPE;
    use hyper_util::rt::TokioIo;

    /// A mounted router over a temp file, counting persist/on_change calls.
    struct Harness {
        addr: std::net::SocketAddr,
        persists: Arc<AtomicUsize>,
        changes: Arc<AtomicUsize>,
        last_saved: Arc<Mutex<Option<FileConfig>>>,
        _dir: tempfile::TempDir,
    }

    async fn harness() -> Harness {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("portforward.json");
        let persists = Arc::new(AtomicUsize::new(0));
        let changes = Arc::new(AtomicUsize::new(0));
        let last_saved: Arc<Mutex<Option<FileConfig>>> = Arc::new(Mutex::new(None));
        let config = Arc::new(RwLock::new(FileConfig::default()));
        let (file, count_persist, slot) = (path.clone(), persists.clone(), last_saved.clone());
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
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
        let state = Arc::new(RoutesState {
            config,
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

        /// POSTs a rule; returns the created rule as JSON.
        async fn create(&self, rule: serde_json::Value) -> serde_json::Value {
            let (status, body) = self
                .send("POST", "/api/portforward/rules", Some(rule))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }

        async fn keys(&self) -> Vec<String> {
            let (_, body) = self.send("GET", "/api/portforward/rules", None).await;
            body.as_array()
                .expect("rules array")
                .iter()
                .map(|rule| rule["key"].as_str().expect("key").to_owned())
                .collect()
        }
    }

    fn base_rule(key: &str) -> serde_json::Value {
        json!({
            "key": key,
            "name": key,
            "enable": false,
            "group": "",
            "protocols": ["tcp"],
            "listen_address": "127.0.0.1",
            "listen_ports": "18080",
            "auto_firewall": false,
            "target_addresses": ["127.0.0.1:9"],
            "target_ports": "9",
            "max_connections": 0,
            "max_conns_per_source": 0,
            "udp_session_timeout": 0,
            "proxy_protocol": "none",
            "remark": ""
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
        let created = app.create(base_rule("")).await;
        assert!(
            is_generated_key(created["key"].as_str().expect("key")),
            "{created}"
        );
        assert_eq!(created["name"], "");
        let (status, rules) = app.send("GET", "/api/portforward/rules", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rules[0]["key"], created["key"]);
        assert_eq!(rules.as_array().expect("array").len(), 1);
        // A valid unique client key is kept; a duplicate one is regenerated.
        let kept = app.create(base_rule("web")).await;
        assert_eq!(kept["key"], "web");
        let clash = app.create(base_rule("web")).await;
        let clash = clash["key"].as_str().expect("key");
        assert!(is_generated_key(clash) && clash != "web", "{clash}");
        assert_eq!(app.persists.load(Ordering::SeqCst), 3);
        assert_eq!(app.changes.load(Ordering::SeqCst), 3);
        let saved = app.last_saved.lock().expect("slot").clone().expect("saved");
        assert_eq!(saved.rules.len(), 3);
        assert!(saved.rules.iter().any(|rule| rule.key == "web"));
    }

    #[tokio::test]
    async fn create_rejects_invalid_rule_with_collected_problems() {
        let app = harness().await;
        let (status, body) = app
            .send(
                "POST",
                "/api/portforward/rules",
                Some(json!({"name": "broken"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let problems = body["problems"].as_array().expect("problems");
        assert!(!problems.is_empty(), "{body}");
        assert!(
            problems
                .iter()
                .any(|p| p["field"].as_str().expect("field").ends_with(".protocols"))
        );
        assert!(problems.iter().any(|p| {
            p["field"]
                .as_str()
                .expect("field")
                .ends_with(".listenPorts")
        }));
        // Nothing was applied or persisted.
        assert!(app.keys().await.is_empty());
        assert_eq!(app.persists.load(Ordering::SeqCst), 0);
        assert_eq!(app.changes.load(Ordering::SeqCst), 0);
        let (status, body) = app
            .send(
                "POST",
                "/api/portforward/rules",
                Some(json!({"protocols": ["bogus"]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
    }

    #[tokio::test]
    async fn copy_inserts_after_source_with_fresh_key() {
        let app = harness().await;
        app.create(base_rule("a")).await;
        let mut template = base_rule("");
        template["name"] = json!("copied");
        let (status, created) = app
            .send(
                "POST",
                "/api/portforward/rules/a/copy",
                Some(template.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let key = created["key"].as_str().expect("key");
        assert!(is_generated_key(key) && key != "a", "{created}");
        assert_eq!(created["name"], "copied");
        assert_eq!(created["listen_ports"], "18080");
        assert_eq!(app.keys().await, vec!["a".to_owned(), key.to_owned()]);
        assert_eq!(app.persists.load(Ordering::SeqCst), 2);
        let (status, _) = app
            .send("POST", "/api/portforward/rules/ghost/copy", Some(template))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_replaces_and_rejects_invalid() {
        let app = harness().await;
        app.create(base_rule("web")).await;
        let mut replacement = base_rule("ignored");
        replacement["listen_ports"] = json!("18081");
        let (status, body) = app
            .send("PUT", "/api/portforward/rules/web", Some(replacement))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["key"], "web");
        assert_eq!(body["listen_ports"], "18081");
        assert_eq!(app.persists.load(Ordering::SeqCst), 2);
        // An invalid replacement is rejected wholesale.
        let before = app.persists.load(Ordering::SeqCst);
        let mut broken = base_rule("web");
        broken["target_addresses"] = json!([]);
        let (status, body) = app
            .send("PUT", "/api/portforward/rules/web", Some(broken))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(!body["problems"].as_array().expect("problems").is_empty());
        assert_eq!(app.persists.load(Ordering::SeqCst), before);
        let (status, rules) = app.send("GET", "/api/portforward/rules", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rules[0]["listen_ports"], "18081");
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/rules/ghost",
                Some(base_rule("ghost")),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
    }

    #[tokio::test]
    async fn delete_single_and_batch() {
        let app = harness().await;
        app.create(base_rule("a")).await;
        app.create(base_rule("b")).await;
        let (status, body) = app.send("DELETE", "/api/portforward/rules/a", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["removed"], 1);
        let (status, body) = app
            .send(
                "POST",
                "/api/portforward/rules-delete",
                Some(json!({"keys": ["b"]})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["removed"], 1);
        assert!(app.keys().await.is_empty());
        let (status, body) = app
            .send(
                "POST",
                "/api/portforward/rules-delete",
                Some(json!({"keys": ["ghost"]})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
        let (status, _) = app
            .send(
                "POST",
                "/api/portforward/rules-delete",
                Some(json!({"keys": []})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn order_requires_complete_list_and_persists() {
        let app = harness().await;
        for key in ["a", "b", "c"] {
            app.create(base_rule(key)).await;
        }
        let persists = app.persists.load(Ordering::SeqCst);
        // Identity order changes nothing.
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/rules-order",
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
                "/api/portforward/rules-order",
                Some(json!({"keys": ["c", "a", "b"]})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(app.keys().await, vec!["c", "a", "b"]);
        assert_eq!(app.persists.load(Ordering::SeqCst), persists + 1);
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/rules-order",
                Some(json!({"keys": ["c", "a"]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "order must include every item once");
        let (status, _) = app
            .send(
                "PUT",
                "/api/portforward/rules-order",
                Some(json!({"keys": ["c", "a", "a"]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = app
            .send(
                "PUT",
                "/api/portforward/rules-order",
                Some(json!({"keys": ["c", "a", "ghost"]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn enable_toggles_single_and_batch() {
        let app = harness().await;
        app.create(base_rule("a")).await;
        app.create(base_rule("b")).await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/rules/a/enable",
                Some(json!({"enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/rules-enable",
                Some(json!({"keys": ["a"], "enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["changed"], 0);
        let unchanged = app.persists.load(Ordering::SeqCst);
        assert_eq!(
            unchanged, 3,
            "two creates plus one enable; no-op adds nothing"
        );
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/rules-enable",
                Some(json!({"keys": ["a", "b"], "enable": false})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["changed"], 1, "a flipped back, b was already off");
        let (_, rules) = app.send("GET", "/api/portforward/rules", None).await;
        assert!(
            rules
                .as_array()
                .expect("rules")
                .iter()
                .all(|rule| rule["enable"] == false)
        );
        let (status, _) = app
            .send(
                "PUT",
                "/api/portforward/rules/ghost/enable",
                Some(json!({"enable": true})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn group_persists_trimmed_name() {
        let app = harness().await;
        app.create(base_rule("a")).await;
        app.create(base_rule("b")).await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/rules-group",
                Some(json!({"keys": ["a", "b"], "group": " dmz "})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        let (_, rules) = app.send("GET", "/api/portforward/rules", None).await;
        assert!(
            rules
                .as_array()
                .expect("rules")
                .iter()
                .all(|rule| rule["group"] == "dmz")
        );
        assert!(
            app.last_saved
                .lock()
                .expect("slot")
                .clone()
                .expect("saved")
                .rules
                .iter()
                .all(|rule| rule.group == "dmz")
        );
        let (status, _) = app
            .send(
                "PUT",
                "/api/portforward/rules-group",
                Some(json!({"keys": ["a"], "group": "x".repeat(65)})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn settings_get_put_apply_defaults_and_clamp() {
        let app = harness().await;
        let (status, settings) = app.send("GET", "/api/portforward/settings", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(settings["enable"], true);
        assert_eq!(settings["default_max_connections"], 256);
        assert_eq!(settings["default_udp_session_timeout"], 60);
        assert_eq!(settings["max_udp_sessions"], 1024);
        assert_eq!(settings["dial_timeout"], 5);
        assert_eq!(settings["first_data_timeout"], 60);
        // Zero-valued fields normalize to the upstream defaults; the
        // clamped candidate is what gets persisted.
        let (status, settings) = app
            .send(
                "PUT",
                "/api/portforward/settings",
                Some(json!({"enable": false, "first_data_timeout": 9999})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{settings}");
        assert_eq!(settings["enable"], false);
        assert_eq!(settings["first_data_timeout"], 3600);
        assert_eq!(settings["default_max_connections"], 256);
        assert_eq!(settings["dial_timeout"], 5);
        let saved = app.last_saved.lock().expect("slot").clone().expect("saved");
        assert_eq!(saved.settings.first_data_timeout, 3600);
        assert_eq!(saved.settings.default_max_connections, 256);
        assert!(!saved.settings.enable);
        assert_eq!(app.changes.load(Ordering::SeqCst), 1);
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/settings",
                Some(json!({"bogus_field": 1})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
    }

    #[tokio::test]
    async fn invalid_json_body_is_bad_request() {
        let app = harness().await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/portforward/rules-order",
                Some(json!({"nope": true})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid JSON body");
        let (status, body) = app
            .send("DELETE", "/api/portforward/rules/bad%2Fkey!", None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid item key");
    }
}
