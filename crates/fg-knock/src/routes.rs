//! Knock management routes (WP-54 §4): the rule collection (identities
//! are saved with their rule), secrets, status, grant revocation,
//! firewall view and settings — served with plain axum while mirroring
//! the fg-admin `Collection<T>` contract (JSON shapes, status codes, key
//! handling), like the fg-guard and fg-cron module routes.
//!
//! Endpoints (permission domain `knock`; the 4 generic log endpoints
//! `GET|DELETE /api/knock/logs`, `GET /api/knock/logs/export`,
//! `GET /api/knock/logs/sources` are served by fg-admin and not mounted
//! here; 20 upstream operations − 4 logs = 16):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/knock/rules` | — | `[Rule]` with masked keys |
//! | POST | `/api/knock/rules` | `Rule` | created `Rule` (fresh key if invalid/duplicate) |
//! | POST | `/api/knock/rules/{key}/copy` | `Rule` | created `Rule` (fresh key **and fresh key material**, inserted after the source) |
//! | PUT | `/api/knock/rules/{key}` | `Rule` | replaced `Rule` |
//! | DELETE | `/api/knock/rules/{key}` | — | `{"removed":1}` or `409` with the referencing modules |
//! | PUT | `/api/knock/rules/{key}/enable` | `{"enable":bool}` | `{"ok":true}` (conflict-checked) |
//! | PUT | `/api/knock/rules-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/knock/rules-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/knock/rules-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | POST | `/api/knock/rules-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | GET | `/api/knock/rules/{key}/secrets` | — | plaintext rule + identity keys (write permission in fg-admin; the client dialog builds commands locally) |
//! | GET | `/api/knock/status` | — | settings summary, counters, grant list |
//! | DELETE | `/api/knock/grants` | query: `rule`, `addr` (both optional) | `{"removed":N}` |
//! | GET | `/api/knock/firewall/rules` | — | injected firewall view |
//! | GET | `/api/knock/settings` | — | normalized `Settings` |
//! | PUT | `/api/knock/settings` | `Settings` | normalized `Settings` |
//!
//! Every mutation follows the fg-admin commit order: normalize → validate
//! → persist `knock.json` → publish the in-memory snapshot → apply to the
//! engine (key set rebuild + grant revocation). Validation problems come
//! back as `400` `{"error":…,"problems":[…]}`. Secrets are masked as
//! `********` in list output; submitting `********` keeps the stored
//! value. Authentication is applied by the surrounding management router.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, rejection::PathRejection, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use crate::engine::Engine;
use crate::model::{Access, FileConfig, Rule, Settings, limits};
use crate::validate::{self, Problem};

/// Writes the whole [`FileConfig`] to `knock.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Called after a successful persist with (old, new); the assembler wires
/// this to `Engine::apply_config`.
pub type OnChangeFn = Arc<dyn Fn(&FileConfig, &FileConfig) + Send + Sync>;

/// Read-only view of the firewall windows the injected hook maintains
/// (`GET /api/knock/firewall/rules`; wiring point for WP-51).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRuleView {
    pub rule: String,
    pub ports: Vec<Access>,
    /// Backend text as reported by the hook (empty while unwired).
    pub state: String,
}

/// Shared state behind the knock management routes.
pub struct RoutesState {
    /// The live desired snapshot (already normalized once loaded).
    pub config: Arc<RwLock<FileConfig>>,
    pub persist: PersistFn,
    /// Called after a successful persist with (old, new).
    pub on_change: OnChangeFn,
    pub engine: Arc<Engine>,
    /// Rule references from other modules (delete protection).
    pub references: Option<crate::SharedFn<String, Vec<String>>>,
    /// Ports occupied by protocol-routing `spa` routes (conflict check).
    pub spa_ports: Option<crate::SharedFn<(), Vec<Access>>>,
    /// Firewall window view (status page).
    pub firewall_rules: Option<crate::SharedFn<(), Vec<FirewallRuleView>>>,
}

impl RoutesState {
    /// The protocol-routing ports for conflict checks (empty unwired).
    pub async fn spa_ports(&self) -> Vec<Access> {
        match &self.spa_ports {
            Some(hook) => hook(()).await.unwrap_or_default(),
            None => Vec::new(),
        }
    }
}

/// Adds the knock management routes to `router`.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create) = (state.clone(), state.clone());
    let (replace, remove) = (state.clone(), state.clone());
    let (copy, enable) = (state.clone(), state.clone());
    let (order, batch_enable) = (state.clone(), state.clone());
    let (group, batch_delete) = (state.clone(), state.clone());
    let (secrets, status) = (state.clone(), state.clone());
    let (revoke, firewall) = (state.clone(), state.clone());
    let (settings_get, settings_put) = (state.clone(), state);
    router
        .route(
            "/api/knock/rules",
            get(move || async move { rules_list(list).await })
                .post(move |body: Bytes| async move { rules_create(create, body).await }),
        )
        .route(
            "/api/knock/rules/{key}",
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
            "/api/knock/rules/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rules_copy(copy, path, body).await
                },
            ),
        )
        .route(
            "/api/knock/rules/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rules_enable(enable, path, body).await
                },
            ),
        )
        .route(
            "/api/knock/rules/{key}/secrets",
            get(
                move |path: Result<Path<String>, PathRejection>| async move {
                    rules_secrets(secrets, path).await
                },
            ),
        )
        .route(
            "/api/knock/rules-order",
            put(move |body: Bytes| async move { rules_order(order, body).await }),
        )
        .route(
            "/api/knock/rules-enable",
            put(move |body: Bytes| async move { rules_batch_enable(batch_enable, body).await }),
        )
        .route(
            "/api/knock/rules-group",
            put(move |body: Bytes| async move { rules_group(group, body).await }),
        )
        .route(
            "/api/knock/rules-delete",
            post(move |body: Bytes| async move { rules_batch_delete(batch_delete, body).await }),
        )
        .route(
            "/api/knock/status",
            get(move || async move { status_view(status).await }),
        )
        .route(
            "/api/knock/grants",
            delete(
                move |query: Result<Query<RevokeQuery>, QueryRejection>| async move {
                    grants_revoke(revoke, query).await
                },
            ),
        )
        .route(
            "/api/knock/firewall/rules",
            get(move || async move { firewall_rules_view(firewall).await }),
        )
        .route(
            "/api/knock/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
}

/// A failed mutation: a plain status/message pair shaped like the fg-admin
/// `ApiError` body, or the collected validation problems.
#[derive(Debug)]
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
                    "error": "invalid knock configuration",
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
/// normalized candidate before publishing it, and applies it to the engine
/// afterwards (mirrors the fg-admin `Collection::change` commit order: a
/// failed write leaves the desired state untouched). The change closure is
/// synchronous; the protocol-routing ports for conflict checks are fetched
/// up front.
#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: &RoutesState,
    change: impl FnOnce(&mut FileConfig, &[Access]) -> Change<T> + Send,
) -> Result<T, Response> {
    let spa_ports = state.spa_ports().await;
    let mut guard = state.config.write().await;
    let old = guard.clone();
    let mut candidate = old.clone();
    let (value, changed) = change(&mut candidate, &spa_ports).map_err(Response::from)?;
    if changed {
        let persist = state.persist.clone();
        let saved = candidate.clone();
        tokio::task::spawn_blocking(move || persist(&saved))
            .await
            .map_err(|_| internal())?
            .map_err(|error| {
                tracing::warn!(%error, "persisting knock.json failed");
                internal()
            })?;
        *guard = candidate.clone();
        drop(guard);
        (state.on_change)(&old, &candidate);
        return Ok(value);
    }
    drop(guard);
    Ok(value)
}

fn internal() -> Response {
    Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "configuration operation failed".into(),
    )
    .into_response()
}

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body".to_owned()).into_response()
}

fn invalid_key() -> Failure {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into())
}

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found".into())
}

/// Applies defaults and collects every validation problem.
#[allow(clippy::result_large_err)]
fn settle(config: &mut FileConfig, spa_ports: &[Access]) -> Result<(), Failure> {
    *config = validate::normalize(std::mem::take(config));
    let problems = validate::validate_with(config, spa_ports);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Failure::Problems(problems))
    }
}

fn locate(rules: &[Rule], key: &str) -> Result<usize, Failure> {
    rules
        .iter()
        .position(|rule| rule.key == key)
        .ok_or_else(missing_item)
}

fn valid_key(key: &str) -> bool {
    validate::valid_key(key)
}

#[allow(clippy::result_large_err)]
fn batch_keys(mut keys: Vec<String>) -> Result<Vec<String>, Failure> {
    if keys.is_empty() || keys.len() > 500 || !keys.iter().all(|key| valid_key(key)) {
        return Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        ));
    }
    let mut seen = HashSet::new();
    keys.retain(|key| seen.insert(key.clone()));
    Ok(keys)
}

/// 12 lowercase hex characters, unique within the collection.
#[allow(clippy::result_large_err)]
fn random_key(rules: &[Rule]) -> Result<String, Failure> {
    for _ in 0..8 {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes[2..]).map_err(|_| {
            Failure::Api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key generation failed".into(),
            )
        })?;
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
        if !rules.iter().any(|rule| rule.key == key) {
            return Ok(key);
        }
    }
    Err(Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to generate a unique rule key".into(),
    ))
}

/// One fresh key pair, base64 (32 / 64 bytes like `fwknop -k`).
fn generate_pair() -> (String, String) {
    let mut enc = vec![0u8; limits::GENERATED_ENC_KEY_BYTES];
    let mut hmac = vec![0u8; limits::GENERATED_HMAC_KEY_BYTES];
    let _ = getrandom::fill(&mut enc);
    let _ = getrandom::fill(&mut hmac);
    let engine = base64::engine::general_purpose::STANDARD;
    (engine.encode(enc), engine.encode(hmac))
}

/// Masks secret fields for list output (`********`).
fn masked(mut rule: Rule) -> Rule {
    if !rule.enc_key.is_empty() {
        rule.enc_key = MASK.to_owned();
    }
    if !rule.hmac_key.is_empty() {
        rule.hmac_key = MASK.to_owned();
    }
    for identity in &mut rule.identities {
        if !identity.enc_key.is_empty() {
            identity.enc_key = MASK.to_owned();
        }
        if !identity.hmac_key.is_empty() {
            identity.hmac_key = MASK.to_owned();
        }
    }
    rule
}

/// `********` submitted in a secrets field keeps the stored value.
fn unmask(rule: &mut Rule, stored: &Rule) {
    if rule.enc_key == MASK || rule.enc_key.is_empty() {
        rule.enc_key = stored.enc_key.clone();
    }
    if rule.hmac_key == MASK || rule.hmac_key.is_empty() {
        rule.hmac_key = stored.hmac_key.clone();
    }
    for identity in &mut rule.identities {
        if let Some(previous) = stored
            .identities
            .iter()
            .find(|known| known.id == identity.id)
        {
            if identity.enc_key == MASK || identity.enc_key.is_empty() {
                identity.enc_key = previous.enc_key.clone();
            }
            if identity.hmac_key == MASK || identity.hmac_key.is_empty() {
                identity.hmac_key = previous.hmac_key.clone();
            }
        }
    }
}

const MASK: &str = "********";

async fn rules_list(state: Arc<RoutesState>) -> Response {
    let guard = state.config.read().await;
    let config = validate::normalize(guard.clone());
    Json(
        config
            .rules
            .iter()
            .map(|rule| masked(rule.clone()))
            .collect::<Vec<_>>(),
    )
    .into_response()
}

async fn rules_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(mut rule) = serde_json::from_slice::<Rule>(&body) else {
        return decode_error();
    };
    let result = mutate(&state, |config, spa_ports| {
        // A client-supplied valid unique key is kept; anything else gets a
        // generated one (fg-admin collection behavior on create).
        if !valid_key(&rule.key) || config.rules.iter().any(|row| row.key == rule.key) {
            rule.key = random_key(&config.rules)?;
        }
        config.rules.push(rule);
        settle(config, spa_ports)?;
        let created = masked(config.rules.last().cloned().expect("just pushed"));
        Ok((Json(created), true))
    })
    .await;
    match result {
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
    let Ok(Path(key)) = path else {
        return invalid_key().into();
    };
    if !valid_key(&key) {
        return invalid_key().into();
    }
    let result = mutate(&state, |config, spa_ports| {
        let index = locate(&config.rules, &key)?;
        unmask(&mut rule, &config.rules[index]);
        rule.key = key.clone();
        config.rules[index] = rule;
        settle(config, spa_ports)?;
        let replaced = masked(config.rules[index].clone());
        Ok((Json(replaced), true))
    })
    .await;
    match result {
        Ok(replaced) => replaced.into_response(),
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
    let Ok(Path(source)) = path else {
        return invalid_key().into();
    };
    if !valid_key(&source) {
        return invalid_key().into();
    }
    let result = mutate(&state, |config, spa_ports| {
        let index = locate(&config.rules, &source)?;
        // Copies always receive a generated key AND fresh key material
        // (WP-54 §3.3: "复制规则会生成新密钥").
        rule.key = random_key(&config.rules)?;
        let (enc, hmac) = generate_pair();
        rule.enc_key = enc;
        rule.hmac_key = hmac;
        for identity in &mut rule.identities {
            if !identity.enc_key.is_empty() || !identity.hmac_key.is_empty() {
                let (enc, hmac) = generate_pair();
                identity.enc_key = enc;
                identity.hmac_key = hmac;
            }
        }
        config.rules.insert(index + 1, rule);
        settle(config, spa_ports)?;
        let created = masked(config.rules[index + 1].clone());
        Ok((Json(created), true))
    })
    .await;
    match result {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

/// The referencing modules of one rule (delete protection, WP-54 §3.3).
async fn references_of(state: &RoutesState, key: &str) -> Vec<String> {
    match &state.references {
        Some(hook) => hook(key.to_owned()).await.unwrap_or_default(),
        None => Vec::new(),
    }
}

async fn rules_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(Path(key)) = path else {
        return invalid_key().into();
    };
    if !valid_key(&key) {
        return invalid_key().into();
    }
    let references = references_of(&state, &key).await;
    if !references.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "规则被其他模块引用，无法删除",
                "referencedBy": references,
            })),
        )
            .into_response();
    }
    let result = mutate(&state, |config, _| {
        let index = locate(&config.rules, &key)?;
        config.rules.remove(index);
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await;
    match result {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Enable {
    enable: bool,
}

async fn rules_enable(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(Enable { enable }) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(Path(key)) = path else {
        return invalid_key().into();
    };
    if !valid_key(&key) {
        return invalid_key().into();
    }
    let result = mutate(&state, |config, spa_ports| {
        let index = locate(&config.rules, &key)?;
        let rule = &mut config.rules[index];
        let changed = rule.enable != enable;
        rule.enable = enable;
        settle(config, spa_ports)?;
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await;
    match result {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Order {
    keys: Vec<String>,
}

async fn rules_order(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Order { keys }) = serde_json::from_slice::<Order>(&body) else {
        return decode_error();
    };
    let result = mutate(&state, |config, _| {
        let order = batch_keys(keys.clone())?;
        // The full ordered list must reference every rule exactly once.
        let requested: HashSet<&str> = order.iter().map(String::as_str).collect();
        if order.len() != config.rules.len()
            || config
                .rules
                .iter()
                .any(|rule| !requested.contains(rule.key.as_str()))
        {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "keys must list every rule exactly once".into(),
            ));
        }
        config.rules.sort_by_key(|rule| {
            order
                .iter()
                .position(|key| key == &rule.key)
                .unwrap_or(usize::MAX)
        });
        Ok((Json(json!({ "ok": true })), true))
    })
    .await;
    match result {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchEnable {
    keys: Vec<String>,
    enable: bool,
}

async fn rules_batch_enable(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(BatchEnable { keys, enable }) = serde_json::from_slice::<BatchEnable>(&body) else {
        return decode_error();
    };
    let result = mutate(&state, |config, spa_ports| {
        let keys = batch_keys(keys.clone())?;
        let mut changed = 0;
        for key in &keys {
            if let Some(rule) = config.rules.iter_mut().find(|rule| &rule.key == key)
                && rule.enable != enable
            {
                rule.enable = enable;
                changed += 1;
            }
        }
        settle(config, spa_ports)?;
        Ok((Json(json!({ "changed": changed })), changed > 0))
    })
    .await;
    match result {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Group {
    keys: Vec<String>,
    group: String,
}

async fn rules_group(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Group { keys, group }) = serde_json::from_slice::<Group>(&body) else {
        return decode_error();
    };
    if group.chars().count() > limits::GROUP_MAX_CHARS {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            format!("分组最多 {} 个字符", limits::GROUP_MAX_CHARS),
        )
        .into();
    }
    let result = mutate(&state, |config, spa_ports| {
        let keys = batch_keys(keys.clone())?;
        let mut changed = 0;
        for key in &keys {
            if let Some(rule) = config.rules.iter_mut().find(|rule| &rule.key == key)
                && rule.group != group
            {
                rule.group = group.clone();
                changed += 1;
            }
        }
        settle(config, spa_ports)?;
        Ok((Json(json!({ "ok": true })), changed > 0))
    })
    .await;
    match result {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchDelete {
    keys: Vec<String>,
}

async fn rules_batch_delete(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(BatchDelete { keys }) = serde_json::from_slice::<BatchDelete>(&body) else {
        return decode_error();
    };
    // Reference checks run before the mutation so every key is validated
    // first (all-or-nothing, like the fg-admin batch operations).
    for key in &keys {
        if !valid_key(key) {
            return invalid_key().into();
        }
        let references = references_of(&state, key).await;
        if !references.is_empty() {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "规则被引用，无法删除",
                    "referencedBy": format!("{key}: {}", references.join(", ")),
                })),
            )
                .into_response();
        }
    }
    let result = mutate(&state, |config, spa_ports| {
        let keys = batch_keys(keys.clone())?;
        let before = config.rules.len();
        config.rules.retain(|rule| !keys.contains(&rule.key));
        let removed = before - config.rules.len();
        settle(config, spa_ports)?;
        Ok((Json(json!({ "removed": removed })), removed > 0))
    })
    .await;
    match result {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

/// Plaintext keys for the client dialog (write permission in fg-admin;
/// commands and stanzas are generated locally by the UI from
/// [`crate::client`]).
async fn rules_secrets(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(Path(key)) = path else {
        return invalid_key().into();
    };
    let guard = state.config.read().await;
    let Ok(index) = locate(&guard.rules, &key) else {
        return missing_item().into();
    };
    let rule = &guard.rules[index];
    let identities: Vec<_> = rule
        .identities
        .iter()
        .map(|identity| {
            json!({
                "id": identity.id,
                "name": identity.name,
                "enable": identity.enable,
                "encKey": identity.enc_key,
                "hmacKey": identity.hmac_key,
            })
        })
        .collect();
    Json(json!({
        "key": rule.key,
        "name": rule.name,
        "hmacType": rule.hmac_type,
        "encKey": rule.enc_key,
        "hmacKey": rule.hmac_key,
        "sharedKeyOff": rule.shared_key_off,
        "identities": identities,
    }))
    .into_response()
}

async fn status_view(state: Arc<RoutesState>) -> Response {
    let now = state.engine.now();
    let stats = state.engine.stats(now);
    let config = state.config.read().await;
    let settings = &config.settings;
    let snapshot = state.engine.snapshot();
    Json(json!({
        "port": settings.port,
        "maxAge": settings.max_age,
        "autoFirewall": settings.auto_firewall,
        "allowLan": settings.allow_lan,
        "rules": config.rules.len(),
        "enabledRules": config.rules.iter().filter(|rule| rule.enable).count(),
        "keys": snapshot.keys.len(),
        "opened": stats.opened,
        "rejected": stats.rejected,
        "invalid": stats.invalid,
        "ignored": stats.ignored,
        "rateLimited": stats.rate_limited,
        "failedEvents": stats.failed_events,
        "rateSources": stats.rate_sources,
        "replayCache": stats.replay_cache,
        "grants": state.engine.grants().list(now),
        "grantCount": stats.grants,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct RevokeQuery {
    rule: Option<String>,
    addr: Option<String>,
}

async fn grants_revoke(
    state: Arc<RoutesState>,
    query: Result<Query<RevokeQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = query else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid query".to_owned()).into();
    };
    let grants = state.engine.grants();
    let removed = if let Some(rule) = params.rule.as_deref().filter(|rule| !rule.is_empty()) {
        grants.revoke_rule(rule)
    } else if let Some(addr) = params.addr.as_deref().filter(|addr| !addr.is_empty()) {
        match addr.parse::<std::net::IpAddr>() {
            Ok(addr) => grants.revoke_addr(addr),
            Err(_) => {
                return Failure::Api(StatusCode::BAD_REQUEST, "invalid address".to_owned()).into();
            }
        }
    } else {
        grants.clear()
    };
    Json(json!({ "removed": removed })).into_response()
}

async fn firewall_rules_view(state: Arc<RoutesState>) -> Response {
    let rules = match &state.firewall_rules {
        Some(hook) => hook(()).await.unwrap_or_default(),
        None => Vec::new(),
    };
    Json(json!({ "rules": rules })).into_response()
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let guard = state.config.read().await;
    Json(validate::normalize(guard.clone()).settings).into_response()
}

async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<Settings>(&body) else {
        return decode_error();
    };
    let result = mutate(&state, |config, spa_ports| {
        config.settings = settings;
        settle(config, spa_ports)?;
        let normalized = validate::normalize(config.clone()).settings;
        Ok((Json(normalized), true))
    })
    .await;
    match result {
        Ok(saved) => saved.into_response(),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_and_unmask_roundtrip_secrets() {
        let mut rule = Rule {
            key: "a1b2c3d4e5f6".into(),
            enc_key: "real-enc".into(),
            hmac_key: "real-hmac".into(),
            ..Rule::default()
        };
        rule.identities.push(crate::model::Identity {
            id: "alice".into(),
            name: "Alice".into(),
            enable: true,
            enc_key: "alice-enc".into(),
            hmac_key: "alice-hmac".into(),
            remark: String::new(),
        });
        let shown = masked(rule.clone());
        assert_eq!(shown.enc_key, MASK);
        assert_eq!(shown.identities[0].hmac_key, MASK);
        // A client echoing the mask keeps the stored value.
        let mut submitted = shown.clone();
        unmask(&mut submitted, &rule);
        assert_eq!(submitted.enc_key, "real-enc");
        assert_eq!(submitted.identities[0].enc_key, "alice-enc");
        // An empty submitted key also keeps the stored value.
        let mut submitted = shown;
        submitted.enc_key.clear();
        submitted.identities[0].enc_key.clear();
        unmask(&mut submitted, &rule);
        assert_eq!(submitted.enc_key, "real-enc");
        assert_eq!(submitted.identities[0].enc_key, "alice-enc");
    }

    #[test]
    fn batch_keys_enforce_collection_contract() {
        assert!(
            batch_keys(vec!["a".into(); 501]).is_err(),
            "over 500 keys rejected"
        );
        assert!(batch_keys(vec![]).is_err());
        assert!(batch_keys(vec!["bad key".into()]).is_err());
        let keys = batch_keys(vec!["a".into(), "b".into(), "a".into()]).unwrap();
        assert_eq!(keys, vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn random_key_matches_collection_shape() {
        let rules = vec![Rule {
            key: "a1b2c3d4e5f6".into(),
            ..Rule::default()
        }];
        let key = random_key(&rules).unwrap();
        assert_eq!(key.len(), 12);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!rules.iter().any(|rule| rule.key == key));
    }
}
