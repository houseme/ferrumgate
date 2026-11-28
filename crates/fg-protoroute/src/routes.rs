//! Management API, module summary, and Prometheus metrics for protocol
//! routing (WP-35 §4):
//!
//! - `GET|POST /api/protoroute/rules`
//! - `POST /api/protoroute/rules/{key}/copy`
//! - `PUT|DELETE /api/protoroute/rules/{key}`
//! - `PUT /api/protoroute/rules/{key}/enable`
//! - `PUT /api/protoroute/rules-order`
//! - `PUT /api/protoroute/rules-enable`
//! - `PUT /api/protoroute/rules-group`
//! - `POST /api/protoroute/rules-delete`
//! - `GET|PUT /api/protoroute/settings`
//!
//! Persisted as `protoroute.json` via [`fg_config::ConfigStore`]. Metrics
//! (`ferrumgate_protoroute_*`) are exported via [`metrics`] for the global
//! `/api/metrics` endpoint.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use fg_config::ConfigStore;
use fg_core::metrics::Sample;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::model::{FileConfig, Rule, Settings};
use crate::runtime::{Manager, RuleStatus};
use crate::validate;

/// Configuration file stem (`protoroute.json`).
pub const CONFIG_NAME: &str = "protoroute";
/// Maximum keys accepted by batch endpoints (conventions §3.3).
const BATCH_MAX_KEYS: usize = 500;

/// Shared state for the protoroute admin routes.
#[derive(Clone)]
pub struct ApiState {
    store: Arc<ConfigStore>,
    manager: Arc<Manager>,
    write_lock: Arc<Mutex<()>>,
}

impl ApiState {
    pub fn new(store: Arc<ConfigStore>, manager: Arc<Manager>) -> Self {
        Self {
            store,
            manager,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    fn knock_available(&self) -> bool {
        self.manager.deps().knock.is_some()
    }
}

/// Rule serialized together with its read-only runtime status fields.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleView {
    #[serde(flatten)]
    pub rule: Rule,
    pub listening: bool,
    pub listeners: Vec<crate::runtime::ListenerStatus>,
    pub listen_errors: Vec<String>,
    pub route_hits: Vec<u64>,
    pub default_hits: u64,
    pub dropped: u64,
    pub denied: u64,
    pub active_connections: u64,
    pub firewall_status: String,
    pub firewall_failed: bool,
}

impl RuleView {
    fn from_parts(rule: Rule, status: RuleStatus) -> Self {
        Self {
            rule,
            listening: status.listening,
            listeners: status.listeners,
            listen_errors: status.listen_errors,
            route_hits: status.counters.route_hits,
            default_hits: status.counters.default_hits,
            dropped: status.counters.dropped,
            denied: status.counters.denied,
            active_connections: status.counters.active,
            firewall_status: status.firewall_status,
            firewall_failed: status.firewall_failed,
        }
    }
}

/// Module-level overview summary.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub enabled: bool,
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub listening_rules: usize,
    pub active_connections: u64,
    pub total_hits: u64,
    pub total_dropped: u64,
    pub total_denied: u64,
}

/// Computes the module overview summary from live runtime state.
pub async fn summary(manager: &Manager) -> Summary {
    let config = manager.config().await;
    let statuses = manager.all_statuses().await;
    let mut out = Summary {
        enabled: config.settings.enable,
        total_rules: config.rules.len(),
        enabled_rules: config.rules.iter().filter(|r| r.enable).count(),
        ..Summary::default()
    };
    for status in statuses.values() {
        if status.listening {
            out.listening_rules += 1;
        }
        out.active_connections += status.counters.active;
        out.total_hits +=
            status.counters.route_hits.iter().sum::<u64>() + status.counters.default_hits;
        out.total_dropped += status.counters.dropped;
        out.total_denied += status.counters.denied;
    }
    out
}

/// Collects `ferrumgate_protoroute_*` Prometheus samples for global `/api/metrics`.
pub async fn metrics(manager: &Manager) -> Vec<Sample> {
    let config = manager.config().await;
    let statuses = manager.all_statuses().await;

    let mut samples = Vec::new();
    samples.push(Sample::gauge(
        "ferrumgate_protoroute_rules_total",
        "Total configured protocol routing rules",
        config.rules.len() as f64,
    ));
    samples.push(Sample::gauge(
        "ferrumgate_protoroute_rules_enabled",
        "Enabled protocol routing rules",
        config.rules.iter().filter(|r| r.enable).count() as f64,
    ));

    for rule in &config.rules {
        let status = statuses.get(&rule.key).cloned().unwrap_or_default();
        samples.push(
            Sample::gauge(
                "ferrumgate_protoroute_connections_active",
                "Currently active protocol routing connections",
                status.counters.active as f64,
            )
            .label("rule", &rule.key),
        );
        for (idx, route) in rule.routes.iter().enumerate() {
            let hits = status.counters.route_hits.get(idx).copied().unwrap_or(0);
            samples.push(
                Sample::counter(
                    "ferrumgate_protoroute_route_hits_total",
                    "Total connections matched by a protocol route",
                    hits as f64,
                )
                .label("rule", &rule.key)
                .label("route", &route.name)
                .label("protocol", route.protocol.as_str()),
            );
        }
        samples.push(
            Sample::counter(
                "ferrumgate_protoroute_default_hits_total",
                "Total connections forwarded to a rule default target",
                status.counters.default_hits as f64,
            )
            .label("rule", &rule.key),
        );
        samples.push(
            Sample::counter(
                "ferrumgate_protoroute_dropped_total",
                "Total unmatched connections dropped without a default target",
                status.counters.dropped as f64,
            )
            .label("rule", &rule.key),
        );
        samples.push(
            Sample::counter(
                "ferrumgate_protoroute_denied_total",
                "Total connections rejected by source policy, ban, knock or quota",
                status.counters.denied as f64,
            )
            .label("rule", &rule.key),
        );
    }

    samples
}

/// Builds the axum router mounting all `/api/protoroute/*` endpoints (WP-35 §4).
pub fn router(store: Arc<ConfigStore>, manager: Arc<Manager>) -> Router {
    let state = ApiState::new(store, manager);
    Router::new()
        .route("/api/protoroute/rules", get(list_rules).post(create_rule))
        .route("/api/protoroute/rules/{key}/copy", post(copy_rule))
        .route(
            "/api/protoroute/rules/{key}",
            put(update_rule).delete(delete_rule),
        )
        .route("/api/protoroute/rules/{key}/enable", put(enable_rule))
        .route("/api/protoroute/rules-order", put(order_rules))
        .route("/api/protoroute/rules-enable", put(batch_enable_rules))
        .route("/api/protoroute/rules-group", put(batch_group_rules))
        .route("/api/protoroute/rules-delete", post(batch_delete_rules))
        .route(
            "/api/protoroute/settings",
            get(get_settings).put(put_settings),
        )
        .with_state(state)
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }

    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }

    fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        json_response(
            self.status,
            &ErrorBody {
                error: self.message,
            },
        )
    }
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    let mut res = (status, Json(value)).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn ok_json<T: Serialize>(value: &T) -> Response {
    json_response(StatusCode::OK, value)
}

fn created_json<T: Serialize>(value: &T) -> Response {
    json_response(StatusCode::CREATED, value)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnableBody {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysBody {
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchEnableBody {
    keys: Vec<String>,
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchGroupBody {
    keys: Vec<String>,
    group: String,
}

#[derive(Serialize)]
struct DeletedBody {
    deleted: usize,
}

async fn list_rules(State(state): State<ApiState>) -> Response {
    let config = state.manager.config().await;
    let statuses = state.manager.all_statuses().await;
    let views: Vec<RuleView> = config
        .rules
        .into_iter()
        .map(|rule| {
            let status = statuses.get(&rule.key).cloned().unwrap_or_default();
            RuleView::from_parts(rule, status)
        })
        .collect();
    ok_json(&views)
}

async fn create_rule(
    State(state): State<ApiState>,
    Json(mut rule): Json<Rule>,
) -> Result<Response, ApiError> {
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    if rule.key.trim().is_empty() {
        rule.key = generate_unique_key(&config)?;
    }
    let key = rule.key.trim().to_owned();
    config.rules.push(rule);
    let saved = save_and_apply(&state, config).await?;
    let created = saved
        .rules
        .into_iter()
        .find(|r| r.key == key)
        .ok_or_else(|| ApiError::internal("created rule missing"))?;
    let status = state.manager.rule_status(&created.key).await;
    Ok(created_json(&RuleView::from_parts(created, status)))
}

async fn copy_rule(
    State(state): State<ApiState>,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    let Some(orig) = config.rules.iter().find(|r| r.key == key).cloned() else {
        return Err(ApiError::not_found(format!("rule not found: {key}")));
    };
    let mut copy = orig;
    let new_key = generate_unique_key(&config)?;
    copy.key = new_key.clone();
    copy.enable = false;
    copy.name = format!("{} (copy)", copy.name);
    config.rules.push(copy);
    let saved = save_and_apply(&state, config).await?;
    let created = saved
        .rules
        .into_iter()
        .find(|r| r.key == new_key)
        .ok_or_else(|| ApiError::internal("copied rule missing"))?;
    let status = state.manager.rule_status(&created.key).await;
    Ok(created_json(&RuleView::from_parts(created, status)))
}

async fn update_rule(
    State(state): State<ApiState>,
    Path(key): Path<String>,
    Json(mut rule): Json<Rule>,
) -> Result<Response, ApiError> {
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    let Some(slot) = config.rules.iter_mut().find(|r| r.key == key) else {
        return Err(ApiError::not_found(format!("rule not found: {key}")));
    };
    rule.key = key.clone();
    *slot = rule;
    let saved = save_and_apply(&state, config).await?;
    let updated = saved
        .rules
        .into_iter()
        .find(|r| r.key == key)
        .ok_or_else(|| ApiError::internal("updated rule missing"))?;
    let status = state.manager.rule_status(&updated.key).await;
    Ok(ok_json(&RuleView::from_parts(updated, status)))
}

async fn delete_rule(
    State(state): State<ApiState>,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    let before = config.rules.len();
    config.rules.retain(|r| r.key != key);
    if config.rules.len() == before {
        return Err(ApiError::not_found(format!("rule not found: {key}")));
    }
    save_and_apply(&state, config).await?;
    Ok(ok_json(&DeletedBody { deleted: 1 }))
}

async fn enable_rule(
    State(state): State<ApiState>,
    Path(key): Path<String>,
    Json(body): Json<EnableBody>,
) -> Result<Response, ApiError> {
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    let Some(slot) = config.rules.iter_mut().find(|r| r.key == key) else {
        return Err(ApiError::not_found(format!("rule not found: {key}")));
    };
    slot.enable = body.enable;
    let saved = save_and_apply(&state, config).await?;
    let updated = saved
        .rules
        .into_iter()
        .find(|r| r.key == key)
        .ok_or_else(|| ApiError::internal("updated rule missing"))?;
    let status = state.manager.rule_status(&updated.key).await;
    Ok(ok_json(&RuleView::from_parts(updated, status)))
}

async fn order_rules(
    State(state): State<ApiState>,
    Json(body): Json<KeysBody>,
) -> Result<Response, ApiError> {
    check_batch_keys(&body.keys)?;
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    let existing: HashSet<&str> = config.rules.iter().map(|r| r.key.as_str()).collect();
    for key in &body.keys {
        if !existing.contains(key.as_str()) {
            return Err(ApiError::not_found(format!("rule not found: {key}")));
        }
    }
    let mut by_key: std::collections::HashMap<String, Rule> =
        config.rules.drain(..).map(|r| (r.key.clone(), r)).collect();
    let mut reordered = Vec::with_capacity(by_key.len());
    for key in body.keys {
        if let Some(rule) = by_key.remove(&key) {
            reordered.push(rule);
        }
    }
    // Keep any omitted rules at the tail in deterministic order.
    let mut rest: Vec<Rule> = by_key.into_values().collect();
    rest.sort_by(|a, b| a.key.cmp(&b.key));
    reordered.extend(rest);
    config.rules = reordered;

    let saved = save_and_apply(&state, config).await?;
    let statuses = state.manager.all_statuses().await;
    let views: Vec<RuleView> = saved
        .rules
        .into_iter()
        .map(|rule| {
            let status = statuses.get(&rule.key).cloned().unwrap_or_default();
            RuleView::from_parts(rule, status)
        })
        .collect();
    Ok(ok_json(&views))
}

async fn batch_enable_rules(
    State(state): State<ApiState>,
    Json(body): Json<BatchEnableBody>,
) -> Result<Response, ApiError> {
    check_batch_keys(&body.keys)?;
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    ensure_all_keys_exist(&config, &body.keys)?;
    let targets: HashSet<&str> = body.keys.iter().map(String::as_str).collect();
    for rule in &mut config.rules {
        if targets.contains(rule.key.as_str()) {
            rule.enable = body.enable;
        }
    }
    let saved = save_and_apply(&state, config).await?;
    let statuses = state.manager.all_statuses().await;
    let views: Vec<RuleView> = saved
        .rules
        .into_iter()
        .map(|rule| {
            let status = statuses.get(&rule.key).cloned().unwrap_or_default();
            RuleView::from_parts(rule, status)
        })
        .collect();
    Ok(ok_json(&views))
}

async fn batch_group_rules(
    State(state): State<ApiState>,
    Json(body): Json<BatchGroupBody>,
) -> Result<Response, ApiError> {
    check_batch_keys(&body.keys)?;
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    ensure_all_keys_exist(&config, &body.keys)?;
    let targets: HashSet<&str> = body.keys.iter().map(String::as_str).collect();
    for rule in &mut config.rules {
        if targets.contains(rule.key.as_str()) {
            rule.group = body.group.clone();
        }
    }
    let saved = save_and_apply(&state, config).await?;
    let statuses = state.manager.all_statuses().await;
    let views: Vec<RuleView> = saved
        .rules
        .into_iter()
        .map(|rule| {
            let status = statuses.get(&rule.key).cloned().unwrap_or_default();
            RuleView::from_parts(rule, status)
        })
        .collect();
    Ok(ok_json(&views))
}

async fn batch_delete_rules(
    State(state): State<ApiState>,
    Json(body): Json<KeysBody>,
) -> Result<Response, ApiError> {
    check_batch_keys(&body.keys)?;
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    ensure_all_keys_exist(&config, &body.keys)?;
    let targets: HashSet<&str> = body.keys.iter().map(String::as_str).collect();
    let before = config.rules.len();
    config.rules.retain(|r| !targets.contains(r.key.as_str()));
    let deleted = before - config.rules.len();
    save_and_apply(&state, config).await?;
    Ok(ok_json(&DeletedBody { deleted }))
}

async fn get_settings(State(state): State<ApiState>) -> Response {
    let config = state.manager.config().await;
    ok_json(&config.settings)
}

async fn put_settings(
    State(state): State<ApiState>,
    Json(settings): Json<Settings>,
) -> Result<Response, ApiError> {
    let _guard = state.write_lock.lock().await;
    let mut config = state.manager.config().await;
    config.settings = settings;
    let saved = save_and_apply(&state, config).await?;
    Ok(ok_json(&saved.settings))
}

fn check_batch_keys(keys: &[String]) -> Result<(), ApiError> {
    if keys.len() > BATCH_MAX_KEYS {
        return Err(ApiError::bad_request(format!(
            "batch request supports at most {BATCH_MAX_KEYS} keys"
        )));
    }
    Ok(())
}

fn ensure_all_keys_exist(config: &FileConfig, keys: &[String]) -> Result<(), ApiError> {
    let existing: HashSet<&str> = config.rules.iter().map(|r| r.key.as_str()).collect();
    for key in keys {
        if !existing.contains(key.as_str()) {
            return Err(ApiError::not_found(format!("rule not found: {key}")));
        }
    }
    Ok(())
}

async fn save_and_apply(state: &ApiState, config: FileConfig) -> Result<FileConfig, ApiError> {
    let normalized = validate::normalize(config);
    let problems = validate::validate_with_caps(&normalized, state.knock_available());
    if !problems.is_empty() {
        let joined = problems
            .iter()
            .map(|p| format!("{}: {}", p.field, p.reason))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ApiError::bad_request(joined));
    }
    state
        .store
        .save(CONFIG_NAME, &normalized)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;
    state
        .manager
        .apply(normalized.clone())
        .await
        .map_err(|e| ApiError::internal(format!("apply config: {e}")))?;
    Ok(normalized)
}

/// Generates a 12-character lower-case hex identifier (6 random bytes,
/// conventions §3.3) that does not collide with existing rule keys.
fn generate_unique_key(config: &FileConfig) -> Result<String, ApiError> {
    let existing: HashSet<&str> = config.rules.iter().map(|r| r.key.as_str()).collect();
    for _ in 0..16 {
        let mut raw = [0u8; 6];
        getrandom::fill(&mut raw).map_err(|e| ApiError::internal(format!("generate key: {e}")))?;
        let mut key = String::with_capacity(12);
        for byte in raw {
            use std::fmt::Write as _;
            let _ = write!(key, "{byte:02x}");
        }
        if !existing.contains(key.as_str()) {
            return Ok(key);
        }
    }
    Err(ApiError::internal("failed to allocate unique rule key"))
}
