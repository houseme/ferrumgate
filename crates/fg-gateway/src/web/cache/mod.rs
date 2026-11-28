//! In-memory HTTP response cache (WP-27): cache keys, request/response
//! cacheability predicates, per-path rules, bounded byte-budget LRU storage,
//! and management API routes (`GET /api/webservice/cache`,
//! `POST /api/webservice/cache/purge`).

pub mod key;
pub mod rule;
pub mod store;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub use key::{
    CREDENTIAL_HEADERS, CREDENTIAL_QUERY_PARAMS, CacheKey, OwnCookiePolicy, compute_freshness,
    has_special_path_bytes, is_request_cacheable, is_response_cacheable, response_varies_on_origin,
};
pub use rule::{
    CacheRule, MAX_CACHE_RULES, MAX_CACHE_TTL, match_rule_path, normalize_path, select_rule,
    validate_rule_path, validate_rules, wildcard_match,
};
pub use store::{
    Age, CacheConfig, CacheStats, DEFAULT_MAX_MB, Entry, MAX_ENTRY_BYTES, MAX_MAX_MB, MIN_MAX_MB,
    ResponseCache, X_CACHE, apply_cache_hit_headers, apply_cache_miss_header, apply_cors_headers,
    strip_cors_headers,
};

/// Default site key used when `site` is omitted or empty in cache API requests.
pub const DEFAULT_SITE_KEY: &str = "default";

/// Live registry mapping `(listener_key, site_key)` to its running
/// [`ResponseCache`] instance.
///
/// A listener/site absent from the registry (e.g. listener stopped or site does
/// not exist) produces `404 Not Found` on the cache API endpoints.
#[derive(Default)]
pub struct CacheRegistry {
    caches: RwLock<HashMap<(String, String), Arc<ResponseCache>>>,
}

impl CacheRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers (or replaces) the live cache handle for `(listener, site)`.
    pub fn register(
        &self,
        listener: impl Into<String>,
        site: impl Into<String>,
        cache: Arc<ResponseCache>,
    ) {
        self.caches
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((listener.into(), site.into()), cache);
    }

    /// Removes a listener's caches (e.g. when the listener stops).
    pub fn unregister_listener(&self, listener: &str) {
        self.caches
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(l, _), _| l != listener);
    }

    /// Looks up a running site's cache handle.
    pub fn get(&self, listener: &str, site: &str) -> Option<Arc<ResponseCache>> {
        let site_key = if site.is_empty() {
            DEFAULT_SITE_KEY
        } else {
            site
        };
        self.caches
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(listener.to_owned(), site_key.to_owned()))
            .cloned()
    }
}

fn parse_cache_status_query(uri: &Uri) -> (String, String) {
    let mut listener = String::new();
    let mut site = String::new();
    if let Some(q) = uri.query() {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_k, raw_v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = percent_encoding::percent_decode_str(raw_k).decode_utf8_lossy();
            let v = percent_encoding::percent_decode_str(raw_v).decode_utf8_lossy();
            if k == "listener" {
                listener = v.into_owned();
            } else if k == "site" {
                site = v.into_owned();
            }
        }
    }
    (listener, site)
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct CachePurgeRequest {
    listener: String,
    site: String,
    path: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CachePurgeResponse {
    pub removed: usize,
    pub enabled: bool,
    pub entries: usize,
    pub bytes: usize,
    pub max_bytes: usize,
}

/// Mounts the WP-27 response cache management routes:
/// - `GET /api/webservice/cache?listener=&site=`
/// - `POST /api/webservice/cache/purge`
pub fn mount_cache_routes(router: Router, registry: Arc<CacheRegistry>) -> Router {
    let api = Router::new()
        .route("/api/webservice/cache", get(handle_cache_status))
        .route("/api/webservice/cache/purge", post(handle_cache_purge))
        .with_state(registry);
    router.merge(api)
}

async fn handle_cache_status(State(registry): State<Arc<CacheRegistry>>, uri: Uri) -> Response {
    let (listener, site) = parse_cache_status_query(&uri);
    let Some(cache) = registry.get(&listener, &site) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "listener or site not running" })),
        )
            .into_response();
    };
    (StatusCode::OK, Json(cache.stats())).into_response()
}

async fn handle_cache_purge(
    State(registry): State<Arc<CacheRegistry>>,
    body: Result<Json<CachePurgeRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(req)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid cache purge request body" })),
        )
            .into_response();
    };
    let Some(cache) = registry.get(&req.listener, &req.site) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "listener or site not running" })),
        )
            .into_response();
    };
    if !cache.is_enabled() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "cache is not enabled for this site" })),
        )
            .into_response();
    }
    let removed = if req.path.trim().is_empty() {
        cache.purge_all()
    } else {
        if let Err(err) = validate_rule_path(&req.path) {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": err }))).into_response();
        }
        cache.purge_path(&req.path)
    };
    let stats = cache.stats();
    (
        StatusCode::OK,
        Json(CachePurgeResponse {
            removed,
            enabled: stats.enabled,
            entries: stats.entries,
            bytes: stats.bytes,
            max_bytes: stats.max_bytes,
        }),
    )
        .into_response()
}
