//! Public address lookup with in-memory caching: `GET` reads the last
//! result without any outbound request, `POST` refreshes it (admin
//! sessions only). Concurrent refreshes share one lookup; results within
//! ten seconds are served from the cache.

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{Json, http::Method};
use schemars::JsonSchema;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::{ApiRouter, RouteModels};
use fg_core::check::BoxFut;

/// Repeated refreshes within this window return the cached result.
pub const MIN_INTERVAL: Duration = Duration::from_secs(10);
/// One refresh resolves both families within this budget.
const LOOKUP_BUDGET: Duration = Duration::from_secs(30);

/// One address family of the lookup.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

/// Performs one lookup for a family; tests replace this.
pub type Lookup = Arc<dyn Fn(Family) -> BoxFut<'static, Result<IpAddr, String>> + Send + Sync>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicIpResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<IpAddr>,
    /// Failure reasons keyed by family ("ipv4" / "ipv6").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
}

struct Inner {
    last: Option<(PublicIpResult, SystemTime)>,
}

pub struct PublicIpCache {
    lookup: Lookup,
    inner: Mutex<Inner>,
}

impl PublicIpCache {
    pub fn new(lookup: Lookup) -> Self {
        Self {
            lookup,
            inner: Mutex::new(Inner { last: None }),
        }
    }

    /// The last result without any outbound request.
    pub async fn get(&self) -> PublicIpResult {
        self.inner
            .lock()
            .await
            .last
            .as_ref()
            .map(|(result, _)| result.clone())
            .unwrap_or_default()
    }

    /// Refreshes both families. Holding the lock for the whole lookup makes
    /// concurrent callers wait and then observe the fresh result, and the
    /// ten-second window short-circuits before any request is made.
    pub async fn refresh(&self) -> PublicIpResult {
        let mut inner = self.inner.lock().await;
        if let Some((result, checked)) = &inner.last
            && checked.elapsed().unwrap_or(Duration::MAX) < MIN_INTERVAL
        {
            return result.clone();
        }
        // The lookup must not follow the caller's cancellation: a browser
        // refresh should not abort an in-flight query, so it runs on a
        // detached task with its own budget.
        let ipv4 = self.lookup.clone();
        let ipv6 = self.lookup.clone();
        let query = tokio::spawn(async move {
            let v4 = tokio::time::timeout(LOOKUP_BUDGET, ipv4(Family::Ipv4))
                .await
                .unwrap_or_else(|_| Err("查询超时".to_owned()));
            let v6 = tokio::time::timeout(LOOKUP_BUDGET, ipv6(Family::Ipv6))
                .await
                .unwrap_or_else(|_| Err("查询超时".to_owned()));
            (v4, v6)
        });
        let (v4, v6) = query.await.unwrap_or_else(|error| {
            let reason = error.to_string();
            (Err(reason.clone()), Err(reason))
        });
        let result = Self::combine(v4, v6);
        inner.last = Some((result.clone(), SystemTime::now()));
        result
    }

    fn combine(v4: Result<IpAddr, String>, v6: Result<IpAddr, String>) -> PublicIpResult {
        let mut result = PublicIpResult {
            ipv4: v4.clone().ok(),
            ipv6: v6.clone().ok(),
            errors: None,
            checked_at: Some(
                time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            ),
        };
        let failures: Vec<(String, String)> = [
            v4.err().map(|error| ("ipv4".to_owned(), error)),
            v6.err().map(|error| ("ipv6".to_owned(), error)),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !failures.is_empty() {
            result.errors = Some(failures.into_iter().collect());
        }
        result
    }

    /// Wires `GET` (status:read) and `POST` (admin session) on the router.
    pub(super) fn mount(self, router: ApiRouter) -> ApiRouter {
        let cache = Arc::new(self);
        let read = cache.clone();
        let refresh = cache;
        router
            .modeled_route(
                Method::GET,
                "/api/system/public-ip",
                "Get the last public address result",
                RouteModels::default().response::<PublicIpResult>(),
                move || {
                    let cache = read.clone();
                    async move { Json(cache.get().await) }
                },
            )
            .modeled_route(
                Method::POST,
                "/api/system/public-ip",
                "Refresh the public address (contacts public services)",
                RouteModels::default().response::<PublicIpResult>(),
                move || {
                    let cache = refresh.clone();
                    async move { Json(cache.refresh().await) }
                },
            )
    }
}
