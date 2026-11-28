//! Live request connection registry, per-site history, close, and
//! close-and-ban (WP-28 §3.2/§3.3).
//!
//! Connections are tracked **per HTTP request** (rather than per TCP socket) so
//! HTTP/1.1 keep-alive sockets between requests do not belong to any site and
//! multiplexed HTTP/2 / HTTP/3 streams attribute accurately to their individual
//! sites and can be reset independently.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use hyper::Method;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::web::{upstream::Backend, userroute::RouteUserKey};

/// Maximum active connections returned in the API list (sorted longest-first).
pub const MAX_CONN_LIST: usize = 500;
/// Maximum finished history entries retained per site.
pub const MAX_CONN_HISTORY_PER_SITE: usize = 200;
/// Maximum characters stored for a connection's request path (query stripped).
pub const MAX_CONN_PATH_CHARS: usize = 512;
/// Maximum characters stored for a connection's host header.
pub const MAX_CONN_HOST_CHARS: usize = 255;
/// Minimum request duration for automatic inclusion in finished history.
pub const HISTORY_MIN_DURATION: Duration = Duration::from_secs(1);

/// Site identifier key used in the connection registry.
pub type SiteId = String;

/// Wire protocol of an active request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    H1,
    H2,
    H3,
    Ws,
}

impl Proto {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H1 => "h1",
            Self::H2 => "h2",
            Self::H3 => "h3",
            Self::Ws => "ws",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolved client source address (real IP behind trusted proxies + peer port
/// and forwarding proxy when present).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedAddr {
    pub ip: IpAddr,
    pub port: u16,
    pub via: Option<SocketAddr>,
    pub verified: bool,
}

impl ResolvedAddr {
    /// Direct TCP/QUIC peer with no forwarding proxy.
    pub fn direct(peer: SocketAddr) -> Self {
        Self {
            ip: peer.ip(),
            port: peer.port(),
            via: None,
            verified: false,
        }
    }

    /// Client address resolved via a trusted proxy.
    pub fn proxied(ip: IpAddr, port: u16, via: SocketAddr) -> Self {
        Self {
            ip,
            port,
            via: Some(via),
            verified: true,
        }
    }

    /// Builds a [`ResolvedAddr`] from the raw peer socket and `fg-net`'s
    /// resolved [`fg_net::client_addr::ClientAddr`].
    pub fn from_client_addr(peer: SocketAddr, addr: fg_net::client_addr::ClientAddr) -> Self {
        Self {
            ip: addr.ip,
            port: peer.port(),
            via: addr.via,
            verified: addr.verified,
        }
    }
}

/// Normalized ban target: exact IPv4 address or IPv6 `/64` prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BanTarget {
    V4(Ipv4Addr),
    V6Prefix64(Ipv6Addr),
}

impl BanTarget {
    /// Normalizes `ip` into a ban target (unwraps IPv4-mapped IPv6 to IPv4 and
    /// masks IPv6 to its `/64` network). Returns `None` for loopback addresses.
    pub fn from_ip(ip: IpAddr) -> Option<Self> {
        let unwrapped = unwrap_v4_mapped(ip);
        if unwrapped.is_loopback() {
            return None;
        }
        match unwrapped {
            IpAddr::V4(v4) => Some(Self::V4(v4)),
            IpAddr::V6(v6) => Some(Self::V6Prefix64(mask_v6_64(v6))),
        }
    }

    /// True if `ip` falls inside this ban target (exact IPv4 or same IPv6 `/64`).
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        let unwrapped = unwrap_v4_mapped(ip);
        match (self, unwrapped) {
            (Self::V4(a), IpAddr::V4(b)) => *a == b,
            (Self::V6Prefix64(prefix), IpAddr::V6(v6)) => mask_v6_64(v6) == *prefix,
            _ => false,
        }
    }

    /// Converts into `fg-net`'s [`fg_net::banlist::BanKey`].
    pub fn to_ban_key(self) -> fg_net::banlist::BanKey {
        match self {
            Self::V4(v4) => fg_net::banlist::BanKey::from_ip(IpAddr::V4(v4)),
            Self::V6Prefix64(v6) => fg_net::banlist::BanKey::from_ip(IpAddr::V6(v6)),
        }
    }
}

impl fmt::Display for BanTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(v4) => write!(f, "{v4}"),
            Self::V6Prefix64(v6) => write!(f, "{v6}/64"),
        }
    }
}

fn unwrap_v4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn mask_v6_64(v6: Ipv6Addr) -> Ipv6Addr {
    let s = v6.segments();
    Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)
}

/// Injectable hook called by [`ConnRegistry::close_and_ban`] to add the target
/// into the unified ban table (WP-50).
pub type BanHook = Arc<dyn Fn(BanTarget) -> anyhow::Result<()> + Send + Sync>;

/// Injectable predicate that identifies trusted proxy addresses which must not
/// be banned via `close_and_ban`.
pub type TrustedProxyCheck = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// Errors returned by [`ConnRegistry::close_and_ban`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseBanError {
    NotFound,
    LoopbackRefused,
    TrustedProxyRefused,
    BanFailed(String),
}

impl fmt::Display for CloseBanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "connection not found or already closed"),
            Self::LoopbackRefused => write!(f, "loopback addresses cannot be banned"),
            Self::TrustedProxyRefused => write!(f, "trusted proxy addresses cannot be banned"),
            Self::BanFailed(msg) => write!(f, "failed to ban target: {msg}"),
        }
    }
}

impl std::error::Error for CloseBanError {}

/// Result of [`ConnRegistry::close_and_ban`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseAndBanResult {
    pub target: String,
    pub closed: usize,
}

/// One in-flight HTTP/WebSocket request registered in [`ConnRegistry`].
pub struct ActiveReq {
    pub id: u64,
    pub listener: String,
    pub site: SiteId,
    pub addr: ResolvedAddr,
    pub proto: Proto,
    pub method: Method,
    /// Hostname truncated to 255 characters.
    pub host: String,
    /// Path without query string, truncated to 512 characters.
    pub path: String,
    pub started: Instant,
    pub started_at: SystemTime,
    /// Bytes sent to the visitor (`↑` upstream from gateway to client).
    pub bytes_up: AtomicU64,
    /// Bytes received from the visitor (`↓` client request body / WS frames).
    pub bytes_down: AtomicU64,
    pub identity: Vec<RouteUserKey>,
    /// Cancels the client-side connection (H1) or stream (H2/H3) / WS loop.
    pub cancel: CancellationToken,
    /// Optional cancellation token for the backend connection (e.g. upgraded
    /// WebSocket upstream socket) so closing the request tears down both ends.
    pub backend_cancel: Option<CancellationToken>,
    pub backend: Option<Arc<Backend>>,
    /// Shared flag also readable by [`super::recorder::Recorder`].
    pub killed: Arc<AtomicBool>,
}

impl ActiveReq {
    /// Convenience constructor with sensible defaults (`id = 0` lets
    /// [`ConnRegistry::register`] assign a unique monotonic ID).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listener: impl Into<String>,
        site: impl Into<SiteId>,
        addr: ResolvedAddr,
        proto: Proto,
        method: Method,
        host: &str,
        raw_path: &str,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            id: 0,
            listener: listener.into(),
            site: site.into(),
            addr,
            proto,
            method,
            host: truncate_chars(host, MAX_CONN_HOST_CHARS),
            path: sanitize_conn_path(raw_path),
            started: Instant::now(),
            started_at: SystemTime::now(),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            identity: Vec::new(),
            cancel,
            backend_cancel: None,
            backend: None,
            killed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_backend_cancel(mut self, token: CancellationToken) -> Self {
        self.backend_cancel = Some(token);
        self
    }

    pub fn with_killed_flag(mut self, killed: Arc<AtomicBool>) -> Self {
        self.killed = killed;
        self
    }

    pub fn with_started(mut self, started: Instant, started_at: SystemTime) -> Self {
        self.started = started;
        self.started_at = started_at;
        self
    }

    pub fn with_identity(mut self, identity: Vec<RouteUserKey>) -> Self {
        self.identity = identity;
        self
    }

    pub fn with_backend(mut self, backend: Arc<Backend>) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Records bytes sent to the visitor (`↑`).
    pub fn add_bytes_up(&self, n: u64) {
        self.bytes_up.fetch_add(n, Ordering::Relaxed);
    }

    /// Records bytes received from the visitor (`↓`).
    pub fn add_bytes_down(&self, n: u64) {
        self.bytes_down.fetch_add(n, Ordering::Relaxed);
    }
}

/// Strips query string and fragment and truncates to [`MAX_CONN_PATH_CHARS`].
pub fn sanitize_conn_path(raw: &str) -> String {
    let path_only = raw.split(['?', '#']).next().unwrap_or(raw);
    truncate_chars(path_only, MAX_CONN_PATH_CHARS)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => s[..byte_idx].to_owned(),
        None => s.to_owned(),
    }
}

/// Serialization view of an active request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnView {
    pub id: u64,
    pub listener: String,
    pub site: SiteId,
    pub client_ip: String,
    pub client_port: u16,
    pub via: Option<String>,
    pub proto: Proto,
    pub method: String,
    pub host: String,
    pub path: String,
    pub started_unix: i64,
    pub duration_ms: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub identities: Vec<String>,
    pub backend: Option<String>,
}

/// Outcome of a finished request in per-site connection history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FinishReason {
    Completed,
    Closed,
}

/// One finished request entry retained in per-site history (requests lasting
/// >= 1 s or manually closed by an admin).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishedReq {
    pub id: u64,
    pub listener: String,
    pub site: SiteId,
    pub client_ip: String,
    pub client_port: u16,
    pub via: Option<String>,
    pub proto: Proto,
    pub method: String,
    pub host: String,
    pub path: String,
    pub started_unix: i64,
    pub ended_unix: i64,
    pub duration_ms: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub reason: FinishReason,
}

/// RAII handle that unregisters an active request on drop and records it in
/// per-site history if it lasted >= 1 s or was manually closed.
pub struct ConnGuard {
    registry: Arc<ConnRegistry>,
    req: Arc<ActiveReq>,
    finished: bool,
}

impl ConnGuard {
    pub fn id(&self) -> u64 {
        self.req.id
    }

    pub fn req(&self) -> &Arc<ActiveReq> {
        &self.req
    }

    pub fn add_bytes_up(&self, n: u64) {
        self.req.add_bytes_up(n);
    }

    pub fn add_bytes_down(&self, n: u64) {
        self.req.add_bytes_down(n);
    }

    /// Explicitly finishes the connection using a caller-supplied timestamp
    /// (useful for deterministic unit tests without sleeping).
    pub fn finish_at(mut self, ended: Instant, ended_at: SystemTime) {
        self.finished = true;
        self.registry.unregister(&self.req, ended, ended_at);
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            self.registry
                .unregister(&self.req, Instant::now(), SystemTime::now());
        }
    }
}

/// Thread-safe registry of live requests and per-site finished history.
pub struct ConnRegistry {
    active: RwLock<HashMap<u64, Arc<ActiveReq>>>,
    history: Mutex<HashMap<SiteId, VecDeque<FinishedReq>>>,
    next_id: AtomicU64,
    ban_hook: RwLock<Option<BanHook>>,
    trusted_proxy_check: RwLock<Option<TrustedProxyCheck>>,
}

impl Default for ConnRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnRegistry {
    pub fn new() -> Self {
        Self {
            active: RwLock::new(HashMap::new()),
            history: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            ban_hook: RwLock::new(None),
            trusted_proxy_check: RwLock::new(None),
        }
    }

    /// Installs the ban hook invoked by [`Self::close_and_ban`].
    pub fn set_ban_hook(&self, hook: BanHook) {
        *self
            .ban_hook
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Installs the predicate used to refuse banning trusted proxy addresses.
    pub fn set_trusted_proxy_check(&self, check: TrustedProxyCheck) {
        *self
            .trusted_proxy_check
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(check);
    }

    /// Registers an active request and returns an RAII [`ConnGuard`].
    pub fn register(self: &Arc<Self>, mut req: ActiveReq) -> ConnGuard {
        if req.id == 0 {
            req.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        req.host = truncate_chars(&req.host, MAX_CONN_HOST_CHARS);
        req.path = sanitize_conn_path(&req.path);
        let req = Arc::new(req);
        self.active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(req.id, Arc::clone(&req));
        ConnGuard {
            registry: Arc::clone(self),
            req,
            finished: false,
        }
    }

    fn unregister(&self, req: &ActiveReq, ended: Instant, ended_at: SystemTime) {
        self.active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&req.id);

        let duration = ended.saturating_duration_since(req.started);
        let killed = req.killed.load(Ordering::Acquire);
        if duration < HISTORY_MIN_DURATION && !killed {
            return;
        }
        let entry = FinishedReq {
            id: req.id,
            listener: req.listener.clone(),
            site: req.site.clone(),
            client_ip: req.addr.ip.to_string(),
            client_port: req.addr.port,
            via: req.addr.via.map(|v| v.to_string()),
            proto: req.proto,
            method: req.method.as_str().to_owned(),
            host: req.host.clone(),
            path: req.path.clone(),
            started_unix: unix_secs(req.started_at),
            ended_unix: unix_secs(ended_at),
            duration_ms: duration.as_millis().min(u64::MAX as u128) as u64,
            bytes_up: req.bytes_up.load(Ordering::Relaxed),
            bytes_down: req.bytes_down.load(Ordering::Relaxed),
            reason: if killed {
                FinishReason::Closed
            } else {
                FinishReason::Completed
            },
        };
        let mut hist = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let site_hist = hist.entry(req.site.clone()).or_default();
        if site_hist.len() >= MAX_CONN_HISTORY_PER_SITE {
            site_hist.pop_front();
        }
        site_hist.push_back(entry);
    }

    /// Number of currently active requests across all listeners and sites.
    pub fn active_count(&self) -> usize {
        self.active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Active client IPs, optionally filtered by site (used by topology).
    pub fn active_ips(&self, site: Option<&str>) -> Vec<IpAddr> {
        let map = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.values()
            .filter(|req| site.is_none_or(|s| req.site == s))
            .map(|req| req.addr.ip)
            .collect()
    }

    /// Lists active requests sorted longest-duration first, capped at
    /// [`MAX_CONN_LIST`] (500).
    pub fn list(&self, site: Option<&str>, ip_filter: Option<IpAddr>) -> Vec<ConnView> {
        self.list_filtered(site, ip_filter, None, Instant::now())
    }

    /// Lists active requests with optional substring search and explicit clock.
    pub fn list_filtered(
        &self,
        site: Option<&str>,
        ip_filter: Option<IpAddr>,
        search: Option<&str>,
        now: Instant,
    ) -> Vec<ConnView> {
        let q = search
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let map = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut items: Vec<ConnView> = map
            .values()
            .filter(|req| {
                if let Some(s) = site
                    && req.site != s
                {
                    return false;
                }
                if let Some(ip) = ip_filter
                    && req.addr.ip != ip
                {
                    return false;
                }
                if let Some(ref q) = q {
                    let ip_str = req.addr.ip.to_string();
                    let matches = ip_str.to_ascii_lowercase().contains(q)
                        || req.host.to_ascii_lowercase().contains(q)
                        || req.path.to_ascii_lowercase().contains(q)
                        || req.site.to_ascii_lowercase().contains(q);
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .map(|req| {
                let dur = now.saturating_duration_since(req.started);
                ConnView {
                    id: req.id,
                    listener: req.listener.clone(),
                    site: req.site.clone(),
                    client_ip: req.addr.ip.to_string(),
                    client_port: req.addr.port,
                    via: req.addr.via.map(|v| v.to_string()),
                    proto: req.proto,
                    method: req.method.as_str().to_owned(),
                    host: req.host.clone(),
                    path: req.path.clone(),
                    started_unix: unix_secs(req.started_at),
                    duration_ms: dur.as_millis().min(u64::MAX as u128) as u64,
                    bytes_up: req.bytes_up.load(Ordering::Relaxed),
                    bytes_down: req.bytes_down.load(Ordering::Relaxed),
                    identities: req.identity.iter().map(RouteUserKey::key).collect(),
                    backend: req
                        .backend
                        .as_ref()
                        .map(|b| crate::web::upstream::display_url(&b.target)),
                }
            })
            .collect();

        // Longest duration first; tie-break by id asc for deterministic order.
        items.sort_by(|a, b| {
            b.duration_ms
                .cmp(&a.duration_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        items.truncate(MAX_CONN_LIST);
        items
    }

    /// Returns finished connection history (newest first), optionally filtered
    /// by site and search query.
    pub fn history(&self, site: Option<&str>, search: Option<&str>) -> Vec<FinishedReq> {
        let q = search
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let hist = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut out = Vec::new();
        for (site_key, queue) in hist.iter() {
            if let Some(s) = site
                && site_key != s
            {
                continue;
            }
            for item in queue.iter().rev() {
                if let Some(ref q) = q {
                    let matches = item.client_ip.to_ascii_lowercase().contains(q)
                        || item.host.to_ascii_lowercase().contains(q)
                        || item.path.to_ascii_lowercase().contains(q)
                        || item.site.to_ascii_lowercase().contains(q);
                    if !matches {
                        continue;
                    }
                }
                out.push(item.clone());
            }
        }
        out.sort_by(|a, b| {
            b.ended_unix
                .cmp(&a.ended_unix)
                .then_with(|| b.id.cmp(&a.id))
        });
        if site.is_some() {
            out.truncate(MAX_CONN_HISTORY_PER_SITE);
        }
        out
    }

    /// Disconnects a single active request by ID.
    ///
    /// Cancels both the client token (`cancel`) and any backend token
    /// (`backend_cancel`) so upgraded WebSockets tear down both ends, and marks
    /// `killed = true`. Returns `false` if the request already ended.
    pub fn close(&self, id: u64) -> bool {
        let req = {
            let map = self
                .active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            map.get(&id).cloned()
        };
        let Some(req) = req else {
            return false;
        };
        cancel_request(&req);
        true
    }

    /// Closes all active requests matching `target` across every listener and
    /// site. Returns how many requests were closed.
    pub fn close_by_target(&self, target: &BanTarget) -> usize {
        let matched: Vec<Arc<ActiveReq>> = {
            let map = self
                .active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            map.values()
                .filter(|req| target.matches_ip(req.addr.ip))
                .cloned()
                .collect()
        };
        for req in &matched {
            cancel_request(req);
        }
        matched.len()
    }

    /// Bans the source IP (or IPv6 `/64`) of active request `id` via the
    /// configured ban hook and disconnects every active request from that
    /// source across all listeners and sites.
    ///
    /// Refuses loopback addresses and trusted proxies.
    pub fn close_and_ban(&self, id: u64) -> Result<CloseAndBanResult, CloseBanError> {
        let ip = {
            let map = self
                .active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            map.get(&id)
                .map(|r| r.addr.ip)
                .ok_or(CloseBanError::NotFound)?
        };
        let target = BanTarget::from_ip(ip).ok_or(CloseBanError::LoopbackRefused)?;
        if let Some(check) = self
            .trusted_proxy_check
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            && check(ip)
        {
            return Err(CloseBanError::TrustedProxyRefused);
        }
        if let Some(hook) = self
            .ban_hook
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            hook(target).map_err(|e| CloseBanError::BanFailed(e.to_string()))?;
        }
        let closed = self.close_by_target(&target);
        Ok(CloseAndBanResult {
            target: target.to_string(),
            closed,
        })
    }

    /// Clears all finished history (e.g. when a listener resets).
    pub fn clear_site_history(&self, site: &str) {
        self.history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(site);
    }
}

fn cancel_request(req: &ActiveReq) {
    req.killed.store(true, Ordering::Release);
    req.cancel.cancel();
    if let Some(backend_cancel) = &req.backend_cancel {
        backend_cancel.cancel();
    }
}

fn unix_secs(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_history_only_long_or_killed() {
        let reg = Arc::new(ConnRegistry::new());
        let addr = ResolvedAddr::direct("203.0.113.10:12345".parse().unwrap());
        let t0 = Instant::now();
        let st0 = SystemTime::now();

        // Short normal request (500ms) -> NOT recorded in history.
        let g_short = reg.register(
            ActiveReq::new(
                "l1",
                "site-a",
                addr.clone(),
                Proto::H1,
                Method::GET,
                "a.test",
                "/fast?secret=1",
                CancellationToken::new(),
            )
            .with_started(t0, st0),
        );
        assert_eq!(g_short.req().path, "/fast");
        g_short.finish_at(
            t0 + Duration::from_millis(500),
            st0 + Duration::from_millis(500),
        );
        assert!(reg.history(Some("site-a"), None).is_empty());

        // Long request (>= 1s) -> recorded as Completed.
        let g_long = reg.register(
            ActiveReq::new(
                "l1",
                "site-a",
                addr.clone(),
                Proto::H2,
                Method::GET,
                "a.test",
                "/slow",
                CancellationToken::new(),
            )
            .with_started(t0, st0),
        );
        g_long.add_bytes_up(1024);
        g_long.finish_at(
            t0 + Duration::from_millis(1200),
            st0 + Duration::from_millis(1200),
        );

        // Short request that was manually closed -> recorded as Closed.
        let g_killed = reg.register(
            ActiveReq::new(
                "l1",
                "site-a",
                addr,
                Proto::H1,
                Method::POST,
                "a.test",
                "/killed",
                CancellationToken::new(),
            )
            .with_started(t0, st0),
        );
        assert!(reg.close(g_killed.id()));
        g_killed.finish_at(
            t0 + Duration::from_millis(50),
            st0 + Duration::from_millis(50),
        );

        let hist = reg.history(Some("site-a"), None);
        assert_eq!(hist.len(), 2);
        assert!(
            hist.iter()
                .any(|h| h.path == "/slow" && h.reason == FinishReason::Completed)
        );
        assert!(
            hist.iter()
                .any(|h| h.path == "/killed" && h.reason == FinishReason::Closed)
        );
    }

    #[test]
    fn ban_target_v6_64_and_rejects_loopback() {
        assert_eq!(BanTarget::from_ip("127.0.0.1".parse().unwrap()), None);
        assert_eq!(BanTarget::from_ip("::1".parse().unwrap()), None);
        assert_eq!(
            BanTarget::from_ip("::ffff:127.0.0.1".parse().unwrap()),
            None
        );

        let v6_a: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let v6_b: IpAddr = "2001:db8:abcd:1234:ffff::99".parse().unwrap();
        let v6_c: IpAddr = "2001:db8:abcd:1235::1".parse().unwrap();
        let target = BanTarget::from_ip(v6_a).unwrap();
        assert_eq!(target.to_string(), "2001:db8:abcd:1234::/64");
        assert!(target.matches_ip(v6_a));
        assert!(target.matches_ip(v6_b));
        assert!(!target.matches_ip(v6_c));
    }
}
