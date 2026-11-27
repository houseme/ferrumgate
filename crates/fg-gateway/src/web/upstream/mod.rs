//! WP-23 upstream: backend targets, the pool with four load policies,
//! passive/active health checks and dial-failure retry. Parallel to the
//! legacy `crate::backend` pool, which keeps serving the TOML path until
//! WP-39 migrates it onto this module.
#![allow(dead_code)]

pub mod health;
pub mod pool;
pub mod retry;
pub mod select;
pub mod target;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64};
use std::time::Duration;

pub use pool::{Pool, PoolError};
pub use retry::{Attempt, is_dial_failure};
pub use target::{Target, TargetError, display_url, parse_target};

/// Backends per site (mirrors the legacy `MAX_PER_ROUTE`).
pub const MAX_BACKENDS: usize = 32;
/// Consecutive dial failures before a backend pauses (passive check).
pub const FAILURE_THRESHOLD: u32 = 3;
/// How long a passively failed backend stays out of rotation.
pub const PAUSE: Duration = Duration::from_secs(30);
/// Backends tried per request, counting the first (`maxProxyAttempts`).
pub const MAX_ATTEMPTS: usize = 3;

/// `lbPolicy`: empty/`round_robin` | `random` | `ip_hash` | `least_conn`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Policy {
    #[default]
    RoundRobin,
    Random,
    IpHash,
    LeastConn,
}

impl Policy {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "" | "round_robin" => Some(Self::RoundRobin),
            "random" => Some(Self::Random),
            "ip_hash" => Some(Self::IpHash),
            "least_conn" => Some(Self::LeastConn),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::Random => "random",
            Self::IpHash => "ip_hash",
            Self::LeastConn => "least_conn",
        }
    }
}

/// Active health check mode: HTTP request (`status < 400` is healthy) or
/// TCP connect only. `force_tcp` (PROXY protocol to the backend) demotes
/// HTTP checks to TCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckMode {
    Http,
    Tcp,
}

/// Active check parameters. Defaults 10s / 3s / 3 fails / 2 passes; ranges
/// 1..=3600 / 1..=60 / 1..=20 / 1..=20.
#[derive(Clone, Debug)]
pub struct ActiveCheck {
    pub mode: CheckMode,
    /// Origin-form path for HTTP checks ("/" when unset).
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub fails: u32,
    pub passes: u32,
}

/// Runtime state of one backend. Each compiled pool (config generation)
/// owns its own state; all fields are atomics so `select` and probes lock
/// nothing.
pub struct BackendState {
    /// Passive dial-failure streak (threshold [`FAILURE_THRESHOLD`]).
    pub(crate) fails: AtomicU32,
    /// Unix millis when the passive pause ends; 0 = not paused.
    pub(crate) paused_until: AtomicI64,
    pub(crate) conns: AtomicI32,
    pub(crate) requests: AtomicU64,
    /// Active-probe streaks, separate from the passive counter.
    pub(crate) probe_fails: AtomicU32,
    pub(crate) passes: AtomicU32,
    /// Actively marked down by probes (recovery is probe-driven).
    pub(crate) down: AtomicBool,
    pub(crate) last_error: Mutex<Option<String>>,
}

impl Default for BackendState {
    fn default() -> Self {
        Self {
            fails: AtomicU32::new(0),
            paused_until: AtomicI64::new(0),
            conns: AtomicI32::new(0),
            requests: AtomicU64::new(0),
            probe_fails: AtomicU32::new(0),
            passes: AtomicU32::new(0),
            down: AtomicBool::new(false),
            last_error: Mutex::new(None),
        }
    }
}

/// A compiled backend: its address plus runtime state. Shared through
/// `Arc` (state is not cloneable by design — one state per generation).
pub struct Backend {
    pub target: target::Target,
    pub state: BackendState,
}

impl Backend {
    pub fn new(target: target::Target) -> Self {
        Self {
            target,
            state: BackendState::default(),
        }
    }

    /// Backend origin (scheme + host + port) for duplicate detection.
    pub fn origin(&self) -> String {
        let uri = &self.target.uri;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        format!(
            "{}://{}:{}",
            uri.scheme_str().unwrap_or("http"),
            uri.host().unwrap_or(""),
            port
        )
    }
}

/// One backend's row for the status endpoint / metrics (WP-28 renders it).
pub struct UpstreamStatus {
    /// Display URL: credentials, query and fragment stripped.
    pub url: String,
    pub weight: u32,
    pub backup: bool,
    pub available: bool,
    pub fails: u32,
    /// Seconds remaining in the passive pause, when paused.
    pub paused_for_secs: Option<i64>,
    pub conns: i32,
    pub requests: u64,
}
