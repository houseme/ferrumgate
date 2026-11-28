//! Per-request status, deny reason, first-byte timestamp, and byte-volume
//! recorder (WP-28 §3.2).
//!
//! A [`Recorder`] wraps a single HTTP response write path and feeds the
//! fixed 5-step finish sequence in [`super::finish_request`]. Hot-path flags
//! shared with connection-management tasks (`killed`, `upgraded`, `authed`)
//! use lock-free atomics.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use hyper::StatusCode;
use serde::{Deserialize, Serialize};

/// Number of tracked deny categories in site counters and metrics.
pub const DENY_KIND_COUNT: usize = 5;

/// Why a request was blocked before reaching the site handler.
///
/// Authentication failures are intentionally excluded here (WP-28 §3.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DenyKind {
    #[default]
    None,
    Ban,
    IpList,
    Country,
    RateLimit,
    Waf,
}

impl DenyKind {
    /// Fixed-cardinality label values matching WP-28 §3.3 (`reason` label).
    pub const ALL_REASONS: [Self; DENY_KIND_COUNT] = [
        Self::Ban,
        Self::IpList,
        Self::Country,
        Self::RateLimit,
        Self::Waf,
    ];

    /// Index into `[AtomicU64; 5]` counters, or `None` when not denied.
    pub const fn index(self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Ban => Some(0),
            Self::IpList => Some(1),
            Self::Country => Some(2),
            Self::RateLimit => Some(3),
            Self::Waf => Some(4),
        }
    }

    /// Fixed-cardinality label string used in Prometheus metrics, access logs,
    /// and visitor deny histograms.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Ban => "ban",
            Self::IpList => "ip",
            Self::Country => "country",
            Self::RateLimit => "rateLimit",
            Self::Waf => "waf",
        }
    }

    /// Returns true if the request was blocked for any reason.
    pub const fn is_denied(self) -> bool {
        !matches!(self, Self::None)
    }

    /// True for access-control rejections (ban, IP list, country) where a
    /// bare disconnect on a normal site should be reported to WP-52 as 403.
    pub const fn is_access_control(self) -> bool {
        matches!(self, Self::Ban | Self::IpList | Self::Country)
    }
}

impl From<crate::web::access::DenyReason> for DenyKind {
    fn from(reason: crate::web::access::DenyReason) -> Self {
        match reason {
            crate::web::access::DenyReason::Ban => Self::Ban,
            crate::web::access::DenyReason::IpList
            | crate::web::access::DenyReason::DenyList
            | crate::web::access::DenyReason::Knock => Self::IpList,
            crate::web::access::DenyReason::Country => Self::Country,
        }
    }
}

/// Per-request response and lifecycle recorder.
#[derive(Clone, Debug)]
pub struct Recorder {
    pub status: StatusCode,
    pub wrote_header: bool,
    pub deny: DenyKind,
    /// Optional finer-grained deny reason for visitor audit (e.g. `"auth"`,
    /// `"knock"`, `"denyList"`). Falls back to `deny.as_str()` when `None`.
    pub deny_detail: Option<String>,
    /// Logged-in management admin username when the request carries a valid
    /// admin session cookie.
    pub admin: Option<String>,
    /// Authenticated site username (only recorded on success).
    pub identity: Option<String>,
    /// True when the visitor holds a trusted authenticated credential (skips
    /// path-probe reporting on normal sites, but not on the default site).
    pub trusted_user: bool,
    /// Timestamp when the response header or first body byte was written.
    pub first_byte: Option<Instant>,
    /// Request bytes received from the visitor.
    pub bytes_in: u64,
    /// Response bytes written to the visitor.
    pub bytes_out: u64,
    /// Set by an administrator disconnecting this live request.
    pub killed: Arc<AtomicBool>,
    /// Set when the connection upgraded (e.g. WebSocket).
    pub upgraded: Arc<AtomicBool>,
    /// Set when the request passed site or admin authentication.
    pub authed: Arc<AtomicBool>,
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Recorder {
    /// Creates a fresh recorder before any response bytes have been written.
    pub fn new() -> Self {
        Self {
            status: StatusCode::OK,
            wrote_header: false,
            deny: DenyKind::None,
            deny_detail: None,
            admin: None,
            identity: None,
            trusted_user: false,
            first_byte: None,
            bytes_in: 0,
            bytes_out: 0,
            killed: Arc::new(AtomicBool::new(false)),
            upgraded: Arc::new(AtomicBool::new(false)),
            authed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a recorder sharing an existing `killed` flag (e.g. with an
    /// active connection entry in [`super::connections::ConnRegistry`]).
    pub fn with_killed_flag(killed: Arc<AtomicBool>) -> Self {
        Self {
            killed,
            ..Self::new()
        }
    }

    /// Records the HTTP status code and timestamps the first byte if not yet
    /// set. Subsequent calls after headers have been written are ignored.
    pub fn write_header(&mut self, status: StatusCode) {
        self.write_header_at(status, Instant::now());
    }

    /// Deterministic variant of [`Self::write_header`] with an explicit clock.
    pub fn write_header_at(&mut self, status: StatusCode, now: Instant) {
        if self.wrote_header {
            return;
        }
        self.status = status;
        self.wrote_header = true;
        if self.first_byte.is_none() {
            self.first_byte = Some(now);
        }
    }

    /// Notes `n` response body bytes written to the client. Implicitly marks
    /// headers as written (200 OK) and records `first_byte` if needed.
    pub fn note_write(&mut self, n: usize) {
        self.note_write_at(n, Instant::now());
    }

    /// Deterministic variant of [`Self::note_write`] with an explicit clock.
    pub fn note_write_at(&mut self, n: usize, now: Instant) {
        if !self.wrote_header {
            self.wrote_header = true;
        }
        if self.first_byte.is_none() {
            self.first_byte = Some(now);
        }
        self.bytes_out = self.bytes_out.saturating_add(n as u64);
    }

    /// Notes `n` request bytes received from the visitor.
    pub fn note_read(&mut self, n: usize) {
        self.bytes_in = self.bytes_in.saturating_add(n as u64);
    }

    /// Marks the request as rejected by a security/access policy.
    pub fn set_deny(&mut self, kind: DenyKind) {
        self.deny = kind;
    }

    /// Marks the request as rejected with an extra visitor-audit reason tag.
    pub fn set_deny_with_detail(&mut self, kind: DenyKind, detail: impl Into<String>) {
        self.deny = kind;
        self.deny_detail = Some(detail.into());
    }

    /// Attaches the logged-in admin user and marks the request authenticated.
    pub fn set_admin(&mut self, user: impl Into<String>) {
        self.admin = Some(user.into());
        self.trusted_user = true;
        self.mark_authed();
    }

    /// Attaches a verified site identity and marks the request authenticated.
    pub fn set_identity(&mut self, user: impl Into<String>, trusted: bool) {
        self.identity = Some(user.into());
        if trusted {
            self.trusted_user = true;
        }
        self.mark_authed();
    }

    /// Marks this request as disconnected by an administrator.
    pub fn mark_killed(&self) {
        self.killed.store(true, Ordering::Release);
    }

    /// Returns whether this request was disconnected by an administrator.
    pub fn is_killed(&self) -> bool {
        self.killed.load(Ordering::Acquire)
    }

    /// Marks this request as protocol-upgraded (e.g. WebSocket).
    pub fn mark_upgraded(&self) {
        self.upgraded.store(true, Ordering::Release);
    }

    /// Returns whether this request upgraded protocols.
    pub fn is_upgraded(&self) -> bool {
        self.upgraded.load(Ordering::Acquire)
    }

    /// Marks this request as authenticated.
    pub fn mark_authed(&self) {
        self.authed.store(true, Ordering::Release);
    }

    /// Returns whether this request passed authentication.
    pub fn is_authed(&self) -> bool {
        self.authed.load(Ordering::Acquire)
    }

    /// Effective status code for logs and statistics:
    /// - If headers were already written, preserves the HTTP status code.
    /// - If killed or closed without writing a response, reports `444`.
    pub fn effective_status(&self) -> u16 {
        if self.wrote_header {
            self.status.as_u16()
        } else {
            444
        }
    }

    /// Returns true if this request should contribute to first-byte latency
    /// statistics. Upgraded, admin-killed, unwritten, and 444 responses are
    /// excluded (WP-28 §3.3 step 1).
    pub fn counts_for_latency(&self) -> bool {
        if self.is_upgraded() || self.is_killed() || !self.wrote_header {
            return false;
        }
        if self.effective_status() == 444 {
            return false;
        }
        self.first_byte.is_some()
    }

    /// Computes first-byte latency when [`Self::counts_for_latency`] is true.
    pub fn first_byte_latency(&self, started: Instant) -> Option<Duration> {
        if !self.counts_for_latency() {
            return None;
        }
        let fb = self.first_byte?;
        Some(fb.saturating_duration_since(started))
    }

    /// Visitor-audit deny reason string, if any.
    pub fn visitor_deny_reason(&self) -> Option<&str> {
        if let Some(detail) = self.deny_detail.as_deref()
            && !detail.is_empty()
        {
            return Some(detail);
        }
        if self.deny.is_denied() {
            return Some(self.deny.as_str());
        }
        None
    }
}

/// Maps an HTTP status code to the 4 standard status-class buckets:
/// `0 = 2xx`, `1 = 3xx`, `2 = 4xx`, `3 = 5xx`. Returns `None` for 1xx or 444.
pub const fn status_class_index(status: u16) -> Option<usize> {
    if status == 444 {
        return None;
    }
    match status {
        200..=299 => Some(0),
        300..=399 => Some(1),
        400..=499 => Some(2),
        500..=599 => Some(3),
        _ => None,
    }
}

/// Maps an HTTP status code to the 5-slot histogram used by topology and
/// visitor audit: `0 = 2xx`, `1 = 3xx`, `2 = 4xx`, `3 = 5xx`, `4 = other/444`.
pub const fn status_hist_index(status: u16) -> usize {
    match status_class_index(status) {
        Some(idx) => idx,
        None => 4,
    }
}

/// Fixed-cardinality label strings for `ferrumgate_site_responses_total{class=...}`.
pub const STATUS_CLASS_LABELS: [&str; 4] = ["2xx", "3xx", "4xx", "5xx"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_records_status_deny_and_first_byte() {
        let start = Instant::now();
        let fb_time = start + Duration::from_millis(25);
        let later = start + Duration::from_millis(90);

        let mut rec = Recorder::new();
        assert!(!rec.wrote_header);
        assert_eq!(rec.effective_status(), 444);
        assert!(!rec.counts_for_latency());

        rec.set_deny(DenyKind::RateLimit);
        rec.write_header_at(StatusCode::TOO_MANY_REQUESTS, fb_time);
        // Second header write is ignored; first_byte stays at fb_time.
        rec.write_header_at(StatusCode::INTERNAL_SERVER_ERROR, later);
        rec.note_write_at(128, later);
        rec.note_read(64);

        assert_eq!(rec.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rec.effective_status(), 429);
        assert_eq!(rec.deny, DenyKind::RateLimit);
        assert_eq!(rec.deny.as_str(), "rateLimit");
        assert_eq!(rec.first_byte, Some(fb_time));
        assert_eq!(
            rec.first_byte_latency(start),
            Some(Duration::from_millis(25))
        );
        assert_eq!(rec.bytes_out, 128);
        assert_eq!(rec.bytes_in, 64);
    }

    #[test]
    fn killed_after_header_preserves_status_but_skips_latency() {
        let start = Instant::now();
        let mut rec = Recorder::new();
        rec.write_header_at(StatusCode::OK, start + Duration::from_millis(5));
        rec.mark_killed();
        assert_eq!(rec.effective_status(), 200);
        assert!(!rec.counts_for_latency());
        assert_eq!(rec.first_byte_latency(start), None);
    }

    #[test]
    fn upgraded_skips_latency() {
        let start = Instant::now();
        let mut rec = Recorder::new();
        rec.write_header_at(
            StatusCode::SWITCHING_PROTOCOLS,
            start + Duration::from_millis(3),
        );
        rec.mark_upgraded();
        assert!(!rec.counts_for_latency());
    }
}
