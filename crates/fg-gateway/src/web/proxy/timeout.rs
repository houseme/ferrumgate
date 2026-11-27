//! Backend and visitor timeouts (WP-23 step 6), with the upstream
//! defaults: backend connect/TLS-handshake 10s (1-300), response header
//! unlimited (1-86400s); visitor read/write idle 60s (1-3600). A response
//! header timeout only bounds the wait after the request was fully sent —
//! response body streaming, WebSocket and SSE are never cut off by it.
#![allow(dead_code)]

use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutError {
    OutOfRange(&'static str),
}

impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange(field) => write!(f, "{field} 超出范围"),
        }
    }
}

impl std::error::Error for TimeoutError {}

const CONNECT_RANGE: std::ops::RangeInclusive<u64> = 1..=300;
const TLS_RANGE: std::ops::RangeInclusive<u64> = 1..=300;
const RESPONSE_RANGE: std::ops::RangeInclusive<u64> = 1..=86400;
const IDLE_RANGE: std::ops::RangeInclusive<u64> = 1..=3600;

/// Timeouts toward the backend. `response_header` is `None` (unlimited)
/// by default; when set it starts once the request (including body) has
/// been sent and stops at the first response header byte. Connect errors
/// return 502, response header timeouts 504; both feed the passive check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendTimeouts {
    pub connect: Duration,
    pub tls_handshake: Duration,
    pub response_header: Option<Duration>,
}

impl Default for BackendTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            tls_handshake: Duration::from_secs(10),
            response_header: None,
        }
    }
}

impl BackendTimeouts {
    /// Validates the configured ranges.
    pub fn validate(&self) -> Result<(), TimeoutError> {
        if !CONNECT_RANGE.contains(&self.connect.as_secs()) {
            return Err(TimeoutError::OutOfRange("后端连接超时须在 1..=300 秒"));
        }
        if !TLS_RANGE.contains(&self.tls_handshake.as_secs()) {
            return Err(TimeoutError::OutOfRange("TLS 握手超时须在 1..=300 秒"));
        }
        if let Some(response_header) = self.response_header
            && !RESPONSE_RANGE.contains(&response_header.as_secs())
        {
            return Err(TimeoutError::OutOfRange("响应头超时须在 1..=86400 秒"));
        }
        Ok(())
    }
}

/// Visitor-side idle timeouts. Each bounds a single stalled read or write;
/// an idle read answers 408 and closes (never fed to the passive check),
/// an idle write just disconnects. Applies to HTTP/1, HTTP/2 and HTTP/3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTimeouts {
    pub read_idle: Duration,
    pub write_idle: Duration,
}

impl Default for ClientTimeouts {
    fn default() -> Self {
        Self {
            read_idle: Duration::from_secs(60),
            write_idle: Duration::from_secs(60),
        }
    }
}

impl ClientTimeouts {
    /// Validates the configured ranges.
    pub fn validate(&self) -> Result<(), TimeoutError> {
        for (value, field) in [
            (self.read_idle, "访客读空闲超时须在 1..=3600 秒"),
            (self.write_idle, "访客写空闲超时须在 1..=3600 秒"),
        ] {
            if !IDLE_RANGE.contains(&value.as_secs()) {
                return Err(TimeoutError::OutOfRange(field));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_upstream() {
        let backend = BackendTimeouts::default();
        assert_eq!(backend.connect, Duration::from_secs(10));
        assert_eq!(backend.tls_handshake, Duration::from_secs(10));
        assert_eq!(backend.response_header, None);
        let client = ClientTimeouts::default();
        assert_eq!(client.read_idle, Duration::from_secs(60));
        assert_eq!(client.write_idle, Duration::from_secs(60));
    }

    #[test]
    fn validate_accepts_configured_values() {
        let backend = BackendTimeouts {
            connect: Duration::from_secs(1),
            tls_handshake: Duration::from_secs(300),
            response_header: Some(Duration::from_secs(86400)),
        };
        let client = ClientTimeouts {
            read_idle: Duration::from_secs(1),
            write_idle: Duration::from_secs(3600),
        };
        assert!(backend.validate().is_ok());
        assert!(client.validate().is_ok());
    }

    #[test]
    fn validate_rejects_out_of_range() {
        for backend in [
            BackendTimeouts {
                connect: Duration::from_secs(0),
                ..BackendTimeouts::default()
            },
            BackendTimeouts {
                tls_handshake: Duration::from_secs(301),
                ..BackendTimeouts::default()
            },
            BackendTimeouts {
                response_header: Some(Duration::from_secs(86401)),
                ..BackendTimeouts::default()
            },
        ] {
            assert!(backend.validate().is_err());
        }
        for client in [
            ClientTimeouts {
                read_idle: Duration::from_secs(0),
                ..ClientTimeouts::default()
            },
            ClientTimeouts {
                write_idle: Duration::from_secs(3601),
                ..ClientTimeouts::default()
            },
        ] {
            assert!(client.validate().is_err());
        }
    }
}
