//! Configuration models, defaults, and resource limits for WebDAV (`webdav.json`, WP-63).

use std::{net::IpAddr, time::Duration};

use fg_files::Mount;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Resource limits and protocol timeouts (WP-63 §3.4).
pub mod limits {
    use std::time::Duration;

    /// Default WebDAV listen port (upstream default).
    pub const DEFAULT_PORT: u16 = 18800;
    /// Password mask returned by management read APIs.
    pub const SECRET_MASK: &str = "********";
    /// Timeout for reading HTTP request headers.
    pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
    /// Idle keep-alive connection close timeout (2 minutes).
    pub const IDLE_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(120);
    /// Upload body stall timeout: disconnect if no body bytes arrive for 2 minutes.
    pub const UPLOAD_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
    /// Graceful listener drain deadline on stop/reload.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
    /// Maximum concurrent blocking bcrypt verifications.
    pub const MAX_AUTH_CONCURRENCY: usize = 16;
    /// Maximum XML request body size (PROPFIND / PROPPATCH / LOCK).
    pub const MAX_XML_BODY_BYTES: usize = 1024 * 1024;
    /// Maximum number of active in-memory WebDAV locks.
    pub const MAX_LOCKS: usize = 4096;
    /// Default lock timeout when client omits `Timeout` header.
    pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(300);
    /// Maximum lock timeout accepted from clients.
    pub const MAX_LOCK_TIMEOUT: Duration = Duration::from_secs(3600);
    /// Maximum resources returned by a single recursive PROPFIND.
    pub const MAX_PROPFIND_ENTRIES: usize = 10_000;
}

/// Configurable timeouts for the WebDAV runtime (defaults match WP-63 §3.4;
/// overridable in tests to verify timeout behavior quickly).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeTimeouts {
    pub header_read: Duration,
    pub idle_keepalive: Duration,
    pub upload_body_idle: Duration,
}

impl Default for RuntimeTimeouts {
    fn default() -> Self {
        Self {
            header_read: limits::HEADER_READ_TIMEOUT,
            idle_keepalive: limits::IDLE_KEEPALIVE_TIMEOUT,
            upload_body_idle: limits::UPLOAD_BODY_IDLE_TIMEOUT,
        }
    }
}

/// Serialized layout of `webdav.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Settings {
    pub enable: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_opt_ip",
        serialize_with = "serialize_opt_ip"
    )]
    pub listen_ip: Option<IpAddr>,
    pub port: u16,
    pub tls: bool,
    pub users: Vec<LocalUser>,
    pub shared_users: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable: false,
            listen_ip: None,
            port: limits::DEFAULT_PORT,
            tls: false,
            users: Vec::new(),
            shared_users: false,
            trusted_proxies: Vec::new(),
        }
    }
}

/// A WebDAV-local user account (takes precedence over same-named shared users).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct LocalUser {
    pub name: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub root: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remark: String,
}

impl LocalUser {
    /// Opens this local user's confined virtual root (single root or multi-mount).
    pub fn open_multi_root(&self) -> Result<fg_files::MultiRoot, fg_files::DirError> {
        if self.mounts.is_empty() {
            fg_files::MultiRoot::open_single(std::path::Path::new(&self.root), self.read_only)
        } else {
            let specs: Vec<(String, std::path::PathBuf, bool)> = self
                .mounts
                .iter()
                .map(|m| (m.name.clone(), m.path.clone(), m.read_only))
                .collect();
            fg_files::MultiRoot::open_mounts(&specs)
        }
    }
}

fn deserialize_opt_ip<'de, D>(deserializer: D) -> Result<Option<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw {
        None => Ok(None),
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                trimmed
                    .parse::<IpAddr>()
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
    }
}

fn serialize_opt_ip<S>(ip: &Option<IpAddr>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match ip {
        Some(addr) => serializer.serialize_str(&addr.to_string()),
        None => serializer.serialize_str(""),
    }
}
