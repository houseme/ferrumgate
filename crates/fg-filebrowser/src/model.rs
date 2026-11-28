//! The `filebrowser.json` model (WP-66 §3.2): module settings, the online
//! install block and the instance collection. JSON field names follow the
//! upstream module and FileBrowser Quantum's documented defaults (verified
//! against `gtsteffaniak/filebrowser` v2.1.0-stable); every struct denies
//! unknown fields and fills defaults so a partially written file still
//! loads. `adminPassword` is stored in plain text in the file (0600 via
//! the config store) and masked in the management API; it reaches the
//! process only through the environment (see `render`/`instance`).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Shared ceilings and defaults for the module (conventions §2).
pub mod limits {
    use std::time::Duration;

    /// Quantum default listen port (upstream `port`).
    pub const DEFAULT_PORT: u16 = 8080;
    /// Quantum default base URL (upstream `baseURL`).
    pub const DEFAULT_BASE_URL: &str = "/";
    /// Quantum default proxy auth header (upstream `proxyHeader`).
    pub const DEFAULT_PROXY_HEADER: &str = "Remote-User";
    /// Quantum default admin user (upstream `adminUser`).
    pub const DEFAULT_ADMIN_USER: &str = "admin";
    /// Quantum default token lifetime in hours (upstream `tokenHours`).
    pub const DEFAULT_TOKEN_HOURS: u32 = 2;
    /// Quantum requires at least this many characters for the admin
    /// password when the `password` auth method is active.
    pub const PASSWORD_MIN_CHARS: usize = 8;
    /// FerrumGate protection: instances per file (upstream has no limit;
    /// the 4 MiB request body cap bounds it in practice).
    pub const INSTANCES_MAX: usize = 64;
    /// FerrumGate protection: shared directories per instance.
    pub const SOURCES_MAX: usize = 64;
    /// FerrumGate protection: access URLs per instance.
    pub const ACCESS_URLS_MAX: usize = 16;
    /// FerrumGate protection: field length caps.
    pub const NAME_MAX_CHARS: usize = 128;
    pub const GROUP_MAX_CHARS: usize = 64;
    pub const REMARK_MAX_CHARS: usize = 512;
    pub const BASE_URL_MAX_CHARS: usize = 512;
    pub const PROXY_HEADER_MAX_CHARS: usize = 128;
    pub const ACCESS_URL_MAX_CHARS: usize = 512;
    /// FerrumGate protection: configured `binPath` length.
    pub const PROGRAM_PATH_MAX_CHARS: usize = 1024;
    /// FerrumGate protection: download proxy length.
    pub const PROXY_MAX_CHARS: usize = 255;
    /// Instance data directory under the config dir (upstream
    /// `filebrowser/<key>/`).
    pub const DATA_DIR_NAME: &str = "filebrowser";
    /// The environment variable carrying the admin password into the
    /// process; Quantum expands `${VAR}` references in the config file
    /// from the environment, so the password itself never lands on disk
    /// nor in the process arguments (upstream env prefix `FILEBROWSER_*`).
    pub const PASSWORD_ENV: &str = "FILEBROWSER_ADMIN_PASSWORD";
    /// Grace period for stopping instance processes when the module drains
    /// (fg-proc applies its own 5 s stop grace per process; the module
    /// deadline bounds the whole drain).
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
    /// Secrets are replaced by this placeholder in API output; submitting
    /// it back keeps the stored value (upstream `crud.SecretMask`).
    pub const SECRET_MASK: &str = "********";
}

/// `filebrowser.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
    /// Online install settings (upstream `binstall.Config`).
    pub install: InstallConfig,
    pub instances: Vec<Instance>,
}

/// Module settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Settings {
    /// filebrowser binary path; empty → config dir `bin/` → `PATH`
    /// (upstream `binPath`).
    #[serde(rename = "binPath")]
    pub program_path: String,
}

/// Per-program online install settings (upstream `binstall.Config`): only
/// the download proxy; empty follows the global update proxy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct InstallConfig {
    pub proxy: String,
}

/// The authentication method (Quantum `auth.methods`, upstream
/// `authMethod`: `password` | `proxy` | `noauth`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// Local accounts with username and password (Quantum default).
    #[default]
    Password,
    /// Trust a reverse-proxy-provided username header — the port must not
    /// be reachable from outside, or anyone can forge the header.
    Proxy,
    /// No authentication at all.
    NoAuth,
}

/// One shared directory entry (upstream `sources[]`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Source {
    /// Absolute filesystem path; must not overlap the Gately config dir
    /// (File Browser reads the directory directly and cannot hide a
    /// subtree, unlike WebDAV/FTP/SMB).
    pub path: String,
    /// Display name; empty takes the directory's base name.
    pub name: String,
    /// Read-only share (Quantum `sources[].config.readOnly`).
    pub read_only: bool,
}

/// One File Browser instance = one independent Quantum process.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Instance {
    pub key: String,
    pub name: String,
    /// Display-only group; empty = ungrouped.
    pub group: String,
    /// Start the instance with the module (`enable` toggles start/stop).
    pub enable: bool,
    /// Listen address; `None` = all IPv4 (upstream leaves it empty and
    /// Quantum defaults to `0.0.0.0`).
    pub listen_ip: Option<IpAddr>,
    /// Listen port; 0 normalizes to [`limits::DEFAULT_PORT`].
    pub port: u16,
    /// Sub-path the instance serves under; default `/`.
    pub base_url: String,
    /// Access URLs shown on the card; the first one's scheme, host and
    /// port become Quantum's `http.externalUrl` (share links).
    pub access_urls: Vec<String>,
    /// Shared directories; a missing directory keeps the instance from
    /// starting (the card shows the reason).
    pub sources: Vec<Source>,
    pub auth_method: AuthMethod,
    /// Header carrying the username in `proxy` mode.
    pub proxy_header: String,
    /// Admin account name; Quantum resets it on startup to this value.
    pub admin_user: String,
    /// Admin password; synced into Quantum on every start (later changes
    /// inside File Browser are overwritten) — passed via the environment.
    pub admin_password: String,
    /// Honor X-Forwarded-* headers (Quantum `http.trustProxyHeaders`).
    pub trust_proxy_headers: bool,
    /// Disable the WebDAV endpoint (Quantum `http.disableWebDAV`).
    pub disable_web_dav: bool,
    /// Frontend locale (Quantum `frontend.locale`); empty = default.
    pub locale: String,
    /// Web session token lifetime in hours; 0 normalizes to
    /// [`limits::DEFAULT_TOKEN_HOURS`].
    pub token_hours: u32,
    pub remark: String,
}

impl Instance {
    /// The effective listen port after normalization.
    pub fn effective_port(&self) -> u16 {
        if self.port == 0 {
            limits::DEFAULT_PORT
        } else {
            self.port
        }
    }

    /// The effective token lifetime after normalization.
    pub fn effective_token_hours(&self) -> u32 {
        if self.token_hours == 0 {
            limits::DEFAULT_TOKEN_HOURS
        } else {
            self.token_hours
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_quantum_documented_values() {
        let config: FileConfig = serde_json::from_str("{}").expect("empty file loads");
        assert_eq!(config.settings.program_path, "");
        assert_eq!(config.install.proxy, "");
        assert!(config.instances.is_empty());

        let instance: Instance = serde_json::from_str("{}").expect("empty instance loads");
        assert_eq!(instance.auth_method, AuthMethod::Password);
        assert_eq!(instance.effective_port(), limits::DEFAULT_PORT);
        assert_eq!(
            instance.effective_token_hours(),
            limits::DEFAULT_TOKEN_HOURS
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = r#"{"settings":{"nope":1}}"#;
        assert!(serde_json::from_str::<FileConfig>(text).is_err());
    }

    #[test]
    fn auth_method_parses_the_three_documented_names() {
        for (text, expected) in [
            ("password", AuthMethod::Password),
            ("proxy", AuthMethod::Proxy),
            ("noauth", AuthMethod::NoAuth),
        ] {
            let value = format!(r#"{{"authMethod":"{text}"}}"#);
            let instance: Instance = serde_json::from_str(&value).expect(text);
            assert_eq!(instance.auth_method, expected);
        }
    }
}
