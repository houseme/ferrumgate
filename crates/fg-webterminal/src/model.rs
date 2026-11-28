//! The `webterminal.json` model (WP-61 §3.2/§3.4): module settings, the
//! connection collection, SSH authentication presets, and shortcuts. Field
//! names follow the upstream configuration file (camelCase); secrets are
//! stored in plain text and masked by [`crate::validate`] at the API
//! boundary — the file itself is protected by the config store's 0600
//! permissions.

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here). Values follow WP-61 §3.4.
pub mod limits {
    use std::time::Duration;

    /// Upstream `maxSessions` default: concurrent terminal sessions.
    pub const MAX_SESSIONS_DEFAULT: u32 = 20;
    /// Upstream ceiling for `maxSessions`; a new session beyond the limit
    /// answers HTTP 429.
    pub const MAX_SESSIONS_MAX: u32 = 1000;
    /// Upstream `idleTimeout` default in minutes (0 = no idle limit).
    pub const IDLE_TIMEOUT_DEFAULT: u32 = 0;
    /// Upstream `bufferSize` default in KB (the per-session replay buffer).
    pub const BUFFER_SIZE_KB_DEFAULT: u32 = 256;
    /// Upstream ceiling for `bufferSize`.
    pub const BUFFER_SIZE_KB_MAX: u32 = 16384;
    /// Upstream `heartbeatInterval` default in seconds.
    pub const HEARTBEAT_INTERVAL_DEFAULT: u32 = 30;
    /// Upstream ceiling for `heartbeatInterval`.
    pub const HEARTBEAT_INTERVAL_MAX: u32 = 600;
    /// Upstream `sessionKeepAlive` default in minutes (0 = a session ends
    /// as soon as its last client disconnects).
    pub const SESSION_KEEP_ALIVE_DEFAULT: u32 = 0;
    /// Upstream `maxKeepAliveMin`: ceiling for `sessionKeepAlive` (7 days).
    pub const SESSION_KEEP_ALIVE_MAX: u32 = 10080;
    /// SSH/Telnet connect timeout default in seconds.
    pub const CONNECT_TIMEOUT_DEFAULT: u32 = 15;
    /// Connect timeout lower bound.
    pub const CONNECT_TIMEOUT_MIN: u32 = 1;
    /// Connect timeout upper bound.
    pub const CONNECT_TIMEOUT_MAX: u32 = 120;

    /// Default SSH port.
    pub const SSH_PORT: u16 = 22;
    /// Default Telnet port.
    pub const TELNET_PORT: u16 = 23;

    /// Upstream: SFTP text preview cap; larger files answer HTTP 413.
    pub const SFTP_PREVIEW_MAX_BYTES: usize = 1024 * 1024;
    /// Upstream: an idle SFTP connection is closed after 5 minutes.
    pub const SFTP_IDLE_AFTER: Duration = Duration::from_secs(300);
    /// Upstream: archive preview lists at most 10000 entries.
    pub const ARCHIVE_PREVIEW_MAX_ENTRIES: usize = 10000;

    /// Terminal default window size used when a client does not send one.
    pub const DEFAULT_COLS: u16 = 120;
    /// Terminal default window size used when a client does not send one.
    pub const DEFAULT_ROWS: u16 = 30;
    /// Default `terminalType` for SSH PTY requests.
    pub const TERMINAL_TYPE: &str = "xterm-256color";

    /// WS input: one text frame may carry at most 64 KB of JSON.
    pub const WS_MESSAGE_MAX_BYTES: usize = 64 * 1024;
    /// One replayed broadcast chunk granularity cap: output from the backend
    /// is chunked so no single frame exceeds this size.
    pub const OUTPUT_CHUNK_MAX_BYTES: usize = 16 * 1024;

    /// FerrumGate protection: connection / preset display name length.
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: remark length.
    pub const REMARK_MAX_CHARS: usize = 512;
    /// FerrumGate protection: session remark length.
    pub const SESSION_REMARK_MAX_CHARS: usize = 256;
    /// FerrumGate protection: host name length.
    pub const HOST_MAX_CHARS: usize = 253;
    /// FerrumGate protection: username length.
    pub const USERNAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: shortcut name / command length.
    pub const COMMAND_MAX_CHARS: usize = 4096;
    /// FerrumGate protection: shortcut name length.
    pub const SHORTCUT_NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: `env` entries per connection.
    pub const ENV_MAX: usize = 32;
    /// FerrumGate protection: shortcuts per connection / globally.
    pub const SHORTCUTS_MAX: usize = 64;
    /// FerrumGate protection: quick access directories per connection.
    pub const QUICK_ACCESS_MAX: usize = 32;
    /// FerrumGate protection: group name length (conventions §3.3).
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: pasted private key size.
    pub const PASTED_KEY_MAX_BYTES: usize = 64 * 1024;
    /// FerrumGate protection: work dir / shell path length.
    pub const PATH_MAX_CHARS: usize = 1024;
    /// FerrumGate protection: split layout JSON size.
    pub const SPLIT_LAYOUT_MAX_BYTES: usize = 64 * 1024;
    /// Batch bodies carry at most this many keys (conventions §3.3).
    pub const BATCH_KEYS_MAX: usize = 500;

    /// The mask shown instead of secret values (conventions §3.3).
    pub const SECRET_MASK: &str = "********";

    /// The key format for collection entries (conventions §3.3: 12 hex).
    pub const KEY_HEX_CHARS: usize = 12;
}

/// `webterminal.json`: settings, connections, authentication presets,
/// global shortcuts, security settings and the terminal split layout.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FileConfig {
    pub settings: Settings,
    pub connections: Vec<Connection>,
    pub credentials: Vec<Preset>,
    pub global_shortcuts: Vec<Shortcut>,
    /// The saved pane layout; opaque JSON stored and served verbatim.
    pub split_layout: Option<serde_json::Value>,
    /// User agreement and 2FA settings (WP-61 §3.3).
    pub security: SecurityConfig,
}

/// Security state stored in `webterminal.json` (WP-61 §3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SecurityConfig {
    /// Whether the user has accepted the terminal usage agreement.
    pub agreement_accepted: bool,
    /// RFC 3339 timestamp when the agreement was accepted.
    pub agreement_accepted_at: Option<String>,
    /// Whether TOTP 2FA verification is required to open terminals / view secrets.
    pub two_fa_enabled: bool,
    /// Active Base32-encoded TOTP secret (never returned in plaintext).
    pub two_fa_secret: String,
    /// Pending Base32-encoded TOTP secret generated during setup, before enable.
    pub two_fa_pending_secret: String,
}

/// Module settings (WP-61 §3.4). Zeros fall back to the upstream defaults
/// and values beyond a ceiling are clamped by [`crate::validate::normalize`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    /// Local shell terminals are only offered when enabled (default off —
    /// WP-61 §8: it is a shell with the daemon's user).
    pub allow_local_shell: bool,
    /// Concurrent sessions (`maxSessions`).
    pub max_sessions: u32,
    /// Minutes without input/output before a session ends (`idleTimeout`;
    /// 0 = unlimited).
    pub idle_timeout: u32,
    /// Replay buffer per session in KB (`bufferSize`).
    pub buffer_size: u32,
    /// WS heartbeat period in seconds (`heartbeatInterval`).
    pub heartbeat_interval: u32,
    /// Minutes a session survives its last client (`sessionKeepAlive`;
    /// 0 = ends on disconnect).
    pub session_keep_alive: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow_local_shell: false,
            max_sessions: limits::MAX_SESSIONS_DEFAULT,
            idle_timeout: limits::IDLE_TIMEOUT_DEFAULT,
            buffer_size: limits::BUFFER_SIZE_KB_DEFAULT,
            heartbeat_interval: limits::HEARTBEAT_INTERVAL_DEFAULT,
            session_keep_alive: limits::SESSION_KEEP_ALIVE_DEFAULT,
        }
    }
}

/// The connection types (WP-61 §3.3 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnKind {
    Ssh,
    Telnet,
    /// A shell on the machine running FerrumGate.
    Local,
}

impl ConnKind {
    /// The default TCP port (`local` has none).
    pub fn default_port(self) -> Option<u16> {
        match self {
            Self::Ssh => Some(limits::SSH_PORT),
            Self::Telnet => Some(limits::TELNET_PORT),
            Self::Local => None,
        }
    }
}

/// How a connection authenticates. Upstream stores all shapes flat under
/// `auth`; the `kind` selector decides which fields are meaningful. Secret
/// fields follow the masking rule: `********` or empty on submit means
/// "keep the stored value" (handled by [`crate::validate::merge_auth`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Auth {
    pub kind: AuthKind,
    /// Password authentication.
    pub password: String,
    /// Private key pasted into the form (OpenSSH PEM).
    pub pasted: String,
    /// Private key read from a file on the FerrumGate machine.
    pub key_file: String,
    /// Private key passphrase.
    pub passphrase: String,
    /// Reference to a [`Preset`] key (`kind` = preset).
    pub preset: String,
}

/// The authentication kind selector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    /// Password authentication.
    #[default]
    Password,
    /// Public key authentication (`pasted` or `keyFile`).
    Key,
    /// Look the credentials up in a [`Preset`] at connect time.
    Preset,
}

impl AuthKind {
    /// Whether this kind carries its own secret material.
    pub fn is_secret(self) -> bool {
        matches!(self, Self::Password | Self::Key)
    }
}

/// A recorded SSH host key (TOFU, WP-61 §3.3): fingerprint with the key
/// type used to display it the way `ssh-keygen -l` does. `key_type` may be
/// absent when the fingerprint came from `ssh-keyscan` output for another
/// type; the type is backfilled after the first successful handshake.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HostKey {
    /// The negotiated host key family, if known.
    pub key_type: Option<HostKeyType>,
    /// `SHA256:<base64>` fingerprint (same form as `ssh-keygen -l`).
    pub fingerprint: String,
}

/// The SSH host key families the module can negotiate (`keyType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostKeyType {
    Ed25519,
    Ecdsa,
    Rsa,
    Dsa,
}

impl HostKeyType {
    /// The `ssh-keygen -l` style label (`ECDSA SHA256:…`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "ED25519",
            Self::Ecdsa => "ECDSA",
            Self::Rsa => "RSA",
            Self::Dsa => "DSA",
        }
    }

    /// All families in fallback order: when the recorded type is missing or
    /// the server no longer offers it, the remaining types are tried one by
    /// one (WP-61 §3.3).
    pub const ALL: [HostKeyType; 4] = [
        HostKeyType::Ed25519,
        HostKeyType::Ecdsa,
        HostKeyType::Rsa,
        HostKeyType::Dsa,
    ];
}

/// An outbound proxy for SSH and Telnet connections.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Proxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Secret field (masked at the API boundary).
    pub password: String,
}

/// The proxy protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[default]
    Socks5,
    Http,
}

/// A stored connection entry (`connections` collection).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Connection {
    pub key: String,
    pub name: String,
    pub kind: ConnKind,
    pub group: String,
    pub remark: String,
    pub enable: bool,
    /// Target host (ssh/telnet); unused for `local`.
    pub host: String,
    /// 0 falls back to the kind's default port.
    pub port: u16,
    pub username: String,
    pub auth: Auth,
    /// Login working directory (ssh: `cd` after connect).
    pub work_dir: String,
    /// Shell path for `local` connections (empty = login shell).
    pub shell_path: String,
    /// SSH transport keepalive in seconds; 0 disables it.
    pub keep_alive: u32,
    /// Connect timeout in seconds (default 15; 1–120).
    pub connect_timeout: u32,
    /// Trusted host fingerprint (TOFU record).
    pub host_key: Option<HostKey>,
    pub proxy: Option<Proxy>,
    /// SSH PTY `TERM` value; empty falls back to [`limits::TERMINAL_TYPE`].
    pub terminal_type: Option<String>,
    /// Extra environment variables attached to the session.
    pub env: Vec<(String, String)>,
    /// One-click commands for this connection.
    pub shortcuts: Vec<Shortcut>,
    /// Saved directories for the file manager's quick access.
    pub quick_access: Vec<String>,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            key: String::new(),
            name: String::new(),
            kind: ConnKind::Ssh,
            group: String::new(),
            remark: String::new(),
            enable: true,
            host: String::new(),
            port: 0,
            username: String::new(),
            auth: Auth::default(),
            work_dir: String::new(),
            shell_path: String::new(),
            keep_alive: 0,
            connect_timeout: limits::CONNECT_TIMEOUT_DEFAULT,
            host_key: None,
            proxy: None,
            terminal_type: None,
            env: Vec::new(),
            shortcuts: Vec::new(),
            quick_access: Vec::new(),
        }
    }
}

impl Connection {
    /// Whether the connection is a terminal kind that reaches a TCP host.
    pub fn uses_host(&self) -> bool {
        matches!(self.kind, ConnKind::Ssh | ConnKind::Telnet)
    }

    /// The effective port: the stored one or the kind default.
    pub fn effective_port(&self) -> Option<u16> {
        match self.kind {
            ConnKind::Local => None,
            kind => Some(if self.port == 0 {
                kind.default_port().unwrap_or_default()
            } else {
                self.port
            }),
        }
    }

    /// The effective connect timeout as a duration.
    pub fn effective_timeout(&self) -> std::time::Duration {
        let secs = if self.connect_timeout == 0 {
            limits::CONNECT_TIMEOUT_DEFAULT
        } else {
            self.connect_timeout.min(limits::CONNECT_TIMEOUT_MAX)
        };
        std::time::Duration::from_secs(u64::from(secs))
    }

    /// The effective PTY terminal type.
    pub fn effective_terminal_type(&self) -> &str {
        match self.terminal_type.as_deref() {
            Some(value) if !value.is_empty() => value,
            _ => limits::TERMINAL_TYPE,
        }
    }
}

/// An SSH authentication preset (`credentials` collection): a password or
/// private key shared by several connections; editing the preset updates
/// every connection that references it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Preset {
    pub key: String,
    pub name: String,
    /// Password or key only — a preset cannot reference another preset.
    pub kind: AuthKind,
    /// Optional default username for connections using the preset.
    pub username: String,
    pub password: String,
    /// Private key (OpenSSH PEM).
    pub pasted: String,
    /// Private key passphrase.
    pub passphrase: String,
}

/// A one-click command (per connection or global).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Shortcut {
    pub name: String,
    pub command: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_defaults_match_doc_limits() {
        let settings = Settings::default();
        assert!(!settings.allow_local_shell);
        assert_eq!(settings.max_sessions, 20);
        assert_eq!(settings.idle_timeout, 0);
        assert_eq!(settings.buffer_size, 256);
        assert_eq!(settings.heartbeat_interval, 30);
        assert_eq!(settings.session_keep_alive, 0);
    }

    #[test]
    fn settings_json_is_camel_case_and_rejects_unknown() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "allowLocalShell": true,
            "maxSessions": 5,
            "idleTimeout": 10,
            "bufferSize": 128,
            "heartbeatInterval": 15,
            "sessionKeepAlive": 60
        }))
        .expect("parse settings");
        assert!(settings.allow_local_shell);
        assert_eq!(settings.max_sessions, 5);
        let bad = serde_json::from_value::<Settings>(serde_json::json!({
            "maxSessions": 5,
            "unknown": 1
        }));
        assert!(bad.is_err());
        // Missing fields fall back to the defaults.
        let partial: Settings = serde_json::from_value(serde_json::json!({})).expect("partial");
        assert_eq!(partial, Settings::default());
    }

    #[test]
    fn connection_defaults_fill_ports_and_timeout() {
        let mut conn = Connection::default();
        assert_eq!(conn.kind, ConnKind::Ssh);
        assert!(conn.enable);
        assert_eq!(conn.connect_timeout, 15);
        assert_eq!(conn.effective_port(), Some(22));
        conn.kind = ConnKind::Telnet;
        assert_eq!(conn.effective_port(), Some(23));
        conn.port = 2222;
        assert_eq!(conn.effective_port(), Some(2222));
        conn.kind = ConnKind::Local;
        assert_eq!(conn.effective_port(), None);
        assert_eq!(conn.effective_timeout(), std::time::Duration::from_secs(15));
        conn.connect_timeout = 0;
        assert_eq!(conn.effective_timeout(), std::time::Duration::from_secs(15));
        conn.connect_timeout = 999;
        assert_eq!(
            conn.effective_timeout(),
            std::time::Duration::from_secs(120)
        );
        assert_eq!(conn.effective_terminal_type(), "xterm-256color");
    }

    #[test]
    fn connection_json_round_trips_camel_case() {
        let text = serde_json::json!({
            "key": "0123456789ab",
            "name": "路由器",
            "kind": "ssh",
            "group": "核心",
            "remark": "",
            "enable": true,
            "host": "192.168.1.1",
            "port": 22,
            "username": "root",
            "auth": { "kind": "password", "password": "secret" },
            "hostKey": { "keyType": "ed25519", "fingerprint": "SHA256:abc" },
            "proxy": { "kind": "socks5", "host": "127.0.0.1", "port": 1080 },
            "env": [["TERM_COLORS", "1"]],
            "shortcuts": [{ "name": "状态", "command": "uptime" }],
            "quickAccess": ["/var/log"]
        });
        let conn: Connection = serde_json::from_value(text).expect("parse connection");
        assert_eq!(conn.name, "路由器");
        assert_eq!(conn.auth.kind, AuthKind::Password);
        assert_eq!(
            conn.host_key.as_ref().and_then(|key| key.key_type),
            Some(HostKeyType::Ed25519)
        );
        assert_eq!(conn.proxy.as_ref().map(|proxy| proxy.port), Some(1080));
        assert_eq!(conn.env, vec![("TERM_COLORS".to_owned(), "1".to_owned())]);
        // Unknown fields are rejected.
        let bad = serde_json::from_value::<Connection>(serde_json::json!({
            "key": "k", "nope": 1
        }));
        assert!(bad.is_err());
    }

    #[test]
    fn host_key_types_have_ssh_keygen_labels() {
        assert_eq!(HostKeyType::Ed25519.label(), "ED25519");
        assert_eq!(HostKeyType::Ecdsa.label(), "ECDSA");
        assert_eq!(HostKeyType::Rsa.label(), "RSA");
        assert_eq!(HostKeyType::Dsa.label(), "DSA");
        assert_eq!(HostKeyType::ALL.len(), 4);
    }

    #[test]
    fn preset_defaults_are_password_kind() {
        let preset: Preset = serde_json::from_value(serde_json::json!({
            "key": "0123456789ab", "name": "默认凭据"
        }))
        .expect("parse preset");
        assert_eq!(preset.kind, AuthKind::Password);
        assert!(!preset.kind.is_secret() || preset.kind == AuthKind::Password);
    }
}
