//! Validation and normalization (WP-61 §3.2/§3.4): pure functions over
//! plain data — no I/O. Also the secret masking and "keep the stored value"
//! merge rules that shape the API boundary: secret fields are shown as
//! `********`, and submitting `********` or an empty string keeps the
//! stored value.

use serde::Serialize;

use crate::model::limits;
use crate::model::{
    Auth, AuthKind, ConnKind, Connection, FileConfig, HostKey, Preset, Settings, Shortcut,
};

/// One validation problem, reported as `{"field":…,"reason":…}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

/// Clamps the settings and fills every entry's defaults so each value is
/// within the documented bounds (WP-61 §3.4). 0 means "use the default"
/// where upstream treats it that way; values beyond a ceiling are pulled
/// back to it.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    let settings = &mut config.settings;
    settings.max_sessions = if settings.max_sessions == 0 {
        limits::MAX_SESSIONS_DEFAULT
    } else {
        settings.max_sessions.min(limits::MAX_SESSIONS_MAX)
    };
    settings.buffer_size = if settings.buffer_size == 0 {
        limits::BUFFER_SIZE_KB_DEFAULT
    } else {
        settings.buffer_size.min(limits::BUFFER_SIZE_KB_MAX)
    };
    settings.heartbeat_interval = if settings.heartbeat_interval == 0 {
        limits::HEARTBEAT_INTERVAL_DEFAULT
    } else {
        settings
            .heartbeat_interval
            .min(limits::HEARTBEAT_INTERVAL_MAX)
    };
    settings.session_keep_alive = settings
        .session_keep_alive
        .min(limits::SESSION_KEEP_ALIVE_MAX);
    // `idleTimeout` has no ceiling upstream; 0 stays "no idle limit".

    for conn in &mut config.connections {
        normalize_connection(conn);
    }
    for preset in &mut config.credentials {
        normalize_preset(preset);
    }
    config.global_shortcuts = clean_shortcuts(config.global_shortcuts);
    config
}

/// Applies one connection's defaults and trimming in place.
pub fn normalize_connection(conn: &mut Connection) {
    conn.name = conn.name.trim().to_owned();
    conn.group = conn.group.trim().to_owned();
    conn.host = conn.host.trim().to_owned();
    conn.username = conn.username.trim().to_owned();
    if conn.port == 0 {
        conn.port = conn.kind.default_port().unwrap_or_default();
    }
    conn.connect_timeout = conn
        .connect_timeout
        .clamp(limits::CONNECT_TIMEOUT_MIN, limits::CONNECT_TIMEOUT_MAX);
    if let Some(proxy) = &mut conn.proxy {
        proxy.host = proxy.host.trim().to_owned();
        if proxy.port == 0 {
            proxy.port = default_proxy_port(proxy.kind);
        }
    }
    conn.env.retain(|(name, _)| !name.trim().is_empty());
    if conn.env.len() > limits::ENV_MAX {
        conn.env.truncate(limits::ENV_MAX);
    }
    conn.shortcuts = clean_shortcuts(std::mem::take(&mut conn.shortcuts));
    conn.quick_access.retain(|path| !path.trim().is_empty());
    if conn.quick_access.len() > limits::QUICK_ACCESS_MAX {
        conn.quick_access.truncate(limits::QUICK_ACCESS_MAX);
    }
    // A host key type that is not one of the known families is dropped, the
    // fingerprint stays (WP-61 §3.3: types from other tools may be present).
    if let Some(host_key) = &conn.host_key
        && host_key.fingerprint.trim().is_empty()
    {
        conn.host_key = None;
    }
    if conn.work_dir.len() > limits::PATH_MAX_CHARS {
        conn.work_dir.truncate(limits::PATH_MAX_CHARS);
    }
    if conn.shell_path.len() > limits::PATH_MAX_CHARS {
        conn.shell_path.truncate(limits::PATH_MAX_CHARS);
    }
    // A preset reference must name an existing preset; a stale reference
    // falls back to password auth (reported by `validate`).
}

fn normalize_preset(preset: &mut Preset) {
    preset.name = preset.name.trim().to_owned();
    preset.username = preset.username.trim().to_owned();
    if preset.kind == AuthKind::Preset {
        preset.kind = AuthKind::Password;
    }
}

fn default_proxy_port(kind: crate::model::ProxyKind) -> u16 {
    match kind {
        crate::model::ProxyKind::Socks5 => 1080,
        crate::model::ProxyKind::Http => 8080,
    }
}

/// Trims and caps a shortcut list (shared by connections and globals).
pub fn clean_shortcuts(shortcuts: Vec<Shortcut>) -> Vec<Shortcut> {
    let cleaned: Vec<Shortcut> = shortcuts
        .into_iter()
        .map(|mut shortcut| {
            shortcut.name = shortcut
                .name
                .trim()
                .chars()
                .take(limits::SHORTCUT_NAME_MAX_CHARS)
                .collect();
            shortcut.command = shortcut
                .command
                .trim()
                .chars()
                .take(limits::COMMAND_MAX_CHARS)
                .collect();
            shortcut
        })
        .filter(|shortcut| !shortcut.name.is_empty() && !shortcut.command.is_empty())
        .collect();
    if cleaned.len() > limits::SHORTCUTS_MAX {
        return cleaned.into_iter().take(limits::SHORTCUTS_MAX).collect();
    }
    cleaned
}

/// Settings-level and entry-level problems (apply after [`normalize`]:
/// only what the clamp cannot repair is reported).
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    let preset_keys: std::collections::HashSet<&str> = config
        .credentials
        .iter()
        .map(|preset| preset.key.as_str())
        .collect();

    for (index, conn) in config.connections.iter().enumerate() {
        let prefix = format!("connections[{index}]");
        if conn.name.is_empty() {
            problems.push(Problem {
                field: format!("{prefix}.name"),
                reason: "名称不能为空".into(),
            });
        }
        if conn.name.chars().count() > limits::NAME_MAX_CHARS {
            problems.push(Problem {
                field: format!("{prefix}.name"),
                reason: format!("名称超过 {} 个字符", limits::NAME_MAX_CHARS),
            });
        }
        if conn.uses_host() {
            if conn.host.is_empty() {
                problems.push(Problem {
                    field: format!("{prefix}.host"),
                    reason: "主机不能为空".into(),
                });
            } else if conn.host.len() > limits::HOST_MAX_CHARS {
                problems.push(Problem {
                    field: format!("{prefix}.host"),
                    reason: format!("主机超过 {} 个字符", limits::HOST_MAX_CHARS),
                });
            }
            if conn.effective_port() == Some(0) {
                problems.push(Problem {
                    field: format!("{prefix}.port"),
                    reason: "端口无效".into(),
                });
            }
            if let Some(proxy) = &conn.proxy
                && proxy.host.is_empty()
            {
                problems.push(Problem {
                    field: format!("{prefix}.proxy.host"),
                    reason: "代理主机不能为空".into(),
                });
            }
            if conn.auth.kind == AuthKind::Preset {
                if !preset_keys.contains(conn.auth.preset.as_str()) {
                    problems.push(Problem {
                        field: format!("{prefix}.auth.preset"),
                        reason: format!("凭据预设 {} 不存在", conn.auth.preset),
                    });
                }
            } else if conn.auth.kind.is_secret()
                && conn.auth.password.is_empty()
                && conn.auth.pasted.is_empty()
                && conn.auth.key_file.is_empty()
            {
                problems.push(Problem {
                    field: format!("{prefix}.auth"),
                    reason: "缺少密码或私钥".into(),
                });
            }
        }
        if conn.kind == ConnKind::Ssh
            && let Some(host_key) = &conn.host_key
            && let Some(problem) = host_key_problem(&format!("{prefix}.hostKey"), host_key)
        {
            problems.push(problem);
        }
    }

    for (index, preset) in config.credentials.iter().enumerate() {
        let prefix = format!("credentials[{index}]");
        if preset.name.is_empty() {
            problems.push(Problem {
                field: format!("{prefix}.name"),
                reason: "名称不能为空".into(),
            });
        }
        if preset.kind == AuthKind::Preset {
            problems.push(Problem {
                field: format!("{prefix}.kind"),
                reason: "预设不能引用另一个预设".into(),
            });
        }
        if preset.kind == AuthKind::Key && preset.pasted.len() > limits::PASTED_KEY_MAX_BYTES {
            problems.push(Problem {
                field: format!("{prefix}.pasted"),
                reason: format!("私钥超过 {} 字节", limits::PASTED_KEY_MAX_BYTES),
            });
        }
    }

    for (index, shortcut) in config.global_shortcuts.iter().enumerate() {
        if shortcut.command.is_empty() {
            problems.push(Problem {
                field: format!("globalShortcuts[{index}].command"),
                reason: "命令不能为空".into(),
            });
        }
    }
    problems
}

/// One host key's shape problems, if any.
fn host_key_problem(field: &str, host_key: &HostKey) -> Option<Problem> {
    if !valid_fingerprint(&host_key.fingerprint) {
        return Some(Problem {
            field: format!("{field}.fingerprint"),
            reason: "指纹格式无效（应为 SHA256:开头）".into(),
        });
    }
    None
}

/// A fingerprint is `SHA256:` followed by unpadded base64 (the
/// `ssh-keygen -l` shape); legacy MD5 hex from other tools is not accepted.
pub fn valid_fingerprint(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("SHA256:") else {
        return false;
    };
    let digest = rest.trim_end_matches('=');
    !digest.is_empty()
        && digest.len() == 43
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

/// The `ECDSA SHA256:…` label shown in the UI (same shape as
/// `ssh-keygen -l`, WP-61 §3.3).
pub fn host_key_label(host_key: &HostKey) -> String {
    match host_key.key_type {
        Some(key_type) => format!("{} {}", key_type.label(), host_key.fingerprint),
        None => host_key.fingerprint.clone(),
    }
}

// --- Secret masking ------------------------------------------------------

/// Whether `value` means "keep the stored secret" at the API boundary
/// (`********` or empty).
pub fn is_secret_placeholder(value: &str) -> bool {
    value.is_empty() || value == limits::SECRET_MASK
}

/// Masks a connection's secret fields for API output.
pub fn mask_connection(mut conn: Connection) -> Connection {
    if !conn.auth.password.is_empty() {
        conn.auth.password = limits::SECRET_MASK.into();
    }
    if !conn.auth.pasted.is_empty() {
        conn.auth.pasted = limits::SECRET_MASK.into();
    }
    if !conn.auth.passphrase.is_empty() {
        conn.auth.passphrase = limits::SECRET_MASK.into();
    }
    if let Some(proxy) = &mut conn.proxy
        && !proxy.password.is_empty()
    {
        proxy.password = limits::SECRET_MASK.into();
    }
    conn
}

/// Masks a preset's secret fields for API output.
pub fn mask_preset(mut preset: Preset) -> Preset {
    if !preset.password.is_empty() {
        preset.password = limits::SECRET_MASK.into();
    }
    if !preset.pasted.is_empty() {
        preset.pasted = limits::SECRET_MASK.into();
    }
    if !preset.passphrase.is_empty() {
        preset.passphrase = limits::SECRET_MASK.into();
    }
    preset
}

/// Merges a submitted connection onto the stored one: `********` or an
/// empty secret field keeps the stored value (conventions §3.3). The key,
/// name, group and enable flag are taken from the caller's context.
pub fn merge_connection(existing: &Connection, mut incoming: Connection) -> Connection {
    incoming.auth = merge_auth(&existing.auth, incoming.auth);
    match (&existing.proxy, &mut incoming.proxy) {
        (Some(stored), Some(proxy)) => {
            if is_secret_placeholder(&proxy.password) {
                proxy.password = stored.password.clone();
            }
        }
        (Some(stored), None) => incoming.proxy = Some(stored.clone()),
        (None, Some(proxy)) => {
            if is_secret_placeholder(&proxy.password) {
                // No stored proxy: an empty password stays empty.
                proxy.password.clear();
            }
        }
        (None, None) => {}
    }
    incoming
}

/// Merges authentication secrets with the placeholder rule.
pub fn merge_auth(existing: &Auth, mut incoming: Auth) -> Auth {
    if is_secret_placeholder(&incoming.password) {
        incoming.password = existing.password.clone();
    }
    if is_secret_placeholder(&incoming.pasted) {
        incoming.pasted = existing.pasted.clone();
    }
    if is_secret_placeholder(&incoming.passphrase) {
        incoming.passphrase = existing.passphrase.clone();
    }
    incoming
}

/// Merges a submitted preset onto the stored one (same placeholder rule).
pub fn merge_preset(existing: &Preset, mut incoming: Preset) -> Preset {
    if is_secret_placeholder(&incoming.password) {
        incoming.password = existing.password.clone();
    }
    if is_secret_placeholder(&incoming.pasted) {
        incoming.pasted = existing.pasted.clone();
    }
    if is_secret_placeholder(&incoming.passphrase) {
        incoming.passphrase = existing.passphrase.clone();
    }
    incoming
}

/// The plaintext secret fields of a connection for the `secrets` endpoint
/// (fg-admin's `secrets_guard` decides whether the caller may see them).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSecrets {
    pub password: String,
    pub pasted: String,
    pub key_file: String,
    pub passphrase: String,
    pub proxy_username: String,
    pub proxy_password: String,
}

impl ConnectionSecrets {
    /// Collects the plaintext secrets of a connection.
    pub fn of(conn: &Connection) -> Self {
        Self {
            password: conn.auth.password.clone(),
            pasted: conn.auth.pasted.clone(),
            key_file: conn.auth.key_file.clone(),
            passphrase: conn.auth.passphrase.clone(),
            proxy_username: conn
                .proxy
                .as_ref()
                .map(|proxy| proxy.username.clone())
                .unwrap_or_default(),
            proxy_password: conn
                .proxy
                .as_ref()
                .map(|proxy| proxy.password.clone())
                .unwrap_or_default(),
        }
    }
}

/// The plaintext secret fields of a preset for its `secrets` endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetSecrets {
    pub password: String,
    pub pasted: String,
    pub passphrase: String,
}

impl PresetSecrets {
    /// Collects the plaintext secrets of a preset.
    pub fn of(preset: &Preset) -> Self {
        Self {
            password: preset.password.clone(),
            pasted: preset.pasted.clone(),
            passphrase: preset.passphrase.clone(),
        }
    }
}

/// Whether a connection references a preset with `key`.
pub fn references_preset(conn: &Connection, key: &str) -> bool {
    conn.auth.kind == AuthKind::Preset && conn.auth.preset == key
}

/// Whether any connection in `config` references the preset.
pub fn preset_in_use(config: &FileConfig, key: &str) -> bool {
    config
        .connections
        .iter()
        .any(|conn| references_preset(conn, key))
}

/// Whether the connection opens a local shell (gated by the settings,
/// WP-61 §8: disabled by default).
pub fn local_shell_allowed(settings: &Settings) -> bool {
    settings.allow_local_shell
}

/// A view of one connection for the API: the masked entry plus the
/// computed host-key label.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionView {
    #[serde(flatten)]
    pub connection: Connection,
    /// `ECDSA SHA256:…` or empty when no key is recorded.
    pub host_key_label: String,
    /// Whether a host fingerprint is recorded (untrusted targets are
    /// refused by `ssh_push`/`ssh_exec`).
    pub trusted: bool,
}

/// Builds the API view of a connection (masked secrets, derived fields).
pub fn connection_view(conn: &Connection) -> ConnectionView {
    ConnectionView {
        connection: mask_connection(conn.clone()),
        host_key_label: conn
            .host_key
            .as_ref()
            .map(host_key_label)
            .unwrap_or_default(),
        trusted: conn.host_key.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Proxy;

    fn ssh_conn() -> Connection {
        Connection {
            key: "0123456789ab".into(),
            name: "服务器".into(),
            kind: ConnKind::Ssh,
            host: "192.168.1.10".into(),
            port: 22,
            username: "root".into(),
            auth: Auth {
                kind: AuthKind::Password,
                password: "hunter2".into(),
                ..Auth::default()
            },
            ..Connection::default()
        }
    }

    #[test]
    fn normalize_clamps_settings_and_fills_defaults() {
        let config = FileConfig {
            settings: Settings {
                max_sessions: 0,
                idle_timeout: 999,
                buffer_size: 0,
                heartbeat_interval: 0,
                session_keep_alive: 99999,
                ..Settings::default()
            },
            connections: vec![Connection {
                port: 0,
                connect_timeout: 0,
                ..ssh_conn()
            }],
            ..FileConfig::default()
        };
        let normalized = normalize(config);
        assert_eq!(normalized.settings.max_sessions, 20);
        assert_eq!(normalized.settings.buffer_size, 256);
        assert_eq!(normalized.settings.heartbeat_interval, 30);
        assert_eq!(normalized.settings.session_keep_alive, 10080);
        // idle timeout has no ceiling upstream.
        assert_eq!(normalized.settings.idle_timeout, 999);
        let conn = &normalized.connections[0];
        assert_eq!(conn.port, 22);
        assert_eq!(conn.connect_timeout, 1);
        assert_eq!(conn.connect_timeout, limits::CONNECT_TIMEOUT_MIN);
    }

    #[test]
    fn normalize_connection_cleans_env_shortcuts_and_quick_access() {
        let mut conn = ssh_conn();
        conn.env = vec![
            ("A".into(), "1".into()),
            ("  ".into(), "dropped".into()),
            ("B".into(), "2".into()),
        ];
        conn.shortcuts = vec![
            Shortcut {
                name: " ok ".into(),
                command: " uptime ".into(),
            },
            Shortcut {
                name: "".into(),
                command: "no".into(),
            },
        ];
        conn.quick_access = vec!["/var/log".into(), "  ".into()];
        normalize_connection(&mut conn);
        assert_eq!(conn.env.len(), 2);
        assert_eq!(conn.shortcuts.len(), 1);
        assert_eq!(conn.shortcuts[0].command, "uptime");
        assert_eq!(conn.quick_access, vec!["/var/log".to_owned()]);
    }

    #[test]
    fn validate_reports_missing_host_and_stale_preset() {
        let mut config = normalize(FileConfig {
            connections: vec![ssh_conn()],
            credentials: vec![Preset {
                key: "presetkey001".into(),
                name: "凭据".into(),
                ..Preset::default()
            }],
            ..FileConfig::default()
        });
        config.connections[0].host = String::new();
        config.connections[0].auth.kind = AuthKind::Preset;
        config.connections[0].auth.preset = "missing00000".into();
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with(".host"))
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with("auth.preset"))
        );
        // The clean config has no problems.
        let mut clean = config.clone();
        clean.connections[0].host = "host".into();
        clean.connections[0].auth = Auth {
            kind: AuthKind::Preset,
            preset: "presetkey001".into(),
            ..Auth::default()
        };
        assert!(validate(&normalize(clean)).is_empty());
    }

    #[test]
    fn masking_and_merge_keep_secrets_round_trip() {
        let mut conn = ssh_conn();
        conn.auth.pasted = String::new();
        conn.auth.passphrase = "pp".into();
        conn.proxy = Some(Proxy {
            kind: crate::model::ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: 1080,
            username: "u".into(),
            password: "proxy-pw".into(),
        });
        let view = mask_connection(conn.clone());
        assert_eq!(view.auth.password, limits::SECRET_MASK);
        assert_eq!(view.auth.passphrase, limits::SECRET_MASK);
        assert_eq!(
            view.proxy.as_ref().expect("proxy").password,
            limits::SECRET_MASK
        );

        // Submitting the mask keeps every stored secret.
        let submitted = Connection {
            auth: Auth {
                kind: AuthKind::Password,
                password: limits::SECRET_MASK.into(),
                pasted: String::new(),
                passphrase: limits::SECRET_MASK.into(),
                ..Auth::default()
            },
            proxy: Some(Proxy {
                kind: crate::model::ProxyKind::Socks5,
                host: "127.0.0.2".into(),
                port: 1080,
                username: "u2".into(),
                password: limits::SECRET_MASK.into(),
            }),
            ..Connection::default()
        };
        let merged = merge_connection(&conn, submitted.clone());
        assert_eq!(merged.auth.password, "hunter2");
        assert_eq!(merged.auth.passphrase, "pp");
        assert_eq!(
            merged.proxy.as_ref().expect("proxy kept").password,
            "proxy-pw"
        );
        assert_eq!(merged.proxy.as_ref().expect("proxy kept").host, "127.0.0.2");

        // A proxy dropped from the form keeps the stored one.
        let mut no_proxy = submitted;
        no_proxy.proxy = None;
        let merged = merge_connection(&conn, no_proxy);
        assert_eq!(
            merged.proxy.as_ref().expect("stored proxy").password,
            "proxy-pw"
        );
    }

    #[test]
    fn fingerprint_shape_follows_ssh_keygen() {
        let good = format!("SHA256:{}", "a".repeat(43));
        assert!(valid_fingerprint(&good));
        assert!(!valid_fingerprint("SHA256:short"));
        assert!(!valid_fingerprint("MD5:aa:bb"));
        assert!(!valid_fingerprint(""));
        let host_key = HostKey {
            key_type: Some(crate::model::HostKeyType::Ecdsa),
            fingerprint: good.clone(),
        };
        assert_eq!(host_key_label(&host_key), format!("ECDSA {good}"));
        let without_type = HostKey {
            key_type: None,
            fingerprint: good.clone(),
        };
        assert_eq!(host_key_label(&without_type), good);
    }

    #[test]
    fn preset_in_use_blocks_delete_of_referenced_preset() {
        let mut config = FileConfig::default();
        config.credentials.push(Preset {
            key: "usedkey000001".into(),
            name: "used".into(),
            ..Preset::default()
        });
        config.credentials.push(Preset {
            key: "freekey000001".into(),
            name: "free".into(),
            ..Preset::default()
        });
        let mut conn = ssh_conn();
        conn.auth = Auth {
            kind: AuthKind::Preset,
            preset: "usedkey000001".into(),
            ..Auth::default()
        };
        config.connections.push(conn);
        assert!(preset_in_use(&config, "usedkey000001"));
        assert!(!preset_in_use(&config, "freekey000001"));
    }

    #[test]
    fn secrets_views_expose_plaintext_for_guarded_endpoint() {
        let mut conn = ssh_conn();
        conn.auth.key_file = "/keys/id_ed25519".into();
        let secrets = ConnectionSecrets::of(&conn);
        assert_eq!(secrets.password, "hunter2");
        assert_eq!(secrets.key_file, "/keys/id_ed25519");
        let preset = Preset {
            password: "pw".into(),
            pasted: "-----BEGIN".into(),
            passphrase: "enc".into(),
            ..Preset::default()
        };
        let secrets = PresetSecrets::of(&preset);
        assert_eq!(secrets.passphrase, "enc");
        let masked = mask_preset(preset);
        assert_eq!(masked.password, limits::SECRET_MASK);
    }

    #[test]
    fn local_shell_requires_enabled_setting() {
        assert!(!local_shell_allowed(&Settings::default()));
        let settings = Settings {
            allow_local_shell: true,
            ..Settings::default()
        };
        assert!(local_shell_allowed(&settings));
    }

    #[test]
    fn connection_view_masks_and_marks_trust() {
        let mut conn = ssh_conn();
        let view = connection_view(&conn);
        assert!(!view.trusted);
        assert_eq!(view.host_key_label, "");
        assert_eq!(view.connection.auth.password, limits::SECRET_MASK);
        conn.host_key = Some(HostKey {
            key_type: Some(crate::model::HostKeyType::Ed25519),
            fingerprint: format!("SHA256:{}", "b".repeat(43)),
        });
        let view = connection_view(&conn);
        assert!(view.trusted);
        assert!(view.host_key_label.starts_with("ED25519 SHA256:"));
    }
}
