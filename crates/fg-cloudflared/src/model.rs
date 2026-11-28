//! The `cloudflared.json` model (WP-46 §3.2): module settings, the online
//! install block and the tunnel collection. JSON field names follow the
//! upstream module (`internal/modules/cloudflared/module.go`, camelCase);
//! every struct denies unknown fields and fills defaults so a partially
//! written file still loads. Secrets (`token`, `apiToken`) are stored in
//! plain text in the file (0600 via the config store) and masked in the
//! management API.

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here).
pub mod limits {
    use std::time::Duration;

    /// Cloudflare API endpoint (upstream `cfEndpoint`).
    pub const CF_ENDPOINT: &str = "https://api.cloudflare.com/client/v4";
    /// Per-request timeout for Cloudflare API calls (upstream client).
    pub const CF_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    /// Response body cap for Cloudflare API calls (upstream `LimitReader(8<<20)`).
    pub const CF_RESPONSE_MAX_BYTES: u64 = 8 << 20;
    /// The default service when no rule matched (upstream `defaultCatchAll`).
    pub const DEFAULT_CATCH_ALL: &str = "http_status:404";
    /// FerrumGate protection: tunnels per file (upstream has no limit; the
    /// 4 MiB request body cap bounds it in practice).
    pub const TUNNELS_MAX: usize = 256;
    /// FerrumGate protection: `extraArgs` entries per tunnel.
    pub const EXTRA_ARGS_MAX: usize = 32;
    /// FerrumGate protection: `extraEnv` entries per tunnel.
    pub const EXTRA_ENV_MAX: usize = 32;
    /// One `extraArgs` / `extraEnv` entry length cap.
    pub const EXTRA_ENTRY_MAX_CHARS: usize = 2048;
    /// FerrumGate protection: tunnel name length.
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: group name length (upstream `crud.MaxGroupLen`).
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: remark length.
    pub const REMARK_MAX_CHARS: usize = 512;
    /// FerrumGate protection: configured `binPath` length.
    pub const PROGRAM_PATH_MAX_CHARS: usize = 1024;
    /// FerrumGate protection: download proxy length.
    pub const PROXY_MAX_CHARS: usize = 255;
    /// Grace period for stopping tunnel processes when the module drains
    /// (fg-proc applies its own 5 s stop grace per process; the module
    /// deadline bounds the whole drain).
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
    /// Secrets are replaced by this placeholder in API output; submitting
    /// it back keeps the stored value (upstream `crud.SecretMask`).
    pub const SECRET_MASK: &str = "********";
    /// The environment variable carrying the tunnel token (upstream `Args`).
    pub const TOKEN_ENV: &str = "TUNNEL_TOKEN";
}

/// `cloudflared.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
    /// Online install settings (upstream `binstall.Config`).
    pub install: InstallConfig,
    pub tunnels: Vec<Tunnel>,
}

/// Module settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Settings {
    /// cloudflared binary path; empty → config dir `bin/` → `PATH`
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

/// The tunnel kind (upstream `mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelKind {
    /// A Cloudflare-managed tunnel run from its token (upstream `ModeToken`).
    #[default]
    Token,
    /// A temporary trycloudflare.com tunnel (upstream `ModeQuick`).
    Quick,
}

/// One tunnel entry. Secrets are masked in API responses; submitting
/// [`limits::SECRET_MASK`] keeps the stored value (merge in `routes.rs`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Tunnel {
    pub key: String,
    pub name: String,
    /// Display-only group; empty = ungrouped.
    pub group: String,
    /// Start the tunnel with the module (`enable` toggles start/stop).
    pub enable: bool,
    /// `token` | `quick` (upstream JSON field `mode`).
    #[serde(rename = "mode")]
    pub kind: TunnelKind,
    /// Tunnel token for `kind: token`; base64 JSON `{"a","t","s"}`.
    pub token: String,
    /// Local service URL to expose for `kind: quick`, e.g.
    /// `http://localhost:8080`; empty lets cloudflared pick (random public
    /// name either way). Cleared for token tunnels (upstream JSON field
    /// `service`).
    #[serde(rename = "service", default, skip_serializing_if = "Option::is_none")]
    pub quick_url: Option<String>,
    /// Optional Cloudflare API token for token tunnels: enables editing the
    /// remote ingress and syncing DNS. Cleared for quick tunnels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,
    /// Extra `cloudflared` arguments inserted before the mode-specific
    /// arguments (e.g. `--protocol http2`, `--edge-ip-version 4`).
    pub extra_args: Vec<String>,
    /// Extra environment entries appended after the token environment.
    pub extra_env: Vec<(String, String)>,
    pub remark: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_config_round_trips_camel_case_fields() {
        let config = FileConfig {
            settings: Settings {
                program_path: "/usr/local/bin/cloudflared".into(),
            },
            install: InstallConfig {
                proxy: "http://127.0.0.1:7890".into(),
            },
            tunnels: vec![Tunnel {
                key: "abc123".into(),
                name: "nas".into(),
                group: "内网".into(),
                enable: true,
                kind: TunnelKind::Token,
                token: "eyJhIjoiYWNjIiwidCI6InRpZCIsInMiOiJzIn0".into(),
                quick_url: None,
                api_token: Some("cf-api".into()),
                extra_args: vec!["--protocol".into(), "http2".into()],
                extra_env: vec![("NO_PROXY".into(), "localhost".into())],
                remark: "家庭 NAS".into(),
            }],
        };
        let bytes = serde_json::to_vec(&config).expect("serialize");
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(text.contains("\"binPath\""), "{text}");
        assert!(text.contains("\"mode\":\"token\""), "{text}");
        assert!(text.contains("\"apiToken\":\"cf-api\""), "{text}");
        assert!(text.contains("\"extraArgs\""), "{text}");
        assert!(
            text.contains("\"extraEnv\":[[\"NO_PROXY\",\"localhost\"]]",),
            "{text}"
        );
        // quick_url: None is omitted (upstream omitempty).
        assert!(!text.contains("service"), "{text}");
        let back: FileConfig = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back, config);
    }

    #[test]
    fn file_config_rejects_unknown_fields_and_defaults_missing_ones() {
        let err = serde_json::from_str::<FileConfig>("{\"nope\":1}").expect_err("unknown rejected");
        assert!(err.to_string().contains("nope"), "{err}");
        let config: FileConfig = serde_json::from_str("{}").expect("defaults");
        assert_eq!(config, FileConfig::default());
        assert_eq!(
            serde_json::from_str::<Tunnel>("{\"key\":\"k\"}")
                .expect("tunnel defaults")
                .kind,
            TunnelKind::Token
        );
        // Upstream JSON field name `mode` selects the kind.
        let quick: Tunnel =
            serde_json::from_str("{\"key\":\"k\",\"mode\":\"quick\"}").expect("quick");
        assert_eq!(quick.kind, TunnelKind::Quick);
        // Unknown kind values are rejected.
        assert!(serde_json::from_str::<Tunnel>("{\"mode\":\"other\"}").is_err());
    }

    #[test]
    fn limits_match_upstream_defaults() {
        assert_eq!(limits::CF_ENDPOINT, "https://api.cloudflare.com/client/v4");
        assert_eq!(limits::DEFAULT_CATCH_ALL, "http_status:404");
        assert_eq!(limits::CF_RESPONSE_MAX_BYTES, 8 << 20);
        assert_eq!(limits::TOKEN_ENV, "TUNNEL_TOKEN");
        assert_eq!(limits::SECRET_MASK, "********");
        assert_eq!(
            limits::SHUTDOWN_DEADLINE,
            std::time::Duration::from_secs(30)
        );
    }
}
