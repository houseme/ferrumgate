//! Normalization and validation for the cloudflared model (WP-46): pure
//! functions over plain data. `normalize` applies the per-kind field
//! cleanup (token tunnels drop the quick URL; quick tunnels drop the
//! tokens) and trims user-entered text; `validate` collects every problem.
//! Ingress rule validation lives in [`crate::ingress`].

use url::Url;

use crate::model::{FileConfig, Settings, Tunnel, TunnelKind, limits};

/// A collected validation problem: the offending field path and reason.
#[derive(Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

impl Problem {
    pub fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// Applies defaults and trims user-entered text: names, groups, remarks,
/// the binary path, the download proxy, quick URLs and every extra
/// argument / environment entry. Token tunnels lose their quick URL; quick
/// tunnels lose both tokens (upstream `Validate` cleanup).
pub fn normalize(mut config: FileConfig) -> FileConfig {
    normalize_settings(&mut config.settings);
    config.install.proxy = config.install.proxy.trim().to_owned();
    config.tunnels.truncate(limits::TUNNELS_MAX);
    for tunnel in &mut config.tunnels {
        normalize_tunnel(tunnel);
    }
    config
}

/// Same normalization for a single tunnel being created or edited.
pub fn normalize_tunnel(tunnel: &mut Tunnel) {
    tunnel.key = tunnel.key.trim().to_owned();
    tunnel.name = tunnel.name.trim().to_owned();
    tunnel.group = tunnel.group.trim().to_owned();
    tunnel.token = tunnel.token.trim().to_owned();
    tunnel.api_token = tunnel
        .api_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned);
    tunnel.quick_url = tunnel
        .quick_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned);
    tunnel.remark = tunnel.remark.trim().to_owned();
    tunnel.extra_args = tunnel
        .extra_args
        .iter()
        .map(|arg| arg.trim().to_owned())
        .filter(|arg| !arg.is_empty())
        .take(limits::EXTRA_ARGS_MAX)
        .collect();
    tunnel.extra_env = tunnel
        .extra_env
        .iter()
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .filter(|(key, _)| !key.is_empty())
        .take(limits::EXTRA_ENV_MAX)
        .collect();
    match tunnel.kind {
        TunnelKind::Token => tunnel.quick_url = None,
        TunnelKind::Quick => {
            tunnel.token = String::new();
            tunnel.api_token = None;
        }
    }
}

pub fn normalize_settings(settings: &mut Settings) {
    settings.program_path = settings.program_path.trim().to_owned();
}

/// Validates a normalized config, collecting every problem.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut keys = std::collections::BTreeSet::new();
    for tunnel in &config.tunnels {
        if tunnel.key.is_empty() {
            problems.push(Problem::new("key", "key 不能为空"));
        } else if !keys.insert(tunnel.key.as_str()) {
            problems.push(Problem::new("key", format!("重复的 key {}", tunnel.key)));
        }
        problems.extend(validate_tunnel(tunnel));
    }
    if config.settings.program_path.chars().count() > limits::PROGRAM_PATH_MAX_CHARS {
        problems.push(Problem::new(
            "settings.binPath",
            format!("程序路径最多 {} 个字符", limits::PROGRAM_PATH_MAX_CHARS),
        ));
    }
    if config.install.proxy.chars().count() > limits::PROXY_MAX_CHARS {
        problems.push(Problem::new(
            "install.proxy",
            format!("下载代理最多 {} 个字符", limits::PROXY_MAX_CHARS),
        ));
    }
    problems
}

/// Validates one normalized tunnel (fields prefixed `tunnels.<key>.`).
pub fn validate_tunnel(tunnel: &Tunnel) -> Vec<Problem> {
    let mut problems = Vec::new();
    let prefix = format!("tunnels.{}", tunnel.key);
    if tunnel.name.is_empty() {
        problems.push(Problem::new(format!("{prefix}.name"), "隧道名称不能为空"));
    } else if tunnel.name.chars().count() > limits::NAME_MAX_CHARS {
        problems.push(Problem::new(
            format!("{prefix}.name"),
            format!("名称最多 {} 个字符", limits::NAME_MAX_CHARS),
        ));
    }
    if tunnel.group.chars().count() > limits::GROUP_MAX_CHARS {
        problems.push(Problem::new(
            format!("{prefix}.group"),
            format!("分组最多 {} 个字符", limits::GROUP_MAX_CHARS),
        ));
    }
    if tunnel.remark.chars().count() > limits::REMARK_MAX_CHARS {
        problems.push(Problem::new(
            format!("{prefix}.remark"),
            format!("备注最多 {} 个字符", limits::REMARK_MAX_CHARS),
        ));
    }
    match tunnel.kind {
        TunnelKind::Token => {
            if tunnel.token.is_empty() {
                problems.push(Problem::new(format!("{prefix}.token"), "请填写隧道令牌"));
            } else if let Err(error) = crate::token::parse_token(&tunnel.token) {
                problems.push(Problem::new(format!("{prefix}.token"), error.to_string()));
            }
            // normalize_tunnel already dropped a stray quick URL (the
            // upstream cleanup is silent, no separate problem).
        }
        TunnelKind::Quick => {
            if let Some(error) = tunnel
                .quick_url
                .as_deref()
                .map(validate_quick_url)
                .and_then(|result| result.err())
            {
                problems.push(Problem::new(format!("{prefix}.quickUrl"), error));
            }
            // normalize_tunnel already cleared a stray API token.
        }
    }
    if tunnel.extra_args.len() > limits::EXTRA_ARGS_MAX {
        problems.push(Problem::new(
            format!("{prefix}.extraArgs"),
            format!("额外参数最多 {} 条", limits::EXTRA_ARGS_MAX),
        ));
    }
    if tunnel.extra_env.len() > limits::EXTRA_ENV_MAX {
        problems.push(Problem::new(
            format!("{prefix}.extraEnv"),
            format!("额外环境变量最多 {} 条", limits::EXTRA_ENV_MAX),
        ));
    }
    for (key, value) in &tunnel.extra_env {
        if key.eq_ignore_ascii_case(limits::TOKEN_ENV) {
            problems.push(Problem::new(
                format!("{prefix}.extraEnv"),
                format!("环境变量 {} 由隧道令牌占用", limits::TOKEN_ENV),
            ));
        }
        if key.len() + value.len() > limits::EXTRA_ENTRY_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.extraEnv"),
                format!("环境变量条目最多 {} 个字符", limits::EXTRA_ENTRY_MAX_CHARS),
            ));
        }
    }
    for arg in &tunnel.extra_args {
        if arg.len() > limits::EXTRA_ENTRY_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.extraArgs"),
                format!("额外参数最多 {} 个字符", limits::EXTRA_ENTRY_MAX_CHARS),
            ));
        }
    }
    problems
}

/// The local service URL a quick tunnel exposes: http / https / tcp / ssh /
/// rdp with a host (upstream `Validate` for `ModeQuick`). The port is not
/// required here: `--url` accepts any address cloudflared can dial, and
/// http defaults to port 80.
pub fn validate_quick_url(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url)
        .ok()
        .filter(|parsed| !parsed.host_str().unwrap_or_default().is_empty())
        .filter(|parsed| matches!(parsed.scheme(), "http" | "https" | "tcp" | "ssh" | "rdp"));
    if parsed.is_none() {
        return Err("本地服务地址格式应为 http://localhost:8080".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InstallConfig;

    fn token_tunnel() -> Tunnel {
        Tunnel {
            key: "abc123".into(),
            name: "nas".into(),
            kind: TunnelKind::Token,
            // {"a":"acc","t":"tid","s":"s"} base64 (standard, padded).
            token: "eyJhIjoiYWNjIiwidCI6InRpZCIsInMiOiJzIn0=".into(),
            ..Tunnel::default()
        }
    }

    #[test]
    fn valid_config_has_no_problems() {
        let config = normalize(FileConfig {
            tunnels: vec![token_tunnel()],
            ..FileConfig::default()
        });
        assert!(validate(&config).is_empty(), "{:?}", validate(&config));
        let mut quick = Tunnel {
            key: "q1".into(),
            name: "quick".into(),
            kind: TunnelKind::Quick,
            quick_url: Some("http://localhost:8080".into()),
            token: "leftover".into(),
            api_token: Some("leftover".into()),
            ..Tunnel::default()
        };
        normalize_tunnel(&mut quick);
        let config = normalize(FileConfig {
            tunnels: vec![quick],
            ..FileConfig::default()
        });
        assert!(validate(&config).is_empty(), "{:?}", validate(&config));
        let saved = &config.tunnels[0];
        assert_eq!(saved.token, "", "临时隧道清空令牌");
        assert_eq!(saved.api_token, None, "临时隧道清空 API 令牌");
        assert_eq!(saved.quick_url.as_deref(), Some("http://localhost:8080"));
    }

    #[test]
    fn normalize_token_mode_drops_quick_url() {
        let mut tunnel = token_tunnel();
        tunnel.quick_url = Some(" http://localhost:8080 ".into());
        normalize_tunnel(&mut tunnel);
        assert_eq!(tunnel.quick_url, None, "令牌隧道丢弃本地服务地址");
        assert_eq!(tunnel.token, tunnel.token.trim());
    }

    #[test]
    fn problems_collected_for_every_broken_field() {
        let mut tunnel = token_tunnel();
        tunnel.name = String::new();
        tunnel.token = String::new();
        tunnel.group = "x".repeat(limits::GROUP_MAX_CHARS + 1);
        let mut quick = Tunnel {
            key: "q1".into(),
            name: "quick".into(),
            kind: TunnelKind::Quick,
            quick_url: Some("ftp://x".into()),
            ..Tunnel::default()
        };
        normalize_tunnel(&mut quick);
        let config = normalize(FileConfig {
            tunnels: vec![tunnel, quick],
            ..FileConfig::default()
        });
        let fields: Vec<_> = validate(&config)
            .into_iter()
            .map(|problem| problem.field)
            .collect();
        assert!(fields.iter().any(|f| f.ends_with(".name")), "{fields:?}");
        assert!(fields.iter().any(|f| f.ends_with(".token")), "{fields:?}");
        assert!(fields.iter().any(|f| f.ends_with(".group")), "{fields:?}");
        assert!(
            fields.iter().any(|f| f.ends_with(".quickUrl")),
            "{fields:?}"
        );
    }

    #[test]
    fn token_mode_rejects_unparsable_token() {
        let mut tunnel = token_tunnel();
        tunnel.token = "not base64!".into();
        let config = normalize(FileConfig {
            tunnels: vec![tunnel],
            ..FileConfig::default()
        });
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with(".token")
                    && problem.reason.contains("令牌")),
            "{problems:?}"
        );
    }

    #[test]
    fn token_env_cannot_be_overridden_by_extra_env() {
        let mut tunnel = token_tunnel();
        tunnel.extra_env = vec![("TUNNEL_TOKEN".into(), "evil".into())];
        let config = normalize(FileConfig {
            tunnels: vec![tunnel],
            ..FileConfig::default()
        });
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with(".extraEnv")),
            "{problems:?}"
        );
    }

    #[test]
    fn extra_args_and_env_are_trimmed_and_capped() {
        let mut tunnel = token_tunnel();
        tunnel.extra_args = (0..limits::EXTRA_ARGS_MAX + 5)
            .map(|index| format!(" --arg{index} "))
            .collect();
        tunnel.extra_env = (0..limits::EXTRA_ENV_MAX + 5)
            .map(|index| (format!(" KEY{index} "), format!(" value{index} ")))
            .collect();
        normalize_tunnel(&mut tunnel);
        assert_eq!(tunnel.extra_args.len(), limits::EXTRA_ARGS_MAX);
        assert_eq!(tunnel.extra_args[0], "--arg0");
        assert_eq!(tunnel.extra_env.len(), limits::EXTRA_ENV_MAX);
        assert_eq!(
            tunnel.extra_env[0],
            ("KEY0".to_owned(), "value0".to_owned()),
            "键值两侧空白被去掉"
        );
    }

    #[test]
    fn quick_url_requires_supported_scheme_and_host() {
        assert!(validate_quick_url("http://localhost:8080").is_ok());
        assert!(validate_quick_url("https://127.0.0.1:4443").is_ok());
        assert!(validate_quick_url("tcp://localhost:22").is_ok());
        assert!(validate_quick_url("ssh://localhost:22").is_ok());
        assert!(validate_quick_url("rdp://pc:3389").is_ok());
        assert!(validate_quick_url("localhost:8080").is_err());
        assert!(validate_quick_url("ftp://x").is_err());
        assert!(validate_quick_url("http://").is_err());
        // 端口可省略（http 默认 80）。
        assert!(validate_quick_url("http://localhost").is_ok());
    }

    #[test]
    fn settings_and_proxy_length_are_capped() {
        let config = FileConfig {
            settings: Settings {
                program_path: "x".repeat(limits::PROGRAM_PATH_MAX_CHARS + 1),
            },
            install: InstallConfig {
                proxy: "x".repeat(limits::PROXY_MAX_CHARS + 1),
            },
            tunnels: Vec::new(),
        };
        let fields: Vec<_> = validate(&config)
            .into_iter()
            .map(|problem| problem.field)
            .collect();
        assert!(
            fields.contains(&"settings.binPath".to_owned()),
            "{fields:?}"
        );
        assert!(fields.contains(&"install.proxy".to_owned()), "{fields:?}");
    }

    #[test]
    fn duplicate_keys_are_collected() {
        let tunnel = token_tunnel();
        let config = normalize(FileConfig {
            tunnels: vec![tunnel.clone(), tunnel],
            ..FileConfig::default()
        });
        assert!(
            validate(&config)
                .iter()
                .any(|problem| problem.field == "key")
        );
    }
}
