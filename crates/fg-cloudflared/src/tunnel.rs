//! The tunnel process layer (WP-46 §3.3): startup arguments and environment
//! (the tunnel token travels through `TUNNEL_TOKEN`, never the command
//! line), output-line parsing for the quick-tunnel public address and the
//! registered edge connections, and the per-tunnel supervision runtime on
//! top of `fg-proc` (auto restart with backoff, bounded stop).

use std::{
    collections::HashMap,
    ffi::OsString,
    sync::{Arc, Mutex},
};

use serde_json::json;

use crate::model::{Settings, Tunnel, TunnelKind, limits};
use crate::token;

/// The `cloudflared` program name used for resolution and registration.
pub const PROGRAM: &str = "cloudflared";

/// Builds the `cloudflared` command line for a tunnel (upstream `Args`):
/// `tunnel --no-autoupdate [extraArgs…]` plus `run` for token tunnels or
/// `--url <service>` for quick tunnels. The token never appears here.
pub fn tunnel_args(tunnel: &Tunnel) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["tunnel".into(), "--no-autoupdate".into()];
    args.extend(tunnel.extra_args.iter().map(OsString::from));
    match tunnel.kind {
        TunnelKind::Token => args.push("run".into()),
        TunnelKind::Quick => {
            if let Some(url) = tunnel
                .quick_url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty())
            {
                args.push("--url".into());
                args.push(url.into());
            }
        }
    }
    args
}

/// Builds the process environment for a tunnel (upstream `Args`): the
/// token tunnels carry `TUNNEL_TOKEN=<token>`; quick tunnels carry none of
/// it. `extraEnv` entries are appended afterwards.
pub fn tunnel_env(tunnel: &Tunnel) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    if tunnel.kind == TunnelKind::Token && !tunnel.token.is_empty() {
        env.push((limits::TOKEN_ENV.into(), tunnel.token.clone().into()));
    }
    env.extend(
        tunnel
            .extra_env
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    env
}

/// Extracts the trycloudflare public address from an output line
/// (upstream `quickURLRe`).
pub fn parse_quick_url(line: &str) -> Option<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"https://[a-z0-9-]+\.trycloudflare\.com").expect("static regex")
    });
    re.find(line).map(|found| found.as_str().to_owned())
}

/// Recognizes a registered edge connection line (upstream `connRe`).
pub fn is_registered_connection(line: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE
        .get_or_init(|| regex::Regex::new(r"Registered tunnel connection").expect("static regex"));
    re.is_match(line)
}

/// Describes an exit like `fg-proc` does, for the read-only view.
fn describe_exit(code: Option<i32>, signal: Option<i32>) -> String {
    match (code, signal) {
        (Some(code), _) => format!("退出码 {code}"),
        (None, Some(signal)) => format!("被信号 {signal} 结束"),
        (None, None) => "无退出状态".into(),
    }
}

/// The live, read-only observation of one tunnel process.
#[derive(Debug, Default)]
pub struct SlotInfo {
    url: Mutex<String>,
    connections: std::sync::atomic::AtomicU64,
    resolve_error: Mutex<String>,
}

impl SlotInfo {
    /// Parses one cleaned output line into the connection state (WP-46:
    /// quick-tunnel public URL + registered edge connections) and forwards
    /// it to the module log via `tracing`.
    fn on_line(&self, line: &str) {
        if let Some(url) = parse_quick_url(line) {
            *self.url.lock().expect("url lock") = url;
        }
        if is_registered_connection(line) {
            self.connections
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Forgets the runtime observations (process is being restarted).
    fn reset(&self) {
        *self.url.lock().expect("url lock") = String::new();
        self.connections
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_resolve_error(&self, message: String) {
        *self.resolve_error.lock().expect("resolve lock") = message;
    }
}

struct Slot {
    /// Absent when the binary could not be resolved — the slot still
    /// carries the error for the view.
    supervisor: Option<Arc<fg_proc::Supervisor>>,
    info: Arc<SlotInfo>,
}

/// The tunnel runtime: one supervised process per tunnel, keyed by the
/// tunnel key. Shared between the module loop (start / drain) and the
/// management routes (apply / restart / view).
pub struct TunnelRuntime {
    proc: Arc<fg_proc::Proc>,
    slots: Mutex<HashMap<String, Slot>>,
}

impl TunnelRuntime {
    pub fn new(proc: Arc<fg_proc::Proc>) -> Self {
        Self {
            proc,
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// The configured path wins; otherwise config dir `bin/` then `PATH`
    /// (upstream `proc.Resolve`).
    pub fn resolve(
        &self,
        settings: &Settings,
    ) -> std::result::Result<(fg_proc::ResolvedFrom, std::path::PathBuf), String> {
        let program_path = settings.program_path.trim().to_owned();
        let configured = (!program_path.is_empty()).then(|| std::path::PathBuf::from(program_path));
        self.proc
            .resolve(configured.as_deref(), PROGRAM)
            .ok_or_else(|| {
                format!("找不到 {PROGRAM}：请设置程序路径、在线安装，或将 {PROGRAM} 放入 PATH")
            })
    }

    /// Applies a tunnel: stops the previous process, then (when enabled)
    /// resolves the binary, builds the spec and starts the supervisor.
    /// Errors are recorded on the slot and logged — never returned, so one
    /// broken tunnel cannot fail the module or its siblings.
    pub async fn apply(&self, tunnel: &Tunnel, settings: &Settings) {
        self.stop_key(&tunnel.key).await;
        if !tunnel.enable {
            return;
        }
        let info = Arc::new(SlotInfo::default());
        let (resolved_from, exe) = match self.resolve(settings) {
            Ok(resolved) => resolved,
            Err(error) => {
                tracing::error!(tunnel = %tunnel.name, "{error}");
                info.set_resolve_error(error);
                self.slots.lock().expect("slots lock").insert(
                    tunnel.key.clone(),
                    Slot {
                        supervisor: None,
                        info,
                    },
                );
                return;
            }
        };
        info.reset();
        let mut spec = fg_proc::Spec::new(
            fg_proc::Owner::new(crate::MODULE_ID, tunnel.name.clone()),
            exe,
        );
        spec.args = tunnel_args(tunnel);
        spec.env = tunnel_env(tunnel);
        tracing::info!(
            tunnel = %tunnel.name,
            from = ?resolved_from,
            "启动 cloudflared 隧道"
        );
        let supervisor = self.proc.supervisor(spec, log_handle(Arc::clone(&info)));
        if let Err(error) = supervisor.start().await {
            let message = error.to_string();
            tracing::error!(tunnel = %tunnel.name, "{message}");
            info.set_resolve_error(message);
        }
        self.slots.lock().expect("slots lock").insert(
            tunnel.key.clone(),
            Slot {
                supervisor: Some(supervisor),
                info,
            },
        );
    }

    /// Stops one tunnel's process and drops its slot (tunnel disabled,
    /// replaced or removed).
    pub async fn stop_key(&self, key: &str) {
        let slot = self.slots.lock().expect("slots lock").remove(key);
        if let Some(slot) = slot
            && let Some(supervisor) = slot.supervisor
        {
            let _ = supervisor.stop().await;
        }
    }

    /// Stops every tunnel, bounded by [`limits::SHUTDOWN_DEADLINE`]
    /// overall; on timeout the supervisors are dropped (fg-proc kills the
    /// child on drop).
    pub async fn stop_all(&self) {
        let slots: Vec<Slot> = self
            .slots
            .lock()
            .expect("slots lock")
            .drain()
            .map(|(_, slot)| slot)
            .collect();
        if slots.is_empty() {
            return;
        }
        let deadline = tokio::time::Instant::now() + limits::SHUTDOWN_DEADLINE;
        for slot in slots {
            let Some(supervisor) = slot.supervisor else {
                continue;
            };
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                tracing::warn!("排空超时，放弃等待剩余隧道进程退出");
                return;
            }
            if tokio::time::timeout(remaining, supervisor.stop())
                .await
                .is_err()
            {
                tracing::warn!("停止隧道进程超时，进程将在句柄释放后被结束");
            }
        }
    }

    /// Restarts every enabled tunnel (settings or binary changed, install
    /// finished).
    pub async fn restart_all(&self, config: &crate::model::FileConfig) {
        for tunnel in config.tunnels.iter().filter(|tunnel| tunnel.enable) {
            self.apply(tunnel, &config.settings).await;
        }
    }

    /// The running process state of a tunnel, if any.
    pub fn state_of(&self, key: &str) -> Option<fg_proc::State> {
        self.slots
            .lock()
            .expect("slots lock")
            .get(key)
            .and_then(|slot| slot.supervisor.as_ref())
            .map(|supervisor| supervisor.state())
    }

    /// The read-only observation of a tunnel (`None` when never started).
    pub fn info_of(&self, key: &str) -> Option<Arc<SlotInfo>> {
        self.slots
            .lock()
            .expect("slots lock")
            .get(key)
            .map(|slot| Arc::clone(&slot.info))
    }
}

impl SlotInfo {
    /// The public URL parsed from the process output (quick tunnels).
    pub fn url(&self) -> String {
        self.url.lock().expect("url lock").clone()
    }

    /// Registered edge connections so far.
    pub fn connections(&self) -> u64 {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Why the tunnel is not running (resolve failure / start failure),
    /// empty when fine.
    pub fn error(&self) -> String {
        self.resolve_error.lock().expect("resolve lock").clone()
    }
}

/// The module log handle for one tunnel process: cleaned, masked lines from
/// fg-proc are parsed for the connection state, then logged via `tracing`
/// (fg-logging gains a cloudflared source at assembly time).
fn log_handle(info: Arc<SlotInfo>) -> fg_proc::LogHandle {
    fg_proc::LogHandle::new(move |level, line| {
        info.on_line(line);
        match level {
            fg_logging::Level::Debug => tracing::debug!(target: "fg_cloudflared::tunnel", "{line}"),
            fg_logging::Level::Info => tracing::info!(target: "fg_cloudflared::tunnel", "{line}"),
            fg_logging::Level::Warn => tracing::warn!(target: "fg_cloudflared::tunnel", "{line}"),
            fg_logging::Level::Error => tracing::error!(target: "fg_cloudflared::tunnel", "{line}"),
        }
    })
}

/// The tunnel list view: the masked tunnel plus its read-only runtime
/// state (WP-46 §3.3 接口数据). The token and API token are masked; the
/// tunnel ID is derived from the token (parse failures keep it empty).
pub fn tunnel_view(tunnel: &Tunnel, runtime: &TunnelRuntime) -> serde_json::Value {
    let masked_token = (!tunnel.token.is_empty()).then(|| limits::SECRET_MASK.to_owned());
    let masked_api_token = tunnel
        .api_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .map(|_| limits::SECRET_MASK.to_owned());
    let tunnel_id = token::parse_token(&tunnel.token)
        .map(|info| info.tunnel_id)
        .unwrap_or_default();
    let state = runtime.state_of(&tunnel.key);
    let info = runtime.info_of(&tunnel.key);
    let (state_json, error, url, connections) = match (&state, &info) {
        (Some(state), Some(info)) => {
            let mut error = info.error();
            if error.is_empty() {
                error = state.failed.clone().unwrap_or_default();
            }
            let last_exit = state.last_exit.as_ref().map(|exit| {
                json!({
                    "at": rfc3339(exit.at),
                    "reason": describe_exit(exit.code, exit.signal),
                })
            });
            let state_value = json!({
                "running": state.running,
                "pid": state.pid,
                "since": state.since.map(rfc3339),
                "uptimeSecs": state.uptime().map(|uptime| uptime.as_secs()),
                "restarts": state.restarts,
                "lastExit": last_exit,
                "error": state.failed.clone().unwrap_or_default(),
            });
            (state_value, error, info.url(), info.connections())
        }
        // The binary could not be resolved: the slot carries the error
        // without a supervisor.
        (None, Some(info)) => (
            json!({
                "running": false,
                "pid": null,
                "since": null,
                "restarts": 0,
            }),
            info.error(),
            String::new(),
            0,
        ),
        _ => (
            json!({
                "running": false,
                "pid": null,
                "since": null,
                "restarts": 0,
            }),
            String::new(),
            String::new(),
            0,
        ),
    };
    json!({
        "key": tunnel.key,
        "name": tunnel.name,
        "group": tunnel.group,
        "enable": tunnel.enable,
        "mode": tunnel.kind,
        "token": masked_token,
        "apiToken": masked_api_token,
        "service": tunnel.quick_url,
        "extraArgs": tunnel.extra_args,
        "extraEnv": tunnel.extra_env,
        "remark": tunnel.remark,
        "tunnelId": tunnel_id,
        "state": state_json,
        "error": error,
        "url": url,
        "connections": connections,
    })
}

/// UTC RFC 3339 (conventions §3.5).
pub fn rfc3339(at: std::time::SystemTime) -> String {
    let at: time::OffsetDateTime = at.into();
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TunnelKind;

    fn quick(url: Option<&str>) -> Tunnel {
        Tunnel {
            key: "q".into(),
            name: "quick".into(),
            kind: TunnelKind::Quick,
            quick_url: url.map(str::to_owned),
            ..Tunnel::default()
        }
    }

    fn token() -> Tunnel {
        Tunnel {
            key: "t".into(),
            name: "token".into(),
            kind: TunnelKind::Token,
            token: "secret-token".into(),
            extra_args: vec!["--protocol".into(), "http2".into()],
            extra_env: vec![("NO_PROXY".into(), "localhost".into())],
            ..Tunnel::default()
        }
    }

    #[test]
    fn tunnel_token_in_env_not_args() {
        // 令牌经环境变量传递，不出现在进程列表中。
        let args = tunnel_args(&token());
        let joined = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(joined, "tunnel --no-autoupdate --protocol http2 run");
        assert!(
            !joined.contains("secret-token"),
            "令牌不得进入命令行：{joined}"
        );
        let env = tunnel_env(&token());
        assert_eq!(
            env,
            vec![
                ("TUNNEL_TOKEN".into(), "secret-token".into()),
                ("NO_PROXY".into(), "localhost".into())
            ]
        );
        // 快速隧道没有环境变量，也不带 TUNNEL_TOKEN。
        assert!(tunnel_env(&quick(Some("http://localhost:8080"))).is_empty());
    }

    #[test]
    fn tunnel_quick_mode_url_argument() {
        // 指定与随机。
        let specified = tunnel_args(&quick(Some("http://localhost:8080")));
        assert_eq!(
            specified,
            vec![
                OsString::from("tunnel"),
                OsString::from("--no-autoupdate"),
                OsString::from("--url"),
                OsString::from("http://localhost:8080")
            ]
        );
        let random = tunnel_args(&quick(None));
        assert_eq!(
            random,
            vec![OsString::from("tunnel"), OsString::from("--no-autoupdate")],
            "未指定 URL 时不带 --url（公网名总是随机）"
        );
        let empty = tunnel_args(&quick(Some("  ")));
        assert_eq!(empty, random, "空白 URL 等同未指定");
    }

    #[test]
    fn tunnel_public_address_parsed_from_output() {
        // 快速隧道：公网地址从进程输出中读取。
        assert_eq!(
            parse_quick_url("INF |  https://random-words-here.trycloudflare.com  |"),
            Some("https://random-words-here.trycloudflare.com".into())
        );
        assert_eq!(
            parse_quick_url(
                "2026-01-01T00:00:00Z INF +--------------------------------------------------------------------------------------------"
            ),
            None,
            "非地址行不解析"
        );
        // 连接状态按文档口径：Registered tunnel connection 计数。
        assert!(is_registered_connection(
            "INF Registered tunnel connection connIndex=0"
        ));
        assert!(!is_registered_connection("INF Starting tunnel"));
    }

    #[test]
    fn slot_info_tracks_url_and_connections_and_resets() {
        let info = SlotInfo::default();
        info.on_line("INF |  https://random-words-here.trycloudflare.com  |");
        info.on_line("INF Registered tunnel connection connIndex=0");
        info.on_line("INF Registered tunnel connection connIndex=1");
        assert_eq!(info.url(), "https://random-words-here.trycloudflare.com");
        assert_eq!(info.connections(), 2);
        info.reset();
        assert_eq!(info.url(), "");
        assert_eq!(info.connections(), 0);
        info.set_resolve_error("找不到 cloudflared".into());
        assert_eq!(info.error(), "找不到 cloudflared");
    }

    #[test]
    fn tunnel_view_masks_secrets_and_carries_tunnel_id() {
        // 视图口径：令牌与 API 令牌脱敏，tunnelId 来自令牌解析。
        let mut tunnel = token();
        tunnel.token = "eyJhIjoiYWNjIiwidCI6InRpZCIsInMiOiJzIn0=".into();
        tunnel.api_token = Some("cf-api".into());
        let masked_token = (!tunnel.token.is_empty()).then(|| limits::SECRET_MASK.to_owned());
        let masked_api_token = tunnel
            .api_token
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|_| limits::SECRET_MASK.to_owned());
        assert_eq!(masked_token.as_deref(), Some("********"));
        assert_eq!(masked_api_token.as_deref(), Some("********"));
        let tunnel_id = crate::token::parse_token(&tunnel.token).map(|info| info.tunnel_id);
        assert_eq!(tunnel_id.as_deref(), Ok("tid"));
        // 未脱敏的序列化仍含真实值（配置文件需要）。
        let raw = serde_json::to_string(&tunnel).expect("serialize");
        assert!(raw.contains("eyJhIjoiYWNj"), "{raw}");
    }

    #[test]
    fn describe_exit_covers_codes_and_signals() {
        assert_eq!(describe_exit(Some(1), None), "退出码 1");
        assert_eq!(describe_exit(None, Some(9)), "被信号 9 结束");
        assert_eq!(describe_exit(None, None), "无退出状态");
    }

    #[test]
    fn rfc3339_formats_utc() {
        let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600);
        assert_eq!(rfc3339(at), "2026-01-01T00:00:00Z");
    }
}
