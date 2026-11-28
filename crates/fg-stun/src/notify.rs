//! Address-change notifications (WP-42 §3.3): when a channel's public
//! endpoint is learned or changes, the rule's webhook is sent and the
//! rule's script runs — the `stun.changed` event publication lives with
//! the runtime transitions. The webhook follows the fg-ddns sender's
//! shape (`{var}` placeholders, timeout, proxy flag); the script follows
//! the fg-cron command execution (`sh -c`, environment variables, fixed
//! timeout, truncated output written to the module log).

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::{Duration, SystemTime};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio_util::sync::CancellationToken;

use crate::model::{Rule, Settings, WebhookConfig, limits};

/// One notification payload: the new public endpoint plus when it was
/// learned. `changed` distinguishes a fresh/renewed mapping from an
/// actual endpoint change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    pub rule_name: String,
    pub ip: String,
    pub port: u16,
    pub changed: bool,
    pub at: SystemTime,
}

impl Notification {
    /// Builds the payload for a transition onto `public`.
    pub fn new(rule_name: &str, public: SocketAddr, changed: bool, at: SystemTime) -> Self {
        Self {
            rule_name: rule_name.to_owned(),
            ip: public.ip().to_string(),
            port: public.port(),
            changed,
            at,
        }
    }

    /// The `ipAddr` variable: `ip:port` as one string.
    pub fn ip_addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }

    /// RFC 3339 rendering of [`Notification::at`]; falls back to the Unix
    /// seconds when the clock is out of range.
    pub fn time_text(&self) -> String {
        let datetime: OffsetDateTime = self.at.into();
        datetime.format(&Rfc3339).unwrap_or_else(|_| {
            format!(
                "{}s",
                self.at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            )
        })
    }

    /// Every placeholder value keyed by name (`ruleName`, `time`, `ip`,
    /// `port`, `ipAddr`).
    pub fn vars(&self) -> [(&'static str, String); 5] {
        [
            ("ruleName", self.rule_name.clone()),
            ("time", self.time_text()),
            ("ip", self.ip.clone()),
            ("port", self.port.to_string()),
            ("ipAddr", self.ip_addr()),
        ]
    }
}

/// The webhook a rule uses: its own when set, else the module's
/// (`useGlobalWebhook`).
pub fn effective_webhook<'a>(rule: &'a Rule, settings: &'a Settings) -> &'a WebhookConfig {
    if rule.use_global_webhook {
        &settings.webhook
    } else {
        &rule.webhook
    }
}

/// Whether the rule's webhook fires for this notification
/// (`webhookOnlyOnChange` limits delivery to real endpoint changes).
pub fn webhook_wanted(rule: &Rule, webhook: &WebhookConfig, notif: &Notification) -> bool {
    !webhook.url.trim().is_empty() && (notif.changed || !rule.webhook_only_on_change)
}

/// Renders `{name}` placeholders; unknown names stay literal.
pub fn render(text: &str, vars: &[(&'static str, String)]) -> String {
    if !text.contains('{') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        let name = &rest[start + 1..start + end];
        out.push_str(&rest[..start]);
        if let Some((_, value)) = vars.iter().find(|(key, _)| *key == name) {
            out.push_str(value);
        } else {
            out.push_str(&rest[start..start + end + 1]);
        }
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}

/// Sends the rule webhook once. `proxy` selects the environment-provided
/// outbound proxy (the assembler's global proxy reaches the process via
/// the standard proxy environment variables); off means a direct
/// connection even when one is configured.
pub async fn deliver_webhook(
    webhook: &WebhookConfig,
    notif: &Notification,
    token: &CancellationToken,
) -> Result<(), String> {
    let vars = notif.vars();
    let url = render(webhook.url.trim(), &vars);
    if url.is_empty() || (!url.starts_with("http://") && !url.starts_with("https://")) {
        return Err("Webhook 地址无效".to_owned());
    }
    let method = if webhook.method.trim().is_empty() {
        "GET".to_owned()
    } else {
        webhook.method.trim().to_ascii_uppercase()
    };
    let timeout = Duration::from_secs(u64::from(
        if webhook.timeout == 0 {
            limits::WEBHOOK_TIMEOUT_DEFAULT_SECS
        } else {
            webhook.timeout
        }
        .min(limits::WEBHOOK_TIMEOUT_MAX_SECS),
    ));
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)));
    if !webhook.proxy {
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|error| format!("Webhook 客户端构建失败：{error}"))?;
    let method = method
        .parse::<reqwest::Method>()
        .map_err(|error| format!("Webhook 方法无效：{error}"))?;
    let parsed_url =
        reqwest::Url::parse(&url).map_err(|error| format!("Webhook 地址无效：{error}"))?;
    let mut request = client.request(method, parsed_url);
    for header in &webhook.headers {
        if let Some((name, value)) = crate::validate::parse_header(header) {
            request = request.header(name, render(&value, &vars));
        }
    }
    let body = render(&webhook.body, &vars);
    if !body.is_empty() {
        request = request.body(body);
    }
    let response = tokio::select! {
        biased;
        _ = token.cancelled() => return Err("通道已停止，Webhook 未发送".to_owned()),
        result = request.send() => match result {
            Ok(response) => response,
            Err(error) if error.is_timeout() => return Err("Webhook 请求超时".to_owned()),
            Err(error) => return Err(format!("Webhook 请求失败：{error}")),
        },
    };
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Webhook 返回 HTTP {status}"));
    }
    Ok(())
}

/// The script run result: success plus the merged, truncated output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptOutcome {
    pub success: bool,
    pub output: String,
}

/// Runs the rule script through `sh -c` with the notification in the
/// environment (`ruleName`, `time`, `ip`, `port`, `ipAddr` plus the
/// `FERRUMGATE_RULENAME` alias), bounded by [`limits::SCRIPT_TIMEOUT`] or
/// the token. Output (stdout + stderr) is truncated to
/// [`limits::SCRIPT_OUTPUT_MAX_CHARS`]; the caller logs it.
pub async fn run_script(
    script: &str,
    notif: &Notification,
    token: &CancellationToken,
) -> ScriptOutcome {
    let child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .envs(script_env(notif))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(error) => {
            return ScriptOutcome {
                success: false,
                output: format!("启动脚本失败：{error}"),
            };
        }
    };
    let waited = tokio::time::timeout(limits::SCRIPT_TIMEOUT, child.wait_with_output());
    tokio::select! {
        biased;
        _ = token.cancelled() => ScriptOutcome {
            success: false,
            output: "脚本在通道停止时被终止".into(),
        },
        result = waited => match result {
            Ok(Ok(output)) => ScriptOutcome {
                success: output.status.success(),
                output: truncate_output(&merged_output(
                    &output.stdout,
                    &output.stderr,
                )),
            },
            Ok(Err(error)) => ScriptOutcome {
                success: false,
                output: format!("等待脚本退出失败：{error}"),
            },
            Err(_timeout) => ScriptOutcome {
                success: false,
                output: format!(
                    "脚本超时（超过 {} 秒），已终止",
                    limits::SCRIPT_TIMEOUT.as_secs().max(1)
                ),
            },
        },
    }
}

/// The environment pairs injected into the script: the notification vars
/// plus the `FERRUMGATE_RULENAME` alias (fg-cron naming convention).
pub fn script_env(notif: &Notification) -> Vec<(&'static str, String)> {
    let mut pairs: Vec<(&'static str, String)> = notif.vars().into_iter().collect();
    pairs.push(("FERRUMGATE_RULENAME", notif.rule_name.clone()));
    pairs
}

fn merged_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut merged = String::from_utf8_lossy(stdout).into_owned();
    let stderr = String::from_utf8_lossy(stderr);
    if !stderr.is_empty() {
        if !merged.is_empty() && !merged.ends_with('\n') {
            merged.push('\n');
        }
        merged.push_str(&stderr);
    }
    merged
}

/// Truncates to [`limits::SCRIPT_OUTPUT_MAX_CHARS`] characters on char
/// boundaries (fg-cron pattern).
pub fn truncate_output(text: &str) -> String {
    if text.chars().count() <= limits::SCRIPT_OUTPUT_MAX_CHARS {
        return text.to_owned();
    }
    text.chars().take(limits::SCRIPT_OUTPUT_MAX_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn notif(changed: bool) -> Notification {
        Notification::new(
            "home lab",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 45_001),
            changed,
            SystemTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn notification_vars_carry_rule_time_ip_port_ipaddr() {
        let notif = notif(true);
        let vars = notif.vars();
        let get = |name: &str| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
                .expect("var present")
        };
        assert_eq!(get("ruleName"), "home lab");
        assert_eq!(get("ip"), "203.0.113.7");
        assert_eq!(get("port"), "45001");
        assert_eq!(get("ipAddr"), "203.0.113.7:45001");
        assert!(get("time").contains("T"), "RFC 3339: {}", get("time"));
        // Script environment carries the same names plus the alias.
        let env = script_env(&notif);
        assert_eq!(env[0], ("ruleName", "home lab".to_owned()));
        assert_eq!(env[4], ("ipAddr", "203.0.113.7:45001".to_owned()));
        assert_eq!(env[5], ("FERRUMGATE_RULENAME", "home lab".to_owned()));
    }

    #[test]
    fn webhook_rendering_substitutes_and_keeps_unknown_placeholders() {
        let notif = notif(false);
        let vars = notif.vars();
        assert_eq!(
            render(
                "ip={ip} port={port} addr={ipAddr} by {ruleName} at {time}",
                &vars
            ),
            format!(
                "ip=203.0.113.7 port=45001 addr=203.0.113.7:45001 by home lab at {}",
                notif.time_text()
            )
        );
        assert_eq!(render("{ghost}", &vars), "{ghost}");
        assert_eq!(render("no braces", &vars), "no braces");
    }

    #[test]
    fn webhook_only_on_change_gates_delivery() {
        let settings = Settings::default();
        let mut rule = Rule {
            webhook_only_on_change: true,
            ..Rule::default()
        };
        rule.webhook.url = "http://example.com/hook".into();
        let wanted = |rule: &Rule, changed: bool| {
            webhook_wanted(rule, effective_webhook(rule, &settings), &notif(changed))
        };
        assert!(!wanted(&rule, false), "unchanged suppressed");
        assert!(wanted(&rule, true), "change delivered");
        // Without the switch every success notifies.
        rule.webhook_only_on_change = false;
        assert!(wanted(&rule, false));
        // An empty URL never notifies.
        rule.webhook.url = String::new();
        assert!(!wanted(&rule, true));
    }

    #[test]
    fn output_truncation_respects_char_boundaries() {
        let long = "x".repeat(limits::SCRIPT_OUTPUT_MAX_CHARS + 500);
        let truncated = truncate_output(&long);
        assert_eq!(truncated.chars().count(), limits::SCRIPT_OUTPUT_MAX_CHARS);
        let wide = "汉".repeat(limits::SCRIPT_OUTPUT_MAX_CHARS + 10);
        let truncated = truncate_output(&wide);
        assert_eq!(truncated.chars().count(), limits::SCRIPT_OUTPUT_MAX_CHARS);
        assert!(truncated.ends_with('汉'));
        assert_eq!(merged_output(b"out", b"err"), "out\nerr");
    }
}
