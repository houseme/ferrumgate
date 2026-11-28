//! Task webhook sender (WP-40 §3.3): renders `{…}` variables (URL
//! positions percent-encode the values), sends one request and matches the
//! `successContent` list. This is the DDNS-specific frontend; the generic
//! webhook implementation shared with STUN and cron lands with
//! `fg-net::webhook` and replaces this module's transport.

use std::{collections::BTreeMap, time::Duration};

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

use crate::model::{WebhookConfig, limits};

/// URL encoding of variable values: everything but unreserved characters.
const URL_VALUE_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Variable values for one send. Keyed by the placeholder name without
/// braces (`ipv4Addr`, `STUN_规则名_PORT`, …).
#[derive(Clone, Debug, Default)]
pub struct WebhookVars(pub BTreeMap<String, String>);

impl WebhookVars {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

/// Why a webhook send failed. Never carries credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookError {
    /// The URL is unusable or the client could not be built.
    Config(String),
    /// The request did not complete.
    Transport(String),
    /// A non-2xx response.
    Status(u16),
    /// A 2xx response whose body matched none of `successContent`.
    Unverified,
    /// A variable in the URL could not be resolved; nothing was sent.
    Unresolved,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookError::Config(detail) => write!(f, "Webhook 配置无效：{detail}"),
            WebhookError::Transport(detail) => write!(f, "Webhook 请求失败：{detail}"),
            WebhookError::Status(status) => write!(f, "Webhook 返回 HTTP {status}"),
            WebhookError::Unverified => {
                write!(f, "Webhook 响应未包含 successContent 中的任何一项")
            }
            WebhookError::Unresolved => write!(f, "Webhook 地址中的变量无法解析，未发送"),
        }
    }
}

/// Sends the webhook. `resolve` answers placeholder values; a placeholder
/// in the URL that stays unresolved aborts the send, unresolved
/// placeholders elsewhere render literally.
pub async fn send(
    cfg: &WebhookConfig,
    resolve: &(dyn Fn(&str) -> Option<String> + Send + Sync),
) -> Result<(), WebhookError> {
    let url = render(&cfg.url, resolve, true).ok_or(WebhookError::Unresolved)?;
    let method = if cfg.method.trim().is_empty() {
        "GET".to_owned()
    } else {
        cfg.method.trim().to_ascii_uppercase()
    };
    let mut headers = Vec::new();
    for header in &cfg.headers {
        if let Some((name, value)) = crate::validate::parse_header(header) {
            headers.push((name, render(&value, resolve, false).unwrap_or_default()));
        }
    }
    let body = render(&cfg.body, resolve, false).unwrap_or_default();
    let timeout = Duration::from_secs(
        u64::from(if cfg.timeout == 0 {
            limits::WEBHOOK_TIMEOUT_DEFAULT
        } else {
            cfg.timeout
        })
        .min(u64::from(limits::WEBHOOK_TIMEOUT_MAX)),
    );
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .danger_accept_invalid_certs(cfg.insecure_skip_verify);
    if !cfg.proxy.trim().is_empty() {
        let proxy = reqwest::Proxy::all(cfg.proxy.trim())
            .map_err(|error| WebhookError::Config(error.to_string()))?;
        builder = builder.proxy(proxy);
    }
    let client = builder
        .build()
        .map_err(|error| WebhookError::Config(error.to_string()))?;
    let method = method
        .parse::<reqwest::Method>()
        .map_err(|error| WebhookError::Config(error.to_string()))?;
    let mut request = client.request(method, &url);
    for (name, value) in &headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if !body.is_empty() {
        request = request.body(body);
    }
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            WebhookError::Transport("请求超时".to_owned())
        } else {
            WebhookError::Transport(error.to_string())
        }
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(WebhookError::Status(status.as_u16()));
    }
    if !cfg.success_content.is_empty() {
        let text = response.text().await.unwrap_or_default();
        let hit = cfg
            .success_content
            .iter()
            .any(|needle| text.contains(needle.as_str()));
        if !hit {
            return Err(WebhookError::Unverified);
        }
    }
    Ok(())
}

/// Substitutes `{name}` placeholders. With `encode` (URL positions) the
/// values are percent-encoded; `None` from the resolver keeps the
/// placeholder literal, except for URLs, where it aborts (the caller maps
/// that to [`WebhookError::Unresolved`]).
fn render(
    text: &str,
    resolve: &(dyn Fn(&str) -> Option<String> + Send + Sync),
    encode: bool,
) -> Option<String> {
    if !text.contains('{') {
        return Some(text.to_owned());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        let name = &rest[start + 1..start + end];
        out.push_str(&rest[..start]);
        match resolve(name) {
            Some(value) => {
                if encode {
                    out.push_str(
                        &percent_encoding::utf8_percent_encode(&value, URL_VALUE_ENCODE)
                            .to_string(),
                    );
                } else {
                    out.push_str(&value);
                }
            }
            None => {
                if encode {
                    return None;
                }
                out.push_str(&rest[start..start + end + 1]);
            }
        }
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A minimal HTTP/1.1 fake server; `responder` receives the raw
    /// request and returns the raw response bytes.
    async fn spawn_fake(
        responder: impl Fn(String) -> Vec<u8> + Send + 'static,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..read]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = responder(String::from_utf8_lossy(&buf).to_string());
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{addr}"), task)
    }

    fn vars(pairs: &[(&str, &str)]) -> WebhookVars {
        WebhookVars(
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        )
    }

    #[tokio::test]
    async fn webhook_expands_vars_and_urlencodes() {
        static REQUESTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let (base, task) = spawn_fake(|request| {
            let path = request.lines().next().unwrap_or_default().to_owned();
            REQUESTS.lock().expect("lock").push(path);
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok".to_vec()
        })
        .await;
        let cfg = WebhookConfig {
            enable: true,
            url: format!("{base}/notify?ip={{ipv4Addr}}"),
            method: "POST".into(),
            headers: vec!["X-Task: fixed".into()],
            body: "ip={ipv4Addr}".into(),
            ..WebhookConfig::default()
        };
        let resolved = vars(&[("ipv4Addr", "1.2.3.4 a:b")]);
        send(&cfg, &|name| resolved.get(name).map(str::to_owned))
            .await
            .expect("send");
        task.abort();
        let requests = REQUESTS.lock().expect("lock");
        assert_eq!(requests.len(), 1, "{requests:?}");
        let path = &requests[0];
        assert!(
            path.contains("ip=1.2.3.4%20a%3Ab"),
            "URL values are percent-encoded: {path}"
        );
    }

    #[tokio::test]
    async fn webhook_success_content() {
        let (base, task) = spawn_fake(|_| {
            b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nfail!".to_vec()
        })
        .await;
        let cfg = WebhookConfig {
            enable: true,
            url: format!("{base}/hook"),
            success_content: vec!["success".into(), "ok".into()],
            ..WebhookConfig::default()
        };
        let error = send(&cfg, &|_| Some("x".into()))
            .await
            .expect_err("no marker in body");
        assert_eq!(error, WebhookError::Unverified);
        task.abort();

        let (base, task) = spawn_fake(|_| {
            b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nall ok!!".to_vec()
        })
        .await;
        let cfg = WebhookConfig {
            enable: true,
            url: format!("{base}/hook"),
            success_content: vec!["ok".into()],
            ..WebhookConfig::default()
        };
        send(&cfg, &|_| None).await.expect("marker matches");
        task.abort();
    }

    #[tokio::test]
    async fn webhook_unresolved_url_aborts_and_transport_errors_surface() {
        let cfg = WebhookConfig {
            enable: true,
            url: "https://example.com/{STUN_ghost_IP}".into(),
            ..WebhookConfig::default()
        };
        let error = send(&cfg, &|_| None).await.expect_err("unresolved");
        assert_eq!(error, WebhookError::Unresolved);

        // A refused connection surfaces as a transport error.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let cfg = WebhookConfig {
            enable: true,
            url: format!("http://{addr}/hook"),
            timeout: 2,
            ..WebhookConfig::default()
        };
        let error = send(&cfg, &|_| Some("x".into()))
            .await
            .expect_err("refused");
        assert!(matches!(error, WebhookError::Transport(_)), "{error}");
    }
}
