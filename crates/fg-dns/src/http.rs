//! 统一的出站 HTTP 封装与错误分类（WP-41 §3.3）。
//!
//! 所有提供商的请求都经 [`OutboundHttp`] 发送：固定 User-Agent、每个请求有
//! 超时（任务的 `httpTimeout`，默认 20 秒）、响应体上限 4 MiB、不跟随重定向
//! （hyper legacy 客户端默认不跟随，满足「不跟随重定向到其他主机」）。
//! 日志只记录方法、主机、路径与状态码，不记录查询串（DuckDNS 等把令牌放在
//! 查询串里）、请求头与请求体。
//!
//! 错误按 [`ProviderErrorKind`] 分类：认证失败（401/403）、限速（429，带
//! `Retry-After`）、未找到（404）、无效输入（其余 4xx）、传输错误（连接、
//! 超时、响应体读取）、服务端错误（5xx 与 3xx）、响应无法解析（`Parse`，
//! 由各提供商解析响应体时归类）。

use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, Uri, body::Bytes, header::USER_AGENT};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};

use crate::{ProviderErrorKind, simple};

/// 任务的 `httpTimeout` 默认 20 秒。
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
/// 响应体上限，避免把整页 HTML 读进内存。
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// 固定的 User-Agent。
pub const USER_AGENT_VALUE: &str = concat!(
    "FerrumGate/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/houseme/ferrumgate)"
);

type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// 出站 HTTP 客户端。遵循全局的自定义 DNS 与更新代理的接入点在 WP-40/WP-32
/// 联调时由装配层注入；本类型只负责单次请求的语义。
pub struct OutboundHttp {
    client: HttpsClient,
    timeout: Duration,
}

impl OutboundHttp {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> anyhow::Result<Self> {
        let https = HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(rustls::crypto::aws_lc_rs::default_provider())?
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new())
            .retry_canceled_requests(false)
            .build(https);
        Ok(Self { client, timeout })
    }

    /// 发送一次请求。非 2xx 返回 [`HttpFail::Status`]，传输失败与超时分别
    /// 返回 [`HttpFail::Transport`] 与 [`HttpFail::Timeout`]。
    pub async fn send(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Bytes>,
    ) -> Result<HttpReply, HttpFail> {
        let uri: Uri = url
            .parse()
            .map_err(|e| HttpFail::Transport(format!("invalid request url: {e}")))?;
        let method_name = method.as_str().to_owned();
        let mut builder = Request::builder()
            .method(method)
            .uri(uri.clone())
            .header(USER_AGENT, USER_AGENT_VALUE);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(Full::new(body.unwrap_or_default()))
            .map_err(|e| HttpFail::Transport(format!("build request: {e}")))?;
        let response = match tokio::time::timeout(self.timeout, self.client.request(request)).await
        {
            Err(_) => return Err(HttpFail::Timeout),
            Ok(Err(e)) => {
                return Err(HttpFail::Transport(crate::simple::truncate(
                    &e.to_string(),
                    300,
                )));
            }
            Ok(Ok(response)) => response,
        };
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(parse_retry_after);
        let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
            .collect()
            .await
            .map_err(|_| HttpFail::Transport("read response body".to_owned()))?
            .to_bytes();
        // 只记录主机与路径；查询串可能携带令牌（DuckDNS），不记录。
        tracing::debug!(
            method = method_name,
            host = uri.host().unwrap_or_default(),
            path = uri.path(),
            status = status.as_u16(),
            "dns provider request"
        );
        if !status.is_success() {
            return Err(HttpFail::Status {
                status,
                body,
                retry_after,
            });
        }
        Ok(HttpReply { status, body })
    }
}

/// 一次成功的（2xx）响应。
#[derive(Clone, Debug)]
pub struct HttpReply {
    pub status: StatusCode,
    pub body: Bytes,
}

impl HttpReply {
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// 一次失败的请求。
#[derive(Clone, Debug)]
pub enum HttpFail {
    Transport(String),
    Timeout,
    Status {
        status: StatusCode,
        body: Bytes,
        retry_after: Option<Duration>,
    },
}

impl HttpFail {
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            HttpFail::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn kind(&self) -> ProviderErrorKind {
        match self {
            HttpFail::Transport(_) | HttpFail::Timeout => ProviderErrorKind::Transport,
            HttpFail::Status { status, .. } => kind_for_status(*status),
        }
    }

    pub fn detail(&self) -> String {
        match self {
            HttpFail::Transport(message) => message.clone(),
            HttpFail::Timeout => "request timed out".to_owned(),
            HttpFail::Status { body, .. } => simple::truncate(&String::from_utf8_lossy(body), 300),
        }
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            HttpFail::Status { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// 按 HTTP 状态归类错误。
pub fn kind_for_status(status: StatusCode) -> ProviderErrorKind {
    match status.as_u16() {
        401 | 403 => ProviderErrorKind::Auth,
        404 => ProviderErrorKind::NotFound,
        429 => ProviderErrorKind::RateLimited,
        // 不跟随重定向；3xx 视为传输层异常。
        300..=399 => ProviderErrorKind::Transport,
        400..=499 => ProviderErrorKind::InvalidInput,
        _ => ProviderErrorKind::Server,
    }
}

/// `Retry-After` 只支持 delta-seconds 写法；HTTP-date 忽略。
fn parse_retry_after(value: &hyper::header::HeaderValue) -> Option<Duration> {
    let text = value.to_str().ok()?.trim();
    text.parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderError, msg};

    /// 启动一个最小的 HTTP/1.1 假服务器；`responder` 收到完整请求原文，
    /// 返回要写回的响应原文。
    async fn spawn_fake(
        responder: impl Fn(Vec<u8>) -> Vec<u8> + Send + 'static,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let request = read_request(&mut stream).await;
                let Some(request) = request else { continue };
                let response = responder(request);
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{addr}"), task)
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if request_complete(&buf) {
                return Some(buf);
            }
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return if buf.is_empty() { None } else { Some(buf) };
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn request_complete(buf: &[u8]) -> bool {
        let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&buf[..head_end]);
        let length = head
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        buf.len() >= head_end + 4 + length
    }

    fn raw_response(
        status: u16,
        reason: &str,
        extra_headers: &[(&str, &str)],
        body: &str,
    ) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\n",
            body.len()
        );
        for (k, v) in extra_headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("connection: close\r\n\r\n");
        out.push_str(body);
        out.into_bytes()
    }

    async fn send_get(url: &str) -> Result<HttpReply, HttpFail> {
        let http = OutboundHttp::new().expect("client");
        http.send(Method::GET, url, &[], None).await
    }

    #[tokio::test]
    async fn http_send_success_returns_body() {
        let (url, task) = spawn_fake(|_| raw_response(200, "OK", &[], r#"{"ok":true}"#)).await;
        let reply = send_get(&url).await.expect("reply");
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.text(), r#"{"ok":true}"#);
        task.abort();
    }

    #[tokio::test]
    async fn http_send_connect_refused_is_transport() {
        // 绑定后立刻释放端口，保证连接被拒绝。
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let fail = send_get(&format!("http://{addr}"))
            .await
            .expect_err("transport");
        assert_eq!(fail.kind(), ProviderErrorKind::Transport);
    }

    #[tokio::test]
    async fn http_send_slow_server_times_out() {
        let (url, task) = spawn_fake(|_| {
            // 假服务器先等一会儿再响应，客户端超时（默认 20 秒太长，这里用专用客户端）。
            std::thread::sleep(Duration::from_millis(500));
            raw_response(200, "OK", &[], "")
        })
        .await;
        let http = OutboundHttp::with_timeout(Duration::from_millis(100)).expect("client");
        let fail = http
            .send(Method::GET, &url, &[], None)
            .await
            .expect_err("timeout");
        assert_eq!(fail.kind(), ProviderErrorKind::Transport);
        task.abort();
    }

    #[tokio::test]
    async fn http_send_unauthorized_is_auth() {
        for status in [401, 403] {
            let (url, task) = spawn_fake(move |_| {
                raw_response(status, "Denied", &[], r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}"#)
            })
            .await;
            let fail = send_get(&url).await.expect_err("auth");
            assert_eq!(fail.kind(), ProviderErrorKind::Auth, "{status}");
            task.abort();
        }
    }

    #[tokio::test]
    async fn http_send_not_found_is_not_found() {
        let (url, task) = spawn_fake(|_| raw_response(404, "Not Found", &[], "{}")).await;
        let fail = send_get(&url).await.expect_err("404");
        assert_eq!(fail.kind(), ProviderErrorKind::NotFound);
        task.abort();
    }

    #[tokio::test]
    async fn http_send_rate_limited_carries_retry_after() {
        let (url, task) =
            spawn_fake(|_| raw_response(429, "Slow down", &[("retry-after", "7")], "{}")).await;
        let fail = send_get(&url).await.expect_err("429");
        assert_eq!(fail.kind(), ProviderErrorKind::RateLimited);
        assert_eq!(fail.retry_after(), Some(Duration::from_secs(7)));
        task.abort();
    }

    #[tokio::test]
    async fn http_send_other_client_errors_are_invalid_input() {
        let (url, task) = spawn_fake(|_| raw_response(400, "Bad Request", &[], "{}")).await;
        let fail = send_get(&url).await.expect_err("400");
        assert_eq!(fail.kind(), ProviderErrorKind::InvalidInput);
        task.abort();
    }

    #[tokio::test]
    async fn http_send_server_errors_are_server() {
        let (url, task) = spawn_fake(|_| raw_response(500, "Boom", &[], "oops")).await;
        let fail = send_get(&url).await.expect_err("500");
        assert_eq!(fail.kind(), ProviderErrorKind::Server);
        assert_eq!(fail.detail(), "oops");
        task.abort();
    }

    #[test]
    fn http_kind_for_status_maps_seven_classes() {
        assert_eq!(
            kind_for_status(StatusCode::UNAUTHORIZED),
            ProviderErrorKind::Auth
        );
        assert_eq!(
            kind_for_status(StatusCode::FORBIDDEN),
            ProviderErrorKind::Auth
        );
        assert_eq!(
            kind_for_status(StatusCode::TOO_MANY_REQUESTS),
            ProviderErrorKind::RateLimited
        );
        assert_eq!(
            kind_for_status(StatusCode::NOT_FOUND),
            ProviderErrorKind::NotFound
        );
        assert_eq!(
            kind_for_status(StatusCode::CONFLICT),
            ProviderErrorKind::InvalidInput
        );
        assert_eq!(
            kind_for_status(StatusCode::BAD_GATEWAY),
            ProviderErrorKind::Server
        );
        assert_eq!(
            ProviderError::from_http("x", HttpFail::Transport("connect refused".into())).kind,
            ProviderErrorKind::Transport
        );
        assert_eq!(
            ProviderError::from_http("x", HttpFail::Timeout).kind,
            ProviderErrorKind::Transport
        );
        assert_eq!(
            ProviderError::from_http(
                "x",
                HttpFail::Status {
                    status: StatusCode::UNAUTHORIZED,
                    body: Bytes::new(),
                    retry_after: None,
                }
            )
            .message_key,
            msg::AUTH_FAILED
        );
    }
}
