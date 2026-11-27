//! HTTP task execution (WP-62 §3.3): fire the configured request and judge
//! success by status plus optional `successContent` matching.
//!
//! The actual request goes through an injected [`HttpExecutor`]. The
//! assembler will pass `fg-net`'s outbound client (custom DNS + egress
//! restrictions, WP-14/WP-40) here; the built-in default uses `reqwest`
//! with rustls so the module works standalone.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;

use super::{Outcome, truncate_output};
use crate::model::{HttpTask, limits};
use crate::validate::parse_header;

/// The part of an HTTP task a request runner needs, decoupled from the
/// model so future executors can be injected from outside.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub timeout: Duration,
    pub insecure_skip_verify: bool,
}

impl HttpRequest {
    /// Extracts the request from the task model (headers already parsed
    /// and validated by `validate`).
    pub fn from_task(task: &HttpTask) -> Self {
        Self {
            url: task.url.clone(),
            method: task.method.clone(),
            headers: task
                .headers
                .iter()
                .filter_map(|h| parse_header(h))
                .collect(),
            body: task.body.clone(),
            timeout: Duration::from_secs(u64::from(task.timeout)),
            insecure_skip_verify: task.insecure_skip_verify,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// A pluggable request runner: the module hands over a fully specified
/// request and receives the response (or an error).
pub type HttpExecutor = Arc<
    dyn Fn(HttpRequest) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpResponse>> + Send>>
        + Send
        + Sync,
>;

/// Runs the HTTP task once with the given (or the default) executor.
pub async fn run(
    task: &HttpTask,
    executor: Option<HttpExecutor>,
    cancel: &CancellationToken,
) -> Outcome {
    let request = HttpRequest::from_task(task);
    let executor =
        executor.unwrap_or_else(|| Arc::new(|request| Box::pin(default_executor(request))));
    let send = executor(request);
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            return Outcome {
                success: false,
                output: "任务在模块关闭时被终止".into(),
            };
        }
        result = send => result,
    };
    let response = match result {
        Ok(response) => response,
        Err(error) => {
            return Outcome {
                success: false,
                output: format!("请求失败：{error}"),
            };
        }
    };
    let two_xx = (200..300).contains(&response.status);
    if !two_xx {
        return Outcome {
            success: false,
            output: truncate_output(&format!(
                "HTTP {}（期望 2xx）\n{}",
                response.status,
                excerpt(&response.body)
            )),
        };
    }
    // successContent non-empty: any one entry must appear in the body.
    if !task.success_content.is_empty()
        && !task
            .success_content
            .iter()
            .any(|needle| response.body.contains(needle.as_str()))
    {
        return Outcome {
            success: false,
            output: truncate_output(&format!(
                "HTTP {}：响应未包含 successContent 中的任何一项\n{}",
                response.status,
                excerpt(&response.body)
            )),
        };
    }
    Outcome {
        success: true,
        output: truncate_output(&format!(
            "HTTP {}\n{}",
            response.status,
            excerpt(&response.body)
        )),
    }
}

/// The response body excerpt kept in the summary.
fn excerpt(body: &str) -> String {
    let body = body.trim();
    let mut excerpt: String = body.chars().take(limits::HTTP_BODY_EXCERPT_CHARS).collect();
    if excerpt.chars().count() < body.chars().count() {
        excerpt.push('…');
    }
    excerpt
}

/// The built-in reqwest-based executor.
async fn default_executor(request: HttpRequest) -> anyhow::Result<HttpResponse> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|error| anyhow::anyhow!("无效的 HTTP 方法：{error}"))?;
    let mut builder = reqwest::Client::builder().timeout(request.timeout);
    if request.insecure_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder.build()?;
    let mut out = client.request(method, &request.url);
    for (name, value) in &request.headers {
        out = out.header(name, value);
    }
    if !request.body.is_empty() {
        out = out.body(request.body);
    }
    let response = out.send().await?;
    let status = response.status().as_u16();
    let body = response.text().await?;
    Ok(HttpResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_from_task_parses_headers_and_timeout() {
        let task = HttpTask {
            url: "https://example.com/hook".into(),
            method: "post".into(),
            headers: vec!["X-Token: abc".into(), "broken".into()],
            body: "hello".into(),
            success_content: vec!["done".into()],
            timeout: 15,
            insecure_skip_verify: true,
        };
        let request = HttpRequest::from_task(&task);
        assert_eq!(request.url, "https://example.com/hook");
        assert_eq!(request.method, "post");
        assert_eq!(request.headers, [("X-Token".to_owned(), "abc".to_owned())]);
        assert_eq!(request.timeout, Duration::from_secs(15));
        assert!(request.insecure_skip_verify);
    }
}
