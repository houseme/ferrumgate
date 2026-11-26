//! Backend connectivity probe: one TCP connect, or one non-following HEAD
//! request for http(s) targets performed by an injected HTTP client (the
//! management crate stays out of the TLS stack). It can reach intranet
//! addresses, so it stays admin-session only; responses carry
//! reachability, status and a failure category, never headers or bodies.

use std::{sync::Arc, time::Instant};

use axum::{Json, http::Method};
use fg_core::check::BoxFut;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpStream, sync::Semaphore};

use crate::{ApiError, ApiJson, ApiRouter, RouteModels};

const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_INFLIGHT: usize = 4;

/// Performs one HEAD request for `host:port`, HTTPS when flagged; returns
/// the status code. Any-certificate acceptance is the caller's choice.
pub type HeadFn = dyn Fn(String, bool) -> BoxFut<'static, Result<u16, String>> + Send + Sync;
pub type HeadLookup = Arc<HeadFn>;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    pub target: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Set when the connection needed any-certificate acceptance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// refused / timeout / dns / tls / protocol / unreachable / error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    pub elapsed_ms: u64,
}

pub(super) fn mount(router: ApiRouter, head: HeadLookup) -> ApiRouter {
    let slots = Arc::new(Semaphore::new(MAX_INFLIGHT));

    router.modeled_route(
        Method::POST,
        "/api/system/probe",
        "Probe backend connectivity",
        RouteModels::default()
            .request::<ProbeRequest>()
            .response::<ProbeResult>(),
        move |ApiJson(request): ApiJson<ProbeRequest>| async move {
            let permit = slots.clone().try_acquire_owned().map_err(|_| {
                ApiError::new(axum::http::StatusCode::TOO_MANY_REQUESTS, "probe is busy")
            })?;
            let _permit = permit;
            probe(&request.target, head.clone()).await
        },
    )
}

/// Validates and normalizes the target into `(scheme, host:port)`.
pub fn parse_target(input: &str) -> Result<(&'static str, String), ApiError> {
    let format_error = || {
        ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "地址格式应为 http(s)://主机:端口 或 主机:端口",
        )
    };
    let input = input.trim();
    let (scheme, host, port) = if !input.contains("://") {
        let (host, port) = input.rsplit_once(':').ok_or_else(format_error)?;
        let host = host.trim_matches(['[', ']']);
        ("tcp", host.to_owned(), port.to_owned())
    } else {
        let url = url::Url::parse(input).map_err(|_| format_error())?;
        let scheme: &'static str = match url.scheme() {
            "http" => "http",
            "https" => "https",
            _ => {
                return Err(ApiError::new(
                    axum::http::StatusCode::BAD_REQUEST,
                    "只支持 http 与 https 地址",
                ));
            }
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "地址中不能包含用户名或密码",
            ));
        }
        let port = url
            .port()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let host = url.host_str().ok_or_else(format_error)?;
        (scheme, host.to_owned(), port.to_string())
    };
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| ApiError::new(axum::http::StatusCode::BAD_REQUEST, "端口应为 1-65535"))?;
    Ok((scheme, format!("{host}:{port}")))
}

async fn probe(target: &str, head: Arc<HeadFn>) -> Result<Json<ProbeResult>, ApiError> {
    let (scheme, hostport) = parse_target(target)?;
    let started = Instant::now();
    let connect = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(&hostport)).await;
    let reachable_tcp = match connect {
        Err(_) => return Ok(Json(timeout_result(started))),
        Ok(Err(error)) => {
            return Ok(Json(ProbeResult {
                reachable: false,
                status: None,
                insecure: None,
                reason: Some(classify(&error.to_string())),
                elapsed_ms: elapsed(started),
            }));
        }
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            scheme == "tcp"
        }
    };
    if reachable_tcp {
        return Ok(Json(ProbeResult {
            reachable: true,
            status: None,
            insecure: None,
            reason: None,
            elapsed_ms: elapsed(started),
        }));
    }
    let https = scheme == "https";
    let head_target = hostport.clone();
    let outcome = tokio::time::timeout(TOTAL_TIMEOUT, head(head_target, https)).await;
    match outcome {
        Err(_) => Ok(Json(timeout_result(started))),
        Ok(Err(error)) => Ok(Json(ProbeResult {
            reachable: false,
            status: None,
            insecure: None,
            reason: Some(classify(&error)),
            elapsed_ms: elapsed(started),
        })),
        Ok(Ok(status)) => Ok(Json(ProbeResult {
            reachable: true,
            status: Some(status),
            insecure: Some(true),
            reason: None,
            elapsed_ms: elapsed(started),
        })),
    }
}

fn timeout_result(started: Instant) -> ProbeResult {
    ProbeResult {
        reachable: false,
        status: None,
        insecure: None,
        reason: Some("timeout"),
        elapsed_ms: elapsed(started),
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// Maps connection errors to stable categories; the raw text never leaves.
pub fn classify(text: &str) -> &'static str {
    let text = text.to_ascii_lowercase();
    if text.contains("refused") {
        "refused"
    } else if text.contains("resolve")
        || text.contains("lookup address")
        || text.contains("name or service")
    {
        "dns"
    } else if text.contains("certificate") || text.contains("handshake") || text.contains("alert") {
        "tls"
    } else if text.contains("unreachable") {
        "unreachable"
    } else if text.contains("timed out") || text.contains("deadline") {
        "timeout"
    } else if text.contains("http/1") && text.contains("invalid") {
        "protocol"
    } else {
        "error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing_accepts_hosts_ports_and_urls() {
        assert_eq!(
            parse_target("127.0.0.1:8080").unwrap(),
            ("tcp", "127.0.0.1:8080".to_owned())
        );
        assert_eq!(
            parse_target("http://10.0.0.2:9000/").unwrap(),
            ("http", "10.0.0.2:9000".to_owned())
        );
        assert_eq!(
            parse_target("https://backend.test").unwrap(),
            ("https", "backend.test:443".to_owned())
        );
        assert!(parse_target("ftp://x").is_err());
        assert!(parse_target("http://user:pw@host").is_err());
        assert!(parse_target("host:notaport").is_err());
        assert!(parse_target("").is_err());
    }

    #[test]
    fn errors_map_to_stable_categories() {
        for (text, expected) in [
            ("connection refused", "refused"),
            ("failed to lookup address information", "dns"),
            ("invalid certificate: UnknownIssuer", "tls"),
            ("network unreachable", "unreachable"),
            ("operation timed out", "timeout"),
            ("HTTP/1 invalid token", "protocol"),
            ("something else", "error"),
        ] {
            assert_eq!(classify(text), expected, "{text}");
        }
    }
}
