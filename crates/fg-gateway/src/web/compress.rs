//! HTTP response compression (WP-27): Accept-Encoding negotiation,
//! compressible media-type detection, ETag weakening, WebSocket upgrade
//! passthrough, and gzip encoding.
//!
//! # Encoding support note
//! [`negotiate`] implements the full RFC 9110 priority order (`br` preferred
//! over `gzip`, `q=0` treated as explicit refusal, explicit `gzip` preferred
//! over `*`). Because the workspace currently includes `flate2` without a
//! `brotli` crate, runtime encoding ([`negotiate_runtime`] / [`compress_response`])
//! compresses with `gzip` whenever the client accepts `gzip` (directly or via
//! `*`) and falls back to `Identity` for `br`-only clients.

use std::io::Write;

use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use flate2::{Compression, write::GzEncoder};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};

/// Responses smaller than this byte threshold are left uncompressed.
pub const MIN_COMPRESS_SIZE: usize = 256;

/// Site-level compression toggle (applicable to proxy, static, and text sites;
/// redirect sites are excluded).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CompressConfig {
    pub enabled: bool,
}

/// Content-Coding selected by negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    Br,
    Gzip,
    Identity,
}

impl Encoding {
    /// Wire `Content-Encoding` header value (`None` for [`Encoding::Identity`]).
    pub fn as_header_value(self) -> Option<&'static str> {
        match self {
            Self::Br => Some("br"),
            Self::Gzip => Some("gzip"),
            Self::Identity => None,
        }
    }
}

/// Minimal response metadata needed to decide whether to compress.
#[derive(Clone, Debug)]
pub struct ResponseHead {
    pub status: StatusCode,
    pub headers: HeaderMap,
}

impl ResponseHead {
    pub fn new(status: StatusCode, headers: HeaderMap) -> Self {
        Self { status, headers }
    }
}

/// Parsed q-values extracted from an `Accept-Encoding` header.
#[derive(Clone, Copy, Debug, Default)]
struct AcceptWeights {
    br: Option<f32>,
    gzip: Option<f32>,
    star: Option<f32>,
}

fn parse_accept_encoding(accept_encoding: Option<&HeaderValue>) -> AcceptWeights {
    let mut weights = AcceptWeights::default();
    let Some(raw) = accept_encoding.and_then(|v| v.to_str().ok()) else {
        return weights;
    };

    for item in raw.split(',') {
        let mut parts = item.split(';');
        let Some(coding_raw) = parts.next() else {
            continue;
        };
        let coding = coding_raw.trim().to_ascii_lowercase();
        if coding.is_empty() {
            continue;
        }

        let mut q: f32 = 1.0;
        let mut valid_q = true;
        for param in parts {
            let param = param.trim();
            if let Some((k, v)) = param.split_once('=')
                && k.trim().eq_ignore_ascii_case("q")
            {
                match parse_qvalue(v.trim()) {
                    Some(parsed) => q = parsed,
                    None => valid_q = false,
                }
            }
        }
        if !valid_q {
            continue;
        }

        match coding.as_str() {
            "br" => weights.br = Some(q),
            "gzip" | "x-gzip" => {
                weights.gzip = Some(weights.gzip.map_or(q, |prev| prev.max(q)));
            }
            "*" => weights.star = Some(q),
            _ => {}
        }
    }
    weights
}

/// Parses an RFC 9110 qvalue in `0.0..=1.0`.
fn parse_qvalue(s: &str) -> Option<f32> {
    if s.is_empty() {
        return None;
    }
    let val: f32 = s.parse().ok()?;
    if val.is_finite() && (0.0..=1.0).contains(&val) {
        Some(val)
    } else {
        None
    }
}

/// Negotiates the preferred encoding from `Accept-Encoding`.
///
/// Rules (WP-27 §3.3):
/// - Prefers `br` over `gzip` when both are explicitly accepted at equal weight.
/// - Higher explicit q-value wins (`gzip;q=1.0, br;q=0.5` -> `Gzip`).
/// - `q=0` explicitly rejects an encoding (even if `*` is also present).
/// - An explicit `gzip` preference beats wildcard `*` (e.g. `gzip, *` -> `Gzip`).
/// - Wildcard `*` alone selects `br` (or `gzip` if `br;q=0`).
pub fn negotiate(accept_encoding: Option<&HeaderValue>) -> Encoding {
    let w = parse_accept_encoding(accept_encoding);
    let br_explicit = w.br.filter(|&q| q > 0.0);
    let gzip_explicit = w.gzip.filter(|&q| q > 0.0);

    match (br_explicit, gzip_explicit) {
        (Some(bq), Some(gq)) => {
            if bq >= gq {
                Encoding::Br
            } else {
                Encoding::Gzip
            }
        }
        (Some(_), None) => Encoding::Br,
        // Explicit `gzip` takes precedence over `*`.
        (None, Some(_)) => Encoding::Gzip,
        (None, None) => {
            let star_ok = w.star.is_some_and(|q| q > 0.0);
            if !star_ok {
                return Encoding::Identity;
            }
            let br_rejected = w.br == Some(0.0);
            let gzip_rejected = w.gzip == Some(0.0);
            if !br_rejected {
                Encoding::Br
            } else if !gzip_rejected {
                Encoding::Gzip
            } else {
                Encoding::Identity
            }
        }
    }
}

/// Runtime encoding negotiation matching the encoders compiled into this crate.
///
/// Selects `Gzip` when the client accepts `gzip` (explicitly with `q > 0`, or
/// via `*` without `gzip;q=0`). Falls back to `Identity` when only `br` is
/// accepted (since no brotli encoder crate is in the workspace dependencies).
pub fn negotiate_runtime(accept_encoding: Option<&HeaderValue>) -> Encoding {
    let w = parse_accept_encoding(accept_encoding);
    if w.gzip.is_some_and(|q| q > 0.0) {
        return Encoding::Gzip;
    }
    if w.gzip != Some(0.0) && w.star.is_some_and(|q| q > 0.0) {
        return Encoding::Gzip;
    }
    Encoding::Identity
}

/// Returns `true` when `content_type` represents a compressible text-like type.
///
/// Includes `text/*`, JSON, JavaScript, XML, XHTML, RSS/Atom, WebAssembly, and
/// SVG; explicitly excludes `text/event-stream` (SSE).
pub fn compressible(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media_type.is_empty() || media_type == "text/event-stream" {
        return false;
    }
    if media_type.starts_with("text/") {
        return true;
    }
    matches!(
        media_type.as_str(),
        "application/json"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "application/wasm"
            | "image/svg+xml"
    ) || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
}

/// Returns `true` if request or response headers indicate a WebSocket upgrade.
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    if let Some(upgrade) = headers.get(header::UPGRADE).and_then(|v| v.to_str().ok())
        && upgrade.trim().eq_ignore_ascii_case("websocket")
    {
        return true;
    }
    false
}

/// Decides whether a response with the given head should be compressed.
///
/// Returns `false` when compression is disabled, the response already has a
/// `Content-Encoding`, is a 1xx/204/304 or upgrade response, declares a
/// `Content-Length < 256`, or has a non-compressible `Content-Type`.
pub fn should_compress(cfg: &CompressConfig, resp: &ResponseHead) -> bool {
    if !cfg.enabled {
        return false;
    }
    if resp.status.is_informational()
        || resp.status == StatusCode::NO_CONTENT
        || resp.status == StatusCode::NOT_MODIFIED
    {
        return false;
    }
    if resp.headers.contains_key(header::UPGRADE)
        || resp.headers.contains_key(header::CONTENT_ENCODING)
    {
        return false;
    }
    if let Some(len) = resp
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
        && len < MIN_COMPRESS_SIZE
    {
        return false;
    }
    let Some(ct) = resp
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    compressible(ct)
}

/// Converts a strong `ETag` (`"abc"`) into a weak `ETag` (`W/"abc"`).
/// Weak ETags (`W/...`) and empty values are returned unchanged.
pub fn weaken_etag(etag: &str) -> String {
    let trimmed = etag.trim();
    if trimmed.is_empty() || trimmed.starts_with("W/") {
        return trimmed.to_owned();
    }
    format!("W/{trimmed}")
}

/// Compresses `data` with gzip (default compression level).
pub fn gzip_compress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Ensures `Vary` contains `Accept-Encoding` without duplicating it.
pub fn ensure_vary_accept_encoding(headers: &mut HeaderMap) {
    let already_present = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|tok| {
            let t = tok.trim();
            t == "*" || t.eq_ignore_ascii_case("accept-encoding")
        });
    if !already_present {
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

/// Applies compression to a buffered response in place when eligible.
///
/// Skips WebSocket upgrades, bodies `< 256` bytes, already-encoded responses,
/// and non-compressible content types. Weakens strong `ETag` values and appends
/// `Vary: Accept-Encoding` when compressing.
pub fn compress_parts(
    cfg: &CompressConfig,
    req_headers: &HeaderMap,
    status: StatusCode,
    headers: &mut HeaderMap,
    body: Bytes,
) -> Bytes {
    if !cfg.enabled || is_websocket_upgrade(req_headers) || body.len() < MIN_COMPRESS_SIZE {
        return body;
    }
    let head = ResponseHead::new(status, headers.clone());
    if !should_compress(cfg, &head) {
        return body;
    }
    let encoding = negotiate_runtime(req_headers.get(header::ACCEPT_ENCODING));
    if encoding != Encoding::Gzip {
        return body;
    }
    let Ok(compressed) = gzip_compress(&body) else {
        return body;
    };

    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(compressed.len()));
    ensure_vary_accept_encoding(headers);
    if let Some(etag) = headers
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(weaken_etag)
        && let Ok(val) = HeaderValue::from_str(&etag)
    {
        headers.insert(header::ETAG, val);
    }
    Bytes::from(compressed)
}

/// Compresses an axum [`Response`] when eligible.
pub async fn compress_response(
    cfg: &CompressConfig,
    req_headers: &HeaderMap,
    response: Response,
) -> Response {
    if !cfg.enabled || is_websocket_upgrade(req_headers) {
        return response;
    }
    let head = ResponseHead::new(response.status(), response.headers().clone());
    if !should_compress(cfg, &head) {
        return response;
    }
    if negotiate_runtime(req_headers.get(header::ACCEPT_ENCODING)) != Encoding::Gzip {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let Ok(collected) = body.collect().await else {
        return Response::from_parts(parts, Body::empty());
    };
    let bytes = collected.to_bytes();
    let out = compress_parts(cfg, req_headers, parts.status, &mut parts.headers, bytes);
    Response::from_parts(parts, Body::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    #[test]
    fn negotiate_prefers_br_then_gzip() {
        assert_eq!(negotiate(None), Encoding::Identity);
        assert_eq!(negotiate(Some(&hv(""))), Encoding::Identity);
        assert_eq!(negotiate(Some(&hv("gzip, deflate, br"))), Encoding::Br);
        assert_eq!(negotiate(Some(&hv("gzip, deflate"))), Encoding::Gzip);
        assert_eq!(negotiate(Some(&hv("br;q=0, gzip"))), Encoding::Gzip);
        assert_eq!(negotiate(Some(&hv("br;q=0, gzip;q=0"))), Encoding::Identity);
        assert_eq!(negotiate(Some(&hv("gzip;q=1.0, br;q=0.5"))), Encoding::Gzip);
        assert_eq!(negotiate(Some(&hv("gzip;q=0.5, br;q=1.0"))), Encoding::Br);
        // Explicit gzip beats wildcard `*`.
        assert_eq!(negotiate(Some(&hv("gzip, *"))), Encoding::Gzip);
        assert_eq!(negotiate(Some(&hv("gzip;q=0.5, *"))), Encoding::Gzip);
        // Wildcard alone selects br, unless br is refused.
        assert_eq!(negotiate(Some(&hv("*"))), Encoding::Br);
        assert_eq!(negotiate(Some(&hv("br;q=0, *"))), Encoding::Gzip);
        assert_eq!(
            negotiate(Some(&hv("br;q=0, gzip;q=0, *"))),
            Encoding::Identity
        );
        assert_eq!(negotiate(Some(&hv("*;q=0"))), Encoding::Identity);
    }

    #[test]
    fn compressible_excludes_event_stream() {
        assert!(!compressible("text/event-stream"));
        assert!(!compressible("text/event-stream; charset=utf-8"));
        assert!(!compressible("TEXT/EVENT-STREAM"));
        assert!(compressible("text/html; charset=utf-8"));
        assert!(compressible("text/plain"));
        assert!(compressible("text/css"));
        assert!(compressible("text/javascript"));
        assert!(compressible("application/json"));
        assert!(compressible("application/problem+json"));
        assert!(compressible("application/javascript"));
        assert!(compressible("application/xml"));
        assert!(compressible("application/xhtml+xml"));
        assert!(compressible("application/rss+xml"));
        assert!(compressible("application/atom+xml"));
        assert!(compressible("application/wasm"));
        assert!(compressible("image/svg+xml"));
        assert!(!compressible("image/png"));
        assert!(!compressible("application/octet-stream"));
        assert!(!compressible("video/mp4"));
    }

    #[test]
    fn weaken_etag_transforms_strong_only() {
        assert_eq!(weaken_etag("\"abc123\""), "W/\"abc123\"");
        assert_eq!(weaken_etag("W/\"abc123\""), "W/\"abc123\"");
        assert_eq!(weaken_etag(""), "");
    }

    #[test]
    fn should_compress_checks_threshold_and_existing_encoding() {
        let cfg = CompressConfig { enabled: true };
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, hv("text/plain"));
        h.insert(header::CONTENT_LENGTH, hv("255"));
        assert!(!should_compress(
            &cfg,
            &ResponseHead::new(StatusCode::OK, h)
        ));

        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, hv("text/plain"));
        h.insert(header::CONTENT_LENGTH, hv("256"));
        assert!(should_compress(&cfg, &ResponseHead::new(StatusCode::OK, h)));

        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, hv("text/plain"));
        h.insert(header::CONTENT_ENCODING, hv("br"));
        assert!(!should_compress(
            &cfg,
            &ResponseHead::new(StatusCode::OK, h)
        ));
    }
}
