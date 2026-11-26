use std::{io::Write, sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes, HttpBody, to_bytes},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use flate2::{Compression, write::GzEncoder};
use tokio::sync::Semaphore;

use crate::{ApiError, redact::redact};

pub(super) const MAX_TRANSFORMS: usize = 4;
const MAX_RESPONSE: usize = 8 << 20;
const GZIP_MINIMUM: usize = 1024;

pub(super) async fn transform(
    response: Response,
    restricted: bool,
    gzip: bool,
    budget: Arc<Semaphore>,
) -> Response {
    let status = response.status();
    if status.is_informational()
        || matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        )
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let size = body.size_hint().exact();
    let headers = &mut parts.headers;
    let encoded = headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|encoding| !encoding.as_bytes().eq_ignore_ascii_case(b"identity"));
    let partial =
        status == StatusCode::PARTIAL_CONTENT || headers.contains_key(header::CONTENT_RANGE);
    let mut content_types = headers.get_all(header::CONTENT_TYPE).iter();
    let json = content_types.next().is_some_and(is_json) && content_types.next().is_none();
    if restricted
        && (((!json || encoded || partial) && size != Some(0))
            || size.is_some_and(|size| size > MAX_RESPONSE as u64))
    {
        return unsafe_response();
    }
    if size == Some(0) {
        if restricted {
            invalidate_body_headers(headers);
        }
        return Response::from_parts(parts, body);
    }
    let compressible = json
        && !encoded
        && !partial
        && (restricted
            || size
                .is_some_and(|size| (GZIP_MINIMUM as u64..=MAX_RESPONSE as u64).contains(&size)));
    if compressible {
        add_vary(headers);
    }
    let gzip = gzip && compressible;
    if !restricted && !gzip {
        return Response::from_parts(parts, body);
    }

    let Ok(permit) = budget.try_acquire_owned() else {
        return if restricted {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "response redaction is busy",
            )
            .into_response()
        } else {
            Response::from_parts(parts, body)
        };
    };
    let Ok(Ok(bytes)) =
        tokio::time::timeout(Duration::from_secs(15), to_bytes(body, MAX_RESPONSE)).await
    else {
        return unsafe_response();
    };
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut bytes = bytes;
        if restricted {
            let mut value = serde_json::from_slice(&bytes).ok()?;
            redact(&mut value);
            let redacted = serde_json::to_vec(&value).ok()?;
            if redacted.len() > MAX_RESPONSE {
                return None;
            }
            bytes = Bytes::from(redacted);
        }
        if gzip && bytes.len() >= GZIP_MINIMUM {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            if encoder.write_all(&bytes).is_ok()
                && let Ok(compressed) = encoder.finish()
                && compressed.len() < bytes.len()
            {
                return Some((Bytes::from(compressed), true));
            }
        }
        Some((bytes, false))
    });
    let Ok(Some((bytes, compressed))) = task.await else {
        return unsafe_response();
    };
    if restricted || compressed {
        invalidate_body_headers(headers);
        headers.remove(header::CONTENT_ENCODING);
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    }
    if compressed {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    Response::from_parts(parts, Body::from(bytes))
}

fn unsafe_response() -> Response {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "could not safely process response",
    )
    .into_response()
}

fn is_json(value: &HeaderValue) -> bool {
    let Some(value) = value.to_str().ok().and_then(|text| text.split(';').next()) else {
        return false;
    };
    let Some((category, subtype)) = value.trim().split_once('/') else {
        return false;
    };
    category.eq_ignore_ascii_case("application")
        && (subtype.eq_ignore_ascii_case("json")
            || subtype
                .rsplit_once('+')
                .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json")))
}

fn invalidate_body_headers(headers: &mut HeaderMap) {
    for field in [
        header::CONTENT_LENGTH,
        header::ETAG,
        header::TRANSFER_ENCODING,
        header::TRAILER,
    ] {
        headers.remove(field);
    }
    for field in ["content-md5", "content-digest", "repr-digest", "digest"] {
        headers.remove(field);
    }
}

fn add_vary(headers: &mut HeaderMap) {
    if !headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|name| name.trim() == "*" || name.trim().eq_ignore_ascii_case("accept-encoding"))
    {
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

pub(super) fn accepts_gzip(headers: &HeaderMap) -> bool {
    let mut gzip = None;
    let mut wildcard = None;
    for item in headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
    {
        let mut parts = item.split(';');
        let coding = parts.next().unwrap_or_default().trim();
        let selected = if coding.eq_ignore_ascii_case("gzip") {
            &mut gzip
        } else if coding == "*" {
            &mut wildcard
        } else {
            continue;
        };
        let allowed = parts.all(|parameter| {
            parameter.split_once('=').is_some_and(|(name, number)| {
                name.trim().eq_ignore_ascii_case("q")
                    && number
                        .trim()
                        .parse::<f32>()
                        .is_ok_and(|q| q > 0.0 && q <= 1.0)
            })
        });
        *selected = Some(selected.unwrap_or(true) && allowed);
    }
    gzip.or(wildcard).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;

    #[tokio::test]
    async fn saturation_rejects_unredacted_data_and_allows_identity_compression_fallback() {
        let budget = Arc::new(Semaphore::new(0));
        let payload = serde_json::json!({"secret":"fixture-secret", "padding":"x".repeat(2048)});
        let denied = transform(Json(&payload).into_response(), true, true, budget.clone()).await;
        assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = to_bytes(denied.into_body(), MAX_RESPONSE).await.unwrap();
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains("fixture-secret")
        );

        let original = transform(Json(&payload).into_response(), false, true, budget).await;
        assert_eq!(original.status(), StatusCode::OK);
        assert!(!original.headers().contains_key(header::CONTENT_ENCODING));
        let bytes = to_bytes(original.into_body(), MAX_RESPONSE).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            payload
        );
    }
}
