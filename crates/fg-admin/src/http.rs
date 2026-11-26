use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    body::HttpBody,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use tokio::sync::Semaphore;

use crate::{
    Localizer, Translation,
    response::{accepts_gzip, transform},
    upload::close_incomplete,
};

const MAX_JSON: usize = 4 << 20;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: &'static str,
}

impl ApiError {
    pub const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }

    pub(crate) const fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "configuration operation failed",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({"error": self.message})),
        )
            .into_response()
    }
}

pub struct ApiJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let JsonBody(bytes) = JsonBody::from_request(request, state).await?;
        serde_json::from_slice(&bytes)
            .map(Self)
            .map_err(|_| invalid_json())
    }
}

pub(crate) struct JsonBody(pub Vec<u8>);

pub(crate) fn invalid_json() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON request")
}

impl<S: Send + Sync> FromRequest<S> for JsonBody {
    type Rejection = ApiError;

    async fn from_request(request: Request, _: &S) -> Result<Self, Self::Rejection> {
        if !single_header(request.headers(), header::CONTENT_TYPE)
            .flatten()
            .is_some_and(|mime| {
                mime.split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
            })
        {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "expected application/json",
            ));
        }
        if request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|length| length.to_str().ok())
            .and_then(|length| length.parse::<u64>().ok())
            .is_some_and(|length| length > MAX_JSON as u64)
        {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "JSON request exceeds 4 MiB",
            ));
        }
        let mut body = request.into_body();
        let timed_out = || ApiError::new(StatusCode::REQUEST_TIMEOUT, "request body timed out");
        let bytes = tokio::time::timeout(Duration::from_secs(60), async {
            let mut bytes = Vec::new();
            while let Some(frame) = tokio::time::timeout(Duration::from_secs(15), body.frame())
                .await
                .map_err(|_| timed_out())?
            {
                let frame = frame.map_err(|_| {
                    ApiError::new(StatusCode::BAD_REQUEST, "could not read request body")
                })?;
                if let Ok(data) = frame.into_data() {
                    if data.len() > MAX_JSON - bytes.len() {
                        return Err(ApiError::new(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "JSON request exceeds 4 MiB",
                        ));
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| timed_out())??;
        Ok(Self(bytes))
    }
}

#[derive(Clone)]
pub(crate) struct Presentation {
    pub localizer: Option<Localizer>,
    pub budget: Arc<Semaphore>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct RenderPolicy {
    pub restricted: bool,
    pub stream: bool,
    pub translation: Translation,
}

pub(crate) async fn boundary(
    State(presentation): State<Presentation>,
    mut request: Request,
    next: Next,
) -> Response {
    let language = presentation
        .localizer
        .as_ref()
        .map(|localizer| localizer.negotiate(request.headers()));
    if let Some(language) = &language {
        request.extensions_mut().insert(language.clone());
    }
    let gzip = accepts_gzip(request.headers());
    let mut response = if same_origin(&request) {
        next.run(request).await
    } else {
        let mut response =
            ApiError::new(StatusCode::FORBIDDEN, "cross-origin request denied").into_response();
        if !request.body().is_end_stream() {
            close_incomplete(&mut response, request.version());
        }
        response
    };
    let close = response
        .headers()
        .get(header::CONNECTION)
        .is_some_and(|value| value == "close");
    let render = response
        .extensions_mut()
        .remove::<RenderPolicy>()
        .unwrap_or_default();
    if !render.stream {
        let localized =
            presentation
                .localizer
                .as_ref()
                .zip(language)
                .and_then(|(localizer, language)| {
                    localizer.response(language, render.translation, response.status())
                });
        response = transform(
            response,
            render.restricted,
            gzip,
            presentation.budget,
            localized,
        )
        .await;
    }
    let headers = response.headers_mut();
    if close {
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );

    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    if headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value == "application/json")
    {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
    }
    response
}

fn same_origin(request: &Request) -> bool {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return true;
    }
    let headers = request.headers();
    if let Some(origin) = single_header(headers, header::ORIGIN) {
        let Some(origin) = origin.and_then(|text| text.parse::<Uri>().ok()) else {
            return false;
        };
        if !matches!(origin.scheme_str(), Some("http" | "https"))
            || origin.path() != "/"
            || origin.query().is_some()
        {
            return false;
        }
        let Some(authority) = origin.authority() else {
            return false;
        };
        let host = single_header(headers, header::HOST).unwrap_or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        });
        return !authority.as_str().contains('@')
            && host.is_some_and(|host| host.eq_ignore_ascii_case(authority.as_str()));
    }
    single_header(headers, header::HeaderName::from_static("sec-fetch-site"))
        .is_none_or(|site| matches!(site, Some("same-origin" | "none")))
}

// The outer option distinguishes absence from a duplicate or malformed value.
fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Option<Option<&str>> {
    let all = headers.get_all(name);
    let mut fields = all.iter();
    let first = fields.next()?;
    Some(if fields.next().is_some() {
        None
    } else {
        first.to_str().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use hyper::body::{Body as HttpBody, Frame};
    use std::{
        convert::Infallible,
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::time::{Instant, Sleep, sleep};

    struct Drip {
        timer: Pin<Box<Sleep>>,
        interval: Duration,
    }

    impl HttpBody for Drip {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            if self.timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let deadline = Instant::now() + self.interval;
            self.timer.as_mut().reset(deadline);
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b" ")))))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_and_total_json_deadlines_apply_independently() -> anyhow::Result<()> {
        for (interval, budget) in [(30, 15), (10, 60)] {
            let interval = Duration::from_secs(interval);
            let request = Request::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::new(Drip {
                    timer: Box::pin(sleep(interval)),
                    interval,
                }))?;
            let start = Instant::now();
            let result = ApiJson::<serde_json::Value>::from_request(request, &()).await;
            assert!(matches!(
                result,
                Err(ApiError {
                    status: StatusCode::REQUEST_TIMEOUT,
                    ..
                })
            ));
            assert_eq!(start.elapsed(), Duration::from_secs(budget));
        }
        Ok(())
    }
}
