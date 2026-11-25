use std::{
    net::SocketAddr,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    time::Duration,
};

use http_body_util::{Either, Empty, Full};
use hyper::{
    Method, Request, Response, StatusCode, Uri, Version,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::{
        CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue,
        PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE, VIA,
    },
    http::uri::{Authority, Scheme},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use tokio::time::timeout;

use crate::{
    config::{self, Routes, Settings, milliseconds},
    websocket::{Handshake, Tunnel},
};

pub(crate) type RequestBody = Either<DataBody, Empty<Bytes>>;

type Reply = Response<Either<DataBody, Full<Bytes>>>;

pub(crate) struct Proxy {
    routes: Routes,
    client: Client<HttpsConnector<HttpConnector>, RequestBody>,
    upgrade_client: Client<HttpsConnector<HttpConnector>, RequestBody>,
    h2c_client: Client<HttpConnector, RequestBody>,
    response_header_timeout: Duration,
}

impl Proxy {
    pub fn new(routes: Routes, settings: &Settings, tls: rustls::ClientConfig) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_connect_timeout(Some(milliseconds(settings.connect_timeout_ms)));
        connector.set_nodelay(true);
        let http1 = HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_http1()
            .wrap_connector(connector.clone());
        let negotiated = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector.clone());
        connector.enforce_http(true);

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .retry_canceled_requests(false)
            .http2_initial_stream_window_size(65_535)
            .http2_initial_connection_window_size(1024 * 1024)
            .http2_max_header_list_size(32 * 1024)
            .http2_max_send_buf_size(64 * 1024);

        Self {
            routes,
            client: builder.build(negotiated),
            upgrade_client: builder.build(http1),
            h2c_client: builder.http2_only(true).build(connector),
            response_header_timeout: milliseconds(settings.response_header_timeout_ms),
        }
    }

    pub async fn monitor_health(&self) {
        crate::health::monitor(self, &self.routes).await;
    }

    pub async fn probe_http(&self, request: Request<RequestBody>, h2c: bool) -> bool {
        let response = if h2c {
            self.h2c_client.request(request)
        } else {
            self.client.request(request)
        };
        response
            .await
            .is_ok_and(|response| response.status().as_u16() < 400)
    }

    pub async fn forward(
        &self,
        mut request: Request<Incoming>,
        peer: SocketAddr,
        tls_name: Option<&str>,
        tunnel: Option<&OnceLock<Tunnel>>,
    ) -> Reply {
        let downstream_version = request.version();
        let downstream_h2 = downstream_version == Version::HTTP_2;
        if downstream_version != Version::HTTP_11 && !downstream_h2 {
            return reply(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
        }
        if request.method() == Method::CONNECT {
            return reply(StatusCode::NOT_IMPLEMENTED);
        }
        let uri = request.uri();
        let Some(target) = uri
            .path_and_query()
            .filter(|target| target.path().starts_with('/'))
        else {
            return reply(StatusCode::BAD_REQUEST);
        };
        let mut hosts = request.headers().get_all(HOST).iter();
        let host_header = hosts.next();
        if hosts.next().is_some() {
            return reply(StatusCode::BAD_REQUEST);
        }
        let (authority, original_host) = if downstream_h2 {
            let Some(authority) = uri
                .authority()
                .filter(|_| uri.scheme() == Some(&Scheme::HTTPS))
            else {
                return reply(StatusCode::BAD_REQUEST);
            };
            if host_header.is_some_and(|host| {
                !host
                    .as_bytes()
                    .eq_ignore_ascii_case(authority.as_str().as_bytes())
            }) {
                return reply(StatusCode::BAD_REQUEST);
            }
            let Ok(host) = HeaderValue::from_str(authority.as_str()) else {
                return reply(StatusCode::BAD_REQUEST);
            };
            (authority.clone(), host)
        } else {
            if uri.scheme().is_some() || uri.authority().is_some() {
                return reply(StatusCode::BAD_REQUEST);
            }
            let Some(host) = host_header else {
                return reply(StatusCode::BAD_REQUEST);
            };
            let Some(authority) = host
                .to_str()
                .ok()
                .and_then(|value| value.parse::<Authority>().ok())
            else {
                return reply(StatusCode::BAD_REQUEST);
            };
            (authority, host.clone())
        };
        if !config::valid_authority(&authority) {
            return reply(StatusCode::BAD_REQUEST);
        }
        let (upstream_uri, route, backend) = {
            let host = config::canonical_host(authority.host()).expect("validated authority");
            if tls_name.is_some_and(|sni| sni != host) {
                return reply(StatusCode::MISDIRECTED_REQUEST);
            }
            let Some(route) = self.routes.find(&host, target.path()) else {
                return reply(StatusCode::NOT_FOUND);
            };
            let Some(backend) = route.backends.select(route.health.is_some()) else {
                return reply(StatusCode::SERVICE_UNAVAILABLE);
            };
            let uri = Uri::builder()
                .scheme(backend.scheme.clone())
                .authority(backend.authority.clone())
                .path_and_query(target.clone())
                .build()
                .expect("validated authority and origin-form target");
            (uri, route, backend)
        };
        let grpc = is_grpc(request.headers());
        if grpc && !downstream_h2 {
            return reply(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
        }
        if grpc && !route.upstream_h2c && backend.scheme != Scheme::HTTPS {
            return reply(StatusCode::BAD_GATEWAY);
        }
        let (handshake, chunked) = if request.headers().contains_key(UPGRADE) {
            if downstream_h2 {
                return reply(StatusCode::BAD_REQUEST);
            }
            match Handshake::prepare(&mut request, route.websocket) {
                Ok(handshake) => (Some(handshake), false),
                Err(status) => return reply(status),
            }
        } else {
            match strip_hop_headers(request.headers_mut()) {
                Ok(chunked) => (None, chunked),
                Err(()) => return reply(StatusCode::BAD_REQUEST),
            }
        };
        let headers = request.headers_mut();
        let forwarding_headers: Vec<_> = headers
            .keys()
            .filter(|name| is_forwarding_header(name))
            .cloned()
            .collect();
        for name in forwarding_headers {
            headers.remove(name);
        }
        headers.insert(HOST, backend.host.clone());
        headers.insert("x-forwarded-host", original_host);
        headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if tls_name.is_some() { "https" } else { "http" }),
        );
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&peer.ip().to_string()).expect("IP address is a header value"),
        );
        headers.append(
            VIA,
            HeaderValue::from_static(if downstream_h2 {
                "2 ferrumgate"
            } else {
                "1.1 ferrumgate"
            }),
        );
        let upstream_h2_required = handshake.is_none() && (route.upstream_h2c || grpc);
        if downstream_h2 && upstream_h2_required {
            headers.insert(TE, HeaderValue::from_static("trailers"));
        }
        let body_needs_framing =
            !request.body().is_end_stream() && request.body().size_hint().exact().is_none();
        if !upstream_h2_required && (chunked || body_needs_framing) {
            request
                .headers_mut()
                .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        }
        *request.uri_mut() = upstream_uri;
        *request.version_mut() = if upstream_h2_required {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        };
        let request = request
            .map(|body| Either::Left(DataBody::new(body, downstream_h2 && upstream_h2_required)));
        let pending = if handshake.is_some() {
            self.upgrade_client.request(request)
        } else if route.upstream_h2c {
            self.h2c_client.request(request)
        } else {
            self.client.request(request)
        };
        let result = timeout(self.response_header_timeout, pending).await;

        match &result {
            Ok(Ok(_)) => route.backends.connected(backend, route.health.is_some()),
            Ok(Err(error)) if error.is_connect() => route.backends.connection_failed(backend),
            _ => {}
        }

        match result {
            Ok(Ok(mut response)) if response.status() == StatusCode::SWITCHING_PROTOCOLS => {
                let (Some(handshake), Some(tunnel)) = (handshake, tunnel) else {
                    return reply(StatusCode::BAD_GATEWAY);
                };
                let Ok(upgraded) = handshake.complete(&mut response) else {
                    return reply(StatusCode::BAD_GATEWAY);
                };
                if tunnel.set(upgraded).is_err() {
                    return reply(StatusCode::BAD_GATEWAY);
                }
                response.map(|_| Either::Right(Full::default()))
            }
            Ok(Ok(mut response)) if !response.status().is_informational() => {
                if strip_hop_headers(response.headers_mut()).is_err() {
                    return reply(StatusCode::BAD_GATEWAY);
                }
                let trailers = downstream_h2 && response.version() == Version::HTTP_2;
                *response.version_mut() = downstream_version;
                response.map(|body| Either::Left(DataBody::new(body, trailers)))
            }
            Ok(Ok(_)) => reply(StatusCode::BAD_GATEWAY),
            Ok(Err(error)) => {
                tracing::debug!(
                    connect_error = error.is_connect(),
                    "upstream request failed"
                );
                reply(StatusCode::BAD_GATEWAY)
            }
            Err(_) => {
                tracing::debug!("upstream response header deadline expired");
                reply(StatusCode::GATEWAY_TIMEOUT)
            }
        }
    }
}

pub(crate) fn strip_hop_headers(headers: &mut HeaderMap) -> Result<bool, ()> {
    // Each HTTP connection is framed independently. Hyper decodes chunked data.
    let mut encodings = headers.get_all(TRANSFER_ENCODING).iter();
    let chunked = match encodings.next() {
        None => false,
        Some(encoding)
            if encoding.as_bytes().eq_ignore_ascii_case(b"chunked")
                && encodings.next().is_none()
                && !headers.contains_key(CONTENT_LENGTH) =>
        {
            true
        }
        Some(_) => return Err(()),
    };

    let mut nominated = Vec::new();
    for value in headers.get_all(CONNECTION) {
        for field in value.to_str().map_err(|_| ())?.split(',') {
            let field = field.trim_matches([' ', '\t']);
            if field.is_empty() {
                continue;
            }
            let name = HeaderName::from_bytes(field.as_bytes()).map_err(|_| ())?;
            if matches!(name, HOST | CONTENT_LENGTH | TRANSFER_ENCODING) {
                return Err(());
            }
            nominated.push(name);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
    Ok(chunked)
}

fn reply(status: StatusCode) -> Reply {
    let mut response = Response::new(Either::Right(Full::new(Bytes::from_static(
        status
            .canonical_reason()
            .unwrap_or("Gateway error")
            .as_bytes(),
    ))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn is_forwarding_header(name: &HeaderName) -> bool {
    matches!(name.as_str(), "forwarded" | "x-real-ip") || name.as_str().starts_with("x-forwarded-")
}

fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value.split(';').next().unwrap_or_default().trim();
            let (base, suffix) = media_type.split_once('+').unwrap_or((media_type, ""));
            base.eq_ignore_ascii_case("application/grpc")
                && (media_type == base || !suffix.is_empty())
        })
}

pub(crate) struct DataBody {
    inner: Incoming,
    trailers: bool,
}

impl DataBody {
    fn new(inner: Incoming, trailers: bool) -> Self {
        Self { inner, trailers }
    }
}

impl Body for DataBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        loop {
            match std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
                Some(Ok(frame)) if frame.is_trailers() => {
                    if self.trailers {
                        let mut fields = frame.into_trailers().expect("trailer frame");
                        if strip_hop_headers(&mut fields).is_ok() {
                            for name in [
                                HOST,
                                CONTENT_LENGTH,
                                CONTENT_TYPE,
                                hyper::header::AUTHORIZATION,
                                hyper::header::COOKIE,
                                hyper::header::SET_COOKIE,
                                hyper::header::CONTENT_ENCODING,
                            ] {
                                fields.remove(name);
                            }
                            let forwarding: Vec<_> = fields
                                .keys()
                                .filter(|name| is_forwarding_header(name))
                                .cloned()
                                .collect();
                            for name in forwarding {
                                fields.remove(name);
                            }
                            return Poll::Ready(Some(Ok(Frame::trailers(fields))));
                        }
                    }
                }
                frame => return Poll::Ready(frame),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_all_connection_values_and_only_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.append(CONNECTION, HeaderValue::from_static("X-A, keep-alive"));
        headers.append(CONNECTION, HeaderValue::from_static("X-B"));
        headers.insert("x-a", HeaderValue::from_static("hop header"));
        headers.insert("x-b", HeaderValue::from_static("hop header"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=3"));
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("local credential"),
        );
        headers.insert("x-app", HeaderValue::from_static("end to end"));

        assert_eq!(strip_hop_headers(&mut headers), Ok(false));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers["x-app"], "end to end");
    }

    #[test]
    fn only_accepts_supported_transfer_framing() {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(strip_hop_headers(&mut headers), Ok(true));
        assert!(!headers.contains_key(TRANSFER_ENCODING));

        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));
        assert!(strip_hop_headers(&mut headers).is_err());

        headers.clear();
        headers.insert(CONNECTION, HeaderValue::from_static("content-length"));
        assert!(strip_hop_headers(&mut headers).is_err());
    }
}
