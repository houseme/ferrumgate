use std::{
    net::SocketAddr,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    time::Duration,
};

use http_body_util::{Either, Full};
use hyper::{
    Method, Request, Response, StatusCode, Uri, Version,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::{
        CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue,
        PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE, VIA,
    },
    http::uri::Authority,
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

type Reply = Response<Either<DataBody, Full<Bytes>>>;

pub(crate) struct Proxy {
    routes: Routes,
    client: Client<HttpsConnector<HttpConnector>, DataBody>,
    response_header_timeout: Duration,
}

impl Proxy {
    pub fn new(routes: Routes, settings: &Settings, tls: rustls::ClientConfig) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_connect_timeout(Some(milliseconds(settings.connect_timeout_ms)));
        connector.set_nodelay(true);
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .wrap_connector(connector);
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .retry_canceled_requests(false)
            .build(connector);

        Self {
            routes,
            client,
            response_header_timeout: milliseconds(settings.response_header_timeout_ms),
        }
    }

    pub async fn forward(
        &self,
        mut request: Request<Incoming>,
        peer: SocketAddr,
        tls_name: Option<&str>,
        tunnel: &OnceLock<Tunnel>,
    ) -> Reply {
        if request.version() != Version::HTTP_11 {
            return reply(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
        }
        if request.method() == Method::CONNECT {
            return reply(StatusCode::NOT_IMPLEMENTED);
        }
        let Some(target) = request.uri().path_and_query().filter(|target| {
            request.uri().scheme().is_none()
                && request.uri().authority().is_none()
                && target.path().starts_with('/')
        }) else {
            return reply(StatusCode::BAD_REQUEST);
        };

        let mut hosts = request.headers().get_all(HOST).iter();
        let Some(original_host) = hosts.next().filter(|_| hosts.next().is_none()) else {
            return reply(StatusCode::BAD_REQUEST);
        };
        let Some(authority) = original_host
            .to_str()
            .ok()
            .and_then(|host| host.parse::<Authority>().ok())
            .filter(config::valid_authority)
        else {
            return reply(StatusCode::BAD_REQUEST);
        };

        let (upstream_uri, route) = {
            let host = config::canonical_host(authority.host()).expect("validated authority");
            if tls_name.is_some_and(|sni| sni != host) {
                return reply(StatusCode::MISDIRECTED_REQUEST);
            }
            let Some(route) = self.routes.find(&host, target.path()) else {
                return reply(StatusCode::NOT_FOUND);
            };
            let uri = Uri::builder()
                .scheme(route.scheme.clone())
                .authority(route.authority.clone())
                .path_and_query(target.clone())
                .build()
                .expect("validated authority and origin-form target");
            (uri, route)
        };
        let original_host = original_host.clone();
        let (handshake, chunked) = if request.headers().contains_key(UPGRADE) {
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
            .filter(|name| {
                matches!(name.as_str(), "forwarded" | "x-real-ip")
                    || name.as_str().starts_with("x-forwarded-")
            })
            .cloned()
            .collect();
        for name in forwarding_headers {
            headers.remove(name);
        }
        headers.insert(HOST, route.upstream_host.clone());
        headers.insert("x-forwarded-host", original_host);
        headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if tls_name.is_some() { "https" } else { "http" }),
        );
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&peer.ip().to_string()).expect("IP address is a header value"),
        );
        headers.append(VIA, HeaderValue::from_static("1.1 ferrumgate"));
        if chunked {
            headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        }
        *request.uri_mut() = upstream_uri;

        let result = timeout(
            self.response_header_timeout,
            self.client.request(request.map(DataBody)),
        )
        .await;

        match result {
            Ok(Ok(mut response)) if response.status() == StatusCode::SWITCHING_PROTOCOLS => {
                let Some(handshake) = handshake else {
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
                *response.version_mut() = Version::HTTP_11;
                response.map(|body| Either::Left(DataBody(body)))
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

pub(crate) struct DataBody(Incoming);

impl Body for DataBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        loop {
            match std::task::ready!(Pin::new(&mut self.0).poll_frame(cx)) {
                Some(Ok(frame)) if frame.is_trailers() => {}
                frame => return Poll::Ready(frame),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
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
