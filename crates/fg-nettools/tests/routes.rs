//! Authorization contract (WP-71 §6 `nettools_requires_write_scope`): the
//! surrounding management router maps `/api/nettools/…` to domain
//! `nettools` — GET needs `nettools:read`, every mutation needs
//! `nettools:write`. The middleware below reproduces that mapping so the
//! contract is visible in this crate's tests.

#![forbid(unsafe_code)]

use axum::{
    Router,
    http::header::HeaderValue,
    http::{Request, StatusCode},
    middleware::{Next, from_fn},
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tempfile::TempDir;

mod common;

/// Request scopes come in the `x-scopes` header (comma separated); the
/// fg-admin rule is GET/HEAD → `nettools:read`, anything else →
/// `nettools:write`.
async fn authorize(request: Request<axum::body::Body>, next: Next) -> Response {
    let scopes = request
        .headers()
        .get("x-scopes")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').map(str::trim).collect::<Vec<_>>())
        .unwrap_or_default();
    let required = if request.method() == axum::http::Method::GET
        || request.method() == axum::http::Method::HEAD
    {
        "nettools:read"
    } else {
        "nettools:write"
    };
    if !scopes.contains(&required) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({ "error": format!("需要 {required} 权限") })),
        )
            .into_response();
    }
    next.run(request).await
}

struct Scoped {
    addr: std::net::SocketAddr,
    _dir: TempDir,
}

async fn scoped_router() -> Scoped {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = fg_config::ConfigStore::open(dir.path()).expect("store");
    let module = fg_nettools::Module::new(store, fg_nettools::Deps::default()).expect("module");
    let router: Router = module.mount(Router::new()).layer(from_fn(authorize));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    Scoped { addr, _dir: dir }
}

impl Scoped {
    async fn send(
        &self,
        method: &'static str,
        path: String,
        scopes: &'static str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("connect");
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("x-scopes", HeaderValue::from_static(scopes))
            .header("content-type", "application/json");
        let request = match body {
            Some(body) => builder
                .body(axum::body::Body::from(body.to_string()))
                .expect("body"),
            None => builder.body(axum::body::Body::empty()).expect("body"),
        };
        let response = sender.send_request(request).await.expect("send");
        let status = response.status();
        let bytes = BodyExt::collect(response.into_body())
            .await
            .expect("collect")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nettools_requires_write_scope() {
    let scoped = scoped_router().await;
    // A read-only identity: GET works, every mutation is refused.
    let (status, _) = scoped
        .send(
            "GET",
            "/api/nettools/settings".into(),
            "nettools:read",
            None,
        )
        .await;
    assert_eq!(status, 200);
    let (status, body) = scoped
        .send(
            "POST",
            "/api/nettools/run".into(),
            "nettools:read",
            Some(json!({ "tool": "portprobe", "target": "127.0.0.1", "ports": "80" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = scoped
        .send(
            "DELETE",
            "/api/nettools/tasks/whatever".into(),
            "nettools:read",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A write identity passes through to the handler.
    let (status, view) = scoped
        .send(
            "POST",
            "/api/nettools/run".into(),
            "nettools:write",
            Some(json!({ "tool": "portprobe", "target": "127.0.0.1", "ports": "80" })),
        )
        .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["kind"], "portprobe");
}
