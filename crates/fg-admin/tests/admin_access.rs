//! WP-14 access control over a real HTTP listener: the guard middleware
//! decides, the deny modes render, and the entry marker opens the gate.

use std::{net::IpAddr, net::SocketAddr, sync::Arc, time::SystemTime};

use anyhow::Result;
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::Response,
};
use fg_admin::{
    Principal,
    access::{AccessConfig, DenyMode, GuardConfig, entry},
};
use fg_net::ClientAddr;

/// The marker-signing key the services in this file share with the tests
/// that plant cookies.
const KEY: [u8; 32] = [7u8; 32];

fn service(config: AccessConfig) -> axum::Router {
    // The API router only mounts /api/ paths; the plain page routes the
    // gate also covers are merged in afterwards.
    let admin = fg_admin::ApiRouter::new(|_| Some(Principal::Session { read_only: false }))
        .route(Method::GET, "/api/session", "Session", || async {
            Json(serde_json::json!({ "ok": true }))
        })
        .finish();
    axum::Router::new()
        .merge(admin.router)
        .route(
            "/hidden",
            axum::routing::get(|| async { Json(serde_json::json!({ "hidden": true })) }),
        )
        .route(
            "/panel",
            axum::routing::get(|| async { Json(serde_json::json!({ "panel": true })) }),
        )
        .layer(from_fn_with_state(
            GuardConfig(config, Arc::new(KEY.to_vec())),
            fg_admin::access::guard,
        ))
}

async fn serve(service: axum::Router) -> Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            service.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Ok(address)
}

async fn get(
    address: SocketAddr,
    path: &str,
    cookie: Option<&str>,
) -> Result<(StatusCode, String, HeaderMap)> {
    let stream = tokio::net::TcpStream::connect(address).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = hyper::Request::builder()
        .uri(path)
        .header("host", address.to_string());
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let request = builder.body(http_body_util::Full::new(hyper::body::Bytes::new()))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await?
        .to_bytes();
    Ok((
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        headers,
    ))
}

/// Test-only stand-in for the real listener: plants the resolved client
/// address in the extensions, as a trusted proxy chain would.
async fn inject_client_addr(
    State(ip): State<IpAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(ClientAddr {
        ip,
        via: None,
        verified: false,
    });
    next.run(request).await
}

/// Plants only the peer socket address, exercising the guard's fallback
/// when no resolved client address is available.
async fn inject_peer_addr(
    State(peer): State<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(peer);
    next.run(request).await
}

#[tokio::test]
async fn entry_not_passed_is_404_by_default() -> Result<()> {
    let config = AccessConfig {
        safe_path: Some("/hidden".into()),
        ..AccessConfig::default()
    };
    let address = serve(service(config)).await?;
    // Without the marker every other path answers the minimal 404 page.
    let (status, body, _) = get(address, "/panel", None).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("404 Not Found"), "{body}");
    // The entry path itself stays reachable: visiting it plants the cookie.
    let (status, body, _) = get(address, "/hidden", None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("hidden"), "{body}");
    // A valid marker cookie opens the gate for every path.
    let marker = entry::plant_marker(&KEY, SystemTime::now());
    let (status, body, _) = get(
        address,
        "/api/session",
        Some(&format!("{}={marker}", entry::MARKER_COOKIE)),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body)?,
        serde_json::json!({ "ok": true })
    );
    Ok(())
}

#[tokio::test]
async fn deny_modes_produce_expected_responses() -> Result<()> {
    let outsider: IpAddr = "203.0.113.9".parse().unwrap();

    // notfound: a stock-web-server 404 with no product information.
    let config = AccessConfig {
        lan_only: true,
        deny_mode: DenyMode::NotFound,
        ..AccessConfig::default()
    };
    let address =
        serve(service(config).layer(from_fn_with_state(outsider, inject_client_addr))).await?;
    let (status, body, _) = get(address, "/api/session", None).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("404 Not Found"), "{body}");
    assert!(!body.contains("FerrumGate"), "{body}");
    assert!(!body.contains("gately"), "{body}");

    // blank: the status stays forbidden, the body carries nothing.
    let config = AccessConfig {
        lan_only: true,
        deny_mode: DenyMode::Blank,
        ..AccessConfig::default()
    };
    let address =
        serve(service(config).layer(from_fn_with_state(outsider, inject_client_addr))).await?;
    let (status, body, _) = get(address, "/api/session", None).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.is_empty(), "{body}");

    // custom: the operator's status and sanitized page with sandbox CSP.
    let config = AccessConfig {
        lan_only: true,
        deny_mode: DenyMode::Custom,
        deny_status: StatusCode::GONE,
        deny_page: r#"<p style="color:red">bye</p>"#.to_owned(),
        ..AccessConfig::default()
    };
    let address =
        serve(service(config).layer(from_fn_with_state(outsider, inject_client_addr))).await?;
    let (status, body, headers) = get(address, "/api/session", None).await?;
    assert_eq!(status, StatusCode::GONE);
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .expect("CSP header")
        .to_str()?;
    assert!(csp.contains("sandbox"), "{csp}");
    assert!(body.contains("bye"), "{body}");
    Ok(())
}

#[tokio::test]
async fn decide_lan_only_uses_client_addr() -> Result<()> {
    let config = AccessConfig {
        lan_only: true,
        ..AccessConfig::default()
    };
    // The loopback connection peer counts as internal and passes.
    let peer: SocketAddr = "127.0.0.1:39001".parse().unwrap();
    let address =
        serve(service(config.clone()).layer(from_fn_with_state(peer, inject_peer_addr))).await?;
    let (status, body, _) = get(address, "/api/session", None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    // An external client address is denied with the plain 403.
    let outsider: IpAddr = "203.0.113.9".parse().unwrap();
    let address =
        serve(service(config).layer(from_fn_with_state(outsider, inject_client_addr))).await?;
    let (status, body, headers) = get(address, "/api/session", None).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "403 Forbidden", "{body}");
    assert!(headers.get("vary").is_none(), "{headers:?}");
    let length: usize = headers
        .get(header::CONTENT_LENGTH)
        .expect("content-length")
        .to_str()?
        .parse()?;
    assert_eq!(length, body.len(), "{headers:?}");
    Ok(())
}

#[tokio::test]
async fn lan_only_internal_passthrough() -> Result<()> {
    let config = AccessConfig {
        lan_only: true,
        ..AccessConfig::default()
    };
    let lan: IpAddr = "192.168.1.10".parse().unwrap();
    let address = serve(service(config).layer(from_fn_with_state(lan, inject_client_addr))).await?;
    let (status, body, _) = get(address, "/api/session", None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body)?,
        serde_json::json!({ "ok": true })
    );
    Ok(())
}
