use super::*;
use fg_admin::{AdminAssets, Asset};
use http_body::{Body as HttpBody, Frame};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};

struct Chunks {
    frame: Bytes,
    remaining: usize,
}

impl HttpBody for Chunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        self.remaining -= 1;
        Poll::Ready(Some(Ok(Frame::data(self.frame.clone()))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
}

#[tokio::test]
async fn uploads_stream_past_json_limit_and_reject_sizes_and_unauthorized_writes() -> Result<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let path = "/api/ddns/upload";
    let admin = ApiRouter::new(principal)
        .upload_route(
            Method::POST,
            path,
            "Upload",
            6 << 20,
            move |request: axum::extract::Request| async move {
                observed.fetch_add(1, Ordering::Relaxed);
                let mut body = request.into_body();
                let mut received = 0;
                while let Some(frame) = body.frame().await {
                    let frame = frame.map_err(|_| {
                        ApiError::new(StatusCode::BAD_REQUEST, "upload read failed")
                    })?;
                    if let Ok(bytes) = frame.into_data() {
                        received += bytes.len();
                    }
                }
                Ok::<_, ApiError>(Json(json!({"received":received})))
            },
        )
        .finish();
    assert_eq!(
        admin.document()["paths"][path]["post"]["x-upload-max-bytes"],
        6 << 20
    );
    let server = Server::start(admin.router).await?;
    let frame = Bytes::from(vec![0; 1 << 20]);
    let upload = |remaining| {
        Body::new(Chunks {
            frame: frame.clone(),
            remaining,
        })
    };

    let (status, headers, _) = server
        .call("POST", path, &[("x-test-id", "viewer")], upload(1))
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(headers["connection"], "close");
    let declared = server
        .call("POST", path, &EDIT, vec![0u8; (6 << 20) + 1])
        .await?;
    assert_eq!(declared.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(declared.1["connection"], "close");
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let successful = server
        .call("POST", path, &[("x-test-id", "admin")], upload(5))
        .await?;
    assert_eq!(successful.0, StatusCode::OK);
    assert_eq!(successful.2, json!({"received":5 << 20}));
    assert!(!successful.1.contains_key("connection"));
    let overshoot = server
        .call("POST", path, &[("x-test-id", "admin")], upload(7))
        .await?;
    assert_eq!(overshoot.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(overshoot.1["connection"], "close");
    assert_eq!(overshoot.2, json!({"error":"upload exceeds route limit"}));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    Ok(())
}

#[tokio::test]
async fn management_assets_preserve_gateway_prefix_variants_and_cache_boundaries() -> Result<()> {
    let script = "console.log('admin fixture');".repeat(128);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(script.as_bytes())?;
    let gzip = Bytes::from(encoder.finish()?);
    let asset_path = "/assets/app-a1b2c3d4.js";
    let assets = AdminAssets::new(
        "<!doctype html><html><head><script src=\"assets/app-a1b2c3d4.js\"></script></head><body>Status</body></html>",
        "/gateway/panel",
        [
            Asset {
                path: asset_path,
                content_type: "application/javascript",
                identity: None,
                gzip: Some(gzip.clone()),
                immutable: true,
            },
            Asset {
                path: "/manifest.webmanifest",
                content_type: "application/manifest+json",
                identity: Some(Bytes::from_static(b"{}")),
                gzip: None,
                immutable: false,
            },
        ],
    )?;
    let server = Server::start(
        ApiRouter::new(principal)
            .with_assets(assets)
            .finish()
            .router,
    )
    .await?;
    for page in ["/", "/index.html", "/settings/detail"] {
        let (status, headers, body) = server
            .call_raw("GET", page, &[("accept-encoding", "gzip")], Body::empty())
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["cache-control"], "no-cache");
        assert_eq!(headers["content-type"], "text/html; charset=utf-8");
        assert!(
            headers["content-security-policy"]
                .to_str()?
                .contains("base-uri 'self'")
        );
        assert!(std::str::from_utf8(&body)?.contains("<base href=\"/gateway/panel/\">"));
    }
    let (status, headers, bytes) = server
        .call_raw(
            "GET",
            asset_path,
            &[("accept-encoding", "gzip")],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert_eq!(headers["content-encoding"], "gzip");
    assert_eq!(headers["content-type"], "application/javascript");
    assert_eq!(headers["vary"], "Accept-Encoding");
    assert_eq!(
        headers["content-length"].to_str()?.parse::<usize>()?,
        gzip.len()
    );
    assert_eq!(bytes, gzip);
    let (_, headers, identity) = server
        .call_raw(
            "GET",
            asset_path,
            &[("accept-encoding", "gzip;q=0, *;q=1")],
            Body::empty(),
        )
        .await?;
    assert_eq!(identity, script.as_str());
    assert!(!headers.contains_key("content-encoding"));
    assert_eq!(headers["vary"], "Accept-Encoding");

    let (status, headers, bytes) = server
        .call_raw(
            "HEAD",
            asset_path,
            &[("accept-encoding", "gzip")],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(bytes.is_empty());
    assert_eq!(
        headers["content-length"].to_str()?.parse::<usize>()?,
        gzip.len()
    );
    let (status, headers, range) = server
        .call_raw(
            "GET",
            asset_path,
            &[("accept-encoding", "gzip"), ("range", "bytes=2-5")],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(!headers.contains_key("content-encoding"));
    assert_eq!(
        headers["content-range"],
        format!("bytes 2-5/{}", script.len())
    );
    assert_eq!(range, &script.as_bytes()[2..6]);
    let (status, headers, _) = server
        .call_raw(
            "GET",
            asset_path,
            &[("range", "bytes=999999-")],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(
        headers["content-range"],
        format!("bytes */{}", script.len())
    );
    let manifest = server
        .call_raw("GET", "/manifest.webmanifest", &[], Body::empty())
        .await?;
    assert_eq!(manifest.1["cache-control"], "no-cache");
    assert_eq!(manifest.1["content-type"], "application/manifest+json");
    for unknown in ["/api", "/api/missing", "/assets/missing", "/%2e%2e/secret"] {
        let response = server.call("GET", unknown, &[], Body::empty()).await?;
        assert_eq!(response.0, StatusCode::NOT_FOUND, "{unknown}");
        assert_eq!(response.1["cache-control"], "no-store");
    }
    assert_eq!(
        server
            .call("GET", "/api/openapi.json", &[], Body::empty())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert!(AdminAssets::new("<head></head>", "/with\"-quote", []).is_err());
    Ok(())
}
