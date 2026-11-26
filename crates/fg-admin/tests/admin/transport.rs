use super::*;
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
