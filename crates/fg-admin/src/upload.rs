use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    body::{Body, Bytes, HttpBody},
    extract::Request,
    http::{StatusCode, Version, header},
    response::Response,
};
use http_body::{Frame, SizeHint};
use tokio::time::{Instant, Sleep, sleep_until};

use crate::ApiError;

const IDLE: Duration = Duration::from_secs(30);
const GRACE: Duration = Duration::from_secs(30);
const MIN_RATE: u64 = 4 << 10;
const COMPLETE: u16 = 1;

#[derive(Default)]
pub(super) struct UploadState(AtomicU16);

impl UploadState {
    pub fn complete(&self) -> bool {
        self.0.load(Ordering::Relaxed) == COMPLETE
    }

    pub fn error(&self) -> Option<ApiError> {
        match self.0.load(Ordering::Relaxed) {
            400 => Some(ApiError::new(
                StatusCode::BAD_REQUEST,
                "could not read upload body",
            )),
            408 => Some(ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "upload body timed out or is too slow",
            )),
            413 => Some(too_large()),
            _ => None,
        }
    }
}

pub(super) fn protect(request: &mut Request, limit: u64) -> Result<Arc<UploadState>, ApiError> {
    let length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|length| {
            length
                .to_str()
                .ok()
                .and_then(|length| length.parse::<u64>().ok())
                .ok_or_else(|| {
                    ApiError::new(StatusCode::BAD_REQUEST, "invalid upload content length")
                })
        })
        .transpose()?;
    if length.is_some_and(|length| length > limit) || request.body().size_hint().lower() > limit {
        return Err(too_large());
    }
    let state = Arc::new(UploadState::default());
    if request.body().is_end_stream() {
        state.0.store(COMPLETE, Ordering::Relaxed);
    } else {
        let body = std::mem::replace(request.body_mut(), Body::empty());
        let start = Instant::now();
        *request.body_mut() = Body::new(Guarded {
            body,
            start,
            limit,
            length,
            state: state.clone(),
            bytes: 0,
            timer: Box::pin(sleep_until(start)),
            reading: false,
        });
    }
    Ok(state)
}

pub(super) fn close_incomplete(response: &mut Response, version: Version) {
    if matches!(version, Version::HTTP_10 | Version::HTTP_11) {
        response
            .headers_mut()
            .insert(header::CONNECTION, "close".parse().expect("header value"));
    }
}

fn too_large() -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "upload exceeds route limit")
}

struct Guarded {
    body: Body,
    start: Instant,
    limit: u64,
    length: Option<u64>,
    state: Arc<UploadState>,
    bytes: u64,
    timer: Pin<Box<Sleep>>,
    reading: bool,
}

impl Guarded {
    fn fail(&self, status: u16) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.state.0.store(status, Ordering::Relaxed);
        Poll::Ready(Some(Err(io::Error::other("upload body rejected"))))
    }

    fn too_slow(&self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.start);
        elapsed >= GRACE && self.bytes < MIN_RATE.saturating_mul(elapsed.as_secs())
    }
}

impl HttpBody for Guarded {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if self.state.0.load(Ordering::Relaxed) != 0 {
            return Poll::Ready(None);
        }
        let now = Instant::now();
        if self.reading && now > self.timer.deadline() {
            return self.fail(408);
        }
        if !self.reading {
            let idle = now + IDLE;
            let rate_budget = Duration::from_secs(self.bytes / MIN_RATE + 1).max(GRACE);
            let deadline = self
                .start
                .checked_add(rate_budget)
                .map_or(idle, |rate| rate.min(idle));
            self.timer.as_mut().reset(deadline);
            self.reading = true;
        }
        match Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Pending => {
                if self.timer.as_mut().poll(cx).is_ready() {
                    self.fail(408)
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(_))) => self.fail(400),
            Poll::Ready(frame) => {
                let frame = frame.map(|frame| frame.expect("body error handled"));
                if let Some(data) = frame.as_ref().and_then(Frame::data_ref) {
                    let amount = data.len() as u64;
                    if amount > self.limit - self.bytes {
                        return self.fail(413);
                    }
                    self.bytes += amount;
                    if self.length.is_some_and(|length| self.bytes > length) {
                        return self.fail(400);
                    }
                    if amount != 0 {
                        self.reading = false;
                    }
                }
                if self.too_slow(now) {
                    return self.fail(408);
                }
                if frame.is_none() || self.body.is_end_stream() || self.length == Some(self.bytes) {
                    if self.length.is_some_and(|length| length != self.bytes) {
                        return self.fail(400);
                    }
                    self.state.0.store(COMPLETE, Ordering::Relaxed);
                }
                Poll::Ready(frame.map(Ok))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.state.0.load(Ordering::Relaxed) != 0
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    struct Drip {
        timer: Pin<Box<Sleep>>,
        interval: Duration,
        chunk: Bytes,
        remaining: usize,
    }

    impl HttpBody for Drip {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            if self.timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.remaining -= 1;
            let next = Instant::now() + self.interval;
            self.timer.as_mut().reset(next);
            Poll::Ready(Some(Ok(Frame::data(self.chunk.clone()))))
        }

        fn is_end_stream(&self) -> bool {
            self.remaining == 0
        }
    }

    #[tokio::test(start_paused = true)]
    async fn upload_idle_and_minimum_rate_fail_but_a_fast_stream_can_run_past_sixty_seconds()
    -> anyhow::Result<()> {
        for (interval, size, frames, expected_status, seconds) in [
            (40, 8192, 2, Some(StatusCode::REQUEST_TIMEOUT), 30),
            (5, 1024, 20, Some(StatusCode::REQUEST_TIMEOUT), 30),
            (1, 4096, 70, None, 70),
        ] {
            let interval = Duration::from_secs(interval);
            let start = Instant::now();
            let mut request = Request::new(Body::new(Drip {
                timer: Box::pin(sleep_until(start + interval)),
                interval,
                chunk: Bytes::from(vec![b'x'; size]),
                remaining: frames,
            }));
            let state = protect(&mut request, 8 << 20).unwrap();
            let mut body = request.into_body();
            let mut bytes = 0;
            while let Some(Ok(frame)) = body.frame().await {
                bytes += frame.into_data().unwrap().len();
            }
            assert_eq!(start.elapsed(), Duration::from_secs(seconds));
            assert_eq!(state.error().map(|error| error.status), expected_status);
            assert_eq!(state.complete(), expected_status.is_none());
            if expected_status.is_none() {
                assert_eq!(bytes, size * frames);
                assert!(body.frame().await.is_none());
            }
        }
        Ok(())
    }
}
