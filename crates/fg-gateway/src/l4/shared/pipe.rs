//! Bidirectional TCP relay with half-close, first-data timeout and drain
//! (WP-36); extracted from the TCP forwarder.
#![allow(dead_code)]

use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf, copy_bidirectional},
    time::{sleep, timeout},
};

/// Relay tuning knobs shared by every forwarded connection.
pub struct PipeLimits {
    /// How long the relay waits for the first byte (on the side(s) selected
    /// by [`FirstData`]) before giving up, mirroring the forwarder's
    /// `first_data_timeout_ms`.
    pub first_data_timeout: Duration,
    /// Advisory drain budget for callers: the relay itself returns as soon
    /// as cancellation is observed, leaving how long to keep flushing
    /// in-flight data to the caller (the forwarder wraps each relay in a
    /// connection-lifetime `timeout`).
    pub drain: Duration,
}

/// Which side of the pipe is expected to speak first; `None` means either.
pub enum FirstData {
    /// Either side may speak first (the forwarder's behavior).
    None,
    /// Only the client side is waited on for the first byte.
    Client,
    /// Only the upstream side is waited on for the first byte.
    Upstream,
}

/// Outcome of a completed relay.
pub enum RelayResult {
    /// Both directions finished: each peer half-closed and the shutdown
    /// propagated through the pipe.
    Closed,
    /// No first byte arrived within [`PipeLimits::first_data_timeout`].
    FirstDataTimeout,
    /// Cancellation was observed via the relay's cancel closure.
    Killed,
    /// The relay ended with an I/O error; both streams are returned to the
    /// caller untouched.
    Error(io::Error),
}

/// A pooled connection reference usable by the relay.
pub trait PoolRef: AsyncRead + AsyncWrite + Unpin {
    /// Tears the pooled connection down without a graceful close.
    fn abort(&self);
}

/// How often the cancel closure is polled while relaying.
const KILL_TICK: Duration = Duration::from_millis(100);

/// Relays bytes between `client` and `upstream` until both directions have
/// seen EOF and the shutdowns propagated, mirroring the forwarder's relay:
///
/// - First data: waits for the first byte on the side(s) selected by
///   `first_data` within `limits.first_data_timeout`. EOF counts as data and
///   is relayed so the other peer still sees the close. The byte is buffered
///   and prepended, so nothing read ahead is lost.
/// - Half-close: `copy_bidirectional` semantics propagate each peer's
///   shutdown without closing the opposite direction early.
/// - Cancellation: `cancel` is polled every 100ms; when it turns true the
///   relay returns [`RelayResult::Killed`] promptly, leaving both streams to
///   the caller.
pub async fn relay<R, U>(
    client: &mut R,
    upstream: &mut U,
    limits: PipeLimits,
    first_data: FirstData,
    cancel: impl Fn() -> bool + Send + Sync,
) -> RelayResult
where
    R: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = FirstDataStr::new(client);
    let mut upstream = FirstDataStr::new(upstream);
    tokio::select! {
        biased;
        _ = async {
            loop {
                sleep(KILL_TICK).await;
                if cancel() {
                    break;
                }
            }
        } => RelayResult::Killed,
        result = pipe(&mut client, &mut upstream, limits, first_data) => match result {
            Ok(()) => RelayResult::Closed,
            Err(PhaseError::FirstDataTimeout) => RelayResult::FirstDataTimeout,
            Err(PhaseError::Io(error)) => RelayResult::Error(error),
        },
    }
}

/// [`relay`] with per-direction write counters, mirroring the forwarder's
/// `CountWrites` usage: `client_written` counts bytes written to the client
/// (the forwarder's `bytes_out`) and `upstream_written` bytes written to the
/// upstream (`bytes_in`).
pub async fn relay_counted<R, U>(
    client: &mut R,
    upstream: &mut U,
    limits: PipeLimits,
    first_data: FirstData,
    cancel: impl Fn() -> bool + Send + Sync,
    client_written: &AtomicU64,
    upstream_written: &AtomicU64,
) -> RelayResult
where
    R: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = CountWrites(client, client_written);
    let mut upstream = CountWrites(upstream, upstream_written);
    relay(&mut client, &mut upstream, limits, first_data, cancel).await
}

/// First-data wait followed by the bidirectional copy.
async fn pipe<R, U>(
    client: &mut FirstDataStr<&mut R>,
    upstream: &mut FirstDataStr<&mut U>,
    limits: PipeLimits,
    first_data: FirstData,
) -> Result<(), PhaseError>
where
    R: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let wait = async {
        match first_data {
            FirstData::Client => client.wait_first().await,
            FirstData::Upstream => upstream.wait_first().await,
            FirstData::None => tokio::select! {
                result = client.wait_first() => result,
                result = upstream.wait_first() => result,
            },
        }
    };
    match timeout(limits.first_data_timeout, wait).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(PhaseError::Io(error)),
        Err(_elapsed) => return Err(PhaseError::FirstDataTimeout),
    }
    copy_bidirectional(client, upstream)
        .await
        .map(|_| ())
        .map_err(PhaseError::Io)
}

enum PhaseError {
    FirstDataTimeout,
    Io(io::Error),
}

/// Wraps a stream so a byte captured during the first-data wait is served on
/// subsequent reads before the stream itself (the peek-free replacement for
/// `TcpStream::peek` over generic streams).
struct FirstDataStr<S> {
    inner: S,
    pending: Vec<u8>,
    served: usize,
}

impl<S> FirstDataStr<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            served: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> FirstDataStr<S> {
    /// Waits for the first byte, buffering it for replay. EOF counts as
    /// first data (nothing is buffered; the copy below relays the close).
    async fn wait_first(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            return Ok(());
        }
        let mut scratch = [0u8; 1];
        loop {
            match self.inner.read(&mut scratch).await {
                Ok(0) => return Ok(()),
                Ok(read) => {
                    self.pending.extend_from_slice(&scratch[..read]);
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstDataStr<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.served < self.pending.len() {
            let chunk = &self.pending[self.served..];
            let replayed = chunk.len().min(buffer.remaining());
            buffer.put_slice(&chunk[..replayed]);
            self.served += replayed;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstDataStr<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Counts bytes written through the wrapper, mirroring the forwarder's
/// `CountWrites` stat accounting.
pub struct CountWrites<'a, S>(&'a mut S, &'a AtomicU64);

impl<S: AsyncRead + Unpin> AsyncRead for CountWrites<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountWrites<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.0).poll_write(cx, buffer);
        if let Poll::Ready(Ok(written)) = result {
            self.1.fetch_add(written as u64, Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering::Relaxed},
        },
        time::Instant,
    };

    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    use super::*;

    /// A real loopback socket pair: the first socket is what gets relayed,
    /// the second is its peer the test drives directly.
    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        (client, peer)
    }

    #[tokio::test]
    async fn relay_preserves_half_close() {
        let (mut client, mut client_peer) = socket_pair().await;
        let (mut upstream, mut upstream_peer) = socket_pair().await;
        let task = tokio::spawn(async move {
            relay(
                &mut client,
                &mut upstream,
                PipeLimits {
                    first_data_timeout: Duration::from_secs(5),
                    drain: Duration::ZERO,
                },
                FirstData::None,
                || false,
            )
            .await
        });

        // The client speaks, then half-closes its write side.
        client_peer.write_all(b"ping").await.unwrap();
        client_peer.shutdown().await.unwrap();

        // The upstream sees the data followed by the client's EOF.
        let mut received = Vec::new();
        upstream_peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"ping");

        // The upstream can still answer after the client's EOF.
        upstream_peer.write_all(b"pong").await.unwrap();
        upstream_peer.shutdown().await.unwrap();

        // The client receives "pong" before its read side closes.
        let mut answered = Vec::new();
        client_peer.read_to_end(&mut answered).await.unwrap();
        assert_eq!(answered, b"pong");

        assert!(matches!(task.await.unwrap(), RelayResult::Closed));
    }

    #[tokio::test]
    async fn relay_first_data_timeout() {
        let (mut client, mut upstream) = socket_pair().await;
        let started = Instant::now();
        let result = relay(
            &mut client,
            &mut upstream,
            PipeLimits {
                first_data_timeout: Duration::from_millis(200),
                drain: Duration::ZERO,
            },
            FirstData::None,
            || false,
        )
        .await;
        assert!(matches!(result, RelayResult::FirstDataTimeout));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn relay_first_data_timer_starts_after_outbound() {
        // The upstream only exists after a simulated 100ms outbound delay,
        // so the first-data timer must start when the relay starts (after
        // connect), not before.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let acceptor = tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            let (socket, _) = listener.accept().await.unwrap();
            socket
        });

        let (mut client, mut client_peer) = socket_pair().await;
        sleep(Duration::from_millis(100)).await;
        let mut upstream = TcpStream::connect(upstream_addr).await.unwrap();
        let mut upstream_peer = acceptor.await.unwrap();

        // The upstream echoes everything so both directions stay observable.
        let echo = tokio::spawn(async move {
            let mut scratch = [0u8; 128];
            loop {
                match upstream_peer.read(&mut scratch).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if upstream_peer.write_all(&scratch[..read]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let task = tokio::spawn(async move {
            relay(
                &mut client,
                &mut upstream,
                PipeLimits {
                    first_data_timeout: Duration::from_millis(300),
                    drain: Duration::ZERO,
                },
                FirstData::Client,
                || false,
            )
            .await
        });

        // The client speaks right away, well within the first-data window.
        client_peer.write_all(b"ping").await.unwrap();
        let mut first = [0u8; 4];
        client_peer.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"ping");

        // After the first byte the limit is gone: staying silent longer than
        // the whole first-data timeout must not kill the relay.
        sleep(Duration::from_millis(400)).await;
        client_peer.write_all(b"second").await.unwrap();
        let mut second = [0u8; 6];
        client_peer.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"second");

        // Wind down; the relay ends normally instead of timing out.
        client_peer.shutdown().await.unwrap();
        assert!(matches!(task.await.unwrap(), RelayResult::Closed));
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn relay_drains_on_shutdown() {
        let (mut client, mut upstream) = socket_pair().await;
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move {
            relay(
                &mut client,
                &mut upstream,
                PipeLimits {
                    first_data_timeout: Duration::from_secs(30),
                    drain: Duration::ZERO,
                },
                FirstData::None,
                move || flag.load(Relaxed),
            )
            .await
        });

        // The streams stay silent; shutdown must still be noticed promptly.
        sleep(Duration::from_millis(150)).await;
        shutdown.store(true, Relaxed);
        let result = timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, RelayResult::Killed));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
