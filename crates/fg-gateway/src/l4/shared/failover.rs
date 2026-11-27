//! Sequential multi-target dialing (WP-36): try targets in order, moving
//! to the next on refusal/unreachability/timeout before any byte is
//! forwarded; report the last error when everything fails.
#![allow(dead_code)]

use std::{io, net::SocketAddr, time::Duration};

use tokio::net::TcpStream;

/// Dials the first target that accepts within `timeout`. No data has been
/// exchanged on the returned stream; TCP_NODELAY is set, mirroring the
/// forwarder. When every target fails, the last error is reported.
pub async fn dial_targets(
    targets: &[SocketAddr],
    timeout: Duration,
) -> Result<TcpStream, io::Error> {
    let mut last_error = None;
    for &target in targets {
        match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(_elapsed) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connecting to {target} timed out"),
                ));
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no TCP forward targets")))
}

#[cfg(test)]
mod tests {
    use tokio::{net::TcpListener, time::timeout};

    use super::*;

    const PER_TARGET: Duration = Duration::from_millis(300);

    /// Binds a port and immediately releases it, so connecting to the
    /// returned address is refused.
    async fn dead_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn failover_tries_in_order_before_any_data() {
        let refused = dead_addr().await;
        // Second target accepts the dial but stays silent: a dial counts as
        // success the moment the connection is established, so failover must
        // stop here rather than skip to a responsive third target.
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        // Third target would echo; the dial must never reach it.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();

        let stream = dial_targets(&[refused, silent_addr, echo_addr], PER_TARGET)
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), silent_addr);

        // No byte was exchanged, and the third target was never dialed.
        assert!(
            timeout(Duration::from_millis(100), echo.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn dial_targets_reports_last_target_error() {
        let first = dead_addr().await;
        let last = dead_addr().await;
        let error = dial_targets(&[first, last], PER_TARGET).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }
}
