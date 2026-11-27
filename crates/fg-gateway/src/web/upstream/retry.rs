//! Dial-failure retry (WP-23 step 5): a request tries at most
//! [`MAX_ATTEMPTS`] backends and only switches on connection failures —
//! nothing has been sent yet, so re-issuing is safe even for POST. Once
//! the request body has been read (hence sent), never retry.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::SystemTime;

use super::{Backend, Pool, MAX_ATTEMPTS};

/// One request's backend attempts. `current` is the in-flight backend;
/// `tried` are the pool indices already attempted this request.
pub struct Attempt {
    pub current: Arc<Backend>,
    tried: Vec<usize>,
    /// Set once the request body has been read upstream; from then on the
    /// request must not be resent to another backend.
    pub body_read: Arc<AtomicBool>,
}

impl Attempt {
    /// Picks the first backend for a request.
    pub fn begin(pool: &Pool, client: std::net::IpAddr, now: SystemTime) -> Self {
        let candidates = pool.candidates(now);
        let current = pool.pick(&candidates, client);
        Self {
            current,
            tried: Vec::with_capacity(MAX_ATTEMPTS),
            body_read: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Records `current` as tried (after a dial failure).
    pub fn mark_tried(&mut self, pool: &Pool) {
        if let Some(index) = pool.position(&self.current)
            && !self.tried.contains(&index)
        {
            self.tried.push(index);
        }
    }

    /// The next backend to try: candidate order first, then the remaining
    /// available backups, skipping what was already tried (the caller
    /// marks the failed `current` via [`Attempt::mark_tried`] first).
    /// `None` once the attempt budget is spent, nothing untried remains,
    /// or the body was already read (no resend after bytes went out).
    pub fn next(&self, pool: &Pool, _client: std::net::IpAddr, now: SystemTime) -> Option<Arc<Backend>> {
        if self.body_read.load(Relaxed) || self.tried.len() >= MAX_ATTEMPTS {
            return None;
        }
        // `candidates()` collapses to primaries while any of them is
        // available, so the still-usable backups are appended by hand
        // (deduped — they already lead the list when primaries ran out).
        let mut order: Vec<&Arc<Backend>> = pool.candidates(now);
        for backend in pool.backends.iter().filter(|b| pool.available(b, now)) {
            if !order
                .iter()
                .any(|candidate| std::ptr::eq(candidate.as_ref(), backend.as_ref()))
            {
                order.push(backend);
            }
        }
        order
            .into_iter()
            .find(|backend| {
                pool.position(backend)
                    .is_none_or(|index| !self.tried.contains(&index))
            })
            .cloned()
    }
}

/// Classifies a dial error as retryable: connection refused, unreachable
/// or connect timeout. Errors after the connection was established are not
/// dial failures and never trigger a backend switch.
pub fn is_dial_failure(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkDown
    )
}

/// Walks an arbitrary error's source chain looking for an io::Error that
/// is a dial failure (hyper wraps connector errors).
pub fn is_dial_failure_err(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(io_error) = error.downcast_ref::<std::io::Error>()
            && is_dial_failure(io_error)
        {
            return true;
        }
        source = error.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use std::io::{self, ErrorKind};
    use std::net::IpAddr;

    use super::*;
    use crate::web::upstream::{Policy, parse_target};

    fn compile_pool(targets: &[&str]) -> Pool {
        let targets = targets
            .iter()
            .map(|line| parse_target(line).expect("valid target"))
            .collect();
        Pool::compile(targets, Policy::default(), None).expect("valid pool")
    }

    fn client() -> IpAddr {
        "192.0.2.7".parse().expect("valid address")
    }

    #[test]
    fn dial_failure_switches_backend_up_to_three() {
        let pool = compile_pool(&["http://10.0.0.1:1", "http://10.0.0.2:2", "http://10.0.0.3:3"]);
        let now = SystemTime::UNIX_EPOCH;
        let client = client();

        let mut attempt = Attempt::begin(&pool, client, now);
        let mut seen = vec![Arc::clone(&attempt.current)];
        attempt.mark_tried(&pool);

        for expected in 1..MAX_ATTEMPTS {
            let next = attempt
                .next(&pool, client, now)
                .unwrap_or_else(|| panic!("attempt {expected} must still have budget"));
            assert!(
                seen.iter().all(|tried| !std::ptr::eq(tried.as_ref(), next.as_ref())),
                "attempt {expected} must switch to a fresh backend"
            );
            seen.push(Arc::clone(&next));
            attempt.current = next;
            attempt.mark_tried(&pool);
        }
        assert!(
            attempt.next(&pool, client, now).is_none(),
            "after {MAX_ATTEMPTS} tries the budget is spent"
        );
    }

    #[test]
    fn retry_falls_back_to_backup() {
        let pool = compile_pool(&["http://10.0.0.1:1", "http://10.0.0.2:2 backup"]);
        let now = SystemTime::UNIX_EPOCH;
        let client = client();

        let mut attempt = Attempt::begin(&pool, client, now);
        let primary = Arc::clone(&attempt.current);
        attempt.mark_tried(&pool);

        let backup = attempt.next(&pool, client, now).expect("backup takes over");
        assert!(backup.target.backup, "the fallback must be the backup backend");
        assert!(!std::ptr::eq(primary.as_ref(), backup.as_ref()));
        assert!(std::ptr::eq(backup.as_ref(), pool.get(1).as_ref()));

        attempt.current = backup;
        attempt.mark_tried(&pool);
        assert!(attempt.next(&pool, client, now).is_none(), "both backends tried");
    }

    #[test]
    fn no_retry_after_body_read() {
        let pool = compile_pool(&["http://10.0.0.1:1", "http://10.0.0.2:2"]);
        let now = SystemTime::UNIX_EPOCH;
        let client = client();

        let mut attempt = Attempt::begin(&pool, client, now);
        attempt.mark_tried(&pool);
        // An untried backend remains, but the request already went out.
        attempt.body_read.store(true, Relaxed);
        assert!(attempt.next(&pool, client, now).is_none());
        attempt.mark_tried(&pool);
        assert!(attempt.next(&pool, client, now).is_none());
    }

    #[test]
    fn is_dial_failure_classifies_connect_errors() {
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkDown,
        ] {
            assert!(is_dial_failure(&io::Error::from(kind)), "{kind:?} must retry");
        }
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::UnexpectedEof,
            ErrorKind::BrokenPipe,
        ] {
            assert!(!is_dial_failure(&io::Error::from(kind)), "{kind:?} must not retry");
        }
    }

    #[derive(Debug)]
    struct TestError {
        source: io::Error,
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "wrapped dial error")
        }
    }

    impl std::error::Error for TestError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    #[test]
    fn is_dial_failure_err_walks_the_source_chain() {
        let refused = TestError {
            source: io::Error::from(ErrorKind::ConnectionRefused),
        };
        assert!(is_dial_failure_err(&refused));

        let denied = TestError {
            source: io::Error::from(ErrorKind::PermissionDenied),
        };
        assert!(!is_dial_failure_err(&denied));

        // A bare io error is inspected without needing a wrapper.
        assert!(is_dial_failure_err(&io::Error::from(ErrorKind::TimedOut)));
    }
}
