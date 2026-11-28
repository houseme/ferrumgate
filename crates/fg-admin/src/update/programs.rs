//! Injectable upstream update checking for managed third-party programs
//! (WP-43: frp, Tailscale, NetBird, cloudflared, File Browser, etc.).

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use anyhow::Result;
use time::OffsetDateTime;
use tokio::sync::watch;

use super::cache::ProgramUpdate;

/// Default per-program upstream check timeout.
pub const PROGRAM_CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// Result reported by a single managed program's upstream version checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramCheckResult {
    pub current: String,
    pub latest: String,
    pub url: String,
    pub has_update: bool,
}

/// Boxed future returned by a [`ProgramChecker`].
pub type ProgramCheckFuture =
    Pin<Box<dyn Future<Output = Result<Option<ProgramCheckResult>>> + Send>>;

/// Injectable checker registered by a managed-program module (WP-43).
///
/// Returning `Ok(None)` indicates the managed program is not installed and any
/// stale cache entry should be removed.
#[derive(Clone)]
pub struct ProgramChecker {
    pub id: String,
    pub check: Arc<dyn Fn() -> ProgramCheckFuture + Send + Sync>,
}

impl ProgramChecker {
    pub fn new<F, Fut>(id: impl Into<String>, f: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<ProgramCheckResult>>> + Send + 'static,
    {
        Self {
            id: id.into(),
            check: Arc::new(move || Box::pin(f())),
        }
    }
}

/// Runs all registered program checkers sequentially with per-program timeout
/// and cooperative cancellation.
///
/// When canceled, any existing cached records in `existing` are preserved
/// intact rather than overwritten with cancellation errors.
pub async fn check_programs(
    checkers: &[ProgramChecker],
    existing: &HashMap<String, ProgramUpdate>,
    cancel: &mut watch::Receiver<bool>,
    per_program_timeout: Duration,
    now: OffsetDateTime,
) -> HashMap<String, ProgramUpdate> {
    let mut updated = existing.clone();

    for checker in checkers {
        if *cancel.borrow() {
            break;
        }
        let outcome = tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_ok() && *cancel.borrow() {
                    break;
                }
                continue;
            }
            res = tokio::time::timeout(per_program_timeout, (checker.check)()) => res,
        };

        if *cancel.borrow() {
            break;
        }

        match outcome {
            Ok(Ok(Some(res))) => {
                updated.insert(
                    checker.id.clone(),
                    ProgramUpdate {
                        current: res.current,
                        latest: res.latest,
                        url: res.url,
                        has_update: res.has_update,
                        checked_at: Some(now),
                        error: None,
                    },
                );
            }
            Ok(Ok(None)) => {
                updated.remove(&checker.id);
            }
            Ok(Err(err)) => {
                let entry = updated.entry(checker.id.clone()).or_default();
                entry.error = Some(err.to_string());
            }
            Err(_) => {
                let entry = updated.entry(checker.id.clone()).or_default();
                entry.error = Some("program update check timed out".into());
            }
        }
    }

    updated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_programs_updates_and_preserves_existing_on_cancel() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut existing = HashMap::new();
        existing.insert(
            "frp".into(),
            ProgramUpdate {
                current: "0.58.0".into(),
                latest: "0.59.0".into(),
                url: "https://example.invalid/frp".into(),
                has_update: true,
                checked_at: Some(now),
                error: None,
            },
        );

        let (tx, mut rx) = watch::channel(false);
        let cancel_trigger = tx.clone();
        let checkers = vec![
            ProgramChecker::new("tailscale", || async {
                Ok(Some(ProgramCheckResult {
                    current: "1.70.0".into(),
                    latest: "1.72.0".into(),
                    url: "https://example.invalid/ts".into(),
                    has_update: true,
                }))
            }),
            ProgramChecker::new("frp", move || {
                let trigger = cancel_trigger.clone();
                async move {
                    let _ = trigger.send(true);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    Ok(None)
                }
            }),
        ];

        let res = check_programs(&checkers, &existing, &mut rx, Duration::from_secs(2), now).await;
        assert_eq!(res["tailscale"].latest, "1.72.0");
        assert!(res["tailscale"].has_update);
        // `frp` was canceled mid-flight so its previous record is preserved.
        assert_eq!(res["frp"].latest, "0.59.0");
        assert!(res["frp"].error.is_none());
    }
}
