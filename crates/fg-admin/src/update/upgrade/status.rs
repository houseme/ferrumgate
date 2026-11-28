//! Upgrade state machine, progress tracking, single-flight lock, and
//! cooperative cancellation.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::update::rfc3339;

/// Phase of an ongoing or finished upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UpgradeState {
    Checking,
    Downloading,
    Verifying,
    Installing,
    Restarting,
    Failed,
    Canceled,
}

/// Progress snapshot served by `GET /api/system/upgrade/status`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<UpgradeState>,
    #[serde(default)]
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default)]
    pub downloaded: u64,
    #[serde(default)]
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    #[schemars(with = "Option<String>")]
    pub started_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub unsigned: bool,
}

/// Outcome of calling [`UpgradeTracker::cancel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// Cancellation signal delivered before the install phase began.
    Canceled,
    /// Upgrade already entered `Installing` or `Restarting` (HTTP 409).
    TooLate,
    /// No upgrade is currently running (HTTP 409).
    NotRunning,
}

struct TrackerInner {
    status: UpgradeStatus,
    cancel_tx: Option<watch::Sender<bool>>,
    canceled: bool,
}

/// Thread-safe single-flight upgrade state tracker.
///
/// The upgrade lock stays held once [`UpgradeState::Restarting`] is reached so
/// another upgrade cannot run while the old process is waiting to restart.
pub struct UpgradeTracker {
    active: AtomicBool,
    inner: Mutex<TrackerInner>,
}

impl Default for UpgradeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeTracker {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            inner: Mutex::new(TrackerInner {
                status: UpgradeStatus::default(),
                cancel_tx: None,
                canceled: false,
            }),
        }
    }

    /// Acquires the single-flight upgrade lock and initializes status.
    pub fn try_start(
        &self,
        from: String,
        initial_state: UpgradeState,
    ) -> Result<watch::Receiver<bool>, &'static str> {
        if self
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("upgrade already in progress");
        }
        let (tx, rx) = watch::channel(false);
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        inner.status = UpgradeStatus {
            state: Some(initial_state),
            from,
            to: None,
            downloaded: 0,
            total: 0,
            error: None,
            started_at: Some(OffsetDateTime::now_utc()),
            unsigned: false,
        };
        inner.cancel_tx = Some(tx);
        inner.canceled = false;
        Ok(rx)
    }

    pub fn snapshot(&self) -> UpgradeStatus {
        self.inner
            .lock()
            .expect("upgrade tracker lock poisoned")
            .status
            .clone()
    }

    pub fn set_state(&self, state: UpgradeState) {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        if !inner.canceled {
            inner.status.state = Some(state);
        }
    }

    pub fn set_target(&self, to: String, total: u64) {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        inner.status.to = Some(to);
        inner.status.total = total;
    }

    pub fn set_progress(&self, downloaded: u64, total: u64) {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        inner.status.downloaded = downloaded;
        if total > 0 {
            inner.status.total = total;
        }
    }

    pub fn set_unsigned(&self, unsigned: bool) {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        inner.status.unsigned = unsigned;
    }

    /// Atomically checks for pending cancellation and transitions into
    /// [`UpgradeState::Installing`], closing the cancellation window.
    pub fn enter_installing(&self) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        if inner.canceled {
            inner.status.state = Some(UpgradeState::Canceled);
            inner.cancel_tx = None;
            self.active.store(false, Ordering::Release);
            return Err("upgrade canceled");
        }
        inner.status.state = Some(UpgradeState::Installing);
        inner.cancel_tx = None;
        Ok(())
    }

    /// Requests cancellation of an active upgrade.
    pub fn cancel(&self) -> CancelOutcome {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        match inner.status.state {
            Some(UpgradeState::Checking | UpgradeState::Downloading | UpgradeState::Verifying) => {
                inner.canceled = true;
                inner.status.state = Some(UpgradeState::Canceled);
                if let Some(tx) = inner.cancel_tx.take() {
                    let _ = tx.send(true);
                }
                CancelOutcome::Canceled
            }
            Some(UpgradeState::Installing | UpgradeState::Restarting) => CancelOutcome::TooLate,
            None | Some(UpgradeState::Failed | UpgradeState::Canceled) => CancelOutcome::NotRunning,
        }
    }

    /// Marks the upgrade as finished and awaiting process restart.
    ///
    /// Deliberately keeps `active == true` until the process exits/restarts.
    pub fn finish_restarting(&self, version: Option<String>) {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        if let Some(version) = version
            && !version.is_empty()
        {
            inner.status.to = Some(version);
        }
        inner.status.state = Some(UpgradeState::Restarting);
        inner.status.error = None;
        inner.cancel_tx = None;
    }

    /// Marks the upgrade as canceled and releases the upgrade lock.
    pub fn finish_canceled(&self) {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        inner.canceled = true;
        inner.status.state = Some(UpgradeState::Canceled);
        inner.status.error = None;
        inner.cancel_tx = None;
        self.active.store(false, Ordering::Release);
    }

    /// Records failure (unless already canceled) and releases the upgrade lock.
    pub fn fail(&self, message: String) {
        let mut inner = self.inner.lock().expect("upgrade tracker lock poisoned");
        if !inner.canceled {
            inner.status.state = Some(UpgradeState::Failed);
            inner.status.error = Some(message);
        }
        inner.cancel_tx = None;
        self.active.store(false, Ordering::Release);
    }
}
