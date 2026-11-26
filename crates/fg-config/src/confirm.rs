//! Save confirmation: after an administrator saves a configuration that
//! could cut off their own access, the change must be confirmed over a new
//! connection within a window, or it is rolled back to the archived
//! pre-save contents. The state file uses the upstream field names so the
//! same on-disk shape round-trips.

use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// The status file; it has no `.json` suffix so backups, history and the
/// declarative directory never pick it up.
const STATE_FILE: &str = "pending-confirm.state";
/// Confirmation window when the caller passes zero.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);
/// Minimum remaining window after a restart.
pub const BOOT_GRACE: Duration = Duration::from_secs(45);
/// Registrations that survived this many boots roll back unconditionally.
pub const MAX_BOOTS: u32 = 3;

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_time(value: &SystemTime) -> bool {
    *value == SystemTime::UNIX_EPOCH
}

fn default_applied() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

/// The persisted pending state; field names match the upstream file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingConfirm {
    pub id: String,
    pub created: SystemTime,
    pub deadline: SystemTime,
    /// The registered window in seconds; restarts re-time from it.
    pub timeout: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub wait_restart: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub rollback: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub hold: bool,
    #[serde(default = "default_applied", skip_serializing_if = "is_zero_time")]
    pub applied: SystemTime,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(default)]
    pub boots: u32,
    /// Configuration name → pre-save contents; `None` means the file did
    /// not exist before.
    pub files: BTreeMap<String, Option<String>>,
}

impl PendingConfirm {
    /// The deadline a restart should use: at most `BOOT_GRACE` away, or the
    /// re-derived original window when that leaves more room.
    pub fn resumed_deadline(&self, now: SystemTime) -> SystemTime {
        let grace = now + BOOT_GRACE;
        let timeout = now + Duration::from_secs(self.timeout);
        grace.min(timeout)
    }

    /// Whether the deadline has passed.
    pub fn expired(&self, now: SystemTime) -> bool {
        now >= self.deadline
    }
}

/// The result of a confirmation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmResult {
    Confirmed,
    None,
    WaitRestart,
    RollingBack,
    Hold,
    Applying,
}

impl ConfirmResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::None => "none",
            Self::WaitRestart => "waitRestart",
            Self::RollingBack => "rollingBack",
            Self::Hold => "hold",
            Self::Applying => "applying",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackReason {
    Timeout,
    Manual,
    Boots,
}

impl RollbackReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Manual => "manual",
            Self::Boots => "boots",
        }
    }
}

/// The startup verdict: files to restore (or delete for `None`), plus why.
pub struct Recovery {
    /// Configuration name → pre-save contents; `None` deletes the file.
    pub restore: BTreeMap<String, Option<String>>,
    pub rolled_back: Vec<String>,
    pub reason: Option<RollbackReason>,
    pub errors: Vec<String>,
    /// A pending state worth resuming after a successful start.
    pub resume: Option<PendingConfirm>,
}

/// Reads the pending state; a missing or unreadable file is no pending
/// change (the workflow never blocks startup on a corrupt file).
pub fn read_state(dir: &Path) -> Option<PendingConfirm> {
    let bytes = fs::read(dir.join(STATE_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Writes the state atomically through the same directory as the store's
/// saves, keeping the file out of `.json` globbing.
pub fn write_state(dir: &Path, state: &PendingConfirm) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state)?;
    let path = dir.join(STATE_FILE);
    let temp = dir.join(format!("{STATE_FILE}.tmp"));
    fs::write(&temp, bytes).with_context(|| format!("write {}", temp.display()))?;
    fs::rename(&temp, &path).with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

fn remove_state(dir: &Path) {
    let _ = fs::remove_file(dir.join(STATE_FILE));
}

/// Runs at startup before any configuration is loaded. `rollback` set, an
/// expired deadline, or `boots` reaching the cap each restore the archived
/// contents; otherwise the state resumes with a fresh boot counted.
pub fn recover(dir: &Path, now: SystemTime) -> Result<Recovery> {
    let Some(mut pending) = read_state(dir) else {
        return Ok(Recovery {
            restore: BTreeMap::new(),
            rolled_back: Vec::new(),
            reason: None,
            errors: Vec::new(),
            resume: None,
        });
    };
    let reason = if pending.rollback || pending.expired(now) {
        Some(RollbackReason::Timeout)
    } else if pending.boots + 1 >= MAX_BOOTS {
        Some(RollbackReason::Boots)
    } else {
        None
    };
    let Some(reason) = reason else {
        pending.boots += 1;
        pending.deadline = pending.resumed_deadline(now);
        write_state(dir, &pending)?;
        return Ok(Recovery {
            restore: BTreeMap::new(),
            rolled_back: Vec::new(),
            reason: None,
            errors: Vec::new(),
            resume: Some(pending),
        });
    };
    let restore = pending.files.clone();
    let mut rolled_back = Vec::new();
    for (name, contents) in &restore {
        match contents {
            Some(contents) => {
                fs::write(dir.join(format!("{name}.json")), contents)
                    .with_context(|| format!("restore configuration {name}"))?;
            }
            None => {
                let _ = fs::remove_file(dir.join(format!("{name}.json")));
            }
        }
        rolled_back.push(name.clone());
    }
    if rolled_back.len() != restore.len() {
        // Leave the state file in place so the next boot retries; the
        // caller reports startup failure with the partial list.
        bail!(
            "回滚部分完成：已恢复 [{}]，未恢复 [{}]",
            rolled_back.join(", "),
            restore
                .keys()
                .filter(|name| !rolled_back.contains(name))
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    remove_state(dir);
    Ok(Recovery {
        restore: BTreeMap::new(),
        rolled_back,
        reason: Some(reason),
        errors: pending.errors.clone(),
        resume: None,
    })
}

/// Discards the pending change: the caller restored configuration from a
/// backup or history version, which is an explicit user choice.
pub fn discard(dir: &Path) {
    remove_state(dir);
}

/// Removes the state file, used after a successful confirmation.
pub fn confirm(dir: &Path) -> ConfirmResult {
    if read_state(dir).is_some() {
        remove_state(dir);
        ConfirmResult::Confirmed
    } else {
        ConfirmResult::None
    }
}

/// Marks the state for rollback on the next start; `errors` records what
/// went wrong while the change was live.
pub fn request_rollback(dir: &Path, errors: Vec<String>) -> Result<()> {
    let Some(mut pending) = read_state(dir) else {
        bail!("没有待确认的变更");
    };
    pending.rollback = true;
    pending.errors = errors;
    write_state(dir, &pending)
}

/// Registers a new pending change or merges into the running one; merging
/// keeps the first pre-save contents and restarts the window.
pub fn begin(
    dir: &Path,
    files: BTreeMap<String, Option<String>>,
    timeout: Duration,
    now: SystemTime,
) -> Result<PendingConfirm> {
    let timeout = if timeout.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        timeout
    };
    let pending = match read_state(dir) {
        Some(existing) if !existing.rollback => {
            // First pre-save contents win; later saves only re-time.
            let mut merged = existing;
            for (name, contents) in files {
                merged.files.entry(name).or_insert(contents);
            }
            merged.timeout = timeout.as_secs();
            merged.deadline = now + timeout;
            merged.applied = now;
            merged.hold = false;
            merged.wait_restart = false;
            merged
        }
        _ => PendingConfirm {
            id: format!(
                "{:016x}",
                now.duration_since(SystemTime::UNIX_EPOCH)?.as_nanos()
            ),
            created: now,
            deadline: now + timeout,
            timeout: timeout.as_secs(),
            wait_restart: false,
            rollback: false,
            hold: false,
            applied: now,
            errors: Vec::new(),
            boots: 0,
            files,
        },
    };
    write_state(dir, &pending)?;
    Ok(pending)
}

/// Registers the restart-required settings path: `wait_restart` starts the
/// window on the next boot.
pub fn begin_wait_restart(
    dir: &Path,
    files: BTreeMap<String, Option<String>>,
    timeout: Duration,
    now: SystemTime,
) -> Result<()> {
    let timeout = if timeout.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        timeout
    };
    let pending = PendingConfirm {
        id: format!(
            "{:016x}",
            now.duration_since(SystemTime::UNIX_EPOCH)?.as_nanos()
        ),
        created: now,
        deadline: now,
        timeout: timeout.as_secs(),
        wait_restart: true,
        rollback: false,
        hold: false,
        applied: SystemTime::UNIX_EPOCH,
        errors: Vec::new(),
        boots: 0,
        files,
    };
    write_state(dir, &pending)
}

/// Starts the window for a `wait_restart` registration at boot.
pub fn start_wait_restart(dir: &Path, now: SystemTime) -> Option<PendingConfirm> {
    let mut pending = read_state(dir)?;
    if !pending.wait_restart || pending.rollback {
        return None;
    }
    pending.wait_restart = false;
    pending.applied = now;
    pending.deadline = pending.resumed_deadline(now);
    pending.boots += 1;
    write_state(dir, &pending).ok()?;
    Some(pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn files() -> BTreeMap<String, Option<String>> {
        BTreeMap::from([("ddns".to_owned(), Some("{\"previous\":true}\n".to_owned()))])
    }

    #[test]
    fn state_file_roundtrip_matches_upstream_shape() {
        let dir = tempfile::tempdir().unwrap();
        begin(dir.path(), files(), DEFAULT_TIMEOUT, now()).unwrap();
        let raw = std::fs::read_to_string(dir.path().join(STATE_FILE)).unwrap();
        assert!(raw.contains("\"id\""));
        assert!(raw.contains("\"created\""));
        assert!(raw.contains("\"deadline\""));
        assert!(raw.contains("\"timeout\""));
        assert!(raw.contains("\"files\""));
        // Omitted zero fields.
        assert!(!raw.contains("waitRestart"));
        assert!(!raw.contains("rollback"));
        assert!(!raw.contains("\"hold\""));
        let pending = read_state(dir.path()).unwrap();
        assert_eq!(pending.boots, 0);
        assert_eq!(pending.files, files());
    }

    #[test]
    fn begin_merges_and_retimes_keeping_first_contents() {
        let dir = tempfile::tempdir().unwrap();
        begin(dir.path(), files(), DEFAULT_TIMEOUT, now()).unwrap();
        let later = now() + Duration::from_secs(30);
        let second = BTreeMap::from([
            ("ddns".to_owned(), Some("{\"changed\":1}".to_owned())),
            ("extra".to_owned(), None),
        ]);
        begin(dir.path(), second, Duration::from_secs(300), later).unwrap();
        let pending = read_state(dir.path()).unwrap();
        // First pre-save contents win.
        assert_eq!(
            pending.files["ddns"].as_deref(),
            Some("{\"previous\":true}\n")
        );
        assert_eq!(pending.files.get("extra"), Some(&None));
        assert_eq!(pending.deadline, later + Duration::from_secs(300));
    }

    #[test]
    fn recover_restores_files_for_rollback_flag_and_expiry() {
        for prepare in [
            |dir: &Path, at: SystemTime| {
                let mut pending = begin(dir, files(), DEFAULT_TIMEOUT, at).unwrap();
                pending.rollback = true;
                write_state(dir, &pending).unwrap();
            },
            |dir: &Path, at: SystemTime| {
                // Expired: deadline in the past.
                let mut pending = begin(dir, files(), DEFAULT_TIMEOUT, at).unwrap();
                pending.deadline = at - Duration::from_secs(1);
                write_state(dir, &pending).unwrap();
            },
        ] {
            let dir = tempfile::tempdir().unwrap();
            let contents = "{\"previous\":true}\n";
            std::fs::write(dir.path().join("ddns.json"), "{\"live\":1}").unwrap();
            prepare(dir.path(), now());
            let recovery = recover(dir.path(), now()).unwrap();
            assert_eq!(recovery.rolled_back, ["ddns"]);
            assert_eq!(
                std::fs::read_to_string(dir.path().join("ddns.json")).unwrap(),
                contents
            );
            assert!(
                read_state(dir.path()).is_none(),
                "state removed after rollback"
            );
            assert_eq!(recovery.reason, Some(RollbackReason::Timeout));
        }
    }

    #[test]
    fn recover_rolls_back_after_three_boots() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ddns.json"), "{\"live\":1}").unwrap();
        begin(dir.path(), files(), DEFAULT_TIMEOUT, now()).unwrap();
        for _ in 0..2 {
            let recovery = recover(dir.path(), now()).unwrap();
            assert!(recovery.resume.is_some(), "still waiting");
        }
        assert_eq!(read_state(dir.path()).unwrap().boots, 2);
        let recovery = recover(dir.path(), now()).unwrap();
        assert_eq!(recovery.reason, Some(RollbackReason::Boots));
        assert_eq!(recovery.rolled_back, ["ddns"]);
    }

    #[test]
    fn recover_keeps_the_boot_grace_floor() {
        let dir = tempfile::tempdir().unwrap();
        let mut pending = begin(dir.path(), files(), DEFAULT_TIMEOUT, now()).unwrap();
        // Nearly expired: a restart must not resume an already-dead timer.
        pending.deadline = now() + Duration::from_secs(10);
        write_state(dir.path(), &pending).unwrap();
        let recovery = recover(dir.path(), now()).unwrap();
        let resumed = recovery.resume.unwrap();
        assert_eq!(resumed.deadline, now() + BOOT_GRACE);
    }

    #[test]
    fn wait_restart_starts_on_the_next_boot() {
        let dir = tempfile::tempdir().unwrap();
        begin_wait_restart(dir.path(), files(), DEFAULT_TIMEOUT, now()).unwrap();
        let at_boot = now() + Duration::from_secs(120);
        let started = start_wait_restart(dir.path(), at_boot).unwrap();
        assert_eq!(started.applied, at_boot);
        assert!(!started.wait_restart);
        // A plain boot without the flag resumes nothing extra.
        assert!(start_wait_restart(dir.path(), at_boot).is_none());
    }

    #[test]
    fn discard_removes_the_state() {
        let dir = tempfile::tempdir().unwrap();
        begin(dir.path(), files(), DEFAULT_TIMEOUT, now()).unwrap();
        discard(dir.path());
        assert!(read_state(dir.path()).is_none());
        // Confirming after discard reports none.
        assert_eq!(confirm(dir.path()), ConfirmResult::None);
    }

    #[test]
    fn rollback_request_requires_a_pending_state() {
        let dir = tempfile::tempdir().unwrap();
        assert!(request_rollback(dir.path(), vec![]).is_err());
        begin(dir.path(), files(), DEFAULT_TIMEOUT, now()).unwrap();
        request_rollback(dir.path(), vec!["listen failed".to_owned()]).unwrap();
        let pending = read_state(dir.path()).unwrap();
        assert!(pending.rollback);
        assert_eq!(pending.errors, ["listen failed"]);
    }

    #[test]
    fn failed_partial_rollback_keeps_the_state_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = files();
        files.insert("locked".to_owned(), Some("old".to_owned()));
        begin(dir.path(), files, DEFAULT_TIMEOUT, now()).unwrap();
        let mut pending = read_state(dir.path()).unwrap();
        pending.rollback = true;
        write_state(dir.path(), &pending).unwrap();
        // Make the second restore fail: the target path is a directory.
        std::fs::create_dir(dir.path().join("locked.json")).unwrap();
        assert!(recover(dir.path(), now()).is_err());
        assert!(read_state(dir.path()).is_some(), "state survives for retry");
    }
}
