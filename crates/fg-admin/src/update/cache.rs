//! Update-check cache persistence (`update-check.json`), dynamic view
//! computation against the running version, notification deduplication, and
//! scheduling interval calculation.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    advisories::{ReleaseBrief, SecurityAdvisory, affects},
    rfc3339,
    upgrade::support::UpgradeSupport,
    version::{parse_version, release_base, version_comparable, version_newer},
};

/// Interval between successful automatic update checks (12 hours).
pub const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);

/// Retry delay after a failed automatic update check (1 hour).
pub const CHECK_RETRY: Duration = Duration::from_secs(3600);

/// Initial delay after startup before the first automatic update check (3 minutes).
pub const CHECK_DELAY: Duration = Duration::from_secs(3 * 60);

/// Runtime state file stored in the configuration directory (not tracked in config history).
pub const CACHE_FILE: &str = "update-check.json";

/// Cached upstream version status for a managed third-party program (WP-43).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProgramUpdate {
    #[serde(default)]
    pub current: String,
    #[serde(default)]
    pub latest: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub has_update: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    #[schemars(with = "Option<String>")]
    pub checked_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Raw release/advisory information cached on disk in `update-check.json`.
///
/// Only source data is persisted; whether an update or security issue applies
/// is always recomputed dynamically against the currently running version.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateCache {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    pub checked_at: Option<OffsetDateTime>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    pub failed_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<ReleaseBrief>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub security_releases: Vec<ReleaseBrief>,
    #[serde(default)]
    pub advisories: Vec<SecurityAdvisory>,
    #[serde(default, with = "rfc3339::map")]
    pub notified: HashMap<String, OffsetDateTime>,
    #[serde(default)]
    pub programs: HashMap<String, ProgramUpdate>,
}

/// Computed update status returned by `GET /api/system/update` and
/// `GET /api/system/update/state`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateView {
    pub auto_check: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    #[schemars(with = "Option<String>")]
    pub checked_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    #[schemars(with = "Option<String>")]
    pub failed_at: Option<OffsetDateTime>,
    pub current: String,
    pub latest: String,
    pub url: String,
    pub notes: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    #[schemars(with = "Option<String>")]
    pub published_at: Option<OffsetDateTime>,
    pub has_update: bool,
    pub comparable: bool,
    pub security: bool,
    pub advisories: Vec<SecurityAdvisory>,
    pub security_releases: Vec<ReleaseBrief>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub programs: HashMap<String, ProgramUpdate>,
    pub self_upgrade: UpgradeSupport,
}

/// Notification item that has not yet been emitted for this version/advisory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingNotification {
    Advisory(SecurityAdvisory),
    SecurityRelease(ReleaseBrief),
    NewVersion(ReleaseBrief),
}

impl PendingNotification {
    /// Stable deduplication key stored in [`UpdateCache::notified`].
    pub fn dedup_key(&self) -> String {
        match self {
            Self::Advisory(adv) => format!("advisory:{}", adv.ghsa_id),
            Self::SecurityRelease(rel) => format!("security:{}", rel.tag),
            Self::NewVersion(rel) => format!("version:{}", rel.tag),
        }
    }
}

/// Loads `update-check.json` from `config_dir`. Missing or corrupted files fall
/// back cleanly to an empty [`UpdateCache`].
pub fn load_cache(config_dir: &Path) -> UpdateCache {
    let path = config_dir.join(CACHE_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return UpdateCache::default(),
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "failed to read update cache; starting empty");
            return UpdateCache::default();
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(cache) => cache,
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "corrupted update cache; starting empty");
            UpdateCache::default()
        }
    }
}

/// Atomically persists `update-check.json` directly in `config_dir` without
/// recording configuration history.
pub fn save_cache(config_dir: &Path, cache: &UpdateCache) -> Result<()> {
    fs::create_dir_all(config_dir)
        .with_context(|| format!("create config directory {}", config_dir.display()))?;
    let mut bytes = serde_json::to_vec_pretty(cache).context("serialize update cache")?;
    bytes.push(b'\n');

    let mut temp = tempfile::Builder::new()
        .prefix(".update-check.")
        .suffix(".tmp")
        .tempfile_in(config_dir)
        .context("create temp update cache file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("set update cache file permissions")?;
    }
    temp.as_file_mut()
        .write_all(&bytes)
        .context("write temp update cache")?;
    temp.as_file()
        .sync_all()
        .context("sync temp update cache")?;

    let target = config_dir.join(CACHE_FILE);
    temp.persist(&target)
        .map_err(|err| err.error)
        .with_context(|| format!("replace {}", target.display()))?;
    #[cfg(unix)]
    if let Ok(dir) = File::open(config_dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Dynamically computes the [`UpdateView`] for `current` from cached source data.
pub fn compute_view(
    cache: &UpdateCache,
    current: &str,
    auto_check: bool,
    self_upgrade: UpgradeSupport,
) -> UpdateView {
    let (latest, url, published_at) = match &cache.latest {
        Some(rel) => (rel.tag.clone(), rel.url.clone(), rel.published_at),
        None => (String::new(), String::new(), None),
    };
    let comparable = !latest.is_empty() && version_comparable(&latest, current);
    let has_update = !latest.is_empty() && version_newer(&latest, current);

    let parsed_current = parse_version(release_base(current));
    let advisories: Vec<SecurityAdvisory> = match &parsed_current {
        Some(cur) => cache
            .advisories
            .iter()
            .filter(|adv| affects(adv, cur))
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    let security_releases: Vec<ReleaseBrief> = match &parsed_current {
        Some(_) => cache
            .security_releases
            .iter()
            .filter(|rel| version_newer(&rel.tag, current))
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    let security = !advisories.is_empty() || !security_releases.is_empty();

    UpdateView {
        auto_check,
        checked_at: cache.checked_at,
        error: cache.error.clone(),
        failed_at: cache.failed_at,
        current: current.to_owned(),
        latest,
        url,
        notes: cache.notes.clone(),
        published_at,
        has_update,
        comparable,
        security,
        advisories,
        security_releases,
        programs: cache.programs.clone(),
        self_upgrade,
    }
}

/// Collects notifications that should be emitted for `view` and are not yet
/// recorded in `cache.notified`.
pub fn pending_notifications(cache: &UpdateCache, view: &UpdateView) -> Vec<PendingNotification> {
    let mut pending = Vec::new();
    for adv in &view.advisories {
        let item = PendingNotification::Advisory(adv.clone());
        if !cache.notified.contains_key(&item.dedup_key()) {
            pending.push(item);
        }
    }
    for rel in &view.security_releases {
        let item = PendingNotification::SecurityRelease(rel.clone());
        if !cache.notified.contains_key(&item.dedup_key()) {
            pending.push(item);
        }
    }
    if view.has_update
        && let Some(latest) = &cache.latest
    {
        let item = PendingNotification::NewVersion(latest.clone());
        if !cache.notified.contains_key(&item.dedup_key()) {
            pending.push(item);
        }
    }
    pending
}

/// Computes the duration to wait before the next automatic update check:
/// - Never checked: [`CHECK_DELAY`] (3 minutes)
/// - Last attempt failed: [`CHECK_RETRY`] (1 hour) after `failed_at`
/// - Last attempt succeeded: [`CHECK_INTERVAL`] (12 hours) after `checked_at`
/// - If the system clock moved backwards (`now < ref_time`), clamps wait to at
///   most one interval (`<= CHECK_INTERVAL`).
pub fn next_check(c: &UpdateCache, now: OffsetDateTime) -> Duration {
    let (reference, interval) = match (c.checked_at, c.failed_at) {
        (None, None) => return CHECK_DELAY,
        (None, Some(failed)) => (failed, CHECK_RETRY),
        (Some(checked), None) => (checked, CHECK_INTERVAL),
        (Some(checked), Some(failed)) => {
            if failed >= checked {
                (failed, CHECK_RETRY)
            } else {
                (checked, CHECK_INTERVAL)
            }
        }
    };

    let elapsed = now - reference;
    if elapsed.is_negative() {
        // Clock moved backwards: never wait more than one interval.
        return interval.min(CHECK_INTERVAL);
    }
    let elapsed_std = Duration::new(
        elapsed.whole_seconds() as u64,
        elapsed.subsec_nanoseconds() as u32,
    );
    interval.saturating_sub(elapsed_std).min(CHECK_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::upgrade::support::UpgradeReason;

    fn dummy_support() -> UpgradeSupport {
        UpgradeSupport {
            supported: false,
            reason: Some(UpgradeReason::Os),
            executable: None,
            custom: false,
        }
    }

    #[test]
    fn update_view_computes_security_and_update() {
        let cache = UpdateCache {
            latest: Some(ReleaseBrief {
                tag: "v0.7.0".into(),
                url: "https://github.com/houseme/ferrumgate/releases/tag/v0.7.0".into(),
                notes: String::new(),
                published_at: None,
            }),
            notes: "Release notes".into(),
            security_releases: vec![ReleaseBrief {
                tag: "v0.6.5".into(),
                url: "https://github.com/houseme/ferrumgate/releases/tag/v0.6.5".into(),
                notes: String::new(),
                published_at: None,
            }],
            advisories: vec![SecurityAdvisory {
                ghsa_id: "GHSA-aaaa-bbbb-cccc".into(),
                summary: "Auth bypass".into(),
                severity: Some("high".into()),
                url:
                    "https://github.com/houseme/ferrumgate/security/advisories/GHSA-aaaa-bbbb-cccc"
                        .into(),
                vulnerable_version_range: "< 0.6.5".into(),
                patched_versions: "0.6.5".into(),
                published_at: None,
            }],
            ..Default::default()
        };

        // Running an older version: sees update, advisory, and security release.
        let old_view = compute_view(&cache, "v0.6.4", true, dummy_support());
        assert!(old_view.has_update);
        assert!(old_view.comparable);
        assert!(old_view.security);
        assert_eq!(old_view.advisories.len(), 1);
        assert_eq!(old_view.security_releases.len(), 1);

        // After upgrading to v0.6.5 without re-checking: security flags clear dynamically.
        let patched_view = compute_view(&cache, "v0.6.5", true, dummy_support());
        assert!(patched_view.has_update);
        assert!(patched_view.comparable);
        assert!(!patched_view.security);
        assert!(patched_view.advisories.is_empty());
        assert!(patched_view.security_releases.is_empty());

        // git describe build on v0.7.0 is NOT flagged as behind v0.7.0.
        let describe_view = compute_view(&cache, "v0.7.0-3-gdeadbeef-dirty", true, dummy_support());
        assert!(!describe_view.has_update);
        assert!(describe_view.comparable);
        assert!(!describe_view.security);

        // Unparseable dev version is not comparable.
        let dev_view = compute_view(&cache, "dev", true, dummy_support());
        assert!(!dev_view.has_update);
        assert!(!dev_view.comparable);
        assert!(!dev_view.security);
    }

    #[test]
    fn next_check_schedule() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        // Never checked -> 3m initial delay.
        assert_eq!(next_check(&UpdateCache::default(), now), CHECK_DELAY);

        // Checked 2h ago -> 10h remaining.
        let checked_2h_ago = UpdateCache {
            checked_at: Some(now - time::Duration::hours(2)),
            ..Default::default()
        };
        assert_eq!(
            next_check(&checked_2h_ago, now),
            Duration::from_secs(10 * 3600)
        );

        // Checked 13h ago -> immediate (0).
        let checked_13h_ago = UpdateCache {
            checked_at: Some(now - time::Duration::hours(13)),
            ..Default::default()
        };
        assert_eq!(next_check(&checked_13h_ago, now), Duration::ZERO);

        // Failed 20m ago (more recent than checked_at) -> 40m retry wait.
        let failed_20m_ago = UpdateCache {
            checked_at: Some(now - time::Duration::hours(24)),
            failed_at: Some(now - time::Duration::minutes(20)),
            ..Default::default()
        };
        assert_eq!(
            next_check(&failed_20m_ago, now),
            Duration::from_secs(40 * 60)
        );

        // Clock rolled back 10 days -> clamped to <= CHECK_INTERVAL (12h).
        let clock_rollback = UpdateCache {
            checked_at: Some(now + time::Duration::days(10)),
            ..Default::default()
        };
        assert_eq!(next_check(&clock_rollback, now), CHECK_INTERVAL);

        // Clock rolled back after failure -> clamped to CHECK_RETRY (<= CHECK_INTERVAL).
        let failed_rollback = UpdateCache {
            failed_at: Some(now + time::Duration::days(5)),
            ..Default::default()
        };
        assert_eq!(next_check(&failed_rollback, now), CHECK_RETRY);
    }

    #[test]
    fn corrupted_cache_falls_back_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(CACHE_FILE), b"{not valid json").unwrap();
        let cache = load_cache(dir.path());
        assert_eq!(cache, UpdateCache::default());
    }
}
