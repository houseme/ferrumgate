//! Periodic and on-demand update checker with single-flight deduplication,
//! 30-second manual throttle, request-lifecycle decoupling, response size caps,
//! and EventBus notification publishing.

use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use fg_core::events::{Event, EventBus, Kind};
use time::OffsetDateTime;
use tokio::sync::watch;

use super::{
    advisories::{
        DEFAULT_REPO_BASE, GhAdvisory, GhRelease, parse_advisories_for_repo,
        parse_releases_for_repo,
    },
    cache::{
        PendingNotification, UpdateCache, UpdateView, compute_view, load_cache, next_check,
        pending_notifications, save_cache,
    },
    programs::{PROGRAM_CHECK_TIMEOUT, ProgramChecker, check_programs},
    upgrade::support::UpgradeSupport,
};

/// Minimum gap between manual update checks (30 seconds).
pub const MANUAL_CHECK_MIN_GAP: Duration = Duration::from_secs(30);

/// Total timeout for a single update check (1 minute).
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum response body size for GitHub releases list (8 MiB).
pub const MAX_RELEASES_BODY: u64 = 8 << 20;

/// Maximum response body size for GitHub security advisories (4 MiB).
pub const MAX_ADVISORIES_BODY: u64 = 4 << 20;

/// Default GitHub REST API base URL for FerrumGate.
pub const DEFAULT_API_BASE: &str = "https://api.github.com/repos/houseme/ferrumgate";

/// Default package name matched against GitHub Security Advisories.
pub const DEFAULT_SELF_PACKAGE: &str = "ferrumgate";

/// Parameters passed to the injectable HTTP fetcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchRequest {
    pub url: String,
    pub max_bytes: u64,
    pub timeout: Duration,
    pub proxy: Option<String>,
    pub restrict_outbound: bool,
}

/// Response returned by the injectable HTTP fetcher.
#[derive(Clone, Debug)]
pub struct FetchResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Boxed future returned by [`FetchFn`].
pub type FetchFuture = Pin<Box<dyn Future<Output = Result<FetchResponse>> + Send>>;

/// Injectable anonymous HTTP GET fetcher.
pub type FetchFn = Arc<dyn Fn(FetchRequest) -> FetchFuture + Send + Sync>;

/// Live subset of global settings read by update checks and online upgrades.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateSettingsSnapshot {
    pub disable_update_check: bool,
    pub update_proxy: String,
    pub restrict_outbound: bool,
}

/// Configuration and dependencies for [`UpdateChecker`].
pub struct UpdateCheckerConfig {
    pub config_dir: PathBuf,
    pub current_version: String,
    pub repo_base: String,
    pub api_base: String,
    pub self_package: String,
    pub settings: Arc<dyn Fn() -> UpdateSettingsSnapshot + Send + Sync>,
    pub self_upgrade: Arc<dyn Fn() -> UpgradeSupport + Send + Sync>,
    pub fetcher: FetchFn,
    pub events: Option<EventBus>,
    pub programs: Vec<ProgramChecker>,
    pub check_timeout: Duration,
    pub program_timeout: Duration,
    pub now_fn: Option<Arc<dyn Fn() -> OffsetDateTime + Send + Sync>>,
}

impl UpdateCheckerConfig {
    pub fn new(
        config_dir: PathBuf,
        current_version: impl Into<String>,
        fetcher: FetchFn,
        self_upgrade: Arc<dyn Fn() -> UpgradeSupport + Send + Sync>,
    ) -> Self {
        Self {
            config_dir,
            current_version: current_version.into(),
            repo_base: DEFAULT_REPO_BASE.to_owned(),
            api_base: DEFAULT_API_BASE.to_owned(),
            self_package: DEFAULT_SELF_PACKAGE.to_owned(),
            settings: Arc::new(UpdateSettingsSnapshot::default),
            self_upgrade,
            fetcher,
            events: None,
            programs: Vec::new(),
            check_timeout: CHECK_TIMEOUT,
            program_timeout: PROGRAM_CHECK_TIMEOUT,
            now_fn: None,
        }
    }
}

struct InFlight {
    rx: watch::Receiver<Option<UpdateView>>,
}

/// Coordinates periodic and manual update checks, caching, deduplication, and
/// notifications.
pub struct UpdateChecker {
    config: UpdateCheckerConfig,
    cache: Mutex<UpdateCache>,
    in_flight: tokio::sync::Mutex<Option<InFlight>>,
}

impl UpdateChecker {
    pub fn new(config: UpdateCheckerConfig) -> Arc<Self> {
        let cache = load_cache(&config.config_dir);
        Arc::new(Self {
            config,
            cache: Mutex::new(cache),
            in_flight: tokio::sync::Mutex::new(None),
        })
    }

    fn now(&self) -> OffsetDateTime {
        match &self.config.now_fn {
            Some(f) => f(),
            None => OffsetDateTime::now_utc(),
        }
    }

    /// Returns the computed update view from cache without making any network
    /// calls. Used by `/api/system/update/state` and read-only callers of
    /// `/api/system/update`.
    pub fn view(&self) -> UpdateView {
        let cache = self
            .cache
            .lock()
            .expect("update cache lock poisoned")
            .clone();
        let settings = (self.config.settings)();
        compute_view(
            &cache,
            &self.config.current_version,
            !settings.disable_update_check,
            (self.config.self_upgrade)(),
        )
    }

    /// Returns a snapshot of the persisted cache.
    pub fn cached(&self) -> UpdateCache {
        self.cache
            .lock()
            .expect("update cache lock poisoned")
            .clone()
    }

    /// Triggers an update check (decoupled from the caller's request lifetime).
    ///
    /// When `manual` is `true`:
    /// - Concurrent calls join the same in-flight check rather than issuing
    ///   duplicate network requests.
    /// - Calls within [`MANUAL_CHECK_MIN_GAP`] (30s) of the last attempt
    ///   (whether it succeeded or failed) return the cached view immediately.
    pub async fn check_now(self: &Arc<Self>, manual: bool) -> UpdateView {
        let mut rx = {
            let mut guard = self.in_flight.lock().await;
            if let Some(flight) = guard.as_ref() {
                flight.rx.clone()
            } else {
                if manual && self.within_manual_throttle() {
                    return self.view();
                }
                let (tx, rx) = watch::channel(None);
                *guard = Some(InFlight { rx: rx.clone() });
                let checker = Arc::clone(self);
                // Detach from caller future so dropping an HTTP request never
                // aborts or marks an in-progress update check as failed.
                tokio::spawn(async move {
                    let (_cancel_tx, cancel_rx) = watch::channel(false);
                    let view = checker.execute_check(cancel_rx).await;
                    let _ = tx.send(Some(view));
                    let mut guard = checker.in_flight.lock().await;
                    *guard = None;
                });
                rx
            }
        };

        loop {
            if let Some(view) = rx.borrow().clone() {
                return view;
            }
            if rx.changed().await.is_err() {
                return self.view();
            }
        }
    }

    /// Runs a single check directly with an explicit cancellation signal.
    ///
    /// If canceled before completion, the failure is NOT recorded in the cache
    /// and existing managed program records are preserved.
    pub async fn run_check_once(self: &Arc<Self>, cancel: watch::Receiver<bool>) -> UpdateView {
        self.execute_check(cancel).await
    }

    /// Background scheduler loop. Sleeps according to [`next_check`], pauses
    /// when `disableUpdateCheck` is set, and wakes whenever `settings_changed`
    /// fires. Exits promptly when `drain` becomes `true`.
    pub async fn run_scheduler(
        self: Arc<Self>,
        mut settings_changed: watch::Receiver<bool>,
        mut drain: watch::Receiver<bool>,
    ) {
        loop {
            if *drain.borrow() {
                return;
            }
            let settings = (self.config.settings)();
            if settings.disable_update_check {
                tokio::select! {
                    biased;
                    _ = drain.changed() => {
                        if *drain.borrow() {
                            return;
                        }
                    }
                    res = settings_changed.changed() => {
                        if res.is_err() {
                            return;
                        }
                    }
                }
                continue;
            }

            let delay = {
                let cache = self.cache.lock().expect("update cache lock poisoned");
                next_check(&cache, self.now())
            };
            tokio::select! {
                biased;
                _ = drain.changed() => {
                    if *drain.borrow() {
                        return;
                    }
                }
                res = settings_changed.changed() => {
                    if res.is_err() {
                        return;
                    }
                    continue;
                }
                _ = tokio::time::sleep(delay) => {}
            }

            if *drain.borrow() || (self.config.settings)().disable_update_check {
                continue;
            }
            let _ = self.execute_check(drain.clone()).await;
        }
    }

    fn within_manual_throttle(&self) -> bool {
        let now = self.now();
        let cache = self.cache.lock().expect("update cache lock poisoned");
        let last = match (cache.checked_at, cache.failed_at) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let Some(last) = last else {
            return false;
        };
        let elapsed = now - last;
        if elapsed.is_negative() {
            return false;
        }
        let elapsed_std = Duration::new(
            elapsed.whole_seconds() as u64,
            elapsed.subsec_nanoseconds() as u32,
        );
        elapsed_std < MANUAL_CHECK_MIN_GAP
    }

    async fn execute_check(&self, mut cancel: watch::Receiver<bool>) -> UpdateView {
        if *cancel.borrow() {
            return self.view();
        }
        let settings = (self.config.settings)();
        let proxy = (!settings.update_proxy.trim().is_empty())
            .then(|| settings.update_proxy.trim().to_owned());
        let restrict_outbound = settings.restrict_outbound;
        let api_base = self.config.api_base.trim_end_matches('/');
        let releases_url = format!("{api_base}/releases?per_page=100");
        let advisories_url = format!("{api_base}/security-advisories?state=published&per_page=100");

        let fetch_future = async {
            let releases_resp = (self.config.fetcher)(FetchRequest {
                url: releases_url,
                max_bytes: MAX_RELEASES_BODY,
                timeout: self.config.check_timeout,
                proxy: proxy.clone(),
                restrict_outbound,
            })
            .await
            .context("fetch releases")?;
            ensure!(
                releases_resp.status == 200,
                "releases endpoint returned HTTP {}",
                releases_resp.status
            );
            ensure!(
                releases_resp.body.len() as u64 <= MAX_RELEASES_BODY,
                "releases response exceeds {} bytes",
                MAX_RELEASES_BODY
            );
            let releases: Vec<GhRelease> =
                serde_json::from_slice(&releases_resp.body).context("parse releases JSON")?;

            let advisories_resp = (self.config.fetcher)(FetchRequest {
                url: advisories_url,
                max_bytes: MAX_ADVISORIES_BODY,
                timeout: self.config.check_timeout,
                proxy,
                restrict_outbound,
            })
            .await
            .context("fetch security advisories")?;
            ensure!(
                advisories_resp.status == 200,
                "security advisories endpoint returned HTTP {}",
                advisories_resp.status
            );
            ensure!(
                advisories_resp.body.len() as u64 <= MAX_ADVISORIES_BODY,
                "security advisories response exceeds {} bytes",
                MAX_ADVISORIES_BODY
            );
            let advisories: Vec<GhAdvisory> = serde_json::from_slice(&advisories_resp.body)
                .context("parse security advisories JSON")?;

            Ok::<_, anyhow::Error>((releases, advisories))
        };

        let fetched = tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_ok() && *cancel.borrow() {
                    return self.view();
                }
                return self.view();
            }
            res = tokio::time::timeout(self.config.check_timeout, fetch_future) => res,
        };

        if *cancel.borrow() {
            return self.view();
        }

        let now = self.now();
        let (releases, advisories) = match fetched {
            Ok(Ok(data)) => data,
            Ok(Err(err)) => {
                self.record_failure(now, err.to_string());
                return self.view();
            }
            Err(_) => {
                self.record_failure(now, "update check timed out".into());
                return self.view();
            }
        };

        let (latest, notes, security_releases) =
            parse_releases_for_repo(&releases, &self.config.repo_base);
        let parsed_advisories = parse_advisories_for_repo(
            &advisories,
            &self.config.self_package,
            &self.config.repo_base,
        );

        let existing_programs = self
            .cache
            .lock()
            .expect("update cache lock poisoned")
            .programs
            .clone();
        let updated_programs = if self.config.programs.is_empty() {
            existing_programs
        } else {
            check_programs(
                &self.config.programs,
                &existing_programs,
                &mut cancel,
                self.config.program_timeout,
                now,
            )
            .await
        };

        if *cancel.borrow() {
            return self.view();
        }

        let self_upgrade = (self.config.self_upgrade)();
        let auto_check = !(self.config.settings)().disable_update_check;

        let (view, pending, snapshot_to_save) = {
            let mut cache = self.cache.lock().expect("update cache lock poisoned");
            cache.checked_at = Some(now);
            cache.error = None;
            cache.latest = latest;
            cache.notes = notes;
            cache.security_releases = security_releases;
            cache.advisories = parsed_advisories;
            cache.programs = updated_programs;

            let view = compute_view(
                &cache,
                &self.config.current_version,
                auto_check,
                self_upgrade,
            );
            let pending = pending_notifications(&cache, &view);
            for item in &pending {
                cache.notified.insert(item.dedup_key(), now);
            }
            (view, pending, cache.clone())
        };

        if let Err(err) = save_cache(&self.config.config_dir, &snapshot_to_save) {
            tracing::warn!(error = %err, "failed to save update cache");
        }

        if let Some(bus) = &self.config.events {
            publish_notifications(bus, &pending);
        }

        view
    }

    fn record_failure(&self, now: OffsetDateTime, message: String) {
        let snapshot = {
            let mut cache = self.cache.lock().expect("update cache lock poisoned");
            cache.failed_at = Some(now);
            cache.error = Some(message);
            cache.clone()
        };
        if let Err(err) = save_cache(&self.config.config_dir, &snapshot) {
            tracing::warn!(error = %err, "failed to save failed update check state");
        }
    }
}

fn publish_notifications(bus: &EventBus, pending: &[PendingNotification]) {
    for item in pending {
        match item {
            PendingNotification::Advisory(adv) => {
                let mut event = Event::new(Kind::SystemSecurity, "update");
                event.args.push(("ghsa", adv.ghsa_id.clone()));
                event.args.push(("summary", adv.summary.clone()));
                event.args.push(("url", adv.url.clone()));
                event.dedup = Some(item.dedup_key());
                bus.publish(event);
            }
            PendingNotification::SecurityRelease(rel) => {
                let mut event = Event::new(Kind::SystemSecurity, "update");
                event.args.push(("version", rel.tag.clone()));
                event.args.push(("url", rel.url.clone()));
                event.dedup = Some(item.dedup_key());
                bus.publish(event);
            }
            PendingNotification::NewVersion(rel) => {
                let mut event = Event::new(Kind::SystemUpdate, "update");
                event.args.push(("version", rel.tag.clone()));
                event.args.push(("url", rel.url.clone()));
                event.dedup = Some(item.dedup_key());
                bus.publish(event);
            }
        }
    }
}
