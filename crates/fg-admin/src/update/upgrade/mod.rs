//! Online self-upgrade orchestration, binary upload upgrade, and management API
//! routes (`/api/system/update*` and `/api/system/upgrade*`).

pub mod download;
pub mod install;
pub mod status;
pub mod support;

use std::{cmp::Ordering, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::Request,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use tokio::sync::watch;

use self::{
    download::{
        FIRST_SIGNED_RELEASE, MAX_CHECKSUMS_BODY, MAX_SIGNATURE_BODY, MAX_UPGRADE_ARCHIVE,
        SignatureVerifier, checksum_for, extract_binary, verify_release_signature, verify_sha256,
    },
    install::install_binary,
    status::{CancelOutcome, UpgradeState, UpgradeStatus, UpgradeTracker},
    support::{UpgradeSupport, executable_dir_writable},
};
use super::{
    advisories::{GhAsset, GhRelease},
    cache::UpdateView,
    check::{
        DEFAULT_API_BASE, FetchFn, FetchRequest, MAX_RELEASES_BODY, UpdateChecker,
        UpdateSettingsSnapshot,
    },
    version::{compare_version, parse_version, version_newer},
};
use crate::{ApiRouter, ReadOnly, RouteModels};

/// Total deadline for an online upgrade operation (10 minutes).
pub const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

const MULTIPART_HEADER_OVERHEAD: u64 = 1 << 20;

/// Configuration and dependencies for [`UpgradeManager`].
pub struct UpgradeManagerConfig {
    pub current_version: String,
    pub api_base: String,
    pub asset_os: String,
    pub asset_arch: String,
    pub asset_prefixes: Vec<String>,
    pub first_signed_release: String,
    pub support: Arc<dyn Fn() -> UpgradeSupport + Send + Sync>,
    pub settings: Arc<dyn Fn() -> UpdateSettingsSnapshot + Send + Sync>,
    pub fetcher: FetchFn,
    pub verifier: SignatureVerifier,
    pub on_restart: Arc<dyn Fn() + Send + Sync>,
    pub timeout: Duration,
}

impl UpgradeManagerConfig {
    pub fn new(
        current_version: impl Into<String>,
        fetcher: FetchFn,
        support: Arc<dyn Fn() -> UpgradeSupport + Send + Sync>,
        on_restart: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            current_version: current_version.into(),
            api_base: DEFAULT_API_BASE.to_owned(),
            asset_os: std::env::consts::OS.to_owned(),
            asset_arch: canonical_release_arch(std::env::consts::ARCH).to_owned(),
            asset_prefixes: vec!["ferrumgate".into(), "fgate".into(), "gately".into()],
            first_signed_release: FIRST_SIGNED_RELEASE.to_owned(),
            support,
            settings: Arc::new(UpdateSettingsSnapshot::default),
            fetcher,
            verifier: SignatureVerifier::default(),
            on_restart,
            timeout: UPGRADE_TIMEOUT,
        }
    }
}

/// Manages single-flight online upgrades and manual binary upload upgrades.
pub struct UpgradeManager {
    config: UpgradeManagerConfig,
    tracker: UpgradeTracker,
}

impl UpgradeManager {
    pub fn new(config: UpgradeManagerConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            tracker: UpgradeTracker::new(),
        })
    }

    pub fn status(&self) -> UpgradeStatus {
        self.tracker.snapshot()
    }

    pub fn support(&self) -> UpgradeSupport {
        (self.config.support)()
    }

    pub fn cancel(&self) -> CancelOutcome {
        self.tracker.cancel()
    }

    /// Starts an online upgrade asynchronously in a detached task and returns
    /// the initial [`UpgradeStatus`].
    pub fn start_online(
        self: &Arc<Self>,
    ) -> std::result::Result<UpgradeStatus, (StatusCode, String)> {
        let support = (self.config.support)();
        if !support.supported {
            let reason = support
                .reason
                .map(|r| r.message())
                .unwrap_or("online self-upgrade is not supported");
            return Err((StatusCode::BAD_REQUEST, reason.to_owned()));
        }
        let Some(exe) = support.executable else {
            return Err((
                StatusCode::BAD_REQUEST,
                "cannot determine executable path".to_owned(),
            ));
        };

        let cancel_rx = self
            .tracker
            .try_start(self.config.current_version.clone(), UpgradeState::Checking)
            .map_err(|msg| (StatusCode::CONFLICT, msg.to_owned()))?;

        let manager = Arc::clone(self);
        tokio::spawn(async move {
            manager.run_online_task(exe, cancel_rx).await;
        });

        Ok(self.tracker.snapshot())
    }

    /// Executes an online upgrade to completion and returns the final
    /// [`UpgradeStatus`]. Useful for tests and direct callers.
    pub async fn run_online_and_wait(
        self: &Arc<Self>,
    ) -> std::result::Result<UpgradeStatus, (StatusCode, String)> {
        let support = (self.config.support)();
        if !support.supported {
            let reason = support
                .reason
                .map(|r| r.message())
                .unwrap_or("online self-upgrade is not supported");
            return Err((StatusCode::BAD_REQUEST, reason.to_owned()));
        }
        let Some(exe) = support.executable else {
            return Err((
                StatusCode::BAD_REQUEST,
                "cannot determine executable path".to_owned(),
            ));
        };
        let cancel_rx = self
            .tracker
            .try_start(self.config.current_version.clone(), UpgradeState::Checking)
            .map_err(|msg| (StatusCode::CONFLICT, msg.to_owned()))?;
        self.run_online_task(exe, cancel_rx).await;
        Ok(self.tracker.snapshot())
    }

    /// Installs an uploaded tar.gz archive or raw binary.
    ///
    /// Skips signature verification and allows downgrading. Custom builds are
    /// permitted to use upload upgrades as long as the executable directory is
    /// writable on Linux.
    pub async fn install_upload(
        self: &Arc<Self>,
        payload: Vec<u8>,
    ) -> std::result::Result<UpgradeStatus, (StatusCode, String)> {
        let support = (self.config.support)();
        if !support.upload_allowed() {
            let reason = support
                .reason
                .map(|r| r.message())
                .unwrap_or("upgrade upload is not supported");
            return Err((StatusCode::BAD_REQUEST, reason.to_owned()));
        }
        let Some(exe) = support.executable else {
            return Err((
                StatusCode::BAD_REQUEST,
                "cannot determine executable path".to_owned(),
            ));
        };
        if !executable_dir_writable(&exe) {
            return Err((
                StatusCode::BAD_REQUEST,
                "executable directory is not writable".to_owned(),
            ));
        }
        if payload.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "uploaded file is empty".to_owned()));
        }
        if payload.len() as u64 > MAX_UPGRADE_ARCHIVE {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("uploaded archive exceeds {MAX_UPGRADE_ARCHIVE} bytes"),
            ));
        }

        let _cancel_rx = self
            .tracker
            .try_start(self.config.current_version.clone(), UpgradeState::Verifying)
            .map_err(|msg| (StatusCode::CONFLICT, msg.to_owned()))?;
        self.tracker
            .set_progress(payload.len() as u64, payload.len() as u64);

        let extracted = tokio::task::spawn_blocking(move || extract_binary(&payload))
            .await
            .map_err(|err| anyhow!("extract task failed: {err}"))
            .and_then(|res| res);

        let bin = match extracted {
            Ok(bin) => bin,
            Err(err) => {
                self.tracker.fail(err.to_string());
                return Err((StatusCode::BAD_REQUEST, err.to_string()));
            }
        };

        if let Err(msg) = self.tracker.enter_installing() {
            return Err((StatusCode::CONFLICT, msg.to_owned()));
        }

        match install_binary(&exe, &bin).await {
            Ok(version) => {
                self.tracker.finish_restarting(Some(version));
                (self.config.on_restart)();
                Ok(self.tracker.snapshot())
            }
            Err(err) => {
                self.tracker.fail(err.to_string());
                Err((StatusCode::BAD_REQUEST, err.to_string()))
            }
        }
    }

    async fn run_online_task(&self, exe: std::path::PathBuf, mut cancel: watch::Receiver<bool>) {
        let outcome =
            tokio::time::timeout(self.config.timeout, self.online_flow(&exe, &mut cancel)).await;
        match outcome {
            Ok(Ok(installed_version)) => {
                self.tracker.finish_restarting(Some(installed_version));
                (self.config.on_restart)();
            }
            Ok(Err(FlowAbort::Canceled)) => {
                self.tracker.finish_canceled();
            }
            Ok(Err(FlowAbort::Failed(err))) => {
                self.tracker.fail(err.to_string());
            }
            Err(_) => {
                self.tracker.fail("online upgrade timed out".to_owned());
            }
        }
    }

    async fn online_flow(
        &self,
        exe: &std::path::Path,
        cancel: &mut watch::Receiver<bool>,
    ) -> std::result::Result<String, FlowAbort> {
        let settings = (self.config.settings)();
        let proxy = (!settings.update_proxy.trim().is_empty())
            .then(|| settings.update_proxy.trim().to_owned());
        let restrict_outbound = settings.restrict_outbound;

        // 1. Checking: fetch latest formal release.
        let api_base = self.config.api_base.trim_end_matches('/');
        let releases_url = format!("{api_base}/releases?per_page=100");
        let releases_resp = fetch_cancelable(
            &self.config.fetcher,
            FetchRequest {
                url: releases_url,
                max_bytes: MAX_RELEASES_BODY,
                timeout: self.config.timeout,
                proxy: proxy.clone(),
                restrict_outbound,
            },
            cancel,
        )
        .await?;
        if releases_resp.status != 200 {
            return Err(FlowAbort::Failed(anyhow!(
                "releases endpoint returned HTTP {}",
                releases_resp.status
            )));
        }
        let releases: Vec<GhRelease> = serde_json::from_slice(&releases_resp.body)
            .context("parse releases JSON")
            .map_err(FlowAbort::Failed)?;

        let latest = find_latest_release(&releases)
            .ok_or_else(|| FlowAbort::Failed(anyhow!("no formal release found")))?;

        if !version_newer(&latest.tag_name, &self.config.current_version) {
            return Err(FlowAbort::Failed(anyhow!(
                "already running the latest version ({})",
                self.config.current_version
            )));
        }

        let archive_asset = find_archive_asset(
            &latest.assets,
            &self.config.asset_prefixes,
            &latest.tag_name,
            &self.config.asset_os,
            &self.config.asset_arch,
        )
        .ok_or_else(|| {
            FlowAbort::Failed(anyhow!(
                "release {} does not contain an archive for {}/{}",
                latest.tag_name,
                self.config.asset_os,
                self.config.asset_arch
            ))
        })?;

        let checksums_asset = latest
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case("checksums.txt"))
            .ok_or_else(|| {
                FlowAbort::Failed(anyhow!(
                    "release {} is missing checksums.txt",
                    latest.tag_name
                ))
            })?;

        let signature_asset = latest.assets.iter().find(|a| {
            matches!(
                a.name.to_ascii_lowercase().as_str(),
                "checksums.txt.sig" | "checksums.txt.minisig" | "checksums.txt.asc"
            )
        });

        self.tracker
            .set_target(latest.tag_name.clone(), archive_asset.size);

        // 2. Downloading: checksums.txt -> optional signature -> verify signature -> archive.
        check_canceled(cancel)?;
        self.tracker.set_state(UpgradeState::Downloading);

        let checksums_resp = fetch_cancelable(
            &self.config.fetcher,
            FetchRequest {
                url: checksums_asset.browser_download_url.clone(),
                max_bytes: MAX_CHECKSUMS_BODY,
                timeout: self.config.timeout,
                proxy: proxy.clone(),
                restrict_outbound,
            },
            cancel,
        )
        .await?;
        if checksums_resp.status != 200 || checksums_resp.body.len() as u64 > MAX_CHECKSUMS_BODY {
            return Err(FlowAbort::Failed(anyhow!(
                "failed to download checksums.txt (HTTP {})",
                checksums_resp.status
            )));
        }

        let signature_bytes = match signature_asset {
            Some(sig_asset) => {
                let resp = fetch_cancelable(
                    &self.config.fetcher,
                    FetchRequest {
                        url: sig_asset.browser_download_url.clone(),
                        max_bytes: MAX_SIGNATURE_BODY,
                        timeout: self.config.timeout,
                        proxy: proxy.clone(),
                        restrict_outbound,
                    },
                    cancel,
                )
                .await?;
                if resp.status == 200 && resp.body.len() as u64 <= MAX_SIGNATURE_BODY {
                    Some(resp.body)
                } else if resp.status == 404 {
                    None
                } else {
                    return Err(FlowAbort::Failed(anyhow!(
                        "failed to download release signature (HTTP {})",
                        resp.status
                    )));
                }
            }
            None => None,
        };

        // Security boundary: verify signature before trusting checksums or downloading archive.
        let unsigned = verify_release_signature(
            &latest.tag_name,
            &self.config.first_signed_release,
            &checksums_resp.body,
            signature_bytes.as_deref(),
            &self.config.verifier,
        )
        .map_err(FlowAbort::Failed)?;
        self.tracker.set_unsigned(unsigned);

        let expected_sha256 =
            checksum_for(&checksums_resp.body, &archive_asset.name).ok_or_else(|| {
                FlowAbort::Failed(anyhow!(
                    "checksums.txt does not list {}",
                    archive_asset.name
                ))
            })?;

        check_canceled(cancel)?;
        let archive_resp = fetch_cancelable(
            &self.config.fetcher,
            FetchRequest {
                url: archive_asset.browser_download_url.clone(),
                max_bytes: MAX_UPGRADE_ARCHIVE,
                timeout: self.config.timeout,
                proxy,
                restrict_outbound,
            },
            cancel,
        )
        .await?;
        if archive_resp.status != 200 {
            return Err(FlowAbort::Failed(anyhow!(
                "failed to download release archive (HTTP {})",
                archive_resp.status
            )));
        }
        if archive_resp.body.len() as u64 > MAX_UPGRADE_ARCHIVE {
            return Err(FlowAbort::Failed(anyhow!(
                "release archive exceeds {MAX_UPGRADE_ARCHIVE} bytes"
            )));
        }
        let downloaded = archive_resp.body.len() as u64;
        let total = if archive_asset.size > 0 {
            archive_asset.size
        } else {
            downloaded
        };
        self.tracker.set_progress(downloaded, total);

        // 3. Verifying: SHA-256 + extract binary.
        check_canceled(cancel)?;
        self.tracker.set_state(UpgradeState::Verifying);

        verify_sha256(&archive_resp.body, &expected_sha256).map_err(FlowAbort::Failed)?;

        check_canceled(cancel)?;
        let raw_archive = archive_resp.body;
        let binary = tokio::task::spawn_blocking(move || extract_binary(&raw_archive))
            .await
            .map_err(|err| FlowAbort::Failed(anyhow!("extract task failed: {err}")))?
            .map_err(FlowAbort::Failed)?;

        // 4. Installing: atomic cancel check + close cancellation window (returns 409 from here).
        if self.tracker.enter_installing().is_err() {
            return Err(FlowAbort::Canceled);
        }

        let probed = install_binary(exe, &binary)
            .await
            .map_err(FlowAbort::Failed)?;
        Ok(probed)
    }
}

enum FlowAbort {
    Canceled,
    Failed(anyhow::Error),
}

fn check_canceled(cancel: &watch::Receiver<bool>) -> std::result::Result<(), FlowAbort> {
    if *cancel.borrow() {
        Err(FlowAbort::Canceled)
    } else {
        Ok(())
    }
}

async fn fetch_cancelable(
    fetcher: &FetchFn,
    req: FetchRequest,
    cancel: &mut watch::Receiver<bool>,
) -> std::result::Result<super::check::FetchResponse, FlowAbort> {
    check_canceled(cancel)?;
    tokio::select! {
        biased;
        changed = cancel.changed() => {
            if changed.is_ok() && *cancel.borrow() {
                Err(FlowAbort::Canceled)
            } else {
                Err(FlowAbort::Canceled)
            }
        }
        res = fetcher(req) => res.map_err(FlowAbort::Failed),
    }
}

fn find_latest_release(releases: &[GhRelease]) -> Option<&GhRelease> {
    let mut best: Option<(super::version::ParsedVersion, &GhRelease)> = None;
    for release in releases {
        if release.draft || release.prerelease {
            continue;
        }
        let Some(ver) = parse_version(&release.tag_name) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(b, _)| compare_version(&ver, b) == Ordering::Greater)
        {
            best = Some((ver, release));
        }
    }
    best.map(|(_, r)| r)
}

fn find_archive_asset<'a>(
    assets: &'a [GhAsset],
    prefixes: &[String],
    tag: &str,
    os: &str,
    arch: &str,
) -> Option<&'a GhAsset> {
    let trimmed = tag.trim();
    let without_v = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    let with_v = format!("v{without_v}");
    let versions = [trimmed, without_v, with_v.as_str()];
    let arch_aliases = arch_aliases(arch);

    for prefix in prefixes {
        for ver in &versions {
            for candidate_arch in &arch_aliases {
                let expected = format!("{prefix}_{ver}_{os}_{candidate_arch}.tar.gz");
                if let Some(asset) = assets
                    .iter()
                    .find(|a| a.name.eq_ignore_ascii_case(&expected))
                {
                    return Some(asset);
                }
            }
        }
    }
    None
}

fn canonical_release_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn arch_aliases(arch: &str) -> Vec<&str> {
    match arch {
        "amd64" | "x86_64" => vec!["amd64", "x86_64"],
        "arm64" | "aarch64" => vec!["arm64", "aarch64"],
        "arm" | "armv7" => vec!["armv7", "arm"],
        other => vec![other],
    }
}

/// Mounts the 6 WP-94 update and upgrade endpoints on [`ApiRouter`]:
/// - `GET /api/system/update` (read-only callers receive cached state only)
/// - `GET /api/system/update/state` (cached state, never hits network)
/// - `POST /api/system/upgrade` (session-only, starts online upgrade)
/// - `GET /api/system/upgrade/status` (session-only, returns current progress)
/// - `POST /api/system/upgrade/cancel` (session-only, 409 once installing)
/// - `POST /api/system/upgrade/upload` (session-only, tar.gz or raw binary)
pub fn mount_update_routes(
    router: ApiRouter,
    checker: Arc<UpdateChecker>,
    upgrader: Arc<UpgradeManager>,
) -> ApiRouter {
    let check_get = Arc::clone(&checker);
    let state_get = Arc::clone(&checker);
    let upgrade_post = Arc::clone(&upgrader);
    let upgrade_status = Arc::clone(&upgrader);
    let upgrade_cancel = Arc::clone(&upgrader);
    let upgrade_upload = Arc::clone(&upgrader);

    router
        .modeled_route(
            Method::GET,
            "/api/system/update",
            "Check for updates or return cached status for read-only callers",
            RouteModels::default().response::<UpdateView>(),
            move |Extension(ReadOnly(read_only)): Extension<ReadOnly>| {
                let checker = Arc::clone(&check_get);
                async move {
                    let view = if read_only {
                        checker.view()
                    } else {
                        checker.check_now(true).await
                    };
                    Json(view)
                }
            },
        )
        .modeled_route(
            Method::GET,
            "/api/system/update/state",
            "Get cached update check state without accessing network",
            RouteModels::default().response::<UpdateView>(),
            move || {
                let checker = Arc::clone(&state_get);
                async move { Json(checker.view()) }
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/upgrade",
            "Start online self-upgrade",
            RouteModels::default().response::<UpgradeStatus>(),
            move || {
                let upgrader = Arc::clone(&upgrade_post);
                async move {
                    match upgrader.start_online() {
                        Ok(status) => Json(status).into_response(),
                        Err((code, msg)) => error_response(code, msg),
                    }
                }
            },
        )
        .modeled_route(
            Method::GET,
            "/api/system/upgrade/status",
            "Get current upgrade status and progress",
            RouteModels::default().response::<UpgradeStatus>(),
            move || {
                let upgrader = Arc::clone(&upgrade_status);
                async move { Json(upgrader.status()) }
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/upgrade/cancel",
            "Cancel an ongoing upgrade before installation starts",
            RouteModels::default().response::<UpgradeStatus>(),
            move || {
                let upgrader = Arc::clone(&upgrade_cancel);
                async move {
                    match upgrader.cancel() {
                        CancelOutcome::Canceled => Json(upgrader.status()).into_response(),
                        CancelOutcome::TooLate => error_response(
                            StatusCode::CONFLICT,
                            "cannot cancel upgrade during installation",
                        ),
                        CancelOutcome::NotRunning => {
                            error_response(StatusCode::CONFLICT, "no upgrade is currently running")
                        }
                    }
                }
            },
        )
        .upload_route(
            Method::POST,
            "/api/system/upgrade/upload",
            "Upload a tar.gz release archive or raw binary to upgrade",
            MAX_UPGRADE_ARCHIVE + MULTIPART_HEADER_OVERHEAD,
            move |request: Request| {
                let upgrader = Arc::clone(&upgrade_upload);
                async move { handle_upload(upgrader, request).await }
            },
        )
}

async fn handle_upload(upgrader: Arc<UpgradeManager>, request: Request) -> Response {
    let headers = request.headers().clone();
    let collected = match request.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "could not read upload body");
        }
    };
    let payload = match extract_upload_file(&headers, &collected) {
        Ok(bytes) => bytes,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };
    match upgrader.install_upload(payload).await {
        Ok(status) => Json(status).into_response(),
        Err((code, msg)) => error_response(code, msg),
    }
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

/// Extracts the `file` part from a `multipart/form-data` body, or returns the
/// raw body bytes directly for non-multipart binary uploads.
fn extract_upload_file(headers: &HeaderMap, body: &Bytes) -> Result<Vec<u8>> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type
        .to_ascii_lowercase()
        .starts_with("multipart/form-data")
    {
        ensure!(!body.is_empty(), "upload body is empty");
        return Ok(body.to_vec());
    }

    let boundary = parse_multipart_boundary(content_type)
        .ok_or_else(|| anyhow!("missing multipart boundary"))?;
    let delimiter = format!("--{boundary}");
    let delim_bytes = delimiter.as_bytes();

    let mut pos = find_subslice(body, delim_bytes)
        .ok_or_else(|| anyhow!("multipart boundary not found in body"))?;

    while pos < body.len() {
        pos += delim_bytes.len();
        if body[pos..].starts_with(b"--") {
            break;
        }
        if body[pos..].starts_with(b"\r\n") {
            pos += 2;
        } else if body[pos..].starts_with(b"\n") {
            pos += 1;
        }

        let header_end_rel = find_subslice(&body[pos..], b"\r\n\r\n")
            .map(|idx| (idx, 4))
            .or_else(|| find_subslice(&body[pos..], b"\n\n").map(|idx| (idx, 2)))
            .ok_or_else(|| anyhow!("malformed multipart headers"))?;
        let part_headers = std::str::from_utf8(&body[pos..pos + header_end_rel.0])
            .context("multipart headers must be UTF-8")?;
        let data_start = pos + header_end_rel.0 + header_end_rel.1;

        let next_boundary_rel = find_subslice(&body[data_start..], delim_bytes)
            .ok_or_else(|| anyhow!("unterminated multipart part"))?;
        let mut data_end = data_start + next_boundary_rel;
        if data_end >= data_start + 2 && &body[data_end - 2..data_end] == b"\r\n" {
            data_end -= 2;
        } else if data_end >= data_start + 1 && body[data_end - 1] == b'\n' {
            data_end -= 1;
        }

        if is_file_field(part_headers) {
            return Ok(body[data_start..data_end].to_vec());
        }
        pos = data_start + next_boundary_rel;
    }

    bail!("multipart upload is missing the 'file' form field")
}

fn parse_multipart_boundary(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let param = param.trim();
        if let Some((key, value)) = param.split_once('=')
            && key.trim().eq_ignore_ascii_case("boundary")
        {
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn is_file_field(headers: &str) -> bool {
    headers.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("content-disposition:")
            && (lower.contains("name=\"file\"") || lower.contains("name=file"))
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
