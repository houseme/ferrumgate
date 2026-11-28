//! Detection of whether online self-upgrade is supported in the current
//! deployment environment, covering all 7 unsupported reasons defined by WP-94.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Reason why online self-upgrade is disabled for this deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UpgradeReason {
    /// Non-Linux OS (e.g., macOS or Windows).
    Os,
    /// Running inside a Docker / Podman container (`/.dockerenv` or `/.containerenv`).
    Docker,
    /// Installed via fnOS package manager.
    Fnos,
    /// Installed via OpenWrt `opkg` (24.10 and earlier).
    Opkg,
    /// Installed via OpenWrt `apk` (25.12 and later).
    Apk,
    /// Executable directory is not writable (verified by creating a temp file).
    Readonly,
    /// Custom trimmed build; online release archive would overwrite custom feature selection.
    Custom,
}

impl UpgradeReason {
    /// Returns a human-readable explanation for this unsupported reason.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Os => "online self-upgrade is only supported on Linux",
            Self::Docker => "upgrade container deployments by pulling the new image",
            Self::Fnos => "upgrade fnOS deployments through the fnOS App Center",
            Self::Opkg => "upgrade OpenWrt opkg deployments using opkg",
            Self::Apk => "upgrade OpenWrt apk deployments using apk",
            Self::Readonly => "executable directory is not writable",
            Self::Custom => {
                "custom builds do not support online upgrade; upload a custom binary instead"
            }
        }
    }
}

/// Self-upgrade capability reported by update endpoints and `/api/system/info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeSupport {
    pub supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<UpgradeReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<PathBuf>,
    #[serde(default)]
    pub custom: bool,
}

impl UpgradeSupport {
    /// Whether manual binary upload upgrade is permitted in this deployment.
    ///
    /// Custom builds cannot use online release downloads, but may still upload
    /// a custom-built binary when the executable directory is writable on Linux.
    pub fn upload_allowed(&self) -> bool {
        if self.supported {
            return true;
        }
        self.reason == Some(UpgradeReason::Custom)
            && self
                .executable
                .as_deref()
                .is_some_and(executable_dir_writable)
    }
}

/// Testable snapshot of host deployment signals used by [`detect_upgrade_support`].
#[derive(Clone, Debug)]
pub struct DeployEnv {
    pub os: String,
    pub executable: Option<PathBuf>,
    pub custom_build: bool,
    pub docker_env_paths: Vec<PathBuf>,
    pub is_fnos: bool,
    pub opkg_status_path: Option<PathBuf>,
    pub apk_installed_path: Option<PathBuf>,
    pub package_names: Vec<String>,
    pub probe_writable: bool,
}

impl DeployEnv {
    /// Captures deployment signals from the live system.
    pub fn from_system() -> Self {
        let executable = std::env::current_exe().ok();
        let is_fnos = std::env::var_os("TRIM_APPDEST").is_some()
            || executable
                .as_deref()
                .and_then(|p| p.to_str())
                .is_some_and(|s| s.starts_with("/var/apps/"));
        let custom_build = option_env!("FERRUMGATE_CUSTOM_BUILD")
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        Self {
            os: std::env::consts::OS.to_owned(),
            executable,
            custom_build,
            docker_env_paths: vec![
                PathBuf::from("/.dockerenv"),
                PathBuf::from("/.containerenv"),
            ],
            is_fnos,
            opkg_status_path: Some(PathBuf::from("/usr/lib/opkg/status")),
            apk_installed_path: Some(PathBuf::from("/lib/apk/db/installed")),
            package_names: vec!["ferrumgate".into(), "gately".into()],
            probe_writable: true,
        }
    }
}

/// Detects online self-upgrade support for the live system.
pub fn deploy_upgrade_support() -> UpgradeSupport {
    detect_upgrade_support(&DeployEnv::from_system())
}

/// Evaluates online self-upgrade support against the provided [`DeployEnv`].
pub fn detect_upgrade_support(env: &DeployEnv) -> UpgradeSupport {
    let deny = |reason: UpgradeReason| UpgradeSupport {
        supported: false,
        reason: Some(reason),
        executable: env.executable.clone(),
        custom: env.custom_build,
    };

    if env.os != "linux" {
        return deny(UpgradeReason::Os);
    }
    if env.docker_env_paths.iter().any(|path| path.exists()) {
        return deny(UpgradeReason::Docker);
    }
    if env.is_fnos {
        return deny(UpgradeReason::Fnos);
    }
    if env
        .opkg_status_path
        .as_deref()
        .is_some_and(|path| opkg_has_package(path, &env.package_names))
    {
        return deny(UpgradeReason::Opkg);
    }
    if env
        .apk_installed_path
        .as_deref()
        .is_some_and(|path| apk_has_package(path, &env.package_names))
    {
        return deny(UpgradeReason::Apk);
    }
    if env.custom_build {
        return deny(UpgradeReason::Custom);
    }
    let Some(exe) = env.executable.as_deref() else {
        return deny(UpgradeReason::Readonly);
    };
    if env.probe_writable && !executable_dir_writable(exe) {
        return deny(UpgradeReason::Readonly);
    }

    UpgradeSupport {
        supported: true,
        reason: None,
        executable: Some(exe.to_path_buf()),
        custom: false,
    }
}

/// Probes writability of `exe`'s parent directory by creating and deleting a
/// temporary file (more reliable than permission bits on read-only mounts).
pub fn executable_dir_writable(exe: &Path) -> bool {
    let Some(dir) = exe.parent() else {
        return false;
    };
    tempfile::Builder::new()
        .prefix(".fgate-probe-")
        .tempfile_in(dir)
        .and_then(|tmp| tmp.close())
        .is_ok()
}

fn opkg_has_package(status_path: &Path, packages: &[String]) -> bool {
    let Ok(content) = std::fs::read_to_string(status_path) else {
        return false;
    };
    content.lines().any(|line| {
        line.strip_prefix("Package:")
            .map(str::trim)
            .is_some_and(|name| packages.iter().any(|p| p.eq_ignore_ascii_case(name)))
    })
}

fn apk_has_package(installed_path: &Path, packages: &[String]) -> bool {
    let Ok(content) = std::fs::read_to_string(installed_path) else {
        return false;
    };
    content.lines().any(|line| {
        line.strip_prefix("P:")
            .map(str::trim)
            .is_some_and(|name| packages.iter().any(|p| p.eq_ignore_ascii_case(name)))
    })
}
