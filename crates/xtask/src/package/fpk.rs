//! fnOS `.fpk` package manifest renderer, project staging, and `fnpack`
//! invocation via argument arrays (WP-92 §2, §3.3).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

/// Supported fnOS hardware platforms and their backing Linux musl targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FpkPlatform {
    X86,
    Arm,
}

impl FpkPlatform {
    pub fn from_target_id(target_id: &str) -> Result<Self> {
        match target_id {
            "fnos-x86" | "x86" => Ok(Self::X86),
            "fnos-arm" | "arm" => Ok(Self::Arm),
            other => bail!("unsupported fnOS target `{other}`; expected `fnos-x86` or `fnos-arm`"),
        }
    }

    pub fn target_id(self) -> &'static str {
        match self {
            Self::X86 => "fnos-x86",
            Self::Arm => "fnos-arm",
        }
    }

    /// Value written to the fnOS `manifest` `platform` field.
    pub fn manifest_platform(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::Arm => "arm",
        }
    }

    /// Backing Linux target ID whose static musl binary is packaged.
    pub fn binary_source_target(self) -> &'static str {
        match self {
            Self::X86 => "linux-amd64",
            Self::Arm => "linux-arm64",
        }
    }

    /// Backing Rust target triple.
    pub fn triple(self) -> &'static str {
        match self {
            Self::X86 => "x86_64-unknown-linux-musl",
            Self::Arm => "aarch64-unknown-linux-musl",
        }
    }
}

/// Normalizes a release tag like `v0.5.4` into the fnOS manifest version (`0.5.4`).
pub fn normalize_fpk_version(version: &str) -> Result<String> {
    let trimmed = version.trim();
    let stripped = trimmed.strip_prefix('v').unwrap_or(trimmed);
    ensure!(!stripped.is_empty(), "fnOS version must not be empty");
    ensure!(
        !stripped
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b == b'\n' || b == b'\r'),
        "fnOS version contains control characters: `{version}`"
    );
    Ok(stripped.to_string())
}

/// Renders the fnOS `manifest` file for `version` and `platform`.
pub fn render_manifest(version: &str, platform: FpkPlatform) -> Result<String> {
    let ver = normalize_fpk_version(version)?;
    let plat = platform.manifest_platform();
    Ok(format!(
        "appname               = ferrumgate\n\
         version               = {ver}\n\
         display_name          = FerrumGate\n\
         desc                  = All-in-one reverse proxy, port forwarding, DDNS and network gateway\n\
         platform              = {plat}\n\
         source                = thirdparty\n\
         maintainer            = FerrumGate\n\
         distributor           = FerrumGate\n\
         desktop_uidir         = ui\n\
         desktop_applaunchname = ferrumgate.Application\n\
         service_port          = 16680\n\
         checkport             = false\n\
         os_min_version        = 0.8.0\n"
    ))
}

/// Assembles a self-contained fnOS `.fpk` project directory ready for `fnpack`.
pub fn stage_fpk_project(
    template_dir: Option<&Path>,
    binary: &Path,
    version: &str,
    platform: FpkPlatform,
    staging_dir: &Path,
) -> Result<PathBuf> {
    ensure!(
        binary.is_file(),
        "fnOS source binary does not exist: {}",
        binary.display()
    );

    if staging_dir.exists() {
        std::fs::remove_dir_all(staging_dir)
            .with_context(|| format!("failed to clear {}", staging_dir.display()))?;
    }
    std::fs::create_dir_all(staging_dir)
        .with_context(|| format!("failed to create {}", staging_dir.display()))?;

    for subdir in ["app/server", "cmd", "config", "wizard"] {
        std::fs::create_dir_all(staging_dir.join(subdir))
            .with_context(|| format!("failed to create staging subdir `{subdir}`"))?;
    }

    if let Some(tpl) = template_dir {
        if tpl.is_dir() {
            copy_dir_contents(tpl, staging_dir)?;
        }
    }

    let manifest = render_manifest(version, platform)?;
    std::fs::write(staging_dir.join("manifest"), manifest)
        .with_context(|| format!("failed to write {}/manifest", staging_dir.display()))?;

    let bin_dest = staging_dir.join("app/server/fgate");
    std::fs::copy(binary, &bin_dest).with_context(|| {
        format!(
            "failed to copy binary {} to {}",
            binary.display(),
            bin_dest.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_dest, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod 0755 {}", bin_dest.display()))?;
    }

    Ok(staging_dir.to_path_buf())
}

/// Argument array for invoking `fnpack` (no shell interpolation).
pub fn fnpack_args(staging_dir: &Path, output_fpk: &Path) -> Vec<String> {
    vec![
        "build".to_string(),
        "--directory".to_string(),
        staging_dir.display().to_string(),
        "--output".to_string(),
        output_fpk.display().to_string(),
    ]
}

/// Invokes a verified `fnpack` binary with an argument array to emit `.fpk`.
pub fn build_fpk(fnpack_bin: &Path, staging_dir: &Path, output_fpk: &Path) -> Result<()> {
    ensure!(
        fnpack_bin.is_file(),
        "fnpack binary does not exist: {}",
        fnpack_bin.display()
    );
    if let Some(parent) = output_fpk.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let args = fnpack_args(staging_dir, output_fpk);
    let status = Command::new(fnpack_bin)
        .args(&args)
        .status()
        .with_context(|| format!("failed to spawn {}", fnpack_bin.display()))?;
    if !status.success() {
        bail!(
            "`{} {}` exited with {status}",
            fnpack_bin.display(),
            args.join(" ")
        );
    }
    Ok(())
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    for entry in
        std::fs::read_dir(src).with_context(|| format!("failed to read {}", src.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_dir_contents(&path, &target)?;
        } else if path.is_file() {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}
