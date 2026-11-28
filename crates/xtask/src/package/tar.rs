//! Deterministic `.tar.gz` release archive builder (WP-92 §3.3).
//!
//! Bundles `<fgate|fgate.exe>` (mode `0755`), `LICENSE` (`0644`), and
//! `README.md` (`0644`) in fixed order by invoking the system `tar` binary
//! with an explicit argument array (never through a shell).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

use crate::package::targets::{Target, local_asset_name, tar_asset_name};

/// Files bundled inside every release `.tar.gz`, in exact order.
pub fn archive_member_order(target: &Target) -> [&'static str; 3] {
    [target.exe_name(), "LICENSE", "README.md"]
}

/// Metadata returned when inspecting a `.tar.gz` archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub mode: String,
    pub name: String,
}

/// Builds a release or custom-profile `.tar.gz` archive containing the binary
/// (mode `0755`), `LICENSE`, and `README.md` in fixed order.
pub fn build_tar_gz(
    binary: &Path,
    license: &Path,
    readme: &Path,
    version: &str,
    target: &Target,
    profile: Option<&str>,
    out_dir: &Path,
) -> Result<PathBuf> {
    ensure!(
        binary.is_file(),
        "binary does not exist: {}",
        binary.display()
    );
    ensure!(
        license.is_file(),
        "LICENSE does not exist: {}",
        license.display()
    );
    ensure!(
        readme.is_file(),
        "README.md does not exist: {}",
        readme.display()
    );

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create output directory {}", out_dir.display()))?;

    let asset_name = match profile {
        Some(key) => local_asset_name(version, key, target.id),
        None => tar_asset_name(version, target.id),
    };
    let archive_path = out_dir.join(&asset_name);

    // Stage into a sibling temporary directory so we can enforce exact filenames
    // and POSIX mode bits without mutating the caller's source files.
    let stage_dir = out_dir.join(format!(".stage-tar-{}", target.id));
    if stage_dir.exists() {
        std::fs::remove_dir_all(&stage_dir)
            .with_context(|| format!("failed to clean staging dir {}", stage_dir.display()))?;
    }
    std::fs::create_dir_all(&stage_dir)
        .with_context(|| format!("failed to create staging dir {}", stage_dir.display()))?;

    let result = (|| -> Result<PathBuf> {
        let exe_dest = stage_dir.join(target.exe_name());
        let license_dest = stage_dir.join("LICENSE");
        let readme_dest = stage_dir.join("README.md");

        std::fs::copy(binary, &exe_dest)
            .with_context(|| format!("failed to stage {}", binary.display()))?;
        std::fs::copy(license, &license_dest)
            .with_context(|| format!("failed to stage {}", license.display()))?;
        std::fs::copy(readme, &readme_dest)
            .with_context(|| format!("failed to stage {}", readme.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe_dest, std::fs::Permissions::from_mode(0o755))
                .with_context(|| format!("failed to chmod 0755 {}", exe_dest.display()))?;
            std::fs::set_permissions(&license_dest, std::fs::Permissions::from_mode(0o644))
                .with_context(|| format!("failed to chmod 0644 {}", license_dest.display()))?;
            std::fs::set_permissions(&readme_dest, std::fs::Permissions::from_mode(0o644))
                .with_context(|| format!("failed to chmod 0644 {}", readme_dest.display()))?;
        }

        let members = archive_member_order(target);
        let mut cmd = Command::new("tar");
        cmd.env("COPYFILE_DISABLE", "1")
            .arg("-czf")
            .arg(&archive_path)
            .arg("-C")
            .arg(&stage_dir)
            .args(members);

        let status = cmd
            .status()
            .context("failed to spawn `tar` for archive creation")?;
        if !status.success() {
            bail!("`tar -czf {}` failed with {status}", archive_path.display());
        }
        Ok(archive_path)
    })();

    let _ = std::fs::remove_dir_all(&stage_dir);
    result
}

/// Lists entries and permissions of a `.tar.gz` archive via `tar -tvzf` (arg array).
pub fn inspect_tar_gz(archive_path: &Path) -> Result<Vec<ArchiveEntry>> {
    let output = Command::new("tar")
        .arg("-tvzf")
        .arg(archive_path)
        .output()
        .with_context(|| format!("failed to run `tar -tvzf {}`", archive_path.display()))?;
    if !output.status.success() {
        bail!(
            "`tar -tvzf {}` failed with {}: {}",
            archive_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout).context("tar listing is not valid UTF-8")?;
    let mut entries = Vec::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let mut parts = line.split_whitespace();
        let mode = parts.next().unwrap_or_default().to_string();
        let name = line
            .split_whitespace()
            .last()
            .unwrap_or_default()
            .trim_start_matches("./")
            .to_string();
        entries.push(ArchiveEntry { mode, name });
    }
    Ok(entries)
}
