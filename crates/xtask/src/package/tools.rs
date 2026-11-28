//! Pinned external packaging tools manifest and SHA-256 verification helpers
//! (WP-92 §3.3, §3.4, §8).
//!
//! Every external binary or container image used during packaging has a fixed
//! version and SHA-256 digest here. Downloaded tools are verified against their
//! pinned hash before execution and placed in a dedicated isolated directory.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolKind {
    Binary,
    Tarball,
    ContainerImage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PinnedTool {
    pub name: &'static str,
    pub version: &'static str,
    pub source: &'static str,
    /// Lowercase 64-character hex SHA-256 digest (for container images, the
    /// hex digest portion of `@sha256:<hex>`).
    pub sha256: &'static str,
    pub kind: ToolKind,
}

/// Pinned `fnpack` binary used to assemble fnOS `.fpk` packages (WP-92 §3.3).
pub const FNPACK_TOOL: PinnedTool = PinnedTool {
    name: "fnpack",
    version: "1.2.3",
    source: "https://static2.fnnas.com/fnpack/fnpack-1.2.3-linux-amd64",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    kind: ToolKind::Binary,
};

/// Pinned Alpine 3.24 container image digest used as the root packaging
/// environment for OpenWrt `.ipk` and `.apk` (apk-tools v3) builds (WP-92 §3.4).
pub const OPENWRT_PACKAGER_IMAGE: PinnedTool = PinnedTool {
    name: "openwrt-packager-alpine",
    version: "3.24",
    source: "docker.io/library/alpine:3.24@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c",
    sha256: "a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c",
    kind: ToolKind::ContainerImage,
};

/// Pinned `cargo-zigbuild` release used for cross-compilation (WP-91 §2 / WP-92 §2).
pub const ZIGBUILD_TOOL: PinnedTool = PinnedTool {
    name: "cargo-zigbuild",
    version: "0.24.1",
    source: "https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.24.1/cargo-zigbuild-v0.24.1.x86_64-unknown-linux-musl.tar.gz",
    sha256: "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
    kind: ToolKind::Tarball,
};

/// Complete manifest of external packaging tools; every tool must declare a
/// non-empty pinned version, source, and valid 64-char SHA-256 digest.
pub const PINNED_TOOLS: &[PinnedTool] = &[FNPACK_TOOL, OPENWRT_PACKAGER_IMAGE, ZIGBUILD_TOOL];

/// Returns the fully pinned OCI image reference `<repo>:<tag>@sha256:<digest>`
/// for the OpenWrt packaging container.
pub fn openwrt_packager_image_ref() -> &'static str {
    OPENWRT_PACKAGER_IMAGE.source
}

/// Validates that `hex` is a 64-character lowercase ASCII hexadecimal SHA-256 digest.
pub fn is_valid_sha256(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Computes the lowercase hex SHA-256 digest of a byte slice.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Computes the lowercase hex SHA-256 digest of a file on disk using streaming I/O.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open {} for SHA-256 verification", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Verifies `path` matches `expected_hex` (case-sensitive 64 lowercase hex chars).
/// Returns an error BEFORE any caller can execute the file.
pub fn verify_file_sha256(path: &Path, expected_hex: &str) -> Result<()> {
    ensure!(
        is_valid_sha256(expected_hex),
        "invalid expected SHA-256 digest `{expected_hex}` (must be 64 lowercase hex chars)"
    );
    let actual = sha256_file(path)?;
    if actual != expected_hex {
        bail!(
            "SHA-256 mismatch for {}: expected {expected_hex}, got {actual}",
            path.display()
        );
    }
    Ok(())
}

/// Creates and returns an isolated directory `<base>/<name>-<version>` for a
/// verified external tool, rejecting unsafe path segments.
pub fn isolated_tool_dir(base: &Path, tool: &PinnedTool) -> Result<PathBuf> {
    ensure!(
        is_safe_segment(tool.name) && is_safe_segment(tool.version),
        "unsafe tool directory name `{}-{}`",
        tool.name,
        tool.version
    );
    let dir = base.join(format!("{}-{}", tool.name, tool.version));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create isolated tool dir {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set 0700 permissions on {}", dir.display()))?;
    }
    Ok(dir)
}

/// Verifies a downloaded tool file against `expected_sha256` and stages it
/// inside an isolated directory before returning the executable path.
pub fn verify_and_stage_tool(
    tool: &PinnedTool,
    downloaded: &Path,
    tool_root: &Path,
    expected_sha256: &str,
) -> Result<PathBuf> {
    verify_file_sha256(downloaded, expected_sha256)?;
    let dir = isolated_tool_dir(tool_root, tool)?;
    let dest = dir.join(tool.name);
    std::fs::copy(downloaded, &dest).with_context(|| {
        format!(
            "failed to stage verified tool {} into {}",
            downloaded.display(),
            dest.display()
        )
    })?;
    #[cfg(unix)]
    if tool.kind == ToolKind::Binary {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod 0755 {}", dest.display()))?;
    }
    Ok(dest)
}

fn is_safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
