//! Binary build planning and execution (`cargo` / `cargo-zigbuild`) with
//! version metadata environment injection and argument arrays (WP-92 §3.2–§3.3).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

use crate::modules::resolve::Resolved;
use crate::package::targets::{Kind, Target};

/// Version, commit, date, and resolved feature selection for a packaging build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BuildSpec {
    pub version: String,
    pub commit: String,
    pub build_date: String,
    pub resolved: Resolved,
    /// Custom build profile key (`sha256(...)[..12]`), set for local custom builds.
    pub profile: Option<String>,
}

/// Cargo build driver selected for native vs cross compilation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CargoDriver {
    Cargo,
    Zigbuild,
}

/// Environment variables passed to Cargo for version metadata injection and
/// target-specific static-linking / soft-float flags.
pub fn cargo_env(spec: &BuildSpec, target: &Target) -> Vec<(String, String)> {
    let mut env = vec![
        ("FERRUMGATE_VERSION".to_string(), spec.version.clone()),
        ("FERRUMGATE_COMMIT".to_string(), spec.commit.clone()),
        ("FERRUMGATE_BUILD_DATE".to_string(), spec.build_date.clone()),
    ];
    if target.is_linux_musl() {
        let key = rustflags_env_key(target.triple);
        let value = if target.is_mips_softfloat() {
            "-C target-feature=+crt-static,+soft-float".to_string()
        } else {
            "-C target-feature=+crt-static".to_string()
        };
        env.push((key, value));
    }
    env
}

/// Returns the `CARGO_TARGET_<TRIPLE>_RUSTFLAGS` environment variable name.
pub fn rustflags_env_key(triple: &str) -> String {
    let normalized: String = triple
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("CARGO_TARGET_{normalized}_RUSTFLAGS")
}

/// Builds the Cargo argument array for a release binary build:
/// `build --release --locked --bin fgate --target <triple> --no-default-features --features <...>`.
pub fn cargo_build_args(spec: &BuildSpec, target: &Target) -> Result<Vec<String>> {
    ensure!(
        target.kind != Kind::Docker && !target.triple.is_empty(),
        "target `{}` is not a direct Cargo binary target; use `package docker` instead",
        target.id
    );
    let mut args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--locked".to_string(),
        "--bin".to_string(),
        "fgate".to_string(),
        "--target".to_string(),
        target.triple.to_string(),
    ];
    args.extend(spec.resolved.cargo_args.iter().cloned());
    Ok(args)
}

/// Chooses `cargo zigbuild` when cross-compiling and `cargo-zigbuild` is available,
/// otherwise plain `cargo build`.
pub fn choose_driver(
    host_triple: Option<&str>,
    target: &Target,
    has_zigbuild: bool,
) -> CargoDriver {
    let cross = match host_triple {
        Some(host) => host != target.triple,
        None => true,
    };
    if cross && has_zigbuild {
        CargoDriver::Zigbuild
    } else {
        CargoDriver::Cargo
    }
}

/// Detects the host Rust triple via `rustc -vV` (arg array, no shell).
pub fn detect_host_triple() -> Option<String> {
    let output = Command::new("rustc").arg("-vV").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::trim))
        .map(str::to_string)
}

/// Compiles `fgate` for `target` via `cargo` or `cargo zigbuild` (strictly arg
/// arrays, no shell) and copies the built binary to `out`.
pub fn build_binary(
    root: &Path,
    spec: &BuildSpec,
    target: &Target,
    out: &Path,
    driver: CargoDriver,
) -> Result<PathBuf> {
    let mut args = cargo_build_args(spec, target)?;
    if driver == CargoDriver::Zigbuild {
        if let Some(first) = args.first_mut() {
            *first = "zigbuild".to_string();
        }
    }

    let env = cargo_env(spec, target);
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).args(&args);
    for (k, v) in &env {
        cmd.env(k, v);
    }

    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn `cargo {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`cargo {}` exited with {status}", args.join(" "));
    }

    let built = root
        .join("target")
        .join(target.triple)
        .join("release")
        .join(target.exe_name());
    ensure!(
        built.is_file(),
        "expected compiled binary at {}",
        built.display()
    );

    let dest = if out.is_dir() || out.to_string_lossy().ends_with('/') {
        std::fs::create_dir_all(out)
            .with_context(|| format!("failed to create output directory {}", out.display()))?;
        out.join(target.exe_name())
    } else {
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create parent directory {}", parent.display())
                })?;
            }
        }
        out.to_path_buf()
    };

    std::fs::copy(&built, &dest).with_context(|| {
        format!(
            "failed to copy built binary {} to {}",
            built.display(),
            dest.display()
        )
    })?;
    Ok(dest)
}
