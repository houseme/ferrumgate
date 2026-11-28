//! Full 19-target release matrix matching `features.toml` / `modules.json`
//! (WP-92 §2, §3.2, §8).

use anyhow::{Result, bail};
use serde::Serialize;

/// Multi-architecture Docker platforms built from the three primary Linux musl targets.
pub const DOCKER_PLATFORMS: &[&str] = &["linux/amd64", "linux/arm64", "linux/arm/v7"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Tar,
    Fpk,
    Openwrt,
    Docker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Runner {
    Linux,
    Macos,
}

/// Static description of one release packaging target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    /// Upstream-compatible target identifier (`features.toml` / `modules.json`).
    pub id: &'static str,
    pub kind: Kind,
    /// Rust compilation target triple. Empty for `Kind::Docker`, which builds
    /// the three platforms in [`DOCKER_PLATFORMS`].
    pub triple: &'static str,
    pub runner: Runner,
    /// Whether the workspace's non-TLS `ring` dependency builds on this target
    /// (WP-92 §8).
    pub ring_supported: bool,
    /// Optional compatibility note explaining TLS / FPU constraints (WP-92 §8).
    pub crypto_note: Option<&'static str>,
}

const NOTE_MIPS_LE: &str = "ring 0.17.14 lacks mipsel C/asm support (WP-92 §8); requires pure-Rust CryptoProvider; soft-float MIPS";
const NOTE_MIPS_BE: &str = "ring 0.17.14 lacks mips C/asm support (WP-92 §8); requires pure-Rust CryptoProvider; soft-float MIPS";
const NOTE_RISCV64: &str =
    "ring 0.17.14 lacks riscv64 C/asm support (WP-92 §8); requires pure-Rust CryptoProvider";
const NOTE_ARM_V7: &str =
    "ARMv7 with hardware FPU (musleabihf); non-FPU arm_cortex-a9 devices are unsupported";

/// All 19 release targets in `features.toml` manifest order:
/// 1 `docker`, 10 `tar`, 2 `fpk`, 6 `openwrt`.
pub const TARGETS: &[Target] = &[
    Target {
        id: "docker",
        kind: Kind::Docker,
        triple: "",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "linux-amd64",
        kind: Kind::Tar,
        triple: "x86_64-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "linux-arm64",
        kind: Kind::Tar,
        triple: "aarch64-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "linux-arm",
        kind: Kind::Tar,
        triple: "armv7-unknown-linux-musleabihf",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: Some(NOTE_ARM_V7),
    },
    Target {
        id: "linux-mipsle",
        kind: Kind::Tar,
        triple: "mipsel-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: false,
        crypto_note: Some(NOTE_MIPS_LE),
    },
    Target {
        id: "linux-mips",
        kind: Kind::Tar,
        triple: "mips-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: false,
        crypto_note: Some(NOTE_MIPS_BE),
    },
    Target {
        id: "linux-riscv64",
        kind: Kind::Tar,
        triple: "riscv64gc-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: false,
        crypto_note: Some(NOTE_RISCV64),
    },
    Target {
        id: "windows-amd64",
        kind: Kind::Tar,
        triple: "x86_64-pc-windows-gnu",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "darwin-amd64",
        kind: Kind::Tar,
        triple: "x86_64-apple-darwin",
        runner: Runner::Macos,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "darwin-arm64",
        kind: Kind::Tar,
        triple: "aarch64-apple-darwin",
        runner: Runner::Macos,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "freebsd-amd64",
        kind: Kind::Tar,
        triple: "x86_64-unknown-freebsd",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "fnos-x86",
        kind: Kind::Fpk,
        triple: "x86_64-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "fnos-arm",
        kind: Kind::Fpk,
        triple: "aarch64-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "openwrt-amd64",
        kind: Kind::Openwrt,
        triple: "x86_64-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "openwrt-arm64",
        kind: Kind::Openwrt,
        triple: "aarch64-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: None,
    },
    Target {
        id: "openwrt-arm",
        kind: Kind::Openwrt,
        triple: "armv7-unknown-linux-musleabihf",
        runner: Runner::Linux,
        ring_supported: true,
        crypto_note: Some(NOTE_ARM_V7),
    },
    Target {
        id: "openwrt-mipsle",
        kind: Kind::Openwrt,
        triple: "mipsel-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: false,
        crypto_note: Some(NOTE_MIPS_LE),
    },
    Target {
        id: "openwrt-mips",
        kind: Kind::Openwrt,
        triple: "mips-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: false,
        crypto_note: Some(NOTE_MIPS_BE),
    },
    Target {
        id: "openwrt-riscv64",
        kind: Kind::Openwrt,
        triple: "riscv64gc-unknown-linux-musl",
        runner: Runner::Linux,
        ring_supported: false,
        crypto_note: Some(NOTE_RISCV64),
    },
];

impl Target {
    pub fn is_windows(&self) -> bool {
        self.id.starts_with("windows-")
    }

    /// Executable filename bundled inside archives and staged packages.
    pub fn exe_name(&self) -> &'static str {
        if self.is_windows() {
            "fgate.exe"
        } else {
            "fgate"
        }
    }

    pub fn is_linux_musl(&self) -> bool {
        self.triple.ends_with("-linux-musl") || self.triple.ends_with("-linux-musleabihf")
    }

    pub fn is_mips_softfloat(&self) -> bool {
        self.triple.starts_with("mips-") || self.triple.starts_with("mipsel-")
    }
}

/// Looks up a target by its upstream ID.
pub fn find_target(id: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|target| target.id == id)
}

/// Parses a comma-separated list of target IDs or `"all"`.
pub fn parse_targets(spec: &str) -> Result<Vec<&'static Target>> {
    let spec = spec.trim();
    if spec.is_empty() || spec == "all" {
        return Ok(TARGETS.iter().collect());
    }
    let mut selected = Vec::new();
    for raw in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let Some(target) = find_target(raw) else {
            let known: Vec<&str> = TARGETS.iter().map(|t| t.id).collect();
            bail!("unknown target `{raw}`; known: {}", known.join(", "));
        };
        if !selected
            .iter()
            .any(|existing: &&Target| existing.id == target.id)
        {
            selected.push(target);
        }
    }
    Ok(selected)
}

/// Release tarball filename: `fgate_<ver>_<os>_<arch>.tar.gz` (WP-92 §3.2).
pub fn tar_asset_name(version: &str, target: &str) -> String {
    let os_arch = target.replace('-', "_");
    format!("fgate_{version}_{os_arch}.tar.gz")
}

/// Custom/local build artifact filename:
/// `fgate_<ver>_<profile>_<target>.tar.gz` or `.fpk` for `fnos-*` targets (WP-92 §3.2).
pub fn local_asset_name(version: &str, profile: &str, target: &str) -> String {
    let ext = match find_target(target) {
        Some(t) if t.kind == Kind::Fpk => "fpk",
        None if target.starts_with("fnos-") => "fpk",
        _ => "tar.gz",
    };
    format!("fgate_{version}_{profile}_{target}.{ext}")
}
