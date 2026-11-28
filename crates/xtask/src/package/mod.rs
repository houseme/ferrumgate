//! WP-92 multi-platform build and packaging commands:
//! `cargo xtask package [targets|resolve|build|tar|fpk|openwrt|luci|docker]`.
//!
//! Every external tool (`cargo`, `tar`, `fnpack`, `docker`) is invoked via
//! `std::process::Command` argument arrays — never through shell interpolation.

#![forbid(unsafe_code)]

pub mod build;
pub mod docker;
pub mod fpk;
pub mod luci;
pub mod openwrt;
pub mod tar;
pub mod targets;
pub mod tools;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::ci::env::has_binary;
use crate::modules::implemented_modules;
use crate::modules::manifest::Manifest;
use crate::modules::resolve::{ResolveOptions, resolve};
use crate::package::build::{BuildSpec, build_binary, choose_driver, detect_host_triple};
use crate::package::docker::{
    DockerBuildArgs, DockerBuildSpec, docker_buildx_args, run_docker_buildx,
};
use crate::package::fpk::{FpkPlatform, build_fpk, stage_fpk_project};
use crate::package::luci::stage_luci_tree;
use crate::package::openwrt::{build_openwrt_packages, find_openwrt_arch, stage_openwrt_tree};
use crate::package::tar::build_tar_gz;
use crate::package::targets::{Kind, TARGETS, find_target, parse_targets};

pub fn run(root: &Path, args: &[String]) -> Result<()> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };

    match subcommand {
        "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "targets" => run_targets(&args[1..]),
        "resolve" => {
            let mut forwarded = vec!["resolve".to_string()];
            forwarded.extend_from_slice(&args[1..]);
            crate::modules::run(root, &forwarded)
        }
        "build" => run_build(root, &args[1..]),
        "tar" => run_tar(root, &args[1..]),
        "fpk" => run_fpk(root, &args[1..]),
        "openwrt" => run_openwrt(&args[1..]),
        "luci" => run_luci(&args[1..]),
        "docker" => run_docker(root, &args[1..]),
        other => bail!(
            "unknown package subcommand `{other}`; expected targets, resolve, build, tar, fpk, openwrt, luci or docker"
        ),
    }
}

fn run_targets(args: &[String]) -> Result<()> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other => bail!("package targets: unknown flag `{other}`"),
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(TARGETS)?);
    } else {
        for target in TARGETS {
            let crypto = if target.crypto_supported {
                "aws-lc:configured"
            } else {
                "aws-lc:pending"
            };
            println!(
                "{:<16} {:<8} {:<32} {:<6} {}",
                target.id,
                format!("{:?}", target.kind).to_lowercase(),
                if target.triple.is_empty() {
                    "(multi-arch)"
                } else {
                    target.triple
                },
                format!("{:?}", target.runner).to_lowercase(),
                crypto,
            );
        }
    }
    Ok(())
}

fn run_build(root: &Path, args: &[String]) -> Result<()> {
    let mut version = "v0.1.0".to_string();
    let mut commit = "unknown".to_string();
    let mut build_date = "1970-01-01T00:00:00Z".to_string();
    let mut out_dir = root.join("dist");
    let mut options = ResolveOptions::default();
    let mut target_spec = "all".to_string();
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--skip-ui" => {
                i += 1;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            flag => {
                let value = args
                    .get(i + 1)
                    .with_context(|| format!("package build: missing value for {flag}"))?;
                match flag {
                    "--version" => version = value.clone(),
                    "--commit" => commit = value.clone(),
                    "--build-date" => build_date = value.clone(),
                    "--out" => out_dir = PathBuf::from(value),
                    "--modules" => options.modules = Some(value.clone()),
                    "--preset" => options.preset = Some(value.clone()),
                    "--lang" => options.lang = Some(value.clone()),
                    "--targets" => {
                        options.targets = Some(value.clone());
                        target_spec = value.clone();
                    }
                    other => bail!("package build: unknown flag `{other}`"),
                }
                i += 2;
            }
        }
    }

    let manifest = Manifest::load(&root.join("features.toml"))?;
    let implemented = implemented_modules(root, &manifest);
    let resolved = resolve(&manifest, &options, &implemented)?;
    let selected = parse_targets(&target_spec)?;
    let host = detect_host_triple();
    let has_zigbuild = has_binary("cargo-zigbuild");

    let spec = BuildSpec {
        version,
        commit,
        build_date,
        profile: Some(resolved.profile.clone()),
        resolved,
    };

    for target in selected {
        if target.kind == Kind::Docker {
            println!(
                "package build: skipping `{}` (use `package docker`)",
                target.id
            );
            continue;
        }
        let driver = choose_driver(host.as_deref(), target, has_zigbuild);
        let cargo_args = build::cargo_build_args(&spec, target)?;
        if dry_run {
            println!(
                "dry-run {}: cargo {} (driver={driver:?})",
                target.id,
                cargo_args.join(" ")
            );
            continue;
        }
        let dest_dir = out_dir.join(target.id);
        let built = build_binary(root, &spec, target, &dest_dir, driver)?;
        println!("package build: {} -> {}", target.id, built.display());
    }
    Ok(())
}

fn run_tar(root: &Path, args: &[String]) -> Result<()> {
    let mut binary: Option<PathBuf> = None;
    let mut version: Option<String> = None;
    let mut target_id: Option<String> = None;
    let mut out_dir = root.join("dist");
    let mut profile: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = args
            .get(i + 1)
            .with_context(|| format!("package tar: missing value for {flag}"))?;
        match flag {
            "--binary" => binary = Some(PathBuf::from(value)),
            "--version" => version = Some(value.clone()),
            "--target" => target_id = Some(value.clone()),
            "--out" => out_dir = PathBuf::from(value),
            "--profile" => profile = Some(value.clone()),
            other => bail!("package tar: unknown flag `{other}`"),
        }
        i += 2;
    }

    let binary = binary.context("package tar: --binary is required")?;
    let version = version.context("package tar: --version is required")?;
    let target_id = target_id.context("package tar: --target is required")?;
    let target = find_target(&target_id)
        .with_context(|| format!("package tar: unknown target `{target_id}`"))?;

    let archive = build_tar_gz(
        &binary,
        &root.join("LICENSE"),
        &root.join("README.md"),
        &version,
        target,
        profile.as_deref(),
        &out_dir,
    )?;
    println!("package tar: wrote {}", archive.display());
    Ok(())
}

fn run_fpk(root: &Path, args: &[String]) -> Result<()> {
    let mut binary: Option<PathBuf> = None;
    let mut version: Option<String> = None;
    let mut target_id: Option<String> = None;
    let mut out_dir = root.join("dist");
    let mut fnpack_bin: Option<PathBuf> = None;
    let mut stage_only = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--stage-only" => {
                stage_only = true;
                i += 1;
            }
            flag => {
                let value = args
                    .get(i + 1)
                    .with_context(|| format!("package fpk: missing value for {flag}"))?;
                match flag {
                    "--binary" => binary = Some(PathBuf::from(value)),
                    "--version" => version = Some(value.clone()),
                    "--target" => target_id = Some(value.clone()),
                    "--out" => out_dir = PathBuf::from(value),
                    "--fnpack" => fnpack_bin = Some(PathBuf::from(value)),
                    other => bail!("package fpk: unknown flag `{other}`"),
                }
                i += 2;
            }
        }
    }

    let binary = binary.context("package fpk: --binary is required")?;
    let version = version.context("package fpk: --version is required")?;
    let target_id = target_id.context("package fpk: --target is required")?;
    let platform = FpkPlatform::from_target_id(&target_id)?;
    let stage_dir = out_dir.join(format!("stage-{}", platform.target_id()));
    let template = root.join("deploy/fnos");
    stage_fpk_project(
        template.is_dir().then_some(template.as_path()),
        &binary,
        &version,
        platform,
        &stage_dir,
    )?;

    if stage_only {
        println!("package fpk: staged {}", stage_dir.display());
        return Ok(());
    }

    let fnpack = fnpack_bin.unwrap_or_else(|| PathBuf::from("fnpack"));
    let output_fpk = out_dir.join(format!("fgate_{version}_{}.fpk", platform.target_id()));
    build_fpk(&fnpack, &stage_dir, &output_fpk)?;
    println!("package fpk: wrote {}", output_fpk.display());
    Ok(())
}

fn run_openwrt(args: &[String]) -> Result<()> {
    let mut binary: Option<PathBuf> = None;
    let mut version: Option<String> = None;
    let mut target_id: Option<String> = None;
    let mut out_dir = PathBuf::from("dist");
    let mut stage_only = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--stage-only" => {
                stage_only = true;
                i += 1;
            }
            flag => {
                let value = args
                    .get(i + 1)
                    .with_context(|| format!("package openwrt: missing value for {flag}"))?;
                match flag {
                    "--binary" => binary = Some(PathBuf::from(value)),
                    "--version" => version = Some(value.clone()),
                    "--target" => target_id = Some(value.clone()),
                    "--out" => out_dir = PathBuf::from(value),
                    other => bail!("package openwrt: unknown flag `{other}`"),
                }
                i += 2;
            }
        }
    }

    let binary = binary.context("package openwrt: --binary is required")?;
    let version = version.context("package openwrt: --version is required")?;
    let target_id = target_id.context("package openwrt: --target is required")?;
    let arch = find_openwrt_arch(&target_id)
        .with_context(|| format!("package openwrt: unknown target `{target_id}`"))?;

    let stage_dir = out_dir.join(format!("stage-{}", arch.target_id));
    let parsed_ver = stage_openwrt_tree(&binary, &version, arch, &stage_dir)?;
    if stage_only {
        println!("package openwrt: staged {}", stage_dir.display());
        return Ok(());
    }

    let (ipk, apk) = build_openwrt_packages(&stage_dir, &out_dir, &parsed_ver, arch)?;
    println!(
        "package openwrt: wrote {} and {}",
        ipk.display(),
        apk.display()
    );
    Ok(())
}

fn run_luci(args: &[String]) -> Result<()> {
    let mut version: Option<String> = None;
    let mut out_dir = PathBuf::from("dist");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--stage-only" => {
                i += 1;
            }
            flag => {
                let value = args
                    .get(i + 1)
                    .with_context(|| format!("package luci: missing value for {flag}"))?;
                match flag {
                    "--version" => version = Some(value.clone()),
                    "--out" => out_dir = PathBuf::from(value),
                    other => bail!("package luci: unknown flag `{other}`"),
                }
                i += 2;
            }
        }
    }

    let version = version.context("package luci: --version is required")?;
    let stage_dir = out_dir.join("stage-luci-app-ferrumgate");
    stage_luci_tree(&version, &stage_dir)?;
    println!("package luci: staged {}", stage_dir.display());
    Ok(())
}

fn run_docker(root: &Path, args: &[String]) -> Result<()> {
    let mut version = "v0.1.0".to_string();
    let mut commit = "unknown".to_string();
    let mut build_date = "1970-01-01T00:00:00Z".to_string();
    let mut options = ResolveOptions::default();
    let mut tags = Vec::new();
    let mut push = false;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--push" => {
                push = true;
                i += 1;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            flag => {
                let value = args
                    .get(i + 1)
                    .with_context(|| format!("package docker: missing value for {flag}"))?;
                match flag {
                    "--version" => version = value.clone(),
                    "--commit" => commit = value.clone(),
                    "--build-date" => build_date = value.clone(),
                    "--modules" => options.modules = Some(value.clone()),
                    "--preset" => options.preset = Some(value.clone()),
                    "--lang" => options.lang = Some(value.clone()),
                    "--tag" => tags.push(value.clone()),
                    other => bail!("package docker: unknown flag `{other}`"),
                }
                i += 2;
            }
        }
    }

    let manifest = Manifest::load(&root.join("features.toml"))?;
    let implemented = implemented_modules(root, &manifest);
    let resolved = resolve(&manifest, &options, &implemented)?;
    let build_args =
        DockerBuildArgs::from_resolved(&manifest, &resolved, &version, &commit, &build_date);
    let spec = DockerBuildSpec::new(build_args, tags, push);

    if dry_run {
        println!("docker {}", docker_buildx_args(&spec).join(" "));
        return Ok(());
    }
    run_docker_buildx(root, &spec)
}

fn print_help() {
    println!("usage: cargo xtask package <subcommand> [options]");
    println!();
    println!("subcommands:");
    println!("  targets [--json]          list all 19 release targets and crypto notes");
    println!("  resolve [flags]           resolve modules/features/profile (WP-90)");
    println!("  build [flags]             compile release binaries with version metadata");
    println!("  tar [flags]               create deterministic .tar.gz release archive");
    println!("  fpk [flags]               stage and build fnOS .fpk package");
    println!("  openwrt [flags]           stage and build OpenWrt .ipk/.apk packages");
    println!("  luci [flags]              stage arch-independent luci-app-ferrumgate");
    println!("  docker [flags]            build 3-platform Docker image via buildx");
}
