//! Docker Buildx multi-platform image build arguments derived from WP-90
//! `modules resolve` output (WP-92 §2, §3.3, §4, §8).

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::modules::manifest::Manifest;
use crate::modules::resolve::Resolved;
use crate::package::targets::DOCKER_PLATFORMS;

/// Build arguments passed to `deploy/Dockerfile`.
/// Driven exclusively by WP-90's [`Resolved`] plan so module dependency logic
/// is never duplicated inside the `Dockerfile`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DockerBuildArgs {
    /// `true` iff the `docker` management module is selected.
    pub with_docker_cli: bool,
    /// `true` iff `guard` (intrusion prevention) or `stun` is selected.
    pub with_nftables: bool,
    pub ferrumgate_features: String,
    pub ferrumgate_lang: String,
    pub ferrumgate_locales: String,
    pub version: String,
    pub commit: String,
    pub build_date: String,
}

impl DockerBuildArgs {
    /// Computes Docker build args from a WP-90 [`Resolved`] build plan.
    pub fn from_resolved(
        manifest: &Manifest,
        resolved: &Resolved,
        version: &str,
        commit: &str,
        build_date: &str,
    ) -> Self {
        let has_module = |id: &str| resolved.included.iter().any(|item| item == id);
        let with_docker_cli = has_module("docker");
        let with_nftables = has_module("guard") || has_module("stun");
        let locales = manifest
            .language(&resolved.lang)
            .map(|tier| tier.locales.join(","))
            .unwrap_or_default();

        Self {
            with_docker_cli,
            with_nftables,
            ferrumgate_features: resolved.features.join(","),
            ferrumgate_lang: resolved.lang.clone(),
            ferrumgate_locales: locales,
            version: version.to_string(),
            commit: commit.to_string(),
            build_date: build_date.to_string(),
        }
    }

    /// Key-value pairs formatted for `--build-arg KEY=VALUE`.
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "WITH_DOCKER_CLI",
                if self.with_docker_cli { "1" } else { "0" }.to_string(),
            ),
            (
                "WITH_NFTABLES",
                if self.with_nftables { "1" } else { "0" }.to_string(),
            ),
            ("FERRUMGATE_FEATURES", self.ferrumgate_features.clone()),
            ("FERRUMGATE_LANG", self.ferrumgate_lang.clone()),
            ("FERRUMGATE_LOCALES", self.ferrumgate_locales.clone()),
            ("VERSION", self.version.clone()),
            ("COMMIT", self.commit.clone()),
            ("BUILD_DATE", self.build_date.clone()),
        ]
    }
}

/// Complete specification for a `docker buildx build` invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DockerBuildSpec {
    pub dockerfile: String,
    pub platforms: Vec<String>,
    pub tags: Vec<String>,
    pub build_args: DockerBuildArgs,
    pub push: bool,
    pub provenance_max: bool,
    pub sbom: bool,
}

impl DockerBuildSpec {
    pub fn new(build_args: DockerBuildArgs, tags: Vec<String>, push: bool) -> Self {
        Self {
            dockerfile: "deploy/Dockerfile".to_string(),
            platforms: DOCKER_PLATFORMS.iter().map(|p| (*p).to_string()).collect(),
            tags,
            build_args,
            push,
            provenance_max: push,
            sbom: push,
        }
    }
}

/// Builds the argument array for `docker buildx build` (no shell).
pub fn docker_buildx_args(spec: &DockerBuildSpec) -> Vec<String> {
    let mut args = vec![
        "buildx".to_string(),
        "build".to_string(),
        "--file".to_string(),
        spec.dockerfile.clone(),
        "--platform".to_string(),
        spec.platforms.join(","),
    ];

    for (key, value) in spec.build_args.pairs() {
        args.push("--build-arg".to_string());
        args.push(format!("{key}={value}"));
    }

    for tag in &spec.tags {
        args.push("--tag".to_string());
        args.push(tag.clone());
    }

    if spec.sbom {
        args.push("--sbom=true".to_string());
    }
    if spec.provenance_max {
        args.push("--provenance=mode=max".to_string());
    }
    if spec.push {
        args.push("--push".to_string());
    }

    args.push(".".to_string());
    args
}

/// Generates image tags (`<repo>:<ver>` and, for non-prerelease tags, `<repo>:latest`).
pub fn image_tags(version: &str, repos: &[&str], include_latest: bool) -> Vec<String> {
    let clean_ver = version.trim().strip_prefix('v').unwrap_or(version.trim());
    let is_prerelease = clean_ver.contains('-');
    let mut tags = Vec::new();
    for repo in repos {
        tags.push(format!("{repo}:{clean_ver}"));
        if include_latest && !is_prerelease {
            tags.push(format!("{repo}:latest"));
        }
    }
    tags
}

/// Executes `docker buildx build ...` at `root` using an argument array.
pub fn run_docker_buildx(root: &Path, spec: &DockerBuildSpec) -> Result<()> {
    let args = docker_buildx_args(spec);
    let status = Command::new("docker")
        .current_dir(root)
        .args(&args)
        .status()
        .with_context(|| format!("failed to spawn `docker {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`docker {}` exited with {status}", args.join(" "));
    }
    Ok(())
}
