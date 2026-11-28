//! The WP-91 CI jobs and their local equivalents (`cargo xtask ci <job>`).
//!
//! Every job maps to plain Cargo / git commands executed at the workspace
//! root; no logic lives in the workflow's shell snippets (WP-91 §8). Job
//! names are kebab-case and stable — they are what the workflow file and the
//! `ci` plan reference.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::ci::env::has_binary;
use crate::ci::matrix;
use crate::modules::manifest::Manifest;

/// WP-91 §3.4「交付命令」: the exact commands from AGENT.md; the unit tests
/// below pin them so drift on either side fails loudly.
pub const FMT_ARGS: &[&str] = &["fmt", "--all", "--check"];
pub const CLIPPY_ARGS: &[&str] = &[
    "clippy",
    "--workspace",
    "--locked",
    "--all-targets",
    "--",
    "-D",
    "warnings",
];
pub const TEST_ARGS: &[&str] = &["test", "--workspace", "--locked"];
pub const DOC_ARGS: &[&str] = &[
    "doc",
    "--workspace",
    "--locked",
    "--no-deps",
    "--document-private-items",
];
/// `cargo doc` must fail on warnings just like clippy does.
pub const RUSTDOCFLAGS_DENY_WARNINGS: &str = "-D warnings";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    Fmt,
    Clippy,
    Test,
    /// WP-90 puts the manifest consistency check in CI (`modules check`).
    /// Added to the doc's §3.2 enum, which predates that wiring.
    ModulesCheck,
    Matrix,
    EachFeature,
    Cross,
    X86,
    Ui,
    E2e,
    /// §3.2 lists `Deny` and `Audit` separately; §3.3 runs them as one
    /// `supply-chain` job, so the enum follows the job table.
    SupplyChain,
    Docs,
    ApiDocs,
    Msrv,
    Pebble,
    OpenwrtSmoke,
}

impl Job {
    /// All jobs in WP-91 §3.2 order (with `modules-check` after `test`).
    pub fn all() -> &'static [Job] {
        &[
            Job::Fmt,
            Job::Clippy,
            Job::Test,
            Job::ModulesCheck,
            Job::Matrix,
            Job::EachFeature,
            Job::Cross,
            Job::X86,
            Job::Ui,
            Job::E2e,
            Job::SupplyChain,
            Job::Docs,
            Job::ApiDocs,
            Job::Msrv,
            Job::Pebble,
            Job::OpenwrtSmoke,
        ]
    }

    /// WP-91 §3.3「本地复现」: `cargo xtask ci` runs every job that needs no
    /// external setup, in this order.
    pub fn default_plan() -> &'static [Job] {
        &[
            Job::Fmt,
            Job::Clippy,
            Job::Test,
            Job::ModulesCheck,
            Job::Matrix,
            Job::EachFeature,
            Job::Docs,
            Job::ApiDocs,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Job::Fmt => "fmt",
            Job::Clippy => "clippy",
            Job::Test => "test",
            Job::ModulesCheck => "modules-check",
            Job::Matrix => "matrix",
            Job::EachFeature => "each-feature",
            Job::Cross => "cross",
            Job::X86 => "x86",
            Job::Ui => "ui",
            Job::E2e => "e2e",
            Job::SupplyChain => "supply-chain",
            Job::Docs => "docs",
            Job::ApiDocs => "api-docs",
            Job::Msrv => "msrv",
            Job::Pebble => "pebble",
            Job::OpenwrtSmoke => "openwrt-smoke",
        }
    }

    pub fn from_name(name: &str) -> Option<Job> {
        Job::all().iter().copied().find(|job| job.name() == name)
    }

    /// Needs to reach the network for tools or data beyond the Cargo fetch
    /// every job does anyway.
    pub fn needs_network(self) -> bool {
        matches!(
            self,
            Job::Cross
                | Job::X86
                | Job::Ui
                | Job::SupplyChain
                | Job::Msrv
                | Job::Pebble
                | Job::OpenwrtSmoke
        )
    }

    pub fn needs_docker(self) -> bool {
        matches!(self, Job::OpenwrtSmoke)
    }

    /// Whether the job is wired end to end today. Unwired jobs never fail a
    /// plan run — they are skipped with `pending_reason` printed instead
    /// (WP-91 §3.3: skips must be explained, never silent).
    pub fn available(self) -> bool {
        matches!(
            self,
            Job::Fmt
                | Job::Clippy
                | Job::Test
                | Job::ModulesCheck
                | Job::Matrix
                | Job::EachFeature
                | Job::Docs
        )
    }

    /// Why the job is not wired yet; names the work package that delivers it.
    pub fn pending_reason(self) -> &'static str {
        match self {
            Job::Cross => {
                "waiting on WP-92: cross-compilation tool (cargo-zigbuild or cross) to be picked"
            }
            Job::X86 => "waiting on WP-65: the SMB parser crate is not testable on i686 yet",
            Job::Ui => "waiting on WP-80: the trunk-based UI build is not wired yet",
            Job::E2e => "waiting on WP-80: the browser end-to-end cases are not wired yet",
            Job::SupplyChain => {
                "waiting on WP-91 step 5: deny.toml plus cargo-deny / cargo-audit wiring"
            }
            Job::ApiDocs => "waiting on WP-11: `fgate api-docs` snapshot comparison",
            Job::Msrv => {
                "no minimum supported toolchain declared yet; per AGENT.md a lower toolchain must run CI before it is announced"
            }
            Job::Pebble => "waiting on WP-32: the Pebble ACME end-to-end tests",
            Job::OpenwrtSmoke => "waiting on WP-92: the OpenWrt .ipk/.apk packaging",
            _ => "",
        }
    }

    /// Runs the job at the workspace root. Unwired jobs fail loudly; plan
    /// runs consult `available()`/`pending_reason()` instead of calling this.
    pub fn run(self, root: &Path) -> Result<()> {
        if !self.available() {
            bail!(
                "ci {} is not wired yet: {}",
                self.name(),
                self.pending_reason()
            );
        }
        match self {
            Job::Fmt => {
                cargo(root, FMT_ARGS)?;
                let mut git = Command::new("git");
                git.current_dir(root).arg("diff").arg("--check");
                run_command(&mut git, "git diff --check")?;
                if has_binary("actionlint") {
                    let mut actionlint = Command::new("actionlint");
                    actionlint.current_dir(root);
                    run_command(&mut actionlint, "actionlint")?;
                } else {
                    println!(
                        "ci fmt: skip actionlint (not on PATH; the CI fmt job installs a pinned build)"
                    );
                }
            }
            Job::Clippy => cargo(root, CLIPPY_ARGS)?,
            Job::Test => cargo(root, TEST_ARGS)?,
            Job::ModulesCheck => crate::modules::check::run(root)?,
            Job::Matrix => run_matrix_job(root)?,
            Job::EachFeature => run_each_feature_job(root)?,
            Job::Docs => {
                let mut doc = cargo_command(root, DOC_ARGS);
                doc.env("RUSTDOCFLAGS", RUSTDOCFLAGS_DENY_WARNINGS);
                run_command(&mut doc, "cargo doc")?;
            }
            _ => bail!(
                "ci {} is not wired yet: {}",
                self.name(),
                self.pending_reason()
            ),
        }
        Ok(())
    }
}

fn cargo(root: &Path, args: &[&str]) -> Result<()> {
    let mut command = cargo_command(root, args);
    let what = format!("cargo {}", args.join(" "));
    run_command(&mut command, &what)
}

fn cargo_command(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("cargo");
    command.current_dir(root).args(args);
    command
}

fn run_command(command: &mut Command, what: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("failed to spawn `{what}`"))?;
    if !status.success() {
        bail!("`{what}` failed with {status}");
    }
    Ok(())
}

/// `ci matrix`: the six WP-90 builds (restricted to implemented modules,
/// like `modules gen` is) as `cargo check --locked`, plus full tests for the
/// default and `minimal` variants, plus one check per language tier
/// (WP-91 §3.3 job table).
fn run_matrix_job(root: &Path) -> Result<()> {
    let manifest = Manifest::load(&root.join("features.toml"))?;
    let implemented = crate::modules::implemented_modules(root, &manifest);
    let variants = matrix::variants(&manifest, &implemented)?;
    for variant in &variants {
        let mut args: Vec<&str> = vec!["check", "--locked", "-p", "ferrumgate"];
        args.extend(variant.cargo_args.iter().map(String::as_str));
        println!("ci matrix: check {} …", variant.id);
        cargo(root, &args)?;
    }
    for variant in variants.iter().filter(|variant| variant.run_tests) {
        let mut args: Vec<&str> = vec!["test", "--locked", "-p", "ferrumgate"];
        args.extend(variant.cargo_args.iter().map(String::as_str));
        println!("ci matrix: test {} …", variant.id);
        cargo(root, &args)?;
    }
    println!("ci matrix: {} variants ok", variants.len());
    Ok(())
}

/// `ci each-feature`: every optional feature alone (everything else off) must
/// compile, and each feature added on top of the default set must compile too
/// (WP-91 §3.3 job table).
fn run_each_feature_job(root: &Path) -> Result<()> {
    let manifest = Manifest::load(&root.join("features.toml"))?;
    let implemented = crate::modules::implemented_modules(root, &manifest);
    let flags = matrix::each_feature_flags(&implemented);
    println!("ci each-feature: {} optional feature(s)", flags.len());
    for flag in &flags {
        println!("ci each-feature: {flag} alone …");
        cargo(
            root,
            &[
                "check",
                "--locked",
                "-p",
                "ferrumgate",
                "--no-default-features",
                "--features",
                flag,
            ],
        )?;
        println!("ci each-feature: {flag} on top of default …");
        cargo(
            root,
            &["check", "--locked", "-p", "ferrumgate", "--features", flag],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_plan_lists_all_jobs() {
        // WP-91 §6: the job list is pinned so a change here reminds us to
        // update the doc and the workflow.
        let expected = [
            "fmt",
            "clippy",
            "test",
            "modules-check",
            "matrix",
            "each-feature",
            "cross",
            "x86",
            "ui",
            "e2e",
            "supply-chain",
            "docs",
            "api-docs",
            "msrv",
            "pebble",
            "openwrt-smoke",
        ];
        let names: Vec<&str> = Job::all().iter().map(|job| job.name()).collect();
        assert_eq!(names, expected);

        // Names round-trip and are unique.
        for job in Job::all() {
            assert_eq!(Job::from_name(job.name()), Some(*job));
        }
        assert_eq!(Job::from_name("nope"), None);

        // The default plan is the doc's local sequence (plus modules-check,
        // a non-external job) and is a subset of all jobs; it includes every
        // ready job.
        let plan: Vec<&str> = Job::default_plan().iter().map(|job| job.name()).collect();
        assert_eq!(
            plan,
            [
                "fmt",
                "clippy",
                "test",
                "modules-check",
                "matrix",
                "each-feature",
                "docs",
                "api-docs"
            ]
        );
        for job in Job::default_plan() {
            assert!(Job::all().contains(job));
        }
        for job in Job::all() {
            if job.available() {
                assert!(
                    Job::default_plan().contains(job),
                    "{} ready but not planned",
                    job.name()
                );
            }
        }
    }

    #[test]
    fn job_commands_match_the_delivery_conventions() {
        // AGENT.md「交付」/ WP-91 §3.4 — the CI commands must not drift.
        assert_eq!(FMT_ARGS, ["fmt", "--all", "--check"]);
        assert_eq!(
            CLIPPY_ARGS,
            [
                "clippy",
                "--workspace",
                "--locked",
                "--all-targets",
                "--",
                "-D",
                "warnings"
            ]
        );
        assert_eq!(TEST_ARGS, ["test", "--workspace", "--locked"]);
        assert_eq!(
            DOC_ARGS,
            [
                "doc",
                "--workspace",
                "--locked",
                "--no-deps",
                "--document-private-items"
            ]
        );
        assert_eq!(RUSTDOCFLAGS_DENY_WARNINGS, "-D warnings");
    }

    #[test]
    fn unwired_jobs_declare_requirements() {
        for job in Job::all() {
            if job.available() {
                continue;
            }
            let reason = job.pending_reason();
            assert!(
                !reason.is_empty(),
                "{} must explain why it is pending",
                job.name()
            );
        }
        assert!(Job::OpenwrtSmoke.needs_docker());
        assert!(!Job::Clippy.needs_docker());
        assert!(Job::Pebble.needs_network());
        assert!(
            Job::SupplyChain.needs_network(),
            "advisory databases need the network"
        );
        assert!(!Job::Docs.needs_network());
    }
}
