//! `xtask ci`: local reproduction of the WP-91 CI jobs.
//!
//! The workflow file (`.github/workflows/ci.yml`) only decides where a job
//! runs, which tools it installs and when it triggers; the check logic lives
//! here so every CI failure can be replayed locally with the same command
//! (WP-91 §3.3「原则」/ §8). The plan order mirrors the doc's local sequence:
//! fmt → clippy → test → modules-check → matrix → each-feature → docs →
//! api-docs, with the external-setup jobs (Docker, Pebble, browser) only
//! requested by `ci --all` and skipped with an explicit reason.

pub mod env;
pub mod jobs;
pub mod matrix;

use std::path::Path;

use anyhow::{Context, Result, bail};

use self::env::Env;
use self::jobs::Job;

pub fn run(root: &Path, args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        // `cargo xtask ci` (no arguments): every job that needs no external
        // setup, in the doc's local-reproduction order (WP-91 §3.3).
        None => run_plan(root, Job::default_plan(), &env::detect()),
        // `--all` additionally requests the jobs that need Docker, Pebble or
        // a browser; missing setups are reported as skips, never silent.
        Some("--all") => run_plan(root, Job::all(), &env::detect()),
        Some("--help" | "-h") => {
            print_help();
            Ok(())
        }
        Some("matrix") => run_matrix(root, &args[1..]),
        Some(name) => {
            let Some(job) = Job::from_name(name) else {
                let known = Job::all()
                    .iter()
                    .map(|job| job.name())
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!("unknown ci job `{name}`; known jobs: {known}");
            };
            let env = env::detect();
            // An explicitly requested job must not silently succeed.
            if let Some(reason) = skip_notice(job, &env) {
                bail!("ci {}: {reason}", job.name());
            }
            job.run(root)
                .with_context(|| format!("ci job `{}` failed", job.name()))
        }
    }
}

fn run_plan(root: &Path, plan: &[Job], env: &Env) -> Result<()> {
    println!("ci: {} job(s) requested", plan.len());
    for &job in plan {
        if let Some(reason) = skip_notice(job, env) {
            println!("ci: skip {} — {reason}", job.name());
            continue;
        }
        println!("ci: {} …", job.name());
        job.run(root)
            .with_context(|| format!("ci job `{}` failed", job.name()))?;
        println!("ci: {} ok", job.name());
    }
    println!("ci: done");
    Ok(())
}

/// Why a job is skipped in a plan run: pending work packages first, plus the
/// concrete external setup it would need once it is wired (WP-91 §3.3:
/// 「需要外部环境的测试：默认跳过并在输出里写明原因」).
fn skip_notice(job: Job, env: &Env) -> Option<String> {
    if job.available() {
        return None;
    }
    let mut reason = job.pending_reason().to_string();
    if let Err(setup) = env.ready_for(job) {
        reason.push_str(&format!(" (external setup also missing: {setup})"));
    }
    Some(reason)
}

/// `ci matrix` runs the build matrix; `ci matrix --json` only prints the
/// expansion for the workflow file to consume via `fromJSON` (WP-91 §3.3/§4).
fn run_matrix(root: &Path, args: &[String]) -> Result<()> {
    let mut json = false;
    for flag in args {
        match flag.as_str() {
            "--json" => json = true,
            other => bail!("ci matrix: unknown flag `{other}`; only --json is supported"),
        }
    }
    if json {
        let expansion = matrix::matrix_json(root)?;
        println!("{}", serde_json::to_string(&expansion)?);
        Ok(())
    } else {
        let job = Job::Matrix;
        job.run(root)
            .with_context(|| format!("ci job `{}` failed", job.name()))
    }
}

fn print_help() {
    println!("usage: cargo xtask ci [job | --all | matrix --json]");
    println!();
    println!("  (no arguments)  run every job that needs no external setup, in the");
    println!("                  WP-91 §3.3 order: fmt → clippy → test → modules-check");
    println!("                  → matrix → each-feature → docs → api-docs");
    println!("  --all           additionally request the jobs that need Docker, Pebble");
    println!("                  or a browser; missing setups are reported as skips");
    println!("  matrix --json   print the build matrix as one line of JSON for the");
    println!("                  workflow file (fromJSON), never hand-written in YAML");
    println!();
    println!("jobs:");
    for job in Job::all() {
        println!(
            "  {:<14} {}",
            job.name(),
            if job.available() { "ready" } else { "pending" }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::testing::repo_root;

    #[test]
    fn plan_skips_pending_jobs_with_reasons() {
        let env = Env {
            has_pebble: false,
            has_docker: false,
            net_test: false,
            lucky_sample: None,
        };
        // Ready jobs never skip.
        assert_eq!(skip_notice(Job::Clippy, &env), None);
        assert_eq!(skip_notice(Job::ModulesCheck, &env), None);
        // Pending jobs skip with the waiting work package named.
        let pebble = skip_notice(Job::Pebble, &env).expect("pebble skips");
        assert!(pebble.contains("WP-32"), "{pebble}");
        // … and the external setup it will need is spelled out too.
        assert!(pebble.contains("GATELY_PEBBLE_BIN"), "{pebble}");
        let smoke = skip_notice(Job::OpenwrtSmoke, &env).expect("openwrt-smoke skips");
        assert!(smoke.contains("WP-92"), "{smoke}");
        assert!(smoke.contains("Docker"), "{smoke}");
    }

    #[test]
    fn workflows_least_privilege() {
        let text =
            std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
        // WP-91 §3.3: continuous integration only needs contents: read, and
        // checkouts must not persist credentials.
        assert!(
            text.contains("permissions:"),
            "ci.yml must declare permissions"
        );
        assert!(
            text.contains("contents: read"),
            "ci.yml must be contents: read"
        );
        for line in text.lines() {
            assert!(
                !line.contains(": write"),
                "the CI workflow must not request write permissions: {line}"
            );
        }
        assert!(
            text.contains("persist-credentials: false"),
            "checkout must not persist credentials"
        );
    }

    #[test]
    fn workflows_pin_actions_to_fixed_refs() {
        // Policy for this repository: actions are pinned to a fixed published
        // version tag (actions/checkout@v4) — full commit SHAs are preferred
        // but the major tag is the accepted minimum; floating refs such as
        // @main are never allowed.
        let text =
            std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
        for line in text
            .lines()
            .map(str::trim_start)
            .filter(|line| line.starts_with("uses:") || line.starts_with("- uses:"))
        {
            let reference = line.trim_start_matches("- ").trim();
            let Some((_, version)) = reference.split_once('@') else {
                panic!("action reference must be pinned with @: {line}");
            };
            assert!(
                !matches!(version, "main" | "master" | ""),
                "action must be pinned to a version tag or commit SHA: {line}"
            );
        }
    }

    #[test]
    fn workflow_jobs_call_xtask_ci_commands() {
        // WP-91 §8: the YAML only names the job; every wired job must run
        // through `cargo xtask ci <job>` so CI is locally reproducible.
        let text =
            std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
        for job in ["fmt", "clippy", "test", "modules-check", "supply-chain"] {
            let expected = format!("cargo run --locked -p xtask -- ci {job}");
            assert!(
                text.contains(&expected),
                "ci.yml must run `{expected}` so CI is locally reproducible"
            );
        }
    }

    #[test]
    fn workflow_supply_chain_pins_tools_and_denies_writes() {
        // WP-91 §3.3: the installed tools are pinned versions, and the job
        // inherits the workflow-wide contents: read.
        let text =
            std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).expect("ci.yml");
        assert!(
            text.contains("cargo-deny@0.22.2,cargo-audit@0.23.0"),
            "the supply-chain job must pin both tool versions: {text}"
        );
        assert!(
            text.contains("taiki-e/install-action@"),
            "tool installation must go through the pinned install action: {text}"
        );
    }
}
