//! `xtask modules check`: consistency between `features.toml`, the generated
//! artifacts (`root Cargo.toml` features, `crates/fg-core/src/features.rs`,
//! `modules.json`) and the optional module crates in the workspace (WP-90
//! step 4, the port of upstream `TestManifestMatchesCode`). Modules listed in
//! the manifest without a crate are reported as planned, not as an error.

use std::path::Path;

use anyhow::{Context, Result};

use super::generate::{render_features_rs, render_modules_json, rewrite_cargo_toml};
use super::manifest::Manifest;

#[derive(Debug, Default, PartialEq)]
pub struct CheckReport {
    pub implemented: Vec<String>,
    pub planned: Vec<String>,
    pub problems: Vec<String>,
}

impl CheckReport {
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

pub fn check(root: &Path) -> Result<CheckReport> {
    let manifest = Manifest::load(&root.join("features.toml"))
        .context("modules check: failed to load features.toml")?;
    let implemented = super::implemented_modules(root, &manifest);
    let planned: Vec<String> = manifest
        .optional()
        .map(|module| module.id.clone())
        .filter(|id| !implemented.contains(id))
        .collect();

    let mut problems = Vec::new();

    // Root Cargo.toml: the gen-owned regions must equal the canonical output.
    let cargo_path = root.join("Cargo.toml");
    let content =
        std::fs::read_to_string(&cargo_path).context("modules check: failed to read Cargo.toml")?;
    if rewrite_cargo_toml(&content, &manifest, &implemented)? != content {
        problems.push(
            "root Cargo.toml: [features] section or optional module dependencies are stale; run `cargo xtask modules gen`"
                .to_string(),
        );
    }

    // crates/fg-core/src/features.rs.
    let features_rs = render_features_rs(&manifest, &implemented);
    match std::fs::read_to_string(root.join("crates/fg-core/src/features.rs")) {
        Ok(text) if text == features_rs => {}
        Ok(_) => problems.push(
            "crates/fg-core/src/features.rs is stale; run `cargo xtask modules gen`".to_string(),
        ),
        Err(_) => problems.push(
            "crates/fg-core/src/features.rs is missing; run `cargo xtask modules gen`".to_string(),
        ),
    }

    // modules.json.
    let modules_json = render_modules_json(&manifest)?;
    match std::fs::read_to_string(root.join("modules.json")) {
        Ok(text) if text == modules_json => {}
        Ok(_) => problems.push("modules.json is stale; run `cargo xtask modules gen`".to_string()),
        Err(_) => {
            problems.push("modules.json is missing; run `cargo xtask modules gen`".to_string())
        }
    }

    Ok(CheckReport {
        implemented,
        planned,
        problems,
    })
}

pub fn run(root: &Path) -> Result<()> {
    let report = check(root)?;
    if !report.planned.is_empty() {
        println!(
            "modules check: planned (manifest lists them, no crate yet): {}",
            report.planned.join(", ")
        );
    }
    if report.is_ok() {
        println!(
            "modules check: ok — {} implemented, {} planned, artifacts up to date",
            report.implemented.len(),
            report.planned.len()
        );
        return Ok(());
    }
    for problem in &report.problems {
        eprintln!("modules check: {problem}");
    }
    anyhow::bail!(
        "modules check found {} problem(s); run `cargo xtask modules gen`",
        report.problems.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::testing::{fixture_root, repo_root};

    #[test]
    fn check_manifest_matches_generated_and_crates() {
        let report = check(&repo_root()).expect("repo check runs");
        assert!(
            report.is_ok(),
            "repo artifacts drifted; run `cargo xtask modules gen`: {:?}",
            report.problems
        );
        assert!(report.implemented.contains(&"cron".to_string()));
        assert!(report.implemented.contains(&"guard".to_string()));
        // Everything except cron/guard is still planned.
        assert_eq!(report.implemented.len() + report.planned.len(), 24);
        assert!(!report.planned.contains(&"cron".to_string()));
        assert!(report.planned.contains(&"protoroute".to_string()));
    }

    #[test]
    fn check_detects_stale_artifacts() {
        // Stale modules.json.
        let temp = tempfile::tempdir().unwrap();
        let root = fixture_root(temp.path(), &["cron", "guard"]);
        let json = root.join("modules.json");
        std::fs::write(
            &json,
            format!("{}\n", std::fs::read_to_string(&json).unwrap()),
        )
        .unwrap();
        let report = check(&root).unwrap();
        assert!(!report.is_ok());
        assert!(
            report.problems[0].contains("modules.json"),
            "{:?}",
            report.problems
        );

        // Stale Cargo.toml features.
        let temp = tempfile::tempdir().unwrap();
        let root = fixture_root(temp.path(), &["cron", "guard"]);
        let cargo = root.join("Cargo.toml");
        let content = std::fs::read_to_string(&cargo).unwrap();
        std::fs::write(
            &cargo,
            content.replace(
                "lang-all = [\"fg-core/lang-all\"]",
                "lang-all = [\"fg-core/lang-all\", \"stale\"]",
            ),
        )
        .unwrap();
        let report = check(&root).unwrap();
        assert!(
            report
                .problems
                .iter()
                .any(|problem| problem.contains("[features]")),
            "{:?}",
            report.problems
        );

        // Missing features.rs.
        let temp = tempfile::tempdir().unwrap();
        let root = fixture_root(temp.path(), &["cron", "guard"]);
        std::fs::remove_file(root.join("crates/fg-core/src/features.rs")).unwrap();
        let report = check(&root).unwrap();
        assert!(
            report
                .problems
                .iter()
                .any(|problem| problem.contains("features.rs is missing")),
            "{:?}",
            report.problems
        );
    }

    #[test]
    fn check_reports_planned_modules_not_errors() {
        let temp = tempfile::tempdir().unwrap();
        // Only fg-guard exists: cron and the rest stay planned, no problem.
        let root = fixture_root(temp.path(), &["guard"]);
        let report = check(&root).unwrap();
        assert!(report.is_ok(), "{:?}", report.problems);
        assert_eq!(report.implemented, ["guard"]);
        assert_eq!(report.planned.len(), 23);
        assert!(report.planned.contains(&"cron".to_string()));
    }
}
