//! WP-90 module manifest commands: `gen` (generate the committed artifacts),
//! `check` (consistency) and `resolve` (build planning JSON).

pub mod check;
// `gen` is a reserved keyword in edition 2024; the file keeps the planned
// `gen.rs` name (plan §3.1).
#[path = "gen.rs"]
pub mod generate;
pub mod manifest;
pub mod resolve;

use std::path::Path;

use anyhow::{Result, bail};

use self::manifest::Manifest;
use self::resolve::ResolveOptions;

/// Optional modules whose `crates/fg-<id>` crate exists, in manifest order.
/// The manifest remains the single source of all 27 modules; modules without
/// a crate are "planned" and get no `mod-*` feature this period (see the
/// deviation note in docs/plan/WP-90-custom-build.md §8).
pub fn implemented_modules(root: &Path, manifest: &Manifest) -> Vec<String> {
    manifest
        .optional()
        .filter(|module| {
            root.join("crates")
                .join(format!("fg-{}", module.id))
                .join("Cargo.toml")
                .is_file()
        })
        .map(|module| module.id.clone())
        .collect()
}

pub fn run(root: &Path, args: &[String]) -> Result<()> {
    let Some(subcommand) = args.first() else {
        bail!("modules: a subcommand is required (gen, check, resolve)");
    };
    match subcommand.as_str() {
        "gen" => {
            expect_no_arguments(args)?;
            generate::run(root)
        }
        "check" => {
            expect_no_arguments(args)?;
            check::run(root)
        }
        "resolve" => resolve::run(root, &parse_resolve_args(&args[1..])?),
        other => bail!("unknown modules subcommand `{other}`; expected gen, check or resolve"),
    }
}

fn expect_no_arguments(args: &[String]) -> Result<()> {
    if args.len() != 1 {
        bail!(
            "modules {} takes no arguments, got {:?}",
            args[0],
            &args[1..]
        );
    }
    Ok(())
}

fn parse_resolve_args(args: &[String]) -> Result<ResolveOptions> {
    let mut options = ResolveOptions::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let Some(value) = args.get(index + 1) else {
            bail!("modules resolve: missing value for {flag}");
        };
        match flag {
            "--modules" => options.modules = Some(value.clone()),
            "--lang" => options.lang = Some(value.clone()),
            "--targets" => options.targets = Some(value.clone()),
            "--preset" => options.preset = Some(value.clone()),
            other => bail!("modules resolve: unknown flag `{other}`"),
        }
        index += 2;
    }
    Ok(options)
}

#[cfg(test)]
pub(crate) mod testing {
    use std::path::{Path, PathBuf};

    use super::generate::{render_features_rs, render_modules_json, rewrite_cargo_toml};
    use super::manifest::Manifest;

    /// The workspace root, derived from this crate's location.
    pub fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("xtask lives at crates/xtask")
            .to_path_buf()
    }

    pub fn repo_manifest() -> Manifest {
        Manifest::load(&repo_root().join("features.toml")).expect("repo features.toml parses")
    }

    /// Minimal root manifest a fixture starts from; gen owns the optional
    /// dep block and the `[features]` section, the rest is context.
    pub const FIXTURE_CARGO_TOML: &str = r#"[package]
name = "ferrumgate"
version = "0.1.0"

[dependencies]
anyhow.workspace = true

[features]

[[bin]]
name = "fgate"
path = "src/main.rs"
"#;

    /// Builds a self-consistent mini workspace in `temp`: the real
    /// features.toml, crate stubs for `implemented`, and freshly generated
    /// artifacts. Tests mutate the copy to exercise drift detection.
    pub fn fixture_root(temp: &Path, implemented: &[&str]) -> PathBuf {
        let repo = repo_root();
        std::fs::copy(repo.join("features.toml"), temp.join("features.toml"))
            .expect("copy features.toml");
        for id in implemented {
            let dir = temp.join("crates").join(format!("fg-{id}"));
            std::fs::create_dir_all(&dir).expect("create crate dir");
            std::fs::write(
                dir.join("Cargo.toml"),
                format!("[package]\nname = \"fg-{id}\"\n"),
            )
            .expect("write crate stub");
        }
        std::fs::create_dir_all(temp.join("crates/fg-core/src")).expect("create fg-core src");
        std::fs::write(temp.join("Cargo.toml"), FIXTURE_CARGO_TOML).expect("write fixture Cargo");

        let manifest = Manifest::load(&temp.join("features.toml")).expect("parse manifest");
        // Normalize to manifest order — the order `implemented_modules` and
        // therefore `check` use.
        let wanted: std::collections::HashSet<&str> = implemented.iter().copied().collect();
        let implemented: Vec<String> = manifest
            .optional()
            .map(|module| module.id.clone())
            .filter(|id| wanted.contains(id.as_str()))
            .collect();
        let cargo = rewrite_cargo_toml(FIXTURE_CARGO_TOML, &manifest, &implemented)
            .expect("rewrite fixture Cargo.toml");
        std::fs::write(temp.join("Cargo.toml"), cargo).expect("write normalized Cargo.toml");
        std::fs::write(
            temp.join("crates/fg-core/src/features.rs"),
            render_features_rs(&manifest, &implemented),
        )
        .expect("write fixture features.rs");
        std::fs::write(
            temp.join("modules.json"),
            render_modules_json(&manifest).expect("render fixture modules.json"),
        )
        .expect("write fixture modules.json");
        temp.to_path_buf()
    }
}
