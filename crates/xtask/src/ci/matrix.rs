//! The build-matrix expansion for WP-91: six builds × representative language
//! tiers, one flag per optional feature, and the release cross-compilation
//! targets — all derived from `features.toml` here, never hand-written in the
//! YAML (WP-91 §3.3「特性矩阵的展开」/ §8). The workflow later reads the
//! expansion via `cargo xtask ci matrix --json` + `fromJSON`.

use serde::Serialize;

use crate::modules::manifest::Manifest;
use crate::modules::resolve::{self, ResolveOptions};

/// One entry of the check matrix (WP-91 §3.2 `BuildVariant`).
///
/// Deviation from the doc signature: `id`/`lang` are `String` instead of
/// `&'static str` so the language tiers come from `features.toml` instead of
/// being hardcoded. Like `modules gen`, variants only use modules whose
/// crates exist in the workspace; presets are intersected with the
/// implemented set, so the six ids already exist and grow into the full
/// matrix as modules land.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BuildVariant {
    /// `default | no-default | all | minimal | router | nas` plus
    /// `default-<tier>` for the non-default language tiers.
    pub id: String,
    /// Cargo arguments for `cargo check/test --locked -p ferrumgate`.
    pub cargo_args: Vec<String>,
    /// `default` and `minimal` run the full test suite (WP-91 §3.3).
    pub run_tests: bool,
    /// The language tier id included in this variant (`none` = no tier).
    pub lang: String,
}

/// A release target id from `features.toml` with its Rust triple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CrossTarget {
    pub target: String,
    pub triple: String,
}

/// What `cargo xtask ci matrix --json` prints (one line) for the workflow
/// file; the top-level keys line up with `strategy.matrix.<key>` names.
#[derive(Debug, Serialize)]
pub struct MatrixJson {
    pub variant: Vec<BuildVariant>,
    pub each_feature: Vec<String>,
    pub cross_targets: Vec<CrossTarget>,
}

/// The six WP-90 builds (`--no-default-features`, default, `--all-features`,
/// `minimal`, `router`, `nas`) plus one default-build variant per non-default
/// language tier — the representative combos of「6 种构建 × 3 档语言」
/// (WP-91 §3.2/§3.3).
pub fn variants(manifest: &Manifest, implemented: &[String]) -> anyhow::Result<Vec<BuildVariant>> {
    let default_tier = manifest.default_language();
    let mut variants = vec![
        BuildVariant {
            id: "default".to_string(),
            cargo_args: Vec::new(),
            run_tests: true,
            lang: default_tier.id.clone(),
        },
        BuildVariant {
            id: "no-default".to_string(),
            cargo_args: vec!["--no-default-features".to_string()],
            run_tests: false,
            lang: "none".to_string(),
        },
        BuildVariant {
            id: "all".to_string(),
            cargo_args: vec!["--all-features".to_string()],
            run_tests: false,
            lang: default_tier.id.clone(),
        },
    ];
    variants.push(preset_variant(manifest, implemented, "minimal", true)?);
    variants.push(preset_variant(manifest, implemented, "router", false)?);
    variants.push(preset_variant(manifest, implemented, "nas", false)?);
    for tier in &manifest.language {
        if tier.feature == default_tier.feature {
            continue;
        }
        variants.push(BuildVariant {
            id: format!("default-{}", tier.id),
            cargo_args: vec!["--features".to_string(), tier.feature.clone()],
            run_tests: false,
            lang: tier.id.clone(),
        });
    }
    Ok(variants)
}

/// A preset variant, restricted to implemented modules and expanded through
/// the same `modules resolve` code path the packaging uses, so the Cargo
/// arguments cannot drift from WP-90.
fn preset_variant(
    manifest: &Manifest,
    implemented: &[String],
    preset_id: &str,
    run_tests: bool,
) -> anyhow::Result<BuildVariant> {
    let preset = manifest
        .preset(preset_id)
        .ok_or_else(|| anyhow::anyhow!("unknown preset `{preset_id}`"))?;
    let selectable: Vec<String> = preset
        .modules
        .iter()
        .filter(|id| implemented.contains(id))
        .cloned()
        .collect();
    let resolved = resolve::resolve(
        manifest,
        &ResolveOptions {
            modules: Some(selectable.join(",")),
            ..ResolveOptions::default()
        },
        implemented,
    )?;
    Ok(BuildVariant {
        id: preset_id.to_string(),
        cargo_args: resolved.cargo_args,
        run_tests,
        lang: resolved.lang,
    })
}

/// `--features` values for the `each-feature` job: exactly one per optional
/// module implemented in this workspace (planned modules have no feature to
/// enable yet, WP-91 §6 `each_feature_flags_one_per_optional_module`).
pub fn each_feature_flags(implemented: &[String]) -> Vec<String> {
    implemented.iter().map(|id| format!("mod-{id}")).collect()
}

/// The release target table (WP-91 §3.2 `cross_targets`). The triples are
/// provisional until WP-92 picks `cargo-zigbuild` vs `cross` and finalizes
/// gnu/musl per target; the ids come from `features.toml`, which is already
/// the single source. `docker` is a container build, not a Rust triple.
pub fn cross_targets(manifest: &Manifest) -> anyhow::Result<Vec<CrossTarget>> {
    const TRIPLES: &[(&str, &str)] = &[
        ("linux-amd64", "x86_64-unknown-linux-musl"),
        ("linux-arm64", "aarch64-unknown-linux-musl"),
        ("linux-arm", "arm-unknown-linux-musleabihf"),
        ("linux-mipsle", "mipsel-unknown-linux-musl"),
        ("linux-mips", "mips-unknown-linux-musl"),
        ("linux-riscv64", "riscv64gc-unknown-linux-musl"),
        ("windows-amd64", "x86_64-pc-windows-msvc"),
        ("darwin-amd64", "x86_64-apple-darwin"),
        ("darwin-arm64", "aarch64-apple-darwin"),
        ("freebsd-amd64", "x86_64-unknown-freebsd"),
        ("fnos-x86", "x86_64-unknown-linux-gnu"),
        ("fnos-arm", "aarch64-unknown-linux-gnu"),
        ("openwrt-amd64", "x86_64-unknown-linux-musl"),
        ("openwrt-arm64", "aarch64-unknown-linux-musl"),
        ("openwrt-arm", "arm-unknown-linux-musleabihf"),
        ("openwrt-mipsle", "mipsel-unknown-linux-musl"),
        ("openwrt-mips", "mips-unknown-linux-musl"),
        ("openwrt-riscv64", "riscv64gc-unknown-linux-musl"),
    ];
    let mut targets = Vec::new();
    for id in manifest.target_ids() {
        if id == "docker" {
            continue;
        }
        let triple = TRIPLES
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, triple)| *triple)
            .ok_or_else(|| anyhow::anyhow!("target `{id}` has no Rust triple mapping"))?;
        targets.push(CrossTarget {
            target: id.to_string(),
            triple: triple.to_string(),
        });
    }
    Ok(targets)
}

/// The full expansion printed by `ci matrix --json`.
pub fn matrix_json(root: &std::path::Path) -> anyhow::Result<MatrixJson> {
    let manifest = Manifest::load(&root.join("features.toml"))?;
    let implemented = crate::modules::implemented_modules(root, &manifest);
    Ok(MatrixJson {
        variant: variants(&manifest, &implemented)?,
        each_feature: each_feature_flags(&implemented),
        cross_targets: cross_targets(&manifest)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::implemented_modules;
    use crate::modules::testing::{repo_manifest, repo_root};

    fn repo_variants() -> Vec<BuildVariant> {
        let manifest = repo_manifest();
        let implemented = implemented_modules(&repo_root(), &manifest);
        variants(&manifest, &implemented).expect("variants expand")
    }

    fn mod_features(variant: &BuildVariant) -> Vec<String> {
        variant
            .cargo_args
            .iter()
            .filter(|arg| arg.contains("mod-"))
            .flat_map(|arg| arg.split(','))
            .filter(|feature| feature.starts_with("mod-"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn matrix_variants_match_manifest() {
        let manifest = repo_manifest();
        let implemented = implemented_modules(&repo_root(), &manifest);
        let variants = repo_variants();

        // The six canonical builds first, then one variant per non-default
        // language tier (cjk-en, zh).
        let ids: Vec<&str> = variants.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "default",
                "no-default",
                "all",
                "minimal",
                "router",
                "nas",
                "default-cjk-en",
                "default-zh"
            ]
        );

        let by_id = |id: &str| variants.iter().find(|v| v.id == id).expect(id);
        // Default build = everything, tested.
        let default = by_id("default");
        assert!(default.cargo_args.is_empty());
        assert!(default.run_tests);
        assert_eq!(default.lang, manifest.default_language().id);
        // Core only, no language tier.
        let no_default = by_id("no-default");
        assert_eq!(no_default.cargo_args, ["--no-default-features"]);
        assert_eq!(no_default.lang, "none");
        assert!(!no_default.run_tests);
        // All features on.
        assert_eq!(by_id("all").cargo_args, ["--all-features"]);

        // Presets come from the same resolve path as packaging: minimal is
        // core + the default tier and is tested in full; router/nas are
        // restricted to implemented modules until their crates exist.
        let minimal = by_id("minimal");
        assert_eq!(
            minimal.cargo_args,
            ["--no-default-features", "--features", "lang-all"]
        );
        assert!(minimal.run_tests);
        let implemented_set: std::collections::BTreeSet<&String> = implemented.iter().collect();
        for id in ["router", "nas"] {
            let variant = by_id(id);
            assert!(!variant.run_tests);
            let preset_ids: std::collections::BTreeSet<String> = manifest
                .preset(id)
                .expect("preset")
                .modules
                .iter()
                .filter(|module| implemented.contains(module))
                .cloned()
                .collect();
            let features = mod_features(variant);
            let selected: std::collections::BTreeSet<String> = features
                .iter()
                .map(|feature| feature.trim_start_matches("mod-").to_string())
                .collect();
            let expected: std::collections::BTreeSet<String> = implemented
                .iter()
                .filter(|module| preset_ids.contains(*module))
                .cloned()
                .collect();
            assert_eq!(selected, expected);
            // Every emitted feature exists in this workspace.
            for feature in &features {
                assert!(
                    implemented_set.contains(&feature.trim_start_matches("mod-").to_string()),
                    "{feature} is not implemented"
                );
            }
            // Presets resolve to the default language tier (`lang-all` rides
            // in the comma-joined --features value).
            assert!(
                variant
                    .cargo_args
                    .iter()
                    .any(|arg| arg.split(',').any(|feature| feature == "lang-all")),
                "{:?}",
                variant.cargo_args
            );
        }

        // One extra check per non-default language tier.
        assert_eq!(
            by_id("default-cjk-en").cargo_args,
            ["--features", "lang-cjk-en"]
        );
        assert_eq!(by_id("default-cjk-en").lang, "cjk-en");
        assert_eq!(by_id("default-zh").cargo_args, ["--features", "lang-zh-cn"]);
    }

    #[test]
    fn each_feature_flags_one_per_optional_module() {
        let manifest = repo_manifest();
        let implemented = implemented_modules(&repo_root(), &manifest);
        let flags = each_feature_flags(&implemented);
        assert_eq!(
            flags.len(),
            implemented.len(),
            "one flag per implemented module"
        );
        for (flag, id) in flags.iter().zip(implemented.iter()) {
            assert_eq!(flag, &format!("mod-{id}"));
        }
        // Flags must be usable alone: none of them may list two features.
        assert!(flags.iter().all(|flag| !flag.contains(',')));
    }

    #[test]
    fn cross_targets_cover_release_matrix() {
        let manifest = repo_manifest();
        let targets = cross_targets(&manifest).expect("cross targets");
        // Every non-docker target id is covered exactly once, in manifest
        // order; docker is a container build (WP-92), not a Rust triple.
        let expected: Vec<&str> = manifest.target_ids().filter(|id| *id != "docker").collect();
        let got: Vec<&str> = targets.iter().map(|t| t.target.as_str()).collect();
        assert_eq!(got, expected);
        assert_eq!(targets.len(), 18);
        assert!(targets.iter().all(|t| !t.triple.is_empty()));
        assert!(
            targets
                .iter()
                .any(|t| t.target == "linux-arm64" && t.triple == "aarch64-unknown-linux-musl"),
            "linux/arm64 musl is the size-baseline target (WP-90)"
        );
    }

    #[test]
    fn matrix_json_is_workflow_ready() {
        let root = repo_root();
        let json = matrix_json(&root).expect("matrix json");
        let text = serde_json::to_string(&json).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(
            value["variant"].as_array().expect("variant list").len(),
            json.variant.len()
        );
        assert_eq!(
            value["each_feature"].as_array().expect("flags").len(),
            implemented_modules(&root, &repo_manifest()).len()
        );
        assert_eq!(
            value["cross_targets"].as_array().expect("targets").len(),
            18
        );
    }
}
