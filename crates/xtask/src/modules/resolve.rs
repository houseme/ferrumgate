//! `xtask modules resolve`: validates the requested module set, language tier
//! and targets, expands build-time dependencies transitively, and prints one
//! line of JSON with the included modules, the automatically added ones, the
//! Cargo arguments, the feature list, the language tier and the build profile
//! key (the port of upstream `tools/custombuild`).

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::manifest::Manifest;

#[derive(Debug, Default)]
pub struct ResolveOptions {
    /// Comma separated module ids, `all`, or empty for core only.
    pub modules: Option<String>,
    /// Language tier id; defaults to the `lang-all` tier.
    pub lang: Option<String>,
    /// Comma separated target ids or `all`; validated, not part of the output.
    pub targets: Option<String>,
    /// Preset id: a shorthand for a module list; mutually exclusive with
    /// `--modules`.
    pub preset: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Resolved {
    /// Requested plus dependency-expanded optional modules, manifest order.
    pub included: Vec<String>,
    /// Modules pulled in only by `requires`, manifest order.
    pub added: Vec<String>,
    pub cargo_args: Vec<String>,
    /// The `mod-*` and `lang-*` features encoded in `cargo_args`.
    pub features: Vec<String>,
    pub lang: String,
    /// `sha256("lang=<tier>;modules=<sorted modules>")[..12]` (upstream).
    pub profile: String,
}

pub fn resolve(
    manifest: &Manifest,
    options: &ResolveOptions,
    implemented: &[String],
) -> Result<Resolved> {
    ensure!(
        !(options.preset.is_some() && options.modules.is_some()),
        "use --modules or --preset, not both"
    );

    let requested: Vec<String> = match options.preset.as_deref() {
        Some(preset_id) => {
            let preset = manifest.preset(preset_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown preset `{preset_id}`; known: {}",
                    known_ids(manifest.preset.iter().map(|preset| &preset.id))
                )
            })?;
            preset.modules.clone()
        }
        None => parse_module_spec(manifest, options.modules.as_deref().unwrap_or("all"))?,
    };

    // Expand `requires` transitively. Runtime-only dependencies of core
    // modules (webservice -> ssl/waf) are ignored: core modules are always
    // compiled and optional providers are allowed to be absent.
    let mut chosen: BTreeSet<String> = requested.iter().cloned().collect();
    loop {
        let snapshot: Vec<String> = chosen.iter().cloned().collect();
        let before = chosen.len();
        for id in &snapshot {
            let Some(module) = manifest.module(id) else {
                continue;
            };
            for required in &module.requires {
                let Some(required_module) = manifest.module(required) else {
                    continue;
                };
                if !required_module.core {
                    chosen.insert(required.clone());
                }
            }
        }
        if chosen.len() == before {
            break;
        }
    }

    let included: Vec<String> = manifest
        .optional()
        .map(|module| module.id.clone())
        .filter(|id| chosen.contains(id))
        .collect();
    let added: Vec<String> = included
        .iter()
        .filter(|id| !requested.contains(id))
        .cloned()
        .collect();

    // A request naming modules without crates cannot produce valid Cargo
    // arguments: refuse instead of silently building a different variant.
    let missing: Vec<&str> = included
        .iter()
        .filter(|id| !implemented.iter().any(|known| known == *id))
        .map(|id| id.as_str())
        .collect();
    if !missing.is_empty() {
        bail!(
            "modules not yet implemented in this workspace (no crates/fg-<id>): {}; \
             narrow --modules or implement them first",
            missing.join(", ")
        );
    }

    let lang_id = options
        .lang
        .as_deref()
        .unwrap_or_else(|| manifest.default_language().id.as_str());
    let tier = manifest.language(lang_id).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown language tier `{lang_id}`; known: {}",
            known_ids(manifest.language.iter().map(|tier| &tier.id))
        )
    })?;

    validate_targets(manifest, options.targets.as_deref().unwrap_or("all"))?;

    let mut features: Vec<String> = included.iter().map(|id| format!("mod-{id}")).collect();
    features.push(tier.feature.clone());
    let cargo_args = vec![
        "--no-default-features".to_string(),
        "--features".to_string(),
        features.join(","),
    ];
    let profile = profile_key(lang_id, &included);
    Ok(Resolved {
        included,
        added,
        cargo_args,
        features,
        lang: lang_id.to_string(),
        profile,
    })
}

fn known_ids<'a, I: Iterator<Item = &'a String>>(ids: I) -> String {
    ids.cloned().collect::<Vec<_>>().join(", ")
}

fn parse_module_spec(manifest: &Manifest, spec: &str) -> Result<Vec<String>> {
    let spec = spec.trim();
    if spec == "all" {
        return Ok(manifest
            .optional()
            .map(|module| module.id.to_string())
            .collect());
    }
    let mut requested = Vec::new();
    for token in spec
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let Some(module) = manifest.module(token) else {
            bail!(
                "unknown module `{token}`; `all` selects every optional module, \
                 an empty list selects core only"
            );
        };
        // Core modules are always compiled; passing them is a no-op.
        if module.core {
            continue;
        }
        if !requested.iter().any(|id| id == token) {
            requested.push(token.to_string());
        }
    }
    Ok(requested)
}

fn validate_targets(manifest: &Manifest, spec: &str) -> Result<()> {
    if spec.trim() == "all" {
        return Ok(());
    }
    for token in spec
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        ensure!(
            manifest.target_ids().any(|known| known == token),
            "unknown target `{token}`; run with `--targets all` or see features.toml"
        );
    }
    Ok(())
}

/// Upstream custombuild: `sha256("lang=<tier>;modules=<sorted modules>")[..12]`.
/// Sorting makes the key independent of the order the modules were passed in.
pub fn profile_key(lang: &str, included: &[String]) -> String {
    let mut sorted = included.to_vec();
    sorted.sort();
    let key = format!("lang={lang};modules={}", sorted.join(","));
    let digest = Sha256::digest(key.as_bytes());
    digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Upstream `TestBuildRejectsBadVersion`: versions start with `v` followed by
/// two to four numeric parts.
pub fn version_ok(version: &str) -> bool {
    let Some(rest) = version.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    (2..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

pub fn run(root: &Path, options: &ResolveOptions) -> Result<()> {
    let manifest = Manifest::load(&root.join("features.toml"))?;
    let implemented = super::implemented_modules(root, &manifest);
    let resolved = resolve(&manifest, options, &implemented)?;
    println!("{}", serde_json::to_string(&resolved)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::manifest::{Language, Localized, Module};
    use crate::modules::testing::repo_manifest;

    fn localized() -> Localized {
        Localized {
            zh_cn: "甲".to_string(),
            zh_tw: "甲".to_string(),
            en: "a".to_string(),
        }
    }

    fn module(id: &str, core: bool, requires: &[&str]) -> Module {
        Module {
            id: id.to_string(),
            group: "g".to_string(),
            core,
            requires: requires.iter().map(|id| id.to_string()).collect(),
            tag: (!core).then(|| format!("no_{id}")),
            size_kb: None,
            title: localized(),
            description: localized(),
        }
    }

    fn tier(id: &str, feature: &str, locales: &[&str]) -> Language {
        Language {
            id: id.to_string(),
            feature: feature.to_string(),
            tag: None,
            locales: locales.iter().map(|locale| locale.to_string()).collect(),
            size_kb: None,
        }
    }

    fn chain_manifest() -> Manifest {
        Manifest {
            group: Vec::new(),
            module: vec![
                module("portforward", true, &[]),
                module("aa", false, &["bb"]),
                module("bb", false, &["cc"]),
                module("cc", false, &[]),
            ],
            language: vec![tier("all", "lang-all", &["zh-CN"])],
            target: Vec::new(),
            preset: Vec::new(),
        }
    }

    fn all_optional(manifest: &Manifest) -> Vec<String> {
        manifest
            .optional()
            .map(|module| module.id.clone())
            .collect()
    }

    fn opts(modules: Option<&str>) -> ResolveOptions {
        ResolveOptions {
            modules: modules.map(str::to_string),
            lang: None,
            targets: None,
            preset: None,
        }
    }

    #[test]
    fn resolve_all_empty_core_only_unknown() {
        let manifest = repo_manifest();
        let implemented = all_optional(&manifest);

        let all = resolve(&manifest, &opts(Some("all")), &implemented).unwrap();
        assert_eq!(all.included, implemented);
        assert!(all.added.is_empty());

        let core = resolve(&manifest, &opts(Some("")), &implemented).unwrap();
        assert!(core.included.is_empty());
        assert_eq!(core.features, ["lang-all"]);

        // Core modules and duplicates are ignored; included keeps manifest
        // order (guard precedes cron in the catalog).
        let mixed = resolve(
            &manifest,
            &opts(Some("ssl,portforward,cron,guard,cron")),
            &implemented,
        )
        .unwrap();
        assert_eq!(mixed.included, ["guard", "cron"]);
        assert!(mixed.added.is_empty());

        let error = resolve(&manifest, &opts(Some("nope")), &implemented).unwrap_err();
        assert!(
            error.to_string().contains("unknown module `nope`"),
            "{error}"
        );
    }

    #[test]
    fn resolve_adds_dependencies_transitively() {
        let manifest = chain_manifest();
        let implemented = all_optional(&manifest);
        let resolved = resolve(&manifest, &opts(Some("aa")), &implemented).unwrap();
        assert_eq!(resolved.included, ["aa", "bb", "cc"]);
        assert_eq!(resolved.added, ["bb", "cc"]);

        // Real manifest: backup requires storage (single level today).
        let repo = repo_manifest();
        let implemented = all_optional(&repo);
        let resolved = resolve(&repo, &opts(Some("backup")), &implemented).unwrap();
        assert!(resolved.included.contains(&"backup".to_string()));
        assert!(resolved.included.contains(&"storage".to_string()));
        assert_eq!(resolved.added, ["storage"]);
    }

    #[test]
    fn resolve_unknown_lang_and_target() {
        let manifest = repo_manifest();
        let implemented = all_optional(&manifest);

        let options = ResolveOptions {
            modules: Some("cron".to_string()),
            lang: Some("klingon".to_string()),
            targets: None,
            preset: None,
        };
        let error = resolve(&manifest, &options, &implemented).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unknown language tier `klingon`"),
            "{error}"
        );

        let options = ResolveOptions {
            modules: Some("cron".to_string()),
            lang: None,
            targets: Some("linux-arm64,nope".to_string()),
            preset: None,
        };
        let error = resolve(&manifest, &options, &implemented).unwrap_err();
        assert!(
            error.to_string().contains("unknown target `nope`"),
            "{error}"
        );

        let options = ResolveOptions {
            modules: Some("cron".to_string()),
            lang: None,
            targets: Some("all".to_string()),
            preset: None,
        };
        assert!(resolve(&manifest, &options, &implemented).is_ok());
    }

    #[test]
    fn resolve_profile_is_stable_hash() {
        let manifest = chain_manifest();
        let implemented = all_optional(&manifest);
        let first = resolve(&manifest, &opts(Some("aa")), &implemented).unwrap();
        let second = resolve(&manifest, &opts(Some("cc,aa")), &implemented).unwrap();
        assert_eq!(first.profile, second.profile);
        assert_eq!(first.profile.len(), 12);
        assert!(first.profile.bytes().all(|byte| byte.is_ascii_hexdigit()));

        // Golden values for the empty and a two-module selection.
        let core_only = resolve(&manifest, &opts(Some("")), &implemented).unwrap();
        assert_eq!(core_only.profile, "48101df46283");
        assert_eq!(
            profile_key("cjk-en", &["guard".to_string(), "cron".to_string()]),
            "38c0084cbdde"
        );
    }

    #[test]
    fn resolve_presets_expand_to_module_lists() {
        let manifest = repo_manifest();
        let implemented = all_optional(&manifest);

        let minimal = ResolveOptions {
            preset: Some("minimal".to_string()),
            ..ResolveOptions::default()
        };
        let resolved = resolve(&manifest, &minimal, &implemented).unwrap();
        assert!(resolved.included.is_empty());

        let router = ResolveOptions {
            preset: Some("router".to_string()),
            ..ResolveOptions::default()
        };
        let resolved = resolve(&manifest, &router, &implemented).unwrap();
        assert_eq!(resolved.included.len(), 10);
        assert!(resolved.added.is_empty());

        let nas = ResolveOptions {
            preset: Some("nas".to_string()),
            ..ResolveOptions::default()
        };
        let resolved = resolve(&manifest, &nas, &implemented).unwrap();
        assert_eq!(resolved.included.len(), 20);
        // nas = router plus ten storage/tool modules.
        for id in manifest.preset("router").unwrap().modules.clone() {
            assert!(
                resolved.included.contains(&id),
                "nas extends router: missing {id}"
            );
        }
        assert!(resolved_has(&manifest, "nas", "tailscale"));
        assert!(!resolved_has(&manifest, "nas", "netbird"));

        let unknown = ResolveOptions {
            preset: Some("tiny".to_string()),
            ..ResolveOptions::default()
        };
        let error = resolve(&manifest, &unknown, &implemented).unwrap_err();
        assert!(
            error.to_string().contains("unknown preset `tiny`"),
            "{error}"
        );

        let both = ResolveOptions {
            modules: Some("cron".to_string()),
            preset: Some("router".to_string()),
            ..ResolveOptions::default()
        };
        let error = resolve(&manifest, &both, &implemented).unwrap_err();
        assert!(error.to_string().contains("not both"), "{error}");
    }

    fn resolved_has(manifest: &Manifest, preset: &str, id: &str) -> bool {
        manifest
            .preset(preset)
            .unwrap()
            .modules
            .iter()
            .any(|known| known == id)
    }

    #[test]
    fn resolve_rejects_unimplemented_modules() {
        let manifest = repo_manifest();
        let implemented = vec!["cron".to_string()];
        let error = resolve(&manifest, &opts(Some("cron,guard")), &implemented).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not yet implemented in this workspace (no crates/fg-<id>): guard"),
            "{error}"
        );
        // Implemented modules alone still resolve.
        let resolved = resolve(&manifest, &opts(Some("cron")), &implemented).unwrap();
        assert_eq!(resolved.included, ["cron"]);
    }

    #[test]
    fn resolve_features_and_cargo_args_shape() {
        let manifest = repo_manifest();
        let implemented = all_optional(&manifest);
        let options = ResolveOptions {
            modules: Some("guard".to_string()),
            lang: Some("cjk-en".to_string()),
            targets: None,
            preset: None,
        };
        let resolved = resolve(&manifest, &options, &implemented).unwrap();
        assert_eq!(resolved.features, ["mod-guard", "lang-cjk-en"]);
        assert_eq!(
            resolved.cargo_args,
            [
                "--no-default-features",
                "--features",
                "mod-guard,lang-cjk-en"
            ]
        );
        assert_eq!(resolved.lang, "cjk-en");
    }

    #[test]
    fn version_pattern_two_to_four_parts() {
        for good in ["v1.2", "v1.2.3", "v1.2.3.4", "v10.20.30"] {
            assert!(version_ok(good), "{good} should be accepted");
        }
        for bad in ["1.2.3", "v1", "v", "v1.2.x", "v1..2", "v1.2.3.4.5", "vv1.2"] {
            assert!(!version_ok(bad), "{bad} should be rejected");
        }
    }
}
