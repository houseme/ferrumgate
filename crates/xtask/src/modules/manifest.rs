//! Parses and validates `features.toml`, the single source of the module
//! manifest (WP-90). The shape mirrors the upstream `modules.json`: 27
//! modules (3 core + 24 optional) in 6 groups, 3 language tiers, 19 package
//! targets and 3 presets (plan §3.4「上限与默认值」).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

/// Number of modules in the upstream manifest (3 core + 24 optional).
const MODULE_COUNT: usize = 27;
const CORE_COUNT: usize = 3;
const GROUP_COUNT: usize = 6;
const LANGUAGE_COUNT: usize = 3;
const TARGET_COUNT: usize = 19;
const PRESET_COUNT: usize = 3;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub group: Vec<Group>,
    pub module: Vec<Module>,
    #[serde(default)]
    pub language: Vec<Language>,
    #[serde(default)]
    pub target: Vec<Target>,
    #[serde(default)]
    pub preset: Vec<Preset>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub title: Localized,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Localized {
    pub zh_cn: String,
    pub zh_tw: String,
    pub en: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    pub id: String,
    pub group: String,
    pub core: bool,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub size_kb: Option<u32>,
    pub title: Localized,
    pub description: Localized,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Language {
    pub id: String,
    pub feature: String,
    #[serde(default)]
    pub tag: Option<String>,
    pub locales: Vec<String>,
    #[serde(default)]
    pub size_kb: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub id: String,
    #[serde(default)]
    pub modules: Vec<String>,
}

impl Localized {
    fn ensure_non_empty(&self, what: &str) -> Result<()> {
        for (key, text) in [
            ("zh-CN", &self.zh_cn),
            ("zh-TW", &self.zh_tw),
            ("en", &self.en),
        ] {
            ensure!(!text.is_empty(), "{what}: empty {key} text");
        }
        Ok(())
    }
}

impl Manifest {
    /// Loads and validates the manifest from `features.toml`.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let manifest: Self =
            toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
        manifest
            .validate()
            .with_context(|| format!("invalid manifest in {}", path.display()))?;
        Ok(manifest)
    }

    /// Structural validation: field shapes, references and cycles first, the
    /// documented counts last (plan §3.4「上限与默认值」), so small fixtures
    /// report the real problem instead of a count mismatch.
    pub fn validate(&self) -> Result<()> {
        // Groups.
        let mut groups = BTreeSet::new();
        for group in &self.group {
            ensure!(
                groups.insert(group.id.as_str()),
                "duplicate group `{}`",
                group.id
            );
            group
                .title
                .ensure_non_empty(&format!("group `{}`", group.id))?;
        }

        // Modules.
        let mut ids = BTreeSet::new();
        for module in &self.module {
            ensure!(
                is_module_id(&module.id),
                "module id `{}` must match [a-z][a-z0-9]*",
                module.id
            );
            ensure!(
                ids.insert(module.id.as_str()),
                "duplicate module `{}`",
                module.id
            );
            ensure!(
                groups.contains(module.group.as_str()),
                "module `{}`: unknown group `{}`",
                module.id,
                module.group
            );
            module
                .title
                .ensure_non_empty(&format!("module `{}`", module.id))?;
            module
                .description
                .ensure_non_empty(&format!("module `{}`", module.id))?;
            if module.core {
                ensure!(
                    module.tag.is_none(),
                    "core module `{}` must not carry a build tag",
                    module.id
                );
                ensure!(
                    module.size_kb.is_none(),
                    "core module `{}` must not carry size-kb",
                    module.id
                );
            } else {
                let expected = format!("no_{}", module.id);
                ensure!(
                    module.tag.as_deref() == Some(expected.as_str()),
                    "module `{}`: tag must be `{expected}`",
                    module.id
                );
            }
        }

        // Requires: known targets, no self references, no cycles.
        let by_id: HashMap<&str, &Module> =
            self.module.iter().map(|m| (m.id.as_str(), m)).collect();
        for module in &self.module {
            for required in &module.requires {
                ensure!(
                    required != &module.id,
                    "module `{}` requires itself",
                    module.id
                );
                ensure!(
                    by_id.contains_key(required.as_str()),
                    "module `{}`: unknown required module `{}`",
                    module.id,
                    required
                );
            }
        }
        ensure_acyclic(&by_id)?;

        // Language tiers.
        let mut tier_ids = BTreeSet::new();
        let mut features = BTreeSet::new();
        let mut default_tiers = 0;
        for language in &self.language {
            ensure!(
                tier_ids.insert(language.id.as_str()),
                "duplicate language tier `{}`",
                language.id
            );
            ensure!(
                features.insert(language.feature.as_str()),
                "duplicate language feature `{}`",
                language.feature
            );
            ensure!(
                language.feature.starts_with("lang-"),
                "language tier `{}`: feature must start with `lang-`",
                language.id
            );
            ensure!(
                !language.locales.is_empty(),
                "language tier `{}`: no locales",
                language.id
            );
            let mut locales = BTreeSet::new();
            for locale in &language.locales {
                ensure!(
                    locales.insert(locale.as_str()),
                    "language tier `{}`: duplicate locale `{locale}`",
                    language.id
                );
            }
            if language.feature == "lang-all" {
                default_tiers += 1;
                ensure!(
                    language.tag.is_none(),
                    "default language tier `{}` must not carry a tag",
                    language.id
                );
            } else {
                ensure!(
                    language.tag.is_some(),
                    "language tier `{}` must carry a build tag",
                    language.id
                );
            }
        }

        // Targets.
        let mut targets = BTreeSet::new();
        for target in &self.target {
            ensure!(
                targets.insert(target.id.as_str()),
                "duplicate target `{}`",
                target.id
            );
        }

        // Presets: shorthand for lists of optional module ids.
        let mut presets = BTreeSet::new();
        for preset in &self.preset {
            ensure!(
                presets.insert(preset.id.as_str()),
                "duplicate preset `{}`",
                preset.id
            );
            for id in &preset.modules {
                let module = by_id.get(id.as_str()).ok_or_else(|| {
                    anyhow::anyhow!("preset `{}`: unknown module `{id}`", preset.id)
                })?;
                ensure!(
                    !module.core,
                    "preset `{}`: core module `{id}` is always included and cannot be listed",
                    preset.id
                );
            }
        }

        // Counts mirror the upstream manifest (plan §3.4).
        ensure!(
            self.group.len() == GROUP_COUNT,
            "expected {GROUP_COUNT} groups, found {}",
            self.group.len()
        );
        ensure!(
            self.module.len() == MODULE_COUNT,
            "expected {MODULE_COUNT} modules, found {}",
            self.module.len()
        );
        let core = self.module.iter().filter(|module| module.core).count();
        ensure!(
            core == CORE_COUNT,
            "expected {CORE_COUNT} core modules, found {core}"
        );
        ensure!(
            self.language.len() == LANGUAGE_COUNT,
            "expected {LANGUAGE_COUNT} language tiers, found {}",
            self.language.len()
        );
        ensure!(
            default_tiers == 1,
            "expected exactly one language tier with feature `lang-all`, found {default_tiers}"
        );
        ensure!(
            self.target.len() == TARGET_COUNT,
            "expected {TARGET_COUNT} targets, found {}",
            self.target.len()
        );
        ensure!(
            self.preset.len() == PRESET_COUNT,
            "expected {PRESET_COUNT} presets, found {}",
            self.preset.len()
        );
        Ok(())
    }

    pub fn module(&self, id: &str) -> Option<&Module> {
        self.module.iter().find(|module| module.id == id)
    }

    pub fn optional(&self) -> impl Iterator<Item = &Module> {
        self.module.iter().filter(|module| !module.core)
    }

    pub fn core_ids(&self) -> Vec<&str> {
        self.module
            .iter()
            .filter(|module| module.core)
            .map(|module| module.id.as_str())
            .collect()
    }

    pub fn language(&self, id: &str) -> Option<&Language> {
        self.language.iter().find(|tier| tier.id == id)
    }

    /// The tier selected when no `lang-*` feature is given (`lang-all`).
    pub fn default_language(&self) -> &Language {
        self.language
            .iter()
            .find(|tier| tier.feature == "lang-all")
            .expect("validated: exactly one lang-all tier")
    }

    pub fn target_ids(&self) -> impl Iterator<Item = &str> + '_ {
        self.target.iter().map(|target| target.id.as_str())
    }

    pub fn preset(&self, id: &str) -> Option<&Preset> {
        self.preset.iter().find(|preset| preset.id == id)
    }
}

fn is_module_id(id: &str) -> bool {
    let mut chars = id.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// Detects dependency cycles with a colored depth-first walk.
fn ensure_acyclic(by_id: &HashMap<&str, &Module>) -> Result<()> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Open,
        Done,
    }

    // Returns the cycle path when the walk revisits an open node.
    fn visit(
        id: &str,
        by_id: &HashMap<&str, &Module>,
        marks: &mut HashMap<String, Mark>,
        stack: &mut Vec<String>,
    ) -> Result<(), Vec<String>> {
        match marks.get(id) {
            Some(Mark::Done) => return Ok(()),
            Some(Mark::Open) => {
                let mut cycle = stack.clone();
                cycle.push(id.to_string());
                if let Some(start) = cycle.iter().position(|node| node == id) {
                    cycle.drain(..start);
                }
                return Err(cycle);
            }
            None => {}
        }
        marks.insert(id.to_string(), Mark::Open);
        stack.push(id.to_string());
        if let Some(module) = by_id.get(id) {
            for required in &module.requires {
                visit(required, by_id, marks, stack)?;
            }
        }
        stack.pop();
        marks.insert(id.to_string(), Mark::Done);
        Ok(())
    }

    let mut marks = HashMap::new();
    let mut stack = Vec::new();
    for id in by_id.keys() {
        if let Err(cycle) = visit(id, by_id, &mut marks, &mut stack) {
            bail!("dependency cycle: {}", cycle.join(" -> "));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_manifest() -> Manifest {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("xtask lives at crates/xtask")
            .join("features.toml");
        Manifest::load(&path).expect("repo features.toml parses")
    }

    fn manifest_from(text: &str) -> Result<Manifest> {
        let manifest: Manifest = toml::from_str(text)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn optional_module(id: &str, group: &str, requires: &str) -> String {
        format!(
            r#"
            [[module]]
            id = "{id}"
            group = "{group}"
            core = false
            requires = {requires}
            tag = "no_{id}"
            title = {{ zh_cn = "甲", zh_tw = "甲", en = "a" }}
            description = {{ zh_cn = "甲", zh_tw = "甲", en = "a" }}
            "#
        )
    }

    fn group_toml() -> &'static str {
        r#"
        [[group]]
        id = "network"
        title = { zh_cn = "甲", zh_tw = "甲", en = "a" }
        "#
    }

    #[test]
    fn manifest_parses_and_rejects_invalid() {
        let manifest = repo_manifest();
        assert_eq!(manifest.module.len(), 27);
        assert_eq!(manifest.group.len(), 6);
        assert_eq!(manifest.language.len(), 3);
        assert_eq!(manifest.target.len(), 19);
        assert_eq!(manifest.preset.len(), 3);
        assert_eq!(manifest.core_ids(), ["portforward", "ssl", "webservice"]);
        assert_eq!(manifest.optional().count(), 24);
        assert_eq!(manifest.default_language().id, "all");
        assert_eq!(
            manifest.default_language().locales,
            [
                "zh-CN", "zh-TW", "en", "de", "es", "fr", "ja", "ko", "pt-BR", "ru"
            ]
        );
        assert_eq!(manifest.preset("router").unwrap().modules.len(), 10);
        assert_eq!(manifest.preset("nas").unwrap().modules.len(), 20);
        assert_eq!(
            manifest.preset("minimal").unwrap().modules,
            Vec::<String>::new()
        );
        assert_eq!(manifest.language("zh").unwrap().locales, ["zh-CN"]);
        assert_eq!(
            manifest.module("webservice").unwrap().requires,
            ["ssl", "waf"]
        );
        assert_eq!(manifest.module("backup").unwrap().requires, ["storage"]);
        assert!(manifest.module("webdav").unwrap().requires.is_empty());
    }

    #[test]
    fn manifest_rejects_duplicate_module_id() {
        let text = format!(
            "{}{}{}",
            group_toml(),
            optional_module("ddns", "network", "[]"),
            optional_module("ddns", "network", "[]")
        );
        let error = manifest_from(&text).unwrap_err();
        assert!(error.to_string().contains("duplicate module"), "{error}");
    }

    #[test]
    fn manifest_rejects_unknown_group_and_requirement() {
        let error = manifest_from(&format!(
            "{}{}",
            group_toml(),
            optional_module("ddns", "nobody", "[]")
        ))
        .unwrap_err();
        assert!(error.to_string().contains("unknown group"), "{error}");
        let error = manifest_from(&format!(
            "{}{}",
            group_toml(),
            optional_module("ddns", "network", "[\"ssl\"]")
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains("unknown required module"),
            "{error}"
        );
    }

    #[test]
    fn manifest_rejects_dependency_cycle() {
        let text = format!(
            "{}{}{}",
            group_toml(),
            optional_module("aa", "network", "[\"bb\"]"),
            optional_module("bb", "network", "[\"aa\"]")
        );
        let error = manifest_from(&text).unwrap_err();
        assert!(error.to_string().contains("dependency cycle"), "{error}");
    }

    #[test]
    fn manifest_rejects_wrong_tag_and_core_switches() {
        let with_tag = |core: bool, tag: &str| {
            format!(
                r#"
                [[module]]
                id = "ddns"
                group = "network"
                core = {core}
                tag = "{tag}"
                title = {{ zh_cn = "甲", zh_tw = "甲", en = "a" }}
                description = {{ zh_cn = "甲", zh_tw = "甲", en = "a" }}
                "#
            )
        };
        let error =
            manifest_from(&format!("{}{}", group_toml(), with_tag(false, "no_other"))).unwrap_err();
        assert!(
            error.to_string().contains("tag must be `no_ddns`"),
            "{error}"
        );
        let error =
            manifest_from(&format!("{}{}", group_toml(), with_tag(true, "no_ddns"))).unwrap_err();
        assert!(
            error.to_string().contains("must not carry a build tag"),
            "{error}"
        );
    }

    #[test]
    fn manifest_rejects_unknown_preset_module() {
        let text = format!(
            r#"
            {}
            {}
            [[preset]]
            id = "tiny"
            modules = ["nope"]
            "#,
            group_toml(),
            optional_module("ddns", "network", "[]")
        );
        let error = manifest_from(&text).unwrap_err();
        assert!(
            error.to_string().contains("unknown module `nope`"),
            "{error}"
        );
    }
}
