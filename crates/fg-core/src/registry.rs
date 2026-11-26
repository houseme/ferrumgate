use anyhow::{Result, bail, ensure};

#[derive(Debug)]
pub struct Localized {
    pub zh_cn: &'static str,
    pub zh_tw: &'static str,
    pub en: &'static str,
}

#[derive(Debug)]
pub struct ModuleInfo {
    pub id: &'static str,
    pub group: &'static str,
    pub core: bool,
    pub requires: &'static [&'static str],
    pub tag: Option<&'static str>,
    pub size_kb: Option<u32>,
    pub title: Localized,
    pub description: Localized,
}

include!(concat!(env!("OUT_DIR"), "/catalog.rs"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Enabled,
    Disabled,
    Absent,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Required {
    pub id: &'static str,
    pub by: Vec<&'static str>,
}

#[derive(Debug)]
pub struct Enabled {
    ids: Vec<&'static str>,
    pub restored: Vec<Required>,
}

impl Enabled {
    pub fn contains(&self, id: &str) -> bool {
        self.ids.contains(&id)
    }
}

pub struct Registry {
    built: &'static [&'static str],
}

impl Registry {
    pub const fn new(built: &'static [&'static str]) -> Self {
        Self { built }
    }

    pub fn absent(&self) -> impl Iterator<Item = &'static ModuleInfo> {
        CATALOG
            .iter()
            .filter(|module| !self.built.contains(&module.id))
    }

    pub fn status(&self, enabled: &Enabled, id: &str) -> Option<Status> {
        CATALOG.iter().find(|module| module.id == id).map(|module| {
            if !self.built.contains(&module.id) {
                Status::Absent
            } else if enabled.contains(module.id) {
                Status::Enabled
            } else {
                Status::Disabled
            }
        })
    }

    pub fn requires(&self, id: &str) -> impl Iterator<Item = &'static str> {
        CATALOG
            .iter()
            .find(|module| module.id == id && self.built.contains(&module.id))
            .into_iter()
            .flat_map(|module| module.requires.iter().copied())
            .filter(|dependency| self.built.contains(dependency))
    }

    pub fn resolve_enabled(&self, disabled: &[String], https_listen: bool) -> Enabled {
        let mut ids = self.enabled_ids(disabled);
        let mut restored = Vec::new();
        loop {
            let previously_restored = restored.len();
            for &id in self.built {
                if ids.contains(&id) {
                    continue;
                }
                let by = required_by(id, &ids, https_listen);
                if !by.is_empty() {
                    ids.push(id);
                    restored.push(Required { id, by });
                }
            }
            if restored.len() == previously_restored {
                return Enabled { ids, restored };
            }
        }
    }

    pub fn validate_disabled(&self, disabled: &[String], https_listen: bool) -> Result<()> {
        let enabled = self.enabled_ids(disabled);
        for id in disabled {
            ensure!(
                CATALOG.iter().any(|module| module.id == id),
                "unknown module in disabled list"
            );
            if self.built.contains(&id.as_str()) {
                let by = required_by(id, &enabled, https_listen);
                if !by.is_empty() {
                    bail!("cannot disable module {id}: required by {}", by.join(", "));
                }
            }
        }
        Ok(())
    }

    pub fn keep_absent_disabled(&self, old: &[String], next: &mut Vec<String>) {
        for id in old {
            if self.absent().any(|module| module.id == id) && !next.contains(id) {
                next.push(id.clone());
            }
        }
    }

    fn enabled_ids(&self, disabled: &[String]) -> Vec<&'static str> {
        self.built
            .iter()
            .copied()
            .filter(|id| !disabled.iter().any(|off| off == id))
            .collect()
    }
}

fn required_by(id: &str, enabled: &[&str], https_listen: bool) -> Vec<&'static str> {
    let mut by: Vec<_> = CATALOG
        .iter()
        .filter(|module| enabled.contains(&module.id) && module.requires.contains(&id))
        .map(|module| module.id)
        .collect();
    if id == "ssl" && https_listen {
        by.push("admin HTTPS");
    }
    by
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY: Registry = Registry::new(&["portforward", "ssl", "webservice"]);

    #[test]
    fn catalog_lists_core_and_unbuilt_modules_in_order() {
        assert_eq!(CATALOG.len(), 27);
        let core: Vec<_> = CATALOG
            .iter()
            .filter(|module| module.core)
            .map(|module| module.id)
            .collect();
        assert_eq!(core, ["portforward", "ssl", "webservice"]);
        assert_eq!(REGISTRY.absent().count(), 24);
        assert_eq!(REGISTRY.absent().next().unwrap().id, "protoroute");
        assert_eq!(REGISTRY.requires("webservice").collect::<Vec<_>>(), ["ssl"]);
    }

    #[test]
    fn disabled_list_keeps_required_modules_and_distinguishes_status() {
        let disabled = ["ssl".into(), "portforward".into(), "waf".into()];
        let error = REGISTRY
            .validate_disabled(&disabled, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("ssl") && error.contains("webservice"));
        let enabled = REGISTRY.resolve_enabled(&disabled, false);
        assert_eq!(
            enabled.restored,
            [Required {
                id: "ssl",
                by: vec!["webservice"]
            }]
        );
        assert_eq!(REGISTRY.status(&enabled, "ssl"), Some(Status::Enabled));
        assert_eq!(
            REGISTRY.status(&enabled, "portforward"),
            Some(Status::Disabled)
        );
        assert_eq!(REGISTRY.status(&enabled, "waf"), Some(Status::Absent));
        assert_eq!(REGISTRY.status(&enabled, "unknown"), None);
        assert!(
            REGISTRY
                .validate_disabled(&["unknown".into()], false)
                .is_err()
        );
    }

    #[test]
    fn management_tls_keeps_ssl_when_web_is_disabled() -> Result<()> {
        let disabled = ["ssl".into(), "webservice".into(), "waf".into()];
        REGISTRY.validate_disabled(&disabled, false)?;
        assert!(REGISTRY.validate_disabled(&disabled, true).is_err());
        let enabled = REGISTRY.resolve_enabled(&disabled, true);
        assert_eq!(
            enabled.restored,
            [Required {
                id: "ssl",
                by: vec!["admin HTTPS"]
            }]
        );
        Ok(())
    }

    #[test]
    fn old_switches_are_preserved_only_for_known_absent_modules() {
        let mut next = vec!["portforward".into(), "waf".into()];
        REGISTRY.keep_absent_disabled(
            &["ddns".into(), "waf".into(), "ssl".into(), "unknown".into()],
            &mut next,
        );
        assert_eq!(next, ["portforward", "waf", "ddns"]);
    }
}
