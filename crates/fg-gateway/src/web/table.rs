//! SiteTable: compiles listener sites into a lookup table (WP-20 step 4).
//! Exact domains go into a hash index, wildcards into a prioritized list,
//! and the default site is a fallback.
#![allow(dead_code)]

use std::collections::HashMap;

use super::domains::{self, Pattern};
use super::model::{Listener, Site};

/// A compiled site: the original config plus pre-parsed domain patterns.
pub struct CompiledSite {
    pub site: Site,
    pub patterns: Vec<Pattern>,
}

impl CompiledSite {
    pub fn compile(site: &Site) -> Self {
        let patterns = site
            .domains
            .iter()
            .filter_map(|domain| domains::normalize_pattern(domain).ok())
            .collect();
        Self {
            site: site.clone(),
            patterns,
        }
    }
}

/// Canonical text length of a normalized pattern; the specificity measure
/// for wildcard ties (mirrors the legacy config sorting by pattern length).
fn pattern_len(pattern: &Pattern) -> usize {
    match pattern {
        Pattern::Exact(text) => text.len(),
        Pattern::Any => 1,
        Pattern::WildcardSubdomain { suffix } => suffix.len() + 2, // "*." + suffix
        Pattern::InLabel {
            before,
            after,
            suffix,
        } => {
            let label = before.len() + 1 + after.len();
            if suffix.is_empty() {
                label
            } else {
                label + 1 + suffix.len()
            }
        }
        Pattern::MiddleLabel { prefix, suffix } => {
            prefix.iter().map(|label| label.len() + 1).sum::<usize>()
                + 1
                + suffix.iter().map(|label| label.len() + 1).sum::<usize>()
        }
        Pattern::TrailingLabels { prefix } => {
            prefix.iter().map(|label| label.len() + 1).sum::<usize>() + 1
        }
    }
}

/// Per-listener site lookup table.
pub struct SiteTable {
    exact: HashMap<Box<str>, usize>,
    wildcards: Vec<(Pattern, usize)>,
    default: Option<usize>,
    sites: Vec<CompiledSite>,
}

impl SiteTable {
    /// Compiles the listener's sites into the lookup table. Disabled sites
    /// are skipped; domain patterns that fail to normalize are dropped
    /// silently (validate reports them). Exact patterns index the site,
    /// first site wins on duplicate domains; wildcard patterns keep config
    /// order; the first enabled site with no domains becomes the default
    /// fallback. `old` allows state reuse (statistics, pools) — unused in
    /// this increment, the parameter is kept for consumers.
    pub fn compile(listener: &Listener, old: Option<&SiteTable>) -> Self {
        let _ = old;
        let mut table = Self {
            exact: HashMap::new(),
            wildcards: Vec::new(),
            default: None,
            sites: Vec::new(),
        };
        for site in &listener.sites {
            if !site.enable {
                continue;
            }
            let index = table.sites.len();
            let compiled = CompiledSite::compile(site);
            if site.domains.is_empty() && table.default.is_none() {
                table.default = Some(index);
            }
            for pattern in &compiled.patterns {
                match pattern {
                    Pattern::Exact(domain) => {
                        table.exact.entry(domain.as_str().into()).or_insert(index);
                    }
                    pattern => table.wildcards.push((pattern.clone(), index)),
                }
            }
            table.sites.push(compiled);
        }
        table
    }

    /// Finds the site index for a host: exact match first, then wildcard
    /// match by specificity (longer pattern wins, mirroring the legacy
    /// wildcard sorting; same length → earlier config order), then the
    /// default site (the first enabled site with empty domains).
    pub fn find(&self, host: &str) -> Option<usize> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(index) = self.exact.get(host.as_str()) {
            return Some(*index);
        }
        let mut best: Option<(usize, usize)> = None; // (pattern length, site index)
        for (pattern, index) in &self.wildcards {
            if domains::capture(pattern, &host).is_some() {
                let len = pattern_len(pattern);
                let better = match best {
                    None => true,
                    Some((best_len, _)) => len > best_len,
                };
                if better {
                    best = Some((len, *index));
                }
            }
        }
        if let Some((_, index)) = best {
            return Some(index);
        }
        self.default
    }

    pub fn site(&self, index: usize) -> &CompiledSite {
        &self.sites[index]
    }

    pub fn len(&self) -> usize {
        self.sites.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(key: &str, enable: bool, domains: &[&str]) -> Site {
        Site {
            key: key.to_string(),
            enable,
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            ..Site::default()
        }
    }

    fn listener(sites: Vec<Site>) -> Listener {
        Listener {
            key: "main".to_string(),
            enable: true,
            sites,
            ..Listener::default()
        }
    }

    #[test]
    fn exact_wins_over_wildcard() {
        let table = SiteTable::compile(
            &listener(vec![
                site("wild", true, &["*.example.com"]),
                site("exact", true, &["example.com"]),
            ]),
            None,
        );
        assert_eq!(table.find("example.com"), Some(1));
        assert_eq!(table.find("sub.example.com"), Some(0));
        assert_eq!(table.find("EXAMPLE.com."), Some(1), "host is normalized");
    }

    #[test]
    fn longer_wildcard_wins() {
        let table = SiteTable::compile(
            &listener(vec![
                site("short", true, &["*.example.com"]),
                site("long", true, &["*.a.example.com"]),
            ]),
            None,
        );
        assert_eq!(table.find("x.a.example.com"), Some(1));
        assert_eq!(table.find("y.example.com"), Some(0));
    }

    #[test]
    fn first_site_wins_on_duplicate_domain() {
        let table = SiteTable::compile(
            &listener(vec![
                site("first", true, &["example.com"]),
                site("second", true, &["example.com"]),
                site("wild-1", true, &["*.dup.test"]),
                site("wild-2", true, &["*.dup.test"]),
            ]),
            None,
        );
        assert_eq!(table.find("example.com"), Some(0));
        assert_eq!(table.find("x.dup.test"), Some(2));
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn default_site_catches_unmatched() {
        let table = SiteTable::compile(
            &listener(vec![
                site("known", true, &["example.com"]),
                site("fallback", true, &[]),
            ]),
            None,
        );
        assert_eq!(table.find("example.com"), Some(0));
        assert_eq!(table.find("other.test"), Some(1));
    }

    #[test]
    fn disabled_sites_excluded() {
        let table = SiteTable::compile(
            &listener(vec![
                site("off-exact", false, &["example.com"]),
                site("off-wild", false, &["*.example.com"]),
                site("off-default", false, &[]),
            ]),
            None,
        );
        assert_eq!(table.find("example.com"), None);
        assert_eq!(table.find("sub.example.com"), None);
        assert_eq!(table.find("anything.test"), None);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn old_table_state_note() {
        let first = SiteTable::compile(&listener(vec![site("a", true, &["a.test"])]), None);
        let second =
            SiteTable::compile(&listener(vec![site("b", true, &["b.test"])]), Some(&first));
        assert_eq!(second.find("b.test"), Some(0));
        assert_eq!(second.find("a.test"), None, "state reuse not wired yet");
    }
}
