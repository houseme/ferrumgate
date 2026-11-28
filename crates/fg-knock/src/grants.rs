//! The in-process grant registry (WP-54 §3.3 "授权登记表"): authorizations
//! produced by SPA packets, consulted lock-free by Gately entrances that
//! require a knock (port forwarding, protocol routing, STUN, web sites).
//!
//! This is the fg-knock-local slice of the `knockgate` registry described
//! in the plan: WP-01 will hoist it into `fg-core::knockgate` so modules
//! that cannot depend on the optional `fg-knock` crate can query it
//! (wiring point — see `lib.rs::Deps`). Web-login grants (`GrantSource::Web`,
//! WP-26) are carried by the shared registry once it exists; this local
//! table stores only `Knock` grants.
//!
//! Grants are memory-only by design (upstream trade-off): after a restart
//! clients knock again, because replay protection is bound to the same
//! lifetime.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use arc_swap::ArcSwap;

use crate::model::limits;

/// How an authorization was obtained. `Web` is produced by WP-26's
/// login flow through the shared registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantSource {
    Knock,
    Web,
}

impl GrantSource {
    /// Stable wire text for status views.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Knock => "knock",
            Self::Web => "web",
        }
    }
}

/// One live authorization: an address admitted for one rule until a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub addr: IpAddr,
    pub rule: String,
    pub until: SystemTime,
    pub source: GrantSource,
    /// The identity credential used; `None` for the rule's shared key.
    pub identity: Option<String>,
    /// Username carried by the packet, when the rule pins one.
    pub user: Option<String>,
    /// Credential fingerprint at grant time; stale after the identity or
    /// shared key is edited.
    pub cred: String,
}

impl Grant {
    /// Whether the grant is live at `now`.
    pub fn active(&self, now: SystemTime) -> bool {
        self.until > now
    }
}

/// A grant row for the status endpoint.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantView {
    pub addr: IpAddr,
    pub rule: String,
    pub source: &'static str,
    pub identity: Option<String>,
    pub user: Option<String>,
    /// Seconds remaining, rounded up.
    pub remaining_seconds: u64,
}

/// Registry key: one address per rule.
type GrantKey = (IpAddr, String);

/// The shared grant table. Reads (`admitted`) are lock-free; writes happen
/// under a mutex and republish the snapshot.
pub struct Grants {
    entries: Mutex<BTreeMap<GrantKey, Grant>>,
    snapshot: ArcSwap<Snapshot>,
    rules: Mutex<HashSet<String>>,
}

#[derive(Default)]
struct Snapshot {
    by_addr: HashMap<IpAddr, Vec<(String, SystemTime)>>,
}

impl Grants {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(BTreeMap::new()),
            snapshot: ArcSwap::from_pointee(Snapshot::default()),
            rules: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Replaces the set of knock rules other entrances may reference
    /// (`knockgate::set_rules`).
    pub fn set_rules(&self, rules: Vec<String>) {
        let mut current = self.rules.lock().expect("grant rules");
        current.clear();
        current.extend(rules);
    }

    /// Whether a rule key exists.
    pub fn has_rule(&self, key: &str) -> bool {
        self.rules.lock().expect("grant rules").contains(key)
    }

    /// The registered rule keys.
    pub fn rules(&self) -> Vec<String> {
        self.rules
            .lock()
            .expect("grant rules")
            .iter()
            .cloned()
            .collect()
    }

    /// The hot-path question ("is this address admitted for this rule?"):
    /// a lock-free snapshot read, safe on every connection.
    pub fn admitted(&self, addr: IpAddr, rule: &str, now: SystemTime) -> bool {
        let snapshot = self.snapshot.load();
        snapshot.by_addr.get(&addr).is_some_and(|entries| {
            entries
                .iter()
                .any(|(name, until)| name == rule && *until > now)
        })
    }

    /// Inserts or extends a knock grant. `single_addr` revokes the
    /// credential's other addresses first (web grants and established
    /// connections are not stored here, hence untouched). Returns `None`
    /// when the table is over its limit even after pruning.
    pub fn grant(&self, mut grant: Grant, single_addr: bool, now: SystemTime) -> Option<Grant> {
        let key: GrantKey = (grant.addr, grant.rule.clone());
        {
            let mut entries = self.entries.lock().expect("grant entries");
            if single_addr {
                // Revoke this credential's other knock addresses.
                let stale: Vec<GrantKey> = entries
                    .iter()
                    .filter(|((_, rule), existing)| {
                        rule == &grant.rule
                            && existing.source == GrantSource::Knock
                            && existing.identity == grant.identity
                            && existing.cred == grant.cred
                            && existing.addr != grant.addr
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                for stale in stale {
                    entries.remove(&stale);
                }
            }
            // Repeat knocks extend the validity; the newest credential
            // (identity, user, fingerprint) wins.
            if let Some(existing) = entries.get(&key) {
                grant.until = grant.until.max(existing.until);
            }
            // Over the limit: prune expired, then refuse.
            if entries.len() >= limits::GRANTS_LIMIT && !entries.contains_key(&key) {
                entries.retain(|_, existing| existing.active(now));
                if entries.len() >= limits::GRANTS_LIMIT {
                    return None;
                }
            }
            entries.insert(key, grant.clone());
        }
        self.publish();
        Some(grant)
    }

    /// Removes every grant of one rule (rule deleted or disabled); returns
    /// how many were removed.
    pub fn revoke_rule(&self, rule: &str) -> usize {
        let removed = {
            let mut entries = self.entries.lock().expect("grant entries");
            let stale: Vec<GrantKey> = entries
                .keys()
                .filter(|(_, key)| key.as_str() == rule)
                .cloned()
                .collect();
            for key in &stale {
                entries.remove(key);
            }
            stale.len()
        };
        if removed > 0 {
            self.publish();
        }
        removed
    }

    /// Removes every grant of one address (management revoke); returns the
    /// count.
    pub fn revoke_addr(&self, addr: IpAddr) -> usize {
        let removed = {
            let mut entries = self.entries.lock().expect("grant entries");
            let stale: Vec<GrantKey> = entries
                .keys()
                .filter(|(target, _)| *target == addr)
                .cloned()
                .collect();
            for key in &stale {
                entries.remove(key);
            }
            stale.len()
        };
        if removed > 0 {
            self.publish();
        }
        removed
    }

    /// Removes grants of one rule whose credential is no longer valid
    /// (identity disabled, deleted or re-keyed; shared key changed or
    /// turned off). Web grants are never passed to this predicate.
    pub fn revoke_stale_in_rule(&self, rule: &str, valid_creds: &HashSet<String>) -> usize {
        let removed = {
            let mut entries = self.entries.lock().expect("grant entries");
            let stale: Vec<GrantKey> = entries
                .iter()
                .filter(|((_, key), grant)| key == rule && !valid_creds.contains(&grant.cred))
                .map(|(key, _)| key.clone())
                .collect();
            for key in &stale {
                entries.remove(key);
            }
            stale.len()
        };
        if removed > 0 {
            self.publish();
        }
        removed
    }

    /// Drops expired grants; returns how many were removed.
    pub fn prune(&self, now: SystemTime) -> usize {
        let removed = {
            let mut entries = self.entries.lock().expect("grant entries");
            let before = entries.len();
            entries.retain(|_, grant| grant.active(now));
            before - entries.len()
        };
        if removed > 0 {
            self.publish();
        }
        removed
    }

    /// Revokes every stored grant (management endpoint); returns the count.
    pub fn clear(&self) -> usize {
        let removed = {
            let mut entries = self.entries.lock().expect("grant entries");
            let count = entries.len();
            entries.clear();
            count
        };
        if removed > 0 {
            self.publish();
        }
        removed
    }

    /// Live grants, soonest expiry first.
    pub fn list(&self, now: SystemTime) -> Vec<GrantView> {
        let entries = self.entries.lock().expect("grant entries");
        let mut views: Vec<GrantView> = entries
            .values()
            .filter(|grant| grant.active(now))
            .map(|grant| {
                let remaining = grant
                    .until
                    .duration_since(now)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                GrantView {
                    addr: grant.addr,
                    rule: grant.rule.clone(),
                    source: grant.source.as_str(),
                    identity: grant.identity.clone(),
                    user: grant.user.clone(),
                    remaining_seconds: remaining + u64::from(remaining == 0),
                }
            })
            .collect();
        views.sort_by(|a, b| a.rule.cmp(&b.rule).then_with(|| a.addr.cmp(&b.addr)));
        views
    }

    /// Number of live grants.
    pub fn active_count(&self, now: SystemTime) -> usize {
        self.entries
            .lock()
            .expect("grant entries")
            .values()
            .filter(|grant| grant.active(now))
            .count()
    }

    fn publish(&self) {
        let entries = self.entries.lock().expect("grant entries");
        let mut by_addr: HashMap<IpAddr, Vec<(String, SystemTime)>> = HashMap::new();
        for grant in entries.values() {
            by_addr
                .entry(grant.addr)
                .or_default()
                .push((grant.rule.clone(), grant.until));
        }
        drop(entries);
        self.snapshot.store(Arc::new(Snapshot { by_addr }));
    }
}

impl Default for Grants {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn grant(addr: IpAddr, rule: &str, identity: Option<&str>, cred: &str, until: u64) -> Grant {
        Grant {
            addr,
            rule: rule.to_owned(),
            until: at(until),
            source: GrantSource::Knock,
            identity: identity.map(str::to_owned),
            user: None,
            cred: cred.to_owned(),
        }
    }

    #[test]
    fn admitted_is_lock_free_and_time_bounded() {
        let grants = Grants::new();
        grants.set_rules(vec!["r1".into()]);
        let addr = "203.0.113.7".parse().unwrap();
        grants.grant(grant(addr, "r1", None, "c1", 110), false, at(100));
        assert!(grants.admitted(addr, "r1", at(100)));
        assert!(grants.admitted(addr, "r1", at(109)));
        assert!(!grants.admitted(addr, "r1", at(110)), "expiry is exclusive");
        assert!(!grants.admitted(addr, "other", at(100)));
        assert!(!grants.admitted("203.0.113.8".parse().unwrap(), "r1", at(100)));
    }

    #[test]
    fn repeat_knock_extends_grant() {
        let grants = Grants::new();
        let addr = "203.0.113.7".parse().unwrap();
        grants.grant(grant(addr, "r1", None, "c1", 130), false, at(100));
        grants.grant(grant(addr, "r1", None, "c1", 120), false, at(100));
        assert!(
            grants.admitted(addr, "r1", at(125)),
            "a shorter later knock keeps the longer expiry"
        );
        assert!(!grants.admitted(addr, "r1", at(135)));
    }

    #[test]
    fn single_addr_revokes_other_addresses() {
        let grants = Grants::new();
        let first = "203.0.113.7".parse().unwrap();
        let second = "203.0.113.8".parse().unwrap();
        grants.grant(grant(first, "r1", Some("alice"), "cA", 200), true, at(100));
        // A second address knocks: the first is revoked for this identity.
        grants.grant(grant(second, "r1", Some("alice"), "cA", 200), true, at(110));
        assert!(!grants.admitted(first, "r1", at(111)));
        assert!(grants.admitted(second, "r1", at(111)));
        // A different identity keeps both addresses.
        grants.grant(grant(first, "r1", Some("bob"), "cB", 200), true, at(120));
        assert!(grants.admitted(first, "r1", at(121)));
        assert!(grants.admitted(second, "r1", at(121)));
    }

    #[test]
    fn edit_rule_revokes_knock_grants_only() {
        let grants = Grants::new();
        let addr = "203.0.113.7".parse().unwrap();
        grants.grant(grant(addr, "r1", None, "c1", 200), false, at(100));
        grants.grant(grant(addr, "r2", None, "c2", 200), false, at(100));
        assert_eq!(grants.revoke_rule("r1"), 1);
        assert!(!grants.admitted(addr, "r1", at(101)));
        assert!(grants.admitted(addr, "r2", at(101)));
    }

    #[test]
    fn edit_identity_revokes_only_stale_keys() {
        let grants = Grants::new();
        let addr = "203.0.113.7".parse().unwrap();
        grants.grant(
            grant(addr, "r1", Some("alice"), "cOld", 200),
            false,
            at(100),
        );
        grants.grant(
            grant("203.0.113.8".parse().unwrap(), "r1", Some("bob"), "cB", 200),
            false,
            at(100),
        );
        // After the edit only cB (bob) remains valid.
        let valid: HashSet<String> = ["cB".to_owned()].into_iter().collect();
        assert_eq!(grants.revoke_stale_in_rule("r1", &valid), 1);
        assert!(!grants.admitted(addr, "r1", at(101)));
        assert!(grants.admitted("203.0.113.8".parse().unwrap(), "r1", at(101)));
    }

    #[test]
    fn grants_lost_on_restart_is_modeled_by_empty_registry() {
        // Grants live only in memory: a fresh registry admits nobody, which
        // is exactly the post-restart state.
        let grants = Grants::new();
        let addr = "203.0.113.7".parse().unwrap();
        assert!(!grants.admitted(addr, "r1", at(100)));
    }

    #[test]
    fn allow_cap_rejects_when_full_of_live_grants() {
        let grants = Grants::new();
        for i in 0..limits::GRANTS_LIMIT {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 + i as u32));
            if grants
                .grant(grant(addr, "r1", None, "c1", 1000), false, at(1))
                .is_none()
            {
                panic!("limit {i} rejected before the cap");
            }
        }
        // Still full: a new grant is refused after pruning finds nothing.
        let overflow = "203.0.113.99".parse().unwrap();
        assert!(
            grants
                .grant(grant(overflow, "r1", None, "c1", 1000), false, at(1))
                .is_none()
        );
        // Expire everything: pruning makes room again.
        assert_eq!(grants.prune(at(2000)), limits::GRANTS_LIMIT);
        assert!(
            grants
                .grant(grant(overflow, "r1", None, "c1", 3000), false, at(2000))
                .is_some()
        );
    }

    #[test]
    fn clear_and_list_report_views() {
        let grants = Grants::new();
        grants.grant(
            grant(
                "203.0.113.7".parse().unwrap(),
                "r1",
                Some("alice"),
                "cA",
                160,
            ),
            false,
            at(100),
        );
        grants.grant(
            grant("203.0.113.8".parse().unwrap(), "r2", None, "cB", 200),
            false,
            at(100),
        );
        let views = grants.list(at(101));
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].source, "knock");
        assert_eq!(views[0].remaining_seconds, 59);
        assert_eq!(grants.active_count(at(101)), 2);
        assert_eq!(grants.clear(), 2);
        assert!(grants.list(at(101)).is_empty());
    }
}
