//! Registry of confirmed-identity sources: addresses the intrusion
//! protection modules should exempt because a trusted component (the
//! gateway, an overlay peer) vouches for them. Owners replace their own
//! entries atomically.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, SystemTime},
};

/// One vouched address, optionally expiring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedSource {
    /// Which component vouches for the address (a module or feature id).
    pub owner: String,
    pub addr: IpAddr,
    /// Absent means valid until cleared.
    pub until: Option<SystemTime>,
    pub note: String,
}

impl TrustedSource {
    pub fn valid(&self, now: SystemTime) -> bool {
        self.until.is_none_or(|until| now < until)
    }
}

static REGISTRY: std::sync::LazyLock<Mutex<HashMap<String, Vec<TrustedSource>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn registry() -> std::sync::MutexGuard<'static, HashMap<String, Vec<TrustedSource>>> {
    REGISTRY.lock().expect("trusted-source registry poisoned")
}

/// Replaces every entry previously set by `owner`.
pub fn set(owner: &str, list: Vec<TrustedSource>) {
    registry().insert(owner.to_owned(), list);
}

/// Removes every entry previously set by `owner`.
pub fn clear(owner: &str) {
    registry().remove(owner);
}

/// All currently valid entries across owners; expired entries are dropped
/// on the way out.
pub fn all() -> Vec<TrustedSource> {
    let now = SystemTime::now();
    let mut guard = registry();
    let mut alive = Vec::new();
    for entries in guard.values_mut() {
        entries.retain(|source| source.valid(now));
        alive.extend(entries.iter().cloned());
    }
    alive.sort_by(|a, b| (&a.owner, &a.addr).cmp(&(&b.owner, &b.addr)));
    alive
}

/// Whether `addr` carries a currently valid voucher.
pub fn is_trusted(addr: IpAddr) -> bool {
    let now = SystemTime::now();
    let mut guard = registry();
    guard.values_mut().any(|entries| {
        entries.retain(|source| source.valid(now));
        entries.iter().any(|source| source.addr == addr)
    })
}

/// How long a voucher typically lives when the vouching component cannot
/// push updates; owners set explicit `until` values themselves.
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

#[cfg(test)]
mod tests {
    use super::*;

    fn source(owner: &str, addr: &str, until: Option<SystemTime>) -> TrustedSource {
        TrustedSource {
            owner: owner.to_owned(),
            addr: addr.parse().unwrap(),
            until,
            note: "fixture".to_owned(),
        }
    }

    // Each test uses a unique owner name so parallel tests never see each
    // other's registry entries.
    #[test]
    fn set_replaces_and_clear_removes() {
        let owner = "test-set-replace";
        set(owner, vec![source(owner, "10.0.0.1", None)]);
        set(owner, vec![source(owner, "10.0.0.2", None)]);
        let listed = all();
        assert_eq!(
            listed.iter().filter(|source| source.owner == owner).count(),
            1,
            "the owner's previous list is replaced"
        );
        clear(owner);
        assert!(all().iter().all(|source| source.owner != owner));
    }

    #[test]
    fn expiry_drops_entries_lazily() {
        let owner = "test-expiry";
        let now = SystemTime::now();
        set(
            owner,
            vec![
                source(owner, "10.0.0.3", Some(now - Duration::from_secs(1))),
                source(owner, "10.0.0.4", Some(now + DEFAULT_TTL)),
            ],
        );
        let alive: Vec<_> = all()
            .into_iter()
            .filter(|source| source.owner == owner)
            .collect();
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].addr.to_string(), "10.0.0.4");
        assert!(is_trusted("10.0.0.4".parse().unwrap()));
        assert!(!is_trusted("10.0.0.3".parse().unwrap()));
        clear(owner);
    }

    #[test]
    fn is_trusted_covers_all_owners() {
        let a = "test-cross-a";
        let b = "test-cross-b";
        set(a, vec![source(a, "10.0.0.5", None)]);
        set(b, vec![source(b, "10.0.0.6", None)]);
        assert!(is_trusted("10.0.0.5".parse().unwrap()));
        assert!(is_trusted("10.0.0.6".parse().unwrap()));
        clear(a);
        clear(b);
    }
}
