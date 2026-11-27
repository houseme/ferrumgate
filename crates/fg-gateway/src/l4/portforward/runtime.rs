//! Runtime state for the portforward module (WP-34): an atomically
//! replaceable snapshot of compiled rules plus the process-wide UDP session
//! budget derived from `settings.max_udp_sessions` (normalized to 1024).
//!
//! TODO(WP-34 runtime): the data plane is deferred to the TOML migration
//! (WP-39 batch). Binding listeners, accept loops, admission through
//! [`AccessFilter`] + [`fg_net::quota`] (per-port and per-source), the
//! UDP session table over [`UdpBudget`], and the TCP path of
//! `l4::shared` (`failover::dial_targets`, PROXY `write_header`,
//! `pipe::relay_counted`) land there. This increment delivers the compile
//! step, the snapshot holder and the UDP budget so the serve loop only has
//! to wire them together.

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use arc_swap::ArcSwap;

use super::compile::CompiledRule;

/// Process-wide UDP session budget: new sessions acquire a slot via
/// [`UdpBudget::try_acquire`]; once `active == max` further sessions are
/// dropped at the door. Slots release when the lease drops.
pub struct UdpBudget {
    max: u32,
    active: Arc<AtomicU32>,
}

/// One held UDP session slot; releases it on drop.
pub struct UdpLease {
    active: Arc<AtomicU32>,
}

impl UdpBudget {
    pub fn new(max: u32) -> Self {
        Self {
            max,
            active: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Acquires one session slot if `active < max`; `None` means over
    /// budget (drop the datagram/session). The slot releases when the lease
    /// drops.
    pub fn try_acquire(&self) -> Option<UdpLease> {
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.max).then_some(active + 1)
            })
            .ok()
            .map(|_| UdpLease {
                active: Arc::clone(&self.active),
            })
    }

    /// Currently held sessions.
    pub fn active(&self) -> u32 {
        self.active.load(Ordering::Acquire)
    }

    /// Configured ceiling (the normalized `settings.max_udp_sessions`).
    pub fn max(&self) -> u32 {
        self.max
    }
}

impl Drop for UdpLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Holds the compiled rule set and the shared UDP budget. Readers clone the
/// current snapshot (`rules`); the loader swaps in a fresh set wholesale
/// (`replace_rules`). In-flight connections keep serving from their own
/// snapshot until it is released.
pub struct Runtime {
    rules: ArcSwap<Vec<Arc<CompiledRule>>>,
    udp_sessions: Arc<UdpBudget>,
}

impl Runtime {
    pub fn new(rules: Vec<Arc<CompiledRule>>, max_udp_sessions: u32) -> Self {
        Self {
            rules: ArcSwap::from_pointee(rules),
            udp_sessions: Arc::new(UdpBudget::new(max_udp_sessions)),
        }
    }

    /// Clone of the current rule snapshot.
    pub fn rules(&self) -> Arc<Vec<Arc<CompiledRule>>> {
        self.rules.load_full()
    }

    /// Swaps in the next compiled set atomically.
    pub fn replace_rules(&self, next: Vec<Arc<CompiledRule>>) {
        self.rules.store(Arc::new(next));
    }

    /// The shared UDP session budget, leased per new UDP session.
    pub fn udp_sessions(&self) -> Arc<UdpBudget> {
        Arc::clone(&self.udp_sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l4::portforward::compile::compile;
    use crate::l4::portforward::model::{FileConfig, Protocol, Rule};

    fn compiled_rules(keys: &[&str]) -> Vec<Arc<CompiledRule>> {
        let config = FileConfig {
            rules: keys
                .iter()
                .map(|&key| Rule {
                    key: key.into(),
                    name: key.into(),
                    enable: true,
                    protocols: vec![Protocol::Tcp],
                    listen_ports: "8080".into(),
                    target_addresses: vec!["10.0.0.1:80".into()],
                    target_ports: "80".into(),
                    ..Rule::default()
                })
                .collect(),
            ..FileConfig::default()
        };
        compile(&config)
            .expect("rules should compile")
            .into_iter()
            .map(Arc::new)
            .collect()
    }

    #[test]
    fn udp_budget_acquires_and_releases() {
        let budget = UdpBudget::new(2);
        let first = budget.try_acquire().expect("first slot");
        let second = budget.try_acquire().expect("second slot");
        assert_eq!(budget.active(), 2);
        assert!(budget.try_acquire().is_none(), "over budget");
        drop(second);
        assert_eq!(budget.active(), 1);
        let third = budget.try_acquire().expect("released slot reusable");
        drop(first);
        drop(third);
        assert_eq!(budget.active(), 0);
    }

    #[test]
    fn runtime_snapshot_replaced_atomically() {
        let runtime = Runtime::new(compiled_rules(&["a"]), 16);
        assert_eq!(runtime.rules().len(), 1);

        let old = runtime.rules();
        runtime.replace_rules(compiled_rules(&["b", "c"]));
        let new = runtime.rules();
        assert_eq!(new.len(), 2);
        assert_eq!(new[0].cfg.key, "b");
        // The old snapshot is untouched: readers finish on their generation.
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].cfg.key, "a");

        assert_eq!(runtime.udp_sessions().max(), 16);
        assert_eq!(runtime.udp_sessions().active(), 0);
    }
}
