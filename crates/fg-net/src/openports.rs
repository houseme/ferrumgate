//! Open-port registry: modules register ports that are actually listening
//! (WP-36); intrusion protection reads the published snapshot.
//!
//! WP-53 extends the registry with the startup timing the detectors need
//! (pure additions, existing API untouched):
//!
//! - [`OpenPorts::begin_startup`] / [`end_startup`] / [`ready`]: the
//!   barrier that keeps decoy ports disabled while modules are still
//!   starting (a decoy computed from an incomplete registry could grab a
//!   port a module is about to bind, or ban a client that merely
//!   reconnects during startup);
//! - [`OpenPorts::hold`]: a module that just started listening marks the
//!   TCP port open immediately instead of waiting for the next
//!   registration or poll; the returned [`Release`] undoes it on drop;
//! - [`OpenPorts::notify`]: a coalescing change signal — any number of
//!   registrations between two observations collapse into one wakeup for
//!   the detector refresh loop.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// One registered listening port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct OpenPort {
    pub proto: Proto,
    pub port: u16,
}

/// Owner-scoped registry; `set` overrides the owner's previous list (an
/// empty list revokes it) and readers get a lock-free snapshot.
pub struct OpenPorts {
    owners: ArcSwap<Vec<(String, Vec<OpenPort>)>>,
    shared: Arc<Shared>,
}

/// The state shared with holds and change subscribers.
#[derive(Default)]
struct Shared {
    /// Startup barrier: `false` between `begin_startup` and
    /// `end_startup` (and before either runs) — decoy ports stay
    /// disabled while the module registry may be incomplete.
    ready: AtomicBool,
    /// Currently held TCP ports with their reference counts.
    holds: Mutex<BTreeMap<u16, usize>>,
    /// Registration generation; subscribers wait for it to move.
    generation: Mutex<u64>,
    generation_changed: Condvar,
}

impl Default for OpenPorts {
    fn default() -> Self {
        Self {
            owners: ArcSwap::from_pointee(Vec::new()),
            shared: Arc::new(Shared::default()),
        }
    }
}

impl OpenPorts {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Marks the startup phase as begun: the registry may be incomplete,
    /// so decoy ports must not be computed (`ready == false`). Called
    /// before the first module starts; idempotent.
    pub fn begin_startup(&self) {
        let was = self.shared.ready.swap(false, Ordering::SeqCst);
        if was {
            self.signal();
        }
    }

    /// Marks the startup phase as done: every module has registered (or
    /// held) its ports, the detectors may compute and enable decoys.
    /// Coalesces into the change signal so waiters recompute once.
    pub fn end_startup(&self) {
        let was = self.shared.ready.swap(true, Ordering::SeqCst);
        if !was {
            self.signal();
        }
    }

    /// Whether startup finished and the registry is complete.
    pub fn ready(&self) -> bool {
        self.shared.ready.load(Ordering::SeqCst)
    }

    /// Marks a just-bound TCP address as open immediately (the module
    /// registered nothing yet or the registration lags behind). The
    /// returned [`Release`] revokes the hold when dropped or passed to
    /// [`Release::release`]; concurrent holds of one port refcount.
    /// Addresses with port 0 are ignored (an inert `Release` comes back).
    pub fn hold(&self, addr: SocketAddr) -> Release {
        let port = addr.port();
        if port == 0 {
            return Release { inner: None };
        }
        {
            let mut holds = lock_holds(&self.shared);
            let count = holds.entry(port).or_insert(0);
            *count += 1;
            if *count != 1 {
                // Already held: the port table did not change.
                return Release {
                    inner: Some((Arc::clone(&self.shared), port)),
                };
            }
        }
        self.signal();
        Release {
            inner: Some((Arc::clone(&self.shared), port)),
        }
    }

    /// The currently held TCP ports, ascending.
    pub fn held(&self) -> Vec<u16> {
        lock_holds(&self.shared).keys().copied().collect()
    }

    /// Subscribes to registration changes; every change between two
    /// observations coalesces into a single wakeup. The first
    /// observation of the returned handle sees nothing yet.
    pub fn notify(&self) -> Changed {
        let generation = *lock_generation(&self.shared);
        Changed {
            shared: Arc::clone(&self.shared),
            seen: generation,
        }
    }

    /// Publish `owner`'s listening ports, replacing any previous list; an
    /// empty slice revokes the owner entirely.
    pub fn set(&self, owner: &str, ports: &[OpenPort]) {
        let mut owners: Vec<(String, Vec<OpenPort>)> = self.owners.load().as_ref().clone();
        owners.retain(|(name, _)| name != owner);
        if !ports.is_empty() {
            owners.push((owner.to_string(), ports.to_vec()));
        }
        owners.sort_by(|a, b| a.0.cmp(&b.0));
        let changed = self.owners.load().as_ref() != &owners;
        self.owners.store(Arc::new(owners));
        if changed {
            self.signal();
        }
    }

    /// Whether any owner currently listens on `proto:port`. A held TCP
    /// port counts as open too (`hold` promises the listener is live).
    pub fn is_open(&self, proto: Proto, port: u16) -> bool {
        if proto == Proto::Tcp && lock_holds(&self.shared).contains_key(&port) {
            return true;
        }
        self.owners
            .load()
            .iter()
            .any(|(_, ports)| ports.iter().any(|p| p.proto == proto && p.port == port))
    }

    /// Merged, deduplicated snapshot of every owner's ports, sorted by
    /// `(proto, port)`.
    pub fn all(&self) -> Vec<OpenPort> {
        let mut merged: Vec<OpenPort> = self
            .owners
            .load()
            .iter()
            .flat_map(|(_, ports)| ports.iter().copied())
            .collect();
        merged.sort_by_key(|p| (p.proto, p.port));
        merged.dedup();
        merged
    }

    /// Bumps the registration generation and wakes every subscriber.
    fn signal(&self) {
        let (generation, changed) = (&self.shared.generation, &self.shared.generation_changed);
        let mut current = generation.lock().expect("openports generation");
        *current += 1;
        changed.notify_all();
    }
}

fn lock_holds(shared: &Shared) -> std::sync::MutexGuard<'_, BTreeMap<u16, usize>> {
    shared
        .holds
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_generation(shared: &Shared) -> std::sync::MutexGuard<'_, u64> {
    shared
        .generation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The undo half of [`OpenPorts::hold`]: dropping it (or calling
/// [`Release::release`]) removes one hold reference; the last reference
/// for a port closes it out and signals the change.
pub struct Release {
    inner: Option<(Arc<Shared>, u16)>,
}

impl Release {
    /// The held port, or `None` for the inert release of an ignored
    /// address.
    pub fn port(&self) -> Option<u16> {
        self.inner.as_ref().map(|(_, port)| *port)
    }

    /// Revokes the hold now instead of on drop.
    pub fn release(self) {
        drop(self);
    }
}

impl std::fmt::Debug for Release {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Release")
            .field("port", &self.port())
            .finish()
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        let Some((shared, port)) = self.inner.take() else {
            return;
        };
        let mut holds = lock_holds(&shared);
        if let Some(count) = holds.get_mut(&port) {
            *count -= 1;
            if *count == 0 {
                holds.remove(&port);
                drop(holds);
                let mut generation = lock_generation(&shared);
                *generation += 1;
                shared.generation_changed.notify_all();
            }
        }
    }
}

/// A subscription to the coalescing registration signal (the std-based
/// stand-in for a watch channel; `fg-net` deliberately stays
/// tokio-free). Cloning is not supported on purpose: subscribe again for
/// a fresh baseline.
pub struct Changed {
    shared: Arc<Shared>,
    seen: u64,
}

impl Changed {
    /// The generation this subscription was created at.
    pub fn seen(&self) -> u64 {
        self.seen
    }

    /// The current registration generation.
    pub fn current(&self) -> u64 {
        *lock_generation(&self.shared)
    }

    /// Blocks until a change since the subscription (or `timeout`
    /// elapses). Returns whether a change was observed; multiple changes
    /// coalesce into one `true`.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let changed = &self.shared.generation_changed;
        let mut guard = lock_generation(&self.shared);
        let deadline = std::time::Instant::now() + timeout;
        while *guard <= self.seen {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (new_guard, _state) = changed
                .wait_timeout(guard, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard = new_guard;
        }
        true
    }

    /// Blocks until a change since the subscription.
    pub fn wait(&self) {
        let changed = &self.shared.generation_changed;
        let mut guard = lock_generation(&self.shared);
        while *guard <= self.seen {
            guard = changed
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(proto: Proto, port: u16) -> OpenPort {
        OpenPort { proto, port }
    }

    #[test]
    fn openports_set_overrides_and_empty_clears() {
        let ports = OpenPorts::new();

        ports.set(
            "listener",
            &[port(Proto::Tcp, 8443), port(Proto::Udp, 5353)],
        );
        assert!(ports.is_open(Proto::Tcp, 8443));
        assert!(ports.is_open(Proto::Udp, 5353));
        assert!(!ports.is_open(Proto::Tcp, 9443));

        // Setting again overrides: the second list wins.
        ports.set("listener", &[port(Proto::Tcp, 9443)]);
        assert!(ports.is_open(Proto::Tcp, 9443));
        assert!(!ports.is_open(Proto::Tcp, 8443));
        assert!(!ports.is_open(Proto::Udp, 5353));

        // A second owner merges into the snapshot.
        ports.set("relay", &[port(Proto::Udp, 5353), port(Proto::Tcp, 8443)]);
        assert_eq!(
            ports.all(),
            vec![
                port(Proto::Tcp, 8443),
                port(Proto::Tcp, 9443),
                port(Proto::Udp, 5353),
            ]
        );
        // Duplicates across owners dedup in all() but is_open stays true.
        assert!(ports.is_open(Proto::Udp, 5353));

        // An empty list revokes only that owner.
        ports.set("relay", &[]);
        assert_eq!(ports.all(), vec![port(Proto::Tcp, 9443)]);
        ports.set("listener", &[]);
        assert!(ports.all().is_empty());
        assert!(!ports.is_open(Proto::Tcp, 9443));
    }

    #[test]
    fn openports_snapshot_is_lock_free() {
        let ports = OpenPorts::new();
        ports.set("listener", &[port(Proto::Tcp, 8443)]);

        // An owned snapshot survives later publishes unchanged...
        let before = ports.all();
        ports.set("listener", &[port(Proto::Udp, 9000)]);
        assert_eq!(before, vec![port(Proto::Tcp, 8443)]);
        assert_eq!(ports.all(), vec![port(Proto::Udp, 9000)]);

        // ...and an ArcSwap guard keeps reading the old generation without
        // blocking, while new readers see the published one.
        let guard = ports.owners.load();
        let stale: Vec<OpenPort> = guard
            .iter()
            .flat_map(|(_, ports)| ports.iter().copied())
            .collect();
        ports.set("listener", &[port(Proto::Tcp, 7000)]);
        assert_eq!(stale, vec![port(Proto::Udp, 9000)]);
        assert_eq!(ports.all(), vec![port(Proto::Tcp, 7000)]);
        drop(guard);
    }

    #[test]
    fn openports_set_notifies_only_on_change() {
        let ports = OpenPorts::new();
        let changed = ports.notify();
        ports.set("listener", &[port(Proto::Tcp, 8443)]);
        assert!(
            changed.wait_timeout(Duration::from_millis(0)),
            "the first set signals"
        );

        // A subscriber created after the change sees nothing pending.
        let fresh = ports.notify();
        assert!(!fresh.wait_timeout(Duration::from_millis(10)));

        // Re-publishing the identical list does not signal.
        ports.set("listener", &[port(Proto::Tcp, 8443)]);
        assert!(
            !fresh.wait_timeout(Duration::from_millis(10)),
            "no change, no signal"
        );

        // An actual change signals, and only the new generation wakes.
        ports.set("listener", &[port(Proto::Tcp, 9443)]);
        assert!(fresh.wait_timeout(Duration::from_millis(10)));
        assert!(fresh.current() > fresh.seen());
    }

    #[test]
    fn openports_notify_coalesces_changes() {
        let ports = OpenPorts::new();
        let changed = ports.notify();
        // Three changes land before anyone waits: one condvar wakeup
        // covers them all (wait_timeout reports a change without
        // consuming it — observation is explicit via seen/current).
        ports.set("a", &[port(Proto::Tcp, 1)]);
        ports.set("b", &[port(Proto::Tcp, 2)]);
        ports.set("a", &[]);
        assert!(changed.wait_timeout(Duration::from_millis(10)));
        // A subscriber created after the changes is already up to date:
        // nothing replays.
        let fresh = ports.notify();
        assert!(!fresh.wait_timeout(Duration::from_millis(10)), "folded");
    }

    #[test]
    fn openports_hold_marks_port_open_immediately() {
        let ports = OpenPorts::new();
        let addr: SocketAddr = "0.0.0.0:8443".parse().expect("addr");
        assert!(!ports.is_open(Proto::Tcp, 8443));

        let release = ports.hold(addr);
        assert_eq!(release.port(), Some(8443));
        assert!(
            ports.is_open(Proto::Tcp, 8443),
            "the held port is open before any registration"
        );
        assert_eq!(ports.held(), [8443]);
        assert!(!ports.is_open(Proto::Udp, 8443), "hold is TCP-only");

        // Dropping the release closes the hold again and signals.
        let changed = ports.notify();
        drop(release);
        assert!(!ports.is_open(Proto::Tcp, 8443));
        assert!(ports.held().is_empty());
        assert!(
            changed.wait_timeout(Duration::from_millis(10)),
            "release signals"
        );
    }

    #[test]
    fn openports_hold_ignores_zero_port() {
        let ports = OpenPorts::new();
        let addr: SocketAddr = "0.0.0.0:0".parse().expect("addr");
        let release = ports.hold(addr);
        assert_eq!(release.port(), None, "port 0 is not a listener");
        assert!(ports.held().is_empty());
        release.release();
        assert!(ports.held().is_empty());
    }

    #[test]
    fn openports_hold_refcounts_concurrent_holds() {
        let ports = OpenPorts::new();
        let addr: SocketAddr = "[::1]:9000".parse().expect("addr");
        let first = ports.hold(addr);
        let second = ports.hold(addr);
        assert_eq!(ports.held(), [9000], "two holds, one port");

        let changed = ports.notify();
        first.release();
        assert!(
            ports.is_open(Proto::Tcp, 9000),
            "the second hold keeps the port"
        );
        assert!(
            !changed.wait_timeout(Duration::from_millis(10)),
            "still held: no change yet"
        );

        second.release();
        assert!(ports.held().is_empty());
        assert!(changed.wait_timeout(Duration::from_millis(10)));
    }

    #[test]
    fn startup_barrier_keeps_trap_disabled_until_end() {
        let ports = OpenPorts::new();
        assert!(
            !ports.ready(),
            "before startup runs the registry may be incomplete: decoys stay off"
        );

        // begin_startup is idempotent and keeps the barrier closed.
        ports.begin_startup();
        assert!(!ports.ready());
        ports.set("early", &[port(Proto::Tcp, 8443)]);
        assert!(!ports.ready());

        // end_startup opens the barrier once, exactly at the switch.
        let changed = ports.notify();
        ports.end_startup();
        assert!(ports.ready());
        assert!(
            changed.wait_timeout(Duration::from_millis(10)),
            "the switch signals"
        );

        let fresh = ports.notify();
        ports.end_startup();
        ports.begin_startup();
        assert!(!ports.ready(), "a restart closes the barrier again");
        assert!(fresh.wait_timeout(Duration::from_millis(10)));
    }
}
