//! Open-port registry: modules register ports that are actually listening
//! (WP-36); intrusion protection reads the published snapshot.

use std::sync::Arc;

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
}

impl Default for OpenPorts {
    fn default() -> Self {
        Self {
            owners: ArcSwap::from_pointee(Vec::new()),
        }
    }
}

impl OpenPorts {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Publish `owner`'s listening ports, replacing any previous list; an
    /// empty slice revokes the owner entirely.
    pub fn set(&self, owner: &str, ports: &[OpenPort]) {
        let mut owners: Vec<(String, Vec<OpenPort>)> = self.owners.load().as_ref().clone();
        owners.retain(|(name, _)| name != owner);
        if !ports.is_empty() {
            owners.push((owner.to_string(), ports.to_vec()));
        }
        self.owners.store(Arc::new(owners));
    }

    /// Whether any owner currently listens on `proto:port`.
    pub fn is_open(&self, proto: Proto, port: u16) -> bool {
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
}
