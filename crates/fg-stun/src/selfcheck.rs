//! The STUN module's self-check (WP-42 §3.3): CGNAT detection from the
//! local interfaces (RFC 6599 `100.64.0.0/10` counts, mesh/tunnel virtual
//! interfaces do not — a VPN adapter handing out CGNAT space is normal and
//! not the ISP's carrier NAT), the presence of a routable public address,
//! and the rule collection's state. The classification is a pure function
//! over `(interface, address)` pairs so tests stay deterministic without
//! touching the host's real NICs.

use std::net::IpAddr;
use std::sync::Arc;

use fg_core::check::{BoxFut, CheckEnv, CheckResult, SelfCheck, Status};

use crate::runtime::Runtime;

/// One observed interface address (name + IP); the input to
/// [`classify_network`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub name: String,
    pub ip: IpAddr,
}

impl InterfaceAddress {
    /// Builds one observation.
    pub fn new(name: impl Into<String>, ip: IpAddr) -> Self {
        Self {
            name: name.into(),
            ip,
        }
    }
}

/// The verdict over the local addresses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkClass {
    /// A non-virtual interface holds a globally routable address.
    pub public: bool,
    /// A non-virtual interface holds carrier-grade NAT space (100.64/10).
    pub cgnat: bool,
    /// A non-virtual interface holds RFC 1918 space (home router LAN).
    pub private: bool,
    /// Addresses ignored because the interface looks like a VPN / tunnel
    /// / container adapter.
    pub virtual_ifaces: usize,
}

impl NetworkClass {
    /// The check status: public addresses traverse directly, CGNAT means
    /// traversal depends on the carrier's NAT type, private-only means a
    /// router port-forward is needed unless UPnP works.
    pub fn status(self) -> Status {
        if self.public {
            Status::Ok
        } else if self.cgnat || self.private {
            Status::Warn
        } else {
            Status::Info
        }
    }
}

/// CGNAT space per RFC 6598: `100.64.0.0/10`.
pub fn is_cgnat(ip: IpAddr) -> bool {
    match ip {
        // 100.64.0.0/10: first octet 100, second octet 64..=127.
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (octets[1] & 0xC0) == 64
        }
        IpAddr::V6(_) => false,
    }
}

/// RFC 1918 private space (and IPv6 unique-local), excluding loopback and
/// link-local.
pub fn is_private_use(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

/// Whether an interface name looks like a VPN / tunnel / container
/// adapter (Tailscale, WireGuard, ZeroTier, Docker, ...). Their addresses
/// say nothing about the real WAN path.
pub fn is_virtual_interface(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    const PREFIXES: [&str; 12] = [
        "tun",
        "tap",
        "wg",
        "utun",
        "zt",
        "tailscale",
        "br-",
        "docker",
        "veth",
        "vmnet",
        "vnic",
        "lo",
    ];
    // "en0"/"eth0"/"wlan0" style hardware names never match; everything
    // with a known virtual prefix does. A bare prefix hit on a longer
    // name (e.g. "wlan0foo") is accepted as virtual on purpose: unknown
    // adapters must not silence the CGNAT warning.
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || name.contains("virtual")
        || name.contains("vpn")
}

/// Whether the IP is link-local (IPv4 `169.254.0.0/16`, IPv6 `fe80::/10`);
/// auto-configuration noise that says nothing about the WAN path.
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10: the first ten segments bits are fixed.
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Classifies the observed addresses (pure; see the module docs).
pub fn classify_network(addresses: &[InterfaceAddress]) -> NetworkClass {
    let mut class = NetworkClass::default();
    for address in addresses {
        if address.ip.is_loopback() || is_link_local(address.ip) {
            continue;
        }
        if is_virtual_interface(&address.name) {
            class.virtual_ifaces += 1;
            continue;
        }
        if is_cgnat(address.ip) {
            class.cgnat = true;
        } else if is_private_use(address.ip) {
            class.private = true;
        } else {
            class.public = true;
        }
    }
    class
}

/// The STUN module check over the shared runtime.
pub struct StunCheck {
    pub runtime: Arc<Runtime>,
}

impl SelfCheck for StunCheck {
    fn check(&self, _env: &CheckEnv) -> BoxFut<'_, Vec<CheckResult>> {
        Box::pin(async move {
            let enabled = self.runtime.module_enabled().await;
            let snapshot = self.runtime.snapshot();
            let channels = snapshot.entries.len();
            let ready = snapshot
                .entries
                .iter()
                .filter(|entry| entry.state == "ready")
                .count();
            let mut results = vec![if enabled {
                CheckResult::ok("stun.module").param("enable", enabled)
            } else {
                CheckResult::info("stun.module").param("enable", enabled)
            }];
            results.push(
                CheckResult::info("stun.rules")
                    .param("channels", channels)
                    .param("ready", ready),
            );
            let addresses = interface_addresses();
            let class = classify_network(&addresses);
            let mut network = CheckResult::with("stun.network", class.status())
                .param("public", class.public)
                .param("cgnat", class.cgnat)
                .param("private", class.private)
                .param("virtualIfaces", class.virtual_ifaces);
            if class.cgnat {
                network = network.param(
                    "hint",
                    "检测到运营商级 NAT（100.64.0.0/10），穿透取决于运营商 NAT 类型；对称型请改用中继方案",
                );
            }
            if class.virtual_ifaces > 0 {
                network = network.param("ignoredVirtual", class.virtual_ifaces);
            }
            results.push(network);
            results
        })
    }
}

/// The host's interface addresses at check time (empty when the
/// enumeration fails — the check reports "unknown" rather than guessing).
fn interface_addresses() -> Vec<InterfaceAddress> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    interfaces
        .iter()
        .map(|iface| InterfaceAddress::new(iface.name.clone(), iface.ip()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FileConfig;
    use std::sync::Arc;
    use tokio::sync::RwLock as AsyncRwLock;

    #[test]
    fn selfcheck_cgnat_detection_ignores_virtual_ifaces() {
        let cgnat: IpAddr = "100.64.1.2".parse().unwrap();
        let lan: IpAddr = "192.168.1.10".parse().unwrap();
        let wan: IpAddr = "203.0.113.7".parse().unwrap();
        let mesh: IpAddr = "100.101.2.3".parse().unwrap();
        // The ISP hands out CGNAT space on the WAN-facing NIC.
        let class = classify_network(&[
            InterfaceAddress::new("en0", cgnat),
            InterfaceAddress::new("lo0", "127.0.0.1".parse().unwrap()),
        ]);
        assert!(class.cgnat);
        assert!(!class.public);
        assert!(!class.private);
        assert_eq!(class.status(), Status::Warn);
        // A mesh VPN adapter on CGNAT space (e.g. Tailscale) is not the
        // carrier NAT: it must be ignored, not reported.
        let class = classify_network(&[
            InterfaceAddress::new("tailscale0", mesh),
            InterfaceAddress::new("utun5", cgnat),
            InterfaceAddress::new("en0", lan),
        ]);
        assert!(class.private);
        assert!(!class.cgnat, "virtual adapters do not count");
        assert_eq!(class.virtual_ifaces, 2);
        // A real public address wins over everything.
        let class = classify_network(&[
            InterfaceAddress::new("eth0", wan),
            InterfaceAddress::new("docker0", "172.17.0.1".parse().unwrap()),
        ]);
        assert!(class.public);
        assert_eq!(class.status(), Status::Ok);
        // Link-local addresses are noise.
        let class =
            classify_network(&[InterfaceAddress::new("en0", "169.254.9.9".parse().unwrap())]);
        assert!(!class.public && !class.cgnat && !class.private);
        assert_eq!(class.status(), Status::Info, "nothing usable observed");
        // The boundary of 100.64.0.0/10: 100.63.x and 100.128.x are not CGNAT.
        assert!(!is_cgnat("100.63.255.255".parse().unwrap()));
        assert!(is_cgnat("100.64.0.0".parse().unwrap()));
        assert!(is_cgnat("100.127.255.255".parse().unwrap()));
        assert!(!is_cgnat("100.128.0.0".parse().unwrap()));
        assert!(!is_cgnat("203.0.113.1".parse().unwrap()));
        assert!(is_virtual_interface("wg0"));
        assert!(!is_virtual_interface("en0"));
        assert!(!is_virtual_interface("eth0"));
    }

    #[tokio::test]
    async fn selfcheck_reports_module_rules_and_network() {
        let config = Arc::new(AsyncRwLock::new(FileConfig::default()));
        let runtime = Arc::new(crate::runtime::Runtime::new(config, None, None));
        let results = StunCheck {
            runtime: Arc::clone(&runtime),
        }
        .check(&CheckEnv::default())
        .await;
        let ids: Vec<&'static str> = results.iter().map(|result| result.id).collect();
        assert_eq!(ids, ["stun.module", "stun.rules", "stun.network"]);
        // The module is off by default: informational, with no channels.
        let module = results.iter().find(|r| r.id == "stun.module").unwrap();
        assert_eq!(module.status, Status::Info);
        assert_eq!(module.params["enable"], "false");
        let rules = results.iter().find(|r| r.id == "stun.rules").unwrap();
        assert_eq!(rules.params["channels"], "0");
        assert_eq!(rules.params["ready"], "0");
        // The network finding always carries the classification flags
        // (values depend on the host running the test).
        let network = results.iter().find(|r| r.id == "stun.network").unwrap();
        assert!(network.params.contains_key("public"));
        assert!(network.params.contains_key("cgnat"));
        assert!(network.params.contains_key("private"));
    }
}
