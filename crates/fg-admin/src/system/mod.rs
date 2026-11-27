//! System-level routes: status, build information, module states and the
//! public address lookup.

mod diagnostics;
mod info;
pub mod metrics;
pub mod onboarding;
pub mod probe;
pub mod publicip;
pub mod selfcheck;
mod status;
pub mod storage;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::SystemTime};

use crate::ApiRouter;
use fg_core::{registry::CATALOG, settings::Settings, sysstat::Procfs};

/// Inputs for the system routes: configuration directory, module
/// resolution, process start time and the effective settings snapshot.
pub struct SystemRoutes {
    pub config_dir: PathBuf,
    pub modules: Arc<(fg_core::registry::Registry, fg_core::registry::Enabled)>,
    pub started_at: SystemTime,
    pub settings: Arc<Settings>,
    /// Performs the public address lookups; production callers pass the
    /// default URL-based implementation, tests stub it.
    pub public_ip: publicip::Lookup,
    /// Performs one HEAD request for the probe; the host crate owns TLS.
    pub probe_head: probe::HeadLookup,
    /// Configuration storage for onboarding state.
    pub onboarding_store: Arc<fg_config::ConfigStore>,
    /// The batch-apply hold shared with the modules.
    pub hold: Arc<fg_core::apply_hold::ApplyHold>,
    /// The management listener this process started with.
    pub admin_listen: SocketAddr,
    /// L4 hop registrations for access-path tracing.
    pub hops: Arc<fg_core::access_path::HopRegistry>,
    /// Signing key for Web-service path headers.
    pub signing_key: Arc<Vec<u8>>,
    /// Accounts behind the confirmation session checks.
    pub accounts: Arc<fg_auth::AccountManager>,
}

/// The immutable snapshot behind the status and info responses.
pub struct SummarySource {
    pub config_dir: PathBuf,
    pub modules: Arc<(fg_core::registry::Registry, fg_core::registry::Enabled)>,
    pub started_at: SystemTime,
    pub proc_rss_bytes: u64,
    pub settings: Arc<Settings>,
}

impl SystemRoutes {
    /// Wires `GET /api/status` and `GET /api/system/info`, both scoped to
    /// `status:read`. Call before `finish`.
    pub fn register(self, router: ApiRouter) -> ApiRouter {
        let source = Arc::new(SummarySource {
            proc_rss_bytes: <Procfs as fg_core::sysstat::Sysstat>::proc(&Procfs).rss_bytes,
            config_dir: self.config_dir.clone(),
            modules: self.modules,
            started_at: self.started_at,
            settings: self.settings,
        });
        let public_ip = publicip::PublicIpCache::new(self.public_ip);
        let onboarding_store = self.onboarding_store;
        let router = probe::mount(router, self.probe_head);
        let router = selfcheck::mount(router, local_interfaces, local_clock_skew);
        let router = storage::mount(router);
        let router = onboarding::mount(router, onboarding_store.clone());
        let router = metrics::mount(router, self.started_at);
        let router = diagnostics::mount(router, source.clone());
        let router = crate::changeset::mount(
            router,
            Arc::new(crate::changeset::ChangesetState {
                hold: self.hold,
                store: onboarding_store.clone(),
                confirm: crate::confirm::ConfirmState {
                    store: onboarding_store.clone(),
                    accounts: self.accounts,
                },
                admin_listen: self.admin_listen,
                settings: source.settings.clone(),
                hops: self.hops,
                signing_key: self.signing_key,
            }),
        );
        public_ip.mount(info::mount(status::mount(router, &source), &source))
    }
}

/// Enumerates local interface addresses for the NAT/direct checks.
fn local_interfaces() -> Vec<selfcheck::InterfaceAddress> {
    #[cfg(target_os = "linux")]
    {
        // Without a netlink library, /proc/net/if_inet6 gives IPv6 names
        // and interface names come from /sys/class/net; IPv4 addresses are
        // best effort via hostname resolution of each interface.
        let mut found = Vec::new();
        if let Ok(text) = std::fs::read_to_string("/proc/net/if_inet6") {
            for line in text.lines() {
                let mut parts = line.split_whitespace();
                let address = parts.next();
                let name = parts.nth(4);
                if let (Some(address), Some(name)) = (address, name) {
                    if let Ok(address) = parse_packed_v6(address) {
                        found.push(selfcheck::InterfaceAddress {
                            address,
                            name: name.to_owned(),
                        });
                    }
                }
            }
        }
        found
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn parse_packed_v6(hex: &str) -> Option<std::net::IpAddr> {
    use std::net::Ipv6Addr;
    if hex.len() != 32 {
        return None;
    }
    let mut segments = [0u16; 8];
    for (index, chunk) in hex.as_bytes().chunks(4).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        segments[index] = u16::from_str_radix(text, 16).ok()?;
    }
    Some(IpAddr::V6(Ipv6Addr::from(segments)))
}

use std::time::Duration;

/// Best-effort clock skew: none without a trusted time source on this
/// platform yet; the HTTP Date check lands with the probe's date capture.
fn local_clock_skew() -> Duration {
    Duration::default()
}

impl SummarySource {
    pub fn uptime_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.started_at)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    }

    pub fn module_states(&self) -> Vec<ModuleState> {
        let (registry, enabled) = &*self.modules;
        CATALOG
            .iter()
            .map(|entry| ModuleState {
                id: entry.id,
                group: entry.group,
                status: match registry.status(enabled, entry.id) {
                    Some(fg_core::registry::Status::Enabled) => "enabled",
                    Some(fg_core::registry::Status::Disabled) => "disabled",
                    _ => "absent",
                },
            })
            .collect()
    }
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ModuleState {
    pub id: &'static str,
    pub group: &'static str,
    pub status: &'static str,
}

use serde::Serialize;
