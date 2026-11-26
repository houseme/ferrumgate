//! The system self-check: user-triggered (it contacts outside services),
//! returning only ids, statuses and machine parameters.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, SystemTime},
};

use axum::{Json, http::Method};
use schemars::JsonSchema;
use serde::Serialize;
use tokio::net::TcpListener;

use crate::{ApiRouter, RouteModels};
use fg_core::check::{CheckEnv, CheckResult, Status};

/// Port and address families excluded from the NAT/direct checks: overlay
/// networks (Tailscale, NetBird, EasyTier) legitimately own CGNAT and
/// private ranges that would otherwise read as "behind carrier NAT".
const OVERLAY_PREFIXES: [&str; 5] = ["100.100", "100.115", "100.72", "100.84", "fd7a"];

/// Ports whose availability decides whether the host can serve public
/// traffic directly.
const SERVED_PORTS: [(u16, &str); 2] = [(80, "port.80"), (443, "port.443")];

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SelfcheckResponse {
    pub results: Vec<CheckResult>,
}

pub(super) fn mount(
    router: ApiRouter,
    interfaces: fn() -> Vec<InterfaceAddress>,
    clock_skew: fn() -> Duration,
) -> ApiRouter {
    router.modeled_route(
        Method::POST,
        "/api/system/selfcheck",
        "Run the system self-check (contacts outside services)",
        RouteModels::default().response::<SelfcheckResponse>(),
        move || async move {
            let env = CheckEnv::default();
            let mut results = Vec::new();
            results.extend(address_checks(&interfaces(), &env));
            results.extend(clock_check(clock_skew()));
            results.extend(port_checks().await);
            Json(SelfcheckResponse { results })
        },
    )
}

/// One local interface address, already resolved by the caller.
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub name: String,
}

/// Checks direct public ownership per family and the CGNAT situation,
/// skipping overlay interfaces by name heuristics.
pub fn address_checks(interfaces: &[InterfaceAddress], env: &CheckEnv) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let is_overlay = |name: &str| {
        OVERLAY_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
            || is_overlay_name(name)
    };
    let v4: Vec<&InterfaceAddress> = interfaces
        .iter()
        .filter(|item| item.address.is_ipv4() && !is_overlay(&item.name))
        .collect();
    let has_public_v4 = v4.iter().any(|item| is_public_v4(item.address));
    let has_cgnat = v4.iter().any(|item| is_cgnat(item.address));
    results.push(if has_public_v4 {
        let address = v4
            .iter()
            .find(|item| is_public_v4(item.address))
            .expect("public address found");
        CheckResult::ok("net.direct").param("interface", &address.name)
    } else if has_cgnat {
        let address = v4
            .iter()
            .find(|item| is_cgnat(item.address))
            .expect("CGNAT address found");
        CheckResult::info("net.cgnat")
            .param("interface", &address.name)
            .param("ip", address.address.to_string())
    } else {
        CheckResult::info("net.private")
    });
    if env.public_ipv4.is_some() {
        results.push(CheckResult::ok("net.reachable4"));
    }
    let has_public_v6 = interfaces.iter().any(|item| {
        item.address.is_ipv6() && !is_loopback_v6(item.address) && !is_overlay(&item.name)
    });
    results.push(if has_public_v6 {
        CheckResult::ok("net.direct6")
    } else {
        CheckResult::info("net.no6")
    });
    results
}

fn is_overlay_name(name: &str) -> bool {
    name.starts_with("tailscale")
        || name.starts_with("ts")
        || name.starts_with("netbird")
        || name.starts_with("wt")
        || name.starts_with("utun") && name.len() > 4
        || name.starts_with("easytier")
        || name.starts_with("ZeroTier")
}

fn is_public_v4(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !is_cgnat(IpAddr::V4(ip))
                && !ip.is_broadcast()
                && ip != Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(_) => false,
    }
}

/// Carrier-grade NAT range 100.64.0.0/10.
fn is_cgnat(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
        }
        IpAddr::V6(_) => false,
    }
}

fn is_loopback_v6(address: IpAddr) -> bool {
    match address {
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

pub fn clock_check(skew: Duration) -> Vec<CheckResult> {
    let seconds = skew.as_secs();
    if seconds < 90 {
        vec![CheckResult::ok("time.clock").param("skewSeconds", seconds)]
    } else if seconds < 600 {
        vec![CheckResult::warn("time.drift").param("skewSeconds", seconds)]
    } else {
        vec![CheckResult::fail("time.drift").param("skewSeconds", seconds)]
    }
}

/// Binds port 80 and 443 on a wildcards-free loop to learn availability.
pub async fn port_checks() -> Vec<CheckResult> {
    let mut results = Vec::new();
    for (port, id) in SERVED_PORTS {
        let listener = TcpListener::bind(("0.0.0.0", port)).await;
        results.push(match listener {
            Ok(listener) => {
                drop(listener);
                CheckResult::ok(id)
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                CheckResult::warn(id).param("reason", "permission")
            }
            Err(_) => {
                // Occupied by another process: informational, the host may
                // already run a web server on purpose.
                CheckResult::info(id).param("reason", "inuse")
            }
        });
    }
    results
}

/// Estimates clock skew from an HTTP `Date` header captured by the caller;
/// the probe's response hook supplies the header once wired end to end.
#[cfg_attr(not(test), allow(dead_code))]
pub fn skew_from_date_header(header: &str, now: SystemTime) -> Option<Duration> {
    let parsed = time::OffsetDateTime::parse(
        header.trim(),
        &time::format_description::well_known::Rfc3339,
    )
    .ok()?;
    let server = parsed.into();
    now.duration_since(server).ok().or_else(|| {
        server
            .duration_since(now)
            .ok()
            .map(|delta| Duration::from_secs(delta.as_secs()))
    })
}

/// Parameters stay deterministic for tests.
#[allow(dead_code)]
fn _params_shape() -> BTreeMap<&'static str, String> {
    BTreeMap::new()
}

#[allow(dead_code)]
fn _status_shape() -> Status {
    Status::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_checks_ignore_overlay_interfaces() {
        let interfaces = |list: &[(&str, IpAddr)]| {
            list.iter()
                .map(|(name, address)| InterfaceAddress {
                    name: (*name).to_owned(),
                    address: *address,
                })
                .collect::<Vec<_>>()
        };
        // A Tailscale CGNAT address on its interface must not read as CGNAT.
        let overlay = interfaces(&[
            ("tailscale0", "100.115.92.1".parse().unwrap()),
            ("eth0", "192.168.1.10".parse().unwrap()),
        ]);
        let results = address_checks(&overlay, &CheckEnv::default());
        assert!(
            results.iter().all(|result| result.id != "net.cgnat"),
            "{results:?}"
        );

        // A non-overlay CGNAT address is reported.
        let cgnat = interfaces(&[("eth0", "100.64.1.2".parse().unwrap())]);
        let results = address_checks(&cgnat, &CheckEnv::default());
        assert!(
            results.iter().any(|result| result.id == "net.cgnat"),
            "{results:?}"
        );

        // A direct public address is reported with its interface.
        let public = interfaces(&[("eth0", "203.0.113.7".parse().unwrap())]);
        let results = address_checks(&public, &CheckEnv::default());
        assert!(
            results.iter().any(|result| result.id == "net.direct"),
            "{results:?}"
        );
    }

    #[test]
    fn clock_check_uses_thresholds() {
        assert_eq!(clock_check(Duration::from_secs(5))[0].id, "time.clock");
        assert_eq!(clock_check(Duration::from_secs(120))[0].id, "time.drift");
        assert_eq!(
            clock_check(Duration::from_secs(120))[0].status,
            Status::Warn
        );
        assert_eq!(
            clock_check(Duration::from_secs(700))[0].status,
            Status::Fail
        );
    }

    #[test]
    fn date_header_skew_is_measured() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let fresh = "1970-01-12T13:46:40Z"; // 1_000_000 seconds
        assert_eq!(
            skew_from_date_header(fresh, now),
            Some(Duration::from_secs(0))
        );
        let stale = "1970-01-12T13:46:30Z"; // ten seconds behind
        assert_eq!(
            skew_from_date_header(stale, now),
            Some(Duration::from_secs(10))
        );
        assert_eq!(skew_from_date_header("not a date", now), None);
    }
}
