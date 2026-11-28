//! LAN scan (WP-71 §3.3): the network is inferred from the local NICs (or
//! taken from the request); every host address is probed with an ICMP echo
//! through [`crate::ping::ping_once`]. Alive hosts are reported with the
//! round-trip time and, when requested, a reverse-resolved host name. The
//! first version does no ARP and no MAC vendor identification (WP-71 §8:
//! recorded as follow-up work); IPv4 only, networks beyond a /24 are
//! clamped to the /24 containing the interface address.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use ipnet::Ipv4Net;
use tokio::sync::Semaphore;

use crate::jobs::{JobError, JobFut, JobHandle};
use crate::model::{LanScanParams, limits};

/// Concurrent probes within one scan.
const SCAN_CONCURRENCY: usize = 50;
/// Concurrent reverse lookups.
const NAME_CONCURRENCY: usize = 10;

/// Masks the host bits of `ip` below `prefix`.
fn network_address(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let address = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(address & mask)
}

/// Turns a dotted netmask into a prefix length (contiguous masks only;
/// anything odd falls back to 24).
fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    let ones = bits.leading_ones() as u8;
    if bits.count_ones() as u8 == ones {
        ones
    } else {
        24
    }
}

/// The IPv4 networks to scan, inferred from the local NICs when `cidr` is
/// empty. Prefixes below /24 are clamped to the /24 containing the address,
/// and each network is capped at [`limits::LAN_SCAN_MAX_HOSTS`] addresses.
pub fn discover_networks() -> Result<Vec<Ipv4Net>, String> {
    let interfaces =
        if_addrs::get_if_addrs().map_err(|error| format!("无法枚举本机网卡：{error}"))?;
    let mut networks: Vec<Ipv4Net> = Vec::new();
    for interface in interfaces {
        if let if_addrs::IfAddr::V4(v4) = interface.addr {
            let prefix = mask_to_prefix(v4.netmask).clamp(0, 32);
            let (prefix, address) = if prefix < 24 {
                (24, network_address(v4.ip, 24))
            } else {
                (prefix, network_address(v4.ip, prefix))
            };
            if let Ok(network) = Ipv4Net::new(address, prefix)
                && !networks.contains(&network)
            {
                networks.push(network);
            }
        }
    }
    Ok(networks)
}

/// The host addresses of one network (ipnet's `hosts()` already skips
/// network/broadcast below a /31), capped at the per-network limit, with
/// denied entries removed. Returns the filtered list and the pre-filter
/// count.
fn host_list(network: Ipv4Net, deny: &[crate::validate::DenyEntry]) -> (Vec<Ipv4Addr>, usize) {
    let mut hosts: Vec<Ipv4Addr> = network.hosts().take(limits::LAN_SCAN_MAX_HOSTS).collect();
    let total = hosts.len();
    hosts.retain(|ip| crate::validate::deny_reason("", &[(*ip).into()], deny).is_none());
    (hosts, total)
}

/// Runs the LAN-scan tool job.
pub fn run(
    params: &LanScanParams,
    handle: JobHandle,
    deny: &[crate::validate::DenyEntry],
) -> JobFut {
    let params = params.clone();
    let deny = deny.to_vec();
    Box::pin(async move {
        let include_names = params.include_names.unwrap_or(false);
        let networks: Vec<Ipv4Net> = match params.cidr.as_deref().map(str::trim) {
            Some("") | None => discover_networks().map_err(JobError::Message)?,
            Some(text) => {
                let network: Ipv4Net = text.parse().map_err(|_| {
                    JobError::Message(format!(
                        "无效的网段 {text}（应为 192.168.1.0/24 形式，首版只支持 IPv4）"
                    ))
                })?;
                vec![network]
            }
        };
        if networks.is_empty() {
            return Err(JobError::Message("未找到可扫描的网段".into()));
        }
        let mut probe_total = 0usize;
        let mut alive: BTreeMap<Ipv4Net, Vec<(Ipv4Addr, Duration)>> = BTreeMap::new();
        'nets: for network in &networks {
            let (mut hosts, total) = host_list(*network, &deny);
            let denied = total - hosts.len();
            if denied > 0 {
                handle.line(format!(
                    "网段 {network}：跳过 {denied} 个在拒绝列表中的地址"
                ));
            }
            if hosts.is_empty() {
                handle.line(format!("网段 {network}：没有可探测的地址"));
                continue;
            }
            let budget = limits::LAN_SCAN_MAX_TOTAL.saturating_sub(probe_total);
            if budget == 0 {
                handle.line(format!(
                    "已达总地址上限 {}，剩余网段跳过",
                    limits::LAN_SCAN_MAX_TOTAL
                ));
                break 'nets;
            }
            if hosts.len() > budget {
                hosts.truncate(budget);
            }
            let scanned = hosts.len();
            probe_total += scanned;
            handle.line(format!("扫描网段 {network}（{scanned} 个地址）"));
            let semaphore = Arc::new(Semaphore::new(SCAN_CONCURRENCY));
            let mut tasks = Vec::with_capacity(scanned);
            for ip in hosts {
                let permit = Arc::clone(&semaphore);
                let cancel = handle.token().clone();
                tasks.push(tokio::spawn(async move {
                    let _permit = permit.acquire_owned().await.ok()?;
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => None,
                        result = crate::ping::ping_once(ip.into(), limits::PING_TIMEOUT) => {
                            result.ok().map(|rtt| (ip, rtt))
                        }
                    }
                }));
            }
            let mut found = Vec::new();
            for task in tasks {
                if let Ok(Some(entry)) = task.await {
                    found.push(entry);
                }
            }
            found.sort_by_key(|(ip, _)| *ip);
            if handle.is_cancelled() {
                break 'nets;
            }
            if include_names {
                // Reverse lookups run concurrently, capped per network.
                let names = Arc::new(Semaphore::new(NAME_CONCURRENCY));
                let mut lookups = Vec::with_capacity(found.len());
                for (ip, rtt) in std::mem::take(&mut found) {
                    let permit = Arc::clone(&names);
                    lookups.push(tokio::spawn(async move {
                        let _permit = permit.acquire_owned().await.ok()?;
                        let name =
                            crate::dns_lookup::reverse_lookup(ip.into(), Duration::from_secs(2))
                                .await;
                        Some((ip, rtt, name))
                    }));
                }
                for lookup in lookups {
                    if let Ok(Some((ip, rtt, name))) = lookup.await {
                        match name {
                            Some(name) => handle.line(format!(
                                "{ip} 在线（{:.1} ms），主机名 {name}",
                                rtt.as_secs_f64() * 1000.0
                            )),
                            None => handle
                                .line(format!("{ip} 在线（{:.1} ms）", rtt.as_secs_f64() * 1000.0)),
                        }
                    }
                }
            } else {
                for (ip, rtt) in &found {
                    handle.line(format!("{ip} 在线（{:.1} ms）", rtt.as_secs_f64() * 1000.0));
                }
            }
            handle.line(format!("网段 {network}：{}/{} 在线", found.len(), scanned));
            alive.insert(*network, found);
        }
        if probe_total == 0 {
            return Err(JobError::Message("没有可探测的地址".into()));
        }
        let found: usize = alive.values().map(Vec::len).sum();
        handle.line(format!(
            "扫描完成：共探测 {probe_total} 个地址，{found} 个在线（首版不识别 MAC 厂商）"
        ));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_scan_network_address_masks_host_bits() {
        assert_eq!(
            network_address("192.168.19.55".parse().unwrap(), 24),
            "192.168.19.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            network_address("10.1.2.3".parse::<Ipv4Addr>().unwrap(), 8),
            "10.0.0.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            network_address("10.1.2.3".parse::<Ipv4Addr>().unwrap(), 32),
            "10.1.2.3".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            network_address("10.1.2.3".parse::<Ipv4Addr>().unwrap(), 0),
            "0.0.0.0".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn lan_scan_mask_to_prefix_counts_contiguous_bits() {
        assert_eq!(mask_to_prefix("255.255.255.0".parse().unwrap()), 24);
        assert_eq!(mask_to_prefix("255.255.0.0".parse().unwrap()), 16);
        assert_eq!(mask_to_prefix("255.255.255.255".parse().unwrap()), 32);
        assert_eq!(mask_to_prefix("0.0.0.0".parse::<Ipv4Addr>().unwrap()), 0);
        assert_eq!(mask_to_prefix("255.0.255.0".parse().unwrap()), 24);
    }

    #[test]
    fn lan_scan_host_list_skips_network_broadcast_and_denied() {
        let network: Ipv4Net = "192.168.1.0/30".parse().unwrap();
        let (hosts, total) = host_list(network, &[]);
        // /30: network and broadcast are excluded, two hosts remain.
        assert_eq!(
            hosts,
            vec![
                "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
                "192.168.1.2".parse::<Ipv4Addr>().unwrap()
            ]
        );
        assert_eq!(total, 2);
        // A single-address network keeps its only host.
        let single: Ipv4Net = "127.0.0.1/32".parse().unwrap();
        let (hosts, _) = host_list(single, &[]);
        assert_eq!(hosts, vec!["127.0.0.1".parse::<Ipv4Addr>().unwrap()]);
        // Denied addresses are filtered out.
        let deny = crate::validate::parse_deny_list(&["192.168.1.2".into()]);
        let (hosts, total) = host_list(network, &deny);
        assert_eq!(hosts, vec!["192.168.1.1".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(total, 2);
    }
}
