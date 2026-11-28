//! TCP connect probe (WP-71 §3.3): at most 1024 ports per run, 100
//! concurrent connects, 1.5s connect timeout each. Only open ports are
//! listed, with the well-known service name and the connect duration.
//! Native tokio TCP — no external commands involved.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::jobs::{JobError, JobFut, JobHandle};
use crate::model::{PortProbeParams, limits};
use crate::validate;

/// Well-known service names shown next to open ports (WP-71 §3.3: ssh,
/// http, https, mysql, redis, postgres, rdp 等).
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        67 | 68 => "dhcp",
        80 => "http",
        110 => "pop3",
        113 => "ident",
        123 => "ntp",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        500 => "isakmp",
        514 => "syslog",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1194 => "openvpn",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        2181 => "zookeeper",
        3128 => "squid",
        3306 => "mysql",
        3389 => "rdp",
        4443 => "https-alt",
        4500 => "ipsec",
        5060 => "sip",
        5432 => "postgres",
        5555 => "adb",
        5900 => "vnc",
        6379 => "redis",
        6443 => "kubernetes",
        8080 => "http-alt",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "port9000",
        9090 => "prometheus",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        51820 => "wireguard",
        64738 => "mumble",
        _ => return None,
    })
}

/// One probe result for an open port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPort {
    pub port: u16,
    pub elapsed: Duration,
}

/// Probes one port; `Ok` with the duration when the connection succeeded.
/// `connect` on a `SocketAddr` does no resolution, so the timeout bounds
/// the connect exactly.
pub async fn probe_port(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<Duration, std::io::Error> {
    let started = Instant::now();
    let connect = TcpStream::connect(SocketAddr::new(ip, port));
    match tokio::time::timeout(timeout, connect).await {
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connect timeout",
        )),
        Ok(Ok(stream)) => {
            drop(stream);
            Ok(started.elapsed())
        }
        Ok(Err(error)) => Err(error),
    }
}

/// Runs the port-probe tool job.
pub fn run(params: &PortProbeParams, handle: JobHandle, deny: &[validate::DenyEntry]) -> JobFut {
    let params = params.clone();
    let deny = deny.to_vec();
    Box::pin(async move {
        let concurrency = params
            .concurrency
            .unwrap_or(limits::PORT_PROBE_CONCURRENCY)
            .clamp(1, 256);
        let timeout = crate::ping::duration_from_secs_f64(
            params
                .timeout
                .unwrap_or(limits::PORT_PROBE_TIMEOUT.as_secs_f64()),
            0.05,
            30.0,
        );
        let ports = validate::parse_ports(&params.ports, limits::PORT_PROBE_MAX_PORTS)
            .map_err(|error| JobError::Message(error.to_string()))?;
        let target = params.target.trim().to_owned();
        if !validate::valid_target(&target) {
            return Err(JobError::Message(format!("无效的目标 {target}")));
        }
        let ip = crate::dns_lookup::resolve_target(&target)
            .await
            .map_err(JobError::Message)?;
        if let Some(reason) = validate::deny_reason(&target, &[ip], &deny) {
            return Err(JobError::Message(reason));
        }
        handle.line(format!(
            "TCP 探测 {target}（{ip}，{}）：{} 个端口，并发 {concurrency}，超时 {:.1} 秒",
            validate::classify(ip).label(),
            ports.len(),
            timeout.as_secs_f64(),
        ));
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let mut tasks = Vec::with_capacity(ports.len());
        for port in ports {
            let permit = Arc::clone(&semaphore);
            let cancel = handle.token().clone();
            tasks.push(tokio::spawn(async move {
                let _permit = permit.acquire_owned().await.ok()?;
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => None,
                    result = probe_port(ip, port, timeout) => {
                        result.ok().map(|elapsed| OpenPort { port, elapsed })
                    }
                }
            }));
        }
        let mut open: Vec<OpenPort> = Vec::new();
        let mut closed = 0usize;
        for task in tasks {
            match task.await {
                Ok(Some(result)) => open.push(result),
                Ok(None) => closed += 1,
                Err(_) => closed += 1,
            }
        }
        open.sort_by_key(|entry| entry.port);
        for entry in &open {
            match service_name(entry.port) {
                Some(service) => handle.line(format!(
                    "{}/tcp 开放 {}（{:.1} ms）",
                    entry.port,
                    service,
                    entry.elapsed.as_secs_f64() * 1000.0
                )),
                None => handle.line(format!(
                    "{}/tcp 开放（{:.1} ms）",
                    entry.port,
                    entry.elapsed.as_secs_f64() * 1000.0
                )),
            }
        }
        if handle.is_cancelled() {
            return Err(JobError::Message("探测被中止".into()));
        }
        handle.line(format!(
            "共探测 {} 个端口，开放 {} 个（{} 个未开放或超时）",
            open.len() + closed,
            open.len(),
            closed
        ));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_probe_service_names_cover_common_ports() {
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(80), Some("http"));
        assert_eq!(service_name(443), Some("https"));
        assert_eq!(service_name(3306), Some("mysql"));
        assert_eq!(service_name(6379), Some("redis"));
        assert_eq!(service_name(5432), Some("postgres"));
        assert_eq!(service_name(3389), Some("rdp"));
        assert_eq!(service_name(7777), None);
    }
}
