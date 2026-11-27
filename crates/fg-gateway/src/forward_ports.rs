use std::net::SocketAddr;

use anyhow::{Context, Result, ensure};
use fg_net::ports::{MAX_PORTS, parse_ports};

pub(crate) const MAX_LISTENERS: usize = MAX_PORTS;

pub(crate) fn parse(address: &str) -> Result<Vec<SocketAddr>> {
    if let Ok(single) = address.parse::<SocketAddr>() {
        return Ok(vec![single]);
    }

    let (host, ports) = address
        .rsplit_once(':')
        .context("expected an IP address and port list")?;
    let mut address = format!("{host}:0")
        .parse::<SocketAddr>()
        .context("invalid socket address")?;
    let list = parse_ports(ports).context("invalid port list")?;
    Ok(list
        .ports
        .into_iter()
        .map(|port| {
            address.set_port(port);
            address
        })
        .collect())
}

pub(crate) fn targets(address: &str, listener_count: usize) -> Result<Vec<SocketAddr>> {
    let mut targets = parse(address)?;
    ensure!(
        targets.len() == 1 || targets.len() == listener_count,
        "target must have one port or the same number of ports as the listener"
    );
    targets.resize(listener_count, targets[0]);
    Ok(targets)
}

/// Counts the expanded ports of a bare port list (no host) using the
/// shared parser; used by validation before any socket exists.
pub(crate) fn listen_count(ports: &str) -> Result<usize, String> {
    match fg_net::ports::parse_ports(ports) {
        Ok(list) => Ok(list.ports.len()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_ranges_in_written_order_and_preserves_ipv6_scope() -> Result<()> {
        let expected = ["[fe80::1%3]:90", "[fe80::1%3]:81", "[fe80::1%3]:82"];
        let expected = expected.map(|address| address.parse::<SocketAddr>().unwrap());
        assert_eq!(parse("[fe80::1%3]:90,81-82")?, expected);
        assert_eq!(targets("[fe80::1%3]:90", 3)?, [expected[0]; 3]);
        assert_eq!(parse("127.0.0.1:65472-65535")?.len(), 64);
        for invalid in [
            "127.0.0.1:65471-65535",
            "127.0.0.1:0-1",
            "127.0.0.1:6-5",
            "127.0.0.1:1,65536",
            "127.0.0.1:,",
            "::1:80-81",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
        Ok(())
    }
}
