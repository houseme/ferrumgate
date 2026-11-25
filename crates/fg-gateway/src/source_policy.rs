use std::net::IpAddr;

use anyhow::{Context, Result, ensure};
use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RawSourcePolicy {
    allow: Option<Vec<String>>,
    deny: Vec<String>,
}

#[derive(Clone, Default)]
pub(crate) struct SourcePolicy {
    allow: Option<Vec<IpNet>>,
    deny: Vec<IpNet>,
}

impl SourcePolicy {
    pub fn compile(config: RawSourcePolicy) -> Result<Self> {
        Ok(Self {
            allow: config
                .allow
                .map(compile_networks)
                .transpose()
                .context("invalid source.allow")?,
            deny: compile_networks(config.deny).context("invalid source.deny")?,
        })
    }

    pub fn permits(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        !self.deny.iter().any(|network| network.contains(&address))
            && self
                .allow
                .as_ref()
                .is_none_or(|allow| allow.iter().any(|network| network.contains(&address)))
    }
}

fn compile_networks(entries: Vec<String>) -> Result<Vec<IpNet>> {
    ensure!(
        entries.len() <= 1024,
        "a source list supports at most 1024 entries"
    );
    let mut networks = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let address = entry.parse::<IpAddr>().ok();
        let network = if let Some(address) = address {
            IpNet::from(address.to_canonical())
        } else {
            match entry
                .parse::<IpNet>()
                .with_context(|| format!("source entry {index} is not an IP or CIDR"))?
            {
                IpNet::V6(network) if network.prefix_len() >= 96 => {
                    if let Some(mapped) = network.network().to_ipv4_mapped() {
                        IpNet::V4(Ipv4Net::new(mapped, network.prefix_len() - 96)?)
                    } else {
                        IpNet::V6(network)
                    }
                }
                network => network,
            }
        };
        networks.push(network.trunc());
    }
    Ok(IpNet::aggregate(&networks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_denials_first_and_normalizes_mapped_addresses() -> Result<()> {
        let policy = SourcePolicy::compile(RawSourcePolicy {
            allow: Some(vec!["::ffff:192.0.2.0/120".into(), "2001:db8::/32".into()]),
            deny: vec!["192.0.2.9".into(), "2001:db8:1::/48".into()],
        })?;
        assert!(policy.permits("192.0.2.8".parse()?));
        assert!(!policy.permits("::ffff:192.0.2.9".parse()?));
        assert!(policy.permits("2001:db8:2::5".parse()?));
        assert!(!policy.permits("2001:db8:1::5".parse()?));
        assert!(!policy.permits("198.51.100.2".parse()?));
        assert!(
            !SourcePolicy::compile(RawSourcePolicy {
                allow: Some(vec![]),
                deny: vec![]
            })?
            .permits("::1".parse()?)
        );
        Ok(())
    }
}
