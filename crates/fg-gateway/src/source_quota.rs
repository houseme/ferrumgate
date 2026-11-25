use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
};

#[derive(Default)]
pub(crate) struct SourceQuota {
    active: Mutex<HashMap<IpAddr, usize>>,
}

pub(crate) struct SourceLease {
    quota: Arc<SourceQuota>,
    group: IpAddr,
}

impl SourceQuota {
    pub fn acquire(self: &Arc<Self>, address: IpAddr, limit: usize) -> Option<SourceLease> {
        let group = source_group(address);
        let mut active = self.active.lock().expect("TCP source quota lock");
        let count = active.entry(group).or_default();
        if *count >= limit {
            return None;
        }
        *count += 1;
        Some(SourceLease {
            quota: self.clone(),
            group,
        })
    }
}

impl Drop for SourceLease {
    fn drop(&mut self) {
        let mut active = self.quota.active.lock().expect("TCP source quota lock");
        if let Some(count) = active.get_mut(&self.group) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.group);
            }
        }
    }
}

fn source_group(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(u128::from(address) & (u128::MAX << 64))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_ipv6_by_prefix_and_releases_slots() -> anyhow::Result<()> {
        let quota = Arc::new(SourceQuota::default());
        let hold = quota.acquire("2001:db8:1:2::1".parse()?, 1).unwrap();
        assert!(quota.acquire("2001:db8:1:2::2".parse()?, 1).is_none());
        assert!(quota.acquire("2001:db8:1:3::1".parse()?, 1).is_some());
        drop(hold);
        assert!(quota.acquire("2001:db8:1:2::2".parse()?, 1).is_some());

        let _mapped = quota.acquire("::ffff:192.0.2.1".parse()?, 1).unwrap();
        assert!(quota.acquire("192.0.2.1".parse()?, 1).is_none());
        assert!(quota.acquire("192.0.2.2".parse()?, 1).is_some());
        Ok(())
    }
}
