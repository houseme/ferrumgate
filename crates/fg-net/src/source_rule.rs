//! Rule-level source access control for L4 entries (WP-36): compiled
//! allow/deny network lists with deny-first semantics. Banning and knock
//! gating integrate above this layer.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;

/// Maximum number of entries accepted for a single allow or deny list.
pub const MAX_SOURCE_ENTRIES: usize = 1024;

/// Error raised while compiling a [`SourceRule`]. The `list` field names the
/// offending list so operators see `source.allow` vs `source.deny` context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// A list exceeded [`MAX_SOURCE_ENTRIES`] entries.
    TooManyEntries { list: &'static str },
    /// An entry was neither a bare IP address nor a valid CIDR network.
    InvalidEntry { list: &'static str, index: usize },
    /// A CIDR prefix was longer than its address width allows.
    PrefixTooLong { list: &'static str, index: usize },
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries { list } => write!(
                f,
                "invalid {list}: a source list supports at most {MAX_SOURCE_ENTRIES} entries"
            ),
            Self::InvalidEntry { list, index } => {
                write!(
                    f,
                    "invalid {list}: source entry {index} is not an IP or CIDR"
                )
            }
            Self::PrefixTooLong { list, index } => write!(
                f,
                "invalid {list}: source entry {index} has a prefix longer than its address width"
            ),
        }
    }
}

impl std::error::Error for RuleError {}

/// Raw, user-facing shape of a rule's source access control. Deserialized
/// from configuration; unknown keys are rejected so typos fail loudly.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawSourceRule {
    pub allow: Option<Vec<String>>,
    pub deny: Vec<String>,
}

/// Compiled source access control for one rule. Semantics, evaluated in
/// order: any matching deny entry rejects; if an allow list is present it
/// must match; otherwise the address is permitted.
#[derive(Clone, Debug, Default)]
pub struct SourceRule {
    allow: Option<Vec<IpNet>>,
    deny: Vec<IpNet>,
}

impl SourceRule {
    /// Compiles the raw lists into aggregated networks. Compile errors carry
    /// the offending list name (`source.allow` / `source.deny`). The
    /// deny-first evaluation order is inherent in the compiled shape.
    pub fn compile(config: RawSourceRule) -> Result<Self, RuleError> {
        Ok(Self {
            allow: config
                .allow
                .map(|entries| compile_list("source.allow", entries))
                .transpose()?,
            deny: compile_list("source.deny", config.deny)?,
        })
    }

    /// Deny-first: any matching deny entry rejects; an allow list that is
    /// present must match; an absent allow list accepts the rest. Both the
    /// address and any mapped entries are canonicalized, so an IPv4 peer is
    /// always matched against IPv4 networks regardless of how either side
    /// was written.
    pub fn permits(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        !self.deny.iter().any(|network| network.contains(&address))
            && self
                .allow
                .as_ref()
                .is_none_or(|allow| allow.iter().any(|network| network.contains(&address)))
    }
}

/// Compiles a source list with the neutral `source` label. Rule compilation
/// goes through [`SourceRule::compile`], which names the specific list.
pub fn compile_networks(entries: Vec<String>) -> Result<Vec<IpNet>, RuleError> {
    compile_list("source", entries)
}

/// Compiles a list of IP / CIDR entries:
/// - at most [`MAX_SOURCE_ENTRIES`] entries;
/// - a bare IP becomes a /32 (IPv4) or /128 (IPv6) host network;
/// - `::ffff:`-mapped IPv6 networks with prefix >= 96 are reduced to plain
///   IPv4 networks (prefix minus 96), so mapped and plain forms merge;
/// - every network is truncated to its host bits and the result is
///   aggregated into a minimal set of covering prefixes.
fn compile_list(list: &'static str, entries: Vec<String>) -> Result<Vec<IpNet>, RuleError> {
    if entries.len() > MAX_SOURCE_ENTRIES {
        return Err(RuleError::TooManyEntries { list });
    }
    let mut networks = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let network = match entry.parse::<IpAddr>() {
            Ok(address) => IpNet::from(address.to_canonical()),
            Err(_) => match entry.parse::<IpNet>() {
                Ok(IpNet::V6(network)) if network.prefix_len() >= 96 => {
                    match network.network().to_ipv4_mapped() {
                        Some(mapped) => IpNet::V4(
                            Ipv4Net::new(mapped, network.prefix_len() - 96)
                                .map_err(|_| RuleError::PrefixTooLong { list, index })?,
                        ),
                        None => IpNet::V6(network),
                    }
                }
                Ok(network) => network,
                Err(_) => return Err(RuleError::InvalidEntry { list, index }),
            },
        };
        networks.push(network.trunc());
    }
    Ok(IpNet::aggregate(&networks))
}

/// Live ban-registry lookup (WP-26 will provide the real implementation).
/// Queried per admission decision, so bans take effect without rebuilding
/// the filter.
pub trait BanCheck: Send + Sync {
    fn banned(&self, address: IpAddr) -> bool;
}

/// Live knock-status gate (WP-50 will provide the real implementation).
/// Queried per admission decision when knocking is required.
pub trait KnockGate: Send + Sync {
    fn open(&self, address: IpAddr) -> bool;
}

/// Full entry admission pipeline: 封禁 → 优先拒绝 → 白名单/黑名单 → 敲门.
/// Composes a compiled [`SourceRule`] with optional ban-registry and
/// knock-gate hooks; both hooks are queried live on every decision.
#[derive(Clone)]
pub struct AccessFilter {
    rule: SourceRule,
    ban: Option<Arc<dyn BanCheck>>,
    knock: Option<Arc<dyn KnockGate>>,
    require_knock: bool,
}

impl AccessFilter {
    /// A filter without ban or knock hooks decides purely on the rule.
    pub fn new(rule: SourceRule) -> Self {
        Self {
            rule,
            ban: None,
            knock: None,
            require_knock: false,
        }
    }

    /// Attaches a live ban registry consulted before the rule.
    pub fn with_ban(mut self, ban: Arc<dyn BanCheck>) -> Self {
        self.ban = Some(ban);
        self
    }

    /// Attaches a knock gate; knocking becomes required for admission.
    pub fn with_knock(mut self, knock: Arc<dyn KnockGate>) -> Self {
        self.knock = Some(knock);
        self.require_knock = true;
        self
    }

    /// Admission order: a banned address is rejected outright; a deny-list
    /// match is rejected; an allow list, when present, must match; when
    /// knocking is required the gate must be open for the address; else the
    /// address is admitted.
    pub fn admits(&self, address: IpAddr) -> bool {
        if let Some(ban) = &self.ban
            && ban.banned(address)
        {
            return false;
        }
        if !self.rule.permits(address) {
            return false;
        }
        if self.require_knock {
            return self.knock.as_ref().is_some_and(|gate| gate.open(address));
        }
        true
    }

    /// An empty filter (empty rule, no ban source, no knock requirement)
    /// does nothing at the entry: it admits everything.
    pub fn is_empty(&self) -> bool {
        self.ban.is_none()
            && !self.require_knock
            && self.rule.allow.is_none()
            && self.rule.deny.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct FixedBan(IpAddr);

    impl BanCheck for FixedBan {
        fn banned(&self, address: IpAddr) -> bool {
            address == self.0
        }
    }

    #[derive(Debug)]
    struct FixedGate(bool);

    impl KnockGate for FixedGate {
        fn open(&self, _address: IpAddr) -> bool {
            self.0
        }
    }

    fn rule(allow: Option<Vec<&str>>, deny: Vec<&str>) -> SourceRule {
        SourceRule::compile(RawSourceRule {
            allow: allow.map(|entries| entries.into_iter().map(String::from).collect()),
            deny: deny.into_iter().map(String::from).collect(),
        })
        .expect("rule should compile")
    }

    fn addr(value: &str) -> IpAddr {
        value.parse().expect("test address should parse")
    }

    /// Plan order: 封禁 → 优先拒绝 → 白名单/黑名单 → 敲门.
    #[test]
    fn source_rule_order_ban_deny_list_mode_knock() {
        let banned = addr("10.0.0.5");

        // Ban wins even though the address matches the allow list.
        let filter = AccessFilter::new(rule(Some(vec!["10.0.0.0/24"]), vec![]))
            .with_ban(Arc::new(FixedBan(banned)));
        assert!(!filter.admits(banned));
        assert!(filter.admits(addr("10.0.0.6")));

        // Deny-first inside the rule: allow match does not rescue a deny.
        let filter = AccessFilter::new(rule(Some(vec!["10.0.0.0/24"]), vec!["10.0.0.5"]));
        assert!(!filter.admits(banned));
        assert!(filter.admits(addr("10.0.0.6")));

        // Allow list absent: deny-only, everything else admitted.
        let filter = AccessFilter::new(rule(None, vec!["10.0.0.5"]));
        assert!(!filter.admits(banned));
        assert!(filter.admits(addr("10.0.0.6")));

        // Knock required: a closed gate rejects even allow-listed
        // addresses, an open gate admits them, and the allow list still
        // applies under an open gate.
        let filter = AccessFilter::new(rule(Some(vec!["10.0.0.5"]), vec![]))
            .with_knock(Arc::new(FixedGate(false)));
        assert!(!filter.admits(banned));
        let open = AccessFilter::new(rule(Some(vec!["10.0.0.5"]), vec![]))
            .with_knock(Arc::new(FixedGate(true)));
        assert!(open.admits(banned));
        assert!(!open.admits(addr("10.0.0.6")));

        // An empty filter is a no-op at the entry.
        let empty = AccessFilter::new(SourceRule::default());
        assert!(empty.is_empty());
        assert!(empty.admits(banned));

        // Hooks or configured lists make the filter non-empty.
        assert!(!AccessFilter::new(rule(None, vec!["10.0.0.5"])).is_empty());
        assert!(
            !AccessFilter::new(SourceRule::default())
                .with_ban(Arc::new(FixedBan(banned)))
                .is_empty()
        );
        assert!(
            !AccessFilter::new(SourceRule::default())
                .with_knock(Arc::new(FixedGate(true)))
                .is_empty()
        );
    }

    /// The ban registry is consulted live: mutations to the backing list
    /// take effect through the same filter instance, with no rebuild.
    #[test]
    fn source_rule_queries_registry_live() {
        struct Registry(Mutex<Vec<IpAddr>>);

        impl BanCheck for Registry {
            fn banned(&self, address: IpAddr) -> bool {
                self.0.lock().expect("registry lock").contains(&address)
            }
        }

        let registry = Arc::new(Registry(Mutex::new(Vec::new())));
        let filter = AccessFilter::new(SourceRule::default())
            .with_ban(Arc::clone(&registry) as Arc<dyn BanCheck>);
        let peer = addr("203.0.113.7");

        assert!(filter.admits(peer));
        registry.0.lock().unwrap().push(peer);
        assert!(!filter.admits(peer));
        registry.0.lock().unwrap().clear();
        assert!(filter.admits(peer));
    }

    /// Ported from fg-gateway source_policy: deny-first evaluation and
    /// canonicalization of `::ffff:`-mapped addresses and prefixes.
    #[test]
    fn permits_denies_first_and_normalizes_mapped_addresses() {
        let policy = rule(
            Some(vec!["::ffff:192.0.2.0/120", "2001:db8::/32"]),
            vec!["192.0.2.9", "2001:db8:1::/48"],
        );
        assert!(policy.permits(addr("192.0.2.8")));
        assert!(!policy.permits(addr("::ffff:192.0.2.9")));
        assert!(policy.permits(addr("2001:db8:2::5")));
        assert!(!policy.permits(addr("2001:db8:1::5")));
        // Allow list present, no match: rejected.
        assert!(!policy.permits(addr("198.51.100.2")));

        // An empty-but-present allow list admits nothing.
        assert!(!rule(Some(vec![]), vec![]).permits(addr("::1")));
    }

    /// Ported from fg-gateway source_policy: single IPs become host
    /// networks, mapped prefixes reduce to IPv4, and the result aggregates.
    #[test]
    fn compile_networks_reduces_mapped_prefixes_and_aggregates() {
        let networks = compile_networks(vec![
            "192.0.2.0".into(),
            "192.0.2.1".into(),
            "::ffff:198.51.100.0/120".into(),
            "198.51.100.5".into(),
        ])
        .expect("entries should compile");
        assert_eq!(
            networks,
            vec![
                IpNet::new(addr("192.0.2.0"), 31).unwrap(),
                IpNet::new(addr("198.51.100.0"), 24).unwrap(),
            ]
        );

        // IPv6 entries stay IPv6.
        let networks =
            compile_networks(vec!["2001:db8::/32".into()]).expect("entries should compile");
        assert_eq!(networks, vec![IpNet::new(addr("2001:db8::"), 32).unwrap()]);
    }

    /// Compile errors name the offending list and enforce the entry cap.
    #[test]
    fn compile_errors_name_the_list_and_cap_entries() {
        let error = SourceRule::compile(RawSourceRule {
            allow: Some(vec!["not-a-network".into()]),
            deny: vec![],
        })
        .expect_err("bad allow entry must fail");
        assert_eq!(
            error,
            RuleError::InvalidEntry {
                list: "source.allow",
                index: 0
            }
        );
        assert!(error.to_string().contains("source.allow"));

        let error = SourceRule::compile(RawSourceRule {
            allow: None,
            deny: vec!["10.0.0.0/40".into()],
        })
        .expect_err("bad deny entry must fail");
        assert_eq!(
            error,
            RuleError::InvalidEntry {
                list: "source.deny",
                index: 0
            }
        );
        assert!(error.to_string().contains("source.deny"));

        let error = compile_networks(
            (0..MAX_SOURCE_ENTRIES + 1)
                .map(|index| format!("2001:db8:{index:x}::/48"))
                .collect(),
        )
        .expect_err("over-long list must fail");
        assert_eq!(error, RuleError::TooManyEntries { list: "source" });
        assert!(error.to_string().contains("at most 1024 entries"));
    }
}
