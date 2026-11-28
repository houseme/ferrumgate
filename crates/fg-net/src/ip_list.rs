//! Subscription IP lists (WP-26 step: `ip_list.rs`): text parsing into
//! ordered, merged spans, and the key registry the rules query lock-free.
//! One list holds at most [`MAX_ENTRIES`] entries; unknown lines are
//! counted, not fatal (annotations like `1.2.3.0/24 广东电信` parse).
#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

/// Entries per list (upstream `MaxEntries`).
pub const MAX_ENTRIES: usize = 1_000_000;

/// One merged, closed address span (both bounds inclusive), kept in one
/// family per set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Span {
    V4(std::net::Ipv4Addr, std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr, std::net::Ipv6Addr),
}

/// A parsed address or range line: `1.2.3.4`, `10.0.0.0/8`,
/// `10.0.0.1-10.0.0.9`.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    InvalidLine(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLine(line) => write!(f, "无法识别的行：{line}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The parse result: the set, how many lines fed it, and the unrecognized
/// lines (annotations are normal — the count drives the UI's `skipped`).
pub struct ParsedSet {
    pub set: IpSet,
    pub entries: usize,
    pub skipped: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct IpSet {
    v4: Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)>,
    v6: Vec<(std::net::Ipv6Addr, std::net::Ipv6Addr)>,
}

impl IpSet {
    /// Parses list text (comments `#` `;` `//`, first field per line)
    /// into an ordered, merged set. More than [`MAX_ENTRIES`] recognized
    /// entries is an error.
    pub fn parse(text: &[u8]) -> Result<ParsedSet, ParseError> {
        let text = String::from_utf8_lossy(text);
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut skipped = Vec::new();
        for line in text.lines() {
            // Strip the comment forms; take the first remaining field so
            // annotated lines (`1.2.3.0/24 广东电信`) still parse.
            let line = line
                .split('#')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("");
            let line = match line.split_once("//") {
                Some((before, _)) => before,
                None => line,
            };
            let field = line.split_whitespace().next().unwrap_or("");
            if field.is_empty() {
                continue;
            }
            match parse_entry(field) {
                Some(Span::V4(start, end)) => v4.push((start, end)),
                Some(Span::V6(start, end)) => v6.push((start, end)),
                None => skipped.push(field.to_owned()),
            }
        }
        if v4.len() + v6.len() > MAX_ENTRIES {
            return Err(ParseError::InvalidLine(format!(
                "条目超过 {} 上限",
                MAX_ENTRIES
            )));
        }
        let entries = v4.len() + v6.len();
        let set = IpSet {
            v4: merge_v4(v4),
            v6: merge_v6(v6),
        };
        Ok(ParsedSet {
            set,
            entries,
            skipped,
        })
    }

    /// Binary search over the merged spans; IPv4-mapped IPv6 addresses
    /// compare as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => return self.contains_v4(v4),
                None => return self.contains_v6(v6),
            },
        };
        self.contains_v4(ip)
    }

    fn contains_v4(&self, ip: std::net::Ipv4Addr) -> bool {
        self.v4
            .binary_search_by(|(start, end)| {
                if ip < *start {
                    std::cmp::Ordering::Greater
                } else if ip > *end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    fn contains_v6(&self, ip: std::net::Ipv6Addr) -> bool {
        self.v6
            .binary_search_by(|(start, end)| {
                if ip < *start {
                    std::cmp::Ordering::Greater
                } else if ip > *end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

/// Parses one entry into a span.
fn parse_entry(field: &str) -> Option<Span> {
    use std::str::FromStr;
    if let Ok(net) = ipnet::IpNet::from_str(field) {
        return match net {
            ipnet::IpNet::V4(net) => Some(Span::V4(network_start(&net), broadcast_end(&net))),
            ipnet::IpNet::V6(net) => Some(Span::V6(network_start6(&net), broadcast_end6(&net))),
        };
    }
    if let Some((start, end)) = field.split_once('-') {
        let (start, end) = (
            IpAddr::from_str(start.trim()).ok()?,
            IpAddr::from_str(end.trim()).ok()?,
        );
        return match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => Some(Span::V4(start, end)),
            (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => Some(Span::V6(start, end)),
            _ => None,
        };
    }
    match IpAddr::from_str(field).ok()? {
        IpAddr::V4(ip) => Some(Span::V4(ip, ip)),
        IpAddr::V6(ip) => Some(Span::V6(ip, ip)),
    }
}

fn network_start(net: &ipnet::Ipv4Net) -> std::net::Ipv4Addr {
    net.network()
}

fn broadcast_end(net: &ipnet::Ipv4Net) -> std::net::Ipv4Addr {
    net.broadcast()
}

fn network_start6(net: &ipnet::Ipv6Net) -> std::net::Ipv6Addr {
    net.network()
}

fn broadcast_end6(net: &ipnet::Ipv6Net) -> std::net::Ipv6Addr {
    net.broadcast()
}

/// Sorts and merges overlapping or adjacent spans.
fn merge_v4(
    mut spans: Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)>,
) -> Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    spans.sort();
    let mut merged: Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            // Overlapping or adjacent (end + 1 == next start) merge; the
            // u32 arithmetic sidesteps the last-address overflow.
            Some((_, last_end)) if start.to_bits() <= last_end.to_bits().saturating_add(1) => {
                if end.to_bits() > last_end.to_bits() {
                    *last_end = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn merge_v6(
    mut spans: Vec<(std::net::Ipv6Addr, std::net::Ipv6Addr)>,
) -> Vec<(std::net::Ipv6Addr, std::net::Ipv6Addr)> {
    spans.sort();
    let mut merged: Vec<(std::net::Ipv6Addr, std::net::Ipv6Addr)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some((_, last_end)) if start <= next_after(*last_end) => {
                if end > *last_end {
                    *last_end = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// The address right after `addr`, saturating at the family maximum.
fn next_after(addr: std::net::Ipv6Addr) -> std::net::Ipv6Addr {
    let bits = u128::from_be_bytes(addr.octets());
    let next = bits.saturating_add(1);
    std::net::Ipv6Addr::from(next.to_be_bytes())
}

/// key → IpSet, swapped atomically; lookups never lock. Refreshing a
/// list takes effect for every rule referencing it without a recompile.
#[derive(Default)]
pub struct Registry(ArcSwap<HashMap<String, Arc<IpSet>>>);

use std::collections::HashMap;

impl Registry {
    pub fn new() -> Self {
        Self(ArcSwap::from_pointee(HashMap::new()))
    }

    /// Stores (or clears with None) the set under `key`.
    pub fn store(&self, key: &str, set: Option<Arc<IpSet>>) {
        let mut current = self.0.load_full();
        let map = Arc::make_mut(&mut current);
        match set {
            Some(set) => {
                map.insert(key.to_owned(), set);
            }
            None => {
                map.remove(key);
            }
        }
        self.0.store(current);
    }

    pub fn get(&self, key: &str) -> Option<Arc<IpSet>> {
        self.0.load().get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid ip")
    }

    const SAMPLE: &str = concat!(
        "# comment line\n",
        "1.2.3.4\n",
        "10.0.0.0/8\n",
        "10.0.0.0/8 广东电信\n",
        "192.168.1.1-192.168.1.9 ; inline comment\n",
        "// slash comment\n",
        "not-an-address\n",
        "2001:db8::/32\n",
    );

    #[test]
    fn parses_entries_comments_and_counts_skipped() {
        let parsed = IpSet::parse(SAMPLE.as_bytes()).expect("parses");
        assert_eq!(
            parsed.entries, 5,
            "5 recognized entries: ip, cidr, annotated cidr, range, v6 net"
        );
        assert_eq!(parsed.skipped, vec!["not-an-address".to_owned()]);
        let set = &parsed.set;
        assert!(set.contains(ip("1.2.3.4")));
        assert!(set.contains(ip("10.1.2.3")), "inside 10/8");
        assert!(set.contains(ip("192.168.1.5")), "inside the range");
        assert!(!set.contains(ip("192.168.1.10")), "range end exclusive");
        assert!(set.contains(ip("2001:db8::1")), "inside v6 net");
        assert!(!set.contains(ip("9.9.9.9")));
        // Annotated line parsed as the plain CIDR.
        assert!(set.contains(ip("10.255.0.1")));
    }

    #[test]
    fn merged_adjacent_and_overlapping_spans_binary_search() {
        let text = "1.2.3.4\n1.2.3.5-1.2.3.9\n1.2.3.9-1.2.3.20\n2.0.0.0/8\n";
        let parsed = IpSet::parse(text.as_bytes()).expect("parses");
        // 1.2.3.4-9 + 9-20 merge; 2/8 is disjoint.
        assert_eq!(parsed.set.len(), 2);
        for i in [4u16, 5, 9, 12, 20] {
            assert!(
                parsed.set.contains(ip(&format!("1.2.3.{i}"))),
                "1.2.3.{i} inside merged span"
            );
        }
        assert!(!parsed.set.contains(ip("1.2.3.3")));
        assert!(!parsed.set.contains(ip("1.2.3.21")));
    }

    #[test]
    fn ipv4_mapped_ipv6_reads_as_ipv4() {
        let parsed = IpSet::parse(b"1.2.3.4\n").expect("parses");
        let mapped = IpAddr::V6("::ffff:1.2.3.4".parse().expect("mapped"));
        assert!(parsed.set.contains(mapped));
        assert!(!parsed.set.contains(ip("2001:db8::1")));
    }

    #[test]
    fn registry_stores_and_clears_by_key() {
        let registry = Registry::new();
        let parsed = IpSet::parse(b"1.2.3.4\n").expect("parses");
        registry.store("feed", Some(Arc::new(parsed.set)));
        assert!(
            registry
                .get("feed")
                .expect("stored")
                .contains(ip("1.2.3.4"))
        );
        registry.store("feed", None);
        assert!(registry.get("feed").is_none());
    }
}
