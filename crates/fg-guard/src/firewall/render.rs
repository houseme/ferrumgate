//! Pure rendering for the guard firewall mirror (WP-51 §3.3): the shared
//! ban table becomes structured elements, and the elements become an
//! nftables script (atomic `inet gately` table replace) or iptables
//! (legacy) argument arrays plus `ipset restore` input. Also parses the
//! `nft -j list table` JSON used by the structure check and the counters.
//!
//! No I/O happens here; everything is compiled on every platform so the
//! snapshot tests run everywhere, while the command backend that uses the
//! rendering is Linux-only. The whitelist never reaches this layer: the
//! ban table already rejects whitelisted / ignore-private addresses, so
//! the mirror contains exactly the entries the table holds (same internal
//! ranges criteria as the application layer).

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::SystemTime,
};

use fg_net::banlist::{BanKey, Entry};
use ipnet::IpNet;

use super::{
    CHAIN_PRE, COMMENT_BAN, COMMENT_DENY, IPT_CHAIN_PRE, IPT_SET_BAN4, IPT_SET_BAN6,
    IPT_TIMEOUT_CAP, SET_BAN4, SET_BAN6, SET_DENY4, SET_DENY6, SET_SIZE, TABLE, V6_MASK_64,
};

/// Address family of a set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

/// The nftables set (or iptables counterpart) an element belongs to.
/// `ban*` holds timed single-address bans (IPv6 /64 for auto bans; the
/// kernel timeout removes them), `deny*` holds manual CIDRs and permanent
/// bans as interval ranges without kernel timeouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SetName {
    Ban4,
    Ban6,
    Deny4,
    Deny6,
}

impl SetName {
    /// The nftables set name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ban4 => SET_BAN4,
            Self::Ban6 => SET_BAN6,
            Self::Deny4 => SET_DENY4,
            Self::Deny6 => SET_DENY6,
        }
    }

    /// The ipset set name ([`IPT_SET_BAN4`] / [`IPT_SET_BAN6`]); deny
    /// entries do not use ipset (they become `GATELY_DENY` chain rules).
    pub fn ipset_name(self) -> Option<&'static str> {
        match self {
            Self::Ban4 => Some(IPT_SET_BAN4),
            Self::Ban6 => Some(IPT_SET_BAN6),
            Self::Deny4 | Self::Deny6 => None,
        }
    }

    pub fn family(self) -> Family {
        match self {
            Self::Ban4 | Self::Deny4 => Family::V4,
            Self::Ban6 | Self::Deny6 => Family::V6,
        }
    }

    /// Whether elements carry a kernel-side timeout.
    pub fn timed(self) -> bool {
        matches!(self, Self::Ban4 | Self::Ban6)
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            SET_BAN4 => Some(Self::Ban4),
            SET_BAN6 => Some(Self::Ban6),
            SET_DENY4 => Some(Self::Deny4),
            SET_DENY6 => Some(Self::Deny6),
            _ => None,
        }
    }
}

/// One element mirrored into the firewall, derived from a ban entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FwElement {
    /// Stable identity `<set>:<value>` used by the reconcile diff.
    pub key: String,
    pub set: SetName,
    /// Address for the ban sets, CIDR network for the deny sets.
    pub value: String,
    /// The normalized network behind `value` (containment absorption).
    pub net: IpNet,
    /// Kernel-side lifetime in seconds; `None` = permanent. The iptables
    /// backend clamps this to [`IPT_TIMEOUT_CAP`] when writing ipset
    /// entries ([`ipt_timeout_secs`]).
    pub timeout: Option<u64>,
    /// When the source ban entry expires (bookkeeping that drives the
    /// delete of the timeout-less deny elements).
    pub expires: Option<SystemTime>,
    /// Creation time; newest first when the set capacity is cut.
    pub created: SystemTime,
}

/// Maps active ban entries to firewall elements: timed single addresses
/// (IPv6 /64 for auto bans) land in `ban4` / `ban6` with a timeout,
/// everything else (manual CIDRs, permanent bans) in the interval sets
/// `deny4` / `deny6`. Deduplicates, absorbs deny networks covered by a
/// wider one (nft interval sets reject overlapping ranges), cuts each set
/// to `per_set_limit` keeping the newest bans (upstream `nftSetSize`
/// 65536; the overflow only stays effective in the application layer),
/// and returns the rest sorted by set and value.
pub fn elements_from_entries(
    entries: &[Entry],
    now: SystemTime,
    per_set_limit: usize,
) -> Vec<FwElement> {
    let mut by_key: BTreeMap<String, FwElement> = BTreeMap::new();
    for entry in entries {
        if !entry.active(now) {
            continue;
        }
        let Some(element) = element_from_entry(entry, now) else {
            continue;
        };
        match by_key.get(&element.key) {
            Some(existing) if existing.created >= element.created => {}
            _ => {
                by_key.insert(element.key.clone(), element);
            }
        }
    }
    let mut elements: Vec<FwElement> = by_key.into_values().collect();
    absorb_covered(&mut elements);
    cap_per_set(&mut elements, per_set_limit);
    elements.sort_by(|a, b| a.set.cmp(&b.set).then_with(|| a.value.cmp(&b.value)));
    elements
}

/// The element for one entry, or `None` when it expires right now.
fn element_from_entry(entry: &Entry, now: SystemTime) -> Option<FwElement> {
    let remaining = match entry.until {
        Some(until) => Some(until.duration_since(now).ok()?),
        None => None,
    };
    let (set, net) = match entry.key {
        BanKey::V4(v4) => {
            let net = IpNet::new(IpAddr::from(v4), 32).ok()?;
            match remaining.is_some() {
                true => (SetName::Ban4, net),
                false => (SetName::Deny4, net),
            }
        }
        BanKey::Net(net) => match (net, remaining.is_some()) {
            (IpNet::V4(_), true) if net.prefix_len() == 32 => (SetName::Ban4, net),
            (IpNet::V6(_), true) if net.prefix_len() == 64 => (SetName::Ban6, net),
            (IpNet::V4(_), _) => (SetName::Deny4, net),
            (IpNet::V6(_), _) => (SetName::Deny6, net),
        },
    };
    let net = net.trunc();
    let value = match set {
        SetName::Ban4 | SetName::Ban6 => net.addr().to_string(),
        SetName::Deny4 | SetName::Deny6 => net.to_string(),
    };
    Some(FwElement {
        key: format!("{}:{}", set.name(), value),
        set,
        value,
        net,
        // Only the ban sets carry a kernel timeout; the deny sets hold no
        // `timeout` flag, so their expiry is driven by the engine's
        // reconcile delete ([`FwElement::expires`]).
        timeout: if set.timed() {
            remaining.map(|remaining| remaining.as_secs().max(1))
        } else {
            None
        },
        expires: entry.until,
        created: entry.created,
    })
}

/// Drops deny elements fully contained in another deny element of the same
/// family: nftables interval sets reject overlapping ranges and the wider
/// range already drops everything the narrower one would.
pub fn absorb_covered(elements: &mut Vec<FwElement>) {
    let deny: Vec<(usize, IpNet)> = elements
        .iter()
        .enumerate()
        .filter(|(_, element)| !element.set.timed())
        .map(|(index, element)| (index, element.net))
        .collect();
    let mut covered = vec![false; elements.len()];
    for (index, net) in &deny {
        for (other_index, other) in &deny {
            if other_index != index
                && other.prefix_len() < net.prefix_len()
                && other.contains(&net.network())
            {
                covered[*index] = true;
            }
        }
    }
    let mut position = 0;
    elements.retain(|_| {
        let keep = !covered[position];
        position += 1;
        keep
    });
}

/// Cuts every set to `per_set_limit` elements, keeping the newest bans
/// first (upstream: "按封禁时间从新到旧写入"). `0` keeps everything.
pub fn cap_per_set(elements: &mut Vec<FwElement>, per_set_limit: usize) {
    if per_set_limit == 0 || per_set_limit >= elements.len() {
        return;
    }
    elements.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.key.cmp(&b.key)));
    let mut counts: BTreeMap<SetName, usize> = BTreeMap::new();
    elements.retain(|element| {
        let count = counts.entry(element.set).or_default();
        if *count >= per_set_limit {
            return false;
        }
        *count += 1;
        true
    });
}

/// Splits elements by address family (the iptables backend drives
/// iptables and ip6tables separately).
pub fn split_families(elements: &[FwElement]) -> (Vec<FwElement>, Vec<FwElement>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for element in elements {
        match element.set.family() {
            Family::V4 => v4.push(element.clone()),
            Family::V6 => v6.push(element.clone()),
        }
    }
    (v4, v6)
}

/// Chunks elements so one nft / ipset invocation stays bounded; a size of
/// zero is treated as one.
pub fn chunked(elements: &[FwElement], size: usize) -> Vec<Vec<FwElement>> {
    elements
        .chunks(size.max(1))
        .map(<[FwElement]>::to_vec)
        .collect()
}

/// The ipset lifetime of a ban element: remaining time over the cap is
/// written at the cap and refreshed before it lapses (upstream caps ipset
/// timeouts and refreshes every 24 hours).
pub fn ipt_timeout_secs(timeout: Option<u64>) -> u64 {
    match timeout {
        None => 0,
        Some(secs) => secs.min(IPT_TIMEOUT_CAP.as_secs()),
    }
}

// ---------------------------------------------------------------------------
// nftables script
// ---------------------------------------------------------------------------

/// The nft element text inside `{ … }`: the value plus the timeout for
/// timed sets (permanent bans carry no `timeout`, upstream snapshot
/// `guard_script_bans_with_and_without_timeout`).
pub fn nft_element_text(element: &FwElement) -> String {
    match element.timeout {
        Some(secs) => format!("{} timeout {}", element.value, secs),
        None => element.value.clone(),
    }
}

fn set_block(set: SetName, elements: &[FwElement]) -> String {
    let members: Vec<&FwElement> = elements.iter().filter(|e| e.set == set).collect();
    let mut out = format!("\tset {} {{\n", set.name());
    out.push_str(match set.family() {
        Family::V4 => "\t\ttype ipv4_addr\n",
        Family::V6 => "\t\ttype ipv6_addr\n",
    });
    if set.timed() {
        out.push_str("\t\tflags timeout\n");
        out.push_str(&format!("\t\tsize {}\n", SET_SIZE));
    } else {
        out.push_str("\t\tflags interval\n");
    }
    if !members.is_empty() {
        out.push_str("\t\telements = { ");
        for (index, element) in members.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            // Wrap long lists so the "view rules" output stays readable.
            if index > 0 && index % 8 == 0 {
                out.push_str("\n\t\t\t");
            }
            out.push_str(&nft_element_text(element));
        }
        out.push_str(" }\n");
    }
    out.push_str("\t}\n\n");
    out
}

/// Renders the whole `inet gately` table. The script opens with an empty
/// table declaration plus `delete table inet gately` so the following
/// rebuild replaces the table atomically (deleting a missing table would
/// fail, hence the declaration first). Chains: `pre` (filter, prerouting,
/// priority -190) drops loopback-exempted, reply-exempted, banned and
/// denied sources; the redirect chain and the trap / scan sets belong to
/// WP-53 and are intentionally absent.
pub fn guard_script(elements: &[FwElement]) -> String {
    let mut out = format!("table inet {} {{}}\n", TABLE);
    out.push_str(&format!("delete table inet {}\n\n", TABLE));
    out.push_str(&format!("table inet {} {{\n", TABLE));
    for set in [SetName::Ban4, SetName::Ban6, SetName::Deny4, SetName::Deny6] {
        out.push_str(&set_block(set, elements));
    }
    out.push_str(&format!("\tchain {} {{\n", CHAIN_PRE));
    out.push_str("\t\ttype filter hook prerouting priority -190; policy accept;\n");
    out.push_str("\t\tiif \"lo\" accept\n");
    // Replies of locally initiated connections pass even when the peer is
    // banned; without this the host's own outgoing connections hang.
    out.push_str("\t\tct direction reply accept\n");
    out.push_str(&format!(
        "\t\tip saddr @{SET_BAN4} counter drop comment \"{COMMENT_BAN}\"\n"
    ));
    // IPv6 auto bans are /64 networks: mask the source before the lookup.
    out.push_str(&format!(
        "\t\tip6 saddr & {V6_MASK_64} @{SET_BAN6} counter drop comment \"{COMMENT_BAN}\"\n"
    ));
    out.push_str(&format!(
        "\t\tip saddr @{SET_DENY4} counter drop comment \"{COMMENT_DENY}\"\n"
    ));
    out.push_str(&format!(
        "\t\tip6 saddr @{SET_DENY6} counter drop comment \"{COMMENT_DENY}\"\n"
    ));
    out.push_str("\t}\n}\n");
    out
}

/// One `add element` statement per line, for the incremental path.
pub fn nft_add_script(elements: &[FwElement]) -> String {
    let mut out = String::new();
    for element in elements {
        out.push_str(&format!(
            "add element inet {} {} {{ {} }}\n",
            TABLE,
            element.set.name(),
            nft_element_text(element)
        ));
    }
    out
}

/// One `delete element` statement per line. Deny elements carry their
/// CIDR; ban elements their address.
pub fn nft_del_script(elements: &[FwElement]) -> String {
    let mut out = String::new();
    for element in elements {
        out.push_str(&format!(
            "delete element inet {} {} {{ {} }}\n",
            TABLE,
            element.set.name(),
            element.value
        ));
    }
    out
}

/// The startup table removal (engine stop path).
pub fn nft_remove_script() -> String {
    format!("table inet {} {{}}\ndelete table inet {}\n", TABLE, TABLE)
}

// ---------------------------------------------------------------------------
// iptables (legacy) + ipset
// ---------------------------------------------------------------------------

/// Match rules of the `GATELY_PRE` chain, mirroring the nft `pre` chain:
/// loopback and established connections return, the ban ipset drops, and
/// the remaining traffic jumps to the per-CIDR `GATELY_DENY` chain.
pub fn ipt_pre_rules(v6: bool) -> Vec<Vec<String>> {
    let ban_set = if v6 { IPT_SET_BAN6 } else { IPT_SET_BAN4 };
    vec![
        s(vec!["-A", IPT_CHAIN_PRE, "-i", "lo", "-j", "RETURN"]),
        // Approximation of nft's `ct direction reply accept`.
        s(vec![
            "-A",
            CHAIN_PRE,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "RETURN",
        ]),
        s(vec![
            "-A",
            CHAIN_PRE,
            "-m",
            "set",
            "--match-set",
            ban_set,
            "src",
            "-m",
            "comment",
            "--comment",
            COMMENT_BAN,
            "-j",
            "DROP",
        ]),
        s(vec![
            "-A",
            CHAIN_PRE,
            "-m",
            "comment",
            "--comment",
            COMMENT_DENY,
            "-j",
            super::IPT_CHAIN_DENY,
        ]),
    ]
}

/// One `-s <cidr> -j DROP` rule of the `GATELY_DENY` chain (the same
/// arguments serve iptables and ip6tables: separate tables per family).
pub fn ipt_deny_rule(cidr: &str) -> Vec<String> {
    ipt_deny_args("-A", cidr)
}

/// The matching `-D` form for removals: iptables matches the whole rule
/// spec, so the comment must be repeated exactly.
pub fn ipt_deny_delete_rule(cidr: &str) -> Vec<String> {
    ipt_deny_args("-D", cidr)
}

fn ipt_deny_args(op: &str, cidr: &str) -> Vec<String> {
    s(vec![
        op,
        super::IPT_CHAIN_DENY,
        "-s",
        cidr,
        "-m",
        "comment",
        "--comment",
        COMMENT_DENY,
        "-j",
        "DROP",
    ])
}

/// The `ipset restore` input that (re)creates both ban sets: timeout
/// support enabled with a default of 0, one family per set, 65536
/// elements each ([`SET_SIZE`]).
pub fn ipset_restore_setup() -> String {
    format!(
        "create {IPT_SET_BAN4} hash:ip family inet timeout 0 maxelem {SET_SIZE}\n\
         create {IPT_SET_BAN6} hash:net family inet6 timeout 0 maxelem {SET_SIZE}\n"
    )
}

/// The member text of a ban element for ipset: IPv6 auto bans are /64
/// networks (`hash:net`), IPv4 entries plain addresses.
pub fn ipset_ban_member(element: &FwElement) -> String {
    match element.set {
        SetName::Ban6 => format!("{}/64", element.value),
        _ => element.value.clone(),
    }
}

/// `ipset restore` input for a full rebuild: creates both sets (idempotent
/// with `-exist`), flushes them and re-adds `elements` with their (capped)
/// timeouts.
pub fn ipset_restore_full(elements: &[FwElement]) -> String {
    let mut out = format!(
        "{}flush {IPT_SET_BAN4}\nflush {IPT_SET_BAN6}\n",
        ipset_restore_setup()
    );
    out.push_str(&ipset_restore_adds(elements));
    out
}

/// `ipset restore` input adding the given elements (no flush: the
/// incremental path must not touch unrelated entries).
pub fn ipset_restore_adds(elements: &[FwElement]) -> String {
    let mut out = String::new();
    for element in elements {
        let Some(set) = element.set.ipset_name() else {
            continue;
        };
        out.push_str(&format!(
            "add {} {} timeout {}\n",
            set,
            ipset_ban_member(element),
            ipt_timeout_secs(element.timeout)
        ));
    }
    out
}

/// `ipset restore` input deleting the given ban elements.
pub fn ipset_restore_dels(elements: &[FwElement]) -> String {
    let mut out = String::new();
    for element in elements {
        let Some(set) = element.set.ipset_name() else {
            continue;
        };
        out.push_str(&format!("delete {} {}\n", set, ipset_ban_member(element)));
    }
    out
}

/// Adds timeout-bearing elements only (the deny rules carry no timeout).
pub fn ipset_ban_elements(elements: &[FwElement]) -> Vec<FwElement> {
    elements
        .iter()
        .filter(|element| element.set.ipset_name().is_some())
        .cloned()
        .collect()
}

fn s(args: Vec<&str>) -> Vec<String> {
    args.into_iter().map(str::to_owned).collect()
}

// ---------------------------------------------------------------------------
// `nft -j list table` parsing (structure check + counters)
// ---------------------------------------------------------------------------

/// The parsed structure of the `inet gately` table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuardTable {
    pub sets: BTreeSet<String>,
    /// The `pre` chain exists with the prerouting hook.
    pub pre_hook: bool,
    /// A counter rule commented `ban` exists.
    pub ban_rule: bool,
    /// A counter rule commented `deny` exists.
    pub deny_rule: bool,
    /// Packets per rule comment (`ban` / `deny`).
    pub counters: BTreeMap<String, u64>,
}

impl GuardTable {
    /// The rules survive a `fw4 reload` / `nft flush ruleset` only when
    /// every set, the prerouting hook and the commented counter rules are
    /// back; anything missing triggers a full rewrite.
    pub fn rules_present(&self) -> bool {
        [SET_BAN4, SET_BAN6, SET_DENY4, SET_DENY6]
            .iter()
            .all(|set| self.sets.contains(*set))
            && self.pre_hook
            && self.ban_rule
            && self.deny_rule
    }
}

/// Parses `nft -j list table inet gately`. Both the object form of modern
/// nft versions and the older pair form of rule expressions are accepted;
/// counters are located by scanning for a `counter` object with
/// `packets`.
pub fn parse_guard_table(raw: &str) -> Result<GuardTable, super::FwError> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|error| super::FwError::Parse(format!("解析 nft 输出失败: {error}")))?;
    let Some(items) = value.get("nftables").and_then(|v| v.as_array()) else {
        return Err(super::FwError::Parse(
            "nft 输出缺少 nftables 数组".to_owned(),
        ));
    };
    let mut table = GuardTable::default();
    for item in items {
        if let Some(name) = item
            .get("set")
            .and_then(|set| set.get("name"))
            .and_then(|n| n.as_str())
            && SetName::from_name(name).is_some()
        {
            table.sets.insert(name.to_owned());
        }
        if let Some(chain) = item.get("chain")
            && chain.get("name").and_then(|n| n.as_str()) == Some(CHAIN_PRE)
            && chain.get("hook").and_then(|h| h.as_str()) == Some("prerouting")
        {
            table.pre_hook = true;
        }
        if let Some(rule) = item.get("rule")
            && rule.get("chain").and_then(|c| c.as_str()) == Some(CHAIN_PRE)
        {
            let comment = rule.get("comment").and_then(|c| c.as_str()).unwrap_or("");
            match comment {
                COMMENT_BAN => {
                    table.ban_rule = true;
                    if let Some(packets) = counter_packets(rule) {
                        // Both family rules carry the same comment: sum.
                        *table.counters.entry(COMMENT_BAN.to_owned()).or_default() += packets;
                    }
                }
                COMMENT_DENY => {
                    table.deny_rule = true;
                    if let Some(packets) = counter_packets(rule) {
                        *table.counters.entry(COMMENT_DENY.to_owned()).or_default() += packets;
                    }
                }
                _ => {}
            }
        }
    }
    Ok(table)
}

/// Finds the packet count of the counter expression of one rule; both the
/// `[["counter", {"packets": N}]]` pair form and the
/// `{"counter": {"packets": N}}` object form are accepted.
fn counter_packets(rule: &serde_json::Value) -> Option<u64> {
    fn scan(value: &serde_json::Value) -> Option<u64> {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(packets) = map
                    .get("counter")
                    .and_then(|counter| counter.get("packets"))
                    .and_then(|packets| packets.as_u64())
                {
                    return Some(packets);
                }
                map.values().find_map(scan)
            }
            serde_json::Value::Array(items) => {
                if items.len() == 2
                    && items[0] == "counter"
                    && let Some(packets) = items[1].get("packets").and_then(|p| p.as_u64())
                {
                    return Some(packets);
                }
                items.iter().find_map(scan)
            }
            _ => None,
        }
    }
    scan(rule)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use fg_net::banlist::{Entry, Source};
    use ipnet::IpNet;

    use super::*;

    fn at(secs: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)
    }

    fn entry(key: &str, until: Option<SystemTime>, created: i64) -> Entry {
        Entry {
            key: BanKey::parse(key).expect("valid ban key"),
            until,
            created: at(created),
            reason: "guard.reason.scan".to_owned(),
            source: Source::Scan,
            count: 1,
        }
    }

    fn keys(elements: &[FwElement]) -> Vec<String> {
        elements.iter().map(|e| e.key.clone()).collect()
    }

    /// Whether `needles` appear in `text` in exactly this order.
    fn ordered(text: &str, needles: &[&str]) -> bool {
        let mut at = 0;
        for needle in needles {
            match text[at..].find(needle) {
                Some(found) => at += found + needle.len(),
                None => return false,
            }
        }
        true
    }

    // -- element mapping -------------------------------------------------

    #[test]
    fn elements_map_entry_kinds_to_sets_and_timeouts() {
        let now = at(1000);
        let entries = vec![
            entry("203.0.113.5", Some(at(4600)), 100),
            entry("203.0.113.9", None, 200),
            entry("2001:db8:aa::1", Some(at(2800)), 300),
            entry("2001:db8:bb::/48", None, 400),
            entry("198.51.100.0/24", Some(at(1060)), 500),
            entry("203.0.113.5", Some(at(8200)), 50),
        ];
        let elements = elements_from_entries(&entries, now, 0);
        assert_eq!(
            keys(&elements),
            [
                "ban4:203.0.113.5",
                "ban6:2001:db8:aa::",
                "deny4:198.51.100.0/24",
                "deny4:203.0.113.9/32",
                "deny6:2001:db8:bb::/48",
            ],
            "timed single addresses (v6 as /64) to ban sets, CIDRs and permanent to deny sets"
        );
        let ban4 = &elements[0];
        assert_eq!(
            ban4.timeout,
            Some(3600),
            "duplicate entry keeps the newest created, not the longest"
        );
        assert_eq!(ban4.expires, Some(at(4600)));
        let ban6 = &elements[1];
        assert_eq!(
            ban6.value, "2001:db8:aa::",
            "the /64 network address is the element"
        );
        assert_eq!(ban6.net.prefix_len(), 64);
        // A temporary manual CIDR lives in a deny set without a kernel
        // timeout: the engine deletes it on expiry.
        let deny4 = &elements[2];
        assert_eq!(deny4.key, "deny4:198.51.100.0/24");
        assert_eq!(deny4.timeout, None, "deny sets carry no kernel timeout");
        assert_eq!(deny4.expires, Some(at(1060)));
        // An expired entry is skipped.
        let elements = elements_from_entries(&[entry("203.0.113.5", Some(at(999)), 100)], now, 0);
        assert!(
            elements.is_empty(),
            "expired bans do not reach the firewall"
        );
    }

    #[test]
    fn elements_cap_keeps_newest_per_set() {
        let now = at(1000);
        let entries: Vec<Entry> = (0..5)
            .map(|step| entry(&format!("203.0.113.{step}"), Some(at(100_000)), step))
            .collect();
        let elements = elements_from_entries(&entries, now, 2);
        // The two newest bans survive the cut; the output stays sorted by
        // set and value.
        assert_eq!(keys(&elements), ["ban4:203.0.113.3", "ban4:203.0.113.4"]);
        assert_eq!(elements_from_entries(&entries, now, 0).len(), 5);
        assert_eq!(SET_SIZE, 65536, "the production limit (WP-50 §3.4)");
    }

    #[test]
    fn elements_absorb_covered_deny_networks() {
        let now = at(1000);
        let elements = elements_from_entries(
            &[
                entry("10.0.0.0/8", None, 1),
                entry("10.1.0.0/16", None, 2),
                entry("203.0.113.9", None, 3),
            ],
            now,
            0,
        );
        assert_eq!(
            keys(&elements),
            ["deny4:10.0.0.0/8", "deny4:203.0.113.9/32"],
            "the narrower net inside /8 is absorbed (interval sets reject overlap)"
        );
    }

    #[test]
    fn elements_split_by_family() {
        let now = at(1000);
        let elements = elements_from_entries(
            &[
                entry("203.0.113.5", Some(at(4600)), 1),
                entry("2001:db8:aa::1", Some(at(2800)), 2),
            ],
            now,
            0,
        );
        let (v4, v6) = split_families(&elements);
        assert_eq!(keys(&v4), ["ban4:203.0.113.5"]);
        assert_eq!(keys(&v6), ["ban6:2001:db8:aa::"]);
    }

    #[test]
    fn elements_chunked_by_batch_limit() {
        let now = at(1000);
        let elements = elements_from_entries(
            &(0..5)
                .map(|step| entry(&format!("203.0.113.{step}"), Some(at(100_000)), step))
                .collect::<Vec<_>>(),
            now,
            0,
        );
        let sizes: Vec<usize> = chunked(&elements, 2).iter().map(Vec::len).collect();
        assert_eq!(sizes, [2, 2, 1]);
        assert_eq!(chunked(&elements, 0).len(), 5, "zero means one per chunk");
        assert_eq!(chunked(&elements, 10).len(), 1);
    }

    // -- nftables script ---------------------------------------------------

    #[test]
    fn guard_script_renders_sets_chains_and_rules() {
        let now = at(1000);
        let elements = elements_from_entries(
            &[
                entry("203.0.113.5", Some(at(4600)), 1),
                entry("203.0.113.9", None, 2),
                entry("2001:db8:aa::1", Some(at(2800)), 3),
                entry("198.51.100.0/24", Some(at(1060)), 4),
            ],
            now,
            0,
        );
        let script = guard_script(&elements);
        assert!(
            script.starts_with("table inet gately {}\ndelete table inet gately\n"),
            "atomic replace preamble (a missing table would fail the delete)"
        );
        assert!(ordered(
            &script,
            &[
                "set ban4 {",
                "type ipv4_addr",
                "flags timeout",
                "size 65536",
                "set ban6 {",
                "type ipv6_addr",
                "set deny4 {",
                "flags interval",
                "set deny6 {",
                "chain pre {",
                "type filter hook prerouting priority -190; policy accept;",
                "iif \"lo\" accept",
                "ct direction reply accept",
                "ip saddr @ban4 counter drop comment \"ban\"",
                "ip6 saddr & ffff:ffff:ffff:ffff:: @ban6 counter drop comment \"ban\"",
                "ip saddr @deny4 counter drop comment \"deny\"",
                "ip6 saddr @deny6 counter drop comment \"deny\"",
            ]
        ));
        assert!(script.contains("elements = { 203.0.113.5 timeout 3600"));
        assert!(script.contains("elements = { 2001:db8:aa:: timeout 1800"));
        assert!(script.contains("203.0.113.9/32"));
        // Deny elements never render a timeout, even when the ban is
        // temporary (the engine deletes them on expiry).
        let deny_block_start = script.find("set deny4").unwrap();
        let deny_block_end = script.find("set deny6").unwrap();
        assert!(
            !script[deny_block_start..deny_block_end].contains("timeout"),
            "{script}"
        );
        // No redirect chain or scan / trap sets: that is WP-53.
        assert!(!script.contains("redirect"));
        assert!(!script.contains("trap"));
        assert!(!script.contains("sus4"));
    }

    #[test]
    fn guard_script_bans_with_and_without_timeout() {
        let timed = element_timed();
        assert_eq!(nft_element_text(&timed), "203.0.113.5 timeout 3600");
        let permanent = element_permanent();
        assert_eq!(
            nft_element_text(&permanent),
            "203.0.113.9/32",
            "permanent bans carry no timeout"
        );
    }

    fn element_timed() -> FwElement {
        elements_from_entries(&[entry("203.0.113.5", Some(at(4600)), 1)], at(1000), 0).remove(0)
    }

    fn element_permanent() -> FwElement {
        elements_from_entries(&[entry("203.0.113.9", None, 1)], at(1000), 0).remove(0)
    }

    #[test]
    fn guard_script_omits_empty_element_lists() {
        let script = guard_script(&[]);
        assert!(!script.contains("elements = {"), "{script}");
        for set in ["ban4", "ban6", "deny4", "deny6"] {
            assert!(script.contains(&format!("set {set} {{")), "{script}");
        }
    }

    #[test]
    fn nft_add_and_del_scripts_render_statements() {
        let now = at(1000);
        let elements = elements_from_entries(
            &[
                entry("203.0.113.5", Some(at(4600)), 1),
                entry("10.0.0.0/8", None, 2),
            ],
            now,
            0,
        );
        let add = nft_add_script(&elements);
        assert!(
            add.contains("add element inet gately ban4 { 203.0.113.5 timeout 3600 }")
                && add.contains("add element inet gately deny4 { 10.0.0.0/8 }"),
            "{add}"
        );
        let del = nft_del_script(&elements);
        assert!(
            del.contains("delete element inet gately ban4 { 203.0.113.5 }")
                && del.contains("delete element inet gately deny4 { 10.0.0.0/8 }"),
            "{del}"
        );
    }

    // -- iptables + ipset ---------------------------------------------------

    #[test]
    fn ipt_args_render_jump_pre_and_deny_rules() {
        let pre = ipt_pre_rules(false);
        assert_eq!(pre[0], ["-A", "GATELY_PRE", "-i", "lo", "-j", "RETURN"]);
        assert!(
            pre[1].iter().any(|arg| arg == "conntrack"),
            "established connections return (ct direction reply)"
        );
        assert!(ordered(
            &pre[2].join(" "),
            &[
                "--match-set",
                "gately_ban4",
                "src",
                "--comment",
                "ban",
                "-j",
                "DROP"
            ]
        ));
        assert!(pre[3].contains(&"-j".to_string()) && pre[3].contains(&"GATELY_DENY".to_string()));
        // The v6 rules point at the inet6 ipset and the same chains.
        let pre6 = ipt_pre_rules(true);
        assert!(ordered(&pre6[2].join(" "), &["gately_ban6", "src"]));

        let rule = ipt_deny_rule("203.0.113.0/24");
        assert_eq!(
            rule,
            [
                "-A",
                "GATELY_DENY",
                "-s",
                "203.0.113.0/24",
                "-m",
                "comment",
                "--comment",
                "deny",
                "-j",
                "DROP"
            ]
        );
        assert_eq!(
            ipt_deny_delete_rule("203.0.113.0/24")[0],
            "-D",
            "deletion matches the full rule spec"
        );
    }

    #[test]
    fn ipset_restore_renders_full_adds_and_dels_with_capped_timeout() {
        let now = at(1000);
        let elements = elements_from_entries(
            &[
                entry("203.0.113.5", Some(at(4600)), 1),
                entry("2001:db8:aa::1", Some(at(2800)), 2),
                // A 7-day ban: written at the 24h cap, refreshed later.
                entry("203.0.113.9", Some(at(1000 + 7 * 24 * 3600)), 3),
                entry("10.0.0.0/8", None, 4),
            ],
            now,
            0,
        );
        let setup = ipset_restore_setup();
        assert!(setup.contains("create gately_ban4 hash:ip family inet timeout 0 maxelem 65536"));
        assert!(setup.contains("create gately_ban6 hash:net family inet6 timeout 0 maxelem 65536"));

        let full = ipset_restore_full(&ipset_ban_elements(&elements));
        assert!(
            ordered(
                &full,
                &[
                    "create gately_ban4",
                    "flush gately_ban4",
                    "flush gately_ban6",
                    "add gately_ban4 203.0.113.5 timeout 3600",
                    "add gately_ban4 203.0.113.9 timeout 86400",
                    "add gately_ban6 2001:db8:aa::/64 timeout 1800",
                ]
            ),
            "{full}"
        );
        assert!(
            !full.contains("10.0.0.0/8"),
            "deny nets are chain rules, not ipset entries"
        );

        let adds = ipset_restore_adds(&ipset_ban_elements(&elements));
        assert!(!adds.contains("flush"), "incremental adds never flush");
        assert!(adds.contains("add gately_ban4 203.0.113.5 timeout 3600"));

        let dels = ipset_restore_dels(&ipset_ban_elements(&elements));
        assert!(
            dels.contains("delete gately_ban4 203.0.113.5")
                && dels.contains("delete gately_ban6 2001:db8:aa::/64"),
            "{dels}"
        );
    }

    // -- nft -j parsing ------------------------------------------------------

    /// A trimmed but real `nft -j list table inet gately` sample (nft 1.0.x
    /// object form): meta info, the table, four sets, the pre chain and the
    /// counter rules commented ban / deny.
    const FIXTURE_JSON: &str = r#"{"nftables":[
        {"metainfo":{"json_schema_version":1,"version":"1.0.6","release_name":"Purple Sturgeon"}},
        {"table":{"family":"inet","name":"gately","handle":3}},
        {"set":{"family":"inet","name":"ban4","handle":4,"type":"ipv4_addr","size":65536,"flags":["timeout"]}},
        {"set":{"family":"inet","name":"ban6","handle":5,"type":"ipv6_addr","size":65536,"flags":["timeout"]}},
        {"set":{"family":"inet","name":"deny4","handle":6,"type":"ipv4_addr","flags":["interval"]}},
        {"set":{"family":"inet","name":"deny6","handle":7,"type":"ipv6_addr","flags":["interval"]}},
        {"chain":{"family":"inet","table":"gately","name":"pre","handle":8,"type":"filter","hook":"prerouting","prio":-190,"policy":"accept"}},
        {"rule":{"family":"inet","table":"gately","chain":"pre","handle":9,"expr":[["iif","lo"],"accept"]}},
        {"rule":{"family":"inet","table":"gately","chain":"pre","handle":10,"expr":[["ct","direction","reply"],"accept"]}},
        {"rule":{"family":"inet","table":"gately","chain":"pre","handle":11,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"set":"@ban4"}}},{"counter":{"packets":13,"bytes":1040}},{"drop":null}],"comment":"ban"}},
        {"rule":{"family":"inet","table":"gately","chain":"pre","handle":12,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":{"set":"@ban6"}}},{"counter":{"packets":2,"bytes":160}},{"drop":null}],"comment":"ban"}},
        {"rule":{"family":"inet","table":"gately","chain":"pre","handle":13,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"set":"@deny4"}}},{"counter":{"packets":7,"bytes":560}},{"drop":null}],"comment":"deny"}},
        {"rule":{"family":"inet","table":"gately","chain":"pre","handle":14,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":{"set":"@deny6"}}},{"counter":{"packets":1,"bytes":80}},{"drop":null}],"comment":"deny"}}
    ]}"#;

    #[test]
    fn parse_guard_table_reports_structure_and_counters() {
        let table = parse_guard_table(FIXTURE_JSON).expect("fixture parses");
        assert!(table.rules_present(), "{table:?}");
        assert_eq!(
            table.counters.get("ban"),
            Some(&15),
            "both family ban rules sum into one comment"
        );
        assert_eq!(table.counters.get("deny"), Some(&8));
    }

    #[test]
    fn parse_guard_table_missing_rule_flags_rewrite() {
        // `nft flush ruleset` wiped everything except the table object.
        let wiped = r#"{"nftables":[
            {"table":{"family":"inet","name":"gately","handle":3}}
        ]}"#;
        let table = parse_guard_table(wiped).expect("fixture parses");
        assert!(!table.rules_present());
        // A partial table missing the deny rules also needs a rewrite.
        let partial = r#"{"nftables":[
            {"table":{"family":"inet","name":"gately","handle":3}},
            {"set":{"family":"inet","name":"ban4","handle":4,"type":"ipv4_addr","size":65536,"flags":["timeout"]}},
            {"set":{"family":"inet","name":"ban6","handle":5,"type":"ipv6_addr","size":65536,"flags":["timeout"]}},
            {"set":{"family":"inet","name":"deny4","handle":6,"type":"ipv4_addr","flags":["interval"]}},
            {"set":{"family":"inet","name":"deny6","handle":7,"type":"ipv6_addr","flags":["interval"]}},
            {"chain":{"family":"inet","table":"gately","name":"pre","handle":8,"type":"filter","hook":"prerouting","prio":-190,"policy":"accept"}},
            {"rule":{"family":"inet","table":"gately","chain":"pre","handle":11,"expr":[{"counter":{"packets":1,"bytes":64}},{"drop":null}],"comment":"ban"}}
        ]}"#;
        let table = parse_guard_table(partial).expect("fixture parses");
        assert!(!table.rules_present(), "the deny counter rule is missing");
        assert_eq!(table.counters.get("ban"), Some(&1));
    }

    #[test]
    fn parse_guard_table_accepts_legacy_pair_expr_form() {
        // Older nft versions emit expressions as arrays of pairs.
        let legacy = r#"{"nftables":[
            {"table":{"family":"inet","name":"gately","handle":3}},
            {"set":{"family":"inet","name":"ban4","handle":4,"type":"ipv4_addr","size":65536,"flags":["timeout"]}},
            {"set":{"family":"inet","name":"ban6","handle":5,"type":"ipv6_addr","size":65536,"flags":["timeout"]}},
            {"set":{"family":"inet","name":"deny4","handle":6,"type":"ipv4_addr","flags":["interval"]}},
            {"set":{"family":"inet","name":"deny6","handle":7,"type":"ipv6_addr","flags":["interval"]}},
            {"chain":{"family":"inet","table":"gately","name":"pre","handle":8,"type":"filter","hook":"prerouting","prio":-190,"policy":"accept"}},
            {"rule":{"family":"inet","table":"gately","chain":"pre","handle":11,"expr":[["counter",{"packets":4,"bytes":320}],["drop"]],"comment":"ban"}},
            {"rule":{"family":"inet","table":"gately","chain":"pre","handle":13,"expr":[["counter",{"packets":1,"bytes":80}],["drop"]],"comment":"deny"}}
        ]}"#;
        let table = parse_guard_table(legacy).expect("fixture parses");
        assert!(table.rules_present());
        assert_eq!(table.counters.get("ban"), Some(&4));
    }

    #[test]
    fn parse_guard_table_rejects_unusable_output() {
        assert!(parse_guard_table("not json").is_err());
        assert!(parse_guard_table(r#"{"other": []}"#).is_err());
    }

    /// A manual CIDR map sanity check used by the mapping tests.
    #[test]
    fn parse_helpers_agree_with_ipnet() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains(&"10.1.0.0/16".parse::<IpNet>().unwrap().network()));
    }
}
