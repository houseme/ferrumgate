//! Routing table compilation and matching (WP-35 §3.3): TLS, HTTP and
//! Minecraft routes match by domain (SNI / Host / server address), every
//! other protocol has at most one enabled route, `timeout` matches
//! server-speaks-first connections and `spa` captures knock packets.
//!
//! Matching walks from specific to broad: exact domain → longest
//! `*.suffix` wildcard → `*` (any carried domain) → routes without
//! domains (which also match connections without one). Inside a level an
//! ALPN-restricted route beats an unrestricted one; when the level only
//! has ALPN routes and none match, the search continues outward.
//!
//! Matching is a lock-free snapshot read at runtime: the compiled table is
//! immutable once published, so `route()` needs no synchronization.
//!
//! Hit counters are keyed by [`MatchKey`] — protocol plus the sorted
//! domain and ALPN sets — which is deliberately independent of route
//! order, names and targets: a hot update that keeps the match condition
//! keeps counting, changed conditions start from zero.

use std::collections::{BTreeSet, HashMap};

use crate::model::{Protocol, Route};
use crate::sniff::SniffResult;
use crate::validate;

/// The match condition of one route, independent of the order the domains
/// and ALPN ids happen to be written in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MatchKey {
    pub protocol: Protocol,
    pub domains: BTreeSet<String>,
    pub alpn: BTreeSet<String>,
}

/// The match condition of a route. Normalizes the domain set the same way
/// compilation does, so a hot update's old and new keys compare equal
/// exactly when the conditions still match the same connections.
pub fn match_key(route: &Route) -> MatchKey {
    MatchKey {
        protocol: route.protocol,
        domains: route
            .domains
            .iter()
            .filter_map(|domain| validate::punycode_domain(domain))
            .collect(),
        alpn: route.alpn.iter().cloned().collect(),
    }
}

/// What a sniffed connection should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Forward to the route at this index (in the rule's route list).
    Route(usize),
    /// Use the rule's default target.
    Default,
    /// No default target configured: drop the connection.
    Drop,
    /// Hand the captured SPA packet to the port-knock module.
    Spa(usize),
}

/// ALPN-aware bucket of routes for one domain level.
#[derive(Debug, Default)]
pub struct Bucket {
    /// `(alpn set, route index)`, in no particular order; matching follows
    /// the client's ALPN preference order.
    by_alpn: Vec<(Vec<String>, usize)>,
    /// Route without ALPN restrictions, used last.
    generic: Option<usize>,
}

/// Domain table of one domain-routed protocol.
#[derive(Debug, Default)]
pub struct DomainTable {
    /// Exact domains (lower-case punycode).
    exact: HashMap<String, Bucket>,
    /// `*.suffix` wildcards, sorted longest suffix first; matches any
    /// number of subdomain levels.
    wildcard: Vec<(String, Bucket)>,
    /// The bare `*` route: matches any connection carrying a domain.
    any: Option<Bucket>,
    /// Routes without domains: match the protocol's every connection,
    /// including ones without a domain.
    generic: Option<Bucket>,
}

impl DomainTable {
    /// Registers one route (by index) at the levels its condition
    /// describes. A route listing several domains joins every one of them;
    /// `*` lands in the any-domain bucket; the empty set in the generic
    /// (domain-less) bucket.
    fn insert(&mut self, key: MatchKey, index: usize) {
        fn add_entry(bucket: &mut Bucket, alpn: &[String], index: usize) {
            if alpn.is_empty() {
                bucket.generic = Some(index);
            } else {
                bucket.by_alpn.push((alpn.to_vec(), index));
            }
        }
        let alpn: Vec<String> = key.alpn.iter().cloned().collect();
        if key.domains.is_empty() {
            match self.generic.as_mut() {
                Some(bucket) => add_entry(bucket, &alpn, index),
                None => {
                    let mut bucket = Bucket::default();
                    add_entry(&mut bucket, &alpn, index);
                    self.generic = Some(bucket);
                }
            }
            return;
        }
        for domain in &key.domains {
            if domain == "*" {
                match self.any.as_mut() {
                    Some(bucket) => add_entry(bucket, &alpn, index),
                    None => {
                        let mut bucket = Bucket::default();
                        add_entry(&mut bucket, &alpn, index);
                        self.any = Some(bucket);
                    }
                }
            } else if let Some(suffix) = domain.strip_prefix("*.") {
                match self.wildcard.iter_mut().find(|(known, _)| known == suffix) {
                    Some((_, bucket)) => add_entry(bucket, &alpn, index),
                    None => {
                        let mut bucket = Bucket::default();
                        add_entry(&mut bucket, &alpn, index);
                        self.wildcard.push((suffix.to_owned(), bucket));
                    }
                }
            } else {
                let bucket = self.exact.entry(domain.clone()).or_default();
                add_entry(bucket, &alpn, index);
            }
        }
    }
}

/// The compiled routing table of one rule. Immutable after compilation;
/// the runtime publishes it behind an `ArcSwap` snapshot.
#[derive(Debug, Default)]
pub struct RouteTable {
    tls: DomainTable,
    http: DomainTable,
    minecraft: DomainTable,
    /// One enabled route per non-domain protocol.
    plain: HashMap<Protocol, usize>,
    timeout: Option<usize>,
    spa: Option<usize>,
    /// Match keys aligned with the rule's route indices (enabled and
    /// disabled alike) for hit-counter inheritance.
    keys: Vec<MatchKey>,
    /// Whether the rule has a default target (no match + no default =
    /// drop).
    default_target: bool,
}

impl RouteTable {
    /// Compiles the routes of one rule, collecting every conflict among
    /// the enabled routes:
    ///
    /// - the same `(protocol, domain, alpn)` slot may only belong to one
    ///   enabled route,
    /// - non-domain protocols carry at most one enabled route,
    /// - at most one `timeout` route and one `spa` route per rule.
    ///
    /// Disabled routes are skipped (both matching and conflicts) but keep
    /// their match keys, so re-enabling them reuses their counters only if
    /// the runtime stored them.
    pub fn compile(
        routes: &[Route],
        default_target: bool,
        _prev: Option<&RouteTable>,
    ) -> Result<Self, Vec<String>> {
        let mut table = RouteTable {
            default_target,
            ..RouteTable::default()
        };
        table.keys = routes.iter().map(match_key).collect();
        let mut errors = Vec::new();
        let mut domain_slots: HashMap<(Protocol, String, Option<String>), usize> = HashMap::new();
        for (index, route) in routes.iter().enumerate() {
            if route.disabled {
                continue;
            }
            let key = table.keys[index].clone();
            match route.protocol {
                Protocol::Tls | Protocol::Http | Protocol::Minecraft => {
                    let domains: Vec<String> = if key.domains.is_empty() {
                        vec![String::new()]
                    } else {
                        key.domains.iter().cloned().collect()
                    };
                    let alpns: Vec<Option<String>> =
                        if route.protocol == Protocol::Tls && !key.alpn.is_empty() {
                            key.alpn.iter().cloned().map(Some).collect()
                        } else {
                            vec![None]
                        };
                    let mut conflicted = false;
                    let mut reported_pair = BTreeSet::new();
                    for domain in &domains {
                        for alpn in &alpns {
                            let slot = (route.protocol, domain.clone(), alpn.clone());
                            if let Some(&first) = domain_slots.get(&slot) {
                                conflicted = true;
                                if reported_pair.insert(first) {
                                    errors.push(format!(
                                        "同一条件下（{} {}）只能有一条启用的路由：{} 与 {} 冲突",
                                        route.protocol.as_str(),
                                        describe_slot(domain, alpn.as_deref()),
                                        routes[first].name,
                                        route.name
                                    ));
                                }
                            } else {
                                domain_slots.insert(slot, index);
                            }
                        }
                    }
                    if !conflicted {
                        match route.protocol {
                            Protocol::Tls => table.tls.insert(key, index),
                            Protocol::Http => table.http.insert(key, index),
                            Protocol::Minecraft => table.minecraft.insert(key, index),
                            _ => unreachable!(),
                        }
                    }
                }
                Protocol::Timeout => {
                    if let Some(first) = table.timeout {
                        errors.push(format!(
                            "每个规则只能有一条启用的「等待超时」路由：{} 与 {} 冲突",
                            routes[first].name, route.name
                        ));
                    } else {
                        table.timeout = Some(index);
                    }
                }
                Protocol::Spa => {
                    if let Some(first) = table.spa {
                        errors.push(format!(
                            "每个规则只能有一条启用的 spa 路由：{} 与 {} 冲突",
                            routes[first].name, route.name
                        ));
                    } else {
                        table.spa = Some(index);
                    }
                }
                protocol => {
                    if let Some(&first) = table.plain.get(&protocol) {
                        errors.push(format!(
                            "协议 {} 只能有一条启用的路由：{} 与 {} 冲突",
                            protocol.as_str(),
                            routes[first].name,
                            route.name
                        ));
                    } else {
                        table.plain.insert(protocol, index);
                    }
                }
            }
        }
        // Wildcards match longest suffix first.
        table
            .tls
            .wildcard
            .sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));
        table
            .http
            .wildcard
            .sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));
        table
            .minecraft
            .wildcard
            .sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));
        if errors.is_empty() {
            Ok(table)
        } else {
            Err(errors)
        }
    }

    /// The match keys aligned with the rule's route indices.
    pub fn keys(&self) -> &[MatchKey] {
        &self.keys
    }

    /// Whether the rule routes unmatched connections to a default target.
    pub fn has_default(&self) -> bool {
        self.default_target
    }

    /// Whether the rule currently carries an enabled SPA route.
    pub fn has_spa(&self) -> bool {
        self.spa.is_some()
    }

    /// Resolves a sniffed connection to its target. One snapshot read per
    /// connection; no locks.
    pub fn route(&self, sniff: &SniffResult) -> Target {
        match sniff.protocol {
            Protocol::Spa => self
                .spa
                .map(Target::Spa)
                .unwrap_or_else(|| self.unmatched()),
            Protocol::Timeout => self
                .timeout
                .map(Target::Route)
                .unwrap_or_else(|| self.unmatched()),
            Protocol::Tls => {
                self.domain_route(&self.tls, sniff.server_name.as_deref(), &sniff.alpn)
            }
            Protocol::Http => self.domain_route(&self.http, sniff.host.as_deref(), &[]),
            Protocol::Minecraft => {
                self.domain_route(&self.minecraft, sniff.server_name.as_deref(), &[])
            }
            protocol => self
                .plain
                .get(&protocol)
                .copied()
                .map(Target::Route)
                .unwrap_or_else(|| self.unmatched()),
        }
    }

    /// A sniffed protocol with no enabled route: the default target, or
    /// drop when the rule has none.
    fn unmatched(&self) -> Target {
        if self.default_target {
            Target::Default
        } else {
            Target::Drop
        }
    }

    fn domain_route(&self, table: &DomainTable, domain: Option<&str>, alpn: &[String]) -> Target {
        let name = domain
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .and_then(validate::punycode_domain);
        if let Some(host) = name.filter(|host| !host.is_empty() && *host != "*") {
            // Exact, then longest wildcard, then `*`; a level whose ALPN
            // routes all miss falls through to the next wider level.
            for level in table.levels_for(&host) {
                if let Some(index) = level.pick(alpn) {
                    return Target::Route(index);
                }
            }
            // The connection carries no usable domain (or nothing
            // matched): routes without domains still apply.
        }
        if let Some(index) = table.generic.as_ref().and_then(|bucket| bucket.pick(alpn)) {
            return Target::Route(index);
        }
        self.unmatched()
    }
}

impl Bucket {
    /// Picks by client ALPN preference order first, then the route that
    /// accepts any ALPN.
    fn pick(&self, alpn: &[String]) -> Option<usize> {
        for client in alpn {
            for (set, index) in &self.by_alpn {
                if set.iter().any(|id| id == client) {
                    return Some(*index);
                }
            }
        }
        self.generic
    }
}

impl DomainTable {
    /// Lookup levels for a concrete host: the exact entry, every matching
    /// wildcard (longest suffix first), then the `*` bucket.
    fn levels_for<'a>(&'a self, host: &'a str) -> Vec<&'a Bucket> {
        let mut levels = Vec::new();
        if let Some(bucket) = self.exact.get(host) {
            levels.push(bucket);
        }
        for (suffix, bucket) in &self.wildcard {
            // Any number of subdomain levels: the host ends with the
            // suffix behind a dot; the bare suffix itself is not a match.
            if host.ends_with(&format!(".{suffix}")) {
                levels.push(bucket);
            }
        }
        if let Some(bucket) = &self.any {
            levels.push(bucket);
        }
        levels
    }
}

/// Human-readable condition for conflict messages.
fn describe_slot(domain: &str, alpn: Option<&str>) -> String {
    let mut parts = Vec::new();
    if !domain.is_empty() {
        parts.push(domain.to_owned());
    }
    if let Some(id) = alpn {
        parts.push(format!("alpn:{id}"));
    }
    if parts.is_empty() {
        "无条件".to_owned()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Net, Rule};
    use crate::sniff::SniffResult;

    fn route(name: &str, protocol: Protocol, domains: &[&str], alpn: &[&str]) -> Route {
        Route {
            name: name.to_owned(),
            protocol,
            domains: domains.iter().map(|d| d.to_string()).collect(),
            alpn: alpn.iter().map(|a| a.to_string()).collect(),
            target_addresses: vec!["127.0.0.1".to_owned()],
            target_port: 9000,
            ..Route::default()
        }
    }

    fn sniffed(protocol: Protocol, name: Option<&str>, alpn: &[&str]) -> SniffResult {
        SniffResult {
            protocol,
            server_name: name.map(|n| n.to_owned()),
            alpn: alpn.iter().map(|a| a.to_string()).collect(),
            host: name.map(|n| n.to_owned()),
            raw: Vec::new(),
        }
    }

    fn compile(routes: Vec<Route>) -> RouteTable {
        RouteTable::compile(&routes, true, None).expect("routes compile")
    }

    fn compile_conflict(routes: Vec<Route>) -> Vec<String> {
        RouteTable::compile(&routes, true, None).expect_err("expected conflicts")
    }

    #[test]
    fn match_exact_then_longest_wildcard_then_star_then_generic() {
        let table = compile(vec![
            route("wild", Protocol::Tls, &["*.example"], &[]),
            route("deep", Protocol::Tls, &["*.deep.example"], &[]),
            route("exact", Protocol::Tls, &["a.example"], &[]),
            route("star", Protocol::Tls, &["*"], &[]),
            route("generic", Protocol::Tls, &[], &[]),
        ]);
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("a.example"), &[])),
            Target::Route(2),
            "exact beats wildcard"
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("x.deep.example"), &[])),
            Target::Route(1),
            "longest wildcard wins over the shorter one"
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("b.example"), &[])),
            Target::Route(0)
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("other.net"), &[])),
            Target::Route(3),
            "`*` matches any carried domain"
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, None, &[])),
            Target::Route(4),
            "no SNI falls through to the domain-less route"
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Http, Some("a.example"), &[])),
            Target::Default,
            "TLS routes never take HTTP connections"
        );
    }

    #[test]
    fn match_wildcard_matches_any_subdomain_depth() {
        let table = compile(vec![route("wild", Protocol::Tls, &["*.example"], &[])]);
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("a.b.c.example"), &[])),
            Target::Route(0)
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("example"), &[])),
            Target::Default,
            "the bare domain is not a subdomain of *.example"
        );
    }

    #[test]
    fn match_alpn_more_specific_wins_and_falls_back_outward() {
        let table = compile(vec![
            route("exact-h2", Protocol::Tls, &["a.example"], &["h2"]),
            route("wild-http11", Protocol::Tls, &["*.example"], &["http/1.1"]),
            route("wild-any", Protocol::Tls, &["*.example"], &[]),
            route("generic", Protocol::Tls, &[], &[]),
        ]);
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("a.example"), &["h2"])),
            Target::Route(0)
        );
        // The exact level has only the h2 route, which does not match:
        // continue outward to the wildcard's http/1.1 route before using its
        // unrestricted one.
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("a.example"), &["http/1.1"])),
            Target::Route(1),
            "ALPN-restricted routes match outward before the generic one"
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("b.example"), &["mqtt"])),
            Target::Route(2)
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Tls, Some("other.net"), &[])),
            Target::Route(3)
        );
    }

    #[test]
    fn match_alpn_by_client_preference_order() {
        let table = compile(vec![
            route("h2", Protocol::Tls, &["a.example"], &["h2"]),
            route("http11", Protocol::Tls, &["a.example"], &["http/1.1"]),
        ]);
        // The client offers both; the first client preference decides.
        assert_eq!(
            table.route(&sniffed(
                Protocol::Tls,
                Some("a.example"),
                &["http/1.1", "h2"]
            )),
            Target::Route(1)
        );
        assert_eq!(
            table.route(&sniffed(
                Protocol::Tls,
                Some("a.example"),
                &["h2", "http/1.1"]
            )),
            Target::Route(0)
        );
    }

    #[test]
    fn match_plain_protocols_and_timeout_and_spa() {
        let table = compile(vec![
            route("ssh", Protocol::Ssh, &[], &[]),
            route("wait", Protocol::Timeout, &[], &[]),
            route("knock", Protocol::Spa, &[], &[]),
        ]);
        assert_eq!(
            table.route(&sniffed(Protocol::Ssh, None, &[])),
            Target::Route(0)
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Timeout, None, &[])),
            Target::Route(1)
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Spa, None, &[])),
            Target::Spa(2)
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Redis, None, &[])),
            Target::Default
        );
    }

    #[test]
    fn match_no_default_target_drops() {
        let routes = vec![route("ssh", Protocol::Ssh, &[], &[])];
        let table = RouteTable::compile(&routes, false, None).expect("compile");
        assert_eq!(
            table.route(&sniffed(Protocol::Redis, None, &[])),
            Target::Drop
        );
        assert_eq!(
            table.route(&sniffed(Protocol::Timeout, None, &[])),
            Target::Drop
        );
    }

    #[test]
    fn compile_conflicts_within_enabled_routes_only() {
        // Same condition twice, both enabled: conflict.
        let errors = compile_conflict(vec![
            route("one", Protocol::Tls, &["a.example"], &[]),
            route("two", Protocol::Tls, &["a.example"], &[]),
        ]);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("one") && e.contains("two"))
        );
        // The same pair with one disabled: no conflict.
        let mut disabled = route("two", Protocol::Tls, &["a.example"], &[]);
        disabled.disabled = true;
        assert!(
            RouteTable::compile(
                &[route("one", Protocol::Tls, &["a.example"], &[]), disabled],
                true,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn compile_conflicts_per_protocol_and_condition() {
        // Two plain routes of the same protocol.
        let errors = compile_conflict(vec![
            route("ssh1", Protocol::Ssh, &[], &[]),
            route("ssh2", Protocol::Ssh, &[], &[]),
        ]);
        assert_eq!(errors.len(), 1);
        // Same domain but different ALPN sets: separate conditions.
        assert!(
            RouteTable::compile(
                &[
                    route("h2", Protocol::Tls, &["a.example"], &["h2"]),
                    route("plain", Protocol::Tls, &["a.example"], &[]),
                ],
                true,
                None
            )
            .is_ok()
        );
        // Condition order-free: the same sets in a different order are the
        // same condition.
        let mut reordered = route("dup", Protocol::Tls, &["b.example", "a.example"], &[]);
        reordered.domains = vec!["a.example".into(), "b.example".into()];
        let errors = compile_conflict(vec![
            route("orig", Protocol::Tls, &["a.example", "b.example"], &[]),
            reordered,
        ]);
        assert_eq!(errors.len(), 1, "order must not hide the conflict");
    }

    #[test]
    fn counts_inherit_by_match_key() {
        // Renaming, moving and re-targeting keep the key; changing the
        // protocol, domains or ALPN changes it.
        let base = route("web", Protocol::Tls, &["a.example"], &["h2"]);
        let mut renamed = base.clone();
        renamed.name = "renamed".to_owned();
        renamed.target_addresses = vec!["10.9.9.9".into()];
        renamed.target_port = 7777;
        assert_eq!(match_key(&base), match_key(&renamed));

        let mut domains_changed = base.clone();
        domains_changed.domains = vec!["b.example".into()];
        assert_ne!(match_key(&base), match_key(&domains_changed));

        let mut alpn_changed = base.clone();
        alpn_changed.alpn.push("http/1.1".into());
        assert_ne!(match_key(&base), match_key(&alpn_changed));

        let mut protocol_changed = base.clone();
        protocol_changed.protocol = Protocol::Http;
        assert_ne!(match_key(&base), match_key(&protocol_changed));

        // A table compiled over the renamed route reuses the old key, so
        // counters map over; the changed route does not.
        let old = compile(vec![base]);
        let new = compile(vec![renamed, domains_changed]);
        assert_eq!(new.keys()[0], old.keys()[0]);
        assert_ne!(new.keys()[1], old.keys()[0]);
    }

    #[test]
    fn compile_keeps_disabled_route_keys_aligned() {
        let mut disabled = route("off", Protocol::Ssh, &[], &[]);
        disabled.disabled = true;
        let table = compile(vec![
            route("on", Protocol::Http, &["a.example"], &[]),
            disabled,
        ]);
        assert_eq!(table.keys().len(), 2);
        assert_eq!(
            table.route(&sniffed(Protocol::Ssh, None, &[])),
            Target::Default
        );
    }

    #[test]
    fn match_http_uses_host_and_minecraft_the_server_address() {
        let table = compile(vec![
            route("http-route", Protocol::Http, &["web.example"], &[]),
            route("mc-route", Protocol::Minecraft, &["mc.example"], &[]),
        ]);
        let mut http = sniffed(Protocol::Http, Some("web.example"), &[]);
        http.server_name = None;
        assert_eq!(table.route(&http), Target::Route(0));
        let mut mc = sniffed(Protocol::Minecraft, Some("mc.example"), &[]);
        mc.host = None;
        assert_eq!(table.route(&mc), Target::Route(1));
    }

    /// Guard against accidental `Rule` coupling: the compiler only sees
    /// routes.
    #[test]
    fn compile_is_independent_of_rule_shape() {
        let rule = Rule {
            key: "k".into(),
            name: "n".into(),
            protocols: vec![Net::Tcp],
            routes: vec![route("only", Protocol::Tls, &["a.example"], &[])],
            ..Rule::default()
        };
        assert!(RouteTable::compile(&rule.routes, true, None).is_ok());
    }
}
