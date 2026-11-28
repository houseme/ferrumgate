//! Site access control (WP-26): the decision chain — bans first, then
//! the deny lists, then the IP lists (site level or path rules), then
//! knock admission, then country filtering — plus path rules and share
//! links. The decision order is fixed (§3.3); denyClose turns every
//! rejection into a bare disconnect instead of a 403.
#![allow(dead_code)]

pub mod path_rules;
pub mod share_link;

use std::net::IpAddr;

/// Why the access chain refused this source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenyReason {
    Ban,
    IpList,
    DenyList,
    Knock,
    Country,
}

/// How a rejection answers the visitor (§3.3 拒绝方式): a 403 or a bare
/// disconnect (logged as 444).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DenyMode {
    #[default]
    Forbid403,
    Close,
}

/// The site-level decision inputs compiled once per site.
#[derive(Clone, Debug, Default)]
pub struct AccessDecision {
    pub deny_mode: DenyMode,
    /// `ipDenyList` — hit means rejected before anything else (bans
    /// excepted).
    pub deny_entries: Vec<String>,
    /// `ipMode` list/sets keys, whitelist or blacklist.
    pub whitelist: bool,
    pub list_entries: Vec<String>,
    /// Country filtering (GeoIP, WP-26): allow or deny the listed
    /// countries; private addresses always pass; an unloaded database
    /// disables the filter.
    pub country_mode: Option<CountryMode>,
    pub countries: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountryMode {
    Allow,
    Deny,
}

/// The access chain verdict for one request (§3.3 fixed order): bans,
/// the deny lists, the IP lists (site level or the selected path rule),
/// knock admission, country filtering. `Ok(())` continues the pipeline;
/// `Err(reason)` answers per the deny mode.
pub fn decide(
    source: IpAddr,
    banned: bool,
    decision: &AccessDecision,
    rules: &[path_rules::PathRule],
    path: &str,
    knock_ok: bool,
    country_of: &dyn Fn(IpAddr) -> Option<String>,
    contains_entry: &dyn Fn(&str, IpAddr) -> bool,
) -> Result<(), DenyReason> {
    // 1. Bans beat every list — a whitelisted banned address still loses.
    if banned {
        return Err(DenyReason::Ban);
    }
    // Private and link-local sources pass the knock and country checks
    // (the site owner sits behind them).
    let private = source.is_loopback()
        || matches!(source, IpAddr::V4(v4) if v4.is_private())
        || matches!(source, IpAddr::V4(v4) if v4.is_link_local())
        || matches!(source, IpAddr::V6(v6) if v6.is_unique_local() || (v6.segments()[4] & 0xffc0) == 0xfe80)
        || is_shared_range(source);
    // 2a. The deny lists fire before any list decision.
    if decision
        .deny_entries
        .iter()
        .any(|key| contains_entry(key, source))
    {
        return Err(DenyReason::DenyList);
    }
    // 2b. The path rule's lists override the site's.
    let normalized = path_rules::normalize(path);
    let rule_lists = path_rules::select(rules, &normalized)
        .map(|rule| &rule.ip_list)
        .filter(|lists| !lists.is_empty());
    let lists = rule_lists.unwrap_or(&decision.list_entries);
    let in_list = lists.iter().any(|key| contains_entry(key, source));
    // An empty configured list never rejects anything (an empty
    // whitelist with no feeds would otherwise deny the world).
    if !lists.is_empty() {
        let listed = match decision.whitelist {
            true => !in_list,
            false => in_list,
        };
        if listed {
            return Err(DenyReason::IpList);
        }
    }
    // 3. Knock admission.
    if !knock_ok && !private {
        return Err(DenyReason::Knock);
    }
    // 4. Country filtering; private addresses always pass, and deny
    // mode admits addresses the database cannot resolve.
    if let Some(mode) = decision.country_mode
        && !private
    {
        let country = country_of(source);
        let listed = country.is_some_and(|c| decision.countries.contains(&c));
        let admitted = match mode {
            CountryMode::Allow => listed,
            CountryMode::Deny => !listed,
        };
        if !admitted {
            return Err(DenyReason::Country);
        }
    }
    Ok(())
}

/// 100.64.0.0/10 — carrier-grade NAT; all visitors behind it share one
/// address, so IP checks treat it like private space.
fn is_shared_range(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid ip")
    }

    fn decision(list_entries: Vec<&str>, whitelist: bool) -> AccessDecision {
        AccessDecision {
            deny_mode: DenyMode::Forbid403,
            deny_entries: Vec::new(),
            whitelist,
            list_entries: list_entries.into_iter().map(str::to_owned).collect(),
            country_mode: None,
            countries: Vec::new(),
        }
    }

    // The test registry: "feeds" contains 203.0.113.0/24.
    fn contains(key: &str, ip: IpAddr) -> bool {
        key == "feeds" && ip.to_string().starts_with("203.0.113.")
    }
    fn no_country(_: IpAddr) -> Option<String> {
        None
    }
    fn rules() -> Vec<path_rules::PathRule> {
        Vec::new()
    }

    #[test]
    fn bans_beat_the_whitelist() {
        let d = decision(vec!["feeds"], true);
        assert_eq!(
            decide(
                ip("203.0.113.9"),
                true,
                &d,
                &rules(),
                "/",
                true,
                &no_country,
                &contains
            ),
            Err(DenyReason::Ban)
        );
    }

    #[test]
    fn whitelist_and_blacklist_directions() {
        let whitelist = decision(vec!["feeds"], true);
        assert!(decide(
            ip("203.0.113.9"),
            false,
            &whitelist,
            &rules(),
            "/",
            true,
            &no_country,
            &contains
        )
        .is_ok());
        assert_eq!(
            decide(
                ip("198.51.100.1"),
                false,
                &whitelist,
                &rules(),
                "/",
                true,
                &no_country,
                &contains
            ),
            Err(DenyReason::IpList)
        );
        let blacklist = decision(vec!["feeds"], false);
        assert_eq!(
            decide(
                ip("203.0.113.9"),
                false,
                &blacklist,
                &rules(),
                "/",
                true,
                &no_country,
                &contains
            ),
            Err(DenyReason::IpList)
        );
        assert!(decide(
            ip("198.51.100.1"),
            false,
            &blacklist,
            &rules(),
            "/",
            true,
            &no_country,
            &contains
        )
        .is_ok());
    }

    #[test]
    fn knock_required_but_private_passes() {
        let d = decision(vec![], false);
        assert_eq!(
            decide(
                ip("198.51.100.1"),
                false,
                &d,
                &rules(),
                "/",
                false,
                &no_country,
                &contains
            ),
            Err(DenyReason::Knock)
        );
        // A private source needs no knock admission.
        assert!(decide(
            ip("192.168.1.5"),
            false,
            &d,
            &rules(),
            "/",
            false,
            &no_country,
            &contains
        )
        .is_ok());
    }

    #[test]
    fn path_rule_overrides_the_site_lists() {
        // The site list is empty, but the /admin rule's override has the
        // feed: only /admin paths feel it.
        let d = decision(vec![], false);
        let overrides = vec![path_rules::PathRule {
            prefix: "/admin".to_owned(),
            auth: path_rules::AuthRule::Inherit,
            ip_list: vec!["feeds".to_owned()],
        }];
        assert!(decide(
            ip("203.0.113.9"),
            false,
            &d,
            &overrides,
            "/",
            true,
            &no_country,
            &contains
        )
        .is_ok());
        assert_eq!(
            decide(
                ip("203.0.113.9"),
                false,
                &d,
                &overrides,
                "/admin/x",
                true,
                &no_country,
                &contains
            ),
            Err(DenyReason::IpList)
        );
    }

    #[test]
    fn deny_list_fires_before_the_lists() {
        let mut d = decision(vec!["feeds"], true);
        // The address is whitelisted AND deny-listed: the deny list wins.
        d.deny_entries = vec!["feeds".to_owned()];
        assert_eq!(
            decide(
                ip("203.0.113.9"),
                false,
                &d,
                &rules(),
                "/",
                true,
                &no_country,
                &contains
            ),
            Err(DenyReason::DenyList)
        );
    }

    #[test]
    fn country_modes_admit_private_unlisted_unknowns() {
        let mut d = decision(vec![], false);
        d.country_mode = Some(CountryMode::Allow);
        d.countries = vec!["CN".to_owned()];
        let country_of = |ip: IpAddr| {
            (ip.to_string().starts_with("203.")).then(|| "US".to_owned())
        };
        // Allow mode rejects a US source.
        assert_eq!(
            decide(
                ip("203.0.113.9"),
                false,
                &d,
                &rules(),
                "/",
                true,
                &country_of,
                &contains
            ),
            Err(DenyReason::Country)
        );
        // A private address passes regardless of its country.
        assert!(decide(
            ip("192.168.1.5"),
            false,
            &d,
            &rules(),
            "/",
            true,
            &country_of,
            &contains
        )
        .is_ok());
        // Deny mode admits unknown-country addresses.
        d.country_mode = Some(CountryMode::Deny);
        assert!(decide(
            ip("198.51.100.1"),
            false,
            &d,
            &rules(),
            "/",
            true,
            &no_country,
            &contains
        )
        .is_ok());
        // Deny mode rejects listed countries: switch the list to the US.
        d.countries = vec!["US".to_owned()];
        assert_eq!(
            decide(
                ip("203.0.113.9"),
                false,
                &d,
                &rules(),
                "/",
                true,
                &country_of,
                &contains
            ),
            Err(DenyReason::Country)
        );
    }
}
