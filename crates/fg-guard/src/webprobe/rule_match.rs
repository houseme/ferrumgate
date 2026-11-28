//! Web path probe matching (WP-52 §3.3): the counting semantics shared
//! by every `web` jail. The web service reports each finished request
//! once; the guard decides whether it counts — default 404/444 only,
//! access-control denies as 403 on ordinary sites and 444 on the default
//! site, trusted visitors never counted, `unknownHost` jails restricted
//! to unmatched domains, path rules checked against the raw and the
//! normalized path.

use super::path_rule::{PathRule, normalize_path, path_matches};

/// One finished request as the web service reports it. All the site /
/// listener context is already resolved here; the guard never inspects
/// request bodies or credentials.
#[derive(Clone, Copy, Debug)]
pub struct WebRequestSummary<'a> {
    /// The listener that served the request.
    pub listener: &'a str,
    /// The raw request path (decoded, no query string).
    pub path: &'a str,
    /// The Host header the request came with.
    pub host: &'a str,
    /// The response status actually sent.
    pub status: u16,
    /// The client address (PROXY protocol / CDN restored).
    pub ip: std::net::IpAddr,
    /// The host matched no site (handled by the default site, or answered
    /// by the listener directly when no default site exists).
    pub unknown_host: bool,
    /// The request landed on the default site.
    pub default_site: bool,
    /// The site trusts logged-in users and the visitor passed its
    /// Gately authentication. Default-site unknown-host requests and
    /// anonymous visitors keep counting, so the reporter only sets this
    /// for the site-trust case.
    pub trusted_user: bool,
    /// The request was refused by the site's access control; the
    /// effective status then follows the deny semantics (403 on ordinary
    /// sites, 444 on the default site) instead of the sent status.
    pub access_denied: bool,
}

/// The status a `web` jail counts the request under: access-control
/// denies map to 403 on ordinary sites and 444 on the default site — the
/// same treatment as the "disconnect" deny type — so visitors outside a
/// site's lists are not banned for using the site normally.
pub fn effective_status(request: &WebRequestSummary<'_>) -> u16 {
    if request.access_denied {
        if request.default_site { 444 } else { 403 }
    } else {
        request.status
    }
}

/// The default statuses that count: 404 (nothing at that path) and 444
/// (a "disconnect" site answered).
pub const DEFAULT_COUNTED_STATUSES: [u16; 2] = [404, 444];

/// Whether the jail counts the request. `target` is the listener filter
/// (empty = all), `rules` the path rules (empty = every path), `ignores`
/// the excluded paths, `any_status` lifts the 404/444 restriction and
/// `unknown_host_only` restricts counting to unmatched domains.
pub fn web_jail_counts(
    target: &str,
    rules: &[PathRule],
    ignores: &[PathRule],
    any_status: bool,
    unknown_host_only: bool,
    request: &WebRequestSummary<'_>,
) -> bool {
    if request.trusted_user {
        return false;
    }
    if !target.is_empty() && request.listener != target {
        return false;
    }
    if unknown_host_only && !request.unknown_host {
        return false;
    }
    if !any_status && !DEFAULT_COUNTED_STATUSES.contains(&effective_status(request)) {
        return false;
    }
    if path_matches(ignores, request.path, &normalize_path(request.path)) {
        return false;
    }
    // An empty rule list means every path counts (WP-52 §3.3).
    rules.is_empty() || path_matches(rules, request.path, &normalize_path(request.path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webprobe::path_rule::compile_paths;
    use std::net::{IpAddr, Ipv4Addr};

    fn request(path: &'static str, status: u16) -> WebRequestSummary<'static> {
        WebRequestSummary {
            listener: "web",
            path,
            host: "example.test",
            status,
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
            unknown_host: false,
            default_site: false,
            trusted_user: false,
            access_denied: false,
        }
    }

    fn paths(text: &str) -> Vec<PathRule> {
        compile_paths(text).expect("compile")
    }

    fn counts(jail: &Jail, request: &WebRequestSummary<'_>) -> bool {
        web_jail_counts(
            &jail.target,
            &jail.rules,
            &jail.ignores,
            jail.any_status,
            jail.unknown_host,
            request,
        )
    }

    /// Local mirror of a compiled web jail for the tests below.
    struct Jail {
        target: String,
        rules: Vec<PathRule>,
        ignores: Vec<PathRule>,
        any_status: bool,
        unknown_host: bool,
    }

    #[test]
    fn web_default_counts_404_and_444_only() {
        let jail = Jail {
            target: String::new(),
            rules: Vec::new(),
            ignores: Vec::new(),
            any_status: false,
            unknown_host: false,
        };
        assert!(counts(&jail, &request("/missing", 404)));
        assert!(counts(&jail, &request("/gone", 444)));
        assert!(!counts(&jail, &request("/", 200)));
        assert!(!counts(&jail, &request("/login", 401)));
        assert!(!counts(&jail, &request("/", 500)));
    }

    #[test]
    fn web_access_deny_403_on_site_444_on_default() {
        let jail = Jail {
            target: String::new(),
            rules: Vec::new(),
            ignores: Vec::new(),
            any_status: false,
            unknown_host: false,
        };
        // An access-control deny on an ordinary site counts as 403 —
        // which does NOT count by default (list members browsing a
        // normal site are not punished).
        let denied = WebRequestSummary {
            access_denied: true,
            ..request("/admin", 403)
        };
        assert!(!counts(&jail, &denied));
        // On the default site a deny counts as 444 and does count.
        let default_denied = WebRequestSummary {
            access_denied: true,
            default_site: true,
            ..request("/admin", 403)
        };
        assert!(counts(&jail, &default_denied));
    }

    #[test]
    fn web_unknown_host_only() {
        let jail = Jail {
            target: String::new(),
            rules: Vec::new(),
            ignores: Vec::new(),
            any_status: false,
            unknown_host: true,
        };
        let mut probe = request("/whatever", 404);
        assert!(!counts(&jail, &probe), "a matched host does not count");
        probe.unknown_host = true;
        assert!(counts(&jail, &probe));
    }

    #[test]
    fn web_trusted_user_not_counted() {
        let jail = Jail {
            target: String::new(),
            rules: Vec::new(),
            ignores: Vec::new(),
            any_status: false,
            unknown_host: false,
        };
        // A trusted visitor never counts, whatever the status.
        let trusted = WebRequestSummary {
            trusted_user: true,
            ..request("/missing", 404)
        };
        assert!(!counts(&jail, &trusted));
        // Anonymous visitors on the default site keep counting.
        let anonymous = WebRequestSummary {
            default_site: true,
            unknown_host: true,
            ..request("/missing", 404)
        };
        assert!(counts(&jail, &anonymous));
    }

    #[test]
    fn web_paths_rules_and_ignores_apply() {
        let jail = Jail {
            target: "web".to_owned(),
            rules: paths("*/.env"),
            ignores: paths("*/keep/.env"),
            any_status: true,
            unknown_host: false,
        };
        assert!(counts(&jail, &request("/.env", 200)));
        assert!(!counts(
            &jail,
            &request("/.env", 200).listener_swap("metrics")
        ));
        assert!(!counts(&jail, &request("/keep/.env", 200)));
        assert!(!counts(&jail, &request("/other", 200)));
    }

    impl WebRequestSummary<'static> {
        fn listener_swap(self, listener: &'static str) -> Self {
            WebRequestSummary { listener, ..self }
        }
    }
}
