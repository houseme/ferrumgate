//! Redirect variable expansion (WP-22 §3.3, upstream `redirectvars.go`).
//!
//! `Site::redirect_to` is a target prefix that may contain `{...}` variables
//! (`{host}`, `{port}`, `{path}`, `{ClientIP}`, `{domainPartN}`, `{1}`, ...).
//! This module parses a target into [`RedirectTarget::Fixed`] (no variables,
//! no expansion needed) or [`RedirectTarget::Template`] (parsed parts), and
//! expands a template against a [`RedirectContext`].
//!
//! Semantics ported from upstream:
//! - Unknown `{xxx}` tokens are preserved verbatim in the output.
//! - When the template uses a path variable (`{path}`, `{PATH}`,
//!   `{pathPart}`, `{pathPartN}`), the original request path is *not*
//!   appended; when it uses an args variable (`{args}`, `{Args}`), the
//!   original query string is *not* appended. The other half is still
//!   appended as usual.
//! - Values derived from the `Host` header must only contain hostname / IP /
//!   port characters (`[a-zA-Z0-9.:\[\]]`): HTTP/1 allows `&`, `=` and
//!   similar characters in `Host`, and substituting them verbatim would
//!   change the redirect target. If the check fails the redirect is rejected
//!   (400 in production); expansion yields an empty string.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// A parsed redirect target: either a fixed string without variables or a
/// template built from literal chunks and variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectTarget {
    /// No `{...}` present; use as-is.
    Fixed(String),
    /// Contains variables; expand with [`expand`] at request time.
    Template(Vec<TemplatePart>),
}

/// One chunk of a parsed redirect template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplatePart {
    /// Verbatim text between variables (unknown `{xxx}` tokens are kept as
    /// literals so they survive expansion unchanged).
    Literal(String),
    /// A recognized variable.
    Var(Var),
}

/// A redirect variable recognized by [`parse_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Var {
    /// `{host}` — requested hostname, IPv6 brackets stripped.
    Host,
    /// `{port}` — the listener port.
    Port,
    /// `{hostAndPort}` — `{host}:{port}` (IPv6 keeps its brackets so the
    /// result stays a valid URL authority).
    HostAndPort,
    /// `{path}` (no leading `/`) or `{PATH}` (with leading `/`).
    Path(bool),
    /// `{args}` (no `?`) or `{Args}` (with leading `?`).
    Args(bool),
    /// `{pathPart}` — path-class variable equivalent to `{path}`.
    PathPart,
    /// `{ClientIP}` — real client address.
    ClientIp,
    /// `{RemoteIP}` — TCP peer address.
    RemoteIp,
    /// `{time}` — current time as `YYYY-MM-DD HH:MM:SS`, space written `%20`.
    Time,
    /// `{domainPartN}` — Nth dot-separated host segment (empty segments
    /// dropped, N starts at 1); empty when the host has no such segment.
    DomainPart(u8),
    /// `{pathPartN}` — Nth `/`-separated path segment (empty segments
    /// dropped, N starts at 1); empty when the path has no such segment.
    PathPartN(u8),
    /// `{1}` — the part a `*` in the site's domain pattern captured.
    WildcardCapture,
    /// `{STUN_<rule>_PORT}` / `{STUN_<rule>_IP}` / `{STUN_<rule>_ADDR}` —
    /// the STUN rule's current public port / IP / address. WP-42 provides
    /// the resolver; until it is wired in this expands to an empty string.
    Stun { rule: String, part: StunPart },
}

/// Which part of a STUN rule's public address a variable asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunPart {
    /// `_PORT` — public port.
    Port,
    /// `_IP` — public IP.
    Ip,
    /// `_ADDR` — public IP plus port.
    Addr,
}

/// Request-derived values the variables resolve against.
#[derive(Debug, Clone, Copy)]
pub struct RedirectContext<'a> {
    /// From the `Host` header (may still carry a `:port` suffix; IPv6 may
    /// have brackets).
    pub host: &'a str,
    /// The listener port.
    pub port: u16,
    /// Request path.
    pub path: &'a str,
    /// Query string without the leading `?`.
    pub args: &'a str,
    /// Resolved client address.
    pub client_ip: IpAddr,
    /// TCP peer address.
    pub remote_ip: IpAddr,
    /// The part a `*` in the site's domain pattern captured, if any.
    pub wildcard_capture: Option<&'a str>,
    /// Current time.
    pub now: SystemTime,
}

/// Parses a redirect target into [`RedirectTarget::Fixed`] (no `{` at all)
/// or [`RedirectTarget::Template`]. Unknown `{xxx}` names are kept as
/// [`TemplatePart::Literal`] chunks so they are preserved verbatim.
pub fn parse_target(target: &str) -> RedirectTarget {
    if target.contains('{') {
        RedirectTarget::Template(parse_parts(target).0)
    } else {
        RedirectTarget::Fixed(target.to_string())
    }
}

/// Expands a parsed template against the request context.
///
/// `wildcard_capture`, when given, takes precedence over
/// [`RedirectContext::wildcard_capture`] for the `{1}` variable.
///
/// After substitution the original request path is appended unless the
/// template contains a path variable, and the original query string
/// (prefixed with `?`) is appended unless the template contains an args
/// variable — upstream's `keepPath` behavior. If the template uses any
/// host-derived variable and the `Host` header contains characters outside
/// `[a-zA-Z0-9.:\[\]]`, the expansion yields an empty string (production
/// turns this into a 400 instead of a redirect).
pub fn expand(
    template: &[TemplatePart],
    ctx: &RedirectContext,
    wildcard_capture: Option<&str>,
) -> String {
    let uses_host_var = template.iter().any(|part| {
        matches!(
            part,
            TemplatePart::Var(Var::Host | Var::HostAndPort | Var::DomainPart(_))
        )
    });
    if uses_host_var && !host_is_safe(ctx.host) {
        return String::new();
    }
    let wildcard = wildcard_capture.or(ctx.wildcard_capture).unwrap_or("");
    let mut out = String::new();
    let mut has_path_var = false;
    let mut has_args_var = false;
    for part in template {
        match part {
            TemplatePart::Literal(text) => out.push_str(text),
            TemplatePart::Var(var) => {
                if matches!(var, Var::Path(_) | Var::PathPart | Var::PathPartN(_)) {
                    has_path_var = true;
                }
                if matches!(var, Var::Args(_)) {
                    has_args_var = true;
                }
                out.push_str(&resolve(var, ctx, wildcard));
            }
        }
    }
    if !has_path_var {
        out.push_str(ctx.path);
    }
    if !has_args_var && !ctx.args.is_empty() {
        out.push('?');
        out.push_str(ctx.args);
    }
    out
}

/// Validates a redirect target at save time: every variable is replaced by a
/// sample value and the result must parse as an absolute URL (scheme
/// present). Returns `Err` with the list of unknown `{xxx}` variables; an
/// empty list means the sampled string was not a parseable URL.
pub fn validate_target(target: &str) -> Result<(), Vec<String>> {
    let (parts, unknown) = parse_parts(target);
    if !unknown.is_empty() {
        return Err(unknown);
    }
    let sample: String = parts
        .iter()
        .map(|part| match part {
            TemplatePart::Literal(text) => text.as_str(),
            TemplatePart::Var(var) => sample_value(var),
        })
        .collect();
    match sample.parse::<hyper::Uri>() {
        Ok(uri) if uri.scheme_str().is_some() => Ok(()),
        _ => Err(Vec::new()),
    }
}

/// Splits `target` into template parts, collecting unknown `{xxx}` tokens
/// (with braces, e.g. `"{bogus}"`) for `validate_target`.
fn parse_parts(target: &str) -> (Vec<TemplatePart>, Vec<String>) {
    let mut parts = Vec::new();
    let mut unknown = Vec::new();
    let mut literal = String::new();
    let mut rest = target;
    while let Some(start) = rest.find('{') {
        literal.push_str(&rest[..start]);
        let after = &rest[start..];
        match after.find('}') {
            Some(end) => {
                let name = &after[1..end];
                match classify(name) {
                    Some(var) => {
                        if !literal.is_empty() {
                            parts.push(TemplatePart::Literal(std::mem::take(&mut literal)));
                        }
                        parts.push(TemplatePart::Var(var));
                    }
                    None => {
                        let token = &after[..=end];
                        literal.push_str(token);
                        unknown.push(token.to_string());
                    }
                }
                rest = &after[end + 1..];
            }
            // No closing brace: keep the remainder verbatim.
            None => {
                literal.push_str(after);
                rest = "";
            }
        }
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        parts.push(TemplatePart::Literal(literal));
    }
    (parts, unknown)
}

/// Maps a variable name (the text between braces) to a [`Var`]; `None` means
/// the name is unknown and the token is preserved verbatim.
fn classify(name: &str) -> Option<Var> {
    match name {
        "host" => Some(Var::Host),
        "port" => Some(Var::Port),
        "hostAndPort" => Some(Var::HostAndPort),
        "path" => Some(Var::Path(false)),
        "PATH" => Some(Var::Path(true)),
        "pathPart" => Some(Var::PathPart),
        "args" => Some(Var::Args(false)),
        "Args" => Some(Var::Args(true)),
        "ClientIP" => Some(Var::ClientIp),
        "RemoteIP" => Some(Var::RemoteIp),
        "time" => Some(Var::Time),
        "1" => Some(Var::WildcardCapture),
        _ => {
            if let Some(n) = indexed_suffix(name, "domainPart") {
                return Some(Var::DomainPart(n));
            }
            if let Some(n) = indexed_suffix(name, "pathPart") {
                return Some(Var::PathPartN(n));
            }
            parse_stun(name)
        }
    }
}

/// `"{prefix}<digits>"` with digits >= 1 → the index.
fn indexed_suffix(name: &str, prefix: &str) -> Option<u8> {
    let digits = name.strip_prefix(prefix)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u8 = digits.parse().ok()?;
    (n >= 1).then_some(n)
}

/// `"{STUN_<rule>_PORT|_IP|_ADDR}"` with a non-empty rule name.
fn parse_stun(name: &str) -> Option<Var> {
    let rest = name.strip_prefix("STUN_")?;
    let (rule, part) = if let Some(rule) = rest.strip_suffix("_PORT") {
        (rule, StunPart::Port)
    } else if let Some(rule) = rest.strip_suffix("_ADDR") {
        (rule, StunPart::Addr)
    } else {
        rest.strip_suffix("_IP").map(|rule| (rule, StunPart::Ip))?
    };
    if rule.is_empty() {
        return None;
    }
    Some(Var::Stun {
        rule: rule.to_string(),
        part,
    })
}

/// Resolves one variable to its string value.
fn resolve(var: &Var, ctx: &RedirectContext, wildcard: &str) -> String {
    match var {
        Var::Host => strip_host_brackets(ctx.host).to_string(),
        Var::Port => ctx.port.to_string(),
        Var::HostAndPort => format!("{}:{}", ctx.host, ctx.port),
        Var::Path(with_slash) => {
            if *with_slash {
                ctx.path.to_string()
            } else {
                ctx.path.strip_prefix('/').unwrap_or(ctx.path).to_string()
            }
        }
        Var::PathPart => ctx.path.strip_prefix('/').unwrap_or(ctx.path).to_string(),
        Var::Args(with_q) => {
            if *with_q {
                format!("?{}", ctx.args)
            } else {
                ctx.args.to_string()
            }
        }
        Var::ClientIp => ctx.client_ip.to_string(),
        Var::RemoteIp => ctx.remote_ip.to_string(),
        Var::Time => format_time(ctx.now),
        Var::DomainPart(n) => nth_part(strip_host_brackets(ctx.host), '.', *n).unwrap_or_default(),
        Var::PathPartN(n) => nth_part(ctx.path, '/', *n).unwrap_or_default(),
        Var::WildcardCapture => wildcard.to_string(),
        // No STUN resolver until WP-42 wires one in: expand to nothing.
        Var::Stun { .. } => String::new(),
    }
}

/// Nth non-empty segment of `s` split on `sep`, 1-based.
fn nth_part(s: &str, sep: char, n: u8) -> Option<String> {
    s.split(sep)
        .filter(|part| !part.is_empty())
        .nth(n as usize - 1)
        .map(str::to_string)
}

/// Host-derived values may only contain hostname / IP / port characters;
/// HTTP/1 `Host` can carry `&`, `=` and friends which would corrupt the
/// redirect target.
fn host_is_safe(host: &str) -> bool {
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'[' | b']'))
}

fn strip_host_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

/// Formats a timestamp as UTC `YYYY-MM-DD HH:MM:SS` with the space written
/// `%20` (upstream uses local time; the gateway keeps UTC since no TZ data
/// is available). Days-to-civil conversion (Howard Hinnant's algorithm).
fn format_time(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year,
        month,
        day,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
    )
    .replace(' ', "%20")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Sample values used by [`validate_target`] to test-expand a template.
fn sample_value(var: &Var) -> &'static str {
    match var {
        Var::Host => "example.com",
        Var::Port => "8443",
        Var::HostAndPort => "example.com:8443",
        Var::Path(false) | Var::PathPart => "some/path",
        Var::Path(true) => "/some/path",
        Var::Args(false) => "k=v",
        Var::Args(true) => "?k=v",
        Var::ClientIp | Var::RemoteIp => "203.0.113.7",
        Var::Time => "2026-01-01%2000:00:00",
        Var::DomainPart(_) => "www",
        Var::PathPartN(_) => "some",
        Var::WildcardCapture => "sub",
        Var::Stun { part, .. } => match part {
            StunPart::Port => "3478",
            StunPart::Ip => "203.0.113.7",
            StunPart::Addr => "203.0.113.7:3478",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 2025-01-01 00:00:00 UTC.
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_735_689_600)
    }

    fn make_ctx<'a>(host: &'a str, port: u16, path: &'a str, args: &'a str) -> RedirectContext<'a> {
        RedirectContext {
            host,
            port,
            path,
            args,
            client_ip: "203.0.113.7".parse().unwrap(),
            remote_ip: "198.51.100.9".parse().unwrap(),
            wildcard_capture: None,
            now: now(),
        }
    }

    fn parts_of(target: &str) -> Vec<TemplatePart> {
        match parse_target(target) {
            RedirectTarget::Template(parts) => parts,
            RedirectTarget::Fixed(_) => panic!("expected a template"),
        }
    }

    #[test]
    fn parse_fixed_vs_template() {
        assert_eq!(
            parse_target("https://example.com/"),
            RedirectTarget::Fixed("https://example.com/".to_string())
        );
        assert_eq!(
            parts_of("https://{host}:{port}/x"),
            vec![
                TemplatePart::Literal("https://".to_string()),
                TemplatePart::Var(Var::Host),
                TemplatePart::Literal(":".to_string()),
                TemplatePart::Var(Var::Port),
                TemplatePart::Literal("/x".to_string()),
            ]
        );
        assert_eq!(
            parts_of("{domainPart2}.example.com"),
            vec![
                TemplatePart::Var(Var::DomainPart(2)),
                TemplatePart::Literal(".example.com".to_string()),
            ]
        );
    }

    #[test]
    fn expand_host_port_and_path_vars() {
        let ctx = make_ctx("example.com", 8080, "/foo/bar", "a=1&b=2");
        // {PATH} carries the leading `/` and {Args} the leading `?`, so the
        // template must not repeat them.
        assert_eq!(
            expand(&parts_of("https://{host}:{port}{PATH}{Args}"), &ctx, None),
            "https://example.com:8080/foo/bar?a=1&b=2"
        );
        // {path} suppresses the path append; the query is still appended.
        assert_eq!(
            expand(&parts_of("https://{hostAndPort}/{path}"), &ctx, None),
            "https://example.com:8080/foo/bar?a=1&b=2"
        );
        // IPv6: brackets stripped from {host}, kept in {hostAndPort}.
        let v6 = make_ctx("[2001:db8::1]", 8443, "", "");
        assert_eq!(
            expand(&parts_of("https://{host}/{hostAndPort}"), &v6, None),
            "https://2001:db8::1/[2001:db8::1]:8443"
        );
    }

    #[test]
    fn expand_client_ip_and_time() {
        let ctx = make_ctx("example.com", 80, "", "");
        assert_eq!(
            expand(
                &parts_of("ip={ClientIP} peer={RemoteIP} t={time}"),
                &ctx,
                None
            ),
            "ip=203.0.113.7 peer=198.51.100.9 t=2025-01-01%2000:00:00"
        );
    }

    #[test]
    fn expand_wildcard_capture() {
        let mut ctx = make_ctx("sub.example.com", 443, "", "");
        ctx.wildcard_capture = Some("blog");
        assert_eq!(
            expand(&parts_of("https://{1}.example.com/"), &ctx, None),
            "https://blog.example.com/"
        );
        // The explicit parameter wins over the context field.
        assert_eq!(
            expand(&parts_of("https://{1}.example.com/"), &ctx, Some("shop")),
            "https://shop.example.com/"
        );
        // No capture anywhere → empty substitution.
        let plain = make_ctx("example.com", 443, "", "");
        assert_eq!(
            expand(&parts_of("https://{1}.example.com/"), &plain, None),
            "https://.example.com/"
        );
    }

    #[test]
    fn expand_domain_and_path_parts() {
        let ctx = make_ctx("www.example.com", 80, "/a/b/c", "");
        assert_eq!(
            expand(
                &parts_of(
                    "{domainPart1}.{domainPart2}.{domainPart3}/{pathPart1}/{pathPart2}/{pathPart5}"
                ),
                &ctx,
                None
            ),
            "www.example.com/a/b/"
        );
        // Empty host segments are dropped before indexing.
        let spaced = make_ctx(".example..com", 80, "", "");
        assert_eq!(
            expand(&parts_of("{domainPart1}.{domainPart2}"), &spaced, None),
            "example.com"
        );
    }

    #[test]
    fn unknown_vars_preserved() {
        let ctx = make_ctx("example.com", 80, "", "q=1");
        assert_eq!(
            expand(&parts_of("https://{host}/{bogus}?{args}"), &ctx, None),
            "https://example.com/{bogus}?q=1"
        );
        // No args variable → the context query is appended after the
        // preserved token; no path variable → the (empty) path too.
        let bare = make_ctx("example.com", 80, "", "");
        assert_eq!(
            expand(&parts_of("x{2}y{STUN_}z{}w"), &bare, None),
            "x{2}y{STUN_}z{}w"
        );
        // A `{` without a closing brace is literal text.
        assert_eq!(
            expand(&parts_of("https://{host}/{open"), &bare, None),
            "https://example.com/{open"
        );
    }

    #[test]
    fn host_sanitization_rejects_bad_chars() {
        // `/` and `?` are not allowed in a Host-derived value.
        let evil = make_ctx("example.com/path?x=1", 80, "", "");
        assert_eq!(expand(&parts_of("https://{host}/"), &evil, None), "");
        assert_eq!(expand(&parts_of("https://{hostAndPort}/"), &evil, None), "");
        assert_eq!(expand(&parts_of("{domainPart1}"), &evil, None), "");
        // `&` is likewise rejected.
        let ampersand = make_ctx("bad&host", 80, "/", "");
        assert_eq!(
            expand(&parts_of("https://{hostAndPort}/"), &ampersand, None),
            ""
        );
        // A `:port` suffix is legitimate and passes.
        let with_port = make_ctx("example.com:8443", 80, "", "");
        assert_eq!(
            expand(&parts_of("https://{host}/"), &with_port, None),
            "https://example.com:8443/"
        );
        // Templates without host-derived variables are unaffected.
        assert_eq!(
            expand(&parts_of("ip={ClientIP}"), &evil, None),
            "ip=203.0.113.7"
        );
    }

    #[test]
    fn validate_target_checks_url_parsability() {
        assert!(validate_target("https://{host}/{PATH}?{args}").is_ok());
        assert!(validate_target("https://example.com/").is_ok());
        assert!(validate_target("https://{1}.{host}:{port}/").is_ok());
        assert!(validate_target("https://{STUN_my_rule_PORT}{Args}").is_ok());
        // Unknown variables are reported (with braces).
        assert_eq!(
            validate_target("https://{bogus}/"),
            Err(vec!["{bogus}".to_string()])
        );
        // No scheme → not a parseable absolute URL.
        assert!(validate_target("{host}/x").is_err());
        assert!(validate_target("").is_err());
    }

    #[test]
    fn path_and_args_not_appended_when_vars_present() {
        let ctx = make_ctx("example.com", 80, "/foo", "a=1&b=2");
        // Neither var present → path and query both appended.
        assert_eq!(
            expand(&parts_of("https://{host}"), &ctx, None),
            "https://example.com/foo?a=1&b=2"
        );
        // Path variable present → path not appended (no "/foo/foo"),
        // query still appended. {PATH} carries the leading `/` itself.
        assert_eq!(
            expand(&parts_of("https://{host}{PATH}"), &ctx, None),
            "https://example.com/foo?a=1&b=2"
        );
        assert_eq!(
            expand(&parts_of("https://{host}/{pathPart1}/x"), &ctx, None),
            "https://example.com/foo/x?a=1&b=2"
        );
        // Args variable present → query not appended, path still appended
        // (upstream rule: the other half is appended as usual).
        assert_eq!(
            expand(&parts_of("https://{host}?{args}"), &ctx, None),
            "https://example.com?a=1&b=2/foo"
        );
        // Both present → nothing appended.
        assert_eq!(
            expand(&parts_of("https://{host}/{path}?{args}"), &ctx, None),
            "https://example.com/foo?a=1&b=2"
        );
        // Empty query string → no dangling `?`.
        let no_args = make_ctx("example.com", 80, "/foo", "");
        assert_eq!(
            expand(&parts_of("https://{host}"), &no_args, None),
            "https://example.com/foo"
        );
    }
}
