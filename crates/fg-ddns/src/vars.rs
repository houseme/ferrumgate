//! Record value variable expansion (WP-40 §3.3): `{ipv4Addr}`,
//! `{ipv6Addr}` and the STUN rule variables `{STUN_规则名_PORT|IP|ADDR}`
//! (the rule may be named by `name` or `key`; rule names may contain
//! underscores). A pure module: the STUN values come in through the
//! [`ValueCtx`] lookup so WP-42 lands independently.

use std::net::IpAddr;

use crate::ip_source::Family;

/// Which piece of a STUN rule result a variable asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StunPart {
    /// Public port: `{STUN_规则名_PORT}`.
    Port,
    /// Public address: `{STUN_规则名_IP}`.
    Ip,
    /// Address plus port: `{STUN_规则名_ADDR}`.
    Addr,
}

/// The resolved value of a STUN lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StunValue {
    Port(u16),
    Ip(IpAddr),
    Addr(String),
}

impl std::fmt::Display for StunValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StunValue::Port(port) => write!(f, "{port}"),
            StunValue::Ip(ip) => write!(f, "{ip}"),
            StunValue::Addr(addr) => f.write_str(addr),
        }
    }
}

/// Expansion context: the addresses this round fetched and the STUN rule
/// lookup injected by the assembler (may answer `None` while a rule is
/// disabled or has not pierced yet).
pub struct ValueCtx<'a> {
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
    pub stun: &'a (dyn Fn(&str, StunPart) -> Option<StunValue> + Send + Sync),
}

impl<'a> ValueCtx<'a> {
    /// A context without STUN support: every STUN variable stays
    /// unresolved.
    pub fn without_stun(ipv4: Option<IpAddr>, ipv6: Option<IpAddr>) -> Self {
        Self {
            ipv4,
            ipv6,
            stun: &|_, _| None,
        }
    }
}

/// Why a template could not be expanded this round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarError {
    /// The task did not fetch an address of this family this round.
    MissingFamily(Family),
    /// The STUN rule is unknown, disabled or has not pierced yet; the
    /// payload is the rule name as written.
    StunUnresolved(String),
}

impl std::fmt::Display for VarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VarError::MissingFamily(family) => {
                write!(f, "本轮没有取到 {family} 地址")
            }
            VarError::StunUnresolved(rule) => {
                write!(f, "STUN 规则 {rule:?} 未启用或尚未穿透成功")
            }
        }
    }
}

/// Expands `{…}` variables in a record value template.
pub fn expand_value(template: &str, ctx: &ValueCtx<'_>) -> Result<String, VarError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            // Unterminated braces stay literal.
            break;
        };
        let name = &rest[start + 1..start + end];
        out.push_str(&rest[..start]);
        out.push_str(&resolve_variable(name, ctx)?);
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Resolves one variable name (`ipv4Addr`, `ipv6Addr`,
/// `STUN_规则名_PORT|IP|ADDR`); unknown names stay literal.
pub fn resolve_variable(name: &str, ctx: &ValueCtx<'_>) -> Result<String, VarError> {
    match name {
        "ipv4Addr" => ctx
            .ipv4
            .map(|ip| ip.to_string())
            .ok_or(VarError::MissingFamily(Family::V4)),
        "ipv6Addr" => ctx
            .ipv6
            .map(|ip| ip.to_string())
            .ok_or(VarError::MissingFamily(Family::V6)),
        _ => {
            let Some(rule) = name.strip_prefix("STUN_") else {
                // Unknown variables stay literal, matching the upstream
                // behavior for user-defined text.
                let mut literal = String::with_capacity(name.len() + 2);
                literal.push('{');
                literal.push_str(name);
                literal.push('}');
                return Ok(literal);
            };
            let (rule, part) =
                split_stun(rule).ok_or_else(|| VarError::StunUnresolved(rule.to_owned()))?;
            (ctx.stun)(rule, part)
                .map(|value| value.to_string())
                .ok_or_else(|| VarError::StunUnresolved(rule.to_owned()))
        }
    }
}

/// Splits `规则名_PORT|IP|ADDR` into the rule and the part; the longest
/// suffix wins so rule names ending in "PORT" are not misparsed.
fn split_stun(rule: &str) -> Option<(&str, StunPart)> {
    for (suffix, part) in [
        ("_ADDR", StunPart::Addr),
        ("_PORT", StunPart::Port),
        ("_IP", StunPart::Ip),
    ] {
        if let Some(name) = rule.strip_suffix(suffix)
            && !name.is_empty()
        {
            return Some((name, part));
        }
    }
    None
}

/// Whether a template references any STUN variable (used to kick tasks
/// when a `stun.changed` event arrives).
pub fn references_stun(template: &str) -> bool {
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        if rest[start + 1..start + end].starts_with("STUN_") {
            return true;
        }
        rest = &rest[start + end + 1..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(ipv4: Option<&str>, ipv6: Option<&str>) -> ValueCtx<'static> {
        ValueCtx::without_stun(
            ipv4.map(|text| text.parse().expect("ip")),
            ipv6.map(|text| text.parse().expect("ip")),
        )
    }

    fn stun_ctx<'a>(
        ipv4: Option<IpAddr>,
        ipv6: Option<IpAddr>,
        lookup: &'a (dyn Fn(&str, StunPart) -> Option<StunValue> + Send + Sync),
    ) -> ValueCtx<'a> {
        ValueCtx {
            ipv4,
            ipv6,
            stun: lookup,
        }
    }

    #[test]
    fn value_expansion_ipv4_ipv6_default_for_a_aaaa() {
        let value = expand_value(
            "my ip is {ipv4Addr} and {ipv6Addr}",
            &ctx(Some("1.2.3.4"), Some("2001:db8::1")),
        )
        .expect("expand");
        assert_eq!(value, "my ip is 1.2.3.4 and 2001:db8::1");
        // Missing family is an explicit error, not an empty string.
        assert_eq!(
            expand_value("{ipv6Addr}", &ctx(Some("1.2.3.4"), None)),
            Err(VarError::MissingFamily(Family::V6))
        );
        // Unknown or unterminated braces stay literal.
        assert_eq!(
            expand_value("{nope}", &ctx(None, None)),
            Ok("{nope}".into())
        );
        assert_eq!(
            expand_value("{ipv4Addr", &ctx(None, None)),
            Ok("{ipv4Addr".into())
        );
    }

    #[test]
    fn value_expansion_stun_variables() {
        let lookup = |rule: &str, part: StunPart| match (rule, part) {
            ("视频线", StunPart::Port) => Some(StunValue::Port(4500)),
            ("video", StunPart::Ip) => Some(StunValue::Ip("9.9.9.9".parse().expect("ip"))),
            ("video", StunPart::Addr) => Some(StunValue::Addr("9.9.9.9:4500".into())),
            _ => None,
        };
        let value = stun_ctx(None, None, &lookup);
        assert_eq!(
            expand_value("{STUN_视频线_PORT}", &value),
            Ok("4500".into()),
            "rule names may contain non-ASCII and are matched by name"
        );
        assert_eq!(
            expand_value("{STUN_video_ADDR}", &value),
            Ok("9.9.9.9:4500".into())
        );
        assert_eq!(
            expand_value("{STUN_video_IP}", &value),
            Ok("9.9.9.9".into())
        );
        // Unknown rule reports the reason used for the skip status.
        assert_eq!(
            expand_value("{STUN_ghost_IP}", &value),
            Err(VarError::StunUnresolved("ghost".into()))
        );
        // No STUN support at all: the variables stay unresolved.
        assert!(matches!(
            expand_value("{STUN_video_PORT}", &ctx(None, None)),
            Err(VarError::StunUnresolved(_))
        ));
        // Combined template.
        assert_eq!(
            expand_value(
                "{STUN_video_ADDR}|{ipv4Addr}",
                &stun_ctx(Some("1.2.3.4".parse().expect("ip")), None, &lookup)
            ),
            Ok("9.9.9.9:4500|1.2.3.4".into())
        );
    }

    #[test]
    fn stun_suffix_longest_match_and_detection() {
        assert_eq!(split_stun("a.b_PORT"), Some(("a.b", StunPart::Port)));
        assert_eq!(split_stun("a_PORT_ADDR"), Some(("a_PORT", StunPart::Addr)));
        assert_eq!(split_stun("_IP"), None, "empty rule name is rejected");
        assert!(references_stun("{STUN_x_PORT}"));
        assert!(references_stun("x {STUN_y_ADDR} z"));
        assert!(!references_stun("{ipv4Addr}"));
        assert!(!references_stun("{STUN_broken"));
    }
}
