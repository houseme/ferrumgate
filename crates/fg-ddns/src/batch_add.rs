//! Batch record add (WP-40 §3.3): the pure parser behind the task editor's
//! batch-add dialog. One line per input:
//!
//! ```text
//! emby                              # hostname under the default zone
//! home.example.com                  # full domain (split against the default zone)
//! nas.example.com A                 # explicit type, default value variable
//! v6.example.com AAAA 2001:db8::1   # explicit type and value
//! shop.example.com.cn               # multi-level public suffix
//! https://my.example.com:8443/path  # pasted URLs, ports and paths are cleaned
//! ```
//!
//! Lines missing a type produce one record per checked type (A / AAAA with
//! the matching default variable); a bare IP value infers the type.
//! Duplicates against the existing records (and within the input) are
//! skipped; invalid lines are reported by line number and block the add.
//!
//! The public suffix table is a small static list of common multi-level
//! suffixes — a heuristic, not the full PSL: the UI shows the split
//! result for confirmation before anything is saved.

use crate::model::{Record, RecordType, limits};

/// Inputs shared by every line of one batch.
pub struct BatchOptions<'a> {
    /// Hostname-only lines hang below this zone; also the first split
    /// candidate. Empty when the task has no default zone yet.
    pub default_zone: String,
    /// Existing records of the task: their zones are split candidates and
    /// duplicates against them are skipped.
    pub existing: &'a [Record],
    /// The types checked in the dialog (only A / AAAA are meaningful);
    /// used for lines without an explicit type.
    pub types: &'a [RecordType],
    pub ttl: u32,
    pub line: String,
    pub remark: String,
    pub group: String,
}

/// One invalid line, reported by number (1-based, comments included).
#[derive(Debug, PartialEq, Eq)]
pub struct LineError {
    pub line: usize,
    pub reason: String,
}

/// Common multi-level public suffixes (static heuristic subset).
const MULTI_SUFFIXES: &[&str] = &[
    "com.cn", "net.cn", "org.cn", "gov.cn", "ac.cn", "edu.cn", "co.uk", "org.uk", "me.uk", "ac.uk",
    "com.au", "net.au", "org.au", "com.tw", "com.hk", "com.sg", "com.my", "co.jp", "ne.jp",
    "or.jp", "co.kr", "co.in", "co.nz", "com.br", "com.mx", "com.tr", "com.ar",
];

/// Parses the batch text; `Ok(records)` when every line is valid,
/// `Err(errors)` listing every invalid line by number otherwise.
pub fn parse_batch(opts: &BatchOptions<'_>, text: &str) -> Result<Vec<Record>, Vec<LineError>> {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut seen = existing_keys(opts.existing);
    let default_zone = opts.default_zone.trim().to_ascii_lowercase();
    let known_zones: Vec<String> = {
        let mut zones: Vec<String> = opts
            .existing
            .iter()
            .map(|record| record.zone.trim().to_ascii_lowercase())
            .filter(|zone| !zone.is_empty())
            .collect();
        zones.sort();
        zones.dedup();
        zones
    };
    let checked: Vec<RecordType> = opts
        .types
        .iter()
        .copied()
        .filter(|typ| matches!(typ, RecordType::A | RecordType::AAAA))
        .collect();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_line(trimmed, &default_zone, &known_zones, &checked, opts) {
            Ok(entries) => {
                for entry in entries {
                    let identity = (entry.zone.clone(), entry.sub.clone(), entry.typ);
                    if seen.contains(&identity) {
                        continue; // duplicate: skipped silently
                    }
                    seen.push(identity);
                    records.push(entry);
                }
            }
            Err(reason) => errors.push(LineError {
                line: number,
                reason,
            }),
        }
    }
    if records.len() > limits::BATCH_LINES_MAX {
        errors.push(LineError {
            line: 0,
            reason: format!("一次最多添加 {} 条记录", limits::BATCH_LINES_MAX),
        });
    }
    if errors.is_empty() {
        Ok(records)
    } else {
        Err(errors)
    }
}

/// Record identity for duplicate detection (zone + owner + type).
type Identity = (String, String, RecordType);

fn existing_keys(existing: &[Record]) -> Vec<Identity> {
    existing
        .iter()
        .map(|record| {
            (
                record.zone.to_ascii_lowercase(),
                record.sub.to_ascii_lowercase(),
                record.typ,
            )
        })
        .collect()
}

fn parse_line(
    raw: &str,
    default_zone: &str,
    known_zones: &[String],
    checked: &[RecordType],
    opts: &BatchOptions<'_>,
) -> Result<Vec<Record>, String> {
    let mut parts = raw.split_whitespace();
    let Some(domain_token) = parts.next() else {
        return Err("域名不能为空".to_owned());
    };
    let domain = clean_domain(domain_token)?;
    let mut typ: Option<RecordType> = None;
    let mut value: Option<String> = None;
    if let Some(second) = parts.next() {
        if let Some(parsed) = RecordType::parse(second) {
            if !matches!(parsed, RecordType::A | RecordType::AAAA) {
                return Err(format!("批量添加只支持 A / AAAA，收到 {second}"));
            }
            typ = Some(parsed);
            if let Some(third) = parts.next() {
                value = Some(third.to_owned());
                if parts.next().is_some() {
                    return Err("一行最多为「域名 类型 记录值」三段".to_owned());
                }
            }
        } else if let Ok(ip) = second.parse::<std::net::IpAddr>() {
            // A bare IP value infers the type.
            typ = Some(match ip {
                std::net::IpAddr::V4(_) => RecordType::A,
                std::net::IpAddr::V6(_) => RecordType::AAAA,
            });
            value = Some(ip.to_string());
            if parts.next().is_some() {
                return Err("一行最多为「域名 记录值」两段".to_owned());
            }
        } else {
            return Err(format!("类型无法识别：{second}"));
        }
    }
    let (sub, zone) = split_domain(&domain, default_zone, known_zones)?;
    match typ {
        Some(typ) => {
            let value = match value {
                Some(value) => value,
                None => default_value(typ).to_owned(),
            };
            Ok(vec![make_record(opts, &zone, &sub, typ, &value)])
        }
        None => {
            if checked.is_empty() {
                return Err("未勾选任何记录类型".to_owned());
            }
            Ok(checked
                .iter()
                .map(|typ| make_record(opts, &zone, &sub, *typ, default_value(*typ)))
                .collect())
        }
    }
}

fn default_value(typ: RecordType) -> &'static str {
    match typ {
        RecordType::AAAA => "{ipv6Addr}",
        _ => "{ipv4Addr}",
    }
}

fn make_record(
    opts: &BatchOptions<'_>,
    zone: &str,
    sub: &str,
    typ: RecordType,
    value: &str,
) -> Record {
    Record {
        key: crate::model::new_key(),
        enable: true,
        zone: zone.to_owned(),
        sub: sub.to_owned(),
        typ,
        value: value.to_owned(),
        ttl: opts.ttl,
        line: opts.line.clone(),
        remark: opts.remark.clone(),
        group: opts.group.clone(),
    }
}

/// Strips a pasted scheme, userinfo, port and path from a domain token.
/// IPv6 literals (no dot, or bracketed) are kept intact.
fn clean_domain(token: &str) -> Result<String, String> {
    let mut domain = token.trim().to_owned();
    if let Some(rest) = domain
        .strip_prefix("https://")
        .or_else(|| domain.strip_prefix("http://"))
    {
        domain = rest.to_owned();
    }
    if let Some(at) = domain.find(['/', '?', '#']) {
        domain.truncate(at);
    }
    if let Some(start) = domain.find('@') {
        // userinfo@
        domain = domain[start + 1..].to_owned();
    }
    if domain.starts_with('[') {
        if let Some(end) = domain.find(']') {
            domain = domain[1..end].to_owned();
        }
    } else if domain.contains(':') && domain.contains('.') {
        // Hostname with a port (an IPv6 literal never contains a dot).
        if let Some(colon) = domain.rfind(':') {
            let port = &domain[colon + 1..];
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
                domain.truncate(colon);
            }
        }
    }
    if domain.is_empty() {
        return Err("域名不能为空".to_owned());
    }
    if domain.contains(char::is_whitespace) || domain.contains('/') {
        return Err(format!("域名无效：{token}"));
    }
    Ok(domain.to_ascii_lowercase())
}

/// Splits a domain into (owner, zone): the default zone wins, then the
/// zones already present in the task, then the static public suffix
/// table, then the last two labels.
fn split_domain(
    domain: &str,
    default_zone: &str,
    known_zones: &[String],
) -> Result<(String, String), String> {
    if !domain.contains('.') {
        if default_zone.is_empty() {
            return Err(format!("仅主机记录 {domain:?} 需要先填写默认主域名"));
        }
        return Ok((domain.to_owned(), default_zone.to_owned()));
    }
    if let Some(sub) = strip_zone_suffix(domain, default_zone) {
        return Ok((sub.to_owned(), default_zone.to_owned()));
    }
    let mut zones: Vec<&str> = known_zones.iter().map(String::as_str).collect();
    zones.sort_by_key(|zone| std::cmp::Reverse(zone.len()));
    for zone in zones {
        if let Some(sub) = strip_zone_suffix(domain, zone) {
            return Ok((sub.to_owned(), zone.to_owned()));
        }
    }
    let (sub, zone) = split_public_suffix(domain)?;
    Ok((sub.to_owned(), zone))
}

fn strip_zone_suffix<'a>(domain: &'a str, zone: &str) -> Option<&'a str> {
    let zone = zone.trim_end_matches('.');
    if zone.is_empty() {
        return None;
    }
    if domain == zone {
        return Some("@");
    }
    domain.strip_suffix(zone).and_then(|rest| {
        let rest = rest.strip_suffix('.')?;
        if rest.is_empty() {
            Some("@")
        } else {
            Some(rest)
        }
    })
}

fn split_public_suffix(domain: &str) -> Result<(String, String), String> {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return Err(format!("域名无效：{domain}"));
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let suffix_len = if MULTI_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };
    if labels.len() < suffix_len {
        return Err(format!("域名缺少主机记录：{domain}"));
    }
    let zone_start = labels.len() - suffix_len;
    let zone = labels[zone_start..].join(".");
    let sub = if zone_start == 0 {
        "@".to_owned()
    } else {
        labels[..zone_start].join(".")
    };
    Ok((sub, zone))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts<'a>(
        default_zone: &str,
        existing: &'a [Record],
        types: &'a [RecordType],
    ) -> BatchOptions<'a> {
        BatchOptions {
            default_zone: default_zone.into(),
            existing,
            types,
            ttl: 600,
            line: "默认".into(),
            remark: "批量".into(),
            group: "batch".into(),
        }
    }

    fn record(zone: &str, sub: &str, typ: RecordType) -> Record {
        Record {
            key: format!("k-{zone}-{sub}-{}", typ.as_str()),
            zone: zone.into(),
            sub: sub.into(),
            typ,
            ..Record::default()
        }
    }

    #[test]
    fn batch_add_parses_examples() {
        let types = [RecordType::A, RecordType::AAAA];
        let text = "emby\nhome.example.com\nnas.example.com A\nv6.example.com AAAA 2001:db8::1\nshop.example.com.cn\n# comment\n\nhttps://my.example.com:8443/path";
        let records = parse_batch(&opts("example.com", &[], &types), text).expect("valid");
        let described: Vec<String> = records
            .iter()
            .map(|r| format!("{} {} {} {}", r.zone, r.sub, r.typ.as_str(), r.value))
            .collect();
        assert_eq!(
            described,
            [
                "example.com emby A {ipv4Addr}",
                "example.com emby AAAA {ipv6Addr}",
                "example.com home A {ipv4Addr}",
                "example.com home AAAA {ipv6Addr}",
                "example.com nas A {ipv4Addr}",
                "example.com v6 AAAA 2001:db8::1",
                // Multi-level public suffix heuristic.
                "example.com.cn shop A {ipv4Addr}",
                "example.com.cn shop AAAA {ipv6Addr}",
                "example.com my A {ipv4Addr}",
                "example.com my AAAA {ipv6Addr}",
            ],
            "{described:?}"
        );
        // Shared options apply to every record of the batch.
        assert_eq!(records[0].ttl, 600);
        assert_eq!(records[0].line, "默认");
        assert_eq!(records[0].group, "batch");
        // Every generated record carries a fresh key.
        let mut keys: Vec<_> = records.iter().map(|r| r.key.as_str()).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), records.len());
    }

    #[test]
    fn batch_add_reports_invalid_lines_by_number() {
        let types = [RecordType::A, RecordType::AAAA];
        let text = "ok.example.com\nbadspace .com\nx.example.com CNAME\nonlyhost\ny.example.com A 1.2.3.4 extra";
        let errors = parse_batch(&opts("", &[], &types), text).expect_err("invalid");
        let numbers: Vec<usize> = errors.iter().map(|error| error.line).collect();
        assert_eq!(numbers, [2, 3, 4, 5], "{errors:?}");
        assert!(errors[1].reason.contains("CNAME"), "{errors:?}");
        assert!(errors[2].reason.contains("默认主域名"), "{errors:?}");
        assert!(errors[3].reason.contains("三段"), "{errors:?}");
    }

    #[test]
    fn batch_add_skips_duplicates() {
        let types = [RecordType::A];
        let existing = vec![record("example.com", "home", RecordType::A)];
        let text = "home.example.com\nhome.example.com\nfresh.example.com\nfresh.example.com A";
        let records = parse_batch(&opts("example.com", &existing, &types), text).expect("valid");
        let subs: Vec<&str> = records.iter().map(|record| record.sub.as_str()).collect();
        assert_eq!(
            subs,
            ["fresh"],
            "existing and in-batch duplicates are skipped: {subs:?}"
        );
    }

    #[test]
    fn batch_add_infers_type_from_ip_value() {
        let types = [RecordType::A];
        let records = parse_batch(
            &opts("example.com", &[], &types),
            "a.example.com 9.9.9.9\nb.example.com 2001:db8::9",
        )
        .expect("valid");
        assert_eq!(records[0].typ, RecordType::A);
        assert_eq!(records[0].value, "9.9.9.9");
        assert_eq!(
            records[1].typ,
            RecordType::AAAA,
            "the type is inferred from the address"
        );
    }

    #[test]
    fn batch_add_uses_existing_zones_before_suffix_table() {
        let types = [RecordType::A];
        let existing = vec![record("myhost.example.org", "@", RecordType::A)];
        let records = parse_batch(
            &opts("default.example", &existing, &types),
            "sub.myhost.example.org",
        )
        .expect("valid");
        assert_eq!(records[0].zone, "myhost.example.org");
        assert_eq!(records[0].sub, "sub");
    }

    #[test]
    fn batch_add_requires_a_checked_type_for_bare_hostnames() {
        let records = parse_batch(&opts("example.com", &[], &[]), "emby");
        assert!(
            records.is_err(),
            "no checked type: bare hostnames cannot expand"
        );
        // Full domains with explicit types still parse.
        let records = parse_batch(&opts("example.com", &[], &[]), "a.example.com A")
            .expect("explicit type needs no checked list");
        assert_eq!(records[0].typ, RecordType::A);
    }
}
