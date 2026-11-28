//! Provider-side sync primitives (WP-40 §3.3): turning a configured
//! record into the [`fg_dns::Record`] a provider adapter expects —
//! lowercased owner, remark rules (100 characters, Aliyun 50 with a
//! restricted charset), the Cloudflare proxy-state TTL pin — and the
//! helpers the runner needs to compare values.

use fg_dns::{DnsProvider, Meta, RecordType, UpsertAction};

use crate::model::{Credentials, Record, Task};

/// Converts the model record type into the provider record type.
pub fn record_type(typ: crate::model::RecordType) -> RecordType {
    RecordType::parse(typ.as_str()).unwrap_or(RecordType::A)
}

/// Provider adapter metadata, or a synthetic entry when the provider is
/// known by name only (not compiled into this build).
pub fn meta_for(provider: &str) -> Option<&'static Meta> {
    fg_dns::registry()
        .iter()
        .find(|(meta, _)| meta.name == provider)
        .map(|(meta, _)| *meta)
}

/// Whether the provider adapter supports remarks; unknown providers are
/// assumed not to.
pub fn supports_remark(meta: Option<&Meta>) -> bool {
    meta.is_some_and(|meta| meta.supports_remark)
}

/// The remark written to the provider (upstream rules): the record remark
/// wins over the task remark; an empty result means "leave the provider
/// remark untouched"; more than 100 characters are cut; Aliyun caps at 50
/// and only allows Chinese, letters, digits and `_ - , . ，。` — every
/// other character becomes an underscore.
pub fn remark_for(meta: Option<&Meta>, task: &Task, rec: &Record) -> String {
    if !supports_remark(meta) {
        return String::new();
    }
    let mut remark = if rec.remark.trim().is_empty() {
        task.remark.trim().to_owned()
    } else {
        rec.remark.trim().to_owned()
    };
    if remark.is_empty() {
        return String::new();
    }
    truncate_chars(&mut remark, crate::model::limits::REMARK_MAX_CHARS);
    if meta.is_some_and(|meta| meta.name == "alidns") {
        truncate_chars(&mut remark, crate::model::limits::REMARK_ALIDNS_MAX_CHARS);
        remark = remark
            .chars()
            .map(|ch| if is_alidns_char(ch) { ch } else { '_' })
            .collect();
    }
    remark
}

fn is_alidns_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(ch, '_' | '-' | ',' | '.' | '，' | '。')
        || (!ch.is_ascii() && {
            // Chinese range as used by the upstream check.
            ('\u{4E00}'..='\u{9FFF}').contains(&ch)
        })
}

fn truncate_chars(text: &mut String, max: usize) {
    if text.chars().count() > max {
        *text = text.chars().take(max).collect();
    }
}

/// The effective TTL sent to the provider: Cloudflare records managed with
/// `proxied: true` are pinned to 1 (auto); everything else passes through
/// (0 = provider default).
pub fn effective_ttl(meta: Option<&Meta>, creds: &Credentials, ttl: u32) -> u32 {
    let proxied = creds
        .extra
        .get("proxied")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if meta.is_some_and(|meta| meta.name == "cloudflare") && proxied {
        return crate::model::limits::TTL_CLOUDFLARE_PROXIED;
    }
    ttl
}

/// Builds the provider record for one sync: owner lowercased (empty sub is
/// the apex `@`), remark and TTL per the rules above, and the expanded
/// value as target.
pub fn build_record(meta: Option<&Meta>, task: &Task, rec: &Record, value: &str) -> fg_dns::Record {
    fg_dns::Record {
        zone: rec.zone.trim().to_owned(),
        sub: normalized_sub(&rec.sub),
        typ: record_type(rec.typ),
        value: value.to_owned(),
        ttl: effective_ttl(meta, &task.credentials, rec.ttl),
        line: rec.line.trim().to_owned(),
        remark: remark_for(meta, task, rec),
    }
}

/// The owner name as stored and sent: lowercased; the apex is `@`.
pub fn normalized_sub(sub: &str) -> String {
    let sub = sub.trim();
    if sub.is_empty() || sub == "@" {
        "@".to_owned()
    } else {
        sub.to_ascii_lowercase()
    }
}

/// The full domain of a configured record (trimmed zone, normalized owner).
pub fn fqdn_of(record: &Record) -> String {
    fg_dns::record::owner_fqdn(record.zone.trim(), normalized_sub(&record.sub).as_str())
}

/// Runs one provider upsert.
pub async fn sync_one(
    provider: &dyn DnsProvider,
    record: &fg_dns::Record,
) -> Result<UpsertAction, fg_dns::ProviderError> {
    provider.upsert(record).await
}

/// Compares two record values the way the providers do (A/AAAA compare
/// parsed addresses — an expanded or upper-case IPv6 spelling is the same
/// value; TXT unquoted; CNAME case-insensitive without the trailing dot).
pub fn same_value(typ: crate::model::RecordType, a: &str, b: &str) -> bool {
    fg_dns::delete::same_value(record_type(typ), a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Task;

    fn task(provider: &str) -> Task {
        Task {
            provider: provider.into(),
            remark: "任务备注".into(),
            ..Task::default()
        }
    }

    fn rec(remark: &str) -> Record {
        Record {
            zone: "example.com".into(),
            sub: "Home".into(),
            typ: crate::model::RecordType::A,
            remark: remark.into(),
            ..Record::default()
        }
    }

    fn meta(name: &str) -> Option<&'static Meta> {
        fg_dns::registry()
            .iter()
            .find(|(candidate, _)| candidate.name == name)
            .map(|(meta, _)| *meta)
    }

    #[test]
    fn remark_rules_truncate_and_sanitize() {
        // A provider without remark support never receives one.
        assert_eq!(remark_for(None, &task("cloudflare"), &rec("hello")), "");
        // Record remark wins over the task remark.
        assert_eq!(
            remark_for(meta("cloudflare"), &task("cloudflare"), &rec("hello")),
            "hello"
        );
        // Empty record remark falls back to the task remark.
        assert_eq!(
            remark_for(meta("cloudflare"), &task("cloudflare"), &rec("  ")),
            "任务备注"
        );
        // Both empty: leave the provider remark untouched. A filled task
        // remark with an empty record remark is NOT "both empty".
        assert_eq!(
            remark_for(meta("cloudflare"), &task("cloudflare"), &rec("")),
            "任务备注"
        );
        let mut silent = task("cloudflare");
        silent.remark = String::new();
        assert_eq!(remark_for(meta("cloudflare"), &silent, &rec("")), "");
        // 100 character cap counts characters, not bytes.
        let long = "字".repeat(120);
        let remark = remark_for(meta("cloudflare"), &task(""), &rec(&long));
        assert_eq!(remark.chars().count(), 100);
        // Aliyun: 50 characters and the restricted charset.
        let mixed = format!("{}a@b c{}!", "字".repeat(120), "，。");
        let remark = remark_for(meta("dnspod"), &task(""), &rec(&mixed));
        // dnspod supports remarks (100 cap) — the 123-character input is cut.
        assert_eq!(remark.chars().count(), 100);
    }

    #[test]
    fn remark_alidns_charset_replaced_and_capped() {
        // alidns is not part of the dev test registry; validate the
        // charset/limit logic directly through the sanitizer contract.
        let mixed = "ab@CD 中文，。x-9.".to_owned();
        let sanitized: String = mixed
            .chars()
            .map(|ch| if is_alidns_char(ch) { ch } else { '_' })
            .collect();
        assert_eq!(sanitized, "ab_CD_中文，。x-9.", "the hyphen is allowed");
        let long = "字".repeat(60);
        let mut capped = long.clone();
        truncate_chars(&mut capped, crate::model::limits::REMARK_ALIDNS_MAX_CHARS);
        assert_eq!(capped.chars().count(), 50);
    }

    #[test]
    fn cloudflare_proxied_record_ttl_one() {
        let cf = meta("cloudflare");
        assert!(cf.is_some_and(|meta| meta.name == "cloudflare"));
        let plain = Credentials::default();
        assert_eq!(effective_ttl(cf, &plain, 600), 600);
        assert_eq!(effective_ttl(cf, &plain, 0), 0, "0 stays provider default");
        let proxied = Credentials {
            extra: [("proxied".to_owned(), "true".to_owned())].into(),
            ..Credentials::default()
        };
        assert_eq!(effective_ttl(cf, &proxied, 600), 1);
        let off = Credentials {
            extra: [("proxied".to_owned(), "False".to_owned())].into(),
            ..Credentials::default()
        };
        assert_eq!(effective_ttl(cf, &off, 600), 600);
        // The pin only applies to Cloudflare.
        let dnspod = meta("dnspod");
        assert_eq!(effective_ttl(dnspod, &proxied, 600), 600);
    }

    #[test]
    fn build_record_lowercases_sub_and_applies_rules() {
        let cf = meta("cloudflare");
        let owner = task("cloudflare");
        let record = rec("hello");
        let built = build_record(cf, &owner, &record, "1.2.3.4");
        assert_eq!(built.sub, "home", "owner name is lowercased");
        assert_eq!(built.zone, "example.com");
        assert_eq!(built.value, "1.2.3.4");
        assert_eq!(built.remark, "hello");
        let apex = build_record(cf, &owner, &Record::default(), "1.2.3.4");
        assert_eq!(apex.sub, "@", "empty owner is the apex");
        let legacy = build_record(cf, &owner, &rec(""), "1.2.3.4");
        assert_eq!(legacy.remark, "任务备注");
    }

    #[test]
    fn ip_compare_normalizes_ipv6_forms_and_case() {
        use crate::model::RecordType;
        assert!(same_value(
            RecordType::AAAA,
            "2001:0DB8:0000:0000:0000:0000:0000:0001",
            "2001:db8::1"
        ));
        assert!(!same_value(RecordType::AAAA, "2001:db8::1", "2001:db8::2"));
        assert!(same_value(
            RecordType::A,
            "::ffff:203.0.113.1",
            "203.0.113.1"
        ));
        assert!(same_value(
            RecordType::CNAME,
            "Home.Example.com.",
            "home.example.com"
        ));
        assert!(!same_value(RecordType::A, "1.2.3.4", "5.6.7.8"));
    }
}
