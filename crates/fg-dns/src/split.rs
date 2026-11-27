//! 记录值拆分的通用逻辑（上游 split.go）。
//!
//! `split_fqdn` 把完整域名拆成主机记录与主域名：支持 `sub:example.com`
//! 显式写法；默认取最后两段，内置表中的多级公共后缀取最后三段。完整的
//! 公共后缀表过大，这里只覆盖国内外常用后缀；无法正确拆分时（未收录的
//! ICANN 多级后缀），可在配置中显式指定主域名。私有后缀（如 dynv6.net、
//! github.io）保持取最后两段，用户可能拥有的是其父域名下的主域名。

/// 常见的多级公共后缀（上游内置表 + 常见 ICANN 多级后缀）。
pub const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "ac.cn", "co.id", "co.in", "co.jp", "co.kr", "co.nz", "co.th", "co.uk", "co.za", "com.ar",
    "com.au", "com.br", "com.cn", "com.hk", "com.mo", "com.mx", "com.my", "com.sg", "com.tr",
    "com.tw", "cn.com", "edu.cn", "eu.org", "gov.br", "gov.cn", "ne.jp", "net.au", "net.cn",
    "or.jp", "org.br", "org.cn", "org.uk", "uk.com", "us.com", "us.org",
];

/// 把完整域名拆成主机记录与主域名；主域名本身返回主机记录 "@"。
pub fn split_fqdn(full: &str) -> (String, String) {
    let trimmed = full.trim().trim_matches('.').to_ascii_lowercase();
    if let Some((sub, zone)) = trimmed.split_once(':') {
        return (sub.to_owned(), zone.to_owned());
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    let n = if labels.len() >= 3
        && MULTI_LABEL_SUFFIXES.contains(&labels[labels.len() - 2..].join(".").as_str())
    {
        3
    } else {
        2
    };
    if labels.len() <= n {
        return ("@".to_owned(), trimmed);
    }
    (
        labels[..labels.len() - n].join("."),
        labels[labels.len() - n..].join("."),
    )
}

/// 返回 fqdn 在给定主域名下的主机记录；fqdn 不属于该主域名时返回 None。
pub fn sub_for_zone(fqdn: &str, zone: &str) -> Option<String> {
    let fqdn = fqdn.trim().trim_matches('.').to_ascii_lowercase();
    let zone = zone.trim().trim_matches('.').to_ascii_lowercase();
    if fqdn == zone {
        return Some("@".to_owned());
    }
    fqdn.strip_suffix(&format!(".{zone}")).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_fqdn_basic_cases() {
        let cases = [
            ("example.com", "@", "example.com"),
            ("a.b.example.com", "a.b", "example.com"),
            ("*.Example.com.", "*", "example.com"),
            ("x:sub.example.co.uk", "x", "sub.example.co.uk"),
            (
                "_acme-challenge.a.example.co.uk",
                "_acme-challenge.a",
                "example.co.uk",
            ),
        ];
        for (input, want_sub, want_zone) in cases {
            assert_eq!(
                split_fqdn(input),
                (want_sub.to_owned(), want_zone.to_owned()),
                "{input}"
            );
        }
    }

    #[test]
    fn split_fqdn_multilabel_suffix_table() {
        assert_eq!(
            split_fqdn("www.example.com.cn"),
            ("www".to_owned(), "example.com.cn".to_owned())
        );
        assert_eq!(
            split_fqdn("example.com.cn"),
            ("@".to_owned(), "example.com.cn".to_owned())
        );
        assert_eq!(
            split_fqdn("a.b.example.or.jp"),
            ("a.b".to_owned(), "example.or.jp".to_owned())
        );
    }

    #[test]
    fn split_fqdn_extended_table_covers_common_icann_suffixes() {
        assert_eq!(
            split_fqdn("www.example.com.ar"),
            ("www".to_owned(), "example.com.ar".to_owned())
        );
        assert_eq!(
            split_fqdn("a.b.example.org.br"),
            ("a.b".to_owned(), "example.org.br".to_owned())
        );
        assert_eq!(
            split_fqdn("nas.example.gov.br"),
            ("nas".to_owned(), "example.gov.br".to_owned())
        );
    }

    #[test]
    fn split_fqdn_private_suffix_keeps_two_labels() {
        assert_eq!(
            split_fqdn("x.my.dynv6.net"),
            ("x.my".to_owned(), "dynv6.net".to_owned())
        );
    }

    #[test]
    fn split_fqdn_unknown_tld_keeps_two_labels() {
        assert_eq!(
            split_fqdn("host.lan"),
            ("@".to_owned(), "host.lan".to_owned())
        );
    }

    #[test]
    fn sub_for_zone_matches_suffix() {
        assert_eq!(
            sub_for_zone("_acme-challenge.www.example.com.", "example.com"),
            Some("_acme-challenge.www".to_owned())
        );
        assert_eq!(
            sub_for_zone("example.com", "example.com"),
            Some("@".to_owned())
        );
        assert_eq!(sub_for_zone("a.other.com", "example.com"), None);
    }
}
