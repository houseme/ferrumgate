//! Domain rules for the web service model (WP-20 step 1): the five
//! pattern forms, their normalization and host matching with wildcard
//! capture. The legacy string-based matcher in `crate::domains` keeps
//! serving the TOML path until WP-39.

use std::net::IpAddr;

/// A domain rule. At most one `*` per rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// An exact hostname or IP literal.
    Exact(String),
    /// `*` alone: matches everything.
    Any,
    /// `*.example.com`: one or more leading subdomain labels.
    WildcardSubdomain { suffix: String },
    /// `api-*.example.com`: the `*` sits inside one label; `before` and
    /// `after` are the fixed parts around it within that label.
    InLabel {
        before: String,
        after: String,
        suffix: String,
    },
    /// `audiobook.*.example.com`: the `*` is exactly one middle label.
    MiddleLabel {
        prefix: Vec<String>,
        suffix: Vec<String>,
    },
    /// `audiobook.*`: everything after the fixed prefix labels.
    TrailingLabels { prefix: Vec<String> },
}

#[derive(Debug, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    TooLong,
    MultipleWildcards,
    /// A lone `*` must stand for a whole label.
    PartialWildLabel,
    /// The wildcarded result would not be a valid label (leading/trailing
    /// `-` after substitution).
    InvalidWildLabel,
    /// Wildcards combined with IP-looking fixed parts (`api-*.1.2.3.4`,
    /// `192.168.1.*`): wildcards only apply to hostnames.
    IpWildcard,
    /// A label is empty or has invalid characters.
    InvalidLabel(String),
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "域名为空"),
            Self::TooLong => write!(f, "域名超过 253 个字符"),
            Self::MultipleWildcards => write!(f, "一条域名规则最多一个 *"),
            Self::PartialWildLabel => write!(f, "* 必须占据整个标签"),
            Self::InvalidWildLabel => write!(f, "通配标签不是合法的域名标签"),
            Self::IpWildcard => write!(f, "通配不能与 IP 地址混用"),
            Self::InvalidLabel(label) => write!(f, "标签 {label:?} 含非法字符"),
        }
    }
}

impl std::error::Error for PatternError {}

const MAX_LEN: usize = 253;

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn looks_like_ip(labels: &[&str]) -> bool {
    !labels.is_empty()
        && labels.iter().all(|label| {
            label
                .split('.')
                .all(|part| part.bytes().all(|b| b.is_ascii_digit()))
        })
        && labels
            .last()
            .and_then(|last| last.split('.').next_back())
            .is_some_and(|last| last.parse::<u8>().is_ok())
}

fn split_labels(host: &str) -> Vec<&str> {
    host.split('.').collect()
}

/// Normalizes a domain rule: lowercase, trailing dots stripped, the single
/// wildcard classified into one of the five forms.
pub fn normalize_pattern(input: &str) -> Result<Pattern, PatternError> {
    let trimmed = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(PatternError::Empty);
    }
    if trimmed.len() > MAX_LEN {
        return Err(PatternError::TooLong);
    }
    let wildcard_count = trimmed.matches('*').count();
    if wildcard_count == 0 {
        if trimmed.parse::<IpAddr>().is_ok() || looks_like_ip(&split_labels(&trimmed)) {
            return Ok(Pattern::Exact(trimmed));
        }
        for label in split_labels(&trimmed) {
            if !valid_label(label) {
                return Err(PatternError::InvalidLabel(label.to_string()));
            }
        }
        return Ok(Pattern::Exact(trimmed));
    }
    if wildcard_count > 1 {
        return Err(PatternError::MultipleWildcards);
    }
    if trimmed == "*" {
        return Ok(Pattern::Any);
    }
    let labels = split_labels(&trimmed);
    let wildcard_label = labels.iter().position(|label| label.contains('*'));
    let Some(position) = wildcard_label else {
        return Err(PatternError::PartialWildLabel);
    };
    for (index, label) in labels.iter().enumerate() {
        if index == position {
            continue;
        }
        if !valid_label(label) {
            return Err(PatternError::InvalidLabel(label.to_string()));
        }
    }
    let owned = |labels: &[&str]| labels.iter().map(|label| label.to_string()).collect();
    let wildcard = labels[position];
    if wildcard != "*" {
        // The wildcard sits inside one label: the label must become valid
        // when the wildcard is replaced by an alphanumeric character, and
        // the fixed parts must not form an IP.
        let (before, after) = wildcard.split_once('*').unwrap_or(("", ""));
        let check = format!("{before}x{after}");
        if !valid_label(&check) {
            return Err(PatternError::InvalidWildLabel);
        }
        if looks_like_ip(&labels[position + 1..]) {
            return Err(PatternError::IpWildcard);
        }
        let mut all = labels.clone();
        all[position] = &check;
        if looks_like_ip(&all) {
            return Err(PatternError::IpWildcard);
        }
        return Ok(Pattern::InLabel {
            before: before.to_owned(),
            after: after.to_owned(),
            suffix: labels[position + 1..].join("."),
        });
    }
    let fixed: Vec<&str> = labels
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != position)
        .map(|(_, label)| *label)
        .collect();
    if looks_like_ip(&fixed) {
        return Err(PatternError::IpWildcard);
    }
    match position {
        0 => Ok(Pattern::WildcardSubdomain {
            suffix: labels[1..].join("."),
        }),
        index if index + 1 == labels.len() => Ok(Pattern::TrailingLabels {
            prefix: owned(&labels[..index]),
        }),
        _ => Ok(Pattern::MiddleLabel {
            prefix: owned(&labels[..position]),
            suffix: owned(&labels[position + 1..]),
        }),
    }
}

/// Matches a host against the pattern, returning the `*` capture (the
/// text the wildcard consumed) for redirect variables.
pub fn capture(pattern: &Pattern, host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    match pattern {
        Pattern::Exact(exact) => (exact == &host).then_some(host.clone()),
        Pattern::Any => Some(host),
        Pattern::WildcardSubdomain { suffix } => {
            let dotted = format!(".{suffix}");
            host.strip_suffix(&dotted)
                .filter(|prefix| !prefix.is_empty())
                .map(str::to_owned)
        }
        Pattern::InLabel {
            before,
            after,
            suffix,
        } => {
            let host_label: &str = if suffix.is_empty() {
                &host
            } else {
                let dotted = format!(".{suffix}");
                host.strip_suffix(&dotted).unwrap_or(&host)
            };
            host_label
                .strip_prefix(before)
                .and_then(|rest| rest.strip_suffix(after))
                .filter(|capture| {
                    !capture.contains('.') && valid_label(&format!("{before}{capture}{after}"))
                })
                .map(str::to_owned)
        }
        Pattern::MiddleLabel { prefix, suffix } => {
            let joined_prefix = prefix.join(".");
            let joined_suffix = suffix.join(".");
            let prefix_labels = split_labels(&joined_prefix);
            let suffix_labels = split_labels(&joined_suffix);
            let host_labels = split_labels(&host);
            if host_labels.len() != prefix_labels.len() + suffix_labels.len() + 1 {
                return None;
            }
            let (before, middle, after) = (
                &host_labels[..prefix_labels.len()],
                host_labels[prefix_labels.len()],
                &host_labels[prefix_labels.len() + 1..],
            );
            let before_matches = before.len() == prefix_labels.len()
                && before
                    .iter()
                    .zip(prefix_labels.iter())
                    .all(|(host, prefix)| host == prefix);
            let after_matches = after.len() == suffix_labels.len()
                && after
                    .iter()
                    .zip(suffix_labels.iter())
                    .all(|(host, suffix)| host == suffix);
            (before_matches && after_matches).then(|| middle.to_owned())
        }
        Pattern::TrailingLabels { prefix } => {
            let joined_prefix = prefix.join(".");
            let prefix_labels = split_labels(&joined_prefix);
            let host_labels = split_labels(&host);
            (host_labels.len() > prefix_labels.len()
                && host_labels[..prefix_labels.len()]
                    .iter()
                    .zip(prefix_labels.iter())
                    .all(|(host, prefix)| host == prefix))
            .then(|| host_labels[prefix_labels.len()..].join("."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_five_forms() {
        assert_eq!(
            normalize_pattern("Example.COM."),
            Ok(Pattern::Exact("example.com".into()))
        );
        assert_eq!(normalize_pattern("*"), Ok(Pattern::Any));
        assert_eq!(
            normalize_pattern("*.Example.COM"),
            Ok(Pattern::WildcardSubdomain {
                suffix: "example.com".into()
            })
        );
        assert_eq!(
            normalize_pattern("api-*.example.com"),
            Ok(Pattern::InLabel {
                before: "api-".into(),
                after: String::new(),
                suffix: "example.com".into()
            })
        );
        assert_eq!(
            normalize_pattern("audiobook.*.example.com"),
            Ok(Pattern::MiddleLabel {
                prefix: vec!["audiobook".into()],
                suffix: vec!["example".into(), "com".into()]
            })
        );
        assert_eq!(
            normalize_pattern("audiobook.*"),
            Ok(Pattern::TrailingLabels {
                prefix: vec!["audiobook".into()]
            })
        );
        assert_eq!(
            normalize_pattern("192.168.1.5"),
            Ok(Pattern::Exact("192.168.1.5".into()))
        );
    }

    #[test]
    fn rejects_invalid_patterns() {
        for (input, expected) in [
            ("", PatternError::Empty),
            ("a..b", PatternError::InvalidLabel("".into())),
            ("*a*b.example.com", PatternError::MultipleWildcards),
            ("api-*x*.example.com", PatternError::MultipleWildcards),
            ("-*", PatternError::InvalidWildLabel),
            ("a*-", PatternError::InvalidWildLabel),
            ("api-*.1.2.3.4", PatternError::IpWildcard),
            ("192.168.1.*", PatternError::IpWildcard),
            ("10.*", PatternError::IpWildcard),
            (
                "exa mple.com",
                PatternError::InvalidLabel("exa mple".into()),
            ),
        ] {
            assert_eq!(normalize_pattern(input).unwrap_err(), expected, "{input}");
        }
    }

    #[test]
    fn capture_matches_and_extracts_the_wildcard() {
        let subdomain = normalize_pattern("*.example.com").unwrap();
        assert_eq!(capture(&subdomain, "a.example.com"), Some("a".into()));
        assert_eq!(
            capture(&subdomain, "a.b.example.com"),
            Some("a.b".into()),
            "one or more labels"
        );
        assert_eq!(capture(&subdomain, "example.com"), None);
        assert_eq!(capture(&subdomain, "aexample.com"), None);

        let in_label = normalize_pattern("api-*.example.com").unwrap();
        assert_eq!(capture(&in_label, "api-1.example.com"), Some("1".into()));
        assert_eq!(capture(&in_label, "api-a.b.example.com"), None);
        assert_eq!(capture(&in_label, "api-.example.com"), None);

        let middle = normalize_pattern("audiobook.*.example.com").unwrap();
        assert_eq!(
            capture(&middle, "audiobook.fr.example.com"),
            Some("fr".into())
        );
        assert_eq!(capture(&middle, "audiobook.example.com"), None);

        let trailing = normalize_pattern("audiobook.*").unwrap();
        assert_eq!(capture(&trailing, "audiobook.lan"), Some("lan".into()));
        assert_eq!(capture(&trailing, "audiobook.co.uk"), Some("co.uk".into()));

        let any = normalize_pattern("*").unwrap();
        assert_eq!(capture(&any, "anything.test"), Some("anything.test".into()));

        let exact = normalize_pattern("exact.test").unwrap();
        assert_eq!(capture(&exact, "exact.test"), Some("exact.test".into()));
        assert_eq!(capture(&exact, "other.test"), None);
    }
}
