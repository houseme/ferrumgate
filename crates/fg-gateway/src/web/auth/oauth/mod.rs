//! OAuth third-party login (WP-25): the signed state, the allow list
//! entries and identity matching. The three-stage flow (start, callback,
//! finish) wires in a later batch.
#![allow(dead_code)]

pub mod state;

pub use state::{sign_state, verify_state, OAuthState};

/// One configured provider. `key` doubles as the identity prefix
/// (`github:octocat`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthProvider {
    pub key: String,
    pub name: String,
    pub kind: ProviderKind,
    pub client_id: String,
    pub client_secret: String,
    pub issuer: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderKind {
    Github,
    Google,
    Qq,
    Oidc,
}

impl ProviderKind {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "github" => Some(Self::Github),
            "google" => Some(Self::Google),
            "qq" => Some(Self::Qq),
            "oidc" => Some(Self::Oidc),
            _ => None,
        }
    }
}

/// One allow-list entry: `provider:identity` with optional `# remark`.
/// `provider:*` allows any account of that provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowEntry {
    pub provider: String,
    pub identity: String,
    /// `*` = any account of the provider.
    pub wildcard: bool,
}

/// Parses one allow-list line; comments (`#`) and blanks are None.
pub fn parse_allow_entry(line: &str) -> Option<AllowEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // Everything after the first `#` is a remark.
    let body = line.split_once('#').map_or(line, |(body, _)| body).trim();
    let (provider, identity) = body.split_once(':')?;
    let (provider, identity) = (provider.trim(), identity.trim());
    if provider.is_empty() || identity.is_empty() {
        return None;
    }
    Some(AllowEntry {
        provider: provider.to_owned(),
        identity: identity.to_owned(),
        wildcard: identity == "*",
    })
}

/// Does the (provider, ids) pair satisfy any entry? Ids include every
/// alias of the account (GitHub numeric id, OIDC `sub`, email…).
/// Provider and identity compare case-insensitively.
pub fn identity_matches(allow: &[AllowEntry], provider: &str, ids: &[String]) -> bool {
    allow.iter().any(|entry| {
        entry.provider.eq_ignore_ascii_case(provider)
            && (entry.wildcard || ids.iter().any(|id| entry.identity.eq_ignore_ascii_case(id)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(line: &str) -> AllowEntry {
        parse_allow_entry(line).expect("valid allow entry")
    }

    fn allow_entry(provider: &str, identity: &str) -> AllowEntry {
        AllowEntry {
            provider: provider.to_owned(),
            identity: identity.to_owned(),
            wildcard: identity == "*",
        }
    }

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn allow_entry_parses_remarks_and_trims() {
        // 备注被剥离，无论 `#` 前有无空格。
        assert_eq!(
            entry("github:octocat # 我自己的账号"),
            AllowEntry {
                provider: "github".to_owned(),
                identity: "octocat".to_owned(),
                wildcard: false,
            }
        );
        assert_eq!(
            entry("google:me@gmail.com#inline remark"),
            AllowEntry {
                provider: "google".to_owned(),
                identity: "me@gmail.com".to_owned(),
                wildcard: false,
            }
        );
        // 普通行原样保留（首尾空白去掉）。
        assert_eq!(entry("google:me@gmail.com").identity, "me@gmail.com");
        // 提供方与标识各自 trim。
        assert_eq!(entry("  qq : openid_42  ").provider, "qq");
        assert_eq!(entry("  qq : openid_42  ").identity, "openid_42");
    }

    #[test]
    fn allow_entry_parses_wildcard() {
        let wildcard = entry("github:*");
        assert!(wildcard.wildcard);
        assert_eq!(wildcard.provider, "github");
        assert_eq!(wildcard.identity, "*");
        // 非通配行不误标。
        assert!(!entry("github:octocat").wildcard);
    }

    #[test]
    fn allow_entry_rejects_blank_comments_and_malformed() {
        // 空行与纯空白。
        assert_eq!(parse_allow_entry(""), None);
        assert_eq!(parse_allow_entry("   "), None);
        // 纯注释行（含缩进后的）。
        assert_eq!(parse_allow_entry("# 只是一段备注"), None);
        assert_eq!(parse_allow_entry("   # note"), None);
        // 无冒号。
        assert_eq!(parse_allow_entry("github-octocat"), None);
        assert_eq!(parse_allow_entry("github # no colon"), None);
        // 提供方或标识缺失（trim 后为空）。
        assert_eq!(parse_allow_entry("github:"), None);
        assert_eq!(parse_allow_entry("github:   # empty identity"), None);
        assert_eq!(parse_allow_entry(":octocat"), None);
        assert_eq!(parse_allow_entry(":"), None);
    }

    #[test]
    fn identity_matches_exact_and_alias() {
        let allow = [
            allow_entry("github", "octocat"),
            allow_entry("github", "12345"),
        ];
        // 精确命中。
        assert!(identity_matches(&allow, "github", &ids(&["octocat"])));
        // 别名（数字 ID）同样命中。
        assert!(identity_matches(&allow, "github", &ids(&["other-login", "12345"])));
        // 列表中的标识都不匹配。
        assert!(!identity_matches(&allow, "github", &ids(&["someone-else"])));
        // 没有任何标识。
        assert!(!identity_matches(&allow, "github", &[]));
    }

    #[test]
    fn identity_matches_wildcard_and_provider_gate() {
        let wildcard = [allow_entry("google", "*")];
        assert!(identity_matches(&wildcard, "google", &ids(&["anyone@gmail.com"])));
        // 通配也不跨提供方。
        assert!(!identity_matches(&wildcard, "github", &ids(&["anyone@gmail.com"])));

        // 精确条目对不同的提供方不命中，即使标识相同。
        let exact = [allow_entry("github", "octocat")];
        assert!(!identity_matches(&exact, "google", &ids(&["octocat"])));
        // 空允许列表不命中。
        assert!(!identity_matches(&[], "github", &ids(&["octocat"])));
    }

    #[test]
    fn identity_matches_case_insensitive() {
        let allow = [allow_entry("GitHub", "OctoCat")];
        assert!(identity_matches(&allow, "github", &ids(&["octocat"])));
        assert!(identity_matches(&allow, "GITHUB", &ids(&["OCTOCAT"])));
        assert!(identity_matches(&allow, "GitHub", &ids(&["OctoCat"])));
        // 大小写不同但拼写不同仍然不命中。
        assert!(!identity_matches(&allow, "github", &ids(&["octocat2"])));
        // 通配条目对任意大小写的提供方与标识都命中。
        let wildcard = [allow_entry("QQ", "*")];
        assert!(identity_matches(&wildcard, "qq", &ids(&["OpenID_42"])));
        assert!(identity_matches(&wildcard, "qq", &ids(&["openID_42"])));
    }
}
