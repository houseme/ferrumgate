//! Tunnel token parsing (WP-46 §3.3, pure functions). A tunnel token is
//! base64-encoded JSON `{"a":account,"t":tunnelId,"s":secret}`; all four
//! base64 variants (standard / URL safe, with / without padding) are
//! accepted. The secret is never logged and never appears in an error.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};

/// The account / tunnel identifiers parsed from a token. The secret is
/// carried for the process environment only; `Debug` redacts it.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    pub account_tag: String,
    pub tunnel_id: String,
    pub secret: String,
}

impl std::fmt::Debug for TokenInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenInfo")
            .field("account_tag", &self.account_tag)
            .field("tunnel_id", &self.tunnel_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl TokenInfo {
    /// The target a tunnel CNAME record points at (upstream DNS sync).
    pub fn cname_target(&self) -> String {
        format!("{}.cfargotunnel.com", self.tunnel_id)
    }
}

/// Token parse failure. The message is static: neither the token nor its
/// secret is ever included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenError;

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("无法从隧道令牌解析账号与隧道 ID，请确认令牌完整")
    }
}

impl std::error::Error for TokenError {}

/// The token payload before validation; `s` may be empty (the account tag
/// and tunnel ID are what the module itself needs).
#[derive(Deserialize)]
struct RawToken {
    #[serde(default)]
    a: String,
    #[serde(default)]
    t: String,
    #[serde(default)]
    s: String,
}

/// Parses a tunnel token, accepting the four base64 variants in turn
/// (upstream `parseToken`). Surrounding whitespace is ignored.
pub fn parse_token(token: &str) -> Result<TokenInfo, TokenError> {
    let trimmed = token.trim();
    let raw = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .into_iter()
        .find_map(|engine| engine.decode(trimmed).ok())
        .ok_or(TokenError)?;
    let parsed: RawToken = serde_json::from_slice(&raw).map_err(|_| TokenError)?;
    if parsed.a.is_empty() || parsed.t.is_empty() {
        // Upstream only requires the account tag and tunnel ID; the secret
        // may be empty (the process would still fail auth downstream).
        return Err(TokenError);
    }
    Ok(TokenInfo {
        account_tag: parsed.a,
        tunnel_id: parsed.t,
        secret: parsed.s,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;

    const RAW_JSON: &str = r#"{"a":"acc","t":"5f0c-tid","s":"c2VjcmV0"}"#;

    #[test]
    fn parse_token_four_base64_variants() {
        let raw = RAW_JSON.as_bytes();
        let variants = [
            B64.encode(raw),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw),
            base64::engine::general_purpose::URL_SAFE.encode(raw),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        ];
        for variant in &variants {
            // Surrounding whitespace is tolerated (upstream trims).
            let info = parse_token(&format!(" {variant}\n")).expect("parses");
            assert_eq!(info.account_tag, "acc", "{variant}");
            assert_eq!(info.tunnel_id, "5f0c-tid");
            assert_eq!(info.secret, "c2VjcmV0");
            assert_eq!(info.cname_target(), "5f0c-tid.cfargotunnel.com");
        }
    }

    #[test]
    fn parse_token_malformed() {
        // 不是 JSON、缺字段、非法 base64。空密钥不算缺失（上游只要求 a/t）。
        let missing_tunnel = B64.encode(br#"{"a":"acc"}"#);
        let not_json = B64.encode(b"hello world");
        let no_secret = parse_token(&B64.encode(br#"{"a":"acc","t":"tid"}"#)).expect("parses");
        assert_eq!(no_secret.secret, "");
        for bad in ["", "eyJ0", &missing_tunnel, &not_json, "%%不合法%%"] {
            assert_eq!(parse_token(bad), Err(TokenError), "{bad} 应解析失败");
        }
    }

    #[test]
    fn parse_token_never_logs_secret() {
        // 错误信息与 Debug 输出都不含密钥。
        let error = parse_token("not-a-token").expect_err("fails");
        assert!(!error.to_string().contains("c2VjcmV0"));
        assert!(!error.to_string().contains("not-a-token"));
        let info = parse_token(&B64.encode(RAW_JSON)).expect("parses");
        let debug = format!("{info:?}");
        assert!(!debug.contains("c2VjcmV0"), "{debug}");
        assert!(debug.contains("5f0c-tid"), "{debug}");
    }
}
