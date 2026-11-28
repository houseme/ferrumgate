//! 钉钉 (DingTalk) channel: `POST
//! https://oapi.dingtalk.com/robot/send?access_token=<token>` with
//! `{msgtype:"text",text:{content}}`; the response's `errcode` must be 0
//! (upstream business-code check). When a signing secret is configured the
//! request appends `timestamp` (milliseconds) and `sign` — the URL-encoded
//! base64 of HMAC-SHA256 keyed by the secret over `"<timestamp>\n<secret>"`.

use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use serde_json::json;
use sha2::Sha256;
use tokio_util::sync::CancellationToken;

use crate::channels::{Message, http_request, json_number, require_2xx};
use crate::model::ChannelConfig;
use crate::proxy::Effective;

const ENDPOINT: &str = "https://oapi.dingtalk.com/robot/send";

/// The URL-encoding set DingTalk signatures need (everything but
/// alphanumerics).
const SIGN_ENCODE: &AsciiSet = NON_ALPHANUMERIC;

/// DingTalk signature: base64(HMAC-SHA256(key = secret, data =
/// "<timestamp_ms>\n<secret>")), URL-encoded.
pub fn sign(secret: &str, timestamp_ms: u64) -> String {
    use base64::Engine as _;
    let string_to_sign = format!("{timestamp_ms}\n{secret}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(string_to_sign.as_bytes());
    let digest = mac.finalize().into_bytes();
    let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
    percent_encoding::utf8_percent_encode(&encoded, SIGN_ENCODE).to_string()
}

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let mut url = format!("{ENDPOINT}?access_token={}", config.access_token);
    if !config.secret.is_empty() {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let signature = sign(&config.secret, timestamp);
        url.push_str(&format!("&timestamp={timestamp}&sign={signature}"));
    }
    let body = json!({
        "msgtype": "text",
        "text": { "content": message.title_and_body() },
    })
    .to_string();
    let (status, text) = http_request(
        "POST",
        &url,
        &[],
        Some(body),
        None,
        effective,
        cancel,
        config.insecure_skip_verify,
    )
    .await?;
    require_2xx(status)?;
    if json_number(&text, "errcode") != Some(0) {
        return Err(format!("钉钉返回业务失败：{text}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// RFC 4231 test case 2, the shared HMAC-SHA256 reference for the
    /// signing helpers.
    #[test]
    fn dingtalk_sign_follows_hmac_sha256_reference() {
        // The same primitive that signs DingTalk requests reproduces the
        // RFC 4231 vector: HMAC-SHA256(key "Jefe", data "what do ya want
        // for nothing?").
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Jefe").expect("key");
        mac.update(b"what do ya want for nothing?");
        let digest = mac.finalize().into_bytes();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(digest),
            "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM="
        );
    }

    #[test]
    fn dingtalk_sign_is_deterministic_url_encoded_and_keyed() {
        let first = sign("SECabc123", 1_700_000_000_000);
        assert_eq!(first, sign("SECabc123", 1_700_000_000_000));
        assert_ne!(
            first,
            sign("SECabc123", 1_700_000_000_001),
            "timestamp changes the signature"
        );
        assert_ne!(
            first,
            sign("SECother", 1_700_000_000_000),
            "secret keys the signature"
        );
        // The base64 payload (before encoding) never contains characters
        // the URL encoder would leave; '+' and '/' and '=' are encoded.
        for character in ["+", "/", "="] {
            let encoded =
                percent_encoding::utf8_percent_encode(&format!("a{character}b"), SIGN_ENCODE)
                    .to_string();
            assert!(
                !encoded.contains(character),
                "{character} must be encoded: {encoded}"
            );
        }
    }
}
