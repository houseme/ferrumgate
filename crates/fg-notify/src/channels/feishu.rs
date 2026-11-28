//! 飞书 (Feishu) channel: `POST <configured webhook URL>` with
//! `{msg_type:"text",content:{text}}`; the response's `code` must be 0
//! (legacy responses carry the same value in `StatusCode`). When a signing
//! secret is configured the body carries `timestamp` (seconds) and `sign` —
//! base64 of HMAC-SHA256 keyed by `"<timestamp>\n<secret>"` over the empty
//! message.

use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use tokio_util::sync::CancellationToken;

use crate::channels::{Message, http_request, require_2xx};
use crate::model::ChannelConfig;
use crate::proxy::Effective;

/// Feishu signature: base64(HMAC-SHA256(key = "<timestamp>\n<secret>",
/// data = "")).
pub fn sign(secret: &str, timestamp_seconds: u64) -> String {
    use base64::Engine as _;
    let key = format!("{timestamp_seconds}\n{secret}");
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key");
    mac.update(b"");
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// The business code out of a Feishu response (`code`, falling back to the
/// legacy `StatusCode` field).
fn business_code(text: &str) -> Option<i64> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value
        .get("code")
        .and_then(serde_json::Value::as_i64)
        .or_else(|| value.get("StatusCode").and_then(serde_json::Value::as_i64))
}

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let mut body = json!({
        "msg_type": "text",
        "content": { "text": message.title_and_body() },
    });
    if !config.secret.is_empty() {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        body["timestamp"] = json!(timestamp.to_string());
        body["sign"] = json!(sign(&config.secret, timestamp));
    }
    let (status, text) = http_request(
        "POST",
        &config.url,
        &[],
        Some(body.to_string()),
        None,
        effective,
        cancel,
        config.insecure_skip_verify,
    )
    .await?;
    require_2xx(status)?;
    if business_code(&text) != Some(0) {
        return Err(format!("飞书返回业务失败：{text}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 1 through the shared HMAC-SHA256 primitive.
    #[test]
    fn feishu_sign_follows_hmac_sha256_reference() {
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0x0b; 20]).expect("key");
        mac.update(b"Hi There");
        use base64::Engine as _;
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()),
            "sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c="
        );
    }

    #[test]
    fn feishu_sign_is_deterministic_and_keyed_by_timestamp_and_secret() {
        assert_eq!(sign("s3cret", 1_591_424_231), sign("s3cret", 1_591_424_231));
        assert_ne!(sign("s3cret", 1_591_424_231), sign("s3cret", 1_591_424_232));
        assert_ne!(sign("s3cret", 1_591_424_231), sign("other", 1_591_424_231));
    }

    #[test]
    fn feishu_business_code_reads_legacy_field() {
        assert_eq!(business_code(r#"{"code":0,"msg":"success"}"#), Some(0));
        assert_eq!(
            business_code(r#"{"StatusCode":0,"StatusMessage":"success"}"#),
            Some(0)
        );
        assert_eq!(
            business_code(r#"{"code":19021,"msg":"sign match fail"}"#),
            Some(19021)
        );
        assert_eq!(business_code("not json"), None);
        assert_eq!(business_code("{}"), None);
    }
}
