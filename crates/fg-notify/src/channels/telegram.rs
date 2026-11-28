//! Telegram channel: `POST https://api.telegram.org/bot<token>/sendMessage`
//! with `{chat_id, text}`; the response's `ok` field must be true (a 200
//! with `ok: false` is a failure).

use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::channels::{Message, http_request, require_2xx};
use crate::model::ChannelConfig;
use crate::proxy::Effective;

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", config.token);
    let body = json!({
        "chat_id": config.chat_id,
        "text": message.title_and_body(),
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
    if !crate::channels::json_ok(&text) {
        return Err(format!("Telegram 返回失败：{text}"));
    }
    Ok(())
}
