//! Bark channel: `POST <server>/push` with `{device_key,title,body}`; the
//! response's `code` field must be 200 (the upstream business-code check).

use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::channels::{Message, http_request, json_number, require_2xx};
use crate::model::{ChannelConfig, limits};
use crate::proxy::Effective;

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let server = if config.server.is_empty() {
        limits::BARK_SERVER_DEFAULT
    } else {
        config.server.trim_end_matches('/')
    };
    let url = format!("{server}/push");
    let body = json!({
        "device_key": config.device_key,
        "title": message.title,
        "body": message.body,
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
    let code = json_number(&text, "code");
    if code != Some(200) {
        return Err(format!("Bark 返回业务码 {code:?}：{text}"));
    }
    Ok(())
}
