//! Gotify channel: `POST <server>/message?token=<app token>` with
//! `{title,message}`; a 2xx response is success.

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
    let server = config.server.trim_end_matches('/');
    let url = format!("{server}/message?token={}", config.token);
    let body = json!({
        "title": message.title,
        "message": message.body,
    })
    .to_string();
    let (status, _) = http_request(
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
    Ok(())
}
