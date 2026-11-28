//! Discord channel: `POST <configured webhook URL>` with `{content}`; 2xx
//! (Discord answers 204) is success.

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
    let body = json!({ "content": message.title_and_body() }).to_string();
    let (status, _) = http_request(
        "POST",
        &config.url,
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
