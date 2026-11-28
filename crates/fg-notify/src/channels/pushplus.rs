//! PushPlus channel: `POST https://www.pushplus.plus/send` with
//! `{token,title,content,template:"html"}`; the content is HTML-escaped
//! (the upstream keeps PushPlus' HTML template from mangling message
//! text). 2xx is success.

use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::channels::{Message, escape_html, http_request, require_2xx};
use crate::model::ChannelConfig;
use crate::proxy::Effective;

const ENDPOINT: &str = "https://www.pushplus.plus/send";

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let body = json!({
        "token": config.token,
        "title": escape_html(&message.title),
        "content": escape_html(&message.title_and_body()),
        "template": "html",
    })
    .to_string();
    let (status, _) = http_request(
        "POST",
        ENDPOINT,
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
