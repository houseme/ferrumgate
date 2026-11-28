//! Pushover channel: `POST https://api.pushover.net/1/messages.json` with
//! the form fields `token`, `user`, `title` and `message`; 2xx is success.

use tokio_util::sync::CancellationToken;

use crate::channels::{Message, form_body, http_request, require_2xx};
use crate::model::ChannelConfig;
use crate::proxy::Effective;

const ENDPOINT: &str = "https://api.pushover.net/1/messages.json";

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let body = form_body(&[
        ("token", config.token.as_str()),
        ("user", config.user.as_str()),
        ("title", message.title.as_str()),
        ("message", message.body.as_str()),
    ]);
    let (status, _) = http_request(
        "POST",
        ENDPOINT,
        &[],
        Some(body),
        Some("application/x-www-form-urlencoded"),
        effective,
        cancel,
        config.insecure_skip_verify,
    )
    .await?;
    require_2xx(status)?;
    Ok(())
}
