//! Server酱 channel: `POST https://sctapi.ftqq.com/<SendKey>.send` with the
//! form fields `title` and `desp`; 2xx is success.

use tokio_util::sync::CancellationToken;

use crate::channels::{Message, form_body, http_request, require_2xx};
use crate::model::ChannelConfig;
use crate::proxy::Effective;

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let url = format!("https://sctapi.ftqq.com/{}.send", config.send_key);
    let body = form_body(&[
        ("title", message.title.as_str()),
        ("desp", message.body.as_str()),
    ]);
    let (status, _) = http_request(
        "POST",
        &url,
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
