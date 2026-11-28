//! ntfy channel: `POST <server>/<topic>` with the plain notification text;
//! authentication is optional — an access token (`Bearer`) or basic auth
//! (`username`/`password`).

use base64::Engine as _;
use tokio_util::sync::CancellationToken;

use crate::channels::{Message, http_request, require_2xx};
use crate::model::{ChannelConfig, limits};
use crate::proxy::Effective;

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let server = if config.server.is_empty() {
        limits::NTFY_SERVER_DEFAULT
    } else {
        config.server.trim_end_matches('/')
    };
    let url = format!("{server}/{}", config.topic);
    let mut headers = Vec::new();
    headers.push(("Title".to_owned(), message.title.clone()));
    if !config.token.is_empty() {
        headers.push((
            "Authorization".to_owned(),
            format!("Bearer {}", config.token),
        ));
    } else if !config.username.is_empty() {
        headers.push((
            "Authorization".to_owned(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", config.username, config.password))
            ),
        ));
    }
    let (status, _) = http_request(
        "POST",
        &url,
        &headers,
        Some(message.body.clone()),
        Some("text/plain"),
        effective,
        cancel,
        config.insecure_skip_verify,
    )
    .await?;
    require_2xx(status)?;
    Ok(())
}
