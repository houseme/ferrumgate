//! Webhook channel (WP-68 §3.3): configurable method, URL, headers and
//! body template over the shared HTTP transport. `{var}` placeholders in
//! the URL are percent-encoded; placeholders in headers and the body
//! render literally. An empty body template sends the default JSON
//! envelope (`{"title","message","kind","level","time","server","vars"}`).
//! A 2xx response is success.

use tokio_util::sync::CancellationToken;

use crate::channels::{
    Message, default_webhook_body, http_request, render_url_values, render_values, require_2xx,
};
use crate::model::ChannelConfig;
use crate::proxy::Effective;

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let resolve = message.resolver();
    let url = render_url_values(&config.url, &resolve);
    let method = if config.method.trim().is_empty() {
        "POST".to_owned()
    } else {
        config.method.trim().to_ascii_uppercase()
    };
    let mut headers = Vec::new();
    for header in &config.headers {
        if let Some((name, value)) = crate::validate::parse_header(header) {
            headers.push((name, render_values(&value, &resolve)));
        }
    }
    let (body, content_type) = if config.body.is_empty() {
        (default_webhook_body(message), None)
    } else {
        (render_values(&config.body, &resolve), Some("text/plain"))
    };
    let (status, _) = http_request(
        &method,
        &url,
        &headers,
        Some(body),
        content_type,
        effective,
        cancel,
        config.insecure_skip_verify,
    )
    .await?;
    require_2xx(status)?;
    Ok(())
}
