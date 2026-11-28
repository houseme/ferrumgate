//! 企业微信 (WeCom) channel: `POST
//! https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<robot key>` with
//! `{msgtype:"text",text:{content}}`; the response's `errcode` must be 0
//! (the upstream business-code check — HTTP 200 with a non-zero errcode is
//! a failure).

use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::channels::{Message, http_request, json_number, require_2xx};
use crate::model::ChannelConfig;
use crate::proxy::Effective;

const ENDPOINT: &str = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send";

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let url = format!("{ENDPOINT}?key={}", config.key);
    let body = json!({
        "msgtype": "text",
        "text": { "content": message.title_and_body() },
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
    if json_number(&text, "errcode") != Some(0) {
        return Err(format!("企业微信返回业务失败：{text}"));
    }
    Ok(())
}
