//! The 14 notification channel senders (WP-68 §3.3). Each module owns one
//! channel kind's request construction; `send` dispatches on the channel
//! kind. Transport errors are plain strings with any proxy password
//! already redacted; the business-code checks required by the upstream
//! (WeCom, DingTalk, Feishu, Bark — plus Telegram's `ok` field) live in
//! their modules.
//!
//! Request formats follow each service's public API documentation:
//!
//! | Kind | Endpoint | Body | Business check |
//! |---|---|---|---|
//! | webhook | configured URL | configured template | 2xx |
//! | telegram | `POST https://api.telegram.org/bot<token>/sendMessage` | `{chat_id,text}` | `ok == true` |
//! | bark | `POST <server>/push` | `{device_key,title,body}` | `code == 200` |
//! | ntfy | `POST <server>/<topic>` | plain text | 2xx |
//! | gotify | `POST <server>/message?token=<token>` | `{title,message}` | 2xx |
//! | pushover | `POST https://api.pushover.net/1/messages.json` | form `token,user,title,message` | 2xx |
//! | discord | configured webhook URL | `{content}` | 2xx |
//! | slack | configured webhook URL | `{text}` | 2xx |
//! | serverchan | `POST https://sctapi.ftqq.com/<key>.send` | form `title,desp` | 2xx |
//! | pushplus | `POST https://www.pushplus.plus/send` | `{token,title,content,template:"html"}` (HTML-escaped content) | 2xx |
//! | wecom | `POST https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<key>` | `{msgtype:"text",text:{content}}` | `errcode == 0` |
//! | dingtalk | `POST https://oapi.dingtalk.com/robot/send?access_token=<token>` (+`timestamp`+`sign` when secret set) | `{msgtype:"text",text:{content}}` | `errcode == 0` |
//! | feishu | configured webhook URL (+`timestamp`+`sign` when secret set) | `{msg_type:"text",content:{text}}` | `code == 0` (legacy `StatusCode == 0`) |
//! | email | SMTP | RFC 5322 message | 2xx replies |

pub mod bark;
pub mod dingtalk;
pub mod discord;
pub mod email;
pub mod feishu;
pub mod gotify;
pub mod ntfy;
pub mod pushover;
pub mod pushplus;
pub mod serverchan;
pub mod slack;
pub mod telegram;
pub mod webhook;
pub mod wecom;

use std::collections::BTreeMap;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::model::{Channel, ChannelKind, limits};
use crate::proxy::Effective;

/// URL encoding of variable values: everything but unreserved characters.
const URL_VALUE_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// One rendered notification ready to send.
#[derive(Clone, Debug, Default)]
pub struct Message {
    /// Title with the server-name prefix (WP-68 §3.3).
    pub title: String,
    /// Rendered message body.
    pub body: String,
    /// Event type name (`auth.failed`).
    pub kind: String,
    /// Level label (`info`/`warn`/`error`).
    pub level: String,
    /// Event time, UTC RFC 3339.
    pub time: String,
    /// The configured server name (may be empty).
    pub server: String,
    /// Extra template variables from the event (address, domain, …).
    pub vars: BTreeMap<String, String>,
}

impl Message {
    /// The template variable resolver: the fixed variables plus every
    /// event variable.
    pub fn resolver(&self) -> impl Fn(&str) -> Option<String> + use<'_> {
        move |name| match name {
            "title" => Some(self.title.clone()),
            "message" => Some(self.body.clone()),
            "kind" => Some(self.kind.clone()),
            "level" => Some(self.level.clone()),
            "time" => Some(self.time.clone()),
            "server" => Some(self.server.clone()),
            other => self.vars.get(other).cloned(),
        }
    }

    /// `title\nbody` (the common channel payload shape), skipping the
    /// title or body when empty.
    pub fn title_and_body(&self) -> String {
        match (self.title.is_empty(), self.body.is_empty()) {
            (true, true) => String::new(),
            (true, false) => self.body.clone(),
            (false, true) => self.title.clone(),
            (false, false) => format!("{}\n{}", self.title, self.body),
        }
    }
}

/// Substitutes `{name}` placeholders; unresolved placeholders stay
/// literal.
pub fn render_values(template: &str, resolve: &dyn Fn(&str) -> Option<String>) -> String {
    render_with(template, resolve, false).unwrap_or_default()
}

/// Substitutes `{name}` placeholders with the values percent-encoded (URL
/// positions); an unresolved placeholder stays literal.
pub fn render_url_values(template: &str, resolve: &dyn Fn(&str) -> Option<String>) -> String {
    render_with(template, resolve, true).unwrap_or_default()
}

fn render_with(
    template: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
    encode: bool,
) -> Option<String> {
    if !template.contains('{') {
        return Some(template.to_owned());
    }
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        let name = &rest[start + 1..start + end];
        if !valid_var_name(name) {
            // Not a placeholder (JSON braces and the like): keep the brace
            // literal and keep scanning inside it.
            out.push_str(&rest[..start + 1]);
            rest = &rest[start + 1..];
            continue;
        }
        out.push_str(&rest[..start]);
        match resolve(name) {
            Some(value) => {
                if encode {
                    out.push_str(
                        &percent_encoding::utf8_percent_encode(&value, URL_VALUE_ENCODE)
                            .to_string(),
                    );
                } else {
                    out.push_str(&value);
                }
            }
            None => out.push_str(&rest[start..start + end + 1]),
        }
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Placeholder names are plain identifiers (`sourceAddr`, `ip`, ...);
/// anything else (JSON braces, quoted keys) is template text.
fn valid_var_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Builds an `application/x-www-form-urlencoded` body (Pushover,
/// Server酱).
pub(crate) fn form_body(fields: &[(&str, &str)]) -> String {
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        out.append_pair(name, value);
    }
    out.finish()
}

/// HTML-escapes message text (PushPlus `template: html`).
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// One outbound HTTP request for a channel send. Transport failures map to
/// `Err`; the response status and body are returned for the caller's
/// business-code checks. `insecure` skips TLS certificate verification
/// (the channel's `insecureSkipVerify`; tests pin self-signed fake
/// servers with it).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<String>,
    content_type: Option<&str>,
    effective: &Effective,
    cancel: &CancellationToken,
    insecure: bool,
) -> Result<(u16, String), String> {
    let client = crate::proxy::client(effective, limits::SEND_TIMEOUT, insecure)?;
    let method = method
        .parse::<reqwest::Method>()
        .map_err(|error| format!("请求方法无效：{error}"))?;
    let mut request = client.request(method, url);
    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if let Some(body) = body {
        request = request.header(
            reqwest::header::CONTENT_TYPE,
            content_type.unwrap_or("application/json"),
        );
        request = request.body(body);
    }
    let send = request.send();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err("投递在模块关闭时被终止".to_owned()),
        response = send => match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let text = response.text().await.unwrap_or_default();
                Ok((status, text))
            }
            Err(error) => {
                if error.is_timeout() {
                    Err("请求超时".to_owned())
                } else {
                    Err(format!("请求失败：{error}"))
                }
            }
        },
    }
}

/// The 2xx check shared by channels without a business code.
pub(crate) fn require_2xx(status: u16) -> Result<(), String> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("HTTP 返回 {status}"))
    }
}

/// Parses a JSON response body and reads a numeric field; missing fields
/// stay `None`.
fn json_number(text: &str, field: &str) -> Option<i64> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| value.get(field).and_then(serde_json::Value::as_i64))
}

/// Whether a JSON response body carries `"ok": true` (Telegram).
fn json_ok(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

/// Sends one notification through the channel. Test sends and live sends
/// share this path; retry/pending policy belongs to the dispatcher.
pub async fn send(
    channel: &Channel,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    match channel.kind {
        ChannelKind::Webhook => webhook::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Telegram => telegram::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Bark => bark::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Ntfy => ntfy::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Gotify => gotify::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Pushover => pushover::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Discord => discord::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Slack => slack::send(&channel.config, message, effective, cancel).await,
        ChannelKind::ServerChan => {
            serverchan::send(&channel.config, message, effective, cancel).await
        }
        ChannelKind::PushPlus => pushplus::send(&channel.config, message, effective, cancel).await,
        ChannelKind::WeCom => wecom::send(&channel.config, message, effective, cancel).await,
        ChannelKind::DingTalk => dingtalk::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Feishu => feishu::send(&channel.config, message, effective, cancel).await,
        ChannelKind::Email => email::send(&channel.config, message, effective, cancel).await,
    }
}

/// The JSON envelope used by the webhook channel when no body template is
/// configured.
pub(crate) fn default_webhook_body(message: &Message) -> String {
    json!({
        "title": message.title,
        "message": message.body,
        "kind": message.kind,
        "level": message.level,
        "time": message.time,
        "server": message.server,
        "vars": message.vars,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_and_keeps_unresolved_literal() {
        let resolver = |name: &str| match name {
            "ip" => Some("1.2.3.4".to_owned()),
            _ => None,
        };
        assert_eq!(
            render_values("{kind} at {ip}", &resolver),
            "{kind} at 1.2.3.4",
            "unresolved placeholders stay literal"
        );
        assert_eq!(render_values("ip={ip}", &resolver), "ip=1.2.3.4");
        assert_eq!(render_values("ip={ghost}", &resolver), "ip={ghost}");
        assert_eq!(
            render_url_values("?q={ip}&x={ghost}", &resolver),
            "?q=1.2.3.4&x={ghost}"
        );
        assert_eq!(
            render_url_values("{ip}", &|_| Some("a b:c".to_owned())),
            "a%20b%3Ac"
        );
        assert_eq!(render_values("no braces", &resolver), "no braces");
    }

    #[test]
    fn escape_html_replaces_specials() {
        assert_eq!(
            escape_html("<b>Tom & \"Jerry\"</b>"),
            "&lt;b&gt;Tom &amp; &quot;Jerry&quot;&lt;/b&gt;"
        );
        assert_eq!(escape_html("plain"), "plain");
    }

    #[test]
    fn title_and_body_combinations() {
        let message = Message {
            title: "t".into(),
            body: "b".into(),
            ..Message::default()
        };
        assert_eq!(message.title_and_body(), "t\nb");
        let message = Message {
            title: "t".into(),
            ..Message::default()
        };
        assert_eq!(message.title_and_body(), "t");
        let message = Message {
            body: "b".into(),
            ..Message::default()
        };
        assert_eq!(message.title_and_body(), "b");
        assert_eq!(Message::default().title_and_body(), "");
    }
}
