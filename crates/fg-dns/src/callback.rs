//! 自定义回调（上游 simple.go 的 callback 与 internal/webhook）。
//!
//! 地址、请求头与请求体可用变量 `{ip}` `{domain}` `{subDomain}` `{zone}`
//! `{recordType}` `{ttl}`（为 0 时取 600）`{timestamp}`（当前 Unix 秒）
//! `{id}` `{secret}`，同时兼容导入配置常用的 `#{name}` 写法。地址中的变量
//! 值做 URL 编码；JSON 请求体中位于字符串内的变量按 JSON 字符串转义；
//! 2xx 视为成功；配置了 `successContent` 时响应体需包含其中任意一项。

use std::{collections::BTreeMap, sync::Arc};

use hyper::{Method, body::Bytes};

use crate::http::OutboundHttp;
use crate::{
    Credentials, Field, Meta, ProviderError, ProviderErrorKind, Record, UpsertAction, msg, simple,
};

/// 未配置 TTL 时 `{ttl}` 取 600（WP-41 §3.4）。
pub const CALLBACK_DEFAULT_TTL: u32 = 600;

const NAME: &str = "callback";

pub static FIELDS: [Field; 5] = [
    Field::new(
        "url",
        "回调地址",
        "https://example.com/ddns?domain={domain}&ip={ip}",
    )
    .required(),
    Field::new("method", "请求方法", "GET"),
    Field::new("headers", "请求头", "每行一个，格式 Key: Value").multiline(),
    Field::new(
        "body",
        "请求体",
        "可用变量 {ip} {domain} {subDomain} {zone} {recordType} {ttl} {timestamp}",
    )
    .multiline(),
    Field::new(
        "successContent",
        "成功标识",
        "每行一个，响应包含任意一项即成功；留空只检查状态码",
    )
    .multiline(),
];

pub static META: Meta = Meta::new("callback", "自定义回调").extra(&FIELDS);

/// 回调配置。URL、Headers、Body 中的 `{变量名}` 会被替换。
#[derive(Clone, Debug, Default)]
pub struct CallbackConfig {
    pub url: String,
    pub method: String,
    /// 每项格式为 "Key: Value"
    pub headers: Vec<String>,
    pub body: String,
    /// 非空时响应体需包含其中任意一项才视为成功；为空时仅检查 2xx。
    pub success_content: Vec<String>,
}

impl CallbackConfig {
    /// 从凭据的附加字段构造并校验。
    pub fn from_extra(creds: &Credentials) -> Result<Self, ProviderError> {
        let cfg = Self {
            url: creds.extra("url").unwrap_or_default().to_owned(),
            method: creds.extra("method").unwrap_or_default().to_owned(),
            headers: simple::split_lines(creds.extra("headers").unwrap_or_default()),
            body: creds.extra("body").unwrap_or_default().to_owned(),
            success_content: simple::split_lines(creds.extra("successContent").unwrap_or_default()),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// 校验配置。
    pub fn validate(&self) -> Result<(), ProviderError> {
        let invalid = |detail: String| {
            ProviderError::new(NAME, ProviderErrorKind::InvalidInput, msg::INVALID_INPUT)
                .with_detail(detail)
        };
        let uri = hyper::Uri::try_from(self.url.trim())
            .map_err(|_| invalid("Webhook 地址无效".to_owned()))?;
        let scheme_ok = uri
            .scheme_str()
            .is_some_and(|s| s == "http" || s == "https");
        if !scheme_ok || uri.host().is_none_or(str::is_empty) {
            return Err(invalid("Webhook 地址无效".to_owned()));
        }
        match self.method.to_ascii_uppercase().as_str() {
            "" | "GET" | "POST" | "PUT" | "PATCH" | "DELETE" => {}
            other => return Err(invalid(format!("不支持的 Webhook 方法 {other:?}"))),
        }
        for header in &self.headers {
            if header.trim().is_empty() {
                continue;
            }
            let bad = || invalid(format!("请求头格式应为 Key: Value，实际 {header:?}"));
            let Some((key, _)) = header.split_once(':') else {
                return Err(bad());
            };
            if key.trim().is_empty() {
                return Err(bad());
            }
        }
        Ok(())
    }
}

/// 自定义回调提供商客户端。
pub struct Callback {
    cfg: CallbackConfig,
    creds: Credentials,
    http: Arc<OutboundHttp>,
}

impl Callback {
    pub fn new(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        let cfg = CallbackConfig::from_extra(&creds)?;
        Ok(Self { cfg, creds, http })
    }

    /// 调用用户配置的回调地址。
    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let mut vars = BTreeMap::new();
        vars.insert("ip".to_owned(), rec.value.clone());
        vars.insert("recordType".to_owned(), rec.typ.as_str().to_owned());
        vars.insert("domain".to_owned(), rec.fqdn());
        vars.insert("subDomain".to_owned(), rec.rr().to_owned());
        vars.insert("zone".to_owned(), rec.zone.clone());
        vars.insert("ttl".to_owned(), ttl_value(rec.ttl));
        vars.insert("timestamp".to_owned(), unix_now());
        vars.insert("id".to_owned(), self.creds.id.clone());
        vars.insert("secret".to_owned(), self.creds.secret.clone());
        webhook_send(&self.http, &self.cfg, &vars).await?;
        Ok(UpsertAction::Updated)
    }
}

crate::impl_provider!(Callback, META);

fn ttl_value(ttl: u32) -> String {
    if ttl == 0 {
        CALLBACK_DEFAULT_TTL.to_string()
    } else {
        ttl.to_string()
    }
}

fn unix_now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

/// 按配置发送请求。
async fn webhook_send(
    http: &OutboundHttp,
    cfg: &CallbackConfig,
    vars: &BTreeMap<String, String>,
) -> Result<(), ProviderError> {
    let method = if cfg.method.is_empty() {
        Method::GET
    } else {
        Method::from_bytes(cfg.method.to_ascii_uppercase().as_bytes()).map_err(|_| {
            ProviderError::new(NAME, ProviderErrorKind::InvalidInput, msg::INVALID_INPUT)
                .with_detail(format!("不支持的 Webhook 方法 {:?}", cfg.method))
        })?
    };
    let target = render(cfg.url.trim(), vars, Some(simple::query_escape));
    let mut body: Option<Bytes> = None;
    if method != Method::GET && !cfg.body.is_empty() {
        // 默认按 JSON 发送；请求头中明确写了其他内容类型（表单、纯文本）时原样替换。
        let rendered = if json_content(&cfg.headers) {
            render_json(&cfg.body, vars)
        } else {
            render(&cfg.body, vars, None)
        };
        body = Some(rendered.into_bytes().into());
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    for header in &cfg.headers {
        let Some((key, value)) = header.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let rendered = render(value.trim(), vars, None);
        headers.push((key.to_owned(), sanitize_header_value(&rendered)));
    }
    if body.is_some()
        && !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
    }
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let reply = simple::send(http, NAME, method, &target, &header_refs, body).await?;
    if !cfg.success_content.is_empty() {
        let text = reply.text();
        let ok = cfg
            .success_content
            .iter()
            .any(|marker| !marker.is_empty() && text.contains(marker.as_str()));
        if !ok {
            return Err(ProviderError::new(
                NAME,
                ProviderErrorKind::InvalidInput,
                msg::CALLBACK_FAILED,
            )
            .with_detail(format!(
                "响应中未包含成功标识: {}",
                simple::truncate(&text, 200)
            )));
        }
    }
    Ok(())
}

/// 去掉请求头值中的换行等控制字符（换成空格），访客文本不能借换行注入额外请求头。
fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c != '\t' && (c.is_control() || c == '\u{7f}') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// 请求体是否按 JSON 发送：没有填写 Content-Type（默认 application/json）
/// 或填写的是 JSON 类型。
fn json_content(headers: &[String]) -> bool {
    for header in headers {
        let Some((key, value)) = header.split_once(':') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("Content-Type") {
            continue;
        }
        let media = value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        return media.is_empty()
            || media == "application/json"
            || media.ends_with("+json")
            || media.contains('{');
    }
    true
}

/// 把 s 中的 {name}（或 #{name}）替换为 vars[name]；未知变量保持原样。
/// escape 不为 None 时对替换值做编码（回调地址使用 URL 编码）。
pub fn render(
    s: &str,
    vars: &BTreeMap<String, String>,
    escape: Option<fn(&str) -> String>,
) -> String {
    match escape {
        Some(f) => render_impl(s, vars, Some(&|value: &str, _in_string: bool| f(value))),
        None => render_impl(s, vars, None),
    }
}

/// 与 [`render`] 相同，但模板是 JSON（对象或数组）时，位于 JSON 字符串内的
/// 变量按 JSON 字符串转义；字符串外的变量（通常是数字）原样替换。
/// 模板不是 JSON 时与 [`render`] 相同。
pub fn render_json(s: &str, vars: &BTreeMap<String, String>) -> String {
    if !json_template(s, vars) {
        return render_impl(s, vars, None);
    }
    render_impl(
        s,
        vars,
        Some(&|value: &str, in_string: bool| {
            if in_string {
                json_escape(value)
            } else {
                value.to_owned()
            }
        }),
    )
}

/// 判断模板是否为 JSON 对象或数组：把已知变量都换成 0 后检查是否为合法 JSON。
fn json_template(s: &str, vars: &BTreeMap<String, String>) -> bool {
    let probe = render_impl(s, vars, Some(&|_: &str, _: bool| "0".to_owned()));
    let probe = probe.trim();
    if probe.is_empty() || (!probe.starts_with('{') && !probe.starts_with('[')) {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(probe).is_ok()
}

/// 返回 v 作为 JSON 字符串内容（不含两侧引号）的转义结果。
fn json_escape(v: &str) -> String {
    let encoded = serde_json::to_string(v).unwrap_or_else(|_| format!("{v:?}"));
    encoded[1..encoded.len() - 1].to_owned()
}

/// 替换值的转义回调；`bool` 表示变量位于模板中的 JSON 字符串内。
type EscapeFn<'a> = &'a dyn Fn(&str, bool) -> String;

/// `render` 的实现：escape 不为 None 时对替换值转义，in_string 表示变量位于
/// 模板中的 JSON 字符串内（按模板本身的引号与反斜杠判断，不考虑替换进去的值）。
fn render_impl(s: &str, vars: &BTreeMap<String, String>, escape: Option<EscapeFn<'_>>) -> String {
    if !s.contains('{') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut in_string = false;
    let mut escaped = false;
    fn literal(out: &mut String, text: &str, in_string: &mut bool, escaped: &mut bool) {
        out.push_str(text);
        for byte in text.bytes() {
            if *escaped {
                *escaped = false;
            } else if *in_string && byte == b'\\' {
                *escaped = true;
            } else if byte == b'"' {
                *in_string = !*in_string;
            }
        }
    }
    let mut rest = s;
    loop {
        let Some(start) = rest.find('{') else {
            literal(&mut out, rest, &mut in_string, &mut escaped);
            break;
        };
        let Some(rel_end) = rest[start..].find('}') else {
            literal(&mut out, rest, &mut in_string, &mut escaped);
            break;
        };
        let end = start + rel_end;
        // JSON 等内容本身含有花括号，取离 } 最近的 { 作为变量起点。
        if let Some(inner) = rest[start..end].rfind('{')
            && inner > 0
        {
            literal(
                &mut out,
                &rest[..start + inner],
                &mut in_string,
                &mut escaped,
            );
            rest = &rest[start + inner..];
            continue;
        }
        let name = &rest[start + 1..end];
        let known = vars.get(name);
        let mut prefix = &rest[..start];
        // 同时支持 #{name} 写法（导入的配置常用）。
        if known.is_some() && prefix.ends_with('#') {
            prefix = &prefix[..prefix.len() - 1];
        }
        literal(&mut out, prefix, &mut in_string, &mut escaped);
        match known {
            Some(value) => {
                let rendered = match escape {
                    Some(escape) => escape(value, in_string),
                    None => value.clone(),
                };
                out.push_str(&rendered);
                // 变量前的反斜杠只作用于变量本身。
                escaped = false;
            }
            None => literal(&mut out, &rest[start..=end], &mut in_string, &mut escaped),
        }
        rest = &rest[end + 1..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record;

    fn vars() -> BTreeMap<String, String> {
        [
            ("ip".to_owned(), "1.2.3.4".to_owned()),
            ("text".to_owned(), "a\"b\\c\nd".to_owned()),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn render_replaces_known_and_keeps_unknown_vars() {
        let v = vars();
        assert_eq!(render("{ip} -> {ip}", &v, None), "1.2.3.4 -> 1.2.3.4");
        assert_eq!(render("{nope}", &v, None), "{nope}");
        assert_eq!(render("#{ip}", &v, None), "1.2.3.4");
    }

    #[test]
    fn render_url_escape_applies_to_values() {
        let v = vars();
        assert_eq!(
            render("/?ip={ip}&t={text}", &v, Some(simple::query_escape)),
            "/?ip=1.2.3.4&t=a%22b%5Cc%0Ad"
        );
    }

    #[test]
    fn render_json_escapes_only_inside_strings() {
        let v = vars();
        assert_eq!(
            render_json(r#"{"msg":"{text}","port":8443}"#, &v),
            r#"{"msg":"a\"b\\c\nd","port":8443}"#
        );
        assert_eq!(render_json("msg={ip}", &v), "msg=1.2.3.4");
    }

    #[test]
    fn callback_config_validate_rejects_bad_url_and_method_and_headers() {
        let ok = CallbackConfig {
            url: "http://example.com/x".into(),
            ..Default::default()
        };
        ok.validate().expect("ok");
        let ftp = CallbackConfig {
            url: "ftp://example.com".into(),
            ..Default::default()
        };
        assert_eq!(
            ftp.validate().expect_err("scheme").kind,
            ProviderErrorKind::InvalidInput
        );
        let nohost = CallbackConfig {
            url: "http://".into(),
            ..Default::default()
        };
        assert!(nohost.validate().is_err());
        let method = CallbackConfig {
            url: "http://example.com".into(),
            method: "TRACE".into(),
            ..Default::default()
        };
        assert!(method.validate().is_err());
        let header = CallbackConfig {
            url: "http://example.com".into(),
            headers: vec!["NoColon".into()],
            ..Default::default()
        };
        assert!(header.validate().is_err());
    }

    #[test]
    fn callback_ttl_defaults_to_600() {
        assert_eq!(ttl_value(0), "600");
        assert_eq!(ttl_value(120), "120");
    }

    #[test]
    fn callback_header_value_strips_control_chars() {
        assert_eq!(sanitize_header_value("a\r\nb"), "a  b");
        assert_eq!(sanitize_header_value("tab\tkept"), "tab\tkept");
    }

    #[test]
    fn callback_json_content_detection() {
        assert!(json_content(&[]));
        assert!(json_content(&["Content-Type: application/json".into()]));
        assert!(!json_content(&["Content-Type: text/plain".into()]));
        assert!(json_content(&["X-Other: 1".into()]));
    }

    #[test]
    fn callback_meta_records_form_fields() {
        assert_eq!(META.name, "callback");
        assert_eq!(record::owner_fqdn("example.com", "@"), "example.com");
        assert_eq!(FIELDS.len(), 5);
        assert!(FIELDS.iter().any(|f| f.key == "url" && f.required));
    }
}
