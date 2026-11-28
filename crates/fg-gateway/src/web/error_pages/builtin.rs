//! Built-in error page styles (10 responsive themes), locale negotiation,
//! UTC timestamp formatting, and HTML-escaped placeholder rendering (WP-27).

use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::http::{HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};

/// The 10 built-in error page visual themes (WP-27 §3.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StyleId {
    #[default]
    Minimal,
    Terminal,
    Neon,
    Starfield,
    Editorial,
    Brutalist,
    Aurora,
    Pixel,
    Blueprint,
    StatusChain,
}

/// Public metadata for one built-in style (`GET /api/webservice/errorpages/styles`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StyleInfo {
    pub id: StyleId,
    pub name_en: &'static str,
    pub name_zh: &'static str,
}

impl StyleId {
    /// All 10 built-in styles in display order.
    pub const ALL: [StyleId; 10] = [
        Self::Minimal,
        Self::Terminal,
        Self::Neon,
        Self::Starfield,
        Self::Editorial,
        Self::Brutalist,
        Self::Aurora,
        Self::Pixel,
        Self::Blueprint,
        Self::StatusChain,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Terminal => "terminal",
            Self::Neon => "neon",
            Self::Starfield => "starfield",
            Self::Editorial => "editorial",
            Self::Brutalist => "brutalist",
            Self::Aurora => "aurora",
            Self::Pixel => "pixel",
            Self::Blueprint => "blueprint",
            Self::StatusChain => "status-chain",
        }
    }

    pub const fn info(self) -> StyleInfo {
        let (name_en, name_zh) = match self {
            Self::Minimal => ("Minimal", "极简"),
            Self::Terminal => ("Terminal", "终端"),
            Self::Neon => ("Neon", "霓虹"),
            Self::Starfield => ("Starfield", "星空"),
            Self::Editorial => ("Editorial", "报刊"),
            Self::Brutalist => ("Brutalist", "粗野"),
            Self::Aurora => ("Aurora", "极光"),
            Self::Pixel => ("Pixel", "像素"),
            Self::Blueprint => ("Blueprint", "蓝图"),
            Self::StatusChain => ("Status Chain", "状态链路"),
        };
        StyleInfo {
            id: self,
            name_en,
            name_zh,
        }
    }
}

impl FromStr for StyleId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "minimal" => Ok(Self::Minimal),
            "terminal" => Ok(Self::Terminal),
            "neon" => Ok(Self::Neon),
            "starfield" => Ok(Self::Starfield),
            "editorial" => Ok(Self::Editorial),
            "brutalist" => Ok(Self::Brutalist),
            "aurora" => Ok(Self::Aurora),
            "pixel" => Ok(Self::Pixel),
            "blueprint" => Ok(Self::Blueprint),
            "status-chain" | "status_chain" | "statuschain" => Ok(Self::StatusChain),
            other => Err(format!("unknown error page style '{other}'")),
        }
    }
}

/// Visitor display language negotiated from `Accept-Language`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lang {
    #[default]
    En,
    Zh,
}

impl Lang {
    /// Negotiates display language from an HTTP `Accept-Language` header.
    pub fn from_accept_language(header: Option<&HeaderValue>) -> Self {
        let Some(raw) = header.and_then(|v| v.to_str().ok()) else {
            return Self::En;
        };
        for part in raw.split(',') {
            let tag = part
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if tag.starts_with("zh") {
                return Self::Zh;
            }
            if tag.starts_with("en") {
                return Self::En;
            }
        }
        Self::En
    }
}

/// Template variables substituted into error page HTML (all values are
/// HTML-escaped during [`render`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ErrorCtx {
    pub code: u16,
    pub status: String,
    pub title: String,
    pub detail: String,
    pub host: String,
    pub path: String,
    pub time: String,
}

impl ErrorCtx {
    /// Builds an [`ErrorCtx`] with localized `title` / `detail`, English
    /// canonical status reason, and UTC RFC 3339 `time`.
    pub fn new(
        status: StatusCode,
        host: impl Into<String>,
        path: impl Into<String>,
        lang: Lang,
        now: SystemTime,
    ) -> Self {
        let code = status.as_u16();
        let reason = status.canonical_reason().unwrap_or("Error").to_owned();
        let (title, detail) = localized_copy(code, &reason, lang);
        Self {
            code,
            status: reason,
            title,
            detail,
            host: host.into(),
            path: path.into(),
            time: format_utc_rfc3339(now),
        }
    }
}

fn localized_copy(code: u16, reason: &str, lang: Lang) -> (String, String) {
    match lang {
        Lang::Zh => match code {
            400 => ("错误请求".into(), "服务器无法理解此请求。".into()),
            401 => ("未授权".into(), "访问此资源需要先完成身份验证。".into()),
            403 => ("禁止访问".into(), "您没有权限访问此资源。".into()),
            404 => ("页面未找到".into(), "请求的页面不存在或已被移除。".into()),
            405 => ("方法不允许".into(), "此路径不支持当前请求方法。".into()),
            408 => ("请求超时".into(), "客户端未在规定时间内完成请求。".into()),
            413 => (
                "请求体过大".into(),
                "提交的数据超出了允许的大小上限。".into(),
            ),
            429 => (
                "请求过于频繁".into(),
                "您的请求速率超出限制，请稍后重试。".into(),
            ),
            500 => ("服务器内部错误".into(), "处理请求时发生内部错误。".into()),
            502 => (
                "网关错误".into(),
                "上游服务暂时不可达或返回了无效响应。".into(),
            ),
            503 => (
                "服务暂不可用".into(),
                "目标服务正在维护或过载，请稍后再试。".into(),
            ),
            504 => ("网关超时".into(), "等待上游服务响应超时。".into()),
            c if (400..=499).contains(&c) => (
                format!("客户端错误 ({code})"),
                format!("请求无法完成：{reason}。"),
            ),
            _ => (
                format!("服务错误 ({code})"),
                format!("服务器处理请求时出错：{reason}。"),
            ),
        },
        Lang::En => match code {
            400 => (
                "Bad Request".into(),
                "The server could not understand the request.".into(),
            ),
            401 => (
                "Unauthorized".into(),
                "Authentication is required to access this resource.".into(),
            ),
            403 => (
                "Forbidden".into(),
                "You do not have permission to access this resource.".into(),
            ),
            404 => (
                "Page Not Found".into(),
                "The requested resource could not be found.".into(),
            ),
            405 => (
                "Method Not Allowed".into(),
                "The request method is not allowed for this resource.".into(),
            ),
            408 => (
                "Request Timeout".into(),
                "The client did not finish sending the request in time.".into(),
            ),
            413 => (
                "Payload Too Large".into(),
                "The request body exceeds the maximum allowed size.".into(),
            ),
            429 => (
                "Too Many Requests".into(),
                "Rate limit exceeded. Please try again later.".into(),
            ),
            500 => (
                "Internal Server Error".into(),
                "An unexpected error occurred while handling the request.".into(),
            ),
            502 => (
                "Bad Gateway".into(),
                "The upstream service is unreachable or returned an invalid response.".into(),
            ),
            503 => (
                "Service Unavailable".into(),
                "The service is temporarily unavailable. Please try again shortly.".into(),
            ),
            504 => (
                "Gateway Timeout".into(),
                "The upstream service did not respond in time.".into(),
            ),
            c if (400..=499).contains(&c) => (
                reason.to_owned(),
                format!("The request could not be completed ({code} {reason})."),
            ),
            _ => (
                reason.to_owned(),
                format!("The server encountered an error ({code} {reason})."),
            ),
        },
    }
}

/// Formats a [`SystemTime`] as UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`) without
/// requiring external date crates.
pub fn format_utc_rfc3339(time: SystemTime) -> String {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Howard Hinnant's civil-from-days algorithm (exact proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// HTML-escapes special characters (`&`, `<`, `>`, `"`, `'`).
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
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

/// Replaces the 7 WP-27 error-page placeholders in a single pass, HTML-escaping
/// every substituted value so attacker-controlled fields such as `{path}` or
/// `{host}` cannot inject markup or scripts.
pub fn render(html: &str, ctx: &ErrorCtx) -> String {
    let code_str = ctx.code.to_string();
    let status_esc = escape_html(&ctx.status);
    let title_esc = escape_html(&ctx.title);
    let detail_esc = escape_html(&ctx.detail);
    let host_esc = escape_html(&ctx.host);
    let path_esc = escape_html(&ctx.path);
    let time_esc = escape_html(&ctx.time);

    let mut out = String::with_capacity(html.len() + 64);
    let bytes = html.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let rest = &html[i..];
            let replacement = if rest.starts_with("{code}") {
                Some((6, code_str.as_str()))
            } else if rest.starts_with("{status}") {
                Some((8, status_esc.as_str()))
            } else if rest.starts_with("{title}") {
                Some((7, title_esc.as_str()))
            } else if rest.starts_with("{detail}") {
                Some((8, detail_esc.as_str()))
            } else if rest.starts_with("{host}") {
                Some((6, host_esc.as_str()))
            } else if rest.starts_with("{path}") {
                Some((6, path_esc.as_str()))
            } else if rest.starts_with("{time}") {
                Some((6, time_esc.as_str()))
            } else {
                None
            };
            if let Some((len, val)) = replacement {
                out.push_str(val);
                i += len;
                continue;
            }
        }
        // Advance one UTF-8 character.
        let ch = html[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Renders one of the 10 built-in responsive HTML error pages.
pub fn render_builtin(style: StyleId, ctx: &ErrorCtx) -> String {
    render(builtin_template(style), ctx)
}

/// Returns the static HTML5 template for `style` (inline CSS only, mobile
/// viewport meta, zero scripts, all 7 placeholders).
pub const fn builtin_template(style: StyleId) -> &'static str {
    match style {
        StyleId::Minimal => TEMPLATE_MINIMAL,
        StyleId::Terminal => TEMPLATE_TERMINAL,
        StyleId::Neon => TEMPLATE_NEON,
        StyleId::Starfield => TEMPLATE_STARFIELD,
        StyleId::Editorial => TEMPLATE_EDITORIAL,
        StyleId::Brutalist => TEMPLATE_BRUTALIST,
        StyleId::Aurora => TEMPLATE_AURORA,
        StyleId::Pixel => TEMPLATE_PIXEL,
        StyleId::Blueprint => TEMPLATE_BLUEPRINT,
        StyleId::StatusChain => TEMPLATE_STATUS_CHAIN,
    }
}

const TEMPLATE_MINIMAL: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#fafafa;color:#18181b;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
main{max-width:480px;width:100%;text-align:center}
.code{font-size:clamp(3.5rem,12vw,5.5rem);font-weight:700;letter-spacing:-0.04em;line-height:1}
h1{font-size:1.25rem;font-weight:600;margin-top:12px}
p{color:#52525b;margin-top:8px;line-height:1.5}
footer{margin-top:24px;padding-top:16px;border-top:1px solid #e4e4e7;font-size:0.75rem;color:#71717a;word-break:break-all}
</style></head>
<body data-style="minimal"><main><div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<footer>{status} · {host}{path} · {time}</footer></main></body></html>"#;

const TEMPLATE_TERMINAL: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#0b0f10;color:#4ade80;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.term{max-width:600px;width:100%;border:1px solid #1f2937;border-radius:8px;background:#111618;padding:20px;box-shadow:0 12px 32px rgba(0,0,0,.5)}
.bar{font-size:.75rem;color:#6b7280;margin-bottom:14px;border-bottom:1px solid #1f2937;padding-bottom:8px}
.line{margin:6px 0;line-height:1.5;word-break:break-all}
.dim{color:#9ca3af}
</style></head>
<body data-style="terminal"><div class="term"><div class="bar">ferrumgate://error-console</div>
<div class="line">$ status --code {code} --reason "{status}"</div>
<div class="line">ERR {code}: {title}</div>
<div class="line dim"># {detail}</div>
<div class="line dim"># target={host}{path} time={time}</div></div></body></html>"#;

const TEMPLATE_NEON: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#090514;color:#f5f3ff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{max-width:520px;width:100%;padding:32px;border-radius:16px;border:1px solid #a855f7;background:rgba(24,16,44,.9);box-shadow:0 0 36px rgba(168,85,247,.35)}
.code{font-size:clamp(3.5rem,12vw,5.5rem);font-weight:800;color:#f0abfc;text-shadow:0 0 18px #c026d3}
h1{margin-top:8px;font-size:1.35rem;color:#38bdf8}
p{margin-top:10px;color:#cbd5e1;line-height:1.5}
.meta{margin-top:20px;font-size:.75rem;color:#94a3b8;word-break:break-all}
</style></head>
<body data-style="neon"><section class="card"><div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<div class="meta">{status} · {host}{path} · {time}</div></section></body></html>"#;

const TEMPLATE_STARFIELD: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:radial-gradient(circle at 20% 20%,#1e293b,#020617 70%);color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
main{max-width:500px;width:100%;text-align:center;padding:32px;border-radius:16px;background:rgba(15,23,42,.7);border:1px solid rgba(148,163,184,.2)}
.code{font-size:clamp(3.5rem,12vw,5rem);font-weight:700;letter-spacing:.08em;color:#f8fafc}
h1{margin-top:10px;font-size:1.25rem}
p{margin-top:8px;color:#94a3b8;line-height:1.6}
.meta{margin-top:22px;font-size:.75rem;color:#64748b;word-break:break-all}
</style></head>
<body data-style="starfield"><main><div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<div class="meta">{status} · {host}{path} · {time}</div></main></body></html>"#;

const TEMPLATE_EDITORIAL: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Georgia,'Times New Roman',serif;background:#f7f4ee;color:#1c1917;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
article{max-width:560px;width:100%;border-top:4px solid #1c1917;border-bottom:1px solid #a8a29e;padding:28px 0}
.kicker{font-family:system-ui,sans-serif;text-transform:uppercase;letter-spacing:.14em;font-size:.75rem;color:#78716c}
.code{font-size:clamp(3.5rem,11vw,5rem);font-weight:700;margin-top:6px;line-height:1}
h1{font-size:1.5rem;margin-top:12px}
p{margin-top:10px;color:#44403c;line-height:1.65}
footer{margin-top:20px;font-family:system-ui,sans-serif;font-size:.75rem;color:#78716c;word-break:break-all}
</style></head>
<body data-style="editorial"><article><div class="kicker">HTTP {status}</div><div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<footer>{host}{path} · {time}</footer></article></body></html>"#;

const TEMPLATE_BRUTALIST: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:ui-monospace,monospace;background:#facc15;color:#000;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.box{max-width:540px;width:100%;background:#fff;border:4px solid #000;box-shadow:8px 8px 0 #000;padding:24px}
.code{font-size:clamp(3.5rem,12vw,5.5rem);font-weight:900;line-height:1}
h1{margin-top:10px;font-size:1.35rem;text-transform:uppercase}
p{margin-top:10px;line-height:1.5}
.meta{margin-top:18px;padding-top:12px;border-top:2px solid #000;font-size:.75rem;word-break:break-all}
</style></head>
<body data-style="brutalist"><div class="box"><div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<div class="meta">{status} | {host}{path} | {time}</div></div></body></html>"#;

const TEMPLATE_AURORA: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:linear-gradient(135deg,#0f172a 0%,#134e4a 50%,#312e81 100%);color:#f8fafc;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
main{max-width:520px;width:100%;padding:32px;border-radius:20px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.2)}
.code{font-size:clamp(3.5rem,12vw,5rem);font-weight:700;color:#5eead4}
h1{margin-top:8px;font-size:1.35rem}
p{margin-top:10px;color:#e2e8f0;line-height:1.6}
.meta{margin-top:20px;font-size:.75rem;color:#cbd5e1;word-break:break-all}
</style></head>
<body data-style="aurora"><main><div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<div class="meta">{status} · {host}{path} · {time}</div></main></body></html>"#;

const TEMPLATE_PIXEL: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:ui-monospace,monospace;background:#1d2b53;color:#fff1e8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.frame{max-width:520px;width:100%;background:#000;border:4px solid #ff004d;padding:24px;box-shadow:0 0 0 4px #29adff}
.code{font-size:clamp(3rem,11vw,4.5rem);font-weight:900;color:#ffec27;letter-spacing:.12em}
h1{margin-top:10px;font-size:1.2rem;color:#00e436}
p{margin-top:10px;line-height:1.6;color:#c2c3c7}
.meta{margin-top:18px;font-size:.75rem;color:#83769c;word-break:break-all}
</style></head>
<body data-style="pixel"><div class="frame"><div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<div class="meta">{status} · {host}{path} · {time}</div></div></body></html>"#;

const TEMPLATE_BLUEPRINT: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:ui-monospace,monospace;background:#0c4a6e;background-image:linear-gradient(rgba(255,255,255,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.08) 1px,transparent 1px);background-size:24px 24px;color:#e0f2fe;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.sheet{max-width:560px;width:100%;border:2px solid #7dd3fc;padding:28px;background:rgba(12,74,110,.88)}
.code{font-size:clamp(3.2rem,11vw,5rem);font-weight:700;letter-spacing:.06em}
h1{margin-top:8px;font-size:1.25rem}
p{margin-top:10px;color:#bae6fd;line-height:1.5}
.meta{margin-top:20px;padding-top:12px;border-top:1px dashed #7dd3fc;font-size:.75rem;word-break:break-all}
</style></head>
<body data-style="blueprint"><div class="sheet"><div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<div class="meta">SPEC {status} · {host}{path} · {time}</div></div></body></html>"#;

const TEMPLATE_STATUS_CHAIN: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{code} {status}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
main{max-width:600px;width:100%;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:28px}
.chain{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:.85rem;margin-bottom:20px}
.node{padding:6px 12px;border-radius:999px;background:#f1f5f9;border:1px solid #cbd5e1}
.node.err{background:#fef2f2;border-color:#ef4444;color:#b91c1c;font-weight:600}
.code{font-size:clamp(2.5rem,10vw,4rem);font-weight:700;line-height:1}
h1{margin-top:8px;font-size:1.25rem}
p{margin-top:8px;color:#475569;line-height:1.5}
.meta{margin-top:20px;font-size:.75rem;color:#64748b;word-break:break-all}
</style></head>
<body data-style="status-chain"><main>
<div class="chain"><span class="node">Client</span><span>&rarr;</span><span class="node">Gateway</span><span>&rarr;</span><span class="node err">{code} {status}</span></div>
<div class="code">{code}</div><h1>{title}</h1><p>{detail}</p>
<div class="meta">{host}{path} · {time}</div></main></body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::error_pages::sanitize::sanitize;
    use std::time::Duration;

    #[test]
    fn error_page_placeholders_escaped() {
        let ctx = ErrorCtx {
            code: 404,
            status: "Not Found".into(),
            title: "Page Not Found".into(),
            detail: "Missing".into(),
            host: "evil\"><script>".into(),
            path: "/a/<script>alert(1)</script>?x=1&y='2'".into(),
            time: "2026-01-01T00:00:00Z".into(),
        };
        let html = render(
            "<p>{code} {status} {title} {detail} {host} {path} {time}</p>",
            &ctx,
        );
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("evil&quot;&gt;&lt;script&gt;"));
        assert!(html.contains("x=1&amp;y=&#39;2&#39;"));
    }

    #[test]
    fn all_ten_builtin_styles_render_and_pass_sanitizer() {
        let ctx = ErrorCtx::new(
            StatusCode::BAD_GATEWAY,
            "app.example.com",
            "/dashboard",
            Lang::Zh,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        );
        assert_eq!(StyleId::ALL.len(), 10);
        for style in StyleId::ALL {
            let tpl = builtin_template(style);
            let checked = sanitize(tpl).expect("builtin template must pass sanitizer");
            assert!(
                checked.removed.is_empty(),
                "style {:?} had removed items: {:?}",
                style,
                checked.removed
            );
            assert!(
                checked.warnings.is_empty(),
                "style {:?} had warnings: {:?}",
                style,
                checked.warnings
            );
            let rendered = render_builtin(style, &ctx);
            assert!(rendered.contains("502"));
            assert!(rendered.contains("Bad Gateway"));
            assert!(rendered.contains("网关错误"));
            assert!(rendered.contains("app.example.com"));
            assert!(rendered.contains("/dashboard"));
            assert!(rendered.contains("2023-11-14T22:13:20Z"));
        }
    }
}
