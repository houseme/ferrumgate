//! Login page model and rendering (WP-24 steps 8/10): the `loginPage`
//! branding model (WP-24 §3.3「登录页外观」), its limit validation
//! (§3.4) and the one style this package renders — a complete
//! default-look login document built from inline styles.
//!
//! Legal style ids and their plan §3.3 counterparts (English names are
//! chosen by this task):
//! `default`=默认样式、`split`=分屏、`minimal`=极简、`terminal`=终端、
//! `letter`=信笺、`brutal`=粗野、`aurora`=极光、`pixel`=像素、
//! `blueprint`=蓝图. (The plan also names 锁屏 — upstream `lockscreen`;
//! the fixed legal set of this task does not carry a separate id for it,
//! these nine values are the only ones accepted.) Only the `default`
//! look is rendered here; the other style assets migrate with WP-86.
#![allow(dead_code)]

use super::AUTH_PATH;
use serde::{Deserialize, Serialize};

/// §3.4: the login-page title is at most 60 characters.
pub const MAX_TITLE_CHARS: usize = 60;
/// §3.4: the description is at most 160 characters (shown verbatim,
/// never translated).
pub const MAX_DESCRIPTION_CHARS: usize = 160;
/// §3.4: custom CSS is at most 32 KiB, appended after the chosen style.
pub const MAX_CSS_BYTES: usize = 32 * 1024;
/// §3.4: the uploaded logo is at most 256 KiB.
pub const MAX_LOGO_BYTES: usize = 256 * 1024;
/// §3.4: the uploaded background image is at most 1 MiB.
pub const MAX_BACKGROUND_BYTES: usize = 1024 * 1024;
/// §3.4: the background dimming overlay is at most 90.
pub const MAX_BACKGROUND_DIM: u8 = 90;

/// The nine legal style ids (see the module docs for the mapping).
pub const LOGIN_STYLES: [&str; 9] = [
    "default",
    "split",
    "minimal",
    "terminal",
    "letter",
    "brutal",
    "aurora",
    "pixel",
    "blueprint",
];

/// Login page branding (§3.3): style, brand texts, uploads and custom
/// CSS. JSON field names follow the upstream camelCase model; empty
/// title/description render with the default copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginPage {
    /// One of [`LOGIN_STYLES`]; the site may override this per site with
    /// `loginStyle` (WP-25).
    pub style: String,
    /// Card title, shown verbatim; empty falls back to default copy.
    pub title: String,
    /// Card description, shown verbatim (never translated).
    pub description: String,
    /// Custom CSS appended after the chosen style; `<` is escaped.
    pub css: String,
    /// Uploaded logo bytes (≤256 KiB).
    pub logo: Vec<u8>,
    /// Uploaded background image bytes (≤1 MB).
    pub background: Vec<u8>,
    /// Background dimming overlay strength 0–90.
    pub background_dim: u8,
    /// Hide the footer branding (visited host + product mark).
    pub hide_footer: bool,
}

impl Default for LoginPage {
    fn default() -> Self {
        Self {
            style: "default".to_owned(),
            title: String::new(),
            description: String::new(),
            css: String::new(),
            logo: Vec::new(),
            background: Vec::new(),
            background_dim: 0,
            hide_footer: false,
        }
    }
}

/// Validates the §3.4 limits: one Chinese problem per exceeded limit,
/// plus one for a style outside [`LOGIN_STYLES`]. Every problem is
/// reported (the list is not truncated at the first failure).
pub fn validate(page: &LoginPage) -> Vec<String> {
    let mut problems = Vec::new();
    if !LOGIN_STYLES.contains(&page.style.as_str()) {
        problems.push(format!(
            "登录页样式未知：{}（可用：{}）",
            page.style,
            LOGIN_STYLES.join("、")
        ));
    }
    let title_chars = page.title.chars().count();
    if title_chars > MAX_TITLE_CHARS {
        problems.push(format!(
            "登录页标题最长 {MAX_TITLE_CHARS} 个字符，当前 {title_chars} 个"
        ));
    }
    let description_chars = page.description.chars().count();
    if description_chars > MAX_DESCRIPTION_CHARS {
        problems.push(format!(
            "登录页说明最长 {MAX_DESCRIPTION_CHARS} 个字符，当前 {description_chars} 个"
        ));
    }
    if page.css.len() > MAX_CSS_BYTES {
        problems.push(format!(
            "自定义 CSS 最大 32 KiB，当前 {} 字节",
            page.css.len()
        ));
    }
    if page.logo.len() > MAX_LOGO_BYTES {
        problems.push(format!("Logo 最大 256 KiB，当前 {} 字节", page.logo.len()));
    }
    if page.background.len() > MAX_BACKGROUND_BYTES {
        problems.push(format!(
            "背景图最大 1 MB，当前 {} 字节",
            page.background.len()
        ));
    }
    if page.background_dim > MAX_BACKGROUND_DIM {
        problems.push(format!(
            "背景图遮罩浓度最大 {MAX_BACKGROUND_DIM}，当前 {}",
            page.background_dim
        ));
    }
    problems
}

/// Copy used when the branding fields are empty (「空为默认文案」).
const DEFAULT_TITLE: &str = "请登录";
/// See [`DEFAULT_TITLE`].
const DEFAULT_DESCRIPTION: &str = "此站点受保护，请输入用户名与密码继续访问。";

/// Renders the default look: a complete standalone HTML document with
/// inline styles only (no scripts, no external resources). The form
/// posts to [`AUTH_PATH`]; `next` rides along as a hidden field;
/// `error` (when present) shows above the form; `need_code` adds the
/// verification-code input for the shared-user TOTP step. `shown_host`
/// appears in the footer together with the product mark — `hide_footer`
/// omits the whole footer. Texts, hosts, `next` and `error` are
/// HTML-escaped; custom CSS has its `<` escaped before being appended
/// in a second `<style>` tag.
pub fn render(
    page: &LoginPage,
    error: Option<&str>,
    need_code: bool,
    shown_host: &str,
    next: &str,
) -> String {
    let title = if page.title.is_empty() {
        DEFAULT_TITLE
    } else {
        &page.title
    };
    let description = if page.description.is_empty() {
        DEFAULT_DESCRIPTION
    } else {
        &page.description
    };
    let mut out = String::with_capacity(4096 + page.css.len());
    out.push_str("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<meta name=\"robots\" content=\"noindex,nofollow\">\n<title>");
    out.push_str(&html_escape(title));
    out.push_str("</title>\n<style>");
    out.push_str(BASE_CSS);
    out.push_str("</style>\n");
    if !page.css.is_empty() {
        out.push_str("<style>");
        out.push_str(&css_escape(&page.css));
        out.push_str("</style>\n");
    }
    out.push_str("</head>\n<body>\n<main>\n<h1>");
    out.push_str(&html_escape(title));
    out.push_str("</h1>\n<p class=\"desc\">");
    out.push_str(&html_escape(description));
    out.push_str("</p>\n");
    if let Some(message) = error {
        out.push_str("<p class=\"error\" role=\"alert\">");
        out.push_str(&html_escape(message));
        out.push_str("</p>\n");
    }
    out.push_str("<form method=\"post\" action=\"");
    out.push_str(AUTH_PATH);
    out.push_str("\">\n<input type=\"hidden\" name=\"next\" value=\"");
    out.push_str(&html_escape(next));
    out.push_str("\">\n<label>用户名\n<input name=\"username\" autocomplete=\"username\" required></label>\n");
    out.push_str("<label>密码\n<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>\n");
    if need_code {
        out.push_str("<label>验证码\n<input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" required></label>\n");
    }
    out.push_str("<button type=\"submit\">登录</button>\n</form>\n</main>\n");
    if !page.hide_footer {
        out.push_str("<footer>");
        out.push_str(&html_escape(shown_host));
        out.push_str(" · FerrumGate</footer>\n");
    }
    out.push_str("</body>\n</html>\n");
    out
}

/// Escapes the five HTML-sensitive characters (`& < > " '`) for safe
/// interpolation into element text and attribute values.
fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escapes `<` inside custom CSS so it cannot close the `<style>` tag
/// early or start new markup; everything else passes through.
fn css_escape(value: &str) -> String {
    value.replace('<', "&lt;")
}

// ---------------------------------------------------------------------------
// WP-24 batch 3: login submission, verification-code step and logout
// handling. The rendering above is untouched; these helpers shape the
// request side (form parsing, same-origin and `next` restrictions) and
// the replies the authenticator returns for the reserved paths.
// ---------------------------------------------------------------------------

use super::AuthPathReply;

/// Content type of every rendered page.
const HTML: &str = "text/html; charset=utf-8";
/// Content type of the empty-body redirects and throttle replies.
const TEXT: &str = "text/plain; charset=utf-8";

/// The four fields the login form submits (`next` as a hidden field,
/// the credentials, and the optional verification code).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LoginForm {
    pub next: String,
    pub username: String,
    pub password: String,
    pub code: String,
}

/// Parses an `application/x-www-form-urlencoded` body into the login
/// form fields; unknown fields are dropped, malformed pairs are skipped
/// (`+` decodes as a space, as browsers encode form bodies).
pub fn parse_login_form(body: &[u8]) -> LoginForm {
    let mut form = LoginForm::default();
    let text = String::from_utf8_lossy(body);
    for pair in text.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        let value = decode_percent(value, true);
        match name {
            "next" => form.next = value,
            "username" => form.username = value,
            "password" => form.password = value,
            "code" => form.code = value,
            _ => {}
        }
    }
    form
}

/// The `next` target from the auth-path query (`?next=...`), decoded
/// and restricted by [`safe_next`] (falls back to `/`).
pub fn next_from_query(query: &str) -> String {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("next="))
        .map(|value| safe_next(&decode_percent(value, false)).to_owned())
        .unwrap_or_else(|| "/".to_owned())
}

/// Restricts the post-login target to a site-relative path (§3.3): it
/// must start with `/`, must not start with `//`, must not contain a
/// backslash or control characters — anything else falls back to `/`,
/// so `//evil`, `/\evil` and `https://evil` cannot leave the site.
pub fn safe_next(next: &str) -> &str {
    let safe = next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\\')
        && !next.chars().any(char::is_control);
    if safe {
        next
    } else {
        "/"
    }
}

/// Extracts the host of an `Origin`/`Referer` header value (the caller
/// passes the Origin first, falling back to Referer). Scheme-less,
/// `null` and empty values yield `None`; a numeric port tail is stripped
/// because the session host never carries one.
pub fn origin_host(header: Option<&str>) -> Option<String> {
    let value = header?.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("null") {
        return None;
    }
    let rest = value.split_once("://").map_or(value, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.rsplit_once(':') {
        // Only a numeric tail counts as a port (IPv6 literals keep
        // their colons; the bracketed host compares fine).
        Some((host, port)) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => {
            host
        }
        _ => authority,
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Percent-encodes a `next` target for the `?next=` query value (RFC
/// 3986 unreserved characters and `/` pass through; `&`, `=` and `?`
/// inside the target must not break the query).
pub fn encode_next(target: &str) -> String {
    const NEXT_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'/')
        .remove(b'.')
        .remove(b'-')
        .remove(b'_')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(target, NEXT_SET).to_string()
}

/// Percent-decodes one component. `plus_as_space` follows the form
/// encoding (`+` = space) for bodies; query values keep their `+`.
fn decode_percent(value: &str, plus_as_space: bool) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match (hex_val(bytes[index + 1]), hex_val(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high << 4 | low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The login (or verification-code) page as a 200 reply.
pub fn page_reply(
    page: &LoginPage,
    error: Option<&str>,
    need_code: bool,
    host: &str,
    next: &str,
) -> AuthPathReply {
    AuthPathReply::Handled {
        status: 200,
        content_type: HTML,
        body: render(page, error, need_code, host, next),
        location: String::new(),
        set_cookies: Vec::new(),
    }
}

/// A locked-out source: the page renders, but the status says 429 —
/// even correct credentials are refused until the window expires.
pub fn throttled_reply(
    page: &LoginPage,
    need_code: bool,
    host: &str,
    next: &str,
) -> AuthPathReply {
    AuthPathReply::Handled {
        status: 429,
        content_type: HTML,
        body: render(page, Some("尝试次数过多，请稍后再试"), need_code, host, next),
        location: String::new(),
        set_cookies: Vec::new(),
    }
}

/// An exhausted gate pool: the verification itself never ran, so no
/// failure counts; the source may retry once the pool drains.
pub fn busy_reply(page: &LoginPage, host: &str) -> AuthPathReply {
    AuthPathReply::Handled {
        status: 503,
        content_type: HTML,
        body: render(page, Some("系统繁忙，请稍后再试"), false, host, "/"),
        location: String::new(),
        set_cookies: Vec::new(),
    }
}

/// The verification-code step's page: the code input rides on the
/// normal form (it posts back to the reserved path), and the one-time
/// token travels in a short-lived cookie scoped to the auth path.
pub fn code_reply(
    page: &LoginPage,
    host: &str,
    next: &str,
    token_cookie: (String, String),
) -> AuthPathReply {
    AuthPathReply::Handled {
        status: 200,
        content_type: HTML,
        body: render(page, None, true, host, next),
        location: String::new(),
        set_cookies: vec![token_cookie],
    }
}

/// An empty-body redirect with the cookies to set (session issuance,
/// token clearing, logout).
pub fn redirect_reply(location: &str, set_cookies: Vec<(String, String)>) -> AuthPathReply {
    AuthPathReply::Handled {
        status: 302,
        content_type: TEXT,
        body: String::new(),
        location: location.to_owned(),
        set_cookies,
    }
}

/// 退出: clears the site's session cookie and bounces to the root.
pub fn logout_reply(cookie_name: &str) -> AuthPathReply {
    redirect_reply(
        "/",
        vec![(
            cookie_name.to_owned(),
            "; Path=/; HttpOnly; Max-Age=0".to_owned(),
        )],
    )
}

/// The default look's base stylesheet (inline, no external resources).
const BASE_CSS: &str = concat!(
    ":root{color-scheme:light dark}",
    "body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;",
    "font-family:system-ui,sans-serif;background:#f2f4f6;color:#1d2129}",
    "main{width:min(22rem,90vw);box-sizing:border-box;background:#fff;border:1px solid #dcdfe3;border-radius:8px;padding:2rem}",
    "h1{font-size:1.25rem;margin:0 0 .25rem}",
    "p.desc{margin:0 0 1rem;color:#5c6470}",
    "label{display:block;margin:.75rem 0}",
    "input{width:100%;box-sizing:border-box;padding:.5rem;border:1px solid #ccd2d9;border-radius:4px;font:inherit}",
    "button{width:100%;margin-top:1rem;padding:.55rem;border:0;border-radius:4px;background:#1668dc;color:#fff;font:inherit;cursor:pointer}",
    "p.error{margin:0 0 1rem;padding:.5rem .75rem;border-radius:4px;background:#fdecec;color:#c23b3b}",
    "footer{margin-top:1rem;color:#5c6470;font-size:.85rem}",
);

#[cfg(test)]
mod tests {
    use super::*;

    /// A page sitting exactly on every §3.4 limit (all values legal).
    fn boundary_page() -> LoginPage {
        LoginPage {
            style: "default".to_owned(),
            title: "标".repeat(MAX_TITLE_CHARS),
            description: "说".repeat(MAX_DESCRIPTION_CHARS),
            css: "a".repeat(MAX_CSS_BYTES),
            logo: vec![0u8; MAX_LOGO_BYTES],
            background: vec![0u8; MAX_BACKGROUND_BYTES],
            background_dim: MAX_BACKGROUND_DIM,
            hide_footer: false,
        }
    }

    #[test]
    fn login_page_limits_validated() {
        // §6 login_page_limits_validated：每个上限的边界值都合法，九种
        // 内置样式全部接受。
        let legal = boundary_page();
        assert_eq!(validate(&legal), Vec::<String>::new());
        for style in LOGIN_STYLES {
            let mut page = legal.clone();
            page.style = style.to_owned();
            assert!(validate(&page).is_empty(), "样式 {style} 应在合法集合内");
        }

        // 每个上限越界各产生恰好一条问题，其余字段保持合法不动。
        let mut page = legal.clone();
        page.title.push('长');
        let problems = validate(&page);
        assert_eq!(problems.len(), 1, "标题越界应只有一条问题：{problems:?}");
        assert!(
            problems[0].contains("标题"),
            "应指出标题超限：{}",
            problems[0]
        );

        let mut page = legal.clone();
        page.description.push('长');
        let problems = validate(&page);
        assert_eq!(problems.len(), 1, "说明越界应只有一条问题：{problems:?}");
        assert!(
            problems[0].contains("说明"),
            "应指出说明超限：{}",
            problems[0]
        );

        let mut page = legal.clone();
        page.css.push('x');
        let problems = validate(&page);
        assert_eq!(problems.len(), 1, "CSS 越界应只有一条问题：{problems:?}");
        assert!(
            problems[0].contains("CSS"),
            "应指出 CSS 超限：{}",
            problems[0]
        );

        let mut page = legal.clone();
        page.logo.push(0);
        let problems = validate(&page);
        assert_eq!(problems.len(), 1, "Logo 越界应只有一条问题：{problems:?}");
        assert!(
            problems[0].contains("Logo"),
            "应指出 Logo 超限：{}",
            problems[0]
        );

        let mut page = legal.clone();
        page.background.push(0);
        let problems = validate(&page);
        assert_eq!(problems.len(), 1, "背景图越界应只有一条问题：{problems:?}");
        assert!(
            problems[0].contains("背景图"),
            "应指出背景图超限：{}",
            problems[0]
        );

        let mut page = legal.clone();
        page.background_dim += 1;
        let problems = validate(&page);
        assert_eq!(problems.len(), 1, "遮罩越界应只有一条问题：{problems:?}");
        assert!(
            problems[0].contains("遮罩"),
            "应指出遮罩浓度超限：{}",
            problems[0]
        );

        // 非法样式一条问题；多个问题互不影响、全部列出。
        let mut page = legal;
        page.style = "neon".to_owned();
        let problems = validate(&page);
        assert_eq!(problems.len(), 1, "非法样式应只有一条问题：{problems:?}");
        assert!(
            problems[0].contains("neon") && problems[0].contains("样式"),
            "应指出样式未知并列出该值：{}",
            problems[0]
        );

        let page = LoginPage {
            style: "minimal".to_owned(),
            title: "标".repeat(MAX_TITLE_CHARS + 1),
            css: "a".repeat(MAX_CSS_BYTES + 1),
            ..LoginPage::default()
        };
        let problems = validate(&page);
        assert_eq!(
            problems.len(),
            2,
            "标题与 CSS 同时越界应报两条：{problems:?}"
        );
    }

    #[test]
    fn login_page_json_uses_camel_case_and_rejects_unknown() {
        let page = LoginPage {
            style: "terminal".to_owned(),
            background_dim: 40,
            hide_footer: true,
            ..LoginPage::default()
        };
        let json = serde_json::to_string(&page).expect("序列化");
        assert!(json.contains("\"style\":\"terminal\""), "{json}");
        assert!(json.contains("\"backgroundDim\":40"), "{json}");
        assert!(json.contains("\"hideFooter\":true"), "{json}");

        let parsed: LoginPage = serde_json::from_str(&json).expect("camelCase 字段应可解析");
        assert_eq!(parsed, page);

        // 未提供字段回退默认值（style 默认 default）。
        let partial: LoginPage = serde_json::from_str("{\"hideFooter\":true}").expect("部分字段");
        assert_eq!(partial.style, "default");
        assert!(partial.hide_footer);

        // deny_unknown_fields：未知字段拒绝。
        let unknown = serde_json::from_str::<LoginPage>("{\"color\":\"#fff\"}");
        assert!(unknown.is_err(), "未知字段应被拒绝");
    }

    #[test]
    fn render_matches_snapshot() {
        // 默认渲染样例：LoginPage::default() + 固定参数，逐字符相等。
        let page = LoginPage::default();
        let html = render(
            &page,
            Some("用户名或密码错误"),
            true,
            "demo.example.com",
            "/dashboard?a=1&b=2",
        );
        assert_eq!(html, SNAPSHOT_DEFAULT_RENDER);
    }

    #[test]
    fn render_escapes_injected_content() {
        let page = LoginPage {
            title: "<script>alert(1)</script>".to_owned(),
            css: "</style><script>alert(1)</script><style>".to_owned(),
            ..LoginPage::default()
        };
        let html = render(&page, None, false, "evil.example.com", "/");

        // 标题中的 <script> 被转义（title 元素与 h1 各出现一次，
        // 开标签与闭标签各两次）。
        assert!(html.contains("&lt;script&gt;"), "标题应被转义：{html}");
        assert_eq!(html.matches("&lt;script&gt;").count(), 2);
        assert_eq!(html.matches("&lt;/script&gt;").count(), 2);
        // css 中的 < 全部被转义（规格只转义 <，足以让注入的
        // </style> 无法提前闭合标签），出现的是文本 &lt;/style>。
        assert!(html.contains("&lt;/style>"), "css 的 < 应被转义：{html}");
        // 文档里 style 标签数固定：基础样式一份 + 自定义 CSS 一份，
        // 且闭合标签同样只有两份（注入的 </style> 没有生效）。
        assert_eq!(html.matches("<style>").count(), 2);
        assert_eq!(html.matches("</style>").count(), 2);
        // 整个文档没有残留任何未转义的 script 标签。
        assert!(!html.contains("<script>"), "不允许出现未转义脚本：{html}");
    }

    #[test]
    fn render_code_input_form_and_footer_flags() {
        let page = LoginPage::default();

        // need_code：有验证码输入框；否则没有。
        let with_code = render(&page, None, true, "site.example.com", "/");
        assert!(with_code.contains("name=\"code\""), "应有验证码输入框");
        assert!(!render(&page, None, false, "site.example.com", "/").contains("name=\"code\""));

        // 表单 POST 到认证保留路径，next 作为隐藏字段带回。
        assert!(
            with_code.contains("action=\"/__gately_auth\""),
            "表单应提交到 AUTH_PATH"
        );
        assert!(
            with_code.contains("name=\"next\" value=\"/\""),
            "next 应为隐藏字段"
        );

        // hide_footer 省略页脚标识；默认页脚展示访问域名与品牌。
        let hidden = LoginPage {
            hide_footer: true,
            ..LoginPage::default()
        };
        let without_footer = render(&hidden, None, false, "site.example.com", "/");
        assert!(!without_footer.contains("<footer>"), "页脚应被省略");
        assert!(
            with_code.contains("<footer>site.example.com · FerrumGate</footer>"),
            "页脚应含域名与品牌：{with_code}"
        );
    }

    /// Snapshot: the exact default-style render for fixed arguments
    /// (`LoginPage::default()`, error「用户名或密码错误」, `need_code`,
    /// host `demo.example.com`, next `/dashboard?a=1&b=2`).
    const SNAPSHOT_DEFAULT_RENDER: &str = r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>请登录</title>
<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:system-ui,sans-serif;background:#f2f4f6;color:#1d2129}main{width:min(22rem,90vw);box-sizing:border-box;background:#fff;border:1px solid #dcdfe3;border-radius:8px;padding:2rem}h1{font-size:1.25rem;margin:0 0 .25rem}p.desc{margin:0 0 1rem;color:#5c6470}label{display:block;margin:.75rem 0}input{width:100%;box-sizing:border-box;padding:.5rem;border:1px solid #ccd2d9;border-radius:4px;font:inherit}button{width:100%;margin-top:1rem;padding:.55rem;border:0;border-radius:4px;background:#1668dc;color:#fff;font:inherit;cursor:pointer}p.error{margin:0 0 1rem;padding:.5rem .75rem;border-radius:4px;background:#fdecec;color:#c23b3b}footer{margin-top:1rem;color:#5c6470;font-size:.85rem}</style>
</head>
<body>
<main>
<h1>请登录</h1>
<p class="desc">此站点受保护，请输入用户名与密码继续访问。</p>
<p class="error" role="alert">用户名或密码错误</p>
<form method="post" action="/__gately_auth">
<input type="hidden" name="next" value="/dashboard?a=1&amp;b=2">
<label>用户名
<input name="username" autocomplete="username" required></label>
<label>密码
<input type="password" name="password" autocomplete="current-password" required></label>
<label>验证码
<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
<button type="submit">登录</button>
</form>
</main>
<footer>demo.example.com · FerrumGate</footer>
</body>
</html>
"#;
}

#[cfg(test)]
mod handling_tests {
    use super::*;

    #[test]
    fn safe_next_keeps_site_relative_targets_only() {
        // §3.3：next 只接受站内相对路径；越界一律回落 /。
        assert_eq!(safe_next("/dashboard?a=1&b=2"), "/dashboard?a=1&b=2");
        assert_eq!(safe_next("/"), "/");
        assert_eq!(safe_next("//evil.test"), "/");
        assert_eq!(safe_next("/\\evil.test"), "/");
        assert_eq!(safe_next("https://evil.test"), "/");
        assert_eq!(safe_next(""), "/");
        // 控制字符（包括 \n 伪造的头注入）不可接受。
        assert_eq!(safe_next("/a\nX: y"), "/");
    }

    #[test]
    fn origin_host_parses_scheme_port_and_null() {
        assert_eq!(
            origin_host(Some("http://a.test")).as_deref(),
            Some("a.test")
        );
        assert_eq!(
            origin_host(Some("https://A.test:8443/path?x=1")).as_deref(),
            Some("a.test")
        );
        assert_eq!(
            origin_host(Some("http://[2001:db8::1]:8080/")).as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(origin_host(None), None);
        assert_eq!(origin_host(Some("")), None);
        assert_eq!(origin_host(Some("null")), None);
        assert_eq!(origin_host(Some("http://")).as_deref(), None);
    }

    #[test]
    fn form_fields_round_trip_through_the_encodings() {
        // 表单体：+ 是空格，%XX 逐字节解码。
        let form = parse_login_form(
            b"next=%2Fdash%3Fa%3D1%26b%3D2&username=ali+ce&password=pa%3Ass&code=123456",
        );
        assert_eq!(form.next, "/dash?a=1&b=2");
        assert_eq!(form.username, "ali ce");
        assert_eq!(form.password, "pa:ss");
        assert_eq!(form.code, "123456");

        // 空体与未知字段安全。
        assert_eq!(parse_login_form(b""), LoginForm::default());
        assert_eq!(parse_login_form(b"junk&x=1").username, "");

        // 查询里的 next 解码后再做安全检查。
        assert_eq!(next_from_query("next=%2Fhtml"), "/html");
        assert_eq!(next_from_query("next=%2F%2Fevil"), "/");
        assert_eq!(next_from_query(""), "/");

        // encode_next：/ 与未保留字符原样，&=? 编码（不破坏查询）。
        assert_eq!(encode_next("/"), "/");
        assert_eq!(encode_next("/a?b=1&c=2"), "/a%3Fb%3D1%26c%3D2");
        assert_eq!(encode_next("/组"), "/%E7%BB%84");
    }

    #[test]
    fn replies_carry_status_cookies_and_redirects() {
        let page = LoginPage::default();
        // 登录页 200、无 Cookie、无跳转。
        let reply = page_reply(&page, None, false, "h.test", "/");
        let AuthPathReply::Handled {
            status,
            content_type,
            location,
            set_cookies,
            ..
        } = reply
        else {
            panic!("page reply must be Handled");
        };
        assert_eq!(status, 200);
        assert_eq!(content_type, "text/html; charset=utf-8");
        assert!(location.is_empty());
        assert!(set_cookies.is_empty());

        // 退出：清 Cookie 并回根。
        let AuthPathReply::Handled {
            status,
            location,
            set_cookies,
            ..
        } = logout_reply("gately_site_x")
        else {
            panic!("logout reply must be Handled");
        };
        assert_eq!(status, 302);
        assert_eq!(location, "/");
        assert_eq!(
            set_cookies,
            vec![(
                "gately_site_x".to_owned(),
                "; Path=/; HttpOnly; Max-Age=0".to_owned()
            )]
        );
    }
}

