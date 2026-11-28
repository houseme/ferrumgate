//! HTML sanitizer for custom error pages (WP-27 §3.3, aligned with WP-14).
//!
//! Strips active scripts, embedded frames/plugins/forms/base/meta-refresh,
//! inline `on*` event attributes, dangerous URI schemes (`javascript:`,
//! `vbscript:`, `data:text/html`), and dangerous CSS (`expression()`,
//! `url(javascript:...)`, `@import`, `behavior:`, `-moz-binding`).
//!
//! Custom pages are also always served under [`ERROR_PAGE_CSP`] as a second
//! defense-in-depth sandbox layer.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Maximum accepted custom error page size (256 KiB).
pub const MAX_CUSTOM_PAGE_BYTES: usize = 256 * 1024;

/// Defense-in-depth sandbox Content-Security-Policy attached to rendered error
/// pages (WP-27 §3.3).
pub const ERROR_PAGE_CSP: &str = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; media-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'";

/// Known placeholder tokens rendered on error pages.
pub const PLACEHOLDERS: [&str; 7] = [
    "{code}", "{status}", "{title}", "{detail}", "{host}", "{path}", "{time}",
];

/// Output of [`sanitize`]: the cleaned HTML together with a report of removed
/// dangerous constructs and non-fatal advisory warnings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sanitized {
    pub html: String,
    pub removed: Vec<String>,
    pub warnings: Vec<String>,
}

static RE_HAS_HTML_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<(?:!doctype\b|[a-z][a-z0-9-]*\b)[^>]*>").unwrap());

static RE_PAIRED_DANGEROUS: LazyLock<Vec<(Regex, Regex, &'static str)>> = LazyLock::new(|| {
    [
        ("script", "<script>"),
        ("iframe", "<iframe>"),
        ("object", "<object>"),
        ("applet", "<applet>"),
        ("form", "<form>"),
    ]
    .into_iter()
    .map(|(tag, label)| {
        let paired = Regex::new(&format!(r"(?is)<{tag}\b[^>]*>.*?</{tag}\s*>")).unwrap();
        let dangling = Regex::new(&format!(r"(?is)</?{tag}\b[^>]*>")).unwrap();
        (paired, dangling, label)
    })
    .collect()
});

static RE_VOID_DANGEROUS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (Regex::new(r"(?is)</?embed\b[^>]*>").unwrap(), "<embed>"),
        (Regex::new(r"(?is)</?base\b[^>]*>").unwrap(), "<base>"),
        (
            Regex::new(r"(?is)<meta\b[^>]*\bhttp-equiv\b[^>]*>").unwrap(),
            "<meta http-equiv>",
        ),
    ]
});

static RE_HTML_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<[a-z][a-z0-9:-]*\b[^>]*>").unwrap());

static RE_EVENT_ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:[\s/]+)on[a-z][a-z0-9_-]*\s*=\s*(?:"[^"]*"|'[^']*'|[^\s/>]+)"#).unwrap()
});

static RE_URI_ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)(?:[\s/]+)(href|src|action|formaction|xlink:href|data|poster|background|cite|longdesc)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s/>]+))"#,
    )
    .unwrap()
});

static RE_STYLE_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)(<style\b[^>]*>)(.*?)(</style\s*>)").unwrap());

static RE_STYLE_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)(\bstyle\s*=\s*)(?:"([^"]*)"|'([^']*)')"#).unwrap());

static RE_CSS_EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)expression\s*\([^)]*\)").unwrap());

static RE_CSS_BAD_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)url\s*\(\s*['"]?\s*(?:javascript|vbscript|data\s*:\s*text/html)\s*:[^)]*\)"#)
        .unwrap()
});

static RE_CSS_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)@import\b[^;}\n]*;?").unwrap());

static RE_CSS_BEHAVIOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:-moz-binding|\bbehavior)\s*:[^;}"']*;?"#).unwrap());

static RE_META_VIEWPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<meta\b[^>]*\bname\s*=\s*['"]?viewport\b[^>]*>"#).unwrap());

static RE_META_CHARSET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<meta\b[^>]*\bcharset\s*=\s*['"]?([a-z0-9_-]+)"#).unwrap());

fn push_unique(list: &mut Vec<String>, item: impl Into<String>) {
    let item = item.into();
    if !list.contains(&item) {
        list.push(item);
    }
}

/// Validates and sanitizes raw bytes (rejects invalid UTF-8, > 256 KiB, empty,
/// or non-HTML inputs).
pub fn sanitize_bytes(bytes: &[u8]) -> Result<Sanitized, Vec<String>> {
    if bytes.is_empty() {
        return Err(vec!["error page content cannot be empty".to_owned()]);
    }
    if bytes.len() > MAX_CUSTOM_PAGE_BYTES {
        return Err(vec![format!(
            "error page exceeds {} byte limit",
            MAX_CUSTOM_PAGE_BYTES
        )]);
    }
    let html = std::str::from_utf8(bytes)
        .map_err(|_| vec!["error page must be valid UTF-8".to_owned()])?;
    sanitize(html)
}

/// Sanitizes operator-supplied HTML for use as a custom error page (WP-27 §3.2).
///
/// Rejects (`Err`) when the input is empty, exceeds 256 KiB, or does not look
/// like HTML. Otherwise strips dangerous elements, event attributes, URI
/// schemes, and CSS directives, reporting what was removed and any warnings.
pub fn sanitize(html: &str) -> Result<Sanitized, Vec<String>> {
    let mut errors = Vec::new();
    if html.trim().is_empty() {
        errors.push("error page content cannot be empty".to_owned());
    }
    if html.len() > MAX_CUSTOM_PAGE_BYTES {
        errors.push(format!(
            "error page exceeds {} byte limit",
            MAX_CUSTOM_PAGE_BYTES
        ));
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    if !RE_HAS_HTML_TAG.is_match(html) {
        return Err(vec!["content does not appear to be valid HTML".to_owned()]);
    }

    let mut cleaned = html.to_owned();
    let mut removed = Vec::new();

    // 1. Strip paired dangerous elements (including inner content) + any dangling tags.
    for (paired, dangling, label) in RE_PAIRED_DANGEROUS.iter() {
        if paired.is_match(&cleaned) {
            cleaned = paired.replace_all(&cleaned, "").into_owned();
            push_unique(&mut removed, *label);
        }
        if dangling.is_match(&cleaned) {
            cleaned = dangling.replace_all(&cleaned, "").into_owned();
            push_unique(&mut removed, *label);
        }
    }

    // 2. Strip void dangerous elements (<embed>, <base>, <meta http-equiv>).
    for (re, label) in RE_VOID_DANGEROUS.iter() {
        if re.is_match(&cleaned) {
            cleaned = re.replace_all(&cleaned, "").into_owned();
            push_unique(&mut removed, *label);
        }
    }

    // 3. Inside every remaining HTML tag, strip `on*` event attributes,
    // dangerous URI schemes, and dangerous inline `style="..."` CSS.
    cleaned = RE_HTML_TAG
        .replace_all(&cleaned, |caps: &regex::Captures<'_>| {
            let mut tag = caps[0].to_owned();

            if RE_EVENT_ATTR.is_match(&tag) {
                tag = RE_EVENT_ATTR.replace_all(&tag, "").into_owned();
                push_unique(&mut removed, "on* event attribute");
            }

            tag = RE_URI_ATTR
                .replace_all(&tag, |attr_caps: &regex::Captures<'_>| {
                    let raw_val = attr_caps
                        .get(2)
                        .or_else(|| attr_caps.get(3))
                        .or_else(|| attr_caps.get(4))
                        .map_or("", |m| m.as_str());
                    if let Some(scheme_label) = dangerous_uri_scheme(raw_val) {
                        push_unique(&mut removed, scheme_label);
                        String::new()
                    } else {
                        attr_caps[0].to_owned()
                    }
                })
                .into_owned();

            tag = RE_STYLE_ATTR
                .replace_all(&tag, |style_caps: &regex::Captures<'_>| {
                    let prefix = &style_caps[1];
                    let (quote, val) = if let Some(m) = style_caps.get(2) {
                        ('"', m.as_str())
                    } else if let Some(m) = style_caps.get(3) {
                        ('\'', m.as_str())
                    } else {
                        return style_caps[0].to_owned();
                    };
                    let sanitized_css = sanitize_css(val, &mut removed);
                    format!("{prefix}{quote}{sanitized_css}{quote}")
                })
                .into_owned();

            tag
        })
        .into_owned();

    // 4. Sanitize `<style>...</style>` blocks.
    cleaned = RE_STYLE_BLOCK
        .replace_all(&cleaned, |caps: &regex::Captures<'_>| {
            let open = &caps[1];
            let css = &caps[2];
            let close = &caps[3];
            let sanitized_css = sanitize_css(css, &mut removed);
            format!("{open}{sanitized_css}{close}")
        })
        .into_owned();

    // 5. Collect non-blocking advisory warnings.
    let mut warnings = Vec::new();
    if !RE_META_VIEWPORT.is_match(&cleaned) {
        warnings.push("missing <meta name=\"viewport\"> for mobile screens".to_owned());
    }
    for caps in RE_META_CHARSET.captures_iter(&cleaned) {
        if let Some(cs) = caps.get(1) {
            let val = cs.as_str().to_ascii_lowercase();
            if val != "utf-8" && val != "utf8" {
                push_unique(
                    &mut warnings,
                    format!("non-UTF-8 charset declaration: {val}"),
                );
            }
        }
    }
    if !PLACEHOLDERS.iter().any(|ph| cleaned.contains(ph)) {
        warnings
            .push("page does not use any dynamic placeholders ({code}, {title}, etc.)".to_owned());
    }

    Ok(Sanitized {
        html: cleaned,
        removed,
        warnings,
    })
}

fn dangerous_uri_scheme(raw: &str) -> Option<&'static str> {
    // Strip ASCII whitespace and control characters that browsers ignore
    // inside URL schemes (e.g. `java\tscript:`).
    let normalized: String = raw
        .chars()
        .filter(|c| !c.is_ascii_control() && !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if normalized.starts_with("javascript:") {
        Some("javascript: URI")
    } else if normalized.starts_with("vbscript:") {
        Some("vbscript: URI")
    } else if normalized.starts_with("data:text/html") {
        Some("data:text/html URI")
    } else {
        None
    }
}

fn sanitize_css(css: &str, removed: &mut Vec<String>) -> String {
    let mut out = css.to_owned();
    if RE_CSS_EXPRESSION.is_match(&out) {
        out = RE_CSS_EXPRESSION.replace_all(&out, "").into_owned();
        push_unique(removed, "CSS expression()");
    }
    if RE_CSS_BAD_URL.is_match(&out) {
        out = RE_CSS_BAD_URL.replace_all(&out, "").into_owned();
        push_unique(removed, "CSS dangerous url()");
    }
    if RE_CSS_IMPORT.is_match(&out) {
        out = RE_CSS_IMPORT.replace_all(&out, "").into_owned();
        push_unique(removed, "CSS @import");
    }
    if RE_CSS_BEHAVIOR.is_match(&out) {
        out = RE_CSS_BEHAVIOR.replace_all(&out, "").into_owned();
        push_unique(removed, "CSS behavior/-moz-binding");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_scripts_and_handlers() {
        let dirty = r#"<!DOCTYPE html>
<html>
<head>
<meta charset="latin1">
<meta http-equiv="refresh" content="0;url=https://evil.test">
<base href="https://evil.test/">
<style>
@import url("https://evil.test/a.css");
body { color: #222; background: url(javascript:alert(1)); width: expression(alert(2)); }
</style>
</head>
<body onload="evil()">
<h1 onclick='steal()' onmouseover=bad()>{code}</h1>
<script>alert('xss')</script>
<iframe src="https://evil.test"></iframe>
<object data="x"></object>
<embed src="x">
<applet code="x"></applet>
<form action="/steal"><input name="p"></form>
<a href="javascript:alert(3)">click</a>
<a href="vbscript:msgbox(1)">vb</a>
<a href="data:text/html,<script>alert(4)</script>">data</a>
<img src="data:image/png;base64,iVBORw0KGgo=" alt="ok">
</body>
</html>"#;

        let res = sanitize(dirty).expect("sanitizes valid HTML");
        let lower = res.html.to_ascii_lowercase();
        assert!(!lower.contains("<script"));
        assert!(!lower.contains("alert("));
        assert!(!lower.contains("<iframe"));
        assert!(!lower.contains("<object"));
        assert!(!lower.contains("<embed"));
        assert!(!lower.contains("<applet"));
        assert!(!lower.contains("<form"));
        assert!(!lower.contains("<base"));
        assert!(!lower.contains("http-equiv"));
        assert!(!lower.contains("onload="));
        assert!(!lower.contains("onclick="));
        assert!(!lower.contains("onmouseover="));
        assert!(!lower.contains("javascript:"));
        assert!(!lower.contains("vbscript:"));
        assert!(!lower.contains("data:text/html"));
        assert!(!lower.contains("@import"));
        assert!(!lower.contains("expression("));
        // Safe data:image/png and safe CSS are preserved.
        assert!(res.html.contains("data:image/png;base64,iVBORw0KGgo="));
        assert!(res.html.contains("color: #222"));
        assert!(res.html.contains("{code}"));

        // Removed list reports each stripped category.
        assert!(res.removed.iter().any(|r| r == "<script>"));
        assert!(res.removed.iter().any(|r| r == "<iframe>"));
        assert!(res.removed.iter().any(|r| r == "on* event attribute"));
        assert!(res.removed.iter().any(|r| r == "javascript: URI"));
        assert!(res.removed.iter().any(|r| r == "CSS @import"));
        assert!(res.removed.iter().any(|r| r == "CSS expression()"));

        // Warnings report missing viewport and non-UTF-8 charset.
        assert!(res.warnings.iter().any(|w| w.contains("viewport")));
        assert!(res.warnings.iter().any(|w| w.contains("non-UTF-8")));
    }

    #[test]
    fn sanitize_rejects_empty_non_html_oversized_and_bad_utf8() {
        assert!(sanitize("").is_err());
        assert!(sanitize("   \n\t ").is_err());
        assert!(sanitize("just plain text without tags").is_err());
        let huge = format!("<html>{}</html>", "a".repeat(MAX_CUSTOM_PAGE_BYTES));
        assert!(sanitize(&huge).is_err());
        assert!(sanitize_bytes(&[0xff, 0xfe, 0xfd]).is_err());
    }

    #[test]
    fn sanitize_clean_html_has_no_removals_or_warnings() {
        let clean = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><h1>{code} {title}</h1><p>{detail}</p></body></html>"#;
        let res = sanitize(clean).unwrap();
        assert!(res.removed.is_empty(), "removed: {:?}", res.removed);
        assert!(res.warnings.is_empty(), "warnings: {:?}", res.warnings);
    }
}
