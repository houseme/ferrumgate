//! 托管进程输出的清理、分级与打码（WP-43 §3.3，纯逻辑）：
//!
//! - [`clean`]：按行拆分后去掉颜色码、回车与行首时间戳；
//! - [`classify`]：按 frp（`[I]` `[W]` `[E]`）与 cloudflared（`INF` `WRN`
//!   `ERR`）等已知日志格式判断级别，未知格式按信息级别；
//! - [`mask_url_paths`]：把一行中网址的路径与查询部分换成 `********`，只
//!   保留协议与主机——Tailscale、NetBird 的登录链接路径里带一次性令牌，
//!   不应进入日志。

use std::borrow::Cow;

use fg_logging::Level;

/// 每行输出的处理结果：级别与清理打码后的文本。
pub fn process_line(raw: &str) -> (Level, String) {
    let cleaned = clean(raw);
    let level = classify(&cleaned);
    let masked = mask_url_paths(&cleaned);
    (level, masked.into_owned())
}

/// 去掉 ANSI 颜色码、回车、行尾换行与行首时间戳。
pub fn clean(line: &str) -> String {
    let stripped = strip_colors(line).into_owned();
    let stripped = if stripped.contains('\r') {
        stripped.chars().filter(|&c| c != '\r').collect::<String>()
    } else {
        stripped
    };
    strip_timestamp(stripped.trim_end_matches('\n')).into_owned()
}

/// 去掉 ESC 控制序列（`ESC [ … <终止字节>`）与孤立的 ESC。
fn strip_colors(line: &str) -> Cow<'_, str> {
    if !line.contains('\u{1b}') {
        return Cow::Borrowed(line);
    }
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // CSI 序列：ESC [ 参数… 终止字节（0x40..=0x7E）。
        if chars.peek() == Some(&'[') {
            let _ = chars.next();
            for c in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    break;
                }
            }
        }
    }
    Cow::Owned(out)
}

/// 识别并去掉行首时间戳，支持 `2024-01-02T03:04:05Z`、
/// `2024-01-02 03:04:05.123+08:00`、`2024/01/02 03:04:05` 这类前缀。
fn strip_timestamp(line: &str) -> Cow<'_, str> {
    let bytes = line.as_bytes();
    if bytes.len() < 19 {
        return Cow::Borrowed(line);
    }
    let digit = |b: u8| b.is_ascii_digit();
    let dash = bytes[4] == b'-' && bytes[7] == b'-';
    let slash = bytes[4] == b'/' && bytes[7] == b'/';
    let date_digits = bytes[0..4].iter().all(|&b| digit(b))
        && digit(bytes[5])
        && digit(bytes[6])
        && digit(bytes[8])
        && digit(bytes[9]);
    if !(date_digits && (dash || slash)) {
        return Cow::Borrowed(line);
    }
    // 日期之后必须是 'T' 或空格（slash 形式固定为空格）。
    let sep = bytes[10];
    if !(sep == b' ' || (dash && sep == b'T')) {
        return Cow::Borrowed(line);
    }
    if !bytes[11..19].iter().copied().enumerate().all(|(i, b)| {
        if matches!(i, 2 | 5) {
            b == b':'
        } else {
            digit(b)
        }
    }) {
        return Cow::Borrowed(line);
    }
    let mut end = 19usize;
    // 小数秒。
    if bytes.get(end) == Some(&b'.') {
        end += 1;
        while bytes.get(end).is_some_and(|&b| digit(b)) {
            end += 1;
        }
    }
    // 时区：Z 或 ±hh:mm。
    match bytes.get(end) {
        Some(b'Z') => end += 1,
        Some(b'+') | Some(b'-') => {
            let rest = &bytes[end + 1..];
            if rest.len() >= 5
                && digit(rest[0])
                && digit(rest[1])
                && rest[2] == b':'
                && digit(rest[3])
                && digit(rest[4])
            {
                end += 6;
            } else {
                return Cow::Borrowed(line);
            }
        }
        _ => {}
    }
    // 时间戳后必须跟一个空格才算前缀。
    if bytes.get(end) != Some(&b' ') {
        return Cow::Borrowed(line);
    }
    Cow::Borrowed(&line[end + 1..])
}

/// 按已知日志格式判断级别：frp 风格 `[I]` `[W]` `[E]`（`[D]` `[F]` 一并
/// 处理）、cloudflared 风格 `INF` `WRN` `ERR`（`DBG` `FATAL` 一并处理），
/// 以及常见英文词 `INFO` `WARN` `ERROR`；未知格式按信息级别。
pub fn classify(line: &str) -> Level {
    let bytes = line.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] == b'[' {
            let level = match bytes[i + 1] {
                b'E' | b'F' => Some(Level::Error),
                b'W' => Some(Level::Warn),
                b'D' => Some(Level::Debug),
                b'I' => Some(Level::Info),
                _ => None,
            };
            if let Some(level) = level.filter(|_| bytes[i + 2] == b']') {
                return level;
            }
        }
    }
    for (token, level) in [
        ("ERROR", Level::Error),
        ("FATAL", Level::Error),
        ("ERR", Level::Error),
        ("WARNING", Level::Warn),
        ("WARN", Level::Warn),
        ("WRN", Level::Warn),
        ("DEBUG", Level::Debug),
        ("DBG", Level::Debug),
        ("INFO", Level::Info),
        ("INF", Level::Info),
    ] {
        if contains_token(line, token) {
            return level;
        }
    }
    Level::Info
}

/// 词边界形式的子串匹配：命中位置两侧必须不是字母或数字，避免把
/// "INFORMATION" 这类普通词当成级别标记。
fn contains_token(line: &str, token: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = line[from..].find(token) {
        let start = from + pos;
        let end = start + token.len();
        let before_ok = line[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
        let after_ok = line[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// 把一行中每个网址的路径与查询部分换成 `********`，只保留协议与主机。
pub fn mask_url_paths(line: &str) -> Cow<'_, str> {
    let mut out: Option<String> = None;
    let mut copied_until = 0usize;
    let mut search_from = 0usize;
    while let Some(at) = line[search_from..]
        .find("http://")
        .or_else(|| line[search_from..].find("https://"))
    {
        let start = search_from + at;
        let scheme_end = start + line[start..].find("://").expect("scheme found above") + 3;
        // 主机到第一个 '/' 或 '?'；分隔符集合之外都是 URL 的一部分。
        let url_end = line[scheme_end..]
            .find([' ', '\t', '"', '\'', ')', ']', '}', ','])
            .map(|end| scheme_end + end)
            .unwrap_or(line.len());
        let out = out.get_or_insert_with(|| String::with_capacity(line.len()));
        match line[scheme_end..url_end].find(['/', '?']) {
            Some(path_at) => {
                let keep_to = scheme_end + path_at;
                out.push_str(&line[copied_until..start]);
                // 路径开头的斜杠保留，可读性更好；查询从 '?' 处直接打码。
                if line.as_bytes()[keep_to] == b'/' {
                    out.push_str(&line[start..=keep_to]);
                } else {
                    out.push_str(&line[start..keep_to]);
                }
                out.push_str("********");
            }
            None => {
                // 只有主机名，没有路径与查询，原样保留。
                out.push_str(&line[copied_until..url_end]);
            }
        }
        copied_until = url_end;
        search_from = url_end;
    }
    match out {
        Some(mut out) => {
            out.push_str(&line[copied_until..]);
            Cow::Owned(out)
        }
        None => Cow::Borrowed(line),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_clean_strips_colors_cr_timestamps() {
        assert_eq!(clean("\u{1b}[31mred\u{1b}[0m text"), "red text");
        assert_eq!(clean("plain\r\n"), "plain");
        assert_eq!(clean("plain\rline"), "plainline");
        assert_eq!(clean("2024/01/02 15:04:05 [I] hello"), "[I] hello");
        assert_eq!(clean("2024-01-02 03:04:05.123 world"), "world");
        assert_eq!(clean("2024-01-02T03:04:05Z done"), "done");
        assert_eq!(clean("2024-01-02T03:04:05+08:00 done"), "done");
        assert_eq!(clean("no timestamp here"), "no timestamp here");
        // 数字开头的普通内容不能误伤。
        assert_eq!(clean("2024 bytes transferred"), "2024 bytes transferred");
    }

    #[test]
    fn output_classify_frp_and_cloudflared() {
        assert_eq!(
            classify("2024/01/02 15:04:05 [I] [proxy.go:123] start"),
            Level::Info
        );
        assert_eq!(classify("[W] [proxy.go:88] slow"), Level::Warn);
        assert_eq!(classify("[E] [proxy.go:99] connect failed"), Level::Error);
        assert_eq!(
            classify("2024-01-02T00:00:00Z INF connection registered"),
            Level::Info
        );
        assert_eq!(
            classify("2024-01-02T00:00:00Z WRN fallback to udp"),
            Level::Warn
        );
        assert_eq!(
            classify("2024-01-02T00:00:00.000Z ERR failed to serve"),
            Level::Error
        );
        assert_eq!(classify("FATAL: bad config"), Level::Error);
        assert_eq!(classify("ordinary line"), Level::Info, "未知格式按信息级别");
        // 词边界：普通单词不算级别标记。
        assert_eq!(classify("INFORMATION about the outage"), Level::Info);
    }

    #[test]
    fn output_mask_url_paths_and_query() {
        // 登录链接的路径与查询（一次性令牌）被打码，协议与主机保留。
        assert_eq!(
            mask_url_paths(
                "2024-01-02T00:00:00Z INF login: https://login.tailscale.com/a/abc123def"
            ),
            "2024-01-02T00:00:00Z INF login: https://login.tailscale.com/********"
        );
        assert_eq!(
            mask_url_paths("open http://10.1.2.3:8000/login?token=secret now"),
            "open http://10.1.2.3:8000/******** now"
        );
        assert_eq!(
            mask_url_paths("visit https://example.com and https://other.com/x?y=1"),
            "visit https://example.com and https://other.com/********"
        );
        // 只有主机名不打码。
        assert_eq!(
            mask_url_paths("dial https://example.com failed"),
            "dial https://example.com failed"
        );
        // 没有 URL 原样返回。
        assert_eq!(
            mask_url_paths("no urls in this line"),
            "no urls in this line"
        );
    }
}
