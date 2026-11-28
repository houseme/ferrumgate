//! Pure-function ModSecurity transformation chain (WP-55 step E3).
//!
//! Every transformation is linear-time, allocation-bounded, and safe on
//! arbitrary UTF-8 inputs.

/// Supported ModSecurity `t:*` transformation functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transform {
    None,
    Lowercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    RemoveNulls,
    RemoveWhitespace,
    ReplaceComments,
    CompressWhitespace,
    NormalizePath,
    NormalizePathWin,
    CmdLine,
    HexDecode,
    HexEncode,
    EscapeSeqDecode,
    Length,
    Trim,
    TrimLeft,
    TrimRight,
    RemoveComments,
    RemoveCommentsChar,
}

impl Transform {
    /// Parses a SecLang transformation name (ASCII case-insensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "lowercase" => Some(Self::Lowercase),
            "urldecode" => Some(Self::UrlDecode),
            "urldecodeuni" => Some(Self::UrlDecodeUni),
            "htmlentitydecode" => Some(Self::HtmlEntityDecode),
            "jsdecode" => Some(Self::JsDecode),
            "cssdecode" => Some(Self::CssDecode),
            "removenulls" => Some(Self::RemoveNulls),
            "removewhitespace" => Some(Self::RemoveWhitespace),
            "replacecomments" => Some(Self::ReplaceComments),
            "compresswhitespace" => Some(Self::CompressWhitespace),
            "normalisepath" | "normalizepath" => Some(Self::NormalizePath),
            "normalisepathwin" | "normalizepathwin" => Some(Self::NormalizePathWin),
            "cmdline" => Some(Self::CmdLine),
            "hexdecode" => Some(Self::HexDecode),
            "hexencode" => Some(Self::HexEncode),
            "escapeseqdecode" => Some(Self::EscapeSeqDecode),
            "length" => Some(Self::Length),
            "trim" => Some(Self::Trim),
            "trimleft" => Some(Self::TrimLeft),
            "trimright" => Some(Self::TrimRight),
            "removecomments" => Some(Self::RemoveComments),
            "removecommentschar" => Some(Self::RemoveCommentsChar),
            _ => None,
        }
    }
}

/// Applies a single ModSecurity transformation to `input`.
pub fn apply_transform(transform: Transform, input: &str) -> String {
    match transform {
        Transform::None => input.to_owned(),
        Transform::Lowercase => input.to_ascii_lowercase(),
        Transform::UrlDecode => url_decode(input, false),
        Transform::UrlDecodeUni => url_decode(input, true),
        Transform::HtmlEntityDecode => html_entity_decode(input),
        Transform::JsDecode => js_decode(input),
        Transform::CssDecode => css_decode(input),
        Transform::RemoveNulls => input.replace('\0', ""),
        Transform::RemoveWhitespace => remove_whitespace(input),
        Transform::ReplaceComments => replace_comments(input),
        Transform::CompressWhitespace => compress_whitespace(input),
        Transform::NormalizePath => normalize_path(input),
        Transform::NormalizePathWin => normalize_path(&input.replace('\\', "/")),
        Transform::CmdLine => cmd_line(input),
        Transform::HexDecode => hex_decode(input),
        Transform::HexEncode => hex_encode(input),
        Transform::EscapeSeqDecode => escape_seq_decode(input),
        Transform::Length => input.len().to_string(),
        Transform::Trim => input.trim().to_owned(),
        Transform::TrimLeft => input.trim_start().to_owned(),
        Transform::TrimRight => input.trim_end().to_owned(),
        Transform::RemoveComments => remove_comments(input),
        Transform::RemoveCommentsChar => remove_comments_char(input),
    }
}

/// Applies a chain of transformations in order.
pub fn apply_transforms(transforms: &[Transform], input: &str) -> String {
    if transforms.is_empty() {
        return input.to_owned();
    }
    let mut current = input.to_owned();
    for &t in transforms {
        if t == Transform::None {
            continue;
        }
        current = apply_transform(t, &current);
    }
    current
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn url_decode(input: &str, unicode: bool) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if unicode
                    && i + 5 < len
                    && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U')
                    && let (Some(h0), Some(h1), Some(h2), Some(h3)) = (
                        hex_val(bytes[i + 2]),
                        hex_val(bytes[i + 3]),
                        hex_val(bytes[i + 4]),
                        hex_val(bytes[i + 5]),
                    )
                {
                    let code =
                        ((h0 as u32) << 12) | ((h1 as u32) << 8) | ((h2 as u32) << 4) | (h3 as u32);
                    // IIS fullwidth mapping: U+FF01..=U+FF5E -> ASCII 0x21..=0x7E.
                    if (0xFF01..=0xFF5E).contains(&code) {
                        out.push((code - 0xFF00 + 0x20) as u8);
                    } else if code <= 0xFF {
                        out.push(code as u8);
                    } else if let Some(ch) = char::from_u32(code) {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    } else {
                        out.push((code & 0xFF) as u8);
                    }
                    i += 6;
                    continue;
                }
                if i + 2 < len
                    && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
                {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

fn html_entity_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'&'
            && let Some((decoded, consumed)) = decode_html_entity(&input[i..])
        {
            out.push(decoded);
            i += consumed;
            continue;
        }
        let ch = input[i..].chars().next().expect("valid utf-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn decode_html_entity(s: &str) -> Option<(char, usize)> {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes[0] != b'&' {
        return None;
    }

    if bytes[1] == b'#' {
        // Numeric entity: `&#NNN;` or `&#xHHH;` (semicolon optional per ModSecurity).
        let is_hex = bytes.len() > 2 && (bytes[2] == b'x' || bytes[2] == b'X');
        let start = if is_hex { 3 } else { 2 };
        let mut j = start;
        let mut val: u32 = 0;
        let mut digits = 0usize;
        while j < bytes.len() && digits < 8 {
            let d = if is_hex {
                hex_val(bytes[j])
            } else if bytes[j].is_ascii_digit() {
                Some(bytes[j] - b'0')
            } else {
                None
            };
            let Some(d) = d else { break };
            val = val
                .saturating_mul(if is_hex { 16 } else { 10 })
                .saturating_add(d as u32);
            j += 1;
            digits += 1;
        }
        if digits == 0 {
            return None;
        }
        let consumed = if j < bytes.len() && bytes[j] == b';' {
            j + 1
        } else {
            j
        };
        let ch = char::from_u32(val).unwrap_or(char::REPLACEMENT_CHARACTER);
        return Some((ch, consumed));
    }

    // Named entities (case-insensitive match up to 8 ASCII letters).
    let mut j = 1;
    while j < bytes.len() && j < 10 && bytes[j].is_ascii_alphabetic() {
        j += 1;
    }
    let name = &s[1..j];
    let has_semi = j < bytes.len() && bytes[j] == b';';
    let consumed = if has_semi { j + 1 } else { j };
    let decoded = match name.to_ascii_lowercase().as_str() {
        "quot" => '"',
        "apos" => '\'',
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "nbsp" => '\u{00A0}',
        _ => return None,
    };
    Some((decoded, consumed))
}

fn js_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            let next = bytes[i + 1];
            match next {
                b'u' if i + 5 < len => {
                    if let (Some(h0), Some(h1), Some(h2), Some(h3)) = (
                        hex_val(bytes[i + 2]),
                        hex_val(bytes[i + 3]),
                        hex_val(bytes[i + 4]),
                        hex_val(bytes[i + 5]),
                    ) {
                        let code = ((h0 as u32) << 12)
                            | ((h1 as u32) << 8)
                            | ((h2 as u32) << 4)
                            | (h3 as u32);
                        if let Some(ch) = char::from_u32(code) {
                            out.push(ch);
                        }
                        i += 6;
                        continue;
                    }
                }
                b'x' if i + 3 < len => {
                    if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                        out.push(((hi << 4) | lo) as char);
                        i += 4;
                        continue;
                    }
                }
                b'0'..=b'7' => {
                    let mut val: u32 = (next - b'0') as u32;
                    let mut consumed = 2;
                    for k in 0..2 {
                        let idx = i + 2 + k;
                        if idx < len && (b'0'..=b'7').contains(&bytes[idx]) {
                            let next_val = (val << 3) | ((bytes[idx] - b'0') as u32);
                            if next_val <= 0xFF {
                                val = next_val;
                                consumed += 1;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    out.push((val as u8) as char);
                    i += consumed;
                    continue;
                }
                b'a' => {
                    out.push('\x07');
                    i += 2;
                    continue;
                }
                b'b' => {
                    out.push('\x08');
                    i += 2;
                    continue;
                }
                b'f' => {
                    out.push('\x0c');
                    i += 2;
                    continue;
                }
                b'n' => {
                    out.push('\n');
                    i += 2;
                    continue;
                }
                b'r' => {
                    out.push('\r');
                    i += 2;
                    continue;
                }
                b't' => {
                    out.push('\t');
                    i += 2;
                    continue;
                }
                b'v' => {
                    out.push('\x0b');
                    i += 2;
                    continue;
                }
                b'\\' | b'\'' | b'"' | b'/' => {
                    out.push(next as char);
                    i += 2;
                    continue;
                }
                _ => {
                    // JS drops the backslash before non-special characters.
                    let ch = input[i + 1..].chars().next().expect("valid utf-8");
                    out.push(ch);
                    i += 1 + ch.len_utf8();
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().expect("valid utf-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn css_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            if hex_val(bytes[i + 1]).is_some() {
                let mut val: u32 = 0;
                let mut j = i + 1;
                let mut count = 0;
                while j < len && count < 6 {
                    let Some(d) = hex_val(bytes[j]) else { break };
                    val = (val << 4) | (d as u32);
                    j += 1;
                    count += 1;
                }
                // Optional single trailing whitespace after CSS hex escape.
                if j < len {
                    if bytes[j] == b'\r' && j + 1 < len && bytes[j + 1] == b'\n' {
                        j += 2;
                    } else if matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r' | b'\x0c') {
                        j += 1;
                    }
                }
                if let Some(ch) = char::from_u32(val) {
                    out.push(ch);
                }
                i = j;
                continue;
            }
            // Escaped non-hex char: drop backslash.
            let ch = input[i + 1..].chars().next().expect("valid utf-8");
            out.push(ch);
            i += 1 + ch.len_utf8();
            continue;
        }
        let ch = input[i..].chars().next().expect("valid utf-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn is_modsec_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0b' | b'\x0c')
}

fn remove_whitespace(input: &str) -> String {
    input
        .chars()
        .filter(|&c| !(c.is_ascii() && is_modsec_ws(c as u8)))
        .collect()
}

fn compress_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_ws = false;
    for ch in input.chars() {
        if ch.is_ascii() && is_modsec_ws(ch as u8) {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            in_ws = false;
            out.push(ch);
        }
    }
    out
}

fn replace_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            i += 2;
            while i < len {
                if bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            out.push(' ');
            continue;
        }
        let ch = input[i..].chars().next().expect("valid utf-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn remove_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            i += 2;
            while i < len {
                if bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            out.push(' ');
            continue;
        }
        if (bytes[i] == b'-' && i + 1 < len && bytes[i + 1] == b'-') || bytes[i] == b'#' {
            break;
        }
        let ch = input[i..].chars().next().expect("valid utf-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn remove_comments_char(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if i + 1 < len
            && ((bytes[i] == b'/' && bytes[i + 1] == b'*')
                || (bytes[i] == b'*' && bytes[i + 1] == b'/')
                || (bytes[i] == b'-' && bytes[i + 1] == b'-'))
        {
            i += 2;
            continue;
        }
        if bytes[i] == b'#' {
            i += 1;
            continue;
        }
        let ch = input[i..].chars().next().expect("valid utf-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn normalize_path(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let leading_slash = input.starts_with('/');
    let trailing_slash = input.ends_with('/') && input.len() > 1;

    let mut stack: Vec<&str> = Vec::new();
    for seg in input.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if let Some(&last) = stack.last() {
                    if last != ".." {
                        stack.pop();
                    } else if !leading_slash {
                        stack.push("..");
                    }
                } else if !leading_slash {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }

    let mut out = String::with_capacity(input.len());
    if leading_slash {
        out.push('/');
    }
    out.push_str(&stack.join("/"));
    if trailing_slash && !out.ends_with('/') {
        out.push('/');
    }
    out
}

/// ModSecurity `t:cmdLine` transformation:
/// - deletes `"`, `'`, `\`, `^`
/// - replaces `,`, `;`, and whitespace with a single space
/// - removes space immediately preceding `/` or `(`
/// - converts ASCII uppercase to lowercase
fn cmd_line(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut pending_space = false;

    for ch in input.chars() {
        match ch {
            '"' | '\'' | '\\' | '^' => {}
            ' ' | '\t' | '\r' | '\n' | '\x0b' | '\x0c' | ',' | ';' => {
                pending_space = true;
            }
            '/' | '(' => {
                // Drop preceding space before `/` or `(`.
                pending_space = false;
                out.push(ch);
            }
            other => {
                if pending_space {
                    out.push(' ');
                    pending_space = false;
                }
                out.push(other.to_ascii_lowercase());
            }
        }
    }
    if pending_space {
        out.push(' ');
    }
    out
}

fn hex_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        if let (Some(hi), Some(lo)) = (hex_val(bytes[i]), hex_val(bytes[i + 1])) {
            out.push((hi << 4) | lo);
            i += 2;
        } else {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input.as_bytes() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn escape_seq_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            let next = bytes[i + 1];
            match next {
                b'a' => {
                    out.push('\x07');
                    i += 2;
                    continue;
                }
                b'b' => {
                    out.push('\x08');
                    i += 2;
                    continue;
                }
                b'f' => {
                    out.push('\x0c');
                    i += 2;
                    continue;
                }
                b'n' => {
                    out.push('\n');
                    i += 2;
                    continue;
                }
                b'r' => {
                    out.push('\r');
                    i += 2;
                    continue;
                }
                b't' => {
                    out.push('\t');
                    i += 2;
                    continue;
                }
                b'v' => {
                    out.push('\x0b');
                    i += 2;
                    continue;
                }
                b'\\' | b'?' | b'\'' | b'"' => {
                    out.push(next as char);
                    i += 2;
                    continue;
                }
                b'x' if i + 3 < len => {
                    if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                        out.push(((hi << 4) | lo) as char);
                        i += 4;
                        continue;
                    }
                }
                b'0'..=b'7' => {
                    let mut val: u32 = (next - b'0') as u32;
                    let mut consumed = 2;
                    for k in 0..2 {
                        let idx = i + 2 + k;
                        if idx < len && (b'0'..=b'7').contains(&bytes[idx]) {
                            let next_val = (val << 3) | ((bytes[idx] - b'0') as u32);
                            if next_val <= 0xFF {
                                val = next_val;
                                consumed += 1;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    out.push((val as u8) as char);
                    i += consumed;
                    continue;
                }
                _ => {
                    out.push('\\');
                    i += 1;
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().expect("valid utf-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_required_transforms_match_modsecurity_semantics() {
        assert_eq!(apply_transform(Transform::None, "AbC"), "AbC");
        assert_eq!(
            apply_transform(Transform::Lowercase, "HeLLo123"),
            "hello123"
        );
        assert_eq!(
            apply_transform(Transform::UrlDecode, "hello+world%21%2F%ZZ"),
            "hello world!/%ZZ"
        );
        assert_eq!(
            apply_transform(Transform::UrlDecodeUni, "%u003cscript%uff1e%20ok"),
            "<script> ok"
        );
        assert_eq!(
            apply_transform(
                Transform::HtmlEntityDecode,
                "&lt;img src=&quot;x&quot; &#x6f;n&#101;rror&gt;"
            ),
            "<img src=\"x\" onerror>"
        );
        assert_eq!(
            apply_transform(Transform::JsDecode, r"\u003c\x73cript\n\101"),
            "<script\nA"
        );
        assert_eq!(
            apply_transform(Transform::CssDecode, r"\6a avascript\3a alert"),
            "javascript:alert"
        );
        assert_eq!(apply_transform(Transform::RemoveNulls, "a\0b\0c"), "abc");
        assert_eq!(
            apply_transform(Transform::RemoveWhitespace, "a b\tc\r\nd"),
            "abcd"
        );
        assert_eq!(
            apply_transform(
                Transform::ReplaceComments,
                "UNION/*comment*/SELECT/*unclosed"
            ),
            "UNION SELECT "
        );
        assert_eq!(
            apply_transform(Transform::CompressWhitespace, "a   b\t\n\rc"),
            "a b c"
        );
        assert_eq!(
            apply_transform(Transform::NormalizePath, "/a/b/../c/./d//e"),
            "/a/c/d/e"
        );
        assert_eq!(
            apply_transform(Transform::NormalizePathWin, r"\a\b\..\c\d"),
            "/a/c/d"
        );
        assert_eq!(
            apply_transform(Transform::CmdLine, r#"c^m"d" /c;  ECHO  'hi'"#),
            "cmd/c echo hi"
        );
        assert_eq!(apply_transform(Transform::HexDecode, "414243"), "ABC");
        assert_eq!(apply_transform(Transform::HexEncode, "ABC"), "414243");
        assert_eq!(
            apply_transform(Transform::EscapeSeqDecode, r"a\nb\x41\102\\"),
            "a\nbAB\\"
        );
    }
}
