//! Bounded pure-Rust request body parsers for `application/x-www-form-urlencoded`,
//! `multipart/form-data`, `application/json`, and lightweight XML extraction
//! (WP-55 step E6).
//!
//! All parsers run in linear time with explicit depth and entry-count limits
//! and never panic on malformed or binary input.

use serde_json::Value;

use crate::transforms::{Transform, apply_transform};

/// Maximum number of extracted argument pairs per request body.
pub const MAX_BODY_ARGS: usize = 4096;
/// Maximum JSON object/array nesting depth traversed.
pub const MAX_JSON_DEPTH: usize = 64;
/// Maximum XML element nesting depth tracked.
pub const MAX_XML_DEPTH: usize = 64;
/// Maximum multipart sections parsed.
pub const MAX_MULTIPART_PARTS: usize = 256;

/// Body processor kind selected by `Content-Type` or `ctl:requestBodyProcessor`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BodyProcessor {
    #[default]
    Raw,
    UrlEncoded,
    Multipart,
    Json,
    Xml,
}

impl BodyProcessor {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_uppercase().as_str() {
            "URLENCODED" => Some(Self::UrlEncoded),
            "MULTIPART" => Some(Self::Multipart),
            "JSON" => Some(Self::Json),
            "XML" => Some(Self::Xml),
            "RAW" => Some(Self::Raw),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::UrlEncoded => "URLENCODED",
            Self::Multipart => "MULTIPART",
            Self::Json => "JSON",
            Self::Xml => "XML",
        }
    }

    pub fn from_content_type(ct: &str) -> Self {
        let mime = ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if mime == "application/x-www-form-urlencoded" {
            Self::UrlEncoded
        } else if mime == "multipart/form-data" {
            Self::Multipart
        } else if mime == "application/json" || mime.ends_with("+json") {
            Self::Json
        } else if mime == "application/xml" || mime == "text/xml" || mime.ends_with("+xml") {
            Self::Xml
        } else {
            Self::Raw
        }
    }
}

/// Structured output extracted from a request body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedBody {
    pub processor: BodyProcessor,
    /// Name/value argument pairs (`ARGS_POST` / `ARGS`).
    pub args: Vec<(String, String)>,
    /// Uploaded file names (`FILES`).
    pub files: Vec<String>,
    /// Form field names carrying files (`FILES_NAMES`).
    pub files_names: Vec<String>,
    /// Extracted XML text nodes (`XML:/*`).
    pub xml_texts: Vec<String>,
    /// Extracted XML attributes (`XML://@*`).
    pub xml_attrs: Vec<(String, String)>,
    /// True if parsing stopped early due to entry or depth limits.
    pub truncated: bool,
    /// Set if the body was syntactically malformed for the chosen processor.
    pub parse_error: Option<String>,
}

/// Parses a request body using an explicit processor override or the
/// `Content-Type` header.
pub fn parse_body(
    body: &[u8],
    content_type: Option<&str>,
    forced: Option<BodyProcessor>,
    arg_separator: u8,
) -> ParsedBody {
    let processor = forced.unwrap_or_else(|| {
        content_type
            .map(BodyProcessor::from_content_type)
            .unwrap_or(BodyProcessor::Raw)
    });
    match processor {
        BodyProcessor::UrlEncoded => parse_urlencoded(body, arg_separator, MAX_BODY_ARGS),
        BodyProcessor::Multipart => {
            parse_multipart(body, content_type.unwrap_or(""), MAX_MULTIPART_PARTS)
        }
        BodyProcessor::Json => parse_json(body, MAX_BODY_ARGS, MAX_JSON_DEPTH),
        BodyProcessor::Xml => parse_xml(body, MAX_BODY_ARGS, MAX_XML_DEPTH),
        BodyProcessor::Raw => ParsedBody {
            processor: BodyProcessor::Raw,
            ..Default::default()
        },
    }
}

/// Parses `application/x-www-form-urlencoded` bytes into name/value pairs.
pub fn parse_urlencoded(body: &[u8], separator: u8, max_args: usize) -> ParsedBody {
    let mut out = ParsedBody {
        processor: BodyProcessor::UrlEncoded,
        ..Default::default()
    };
    if body.is_empty() {
        return out;
    }

    for part in body.split(|&b| b == separator) {
        if part.is_empty() {
            continue;
        }
        if out.args.len() >= max_args {
            out.truncated = true;
            break;
        }
        let (k_raw, v_raw) = match part.iter().position(|&b| b == b'=') {
            Some(eq) => (&part[..eq], &part[eq + 1..]),
            None => (part, &[][..]),
        };
        let key = decode_form_component(k_raw);
        let val = decode_form_component(v_raw);
        out.args.push((key, val));
    }
    out
}

/// Parses a query string (same encoding as `application/x-www-form-urlencoded`).
pub fn parse_query_string(query: &str, separator: u8, max_args: usize) -> Vec<(String, String)> {
    let trimmed = query.strip_prefix('?').unwrap_or(query);
    parse_urlencoded(trimmed.as_bytes(), separator, max_args).args
}

fn decode_form_component(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    apply_transform(Transform::UrlDecode, &s)
}

/// Parses `multipart/form-data` bodies using the boundary in `content_type`.
pub fn parse_multipart(body: &[u8], content_type: &str, max_parts: usize) -> ParsedBody {
    let mut out = ParsedBody {
        processor: BodyProcessor::Multipart,
        ..Default::default()
    };
    let Some(boundary) = extract_boundary(content_type) else {
        out.parse_error = Some("multipart Content-Type missing boundary".to_owned());
        return out;
    };
    if boundary.is_empty() || boundary.len() > 256 {
        out.parse_error = Some("invalid multipart boundary length".to_owned());
        return out;
    }

    let mut delim = Vec::with_capacity(boundary.len() + 2);
    delim.extend_from_slice(b"--");
    delim.extend_from_slice(boundary.as_bytes());

    let Some(first) = find_bytes(body, &delim) else {
        out.parse_error = Some("multipart boundary not found in body".to_owned());
        return out;
    };

    let mut cursor = first + delim.len();
    let mut parts_seen = 0usize;

    while cursor < body.len() {
        // Closing boundary `--`.
        if body[cursor..].starts_with(b"--") {
            break;
        }
        // Skip CRLF or LF after boundary line.
        if body[cursor..].starts_with(b"\r\n") {
            cursor += 2;
        } else if body[cursor..].starts_with(b"\n") {
            cursor += 1;
        } else {
            out.parse_error = Some("malformed multipart boundary line".to_owned());
            break;
        }

        if parts_seen >= max_parts {
            out.truncated = true;
            break;
        }
        parts_seen += 1;

        // Locate next boundary.
        let rest = &body[cursor..];
        let next_pos = find_bytes(rest, &delim);
        let part_end = match next_pos {
            Some(pos) => {
                // Trim preceding CRLF or LF before `--boundary`.
                if pos >= 2 && rest[pos - 2] == b'\r' && rest[pos - 1] == b'\n' {
                    pos - 2
                } else if pos >= 1 && rest[pos - 1] == b'\n' {
                    pos - 1
                } else {
                    pos
                }
            }
            None => rest.len(),
        };
        let part = &rest[..part_end];

        // Split part headers and payload at `\r\n\r\n` or `\n\n`.
        let (headers_bytes, payload_bytes) = if let Some(sep) = find_bytes(part, b"\r\n\r\n") {
            (&part[..sep], &part[sep + 4..])
        } else if let Some(sep) = find_bytes(part, b"\n\n") {
            (&part[..sep], &part[sep + 2..])
        } else {
            (&[][..], part)
        };

        let (field_name, filename) = parse_content_disposition(headers_bytes);
        if let Some(fname) = filename {
            if out.files.len() < MAX_BODY_ARGS {
                out.files.push(fname);
            }
            if let Some(name) = field_name
                && out.files_names.len() < MAX_BODY_ARGS
            {
                out.files_names.push(name);
            }
        } else if let Some(name) = field_name {
            if out.args.len() < MAX_BODY_ARGS {
                out.args
                    .push((name, String::from_utf8_lossy(payload_bytes).into_owned()));
            } else {
                out.truncated = true;
            }
        }

        match next_pos {
            Some(pos) => cursor += pos + delim.len(),
            None => break,
        }
    }

    out
}

fn extract_boundary(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let trimmed = param.trim();
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("boundary") {
            let v = v.trim();
            let unquoted = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                &v[1..v.len() - 1]
            } else {
                v
            };
            return Some(unquoted.to_owned());
        }
    }
    None
}

fn parse_content_disposition(headers: &[u8]) -> (Option<String>, Option<String>) {
    let text = String::from_utf8_lossy(headers);
    let mut name = None;
    let mut filename = None;

    for line in text.lines() {
        let Some((hname, hval)) = line.split_once(':') else {
            continue;
        };
        if !hname.trim().eq_ignore_ascii_case("content-disposition") {
            continue;
        }
        for param in hval.split(';').skip(1) {
            let trimmed = param.trim();
            let Some((k, v)) = trimmed.split_once('=') else {
                continue;
            };
            let k_lower = k.trim().to_ascii_lowercase();
            let v = v.trim();
            let unquoted = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                v[1..v.len() - 1].replace("\\\"", "\"")
            } else {
                v.to_owned()
            };
            match k_lower.as_str() {
                "name" => name = Some(unquoted),
                "filename" => filename = Some(unquoted),
                _ => {}
            }
        }
    }

    (name, filename)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parses a JSON body into flattened `json.<path>` key/value pairs with
/// bounded depth and argument count.
pub fn parse_json(body: &[u8], max_args: usize, max_depth: usize) -> ParsedBody {
    let mut out = ParsedBody {
        processor: BodyProcessor::Json,
        ..Default::default()
    };
    if body.is_empty() {
        return out;
    }

    match serde_json::from_slice::<Value>(body) {
        Ok(value) => {
            flatten_json(&value, "json", 0, max_args, max_depth, &mut out);
        }
        Err(err) => {
            out.parse_error = Some(format!("invalid JSON: {err}"));
        }
    }
    out
}

fn flatten_json(
    value: &Value,
    prefix: &str,
    depth: usize,
    max_args: usize,
    max_depth: usize,
    out: &mut ParsedBody,
) {
    if out.args.len() >= max_args {
        out.truncated = true;
        return;
    }
    if depth > max_depth {
        out.truncated = true;
        return;
    }
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let next = format!("{prefix}.{k}");
                flatten_json(v, &next, depth + 1, max_args, max_depth, out);
                if out.args.len() >= max_args {
                    out.truncated = true;
                    break;
                }
            }
        }
        Value::Array(items) => {
            for (idx, v) in items.iter().enumerate() {
                let next = format!("{prefix}.{idx}");
                flatten_json(v, &next, depth + 1, max_args, max_depth, out);
                if out.args.len() >= max_args {
                    out.truncated = true;
                    break;
                }
            }
        }
        Value::String(s) => out.args.push((prefix.to_owned(), s.clone())),
        Value::Number(n) => out.args.push((prefix.to_owned(), n.to_string())),
        Value::Bool(b) => out.args.push((prefix.to_owned(), b.to_string())),
        Value::Null => out.args.push((prefix.to_owned(), String::new())),
    }
}

/// Lightweight, linear-time, XXE-safe XML text & attribute extractor.
pub fn parse_xml(body: &[u8], max_args: usize, max_depth: usize) -> ParsedBody {
    let mut out = ParsedBody {
        processor: BodyProcessor::Xml,
        ..Default::default()
    };
    if body.is_empty() {
        return out;
    }

    let text = String::from_utf8_lossy(body);
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut stack: Vec<String> = Vec::new();
    let mut saw_element = false;

    while i < len {
        if bytes[i] == b'<' {
            // Comment `<!-- ... -->`
            if text[i..].starts_with("<!--") {
                if let Some(end) = text[i + 4..].find("-->") {
                    i += 4 + end + 3;
                } else {
                    out.parse_error = Some("unterminated XML comment".to_owned());
                    break;
                }
                continue;
            }
            // CDATA `<![CDATA[ ... ]]>`
            if text[i..].starts_with("<![CDATA[") {
                if let Some(end) = text[i + 9..].find("]]>") {
                    let cdata = &text[i + 9..i + 9 + end];
                    push_xml_text(&mut out, &stack, cdata, max_args);
                    i += 9 + end + 3;
                } else {
                    out.parse_error = Some("unterminated XML CDATA".to_owned());
                    break;
                }
                continue;
            }
            // Processing instruction `<? ... ?>`
            if text[i..].starts_with("<?") {
                if let Some(end) = text[i + 2..].find("?>") {
                    i += 2 + end + 2;
                } else {
                    out.parse_error = Some("unterminated XML processing instruction".to_owned());
                    break;
                }
                continue;
            }
            // DOCTYPE / declaration `<! ... >` (never expanded: safe against XXE)
            if text[i..].starts_with("<!") {
                i = skip_xml_declaration(&text, i + 2);
                continue;
            }
            // Closing tag `</tag>`
            if text[i..].starts_with("</") {
                if let Some(end) = text[i + 2..].find('>') {
                    let close_name = text[i + 2..i + 2 + end].trim();
                    if let Some(pos) = stack.iter().rposition(|t| t == close_name) {
                        stack.truncate(pos);
                    } else {
                        stack.pop();
                    }
                    i += 2 + end + 1;
                } else {
                    out.parse_error = Some("unterminated XML closing tag".to_owned());
                    break;
                }
                continue;
            }
            // Opening / self-closing tag `<tag attr="val" ...>`
            let Some((tag_end, tag_body)) = scan_xml_tag(&text, i + 1) else {
                out.parse_error = Some("unterminated XML opening tag".to_owned());
                break;
            };
            saw_element = true;
            let trimmed = tag_body.trim();
            let self_closing = trimmed.ends_with('/');
            let header = trimmed.strip_suffix('/').unwrap_or(trimmed).trim();
            let (tag_name, attr_str) = match header.find(|c: char| c.is_ascii_whitespace()) {
                Some(ws) => (&header[..ws], &header[ws..]),
                None => (header, ""),
            };
            if !tag_name.is_empty() {
                if stack.len() < max_depth {
                    stack.push(tag_name.to_owned());
                } else {
                    out.truncated = true;
                }
                let path = stack.join("/");
                for (aname, aval) in parse_xml_attributes(attr_str) {
                    let decoded = decode_xml_entities(&aval);
                    if out.xml_attrs.len() < max_args {
                        out.xml_attrs.push((aname.clone(), decoded.clone()));
                    }
                    if out.args.len() < max_args {
                        out.args.push((format!("{path}@{aname}"), decoded));
                    } else {
                        out.truncated = true;
                    }
                }
                if self_closing {
                    stack.pop();
                }
            }
            i = tag_end;
        } else {
            let start = i;
            while i < len && bytes[i] != b'<' {
                i += 1;
            }
            let raw_chunk = &text[start..i];
            let trimmed = raw_chunk.trim();
            if !trimmed.is_empty() {
                let decoded = decode_xml_entities(trimmed);
                push_xml_text(&mut out, &stack, &decoded, max_args);
            }
        }
    }

    if !saw_element && out.parse_error.is_none() {
        out.parse_error = Some("XML body contains no elements".to_owned());
    }
    out
}

fn push_xml_text(out: &mut ParsedBody, stack: &[String], text: &str, max_args: usize) {
    if out.xml_texts.len() < max_args {
        out.xml_texts.push(text.to_owned());
    }
    if out.args.len() < max_args {
        let key = if stack.is_empty() {
            "xml".to_owned()
        } else {
            stack.join("/")
        };
        out.args.push((key, text.to_owned()));
    } else {
        out.truncated = true;
    }
}

fn skip_xml_declaration(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut i = start;
    let mut depth = 1usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() && depth > 0 {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else {
            match b {
                b'"' | b'\'' => quote = Some(b),
                b'<' => depth += 1,
                b'>' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }
    i
}

fn scan_xml_tag(text: &str, start: usize) -> Option<(usize, &str)> {
    let bytes = text.as_bytes();
    let mut i = start;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            quote = Some(b);
        } else if b == b'>' {
            return Some((i + 1, &text[start..i]));
        }
        i += 1;
    }
    None
}

fn parse_xml_attributes(raw: &str) -> Vec<(String, String)> {
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut attrs = Vec::new();

    while i < len {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }
        let name_start = i;
        while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
            i += 1;
        }
        let name = &raw[name_start..i];
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || bytes[i] != b'=' {
            continue;
        }
        i += 1; // skip `=`
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }
        let val = if bytes[i] == b'"' || bytes[i] == b'\'' {
            let q = bytes[i];
            i += 1;
            let v_start = i;
            while i < len && bytes[i] != q {
                i += 1;
            }
            let slice = &raw[v_start..i];
            if i < len {
                i += 1;
            }
            slice
        } else {
            let v_start = i;
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            &raw[v_start..i]
        };
        if !name.is_empty() {
            attrs.push((name.to_owned(), val.to_owned()));
        }
    }
    attrs
}

fn decode_xml_entities(input: &str) -> String {
    apply_transform(Transform::HtmlEntityDecode, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urlencoded_multipart_json_and_xml() {
        let form = parse_urlencoded(b"a=1+2&b=%3Cscript%3E&empty=&flag", b'&', 64);
        assert_eq!(form.args.len(), 4);
        assert_eq!(form.args[0], ("a".into(), "1 2".into()));
        assert_eq!(form.args[1], ("b".into(), "<script>".into()));
        assert_eq!(form.args[3], ("flag".into(), "".into()));

        let mp_ct = "multipart/form-data; boundary=----TestBound";
        let mp_body = b"------TestBound\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n------TestBound\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php ?>\r\n------TestBound--\r\n";
        let mp = parse_multipart(mp_body, mp_ct, 16);
        assert!(mp.parse_error.is_none());
        assert_eq!(mp.args, vec![("user".into(), "alice".into())]);
        assert_eq!(mp.files, vec!["shell.php".to_owned()]);
        assert_eq!(mp.files_names, vec!["avatar".to_owned()]);

        let json = parse_json(br#"{"user":{"name":"bob"},"tags":["a","b"]}"#, 64, 16);
        assert!(json.parse_error.is_none());
        assert!(json.args.contains(&("json.user.name".into(), "bob".into())));
        assert!(json.args.contains(&("json.tags.0".into(), "a".into())));

        let xml = parse_xml(
            br#"<?xml version="1.0"?><root id="42"><msg>&lt;hello&gt;</msg><![CDATA[raw]]></root>"#,
            64,
            16,
        );
        assert!(xml.parse_error.is_none());
        assert_eq!(xml.xml_attrs, vec![("id".into(), "42".into())]);
        assert_eq!(xml.xml_texts, vec!["<hello>".to_owned(), "raw".to_owned()]);
    }

    #[test]
    fn malformed_inputs_never_panic() {
        let _ = parse_urlencoded(b"%%%=&&&\xff\xfe", b'&', 8);
        let _ = parse_multipart(b"\xff\x00--b", "multipart/form-data; boundary=b", 8);
        let bad_json = parse_json(b"{not json", 8, 4);
        assert!(bad_json.parse_error.is_some());
        let bad_xml = parse_xml(b"<root><unclosed attr=\"x", 8, 4);
        assert!(bad_xml.parse_error.is_some());
    }
}
