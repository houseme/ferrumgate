//! Site-configured request/response header edits (WP-23 step 10): each
//! entry is a `Key: Value` line; an empty value deletes the header.
#![allow(dead_code)]

use hyper::HeaderMap;
use hyper::header::{HeaderName, HeaderValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    BadLine(String),
    BadName(String),
}

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLine(line) => write!(f, "请求头行必须是 Key: Value 形式：{line}"),
            Self::BadName(name) => write!(f, "非法请求头名：{name}"),
        }
    }
}

impl std::error::Error for EditError {}

/// One configured header edit. An empty `value` deletes `name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderEdit {
    pub name: HeaderName,
    pub value: String,
}

/// Parses one `Key: Value` line. The key must be a valid header name;
/// the value is trimmed and may be empty (delete semantics).
pub fn parse_edit(line: &str) -> Result<HeaderEdit, EditError> {
    let Some((key, value)) = line.split_once(':') else {
        return Err(EditError::BadLine(line.to_string()));
    };
    let key = key.trim();
    let name =
        HeaderName::from_bytes(key.as_bytes()).map_err(|_| EditError::BadName(key.to_string()))?;
    Ok(HeaderEdit {
        name,
        value: value.trim().to_string(),
    })
}

/// Parses a whole block, reporting the first bad line.
pub fn parse_edits(lines: &[String]) -> Result<Vec<HeaderEdit>, EditError> {
    lines.iter().map(|line| parse_edit(line)).collect()
}

/// Applies the edits in order: an empty value removes the header (all its
/// variants), otherwise the value replaces any previous occurrences.
pub fn apply(headers: &mut HeaderMap, edits: &[HeaderEdit]) {
    for edit in edits {
        if edit.value.is_empty() {
            headers.remove(&edit.name);
        } else if let Ok(value) = HeaderValue::from_str(edit.value.as_str()) {
            headers.insert(edit.name.clone(), value);
        }
        // Values with invalid characters are dropped silently; validate
        // reports them at compile time.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edits(lines: &[&str]) -> Vec<HeaderEdit> {
        lines.iter().map(|line| parse_edit(line).unwrap()).collect()
    }

    #[test]
    fn headers_add_delete() {
        let mut headers = HeaderMap::new();
        headers.insert("x-trace", "keep".parse().unwrap());
        apply(
            &mut headers,
            &edits(&["X-Extra: hello", "X-Trace:", "X-Lower: v"]),
        );
        assert_eq!(headers.get("x-extra").unwrap(), "hello");
        assert_eq!(headers.get("x-lower").unwrap(), "v");
        assert_eq!(headers.get("x-trace"), None, "empty value deletes");
    }

    #[test]
    fn value_replaces_previous_occurrences() {
        let mut headers = HeaderMap::new();
        headers.append("x-multi", "one".parse().unwrap());
        headers.append("x-multi", "two".parse().unwrap());
        apply(&mut headers, &edits(&["X-Multi: final"]));
        assert_eq!(headers.get("x-multi").unwrap(), "final");
        assert_eq!(headers.iter().filter(|(_, v)| *v == "final").count(), 1);
    }

    #[test]
    fn rejects_bad_lines_and_names() {
        assert_eq!(
            parse_edit("no-colon-here"),
            Err(EditError::BadLine("no-colon-here".into()))
        );
        assert!(matches!(
            parse_edit("bad name!: v"),
            Err(EditError::BadName(_))
        ));
    }
}
