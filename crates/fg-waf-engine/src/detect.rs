//! Pure-Rust SQLi and XSS lexical/fingerprint detectors (WP-55 step E7).
//!
//! Inspired by `libinjection`'s multi-context tokenization approach:
//! - [`detect_sqli`] tokenizes inputs under bare, single-quoted, and
//!   double-quoted SQL contexts, folding expressions and matching injection
//!   fingerprints (tautologies, `UNION SELECT`, stacked queries, comment
//!   terminators, blind time-based functions, schema extraction).
//! - [`detect_xss`] scans HTML5-like tag/attribute/URI contexts (plus
//!   attribute breakout contexts) for script elements, event handlers,
//!   dangerous URI schemes, and DOM sinks.
//!
//! Both detectors run in linear time and are tuned for low false-positive
//! rates on ordinary web application payloads.

use crate::transforms::{Transform, apply_transform};

/// Maximum input bytes inspected by heuristic detectors.
const MAX_DETECT_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// SQL Injection detection
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum SqlTokKind {
    Word(String), // upper-cased identifier / keyword
    Str,          // '...' or "..."
    Num,          // 123, 0x1a
    Op(String),   // =, !=, <>, <, >, <=, >=, ||, &&, +, -, *, /
    LParen,
    RParen,
    Comma,
    Semi,
    Comment,
    Null,
}

/// Detects SQL injection payloads and returns a short fingerprint string on hit.
pub fn detect_sqli(input: &str) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    let slice = truncate_utf8(input, MAX_DETECT_LEN);

    // Quick ASCII pre-screen: every SQLi vector contains at least one SQL
    // metacharacter or whitespace separating keywords.
    if !slice.bytes().any(|b| {
        matches!(
            b,
            b'\'' | b'"' | b';' | b'=' | b'(' | b'-' | b'/' | b'#' | b' ' | b'\t' | b'\n'
        )
    }) {
        return None;
    }

    // Context 1: Bare expression (e.g. `1 OR 1=1`, `1 UNION SELECT ...`).
    let bare_tokens = tokenize_sql(slice);
    if let Some(fp) = match_sqli_tokens(&bare_tokens, false) {
        return Some(fp);
    }

    // Context 2: Inside single-quoted SQL string (prepend `'` so `admin' OR '1'='1`
    // tokenizes as `'admin' OR '1'='1`).
    if slice.contains('\'') {
        let mut wrapped = String::with_capacity(slice.len() + 1);
        wrapped.push('\'');
        wrapped.push_str(slice);
        let tokens = tokenize_sql(&wrapped);
        if let Some(fp) = match_sqli_tokens(&tokens, true) {
            return Some(fp);
        }
    }

    // Context 3: Inside double-quoted SQL string.
    if slice.contains('"') {
        let mut wrapped = String::with_capacity(slice.len() + 1);
        wrapped.push('"');
        wrapped.push_str(slice);
        let tokens = tokenize_sql(&wrapped);
        if let Some(fp) = match_sqli_tokens(&tokens, true) {
            return Some(fp);
        }
    }

    None
}

fn tokenize_sql(input: &str) -> Vec<SqlTokKind> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut tokens = Vec::new();

    while i < len && tokens.len() < 512 {
        let b = bytes[i];
        // Whitespace
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Line comment `--` (SQL standard: `-- ` / `--\t` / `--+` / `--\n` / `--` at EOF)
        if b == b'-' && i + 1 < len && bytes[i + 1] == b'-' {
            let is_sql_comment = i + 2 >= len
                || bytes[i + 2].is_ascii_whitespace()
                || bytes[i + 2] == b'+'
                || bytes[i + 2] == b'-';
            if is_sql_comment {
                tokens.push(SqlTokKind::Comment);
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
        }
        // Hash comment `#`
        if b == b'#' {
            tokens.push(SqlTokKind::Comment);
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment `/* ... */` or MySQL conditional comment `/*!50000 ... */`
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            if i + 2 < len && bytes[i + 2] == b'!' {
                // MySQL conditional comment: skip `/*!` and optional version digits,
                // then tokenize the inside!
                i += 3;
                while i < len && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                continue;
            }
            // Regular block comment: skip to `*/` (acting as token separator).
            i += 2;
            let mut closed = false;
            while i < len {
                if bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                    i += 2;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                tokens.push(SqlTokKind::Comment);
            }
            continue;
        }
        // Stray `*/` from conditional comment end
        if b == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
            i += 2;
            continue;
        }
        // Quoted string literal (`'` or `"`)
        if b == b'\'' || b == b'"' {
            let quote = b;
            i += 1;
            while i < len {
                if bytes[i] == b'\\' && i + 1 < len {
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    // SQL doubled quote escape `''`
                    if i < len && bytes[i] == quote {
                        i += 1;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            tokens.push(SqlTokKind::Str);
            continue;
        }
        // Backtick identifier
        if b == b'`' {
            i += 1;
            let start = i;
            while i < len && bytes[i] != b'`' {
                i += 1;
            }
            let word = input[start..i].to_ascii_uppercase();
            if i < len {
                i += 1;
            }
            if !word.is_empty() {
                tokens.push(SqlTokKind::Word(word));
            }
            continue;
        }
        // Numbers and hex literals (`0x...`)
        if b.is_ascii_digit() {
            i += 1;
            if b == b'0' && i < len && (bytes[i] == b'x' || bytes[i] == b'X') {
                i += 1;
                while i < len && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
            } else {
                while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
            }
            tokens.push(SqlTokKind::Num);
            continue;
        }
        // Identifier / keyword
        if b.is_ascii_alphabetic() || b == b'_' || b == b'@' || b == b'$' {
            let start = i;
            i += 1;
            while i < len
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
            {
                i += 1;
            }
            let word = input[start..i].to_ascii_uppercase();
            if word == "NULL" {
                tokens.push(SqlTokKind::Null);
            } else {
                tokens.push(SqlTokKind::Word(word));
            }
            continue;
        }
        // Multi-char operators
        if i + 1 < len {
            let pair = &bytes[i..i + 2];
            if matches!(pair, b"!=" | b"<>" | b"<=" | b">=" | b"||" | b"&&" | b":=") {
                tokens.push(SqlTokKind::Op(
                    std::str::from_utf8(pair).unwrap_or("").to_owned(),
                ));
                i += 2;
                continue;
            }
        }
        match b {
            b'(' => tokens.push(SqlTokKind::LParen),
            b')' => tokens.push(SqlTokKind::RParen),
            b',' => tokens.push(SqlTokKind::Comma),
            b';' => tokens.push(SqlTokKind::Semi),
            b'=' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'%' | b'!' | b'~' | b'|' | b'&'
            | b'^' => {
                tokens.push(SqlTokKind::Op((b as char).to_string()));
            }
            _ => {}
        }
        i += 1;
    }

    tokens
}

fn is_word(tok: &SqlTokKind, target: &str) -> bool {
    matches!(tok, SqlTokKind::Word(w) if w == target)
}

fn is_logic_op(tok: &SqlTokKind) -> bool {
    match tok {
        SqlTokKind::Word(w) => matches!(w.as_str(), "OR" | "AND" | "XOR"),
        SqlTokKind::Op(o) => matches!(o.as_str(), "||" | "&&"),
        _ => false,
    }
}

fn is_comparison_op(tok: &SqlTokKind) -> bool {
    match tok {
        SqlTokKind::Op(o) => matches!(o.as_str(), "=" | "!=" | "<>" | "<" | ">" | "<=" | ">="),
        SqlTokKind::Word(w) => matches!(w.as_str(), "LIKE" | "RLIKE" | "REGEXP" | "IS" | "IN"),
        _ => false,
    }
}

fn is_value_like(tok: &SqlTokKind) -> bool {
    matches!(tok, SqlTokKind::Num | SqlTokKind::Str | SqlTokKind::Null)
        || matches!(tok, SqlTokKind::Word(w) if matches!(w.as_str(), "TRUE" | "FALSE"))
}

fn is_expr_atom(tok: &SqlTokKind) -> bool {
    is_value_like(tok) || matches!(tok, SqlTokKind::Word(_))
}

fn match_sqli_tokens(tokens: &[SqlTokKind], quoted_ctx: bool) -> Option<String> {
    let n = tokens.len();
    if n < 2 {
        return None;
    }

    for i in 0..n {
        // 1. UNION [ALL|DISTINCT] SELECT
        if is_word(&tokens[i], "UNION") {
            let next = if i + 1 < n
                && (is_word(&tokens[i + 1], "ALL") || is_word(&tokens[i + 1], "DISTINCT"))
            {
                i + 2
            } else {
                i + 1
            };
            if next < n && is_word(&tokens[next], "SELECT") {
                return Some("sqli:union-select".to_owned());
            }
        }

        // 2. Stacked query: `; <DML/DDL/EXEC>`
        if tokens[i] == SqlTokKind::Semi
            && i + 1 < n
            && let SqlTokKind::Word(w) = &tokens[i + 1]
            && matches!(
                w.as_str(),
                "SELECT"
                    | "DROP"
                    | "DELETE"
                    | "INSERT"
                    | "UPDATE"
                    | "ALTER"
                    | "CREATE"
                    | "TRUNCATE"
                    | "EXEC"
                    | "EXECUTE"
                    | "SHUTDOWN"
                    | "DECLARE"
                    | "WAITFOR"
                    | "CALL"
            )
        {
            return Some(format!("sqli:stacked-{}", w.to_ascii_lowercase()));
        }

        // 3. Blind/time-based & dangerous SQL functions: `SLEEP(...)`, `BENCHMARK(...)`, etc.
        if let SqlTokKind::Word(w) = &tokens[i] {
            if i + 1 < n
                && tokens[i + 1] == SqlTokKind::LParen
                && matches!(
                    w.as_str(),
                    "SLEEP"
                        | "PG_SLEEP"
                        | "BENCHMARK"
                        | "EXTRACTVALUE"
                        | "UPDATEXML"
                        | "LOAD_FILE"
                        | "DBMS_PIPE.RECEIVE_MESSAGE"
                        | "XP_CMDSHELL"
                )
            {
                return Some(format!("sqli:func-{}", w.to_ascii_lowercase()));
            }
            if w == "WAITFOR" && i + 1 < n && is_word(&tokens[i + 1], "DELAY") {
                return Some("sqli:waitfor-delay".to_owned());
            }
            if w == "INTO"
                && i + 1 < n
                && (is_word(&tokens[i + 1], "OUTFILE") || is_word(&tokens[i + 1], "DUMPFILE"))
            {
                return Some("sqli:into-outfile".to_owned());
            }
            if w.contains("INFORMATION_SCHEMA") || w == "PG_CATALOG" || w == "SYSOBJECTS" {
                return Some("sqli:schema-enum".to_owned());
            }
        }

        // 4. Boolean tautology / injection after value or string breakout:
        //    e.g. `1 OR 1=1`, `' OR '1'='1`, `') OR ('a'='a`, `1 AND 1=2`, `' OR TRUE--`
        if is_logic_op(&tokens[i]) && i >= 1 {
            // Skip optional `)` before logic op and `(` / `NOT` after logic op.
            let prev_is_expr =
                is_value_like(&tokens[i - 1]) || (tokens[i - 1] == SqlTokKind::RParen && i >= 2);
            if prev_is_expr {
                let mut j = i + 1;
                while j < n
                    && (tokens[j] == SqlTokKind::LParen
                        || is_word(&tokens[j], "NOT")
                        || matches!(&tokens[j], SqlTokKind::Op(o) if o == "!"))
                {
                    j += 1;
                }
                // `OR 1=1` / `OR 'a'='a` / `AND 1<2` / `OR x LIKE 'a'`
                if j + 2 < n
                    && is_expr_atom(&tokens[j])
                    && is_comparison_op(&tokens[j + 1])
                    && (is_expr_atom(&tokens[j + 2]) || tokens[j + 2] == SqlTokKind::LParen)
                {
                    // Avoid false positive on bare English if both sides are bare words
                    // and operator is `IS` or `LIKE` unless in quoted context.
                    let both_plain_words = matches!(tokens[j], SqlTokKind::Word(_))
                        && matches!(tokens[j + 2], SqlTokKind::Word(_))
                        && !is_value_like(&tokens[j])
                        && !is_value_like(&tokens[j + 2]);
                    if quoted_ctx || !both_plain_words {
                        return Some("sqli:boolean-tautology".to_owned());
                    }
                }
                // `' OR 1--` / `' OR TRUE--` / `' OR 1#`
                if quoted_ctx
                    && j < n
                    && is_value_like(&tokens[j])
                    && (j + 1 >= n
                        || tokens[j + 1] == SqlTokKind::Comment
                        || tokens[j + 1] == SqlTokKind::Semi)
                {
                    return Some("sqli:quoted-boolean".to_owned());
                }
            }
        }

        // 5. Quote breakout followed directly by SQL comment: `admin'--` / `admin'#`
        if quoted_ctx
            && i == 0
            && tokens[0] == SqlTokKind::Str
            && n >= 2
            && tokens[1] == SqlTokKind::Comment
        {
            return Some("sqli:quote-comment".to_owned());
        }

        // 6. Quote breakout followed by SQL clause (`ORDER BY 1`, `GROUP BY`, `HAVING 1=1`)
        if quoted_ctx && i >= 1 {
            if (is_word(&tokens[i], "ORDER") || is_word(&tokens[i], "GROUP"))
                && i + 2 < n
                && is_word(&tokens[i + 1], "BY")
                && matches!(tokens[i + 2], SqlTokKind::Num)
            {
                return Some("sqli:order-by-num".to_owned());
            }
            if is_word(&tokens[i], "HAVING")
                && i + 3 < n
                && is_value_like(&tokens[i + 1])
                && is_comparison_op(&tokens[i + 2])
                && is_value_like(&tokens[i + 3])
            {
                return Some("sqli:having-tautology".to_owned());
            }
        }

        // 7. Subquery / full SELECT ... FROM ...
        if is_word(&tokens[i], "SELECT") {
            // Look ahead for `FROM` within a bounded window, ensuring SQL-like
            // syntax (either preceded by `(`, `;`, `UNION`, or followed by `*`,
            // function call, or column list + `FROM` + identifier).
            let sql_lead = i > 0
                && matches!(
                    tokens[i - 1],
                    SqlTokKind::LParen | SqlTokKind::Semi | SqlTokKind::Op(_)
                );
            let star_or_func = i + 1 < n
                && (matches!(&tokens[i + 1], SqlTokKind::Op(o) if o == "*")
                    || (matches!(tokens[i + 1], SqlTokKind::Word(_))
                        && i + 2 < n
                        && tokens[i + 2] == SqlTokKind::LParen));
            if sql_lead || star_or_func || quoted_ctx {
                let window_end = (i + 12).min(n);
                if tokens[i + 1..window_end].iter().any(|t| is_word(t, "FROM")) {
                    return Some("sqli:select-from".to_owned());
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Cross-Site Scripting (XSS) detection
// ---------------------------------------------------------------------------

/// Detects XSS payloads and returns a short fingerprint string on hit.
pub fn detect_xss(input: &str) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    let slice = truncate_utf8(input, MAX_DETECT_LEN);

    // Decode HTML entities once for entity-obfuscated payloads (e.g., `&#x6a;avascript:`).
    let decoded = if slice.contains('&') {
        Some(apply_transform(Transform::HtmlEntityDecode, slice))
    } else {
        None
    };

    if let Some(hit) = detect_xss_single(slice) {
        return Some(hit);
    }
    if let Some(ref dec) = decoded
        && dec != slice
        && let Some(hit) = detect_xss_single(dec)
    {
        return Some(hit);
    }
    None
}

fn detect_xss_single(input: &str) -> Option<String> {
    // 1. Dangerous URI schemes (even outside tags, e.g., href/src parameter values).
    if let Some(scheme) = find_dangerous_uri_scheme(input) {
        return Some(format!("xss:uri-{scheme}"));
    }

    // 2. HTML tag scanning (`<tag ...>`).
    if input.contains('<')
        && let Some(hit) = scan_html_tags(input)
    {
        return Some(hit);
    }

    // 3. Attribute-breakout context (e.g. `" onmouseover=alert(1)`, `' onfocus=alert(1) x='`).
    if (input.contains('"') || input.contains('\''))
        && let Some(hit) = scan_attr_breakout(input)
    {
        return Some(hit);
    }

    // 4. CSS expression injection (`expression(...)`).
    let lower = input.to_ascii_lowercase();
    if let Some(idx) = lower.find("expression") {
        let rest = lower[idx + "expression".len()..].trim_start();
        if rest.starts_with('(')
            && (lower.contains("style") || lower.contains(':') || lower.contains(';'))
        {
            return Some("xss:css-expression".to_owned());
        }
    }

    None
}

fn find_dangerous_uri_scheme(input: &str) -> Option<&'static str> {
    // Strip ASCII control chars & whitespace inside the scheme candidate
    // (browsers strip tabs/newlines/NULs inside `java\tscript:`).
    let bytes = input.as_bytes();
    let len = bytes.len();
    for start in 0..len {
        let b = bytes[start].to_ascii_lowercase();
        if !matches!(b, b'j' | b'v' | b'd') {
            continue;
        }
        // Must be at start of string or preceded by delimiter (not inside a normal word).
        if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            continue;
        }
        // Collect up to 24 non-control/non-ws lowercase chars until `:` or limit.
        let mut buf = [0u8; 32];
        let mut n = 0usize;
        let mut j = start;
        let mut saw_colon = false;
        while j < len && n < buf.len() {
            let c = bytes[j];
            if c <= 0x20 {
                j += 1;
                continue;
            }
            let lc = c.to_ascii_lowercase();
            buf[n] = lc;
            n += 1;
            j += 1;
            if lc == b':' {
                saw_colon = true;
                break;
            }
        }
        if !saw_colon {
            continue;
        }
        let scheme = std::str::from_utf8(&buf[..n]).unwrap_or("");
        if scheme == "javascript:" {
            // Confirm something script-like follows (avoid prose `"JavaScript: The Good Parts"`).
            let after = input[j..].trim_start();
            if after.is_empty() {
                continue;
            }
            let after_lower = after.to_ascii_lowercase();
            let looks_code = after.contains('(')
                || after.contains(';')
                || after.contains('=')
                || after.starts_with("void")
                || after.starts_with("//")
                || after.starts_with("/*")
                || after_lower.starts_with("alert")
                || after_lower.starts_with("eval")
                || after_lower.starts_with("document")
                || after_lower.starts_with("window")
                || after_lower.starts_with("location")
                || after_lower.starts_with("fetch")
                || after_lower.starts_with("import");
            if looks_code {
                return Some("javascript");
            }
        } else if scheme == "vbscript:" {
            let after = input[j..].trim_start();
            if !after.is_empty() && (after.contains('(') || after.contains(':')) {
                return Some("vbscript");
            }
        } else if scheme == "data:" {
            let after = input[j..].trim_start().to_ascii_lowercase();
            if after.starts_with("text/html") || after.starts_with("image/svg+xml") {
                return Some("data-html");
            }
        }
    }
    None
}

fn scan_html_tags(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        i += 1;
        // Skip optional `/` (closing tag like `</script>` still shouldn't occur
        // in plain user input if it's `</script>`).
        let is_closing = if i < len && bytes[i] == b'/' {
            i += 1;
            true
        } else {
            false
        };
        if i >= len || !bytes[i].is_ascii_alphabetic() {
            continue;
        }
        let name_start = i;
        while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b':')
        {
            i += 1;
        }
        let tag_name = input[name_start..i].to_ascii_lowercase();

        // Must be followed by whitespace, `/`, `>`, or end of tag context —
        // NOT `@` (which rules out emails like `<alice@example.com>`)!
        if i < len && !matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>') {
            continue;
        }

        // Capture tag attribute section up to `>` (or end of string for unclosed tags).
        let attr_start = i;
        let mut quote: Option<u8> = None;
        while i < len {
            let c = bytes[i];
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                }
            } else if c == b'"' || c == b'\'' {
                quote = Some(c);
            } else if c == b'>' {
                break;
            }
            i += 1;
        }
        let attrs = &input[attr_start..i];
        if i < len && bytes[i] == b'>' {
            i += 1;
        }

        // Always-dangerous active tags.
        if matches!(
            tag_name.as_str(),
            "script" | "iframe" | "object" | "embed" | "applet"
        ) {
            return Some(format!("xss:tag-{tag_name}"));
        }

        if is_closing {
            continue;
        }

        // Event handler attributes (`on*=`) inside ANY HTML tag.
        if let Some(ev) = find_event_handler_attr(attrs) {
            return Some(format!("xss:event-{ev}"));
        }

        // Dangerous URI inside tag attributes (even without parens, e.g. `<a href="javascript:alert">`).
        let attrs_lower = attrs.to_ascii_lowercase();
        if attrs_lower.contains("javascript:")
            || attrs_lower.contains("vbscript:")
            || attrs_lower.contains("data:text/html")
            || attrs_lower.contains("data:image/svg+xml")
        {
            return Some(format!("xss:attr-uri-{tag_name}"));
        }

        // `<svg ...>` or `<math ...>` with script/animate/set/xlink payload.
        if matches!(tag_name.as_str(), "svg" | "math")
            && (attrs_lower.contains("onload")
                || attrs_lower.contains("href")
                || attrs_lower.contains("xlink")
                || input[i..].to_ascii_lowercase().contains("<script")
                || input[i..].to_ascii_lowercase().contains("<animate"))
        {
            return Some(format!("xss:tag-{tag_name}"));
        }

        // `<meta http-equiv="refresh" ...>`
        if tag_name == "meta" && attrs_lower.contains("refresh") {
            return Some("xss:meta-refresh".to_owned());
        }

        // `<base href=...>`
        if tag_name == "base" && attrs_lower.contains("href") {
            return Some("xss:base-href".to_owned());
        }
    }

    None
}

fn scan_attr_breakout(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b'"' || b == b'\'' {
            let after = &input[idx + 1..];
            // Require whitespace or `/` before an event handler attribute after quote breakout.
            if after.starts_with(|c: char| c.is_ascii_whitespace() || c == '/')
                && let Some(ev) = find_event_handler_attr(after)
            {
                return Some(format!("xss:attr-breakout-{ev}"));
            }
        }
    }
    None
}

/// Searches a tag attribute string for HTML event handlers (`on[a-z]+\s*=`).
fn find_event_handler_attr(attrs: &str) -> Option<String> {
    let bytes = attrs.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        // Event handler names must start after whitespace, `/`, or at start of attr slice.
        let at_boundary = i == 0
            || bytes[i - 1].is_ascii_whitespace()
            || bytes[i - 1] == b'/'
            || bytes[i - 1] == b'"'
            || bytes[i - 1] == b'\'';
        if at_boundary
            && i + 4 < len
            && bytes[i].eq_ignore_ascii_case(&b'o')
            && bytes[i + 1].eq_ignore_ascii_case(&b'n')
            && bytes[i + 2].is_ascii_alphabetic()
        {
            let start = i;
            let mut j = i + 2;
            while j < len && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            let name = attrs[start..j].to_ascii_lowercase();
            let mut k = j;
            while k < len && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < len && bytes[k] == b'=' && is_known_dom_event(&name) {
                return Some(name);
            }
            i = j;
            continue;
        }
        i += 1;
    }
    None
}

fn is_known_dom_event(name: &str) -> bool {
    matches!(
        name,
        "onabort"
            | "onafterprint"
            | "onanimationend"
            | "onanimationiteration"
            | "onanimationstart"
            | "onauxclick"
            | "onbeforeinput"
            | "onbeforeprint"
            | "onbeforetoggle"
            | "onbeforeunload"
            | "onbegin"
            | "onblur"
            | "oncanplay"
            | "oncanplaythrough"
            | "onchange"
            | "onclick"
            | "onclose"
            | "oncontextmenu"
            | "oncopy"
            | "oncut"
            | "ondblclick"
            | "ondrag"
            | "ondragend"
            | "ondragenter"
            | "ondragleave"
            | "ondragover"
            | "ondragstart"
            | "ondrop"
            | "ondurationchange"
            | "onended"
            | "onerror"
            | "onfocus"
            | "onfocusin"
            | "onfocusout"
            | "onformdata"
            | "onhashchange"
            | "oninput"
            | "oninvalid"
            | "onkeydown"
            | "onkeypress"
            | "onkeyup"
            | "onload"
            | "onloadeddata"
            | "onloadedmetadata"
            | "onloadstart"
            | "onmessage"
            | "onmousedown"
            | "onmouseenter"
            | "onmouseleave"
            | "onmousemove"
            | "onmouseout"
            | "onmouseover"
            | "onmouseup"
            | "onmousewheel"
            | "onpageshow"
            | "onpaste"
            | "onpause"
            | "onplay"
            | "onplaying"
            | "onpointerdown"
            | "onpointerenter"
            | "onpointerleave"
            | "onpointermove"
            | "onpointerout"
            | "onpointerover"
            | "onpointerup"
            | "onpopstate"
            | "onprogress"
            | "onratechange"
            | "onreset"
            | "onresize"
            | "onscroll"
            | "onsearch"
            | "onseeked"
            | "onseeking"
            | "onselect"
            | "onshow"
            | "onstart"
            | "onsubmit"
            | "ontoggle"
            | "ontouchend"
            | "ontouchmove"
            | "ontouchstart"
            | "ontransitionend"
            | "onunload"
            | "onvolumechange"
            | "onwaiting"
            | "onwheel"
    )
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqli_detects_classic_payloads_and_avoids_benign_text() {
        let attacks = [
            "' OR '1'='1",
            "1 OR 1=1",
            "admin'--",
            "1 UNION SELECT username, password FROM users",
            "1 UNION/**/ALL/**/SELECT 1,2,3",
            "1; DROP TABLE users--",
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(1000000,MD5('a'))--",
            "1' ORDER BY 10--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        ];
        for payload in attacks {
            assert!(
                detect_sqli(payload).is_some(),
                "expected SQLi hit for: {payload}"
            );
        }

        let benign = [
            "hello world",
            "O'Brien",
            "Please select one option or another from the list",
            "Update your profile settings",
            "https://example.com/search?q=union+station&page=2",
            r#"{"name":"Alice","note":"It's a nice day"}"#,
            "2026-11-28T10:00:00Z",
        ];
        for text in benign {
            assert!(
                detect_sqli(text).is_none(),
                "unexpected SQLi false positive for: {text}"
            );
        }
    }

    #[test]
    fn xss_detects_classic_payloads_and_avoids_benign_text() {
        let attacks = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=\"https://evil.test\"></iframe>",
            "javascript:alert(document.cookie)",
            "&#x6a;avascript:alert(1)",
            "\" onmouseover=alert(1) x=\"",
            "<details open ontoggle=alert(1)>",
            "data:text/html,<script>alert(1)</script>",
        ];
        for payload in attacks {
            assert!(
                detect_xss(payload).is_some(),
                "expected XSS hit for: {payload}"
            );
        }

        let benign = [
            "Hello, world!",
            "a < b and c > d",
            "Alice <alice@example.com>",
            "JavaScript: The Good Parts",
            r#"{"title":"Learning HTML and CSS","count":42}"#,
            "on Monday = great weather",
            "https://example.com/docs/getting-started",
        ];
        for text in benign {
            assert!(
                detect_xss(text).is_none(),
                "unexpected XSS false positive for: {text}"
            );
        }
    }
}
