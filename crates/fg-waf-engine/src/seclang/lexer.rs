//! Linear-time lexer for ModSecurity SecLang files.
//!
//! Splits input into logical directive lines, handling `#` comments, trailing
//! `\` line continuations, and quoted/unquoted word tokens in a single `O(n)`
//! pass.

use crate::seclang::ast::{MAX_SECLANG_INPUT_BYTES, SecLangError};

/// One token on a logical directive line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub quoted: bool,
}

/// One logical directive line (after joining `\` line continuations and
/// stripping comments).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalLine {
    pub line: u32,
    pub tokens: Vec<Token>,
}

/// Tokenises a SecLang source string into logical directive lines in linear
/// time.
pub fn lex(file: &str, input: &str) -> Result<Vec<LogicalLine>, Vec<SecLangError>> {
    if input.len() > MAX_SECLANG_INPUT_BYTES {
        return Err(vec![SecLangError {
            file: file.to_owned(),
            line: 1,
            message: format!(
                "SecLang input exceeds maximum size of {MAX_SECLANG_INPUT_BYTES} bytes"
            ),
        }]);
    }

    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut pos = 0usize;
    let mut cur_line: u32 = 1;

    let mut lines = Vec::new();
    let mut errors = Vec::new();

    let mut cur_tokens: Vec<Token> = Vec::new();
    let mut stmt_start_line: u32 = 1;

    while pos < len {
        // Skip horizontal whitespace.
        while pos < len && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
            pos += 1;
        }
        if pos >= len {
            break;
        }

        let b = bytes[pos];

        // End of line: finish current logical line.
        if b == b'\n' || b == b'\r' {
            if b == b'\r' && pos + 1 < len && bytes[pos + 1] == b'\n' {
                pos += 2;
            } else {
                pos += 1;
            }
            cur_line = cur_line.saturating_add(1);
            if !cur_tokens.is_empty() {
                lines.push(LogicalLine {
                    line: stmt_start_line,
                    tokens: std::mem::take(&mut cur_tokens),
                });
            }
            continue;
        }

        // Comment: skip to end of line.
        if b == b'#' {
            while pos < len && bytes[pos] != b'\n' && bytes[pos] != b'\r' {
                pos += 1;
            }
            continue;
        }

        // Line continuation: `\` followed by optional horizontal whitespace
        // and a newline joins the next physical line onto the current logical
        // directive.
        if b == b'\\' {
            let mut look = pos + 1;
            while look < len && (bytes[look] == b' ' || bytes[look] == b'\t') {
                look += 1;
            }
            if look >= len {
                break;
            }
            if bytes[look] == b'\n' {
                pos = look + 1;
                cur_line = cur_line.saturating_add(1);
                continue;
            }
            if bytes[look] == b'\r' {
                pos = if look + 1 < len && bytes[look + 1] == b'\n' {
                    look + 2
                } else {
                    look + 1
                };
                cur_line = cur_line.saturating_add(1);
                continue;
            }
        }

        if cur_tokens.is_empty() {
            stmt_start_line = cur_line;
        }

        if b == b'"' {
            let quote_line = cur_line;
            pos += 1; // consume opening `"`
            let mut out = String::new();
            let mut closed = false;
            while pos < len {
                let c = bytes[pos];
                if c == b'"' {
                    pos += 1;
                    closed = true;
                    break;
                }
                if c == b'\\' && pos + 1 < len {
                    let next = bytes[pos + 1];
                    match next {
                        b'"' => {
                            out.push('"');
                            pos += 2;
                            continue;
                        }
                        b'\\' => {
                            // Preserve both backslashes so regex patterns like
                            // `[/\\]` or trailing `\\"` stay intact while not
                            // escaping a subsequent closing quote.
                            out.push('\\');
                            out.push('\\');
                            pos += 2;
                            continue;
                        }
                        b'\n' => {
                            // Line continuation inside quoted string.
                            pos += 2;
                            cur_line = cur_line.saturating_add(1);
                            continue;
                        }
                        b'\r' => {
                            pos += if pos + 2 < len && bytes[pos + 2] == b'\n' {
                                3
                            } else {
                                2
                            };
                            cur_line = cur_line.saturating_add(1);
                            continue;
                        }
                        _ => {
                            // Keep regex/escape sequences like `\d`, `\s`, `\.`
                            // verbatim.
                            out.push('\\');
                            pos += 1;
                            continue;
                        }
                    }
                }
                if c == b'\n' {
                    cur_line = cur_line.saturating_add(1);
                }
                // Copy full UTF-8 character safely.
                let ch = input[pos..].chars().next().expect("valid UTF-8 slice");
                out.push(ch);
                pos += ch.len_utf8();
            }
            if !closed {
                errors.push(SecLangError {
                    file: file.to_owned(),
                    line: quote_line,
                    message: "unterminated double-quoted string".to_owned(),
                });
            }
            cur_tokens.push(Token {
                text: out,
                quoted: true,
            });
        } else {
            let start = pos;
            while pos < len {
                let c = bytes[pos];
                if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                    break;
                }
                // Stop before a trailing line continuation `\` at EOL.
                if c == b'\\' {
                    let mut look = pos + 1;
                    while look < len && (bytes[look] == b' ' || bytes[look] == b'\t') {
                        look += 1;
                    }
                    if look >= len || bytes[look] == b'\n' || bytes[look] == b'\r' {
                        break;
                    }
                }
                pos += 1;
            }
            cur_tokens.push(Token {
                text: input[start..pos].to_owned(),
                quoted: false,
            });
        }
    }

    if !cur_tokens.is_empty() {
        lines.push(LogicalLine {
            line: stmt_start_line,
            tokens: cur_tokens,
        });
    }

    if errors.is_empty() {
        Ok(lines)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_handles_continuations_comments_and_quotes() {
        let src = r#"
# Leading comment
SecRule ARGS|ARGS_NAMES \
    "@rx (?i)select\s+from" \
    "id:1001,phase:2,deny,msg:'SQLi \"quoted\"'" # trailing comment
SecMarker END_CHECK
"#;
        let lines = lex("test.conf", src).expect("lexes cleanly");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].line, 3);
        assert_eq!(lines[0].tokens.len(), 4);
        assert_eq!(lines[0].tokens[0].text, "SecRule");
        assert_eq!(lines[0].tokens[1].text, "ARGS|ARGS_NAMES");
        assert_eq!(lines[0].tokens[2].text, r"@rx (?i)select\s+from");
        assert!(lines[0].tokens[2].quoted);
        assert_eq!(
            lines[0].tokens[3].text,
            "id:1001,phase:2,deny,msg:'SQLi \"quoted\"'"
        );
        assert_eq!(lines[1].line, 6);
        assert_eq!(lines[1].tokens[0].text, "SecMarker");
        assert_eq!(lines[1].tokens[1].text, "END_CHECK");
    }

    #[test]
    fn lex_preserves_double_backslash_before_closing_quote() {
        let src = r#"SecRule ARGS "@rx [/\\]" "id:1""#;
        let lines = lex("", src).expect("lexes");
        assert_eq!(lines[0].tokens[2].text, r"@rx [/\\]");
    }

    #[test]
    fn lex_reports_unterminated_quote() {
        let errs = lex("bad.conf", "SecRule ARGS \"@rx foo").expect_err("unterminated");
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].line, 1);
        assert!(errs[0].message.contains("unterminated"));
    }
}
