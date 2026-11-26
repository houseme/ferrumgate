//! `tr!` literal extraction and locale catalog consistency checks.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

/// Scans Rust sources for `tr!(<lang>, "<Chinese literal>" ...)` keys.
/// Test files (`tests/` directories) are skipped, matching the upstream
/// extractor.
pub fn extract_literals(roots: &[PathBuf]) -> Result<Vec<String>> {
    let mut keys = BTreeSet::new();
    for root in roots {
        collect_from(root, &mut keys)?;
    }
    Ok(keys.into_iter().collect())
}

fn collect_from(dir: &Path, keys: &mut BTreeSet<String>) -> Result<()> {
    if dir.file_name().is_some_and(|name| name == "tests") {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("scan {}", dir.display()))? {
        let entry = entry.with_context(|| format!("list {}", dir.display()))?;
        let path = entry.path();
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            collect_from(&path, keys)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            for key in literal_keys(&source) {
                keys.insert(key);
            }
        }
    }
    Ok(())
}

/// Yields the second top-level argument of each `tr!(` invocation when it is
/// a string literal containing Han characters.
fn literal_keys(source: &str) -> impl Iterator<Item = String> {
    let mut keys = Vec::new();
    let mut position = 0;
    while let Some(found) = source[position..].find("tr!(") {
        position += found + 4;
        let Some((literal, end)) = second_argument_literal(source, position) else {
            continue;
        };
        position = end;
        if literal.chars().any(is_han) {
            keys.push(literal);
        }
    }
    keys.into_iter()
}

fn is_han(character: char) -> bool {
    matches!(character as u32, 0x4E00..=0x9FFF)
}

/// Reads the string literal starting at `from` (after optional whitespace),
/// returning its unescaped value and the offset just past the closing quote.
fn string_literal(source: &str, from: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let mut position = from;
    while position < bytes.len() && bytes[position].is_ascii_whitespace() {
        position += 1;
    }
    if position >= bytes.len() || bytes[position] != b'"' {
        return None;
    }
    position += 1;
    let mut literal = String::new();
    while position < bytes.len() {
        match bytes[position] {
            b'"' => return Some((literal, position + 1)),
            b'\\' => {
                position += 1;
                let escaped = *bytes.get(position)?;
                literal.push(match escaped {
                    b'n' => '\n',
                    b't' => '\t',
                    b'r' => '\r',
                    b'0' => '\0',
                    b'\\' => '\\',
                    b'"' => '"',
                    b'\'' => '\'',
                    b'u' => {
                        // \u{XXXX}
                        let rest = &source[position + 1..];
                        let close = rest.find('}')?;
                        let hex = rest[..close].trim_start_matches('{');
                        let code = u32::from_str_radix(hex, 16).ok()?;
                        let decoded = char::from_u32(code)?;
                        position += close + 1;
                        decoded
                    }
                    _ => return None,
                });
                position += 1;
            }
            _ => {
                // Copy the whole UTF-8 sequence.
                let character = source[position..].chars().next()?;
                literal.push(character);
                position += character.len_utf8();
            }
        }
    }
    None
}

/// Skips the first macro argument and reads the second when it is a string
/// literal.
fn second_argument_literal(source: &str, from: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let mut position = from;
    let mut depth = 0usize;
    while position < bytes.len() {
        match bytes[position] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
            }
            b',' if depth == 0 => {
                return string_literal(source, position + 1);
            }
            _ => {}
        }
        position += 1;
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    MissingTranslation { language: String, key: String },
    ExtraTranslation { language: String, key: String },
    PlaceholderMismatch { language: String, key: String },
    UntranslatedIdentity { language: String, key: String },
}

/// Compares every non-source locale against the extracted keys: identical
/// key sets, matching `{name}` placeholders and no translation equal to its
/// source key.
pub fn check_catalogs(locales: &Path, keys: &[String]) -> Result<Vec<Violation>> {
    let mut violations = Vec::new();
    let mut files = Vec::new();
    for entry in fs::read_dir(locales).with_context(|| format!("list {}", locales.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    for path in files {
        let language = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .context("locale file name")?
            .to_owned();
        let raw = fs::read_to_string(&path)?;
        let catalog: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        let translated: BTreeSet<&String> = catalog.keys().collect();
        let expected: BTreeSet<&String> = keys.iter().collect();
        for key in expected.difference(&translated) {
            violations.push(Violation::MissingTranslation {
                language: language.clone(),
                key: (*key).clone(),
            });
        }
        for key in translated.difference(&expected) {
            violations.push(Violation::ExtraTranslation {
                language: language.clone(),
                key: (*key).clone(),
            });
        }
        for (key, value) in &catalog {
            let Some(text) = value.as_str() else {
                bail!("locale {language} key {key} must map to a string");
            };
            if !text.is_empty() {
                if text == key {
                    violations.push(Violation::UntranslatedIdentity {
                        language: language.clone(),
                        key: key.clone(),
                    });
                }
                if placeholders(key) != placeholders(text) {
                    violations.push(Violation::PlaceholderMismatch {
                        language: language.clone(),
                        key: key.clone(),
                    });
                }
            }
        }
    }
    Ok(violations)
}

/// Adds missing keys with empty values (waiting for translation) to every
/// non-source locale. Existing translations are kept; keys that no longer
/// appear in sources survive unless `prune` is set.
pub fn sync_catalogs(locales: &Path, keys: &[String], prune: bool) -> Result<usize> {
    let mut written = 0;
    for entry in fs::read_dir(locales)? {
        let entry = entry?;
        let path = entry.path();
        if !path.extension().is_some_and(|ext| ext == "json") {
            continue;
        }
        let raw = fs::read_to_string(&path)?;
        let mut catalog: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&raw)?;
        if prune {
            catalog.retain(|key, _| keys.contains(key));
        }
        for key in keys {
            catalog
                .entry(key.to_owned())
                .or_insert_with(|| serde_json::Value::String(String::new()));
        }
        let mut serialized = serde_json::to_string_pretty(&catalog)?;
        serialized.push('\n');
        fs::write(&path, serialized)?;
        written += 1;
    }
    Ok(written)
}

fn placeholders(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start + 1..].find('}') else {
            break;
        };
        let name = &rest[start + 1..start + 1 + end];
        if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            names.push(name.to_owned());
        }
        rest = &rest[start + 2 + end..];
    }
    names
}
