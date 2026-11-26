//! Server-side translations with simplified Chinese source keys.
//!
//! Call sites use [`tr!`] with the Chinese original as the key; the catalogs
//! under `locales/` map keys to per-language translations with `{name}`
//! placeholders. Missing or untranslated keys return the key itself, so the
//! source language doubles as the fallback.

pub mod catalog;
pub mod format;
pub mod lang;

pub use lang::{ALL, BUILT, SOURCE};

use serde_json::Value;

/// Translates `key`; the source language and untranslated keys return the
/// key itself.
pub fn tr(lang: &str, key: &str) -> String {
    catalog::lookup(lang, key).unwrap_or(key).to_owned()
}

/// Translates `key` and renders `{name}` placeholders from `args`. Without a
/// translation the key itself is the template, so the source language (and
/// untranslated keys) still render their arguments.
pub fn tr_args(lang: &str, key: &str, args: &[(&str, String)]) -> String {
    let template = catalog::lookup(lang, key).unwrap_or(key);
    let borrowed: Vec<(&str, &str)> = args
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    format::render(template, &borrowed)
}

/// Recursively translates every string in `value`. Only use this for data
/// that is entirely program-generated; user-entered content must go through
/// [`tr_fields`] instead.
pub fn tr_deep(lang: &str, value: &mut Value) {
    match value {
        Value::String(text) => {
            let translated = tr(lang, text);
            *text = translated;
        }
        Value::Array(items) => items.iter_mut().for_each(|item| tr_deep(lang, item)),
        Value::Object(fields) => fields.values_mut().for_each(|item| tr_deep(lang, item)),
        _ => {}
    }
}

/// Program-generated explanatory field names translated by [`tr_fields`].
const MESSAGE_KEYS: &[&str] = &[
    "error",
    "errors",
    "lastError",
    "ipError",
    "errorDetail",
    "detail",
    "details",
    "message",
    "reason",
    "warnings",
    "mappingNote",
    "hint",
    "title",
    "label",
    "issues",
    "status",
    "description",
];

/// Field names translated only while their value is a string: the same names
/// elsewhere carry user configuration objects.
const STRING_MESSAGE_KEYS: &[&str] = &["mapping", "unsupported", "firewall"];

/// Recursively translates explanatory fields (errors, status text, hints)
/// and leaves names, remarks, commands and other user content untouched, so
/// a client that reads a value and saves it back never stores a translation.
pub fn tr_fields(lang: &str, value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(|item| tr_fields(lang, item)),
        Value::Object(fields) => {
            for (name, item) in fields.iter_mut() {
                if MESSAGE_KEYS.contains(&name.as_str()) {
                    tr_deep(lang, item);
                } else if STRING_MESSAGE_KEYS.contains(&name.as_str())
                    && let Value::String(text) = item
                {
                    let translated = tr(lang, text);
                    *text = translated;
                } else {
                    tr_fields(lang, item);
                }
            }
        }
        _ => {}
    }
}

/// Translates with the Chinese source key as the literal.
#[macro_export]
macro_rules! tr {
    ($lang:expr, $key:literal) => {
        $crate::tr($lang, $key)
    };
    ($lang:expr, $key:literal, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::tr_args($lang, $key, &[$((stringify!($name), ($value).to_string())),+])
    };
}
