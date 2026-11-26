//! Embedded per-language catalogs, decompressed and indexed on first use.

use std::{
    collections::HashMap,
    io::Read,
    sync::{LazyLock, OnceLock},
};

include!(concat!(env!("OUT_DIR"), "/embedded.rs"));

type Table = HashMap<String, String>;

static TABLES: LazyLock<HashMap<&'static str, OnceLock<Table>>> = LazyLock::new(|| {
    EMBEDDED
        .iter()
        .map(|&(language, _)| (language, OnceLock::new()))
        .collect()
});

fn table(language: &str) -> Option<&'static Table> {
    let slot = TABLES.get(language)?;
    if let Some(table) = slot.get() {
        return Some(table);
    }
    let &(_, blob) = EMBEDDED
        .iter()
        .find(|&&(tag, _)| tag.eq_ignore_ascii_case(language))?;
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(blob)
        .read_to_end(&mut raw)
        .expect("a valid embedded locale");
    let table: Table = serde_json::from_slice(&raw).expect("a valid embedded catalog");
    // A concurrent winner may have installed an equivalent table first.
    let _ = slot.set(table);
    Some(slot.get().expect("the catalog was just installed"))
}

/// Returns the translation for `key`, or `None` when the language or the key
/// has no translation. The source language needs no catalog, and empty
/// values count as untranslated.
pub fn lookup(language: &str, key: &str) -> Option<&'static str> {
    if language.eq_ignore_ascii_case(crate::SOURCE) {
        return None;
    }
    let value = table(language)?.get(key)?;
    (!value.is_empty()).then_some(value.as_str())
}
