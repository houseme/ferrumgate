use std::{cmp::Reverse, sync::Arc};

use anyhow::{Result, ensure};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::Value;

#[derive(Clone, Copy, Default)]
pub enum Translation {
    #[default]
    None,
    /// JSON Pointers to program-generated fields. All other values stay in their original language.
    Fields(&'static [&'static str]),
    /// The complete response contains only program-generated values.
    Generated,
}

#[derive(Clone)]
pub struct RequestLanguage(Arc<str>);

impl RequestLanguage {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

type Translate = Box<dyn Fn(&str, &str) -> Option<String> + Send + Sync>;

#[derive(Clone)]
pub struct Localizer(Arc<Catalog>);

struct Catalog {
    source: usize,
    default: usize,
    languages: Vec<Arc<str>>,
    translate: Translate,
}

impl Localizer {
    pub fn new(
        source: &str,
        default: &str,
        supported: &[&str],
        translate: impl Fn(&str, &str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        ensure!(
            (1..=64).contains(&supported.len()),
            "expected between 1 and 64 supported languages"
        );
        for (index, language) in supported.iter().enumerate() {
            ensure!(valid_tag(language), "invalid supported language tag");
            ensure!(
                !supported[..index]
                    .iter()
                    .any(|other| other.eq_ignore_ascii_case(language)),
                "duplicate supported language tag"
            );
        }
        let index = |language: &str| {
            supported
                .iter()
                .position(|tag| tag.eq_ignore_ascii_case(language))
        };
        let source =
            index(source).ok_or_else(|| anyhow::anyhow!("source language must be supported"))?;
        let default =
            index(default).ok_or_else(|| anyhow::anyhow!("default language must be supported"))?;
        let languages = supported.iter().map(|&tag| Arc::from(tag)).collect();
        Ok(Self(Arc::new(Catalog {
            source,
            default,
            languages,
            translate: Box::new(translate),
        })))
    }

    pub(super) fn negotiate(&self, headers: &HeaderMap) -> RequestLanguage {
        let preferences: Vec<_> = headers
            .get_all(header::ACCEPT_LANGUAGE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .take(32)
            .filter_map(preference)
            .collect();
        let selected = self
            .0
            .languages
            .iter()
            .enumerate()
            .filter_map(|(language_index, language)| {
                let (rank, specificity, header_index, weight) = preferences
                    .iter()
                    .enumerate()
                    .filter_map(|(index, &(range, weight))| {
                        specificity(range, language)
                            .map(|(rank, length)| (rank, length, Reverse(index), weight))
                    })
                    .max()?;
                (weight > 0).then_some((
                    weight,
                    header_index,
                    rank,
                    specificity,
                    language_index == self.0.default,
                    Reverse(language_index),
                ))
            })
            .max()
            .map_or(self.0.default, |(_, _, _, _, _, Reverse(index))| index);
        RequestLanguage(self.0.languages[selected].clone())
    }

    pub(super) fn response(
        &self,
        language: RequestLanguage,
        scope: Translation,
        status: StatusCode,
    ) -> Option<Localized> {
        let scope = if status.is_client_error() || status.is_server_error() {
            Translation::Fields(&["/error"])
        } else {
            scope
        };
        if matches!(scope, Translation::None) {
            return None;
        }
        Some(Localized {
            catalog: self.clone(),
            language,
            scope,
        })
    }
}

pub(super) struct Localized {
    catalog: Localizer,
    language: RequestLanguage,
    scope: Translation,
}

impl Localized {
    pub fn translates(&self) -> bool {
        self.language.as_str() != self.catalog.0.languages[self.catalog.0.source].as_ref()
    }

    pub fn header(&self) -> HeaderValue {
        HeaderValue::from_str(self.language.as_str()).expect("validated language tag")
    }

    pub fn translate(&self, value: &mut Value) -> bool {
        let translate = |text: &str| (self.catalog.0.translate)(self.language.as_str(), text);
        match self.scope {
            Translation::None => false,
            Translation::Generated => strings(value, &translate),
            Translation::Fields(fields) => {
                let mut changed = false;
                for pointer in fields {
                    if let Some(value) = value.pointer_mut(pointer) {
                        changed |= strings(value, &translate);
                    }
                }
                changed
            }
        }
    }
}

fn strings(value: &mut Value, translate: &impl Fn(&str) -> Option<String>) -> bool {
    match value {
        Value::String(text) => {
            if let Some(localized) = translate(text)
                && localized != *text
            {
                *text = localized;
                return true;
            }
            false
        }
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |changed, value| changed | strings(value, translate)),
        Value::Object(items) => items
            .values_mut()
            .fold(false, |changed, value| changed | strings(value, translate)),
        _ => false,
    }
}

fn valid_tag(tag: &str) -> bool {
    tag.len() <= 63
        && tag.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && tag.split('-').all(|part| {
            (1..=8).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn preference(item: &str) -> Option<(&str, u16)> {
    let mut parts = item.split(';');
    let range = parts.next()?.trim();
    if range != "*" && !valid_tag(range) {
        return None;
    }
    let weight = match parts.next() {
        None => 1000,
        Some(parameter) => {
            let (name, number) = parameter.split_once('=')?;
            if !name.trim().eq_ignore_ascii_case("q") || parts.next().is_some() {
                return None;
            }
            let number = number.trim();
            let (whole, fractional) = number.split_once('.').unwrap_or((number, ""));
            if fractional.len() > 3 || !fractional.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            match whole {
                "1" if fractional.bytes().all(|byte| byte == b'0') => 1000,
                "0" => fractional
                    .bytes()
                    .zip([100, 10, 1])
                    .map(|(byte, place)| u16::from(byte - b'0') * place)
                    .sum(),
                _ => return None,
            }
        }
    };
    Some((range, weight))
}

fn specificity(range: &str, language: &str) -> Option<(u8, usize)> {
    let prefixes = |prefix: &str, tag: &str| {
        tag.as_bytes().get(prefix.len()) == Some(&b'-')
            && tag
                .get(..prefix.len())
                .is_some_and(|tag| tag.eq_ignore_ascii_case(prefix))
    };
    if range.eq_ignore_ascii_case(language) {
        Some((3, range.len()))
    } else if prefixes(range, language) {
        Some((2, range.len()))
    } else if prefixes(language, range) {
        Some((1, language.len()))
    } else if range == "*" {
        Some((0, 0))
    } else {
        None
    }
}
