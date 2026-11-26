//! The language list, tag normalization and the server-language chain.

/// Translations are written against simplified Chinese keys.
pub const SOURCE: &str = "zh-CN";

pub const ALL: &[&str] = &[
    "zh-CN", "en", "zh-TW", "ja", "ko", "es", "fr", "de", "ru", "pt-BR",
];

/// The languages compiled into this build; language tiers arrive with WP-90.
pub const BUILT: &[&str] = ALL;

/// English when it is built (it always is today), otherwise the source.
pub fn fallback(built: &[&'static str]) -> &'static str {
    built
        .iter()
        .find(|tag| **tag == "en")
        .copied()
        .unwrap_or(SOURCE)
}

/// Normalizes case and separators; script and region variants collapse to
/// the closest catalog language. Unknown tags return `None`.
pub fn normalize(tag: &str) -> Option<&'static str> {
    let canonical = tag.replace('_', "-").to_ascii_lowercase();
    let mut parts = canonical.split('-');
    let language = parts.next()?;
    let variants: Vec<&str> = parts.collect();
    let listed = |tag: &str| {
        ALL.iter()
            .find(|other| other.eq_ignore_ascii_case(tag))
            .copied()
    };
    match language {
        // Simplified unless a Traditional script or region subtag appears.
        "zh" => {
            if variants
                .iter()
                .any(|part| matches!(*part, "hant" | "tw" | "hk" | "mo"))
            {
                listed("zh-TW")
            } else {
                listed("zh-CN")
            }
        }
        "pt" if variants.contains(&"br") => listed("pt-BR"),
        // Region suffixes such as en-US collapse to the base language.
        _ => listed(&canonical).or_else(|| listed(language)),
    }
}

/// Picks the first built language from an `Accept-Language` value, honoring
/// q-values then header order; `*` matches the fallback. Returns `None` when
/// no preference matches a built language.
pub fn from_accept_language(header: &str, built: &[&'static str]) -> Option<&'static str> {
    let mut preferences: Vec<(&str, f32, usize)> = header
        .split(',')
        .enumerate()
        .filter_map(|(index, item)| {
            let mut parts = item.split(';');
            let range = parts.next()?.trim();
            if range.is_empty() || (range != "*" && normalize(range).is_none()) {
                return None;
            }
            let mut quality = 1.0f32;
            if let Some(parameter) = parts.next() {
                let (name, value) = parameter.trim().split_once('=')?;
                if !name.eq_ignore_ascii_case("q") {
                    return None;
                }
                quality = value.trim().parse().ok()?;
            }
            Some((range, quality, index))
        })
        .collect();
    preferences.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.2.cmp(&b.2)));
    for (range, quality, _) in preferences {
        if quality <= 0.0 {
            continue;
        }
        if range == "*" {
            return Some(fallback(built));
        }
        if let Some(tag) = normalize(range)
            && built.iter().any(|other| other.eq_ignore_ascii_case(tag))
        {
            return Some(tag);
        }
    }
    None
}

/// Reads the server language from the environment chain
/// `FERRUMGATE_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG`.
pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Option<&'static str> {
    for name in ["FERRUMGATE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        let Some(value) = get(name) else {
            continue;
        };
        // Strip the encoding suffix of POSIX locale values such as
        // zh_CN.UTF-8, then normalize.
        let tag = value
            .split('.')
            .next()
            .unwrap_or_default()
            .replace('_', "-");
        if let Some(tag) = normalize(&tag) {
            return Some(tag);
        }
    }
    None
}
