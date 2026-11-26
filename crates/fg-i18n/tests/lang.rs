use fg_i18n::lang::{fallback, from_accept_language, from_env, normalize};

#[test]
fn normalize_handles_case_separators_and_variants() {
    for tag in [
        "zh-CN",
        "zh-cn",
        "ZH_CN",
        "zh",
        "zh-Hans",
        "zh-Hans-CN",
        "zh-SG",
    ] {
        assert_eq!(normalize(tag), Some("zh-CN"), "{tag}");
    }
    for tag in ["zh-TW", "zh-tw", "zh-Hant", "zh-HK"] {
        assert_eq!(normalize(tag), Some("zh-TW"), "{tag}");
    }
    assert_eq!(normalize("PT-BR"), Some("pt-BR"));
    assert_eq!(normalize("pt"), None);
    assert_eq!(normalize("en-US"), Some("en"));
    assert_eq!(normalize("JA"), Some("ja"));
    assert_eq!(normalize("xx-YY"), None);
    assert_eq!(normalize(""), None);
}

#[test]
fn fallback_prefers_english_when_built() {
    assert_eq!(fallback(&["zh-CN", "en"]), "en");
    assert_eq!(fallback(&["zh-CN"]), "zh-CN");
}

#[test]
fn accept_language_respects_q_and_order() {
    // ja has no q and therefore outranks en;q=0.5.
    assert_eq!(
        from_accept_language("en;q=0.5, ja", fg_i18n::BUILT),
        Some("ja")
    );
    assert_eq!(
        from_accept_language("zh-TW,zh;q=0.9,en;q=0.8", fg_i18n::BUILT),
        Some("zh-TW")
    );
    assert_eq!(
        from_accept_language("zh-Hant,zh-Hans;q=0.9", fg_i18n::BUILT),
        Some("zh-TW")
    );
    // Zero quality removes a candidate.
    assert_eq!(
        from_accept_language("zh-CN;q=0, en;q=0.3", fg_i18n::BUILT),
        Some("en")
    );
}

#[test]
fn accept_language_handles_wildcard_and_unknowns() {
    assert_eq!(
        from_accept_language("*", fg_i18n::BUILT),
        Some(fallback(fg_i18n::BUILT))
    );
    assert_eq!(
        from_accept_language("fr-CA,xx-YY;q=0.9,*;q=0.1", fg_i18n::BUILT),
        Some("fr")
    );
    assert_eq!(from_accept_language("xx,yy;q=1", fg_i18n::BUILT), None);
    assert_eq!(from_accept_language("", fg_i18n::BUILT), None);
}

#[test]
fn accept_language_skips_unbuilt_langs() {
    let tier: [&'static str; 2] = ["zh-CN", "en"];
    assert_eq!(from_accept_language("ja, en", &tier), Some("en"));
    assert_eq!(from_accept_language("zh-TW, zh", &tier), Some("zh-CN"));
    assert_eq!(from_accept_language("*", &tier), Some("en"));
    assert_eq!(
        fallback(&tier),
        "en",
        "the fallback for a reduced tier is still English"
    );
}

#[test]
fn server_lang_env_precedence() {
    let get = |name: &str| match name {
        "FERRUMGATE_LANG" => None,
        "LC_ALL" => Some("ja_JP.UTF-8".to_owned()),
        "LC_MESSAGES" => Some("de".to_owned()),
        "LANG" => Some("en_US.UTF-8".to_owned()),
        _ => None,
    };
    assert_eq!(from_env(get), Some("ja"));
    let get = |name: &str| match name {
        "FERRUMGATE_LANG" => Some("zh-TW".to_owned()),
        "LC_ALL" => Some("ja".to_owned()),
        _ => None,
    };
    assert_eq!(from_env(get), Some("zh-TW"));
    let get = |name: &str| (name == "LANG").then(|| "unknown-lang".to_owned());
    assert_eq!(from_env(get), None);
}
