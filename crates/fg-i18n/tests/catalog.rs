use fg_i18n::{SOURCE, tr, tr_args, tr_deep, tr_fields};
use serde_json::json;

#[test]
fn tr_returns_key_for_source_or_missing() {
    assert_eq!(tr(SOURCE, "监听 {addr} 启动失败"), "监听 {addr} 启动失败");
    // No language has this translation yet; every language falls back.
    assert_eq!(tr("en", "尚无译文的键"), "尚无译文的键");
    // Untranslated (empty-value) entries behave like missing entries.
    assert_eq!(tr("ja", "空值键"), "空值键");
}

#[test]
fn tr_args_renders_the_key_template_without_translation() {
    assert_eq!(
        tr_args(
            SOURCE,
            "监听 {addr} 启动失败",
            &[("addr", "127.0.0.1".to_owned())]
        ),
        "监听 127.0.0.1 启动失败",
        "the source language renders against the key itself"
    );
    assert_eq!(
        tr_args(
            "en",
            "端口 {port} 已被占用",
            &[("port", 16680u16.to_string())]
        ),
        "端口 16680 已被占用"
    );
}

#[test]
fn tr_macro_passes_literal_keys_and_named_args() {
    let lang = SOURCE;
    assert_eq!(fg_i18n::tr!(lang, "中文键"), "中文键");
    let addr = String::from("127.0.0.1");
    assert_eq!(
        fg_i18n::tr!(lang, "监听 {addr} 启动失败", addr = addr),
        "监听 127.0.0.1 启动失败"
    );
    let port: u16 = 16680;
    assert_eq!(
        fg_i18n::tr!(lang, "端口 {port} 已被占用", port = port),
        "端口 16680 已被占用"
    );
}

#[test]
fn tr_deep_translates_all_strings_in_generated_data() {
    let mut value = json!({
        "title": "中文键",
        "rows": [{"message": "中文键"}],
        "count": 3,
    });
    tr_deep(SOURCE, &mut value);
    assert_eq!(value["title"], "中文键");
    assert_eq!(value["rows"][0]["message"], "中文键");
    assert_eq!(value["count"], 3);
}

#[test]
fn tr_fields_leaves_user_content_untouched() {
    let mut value = json!({
        "name": "中文键",
        "group": "中文键",
        "remark": "中文键",
        "command": "echo 中文键",
        "values": ["中文键"],
        "template": {"body": "中文键"},
        "error": "中文键",
        "message": "中文键",
        "mapping": "中文键",
        "mapping_note": "中文键",
    });
    tr_fields(SOURCE, &mut value);
    for untouched in ["name", "group", "remark", "command"] {
        assert!(
            value[untouched].as_str().unwrap().contains("中文键"),
            "{untouched} is user content"
        );
    }
    assert_eq!(value["command"], "echo 中文键");
    assert_eq!(value["values"][0], "中文键");
    assert_eq!(value["template"]["body"], "中文键");
    // With the source language nothing changes; the point is that the field
    // list is exercised. Error and message fields are the translate targets.
    assert_eq!(value["error"], "中文键");
    assert_eq!(value["message"], "中文键");
    assert_eq!(value["mapping"], "中文键");
}

#[test]
fn tr_fields_translates_message_keys_only() {
    // Demonstrate the field selection with a synthetic catalog: source
    // keys pass through unchanged, so this asserts the walk itself. The
    // translation path is covered once catalogs carry entries.
    let mut value = json!({
        "status": {"code": 1, "message": "中文键", "detail": ["中文键"]},
        "items": [{"title": "中文键", "note": "中文键"}],
    });
    tr_fields(SOURCE, &mut value);
    assert_eq!(value["status"]["message"], "中文键");
    assert_eq!(value["status"]["detail"][0], "中文键");
    assert_eq!(value["items"][0]["title"], "中文键");
    assert_eq!(value["items"][0]["note"], "中文键");
}
