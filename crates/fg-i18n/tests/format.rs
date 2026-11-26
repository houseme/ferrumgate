use fg_i18n::format::{placeholders, render};

#[test]
fn render_replaces_named_placeholders() {
    assert_eq!(
        render(
            "监听 {addr} 于 {port} 启动失败",
            &[("addr", "127.0.0.1"), ("port", "16680")]
        ),
        "监听 127.0.0.1 于 16680 启动失败"
    );
    // Reordering in the translation is irrelevant to named parameters.
    assert_eq!(
        render(
            "failed to listen on {port} at {addr}",
            &[("addr", "[::1]"), ("port", "443")]
        ),
        "failed to listen on 443 at [::1]"
    );
}

#[test]
fn render_ignores_extra_and_keeps_missing_arguments() {
    assert_eq!(
        render("{known}", &[("known", "值"), ("extra", "ignored")]),
        "值"
    );
    assert_eq!(render("{missing}", &[("other", "值")]), "{missing}");
    assert_eq!(render("no placeholders", &[("x", "y")]), "no placeholders");
}

#[test]
fn render_leaves_braces_that_are_not_placeholders_alone() {
    assert_eq!(render("a {0} b {{}} c", &[]), "a {0} b {{}} c");
    assert_eq!(render("trailing { open", &[]), "trailing { open");
    assert_eq!(render("json {\"k\": 1}", &[]), "json {\"k\": 1}");
}

#[test]
fn placeholders_lists_names_in_order() {
    assert_eq!(
        placeholders("先 {first} 后 {second}，再 {first}"),
        ["first", "second", "first"]
    );
    assert!(placeholders("plain text").is_empty());
    assert!(placeholders("{not a name}").is_empty());
}
