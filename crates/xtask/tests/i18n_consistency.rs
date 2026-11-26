use std::path::PathBuf;

use xtask::i18n::{Violation, check_catalogs, extract_literals, sync_catalogs};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn catalogs_are_consistent_across_languages() {
    let root = repo_root();
    let sources: Vec<PathBuf> = ["crates", "src"].iter().map(|dir| root.join(dir)).collect();
    let keys = extract_literals(&sources).expect("extract tr! literals");
    let violations =
        check_catalogs(&root.join("crates/fg-i18n/locales"), &keys).expect("check locale catalogs");
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn missing_translation_fails_check() {
    let dir = tempfile_dir();
    std::fs::write(dir.join("en.json"), "{}\n").unwrap();
    let violations = check_catalogs(&dir, &["监听 {addr} 启动失败".to_owned()]).unwrap();
    assert_eq!(
        violations,
        [Violation::MissingTranslation {
            language: "en".to_owned(),
            key: "监听 {addr} 启动失败".to_owned()
        }]
    );

    // Syncing adds the key with an empty value, which passes the check and
    // reads as untranslated at runtime.
    sync_catalogs(&dir, &["监听 {addr} 启动失败".to_owned()], false).unwrap();
    assert!(
        check_catalogs(&dir, &["监听 {addr} 启动失败".to_owned()])
            .unwrap()
            .is_empty()
    );

    // A placeholder mismatch and an identity translation are violations.
    std::fs::write(
        dir.join("en.json"),
        r#"{"监听 {addr} 启动失败":"listen failed on {address}"}"#,
    )
    .unwrap();
    assert_eq!(
        check_catalogs(&dir, &["监听 {addr} 启动失败".to_owned()]).unwrap(),
        [Violation::PlaceholderMismatch {
            language: "en".to_owned(),
            key: "监听 {addr} 启动失败".to_owned()
        }]
    );
    std::fs::write(
        dir.join("en.json"),
        r#"{"监听 {addr} 启动失败":"监听 {addr} 启动失败"}"#,
    )
    .unwrap();
    assert_eq!(
        check_catalogs(&dir, &["监听 {addr} 启动失败".to_owned()]).unwrap(),
        [Violation::UntranslatedIdentity {
            language: "en".to_owned(),
            key: "监听 {addr} 启动失败".to_owned()
        }]
    );
}

#[test]
fn extract_finds_literal_keys_and_skips_tests() {
    let dir = tempfile_dir();
    std::fs::write(
        dir.join("lib.rs"),
        r#"
            fn demo(lang: &str) {
                let _ = fg_i18n::tr!(lang, "监听 {addr} 启动失败", addr = "x");
                let _ = fg_i18n::tr!(lang, "无参数键");
                let _ = fg_i18n::tr!(lang, "no han characters");
                let nested = vec![fg_i18n::tr!(format!("{lang}"), "嵌套（括号）键")];
                let _ = nested;
                let quote = fg_i18n::tr!(lang, "带 \"引号\" 的键");
                let _ = quote;
            }
        "#,
    )
    .unwrap();
    std::fs::create_dir(dir.join("tests")).unwrap();
    std::fs::write(
        dir.join("tests/ignored.rs"),
        r#"#[test] fn t() { let _ = fg_i18n::tr!("测试目录不参与提取"); }"#,
    )
    .unwrap();
    let keys = extract_literals(std::slice::from_ref(&dir)).unwrap();
    assert_eq!(
        keys,
        [
            "嵌套（括号）键".to_owned(),
            "带 \"引号\" 的键".to_owned(),
            "无参数键".to_owned(),
            "监听 {addr} 启动失败".to_owned()
        ]
    );
}

fn tempfile_dir() -> PathBuf {
    // xtask has no tempfile dependency; hand-roll a unique directory.
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let sequence =
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + std::process::id() as usize;
    let dir = std::env::temp_dir().join(format!("xtask-i18n-test-{sequence}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
