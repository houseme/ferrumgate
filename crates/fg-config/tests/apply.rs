use std::fs;

use anyhow::Result;
use fg_config::{ConfigStore, apply::apply_config_dir};

#[test]
fn apply_writes_changed_file_once_and_skips_identical_content() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    let source = tempfile::tempdir()?;
    fs::write(source.path().join("ddns.json"), r#"{"tasks":[]}"#)?;

    let first = apply_config_dir(&store, source.path())?;
    assert_eq!(first.applied, 1);
    assert_eq!(first.skipped, 0);
    assert_eq!(first.names, ["ddns"]);
    assert_eq!(
        store.load_raw("ddns")?.as_deref(),
        Some(
            r#"{"tasks":[]}
"#
            .as_bytes()
        ),
        "the stored file carries the trailing newline"
    );

    let second = apply_config_dir(&store, source.path())?;
    assert_eq!(second.applied, 0);
    assert_eq!(second.skipped, 1);
    Ok(())
}

#[test]
fn apply_appends_missing_newline_before_comparing() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    store.save("ddns", &serde_json::json!({"tasks": []}))?;
    let before = store.load_raw("ddns")?.expect("stored file");

    let source = tempfile::tempdir()?;
    let trimmed = &before[..before.len() - 1];
    assert_eq!(trimmed.last(), Some(&b'}'));
    fs::write(source.path().join("ddns.json"), trimmed)?;
    let report = apply_config_dir(&store, source.path())?;
    assert_eq!(report.applied, 0, "missing newline alone is not a change");
    assert_eq!(report.skipped, 1);
    Ok(())
}

#[test]
fn apply_preserves_replaced_content_in_history() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    store.enable_history(10, &[]);
    store.write_raw("ddns", b"{\"previous\":true}\n")?;

    let source = tempfile::tempdir()?;
    fs::write(source.path().join("ddns.json"), r#"{"tasks":[]}"#)?;
    apply_config_dir(&store, source.path())?;

    let versions = store.versions("ddns")?;
    assert_eq!(versions.len(), 1);
    assert_eq!(
        store.read_version("ddns", &versions[0].id)?,
        b"{\"previous\":true}\n",
        "the replaced content is rollback-readable"
    );
    Ok(())
}

#[test]
fn apply_rejects_account_and_tokens_without_partial_writes() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    let source = tempfile::tempdir()?;
    fs::write(source.path().join("aa-first.json"), "{}")?;
    fs::write(source.path().join("account.json"), "{}")?;
    fs::write(source.path().join("tokens.json"), "{}")?;

    let error = apply_config_dir(&store, source.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("account"), "{error}");
    assert!(
        store.load_raw("aa-first")?.is_none(),
        "no file is written when another is rejected"
    );

    fs::remove_file(source.path().join("account.json"))?;
    fs::remove_file(source.path().join("tokens.json"))?;
    let report = apply_config_dir(&store, source.path())?;
    assert_eq!(report.names, ["aa-first"]);
    Ok(())
}

#[test]
fn apply_rejects_invalid_json_and_names_the_file() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    let source = tempfile::tempdir()?;
    fs::write(source.path().join("broken.json"), "{\"tasks\":")?;

    let error = apply_config_dir(&store, source.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("broken.json"), "{error}");
    assert!(error.contains("1 candidate file"), "{error}");
    Ok(())
}

#[test]
fn apply_rejects_invalid_configuration_names() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    let source = tempfile::tempdir()?;
    fs::write(source.path().join("Not-A-Name.json"), "{}")?;
    let error = apply_config_dir(&store, source.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("Not-A-Name.json"), "{error}");
    Ok(())
}

#[test]
fn apply_ignores_subdirectories_hidden_and_other_extensions() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    let source = tempfile::tempdir()?;
    fs::create_dir(source.path().join("nested"))?;
    fs::write(source.path().join("nested/inner.json"), "{}")?;
    fs::write(source.path().join(".hidden.json"), "{}")?;
    fs::write(source.path().join("notes.txt"), "not json")?;
    fs::write(source.path().join("ddns.json"), "{}")?;

    let report = apply_config_dir(&store, source.path())?;
    assert_eq!(report.names, ["ddns"]);
    assert!(store.load_raw("inner")?.is_none());
    assert!(store.load_raw("hidden")?.is_none());
    Ok(())
}

#[test]
fn apply_processes_files_in_name_order() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    let source = tempfile::tempdir()?;
    for name in ["zeta", "alpha", "mid-dle"] {
        fs::write(source.path().join(format!("{name}.json")), "{}")?;
    }
    let report = apply_config_dir(&store, source.path())?;
    assert_eq!(report.names, ["alpha", "mid-dle", "zeta"]);
    Ok(())
}

#[test]
fn apply_registers_the_source_directory_as_protected() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    let source = tempfile::tempdir()?;
    fs::write(source.path().join("ddns.json"), "{}")?;
    apply_config_dir(&store, source.path())?;
    assert!(
        fg_core::fsperm::inside(source.path()).is_some(),
        "the declarative directory is never served externally"
    );
    Ok(())
}

#[test]
fn apply_reports_a_missing_source_directory() -> Result<()> {
    let config = tempfile::tempdir()?;
    let store = ConfigStore::open(config.path())?;
    let missing = config.path().join("absent");
    let error = apply_config_dir(&store, &missing).unwrap_err().to_string();
    assert!(error.contains("declarative directory"), "{error}");
    Ok(())
}
