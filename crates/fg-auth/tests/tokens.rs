use std::{
    fs,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use fg_auth::token::{TokenError, TokenInput, TokenManager};
use fg_config::ConfigStore;
use ring::digest;
use serde_json::{Value, json};
use time::{OffsetDateTime, macros::datetime};

const NOW: OffsetDateTime = datetime!(2026-11-26 00:00 UTC);

fn input() -> TokenInput {
    TokenInput {
        name: "fixture automation".into(),
        scopes: vec![
            "webservice:read".into(),
            "logs:read".into(),
            "webservice:read".into(),
        ],
        expires_at: None,
        disabled: false,
        group: Some(" jobs ".into()),
    }
}

fn domains() -> [String; 2] {
    ["webservice".into(), "logs".into()]
}

#[test]
fn token_signing_keeps_plaintext_one_time_and_rotation_invalidates_old_value() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    store.enable_history(3, &[]);
    let tokens = TokenManager::open(store.clone(), domains(), Instant::now())?;
    assert!(TokenManager::open(store.clone(), domains(), Instant::now()).is_err());
    let (view, original) = tokens.create(input(), NOW)?;
    assert_eq!(view.scopes, ["logs:read", "webservice:read"]);
    assert_eq!(view.group, "jobs");
    assert_eq!(original.len(), 52);
    assert!(original.starts_with("gtl_"));
    let files = store.load_raw("tokens")?.context("persisted tokens")?;
    let disk: Value = serde_json::from_slice(&files)?;
    assert_eq!(disk["tokens"][0]["hash"].as_str().unwrap().len(), 64);
    assert!(!std::str::from_utf8(&files)?.contains(&original));
    let listed = serde_json::to_string(&tokens.list(NOW))?;
    assert!(!listed.contains(&original));
    assert!(!listed.contains("hash"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dir.path().join("tokens.json"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let identity = tokens.authenticate(&original, NOW, None)?;
    assert_eq!(identity.id(), view.id);
    assert_eq!(identity.name(), view.name);
    assert_eq!(identity.scopes(), view.scopes);
    let fresh = tokens.regenerate(&view.id)?;
    assert_ne!(original, fresh);
    assert!(matches!(
        tokens.authenticate(&original, NOW, None),
        Err(TokenError::Invalid)
    ));
    assert!(tokens.authenticate(&fresh, NOW, None).is_ok());
    tokens.delete(&view.id)?;
    assert!(matches!(
        tokens.authenticate(&fresh, NOW, None),
        Err(TokenError::Invalid)
    ));
    assert!(store.versions("tokens")?.is_empty());
    Ok(())
}

#[test]
fn token_usage_is_visible_immediately_and_flush_is_throttled() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let tokens = TokenManager::open(store.clone(), domains(), Instant::now())?;
    let (_, raw) = tokens.create(input(), NOW)?;
    let start = Instant::now();
    let first = "192.0.2.5".parse()?;
    tokens.authenticate(&raw, NOW, Some(first))?;
    assert_eq!(tokens.list(NOW)[0].last_used_at, Some(NOW));
    assert_eq!(tokens.list(NOW)[0].last_used_ip, "192.0.2.5");
    assert!(!tokens.flush_usage(start + Duration::from_secs(30))?);
    assert!(tokens.flush_usage(start + Duration::from_secs(60))?);
    let last = NOW + time::Duration::seconds(1);
    tokens.authenticate(&raw, last, Some("::ffff:198.51.100.9".parse()?))?;
    assert!(!tokens.flush_usage(start + Duration::from_secs(119))?);
    assert!(tokens.flush_usage_on_shutdown()?);
    assert!(!tokens.flush_usage_on_shutdown()?);
    drop(tokens);
    let tokens = TokenManager::open(store, domains(), Instant::now())?;
    let view = &tokens.list(last)[0];
    assert_eq!(view.last_used_at, Some(last));
    assert_eq!(view.last_used_ip, "198.51.100.9");
    Ok(())
}

#[test]
fn token_validation_rejects_bad_input_and_keeps_existing_unbuilt_scopes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let tokens = TokenManager::open(store.clone(), domains(), Instant::now())?;
    for invalid in [
        TokenInput {
            name: " ".into(),
            ..input()
        },
        TokenInput {
            name: "字".repeat(65),
            ..input()
        },
        TokenInput {
            scopes: Vec::new(),
            ..input()
        },
        TokenInput {
            scopes: vec!["webservice:root".into()],
            ..input()
        },
        TokenInput {
            scopes: vec!["absent:read".into()],
            ..input()
        },
        TokenInput {
            expires_at: Some(NOW),
            ..input()
        },
    ] {
        assert!(tokens.create(invalid, NOW).is_err());
    }
    let expiry = NOW + time::Duration::seconds(5);
    let (view, raw) = tokens.create(
        TokenInput {
            expires_at: Some(expiry),
            ..input()
        },
        NOW,
    )?;
    assert!(tokens.authenticate(&raw, NOW, None).is_ok());
    assert!(matches!(
        tokens.authenticate(&raw, expiry, None),
        Err(TokenError::Expired)
    ));
    drop(tokens);

    let tokens = TokenManager::open(store, ["logs".into()], Instant::now())?;
    let view = tokens.update(
        &view.id,
        TokenInput {
            disabled: true,
            expires_at: Some(expiry),
            group: None,
            scopes: vec!["logs:read".into()],
            ..input()
        },
        expiry,
    )?;
    assert_eq!(view.scopes, ["logs:read", "webservice:read"]);
    assert_eq!(view.group, "jobs");
    assert!(matches!(
        tokens.authenticate(&raw, NOW, None),
        Err(TokenError::Disabled)
    ));
    assert!(matches!(
        tokens.authenticate("gtl_invalid", NOW, None),
        Err(TokenError::Invalid)
    ));
    Ok(())
}

#[test]
fn token_write_failure_keeps_the_published_credential() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let tokens = TokenManager::open(store, domains(), Instant::now())?;
    let (view, raw) = tokens.create(input(), NOW)?;
    let path = dir.path().join("tokens.json");
    let backup = dir.path().join("tokens-fixture-backup");
    fs::rename(&path, &backup)?;
    fs::create_dir(&path)?;
    assert!(tokens.regenerate(&view.id).is_err());
    assert!(tokens.authenticate(&raw, NOW, None).is_ok());
    fs::remove_dir(&path)?;
    fs::rename(&backup, &path)?;
    tokens.regenerate(&view.id)?;
    assert!(matches!(
        tokens.authenticate(&raw, NOW, None),
        Err(TokenError::Invalid)
    ));
    Ok(())
}

#[test]
fn token_capacity_and_imported_legacy_records_are_bounded() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    store.save("tokens", &json!({"tokens":null}))?;
    let tokens = TokenManager::open(store.clone(), domains(), Instant::now())?;
    assert!(tokens.list(NOW).is_empty());
    drop(tokens);
    let legacy = "fixture-existing-legacy-value";
    let mut imported = vec![json!({
        "id":"000000000000", "name":"Legacy", "hash":data_encoding::HEXLOWER.encode(digest::digest(&digest::SHA256, legacy.as_bytes()).as_ref()),
        "hint":"fixt…alue", "scopes":["*"], "legacy":true, "createdAt":"2026-11-26T00:00:00Z"
    })];
    for index in 1..100 {
        imported.push(json!({
            "id":format!("{index:012x}"), "name":"Fixture", "hash":format!("{index:064x}"),
            "hint":"gtl_0000…0000", "scopes":["logs:read"], "createdAt":"2026-11-26T00:00:00Z"
        }));
    }
    store.save("tokens", &json!({"tokens":imported,"ordered":true}))?;
    let tokens = TokenManager::open(store, domains(), Instant::now())?;
    assert_eq!(tokens.list(NOW).len(), 100);
    assert_eq!(tokens.authenticate(legacy, NOW, None)?.scopes(), ["*"]);
    assert!(tokens.create(input(), NOW).is_err());
    assert!(
        tokens
            .import_legacy("fixture-another-legacy-value", NOW)
            .is_err()
    );
    Ok(())
}

#[test]
fn legacy_settings_migration_is_idempotent_and_never_archives_plaintext() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    store.enable_history(4, &[]);
    let legacy = "fixture-legacy-settings-token";
    let raw = format!(
        r#"{{"port":8000,"apiToken":"{legacy}","future":{{"number":98765432109876543210987654321}}}}"#
    );
    store.write_raw("ferrumgate", raw.as_bytes())?;
    let tokens = TokenManager::open(store.clone(), domains(), Instant::now())?;
    assert!(tokens.import_legacy(legacy, NOW)?);
    assert!(tokens.migrate_legacy_settings("ferrumgate", NOW)?);
    assert!(!tokens.migrate_legacy_settings("ferrumgate", NOW)?);
    assert_eq!(tokens.list(NOW).len(), 1);
    assert!(tokens.list(NOW)[0].legacy);
    assert_eq!(tokens.authenticate(legacy, NOW, None)?.scopes(), ["*"]);
    assert!(store.versions("ferrumgate")?.is_empty());
    let settings = store.load_raw("ferrumgate")?.context("migrated settings")?;
    let text = std::str::from_utf8(&settings)?;
    assert!(text.contains("98765432109876543210987654321"));
    assert!(!text.contains("apiToken"));
    assert!(!text.contains(legacy));
    assert!(!store.replace_unversioned("ferrumgate", raw.as_bytes(), b"{}")?);
    assert_eq!(
        store.load_raw("ferrumgate")?.as_deref(),
        Some(settings.as_slice())
    );
    assert!(
        !std::str::from_utf8(&store.load_raw("tokens")?.context("token records")?)?
            .contains(legacy)
    );
    drop(tokens);
    let tokens = TokenManager::open(store, domains(), Instant::now())?;
    assert!(tokens.authenticate(legacy, NOW, None).is_ok());
    Ok(())
}

#[test]
fn legacy_migration_preserves_the_source_until_token_storage_succeeds() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    store.save("ferrumgate", &json!({"apiToken":"tiny"}))?;
    let source = store.load_raw("ferrumgate")?;
    let tokens = TokenManager::open(store.clone(), domains(), Instant::now())?;
    let unavailable = dir.path().join("tokens.json");
    fs::create_dir(&unavailable)?;
    assert!(tokens.migrate_legacy_settings("ferrumgate", NOW).is_err());
    assert_eq!(store.load_raw("ferrumgate")?, source);
    assert!(matches!(
        tokens.authenticate("tiny", NOW, None),
        Err(TokenError::Invalid)
    ));
    fs::remove_dir(unavailable)?;
    assert!(tokens.migrate_legacy_settings("ferrumgate", NOW)?);
    assert_eq!(tokens.list(NOW)[0].hint, "…");

    let (native, raw) = tokens.create(
        TokenInput {
            disabled: true,
            ..input()
        },
        NOW,
    )?;
    store.save("ferrumgate", &json!({"apiToken":raw}))?;
    assert!(tokens.migrate_legacy_settings("ferrumgate", NOW)?);
    let saved = tokens.list(NOW);
    let retained = saved
        .iter()
        .find(|view| view.id == native.id)
        .context("retained token")?;
    assert!(!retained.legacy);
    assert!(retained.disabled);
    assert_eq!(retained.scopes, native.scopes);
    Ok(())
}

#[test]
fn scope_inheritance_keeps_existing_grants_and_only_adds_uncovered_access() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let tokens = TokenManager::open(store.clone(), ["old".into(), "new".into()], Instant::now())?;
    let issued = [
        vec!["old:read"],
        vec!["*:read", "old:write"],
        vec!["*:read", "old:read"],
        vec!["new:write", "old:read"],
        vec!["*", "old:write"],
    ]
    .map(|scopes| {
        tokens.create(
            TokenInput {
                scopes: scopes.into_iter().map(str::to_owned).collect(),
                ..input()
            },
            NOW,
        )
    });
    let issued = issued.into_iter().collect::<Result<Vec<_>>>()?;
    tokens.set_domains(["new".into(), "new".into()]);
    assert_eq!(tokens.domains(), ["new"]);
    assert!(tokens.inherit_scopes("old", "*").is_err());
    assert_eq!(tokens.inherit_scopes("old", "old")?, 0);
    assert_eq!(tokens.inherit_scopes("old", "new")?, 2);
    let saved = store.load_raw("tokens")?;
    assert_eq!(tokens.inherit_scopes("old", "new")?, 0);
    assert_eq!(store.load_raw("tokens")?, saved);
    drop(tokens);
    let tokens = TokenManager::open(store, ["new".into()], Instant::now())?;
    let expected = [
        vec!["new:read", "old:read"],
        vec!["*:read", "new:write", "old:write"],
        vec!["*:read", "old:read"],
        vec!["new:write", "old:read"],
        vec!["*", "old:write"],
    ];
    for ((view, raw), scopes) in issued.iter().zip(expected) {
        let identity = tokens.authenticate(raw, NOW, None)?;
        assert_eq!(identity.id(), view.id);
        assert_eq!(identity.scopes(), scopes);
    }
    Ok(())
}
