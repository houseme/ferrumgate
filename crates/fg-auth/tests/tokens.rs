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
    Ok(())
}
