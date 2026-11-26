use std::{
    fs,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use fg_auth::AccountManager;
use fg_config::ConfigStore;
use serde_json::{Value, json};

const PASSWORD: &str = "fixture-admin-password";

fn fixture() -> Result<(tempfile::TempDir, Arc<ConfigStore>, Value)> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let account = json!({
        "username": "operator",
        "passwordHash": bcrypt::hash(PASSWORD, 4)?,
        "sessionSecret": "fixture-session-key-for-tests-only",
        "tokenTTLHours": 2,
        "passkeys": [{"id": "preserve-fixture-record"}],
    });
    Ok((dir, store, account))
}

#[test]
fn account_initializes_once_and_does_not_archive_credentials() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    store.enable_history(10, &[]);
    let (manager, generated) = AccountManager::open(store.clone(), None)?;
    let initial = generated.context("generated initial password")?;
    assert_eq!(initial.len(), 32);
    let disk = fs::read_to_string(dir.path().join("account.json"))?;
    assert!(!disk.contains(&initial));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dir.path().join("account.json"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(AccountManager::open(ConfigStore::open(dir.path())?, None).is_err());
    let session = manager
        .login("admin", &initial)?
        .context("initial session")?;
    let identity = manager.identify(&session.token).context("identity")?;
    assert_eq!(identity.username, "admin");
    assert!(identity.must_change_password);
    let remaining = session.expires_at.duration_since(SystemTime::now())?;
    assert!(
        (Duration::from_secs(72 * 3600 - 5)..=Duration::from_secs(72 * 3600)).contains(&remaining)
    );
    manager.revoke_all()?;
    assert!(manager.identify(&session.token).is_none());
    assert!(store.versions("account")?.is_empty());
    drop(manager);
    let (manager, generated) = AccountManager::open(store.clone(), None)?;
    assert!(generated.is_none());
    assert!(manager.identify(&session.token).is_none());
    assert!(manager.login("admin", &initial)?.is_some());
    assert!(store.versions("account")?.is_empty());
    Ok(())
}

#[test]
fn sessions_are_distinct_signed_and_revocation_survives_restart() -> Result<()> {
    let (_dir, store, account) = fixture()?;
    store.save("account", &account)?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    assert!(manager.login("wrong-user", PASSWORD)?.is_none());
    assert!(manager.login("operator", "wrong-password")?.is_none());
    assert!(manager.login("operator", &"a".repeat(73))?.is_none());
    let first = manager
        .login("operator", PASSWORD)?
        .context("first session")?;
    let second = manager
        .login("operator", PASSWORD)?
        .context("second session")?;
    assert_ne!(first.token, second.token);
    let mut changed = first.token.clone().into_bytes();
    changed[0] = if changed[0] == b'A' { b'B' } else { b'A' };
    assert!(manager.identify(std::str::from_utf8(&changed)?).is_none());
    assert!(manager.identify(&"a".repeat(4097)).is_none());
    manager.revoke(&first.token)?;
    let saved = store.load_raw("account")?;
    manager.revoke(&first.token)?;
    assert_eq!(store.load_raw("account")?, saved);
    assert!(manager.identify(&first.token).is_none());
    assert!(manager.identify(&second.token).is_some());
    drop(manager);
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    assert!(manager.identify(&first.token).is_none());
    assert!(manager.identify(&second.token).is_some());
    let persisted: Value = serde_json::from_slice(&saved.context("saved account")?)?;
    assert_eq!(persisted["passkeys"], account["passkeys"]);
    Ok(())
}

#[test]
fn full_revocation_list_invalidates_the_previous_epoch() -> Result<()> {
    let (_dir, store, mut account) = fixture()?;
    let expires = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
    account["revoked"] = (0..1024)
        .map(|id| json!({"id":format!("fixture-{id:014}"),"e":expires}))
        .collect();
    store.save("account", &account)?;
    let (manager, _) = AccountManager::open(store, None)?;
    let first = manager
        .login("operator", PASSWORD)?
        .context("first session")?;
    let second = manager
        .login("operator", PASSWORD)?
        .context("second session")?;
    manager.revoke(&first.token)?;
    assert!(manager.identify(&first.token).is_none());
    assert!(manager.identify(&second.token).is_none());
    let current = manager.login("operator", PASSWORD)?.context("new epoch")?;
    assert!(manager.identify(&current.token).is_some());
    Ok(())
}

#[test]
fn password_verification_respects_persisted_factor_requirements() -> Result<()> {
    let (_dir, store, mut account) = fixture()?;
    store.save("account", &account)?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    let session = manager.login("operator", PASSWORD)?.context("session")?;
    drop(manager);
    for (field, value) in [
        ("totpSecret", json!("fixture-mfa")),
        ("passwordLoginOff", json!(true)),
    ] {
        account[field] = value;
        store.save("account", &account)?;
        let (manager, _) = AccountManager::open(store.clone(), None)?;
        assert!(manager.login("operator", PASSWORD)?.is_none());
        if field == "totpSecret" {
            assert!(manager.identify(&session.token).is_none());
        }
        account.as_object_mut().unwrap().remove(field);
    }
    Ok(())
}

#[test]
fn failed_write_keeps_the_published_session_state() -> Result<()> {
    let (dir, store, account) = fixture()?;
    store.save("account", &account)?;
    let (manager, _) = AccountManager::open(store, None)?;
    let session = manager.login("operator", PASSWORD)?.context("session")?;
    let path = dir.path().join("account.json");
    let backup = dir.path().join("account-fixture-backup");
    fs::rename(&path, &backup)?;
    fs::create_dir(&path)?;
    assert!(manager.revoke(&session.token).is_err());
    assert!(manager.identify(&session.token).is_some());
    fs::remove_dir(path)?;
    fs::rename(backup, dir.path().join("account.json"))?;
    manager.revoke(&session.token)?;
    assert!(manager.identify(&session.token).is_none());
    Ok(())
}
