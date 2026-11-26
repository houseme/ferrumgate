use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use fg_auth::{AccountManager, LoginError, LoginLimits, Role};
use fg_config::ConfigStore;
use serde_json::{Value, json};

const ADMIN_PASSWORD: &str = "fixture-administrator-password";
const VIEW_PASSWORD: &str = "fixture-viewer-password";

fn fixture() -> Result<(tempfile::TempDir, Arc<ConfigStore>, Value)> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let hash = bcrypt::hash(VIEW_PASSWORD, 4)?;
    let account = json!({
        "username":"operator",
        "passwordHash":bcrypt::hash(ADMIN_PASSWORD, 4)?,
        "sessionSecret":"fixture-session-key-for-tests-only",
        "users":[
            {"username":"viewer", "passwordHash":hash, "role":"readonly"},
            {"username":"observer", "passwordHash":hash, "role":"readonly"}
        ],
    });
    Ok((dir, store, account))
}

#[test]
fn readonly_login_keeps_administrator_failure_counters_and_safety_policy() -> Result<()> {
    let (_dir, store, mut account) = fixture()?;
    account["passwordLoginOff"] = json!(true);
    account["totpSecret"] = json!("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    store.save("account", &account)?;
    let (manager, _) = AccountManager::open(store, None)?;
    manager.configure_login_limits(LoginLimits {
        max_failures: 2,
        unknown_failures: None,
        ..LoginLimits::default()
    })?;
    let address = "192.0.2.1".parse()?;
    assert!(matches!(
        manager.login_from(address, "operator", ADMIN_PASSWORD),
        Err(LoginError::InvalidCredentials)
    ));
    let viewer = manager.login_from(address, "viewer", VIEW_PASSWORD)?;
    assert_eq!(
        manager
            .identify(&viewer.token)
            .context("view-only identity")?
            .role,
        Role::Readonly
    );
    assert!(manager.prepare_totp(&viewer.token).is_err());
    assert!(
        manager
            .delete_readonly_user(&viewer.token, "observer")
            .is_err()
    );
    assert!(matches!(
        manager.login_from(address, "operator", "wrong"),
        Err(LoginError::InvalidCredentials)
    ));
    assert!(matches!(
        manager.login_from(address, "viewer", VIEW_PASSWORD),
        Err(LoginError::Locked(_))
    ));

    manager.configure_login_limits(LoginLimits {
        unknown_failures: Some(1),
        ..LoginLimits::default()
    })?;
    let separate = "198.51.100.1".parse()?;
    assert!(
        manager
            .login_from(separate, "viewer", VIEW_PASSWORD)
            .is_ok()
    );
    assert!(matches!(
        manager.login_from("198.51.100.2".parse()?, "operator", "wrong"),
        Err(LoginError::InvalidCredentials)
    ));
    assert!(matches!(
        manager.login_from(separate, "viewer", VIEW_PASSWORD),
        Err(LoginError::Flood)
    ));
    Ok(())
}

#[test]
fn readonly_logout_at_revocation_limit_only_invalidates_that_account() -> Result<()> {
    let (_dir, store, mut account) = fixture()?;
    let expires = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
    account["revoked"] = (0..512)
        .map(|index| json!({"id":format!("fixture-{index}"), "e":expires}))
        .collect();
    store.save("account", &account)?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    let administrator = manager
        .login("operator", ADMIN_PASSWORD)?
        .context("administrator session")?;
    let first = manager
        .login("viewer", VIEW_PASSWORD)?
        .context("first viewer session")?;
    let second = manager
        .login("viewer", VIEW_PASSWORD)?
        .context("second viewer session")?;
    let other = manager
        .login("observer", VIEW_PASSWORD)?
        .context("observer session")?;
    manager.revoke(&first.token)?;
    assert!(manager.identify(&first.token).is_none());
    assert!(manager.identify(&second.token).is_none());
    drop(manager);
    let (manager, _) = AccountManager::open(store, None)?;
    assert!(manager.identify(&first.token).is_none());
    assert!(manager.identify(&second.token).is_none());
    assert!(manager.identify(&administrator.token).is_some());
    assert!(manager.identify(&other.token).is_some());
    Ok(())
}
