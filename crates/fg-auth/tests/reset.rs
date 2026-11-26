use anyhow::{Context, Result};
use fg_auth::{AccountManager, ResetRequest, ResetStatus, submit_reset};
use fg_config::ConfigStore;
use serde_json::{Value, json};

#[test]
fn resets_merge_online_expire_sessions_and_apply_offline() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    store.enable_history(10, &[]);
    let original = "fixture-administrator-password";
    let password = "nk8$Lw3=By9";
    store.save(
        "account",
        &json!({
            "username":"operator",
            "passwordHash":bcrypt::hash(original, 4)?,
            "sessionSecret":"fixture-session-secret-for-tests-only",
        }),
    )?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    let old = manager
        .login("operator", original)?
        .context("original session")?;
    assert_eq!(
        submit_reset(store.clone(), ResetRequest::password(password, false)?)?,
        ResetStatus::Pending
    );
    assert_eq!(
        submit_reset(store.clone(), ResetRequest::totp()?)?,
        ResetStatus::Pending
    );
    let queued = store.load_raw("account-reset")?.context("queued reset")?;
    assert!(manager.apply_pending_reset()?);
    assert!(manager.identify(&old.token).is_none());
    assert!(manager.login("operator", original)?.is_none());
    let current = manager
        .login("operator", password)?
        .context("current session")?;
    store.write_raw("account-reset", &queued)?;
    assert!(!manager.apply_pending_reset()?);
    assert!(manager.identify(&current.token).is_some());
    drop(manager);

    let mut account: Value =
        serde_json::from_slice(&store.load_raw("account")?.context("account")?)?;
    account["totpSecret"] = json!("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    store.save("account", &account)?;
    assert_eq!(
        submit_reset(store.clone(), ResetRequest::totp()?)?,
        ResetStatus::Applied
    );
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    assert!(!manager.totp_enabled());
    assert!(manager.identify(&current.token).is_none());
    assert!(manager.login("operator", password)?.is_some());
    assert!(store.versions("account").unwrap().is_empty());
    assert!(store.versions("account-reset").unwrap().is_empty());
    Ok(())
}
