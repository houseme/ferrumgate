use std::{
    fs,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use fg_auth::{AccountManager, LoginError, LoginLimits, PasswordIssue};
use fg_config::ConfigStore;
use fg_core::events::{Event, EventBus, Kind};
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

#[test]
fn concurrent_password_changes_keep_one_winner_and_invalidate_old_sessions() -> Result<()> {
    const CHANGES: [(&str, &str); 2] = [("keeper", "Fm9!rQ2-vNZ"), ("curator", "Cd7$mh3=YW")];
    let (_dir, store, mut account) = fixture()?;
    store.enable_history(10, &[]);
    account["usingDefaultPassword"] = json!(true);
    account["weakPassword"] = json!(true);
    store.save("account", &account)?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    let old = manager
        .login("operator", PASSWORD)?
        .context("old session")?;
    assert!(manager.identify(&old.token).unwrap().must_change_password);
    let before = store.load_raw("account")?;
    let weak = manager
        .change_credentials(PASSWORD, "keeper", "Password2024!")
        .unwrap_err();
    assert_eq!(
        weak.downcast_ref::<PasswordIssue>(),
        Some(&PasswordIssue::Common)
    );
    assert!(
        manager
            .change_credentials("wrong-password", "keeper", CHANGES[0].1)
            .is_err()
    );
    assert_eq!(store.load_raw("account")?, before);
    assert!(manager.identify(&old.token).is_some());

    let gate = std::sync::Barrier::new(CHANGES.len());
    let [first, second] = std::thread::scope(|scope| {
        let gate = &gate;
        let manager = &manager;
        CHANGES
            .map(|(user, password)| {
                scope.spawn(move || {
                    gate.wait();
                    manager.change_credentials(PASSWORD, user, password)
                })
            })
            .map(|task| task.join().unwrap())
    });
    assert_ne!(first.is_ok(), second.is_ok());
    let (winner, loser) = if first.is_ok() { (0, 1) } else { (1, 0) };
    assert!(manager.identify(&old.token).is_none());
    let saved: Value =
        serde_json::from_slice(&store.load_raw("account")?.context("stored credentials")?)?;
    assert_eq!(saved["username"], CHANGES[winner].0);
    assert_ne!(saved["sessionSecret"], account["sessionSecret"]);
    assert_eq!(saved["sessionEpoch"], 1);
    assert_eq!(saved["passkeys"], account["passkeys"]);
    assert!(store.versions("account")?.is_empty());

    drop(manager);
    let (manager, _) = AccountManager::open(store, None)?;
    assert!(manager.identify(&old.token).is_none());
    assert!(manager.login(CHANGES[winner].0, PASSWORD)?.is_none());
    assert!(manager.login(CHANGES[loser].0, CHANGES[loser].1)?.is_none());
    let current = manager
        .login(CHANGES[winner].0, CHANGES[winner].1)?
        .context("rotated credentials")?;
    let identity = manager
        .identify(&current.token)
        .context("updated identity")?;
    assert_eq!(identity.username, CHANGES[winner].0);
    assert!(!identity.must_change_password);
    Ok(())
}

#[tokio::test]
async fn lockout_notifies_once_and_remembers_successful_subnets_after_restart() -> Result<()> {
    let (_dir, store, account) = fixture()?;
    store.enable_history(10, &[]);
    store.save("account", &account)?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    let home = "2001:db8:1::19".parse()?;
    let renewed = "2001:db8:1::20".parse()?;
    let first = manager.login_from(home, "operator", PASSWORD)?;
    assert!(manager.identify(&first.token).is_some());
    assert!(store.versions("login-ips")?.is_empty());
    drop(manager);

    let bus = EventBus::default();
    let (sent, mut events) = tokio::sync::mpsc::unbounded_channel();
    let _subscription = bus.subscribe(move |event| {
        let _ = sent.send(event);
        std::future::ready(())
    })?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    let manager = manager.with_login_events(bus.clone());
    manager.configure_login_limits(LoginLimits {
        unknown_failures: Some(2),
        ..LoginLimits::default()
    })?;
    for address in ["192.0.2.1", "198.51.100.1"] {
        assert!(matches!(
            manager.login_from(address.parse()?, "operator", "wrong-password"),
            Err(LoginError::InvalidCredentials)
        ));
    }
    for address in ["192.0.2.2", "2001:db8:2::10"] {
        assert!(matches!(
            manager.login_from(address.parse()?, "operator", PASSWORD),
            Err(LoginError::Flood)
        ));
    }
    assert!(manager.login_from(renewed, "operator", PASSWORD).is_ok());
    bus.publish(Event::new(Kind::NotifyTest, "fixture"));
    let flood = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await?
        .context("flood event")?;
    assert_eq!(flood.kind, Kind::AuthFlood);
    assert_eq!(flood.args, [("failures", "2".into())]);
    let next = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await?
        .context("marker event")?;
    assert_eq!(next.kind, Kind::NotifyTest);
    let login_ips: Value =
        serde_json::from_slice(&store.load_raw("login-ips")?.context("persisted source")?)?;
    assert!(
        login_ips
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["key"] == "2001:db8:1::/64")
    );
    Ok(())
}

#[test]
fn totp_replay_is_rejected_concurrently_and_after_restart() -> Result<()> {
    use ring::hmac;

    let (dir, store, mut account) = fixture()?;
    let password = "Password2024!";
    account["passwordHash"] = json!(bcrypt::hash(password, 4)?);
    account["totpSecret"] = json!("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    store.save("account", &account)?;
    let before = store.load_raw("account")?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, b"12345678901234567890");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let digest = hmac::sign(&key, &(now / 30).to_be_bytes());
    let bytes = digest.as_ref();
    let start = usize::from(bytes[19] & 15);
    let value = u32::from_be_bytes(bytes[start..start + 4].try_into()?) & 0x7fff_ffff;
    let code = format!("{:06}", value % 1_000_000);
    let addr = "192.0.2.5".parse()?;
    assert!(matches!(
        manager.login_from(addr, "operator", password),
        Err(LoginError::TotpRequired)
    ));
    assert_eq!(store.load_raw("account")?, before);
    let path = dir.path().join("account.json");
    let backup = dir.path().join("account-fixture-backup");
    fs::rename(&path, &backup)?;
    fs::create_dir(&path)?;
    assert!(matches!(
        manager.login_with_totp_from(addr, "operator", password, Some(&code)),
        Err(LoginError::Internal(_))
    ));
    fs::remove_dir(&path)?;
    fs::rename(&backup, &path)?;

    let guard = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let (manager, code, guard) = (&manager, &code, &guard);
        let tasks = [addr, "198.51.100.9".parse().unwrap()].map(|addr| {
            scope.spawn(move || {
                guard.wait();
                manager.login_with_totp_from(addr, "operator", password, Some(code))
            })
        });
        tasks.map(|task| task.join().unwrap())
    });
    assert_eq!(results.iter().filter(|attempt| attempt.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .any(|attempt| matches!(attempt, Err(LoginError::InvalidCredentials)))
    );
    let session = results
        .into_iter()
        .find_map(Result::ok)
        .context("accepted TOTP")?;
    drop(manager);
    let (manager, _) = AccountManager::open(store, None)?;
    assert_eq!(
        manager
            .identify(&session.token)
            .context("persisted identity")?
            .password_issue(),
        "weak"
    );
    manager.configure_login_limits(LoginLimits {
        max_failures: 2,
        ..LoginLimits::default()
    })?;
    assert!(matches!(
        manager.login_with_totp_from(addr, "operator", password, Some(&code)),
        Err(LoginError::InvalidCredentials)
    ));
    assert!(matches!(
        manager.login_from(addr, "operator", password),
        Err(LoginError::TotpRequired)
    ));
    assert!(matches!(
        manager.login_with_totp_from(addr, "operator", password, Some("not-a-code")),
        Err(LoginError::InvalidCredentials)
    ));
    assert!(matches!(
        manager.login_from(addr, "operator", password),
        Err(LoginError::Locked(_))
    ));
    Ok(())
}

#[test]
fn legacy_password_flags_persist_and_validated_strong_logins_leave_the_account_unchanged()
-> Result<()> {
    for (password, issue) in [
        ("gately.cn", "default"),
        ("Password2024!", "weak"),
        ("Lk8$yN3-pv", ""),
    ] {
        let (dir, store, mut account) = fixture()?;
        account["passwordHash"] = json!(bcrypt::hash(password, 4)?);
        store.save("account", &account)?;
        let before = store.load_raw("account")?;
        let (manager, _) = AccountManager::open(store.clone(), None)?;
        assert!(manager.login("operator", "wrong")?.is_none());
        assert_eq!(store.load_raw("account")?, before);
        if issue == "weak" {
            let path = dir.path().join("account.json");
            let backup = dir.path().join("account-fixture-backup");
            fs::rename(&path, &backup)?;
            fs::create_dir(&path)?;
            assert!(manager.login("operator", password).is_err());
            fs::remove_dir(&path)?;
            fs::rename(&backup, &path)?;
        }
        let session = manager
            .login("operator", password)?
            .context("verified administrator session")?;
        if issue.is_empty() {
            assert_eq!(store.load_raw("account")?, before);
        }
        drop(manager);
        let (manager, _) = AccountManager::open(store, None)?;
        assert_eq!(
            manager
                .identify(&session.token)
                .context("persisted administrator identity")?
                .password_issue(),
            issue
        );
    }
    Ok(())
}
