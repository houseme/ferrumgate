use std::sync::Arc;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fg_auth::{
    AccountManager, LoginError, LoginLimits,
    passkey::{Passkeys, Url},
};
use fg_config::ConfigStore;
use serde_json::json;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

const PASSWORD: &str = "fixture-administrator-password";

fn account() -> Result<(tempfile::TempDir, Arc<ConfigStore>, Arc<AccountManager>)> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    store.save(
        "account",
        &json!({
            "username":"operator",
            "passwordHash":bcrypt::hash(PASSWORD, 4)?,
            "sessionSecret":"fixture-session-secret-for-tests-only",
        }),
    )?;
    let (manager, _) = AccountManager::open(store.clone(), None)?;
    Ok((dir, store, Arc::new(manager)))
}

#[test]
fn passkey_requires_a_configured_secure_domain_or_localhost() -> Result<()> {
    let (_dir, _, manager) = account()?;
    for origin in [
        "http://admin.example.test",
        "https://192.0.2.1",
        "https://admin.example.test/panel",
    ] {
        assert!(Passkeys::new(manager.clone(), &Url::parse(origin)?).is_err());
    }
    assert!(Passkeys::new(manager.clone(), &Url::parse("http://localhost:8080")?).is_ok());
    assert!(Passkeys::new(manager, &Url::parse("https://admin.example.test")?).is_ok());
    Ok(())
}

#[test]
fn passkey_registration_and_login_bind_challenges_and_persist_counters() -> Result<()> {
    let (_dir, store, manager) = account()?;
    let origin = Url::parse("https://admin.example.test")?;
    let peer = "198.51.100.7".parse()?;
    let passkeys = Passkeys::new(manager.clone(), &origin)?;
    let administrator = manager
        .login("operator", PASSWORD)?
        .context("administrator session")?;
    let second = manager
        .login("operator", PASSWORD)?
        .context("second administrator session")?;
    assert!(
        passkeys
            .set_password_login_disabled(&administrator.token, PASSWORD, true)
            .is_err()
    );

    let mut authenticator = SoftPasskey::new(true);
    let registration = passkeys.begin_registration(&administrator.token)?;
    let challenge = URL_SAFE_NO_PAD.encode(registration.public_key.challenge.as_slice());
    let proof = authenticator.do_registration(origin.clone(), registration)?;
    assert!(
        passkeys
            .finish_registration(&second.token, &challenge, PASSWORD, "fixture", &proof)
            .is_err()
    );
    let record = passkeys.finish_registration(
        &administrator.token,
        &challenge,
        PASSWORD,
        "fixture",
        &proof,
    )?;
    assert_eq!(passkeys.list()[0].id, record.id);
    assert!(
        passkeys
            .finish_registration(
                &administrator.token,
                &challenge,
                PASSWORD,
                "fixture",
                &proof
            )
            .is_err()
    );

    manager.configure_login_limits(LoginLimits {
        unknown_failures: Some(1),
        ..LoginLimits::default()
    })?;
    assert!(matches!(
        manager.login_from(peer, "operator", "wrong"),
        Err(LoginError::InvalidCredentials)
    ));
    assert!(matches!(
        manager.login_from(peer, "operator", PASSWORD),
        Err(LoginError::Flood)
    ));
    let wrong_origin = passkeys.begin_login(peer)?;
    let challenge = URL_SAFE_NO_PAD.encode(wrong_origin.public_key.challenge.as_slice());
    let assertion = authenticator
        .do_authentication(Url::parse("https://admin.example.test:8443")?, wrong_origin)?;
    assert!(matches!(
        passkeys.finish_login(peer, &challenge, &assertion),
        Err(LoginError::InvalidCredentials)
    ));

    let older = passkeys.begin_login(peer)?;
    let newer = passkeys.begin_login(peer)?;
    let older_challenge = URL_SAFE_NO_PAD.encode(older.public_key.challenge.as_slice());
    let newer_challenge = URL_SAFE_NO_PAD.encode(newer.public_key.challenge.as_slice());
    let older_proof = authenticator.do_authentication(origin.clone(), older)?;
    let newer_proof = authenticator.do_authentication(origin.clone(), newer)?;
    let (session, name) = passkeys.finish_login(peer, &newer_challenge, &newer_proof)?;
    assert_eq!(name, "operator");
    assert!(manager.identify(&session.token).is_some());
    assert!(matches!(
        passkeys.finish_login(peer, &older_challenge, &older_proof),
        Err(LoginError::InvalidCredentials)
    ));
    assert!(matches!(
        passkeys.finish_login(peer, &newer_challenge, &newer_proof),
        Err(LoginError::InvalidCredentials)
    ));
    passkeys.set_password_login_disabled(&session.token, PASSWORD, true)?;
    assert!(passkeys.password_login_disabled());
    assert!(
        passkeys
            .remove(&session.token, PASSWORD, &record.id)
            .is_err()
    );
    drop(passkeys);
    drop(manager);
    let (manager, _) = AccountManager::open(store, None)?;
    let passkeys = Passkeys::new(Arc::new(manager), &origin)?;
    assert!(passkeys.password_login_disabled());
    assert_eq!(passkeys.list()[0].id, record.id);
    let next = passkeys.begin_login(peer)?;
    let challenge = URL_SAFE_NO_PAD.encode(next.public_key.challenge.as_slice());
    let assertion = authenticator.do_authentication(origin, next)?;
    let (current, _) = passkeys.finish_login(peer, &challenge, &assertion)?;
    passkeys.set_password_login_disabled(&current.token, PASSWORD, false)?;
    passkeys.remove(&current.token, PASSWORD, &record.id)?;
    assert!(passkeys.list().is_empty());
    assert!(matches!(
        passkeys.begin_login(peer),
        Err(LoginError::InvalidCredentials)
    ));
    Ok(())
}
