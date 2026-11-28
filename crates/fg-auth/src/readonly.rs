use std::{collections::HashMap, fmt, time::SystemTime};

use anyhow::{Context, Result, ensure};
use aws_lc_rs::digest;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::{
    AccountManager, CredentialChangeRejected, Role,
    account::Account,
    password::{self, check_password_strength},
    session::{Snapshot, unix_seconds},
};

const MAX_USERS: usize = 20;
const MAX_USERNAME_BYTES: usize = 64;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ReadonlyUser {
    pub username: String,
    pub password_hash: String,
    role: Role,
    #[serde(default)]
    pub session_epoch: u64,
}

#[derive(Debug)]
pub struct ReadonlyUserNotFound;

impl fmt::Display for ReadonlyUserNotFound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("read-only account was not found")
    }
}

impl std::error::Error for ReadonlyUserNotFound {}

#[derive(Debug, PartialEq, Eq)]
pub struct ReadonlyUserInfo {
    pub username: String,
}

pub(super) fn versions(account: &Account) -> Result<HashMap<String, String>> {
    ensure!(
        account.users.len() <= MAX_USERS,
        "read-only account count exceeds its limit"
    );
    let mut versions = HashMap::with_capacity(account.users.len());
    for user in &account.users {
        ensure!(
            user.role == Role::Readonly
                && valid_name(&user.username)
                && user.username != account.username,
            "invalid read-only account"
        );
        ensure!(
            user.password_hash.parse::<bcrypt::HashParts>().is_ok(),
            "invalid read-only account password hash"
        );
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(user.password_hash.as_bytes());
        hash.update(&user.session_epoch.to_be_bytes());
        let version = URL_SAFE_NO_PAD.encode(&hash.finish().as_ref()[..16]);
        ensure!(
            versions.insert(user.username.clone(), version).is_none(),
            "duplicate read-only account"
        );
    }
    Ok(versions)
}

fn valid_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= MAX_USERNAME_BYTES
        && !name.chars().any(char::is_control)
}

impl AccountManager {
    pub fn readonly_users(&self) -> Vec<ReadonlyUserInfo> {
        self.snapshot
            .load()
            .account
            .users
            .iter()
            .map(|user| ReadonlyUserInfo {
                username: user.username.clone(),
            })
            .collect()
    }

    pub fn add_readonly_user(&self, token: &str, username: &str, password: &str) -> Result<()> {
        let username = username.trim();
        ensure!(
            valid_name(username),
            CredentialChangeRejected("invalid read-only account username")
        );
        let current = self.snapshot.load_full();
        require_admin(&current, token)?;
        can_add(&current.account, username)?;
        check_password_strength(username, password)?;
        let password_hash = password::hash(password)?;
        self.edit_readonly(token, |next| {
            can_add(next, username)?;
            next.users.push(ReadonlyUser {
                username: username.into(),
                password_hash,
                role: Role::Readonly,
                session_epoch: 0,
            });
            Ok(())
        })
    }

    pub fn reset_readonly_password(
        &self,
        token: &str,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let current = self.snapshot.load_full();
        require_admin(&current, token)?;
        let existing = current
            .account
            .users
            .iter()
            .find(|user| user.username == username)
            .ok_or(ReadonlyUserNotFound)?;
        check_password_strength(username, password)?;
        let password_hash = password::hash(password)?;
        self.edit_readonly(token, |next| {
            let user = next
                .users
                .iter_mut()
                .find(|user| user.username == username)
                .ok_or(ReadonlyUserNotFound)?;
            ensure!(
                user.password_hash == existing.password_hash,
                CredentialChangeRejected("read-only account changed during verification")
            );
            user.password_hash = password_hash;
            Ok(())
        })
    }

    pub fn delete_readonly_user(&self, token: &str, username: &str) -> Result<()> {
        self.edit_readonly(token, |next| {
            let index = next
                .users
                .iter()
                .position(|user| user.username == username)
                .ok_or(ReadonlyUserNotFound)?;
            next.users.remove(index);
            Ok(())
        })
    }

    fn edit_readonly(
        &self,
        token: &str,
        edit: impl FnOnce(&mut Account) -> Result<()>,
    ) -> Result<()> {
        let _writer = self.writer.lock().expect("account writer poisoned");
        let current = self.snapshot.load();
        require_admin(&current, token)?;
        let mut next = current.account.clone();
        edit(&mut next)?;
        self.save(next)
    }
}

fn can_add(account: &Account, username: &str) -> Result<()> {
    ensure!(
        username != account.username && !account.users.iter().any(|user| user.username == username),
        CredentialChangeRejected("account username already exists")
    );
    ensure!(
        account.users.len() < MAX_USERS,
        CredentialChangeRejected("read-only account limit reached")
    );
    Ok(())
}

fn require_admin(snapshot: &Snapshot, token: &str) -> Result<()> {
    let time = unix_seconds(SystemTime::now()).context("system clock predates Unix epoch")?;
    ensure!(
        snapshot.verify_admin(token, time).is_some(),
        CredentialChangeRejected("administrator session is invalid")
    );
    ensure!(
        !snapshot.account.must_change_password(),
        CredentialChangeRejected("administrator password must be changed")
    );
    Ok(())
}
