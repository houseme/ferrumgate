use std::{fs::TryLockError, sync::Arc};

use anyhow::{Context, Result, ensure};
use fg_config::{ConfigStore, Loaded};
use serde::{Deserialize, Serialize};

use crate::{
    AccountManager,
    account::{ACCOUNT, open_lock, random_urlsafe},
    password::{self, check_password_strength},
};

const PENDING: &str = "account-reset";
const LOCK: &str = ".account-reset.lock";

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResetRequest {
    id: String,
    password_hash: Option<String>,
    disable_totp: bool,
}

impl ResetRequest {
    pub fn password(password: &str, disable_totp: bool) -> Result<Self> {
        check_password_strength("", password)?;
        Ok(Self {
            id: random_urlsafe::<16>()?,
            password_hash: Some(password::hash(password)?),
            disable_totp,
        })
    }

    pub fn totp() -> Result<Self> {
        Ok(Self {
            id: random_urlsafe::<16>()?,
            password_hash: None,
            disable_totp: true,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResetStatus {
    Applied,
    Pending,
}

pub fn submit_reset(store: Arc<ConfigStore>, mut request: ResetRequest) -> Result<ResetStatus> {
    let lock = open_lock(&store, LOCK)?;
    lock.lock().context("lock account reset queue")?;
    ensure!(
        store.load_raw(ACCOUNT)?.is_some(),
        "administrator account has not been initialized"
    );
    if let Loaded::Found(previous) = store.load::<ResetRequest>(PENDING)? {
        request.password_hash = request.password_hash.or(previous.password_hash);
        request.disable_totp |= previous.disable_totp;
    }
    store.save(PENDING, &request)?;
    match AccountManager::open(store, None) {
        Ok((manager, _)) => {
            manager.apply_reset(&request)?;
            manager.store.remove(PENDING)?;
            Ok(ResetStatus::Applied)
        }
        Err(error)
            if matches!(
                error.downcast_ref::<TryLockError>(),
                Some(TryLockError::WouldBlock)
            ) =>
        {
            Ok(ResetStatus::Pending)
        }
        Err(error) => Err(error),
    }
}

impl AccountManager {
    pub fn apply_pending_reset(&self) -> Result<bool> {
        if !self.store.dir().join("account-reset.json").exists() {
            return Ok(false);
        }
        let lock = open_lock(&self.store, LOCK)?;
        lock.lock().context("lock account reset queue")?;
        let Loaded::Found(request) = self.store.load::<ResetRequest>(PENDING)? else {
            return Ok(false);
        };
        let changed = self.apply_reset(&request)?;
        self.store.remove(PENDING)?;
        Ok(changed)
    }

    fn apply_reset(&self, request: &ResetRequest) -> Result<bool> {
        ensure!(
            request.id.len() == 22
                && (request.password_hash.is_some() || request.disable_totp)
                && request
                    .password_hash
                    .as_ref()
                    .is_none_or(|hash| hash.parse::<bcrypt::HashParts>().is_ok()),
            "invalid administrator reset request"
        );
        let mut writer = self.writer.lock().expect("account writer poisoned");
        let current = self.snapshot.load();
        if current.account.last_reset.as_deref() == Some(&request.id) {
            *writer = None;
            self.limiter.clear_failures();
            return Ok(false);
        }
        let mut next = current.account.clone();
        if let Some(hash) = &request.password_hash {
            next.password_hash.clone_from(hash);
            next.password_login_off = false;
            next.using_default_password = false;
            next.weak_password = false;
        }
        if request.disable_totp {
            next.totp_secret.clear();
            next.totp_last_step = None;
        }
        next.last_reset = Some(request.id.clone());
        next.session_secret = random_urlsafe::<32>()?;
        next.invalidate_sessions()?;
        self.save(next)?;
        *writer = None;
        self.limiter.clear_failures();
        self.report_reset();
        Ok(true)
    }
}
