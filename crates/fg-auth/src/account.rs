use std::{
    fs::{File, OpenOptions},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{Context, Result, anyhow, ensure};
use arc_swap::ArcSwap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fg_config::{ConfigStore, Loaded};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::session::{Identity, Session, Snapshot, unix_seconds};

const ACCOUNT: &str = "account";
const MAX_PASSWORD_BYTES: usize = 72;
pub(super) const MAX_REVOKED: usize = 1024;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Account {
    pub username: String,
    pub password_hash: String,
    pub session_secret: String,
    #[serde(rename = "tokenTTLHours")]
    pub token_ttl_hours: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub totp_secret: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    users: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    passkeys: Vec<Value>,
    #[serde(skip_serializing_if = "is_false")]
    onboarding_pending: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub using_default_password: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub weak_password: bool,
    #[serde(skip_serializing_if = "is_false")]
    password_login_off: bool,
    pub session_epoch: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<Revoked>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revoked {
    pub id: String,
    #[serde(rename = "e")]
    pub expires: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Owns the only active writer for one account file.
pub struct AccountManager {
    store: Arc<ConfigStore>,
    snapshot: ArcSwap<Snapshot>,
    writer: Mutex<()>,
    _owner: File,
}

impl AccountManager {
    /// Loads the account or creates it. A random initial password is returned only on creation.
    pub fn open(
        store: Arc<ConfigStore>,
        initial_password: Option<&str>,
    ) -> Result<(Self, Option<String>)> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let owner = options
            .open(store.dir().join(".account.lock"))
            .context("open account lock")?;
        ensure!(
            owner.metadata()?.is_file(),
            "account lock must be a regular file"
        );
        owner
            .try_lock()
            .context("account directory already has a writer")?;
        let (snapshot, generated) = match store.load::<Account>(ACCOUNT)? {
            Loaded::Found(account) => (Snapshot::new(account)?, None),
            Loaded::Missing => {
                let generated = initial_password
                    .is_none()
                    .then(random_urlsafe::<24>)
                    .transpose()?;
                let password = initial_password
                    .or(generated.as_deref())
                    .expect("initial password");
                ensure!(
                    (8..=MAX_PASSWORD_BYTES).contains(&password.len()) && password != "gately.cn",
                    "invalid initial administrator password"
                );
                let account = Account {
                    username: "admin".into(),
                    password_hash: bcrypt::non_truncating_hash(password, bcrypt::DEFAULT_COST)
                        .map_err(|_| anyhow!("hash initial administrator password"))?,
                    session_secret: random_urlsafe::<32>()?,
                    onboarding_pending: true,
                    using_default_password: true,
                    ..Account::default()
                };
                let snapshot = Snapshot::new(account)?;
                store.save(ACCOUNT, &snapshot.account)?;
                (snapshot, generated)
            }
        };
        Ok((
            Self {
                store,
                snapshot: ArcSwap::from_pointee(snapshot),
                writer: Mutex::new(()),
                _owner: owner,
            },
            generated,
        ))
    }

    /// Checks the administrator password and signs a session. Call from a bounded blocking worker.
    pub fn login(&self, username: &str, password: &str) -> Result<Option<Session>> {
        let snapshot = self.snapshot.load_full();
        let account = &snapshot.account;
        if password.is_empty()
            || password.len() > MAX_PASSWORD_BYTES
            || account.password_login_off
            || !account.totp_secret.is_empty()
        {
            return Ok(None);
        }
        let accepted = bcrypt::verify(password, &account.password_hash)
            .map_err(|_| anyhow!("verify administrator password hash"))?;
        if !accepted || account.username != username {
            return Ok(None);
        }
        Ok(Some(snapshot.issue(SystemTime::now())?))
    }

    pub fn identify(&self, token: &str) -> Option<Identity> {
        let snapshot = self.snapshot.load();
        let now = unix_seconds(SystemTime::now())?;
        let _ = snapshot.verify(token, now)?;
        Some(Identity {
            username: snapshot.account.username.clone(),
            must_change_password: snapshot.account.using_default_password
                || snapshot.account.weak_password,
        })
    }

    /// Revokes a live token. Repeated revocations and expired tokens require no write.
    pub fn revoke(&self, token: &str) -> Result<()> {
        let _writer = self.writer.lock().expect("account writer poisoned");
        let snapshot = self.snapshot.load();
        let now = unix_seconds(SystemTime::now()).context("system clock predates Unix epoch")?;
        let Some((id, expires)) = snapshot.verify(token, now) else {
            return Ok(());
        };
        let mut next = snapshot.account.clone();
        next.revoked.retain(|token| token.expires > now);
        if next.revoked.len() == MAX_REVOKED {
            next.invalidate_sessions()?;
        } else {
            next.revoked.push(Revoked {
                id: id.into(),
                expires,
            });
        }
        self.save(next)
    }

    pub fn revoke_all(&self) -> Result<()> {
        let _writer = self.writer.lock().expect("account writer poisoned");
        let mut next = self.snapshot.load().account.clone();
        next.invalidate_sessions()?;
        self.save(next)
    }

    fn save(&self, account: Account) -> Result<()> {
        let next = Snapshot::new(account)?;
        let mut bytes =
            serde_json::to_vec_pretty(&next.account).context("encode administrator account")?;
        bytes.push(b'\n');
        let saved = self.store.write_raw(ACCOUNT, &bytes);
        // A failed directory sync can follow a successful replacement.
        if saved.is_ok() || self.store.load_raw(ACCOUNT).ok().flatten().as_deref() == Some(&bytes) {
            self.snapshot.store(Arc::new(next));
        }
        saved.map(|_| ())
    }
}

impl Account {
    fn invalidate_sessions(&mut self) -> Result<()> {
        self.session_epoch = self
            .session_epoch
            .checked_add(1)
            .context("session epoch exhausted")?;
        self.revoked.clear();
        Ok(())
    }
}

pub(super) fn random_urlsafe<const N: usize>() -> Result<String> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| anyhow!("get randomness for administrator credentials"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
