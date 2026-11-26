use std::{
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
pub use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url,
};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, Uuid, Webauthn, WebauthnBuilder,
};

use crate::{
    AccountManager, CredentialChangeRejected, LoginError, Session,
    lockout::{LoginLimiter, source_key},
    password,
    session::{Snapshot, unix_seconds},
};

const TTL: Duration = Duration::from_secs(180);
const MAX_SCOPE: usize = 256;
const MAX_PER_SCOPE: usize = 16;
const MAX_PASSKEYS: usize = 10;

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum StoredPasskey {
    Native(Box<PasskeyRecord>),
    Legacy(Value),
}

impl StoredPasskey {
    fn native(&self) -> Option<&PasskeyRecord> {
        match self {
            Self::Native(record) => Some(record),
            Self::Legacy(_) => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PasskeyRecord {
    rp_id: String,
    name: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    counter: u32,
    credential: Passkey,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyInfo {
    pub id: String,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl PasskeyRecord {
    fn info(&self) -> PasskeyInfo {
        PasskeyInfo {
            id: URL_SAFE_NO_PAD.encode(self.credential.cred_id().as_slice()),
            name: self.name.clone(),
            created_at: self.created_at,
        }
    }
}

pub struct Passkeys {
    accounts: Arc<AccountManager>,
    webauthn: Webauthn,
    rp_id: String,
    registration: Challenges<String, PasskeyRegistration>,
    login: Challenges<IpAddr, (PasskeyAuthentication, u64)>,
    limits: LoginLimiter,
}

impl Passkeys {
    /// The origin is supplied by trusted server configuration.
    pub fn new(accounts: Arc<AccountManager>, origin: &Url) -> Result<Self> {
        let rp_id = origin
            .domain()
            .context("Passkey origin must use a domain")?;
        ensure!(
            (origin.scheme() == "https" || (origin.scheme() == "http" && rp_id == "localhost"))
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.username().is_empty()
                && origin.password().is_none(),
            "Passkey origin must be HTTPS or an HTTP localhost origin"
        );
        let webauthn = WebauthnBuilder::new(rp_id, origin)?
            .rp_name("FerrumGate")
            .timeout(TTL)
            .build()?;
        Ok(Self {
            accounts,
            webauthn,
            rp_id: rp_id.into(),
            registration: Challenges::default(),
            login: Challenges::default(),
            limits: LoginLimiter::for_passkeys(),
        })
    }

    pub fn list(&self) -> Vec<PasskeyInfo> {
        let snapshot = self.accounts.snapshot.load();
        self.records(&snapshot).map(PasskeyRecord::info).collect()
    }

    pub fn begin_registration(&self, token: &str) -> Result<CreationChallengeResponse> {
        let (user_id, snapshot, session) = {
            let _writer = self
                .accounts
                .writer
                .lock()
                .expect("account writer poisoned");
            let snapshot = self.accounts.snapshot.load_full();
            let session = registration_owner(&snapshot, token)?.to_owned();
            ensure!(
                snapshot
                    .account
                    .passkeys
                    .iter()
                    .filter_map(StoredPasskey::native)
                    .count()
                    < MAX_PASSKEYS,
                rejected("Passkey limit reached")
            );
            let id = if let Some(id) = snapshot.account.passkey_user_id {
                id
            } else {
                let id = Uuid::new_v4();
                let mut next = snapshot.account.clone();
                next.passkey_user_id = Some(id);
                self.accounts.save(next)?;
                id
            };
            (id, snapshot, session)
        };
        let name = &snapshot.account.username;
        let excluded = self
            .records(&snapshot)
            .map(|record| record.credential.cred_id().clone())
            .collect();
        let (request, state) =
            self.webauthn
                .start_passkey_registration(user_id, name, name, Some(excluded))?;
        self.registration
            .insert(session, request.public_key.challenge.as_slice(), state)?;
        Ok(request)
    }

    pub fn finish_registration(
        &self,
        token: &str,
        challenge: &str,
        password: &str,
        name: &str,
        proof: &RegisterPublicKeyCredential,
    ) -> Result<PasskeyInfo> {
        let snapshot = self.accounts.snapshot.load_full();
        let session = registration_owner(&snapshot, token)?.to_owned();
        let state = self
            .registration
            .take(&session, challenge)
            .ok_or_else(|| rejected("Passkey challenge is missing or expired"))?;
        let name = name.trim();
        ensure!(
            name.chars().count() <= 40,
            rejected("Passkey name is too long")
        );
        let credential = self
            .webauthn
            .finish_passkey_registration(proof, &state)
            .map_err(|_| rejected("invalid Passkey registration"))?;
        let record = PasskeyRecord {
            rp_id: self.rp_id.clone(),
            name: if name.is_empty() {
                "Passkey".into()
            } else {
                name.into()
            },
            created_at: OffsetDateTime::now_utc(),
            counter: 0,
            credential,
        };
        let info = record.info();
        self.edit_account(&snapshot, token, password, |account| {
            let mut records = account.passkeys.iter().filter_map(StoredPasskey::native);
            ensure!(
                records.clone().count() < MAX_PASSKEYS,
                rejected("Passkey limit reached")
            );
            ensure!(
                !records.any(|current| current.credential.cred_id() == record.credential.cred_id()),
                rejected("Passkey is already registered")
            );
            account
                .passkeys
                .push(StoredPasskey::Native(Box::new(record)));
            Ok(())
        })?;
        Ok(info)
    }

    pub fn remove(&self, token: &str, password: &str, id: &str) -> Result<()> {
        let snapshot = self.accounts.snapshot.load_full();
        let id = URL_SAFE_NO_PAD
            .decode(id)
            .map_err(|_| rejected("invalid Passkey identifier"))?;
        self.edit_account(&snapshot, token, password, |account| {
            let index = account
                .passkeys
                .iter()
                .position(|entry| {
                    entry
                        .native()
                        .is_some_and(|record| record.credential.cred_id().as_slice() == id)
                })
                .ok_or_else(|| rejected("Passkey is not registered"))?;
            let entry = account.passkeys[index].native().expect("matched Passkey");
            ensure!(
                !account.password_login_off
                    || entry.rp_id != self.rp_id
                    || account
                        .passkeys
                        .iter()
                        .filter_map(StoredPasskey::native)
                        .filter(|record| record.rp_id == self.rp_id)
                        .count()
                        > 1,
                rejected("cannot remove the last Passkey while password login is disabled")
            );
            account.passkeys.remove(index);
            account.invalidate_sessions()?;
            Ok(())
        })
    }

    pub fn password_login_disabled(&self) -> bool {
        self.accounts.snapshot.load().account.password_login_off
    }

    pub fn set_password_login_disabled(
        &self,
        token: &str,
        password: &str,
        disabled: bool,
    ) -> Result<()> {
        let snapshot = self.accounts.snapshot.load_full();
        self.edit_account(&snapshot, token, password, |account| {
            ensure!(
                !disabled
                    || account
                        .passkeys
                        .iter()
                        .filter_map(StoredPasskey::native)
                        .any(|record| record.rp_id == self.rp_id),
                rejected("register a Passkey before disabling password login")
            );
            account.password_login_off = disabled;
            if !disabled {
                (account.using_default_password, account.weak_password) =
                    account.verified_password_flags(password);
            }
            Ok(())
        })
    }

    fn edit_account(
        &self,
        verified: &Snapshot,
        token: &str,
        password: &str,
        edit: impl FnOnce(&mut crate::account::Account) -> Result<()>,
    ) -> Result<()> {
        registration_owner(verified, token)?;
        ensure!(
            password::verify(password, &verified.account.password_hash)?,
            rejected("invalid administrator credentials")
        );
        let _writer = self
            .accounts
            .writer
            .lock()
            .expect("account writer poisoned");
        let current = self.accounts.snapshot.load();
        registration_owner(&current, token)?;
        ensure!(
            current.account.password_hash == verified.account.password_hash,
            rejected("administrator credentials changed during verification")
        );
        let mut next = current.account.clone();
        edit(&mut next)?;
        self.accounts.save(next)
    }

    pub fn begin_login(&self, address: IpAddr) -> Result<RequestChallengeResponse, LoginError> {
        let snapshot = self.accounts.snapshot.load();
        let credentials: Vec<_> = self
            .records(&snapshot)
            .map(|record| record.credential.clone())
            .collect();
        if credentials.is_empty() {
            return Err(LoginError::InvalidCredentials);
        }
        let (request, state) = self
            .webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|error| LoginError::Internal(error.into()))?;
        self.login.insert(
            source_key(address),
            request.public_key.challenge.as_slice(),
            (state, snapshot.account.session_epoch),
        )?;
        Ok(request)
    }

    pub fn finish_login(
        &self,
        address: IpAddr,
        challenge: &str,
        proof: &PublicKeyCredential,
    ) -> Result<(Session, String), LoginError> {
        let attempt = self.limits.begin(address)?;
        let result = self.verify_login(address, challenge, proof);
        match result {
            Ok(session) => {
                attempt.complete(session.is_some());
                let session = session.ok_or(LoginError::InvalidCredentials)?;
                if self.accounts.limiter.remember_success(address) {
                    self.accounts.save_login_sources();
                }
                Ok(session)
            }
            Err(error) => Err(LoginError::Internal(error)),
        }
    }

    fn verify_login(
        &self,
        address: IpAddr,
        challenge: &str,
        proof: &PublicKeyCredential,
    ) -> Result<Option<(Session, String)>> {
        let Some((state, epoch)) = self.login.take(&source_key(address), challenge) else {
            return Ok(None);
        };
        let Ok(proof) = self.webauthn.finish_passkey_authentication(proof, &state) else {
            return Ok(None);
        };
        let _writer = self
            .accounts
            .writer
            .lock()
            .expect("account writer poisoned");
        let snapshot = self.accounts.snapshot.load();
        if !proof.user_verified() || epoch != snapshot.account.session_epoch {
            return Ok(None);
        }
        let Some((index, record)) =
            snapshot
                .account
                .passkeys
                .iter()
                .enumerate()
                .find_map(|(index, stored)| {
                    stored
                        .native()
                        .filter(|record| {
                            record.rp_id == self.rp_id
                                && record.credential.cred_id() == proof.cred_id()
                        })
                        .map(|record| (index, record))
                })
        else {
            return Ok(None);
        };
        if (record.counter != 0 || proof.counter() != 0) && proof.counter() <= record.counter {
            return Ok(None);
        }
        let session = snapshot.issue(SystemTime::now())?;
        let mut next_record = record.clone();
        let updated = next_record.credential.update_credential(&proof) == Some(true);
        if updated || next_record.counter != proof.counter() {
            next_record.counter = proof.counter();
            let mut next = snapshot.account.clone();
            next.passkeys[index] = StoredPasskey::Native(Box::new(next_record));
            self.accounts.save(next)?;
        }
        Ok(Some((session, snapshot.account.username.clone())))
    }

    fn records<'a>(
        &'a self,
        snapshot: &'a Snapshot,
    ) -> impl Iterator<Item = &'a PasskeyRecord> + Clone {
        snapshot
            .account
            .passkeys
            .iter()
            .filter_map(StoredPasskey::native)
            .filter(move |record| record.rp_id == self.rp_id)
    }
}

fn registration_owner<'a>(snapshot: &Snapshot, token: &'a str) -> Result<&'a str> {
    let now = unix_seconds(SystemTime::now()).context("system clock predates Unix epoch")?;
    let session = snapshot
        .verify_admin(token, now)
        .ok_or_else(|| rejected("administrator session is invalid"))?;
    ensure!(
        !snapshot.account.must_change_password(),
        rejected("administrator password must be changed")
    );
    Ok(session)
}

fn rejected(message: &'static str) -> CredentialChangeRejected {
    CredentialChangeRejected(message)
}

struct Challenges<K, T>(Mutex<HashMap<K, Vec<Pending<T>>>>);

struct Pending<T> {
    challenge: String,
    expires: Instant,
    state: T,
}

impl<K, T> Default for Challenges<K, T> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<K: Eq + Hash + Clone, T> Challenges<K, T> {
    fn insert(&self, scope: K, challenge: &[u8], state: T) -> Result<(), LoginError> {
        let mut pending = self.0.lock().expect("Passkey challenges poisoned");
        let now = Instant::now();
        if !pending.contains_key(&scope) && pending.len() == MAX_SCOPE {
            pending.retain(|_, entries| entries.last().is_some_and(|last| now < last.expires));
            if pending.len() == MAX_SCOPE
                && let Some((oldest, _)) = pending
                    .iter()
                    .min_by_key(|(_, entries)| entries.last().map(|entry| entry.expires))
            {
                let oldest = oldest.clone();
                pending.remove(&oldest);
            }
        }
        let entries = pending.entry(scope).or_default();
        entries.retain(|entry| now < entry.expires);
        if entries.len() == MAX_PER_SCOPE {
            return Err(LoginError::Busy);
        }
        entries.push(Pending {
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            expires: now + TTL,
            state,
        });
        Ok(())
    }

    fn take(&self, scope: &K, challenge: &str) -> Option<T> {
        let mut pending = self.0.lock().expect("Passkey challenges poisoned");
        let entries = pending.get_mut(scope)?;
        let index = entries
            .iter()
            .position(|entry| entry.challenge == challenge)?;
        let entry = entries.remove(index);
        if entries.is_empty() {
            pending.remove(scope);
        }
        (Instant::now() < entry.expires).then_some(entry.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_challenges_enforce_scope_capacity_expiry_and_single_use() -> Result<()> {
        let challenges = Challenges::default();
        for id in 0..MAX_PER_SCOPE {
            challenges.insert(1, &[id as u8], id)?;
        }
        assert!(matches!(
            challenges.insert(1, b"extra", 20),
            Err(LoginError::Busy)
        ));
        let encoded = URL_SAFE_NO_PAD.encode([0]);
        assert_eq!(challenges.take(&2, &encoded), None);
        assert_eq!(challenges.take(&1, &encoded), Some(0));
        assert_eq!(challenges.take(&1, &encoded), None);
        challenges.insert(1, b"expired", 20)?;
        challenges
            .0
            .lock()
            .unwrap()
            .get_mut(&1)
            .unwrap()
            .last_mut()
            .unwrap()
            .expires = Instant::now();
        assert_eq!(
            challenges.take(&1, &URL_SAFE_NO_PAD.encode(b"expired")),
            None
        );
        Ok(())
    }
}
