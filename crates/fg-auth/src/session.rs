use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};

use crate::{
    account::{Account, MAX_REVOKED, MAX_USERNAME_BYTES, random_urlsafe},
    readonly,
    totp::Totp,
};

const DEFAULT_TTL_HOURS: u64 = 72;
const MAX_TOKEN_BYTES: usize = 4096;
const REVOCATION_ID_LEN: usize = 22;

pub struct Session {
    pub token: String,
    pub expires_at: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub username: String,
    pub role: Role,
    pub must_change_password: bool,
    pub initial_password: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Readonly,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Readonly => "readonly",
        }
    }
}

impl Identity {
    pub fn password_issue(&self) -> &'static str {
        if self.initial_password {
            "default"
        } else if self.must_change_password {
            "weak"
        } else {
            ""
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims<'a> {
    #[serde(rename = "u", borrow)]
    user: Cow<'a, str>,
    #[serde(rename = "e")]
    expires: u64,
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    role: Option<&'a str>,
    #[serde(rename = "v")]
    version: &'a str,
    #[serde(rename = "n", default)]
    epoch: u64,
    #[serde(rename = "j")]
    nonce: &'a str,
}

pub(super) struct Snapshot {
    pub account: Account,
    pub totp: Option<Totp>,
    key: hmac::Key,
    version: String,
    readonly_versions: HashMap<String, String>,
    pub(super) ttl: Duration,
    revoked: HashSet<String>,
}

pub(super) struct VerifiedSession<'a, 't> {
    pub id: &'t str,
    pub expires: u64,
    pub username: &'a str,
    pub role: Role,
}

impl Snapshot {
    pub fn new(account: Account) -> Result<Self> {
        ensure!(
            !account.username.trim().is_empty() && account.username.len() <= MAX_USERNAME_BYTES,
            "invalid administrator username"
        );
        ensure!(
            account.password_hash.parse::<bcrypt::HashParts>().is_ok(),
            "invalid administrator password hash"
        );
        ensure!(
            account.session_secret.len() >= 32,
            "invalid administrator session secret"
        );
        ensure!(
            account.revoked.len() <= MAX_REVOKED,
            "administrator revocation list exceeds its limit"
        );
        let ttl = u64::try_from(account.token_ttl_hours)
            .ok()
            .filter(|&hours| hours > 0)
            .unwrap_or(DEFAULT_TTL_HOURS)
            .checked_mul(3600)
            .context("administrator session TTL is too large")?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, account.session_secret.as_bytes());
        let mut credential = digest::Context::new(&digest::SHA256);
        credential.update(account.password_hash.as_bytes());
        if !account.totp_secret.is_empty() {
            credential.update(b"\0");
            credential.update(account.totp_secret.as_bytes());
        }
        let version = URL_SAFE_NO_PAD.encode(&credential.finish().as_ref()[..6]);
        let revoked = account
            .revoked
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        let readonly_versions = readonly::versions(&account)?;
        Ok(Self {
            totp: Totp::parse(&account.totp_secret),
            account,
            key,
            version,
            readonly_versions,
            ttl: Duration::from_secs(ttl),
            revoked,
        })
    }

    pub fn issue(&self, now: SystemTime) -> Result<Session> {
        self.issue_session(now, &self.account.username, None, &self.version)
    }

    pub fn issue_readonly(&self, now: SystemTime, username: &str) -> Result<Session> {
        let version = self
            .readonly_versions
            .get(username)
            .context("read-only credentials are missing")?;
        self.issue_session(now, username, Some(Role::Readonly.as_str()), version)
    }

    fn issue_session(
        &self,
        now: SystemTime,
        username: &str,
        role: Option<&str>,
        version: &str,
    ) -> Result<Session> {
        let expires = unix_seconds(now)
            .context("system clock predates Unix epoch")?
            .checked_add(self.ttl.as_secs())
            .context("session expiration overflow")?;
        let expires_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(expires))
            .context("session expiration overflow")?;
        let nonce = random_urlsafe::<12>()?;
        let claims = Claims {
            user: Cow::Borrowed(username),
            expires,
            role,
            version,
            epoch: self.account.session_epoch,
            nonce: &nonce,
        };
        let mut token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let sig = URL_SAFE_NO_PAD.encode(hmac::sign(&self.key, token.as_bytes()).as_ref());
        token.push('.');
        token.push_str(&sig);
        Ok(Session { token, expires_at })
    }

    pub fn unused_totp_step(&self, code: &str, timestamp: u64) -> Option<u64> {
        self.totp
            .as_ref()?
            .match_code(code, timestamp)
            .filter(|&step| self.account.totp_last_step.is_none_or(|last| step > last))
    }

    pub fn verify<'a, 't>(&'a self, token: &'t str, now: u64) -> Option<VerifiedSession<'a, 't>> {
        if token.len() > MAX_TOKEN_BYTES {
            return None;
        }
        let (body, signature) = token.split_once('.')?;
        if signature.len() != 43 {
            return None;
        }
        let mut bytes = [0; 32];
        URL_SAFE_NO_PAD.decode_slice(signature, &mut bytes).ok()?;
        hmac::verify(&self.key, body.as_bytes(), &bytes).ok()?;
        // The decoder above also verifies that the signature is ASCII.
        let id = &signature[..REVOCATION_ID_LEN];
        if self.revoked.contains(id) {
            return None;
        }
        let raw = URL_SAFE_NO_PAD.decode(body).ok()?;
        let claims: Claims<'_> = serde_json::from_slice(&raw).ok()?;
        if claims.expires <= now
            || claims.epoch != self.account.session_epoch
            || claims.nonce.is_empty()
        {
            return None;
        }
        let (username, role, version) = match claims.role {
            None | Some("admin") if claims.user == self.account.username => (
                self.account.username.as_str(),
                Role::Admin,
                self.version.as_str(),
            ),
            Some("readonly") => {
                let (name, version) = self.readonly_versions.get_key_value(claims.user.as_ref())?;
                (name.as_str(), Role::Readonly, version.as_str())
            }
            _ => return None,
        };
        (claims.version == version).then_some(VerifiedSession {
            id,
            expires: claims.expires,
            username,
            role,
        })
    }

    pub fn verify_admin<'t>(&self, token: &'t str, now: u64) -> Option<&'t str> {
        let verified = self.verify(token, now)?;
        (verified.role == Role::Admin).then_some(verified.id)
    }
}

pub(super) fn unix_seconds(now: SystemTime) -> Option<u64> {
    Some(now.duration_since(UNIX_EPOCH).ok()?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_expires_at_the_claimed_second() -> Result<()> {
        let account = serde_json::from_value(serde_json::json!({
            "username": "operator \"测试\"",
            "passwordHash": bcrypt::hash("fixture-password", 4)?,
            "sessionSecret": random_urlsafe::<32>()?,
            "tokenTTLHours": 1,
        }))?;
        let snapshot = Snapshot::new(account)?;
        let started = UNIX_EPOCH + Duration::from_secs(100);
        let session = snapshot.issue(started)?;
        assert_eq!(session.expires_at, UNIX_EPOCH + Duration::from_secs(3700));
        assert!(snapshot.verify(&session.token, 3699).is_some());
        assert!(snapshot.verify(&session.token, 3700).is_none());
        Ok(())
    }
}
