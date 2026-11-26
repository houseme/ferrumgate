use std::{
    borrow::Cow,
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};

use crate::account::{Account, MAX_REVOKED, MAX_USERNAME_BYTES, random_urlsafe};

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
    pub must_change_password: bool,
    pub initial_password: bool,
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
    key: hmac::Key,
    version: String,
    ttl: Duration,
    revoked: HashSet<String>,
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
        Ok(Self {
            account,
            key,
            version,
            ttl: Duration::from_secs(ttl),
            revoked,
        })
    }

    pub fn issue(&self, now: SystemTime) -> Result<Session> {
        let expires = unix_seconds(now)
            .context("system clock predates Unix epoch")?
            .checked_add(self.ttl.as_secs())
            .context("session expiration overflow")?;
        let expires_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(expires))
            .context("session expiration overflow")?;
        let nonce = random_urlsafe::<12>()?;
        let claims = Claims {
            user: Cow::Borrowed(&self.account.username),
            expires,
            role: None,
            version: &self.version,
            epoch: self.account.session_epoch,
            nonce: &nonce,
        };
        let mut token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let sig = URL_SAFE_NO_PAD.encode(hmac::sign(&self.key, token.as_bytes()).as_ref());
        token.push('.');
        token.push_str(&sig);
        Ok(Session { token, expires_at })
    }

    pub fn verify<'a>(&self, token: &'a str, now: u64) -> Option<(&'a str, u64)> {
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
        (claims.expires > now
            && claims.epoch == self.account.session_epoch
            && claims.user == self.account.username
            && matches!(claims.role, None | Some("admin"))
            && claims.version == self.version
            && !claims.nonce.is_empty())
        .then_some((id, claims.expires))
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
