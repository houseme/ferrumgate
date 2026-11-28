//! Self-service password change (WP-24 step 7) — implementation batch.
//!
//! Shared users change their own password at `/__gately_auth/password`:
//! the current password (and, for TOTP users, a valid code) must have
//! been verified first, the new password is 8–128 characters and must
//! differ from the old one, and the same account may not change twice
//! within the one-minute cooldown. The fresh bcrypt hash changes the
//! credential fingerprint, so every existing session of that user is
//! invalidated immediately (see `shared::cred_fingerprint`).
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::shared::AuthUser;

/// bcrypt cost for self-service changes: the upstream default cost.
pub const DEFAULT_COST: u32 = bcrypt::DEFAULT_COST;

/// Same-account cooldown between two changes (upstream: 1 minute).
const COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    /// The current password (or TOTP code) was not verified.
    CurrentPasswordWrong,
    /// The new password has fewer than 8 characters.
    TooShort,
    /// The new password has more than 128 characters.
    TooLong,
    /// The new password equals the current one.
    SameAsCurrent,
    /// The confirmation does not match the new password.
    Mismatch,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentPasswordWrong => write!(f, "当前密码或验证码错误"),
            Self::TooShort => write!(f, "新密码至少 8 个字符"),
            Self::TooLong => write!(f, "新密码最多 128 个字符"),
            Self::SameAsCurrent => write!(f, "新密码不能与当前密码相同"),
            Self::Mismatch => write!(f, "两次输入的新密码不一致"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Validates one self-service change. `current_ok` means the caller has
/// already verified the current password (and TOTP code where enabled).
/// Length is counted in characters, not bytes.
pub fn validate_change(
    current_ok: bool,
    old: &str,
    new: &str,
    confirm: &str,
) -> Result<(), PasswordError> {
    if !current_ok {
        return Err(PasswordError::CurrentPasswordWrong);
    }
    let len = new.chars().count();
    if len < 8 {
        return Err(PasswordError::TooShort);
    }
    if len > 128 {
        return Err(PasswordError::TooLong);
    }
    if new == old {
        return Err(PasswordError::SameAsCurrent);
    }
    if confirm != new {
        return Err(PasswordError::Mismatch);
    }
    Ok(())
}

/// Per-account cooldown: after a successful change the same account
/// cannot change again for [`COOLDOWN`] (60 s). Timestamps are injected
/// so tests do not sleep. Entries never expire (the map is bounded by
/// the number of accounts that change their password).
pub struct Cooldown {
    last: Mutex<HashMap<String, Instant>>,
}

impl Cooldown {
    pub fn new() -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `user` may start another change at `now`.
    pub fn can_change(&self, user: &str, now: Instant) -> bool {
        match self.last.lock().expect("cooldown lock").get(user) {
            Some(&last) => now.saturating_duration_since(last) >= COOLDOWN,
            None => true,
        }
    }

    /// Records a successful change for `user` at `now`.
    pub fn mark_changed(&self, user: &str, now: Instant) {
        self.last
            .lock()
            .expect("cooldown lock")
            .insert(user.to_owned(), now);
    }
}

impl Default for Cooldown {
    fn default() -> Self {
        Self::new()
    }
}

/// Replaces `name`'s password with a fresh bcrypt hash at
/// [`DEFAULT_COST`]. Returns `true` when the user exists. The new hash
/// differs from the stored one, so the credential fingerprint changes
/// and every existing session of this user is invalidated immediately.
pub fn apply(users: &mut [AuthUser], name: &str, new_password: &str) -> bool {
    let Some(user) = users.iter_mut().find(|user| user.name == name) else {
        return false;
    };
    if let Ok(hash) = bcrypt::hash(new_password, DEFAULT_COST) {
        user.password = hash;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, password_hash: String) -> AuthUser {
        AuthUser {
            id: format!("id-{name}"),
            name: name.to_owned(),
            password: password_hash,
            totp_secret: String::new(),
            remark: String::new(),
            email: String::new(),
            display_name: String::new(),
            groups: Vec::new(),
        }
    }

    #[test]
    fn validate_covers_all_branches() {
        // Unverified current credentials are rejected before anything else.
        assert_eq!(
            validate_change(false, "old-pw-1", "new-pw-1", "new-pw-1"),
            Err(PasswordError::CurrentPasswordWrong)
        );
        // 7 characters → too short.
        assert_eq!(
            validate_change(true, "old-pw-1", "shortp7", "shortp7"),
            Err(PasswordError::TooShort)
        );
        // 129 characters → too long.
        let long = "x".repeat(129);
        assert_eq!(
            validate_change(true, "old-pw-1", &long, &long),
            Err(PasswordError::TooLong)
        );
        // Identical to the current password.
        assert_eq!(
            validate_change(true, "same-pw-8", "same-pw-8", "same-pw-8"),
            Err(PasswordError::SameAsCurrent)
        );
        // Confirmation mismatch.
        assert_eq!(
            validate_change(true, "old-pw-1", "new-pw-1", "new-pw-2"),
            Err(PasswordError::Mismatch)
        );
        // The happy path.
        assert_eq!(validate_change(true, "old-pw-1", "new-pw-1", "new-pw-1"), Ok(()));
    }

    #[test]
    fn validate_length_is_chars_not_bytes_and_bounds_inclusive() {
        // 8 and 128 characters are accepted (bounds inclusive).
        assert_eq!(validate_change(true, "old-pw-1", "12345678", "12345678"), Ok(()));
        let max = "x".repeat(128);
        assert_eq!(validate_change(true, "old-pw-1", &max, &max), Ok(()));
        // 7 CJK characters are 21 bytes but only 7 characters → too short;
        // 8 CJK characters are 24 bytes → fine.
        assert_eq!(
            validate_change(true, "旧的密码占位", "一二三四五六七", "一二三四五六七"),
            Err(PasswordError::TooShort)
        );
        assert_eq!(
            validate_change(true, "旧的密码占位", "一二三四五六七八", "一二三四五六七八"),
            Ok(())
        );
    }

    #[test]
    fn cooldown_blocks_within_60s_and_releases_after() {
        let cooldown = Cooldown::new();
        let t0 = Instant::now();
        assert!(cooldown.can_change("alice", t0));
        cooldown.mark_changed("alice", t0);
        assert!(!cooldown.can_change("alice", t0 + Duration::from_secs(59)));
        assert!(!cooldown.can_change("alice", t0 + Duration::from_millis(59_999)));
        assert!(cooldown.can_change("alice", t0 + Duration::from_secs(60)));
        // Other accounts are unaffected.
        assert!(cooldown.can_change("bob", t0 + Duration::from_secs(1)));
    }

    #[test]
    fn apply_rehashes_so_old_password_fails_and_new_verifies() {
        let old_hash = bcrypt::hash("oldpw", 4).expect("hash");
        let mut users = vec![user("alice", old_hash.clone())];
        assert!(bcrypt::verify("oldpw", &users[0].password).expect("verify"));

        assert!(apply(&mut users, "alice", "newpw"));
        // The stored hash changed (fingerprint → existing sessions die).
        assert_ne!(users[0].password, old_hash);
        // Exactly one verification each way, no repeated cost.
        assert!(bcrypt::verify("newpw", &users[0].password).expect("verify new"));
        assert!(!bcrypt::verify("oldpw", &users[0].password).expect("verify old"));
    }

    #[test]
    fn apply_unknown_user_is_noop_false() {
        let old_hash = bcrypt::hash("oldpw", 4).expect("hash");
        let mut users = vec![user("alice", old_hash.clone())];
        assert!(!apply(&mut users, "mallory", "newpw"));
        assert_eq!(users[0].password, old_hash);
    }

    #[test]
    fn password_error_messages_are_chinese() {
        assert_eq!(
            PasswordError::CurrentPasswordWrong.to_string(),
            "当前密码或验证码错误"
        );
        assert_eq!(PasswordError::TooShort.to_string(), "新密码至少 8 个字符");
        assert_eq!(PasswordError::TooLong.to_string(), "新密码最多 128 个字符");
        assert_eq!(
            PasswordError::SameAsCurrent.to_string(),
            "新密码不能与当前密码相同"
        );
        assert_eq!(PasswordError::Mismatch.to_string(), "两次输入的新密码不一致");
    }
}
