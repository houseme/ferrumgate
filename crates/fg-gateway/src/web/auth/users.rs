//! Site users (WP-24 step 1): `users[]` entries are `name:password`
//! lines where the password may be plaintext (hashed on save, bcrypt
//! default cost) or an existing bcrypt hash. Masked or empty passwords
//! keep the previously saved one; the API only ever shows `********`.
#![allow(dead_code)]

/// The mask every interface response shows instead of a password.
pub const MASK: &str = "********";

/// bcrypt's 72-byte input limit; longer passwords are rejected.
pub const MAX_PASSWORD_BYTES: usize = 72;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserError {
    /// A password exceeded 72 bytes.
    TooLong,
    /// An entry looked like a hash but was not a valid bcrypt hash.
    InvalidHash,
    /// A masked/empty password had no original to keep.
    NoOriginal,
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong => write!(f, "密码超过 72 字节"),
            Self::InvalidHash => write!(f, "密码哈希无效"),
            Self::NoOriginal => write!(f, "掩码或空密码没有可沿用的原密码"),
        }
    }
}

impl std::error::Error for UserError {}

/// Whether this entry is shaped like a bcrypt hash (kept as-is on save):
/// a `$2a$`/`$2b$`/`$2y$` prefix, two cost digits and 53 bcrypt-base64
/// characters — 60 bytes in total. Accepts either the bare password text
/// or a full `name:password` line (a hash never contains a colon). Shape
/// only: validity is a cheap parse, never a costly verification.
pub fn is_hash(entry: &str) -> bool {
    let text = match entry.split_once(':') {
        Some((_, pass)) => pass,
        None => entry,
    };
    let bytes = text.as_bytes();
    if bytes.len() != 60 {
        return false;
    }
    if !(bytes.starts_with(b"$2a$") || bytes.starts_with(b"$2b$") || bytes.starts_with(b"$2y$")) {
        return false;
    }
    bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit()
        && bytes[6] == b'$'
        && bytes[7..]
            .iter()
            .all(|byte| matches!(byte, b'.' | b'/' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'))
}

/// Splits a `name:password` entry; entries without a colon are invalid
/// at validate time and never match.
pub fn split_entry(entry: &str) -> Option<(&str, &str)> {
    entry.split_once(':')
}

/// Hashes plaintext passwords in place (bcrypt default cost), keeps
/// existing valid hashes untouched, and resolves masked/empty passwords
/// against `old` — first by username across the previously saved list
/// (exactly one distinct password must match), then for renamed entries
/// by position, provided the list length is unchanged and the previous
/// entry's name appears nowhere in the submitted list. Rejects passwords
/// over 72 bytes, invalid hashes and masks without an original. On error
/// the list is left untouched. Any `$2`-prefixed value counts as a hash
/// attempt: a valid one survives verbatim (so re-saving does not change
/// the credential fingerprint), a corrupted one is rejected instead of
/// being re-hashed as plaintext.
pub fn hash_site_users(users: &mut Vec<String>, old: &[String]) -> Result<(), UserError> {
    let mut out = Vec::with_capacity(users.len());
    for (index, entry) in users.iter().enumerate() {
        let Some((name, pass)) = split_entry(entry) else {
            // A colon-less entry carries no password and nothing to keep.
            return Err(UserError::NoOriginal);
        };
        let value = match pass {
            "" | MASK => keep_original(old, users, index, name)?,
            rest => rest,
        };
        if value.starts_with("$2") {
            value
                .parse::<bcrypt::HashParts>()
                .map_err(|_| UserError::InvalidHash)?;
            out.push(format!("{name}:{value}"));
            continue;
        }
        if value.len() > MAX_PASSWORD_BYTES {
            return Err(UserError::TooLong);
        }
        let hashed = bcrypt::hash(value, bcrypt::DEFAULT_COST)
            .expect("bcrypt hashing cannot fail at default cost with <=72 bytes");
        out.push(format!("{name}:{hashed}"));
    }
    *users = out;
    Ok(())
}

/// The API view: every password becomes `********`. Colon-less entries
/// have no password position and are passed through unchanged.
pub fn mask_site_users(users: &[String]) -> Vec<String> {
    users
        .iter()
        .map(|entry| match split_entry(entry) {
            Some((name, _)) => format!("{name}:{MASK}"),
            None => entry.clone(),
        })
        .collect()
}

/// Verifies credentials against one entry; accepts legacy plaintext
/// entries and bcrypt hashes. The username must match (constant-time).
/// Entries whose password starts with `$2` can only authenticate through
/// a hash comparison — never as plaintext — and the comparison always
/// runs (constant work regardless of password correctness).
pub fn verify_site_user(entry: &str, name: &str, pass: &str) -> bool {
    let Some((entry_name, entry_pass)) = split_entry(entry) else {
        return false;
    };
    if !ct_eq(entry_name, name) {
        return false;
    }
    if entry_pass.starts_with("$2") {
        bcrypt::verify(pass, entry_pass).unwrap_or(false)
    } else {
        ct_eq(entry_pass, pass)
    }
}

/// A password usable as an original: present and not the mask.
fn usable(pass: &str) -> bool {
    !pass.is_empty() && pass != MASK
}

/// Resolves a masked/empty password against the previously saved list:
/// by username first — every same-name entry with a real password is a
/// candidate, and exactly one distinct password must be found (zero or
/// several means `NoOriginal`) — then, for renamed entries, by position,
/// requiring an unchanged list length and the previous entry's name not
/// being used anywhere in the submitted list (it must have been renamed,
/// not reordered).
fn keep_original<'a>(
    old: &'a [String],
    submitted: &[String],
    index: usize,
    name: &str,
) -> Result<&'a str, UserError> {
    let mut found: Option<&str> = None;
    let mut ambiguous = false;
    for entry in old {
        let Some((other, pass)) = split_entry(entry) else {
            continue;
        };
        if other != name || !usable(pass) {
            continue;
        }
        if let Some(previous) = found
            && previous != pass
        {
            ambiguous = true;
        }
        found = Some(pass);
    }
    if ambiguous {
        return Err(UserError::NoOriginal);
    }
    if let Some(pass) = found {
        return Ok(pass);
    }
    if old.len() != submitted.len() {
        return Err(UserError::NoOriginal);
    }
    let Some(previous) = old.get(index) else {
        return Err(UserError::NoOriginal);
    };
    let Some((previous_name, previous_pass)) = split_entry(previous) else {
        return Err(UserError::NoOriginal);
    };
    let renamed = !submitted
        .iter()
        .any(|entry| split_entry(entry).is_some_and(|(entry_name, _)| entry_name == previous_name));
    if usable(previous_pass) && renamed {
        return Ok(previous_pass);
    }
    Err(UserError::NoOriginal)
}

/// Constant-time equality: every byte of both inputs, their lengths
/// included, is mixed into the result wherever the difference lies.
fn ct_eq(a: &str, b: &str) -> bool {
    let (left, right) = (a.as_bytes(), b.as_bytes());
    let mut diff = left.len() ^ right.len();
    for (index, byte) in left.iter().enumerate() {
        let other = right.get(index).copied().unwrap_or(0);
        diff |= u8::from(*byte != other) as usize;
    }
    for byte in right.iter().skip(left.len()) {
        diff |= u8::from(*byte != 0) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cheap fixture hash (cost 4) — the production path always uses
    /// `DEFAULT_COST`, asserted separately in the hashing test.
    fn fixture(name: &str, pass: &str) -> String {
        format!("{name}:{}", bcrypt::hash(pass, 4).unwrap())
    }

    #[test]
    fn site_users_plaintext_hashed_once() {
        let mut users = vec!["alice:secret".to_string()];
        hash_site_users(&mut users, &[]).unwrap();
        let (name, pass) = split_entry(&users[0]).unwrap();
        assert_eq!(name, "alice");
        assert!(is_hash(pass), "plaintext should become a hash: {}", users[0]);
        assert_eq!(pass[4..6].parse::<u32>().unwrap(), bcrypt::DEFAULT_COST);
        assert!(verify_site_user(&users[0], "alice", "secret"));
        // 再次保存：已是有效哈希的保持不变（凭据指纹不变）
        let before = users.clone();
        hash_site_users(&mut users, &before).unwrap();
        assert_eq!(users, before);
        // 掩码沿用的存量明文同样在保存时转换
        let mut users = vec!["carol:********".to_string()];
        hash_site_users(&mut users, &["carol:legacy".to_string()]).unwrap();
        assert!(is_hash(split_entry(&users[0]).unwrap().1));
        assert!(verify_site_user(&users[0], "carol", "legacy"));
    }

    #[test]
    fn site_users_mask_keeps_original() {
        let old = vec![fixture("alice", "one"), fixture("bob", "two")];
        // 掩码与空值都表示不修改
        let mut users = vec!["alice:********".to_string(), "bob:".to_string()];
        hash_site_users(&mut users, &old).unwrap();
        assert_eq!(users, old);
        // 改名的条目按位置沿用
        let mut users = vec!["carol:********".to_string(), "dave:".to_string()];
        hash_site_users(&mut users, &old).unwrap();
        let expected = vec![
            format!("carol:{}", split_entry(&old[0]).unwrap().1),
            format!("dave:{}", split_entry(&old[1]).unwrap().1),
        ];
        assert_eq!(users, expected);
    }

    #[test]
    fn site_users_reject_over_72_bytes() {
        let long = "x".repeat(MAX_PASSWORD_BYTES + 1);
        let original = vec![format!("alice:{long}")];
        let mut users = original.clone();
        assert_eq!(hash_site_users(&mut users, &[]), Err(UserError::TooLong));
        assert_eq!(users, original, "rejected list must stay untouched");
        // 边界：恰好 72 字节可以保存
        let edge = "x".repeat(MAX_PASSWORD_BYTES);
        let mut users = vec![format!("alice:{edge}")];
        hash_site_users(&mut users, &[]).unwrap();
        assert!(is_hash(split_entry(&users[0]).unwrap().1));
        assert!(verify_site_user(&users[0], "alice", &edge));
    }

    #[test]
    fn verify_accepts_legacy_plaintext_and_hash() {
        let entry = fixture("alice", "s3cret");
        assert!(verify_site_user(&entry, "alice", "s3cret"));
        assert!(!verify_site_user(&entry, "alice", "nope"));
        assert!(!verify_site_user(&entry, "bob", "s3cret"));
        // 存量配置中的明文照常可用；密码中的冒号属于密码
        assert!(verify_site_user("carol:pa:ss", "carol", "pa:ss"));
        assert!(!verify_site_user("carol:pa:ss", "carol", "pass"));
        assert!(!verify_site_user("carol:pa:ss", "carol", "pa"));
        // 无冒号的条目永不匹配
        assert!(!verify_site_user("nocolon", "nocolon", "nocolon"));
        // `$2` 形态绝不当明文比较
        assert!(!verify_site_user("dave:$2a$10$broken", "dave", "$2a$10$broken"));
    }

    #[test]
    fn site_users_mask_keeps_by_position_on_rename() {
        let old = vec![fixture("alice", "oldpw")];
        let mut users = vec!["bob:********".to_string()];
        hash_site_users(&mut users, &old).unwrap();
        assert_eq!(users, vec![format!("bob:{}", split_entry(&old[0]).unwrap().1)]);
        // 数量变了就不是改名，不再按位置沿用
        let mut users = vec!["bob:********".to_string(), "carol:********".to_string()];
        assert_eq!(hash_site_users(&mut users, &old), Err(UserError::NoOriginal));
    }

    #[test]
    fn site_users_mask_keeps_by_username() {
        let old = vec![fixture("alice", "first"), fixture("bob", "second")];
        // 顺序打乱也按用户名对应，绝不按位置串密码
        let mut users = vec!["bob:********".to_string(), "alice:********".to_string()];
        hash_site_users(&mut users, &old).unwrap();
        assert_eq!(
            users,
            vec![
                format!("bob:{}", split_entry(&old[1]).unwrap().1),
                format!("alice:{}", split_entry(&old[0]).unwrap().1),
            ]
        );
        // 超出旧列表长度的新条目按用户名在旧表中查找
        let mut users = vec![
            "alice:********".to_string(),
            "bob:********".to_string(),
            "bob:********".to_string(),
        ];
        hash_site_users(&mut users, &old).unwrap();
        assert_eq!(users[2], format!("bob:{}", split_entry(&old[1]).unwrap().1));
    }

    #[test]
    fn site_users_mask_rejects_ambiguous_candidates() {
        let old = vec![
            fixture("alice", "a1"),
            fixture("bob", "b2"),
            fixture("alice", "a3"),
        ];
        let original = vec![
            "alice:********".to_string(),
            "bob:********".to_string(),
            "alice:********".to_string(),
        ];
        let mut users = original.clone();
        // alice 在旧表中有两个不同的密码：拒绝
        assert_eq!(hash_site_users(&mut users, &old), Err(UserError::NoOriginal));
        assert_eq!(users, original, "rejected list must stay untouched");
        // 没有冒号的条目没有密码可沿用
        let mut users = vec!["nocolon".to_string()];
        assert_eq!(hash_site_users(&mut users, &[]), Err(UserError::NoOriginal));
    }

    #[test]
    fn site_users_reject_invalid_hash() {
        // `$2` 形态但不是有效 bcrypt 哈希：拒绝而不是当明文重新哈希
        let original = vec!["dave:$2a$10$broken".to_string()];
        let mut users = original.clone();
        assert_eq!(hash_site_users(&mut users, &[]), Err(UserError::InvalidHash));
        assert_eq!(users, original);
        // 掩码沿用的值同样要验证
        let mut users = vec!["erin:********".to_string()];
        let old = vec!["erin:$2a$10$broken".to_string()];
        assert_eq!(hash_site_users(&mut users, &old), Err(UserError::InvalidHash));
    }

    #[test]
    fn mask_site_users_masks_every_line() {
        let masked = mask_site_users(&[
            "alice:secret".to_string(),
            "bob:".to_string(),
            "carol:pa:ss".to_string(),
            "nocolon".to_string(),
        ]);
        assert_eq!(
            masked,
            vec![
                format!("alice:{MASK}"),
                format!("bob:{MASK}"),
                format!("carol:{MASK}"),
                "nocolon".to_string(),
            ]
        );
    }

    #[test]
    fn is_hash_shape_only() {
        let real = bcrypt::hash("x", 4).unwrap();
        assert!(is_hash(&real));
        assert!(is_hash(&format!("alice:{real}")));
        assert!(!is_hash("secret"));
        assert!(!is_hash(""));
        assert!(!is_hash("$2a$10$broken"));
        assert!(!is_hash(&real[..59]));
        // 前缀限定 $2a/$2b/$2y$
        let swapped = format!("$2c$04{}", &real[7..]);
        assert!(!is_hash(&swapped));
        assert!(!is_hash(&format!("alice:{swapped}")));
    }
}
