//! Shared users (WP-24 step 2): the cross-site authentication accounts
//! (`authUsers[]`), single-sign-on domain selection and credential
//! fingerprints. IDs are immutable random identifiers; passwords are
//! bcrypt; TOTP-enabled users never participate in basic auth.
#![allow(dead_code)]

use std::fmt::Write as _;

use aws_lc_rs::hmac;

/// One shared user. `password` is a bcrypt hash (submitted plaintext is
/// hashed on save); `totp_secret` empty means TOTP is off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthUser {
    pub id: String,
    pub name: String,
    pub password: String,
    pub totp_secret: String,
    pub remark: String,
    pub email: String,
    pub display_name: String,
    pub groups: Vec<String>,
}

impl AuthUser {
    /// Does this user carry a TOTP second factor?
    pub fn has_totp(&self) -> bool {
        !self.totp_secret.is_empty()
    }
}

/// Generates an immutable user id: 128 random bits, hex, lowercase.
///
/// Randomness failure is unrecoverable here (ids must be globally
/// unique; a zero-filled fallback would collide), so it panics — the
/// upstream Go equivalent (`uuid.New`) does the same.
pub fn new_user_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("系统随机源不可用");
    hex(&bytes)
}

/// Fills in missing ids (a fresh list, or entries the UI never saw);
/// existing ids are kept — they are immutable even across renames.
pub fn backfill_ids(users: &mut [AuthUser]) {
    for user in users {
        if user.id.is_empty() {
            user.id = new_user_id();
        }
    }
}

/// Single sign-on: which configured domain covers `host`? A domain
/// matches when it equals `host` or is a suffix of it at a dot boundary
/// (`a.example.com` is covered by `example.com`, `notexample.com` is
/// not). When several configured domains nest (hand-edited configs),
/// the longest match wins; saving nested domains is rejected by the
/// settings validation.
pub fn sso_for(domains: &[String], host: &str) -> Option<String> {
    let mut best: Option<&str> = None;
    for domain in domains {
        if domain.is_empty() {
            continue;
        }
        if domain_covers(domain, host) && best.is_none_or(|best| domain.len() > best.len()) {
            best = Some(domain);
        }
    }
    best.map(str::to_owned)
}

/// Rejects nested/overlapping SSO domains (saving `example.com` and
/// `a.example.com` together is an error); duplicates count as nesting
/// too. Reports the more specific (nested) domain.
pub fn validate_sso_domains(domains: &[String]) -> Result<(), SharedError> {
    for (i, outer) in domains.iter().enumerate() {
        for inner in &domains[i + 1..] {
            if outer.is_empty() || inner.is_empty() {
                continue;
            }
            if domain_covers(outer, inner) {
                return Err(SharedError::NestedDomains(inner.clone()));
            }
            if domain_covers(inner, outer) {
                return Err(SharedError::NestedDomains(outer.clone()));
            }
        }
    }
    Ok(())
}

/// Finds the user by name (constant-time-ish: names are compared for
/// every entry, never short-circuiting on the first mismatch... entries
/// are compared until one matches, but a missing user still performs one
/// bcrypt verification so the timing does not reveal whether the name
/// existed). TOTP-enabled users authenticate through the web flow only.
pub fn check_password(users: &[AuthUser], name: &str, pass: &str) -> Option<AuthUser> {
    let hit = users.iter().find(|user| name_eq(&user.name, name));
    // A missed name still costs one bcrypt run: the first user's hash,
    // or a placeholder of the default cost for an empty list.
    let hash = hit.map_or(PLACEHOLDER_HASH, |user| user.password.as_str());
    let verified = matches!(bcrypt::verify(pass, hash), Ok(true));
    match hit {
        // Password holders only; TOTP users return None here so the web
        // flow can run the verification-code step.
        Some(user) if verified && !user.has_totp() => Some(user.clone()),
        _ => None,
    }
}

/// A valid-format bcrypt hash of default cost used to level the timing
/// of a lookup with an unknown username (or an empty user list): the
/// verification runs the full key schedule and simply fails.
const PLACEHOLDER_HASH: &str = "$2b$12$C6UzMDM.H6dfI/f/IKcEeO7ZBpEbA1Fu6wCmRaFnW9fuvxdpFfxka";

/// The credential fingerprint mixed into sessions: changing a user's
/// password or TOTP secret invalidates their existing sessions.
pub fn cred_fingerprint(secret: &[u8], user: &AuthUser) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut message = String::with_capacity(user.password.len() + user.totp_secret.len());
    message.push_str(&user.password);
    message.push_str(&user.totp_secret);
    let tag = hmac::sign(&key, message.as_bytes());
    hex(tag.as_ref())
}

/// Does `domain` equal `host` or cover it as a dot-separated suffix?
/// Case-insensitive, like DNS names.
fn domain_covers(domain: &str, host: &str) -> bool {
    if host.len() < domain.len() || domain.is_empty() {
        return false;
    }
    let (prefix, tail) = host.split_at(host.len() - domain.len());
    tail.eq_ignore_ascii_case(domain) && (prefix.is_empty() || prefix.ends_with('.'))
}

/// Equality without content-dependent early exit: every byte pair of
/// the shorter input is folded into the accumulator; only the length
/// (not secret) ends the loop sooner. Same shape as `subtle`'s
/// constant-time compare, without the extra dependency.
fn name_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b) {
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedError {
    NestedDomains(String),
}

impl std::fmt::Display for SharedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NestedDomains(domain) => {
                write!(f, "单点登录域相互嵌套：{domain}")
            }
        }
    }
}

impl std::error::Error for SharedError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test user with a fast (cost 4) bcrypt hash; production saves
    /// use the default cost, which does not affect these behaviors.
    fn user(name: &str, password: &str, totp: &str) -> AuthUser {
        AuthUser {
            id: String::new(),
            name: name.to_owned(),
            password: bcrypt::hash(password, 4).expect("bcrypt hash"),
            totp_secret: totp.to_owned(),
            remark: String::new(),
            email: String::new(),
            display_name: String::new(),
            groups: Vec::new(),
        }
    }

    #[test]
    fn shared_user_id_generated_and_immutable() {
        let id = new_user_id();
        assert_eq!(id.len(), 32, "128 位随机数的十六进制应为 32 个字符");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "id 应为小写 hex：{id}"
        );
        assert_ne!(id, new_user_id(), "同名重建（重新生成）得到新 ID");

        let mut users = vec![user("alice", "pw", ""), user("bob", "pw", "")];
        users[1].id = "existing-id".to_owned();
        backfill_ids(&mut users);
        assert_eq!(users[0].id.len(), 32, "空 id 被补齐");
        // 改名后再次保存：已有 id 保持不变
        users[1].name = "robert".to_owned();
        let before = users[1].id.clone();
        backfill_ids(&mut users);
        assert_eq!(users[1].id, before, "已有 id 不可变");
    }

    #[test]
    fn sso_for_rejects_nested_domains() {
        // 保存时拒绝嵌套域；报告更具体（被嵌套）的那个
        assert_eq!(
            validate_sso_domains(&["example.com".to_owned(), "a.example.com".to_owned()]),
            Err(SharedError::NestedDomains("a.example.com".to_owned()))
        );
        // 完全重复同样冲突
        assert_eq!(
            validate_sso_domains(&["example.com".to_owned(), "EXAMPLE.com".to_owned()]),
            Err(SharedError::NestedDomains("EXAMPLE.com".to_owned()))
        );
        // 相互独立的域合法
        assert_eq!(
            validate_sso_domains(&["example.com".to_owned(), "other.org".to_owned()]),
            Ok(())
        );

        // 手工编辑留下的嵌套配置：匹配取最长的那个域
        let nested = ["example.com".to_owned(), "a.example.com".to_owned()];
        assert_eq!(
            sso_for(&nested, "example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            sso_for(&nested, "www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            sso_for(&nested, "x.a.example.com").as_deref(),
            Some("a.example.com")
        );
        // 点分边界：纯子串不算后缀
        assert_eq!(sso_for(&nested, "notexample.com").as_deref(), None);
        assert_eq!(sso_for(&nested, "example.company").as_deref(), None);
        assert_eq!(sso_for(&nested, "other.org").as_deref(), None);
    }

    #[test]
    fn check_password_constant_time_for_unknown_user() {
        let users = [user("alice", "secret", ""), user("bob", "hunter2", "")];
        // 未知名也走一次完整的 bcrypt 校验（首个用户的哈希），结果为 None
        assert!(check_password(&users, "mallory", "hunter2").is_none());
        // 占位哈希必须是有效格式：校验执行完整计算后返回「不匹配」
        assert!(
            matches!(bcrypt::verify("hunter2", PLACEHOLDER_HASH), Ok(false)),
            "占位哈希应能被解析并完成一次完整的校验"
        );
        // 空用户列表：占位哈希路径同样执行一次校验
        assert!(check_password(&[], "mallory", "hunter2").is_none());
        // 正确凭据
        assert!(check_password(&users, "alice", "secret").is_some());
        assert!(check_password(&users, "bob", "hunter2").is_some());
        // 名字命中但密码错误
        assert!(check_password(&users, "alice", "wrong").is_none());
    }

    #[test]
    fn totp_users_rejected_for_direct_check() {
        let plain = [user("carol", "pw", "")];
        let totp = [user("carol", "pw", "JBSWY3DPEHPK3PXP")];
        assert!(check_password(&plain, "carol", "pw").is_some());
        // 密码正确的 TOTP 用户也返回 None——由网页流程处理验证码
        assert!(check_password(&totp, "carol", "pw").is_none());
    }

    #[test]
    fn cred_fingerprint_tracks_password_and_totp() {
        let secret = b"auth-secret";
        let base = user("carol", "pw-one", "");
        let fingerprint = cred_fingerprint(secret, &base);
        assert_eq!(fingerprint.len(), 64, "SHA-256 摘要的 hex 为 64 字符");
        assert!(
            fingerprint
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "指纹应为小写 hex：{fingerprint}"
        );
        // 确定性
        assert_eq!(cred_fingerprint(secret, &base), fingerprint);
        // 换密码（哈希变化）后指纹变化
        let renamed_password = user("carol", "pw-two", "");
        assert_ne!(cred_fingerprint(secret, &renamed_password), fingerprint);
        // 启用 TOTP 后指纹变化
        let with_totp = user("carol", "pw-one", "JBSWY3DPEHPK3PXP");
        assert_ne!(cred_fingerprint(secret, &with_totp), fingerprint);
        // 换签名密钥后指纹变化
        assert_ne!(cred_fingerprint(b"another-secret", &base), fingerprint);
    }
}
