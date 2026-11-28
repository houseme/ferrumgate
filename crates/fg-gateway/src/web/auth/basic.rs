//! HTTP basic verification (WP-24 step 5): credentials are checked
//! against the site users and the shared users without TOTP — the
//! browser's password prompt has no place to enter a verification
//! code — behind the per-source reservation gates.
#![allow(dead_code)]

use std::net::IpAddr;
use std::time::Instant;

use base64::{Engine, engine::general_purpose::STANDARD};

use super::reserve::Reserve;
use super::shared::{AuthUser, check_password};
use super::users::{split_entry, verify_site_user};
use super::BasicOutcome;

/// Verifies HTTP basic credentials. Users come from the site entries
/// (`name:password`, plaintext or bcrypt) and, failing those, the
/// shared users; `check_password` already excludes TOTP users, and the
/// result is re-checked so a TOTP user can never slip through this
/// path (they belong to the web flow only).
///
/// Gate order: a [`Reserve::locked`] source is refused outright even
/// with correct credentials (`Locked`); then a gate slot is acquired —
/// `Overloaded` (without counting a failure) when the source already
/// holds MAX_INFLIGHT running plus MAX_WAITING queued verifications.
///
/// [`BasicOutcome::Denied`] means every configured user missed: **the
/// caller is responsible for `reserve.record_failure(source, now)`**
/// — this function never records failures, so gate checks stay free of
/// counter side effects (the caller owns the lockout policy).
pub fn verify(
    site_users: &[String],
    shared: &[AuthUser],
    reserve: &Reserve,
    source: IpAddr,
    user: &str,
    pass: &str,
) -> BasicOutcome {
    if reserve.locked(source, Instant::now()) {
        return BasicOutcome::Locked;
    }
    let Some(slot) = reserve.try_acquire(source) else {
        // Overload rejection: no verification ran, so nothing counts.
        return BasicOutcome::Overloaded;
    };
    if site_users
        .iter()
        .any(|entry| verify_site_user(entry, user, pass))
    {
        return BasicOutcome::Allowed(slot);
    }
    // `check_password` returns `None` for TOTP users (correct password
    // included); the explicit `has_totp` guard documents the invariant.
    if let Some(hit) = check_password(shared, user, pass)
        && !hit.has_totp()
    {
        return BasicOutcome::Allowed(slot);
    }
    // No entry matched: the slot is released and the caller records
    // the failure (`Running` slots drop themselves; see `Slot`).
    BasicOutcome::Denied
}

/// Parses an `Authorization: Basic base64(user:pass)` header value into
/// its `(user, pass)` parts. The scheme match is case-insensitive (HTTP
/// auth schemes are); the payload must decode as standard base64 to
/// UTF-8 and contain a colon — the user may be empty, but the password
/// field must exist independently, so a colon-less payload is not
/// credentials. `None` for any other scheme, invalid base64, invalid
/// UTF-8 or a missing colon.
pub fn parse_header(value: &str) -> Option<(String, String)> {
    let (scheme, encoded) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::auth::reserve::{MAX_FAILURES, MAX_INFLIGHT, MAX_WAITING};
    use std::net::Ipv4Addr;

    /// A documentation-range source address for the tests.
    fn source() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))
    }

    /// A shared user with a fast (cost 4) bcrypt hash, mirroring the
    /// other auth modules' fixtures (production saves use the default
    /// cost, which does not affect these behaviors).
    fn shared_user(name: &str, password: &str, totp: &str) -> AuthUser {
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

    fn allowed(outcome: BasicOutcome) -> bool {
        matches!(outcome, BasicOutcome::Allowed(_))
    }

    #[test]
    fn basic_requires_at_least_one_user() {
        // 单元形态：site_users 与 shared 都为空时无任何凭据可匹配，
        // 一律 Denied（调用方随后记失败）。
        let reserve = Reserve::new();
        assert!(matches!(
            verify(&[], &[], &reserve, source(), "alice", "pw"),
            BasicOutcome::Denied
        ));
    }

    #[test]
    fn site_user_plaintext_and_hash_allowed() {
        let reserve = Reserve::new();
        let plaintext = ["alice:s3cret".to_string()];
        assert!(allowed(verify(
            &plaintext, &[], &reserve, source(), "alice", "s3cret"
        )));
        assert!(!allowed(verify(
            &plaintext, &[], &reserve, source(), "alice", "wrong"
        )));

        // bcrypt 哈希条目（存量配置）照常通过。
        let hashed = [format!(
            "alice:{}",
            bcrypt::hash("s3cret", 4).expect("bcrypt hash")
        )];
        assert!(allowed(verify(
            &hashed, &[], &reserve, source(), "alice", "s3cret"
        )));
        assert!(!allowed(verify(
            &hashed, &[], &reserve, source(), "bob", "s3cret"
        )));

        // 冒号后的内容整体属于密码（与站点用户的拆分规则一致）。
        let colon = ["carol:pa:ss".to_string()];
        assert!(allowed(verify(
            &colon, &[], &reserve, source(), "carol", "pa:ss"
        )));
    }

    #[test]
    fn shared_user_without_totp_allowed() {
        let reserve = Reserve::new();
        let shared = [
            shared_user("bob", "hunter2", ""),
            shared_user("carol", "other", "JBSWY3DPEHPK3PXP"),
        ];
        // 未启用 TOTP 的共享用户可以走基本认证。
        assert!(allowed(verify(
            &[],
            &shared,
            &reserve,
            source(),
            "bob",
            "hunter2"
        )));
        assert!(!allowed(verify(
            &[],
            &shared,
            &reserve,
            source(),
            "bob",
            "wrong"
        )));
    }

    #[test]
    fn totp_shared_user_denied_even_with_correct_password() {
        // TOTP 共享用户即使密码正确也 Denied：浏览器弹窗没有验证码
        // 输入位，这类用户一律只走网页流程。
        let reserve = Reserve::new();
        let shared = [
            shared_user("carol", "pw", "JBSWY3DPEHPK3PXP"),
            shared_user("dave", "pw", ""),
        ];
        assert!(matches!(
            verify(&[], &shared, &reserve, source(), "carol", "pw"),
            BasicOutcome::Denied
        ));
        assert!(matches!(
            verify(&[], &shared, &reserve, source(), "carol", "wrong"),
            BasicOutcome::Denied
        ));
        // 对照：同一列表中无 TOTP 的用户不受影响。
        assert!(allowed(verify(
            &[], &shared, &reserve, source(), "dave", "pw"
        )));
    }

    #[test]
    fn locked_source_refused_before_gates() {
        // 计满失败后被锁的来源即使给出正确凭据也被拒绝（Locked）。
        let reserve = Reserve::new();
        let start = Instant::now();
        for _ in 0..MAX_FAILURES {
            reserve.record_failure(source(), start);
        }
        let users = ["alice:pw".to_string()];
        assert!(matches!(
            verify(&users, &[], &reserve, source(), "alice", "pw"),
            BasicOutcome::Locked
        ));
    }

    #[test]
    fn exhausted_gates_overload_without_counting() {
        // 8 运行 + 64 排队全满时直接拒绝（Overloaded）——即便凭据
        // 正确；此路径不运行任何校验，也不计失败。
        let reserve = Reserve::new();
        let mut slots = Vec::new();
        for _ in 0..MAX_INFLIGHT + MAX_WAITING {
            slots.push(reserve.try_acquire(source()).expect("the gates hold 72 slots"));
        }
        let users = ["alice:pw".to_string()];
        assert!(matches!(
            verify(&users, &[], &reserve, source(), "alice", "pw"),
            BasicOutcome::Overloaded
        ));
        // 释放一个运行位后同源恢复可校验。
        drop(slots.remove(0));
        assert!(allowed(verify(
            &users,
            &[],
            &reserve,
            source(),
            "alice",
            "pw"
        )));
    }

    #[test]
    fn parse_header_roundtrip() {
        let header = |payload: &str| format!("Basic {}", STANDARD.encode(payload));
        assert_eq!(
            parse_header(&header("alice:s3cret")),
            Some(("alice".to_owned(), "s3cret".to_owned()))
        );
        // 方案名大小写不敏感；多余空白可容忍。
        assert_eq!(
            parse_header(&format!("basic  {}", STANDARD.encode("alice:s3cret"))),
            Some(("alice".to_owned(), "s3cret".to_owned()))
        );
        // 用户可为空，但冒号必须存在。
        assert_eq!(
            parse_header(&header(":nopass")),
            Some(("".to_owned(), "nopass".to_owned()))
        );
        // 密码可为空字符串（字段独立存在）。
        assert_eq!(
            parse_header(&header("alice:")),
            Some(("alice".to_owned(), "".to_owned()))
        );
        // 首个冒号之后的冒号属于密码。
        assert_eq!(
            parse_header(&header("carol:pa:ss")),
            Some(("carol".to_owned(), "pa:ss".to_owned()))
        );

        // 非 Basic 方案拒绝。
        assert_eq!(parse_header("Bearer dXNlcjpwYXNz"), None);
        // 无冒号的载荷不是凭据。
        assert_eq!(parse_header(&header("alice")), None);
        // 非法 base64 拒绝。
        assert_eq!(parse_header("Basic @@not-base64@@"), None);
        // 非法 UTF-8 拒绝。
        assert_eq!(
            parse_header(&format!("Basic {}", STANDARD.encode([0xff, 0xfe]))),
            None
        );
        // 空载荷与纯方案名拒绝。
        assert_eq!(parse_header("Basic "), None);
        assert_eq!(parse_header("Basic"), None);
        assert_eq!(parse_header(""), None);
    }
}
