use fg_auth::{PasswordIssue, check_password_strength};

#[test]
fn password_rules_classify_weak_candidates() {
    use PasswordIssue::*;

    for (username, candidate, issue) in [
        ("owner", "星河海风闲云1!", TooShort),
        ("owner", "abc\tDef-1234", Control),
        ("owner", "MyFerrumGate-29x", Product),
        ("owner", "MyGATELY-29x", Product),
        ("  OpErAtOr ", "Myoperator-N9s", Username),
        ("owner", "Password2024!", Common),
        ("owner", "123password", Common),
        ("owner", "#P@ssw0rd2024!", Common),
        ("owner", "@dmin2024!", Common),
        ("owner", "woaini1314520", Common),
        ("owner", "1234567890", Common),
        ("owner", "qwertyuiopasdf", Sequence),
        ("owner", "LKJHGFDSA9!", Sequence),
        ("owner", "1234567890123", Sequence),
        ("owner", "abcdefghijkl", Sequence),
        ("owner", "abcdefgh!93", Sequence),
        ("owner", "AAAaaAAAaa", Repeat),
        ("owner", "r8!nDr8!nD", Repeat),
        ("owner", "kjxhzpqwmvnb", Simple),
    ] {
        assert_eq!(
            check_password_strength(username, candidate),
            Err(issue),
            "{candidate}"
        );
    }
    assert_eq!(TooShort.code(), "tooShort");
    assert_eq!(TooLong.code(), "tooLong");
    assert_eq!(Username.code(), "username");
}

#[test]
fn password_limits_count_characters_and_bcrypt_bytes_separately() {
    for (username, candidate) in [
        ("owner", "xK9#mPq2vL"),
        ("owner", "kjxhzpqwmvnbtrgd"),
        ("owner", "polar kite sails beyond the orchard"),
        ("owner", "我的密码很长很安全2026"),
        ("ab", "ab-Router-77xyz"),
        ("owner", "dockerfly-77-Zq"),
        ("owner", "abcdefgh!934"),
    ] {
        assert_eq!(
            check_password_strength(username, candidate),
            Ok(()),
            "{candidate}"
        );
    }
    let boundary = "雨".repeat(16) + "彩虹鲤鱼青松新芽";
    assert_eq!(boundary.len(), 72);
    assert_eq!(check_password_strength("owner", &boundary), Ok(()));
    assert_eq!(
        check_password_strength("owner", &(boundary + "x")),
        Err(PasswordIssue::TooLong)
    );
}
