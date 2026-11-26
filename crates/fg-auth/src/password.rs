use std::{collections::HashSet, fmt, sync::LazyLock};

use anyhow::{Result, anyhow};

use crate::account::MAX_USERNAME_BYTES;

pub(super) const MAX_PASSWORD_BYTES: usize = 72;
const MIN_CHARS: usize = 10;
const PASSPHRASE_CHARS: usize = 16;

static COMMON: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    "
    password passwd passw0rd password123 password1 admin admin123 administrator superadmin root root123
    user guest testing test123 qwerty qwerty123 qwertyuiop qwertyuiop123 qwerasdf qazwsx qazwsxedc
    1qaz2wsx 1qaz2wsx3edc 1q2w3e4r 1q2w3e4r5t asdfghjkl asdf1234 zxcvbnm abc123 abc123456
    a123456789 1234567890 123456789 0987654321 9876543210 123123123 12341234 112233445566
    147258369 159357 1357924680 5201314 5201314520 1314520 1111111111 0000000000
    letmein welcome iloveyou love monkey dragon master sunshine princess football baseball
    superman batman starwars pokemon minecraft trustno trustno1 shadow michael jennifer
    login secret default changeme changeit temp demo whatever freedom hello hello123
    woaini woainima wodemima mima nihao zhongguo china beijing shanghai guangzhou shenzhen
    baidu taobao wechat weixin wangwang lucky internet computer server router openwrt
    synology docker linux ubuntu debian proxmox homelab truenas unraid mikrotik
    feiniu google apple microsoft amazon github gitlab spring summer autumn winter
    january february march april june july august september october november december
    20202020 20212021 20222022 20232023 20242024 20252025 20262026
    "
    .split_ascii_whitespace()
    .collect()
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordIssue {
    TooShort,
    TooLong,
    Common,
    Username,
    Product,
    Sequence,
    Repeat,
    Simple,
    Control,
}

impl PasswordIssue {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooShort => "tooShort",
            Self::TooLong => "tooLong",
            Self::Common => "common",
            Self::Username => "username",
            Self::Product => "product",
            Self::Sequence => "sequence",
            Self::Repeat => "repeat",
            Self::Simple => "simple",
            Self::Control => "control",
        }
    }
}

impl fmt::Display for PasswordIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PasswordIssue {}

/// Checks a proposed password without hashing or accessing the account store.
pub fn check_password_strength(username: &str, password: &str) -> Result<(), PasswordIssue> {
    use PasswordIssue::*;

    if password.len() > MAX_PASSWORD_BYTES {
        return Err(TooLong);
    }
    let chars: Vec<_> = password.chars().collect();
    if chars.iter().copied().any(char::is_control) {
        return Err(Control);
    }
    if chars.len() < MIN_CHARS {
        return Err(TooShort);
    }
    let lower = password.to_lowercase();
    if lower.contains("ferrumgate") || lower.contains("gately") {
        return Err(Product);
    }
    let username = username.trim();
    if (3..=MAX_USERNAME_BYTES).contains(&username.len()) {
        let username = username.to_lowercase();
        if username.len() >= 3 && lower.contains(&username) {
            return Err(Username);
        }
    }
    if is_common(&lower) {
        return Err(Common);
    }
    let mut distinct = ['\0'; 5];
    let mut used = 0;
    for ch in lower.chars() {
        if !distinct[..used].contains(&ch) {
            distinct[used] = ch;
            used += 1;
            if used == distinct.len() {
                break;
            }
        }
    }
    if used < distinct.len()
        || (1..=chars.len() / 2).any(|size| {
            chars.len().is_multiple_of(size) && chars[size..] == chars[..chars.len() - size]
        })
    {
        return Err(Repeat);
    }
    if mostly_sequential(&chars) {
        return Err(Sequence);
    }
    if chars.len() < PASSPHRASE_CHARS {
        let classes = chars.iter().fold(0_u8, |classes, ch| {
            let class = if ch.is_lowercase() {
                1
            } else if ch.is_uppercase() {
                2
            } else if ch.is_numeric() {
                4
            } else {
                8
            };
            classes | class
        });
        if classes.count_ones() < 2 {
            return Err(Simple);
        }
    }
    Ok(())
}

fn is_common(lower: &str) -> bool {
    let not_letter = |ch: char| !ch.is_alphabetic();
    let leading = lower.len() - lower.trim_start_matches(not_letter).len();
    let trailing = lower.len() - lower.trim_end_matches(not_letter).len();
    let matches = |candidate: &str| {
        let core = candidate.trim_matches(not_letter);
        COMMON.contains(candidate)
            || (core.len() >= 4 && COMMON.contains(core))
            || (0..=leading.min(8))
                .filter_map(|cut| candidate.get(cut..))
                .any(|tail| {
                    (0..=trailing.min(8))
                        .filter_map(|cut| tail.get(..tail.len().checked_sub(cut)?))
                        .any(|word| {
                            word.len() >= 5
                                && COMMON.contains(word)
                                && word.bytes().any(|byte| byte.is_ascii_alphabetic())
                        })
                })
    };
    if matches(lower) {
        return true;
    }
    let restored: String = lower
        .chars()
        .map(|ch| match ch {
            '0' => 'o',
            '1' | '|' => 'l',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' | '+' => 't',
            '8' => 'b',
            '!' => 'i',
            _ => ch,
        })
        .collect();
    restored != lower && matches(&restored)
}

fn mostly_sequential(chars: &[char]) -> bool {
    const ROWS: &[&[u8]] = &[
        b"qwertyuiop",
        b"asdfghjkl",
        b"zxcvbnm",
        b"1234567890",
        b"!@#$%^&*()",
    ];
    let mut covered = 0;
    let mut end = 0;
    for (start, window) in chars.windows(3).enumerate() {
        if !window.iter().all(char::is_ascii) {
            continue;
        }
        let [a, b, c] = [window[0], window[1], window[2]].map(|ch| ch.to_ascii_lowercase() as u8);
        let delta = i16::from(b) - i16::from(a);
        let consecutive = (a.is_ascii_lowercase() && c.is_ascii_lowercase()
            || a.is_ascii_digit() && c.is_ascii_digit())
            && delta.abs() == 1
            && i16::from(c) - i16::from(b) == delta;
        if consecutive
            || ROWS.iter().any(|row| {
                row.windows(3)
                    .any(|run| run == [a, b, c] || run == [c, b, a])
            })
        {
            covered += start + 3 - start.max(end);
            end = start + 3;
        }
    }
    covered * 10 >= chars.len() * 7
}

pub(super) fn hash(password: &str) -> Result<String> {
    bcrypt::non_truncating_hash(password, bcrypt::DEFAULT_COST)
        .map_err(|_| anyhow!("hash administrator password"))
}

pub(super) fn verify(password: &str, hash: &str) -> Result<bool> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }
    bcrypt::verify(password, hash).map_err(|_| anyhow!("verify administrator password hash"))
}
