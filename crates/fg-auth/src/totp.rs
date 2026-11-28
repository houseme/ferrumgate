use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use aws_lc_rs::hmac;
use data_encoding::BASE32_NOPAD;
use subtle::ConstantTimeEq;

const PERIOD: u64 = 30;
const SETUP_TTL: Duration = Duration::from_secs(300);

pub struct Totp(hmac::Key);

impl Totp {
    pub fn parse(secret: &str) -> Option<Self> {
        let mut normalized = secret.to_ascii_uppercase();
        normalized.retain(|ch| ch != ' ');
        let key = BASE32_NOPAD.decode(normalized.as_bytes()).ok()?;
        (key.len() >= 10).then(|| Self(hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key)))
    }

    pub fn match_code(&self, code: &str, timestamp: u64) -> Option<u64> {
        let code = code.trim();
        if code.len() != 6 || !code.bytes().all(|digit| digit.is_ascii_digit()) {
            return None;
        }
        let code = code.parse::<u32>().ok()?;
        let step = timestamp / PERIOD;
        [Some(step + 1), Some(step), step.checked_sub(1)]
            .into_iter()
            .flatten()
            .find(|&candidate| bool::from(code.ct_eq(&(self.truncated(candidate) % 1_000_000))))
    }

    fn truncated(&self, step: u64) -> u32 {
        let digest = hmac::sign(&self.0, &step.to_be_bytes());
        let digest = digest.as_ref();
        let offset = usize::from(digest[19] & 0x0f);
        u32::from_be_bytes(
            digest[offset..offset + 4]
                .try_into()
                .expect("four-byte HOTP block"),
        ) & 0x7fff_ffff
    }
}

pub(super) struct PendingTotp {
    pub secret: String,
    session: String,
    expires: Instant,
}

impl PendingTotp {
    pub fn new(session: &str) -> Result<Self> {
        let mut bytes = [0; 20];
        getrandom::fill(&mut bytes).map_err(|_| anyhow!("get randomness for TOTP enrollment"))?;
        Ok(Self {
            secret: BASE32_NOPAD.encode(&bytes),
            session: session.into(),
            expires: Instant::now() + SETUP_TTL,
        })
    }

    pub fn valid_for(&self, session: &str) -> bool {
        self.session == session && Instant::now() < self.expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn totp_matches_rfc6238_sha1_vectors() {
        let totp = Totp::parse(TEST_SEED).unwrap();
        for (time, expected) in [
            (59, 94_287_082),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ] {
            assert_eq!(totp.truncated(time / PERIOD) % 100_000_000, expected);
        }
    }

    #[test]
    fn totp_preserves_leading_zeroes_and_bounds_clock_skew() {
        let totp = Totp::parse(&TEST_SEED.to_lowercase()).unwrap();
        assert_eq!(totp.match_code("081804", 1_111_111_109), Some(37_037_036));
        assert_eq!(totp.match_code("287082", 0), Some(1));
        assert_eq!(totp.match_code("287082", 89), Some(1));
        assert_eq!(totp.match_code("287082", 90), None);
        assert_eq!(totp.match_code("81804", 1_111_111_109), None);
        assert!(Totp::parse("A!!B").is_none());
    }
}
