//! SPA keys and cryptographic primitives (WP-54 step 2/3/5): OpenSSL
//! `EVP_BytesToKey` key/IV derivation, AES-256-CBC with PKCS#7 padding,
//! HMAC verification over every configured key, and the [`KeySet`] that
//! reuses per-key HMAC contexts across packets.

use std::fmt;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use base64::Engine as _;
use hmac::Mac;
use md5::{Digest, Md5};
use subtle::ConstantTimeEq;

use super::{B64_PREFIX, DecodeError, EncodeError, MAX_ACCESS, Message, Proto};

/// HMAC algorithm. SHA-256 is the default; MD5 and SHA-1 are not offered.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum HmacType {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl HmacType {
    /// Digest length in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Length of the packet's trailing HMAC field: base64 of the digest
    /// with the `=` padding removed.
    pub fn b64_stripped_len(self) -> usize {
        let digest = self.digest_len();
        let full = digest.div_ceil(3) * 4;
        let padding = match digest % 3 {
            1 => 2,
            2 => 1,
            _ => 0,
        };
        full - padding
    }

    fn label(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    #[cfg(test)]
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub(crate) fn mac_new(self, key: &[u8]) -> Option<MacBox> {
        Some(match self {
            Self::Sha256 => {
                MacBox::Sha256(<hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key).ok()?)
            }
            Self::Sha384 => {
                MacBox::Sha384(<hmac::Hmac<sha2::Sha384> as Mac>::new_from_slice(key).ok()?)
            }
            Self::Sha512 => {
                MacBox::Sha512(<hmac::Hmac<sha2::Sha512> as Mac>::new_from_slice(key).ok()?)
            }
        })
    }
}

impl fmt::Display for HmacType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

pub(crate) enum MacBox {
    Sha256(hmac::Hmac<sha2::Sha256>),
    Sha384(hmac::Hmac<sha2::Sha384>),
    Sha512(hmac::Hmac<sha2::Sha512>),
}

impl MacBox {
    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(mac) => Mac::update(mac, data),
            Self::Sha384(mac) => Mac::update(mac, data),
            Self::Sha512(mac) => Mac::update(mac, data),
        }
    }

    pub(crate) fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(mac) => mac.finalize().into_bytes().to_vec(),
            Self::Sha384(mac) => mac.finalize().into_bytes().to_vec(),
            Self::Sha512(mac) => mac.finalize().into_bytes().to_vec(),
        }
    }
}

/// One accepted credential: encryption key, HMAC key and algorithm.
///
/// `enc` holds 16–32 bytes (AES-256 derives 32 bytes via
/// [`evp_bytes_to_key`] regardless), `hmac` 16–128 bytes; length checks
/// against the configured ranges live in `crate::validate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub enc: Vec<u8>,
    pub hmac: Vec<u8>,
    pub hmac_type: HmacType,
}

impl Key {
    /// Decodes the base64 key material stored in `knock.json`.
    pub fn from_base64(
        enc_b64: &str,
        hmac_b64: &str,
        hmac_type: HmacType,
    ) -> Result<Self, EncodeError> {
        let engine = base64::engine::general_purpose::STANDARD;
        let enc = engine
            .decode(enc_b64.trim())
            .map_err(|_| EncodeError::Field("encKey"))?;
        let hmac = engine
            .decode(hmac_b64.trim())
            .map_err(|_| EncodeError::Field("hmacKey"))?;
        Ok(Self {
            enc,
            hmac,
            hmac_type,
        })
    }

    /// Whether the key lengths fall inside the accepted ranges.
    pub fn lengths_ok(
        &self,
        enc_min: usize,
        enc_max: usize,
        hmac_min: usize,
        hmac_max: usize,
    ) -> bool {
        (enc_min..=enc_max).contains(&self.enc.len())
            && (hmac_min..=hmac_max).contains(&self.hmac.len())
    }

    /// Verifies the packet's trailing HMAC field. The input is the
    /// prefixed base64 ciphertext (`U2FsdGVkX1…`, `=` padding restored);
    /// the expected digest is the packet's tail, base64 with `=` removed.
    /// Comparison is constant time.
    pub(crate) fn verify_hmac(&self, prefixed_body: &[u8], mac_stripped: &str) -> bool {
        let Some(mut mac) = self.hmac_type.mac_new(&self.hmac) else {
            return false;
        };
        mac.update(prefixed_body);
        let computed = mac.finalize();
        let engine = base64::engine::general_purpose::STANDARD;
        let expected_stripped = engine.encode(&computed);
        let expected = expected_stripped.trim_end_matches('=');
        constant_time_eq_str(expected, mac_stripped)
    }
}

/// The HMAC input for a packet body: the fixed prefix plus the body with
/// its trailing `=` padding restored (the original base64 ciphertext
/// form, WP-54 §3.3).
pub(crate) fn prefixed_cipher(body: &[u8]) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(B64_PREFIX.len() + body.len() + 2);
    prefixed.extend_from_slice(B64_PREFIX.as_bytes());
    prefixed.extend_from_slice(body);
    let remainder = prefixed.len() % 4;
    if remainder != 0 {
        prefixed.resize(prefixed.len() + (4 - remainder), b'=');
    }
    prefixed
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// OpenSSL `EVP_BytesToKey` with MD5 and one iteration: derives the
/// 32-byte AES key and 16-byte IV from the raw encryption key (as the
/// password) and the 8-byte salt. MD5 here is only key stretching, exactly
/// as in fwknop — the security rests on the key randomness and the HMAC.
pub fn evp_bytes_to_key(password: &[u8], salt: &[u8; 8]) -> ([u8; 32], [u8; 16]) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    let mut prev: Vec<u8> = Vec::new();
    let mut emitted = 0usize;
    // Needed material: 32 (key) + 16 (IV) = 48 bytes = 3 MD5 blocks.
    while emitted < 48 {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password);
        hasher.update(salt);
        let block = hasher.finalize();
        let take = (48 - emitted).min(16);
        let bytes: &[u8; 16] = block.as_ref();
        for (i, byte) in bytes.iter().take(take).enumerate() {
            let index = emitted + i;
            if index < 32 {
                key[index] = *byte;
            } else {
                iv[index - 32] = *byte;
            }
        }
        emitted += take;
        prev = block.to_vec();
    }
    (key, iv)
}

/// Decrypts AES-256-CBC ciphertext (manual CBC chaining over
/// [`aes::Aes256`], avoiding an extra crate dependency).
pub(crate) fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.is_empty() || !ct.len().is_multiple_of(16) {
        return None;
    }
    let cipher = aes::Aes256::new_from_slice(key).ok()?;
    let mut plain = vec![0u8; ct.len()];
    let mut previous = *iv;
    let (cipher_blocks, plain_blocks) = (ct.as_chunks::<16>().0, plain.as_chunks_mut::<16>().0);
    for (index, block) in plain_blocks.iter_mut().enumerate() {
        // The ciphertext block is the chain input for this block and the
        // XOR mask for the next one.
        let mut cipher_block = cipher_blocks[index];
        cipher.decrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
            &mut cipher_block,
        ));
        for (byte, prev) in cipher_block.iter_mut().zip(&previous) {
            *byte ^= prev;
        }
        *block = cipher_block;
        previous = cipher_blocks[index];
    }
    Some(plain)
}

/// Encrypts with AES-256-CBC and applies PKCS#7 padding (used by
/// [`super::encode`]).
pub(crate) fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let pad = (16 - plain.len() % 16) as u8;
    let mut padded = plain.to_vec();
    padded.resize(plain.len() + usize::from(pad), pad);
    let cipher = aes::Aes256::new_from_slice(key).expect("32-byte key");
    let mut previous = *iv;
    for block in padded.as_chunks_mut::<16>().0 {
        for (byte, prev) in block.iter_mut().zip(&previous) {
            *byte ^= prev;
        }
        cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
            block,
        ));
        previous = *block;
    }
    padded
}

/// Removes PKCS#7 padding; `None` when the padding is invalid.
pub(crate) fn unpad(plain: &[u8]) -> Option<&[u8]> {
    if plain.is_empty() {
        return None;
    }
    let pad = *plain.last()? as usize;
    if pad == 0 || pad > 16 || pad > plain.len() {
        return None;
    }
    let (body, padding) = plain.split_at(plain.len() - pad);
    if padding.iter().any(|byte| *byte as usize != pad) {
        return None;
    }
    Some(body)
}

/// One key inside a [`KeySet`]: the credential plus which rule (and
/// identity) it belongs to, so a matched packet can be attributed.
#[derive(Clone, Debug)]
pub struct KeyEntry {
    pub key: Key,
    /// Owning rule key.
    pub rule: String,
    /// `None` when the credential is the rule's shared key.
    pub identity: Option<String>,
    /// Stable credential fingerprint (hash of the HMAC key); used by the
    /// grant registry to detect stale authorizations after edits.
    pub cred: String,
}

/// All credentials accepted by the enabled rules (shared keys and
/// identities, at most [`crate::model::limits::TOTAL_KEYS_MAX`]).
///
/// Every packet is HMAC-verified against every key before any decryption,
/// so a forged packet costs one HMAC per configured key; contexts are
/// built once and cloned per packet.
#[derive(Clone, Debug, Default)]
pub struct KeySet {
    entries: Vec<KeyEntry>,
}

impl KeySet {
    /// Builds the set; entries with unusable MAC keys are dropped.
    pub fn new(entries: Vec<KeyEntry>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .filter(|entry| !entry.key.hmac.is_empty() && !entry.key.enc.is_empty())
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &[KeyEntry] {
        &self.entries
    }

    /// Decodes one packet: prefilter, HMAC against every key (all keys are
    /// tried before deciding, so key order leaks nothing), then decrypt and
    /// parse with the first matching key that yields a valid message.
    /// Returns the matched entry index and the parsed message.
    pub fn decode(&self, packet: &[u8]) -> Result<(usize, Message), DecodeError> {
        super::prefilter(packet)?;
        let mut matched: Vec<usize> = Vec::new();
        let mut first_error = DecodeError::HmacMismatch;
        for (index, entry) in self.entries.iter().enumerate() {
            let mac_len = entry.key.hmac_type.b64_stripped_len();
            if packet.len() <= mac_len {
                first_error = DecodeError::TooShortOrLong;
                continue;
            }
            let split = packet.len() - mac_len;
            let body = &packet[..split];
            let mac = std::str::from_utf8(&packet[split..]).map_err(|_| DecodeError::BadCharset)?;
            if entry.key.verify_hmac(&prefixed_cipher(body), mac) {
                matched.push(index);
            }
        }
        if matched.is_empty() {
            // HMAC failed for every key: no decryption ever happens.
            return Err(first_error);
        }
        let mut last_error = DecodeError::Decrypt;
        for index in matched {
            match self.decode_with(index, packet) {
                Ok(message) => return Ok((index, message)),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    /// Decrypts and parses with one specific key (HMAC already verified).
    fn decode_with(&self, index: usize, packet: &[u8]) -> Result<Message, DecodeError> {
        let entry = &self.entries[index];
        super::decode::decrypt_and_parse(packet, &entry.key)
    }
}

/// Parses one `proto/port` access item.
pub(crate) fn parse_access(text: &str) -> Option<super::Access> {
    let (proto, port) = text.split_once('/')?;
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(super::Access {
        proto: Proto::parse(proto)?,
        port,
    })
}

/// Parses the base64-decoded message body: an optional address token
/// followed by up to [`MAX_ACCESS`] `proto/port` items.
pub(crate) fn parse_access_body(
    body: &str,
) -> Result<(Option<std::net::IpAddr>, Vec<super::Access>), DecodeError> {
    let mut parts = body.split(',');
    let mut addr = None;
    let mut access = Vec::new();
    let first = parts.next().unwrap_or("");
    match first.parse::<std::net::IpAddr>() {
        // `0.0.0.0` (or `::`) means "the packet's source address" (`-s`).
        Ok(ip) => addr = (!ip.is_unspecified()).then_some(ip),
        Err(_) if first.is_empty() => return Err(DecodeError::BadField("access")),
        // No address token: the first item is already a port spec.
        Err(_) => access.push(parse_access(first).ok_or(DecodeError::BadField("access"))?),
    }
    for part in parts {
        let item = parse_access(part).ok_or(DecodeError::BadField("access"))?;
        access.push(item);
        if access.len() > MAX_ACCESS {
            return Err(DecodeError::BadField("access"));
        }
    }
    if access.is_empty() {
        return Err(DecodeError::BadField("access"));
    }
    Ok((addr, access))
}

/// Fingerprint of a credential (first 16 hex chars of SHA-256 over the
/// HMAC algorithm tag and key material). Grants record it so edits that
/// invalidate a key can revoke exactly the stale grants.
pub fn cred_fingerprint(hmac_key: &[u8], hmac_type: HmacType) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"fg-knock-cred");
    hasher.update(hmac_type.label().as_bytes());
    hasher.update(hmac_key);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(hmac_type: HmacType) -> Key {
        Key {
            enc: vec![0x42; 16],
            hmac: b"hmac-secret-hmac-secret".to_vec(),
            hmac_type,
        }
    }

    #[test]
    fn hmac_type_b64_lengths_match_digest_sizes() {
        // base64(32 bytes) = 44 with one '=', stripped 43.
        assert_eq!(HmacType::Sha256.b64_stripped_len(), 43);
        // base64(48 bytes) = 64 without padding.
        assert_eq!(HmacType::Sha384.b64_stripped_len(), 64);
        // base64(64 bytes) = 88 with '==', stripped 86.
        assert_eq!(HmacType::Sha512.b64_stripped_len(), 86);
        for hmac_type in [HmacType::Sha256, HmacType::Sha384, HmacType::Sha512] {
            let digest = hmac_type.digest_len();
            let engine = base64::engine::general_purpose::STANDARD;
            let encoded = engine.encode(vec![0u8; digest]);
            assert_eq!(
                encoded.trim_end_matches('=').len(),
                hmac_type.b64_stripped_len(),
                "{hmac_type}"
            );
        }
    }

    #[test]
    fn evp_bytes_to_key_matches_openssl_vector() {
        // Generated externally:
        //   printf x | openssl enc -aes-256-cbc -md md5 -P \
        //     -pass pass:0123456789abcdef -S 0011223344556677
        //   salt=0011223344556677
        //   key=C53F5023C9FEC053855767200D736CC2D7872670A5BF96A11F3D9AEE31E25D53
        //   iv =274B271841C88110588318931AFED874
        let (key, iv) = evp_bytes_to_key(
            b"0123456789abcdef",
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        );
        assert_eq!(
            hex(&key),
            "c53f5023c9fec053855767200d736cc2d7872670a5bf96a11f3d9aee31e25d53"
        );
        assert_eq!(hex(&iv), "274b271841c88110588318931afed874");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn unpad_rejects_short_and_bad_padding() {
        assert_eq!(unpad(&[]), None);
        assert_eq!(unpad(&[16; 16]).map(|b| b.len()), Some(0));
        let mut block = vec![b'a'; 5];
        block.extend_from_slice(&[3, 3, 2]);
        assert_eq!(unpad(&block), None);
        let mut ok = vec![b'a'; 5];
        ok.extend_from_slice(&[3, 3, 3]);
        assert_eq!(unpad(&ok), Some(&b"aaaaa"[..]));
    }

    #[test]
    fn key_from_base64_reports_bad_field() {
        assert_eq!(
            Key::from_base64("!!!", "aaaa", HmacType::Sha256),
            Err(EncodeError::Field("encKey"))
        );
        assert_eq!(
            Key::from_base64("aaaa", "!!!", HmacType::Sha256),
            Err(EncodeError::Field("hmacKey"))
        );
    }

    #[test]
    fn hmac_type_parses_labels() {
        assert_eq!(HmacType::from_label("sha384"), Some(HmacType::Sha384));
        assert_eq!(HmacType::from_label("md5"), None);
        assert_eq!(HmacType::default().to_string(), "sha256");
    }

    #[test]
    fn access_body_requires_ports_and_caps_entries() {
        let (addr, ports) = parse_access_body("10.1.2.3,tcp/22,udp/53").unwrap();
        assert_eq!(addr, Some("10.1.2.3".parse().unwrap()));
        assert_eq!(
            ports,
            vec![
                crate::spa::Access::new(Proto::Tcp, 22),
                crate::spa::Access::new(Proto::Udp, 53)
            ]
        );
        // `-s`: source address mode.
        let (addr, _) = parse_access_body("0.0.0.0,tcp/22").unwrap();
        assert_eq!(addr, None);
        assert_eq!(
            parse_access_body("tcp/22").map(|(_, p)| p.len()),
            Ok(1),
            "address token is optional"
        );
        assert!(parse_access_body("0.0.0.0").is_err(), "no ports");
        let body = format!(
            "0.0.0.0,{}",
            (0..MAX_ACCESS + 1)
                .map(|_| "tcp/22")
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            parse_access_body(&body),
            Err(DecodeError::BadField("access"))
        );
        assert_eq!(
            parse_access_body("0.0.0.0,tcp/0"),
            Err(DecodeError::BadField("access"))
        );
        assert_eq!(
            parse_access_body("0.0.0.0,sctp/22"),
            Err(DecodeError::BadField("access"))
        );
    }

    #[test]
    fn hmac_verification_rejects_tampered_packets() {
        let key = key(HmacType::Sha256);
        let message = crate::spa::test_support::sample_message();
        let packet = crate::spa::encode(&message, &key, &[7u8; 16]).unwrap();
        let mac_len = key.hmac_type.b64_stripped_len();
        let body = &packet[..packet.len() - mac_len];
        let mac = std::str::from_utf8(&packet[packet.len() - mac_len..]).unwrap();
        let prefixed = prefixed_cipher(body);
        assert!(key.verify_hmac(&prefixed, mac));
        // One flipped character breaks verification.
        let mut tampered = prefixed.clone();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(!key.verify_hmac(&tampered, mac));
    }
}
