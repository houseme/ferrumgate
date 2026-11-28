//! SPA packet decoding (WP-54 steps 2–4): length/charset prefilter before
//! any HMAC work, `Salted__` framing split, AES-256-CBC decryption with
//! PKCS#7 unpadding, and the plaintext field parser. All functions are
//! pure; HMAC verification lives in [`crate::spa::key::KeySet`] and happens
//! strictly before decryption.

use base64::Engine as _;

use super::key::{aes_cbc_decrypt, evp_bytes_to_key, parse_access_body, unpad};
use super::{
    B64_PREFIX, DecodeError, Key, MAX_ACCESS, MAX_PACKET_LEN, MIN_PACKET_LEN, Message, MsgType,
    SALT_PREFIX,
};
use crate::model::limits;

/// Decodes one packet with a single key: prefilter, HMAC verification,
/// decryption, plaintext parsing. The multi-key path is
/// [`super::KeySet::decode`].
pub fn decode(packet: &[u8], key: &Key) -> Result<Message, DecodeError> {
    prefilter(packet)?;
    let mac_len = key.hmac_type.b64_stripped_len();
    if packet.len() <= mac_len {
        return Err(DecodeError::TooShortOrLong);
    }
    let split = packet.len() - mac_len;
    let body = &packet[..split];
    let mac = std::str::from_utf8(&packet[split..]).map_err(|_| DecodeError::BadCharset)?;
    if !key.verify_hmac(&super::key::prefixed_cipher(body), mac) {
        // HMAC mismatch: never decrypt.
        return Err(DecodeError::HmacMismatch);
    }
    decrypt_and_parse(packet, key)
}

/// Length and charset gate: runs before any HMAC computation, so garbage
/// floods cost nothing. A packet must be 64–1500 bytes of base64 alphabet.
pub fn prefilter(packet: &[u8]) -> Result<(), DecodeError> {
    if !(MIN_PACKET_LEN..=MAX_PACKET_LEN).contains(&packet.len()) {
        return Err(DecodeError::TooShortOrLong);
    }
    if !packet
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(DecodeError::BadCharset);
    }
    Ok(())
}

/// Decrypts the packet (HMAC already verified by the caller) and parses
/// the plaintext. The packet body is the base64 ciphertext without the
/// `U2FsdGVkX1` prefix and without trailing `=`.
pub(crate) fn decrypt_and_parse(packet: &[u8], key: &super::Key) -> Result<Message, DecodeError> {
    let body = decode_cipher_body(packet, key)?;
    let plain_bytes = decrypt_body(&body, &key.enc)?;
    let plain = std::str::from_utf8(&plain_bytes).map_err(|_| DecodeError::Format)?;
    parse_plain(plain)
}

/// Restores the full base64 ciphertext from the packet body.
fn decode_cipher_body(packet: &[u8], key: &super::Key) -> Result<Vec<u8>, DecodeError> {
    let mac_len = key.hmac_type.b64_stripped_len();
    if packet.len() <= mac_len {
        return Err(DecodeError::TooShortOrLong);
    }
    let body = &packet[..packet.len() - mac_len];
    if body.is_empty() {
        return Err(DecodeError::Format);
    }
    let mut full = String::with_capacity(B64_PREFIX.len() + body.len() + 2);
    full.push_str(B64_PREFIX);
    full.push_str(std::str::from_utf8(body).map_err(|_| DecodeError::BadCharset)?);
    // The trailing '=' padding was stripped; restore however many the
    // length demands.
    let remainder = full.len() % 4;
    if remainder != 0 {
        for _ in remainder..4 {
            full.push('=');
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(full.as_bytes())
        .map_err(|_| DecodeError::Decrypt)
}

/// Splits `Salted__ + salt + ct`, derives key/IV via EVP_BytesToKey and
/// decrypts. Padding and framing failures are indistinguishable to the
/// caller apart from the two narrow variants, and both take the same path.
fn decrypt_body(body: &[u8], enc_key: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if body.len() < SALT_PREFIX.len() + 8 + 16 || body[..8] != SALT_PREFIX[..] {
        return Err(DecodeError::Decrypt);
    }
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&body[8..16]);
    let ct = &body[16..];
    if !ct.len().is_multiple_of(16) {
        return Err(DecodeError::Decrypt);
    }
    let (key, iv) = evp_bytes_to_key(enc_key, &salt);
    let plain = aes_cbc_decrypt(&key, &iv, ct).ok_or(DecodeError::Decrypt)?;
    unpad(&plain)
        .ok_or(DecodeError::Padding)
        .map(|padded| padded.to_vec())
}

/// Parses the colon-separated plaintext:
/// `rand:base64(user):timestamp:version:msg_type:base64(message)
/// [:base64(server_auth)][:client_timeout]:digest` — at most 9 fields
/// before the trailing digest (NAT requests are rejected as unsupported).
pub(crate) fn parse_plain(plain: &str) -> Result<Message, DecodeError> {
    let fields: Vec<&str> = plain.split(':').collect();
    // 6 mandatory + digest = 7 minimum; +server_auth +client_timeout = 9+1.
    if !(7..=10).contains(&fields.len()) {
        return Err(DecodeError::Format);
    }
    let digest = *fields.last().expect("len >= 1");
    let rest = &fields[..fields.len() - 1];
    let rand = rand_field(rest[0])?;
    let user = user_field(rest[1])?;
    let timestamp = rest[2]
        .parse::<i64>()
        .map_err(|_| DecodeError::BadField("timestamp"))?;
    let version = rest[3];
    if version.is_empty() || version.len() > 32 {
        return Err(DecodeError::BadField("version"));
    }
    let type_code = rest[4]
        .parse::<u8>()
        .map_err(|_| DecodeError::BadField("message type"))?;
    let msg_type = MsgType::from_code(type_code).ok_or(DecodeError::Unsupported("message type"))?;
    match msg_type {
        MsgType::Access | MsgType::ClientTimeoutAccess => {}
        _ => return Err(DecodeError::Unsupported("message type")),
    }
    let body = b64_field(rest[5], "access")?;
    let body = String::from_utf8(body).map_err(|_| DecodeError::BadField("access"))?;
    let (addr, access) = parse_access_body(&body)?;
    if access.len() > MAX_ACCESS {
        return Err(DecodeError::BadField("access"));
    }
    // Optional trailing fields, positionally: server auth then client
    // timeout (NAT fields belong to unsupported message types only).
    let mut server_auth: Option<String> = None;
    let mut client_timeout = None;
    let extras = &rest[6..];
    let expected = usize::from(msg_type.carries_client_timeout());
    let auth_slots = extras.len() - expected;
    match auth_slots {
        0 => {}
        1 => {
            let decoded = b64_field(extras[0], "serverAuth")?;
            server_auth = Some(String::from_utf8_lossy(&decoded).into_owned());
        }
        _ => return Err(DecodeError::Format),
    }
    if msg_type.carries_client_timeout() {
        let raw = extras
            .last()
            .ok_or(DecodeError::BadField("clientTimeout"))?;
        let value = raw
            .parse::<u32>()
            .map_err(|_| DecodeError::BadField("clientTimeout"))?;
        if value == 0 {
            return Err(DecodeError::BadField("clientTimeout"));
        }
        client_timeout = Some(value);
    }
    digest_field(digest)?;
    Ok(Message {
        rand,
        user,
        timestamp,
        version: version.to_owned(),
        msg_type,
        addr,
        access,
        nat: None,
        server_auth,
        client_timeout,
        digest: digest.to_owned(),
    })
}

/// The random value: fwknop sends 16 hex characters; any alphanumeric
/// value up to 64 characters is accepted for forward compatibility.
fn rand_field(raw: &str) -> Result<String, DecodeError> {
    if raw.is_empty() || raw.len() > 64 || !raw.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(DecodeError::BadField("rand"));
    }
    Ok(raw.to_owned())
}

/// base64-decodes and decodes the username; at most 64 characters.
fn user_field(raw: &str) -> Result<String, DecodeError> {
    let bytes = b64_field(raw, "user")?;
    let user = String::from_utf8(bytes).map_err(|_| DecodeError::BadField("user"))?;
    if user.chars().count() > limits::USERNAME_MAX_CHARS {
        return Err(DecodeError::BadField("user"));
    }
    Ok(user)
}

fn b64_field(raw: &str, name: &'static str) -> Result<Vec<u8>, DecodeError> {
    if raw.is_empty() || raw.len() > 2048 {
        return Err(DecodeError::BadField(name));
    }
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| DecodeError::BadField(name))
}

/// The trailing message digest as sent by the client (hex, 32..=128 chars
/// for SHA-256/SHA-512); it is recorded but never re-verified — the HMAC
/// already authenticates the packet.
fn digest_field(raw: &str) -> Result<(), DecodeError> {
    if raw.len() < 32 || raw.len() > 128 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DecodeError::BadField("digest"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefilter_rejects_short_long_and_bad_charset() {
        let ok = vec![b'A'; MIN_PACKET_LEN];
        assert_eq!(prefilter(&ok), Ok(()));
        assert_eq!(
            prefilter(&[b'A'; MIN_PACKET_LEN - 1]),
            Err(DecodeError::TooShortOrLong)
        );
        assert_eq!(
            prefilter(&vec![b'A'; MAX_PACKET_LEN + 1]),
            Err(DecodeError::TooShortOrLong)
        );
        let mut with_space = [b'A'; MIN_PACKET_LEN];
        with_space[MIN_PACKET_LEN - 1] = b' ';
        assert_eq!(prefilter(&with_space), Err(DecodeError::BadCharset));
        let binary = vec![0u8; MIN_PACKET_LEN];
        assert_eq!(prefilter(&binary), Err(DecodeError::BadCharset));
    }

    #[test]
    fn parse_plain_rejects_wrong_field_counts_and_digest() {
        // Six pre-digest fields + digest = minimal valid Access message.
        let valid = "0123456789abcdef:dGVzdGVy:1700000000:3.0.0:1:MC4wLjAuMCx0Y3AvMjI=:$DIGEST"
            .replace("$DIGEST", &"a".repeat(64));
        assert!(parse_plain(&valid).is_ok());
        // Missing the digest.
        let short = valid.rsplit_once(':').unwrap().0;
        assert_eq!(parse_plain(short), Err(DecodeError::Format));
        // Too many fields.
        let long = format!("{valid}:extra:extra2");
        assert_eq!(parse_plain(&long), Err(DecodeError::Format));
        // Non-hex digest.
        let bad_digest = valid.replace(&"a".repeat(64), &"z".repeat(64));
        assert_eq!(
            parse_plain(&bad_digest),
            Err(DecodeError::BadField("digest"))
        );
    }

    #[test]
    fn parse_plain_rejects_unknown_msg_type() {
        let make = |code: &str| {
            format!(
                "0123456789abcdef:dGVzdGVy:1700000000:3.0.0:{code}:MC4wLjAuMCx0Y3AvMjI=:{}",
                "a".repeat(64)
            )
        };
        // Command (0) and NAT types must not execute or open anything.
        assert_eq!(
            parse_plain(&make("0")),
            Err(DecodeError::Unsupported("message type"))
        );
        assert_eq!(
            parse_plain(&make("2")),
            Err(DecodeError::Unsupported("message type"))
        );
        assert_eq!(
            parse_plain(&make("4")),
            Err(DecodeError::Unsupported("message type"))
        );
        assert_eq!(
            parse_plain(&make("99")),
            Err(DecodeError::Unsupported("message type"))
        );
        assert_eq!(
            parse_plain(&make("x")),
            Err(DecodeError::BadField("message type"))
        );
    }

    fn parsed_type1_marker() -> Message {
        Message {
            rand: "0123456789abcdef".to_owned(),
            user: "tester".to_owned(),
            timestamp: 1_700_000_000,
            version: "3.0.0".to_owned(),
            msg_type: MsgType::Access,
            addr: None,
            access: vec![crate::spa::Access {
                proto: crate::spa::Proto::Tcp,
                port: 22,
            }],
            nat: None,
            server_auth: None,
            client_timeout: None,
            digest: "b".repeat(64),
        }
    }

    #[test]
    fn parse_plain_reads_client_timeout_and_server_auth() {
        let base = "0123456789abcdef:dGVzdGVy:1700000000:3.0.0:3:MC4wLjAuMCx0Y3AvMjI=";
        let msg = parse_plain(&format!("{base}:120:{}", "b".repeat(64))).unwrap();
        assert_eq!(msg.msg_type, MsgType::ClientTimeoutAccess);
        assert_eq!(msg.client_timeout, Some(120));
        assert!(msg.server_auth.is_none());
        let msg = parse_plain(&format!("{base}:c2VydmVy:600:{}", "b".repeat(64))).unwrap();
        assert_eq!(msg.server_auth.as_deref(), Some("server"));
        assert_eq!(msg.client_timeout, Some(600));
        // Type 1 has no client timeout: its one optional field is the
        // server-auth string (invalid base64 reported against that field).
        let base1 = "0123456789abcdef:dGVzdGVy:1700000000:3.0.0:1:MC4wLjAuMCx0Y3AvMjI=";
        assert_eq!(
            parse_plain(&format!("{base1}:!!!:{}", "b".repeat(64))),
            Err(DecodeError::BadField("serverAuth"))
        );
        assert_eq!(
            parse_plain(&format!("{base1}:{}", "b".repeat(64))),
            Ok(parsed_type1_marker())
        );
    }

    #[test]
    fn parse_plain_rejects_bad_user_and_timestamp() {
        let make = |user: &str, ts: &str| {
            format!(
                "0123456789abcdef:{user}:{ts}:3.0.0:1:MC4wLjAuMCx0Y3AvMjI=:{}",
                "a".repeat(64)
            )
        };
        assert_eq!(
            parse_plain(&make("!!!", "1700000000")),
            Err(DecodeError::BadField("user"))
        );
        let long_user = base64::engine::general_purpose::STANDARD.encode(vec![b'u'; 65]);
        assert_eq!(
            parse_plain(&make(&long_user, "1700000000")),
            Err(DecodeError::BadField("user"))
        );
        assert_eq!(
            parse_plain(&make("dGVzdGVy", "not-a-time")),
            Err(DecodeError::BadField("timestamp"))
        );
    }
}
