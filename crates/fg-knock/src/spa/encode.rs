//! SPA packet generation (WP-54 step 6): builds fwknop-compatible packets
//! for the test suite and the "client" dialog. Not used on the hot path.

use base64::Engine as _;
use sha2::Digest;

use super::key::{aes_cbc_encrypt, evp_bytes_to_key};
use super::{
    B64_PREFIX, EncodeError, MAX_ACCESS, Message, PROTOCOL_VERSION, RAND_LEN, SALT_PREFIX,
};
use crate::model::limits;

/// Encodes `m` with `key`. `rand` supplies the 16 random characters
/// (8 bytes expanded to hex) and the 8-byte salt — pass deterministic
/// bytes in tests, or use [`encode_random`].
pub fn encode(m: &Message, key: &super::Key, rand: &[u8; 16]) -> Result<Vec<u8>, EncodeError> {
    let engine = base64::engine::general_purpose::STANDARD;
    if !(limits::ENC_KEY_MIN..=limits::ENC_KEY_MAX).contains(&key.enc.len())
        || !(limits::HMAC_KEY_MIN..=limits::HMAC_KEY_MAX).contains(&key.hmac.len())
    {
        return Err(EncodeError::KeyLength);
    }
    if m.access.is_empty() || m.access.len() > MAX_ACCESS {
        return Err(EncodeError::Field("access"));
    }
    if m.user.is_empty() || m.user.chars().count() > limits::USERNAME_MAX_CHARS {
        return Err(EncodeError::Field("user"));
    }
    if m.nat.is_some() {
        return Err(EncodeError::Field("nat"));
    }
    if m.msg_type.carries_client_timeout() && m.client_timeout.is_none() {
        return Err(EncodeError::Field("clientTimeout"));
    }
    let rand_text: String = rand[..8].iter().map(|byte| format!("{byte:02x}")).collect();
    debug_assert_eq!(rand_text.len(), RAND_LEN);
    let mut body = String::new();
    if let Some(addr) = m.addr {
        body.push_str(&addr.to_string());
        body.push(',');
    }
    for (index, access) in m.access.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&access.to_string());
    }
    let mut plain = format!(
        "{}:{}:{}:{}:{}:{}",
        rand_text,
        engine.encode(m.user.as_bytes()),
        m.timestamp,
        PROTOCOL_VERSION,
        m.msg_type.code(),
        engine.encode(body.as_bytes()),
    );
    if let Some(auth) = &m.server_auth {
        plain.push(':');
        plain.push_str(&engine.encode(auth.as_bytes()));
    }
    if m.msg_type.carries_client_timeout() {
        plain.push(':');
        plain.push_str(&m.client_timeout.expect("checked above").to_string());
    }
    let digest = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(plain.as_bytes());
        let out = hasher.finalize();
        out.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    plain.push(':');
    plain.push_str(&digest);

    // Encrypt: "Salted__" + salt + AES-256-CBC(PKCS#7(plain)).
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&rand[8..16]);
    let (aes_key, iv) = evp_bytes_to_key(&key.enc, &salt);
    let mut framed = Vec::with_capacity(8 + 8 + plain.len() + 16);
    framed.extend_from_slice(&SALT_PREFIX[..]);
    framed.extend_from_slice(&salt);
    framed.extend(aes_cbc_encrypt(&aes_key, &iv, plain.as_bytes()));

    let full_b64 = engine.encode(&framed);
    let mut mac = key
        .hmac_type
        .mac_new(&key.hmac)
        .ok_or(EncodeError::KeyLength)?;
    mac.update(full_b64.as_bytes());
    let mac_text = engine.encode(mac.finalize());
    // Strip the fixed prefix once and the trailing '=' padding.
    let body = full_b64
        .strip_prefix(B64_PREFIX)
        .ok_or(EncodeError::Field("rand"))?
        .trim_end_matches('=');
    let mut out = String::with_capacity(body.len() + mac_text.len());
    out.push_str(body);
    out.push_str(mac_text.trim_end_matches('='));
    Ok(out.into_bytes())
}

/// Like [`encode`] but draws the random bytes from the OS entropy source.
pub fn encode_random(m: &Message, key: &super::Key) -> Result<Vec<u8>, EncodeError> {
    let mut rand = [0u8; 16];
    getrandom::fill(&mut rand).map_err(|_| EncodeError::Field("rand"))?;
    encode(m, key, &rand)
}

#[cfg(test)]
mod tests {
    use super::super::MsgType;
    use super::super::test_support::sample_message;
    use super::super::{Key, decode};
    use super::*;

    fn key() -> Key {
        Key {
            enc: vec![b'k'; 16],
            hmac: vec![b'h'; 32],
            hmac_type: super::super::HmacType::Sha256,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let message = sample_message();
        let packet = encode(&message, &key(), &[0xAB; 16]).unwrap();
        assert!(packet.len() >= super::super::MIN_PACKET_LEN);
        assert!(packet.len() <= super::super::MAX_PACKET_LEN);
        let (index, decoded) = super::super::KeySet::new(vec![super::super::KeyEntry {
            key: key(),
            rule: "r1".into(),
            identity: None,
            cred: "c".into(),
        }])
        .decode(&packet)
        .unwrap();
        assert_eq!(index, 0);
        // The encoder derives the rand field and the trailing digest from
        // its random parameter; every other field roundtrips exactly.
        let mut expected = message;
        expected.rand = "abababababababab".to_owned();
        expected.digest = decoded.digest.clone();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn encode_rejects_bad_fields_and_key_lengths() {
        let key = key();
        let mut message = sample_message();
        message.access.clear();
        assert_eq!(
            encode(&message, &key, &[0; 16]),
            Err(EncodeError::Field("access"))
        );
        message.user = String::new();
        message.access = decoded_access();
        assert_eq!(
            encode(&message, &key, &[0; 16]),
            Err(EncodeError::Field("user"))
        );
        message.user = "tester".into();
        let mut short = key.clone();
        short.enc = vec![b'k'; 8];
        assert_eq!(
            encode(&message, &short, &[0; 16]),
            Err(EncodeError::KeyLength)
        );
        let mut no_timeout = message.clone();
        no_timeout.msg_type = MsgType::ClientTimeoutAccess;
        no_timeout.client_timeout = None;
        assert_eq!(
            encode(&no_timeout, &key, &[0; 16]),
            Err(EncodeError::Field("clientTimeout"))
        );
    }

    fn decoded_access() -> Vec<super::super::Access> {
        vec![super::super::Access {
            proto: super::super::Proto::Tcp,
            port: 22,
        }]
    }

    #[test]
    fn encode_uses_protocol_version_and_hex_rand() {
        let message = sample_message();
        let rand = [
            0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let packet = encode(&message, &key(), &rand).unwrap();
        // Deterministic salt and rand: the same input yields the same packet.
        let again = encode(&message, &key(), &rand).unwrap();
        assert_eq!(packet, again);
        let decoded = decode(&packet, &key()).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.rand, "123456789abcdef0");
    }
}
