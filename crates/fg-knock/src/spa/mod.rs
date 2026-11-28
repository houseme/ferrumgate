//! SPA (single packet authorization) message layer, compatible with the
//! fwknop 2.5+ Rijndael + HMAC mode (FKO protocol 3.0.0), per WP-54 §3.3.
//!
//! Packet layout:
//!
//! ```text
//! plaintext = rand:base64(user):timestamp:version:msg_type:base64(message)
//!             [:base64(nat)][:base64(server_auth)][:client_timeout]:digest
//! cipher    = "Salted__" + 8-byte salt + AES-256-CBC(plaintext, PKCS#7)
//!             key and IV derived with OpenSSL EVP_BytesToKey (MD5, 1 iteration)
//! packet    = base64(cipher) minus the fixed prefix "U2FsdGVkX1" and the
//!             trailing "=" padding, then base64(HMAC(prefixed b64 cipher))
//!             with "=" padding removed appended directly
//! ```
//!
//! Only `Access` (1) and `ClientTimeoutAccess` (3) message types are
//! accepted; command messages are never executed and NAT requests are not
//! supported. A packet requests at most [`MAX_ACCESS`] ports. Digests over
//! the message body are parsed but not re-verified: the HMAC already
//! authenticates the whole packet.

pub mod decode;
pub mod encode;
pub mod key;

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub use decode::{decode, prefilter};
pub use encode::{encode, encode_random};
pub use key::{HmacType, Key, KeyEntry, KeySet, cred_fingerprint, evp_bytes_to_key};

use crate::model::limits;

/// Minimum packet length in bytes (upstream `MinPacketLen`).
pub const MIN_PACKET_LEN: usize = 64;
/// Maximum packet length in bytes (upstream `MaxPacketLen`).
pub const MAX_PACKET_LEN: usize = 1500;
/// Protocol version produced by [`encode`] (upstream `3.0.0`).
pub const PROTOCOL_VERSION: &str = "3.0.0";
/// Fixed base64 prefix of OpenSSL salted ciphertext (`base64("Salted__")`).
pub const B64_PREFIX: &str = "U2FsdGVkX1";
/// Salt marker at the head of the decrypted-to-be ciphertext.
pub const SALT_PREFIX: &[u8; 8] = b"Salted__";
/// Maximum number of ports requested by one packet (upstream `maxAccess`).
pub const MAX_ACCESS: usize = limits::RULE_PORTS_MAX;
/// Length of the random field produced by [`encode`] (fwknop: 16 chars).
pub const RAND_LEN: usize = 16;

/// Transport protocol of one requested port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// Lower-case wire text (`tcp` / `udp`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One requested port (`proto/port` inside the message body).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    pub proto: Proto,
    pub port: u16,
}

impl Access {
    pub fn new(proto: Proto, port: u16) -> Self {
        Self { proto, port }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.proto.as_str(), self.port)
    }
}

/// SPA message types (FKO command codes). Only [`MsgType::Access`] and
/// [`MsgType::ClientTimeoutAccess`] are accepted by [`decode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    Command,
    Access,
    NatAccess,
    ClientTimeoutAccess,
    ClientTimeoutNat,
    LocalNatAccess,
    ClientTimeoutLocalNat,
}

impl MsgType {
    /// The FKO numeric code carried in the plaintext.
    pub fn code(self) -> u8 {
        match self {
            Self::Command => 0,
            Self::Access => 1,
            Self::NatAccess => 2,
            Self::ClientTimeoutAccess => 3,
            Self::ClientTimeoutNat => 4,
            Self::LocalNatAccess => 5,
            Self::ClientTimeoutLocalNat => 6,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Command,
            1 => Self::Access,
            2 => Self::NatAccess,
            3 => Self::ClientTimeoutAccess,
            4 => Self::ClientTimeoutNat,
            5 => Self::LocalNatAccess,
            6 => Self::ClientTimeoutLocalNat,
            _ => return None,
        })
    }

    /// Whether the client requested a grant duration (`-f`).
    pub fn carries_client_timeout(self) -> bool {
        matches!(
            self,
            Self::ClientTimeoutAccess | Self::ClientTimeoutNat | Self::ClientTimeoutLocalNat
        )
    }
}

/// A decoded SPA message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Random value from the client (opaque, used for replay detection).
    pub rand: String,
    /// Decoded username.
    pub user: String,
    /// Unix timestamp (seconds) from the client clock.
    pub timestamp: i64,
    /// Protocol version string as sent by the client.
    pub version: String,
    pub msg_type: MsgType,
    /// Address to admit; `None` means "the address the packet came from"
    /// (`-s`, sent as `0.0.0.0`).
    pub addr: Option<IpAddr>,
    /// Requested ports (at most [`MAX_ACCESS`]).
    pub access: Vec<Access>,
    /// Raw NAT request; parsed but never acted upon (unsupported).
    pub nat: Option<String>,
    /// Raw extra server-auth field.
    pub server_auth: Option<String>,
    /// Requested grant duration in seconds (`-f`).
    pub client_timeout: Option<u32>,
    /// Trailing message digest as sent by the client (not re-verified).
    pub digest: String,
}

/// Why a packet was not decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Structural problem inside the decrypted plaintext.
    Format,
    /// Packet length outside [`MIN_PACKET_LEN`]..=[`MAX_PACKET_LEN`].
    TooShortOrLong,
    /// A byte outside the base64 alphabet — not a knock packet at all.
    BadCharset,
    /// HMAC verification failed for every configured key.
    HmacMismatch,
    /// AES-256-CBC decryption failed (bad framing or ciphertext).
    Decrypt,
    /// PKCS#7 padding is invalid.
    Padding,
    /// A plaintext field is missing or malformed; the payload names it.
    BadField(&'static str),
    /// Valid but unsupported feature (message type, NAT request).
    Unsupported(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format => f.write_str("malformed plaintext"),
            Self::TooShortOrLong => f.write_str("packet length out of range"),
            Self::BadCharset => f.write_str("not base64 text"),
            Self::HmacMismatch => f.write_str("HMAC verification failed"),
            Self::Decrypt => f.write_str("decryption failed"),
            Self::Padding => f.write_str("invalid PKCS#7 padding"),
            Self::BadField(field) => write!(f, "invalid field: {field}"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Failure of message generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Encryption or HMAC key length outside the accepted range.
    KeyLength,
    /// A message field is not serializable (empty access list, bad user…).
    Field(&'static str),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyLength => f.write_str("key length out of range"),
            Self::Field(field) => write!(f, "invalid field: {field}"),
        }
    }
}

impl std::error::Error for EncodeError {}

#[cfg(test)]
pub(crate) mod test_support {
    use base64::Engine as _;

    use super::{Access, Message, MsgType, Proto};

    /// A minimal valid `Access` message used by the encode/decode tests.
    pub fn sample_message() -> Message {
        Message {
            rand: "0123456789abcdef".to_owned(),
            user: "tester".to_owned(),
            timestamp: 1_700_000_000,
            version: super::PROTOCOL_VERSION.to_owned(),
            msg_type: MsgType::Access,
            addr: None,
            access: vec![Access::new(Proto::Tcp, 22)],
            nat: None,
            server_auth: None,
            client_timeout: None,
            digest: String::new(),
        }
    }

    /// base64 helper for key material in tests.
    pub fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}
