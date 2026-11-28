//! RFC 5389 / RFC 8489 minimal subset (WP-42 §3.3): `Binding` request and
//! success response encoding/decoding with `XOR-MAPPED-ADDRESS` (preferred)
//! and `MAPPED-ADDRESS` fallback. Everything here is a pure function over
//! byte slices so the wire format is unit-testable against the RFC example
//! values. Messages never exceed [`MAX_MESSAGE_SIZE`].

use std::io::Read;
use std::net::{IpAddr, SocketAddr};

use getrandom::fill as random_fill;

use crate::model::limits;

/// Magic cookie every RFC 5389 message carries after the type/length.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Hard wire ceiling shared with the model limits.
pub const MAX_MESSAGE_SIZE: usize = limits::MAX_MESSAGE_SIZE;
/// Fixed STUN header: type (2) + length (2) + cookie (4) + transaction (12).
pub const HEADER_LEN: usize = 20;
/// `Binding Request`.
pub const METHOD_BINDING_REQUEST: u16 = 0x0001;
/// `Binding Success Response`.
pub const METHOD_BINDING_RESPONSE: u16 = 0x0101;
/// `MAPPED-ADDRESS` attribute type.
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// `XOR-MAPPED-ADDRESS` attribute type.
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// High 16 bits of the magic cookie: the port XOR mask.
const PORT_MASK: u16 = (MAGIC_COOKIE >> 16) as u16;

/// 96-bit transaction identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxId(pub [u8; 12]);

impl TxId {
    /// A fresh random transaction id (OS randomness).
    pub fn random() -> Self {
        let mut id = [0u8; 12];
        random_fill(&mut id).expect("OS randomness is always available");
        Self(id)
    }
}

/// Codec and framing failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StunError {
    /// Fewer than 20 bytes or a truncated attribute.
    Truncated,
    /// Message exceeds [`MAX_MESSAGE_SIZE`].
    TooLarge,
    /// Not a STUN message (magic cookie mismatch or class bits set).
    NotStun,
    /// The message belongs to another transaction.
    TransactionMismatch,
    /// Message type is not a binding success response.
    UnexpectedType(u16),
    /// Neither address attribute was present.
    NoMappedAddress,
    /// An attribute length or family value violated the RFC layout.
    BadAttribute(&'static str),
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "STUN 报文不完整"),
            Self::TooLarge => write!(f, "STUN 报文超过 {} 字节", MAX_MESSAGE_SIZE),
            Self::NotStun => write!(f, "不是 STUN 报文"),
            Self::TransactionMismatch => write!(f, "STUN 事务 ID 不匹配"),
            Self::UnexpectedType(t) => write!(f, "意外的 STUN 报文类型 0x{t:04x}"),
            Self::NoMappedAddress => write!(f, "响应中没有映射地址"),
            Self::BadAttribute(what) => write!(f, "STUN 属性无效：{what}"),
        }
    }
}

impl std::error::Error for StunError {}

/// Builds a 20-byte `Binding Request` for `tx`.
pub fn binding_request(tx: TxId) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&METHOD_BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&tx.0);
    out
}

/// Whether the datagram looks like a STUN message: the two high bits of
/// the first byte are zero and the magic cookie matches. Used to tell STUN
/// traffic apart from business traffic sharing the channel socket.
pub fn is_message(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN && data[0] & 0xC0 == 0 && data[4..8] == MAGIC_COOKIE.to_be_bytes()
}

/// The transaction id of a STUN message.
pub fn message_tx_id(data: &[u8]) -> Option<TxId> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let mut id = [0u8; 12];
    id.copy_from_slice(&data[8..20]);
    Some(TxId(id))
}

/// Parses a `Binding Success Response` belonging to `tx` and returns the
/// mapped address. `XOR-MAPPED-ADDRESS` wins over `MAPPED-ADDRESS`.
pub fn parse_binding_response(data: &[u8], tx: TxId) -> Result<SocketAddr, StunError> {
    let (attributes, tx_seen) = parse_header_and_attributes(data)?;
    if tx_seen != tx {
        return Err(StunError::TransactionMismatch);
    }
    let mut xor: Option<SocketAddr> = None;
    let mut mapped: Option<SocketAddr> = None;
    let mut rest = attributes;
    while rest.len() >= 4 {
        let attr_type = u16::from_be_bytes([rest[0], rest[1]]);
        let attr_len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let padded = attr_len.div_ceil(4) * 4;
        let Some(value) = rest.get(4..4 + padded) else {
            return Err(StunError::Truncated);
        };
        let value = &value[..attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS if xor.is_none() => {
                xor = Some(decode_address(value, tx, true)?);
            }
            ATTR_MAPPED_ADDRESS if mapped.is_none() => {
                mapped = Some(decode_address(value, tx, false)?);
            }
            _ => {}
        }
        rest = &rest[4 + padded..];
    }
    xor.or(mapped).ok_or(StunError::NoMappedAddress)
}

/// Builds a `Binding Success Response` carrying `XOR-MAPPED-ADDRESS` for
/// `mapped` — the shape the fake test server answers with.
pub fn encode_binding_response(tx: TxId, mapped: SocketAddr) -> Vec<u8> {
    let value = encode_address(mapped, tx, true);
    let mut out = Vec::with_capacity(HEADER_LEN + 4 + value.len());
    out.extend_from_slice(&METHOD_BINDING_RESPONSE.to_be_bytes());
    out.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&tx.0);
    out.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    out
}

/// Message length a buffered stream starts with (header included),
/// validating the ceiling. `Ok(None)` when fewer than 20 bytes are
/// available.
pub fn frame_len(data: &[u8]) -> Result<Option<usize>, StunError> {
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(StunError::TooLarge);
    }
    if data.len() < HEADER_LEN {
        return Ok(None);
    }
    let total = HEADER_LEN + usize::from(u16::from_be_bytes([data[2], data[3]]));
    if total > MAX_MESSAGE_SIZE {
        return Err(StunError::TooLarge);
    }
    Ok(Some(total))
}

/// Blocking, self-delimited read for TCP streams (messages are framed by
/// the header length field). End of stream before a full message reports
/// [`StunError::Truncated`]; an oversized message reports
/// [`StunError::TooLarge`].
pub fn read_message<R: Read>(r: &mut R) -> Result<Vec<u8>, StunError> {
    let mut message = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < HEADER_LEN {
        let read = r
            .read(&mut message[filled..])
            .map_err(|_| StunError::Truncated)?;
        if read == 0 {
            return Err(StunError::Truncated);
        }
        filled += read;
    }
    let length = usize::from(u16::from_be_bytes([message[2], message[3]]));
    let total = HEADER_LEN + length;
    if total > MAX_MESSAGE_SIZE {
        return Err(StunError::TooLarge);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&message[..filled]);
    while out.len() < total {
        let want = (total - out.len()).min(512);
        let mut chunk = vec![0u8; want];
        let read = r.read(&mut chunk).map_err(|_| StunError::Truncated)?;
        if read == 0 {
            return Err(StunError::Truncated);
        }
        out.extend_from_slice(&chunk[..read]);
    }
    Ok(out)
}

/// Validates the header (class bits, cookie, binding response type) and
/// returns the attribute area plus the transaction seen on the wire.
fn parse_header_and_attributes(data: &[u8]) -> Result<(&[u8], TxId), StunError> {
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(StunError::TooLarge);
    }
    if data.len() < HEADER_LEN {
        return Err(StunError::Truncated);
    }
    if data[0] & 0xC0 != 0 {
        return Err(StunError::NotStun);
    }
    let kind = u16::from_be_bytes([data[0], data[1]]);
    let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if data[4..8] != MAGIC_COOKIE.to_be_bytes() {
        return Err(StunError::NotStun);
    }
    if HEADER_LEN + length > data.len() {
        return Err(StunError::Truncated);
    }
    if kind != METHOD_BINDING_RESPONSE {
        return Err(StunError::UnexpectedType(kind));
    }
    let mut tx = [0u8; 12];
    tx.copy_from_slice(&data[8..20]);
    Ok((&data[HEADER_LEN..HEADER_LEN + length], TxId(tx)))
}

/// The 16-byte XOR key for IPv6 addresses: magic cookie followed by the
/// transaction id (RFC 5389 §15.2).
fn xor_key(tx: TxId) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    key[4..].copy_from_slice(&tx.0);
    key
}

/// Decodes a `MAPPED-ADDRESS` / `XOR-MAPPED-ADDRESS` value: one reserved
/// byte, one family byte, then the masked port and address.
fn decode_address(value: &[u8], tx: TxId, xor: bool) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::BadAttribute("address attribute too short"));
    }
    let family = value[1];
    let masked_port = u16::from_be_bytes([value[2], value[3]]);
    let port = if xor {
        masked_port ^ PORT_MASK
    } else {
        masked_port
    };
    let octets = value.len() - 4;
    let (family_byte, width) = match family {
        0x01 => (0x01, 4usize),
        0x02 => (0x02, 16usize),
        _ => return Err(StunError::BadAttribute("address family")),
    };
    if octets != width {
        return Err(StunError::BadAttribute("address length"));
    }
    let mut bytes = [0u8; 16];
    bytes[..width].copy_from_slice(&value[4..4 + width]);
    if xor {
        let key = xor_key(tx);
        for (index, byte) in bytes[..width].iter_mut().enumerate() {
            *byte ^= key[index];
        }
    }
    let ip = match family_byte {
        0x01 => IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]),
        _ => IpAddr::from(bytes),
    };
    Ok(SocketAddr::new(ip, port))
}

/// Encodes a `XOR-MAPPED-ADDRESS` (when `xor`) or `MAPPED-ADDRESS` value
/// for `addr`.
fn encode_address(addr: SocketAddr, tx: TxId, xor: bool) -> Vec<u8> {
    let (family, mut ip) = match addr.ip() {
        IpAddr::V4(ip) => (0x01u8, ip.octets().to_vec()),
        IpAddr::V6(ip) => (0x02u8, ip.octets().to_vec()),
    };
    let port = if xor {
        addr.port() ^ PORT_MASK
    } else {
        addr.port()
    };
    let mut out = Vec::with_capacity(4 + ip.len());
    out.push(0);
    out.push(family);
    out.extend_from_slice(&port.to_be_bytes());
    if xor {
        let key = xor_key(tx);
        for (index, byte) in ip.iter_mut().enumerate() {
            *byte ^= key[index];
        }
    }
    out.extend_from_slice(&ip);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// RFC 5389 / RFC 5769 example transaction: cookie 0x2112A442 followed
    /// by `b7034c8d764abf5a32f8da83`.
    fn rfc_tx() -> TxId {
        TxId([
            0xb7, 0x03, 0x4c, 0x8d, 0x76, 0x4a, 0xbf, 0x5a, 0x32, 0xf8, 0xda, 0x83,
        ])
    }

    /// Hand-built XOR-MAPPED-ADDRESS response for `192.0.2.1:32853` (the
    /// RFC 5389 §J / RFC 5769 example mapped address):
    /// port 0x8055 ^ 0x2112 = 0xA147, address C0 00 02 01 ^ 21 12 A4 42 =
    /// E1 12 A6 43.
    fn rfc_response() -> Vec<u8> {
        [
            0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0x03, 0x4c, 0x8d, 0x76, 0x4a,
            0xbf, 0x5a, 0x32, 0xf8, 0xda, 0x83, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47,
            0xe1, 0x12, 0xa6, 0x43,
        ]
        .to_vec()
    }

    #[test]
    fn binding_request_wire_format_matches_rfc_layout() {
        let tx = rfc_tx();
        let request = binding_request(tx);
        assert_eq!(request.len(), HEADER_LEN);
        assert_eq!(&request[0..2], &METHOD_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&request[2..4], &0u16.to_be_bytes(), "empty attributes");
        assert_eq!(&request[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&request[8..20], &tx.0);
        assert!(is_message(&request));
        assert_eq!(message_tx_id(&request), Some(tx));
    }

    #[test]
    fn is_message_and_tx_id_reject_non_stun_traffic() {
        // High class bits set, cookie present: not STUN.
        let mut framed = rfc_response();
        framed[0] |= 0x80;
        assert!(!is_message(&framed));
        // Cookie missing: not STUN (business traffic on the channel).
        let mut noise = vec![0u8; 40];
        noise[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        assert!(!is_message(&noise));
        assert_eq!(message_tx_id(&noise[..10]), None);
        assert_eq!(message_tx_id(&framed), Some(rfc_tx()));
    }

    #[test]
    fn parse_xor_mapped_address_v4_v6() {
        let addr = parse_binding_response(&rfc_response(), rfc_tx()).expect("v4 vector");
        assert_eq!(addr, "192.0.2.1:32853".parse().expect("addr"));
        // Round-trip an IPv6 mapping through the encoder.
        let tx = TxId::random();
        let mapped: SocketAddr = "[2001:db8::1]:54321".parse().expect("v6");
        let encoded = encode_binding_response(tx, mapped);
        assert_eq!(
            parse_binding_response(&encoded, tx).expect("v6 vector"),
            mapped
        );
        // The transaction must match: a different id fails.
        assert_eq!(
            parse_binding_response(&rfc_response(), TxId::random()),
            Err(StunError::TransactionMismatch)
        );
    }

    #[test]
    fn parse_falls_back_to_mapped_address() {
        let tx = rfc_tx();
        // MAPPED-ADDRESS (not XORed): port 0x8055, address C0 00 02 01.
        let mut message = Vec::new();
        message.extend_from_slice(&METHOD_BINDING_RESPONSE.to_be_bytes());
        message.extend_from_slice(&12u16.to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(&tx.0);
        message.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        message.extend_from_slice(&8u16.to_be_bytes());
        message.extend_from_slice(&[0x00, 0x01, 0x80, 0x55, 0xc0, 0x00, 0x02, 0x01]);
        let addr = parse_binding_response(&message, tx).expect("mapped fallback");
        assert_eq!(addr, "192.0.2.1:32853".parse().expect("addr"));
        // XOR wins when both attributes are present.
        let mut both = rfc_response();
        both.truncate(HEADER_LEN); // keep header, rebuild with two attrs
        let mut attributes = Vec::new();
        attributes.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attributes.extend_from_slice(&8u16.to_be_bytes());
        attributes.extend_from_slice(&[0x00, 0x01, 0x80, 0x55, 0xc0, 0x00, 0x02, 0x01]);
        attributes.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attributes.extend_from_slice(&8u16.to_be_bytes());
        attributes.extend_from_slice(&[0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
        both[2..4].copy_from_slice(&(attributes.len() as u16).to_be_bytes());
        both.extend_from_slice(&attributes);
        assert_eq!(
            parse_binding_response(&both, tx).expect("xor preferred"),
            "192.0.2.1:32853".parse::<SocketAddr>().expect("addr")
        );
    }

    #[test]
    fn tcp_read_message_self_delimited_reassembles() {
        let tx = TxId::random();
        let first = encode_binding_response(tx, "10.0.0.1:1000".parse().expect("addr"));
        let second = encode_binding_response(tx, "10.0.0.2:2000".parse().expect("addr"));
        // Two messages glued together arrive as two reads.
        let mut stream = Cursor::new([first.clone(), second.clone()].concat());
        assert_eq!(read_message(&mut stream).expect("first"), first);
        assert_eq!(read_message(&mut stream).expect("second"), second);
        // A half-delivered header then the rest also reassembles.
        let bytes = first.clone();
        let (head, tail) = bytes.split_at(7);
        let mut halves = Cursor::new([head, tail, &second[..]].concat());
        assert_eq!(read_message(&mut halves).expect("half"), first);
        assert_eq!(read_message(&mut halves).expect("next"), second);
        // Stream cut mid-message: truncated.
        let mut cut = Cursor::new(&first[..first.len() - 2]);
        assert_eq!(read_message(&mut cut), Err(StunError::Truncated));
    }

    #[test]
    fn message_over_2048_rejected() {
        // Header claims a length beyond the ceiling.
        let mut message = vec![0u8; HEADER_LEN];
        message[0..2].copy_from_slice(&METHOD_BINDING_RESPONSE.to_be_bytes());
        message[2..4].copy_from_slice(&(MAX_MESSAGE_SIZE as u16).to_be_bytes());
        assert!(frame_len(&message).unwrap_err() == StunError::TooLarge);
        let mut r = Cursor::new(message);
        assert_eq!(read_message(&mut r), Err(StunError::TooLarge));
        // An oversized datagram is rejected by the parser too.
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert_eq!(
            parse_binding_response(&oversized, TxId::random()),
            Err(StunError::TooLarge)
        );
        // A valid large-but-legal frame passes the length check.
        let mut legal = vec![0u8; HEADER_LEN];
        legal[2..4].copy_from_slice(&((MAX_MESSAGE_SIZE - HEADER_LEN) as u16).to_be_bytes());
        assert_eq!(frame_len(&legal), Ok(Some(MAX_MESSAGE_SIZE)));
    }
}
