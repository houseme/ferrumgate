//! NAT-PMP / PCP mapping client (WP-42 §3.3, RFC 6886): requests against
//! the gateway's port 5351 — opcode 0 reads the gateway's WAN address,
//! opcodes 1 / 2 map UDP / TCP ports (the gateway assigns the external
//! port), and a zero lifetime deletes the mapping again. Protocol flow is
//! exactly RFC 6886 §3-4: two-byte requests with a 250 ms initial
//! retransmit doubling up to the 9-second ceiling.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::model::Proto;

/// NAT-PMP listens on the gateway's UDP port 5351 (RFC 6886 §2.2).
pub const DEFAULT_PORT: u16 = 5351;

/// Opcode 0: read the gateway's external (WAN) address.
pub const OP_PUBLIC_ADDRESS: u8 = 0;
/// Opcode 1 (UDP) / 2 (TCP) share the wire layout.
pub const OP_MAP_UDP: u8 = 1;
pub const OP_MAP_TCP: u8 = 2;

/// Result codes from RFC 6886 §3.3.2.
pub const RESULT_SUCCESS: u16 = 0;
pub const RESULT_UNSUPPORTED_VERSION: u16 = 1;
pub const RESULT_NOT_AUTHORIZED: u16 = 2;
pub const RESULT_NETWORK_FAILURE: u16 = 3;
pub const RESULT_OUT_OF_RESOURCES: u16 = 4;
pub const RESULT_UNSUPPORTED_OPCODE: u16 = 5;

/// Suggested mapping lifetime (2 hours, RFC 6886 §3.3 recommendation of
/// renewing at half-life; upstream keeps the same horizon).
pub const SUGGESTED_LIFETIME_SECS: u32 = 7200;

/// Retransmission pacing (RFC 6886 §2: start at 250 ms, double, 9 s max).
const RETRANSMIT_INITIAL: Duration = Duration::from_millis(250);
const RETRANSMIT_MAX: Duration = Duration::from_millis(9_000);

/// The gateway's WAN address, from opcode 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicAddress {
    pub address: IpAddr,
    /// Gateway epoch (seconds since its boot).
    pub epoch_secs: u32,
}

/// One answer to a mapping request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingAnswer {
    /// The internal port as requested (echoed).
    pub internal_port: u16,
    /// The external port the gateway assigned (0 with a delete).
    pub external_port: u16,
    /// The granted lifetime in seconds.
    pub lifetime_secs: u32,
    /// Gateway epoch (seconds since its boot).
    pub epoch_secs: u32,
}

/// Transport / protocol failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatPmpError {
    /// No answer within the retransmission schedule.
    Timeout,
    /// Socket failure.
    Io(String),
    /// The gateway answered with a non-zero result code (mapped to the
    /// RFC names).
    Result(u16),
    /// The answer could not be parsed.
    Malformed(&'static str),
    /// Cancelled (shutdown or rule restart).
    Cancelled,
}

impl std::fmt::Display for NatPmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "NAT-PMP 网关没有响应"),
            Self::Io(detail) => write!(f, "NAT-PMP 通信失败：{detail}"),
            Self::Result(code) => write!(
                f,
                "NAT-PMP 网关拒绝（结果码 {code}）：{}",
                result_text(*code)
            ),
            Self::Malformed(detail) => write!(f, "NAT-PMP 响应无法解析：{detail}"),
            Self::Cancelled => write!(f, "已取消"),
        }
    }
}

impl std::error::Error for NatPmpError {}

/// Short text for the well-known result codes.
pub fn result_text(code: u16) -> &'static str {
    match code {
        RESULT_SUCCESS => "成功",
        RESULT_UNSUPPORTED_VERSION => "网关不支持此版本",
        RESULT_NOT_AUTHORIZED => "网关未授权",
        RESULT_NETWORK_FAILURE => "网关侧网络失败",
        RESULT_OUT_OF_RESOURCES => "网关端口资源耗尽",
        RESULT_UNSUPPORTED_OPCODE => "网关不支持此操作",
        _ => "未知结果码",
    }
}

/// The opcode for a protocol's mapping requests.
pub fn map_opcode(protocol: Proto) -> u8 {
    match protocol {
        Proto::Tcp => OP_MAP_TCP,
        Proto::Udp => OP_MAP_UDP,
    }
}

/// Encodes a public-address request (version 0, opcode 0).
pub fn encode_public_address_request() -> [u8; 2] {
    [0, OP_PUBLIC_ADDRESS]
}

/// Encodes a map request (RFC 6886 §3.3): version, opcode, reserved,
/// internal port, requested external port (0 = gateway picks), lifetime
/// (`0` deletes the mapping).
pub fn encode_map_request(
    protocol: Proto,
    internal_port: u16,
    requested_external_port: u16,
    lifetime_secs: u32,
) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[1] = map_opcode(protocol);
    out[2..4].copy_from_slice(&0u16.to_be_bytes());
    out[4..6].copy_from_slice(&internal_port.to_be_bytes());
    out[6..8].copy_from_slice(&requested_external_port.to_be_bytes());
    out[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    out
}

/// Parses a public-address response.
pub fn parse_public_address_response(data: &[u8]) -> Result<PublicAddress, NatPmpError> {
    let (result, epoch_secs) = parse_header(data, OP_PUBLIC_ADDRESS)?;
    if result != RESULT_SUCCESS {
        // Error answers may be header-only; the code is what matters.
        return Err(NatPmpError::Result(result));
    }
    if data.len() < 12 {
        return Err(NatPmpError::Malformed("地址响应过短"));
    }
    let address = IpAddr::V4(std::net::Ipv4Addr::new(
        data[8], data[9], data[10], data[11],
    ));
    Ok(PublicAddress {
        address,
        epoch_secs,
    })
}

/// Parses a mapping response.
pub fn parse_map_response(data: &[u8], protocol: Proto) -> Result<MappingAnswer, NatPmpError> {
    let (result, epoch_secs) = parse_header(data, map_opcode(protocol))?;
    if result != RESULT_SUCCESS {
        // Error answers may be header-only; the code is what matters.
        return Err(NatPmpError::Result(result));
    }
    if data.len() < 16 {
        return Err(NatPmpError::Malformed("映射响应过短"));
    }
    Ok(MappingAnswer {
        internal_port: u16::from_be_bytes([data[8], data[9]]),
        external_port: u16::from_be_bytes([data[10], data[11]]),
        lifetime_secs: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        epoch_secs,
    })
}

/// Validates version / opcode and returns `(result code, epoch)`.
fn parse_header(data: &[u8], opcode: u8) -> Result<(u16, u32), NatPmpError> {
    if data.len() < 8 {
        return Err(NatPmpError::Malformed("响应不足 8 字节"));
    }
    if data[0] != 0 {
        return Err(NatPmpError::Malformed("版本不是 0"));
    }
    if data[1] != opcode | 0x80 {
        return Err(NatPmpError::Malformed("操作码不匹配"));
    }
    Ok((
        u16::from_be_bytes([data[2], data[3]]),
        u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
    ))
}

/// One public-address transaction against `gateway` (address with the
/// NAT-PMP port; a bare IP gains [`DEFAULT_PORT`]).
pub async fn public_address(
    gateway: SocketAddr,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<PublicAddress, NatPmpError> {
    let socket = UdpSocket::bind(SocketAddr::new(local_bind_hint(gateway), 0))
        .await
        .map_err(|error| NatPmpError::Io(error.to_string()))?;
    let request = encode_public_address_request();
    let answer = transact(&socket, gateway, &request, timeout, token).await?;
    parse_public_address_response(&answer)
}

/// One map transaction. `requested_external_port` 0 lets the gateway pick;
/// `lifetime_secs` 0 removes the mapping (the answer reports port 0).
pub async fn map_port(
    gateway: SocketAddr,
    protocol: Proto,
    internal_port: u16,
    requested_external_port: u16,
    lifetime_secs: u32,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<MappingAnswer, NatPmpError> {
    let socket = UdpSocket::bind(SocketAddr::new(local_bind_hint(gateway), 0))
        .await
        .map_err(|error| NatPmpError::Io(error.to_string()))?;
    let request = encode_map_request(
        protocol,
        internal_port,
        requested_external_port,
        lifetime_secs,
    );
    let answer = transact(&socket, gateway, &request, timeout, token).await?;
    parse_map_response(&answer, protocol)
}

/// Convenience: removes the mapping again (`lifetime` 0).
pub async fn unmap_port(
    gateway: SocketAddr,
    protocol: Proto,
    internal_port: u16,
    external_port: u16,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<MappingAnswer, NatPmpError> {
    map_port(
        gateway,
        protocol,
        internal_port,
        external_port,
        0,
        timeout,
        token,
    )
    .await
}

/// Resolves the gateway into a socket address with the NAT-PMP port.
pub fn gateway_addr(ip: IpAddr, port: Option<u16>) -> SocketAddr {
    SocketAddr::new(ip, port.unwrap_or(DEFAULT_PORT))
}

fn local_bind_hint(gateway: SocketAddr) -> IpAddr {
    // Bind the request socket to the matching family so it routes to the
    // gateway's link (an IPv4 gateway must not pick an IPv6 source).
    match gateway.ip() {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

/// Sends and retransmits per RFC 6886 §2 until one answer arrives.
async fn transact(
    socket: &UdpSocket,
    gateway: SocketAddr,
    request: &[u8],
    timeout: Duration,
    token: &CancellationToken,
) -> Result<Vec<u8>, NatPmpError> {
    let mut wait = RETRANSMIT_INITIAL;
    let mut buf = vec![0u8; 64];
    loop {
        if wait > RETRANSMIT_MAX || wait >= timeout {
            return Err(NatPmpError::Timeout);
        }
        socket
            .send_to(request, gateway)
            .await
            .map_err(|error| NatPmpError::Io(error.to_string()))?;
        let received = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(NatPmpError::Cancelled),
            result = tokio::time::timeout(wait.min(timeout), socket.recv_from(&mut buf)) => match result {
                Err(_elapsed) => None,
                Ok(Err(error)) => return Err(NatPmpError::Io(error.to_string())),
                Ok(Ok((size, from))) => (from == gateway).then_some(size),
            },
        };
        if let Some(size) = received {
            return Ok(buf[..size].to_vec());
        }
        wait = wait.saturating_mul(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A public-address answer announcing WAN IP 203.0.113.7 at epoch 12.
    fn public_answer() -> Vec<u8> {
        vec![0, 0x80, 0, 0, 0, 0, 0, 12, 203, 0, 113, 7]
    }

    /// A TCP map answer: internal 45000, assigned external 53111,
    /// lifetime 7200, epoch 33.
    fn map_answer() -> Vec<u8> {
        let mut out = vec![0, 0x82, 0, 0, 0, 0, 0, 33];
        out.extend_from_slice(&45000u16.to_be_bytes());
        out.extend_from_slice(&53111u16.to_be_bytes());
        out.extend_from_slice(&7200u32.to_be_bytes());
        out
    }

    #[test]
    fn natpmp_wire_format_round_trips() {
        // Map request: version 0, TCP opcode, ports and lifetime big-endian.
        let request = encode_map_request(Proto::Tcp, 45_000, 0, SUGGESTED_LIFETIME_SECS);
        assert_eq!(request[0], 0);
        assert_eq!(request[1], OP_MAP_TCP);
        assert_eq!(&request[4..6], &45_000u16.to_be_bytes());
        assert_eq!(
            &request[6..8],
            &0u16.to_be_bytes(),
            "gateway picks the port"
        );
        assert_eq!(&request[8..12], &SUGGESTED_LIFETIME_SECS.to_be_bytes());
        // A delete is a map request with lifetime 0.
        let delete = encode_map_request(Proto::Udp, 45_000, 53_111, 0);
        assert_eq!(delete[1], OP_MAP_UDP);
        assert_eq!(&delete[8..12], &0u32.to_be_bytes());

        let answer = parse_public_address_response(&public_answer()).expect("parses");
        assert_eq!(answer.address, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(answer.epoch_secs, 12);
        let answer = parse_map_response(&map_answer(), Proto::Tcp).expect("parses");
        assert_eq!(answer.internal_port, 45_000);
        assert_eq!(answer.external_port, 53_111);
        assert_eq!(answer.lifetime_secs, 7200);
        // Opcode mismatch and truncation are rejected.
        assert!(matches!(
            parse_map_response(&map_answer(), Proto::Udp),
            Err(NatPmpError::Malformed(_))
        ));
        assert!(matches!(
            parse_map_response(&map_answer()[..6], Proto::Tcp),
            Err(NatPmpError::Malformed(_))
        ));
    }

    #[test]
    fn natpmp_result_codes_and_errors_render() {
        let denied = vec![0, 0x80, 0, 2, 0, 0, 0, 1];
        assert_eq!(
            parse_public_address_response(&denied),
            Err(NatPmpError::Result(RESULT_NOT_AUTHORIZED))
        );
        assert!(format!("{}", NatPmpError::Result(RESULT_OUT_OF_RESOURCES)).contains("4"));
        assert_eq!(
            gateway_addr("192.168.1.1".parse().unwrap(), None).port(),
            DEFAULT_PORT
        );
        assert_eq!(
            gateway_addr("192.168.1.1".parse().unwrap(), Some(53_51)).port(),
            5351
        );
    }
}
