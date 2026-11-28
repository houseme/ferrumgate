//! ICMP echo (WP-71 §3.3): packets are built and verified with self-written
//! RFC 792 / RFC 4443 functions; the socket is an **unprivileged datagram
//! ICMP socket** (SOCK_DGRAM + IPPROTO_ICMP). Per decision D13 no raw
//! socket fallback is attempted — when the socket cannot be created the job
//! fails with a reason that points at the kernel knob and at the port-probe
//! alternative. Each echo uses its own connected socket; the kernel assigns
//! the echo identifier (the local port on Linux/macOS), so replies are
//! matched by identifier, sequence and payload.

use std::io::{self, Read as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::jobs::{JobError, JobFut, JobHandle};
use crate::model::{PingParams, limits};
use crate::validate;

/// ICMP type numbers (RFC 792 / RFC 4443).
pub const ECHO_REQUEST_V4: u8 = 8;
pub const ECHO_REPLY_V4: u8 = 0;
pub const ECHO_REQUEST_V6: u8 = 128;
pub const ECHO_REPLY_V6: u8 = 129;

/// Payload length per echo (the classic ping's 56 bytes).
pub const PAYLOAD_LEN: usize = 56;

/// Receive buffer for one echo reply.
const RECV_BUF_LEN: usize = 2048;

/// The Internet checksum (ones-complement sum over 16-bit words).
pub fn checksum(bytes: &[u8]) -> u16 {
    let (chunks, rest) = bytes.as_chunks::<2>();
    let mut sum: u32 = chunks
        .iter()
        .map(|chunk| u16::from_be_bytes(*chunk) as u32)
        .sum();
    if let [odd] = rest {
        sum += u32::from(*odd) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
}

/// The deterministic echo payload stamped with the sequence number.
pub fn payload(seq: u16) -> Vec<u8> {
    (0..PAYLOAD_LEN)
        .map(|index| (index % 255) as u8 ^ (seq as u8))
        .collect()
}

/// An IPv4 echo request with a valid checksum.
pub fn build_echo_request_v4(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut message = header(ident, seq, payload);
    message[0] = ECHO_REQUEST_V4;
    let sum = checksum(&message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

/// An IPv6 echo request with the RFC 4443 checksum (pseudo-header included).
/// The socket layer zeroes the checksum field before sending because the
/// kernel computes it for ICMPv6 sockets (RFC 3542 §3.1).
pub fn build_echo_request_v6(
    src: IpAddr,
    dst: IpAddr,
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut message = header(ident, seq, payload);
    message[0] = ECHO_REQUEST_V6;
    let mut pseudo = Vec::with_capacity(40 + message.len());
    match src {
        IpAddr::V4(v4) => pseudo.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => pseudo.extend_from_slice(&v6.octets()),
    }
    match dst {
        IpAddr::V4(v4) => pseudo.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => pseudo.extend_from_slice(&v6.octets()),
    }
    pseudo.extend_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.push(0);
    pseudo.push(0);
    pseudo.extend_from_slice(&message);
    let sum = checksum(&pseudo);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

/// Zeroes the checksum field of an ICMPv6 message for the kernel to fill.
pub fn v6_wire_zero_checksum(message: &mut [u8]) {
    if message.len() >= 4 {
        message[2..4].copy_from_slice(&[0, 0]);
    }
}

fn header(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(8 + payload.len());
    message.push(0);
    message.push(0);
    message.extend_from_slice(&[0, 0]);
    message.extend_from_slice(&ident.to_be_bytes());
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(payload);
    message
}

/// Echo-reply parse failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    UnexpectedType(u8),
    BadChecksum,
    Mismatched,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "报文过短"),
            Self::UnexpectedType(kind) => write!(f, "非回显应答（类型 {kind}）"),
            Self::BadChecksum => write!(f, "校验和不正确"),
            Self::Mismatched => write!(f, "应答与本请求不匹配"),
        }
    }
}

/// Verifies an IPv4 echo reply: type, code, checksum, identifier, sequence
/// and payload.
pub fn parse_echo_reply_v4(
    bytes: &[u8],
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Result<(), ParseError> {
    if bytes.len() < 8 {
        return Err(ParseError::Truncated);
    }
    if bytes[0] != ECHO_REPLY_V4 {
        return Err(ParseError::UnexpectedType(bytes[0]));
    }
    if bytes[1] != 0 {
        return Err(ParseError::UnexpectedType(bytes[1]));
    }
    let mut full = bytes.to_vec();
    full[2..4].copy_from_slice(&[0, 0]);
    if checksum(&full) != u16::from_be_bytes([bytes[2], bytes[3]]) {
        return Err(ParseError::BadChecksum);
    }
    verify_match(&bytes[4..], ident, seq, payload)
}

/// Verifies an IPv6 echo reply (type, identifier, sequence, payload; the
/// checksum is not re-verified because the kernel validates ICMPv6 datagram
/// sockets before delivery).
pub fn parse_echo_reply_v6(
    bytes: &[u8],
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Result<(), ParseError> {
    if bytes.len() < 8 {
        return Err(ParseError::Truncated);
    }
    if bytes[0] != ECHO_REPLY_V6 {
        return Err(ParseError::UnexpectedType(bytes[0]));
    }
    verify_match(&bytes[4..], ident, seq, payload)
}

fn verify_match(rest: &[u8], ident: u16, seq: u16, payload: &[u8]) -> Result<(), ParseError> {
    if rest.len() < 4 {
        return Err(ParseError::Truncated);
    }
    if u16::from_be_bytes([rest[0], rest[1]]) != ident
        || u16::from_be_bytes([rest[2], rest[3]]) != seq
    {
        return Err(ParseError::Mismatched);
    }
    if &rest[4..] != payload {
        return Err(ParseError::Mismatched);
    }
    Ok(())
}

/// Why one echo failed.
#[derive(Debug)]
pub enum EchoError {
    Timeout,
    Io(io::Error),
    Parse(ParseError),
}

impl std::fmt::Display for EchoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "超时"),
            Self::Io(error) => write!(f, "{}", io_error_text(error)),
            Self::Parse(error) => write!(f, "{error}"),
        }
    }
}

/// Human text for socket errors, including ICMP error deliveries (host
/// unreachable etc., which arrive as recv errors on connected sockets).
pub fn io_error_text(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "端口不可达或被拒绝".into(),
        io::ErrorKind::TimedOut => "传输超时".into(),
        io::ErrorKind::PermissionDenied => "权限不足".into(),
        _ => match error.raw_os_error() {
            Some(113) | Some(65) => "主机不可达".into(),
            Some(114) | Some(51) => "网络不可达".into(),
            Some(64) => "主机已停机".into(),
            _ => format!("{error}"),
        },
    }
}

/// The reason an ICMP socket could not be opened. D13: no raw-socket
/// fallback is attempted, so the message says so and offers alternatives.
pub fn failure_reason(error: &io::Error) -> String {
    let base = format!("无法创建无特权 ICMP 套接字：{error}。");
    let tail = match error.kind() {
        io::ErrorKind::PermissionDenied => {
            "FerrumGate 只使用无特权 ICMP 套接字，不使用原始套接字；Linux 需要 net.ipv4.ping_group_range 覆盖本进程用户（容器内需 NET_RAW），也可以改用端口探测。"
        }
        _ => "FerrumGate 只使用无特权 ICMP 套接字，不使用原始套接字；也可以改用端口探测。",
    };
    format!("{base}{tail}")
}

struct IcmpSocket {
    fd: AsyncFd<Socket>,
    v6: bool,
}

impl IcmpSocket {
    /// Opens an unprivileged datagram ICMP socket connected to `peer` and
    /// returns it together with the assigned identifier (the local port).
    fn open(peer: SocketAddr) -> io::Result<(Self, u16)> {
        let (domain, bind, v6) = match peer {
            SocketAddr::V4(_) => (
                Domain::IPV4,
                SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                false,
            ),
            SocketAddr::V6(_) => (
                Domain::IPV6,
                SockAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                true,
            ),
        };
        let protocol = if v6 {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(protocol))?;
        socket.bind(&bind)?;
        let ident = socket
            .local_addr()?
            .as_socket()
            .map(|addr| addr.port())
            .unwrap_or(0);
        socket.connect(&SockAddr::from(peer))?;
        socket.set_nonblocking(true)?;
        // `AsyncFd::register` is unsafe (I/O-safety rework in tokio 1.54) and
        // the crate forbids unsafe code; `new` is sound here because the
        // `socket2::Socket` owns and closes the descriptor, which never
        // changes over the socket's lifetime.
        #[allow(deprecated)]
        let fd = AsyncFd::new(socket)?;
        Ok((Self { fd, v6 }, ident))
    }

    async fn send(&self, bytes: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(bytes)) {
                Ok(result) => {
                    result.map(|_| ())?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }
}

/// Strips an IP header from a received datagram. Linux dgram ICMP sockets
/// deliver the bare ICMP message; macOS delivers the IP datagram with the
/// header prepended (first nibble = IP version). An ICMP echo reply never
/// starts with version 4 or 6 nibbles, so the check is unambiguous.
pub fn strip_ip_header(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 20 {
        match bytes[0] >> 4 {
            4 => {
                let header = usize::from(bytes[0] & 0x0f) * 4;
                if (20..=bytes.len()).contains(&header) {
                    return &bytes[header..];
                }
            }
            6 if bytes.len() > 40 => return &bytes[40..],
            _ => {}
        }
    }
    bytes
}

/// One echo round trip to an IP: opens a fresh unprivileged socket, sends
/// the request and waits for the matching reply. `Ok` carries the RTT.
pub async fn ping_once(ip: IpAddr, timeout: Duration) -> Result<Duration, EchoError> {
    let peer = SocketAddr::new(ip, 0);
    let (socket, ident) = IcmpSocket::open(peer).map_err(EchoError::Io)?;
    let seq = 0u16;
    let data = payload(seq);
    let started = Instant::now();
    let message = if peer.is_ipv6() {
        let src = if socket.v6 {
            IpAddr::from(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::from(Ipv4Addr::UNSPECIFIED)
        };
        let mut wire = build_echo_request_v6(src, ip, ident, seq, &data);
        v6_wire_zero_checksum(&mut wire);
        wire
    } else {
        build_echo_request_v4(ident, seq, &data)
    };
    socket.send(&message).await.map_err(EchoError::Io)?;
    let wait_reply = async {
        let mut buf = [0u8; RECV_BUF_LEN];
        loop {
            let mut guard = socket.fd.readable().await.map_err(EchoError::Io)?;
            // socket2 implements `Read for &Socket`, the safe path over its
            // `MaybeUninit` recv internals.
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(result) => {
                    let count = result.map_err(EchoError::Io)?;
                    let message = strip_ip_header(&buf[..count]);
                    let parse = if socket.v6 {
                        parse_echo_reply_v6(message, ident, seq, &data)
                    } else {
                        parse_echo_reply_v4(message, ident, seq, &data)
                    };
                    match parse {
                        Ok(()) => return Ok(started.elapsed()),
                        Err(ParseError::Mismatched) => continue,
                        Err(error) => return Err(EchoError::Parse(error)),
                    }
                }
                Err(_would_block) => continue,
            }
        }
    };
    tokio::time::timeout(timeout, wait_reply)
        .await
        .map_err(|_| EchoError::Timeout)?
}

/// Runs the ping tool job: resolves the target, checks the deny list, then
/// echoes `count` times and reports per-echo RTT plus the summary.
pub fn run(params: &PingParams, handle: JobHandle, deny: &[validate::DenyEntry]) -> JobFut {
    let params = params.clone();
    let deny = deny.to_vec();
    Box::pin(async move {
        let count = params
            .count
            .unwrap_or(limits::PING_COUNT_DEFAULT)
            .clamp(1, limits::PING_COUNT_MAX);
        let timeout = duration_from_secs_f64(
            params.timeout.unwrap_or(limits::PING_TIMEOUT.as_secs_f64()),
            0.1,
            30.0,
        );
        let interval = duration_from_secs_f64(
            params
                .interval
                .unwrap_or(limits::PING_INTERVAL.as_secs_f64()),
            0.05,
            30.0,
        );
        let target = params.target.trim().to_owned();
        handle.line(format!(
            "PING {target}：{count} 次，超时 {:.1} 秒，间隔 {:.1} 秒",
            timeout.as_secs_f64(),
            interval.as_secs_f64()
        ));
        let ip = crate::dns_lookup::resolve_target(&target)
            .await
            .map_err(JobError::Message)?;
        if let Some(reason) = validate::deny_reason(&target, &[ip], &deny) {
            return Err(JobError::Message(reason));
        }
        handle.line(format!("目标 {ip}（{}）", validate::classify(ip).label()));
        let mut rtts: Vec<Duration> = Vec::with_capacity(count as usize);
        let mut sent = 0u32;
        let mut first_failure: Option<String> = None;
        for index in 0..count {
            if index > 0 {
                tokio::select! {
                    biased;
                    _ = handle.token().cancelled() => break,
                    _ = tokio::time::sleep(interval) => {}
                }
            }
            sent += 1;
            match ping_once(ip, timeout).await {
                Ok(rtt) => {
                    handle.line(format!(
                        "第 {} 次：{:.1} ms",
                        index + 1,
                        rtt.as_secs_f64() * 1000.0
                    ));
                    rtts.push(rtt);
                }
                Err(error) => {
                    handle.line(format!("第 {} 次：{}", index + 1, error));
                    if first_failure.is_none() {
                        first_failure = Some(error.to_string());
                    }
                }
            }
        }
        let received = rtts.len();
        let loss = if sent == 0 {
            0.0
        } else {
            100.0 * (sent - received as u32) as f64 / sent as f64
        };
        handle.line(format!(
            "共发送 {sent} 次，收到 {received} 次，丢包率 {loss:.0}%"
        ));
        if received == 0 {
            let mut message = "目标无任何响应".to_owned();
            if let Some(first) = first_failure {
                message.push_str(&format!("（{first}）"));
            }
            message.push_str("；如需确认端口可达性，可改用端口探测");
            return Err(JobError::Message(message));
        }
        let min = rtts
            .iter()
            .map(|rtt| rtt.as_secs_f64())
            .fold(f64::MAX, f64::min)
            * 1000.0;
        let max = rtts.iter().map(|rtt| rtt.as_secs_f64()).fold(0.0, f64::max) * 1000.0;
        let avg = rtts.iter().map(|rtt| rtt.as_secs_f64()).sum::<f64>() / received as f64 * 1000.0;
        handle.line(format!(
            "最小 {min:.1} ms，平均 {avg:.1} ms，最大 {max:.1} ms"
        ));
        Ok(())
    })
}

/// Clamped duration from a seconds value.
pub(crate) fn duration_from_secs_f64(seconds: f64, min: f64, max: f64) -> Duration {
    let value = if seconds.is_nan() || seconds < min {
        min
    } else if seconds > max {
        max
    } else {
        seconds
    };
    Duration::from_secs_f64(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_echo_request_and_reply_parse() {
        let data = payload(7);
        assert_eq!(data.len(), PAYLOAD_LEN);
        let request = build_echo_request_v4(0x1234, 7, &data);
        assert_eq!(request[0], ECHO_REQUEST_V4);
        assert_eq!(request[1], 0);
        assert_eq!(&request[4..6], &0x1234u16.to_be_bytes());
        assert_eq!(&request[6..8], &7u16.to_be_bytes());
        assert_eq!(&request[8..], &data[..]);
        // The checksum validates the message.
        let mut copy = request.clone();
        copy[2..4].copy_from_slice(&[0, 0]);
        assert_eq!(
            checksum(&copy),
            u16::from_be_bytes([request[2], request[3]])
        );
        // A reply with the same fields parses; wrong seq or type fails.
        let mut reply = request.clone();
        reply[0] = ECHO_REPLY_V4;
        let mut raw = reply.clone();
        raw[2..4].copy_from_slice(&[0, 0]);
        let sum = checksum(&raw);
        reply[2..4].copy_from_slice(&sum.to_be_bytes());
        assert!(parse_echo_reply_v4(&reply, 0x1234, 7, &data).is_ok());
        assert_eq!(
            parse_echo_reply_v4(&reply, 0x1234, 8, &data),
            Err(ParseError::Mismatched)
        );
        assert_eq!(
            parse_echo_reply_v4(&reply, 0x4321, 7, &data),
            Err(ParseError::Mismatched)
        );
        assert_eq!(
            parse_echo_reply_v4(&reply[..4], 0x1234, 7, &data),
            Err(ParseError::Truncated)
        );
        let mut wrong_type = reply.clone();
        wrong_type[0] = 3;
        assert_eq!(
            parse_echo_reply_v4(&wrong_type, 0x1234, 7, &data),
            Err(ParseError::UnexpectedType(3))
        );
        let mut tampered = reply.clone();
        tampered[8] ^= 0xff;
        assert_eq!(
            parse_echo_reply_v4(&tampered, 0x1234, 7, &data),
            Err(ParseError::BadChecksum)
        );
    }

    #[test]
    fn icmp_v6_request_uses_pseudo_header_checksum() {
        let data = payload(1);
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let message = build_echo_request_v6(IpAddr::V6(src), IpAddr::V6(dst), 0x5678, 1, &data);
        assert_eq!(message[0], ECHO_REQUEST_V6);
        assert_eq!(&message[4..6], &0x5678u16.to_be_bytes());
        // Recomputing over the pseudo-header with a zeroed field reproduces it.
        let mut check = message.clone();
        check[2..4].copy_from_slice(&[0, 0]);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&(check.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58, 0, 0]);
        pseudo.extend_from_slice(&check);
        assert_eq!(
            checksum(&pseudo),
            u16::from_be_bytes([message[2], message[3]])
        );
        v6_wire_zero_checksum(&mut check);
        assert_eq!(&check[2..4], &[0, 0]);
    }

    #[test]
    fn icmp_checksum_handles_odd_lengths_and_known_vectors() {
        // RFC 1071 example: 00 01 f2 03 f4 f5 f6 f7 — the folded sum is
        // ddf2 and the checksum field carries its complement 220d.
        let bytes = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&bytes), 0x220d);
        assert_eq!(checksum(&[0xff]), 0x00ff);
        assert_eq!(checksum(&[]), 0xffff);
    }

    #[test]
    fn ping_without_privilege_reports_reason() {
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        let message = failure_reason(&denied);
        assert!(message.contains("无特权"), "{message}");
        assert!(message.contains("不使用原始套接字"), "{message}");
        assert!(message.contains("ping_group_range"), "{message}");
        assert!(message.contains("端口探测"), "{message}");
        let other = failure_reason(&io::Error::other("socket unavailable"));
        assert!(other.contains("不使用原始套接字"), "{other}");
        assert!(other.contains("端口探测"), "{other}");
    }

    #[test]
    fn ping_duration_clamped_to_range() {
        assert_eq!(
            duration_from_secs_f64(0.7, 0.05, 30.0),
            Duration::from_millis(700)
        );
        assert_eq!(
            duration_from_secs_f64(0.0, 0.05, 30.0),
            Duration::from_millis(50)
        );
        assert_eq!(
            duration_from_secs_f64(99.0, 0.05, 30.0),
            Duration::from_secs_f64(30.0)
        );
        assert_eq!(
            duration_from_secs_f64(f64::NAN, 0.05, 30.0),
            Duration::from_millis(50)
        );
    }
}
