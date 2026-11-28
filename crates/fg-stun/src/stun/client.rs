//! STUN client (WP-42 §3.3): binding transactions with one retransmit per
//! window, servers tried in order (first success wins; a full round of
//! failures fails the round), plus a concurrent consistency probe that
//! queries several servers from the same local socket — matching mapped
//! endpoints indicate an endpoint-independent (full-cone style) mapping,
//! diverging ports or addresses indicate port-restricted / symmetric NAT.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::message::{self, StunError, TxId};
use crate::model::limits;

/// Client-side failures: codec errors wrapped, plus transport level ones.
#[derive(Debug)]
pub enum ClientError {
    /// STUN codec failure with its reason.
    Stun(StunError),
    /// Socket / stream failure.
    Io(std::io::Error),
    /// The transaction window elapsed without a matching response.
    Timeout,
    /// The owning rule stopped (shutdown or config change).
    Cancelled,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stun(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Timeout => write!(f, "等待响应超时"),
            Self::Cancelled => write!(f, "通道已停止"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<StunError> for ClientError {
    fn from(error: StunError) -> Self {
        Self::Stun(error)
    }
}

/// One server's successful binding result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryOutcome {
    /// The server that answered.
    pub server: SocketAddr,
    /// The mapped endpoint it reported.
    pub mapped: SocketAddr,
}

/// Resolves `host:port` entries to socket addresses, skipping entries that
/// cannot resolve (logged by the caller).
pub async fn resolve_servers(entries: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for entry in entries {
        if let Ok(mut addrs) = tokio::net::lookup_host(entry.as_str()).await
            && let Some(addr) = addrs.next()
        {
            out.push(addr);
        }
    }
    out
}

/// One UDP binding transaction on an existing socket: sends the request,
/// retransmits once at half the window and answers with the mapped
/// endpoint from the matching transaction. Non-STUN datagrams (business
/// traffic sharing the channel socket) are skipped.
pub async fn binding_udp_once(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<SocketAddr, ClientError> {
    let tx = TxId::random();
    let request = message::binding_request(tx);
    let start = tokio::time::Instant::now();
    let deadline = start + timeout;
    let retransmit_at = start + timeout.mul_f64(0.5);
    let mut buf = vec![0u8; message::MAX_MESSAGE_SIZE];
    for attempt in 1..=limits::TRANSMIT_ATTEMPTS.max(1) {
        socket
            .send_to(&request, server)
            .await
            .map_err(ClientError::Io)?;
        let phase_end = if attempt < limits::TRANSMIT_ATTEMPTS.max(1) {
            retransmit_at.min(deadline)
        } else {
            deadline
        };
        loop {
            let now = tokio::time::Instant::now();
            if now >= phase_end {
                break;
            }
            let wait = phase_end - now;
            let received = tokio::select! {
                biased;
                _ = token.cancelled() => return Err(ClientError::Cancelled),
                result = tokio::time::timeout(wait, socket.recv_from(&mut buf)) => match result {
                    Err(_elapsed) => None,
                    Ok(Err(error)) => return Err(ClientError::Io(error)),
                    Ok(Ok((size, _from))) => Some(size),
                },
            };
            if let Some(size) = received {
                let data = &buf[..size];
                if message::is_message(data) && message::message_tx_id(data) == Some(tx) {
                    // A malformed or non-response datagram carrying our id
                    // (e.g. a hairpin echo of the request) does not abort
                    // the transaction; the window bounds the wait.
                    if let Ok(mapped) = message::parse_binding_response(data, tx) {
                        return Ok(mapped);
                    }
                }
            }
        }
    }
    Err(ClientError::Timeout)
}

/// One binding transaction over an established TCP stream (messages are
/// self-delimited by the header length field).
pub async fn binding_tcp_once(
    stream: &mut TcpStream,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<SocketAddr, ClientError> {
    let tx = TxId::random();
    let request = message::binding_request(tx);
    let start = tokio::time::Instant::now();
    let deadline = start + timeout;
    tokio::select! {
        biased;
        _ = token.cancelled() => return Err(ClientError::Cancelled),
        result = tokio::time::timeout(timeout, stream.write_all(&request)) => {
            result.map_err(|_| ClientError::Timeout)?.map_err(ClientError::Io)?;
        }
    }
    let mut buf: Vec<u8> = Vec::with_capacity(message::HEADER_LEN);
    let mut chunk = [0u8; 512];
    loop {
        match message::frame_len(&buf)? {
            Some(total) if buf.len() >= total => break,
            _ => {}
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(ClientError::Timeout);
        }
        let wait = deadline - now;
        let read = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(ClientError::Cancelled),
            result = tokio::time::timeout(wait, stream.read(&mut chunk)) => match result {
                Err(_elapsed) => return Err(ClientError::Timeout),
                Ok(Err(error)) => return Err(ClientError::Io(error)),
                Ok(Ok(0)) => return Err(ClientError::Stun(StunError::Truncated)),
                Ok(Ok(read)) => read,
            },
        };
        buf.extend_from_slice(&chunk[..read]);
    }
    message::parse_binding_response(&buf, tx).map_err(ClientError::Stun)
}

/// Tries the servers in order over UDP from one socket bound to `bind`;
/// the first success wins, all failures fail the round.
pub async fn query_servers_udp(
    bind: SocketAddr,
    servers: &[SocketAddr],
    timeout: Duration,
    token: &CancellationToken,
) -> Result<QueryOutcome, Vec<ClientError>> {
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => return Err(vec![ClientError::Io(error)]),
    };
    query_servers_udp_on(&socket, servers, timeout, token).await
}

/// Same in-order round on an existing socket (the channel keeps its
/// mapping socket open between heartbeats).
pub async fn query_servers_udp_on(
    socket: &UdpSocket,
    servers: &[SocketAddr],
    timeout: Duration,
    token: &CancellationToken,
) -> Result<QueryOutcome, Vec<ClientError>> {
    let mut errors = Vec::new();
    for server in servers {
        match binding_udp_once(socket, *server, timeout, token).await {
            Ok(mapped) => {
                return Ok(QueryOutcome {
                    server: *server,
                    mapped,
                });
            }
            Err(ClientError::Cancelled) => return Err(vec![ClientError::Cancelled]),
            Err(error) => errors.push(error),
        }
    }
    Err(errors)
}

/// Connects to a TCP server under the transaction window and the token.
pub async fn connect_tcp(
    server: SocketAddr,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<TcpStream, ClientError> {
    let connect = TcpStream::connect(server);
    tokio::select! {
        biased;
        _ = token.cancelled() => Err(ClientError::Cancelled),
        result = tokio::time::timeout(timeout, connect) => match result {
            Err(_elapsed) => Err(ClientError::Timeout),
            Ok(Err(error)) => Err(ClientError::Io(error)),
            Ok(Ok(stream)) => Ok(stream),
        },
    }
}

/// Tries the servers in order over TCP (one connection per attempt).
pub async fn query_servers_tcp(
    servers: &[SocketAddr],
    timeout: Duration,
    token: &CancellationToken,
) -> Result<QueryOutcome, Vec<ClientError>> {
    let mut errors = Vec::new();
    for server in servers {
        let mut stream = match connect_tcp(*server, timeout, token).await {
            Ok(stream) => stream,
            Err(ClientError::Cancelled) => return Err(vec![ClientError::Cancelled]),
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        match binding_tcp_once(&mut stream, timeout, token).await {
            Ok(mapped) => {
                return Ok(QueryOutcome {
                    server: *server,
                    mapped,
                });
            }
            Err(ClientError::Cancelled) => return Err(vec![ClientError::Cancelled]),
            Err(error) => errors.push(error),
        }
    }
    Err(errors)
}

/// Reachability probe for UDP channels: a binding transaction aimed at the
/// channel's own public endpoint. Success confirms the mapped port
/// forwards from the outside (hairpin NAT permitting).
pub async fn probe_udp(
    socket: &UdpSocket,
    target: SocketAddr,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<SocketAddr, ClientError> {
    binding_udp_once(socket, target, timeout, token).await
}

/// Verdict of the concurrent consistency probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsistencyVerdict {
    /// Fewer than two servers answered; nothing to compare.
    Unknown,
    /// Every server reported the same mapped endpoint: the mapping does
    /// not depend on the peer (full-cone style).
    Consistent,
    /// Same public IP but different ports per server: port-restricted or
    /// symmetric mapping.
    PortDivergent,
    /// Different public IPs per server: multiple egress paths.
    IpDivergent,
}

/// Per-server results of the consistency probe plus the verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyReport {
    /// Query target paired with the endpoint it reported (`None` when the
    /// transaction failed).
    pub pairs: Vec<(SocketAddr, Option<SocketAddr>)>,
    pub verdict: ConsistencyVerdict,
}

/// Pure verdict computation over the probe results (unit-tested).
pub fn judge_consistency(results: &[Option<SocketAddr>]) -> ConsistencyVerdict {
    let answered: Vec<SocketAddr> = results.iter().flatten().copied().collect();
    if answered.len() < 2 {
        return ConsistencyVerdict::Unknown;
    }
    let first = answered[0];
    if answered.iter().all(|addr| *addr == first) {
        return ConsistencyVerdict::Consistent;
    }
    let ip = first.ip();
    if answered.iter().all(|addr| addr.ip() == ip) {
        return ConsistencyVerdict::PortDivergent;
    }
    ConsistencyVerdict::IpDivergent
}

/// Queries every server concurrently from one local socket (so all
/// answers describe the same NAT mapping tuple) and judges whether the
/// mapping is peer-independent. No retransmission here: the probe runs one
/// round with the given timeout.
pub async fn check_consistency(
    socket: &UdpSocket,
    servers: &[SocketAddr],
    timeout: Duration,
    token: &CancellationToken,
) -> ConsistencyReport {
    let transactions: Vec<(SocketAddr, TxId)> = servers
        .iter()
        .map(|server| (*server, TxId::random()))
        .collect();
    let deadline = tokio::time::Instant::now() + timeout;
    for (server, tx) in &transactions {
        let _ = socket
            .send_to(&message::binding_request(*tx), *server)
            .await;
    }
    let mut answers: Vec<Option<SocketAddr>> = vec![None; transactions.len()];
    let mut pending: HashSet<usize> = (0..transactions.len()).collect();
    while !pending.is_empty() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let wait = deadline - now;
        let mut buf = vec![0u8; message::MAX_MESSAGE_SIZE];
        let received = tokio::select! {
            biased;
            _ = token.cancelled() => break,
            result = tokio::time::timeout(wait, socket.recv_from(&mut buf)) => match result {
                Err(_elapsed) => break,
                Ok(Err(_error)) => break,
                Ok(Ok((size, _from))) => Some(size),
            },
        };
        let Some(size) = received else { break };
        let data = &buf[..size];
        if !message::is_message(data) {
            continue;
        }
        let Some(tx) = message::message_tx_id(data) else {
            continue;
        };
        let Some(index) = transactions.iter().position(|(_server, id)| *id == tx) else {
            continue;
        };
        if !pending.contains(&index) {
            continue;
        }
        if let Ok(mapped) = message::parse_binding_response(data, tx) {
            answers[index] = Some(mapped);
        }
        pending.remove(&index);
    }
    let pairs = transactions
        .iter()
        .zip(&answers)
        .map(|((server, _), answer)| (*server, *answer))
        .collect();
    let verdict = judge_consistency(&answers);
    ConsistencyReport { pairs, verdict }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn mapped(port: u16) -> Option<SocketAddr> {
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port,
        ))
    }

    #[test]
    fn consistency_verdict_judges_divergence() {
        assert_eq!(judge_consistency(&[]), ConsistencyVerdict::Unknown);
        assert_eq!(judge_consistency(&[mapped(1)]), ConsistencyVerdict::Unknown);
        assert_eq!(
            judge_consistency(&[None, mapped(1)]),
            ConsistencyVerdict::Unknown
        );
        assert_eq!(
            judge_consistency(&[mapped(1), mapped(1), mapped(1)]),
            ConsistencyVerdict::Consistent
        );
        assert_eq!(
            judge_consistency(&[mapped(1), mapped(2)]),
            ConsistencyVerdict::PortDivergent
        );
        let other_ip = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
            1,
        ));
        assert_eq!(
            judge_consistency(&[mapped(1), other_ip]),
            ConsistencyVerdict::IpDivergent
        );
    }
}
