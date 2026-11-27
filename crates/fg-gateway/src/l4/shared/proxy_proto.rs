//! PROXY protocol v1/v2 encoding (WP-36); extracted from the TCP
//! forwarder's header writer. Parsing of inbound headers arrives with the
//! entries that accept them.
#![allow(dead_code)]

use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use serde::Deserialize;
use tokio::{io::AsyncWriteExt, net::TcpStream};

/// Which PROXY protocol version to emit towards an upstream. Mirrors the
/// forwarder's private configuration enum so a later step can point the
/// config at this shared definition.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    V1,
    V2,
}

/// Writes the PROXY protocol header describing `source` -> `destination` to
/// the freshly dialed `upstream`, before any payload is forwarded.
pub async fn write_header(
    protocol: ProxyProtocol,
    upstream: &mut TcpStream,
    source: SocketAddr,
    destination: SocketAddr,
) -> io::Result<()> {
    let source_ip = source.ip().to_canonical();
    let destination_ip = destination.ip().to_canonical();
    if source_ip.is_ipv4() != destination_ip.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inconsistent TCP address families",
        ));
    }
    match protocol {
        ProxyProtocol::V1 => {
            let family = if source_ip.is_ipv4() { "TCP4" } else { "TCP6" };
            let header = format!(
                "PROXY {family} {source_ip} {destination_ip} {} {}\r\n",
                source.port(),
                destination.port()
            );
            upstream.write_all(header.as_bytes()).await
        }
        ProxyProtocol::V2 => {
            let mut header = [0u8; 52];
            header[..12].copy_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
            header[12] = 0x21; // Version 2, PROXY command.
            let ports_at = match (source_ip, destination_ip) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => {
                    header[13] = 0x11; // Address family IPv4, PROXY command.
                    header[15] = 12; // 2 x (4 address + 2 port).
                    header[16..20].copy_from_slice(&source.octets());
                    header[20..24].copy_from_slice(&destination.octets());
                    24
                }
                (IpAddr::V6(source), IpAddr::V6(destination)) => {
                    header[13] = 0x21; // Address family IPv6, PROXY command.
                    header[15] = 36; // 2 x (16 address + 2 port).
                    header[16..32].copy_from_slice(&source.octets());
                    header[32..48].copy_from_slice(&destination.octets());
                    48
                }
                _ => unreachable!("verified matching address families"),
            };
            header[ports_at..ports_at + 2].copy_from_slice(&source.port().to_be_bytes());
            header[ports_at + 2..ports_at + 4].copy_from_slice(&destination.port().to_be_bytes());
            upstream.write_all(&header[..ports_at + 4]).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::{io::AsyncReadExt as _, net::TcpListener};

    use super::*;

    /// Loopback pair: the writer end and the accept side that observes the
    /// emitted headers.
    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        (upstream, accepted)
    }

    /// Reads one CRLF-terminated line byte by byte.
    async fn read_line(stream: &mut TcpStream) -> String {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = stream.read(&mut byte).await.unwrap();
            assert_eq!(read, 1, "PROXY v1 line ended without a newline");
            line.push(byte[0]);
            if byte[0] == b'\n' {
                return String::from_utf8(line).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn proxy_proto_v1_v2_roundtrip() {
        let (mut upstream, mut accepted) = connected_pair().await;
        let source_ip = Ipv4Addr::new(198, 51, 100, 7);
        let destination_ip = Ipv4Addr::new(203, 0, 113, 9);
        let source = SocketAddr::new(source_ip.into(), 40001);
        let destination = SocketAddr::new(destination_ip.into(), 443);

        // v1: text line, parsed back into its fields.
        write_header(ProxyProtocol::V1, &mut upstream, source, destination)
            .await
            .unwrap();
        let line = read_line(&mut accepted).await;
        assert_eq!(line, "PROXY TCP4 198.51.100.7 203.0.113.9 40001 443\r\n");
        let fields: Vec<&str> = line.trim_end().split(' ').collect();
        assert_eq!(
            fields,
            [
                "PROXY",
                "TCP4",
                "198.51.100.7",
                "203.0.113.9",
                "40001",
                "443"
            ]
        );

        // v2, IPv4 pair: 16-byte header followed by 12 address bytes.
        write_header(ProxyProtocol::V2, &mut upstream, source, destination)
            .await
            .unwrap();
        let mut v4 = [0u8; 28];
        accepted.read_exact(&mut v4).await.unwrap();
        assert_eq!(&v4[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(v4[12], 0x21, "version 2, PROXY command");
        assert_eq!(v4[13], 0x11, "address family IPv4, PROXY command");
        assert_eq!(v4[14], 0, "reserved flags");
        assert_eq!(v4[15], 12, "address + port length");
        assert_eq!(&v4[16..20], &source_ip.octets());
        assert_eq!(&v4[20..24], &destination_ip.octets());
        assert_eq!(&v4[24..26], &40001u16.to_be_bytes());
        assert_eq!(&v4[26..28], &443u16.to_be_bytes());

        // v2, IPv6 pair: 16-byte header followed by 36 address bytes.
        let source6_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination6_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let source6 = SocketAddr::new(source6_ip.into(), 40001);
        let destination6 = SocketAddr::new(destination6_ip.into(), 443);
        write_header(ProxyProtocol::V2, &mut upstream, source6, destination6)
            .await
            .unwrap();
        let mut v6 = [0u8; 52];
        accepted.read_exact(&mut v6).await.unwrap();
        assert_eq!(&v6[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(v6[12], 0x21, "version 2, PROXY command");
        assert_eq!(v6[13], 0x21, "address family IPv6, PROXY command");
        assert_eq!(v6[15], 36, "address + port length");
        assert_eq!(&v6[16..32], &source6_ip.octets());
        assert_eq!(&v6[32..48], &destination6_ip.octets());
        assert_eq!(&v6[48..50], &40001u16.to_be_bytes());
        assert_eq!(&v6[50..52], &443u16.to_be_bytes());
    }
}
