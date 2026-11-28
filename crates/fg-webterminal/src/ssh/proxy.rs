//! Outbound TCP proxy tunneling (WP-61 §3.3): SOCKS5 (RFC 1928 + RFC 1929)
//! and HTTP CONNECT (RFC 9110 §9.3.6, optional Basic `Proxy-Authorization`).
//! Shared by both SSH and Telnet connections.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::model::{Proxy, ProxyKind};

/// Connects a TCP stream to `(host, port)`, optionally tunneling through
/// `proxy`, bounded by `timeout`.
pub async fn connect_tcp(
    host: &str,
    port: u16,
    proxy: Option<&Proxy>,
    timeout: Duration,
) -> Result<TcpStream> {
    tokio::time::timeout(timeout, connect_tcp_inner(host, port, proxy))
        .await
        .map_err(|_| anyhow!("连接超时（{} 秒）", timeout.as_secs()))?
}

async fn connect_tcp_inner(host: &str, port: u16, proxy: Option<&Proxy>) -> Result<TcpStream> {
    match proxy {
        None => TcpStream::connect((host, port))
            .await
            .with_context(|| format!("TCP 连接 {host}:{port} 失败")),
        Some(proxy) => match proxy.kind {
            ProxyKind::Socks5 => connect_socks5(proxy, host, port).await,
            ProxyKind::Http => connect_http(proxy, host, port).await,
        },
    }
}

/// Performs a SOCKS5 handshake (RFC 1928) with optional username/password
/// authentication (RFC 1929) and requests a CONNECT tunnel to `(host, port)`.
async fn connect_socks5(proxy: &Proxy, host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .with_context(|| format!("连接 SOCKS5 代理 {}:{} 失败", proxy.host, proxy.port))?;

    let has_auth = !proxy.username.is_empty() || !proxy.password.is_empty();
    let methods: &[u8] = if has_auth { &[0x00, 0x02] } else { &[0x00] };

    // Greeting: VER=5, NMETHODS, METHODS...
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream
        .write_all(&greeting)
        .await
        .context("SOCKS5 发送握手请求失败")?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .context("SOCKS5 读取握手响应失败")?;
    if resp[0] != 0x05 {
        bail!("SOCKS5 代理协议版本无效: {}", resp[0]);
    }

    match resp[1] {
        0x00 => {}
        0x02 => {
            if !has_auth {
                bail!("SOCKS5 代理要求认证，但未配置用户名或密码");
            }
            let user_bytes = proxy.username.as_bytes();
            let pass_bytes = proxy.password.as_bytes();
            if user_bytes.len() > 255 || pass_bytes.len() > 255 {
                bail!("SOCKS5 代理用户名或密码超过 255 字节");
            }
            let mut auth_req = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
            auth_req.push(0x01); // RFC 1929 subnegotiation version
            auth_req.push(user_bytes.len() as u8);
            auth_req.extend_from_slice(user_bytes);
            auth_req.push(pass_bytes.len() as u8);
            auth_req.extend_from_slice(pass_bytes);
            stream
                .write_all(&auth_req)
                .await
                .context("SOCKS5 发送认证失败")?;

            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .await
                .context("SOCKS5 读取认证响应失败")?;
            if auth_resp[1] != 0x00 {
                bail!("SOCKS5 代理认证被拒绝");
            }
        }
        0xFF => bail!("SOCKS5 代理没有可接受的认证方式"),
        other => bail!("SOCKS5 代理返回未知认证方式: {other}"),
    }

    // CONNECT request: VER=5, CMD=1(CONNECT), RSV=0, ATYP, DST.ADDR, DST.PORT
    let mut req = Vec::with_capacity(64);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let host_bytes = host.as_bytes();
        if host_bytes.len() > 255 {
            bail!("目标主机名超过 SOCKS5 上限（255 字节）");
        }
        req.push(0x03);
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&req)
        .await
        .context("SOCKS5 发送连接请求失败")?;

    // Reply header: VER, REP, RSV, ATYP
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("SOCKS5 读取连接响应失败")?;
    if header[0] != 0x05 {
        bail!("SOCKS5 响应版本无效: {}", header[0]);
    }
    if header[1] != 0x00 {
        bail!("SOCKS5 代理连接目标失败（错误码 {}）", header[1]);
    }
    // Consume BND.ADDR + BND.PORT
    match header[3] {
        0x01 => {
            let mut buf = [0u8; 4 + 2];
            stream.read_exact(&mut buf).await?;
            let _ = Ipv4Addr::from([buf[0], buf[1], buf[2], buf[3]]);
        }
        0x04 => {
            let mut buf = [0u8; 16 + 2];
            stream.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let _ = Ipv6Addr::from(octets);
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut buf).await?;
        }
        other => bail!("SOCKS5 响应地址类型无效: {other}"),
    }

    Ok(stream)
}

/// Performs an HTTP `CONNECT host:port HTTP/1.1` tunnel handshake with optional
/// Basic `Proxy-Authorization`.
async fn connect_http(proxy: &Proxy, host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .with_context(|| format!("连接 HTTP 代理 {}:{} 失败", proxy.host, proxy.port))?;

    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !proxy.username.is_empty() || !proxy.password.is_empty() {
        let cred = format!("{}:{}", proxy.username, proxy.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(cred.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .context("HTTP 代理发送 CONNECT 请求失败")?;

    // Read byte-by-byte until "\r\n\r\n" so we never over-read bytes belonging
    // to the tunneled protocol (SSH banner or Telnet greeting).
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while response.len() < MAX_HEADER_BYTES {
        let n = stream
            .read(&mut byte)
            .await
            .context("HTTP 代理读取响应失败")?;
        if n == 0 {
            bail!("HTTP 代理在响应完成前关闭连接");
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        bail!("HTTP 代理响应头过大或格式无效");
    }

    let text = std::str::from_utf8(&response).context("HTTP 代理响应不是有效 UTF-8")?;
    let status_line = text.lines().next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().unwrap_or_default();
    let status_code: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| anyhow!("HTTP 代理状态行无效: {status_line}"))?;

    if !(200..300).contains(&status_code) {
        bail!("HTTP 代理拒绝 CONNECT：{status_line}");
    }

    Ok(stream)
}
