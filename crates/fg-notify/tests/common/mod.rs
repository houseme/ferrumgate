//! Shared test fixtures for the fg-notify integration tests: fake HTTP
//! servers, a fake HTTP CONNECT proxy, a fake SOCKS5 proxy and a fake SMTP
//! server (plain or STARTTLS with a self-signed certificate). Everything
//! runs on loopback; no test ever dials out. Each integration test binary
//! compiles this module separately, so not every fixture is used by every
//! binary.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

/// A fake HTTP/1.1 server that records every raw request and answers with
/// a canned response.
pub struct FakeHttp {
    pub base: String,
    pub requests: Arc<Mutex<Vec<String>>>,
    pub task: JoinHandle<()>,
}

impl FakeHttp {
    /// Records requests and answers `status`/`body` for every one.
    pub async fn start(status: &'static str, body: &'static str) -> Self {
        Self::start_with(move |_| {
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes()
        })
        .await
    }

    /// Records requests; the responder builds the raw response bytes from
    /// the raw request.
    pub async fn start_with(responder: impl Fn(String) -> Vec<u8> + Send + 'static) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let slot = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let request = match read_request(&mut stream).await {
                    Some(request) => request,
                    None => break,
                };
                slot.lock().expect("requests").push(request.clone());
                let response = responder(request);
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        });
        Self {
            base: format!("http://{addr}"),
            requests,
            task,
        }
    }

    /// The recorded requests.
    pub fn captured(&self) -> Vec<String> {
        self.requests.lock().expect("requests").clone()
    }

    /// The single recorded request (panics otherwise).
    pub fn one(&self) -> String {
        let requests = self.captured();
        assert_eq!(
            requests.len(),
            1,
            "exactly one request expected: {requests:?}"
        );
        requests[0].clone()
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

/// Reads one HTTP request (head plus content-length body) from the
/// stream.
async fn read_request(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(at) = find_head_end(&buffer) {
            let length = content_length(&buffer[..at]);
            if buffer.len() >= at + 4 + length {
                break;
            }
        }
        let read = stream.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    if buffer.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buffer).to_string())
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    text.lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

/// A rendered message for channel contract tests.
pub fn message(title: &str, body: &str) -> fg_notify::Message {
    fg_notify::Message {
        title: title.to_owned(),
        body: body.to_owned(),
        kind: "auth.failed".to_owned(),
        level: "warn".to_owned(),
        time: "2026-01-02T03:04:05Z".to_owned(),
        server: String::new(),
        vars: std::collections::BTreeMap::from([("sourceAddr".to_owned(), "10.0.0.9".to_owned())]),
    }
}

/// Builds a channel from its kind name and a config JSON object.
pub fn channel(kind: &str, config: serde_json::Value) -> fg_notify::Channel {
    let mut channel = fg_notify::Channel {
        kind: fg_notify::ChannelKind::parse(kind).expect("kind"),
        ..fg_notify::Channel::default()
    };
    channel.key = format!("ch{kind}0000001");
    channel.name = kind.to_owned();
    channel.enable = true;
    let config: fg_notify::ChannelConfig = serde_json::from_value(config).expect("channel config");
    channel.config = config;
    channel
}

/// A fresh cancel token (never fired).
pub fn never_cancelled() -> CancellationToken {
    CancellationToken::new()
}

/// A line-oriented SMTP server stream: plain or TLS after STARTTLS.
enum SmtpStream {
    Plain(Box<tokio::net::TcpStream>),
    Tls(Box<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>),
}

impl SmtpStream {
    async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt as _;
        match self {
            SmtpStream::Plain(stream) => stream.read(buffer).await,
            SmtpStream::Tls(stream) => stream.read(buffer).await,
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        match self {
            SmtpStream::Plain(stream) => stream.write_all(bytes).await,
            SmtpStream::Tls(stream) => stream.write_all(bytes).await,
        }
    }

    /// Consumes the plain session and returns the TLS-wrapped one.
    async fn upgrade(self, certified: rcgen::CertifiedKey<rcgen::KeyPair>) -> Option<Self> {
        let stream = match self {
            SmtpStream::Plain(stream) => *stream,
            SmtpStream::Tls(_) => return None,
        };
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        acceptor
            .accept(stream)
            .await
            .ok()
            .map(|tls| SmtpStream::Tls(Box::new(tls)))
    }
}

/// The SMTP conversation the fake server speaks; returns the captured
/// command lines (EHLO, STARTTLS, AUTH, MAIL FROM, RCPT TO and the DATA
/// payload lines).
pub async fn fake_smtp(starttls: bool) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let slot = Arc::clone(&captured);
    let certified = if starttls {
        Some(
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .expect("self-signed cert"),
        )
    } else {
        None
    };
    tokio::spawn(async move {
        let Some((stream, _)) = listener.accept().await.ok() else {
            return;
        };
        let mut session = SmtpStream::Plain(Box::new(stream));
        let _ = session.write_all(b"220 test ESMTP ready\r\n").await;
        let mut upgrade = certified;
        let mut line = Vec::new();
        let mut in_data = false;
        loop {
            let mut chunk = [0u8; 1024];
            let read = match session.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            line.extend_from_slice(&chunk[..read]);
            while let Some(at) = line.iter().position(|byte| *byte == b'\n') {
                let command: Vec<u8> = line.drain(..=at).collect();
                let text = String::from_utf8_lossy(&command)
                    .trim_end_matches(['\r', '\n'])
                    .to_owned();
                if in_data {
                    if text == "." {
                        in_data = false;
                        let _ = session.write_all(b"250 accepted\r\n").await;
                    } else {
                        slot.lock().expect("captured").push(text);
                    }
                    continue;
                }
                let upper = text.to_ascii_uppercase();
                if upper == "QUIT" {
                    let _ = session.write_all(b"221 bye\r\n").await;
                    return;
                }
                slot.lock().expect("captured").push(text.clone());
                if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                    let advertisement = if upgrade.is_some() {
                        "250-STARTTLS\r\n"
                    } else {
                        ""
                    };
                    let _ = session
                        .write_all(
                            format!(
                                "250-test greets\r\n{advertisement}250-AUTH PLAIN\r\n250 8BITMIME\r\n"
                            )
                            .as_bytes(),
                        )
                        .await;
                } else if upper == "STARTTLS" {
                    let Some(key) = upgrade.take() else {
                        let _ = session.write_all(b"454 not available\r\n").await;
                        continue;
                    };
                    let _ = session.write_all(b"220 go ahead\r\n").await;
                    session = match session.upgrade(key).await {
                        Some(upgraded) => upgraded,
                        None => return,
                    };
                } else if upper == "DATA" {
                    in_data = true;
                    let _ = session.write_all(b"354 end with .\r\n").await;
                } else if upper.starts_with("AUTH") {
                    let _ = session.write_all(b"235 authenticated\r\n").await;
                } else {
                    let _ = session.write_all(b"250 ok\r\n").await;
                }
            }
        }
    });
    (addr, captured)
}

/// A fake HTTP CONNECT proxy: records the CONNECT request, answers 200 and
/// pipes everything after to `target`.
pub async fn fake_http_proxy(target: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let slot = Arc::clone(&captured);
    tokio::spawn(async move {
        let Some((mut stream, _)) = listener.accept().await.ok() else {
            return;
        };
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&buffer).to_string();
        slot.lock().expect("captured").push(request);
        if stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        let Ok(mut upstream) = TcpStream::connect(target).await else {
            return;
        };
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    });
    (addr, captured)
}

/// One HTTPS request served behind a CONNECT proxy: the channel dials the
/// proxy (its configured endpoint host), the proxy pipes into a local TLS
/// HTTP server with a self-signed certificate. Returns the proxy base URL
/// (`http://…` for the channel's `proxy` field), the CONNECT log and the
/// TLS-protected requests.
pub struct FakeHttps {
    pub proxy_base: String,
    pub connects: Arc<Mutex<Vec<String>>>,
    pub requests: Arc<Mutex<Vec<String>>>,
    pub task: JoinHandle<()>,
    pub proxy_task: JoinHandle<()>,
}

impl FakeHttps {
    pub async fn start(status: &'static str, body: &'static str) -> Self {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .expect("self-signed cert");
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .expect("server config");
        let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(config)));
        let tls_listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let tls_addr = tls_listener.local_addr().expect("addr");
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let slot = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = tls_listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            if let Some(request) = read_tls_request(&mut tls).await {
                slot.lock().expect("requests").push(request);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(response.as_bytes()).await;
            }
        });
        let (proxy_addr, connects) = fake_http_proxy(tls_addr).await;
        Self {
            proxy_base: format!("http://{proxy_addr}"),
            connects,
            requests,
            task,
            proxy_task: tokio::spawn(async {}),
        }
    }

    pub fn captured(&self) -> Vec<String> {
        self.requests.lock().expect("requests").clone()
    }

    pub fn one(&self) -> String {
        let requests = self.captured();
        assert_eq!(
            requests.len(),
            1,
            "exactly one request expected: {requests:?}"
        );
        requests[0].clone()
    }

    pub fn stop(self) {
        self.task.abort();
        self.proxy_task.abort();
    }
}

/// Reads one HTTP request (head plus content-length body) from a TLS
/// stream.
async fn read_tls_request(tls: &mut tokio_rustls::server::TlsStream<TcpStream>) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = &buffer[..at];
            let text = String::from_utf8_lossy(head);
            let length = text
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|line| line.split(':').nth(1))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= at + 4 + length {
                return Some(String::from_utf8_lossy(&buffer).to_string());
            }
        }
        let read = tls.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            return if buffer.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&buffer).to_string())
            };
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// A fake SOCKS5 proxy (no auth): records the handshake target, answers
/// success and pipes to `target`.
pub async fn fake_socks5_proxy(target: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let slot = Arc::clone(&captured);
    tokio::spawn(async move {
        let Some((mut stream, _)) = listener.accept().await.ok() else {
            return;
        };
        // Greeting: VER NMETHODS METHODS…
        let mut head = [0u8; 2];
        if stream.read_exact(&mut head).await.is_err() {
            return;
        }
        let mut methods = vec![0u8; usize::from(head[1])];
        if stream.read_exact(&mut methods).await.is_err() {
            return;
        }
        if stream.write_all(&[0x05, 0x00]).await.is_err() {
            return;
        }
        let mut head = [0u8; 4];
        if stream.read_exact(&mut head).await.is_err() {
            return;
        }
        let target_host = match head[3] {
            0x01 => {
                let mut bytes = [0u8; 4];
                if stream.read_exact(&mut bytes).await.is_err() {
                    return;
                }
                std::net::IpAddr::from(bytes).to_string()
            }
            0x04 => {
                let mut bytes = [0u8; 16];
                if stream.read_exact(&mut bytes).await.is_err() {
                    return;
                }
                std::net::IpAddr::from(bytes).to_string()
            }
            0x03 => {
                let mut length = [0u8; 1];
                if stream.read_exact(&mut length).await.is_err() {
                    return;
                }
                let mut bytes = vec![0u8; usize::from(length[0])];
                if stream.read_exact(&mut bytes).await.is_err() {
                    return;
                }
                String::from_utf8(bytes).unwrap_or_default()
            }
            _ => return,
        };
        let mut port = [0u8; 2];
        if stream.read_exact(&mut port).await.is_err() {
            return;
        }
        let port = u16::from_be_bytes(port);
        slot.lock()
            .expect("captured")
            .push(format!("{target_host}:{port} atyp={:#x}", head[3]));
        // Answer success with a bound IPv4 address, then pipe.
        if stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .is_err()
        {
            return;
        }
        let Ok(mut upstream) = TcpStream::connect(target).await else {
            return;
        };
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    });
    (addr, captured)
}

/// Waits until `condition` turns true (100 ms steps, 5 s budget).
pub async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..50 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition did not become true in time");
}
