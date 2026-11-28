//! SMTP e-mail channel (WP-68 §3.3): connects directly or through an
//! explicit proxy (`http(s)` → CONNECT tunnel, `socks5`/`socks5h` → SOCKS5
//! handshake; environment proxies are never used for e-mail), then speaks
//! minimal SMTP: `EHLO`, required STARTTLS per the security mode (TLS and
//! authentication happen inside the tunnel, the proxy never sees the
//! message), `AUTH PLAIN` when credentials are set, and one `RCPT TO` per
//! recipient. The subject uses an RFC 2047 UTF-8 encoded word; the body is
//! sent base64-encoded with a UTF-8 charset.
//!
//! `insecureSkipVerify` accepts any server certificate (self-signed SMTP
//! appliances); the default verifies against the webpki roots.

use std::sync::Arc;

use base64::Engine as _;
use time::format_description::well_known::Rfc2822;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::channels::Message;
use crate::model::{ChannelConfig, SmtpSecurity, limits};
use crate::proxy::Effective;

/// The SMTP conversation (greeting through QUIT) is bounded even when the
/// server stalls.
const SESSION_TIMEOUT: std::time::Duration = limits::SMTP_TIMEOUT;

pub(crate) async fn send(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let conversation = smtp(config, message, effective, cancel);
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err("投递在模块关闭时被终止".to_owned()),
        result = tokio::time::timeout(SESSION_TIMEOUT, conversation) => match result {
            Ok(inner) => inner,
            Err(_) => Err(format!(
                "SMTP 会话超时（超过 {} 秒）",
                SESSION_TIMEOUT.as_secs().max(1)
            )),
        },
    }
}

async fn smtp(
    config: &ChannelConfig,
    message: &Message,
    effective: &Effective,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let port = if config.port == 0 {
        config.security.default_port()
    } else {
        config.port
    };
    let (plain, buffered) =
        crate::proxy::connect(&config.host, port, effective, limits::SEND_TIMEOUT, cancel).await?;
    let mut session = match config.security {
        SmtpSecurity::Ssl => Session::tls(tls_wrap(plain, &config.host, config).await?),
        _ => Session::plain(plain, buffered),
    };
    let greeting = session.reply().await?;
    if greeting / 100 != 2 {
        return Err(format!("SMTP 服务器拒绝连接（{greeting}）"));
    }
    session.command("EHLO ferrumgate").await?;
    if config.security == SmtpSecurity::StartTls {
        let code = session.command("STARTTLS").await?;
        if code != 220 {
            return Err(format!("SMTP 服务器不支持 STARTTLS（{code}）"));
        }
        let plain = session
            .take_plain()
            .expect("security starttls starts plain");
        let tls = tls_wrap(plain, &config.host, config).await?;
        session = Session::tls(tls);
        session.command("EHLO ferrumgate").await?;
    }
    if !config.smtp_user.is_empty() {
        let initial = base64_of(format!("\u{0}{}\u{0}{}", config.smtp_user, config.password));
        let code = session.command(&format!("AUTH PLAIN {initial}")).await?;
        if code / 100 != 2 {
            return Err(format!("SMTP 认证被拒绝（{code}）"));
        }
    }
    let from = format!("<{}>", config.from);
    let code = session.command(&format!("MAIL FROM:{from}")).await?;
    if code / 100 != 2 {
        return Err(format!("SMTP MAIL FROM 被拒绝（{code}）"));
    }
    for recipient in &config.to {
        let code = session.command(&format!("RCPT TO:<{recipient}>")).await?;
        if code / 100 != 2 {
            return Err(format!("SMTP 收件人 {recipient} 被拒绝（{code}）"));
        }
    }
    let code = session.command("DATA").await?;
    if code != 354 {
        return Err(format!("SMTP DATA 被拒绝（{code}）"));
    }
    let data = rfc5322_message(config, message);
    session.send_raw(&data).await?;
    let code = session.command(".").await?;
    if code / 100 != 2 {
        return Err(format!("SMTP 消息被拒绝（{code}）"));
    }
    let _ = session.command("QUIT").await;
    Ok(())
}

/// The RFC 5322 message with dot-stuffing and the terminating dot.
fn rfc5322_message(config: &ChannelConfig, message: &Message) -> String {
    let subject = format!("=?UTF-8?B?{}?=", base64_of(message.title.clone()));
    let date = time::OffsetDateTime::now_utc()
        .format(&Rfc2822)
        .unwrap_or_default();
    let mut out = String::new();
    out.push_str(&format!("From: <{}>\r\n", config.from));
    out.push_str(&format!("To: {}\r\n", config.to.join(", ")));
    out.push_str(&format!("Subject: {subject}\r\n"));
    out.push_str(&format!("Date: {date}\r\n"));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
    out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    let encoded = base64_of(message.body.clone());
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push_str("\r\n");
    }
    // Dot-stuffing: a leading dot in the data would end the message
    // early; the terminator is appended after so it stays a bare dot.
    let stuffed = out.replace("\r\n.", "\r\n..");
    format!("{stuffed}.\r\n")
}

fn base64_of(text: String) -> String {
    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
}

/// A client-side TLS connector; `insecure_skip_verify` accepts any
/// certificate chain (the upstream `TestSMTPInsecureSkipVerify` case).
fn tls_connector(insecure_skip_verify: bool) -> Result<TlsConnector, String> {
    let config = if insecure_skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn tls_wrap(
    stream: TcpStream,
    host: &str,
    config: &ChannelConfig,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|error| format!("SMTP 服务器名称无效：{error}"))?;
    tls_connector(config.insecure_skip_verify)?
        .connect(name, stream)
        .await
        .map_err(|error| format!("SMTP TLS 握手失败：{error}"))
}

/// A certificate verifier that accepts everything (`insecureSkipVerify`).
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &rustls::pki_types::CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _certificate: &rustls::pki_types::CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// The SMTP transport: plain TCP, TLS-wrapped TCP, or the transient slot
/// while a STARTTLS upgrade swaps them.
enum Transport {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Taken,
}

impl Transport {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, String> {
        match self {
            Transport::Plain(stream) => {
                stream.read(buffer).await.map_err(|error| error.to_string())
            }
            Transport::Tls(stream) => stream.read(buffer).await.map_err(|error| error.to_string()),
            Transport::Taken => Err("SMTP 传输已被取走".to_owned()),
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), String> {
        match self {
            Transport::Plain(stream) => stream
                .write_all(bytes)
                .await
                .map_err(|error| error.to_string()),
            Transport::Tls(stream) => stream
                .write_all(bytes)
                .await
                .map_err(|error| error.to_string()),
            Transport::Taken => Err("SMTP 传输已被取走".to_owned()),
        }
    }
}

/// One SMTP conversation over a transport.
struct Session {
    transport: Transport,
    line: Vec<u8>,
}

impl Session {
    /// A plain session that starts with bytes the proxy handshake already
    /// buffered (a chatty proxy may deliver the greeting early).
    fn plain(stream: TcpStream, buffered: Vec<u8>) -> Self {
        Self {
            transport: Transport::Plain(stream),
            line: buffered,
        }
    }

    fn tls(stream: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        Self {
            transport: Transport::Tls(Box::new(stream)),
            line: Vec::new(),
        }
    }

    /// Unwraps the plain transport for an in-place STARTTLS upgrade.
    fn take_plain(&mut self) -> Option<TcpStream> {
        match std::mem::replace(&mut self.transport, Transport::Taken) {
            Transport::Plain(stream) => Some(stream),
            other => {
                self.transport = other;
                None
            }
        }
    }

    /// Reads one CRLF-terminated reply line (bounded).
    async fn read_line(&mut self) -> Result<String, String> {
        loop {
            if let Some(at) = self.line.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = self.line.drain(..=at).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return String::from_utf8(line)
                    .map(|text| text.trim_end().to_owned())
                    .map_err(|_| "SMTP 响应包含非 UTF-8 文本".to_owned());
            }
            if self.line.len() > 8 * 1024 {
                return Err("SMTP 响应行过长".to_owned());
            }
            let mut chunk = [0u8; 1024];
            let read = self
                .transport
                .read(&mut chunk)
                .await
                .map_err(|error| format!("SMTP 读取失败：{error}"))?;
            if read == 0 {
                return Err("SMTP 连接被关闭".to_owned());
            }
            self.line.extend_from_slice(&chunk[..read]);
        }
    }

    /// Reads a (possibly multi-line) reply and returns its status code.
    async fn reply(&mut self) -> Result<u16, String> {
        loop {
            let line = self.read_line().await?;
            if line.len() < 3 || !line[..3].bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("SMTP 响应无法解析：{line}"));
            }
            let code: u16 = line[..3]
                .parse()
                .map_err(|_| format!("SMTP 响应无法解析：{line}"))?;
            if line.as_bytes().get(3) != Some(&b'-') {
                return Ok(code);
            }
        }
    }

    /// Sends a command line and returns the reply's status code.
    async fn command(&mut self, command: &str) -> Result<u16, String> {
        self.send_raw(&format!("{command}\r\n")).await?;
        self.reply().await
    }

    async fn send_raw(&mut self, bytes: &str) -> Result<(), String> {
        self.transport
            .write_all(bytes.as_bytes())
            .await
            .map_err(|error| format!("SMTP 发送失败：{error}"))
    }
}
