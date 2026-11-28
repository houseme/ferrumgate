//! Minimal Telnet client (WP-61 §3.3):
//! - RFC 854 IAC negotiation (minimal safe subset: accepts ECHO/SGA, advertises
//!   NAWS window size, rejects everything else cleanly and strips IAC bytes from
//!   terminal output).
//! - One-time auto-fill for `login:` / `username:` and `password:` prompts when
//!   credentials are configured.
//! - Optional SOCKS5 / HTTP CONNECT proxy support via [`crate::ssh::proxy`].

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

use crate::model::{AuthKind, Connection, Preset, Proxy};
use crate::session::{Backend, BackendError, ExitReason, OutputSink};
use crate::ssh::proxy;

// RFC 854 / 855 / 1073 constants.
const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;
const OPT_NAWS: u8 = 31;

/// Resolved Telnet target.
#[derive(Clone, Debug)]
pub struct TelnetTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub connect_timeout: Duration,
    pub proxy: Option<Proxy>,
    pub cols: u16,
    pub rows: u16,
}

impl TelnetTarget {
    /// Builds a Telnet target from a stored connection and preset list.
    pub fn resolve(
        conn: &Connection,
        presets: &[Preset],
        cols: u16,
        rows: u16,
    ) -> Result<Self, String> {
        let port = conn
            .effective_port()
            .ok_or_else(|| "Telnet 连接缺少有效端口".to_owned())?;
        let mut username = conn.username.clone();
        let password = match conn.auth.kind {
            AuthKind::Password => conn.auth.password.clone(),
            AuthKind::Preset => {
                if let Some(preset) = presets.iter().find(|p| p.key == conn.auth.preset) {
                    if username.is_empty() && !preset.username.is_empty() {
                        username = preset.username.clone();
                    }
                    preset.password.clone()
                } else {
                    String::new()
                }
            }
            AuthKind::Key => String::new(),
        };
        Ok(Self {
            host: conn.host.clone(),
            port,
            username,
            password,
            connect_timeout: conn.effective_timeout(),
            proxy: conn.proxy.clone(),
            cols,
            rows,
        })
    }
}

enum TelnetCmd {
    Write(Vec<u8>),
    Resize(u16, u16),
    Terminate,
}

/// Active Telnet terminal backend implementing [`Backend`].
pub struct TelnetBackend {
    cmd_tx: mpsc::UnboundedSender<TelnetCmd>,
    exit_rx: watch::Receiver<Option<ExitReason>>,
}

/// Opens a Telnet session and attaches its reader to `sink`.
pub async fn open(target: &TelnetTarget, sink: OutputSink) -> Result<TelnetBackend, String> {
    let stream = proxy::connect_tcp(
        &target.host,
        target.port,
        target.proxy.as_ref(),
        target.connect_timeout,
    )
    .await
    .map_err(|e| e.to_string())?;

    let (mut reader, mut writer) = stream.into_split();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<TelnetCmd>();
    let (exit_tx, exit_rx) = watch::channel(None);

    let mut parser = IacParser::new(target.cols, target.rows);
    let mut auto_login = AutoLogin::new(target.username.clone(), target.password.clone());

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let reason = loop {
            tokio::select! {
                biased;
                cmd = cmd_rx.recv() => match cmd {
                    Some(TelnetCmd::Write(data)) => {
                        let escaped = escape_iac(&data);
                        if writer.write_all(&escaped).await.is_err() {
                            break ExitReason::Closed;
                        }
                    }
                    Some(TelnetCmd::Resize(cols, rows)) => {
                        parser.cols = cols;
                        parser.rows = rows;
                        if parser.naws_enabled {
                            let pkt = naws_subneg(cols, rows);
                            let _ = writer.write_all(&pkt).await;
                        }
                    }
                    Some(TelnetCmd::Terminate) | None => {
                        let _ = writer.shutdown().await;
                        break ExitReason::Terminated;
                    }
                },
                read_res = reader.read(&mut buf) => match read_res {
                    Ok(0) => break ExitReason::Closed,
                    Ok(n) => {
                        let (display, replies) = parser.feed(&buf[..n]);
                        if !replies.is_empty() && writer.write_all(&replies).await.is_err() {
                            break ExitReason::Closed;
                        }
                        if !display.is_empty() {
                            let auto_writes = auto_login.inspect(&display);
                            sink(display);
                            for line in auto_writes {
                                if writer.write_all(&line).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(err) => break ExitReason::Failed(err.to_string()),
                }
            }
        };
        let _ = exit_tx.send(Some(reason));
    });

    Ok(TelnetBackend { cmd_tx, exit_rx })
}

impl Backend for TelnetBackend {
    fn write(&mut self, data: Vec<u8>) -> Result<(), BackendError> {
        self.cmd_tx
            .send(TelnetCmd::Write(data))
            .map_err(|_| BackendError::Closed)
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        let _ = self.cmd_tx.send(TelnetCmd::Resize(cols, rows));
    }

    fn terminate(&mut self) {
        let _ = self.cmd_tx.send(TelnetCmd::Terminate);
    }

    fn wait_exit(&mut self) -> Pin<Box<dyn Future<Output = ExitReason> + Send + '_>> {
        Box::pin(async move {
            loop {
                if let Some(reason) = self.exit_rx.borrow().clone() {
                    return reason;
                }
                if self.exit_rx.changed().await.is_err() {
                    return ExitReason::Closed;
                }
            }
        })
    }
}

/// Escapes literal `0xFF` bytes as `IAC IAC` on the client -> server path.
fn escape_iac(data: &[u8]) -> Vec<u8> {
    if !data.contains(&IAC) {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len() + 8);
    for &b in data {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out
}

/// Builds an RFC 1073 NAWS subnegotiation frame.
fn naws_subneg(cols: u16, rows: u16) -> Vec<u8> {
    let mut out = vec![IAC, SB, OPT_NAWS];
    for b in cols.to_be_bytes().into_iter().chain(rows.to_be_bytes()) {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out.push(IAC);
    out.push(SE);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IacState {
    Data,
    Iac,
    Negotiate(u8),
    Subneg,
    SubnegIac,
}

/// Incremental RFC 854 IAC parser and responder.
struct IacParser {
    state: IacState,
    cols: u16,
    rows: u16,
    naws_enabled: bool,
}

impl IacParser {
    fn new(cols: u16, rows: u16) -> Self {
        Self {
            state: IacState::Data,
            cols,
            rows,
            naws_enabled: false,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut display = Vec::with_capacity(bytes.len());
        let mut replies = Vec::new();
        for &b in bytes {
            match self.state {
                IacState::Data => {
                    if b == IAC {
                        self.state = IacState::Iac;
                    } else {
                        display.push(b);
                    }
                }
                IacState::Iac => match b {
                    IAC => {
                        display.push(IAC);
                        self.state = IacState::Data;
                    }
                    WILL | WONT | DO | DONT => {
                        self.state = IacState::Negotiate(b);
                    }
                    SB => {
                        self.state = IacState::Subneg;
                    }
                    _ => {
                        // Two-byte command (NOP, GA, etc.) — ignore.
                        self.state = IacState::Data;
                    }
                },
                IacState::Negotiate(cmd) => {
                    match cmd {
                        WILL => {
                            if b == OPT_ECHO || b == OPT_SGA {
                                replies.extend_from_slice(&[IAC, DO, b]);
                            } else {
                                replies.extend_from_slice(&[IAC, DONT, b]);
                            }
                        }
                        DO => {
                            if b == OPT_NAWS {
                                self.naws_enabled = true;
                                replies.extend_from_slice(&[IAC, WILL, OPT_NAWS]);
                                replies.extend_from_slice(&naws_subneg(self.cols, self.rows));
                            } else {
                                replies.extend_from_slice(&[IAC, WONT, b]);
                            }
                        }
                        WONT | DONT => {}
                        _ => {}
                    }
                    self.state = IacState::Data;
                }
                IacState::Subneg => {
                    if b == IAC {
                        self.state = IacState::SubnegIac;
                    }
                }
                IacState::SubnegIac => {
                    if b == SE {
                        self.state = IacState::Data;
                    } else if b != IAC {
                        self.state = IacState::Subneg;
                    }
                }
            }
        }
        (display, replies)
    }
}

/// Watches incoming Telnet text for `login:` / `username:` and `password:`
/// prompts and auto-fills each at most once (WP-61 §3.3).
struct AutoLogin {
    username: String,
    password: String,
    sent_user: bool,
    sent_pass: bool,
    tail: String,
}

impl AutoLogin {
    fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            sent_user: false,
            sent_pass: false,
            tail: String::new(),
        }
    }

    fn inspect(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        if (self.sent_user || self.username.is_empty())
            && (self.sent_pass || self.password.is_empty())
        {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(data);
        self.tail.push_str(&text);
        if self.tail.len() > 256 {
            let start = self.tail.len() - 256;
            // Align to char boundary
            let mut idx = start;
            while !self.tail.is_char_boundary(idx) && idx < self.tail.len() {
                idx += 1;
            }
            self.tail.drain(..idx);
        }

        // Examine the current (trailing) line only.
        let line = self
            .tail
            .rsplit(['\r', '\n'])
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();

        let mut writes = Vec::new();
        if !self.sent_user
            && !self.username.is_empty()
            && (line.ends_with("login:") || line.ends_with("username:") || line.ends_with("user:"))
        {
            self.sent_user = true;
            self.tail.clear();
            writes.push(format!("{}\r\n", self.username).into_bytes());
        } else if !self.sent_pass
            && !self.password.is_empty()
            && (line.ends_with("password:") || line.ends_with("passwd:"))
        {
            self.sent_pass = true;
            self.tail.clear();
            writes.push(format!("{}\r\n", self.password).into_bytes());
        }
        writes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iac_parser_strips_commands_and_negotiates_minimal_subset() {
        let mut p = IacParser::new(100, 30);
        let input = [
            IAC, WILL, OPT_ECHO, // -> DO ECHO
            IAC, WILL, 99, // -> DONT 99
            IAC, DO, OPT_NAWS, // -> WILL NAWS + subneg
            IAC, DO, 24, // -> WONT 24
            b'H', b'i',
        ];
        let (display, replies) = p.feed(&input);
        assert_eq!(display, b"Hi");
        assert!(p.naws_enabled);
        assert!(replies.starts_with(&[IAC, DO, OPT_ECHO, IAC, DONT, 99, IAC, WILL, OPT_NAWS]));
        assert!(replies.ends_with(&[IAC, WONT, 24]));
    }

    #[test]
    fn auto_login_fills_username_and_password_at_most_once() {
        let mut al = AutoLogin::new("admin".into(), "secret".into());
        assert_eq!(
            al.inspect(b"Welcome\r\nlogin: "),
            vec![b"admin\r\n".to_vec()]
        );
        // Second login prompt must NOT auto-fill again.
        assert!(al.inspect(b"\r\nlogin: ").is_empty());
        assert_eq!(al.inspect(b"Password: "), vec![b"secret\r\n".to_vec()]);
        // Second password prompt must NOT auto-fill again.
        assert!(al.inspect(b"\r\nPassword: ").is_empty());
    }
}
