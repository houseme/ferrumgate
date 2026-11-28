//! SSH, TOFU host keys, proxy tunneling (SOCKS5 / HTTP CONNECT), Telnet
//! auto-login, and `ssh_exec` / `ssh_push` / `ssh_targets` integration tests
//! using an in-process `russh::server` + `russh_sftp::server` (WP-61 §6).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine as _;
use fg_config::ConfigStore;
use fg_webterminal::model::{
    Auth, AuthKind, ConnKind, Connection, HostKey, HostKeyType, Preset, Proxy, ProxyKind,
};
use fg_webterminal::ssh::hostkey::HostKeyObservation;
use fg_webterminal::ssh::{self, HostKeyOutcome, PushFile, SshConnectError, SshTarget};
use fg_webterminal::{SshPushRequest, WebTerminalHandle};
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use russh::server::{
    Auth as ServerAuth, ChannelOpenHandle, Handler as ServerHandler, Msg, Session as ServerSession,
};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, SftpHandle, SftpString, Status,
    StatusCode as SftpStatus,
};
use russh_sftp::server::Handler as SftpServerHandler;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn call_api(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let payload = body.map(|v| serde_json::to_vec(&v).unwrap());
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(ref bytes) = payload {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", bytes.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    if let Some(ref bytes) = payload {
        stream.write_all(bytes).await.unwrap();
    }
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let sep = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP response header");
    let head = std::str::from_utf8(&resp[..sep]).unwrap();
    let code: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let json = serde_json::from_slice(&resp[sep + 4..]).unwrap_or(Value::Null);
    (StatusCode::from_u16(code).unwrap(), json)
}

async fn start_api() -> (tempfile::TempDir, Arc<WebTerminalHandle>, SocketAddr) {
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(dir.path()).unwrap();
    let handle = WebTerminalHandle::open(store).unwrap();
    let app = handle.router();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (dir, handle, addr)
}

// =========================================================================
// In-process Test SSH + SFTP Server
// =========================================================================

fn ed25519_key_from_seed(seed_byte: u8) -> PrivateKey {
    let seed = [seed_byte; 32];
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

#[derive(Clone)]
struct TestSshState {
    expected_user: String,
    expected_password: String,
    allowed_pubkey: Option<PublicKey>,
    auth_attempts: Arc<AtomicUsize>,
    exec_log: Arc<Mutex<Vec<String>>>,
    sftp_root: PathBuf,
}

struct TestSshConn {
    state: TestSshState,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl ServerHandler for TestSshConn {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<ServerAuth, Self::Error> {
        self.state.auth_attempts.fetch_add(1, Ordering::SeqCst);
        if user == self.state.expected_user && password == self.state.expected_password {
            Ok(ServerAuth::Accept)
        } else {
            Ok(ServerAuth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<ServerAuth, Self::Error> {
        self.state.auth_attempts.fetch_add(1, Ordering::SeqCst);
        if user == self.state.expected_user
            && self
                .state
                .allowed_pubkey
                .as_ref()
                .is_some_and(|pk| pk.key_data() == key.public_key.key_data())
        {
            Ok(ServerAuth::Accept)
        } else {
            Ok(ServerAuth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        let _ = reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"shell-ready\r\n".as_slice())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        // Only echo on interactive shell channels; leave SFTP channels to their stream!
        if !self.channels.contains_key(&channel) {
            return Ok(());
        }
        // Echo back prefixed with `echo:` so tests verify roundtrip.
        let mut reply = b"echo:".to_vec();
        reply.extend_from_slice(data);
        session.data(channel, reply)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        self.state.exec_log.lock().unwrap().push(cmd.clone());
        session.channel_success(channel)?;
        let out = format!("executed:{cmd}");
        session.data(channel, out.into_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        if name == "sftp"
            && let Some(ch) = self.channels.remove(&channel)
        {
            session.channel_success(channel)?;
            let handler = FsSftpServer::new(self.state.sftp_root.clone());
            tokio::spawn(async move {
                russh_sftp::server::run(ch.into_stream(), handler).await;
            });
            return Ok(());
        }
        session.channel_failure(channel)?;
        Ok(())
    }
}

/// Minimal real SFTP server backed by a tempdir for end-to-end tests.
struct FsSftpServer {
    root: PathBuf,
    next_handle: u64,
    files: HashMap<SftpHandle, PathBuf>,
    dirs: HashMap<SftpHandle, (PathBuf, bool)>,
}

impl FsSftpServer {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            next_handle: 1,
            files: HashMap::new(),
            dirs: HashMap::new(),
        }
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let rel = path.trim_start_matches('/');
        if rel.is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    fn alloc_handle(&mut self) -> SftpHandle {
        let id = self.next_handle;
        self.next_handle += 1;
        SftpHandle::from(format!("h{id}"))
    }

    fn attrs_of(meta: &std::fs::Metadata) -> FileAttributes {
        let mut attrs = FileAttributes::empty();
        attrs.size = Some(meta.len());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_type = if meta.is_dir() { 0o040000 } else { 0o100000 };
            attrs.permissions = Some(file_type | (meta.permissions().mode() & 0o7777));
        }
        attrs
    }
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: SftpStatus::Ok,
        error_message: "ok".into(),
        language_tag: "en".into(),
    }
}

impl SftpServerHandler for FsSftpServer {
    type Error = SftpStatus;

    fn unimplemented(&self) -> Self::Error {
        SftpStatus::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        filename: SftpString,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let full = self.resolve(filename.as_str());
        if pflags.contains(OpenFlags::CREATE) || pflags.contains(OpenFlags::TRUNCATE) {
            if let Some(parent) = full.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&full, b"").map_err(|_| SftpStatus::Failure)?;
        } else if !full.exists() {
            return Err(SftpStatus::NoSuchFile);
        }
        let handle = self.alloc_handle();
        self.files.insert(handle.clone(), full);
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: SftpHandle) -> Result<Status, Self::Error> {
        self.files.remove(&handle);
        self.dirs.remove(&handle);
        Ok(ok_status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let path = self.files.get(&handle).ok_or(SftpStatus::NoSuchFile)?;
        let bytes = std::fs::read(path).map_err(|_| SftpStatus::Failure)?;
        let start = offset as usize;
        if start >= bytes.len() {
            return Err(SftpStatus::Eof);
        }
        let end = (start + len as usize).min(bytes.len());
        Ok(Data {
            id,
            data: bytes[start..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let path = self.files.get(&handle).ok_or(SftpStatus::NoSuchFile)?;
        let mut buf = std::fs::read(path).unwrap_or_default();
        let off = offset as usize;
        if buf.len() < off + data.len() {
            buf.resize(off + data.len(), 0);
        }
        buf[off..off + data.len()].copy_from_slice(&data);
        std::fs::write(path, buf).map_err(|_| SftpStatus::Failure)?;
        Ok(ok_status(id))
    }

    async fn stat(&mut self, id: u32, path: SftpString) -> Result<Attrs, Self::Error> {
        let full = self.resolve(path.as_str());
        let meta = std::fs::metadata(&full).map_err(|_| SftpStatus::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: Self::attrs_of(&meta),
        })
    }

    async fn lstat(&mut self, id: u32, path: SftpString) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: SftpString,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let full = self.resolve(path.as_str());
        if !full.exists() {
            return Err(SftpStatus::NoSuchFile);
        }
        #[cfg(unix)]
        if let Some(perm) = attrs.permissions {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&full, std::fs::Permissions::from_mode(perm & 0o7777));
        }
        Ok(ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: SftpString,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let full = self.resolve(path.as_str());
        std::fs::create_dir_all(&full).map_err(|_| SftpStatus::Failure)?;
        Ok(ok_status(id))
    }

    async fn opendir(&mut self, id: u32, path: SftpString) -> Result<Handle, Self::Error> {
        let full = self.resolve(path.as_str());
        if !full.is_dir() {
            return Err(SftpStatus::NoSuchFile);
        }
        let handle = self.alloc_handle();
        self.dirs.insert(handle.clone(), (full, false));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: SftpHandle) -> Result<Name, Self::Error> {
        let Some((path, done)) = self.dirs.get_mut(&handle) else {
            return Err(SftpStatus::NoSuchFile);
        };
        if *done {
            return Err(SftpStatus::Eof);
        }
        *done = true;
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&*path).map_err(|_| SftpStatus::Failure)? {
            let entry = entry.map_err(|_| SftpStatus::Failure)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = entry.metadata().map_err(|_| SftpStatus::Failure)?;
            files.push(File::new(name, Self::attrs_of(&meta)));
        }
        Ok(Name { id, files })
    }

    async fn remove(&mut self, id: u32, filename: SftpString) -> Result<Status, Self::Error> {
        let full = self.resolve(filename.as_str());
        std::fs::remove_file(&full).map_err(|_| SftpStatus::NoSuchFile)?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: SftpString) -> Result<Status, Self::Error> {
        let full = self.resolve(path.as_str());
        std::fs::remove_dir(&full).map_err(|_| SftpStatus::Failure)?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: SftpString,
        newpath: SftpString,
    ) -> Result<Status, Self::Error> {
        let old = self.resolve(oldpath.as_str());
        let new = self.resolve(newpath.as_str());
        std::fs::rename(&old, &new).map_err(|_| SftpStatus::Failure)?;
        Ok(ok_status(id))
    }
}

struct RunningTestSsh {
    port: u16,
    host_key_fp: String,
    auth_attempts: Arc<AtomicUsize>,
    exec_log: Arc<Mutex<Vec<String>>>,
    sftp_root: PathBuf,
    _sftp_dir: tempfile::TempDir,
}

async fn start_ssh_server(
    host_keys: Vec<PrivateKey>,
    expected_user: &str,
    expected_password: &str,
    allowed_pubkey: Option<PublicKey>,
) -> RunningTestSsh {
    let fp = host_keys[0]
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    let sftp_dir = tempfile::tempdir().unwrap();
    let sftp_root = sftp_dir.path().to_path_buf();
    let auth_attempts = Arc::new(AtomicUsize::new(0));
    let exec_log = Arc::new(Mutex::new(Vec::new()));

    let state = TestSshState {
        expected_user: expected_user.to_owned(),
        expected_password: expected_password.to_owned(),
        allowed_pubkey,
        auth_attempts: Arc::clone(&auth_attempts),
        exec_log: Arc::clone(&exec_log),
        sftp_root: sftp_root.clone(),
    };

    let cfg = Arc::new(russh::server::Config {
        keys: host_keys,
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(10)),
        ..Default::default()
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let cfg = Arc::clone(&cfg);
            let st = state.clone();
            tokio::spawn(async move {
                let handler = TestSshConn {
                    state: st,
                    channels: HashMap::new(),
                };
                if let Ok(session) = russh::server::run_stream(cfg, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });

    RunningTestSsh {
        port,
        host_key_fp: fp,
        auth_attempts,
        exec_log,
        sftp_root,
        _sftp_dir: sftp_dir,
    }
}

fn make_ssh_conn(port: u16, password: &str) -> Connection {
    Connection {
        key: "aabbccddeeff".into(),
        name: "test-ssh".into(),
        kind: ConnKind::Ssh,
        host: "127.0.0.1".into(),
        port,
        username: "alice".into(),
        auth: Auth {
            kind: AuthKind::Password,
            password: password.into(),
            ..Auth::default()
        },
        connect_timeout: 5,
        ..Connection::default()
    }
}

// =========================================================================
// SSH & TOFU Host Key Tests
// =========================================================================

#[tokio::test]
async fn hostkey_tofu_records_fingerprint_and_type() {
    let srv = start_ssh_server(vec![ed25519_key_from_seed(1)], "alice", "secret", None).await;
    let conn = make_ssh_conn(srv.port, "secret");
    let target = SshTarget::resolve(&conn, &[]).unwrap();

    let connected = ssh::connect_ssh(&target, false).await.unwrap();
    assert_eq!(
        connected.host_key_outcome,
        HostKeyOutcome::New(HostKey {
            key_type: Some(HostKeyType::Ed25519),
            fingerprint: srv.host_key_fp.clone(),
        })
    );
    assert!(
        connected
            .server_version
            .as_deref()
            .is_some_and(|v| v.starts_with("SSH-2.0-"))
    );

    // Subsequent connect with recorded key matches cleanly.
    let mut conn2 = conn;
    conn2.host_key = connected.host_key_outcome.updated_key().cloned();
    let target2 = SshTarget::resolve(&conn2, &[]).unwrap();
    let connected2 = ssh::connect_ssh(&target2, false).await.unwrap();
    assert_eq!(connected2.host_key_outcome, HostKeyOutcome::Matched);
}

#[tokio::test]
async fn hostkey_changed_rejects_before_auth() {
    // Server now presents key #2, while connection recorded key #1.
    let old_key = ed25519_key_from_seed(10);
    let old_fp = old_key
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    let srv = start_ssh_server(vec![ed25519_key_from_seed(20)], "alice", "secret", None).await;

    let mut conn = make_ssh_conn(srv.port, "secret");
    conn.host_key = Some(HostKey {
        key_type: Some(HostKeyType::Ed25519),
        fingerprint: old_fp.clone(),
    });
    let target = SshTarget::resolve(&conn, &[]).unwrap();

    let err = match ssh::connect_ssh(&target, false).await {
        Err(e) => e,
        Ok(_) => panic!("changed host key must be rejected"),
    };
    match err {
        SshConnectError::HostKeyChanged { recorded, observed } => {
            assert_eq!(recorded.fingerprint, old_fp);
            assert_eq!(observed.fingerprint, srv.host_key_fp);
            assert_eq!(observed.key_type, Some(HostKeyType::Ed25519));
        }
        other => panic!("expected HostKeyChanged, got {other:?}"),
    }
    // CRITICAL security invariant: ZERO auth requests ever reached the server!
    assert_eq!(
        srv.auth_attempts.load(Ordering::SeqCst),
        0,
        "credentials MUST NOT be sent when host key mismatches"
    );
}

#[tokio::test]
async fn hostkey_type_fallback_to_other_types() {
    let srv_key = ed25519_key_from_seed(33);
    let expected_fp = srv_key
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    let srv = start_ssh_server(vec![srv_key], "alice", "secret", None).await;

    // Case 1: Recorded fingerprint with missing key_type (e.g. pasted from ssh-keyscan).
    let mut conn = make_ssh_conn(srv.port, "secret");
    conn.host_key = Some(HostKey {
        key_type: None,
        fingerprint: expected_fp.clone(),
    });
    let target = SshTarget::resolve(&conn, &[]).unwrap();
    let connected = ssh::connect_ssh(&target, false).await.unwrap();
    assert_eq!(
        connected.host_key_outcome,
        HostKeyOutcome::Backfilled(HostKey {
            key_type: Some(HostKeyType::Ed25519),
            fingerprint: expected_fp.clone(),
        })
    );

    // Case 2: Recorded key_type is stale (RSA), server only offers Ed25519 matching fingerprint.
    conn.host_key = Some(HostKey {
        key_type: Some(HostKeyType::Rsa),
        fingerprint: expected_fp.clone(),
    });
    let target2 = SshTarget::resolve(&conn, &[]).unwrap();
    let connected2 = ssh::connect_ssh(&target2, false).await.unwrap();
    assert_eq!(
        connected2.host_key_outcome,
        HostKeyOutcome::Backfilled(HostKey {
            key_type: Some(HostKeyType::Ed25519),
            fingerprint: expected_fp,
        })
    );
}

#[tokio::test]
async fn hostkey_test_does_not_record() {
    let srv = start_ssh_server(vec![ed25519_key_from_seed(44)], "alice", "secret", None).await;
    let (_dir, handle, addr) = start_api().await;

    // Create connection without host key.
    let conn = make_ssh_conn(srv.port, "secret");
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/connections",
        Some(serde_json::to_value(&conn).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // Call test endpoint -> reports ok + serverVersion + newHostKey, does NOT persist!
    let (st, json) = call_api(
        addr,
        "POST",
        "/api/webterminal/connections/aabbccddeeff/test",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(json["ok"], true);
    assert_eq!(json["newHostKey"]["fingerprint"], srv.host_key_fp);
    assert_eq!(json["newHostKey"]["keyType"], "ed25519");
    assert!(
        json["serverVersion"]
            .as_str()
            .unwrap()
            .starts_with("SSH-2.0-")
    );

    // Stored connection MUST still have host_key == None!
    let stored = handle.config_snapshot();
    assert!(
        stored.connections[0].host_key.is_none(),
        "test connection must NOT record host key"
    );
}

#[tokio::test]
async fn ssh_password_and_key_auth() {
    let client_key = ed25519_key_from_seed(77);
    let client_pub = client_key.public_key().clone();
    let client_pem = client_key.to_openssh(LineEnding::LF).unwrap().to_string();

    let srv = start_ssh_server(
        vec![ed25519_key_from_seed(55)],
        "alice",
        "secret-pw",
        Some(client_pub),
    )
    .await;

    // 1. Password auth + interactive shell I/O roundtrip.
    let pw_conn = make_ssh_conn(srv.port, "secret-pw");
    let target = SshTarget::resolve(&pw_conn, &[]).unwrap();
    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let recv_clone = Arc::clone(&received);
    let (mut backend, _hk) = ssh::open(
        &target,
        Arc::new(move |bytes| recv_clone.lock().unwrap().extend_from_slice(&bytes)),
    )
    .await
    .unwrap();
    use fg_webterminal::session::Backend as _;
    backend.write(b"ping".to_vec()).unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    let out = String::from_utf8_lossy(&received.lock().unwrap()).into_owned();
    assert!(
        out.contains("shell-ready"),
        "expected shell banner, got {out:?}"
    );
    assert!(
        out.contains("echo:ping"),
        "expected echoed input, got {out:?}"
    );
    backend.terminate();

    // 2. Public-key auth (pasted key) via preset.
    let preset = Preset {
        key: "preset111111".into(),
        name: "ed25519 preset".into(),
        kind: AuthKind::Key,
        username: "alice".into(),
        pasted: client_pem,
        ..Preset::default()
    };
    let mut key_conn = make_ssh_conn(srv.port, "");
    key_conn.username.clear(); // verify fallback to preset.username!
    key_conn.auth = Auth {
        kind: AuthKind::Preset,
        preset: "preset111111".into(),
        ..Auth::default()
    };
    let key_target = SshTarget::resolve(&key_conn, &[preset]).unwrap();
    let connected = ssh::connect_ssh(&key_target, false).await.unwrap();
    assert_eq!(
        HostKeyObservation::from_public_key(ed25519_key_from_seed(55).public_key()).key_type,
        Some(HostKeyType::Ed25519)
    );
    assert!(connected.host_key_outcome.updated_key().is_some());
}

#[test]
fn ssh_connect_timeout_default_15s() {
    let conn = Connection::default();
    assert_eq!(conn.connect_timeout, 15);
    assert_eq!(conn.effective_timeout(), Duration::from_secs(15));
    assert_eq!(Algorithm::Ed25519.as_str(), "ssh-ed25519");
}

#[tokio::test]
async fn ssh_push_and_exec_use_trusted_host_only() {
    let srv = start_ssh_server(vec![ed25519_key_from_seed(88)], "alice", "secret", None).await;
    let (_dir, handle, addr) = start_api().await;

    // Add untrusted SSH connection.
    let conn = make_ssh_conn(srv.port, "secret");
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/connections",
        Some(serde_json::to_value(&conn).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    let targets = handle.ssh_targets();
    assert_eq!(targets.len(), 1);
    assert!(!targets[0].trusted);

    // Untrusted host MUST be refused by both ssh_exec and ssh_push!
    assert!(handle.ssh_exec("aabbccddeeff", "uptime").await.is_err());
    assert!(
        handle
            .ssh_push(SshPushRequest {
                conn_key: "aabbccddeeff".into(),
                dir: "/certs".into(),
                files: vec![PushFile {
                    name: "fullchain.pem".into(),
                    content: b"CERT".to_vec(),
                    mode: Some(0o644),
                }],
                command: "reload".into(),
            })
            .await
            .is_err()
    );
    assert_eq!(srv.auth_attempts.load(Ordering::SeqCst), 0);

    // Record TOFU host key (simulating first Web Terminal connect).
    handle.record_host_key(
        "aabbccddeeff",
        HostKey {
            key_type: Some(HostKeyType::Ed25519),
            fingerprint: srv.host_key_fp.clone(),
        },
    );
    assert!(handle.ssh_targets()[0].trusted);

    // Now ssh_exec succeeds!
    let out = handle
        .ssh_exec("aabbccddeeff", "systemctl status")
        .await
        .unwrap();
    assert_eq!(out, "executed:systemctl status");

    // And ssh_push uploads the file via SFTP and runs the command!
    let push_out = handle
        .ssh_push(SshPushRequest {
            conn_key: "aabbccddeeff".into(),
            dir: "/deploy".into(),
            files: vec![PushFile {
                name: "sub/cert.pem".into(),
                content: b"---CERT---".to_vec(),
                mode: Some(0o600),
            }],
            command: "nginx -s reload".into(),
        })
        .await
        .unwrap();
    assert_eq!(push_out, "executed:nginx -s reload");
    let uploaded = std::fs::read(Path::new(&srv.sftp_root).join("deploy/sub/cert.pem")).unwrap();
    assert_eq!(uploaded, b"---CERT---");
    assert!(
        srv.exec_log
            .lock()
            .unwrap()
            .contains(&"nginx -s reload".to_owned())
    );

    // Also exercise remote SFTP HTTP routes through the pooled SFTP connection!
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/sftp/aabbccddeeff/write",
        Some(json!({ "path": "/remote.txt", "content": "via-sftp-pool" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, prev) = call_api(
        addr,
        "GET",
        "/api/webterminal/sftp/aabbccddeeff/read?path=/remote.txt",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(prev["content"], "via-sftp-pool");
    assert_eq!(
        handle.sftp_pool.len(),
        1,
        "SFTP session is pooled and reused"
    );
}

// =========================================================================
// SOCKS5 & HTTP CONNECT Proxy Tests
// =========================================================================

async fn start_fake_socks5_proxy(expected_user: &'static str, expected_pass: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                if client.read_exact(&mut hdr).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; usize::from(hdr[1])];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                // Choose username/password auth (0x02)
                let _ = client.write_all(&[0x05, 0x02]).await;
                let mut ver_ulen = [0u8; 2];
                if client.read_exact(&mut ver_ulen).await.is_err() {
                    return;
                }
                let mut ubuf = vec![0u8; usize::from(ver_ulen[1])];
                let _ = client.read_exact(&mut ubuf).await;
                let mut plen = [0u8; 1];
                let _ = client.read_exact(&mut plen).await;
                let mut pbuf = vec![0u8; usize::from(plen[0])];
                let _ = client.read_exact(&mut pbuf).await;
                if ubuf != expected_user.as_bytes() || pbuf != expected_pass.as_bytes() {
                    let _ = client.write_all(&[0x01, 0x01]).await;
                    return;
                }
                let _ = client.write_all(&[0x01, 0x00]).await;

                let mut req_hdr = [0u8; 4];
                if client.read_exact(&mut req_hdr).await.is_err() {
                    return;
                }
                let dst_host = match req_hdr[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        let _ = client.read_exact(&mut ip).await;
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        let _ = client.read_exact(&mut len).await;
                        let mut dom = vec![0u8; usize::from(len[0])];
                        let _ = client.read_exact(&mut dom).await;
                        String::from_utf8_lossy(&dom).into_owned()
                    }
                    _ => return,
                };
                let mut port_bytes = [0u8; 2];
                let _ = client.read_exact(&mut port_bytes).await;
                let dst_port = u16::from_be_bytes(port_bytes);

                let Ok(mut upstream) = TcpStream::connect((dst_host.as_str(), dst_port)).await
                else {
                    let _ = client
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };
                let _ = client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    port
}

async fn start_fake_http_proxy(expected_user: &'static str, expected_pass: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let expected_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{expected_user}:{expected_pass}"))
    );
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let expected_auth = expected_auth.clone();
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut b = [0u8; 1];
                while !req.ends_with(b"\r\n\r\n") && req.len() < 8192 {
                    if client.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    req.push(b[0]);
                }
                let text = String::from_utf8_lossy(&req);
                let first = text.lines().next().unwrap_or_default();
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                let has_auth = text.lines().any(|l| {
                    l.to_ascii_lowercase().starts_with("proxy-authorization:")
                        && l.contains(&expected_auth)
                });
                if method != "CONNECT" || !has_auth {
                    let _ = client
                        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        .await;
                    return;
                }
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                let _ = client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn proxy_socks5_and_http() {
    let srv = start_ssh_server(vec![ed25519_key_from_seed(99)], "alice", "secret", None).await;
    let socks_port = start_fake_socks5_proxy("puser", "ppass").await;
    let http_port = start_fake_http_proxy("huser", "hpass").await;

    // 1. SSH through SOCKS5 proxy.
    let mut conn = make_ssh_conn(srv.port, "secret");
    conn.proxy = Some(Proxy {
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: socks_port,
        username: "puser".into(),
        password: "ppass".into(),
    });
    let res = ssh::test_connection(&conn, &[]).await.unwrap();
    assert!(res.ok, "SOCKS5 SSH test failed: {:?}", res.error);
    assert_eq!(
        res.new_host_key.as_ref().map(|k| k.fingerprint.as_str()),
        Some(srv.host_key_fp.as_str())
    );

    // 2. SSH through HTTP CONNECT proxy.
    conn.proxy = Some(Proxy {
        kind: ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: http_port,
        username: "huser".into(),
        password: "hpass".into(),
    });
    let res2 = ssh::test_connection(&conn, &[]).await.unwrap();
    assert!(res2.ok, "HTTP CONNECT SSH test failed: {:?}", res2.error);
}

// =========================================================================
// Telnet Auto-Login Integration Test
// =========================================================================

#[tokio::test]
async fn telnet_auto_fill_login_prompts_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received_lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let recv_clone = Arc::clone(&received_lines);

    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // Send IAC WILL ECHO + IAC DO NAWS + login prompt.
            let _ = sock
                .write_all(&[
                    255, 251, 1, 255, 253, 31, b'l', b'o', b'g', b'i', b'n', b':', b' ',
                ])
                .await;
            let mut buf = [0u8; 512];
            let mut got = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while tokio::time::Instant::now() < deadline {
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(150), sock.read(&mut buf)).await
                {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&got).contains("admin\r\n") {
                        break;
                    }
                }
            }
            recv_clone
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&got).into_owned());

            // Send Password prompt.
            let _ = sock.write_all(b"Password: ").await;
            let mut got2 = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while tokio::time::Instant::now() < deadline {
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(150), sock.read(&mut buf)).await
                {
                    if n == 0 {
                        break;
                    }
                    got2.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&got2).contains("pw123\r\n") {
                        break;
                    }
                }
            }
            recv_clone
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&got2).into_owned());

            // Send a second login: prompt to verify auto-login does NOT fire twice!
            let _ = sock.write_all(b"\r\nlogin: ").await;
            let mut extra = [0u8; 64];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(200), sock.read(&mut extra)).await
                && n > 0
            {
                recv_clone
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&extra[..n]).into_owned());
            }
        }
    });

    let conn = Connection {
        key: "telnet000001".into(),
        name: "switch".into(),
        kind: ConnKind::Telnet,
        host: "127.0.0.1".into(),
        port,
        username: "admin".into(),
        auth: Auth {
            kind: AuthKind::Password,
            password: "pw123".into(),
            ..Auth::default()
        },
        connect_timeout: 5,
        ..Connection::default()
    };
    let target = fg_webterminal::telnet::TelnetTarget::resolve(&conn, &[], 80, 24).unwrap();
    let display = Arc::new(Mutex::new(Vec::<u8>::new()));
    let disp_clone = Arc::clone(&display);
    let mut backend = fg_webterminal::telnet::open(
        &target,
        Arc::new(move |b| disp_clone.lock().unwrap().extend_from_slice(&b)),
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(700)).await;
    use fg_webterminal::session::Backend as _;
    backend.terminate();

    let lines = received_lines.lock().unwrap();
    assert_eq!(
        lines.len(),
        2,
        "only username and password once: {:?}",
        *lines
    );
    assert!(lines[0].contains("admin\r\n"));
    assert!(lines[1].contains("pw123\r\n"));
    // IAC bytes must have been stripped from display output.
    assert!(!display.lock().unwrap().contains(&255));
}
