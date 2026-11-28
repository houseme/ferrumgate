//! End-to-end loopback TCP + TLS + Axum management route integration tests for
//! `fg-webdav` covering all WP-63 §6 test items.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::Router;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fg_config::ConfigStore;
use fg_core::{events::EventBus, fsperm};
use fg_files::{
    FailureReporter, FileUsersStore, Mount, PASSWORD_MASK, SharedUser, Throttle, hash_password,
};
use fg_net::openports::{OpenPorts, Proto};
use fg_webdav::{Deps, LocalUser, Module, RuntimeTimeouts, Settings, WebDavRuntime, limits};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn basic_auth(user: &str, pass: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{user}:{pass}")))
}

async fn send_dav(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).unwrap())
        .uri(path)
        .header("host", addr.to_string());
    if let Some(a) = auth {
        builder = builder.header("authorization", a);
    }
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

fn make_shared_store(cfg: Arc<ConfigStore>, bus: Option<EventBus>) -> Arc<FileUsersStore> {
    FileUsersStore::load_with_options(
        cfg,
        Arc::new(Throttle::new()),
        Arc::new(FailureReporter::new(bus)),
        4,
        Arc::new(SystemTime::now),
    )
    .unwrap()
}

async fn start_runtime(
    settings: Settings,
    shared: Arc<FileUsersStore>,
    timeouts: RuntimeTimeouts,
) -> (Arc<WebDavRuntime>, SocketAddr) {
    let mut cfg = settings;
    cfg.enable = true;
    cfg.listen_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    cfg.port = 0;
    let runtime = WebDavRuntime::new(cfg.clone(), shared, None, None, timeouts);
    runtime.apply(cfg).await.unwrap();
    let addr = runtime.bound_addr().expect("bound addr");
    (runtime, addr)
}

#[tokio::test]
async fn webdav_auth_basic_local_and_shared() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let local_dir = tmp.path().join("local");
    let shared_dir = tmp.path().join("shared");
    std::fs::create_dir_all(&local_dir).unwrap();
    std::fs::create_dir_all(&shared_dir).unwrap();
    std::fs::write(local_dir.join("who.txt"), b"from-local").unwrap();
    std::fs::write(shared_dir.join("who.txt"), b"from-shared").unwrap();

    let shared = make_shared_store(cfg, None);
    shared
        .save(vec![
            SharedUser {
                name: "bob".to_string(),
                password: "shared-bob-pw".to_string(),
                root: shared_dir.to_string_lossy().into_owned(),
                read_only: false,
                mounts: Vec::new(),
                remark: String::new(),
            },
            // Same username as local user "alice" -> local MUST win!
            SharedUser {
                name: "alice".to_string(),
                password: "shared-alice-pw".to_string(),
                root: shared_dir.to_string_lossy().into_owned(),
                read_only: false,
                mounts: Vec::new(),
                remark: String::new(),
            },
        ])
        .unwrap();

    let settings = Settings {
        shared_users: true,
        users: vec![LocalUser {
            name: "alice".to_string(),
            password: hash_password("local-alice-pw", 4).unwrap(),
            root: local_dir.to_string_lossy().into_owned(),
            ..LocalUser::default()
        }],
        ..Settings::default()
    };

    let (rt, addr) = start_runtime(settings, shared, RuntimeTimeouts::default()).await;

    // Local user succeeds and reads local directory.
    let (status, _, body) = send_dav(
        addr,
        "GET",
        "/who.txt",
        Some(&basic_auth("alice", "local-alice-pw")),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"from-local");

    // Same-name shared password MUST fail (local wins).
    let (status, _, _) = send_dav(
        addr,
        "GET",
        "/who.txt",
        Some(&basic_auth("alice", "shared-alice-pw")),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Distinct shared user succeeds and reads shared directory.
    let (status, _, body) = send_dav(
        addr,
        "GET",
        "/who.txt",
        Some(&basic_auth("bob", "shared-bob-pw")),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"from-shared");

    rt.stop().await;
}

#[tokio::test]
async fn webdav_readonly_rejects_write_methods() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let dir = tmp.path().join("ro");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("readme.txt"), b"read-only-content").unwrap();

    let shared = make_shared_store(cfg, None);
    let settings = Settings {
        users: vec![LocalUser {
            name: "viewer".to_string(),
            password: hash_password("view-pw", 4).unwrap(),
            root: dir.to_string_lossy().into_owned(),
            read_only: true,
            ..LocalUser::default()
        }],
        ..Settings::default()
    };
    let (rt, addr) = start_runtime(settings, shared, RuntimeTimeouts::default()).await;
    let auth = basic_auth("viewer", "view-pw");

    // Reads succeed.
    assert_eq!(
        send_dav(addr, "OPTIONS", "/", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send_dav(addr, "PROPFIND", "/", Some(&auth), &[("Depth", "1")], b"")
            .await
            .0,
        StatusCode::MULTI_STATUS
    );
    let (status, _, body) = send_dav(addr, "GET", "/readme.txt", Some(&auth), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"read-only-content");

    // All write methods are rejected with 403 Forbidden.
    assert_eq!(
        send_dav(addr, "PUT", "/new.txt", Some(&auth), &[], b"nope")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_dav(addr, "MKCOL", "/newdir", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_dav(addr, "DELETE", "/readme.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_dav(
            addr,
            "MOVE",
            "/readme.txt",
            Some(&auth),
            &[("Destination", "/moved.txt")],
            b""
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_dav(
            addr,
            "COPY",
            "/readme.txt",
            Some(&auth),
            &[("Destination", "/copied.txt")],
            b""
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_dav(addr, "PROPPATCH", "/readme.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_dav(addr, "LOCK", "/readme.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    rt.stop().await;
}

#[tokio::test]
async fn webdav_methods_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let dir = tmp.path().join("rw");
    std::fs::create_dir_all(&dir).unwrap();

    let shared = make_shared_store(cfg, None);
    let settings = Settings {
        users: vec![LocalUser {
            name: "admin".to_string(),
            password: hash_password("pw123456", 4).unwrap(),
            root: dir.to_string_lossy().into_owned(),
            read_only: false,
            ..LocalUser::default()
        }],
        ..Settings::default()
    };
    let (rt, addr) = start_runtime(settings, shared, RuntimeTimeouts::default()).await;
    let auth = basic_auth("admin", "pw123456");

    // OPTIONS advertises DAV 1, 2.
    let (status, headers, _) = send_dav(addr, "OPTIONS", "/", Some(&auth), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("dav").unwrap(), "1, 2");

    // MKCOL creates directory.
    assert_eq!(
        send_dav(addr, "MKCOL", "/docs", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::CREATED
    );

    // PUT creates file.
    assert_eq!(
        send_dav(
            addr,
            "PUT",
            "/docs/hello.txt",
            Some(&auth),
            &[],
            b"0123456789abcdef"
        )
        .await
        .0,
        StatusCode::CREATED
    );

    // GET full + Range + HEAD.
    let (status, _, body) = send_dav(addr, "GET", "/docs/hello.txt", Some(&auth), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"0123456789abcdef");

    let (status, headers, body) = send_dav(
        addr,
        "GET",
        "/docs/hello.txt",
        Some(&auth),
        &[("Range", "bytes=4-9")],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers.get("content-range").unwrap(), "bytes 4-9/16");
    assert_eq!(&body[..], b"456789");

    let (status, headers, body) =
        send_dav(addr, "HEAD", "/docs/hello.txt", Some(&auth), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("content-length").unwrap(), "16");
    assert!(body.is_empty());

    // PROPFIND Depth 0, 1, infinity.
    let (status, _, body) = send_dav(
        addr,
        "PROPFIND",
        "/",
        Some(&auth),
        &[("Depth", "infinity")],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let xml = String::from_utf8(body.to_vec()).unwrap();
    assert!(xml.contains("/docs/"));
    assert!(xml.contains("/docs/hello.txt"));

    // PROPPATCH.
    assert_eq!(
        send_dav(addr, "PROPPATCH", "/docs/hello.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::MULTI_STATUS
    );

    // COPY.
    assert_eq!(
        send_dav(
            addr,
            "COPY",
            "/docs/hello.txt",
            Some(&auth),
            &[("Destination", &format!("http://{addr}/docs/copy.txt"))],
            b""
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let (status, _, body) = send_dav(addr, "GET", "/docs/copy.txt", Some(&auth), &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"0123456789abcdef");

    // MOVE.
    assert_eq!(
        send_dav(
            addr,
            "MOVE",
            "/docs/copy.txt",
            Some(&auth),
            &[("Destination", "/docs/moved.txt")],
            b""
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        send_dav(addr, "GET", "/docs/copy.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send_dav(addr, "GET", "/docs/moved.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::OK
    );

    // LOCK -> blocks unauthenticated-token PUT with 423 -> allows PUT with If token -> UNLOCK.
    let (status, headers, body) = send_dav(
        addr,
        "LOCK",
        "/docs/moved.txt",
        Some(&auth),
        &[("Timeout", "Second-120")],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token_header = headers
        .get("lock-token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(token_header.contains("opaquelocktoken:"));
    assert!(String::from_utf8_lossy(&body).contains("opaquelocktoken:"));

    // PUT without If token gets 423 Locked.
    assert_eq!(
        send_dav(addr, "PUT", "/docs/moved.txt", Some(&auth), &[], b"blocked")
            .await
            .0,
        StatusCode::LOCKED
    );
    // PUT with matching If token succeeds with 204 No Content.
    let if_val = format!("({token_header})");
    assert_eq!(
        send_dav(
            addr,
            "PUT",
            "/docs/moved.txt",
            Some(&auth),
            &[("If", &if_val)],
            b"updated"
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    // UNLOCK releases lock.
    assert_eq!(
        send_dav(
            addr,
            "UNLOCK",
            "/docs/moved.txt",
            Some(&auth),
            &[("Lock-Token", &token_header)],
            b""
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );

    // DELETE removes file and directory.
    assert_eq!(
        send_dav(addr, "DELETE", "/docs/moved.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send_dav(addr, "DELETE", "/docs", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send_dav(addr, "GET", "/docs/hello.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    rt.stop().await;
}

#[tokio::test]
async fn webdav_multi_mount_root_readonly() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let m1 = tmp.path().join("mount_a");
    let m2 = tmp.path().join("mount_b");
    std::fs::create_dir_all(&m1).unwrap();
    std::fs::create_dir_all(&m2).unwrap();
    std::fs::write(m1.join("a.txt"), b"alpha-data").unwrap();

    let shared = make_shared_store(cfg, None);
    let settings = Settings {
        users: vec![LocalUser {
            name: "multi".to_string(),
            password: hash_password("multi-pw", 4).unwrap(),
            mounts: vec![
                Mount {
                    name: "media".to_string(),
                    path: m1,
                    read_only: false,
                },
                Mount {
                    name: "backup".to_string(),
                    path: m2,
                    read_only: false,
                },
            ],
            ..LocalUser::default()
        }],
        ..Settings::default()
    };
    let (rt, addr) = start_runtime(settings, shared, RuntimeTimeouts::default()).await;
    let auth = basic_auth("multi", "multi-pw");

    // Root PROPFIND lists both mount names.
    let (status, _, body) =
        send_dav(addr, "PROPFIND", "/", Some(&auth), &[("Depth", "1")], b"").await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let xml = String::from_utf8(body.to_vec()).unwrap();
    assert!(xml.contains("/media/"));
    assert!(xml.contains("/backup/"));

    // Virtual root itself is read-only.
    assert_eq!(
        send_dav(addr, "MKCOL", "/newmount", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send_dav(addr, "PUT", "/", Some(&auth), &[], b"x").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_dav(addr, "DELETE", "/media", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    // Cross-mount MOVE is forbidden.
    assert_eq!(
        send_dav(
            addr,
            "MOVE",
            "/media/a.txt",
            Some(&auth),
            &[("Destination", "/backup/a.txt")],
            b""
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    // Same-mount MOVE succeeds.
    assert_eq!(
        send_dav(
            addr,
            "MOVE",
            "/media/a.txt",
            Some(&auth),
            &[("Destination", "/media/b.txt")],
            b""
        )
        .await
        .0,
        StatusCode::CREATED
    );

    // Cross-mount COPY succeeds.
    assert_eq!(
        send_dav(
            addr,
            "COPY",
            "/media/b.txt",
            Some(&auth),
            &[("Destination", "/backup/b.txt")],
            b""
        )
        .await
        .0,
        StatusCode::CREATED
    );

    rt.stop().await;
}

#[tokio::test]
async fn webdav_idle_keepalive_2min() {
    // Verify WP-63 default timeout is exactly 2 minutes (120 seconds).
    assert_eq!(limits::IDLE_KEEPALIVE_TIMEOUT, Duration::from_secs(120));
    assert_eq!(
        RuntimeTimeouts::default().idle_keepalive,
        Duration::from_secs(120)
    );

    // Exercise live TCP keep-alive idle disconnect with fast test timeout.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let dir = tmp.path().join("dir");
    std::fs::create_dir_all(&dir).unwrap();
    let shared = make_shared_store(cfg, None);
    let settings = Settings {
        users: vec![LocalUser {
            name: "u".to_string(),
            password: hash_password("p", 4).unwrap(),
            root: dir.to_string_lossy().into_owned(),
            ..LocalUser::default()
        }],
        ..Settings::default()
    };
    let timeouts = RuntimeTimeouts {
        header_read: Duration::from_secs(5),
        idle_keepalive: Duration::from_millis(150),
        upload_body_idle: Duration::from_secs(5),
    };
    let (rt, addr) = start_runtime(settings, shared, timeouts).await;

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let auth = basic_auth("u", "p");
    let req = format!(
        "OPTIONS / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth}\r\nConnection: keep-alive\r\n\r\n"
    );
    tcp.write_all(req.as_bytes()).await.unwrap();

    // Read the 200 OK response headers.
    let mut buf = [0u8; 1024];
    let n = tcp.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 OK"));

    // Stay idle: server closes the keep-alive socket after ~150ms.
    let mut eof_buf = [0u8; 16];
    let read_res = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut eof_buf))
        .await
        .expect("idle keep-alive connection must close before 2s");
    assert_eq!(read_res.unwrap(), 0, "expected clean EOF on idle timeout");

    rt.stop().await;
}

#[tokio::test]
async fn webdav_upload_idle_2min() {
    // Verify WP-63 default upload body idle timeout is exactly 2 minutes.
    assert_eq!(limits::UPLOAD_BODY_IDLE_TIMEOUT, Duration::from_secs(120));
    assert_eq!(limits::HEADER_READ_TIMEOUT, Duration::from_secs(30));

    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let dir = tmp.path().join("up");
    std::fs::create_dir_all(&dir).unwrap();
    let shared = make_shared_store(cfg, None);
    let settings = Settings {
        users: vec![LocalUser {
            name: "u".to_string(),
            password: hash_password("p", 4).unwrap(),
            root: dir.to_string_lossy().into_owned(),
            ..LocalUser::default()
        }],
        ..Settings::default()
    };
    let timeouts = RuntimeTimeouts {
        header_read: Duration::from_secs(5),
        idle_keepalive: Duration::from_millis(120),
        upload_body_idle: Duration::from_millis(150),
    };
    let (rt, addr) = start_runtime(settings, shared, timeouts).await;
    let auth = basic_auth("u", "p");

    // 1. Stalled upload disconnects with 408 Request Timeout and cleans up partial file.
    {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let headers = format!(
            "PUT /stalled.bin HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth}\r\nContent-Length: 100\r\n\r\nhello"
        );
        tcp.write_all(headers.as_bytes()).await.unwrap();
        let mut resp_buf = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut resp_buf))
            .await
            .expect("stalled upload must time out")
            .unwrap();
        let text = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(text.starts_with("HTTP/1.1 408"), "got: {text}");
        assert!(!dir.join("stalled.bin").exists());
    }

    // 2. Slow steady upload (total duration > upload_body_idle & > idle_keepalive) SUCCEEDS!
    {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let chunks = 6usize;
        let payload_len = chunks * 4;
        let headers = format!(
            "PUT /steady.bin HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth}\r\nContent-Length: {payload_len}\r\n\r\n"
        );
        tcp.write_all(headers.as_bytes()).await.unwrap();
        for _ in 0..chunks {
            tokio::time::sleep(Duration::from_millis(60)).await;
            tcp.write_all(b"abcd").await.unwrap();
        }
        let mut resp_buf = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut resp_buf))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(text.starts_with("HTTP/1.1 201"), "got: {text}");
        assert_eq!(
            std::fs::read(dir.join("steady.bin")).unwrap().len(),
            payload_len
        );
    }

    rt.stop().await;
}

#[tokio::test]
async fn webdav_429_after_throttle() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let dir = tmp.path().join("share");
    std::fs::create_dir_all(&dir).unwrap();

    let bus = EventBus::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let _sub = bus
        .subscribe(move |ev| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(ev).await;
            }
        })
        .unwrap();

    let shared = make_shared_store(cfg, Some(bus));
    let settings = Settings {
        users: vec![LocalUser {
            name: "alice".to_string(),
            password: hash_password("good-pw", 4).unwrap(),
            root: dir.to_string_lossy().into_owned(),
            ..LocalUser::default()
        }],
        ..Settings::default()
    };
    let (rt, addr) = start_runtime(settings, shared, RuntimeTimeouts::default()).await;

    // 10 failed attempts -> 401.
    for _ in 0..10 {
        let (status, _, _) = send_dav(
            addr,
            "OPTIONS",
            "/",
            Some(&basic_auth("alice", "bad-pw")),
            &[],
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // 11th attempt MUST return 429 even with the correct password!
    let (status, _, _) = send_dav(
        addr,
        "OPTIONS",
        "/",
        Some(&basic_auth("alice", "good-pw")),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Event reporter throttled the 10 rapid failures into a single `fileauth.failed` event.
    let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev.kind, fg_core::events::Kind::FileAuthFailed);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(rx.try_recv().is_err(), "expected 5s event throttling");

    rt.stop().await;
}

#[tokio::test]
async fn webdav_401_challenge_not_counted() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let dir = tmp.path().join("share");
    std::fs::create_dir_all(&dir).unwrap();

    let shared = make_shared_store(cfg, None);
    let settings = Settings {
        users: vec![LocalUser {
            name: "alice".to_string(),
            password: hash_password("good-pw", 4).unwrap(),
            root: dir.to_string_lossy().into_owned(),
            ..LocalUser::default()
        }],
        ..Settings::default()
    };
    let (rt, addr) = start_runtime(settings, shared, RuntimeTimeouts::default()).await;

    // 15 unauthenticated requests (no Authorization header) must NOT trigger throttle.
    for _ in 0..15 {
        let (status, headers, _) = send_dav(addr, "OPTIONS", "/", None, &[], b"").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.contains_key("www-authenticate"));
    }

    // Subsequent authenticated request succeeds immediately.
    let (status, _, _) = send_dav(
        addr,
        "OPTIONS",
        "/",
        Some(&basic_auth("alice", "good-pw")),
        &[],
        b"",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    rt.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn webdav_hides_config_dir_and_blocks_outside_symlink() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let outside = tmp.path().join("outside");
    let vol = tmp.path().join("vol");
    let inner_cfg = vol.join("secret-config");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&inner_cfg).unwrap();
    std::fs::write(outside.join("leak.txt"), b"outside").unwrap();
    std::fs::write(inner_cfg.join("token.json"), b"admin-secret").unwrap();
    std::fs::write(vol.join("ok.txt"), b"ok").unwrap();
    symlink(outside.join("leak.txt"), vol.join("escape.txt")).unwrap();
    fsperm::protect(&inner_cfg);

    let shared = make_shared_store(cfg, None);
    let settings = Settings {
        users: vec![LocalUser {
            name: "u".to_string(),
            password: hash_password("p", 4).unwrap(),
            root: vol.to_string_lossy().into_owned(),
            ..LocalUser::default()
        }],
        ..Settings::default()
    };
    let (rt, addr) = start_runtime(settings, shared, RuntimeTimeouts::default()).await;
    let auth = basic_auth("u", "p");

    let (status, _, body) =
        send_dav(addr, "PROPFIND", "/", Some(&auth), &[("Depth", "1")], b"").await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let xml = String::from_utf8(body.to_vec()).unwrap();
    assert!(xml.contains("ok.txt"));
    assert!(!xml.contains("secret-config"));
    assert!(!xml.contains("escape.txt"));

    assert_eq!(
        send_dav(
            addr,
            "GET",
            "/secret-config/token.json",
            Some(&auth),
            &[],
            b""
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send_dav(addr, "GET", "/escape.txt", Some(&auth), &[], b"")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_dav(addr, "PUT", "/escape.txt", Some(&auth), &[], b"x")
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    rt.stop().await;
}

#[tokio::test]
async fn webdav_tls_sni_listener() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let dir = tmp.path().join("tls_share");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tls.txt"), b"over-tls").unwrap();

    // Generate self-signed cert via rcgen and wrap in a ResolvesServerCert.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let certified_key = Arc::new(
        rustls::sign::CertifiedKey::from_der(vec![cert_der.clone()], key_der, &provider).unwrap(),
    );

    #[derive(Debug)]
    struct StaticResolver(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for StaticResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    let shared = make_shared_store(cfg, None);
    let settings = Settings {
        enable: true,
        listen_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: 0,
        tls: true,
        users: vec![LocalUser {
            name: "u".to_string(),
            password: hash_password("p", 4).unwrap(),
            root: dir.to_string_lossy().into_owned(),
            ..LocalUser::default()
        }],
        ..Settings::default()
    };

    let rt = WebDavRuntime::new(
        settings.clone(),
        shared,
        Some(Arc::new(StaticResolver(certified_key))),
        None,
        RuntimeTimeouts::default(),
    );
    rt.apply(settings).await.unwrap();
    let addr = rt.bound_addr().unwrap();

    // Connect with tokio-rustls trusting our self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method(Method::GET)
        .uri("/tls.txt")
        .header("host", "localhost")
        .header("authorization", basic_auth("u", "p"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"over-tls");

    rt.stop().await;
}

#[tokio::test]
async fn webdav_and_fileusers_management_routes() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let share = tmp.path().join("share");
    std::fs::create_dir_all(&share).unwrap();

    let open_ports = OpenPorts::new();
    let shared = make_shared_store(cfg.clone(), None);
    let mut deps = Deps::new(Arc::clone(&shared));
    deps.open_ports = Some(Arc::clone(&open_ports));
    deps.bcrypt_cost = 4;

    let module = Module::new(cfg, deps).unwrap();
    let app: Router = module.mount_with_fileusers(Router::new());

    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let api_task = tokio::spawn(async move {
        let _ = axum::serve(api_listener, app).await;
    });

    // PUT /api/fileusers creates a shared user.
    let payload = serde_json::json!({
        "selfServicePassword": true,
        "users": [{
            "name": "suser",
            "password": "shared-secret",
            "root": share.to_string_lossy(),
            "readOnly": false
        }]
    })
    .to_string();
    let (status, _, _) = send_dav(
        api_addr,
        "PUT",
        "/api/fileusers",
        None,
        &[("content-type", "application/json")],
        payload.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // GET /api/fileusers returns masked password `********`.
    let (status, _, body) = send_dav(api_addr, "GET", "/api/fileusers", None, &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["users"][0]["password"], PASSWORD_MASK);

    // GET /api/fileusers/secrets returns stored hash.
    let (status, _, body) =
        send_dav(api_addr, "GET", "/api/fileusers/secrets", None, &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    let sec: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(sec["users"][0]["hashed"], true);
    assert_ne!(sec["users"][0]["password"], PASSWORD_MASK);

    // PUT /api/webdav/settings enables WebDAV using ONLY sharedUsers (0 local users).
    let free_port = pick_free_port();
    let webdav_payload = serde_json::json!({
        "enable": true,
        "listenIp": "127.0.0.1",
        "port": free_port,
        "tls": false,
        "users": [],
        "sharedUsers": true
    })
    .to_string();
    let (status, _, _) = send_dav(
        api_addr,
        "PUT",
        "/api/webdav/settings",
        None,
        &[("content-type", "application/json")],
        webdav_payload.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(open_ports.is_open(Proto::Tcp, free_port));

    // GET /api/webdav/status shows running=true.
    let (status, _, body) = send_dav(api_addr, "GET", "/api/webdav/status", None, &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    let st: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(st["running"], true);

    // Deleting all shared users while WebDAV depends on them MUST fail (400).
    let (status, _, _) = send_dav(
        api_addr,
        "PUT",
        "/api/fileusers",
        None,
        &[("content-type", "application/json")],
        br#"{"users":[],"selfServicePassword":false}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // GET /api/fileusers now shows `webdav` in `services`.
    let (status, _, body) = send_dav(api_addr, "GET", "/api/fileusers", None, &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["users"][0]["services"], serde_json::json!(["webdav"]));

    // Deprecated alias GET /api/webdav/shared-users returns the same list.
    let (status, _, body) =
        send_dav(api_addr, "GET", "/api/webdav/shared-users", None, &[], b"").await;
    assert_eq!(status, StatusCode::OK);
    let alias: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(alias["users"][0]["name"], "suser");

    // POST /api/webdav/restart succeeds.
    let (status, _, _) = send_dav(api_addr, "POST", "/api/webdav/restart", None, &[], b"").await;
    assert_eq!(status, StatusCode::OK);

    // Clean up listeners.
    module.runtime().stop().await;
    api_task.abort();
    assert!(!open_ports.is_open(Proto::Tcp, free_port));
    let _ = Path::new(".");
}

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}
