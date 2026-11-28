//! SFTP, local filesystem manager, and archive security HTTP API tests (WP-61 §6).

use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use base64::Engine as _;
use fg_config::ConfigStore;
use fg_webterminal::WebTerminalHandle;
use fg_webterminal::model::{ConnKind, Connection, Settings, limits};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

async fn http_raw(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let payload = body.unwrap_or(&[]);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    if !payload.is_empty() {
        stream.write_all(payload).await.unwrap();
    }
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();

    let sep = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP header separator");
    let head = std::str::from_utf8(&resp[..sep]).unwrap();
    let body_bytes = resp[sep + 4..].to_vec();
    let mut lines = head.lines();
    let status_line = lines.next().unwrap();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    (StatusCode::from_u16(code).unwrap(), headers, body_bytes)
}

async fn req_json(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let bytes = body.map(|v| serde_json::to_vec(&v).unwrap());
    let (status, _, resp_bytes) = http_raw(addr, method, path, &[], bytes.as_deref()).await;
    let json = serde_json::from_slice(&resp_bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn setup_local_sftp() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<WebTerminalHandle>,
    SocketAddr,
) {
    let cfg_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(cfg_dir.path()).unwrap();
    let handle = WebTerminalHandle::open(store).unwrap();
    let app = handle.router();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Enable allowLocalShell first.
    let settings = Settings {
        allow_local_shell: true,
        ..Settings::default()
    };
    let (st, _) = req_json(
        addr,
        "PUT",
        "/api/webterminal/settings",
        Some(serde_json::to_value(&settings).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Create a local connection.
    let conn = Connection {
        key: "local0000001".into(),
        name: "local".into(),
        kind: ConnKind::Local,
        ..Connection::default()
    };
    let (st, _) = req_json(
        addr,
        "POST",
        "/api/webterminal/connections",
        Some(serde_json::to_value(&conn).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    (cfg_dir, work_dir, handle, addr)
}

#[tokio::test]
async fn sftp_ops_roundtrip() {
    let (_cfg, work, _handle, addr) = setup_local_sftp().await;
    let root = work.path().to_string_lossy().into_owned();

    // mkdir + touch + write + read
    let (st, _) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/mkdir",
        Some(json!({ "path": format!("{root}/alpha") })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/touch",
        Some(json!({ "path": format!("{root}/empty.txt") })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/write",
        Some(json!({ "path": format!("{root}/notes.txt"), "content": "hello ferrumgate" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // list -> dirs first!
    let (st, list) = req_json(
        addr,
        "GET",
        &format!("/api/webterminal/sftp/local0000001/list?path={root}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let arr = list.as_array().unwrap();
    assert_eq!(arr[0]["name"], "alpha");
    assert_eq!(arr[0]["isDir"], true);

    // read
    let (st, preview) = req_json(
        addr,
        "GET",
        &format!("/api/webterminal/sftp/local0000001/read?path={root}/notes.txt"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(preview["content"], "hello ferrumgate");

    // download with Range header -> 206 Partial Content
    let (dl_status, dl_headers, dl_bytes) = http_raw(
        addr,
        "GET",
        &format!("/api/webterminal/sftp/local0000001/download?path={root}/notes.txt"),
        &[("Range", "bytes=6-15")],
        None,
    )
    .await;
    assert_eq!(dl_status, StatusCode::PARTIAL_CONTENT);
    assert!(
        dl_headers
            .iter()
            .any(|(k, v)| k == "content-range" && v == "bytes 6-15/16")
    );
    assert_eq!(dl_bytes.as_slice(), b"ferrumgate");

    // upload preserving subdirectories
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"nested-data");
    let (st, up) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/upload",
        Some(json!({
            "dir": root,
            "files": [{ "path": "sub/nested.txt", "dataBase64": b64 }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(up["uploaded"], 1);
    assert_eq!(
        std::fs::read_to_string(work.path().join("sub/nested.txt")).unwrap(),
        "nested-data"
    );

    // copy into same dir -> auto-renames `notes 副本.txt` then `notes 副本 2.txt`
    let (st, cp1) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/copy",
        Some(json!({ "from": format!("{root}/notes.txt"), "toDir": root })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(cp1["path"].as_str().unwrap().ends_with("notes 副本.txt"));

    let (st, cp2) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/copy",
        Some(json!({ "from": format!("{root}/notes.txt"), "toDir": root })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(cp2["path"].as_str().unwrap().ends_with("notes 副本 2.txt"));

    // rename + chmod
    let (st, _) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/rename",
        Some(json!({ "from": format!("{root}/empty.txt"), "to": format!("{root}/renamed.txt") })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/chmod",
        Some(json!({ "path": format!("{root}/renamed.txt"), "mode": 0o600, "recursive": false })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // compress -> preview-archive -> decompress (zip)
    let zip_path = format!("{root}/pack.zip");
    let (st, _) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/compress",
        Some(json!({
            "paths": [format!("{root}/notes.txt"), format!("{root}/sub")],
            "dest": zip_path,
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, arch_prev) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/preview-archive",
        Some(json!({ "path": zip_path })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(arch_prev["truncated"], false);
    assert!(arch_prev["total"].as_u64().unwrap() >= 2);

    let unpack_dir = format!("{root}/unpacked");
    let (st, dec) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/decompress",
        Some(json!({ "path": zip_path, "destDir": unpack_dir })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(dec["extracted"].as_u64().unwrap() >= 2);
    assert_eq!(
        std::fs::read_to_string(work.path().join("unpacked/notes.txt")).unwrap(),
        "hello ferrumgate"
    );

    // remove file + directory
    let (st, _) = req_json(
        addr,
        "DELETE",
        "/api/webterminal/sftp/local0000001/remove",
        Some(json!({ "paths": [format!("{root}/renamed.txt"), unpack_dir] })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!work.path().join("renamed.txt").exists());
    assert!(!work.path().join("unpacked").exists());
}

#[tokio::test]
async fn sftp_root_protected_from_delete_and_read_over_1mb_413() {
    let (_cfg, work, _handle, addr) = setup_local_sftp().await;
    let big_path = work.path().join("huge.txt");
    std::fs::write(&big_path, vec![b'A'; limits::SFTP_PREVIEW_MAX_BYTES + 1]).unwrap();

    // > 1 MiB preview -> HTTP 413 Payload Too Large!
    let (st, _) = req_json(
        addr,
        "GET",
        &format!(
            "/api/webterminal/sftp/local0000001/read?path={}",
            big_path.display()
        ),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);

    // Deleting `/` -> HTTP 403 Forbidden!
    let (st, _) = req_json(
        addr,
        "DELETE",
        "/api/webterminal/sftp/local0000001/remove",
        Some(json!({ "paths": ["/"] })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Decompressing a zip-slip archive -> HTTP 400 Bad Request!
    let evil_zip = work.path().join("evil.zip");
    {
        let mut cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("../escape.txt", opts).unwrap();
        writer.write_all(b"pwn").unwrap();
        writer.finish().unwrap();
        std::fs::write(&evil_zip, cursor.into_inner()).unwrap();
    }
    let (st, _) = req_json(
        addr,
        "POST",
        "/api/webterminal/sftp/local0000001/decompress",
        Some(json!({
            "path": evil_zip.to_string_lossy(),
            "destDir": work.path().join("out").to_string_lossy(),
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(!work.path().join("escape.txt").exists());
}
