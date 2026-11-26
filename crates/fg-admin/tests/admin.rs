use std::{
    fs,
    io::{Read, Write},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::Extension,
    http::{HeaderMap, Method, Request, StatusCode},
};
use fg_admin::{
    ApiError, ApiRouter, Collection, CollectionPaths, ItemChange, Principal, ReadOnly, SECRET_MASK,
    StreamPolicy, keep_secret,
};
use fg_config::{ConfigStore, Loaded};
use fg_core::registry::Registry;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

#[path = "admin/compat.rs"]
mod compat;
#[path = "admin/models.rs"]
mod models;
#[path = "admin/transport.rs"]
mod transport;

struct Server {
    listen: std::net::SocketAddr,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(router: Router) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen = listener.local_addr()?;
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Ok(Self { listen, task })
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: impl Into<Body>,
    ) -> Result<(StatusCode, HeaderMap, Value)> {
        let (status, headers, bytes) = self.call_raw(method, path, headers, body).await?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok((status, headers, value))
    }

    async fn call_raw(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: impl Into<Body>,
    ) -> Result<(StatusCode, HeaderMap, Bytes)> {
        timeout(Duration::from_secs(5), async {
            let stream = TcpStream::connect(self.listen).await?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("host", "admin.test");
            for (key, value) in headers {
                request = request.header(*key, *value);
            }
            let response = sender.send_request(request.body(body.into())?).await?;
            let (parts, body) = response.into_parts();
            let bytes = body.collect().await?.to_bytes();
            Ok((parts.status, parts.headers, bytes))
        })
        .await?
    }
}

#[tokio::test]
async fn response_redacts_before_gzip_and_preserves_writer_values() -> Result<()> {
    let value = json!({
        "privateKey":"fixture-private-key",
        "passwordEnabled":true, "hasPassword":true, "emptySecret":"",
        "requestHeaders":["Authorization: fixture-header","X-Empty:","malformed-authorization"],
        "responseHeaders":{"Set-Cookie":"fixture-cookie"},
        "extraArgs":["--flag=fixture-argument"],
        "daemonEnv":"SECRET=fixture-env\nmalformed-env\nEMPTY=",
        "users":["alice:fixture-password", {"apiKey":"fixture-api-key"}],
        "credentials":{"extra":{"zone":"fixture-extra","endpoint":"https://dns.test/?secret=fixture-dns"},"EXTRA":{"zone":"fixture-extra-2"}},
        "nested":{"token":["fixture-array-token"],"credentials":[{"extra":{"key":"fixture-array-extra"}}]},
        "template":{"method":"POST","body":{"text":"fixture-body","numeric":12345}},
        "summary":{"body":"preserve explanatory body"},
        "error":"see https://ui:fixture-url@example.test/docs/%61bcDEF0123456789/?key=fixture-query&bare-fixture#fixture-fragment for details",
        "ordinary":"https://example.test/docs",
        "largeInteger":u128::MAX,
        "padding":"x".repeat(4096),
    });
    let payload = value.clone();
    let server = Server::start(
        ApiRouter::new(principal)
            .route(
                Method::GET,
                "/api/ddns/example",
                "Example",
                move || async move {
                    (
                        [
                            ("vary", "Accept-Language"),
                            ("etag", "\"original\""),
                            ("content-digest", "original"),
                        ],
                        Json(payload),
                    )
                },
            )
            .finish()
            .router,
    )
    .await?;
    let path = "/api/ddns/example";
    let (status, headers, compressed) = server
        .call_raw(
            "GET",
            path,
            &[("x-test-id", "viewer"), ("accept-encoding", "gzip")],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-encoding"], "gzip");
    assert_eq!(
        headers["content-length"].to_str()?.parse::<usize>()?,
        compressed.len()
    );
    assert!(
        headers
            .get_all("vary")
            .iter()
            .any(|entry| entry == "Accept-Language")
    );
    assert!(
        headers
            .get_all("vary")
            .iter()
            .any(|entry| entry == "Accept-Encoding")
    );
    assert!(headers.get("etag").is_none());
    assert!(headers.get("content-digest").is_none());
    let mut json = String::new();
    flate2::read::GzDecoder::new(compressed.as_ref()).read_to_string(&mut json)?;
    for forbidden in [
        "fixture-",
        "malformed-",
        "%61bcDEF0123456789",
        "bare-fixture",
        "12345\"}",
    ] {
        assert!(!json.contains(forbidden), "response leaked {forbidden}");
    }
    let masked: Value = serde_json::from_str(&json)?;
    assert_eq!(masked["privateKey"], SECRET_MASK);
    assert_eq!(masked["passwordEnabled"], true);
    assert_eq!(masked["hasPassword"], true);
    assert_eq!(masked["emptySecret"], "");
    assert_eq!(
        masked["requestHeaders"],
        json!(["Authorization: ********", "X-Empty:", SECRET_MASK])
    );
    assert_eq!(masked["responseHeaders"], json!({"Set-Cookie":SECRET_MASK}));
    assert_eq!(masked["daemonEnv"], "SECRET=********\n********\nEMPTY=");
    assert_eq!(masked["users"][0], "alice:********");
    assert_eq!(masked["credentials"]["EXTRA"]["zone"], SECRET_MASK);
    assert_eq!(masked["nested"]["token"][0], SECRET_MASK);
    assert_eq!(
        masked["nested"]["credentials"][0]["extra"]["key"],
        SECRET_MASK
    );
    assert_eq!(masked["template"]["body"]["numeric"], SECRET_MASK);
    assert_eq!(masked["summary"]["body"], "preserve explanatory body");
    assert!(
        masked["error"]
            .as_str()
            .unwrap()
            .starts_with("see https://ui:********@example.test/docs/********/?key=")
    );
    assert_eq!(masked["ordinary"], "https://example.test/docs");
    assert_eq!(masked["largeInteger"], value["largeInteger"]);
    let (_, headers, token) = server
        .call(
            "GET",
            path,
            &[
                ("x-test-id", "token"),
                ("accept-encoding", "*;q=0.8, gzip;q=0"),
            ],
            Body::empty(),
        )
        .await?;
    assert!(headers.get("content-encoding").is_none());
    assert_eq!(token, masked);
    for id in ["writer", "admin"] {
        let (_, headers, original) = server
            .call("GET", path, &[("x-test-id", id)], Body::empty())
            .await?;
        assert_eq!(original, value);
        assert_eq!(headers["etag"], "\"original\"");
    }
    Ok(())
}

#[tokio::test]
async fn response_rejects_unsafe_buffered_json_and_honors_stream_policies() -> Result<()> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(br#"{"secret":"fixture-encoded-secret"}"#)?;
    let encoded = Bytes::from(encoder.finish()?);
    let body = encoded.clone();
    let admin = ApiRouter::new(principal)
        .route(
            Method::GET,
            "/api/ddns/encoded",
            "Encoded JSON",
            move || async move {
                (
                    [
                        ("content-type", "application/json"),
                        ("content-encoding", "gzip"),
                    ],
                    body,
                )
            },
        )
        .route(
            Method::GET,
            "/api/ddns/malformed",
            "Malformed JSON",
            || async {
                (
                    [("content-type", "application/problem+json")],
                    "fixture-corrupt-secret",
                )
            },
        )
        .route(Method::GET, "/api/ddns/large", "Oversized JSON", || async {
            Json(json!({"secret":"x".repeat(8 << 20)}))
        })
        .stream_route(
            Method::GET,
            "/api/ddns/events",
            "Filtered event stream",
            StreamPolicy::ReadOnlySafe,
            |Extension(read_only): Extension<ReadOnly>| async move {
                let event = if read_only.0 {
                    "data: public event\n\n"
                } else {
                    "data: writer event\n\n"
                };
                ([("content-type", "text/event-stream")], event.repeat(100))
            },
        )
        .stream_route(
            Method::GET,
            "/api/ddns/archive",
            "Restricted download",
            StreamPolicy::WritersOnly,
            || async {
                (
                    [("content-type", "application/octet-stream")],
                    "fixture-download",
                )
            },
        )
        .finish();
    assert_eq!(
        admin.document()["paths"]["/api/ddns/events"]["get"]["x-stream"],
        true
    );
    assert_eq!(
        admin.document()["paths"]["/api/ddns/encoded"]["get"]["x-stream"],
        false
    );
    let server = Server::start(admin.router).await?;
    for endpoint in ["encoded", "malformed", "large"] {
        let (status, headers, value) = server
            .call(
                "GET",
                &format!("/api/ddns/{endpoint}"),
                &[("x-test-id", "viewer"), ("accept-encoding", "gzip")],
                Body::empty(),
            )
            .await?;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!headers.contains_key("content-encoding"));
        assert_eq!(value, json!({"error":"could not safely process response"}));
    }
    let (_, headers, original) = server
        .call_raw(
            "GET",
            "/api/ddns/encoded",
            &[("x-test-id", "writer"), ("accept-encoding", "gzip")],
            Body::empty(),
        )
        .await?;
    assert_eq!(headers["content-encoding"], "gzip");
    assert_eq!(original, encoded);
    let (status, headers, stream) = server
        .call_raw(
            "GET",
            "/api/ddns/events",
            &[("x-test-id", "token"), ("accept-encoding", "gzip")],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key("content-encoding"));
    assert_eq!(headers["content-type"], "text/event-stream");
    assert_eq!(stream, "data: public event\n\n".repeat(100));
    assert_eq!(
        server
            .call(
                "GET",
                "/api/ddns/archive",
                &[("x-test-id", "viewer")],
                Body::empty()
            )
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call_raw(
                "GET",
                "/api/ddns/archive",
                &[("x-test-id", "writer")],
                Body::empty()
            )
            .await?
            .2,
        "fixture-download"
    );
    Ok(())
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

const EDIT: [(&str, &str); 2] = [
    ("x-test-id", "admin"),
    ("content-type", "application/json; charset=utf-8"),
];

// Credentials in this fixture are consumed only by the test listener.
fn principal(headers: &HeaderMap) -> Option<Principal> {
    match headers.get("x-test-id")?.to_str().ok()? {
        "admin" => Some(Principal::Session { read_only: false }),
        "viewer" => Some(Principal::Session { read_only: true }),
        "token" => Some(Principal::Token {
            scopes: vec!["ddns:read".into()],
        }),
        "writer" => Some(Principal::Token {
            scopes: vec!["ddns:write".into()],
        }),
        _ => None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(default)]
    key: String,
    name: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    group: String,
}

const RULES: CollectionPaths = CollectionPaths {
    list: "/api/ddns/rules",
    item: "/api/ddns/rules/{key}",
    batch_delete: "/api/ddns/rules/batch-delete",
};

fn open_collection(store: Arc<ConfigStore>) -> Result<Collection<Rule>> {
    Collection::<Rule>::open(
        store,
        "ddns",
        8,
        |row| &row.key,
        |row, key| row.key = key,
        |row| {
            row.name = row.name.trim().to_owned();
            if row.name.is_empty() {
                return Err(ApiError::new(StatusCode::BAD_REQUEST, "name is required"));
            }
            Ok(())
        },
        |row| json!({"key":row.key,"name":row.name,"enable":row.enabled,"group":row.group}),
    )
}

fn attach_collection(router: ApiRouter, store: Arc<ConfigStore>) -> Result<Router> {
    Ok(open_collection(store)?
        .register(router, RULES)
        .finish()
        .router)
}

fn rule(key: &str, name: &str) -> Rule {
    Rule {
        key: key.into(),
        name: name.into(),
        secret: format!("test-secret-{key}"),
        enabled: false,
        group: String::new(),
    }
}

#[tokio::test]
async fn collection_batches_validate_once_publish_once_and_notify_in_request_order() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    store.save(
        "ddns",
        &vec![
            rule("a", "exclusive"),
            rule("b", "exclusive"),
            rule("c", "pinned"),
        ],
    )?;
    store.enable_history(20, &[]);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let events = observed.clone();
    let collection = open_collection(store.clone())?
        .enabled(|row| &mut row.enabled)
        .group(|row| &mut row.group)
        .check_enable(|rows, _| {
            if rows
                .iter()
                .filter(|row| row.name == "exclusive" && row.enabled)
                .count()
                > 1
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "exclusive items cannot run together",
                ));
            }
            Ok(())
        })
        .before_remove(|rows, indices| {
            if indices.iter().any(|&index| rows[index].name == "pinned") {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "item is still referenced",
                ));
            }
            Ok(())
        })
        .on_change(move |change, key| events.lock().unwrap().push((change, key.to_owned())));
    let admin = collection
        .register(ApiRouter::new(principal), RULES)
        .finish();
    assert_eq!(
        admin.document()["paths"]["/api/ddns/rules-enable"]["put"]["x-required-scope"],
        "ddns:write"
    );
    assert!(admin.document()["paths"]["/api/ddns/rules-group"]["put"].is_object());
    let server = Server::start(admin.router).await?;
    let enable = "/api/ddns/rules-enable";
    let before = store.load_raw("ddns")?;
    for (keys, status) in [
        (r#"["a","b"]"#, StatusCode::CONFLICT),
        (r#"["a","missing"]"#, StatusCode::NOT_FOUND),
    ] {
        let body = format!(r#"{{"keys":{keys},"enable":true}}"#);
        assert_eq!(server.call("PUT", enable, &EDIT, body).await?.0, status);
    }
    assert_eq!(store.load_raw("ddns")?, before);
    assert!(store.versions("ddns")?.is_empty());
    assert!(observed.lock().unwrap().is_empty());

    let batch = r#"{"keys":["c","a","a"],"enable":true}"#;
    assert_eq!(
        server.call("PUT", enable, &EDIT, batch).await?.2,
        json!({"changed":2})
    );
    assert_eq!(store.versions("ddns")?.len(), 1);
    assert_eq!(
        server.call("PUT", enable, &EDIT, batch).await?.2,
        json!({"changed":0})
    );
    assert_eq!(store.versions("ddns")?.len(), 1);
    assert_eq!(
        server
            .call(
                "PUT",
                "/api/ddns/rules/c/enable",
                &EDIT,
                r#"{"enable":false}"#
            )
            .await?
            .2,
        json!({"ok":true})
    );
    assert_eq!(
        observed.lock().unwrap().as_slice(),
        &[
            (ItemChange::Updated, "c".into()),
            (ItemChange::Updated, "a".into()),
            (ItemChange::Updated, "c".into())
        ]
    );

    let order = "/api/ddns/rules-order";
    assert_eq!(
        server
            .call("PUT", order, &EDIT, r#"{"keys":["c","c","a"]}"#)
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        server
            .call("PUT", order, &EDIT, r#"{"keys":["c","a","b"]}"#)
            .await?
            .0,
        StatusCode::OK
    );
    let group = "/api/ddns/rules-group";
    let grouped = r#"{"keys":["b","a","a"],"group":"  東區  "}"#;
    assert_eq!(
        server.call("PUT", group, &EDIT, grouped).await?.0,
        StatusCode::OK
    );
    assert_eq!(
        server.call("PUT", group, &EDIT, grouped).await?.0,
        StatusCode::OK
    );
    let too_long = json!({"keys":["a"],"group":"長".repeat(65)}).to_string();
    assert_eq!(
        server.call("PUT", group, &EDIT, too_long).await?.0,
        StatusCode::BAD_REQUEST
    );

    let Loaded::Found(rows) = store.load::<Vec<Rule>>("ddns")? else {
        panic!("persisted collection")
    };
    assert_eq!(
        rows.iter()
            .map(|row| (row.key.as_str(), row.group.as_str(), row.enabled))
            .collect::<Vec<_>>(),
        [("c", "", false), ("a", "東區", true), ("b", "東區", false)]
    );
    assert_eq!(store.versions("ddns")?.len(), 4);
    assert_eq!(observed.lock().unwrap().len(), 3);
    let delete = "/api/ddns/rules-delete";
    assert_eq!(
        server
            .call("POST", delete, &EDIT, r#"{"keys":["a","c"]}"#)
            .await?
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(store.versions("ddns")?.len(), 4);

    let path = store.dir().join("ddns.json");
    let saved = store.dir().join("original");
    fs::rename(&path, &saved)?;
    fs::create_dir(&path)?;
    assert_eq!(
        server
            .call("PUT", enable, &EDIT, r#"{"keys":["a"],"enable":false}"#)
            .await?
            .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(observed.lock().unwrap().len(), 3);
    let listed = server
        .call("GET", "/api/ddns/rules", &EDIT, Body::empty())
        .await?
        .2;
    assert_eq!(listed[1]["enable"], true);
    fs::remove_dir(&path)?;
    fs::rename(&saved, &path)?;

    assert_eq!(
        server
            .call("POST", delete, &EDIT, r#"{"keys":["b","a","a"]}"#)
            .await?
            .2,
        json!({"deleted":2})
    );
    assert_eq!(store.versions("ddns")?.len(), 5);
    assert_eq!(
        observed.lock().unwrap()[3..],
        [
            (ItemChange::Removed, "b".into()),
            (ItemChange::Removed, "a".into())
        ]
    );
    Ok(())
}

#[tokio::test]
async fn collection_copy_and_secret_reads_share_the_unlocked_privilege_guard() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    store.save(
        "ddns",
        &vec![rule("template", "template"), rule("tail", "tail")],
    )?;
    let collection = open_collection(store.clone())?
        .copy_with(|source, target| {
            keep_secret(&source.secret, &mut target.secret);
            Ok(())
        })
        .merge_with(|source, target| {
            keep_secret(&source.secret, &mut target.secret);
            Ok(())
        })
        .check(|rows, indices| {
            let row = &rows[indices[0]];
            if rows.iter().filter(|other| other.name == row.name).count() > 1 {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "item name already used",
                ));
            }
            Ok(())
        })
        .secrets(|row| [("secret".to_owned(), row.secret.clone())].into())
        .secrets_guard(|headers| {
            if headers
                .get("x-test-proof")
                .is_some_and(|proof| proof == "verified")
            {
                Ok(())
            } else {
                Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "secret proof required",
                ))
            }
        });
    let admin = collection
        .register(ApiRouter::new(principal), RULES)
        .finish();
    assert_eq!(
        admin.document()["paths"]["/api/ddns/rules/{key}/secrets"]["get"]["x-required-scope"],
        "ddns:write"
    );
    let server = Server::start(admin.router).await?;
    let copy = json!({"key":"caller-key","name":" copy ","secret":SECRET_MASK}).to_string();
    assert_eq!(
        server
            .call("POST", "/api/ddns/rules/missing/copy", &EDIT, copy.clone())
            .await?
            .2,
        json!({"error":"secret proof required"})
    );
    assert_eq!(
        server
            .call(
                "GET",
                "/api/ddns/rules/missing/secrets",
                &EDIT,
                Body::empty()
            )
            .await?
            .2,
        json!({"error":"secret proof required"})
    );

    let verified = [EDIT[0], EDIT[1], ("x-test-proof", "verified")];
    let before = store.load_raw("ddns")?;
    let duplicate = json!({"key":"tail","name":"tail","secret":SECRET_MASK}).to_string();
    assert_eq!(
        server
            .call(
                "POST",
                "/api/ddns/rules/template/copy",
                &verified,
                duplicate
            )
            .await?
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(store.load_raw("ddns")?, before);
    let (status, _, copied) = server
        .call("POST", "/api/ddns/rules/template/copy", &verified, copy)
        .await?;
    assert_eq!(status, StatusCode::OK);
    let key = copied["key"].as_str().unwrap();
    assert_ne!(key, "caller-key");
    assert!(key.len() == 12 && key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(copied["name"], "copy");
    assert!(!copied.to_string().contains("test-secret-template"));
    let secret_route = format!("/api/ddns/rules/{key}/secrets");
    for user in ["token", "viewer"] {
        assert_eq!(
            server
                .call(
                    "GET",
                    &secret_route,
                    &[("x-test-id", user), ("x-test-proof", "verified")],
                    Body::empty()
                )
                .await?
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let secret = server
        .call(
            "GET",
            &secret_route,
            &[("x-test-id", "writer"), ("x-test-proof", "verified")],
            Body::empty(),
        )
        .await?;
    assert_eq!(secret.2, json!({"secret":"test-secret-template"}));
    assert_eq!(secret.1["cache-control"], "no-store");
    let change = json!({"name":"updated","secret":SECRET_MASK}).to_string();
    assert_eq!(
        server
            .call("PUT", &format!("/api/ddns/rules/{key}"), &EDIT, change)
            .await?
            .0,
        StatusCode::OK
    );

    let Loaded::Found(rows) = store.load::<Vec<Rule>>("ddns")? else {
        panic!("persisted collection")
    };
    assert_eq!(
        rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
        ["template", key, "tail"]
    );
    assert_eq!(rows[1].name, "updated");
    assert_eq!(rows[1].secret, "test-secret-template");
    Ok(())
}

#[tokio::test]
async fn network_writes_persist_one_snapshot_and_reject_a_failed_batch() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    let server =
        Server::start(attach_collection(ApiRouter::new(principal), store.clone())?).await?;
    let add = |key: &str| json!({"key":key,"name":"  rule  ","secret":"test-secret"}).to_string();
    let (_, _, first) = server
        .call("POST", "/api/ddns/rules", &EDIT, add(""))
        .await?;
    let first = first["key"].as_str().unwrap();
    assert!(first.len() == 12 && first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        server
            .call("POST", "/api/ddns/rules", &EDIT, add("second"))
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .call(
                "PUT",
                &format!("/api/ddns/rules/{first}"),
                &EDIT,
                add("ignored")
            )
            .await?
            .2["key"],
        first
    );
    let all = server
        .call(
            "GET",
            "/api/ddns/rules",
            &[("x-test-id", "token")],
            Body::empty(),
        )
        .await?
        .2;
    assert_eq!(all.as_array().unwrap().len(), 2);
    assert!(!all.to_string().contains("test-secret"));
    let before = store.load_raw("ddns")?;
    let missing = json!({"keys":[first,"missing"]}).to_string();
    assert_eq!(
        server
            .call("POST", "/api/ddns/rules/batch-delete", &EDIT, missing)
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(store.load_raw("ddns")?, before);
    assert_eq!(
        server
            .call("GET", "/api/ddns/rules", &EDIT, Body::empty())
            .await?
            .2,
        all
    );

    let path = store.dir().join("ddns.json");
    let saved = store.dir().join("saved");
    fs::rename(&path, &saved)?;
    fs::create_dir(&path)?;
    let failed = server
        .call(
            "DELETE",
            &format!("/api/ddns/rules/{first}"),
            &EDIT,
            Body::empty(),
        )
        .await?;
    assert_eq!(failed.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed.2, json!({"error":"configuration operation failed"}));
    assert_eq!(
        server
            .call("GET", "/api/ddns/rules", &EDIT, Body::empty())
            .await?
            .2,
        all
    );
    fs::remove_dir(&path)?;
    fs::rename(&saved, &path)?;
    let batch = json!({"keys":[first,"second","second"]}).to_string();
    assert_eq!(
        server
            .call("POST", "/api/ddns/rules/batch-delete", &EDIT, batch)
            .await?
            .2,
        json!({"removed":2})
    );
    assert!(matches!(store.load::<Vec<Rule>>("ddns")?, Loaded::Found(rows) if rows.is_empty()));
    Ok(())
}

#[tokio::test]
async fn boundary_checks_origin_credentials_and_body_before_writing() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    let server =
        Server::start(attach_collection(ApiRouter::new(principal), store.clone())?).await?;
    let path = "/api/ddns/rules";
    let rule = r#"{"name":"allowed"}"#;
    assert_eq!(
        server.call("POST", path, &[], rule).await?.0,
        StatusCode::UNAUTHORIZED
    );
    for id in ["viewer", "token"] {
        assert_eq!(
            server
                .call("POST", path, &[("x-test-id", id)], rule)
                .await?
                .0,
            StatusCode::FORBIDDEN
        );
    }
    for (header, value) in [
        ("origin", "https://other.test"),
        ("origin", "null"),
        ("sec-fetch-site", "cross-site"),
    ] {
        assert_eq!(
            server
                .call("POST", path, &[EDIT[0], EDIT[1], (header, value)], rule)
                .await?
                .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        server.call("POST", path, &[EDIT[0]], rule).await?.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        server
            .call(
                "POST",
                path,
                &[EDIT[0], ("content-type", "application/jsonp")],
                rule
            )
            .await?
            .0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    for invalid in ["", r#"{"name":"ignored","unknown":1}"#] {
        assert_eq!(
            server.call("POST", path, &EDIT, invalid).await?.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        server
            .call("POST", path, &EDIT, vec![b'x'; (4 << 20) + 1])
            .await?
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(store.load_raw("ddns")?.is_none());
    let (status, headers, _) = server
        .call(
            "POST",
            path,
            &[EDIT[0], EDIT[1], ("origin", "https://ADMIN.TEST")],
            rule,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["content-type"], "application/json; charset=utf-8");
    assert!(
        headers["content-security-policy"]
            .to_str()?
            .contains("default-src 'none'")
    );
    assert_eq!(
        server.call("PATCH", path, &EDIT, Body::empty()).await?.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    Ok(())
}

#[tokio::test]
async fn documentation_and_enforcement_share_the_registered_operations() -> Result<()> {
    let registry = Registry::new(&["ddns", "portforward"]);
    let enabled = registry.resolve_enabled(&["portforward".into()], false);
    let admin = ApiRouter::new(principal)
        .with_modules(registry, enabled)
        .route(
            Method::GET,
            "/api/ddns/rules/{key}/secrets",
            "Read secret",
            || async { Json(json!("test-only")) },
        )
        .route(
            Method::GET,
            "/api/portforward/rules",
            "Disabled test",
            || async { Json(json!("disabled")) },
        )
        .route(Method::GET, "/api/waf/config", "Absent test", || async {
            Json(json!("absent"))
        })
        .finish();
    let spec = admin.document().clone();
    assert_eq!(spec["openapi"], "3.0.3");
    let paths = spec["paths"].as_object().unwrap();
    assert_eq!(paths.len(), 2);
    let secrets = &paths["/api/ddns/rules/{key}/secrets"]["get"];
    assert_eq!(secrets["x-required-scope"], "ddns:write");
    assert_eq!(secrets["parameters"][0]["name"], "key");
    let server = Server::start(admin.router).await?;
    let protected = "/api/ddns/rules/abc/secrets";
    assert_eq!(
        server
            .call("GET", protected, &[("x-test-id", "token")], Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call("HEAD", protected, &[("x-test-id", "viewer")], Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call("GET", "/api/openapi.json", &[], Body::empty())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .call(
                "GET",
                "/api/openapi.json",
                &[("x-test-id", "token")],
                Body::empty()
            )
            .await?
            .2,
        spec
    );
    assert_eq!(
        server
            .call("POST", "/api/portforward/other", &EDIT, Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call("GET", "/api/waf/config", &EDIT, Body::empty())
            .await?
            .2,
        json!({"error":"module is not included in this build"})
    );
    Ok(())
}
