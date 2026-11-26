use std::{fs, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode},
};
use fg_admin::{ApiError, ApiRouter, Collection, CollectionPaths, Principal};
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
                .header("host", "admin.test")
                .header("connection", "close");
            for (key, value) in headers {
                request = request.header(*key, *value);
            }
            let response = sender.send_request(request.body(body.into())?).await?;
            let (parts, body) = response.into_parts();
            let bytes = body.collect().await?.to_bytes();
            let value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes)?
            };
            Ok((parts.status, parts.headers, value))
        })
        .await?
    }
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
}

fn attach_collection(router: ApiRouter, store: Arc<ConfigStore>) -> Result<Router> {
    let collection = Collection::<Rule>::open(
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
        |row| json!({"key":row.key,"name":row.name}),
    )?;
    Ok(collection
        .register(
            router,
            CollectionPaths {
                list: "/api/ddns/rules",
                item: "/api/ddns/rules/{key}",
                batch_delete: "/api/ddns/rules/batch-delete",
            },
        )
        .finish()
        .router)
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
