//! Renderer and validation integration tests (WP-66 §6 render column):
//! the config document externalUrl comes from the first access URL, the
//! password never lands in the file, and the collection contract holds
//! over real HTTP.

mod common;

use axum::body::Body;
use fg_filebrowser::{AuthMethod, Source};
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde_json::Value;

async fn app() -> (axum::Router, std::path::PathBuf) {
    let harness = common::harness();
    let config_dir = harness.store.dir().to_path_buf();
    let router = harness.module.mount(axum::Router::new());
    (router, config_dir)
}

async fn post_json(
    client: &Client<HttpConnector, Body>,
    url: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = client
        .request(
            hyper::Request::builder()
                .method(hyper::Method::POST)
                .uri(url)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("send");
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.expect("body").to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (parts.status, value)
}

async fn get_json(client: &Client<HttpConnector, Body>, url: &str) -> (StatusCode, Value) {
    let response = client
        .request(
            hyper::Request::builder()
                .method(hyper::Method::GET)
                .uri(url)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("send");
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.expect("body").to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (parts.status, value)
}

#[tokio::test]
async fn instance_api_creates_lists_and_masks_password() {
    let (router, config_dir) = app().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, router).await });
    let client: Client<HttpConnector, Body> = Client::builder(TokioExecutor::new()).build_http();

    let body = serde_json::json!({
        "name": "files",
        "accessUrls": ["https://files.example.com/"],
        "adminPassword": "long-admin-password",
        "sources": [{"path": config_dir.parent().unwrap().join("shares").display().to_string()}],
    });
    let (status, created) = post_json(
        &client,
        &format!("http://{addr}/api/filebrowser/instances"),
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let key = created["key"].as_str().expect("key").to_string();

    let (_, list) = get_json(&client, &format!("http://{addr}/api/filebrowser/instances")).await;
    let instances = list["instances"].as_array().expect("instances");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0]["adminPassword"], "********");
    assert_eq!(instances[0]["effectiveUrl"], "https://files.example.com/");

    // Secrets plaintext endpoint returns the real value.
    let (_, secrets) = get_json(
        &client,
        &format!("http://{addr}/api/filebrowser/instances/{key}/secrets"),
    )
    .await;
    assert_eq!(secrets["adminPassword"], "long-admin-password");

    // Overlap rejection is a 400 with the field named.
    let overlap = serde_json::json!({
        "name": "config",
        "adminPassword": "long-admin-password",
        "sources": [{"path": config_dir.display().to_string()}],
    });
    let (status, reply) = post_json(
        &client,
        &format!("http://{addr}/api/filebrowser/instances"),
        overlap,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        reply.to_string().contains("重叠") || reply.to_string().contains("overlap"),
        "the overlap reason is named: {reply}"
    );

    // The password method requires the minimum length.
    let short = serde_json::json!({ "name": "shorty", "adminPassword": "short" });
    let (status, _) = post_json(
        &client,
        &format!("http://{addr}/api/filebrowser/instances"),
        short,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn proxy_auth_method_requires_header_default_and_warns() {
    let mut instance = fg_filebrowser::Instance {
        name: "proxied".to_string(),
        admin_password: "irrelevant".to_string(),
        auth_method: AuthMethod::Proxy,
        ..fg_filebrowser::Instance::default()
    };
    let mut config = fg_filebrowser::FileConfig::default();
    config.instances.push(instance.clone());
    fg_filebrowser::validate::normalize(&mut config).expect("normalize");
    instance = config.instances.remove(0);
    assert_eq!(instance.proxy_header, "Remote-User");
    assert!(
        !fg_filebrowser::validate::warnings(&{
            let mut config = fg_filebrowser::FileConfig::default();
            config.instances.push(instance.clone());
            config
        })
        .is_empty()
    );

    // The rendered config selects the proxy method with the header.
    let rendered =
        fg_filebrowser::render::render_config(&instance, std::path::Path::new("/tmp/data"));
    assert_eq!(
        rendered["auth"]["methods"]["proxy"]["header"],
        "Remote-User"
    );
    assert!(
        fg_filebrowser::render::render_config(&instance, std::path::Path::new("/tmp/data"))
            .to_string()
            .contains("FILEBROWSER_ADMIN_PASSWORD")
    );

    // A read-only share renders into sources[].config.readOnly.
    instance.sources.push(Source {
        path: "/srv/ro".to_string(),
        read_only: true,
        ..Source::default()
    });
    let rendered =
        fg_filebrowser::render::render_config(&instance, std::path::Path::new("/tmp/data"));
    assert_eq!(rendered["server"]["sources"][0]["config"]["readOnly"], true);
}
