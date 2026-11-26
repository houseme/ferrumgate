use std::sync::Arc;

use anyhow::Result;
use axum::http::StatusCode;
use fg_admin::{
    Admin, ApiRouter, Principal, SystemRoutes,
    publicip::{Family, PublicIpCache},
};
use fg_core::{registry::Registry, settings::Settings};

fn router() -> Admin {
    let registry = Registry::new(&["webservice", "ssl", "portforward"]);
    let enabled = registry.resolve_enabled(&["portforward".to_owned()], false);
    SystemRoutes {
        config_dir: "/tmp/ferrumgate-config".into(),
        modules: Arc::new((registry, enabled)),
        started_at: std::time::SystemTime::now(),
        settings: Arc::new(Settings::default()),
        public_ip: Arc::new(|_| {
            Box::pin(async { Err("测试中不查询".to_owned()) })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = std::result::Result<std::net::IpAddr, String>,
                            > + Send,
                    >,
                >
        }),
        probe_head: Arc::new(|_hostport: String, _https: bool| {
            Box::pin(async { Err("测试中不探测".to_owned()) })
                as std::pin::Pin<Box<dyn std::future::Future<Output = Result<u16, String>> + Send>>
        }),
        onboarding_store: {
            let dir = tempfile::tempdir().unwrap();
            fg_config::ConfigStore::open(dir.path()).unwrap()
        },
    }
    .register(ApiRouter::new(|_| {
        Some(Principal::Session { read_only: false })
    }))
    .finish()
}

async fn get(admin: Admin, path: &str) -> Result<(StatusCode, serde_json::Value)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let service = axum::Router::new().merge(admin.router);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            service.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });
    let stream = tokio::net::TcpStream::connect(address).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .uri(path)
        .header("host", address.to_string())
        .body(http_body_util::Full::new(hyper::body::Bytes::new()))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await?
        .to_bytes();
    let body = serde_json::from_slice(&bytes)?;
    server.abort();
    Ok((status, body))
}

#[tokio::test]
async fn status_lists_module_states_and_runtime_fields() -> Result<()> {
    let admin = router();
    assert_eq!(
        admin.document()["paths"]["/api/status"]["get"]["x-required-scope"],
        "status:read"
    );
    let (status, body) = get(admin, "/api/status").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["os"], std::env::consts::OS);
    assert_eq!(body["arch"], std::env::consts::ARCH);
    assert_eq!(body["uptimeSeconds"], 0);
    assert!(body["startedAt"].as_str().unwrap().contains('T'));
    assert!(
        body["configDir"]
            .as_str()
            .unwrap()
            .contains("ferrumgate-config")
    );
    let modules = body["modules"].as_array().unwrap();
    let state = |id: &str| {
        modules
            .iter()
            .find(|module| module["id"] == id)
            .unwrap_or_else(|| panic!("missing module {id}"))
    };
    assert_eq!(state("webservice")["status"], "enabled");
    assert_eq!(state("ssl")["status"], "enabled");
    assert_eq!(state("portforward")["status"], "disabled");
    assert_eq!(state("ddns")["status"], "absent");
    Ok(())
}

#[tokio::test]
async fn info_reports_build_contents() -> Result<()> {
    let admin = router();
    let (status, body) = get(admin, "/api/system/info").await?;
    assert_eq!(status, StatusCode::OK);
    let included = body["includedModules"].as_array().unwrap();
    assert!(included.iter().any(|id| id == "webservice"));
    assert!(!included.iter().any(|id| id == "ddns"));
    let absent = body["absentModules"].as_array().unwrap();
    assert!(absent.iter().any(|id| id == "ddns"));
    assert!(!absent.iter().any(|id| id == "ssl"));
    assert_eq!(body["languages"], "full");
    Ok(())
}

fn stub_lookup(
    calls: Arc<std::sync::atomic::AtomicUsize>,
    delay: Duration,
) -> fg_admin::publicip::Lookup {
    Arc::new(move |family: Family| {
        let calls = calls.clone();
        Box::pin(async move {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            match family {
                Family::Ipv4 => Ok("203.0.113.10".parse().unwrap()),
                Family::Ipv6 => Ok("2001:db8::10".parse().unwrap()),
            }
        })
            as std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = std::result::Result<std::net::IpAddr, String>>
                        + Send,
                >,
            >
    })
}

use std::time::Duration;

#[tokio::test]
async fn publicip_coalesces_concurrent_lookups() -> Result<()> {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cache = Arc::new(PublicIpCache::new(stub_lookup(
        calls.clone(),
        Duration::from_millis(100),
    )));
    let (a, b, c) = tokio::join!(cache.refresh(), cache.refresh(), cache.refresh());
    assert_eq!(a.ipv4, Some("203.0.113.10".parse()?));
    assert_eq!(b.ipv6, Some("2001:db8::10".parse()?));
    assert_eq!(c.ipv4, a.ipv4);
    // Both families run inside one shared refresh.
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(a.checked_at.is_some());
    Ok(())
}

#[tokio::test]
async fn publicip_throttles_within_ten_seconds() -> Result<()> {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cache = Arc::new(PublicIpCache::new(stub_lookup(
        calls.clone(),
        Duration::from_millis(5),
    )));
    let first = cache.refresh().await;
    let second = cache.refresh().await;
    assert_eq!(first, second);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "no new lookups in the window"
    );
    // The cached read never triggers lookups.
    let cached = cache.get().await;
    assert_eq!(cached.ipv4, first.ipv4);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn publicip_records_family_errors() -> Result<()> {
    let lookup: fg_admin::publicip::Lookup = Arc::new(|family: Family| {
        Box::pin(async move {
            match family {
                Family::Ipv4 => Ok("203.0.113.10".parse().unwrap()),
                Family::Ipv6 => Err("没有公网 IPv6".to_owned()),
            }
        })
            as std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = std::result::Result<std::net::IpAddr, String>>
                        + Send,
                >,
            >
    });
    let cache = PublicIpCache::new(lookup);
    let result = cache.refresh().await;
    assert_eq!(result.ipv4, Some("203.0.113.10".parse()?));
    assert_eq!(result.ipv6, None);
    let errors = result.errors.expect("failure recorded");
    assert_eq!(errors["ipv6"], "没有公网 IPv6");
    assert!(!errors.contains_key("ipv4"));
    Ok(())
}

#[tokio::test]
async fn onboarding_scenes_done_and_dismiss_follow_the_validation_rules() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = fg_config::ConfigStore::open(dir.path())?;
    let registry = Registry::new(&["webservice"]);
    let enabled = registry.resolve_enabled(&[], false);
    let admin = SystemRoutes {
        config_dir: dir.path().to_owned(),
        modules: Arc::new((registry, enabled)),
        started_at: std::time::SystemTime::now(),
        settings: Arc::new(Settings::default()),
        public_ip: unreachable_lookup(),
        probe_head: unreachable_head(),
        onboarding_store: store.clone(),
    }
    .register(ApiRouter::new(|_| {
        Some(Principal::Session { read_only: false })
    }))
    .finish();
    let (status, body) = post_json(
        &admin,
        "/api/system/onboarding/scenes",
        r#"{"scenes":["web","web","vps"]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scenes"], serde_json::json!(["web", "vps"]));
    assert_eq!(body["scenePending"], false);
    let (status, _) = post_json(
        &admin,
        "/api/system/onboarding/scenes",
        r#"{"scenes":["bogus"]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = post_json(
        &admin,
        "/api/system/onboarding/done",
        r#"{"item":"network-check"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["done"], serde_json::json!(["network-check"]));
    let (status, _) = post_json(
        &admin,
        "/api/system/onboarding/done",
        r#"{"item":"Bad_Item"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = post_json(&admin, "/api/system/onboarding/dismiss", "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pending"], false);
    Ok(())
}

fn unreachable_lookup() -> fg_admin::publicip::Lookup {
    Arc::new(|_| {
        Box::pin(async { Err("测试中不查询".to_owned()) })
            as std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = std::result::Result<std::net::IpAddr, String>>
                        + Send,
                >,
            >
    })
}

fn unreachable_head() -> fg_admin::probe::HeadLookup {
    Arc::new(|_: String, _: bool| {
        Box::pin(async { Err("测试中不探测".to_owned()) })
            as std::pin::Pin<Box<dyn std::future::Future<Output = Result<u16, String>> + Send>>
    })
}

async fn post_json(
    admin: &Admin,
    path: &str,
    body: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let service = axum::Router::new().merge(admin.router.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            service.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });
    let stream = tokio::net::TcpStream::connect(address).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(path)
        .header("host", address.to_string())
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(
            body.to_owned(),
        )))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await?
        .to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    server.abort();
    Ok((status, value))
}
