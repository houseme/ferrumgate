use std::sync::Arc;

use anyhow::Result;
use axum::http::StatusCode;
use fg_admin::{Admin, ApiRouter, Principal, SystemRoutes};
use fg_core::{registry::Registry, settings::Settings};

fn router() -> Admin {
    let registry = Registry::new(&["webservice", "ssl", "portforward"]);
    let enabled = registry.resolve_enabled(&["portforward".to_owned()], false);
    SystemRoutes {
        config_dir: "/tmp/ferrumgate-config".into(),
        modules: Arc::new((registry, enabled)),
        started_at: std::time::SystemTime::now(),
        settings: Arc::new(Settings::default()),
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
