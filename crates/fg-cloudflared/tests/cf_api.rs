//! Cloudflare API contract tests (WP-46 §6) against a local fake API
//! server: request shapes (method, path, auth header, body), error
//! surfaces and the DNS sync decisions.

mod common;

use std::sync::Arc;

use fg_cloudflared::cf_api::{BoxFut, CfClient, DnsStatus, FetchResponse};
use serde_json::json;

use common::{FakeCf, TUNNEL_TOKEN};

fn client_for(cf: &FakeCf, api_token: &str) -> CfClient {
    CfClient::new(cf.base_url.clone(), api_token, cf.fetch())
}

fn parsed_info() -> fg_cloudflared::TokenInfo {
    fg_cloudflared::parse_token(TUNNEL_TOKEN).expect("token parses")
}

#[tokio::test]
async fn cf_api_get_put_config_request_shape() {
    // 方法、路径、认证头、请求体。
    let cf = FakeCf::start(json!({
        "ingress": [
            {"hostname": "old.example.com", "service": "http://localhost:80"},
            {"service": "http_status:404"}
        ],
        "warp-routing": {"enabled": true}
    }))
    .await;
    let client = client_for(&cf, "cf-api");
    let info = parsed_info();

    let config = client
        .get_config(&info.account_tag, &info.tunnel_id)
        .await
        .expect("get config");
    assert_eq!(config.version, 3);
    assert_eq!(config.source, "cloudflare");
    assert_eq!(config.config["warp-routing"], json!({"enabled": true}));

    let saved = client
        .put_config(&info.account_tag, &info.tunnel_id, &config.config)
        .await
        .expect("put config");
    assert_eq!(saved.version, 4, "写回后版本前进");

    let mut requests = cf.requests();
    let get = requests.remove(0);
    assert_eq!(get.method, "GET");
    assert_eq!(get.path, "/accounts/acc/cfd_tunnel/tid/configurations");
    assert_eq!(get.auth, "Bearer cf-api");
    assert_eq!(get.body, json!(null), "GET 不带请求体");
    let put = requests.remove(0);
    assert_eq!(put.method, "PUT");
    assert_eq!(put.path, "/accounts/acc/cfd_tunnel/tid/configurations");
    assert_eq!(put.auth, "Bearer cf-api");
    assert_eq!(
        put.body["config"]["warp-routing"],
        json!({"enabled": true}),
        "PUT 请求体只包 config"
    );
    cf.stop().await;
}

#[tokio::test]
async fn cf_api_error_codes() {
    // 认证失败、未找到（错误的隧道 ID）、非 Cloudflare 应答。
    let cf = FakeCf::start(json!({})).await;
    let client = client_for(&cf, "cf-api");

    // 认证失败：code 10000 + message。
    let wrong = client_for(&cf, "wrong-token");
    let error = wrong
        .get_config("acc", "tid")
        .await
        .expect_err("auth fails");
    assert!(
        error.to_string().contains("10000 Authentication error"),
        "{error}"
    );
    assert!(matches!(
        error,
        fg_cloudflared::CfError::Api { code: 10000, .. }
    ));

    // 未找到：假服务器没有这个隧道的路由。
    let error = client.get_config("acc", "unknown").await.expect_err("404");
    assert!(error.to_string().contains("7000"), "{error}");

    // 非应答格式的 HTTP 错误（路径不存在时假服务器已应答 JSON，这里
    // 直接构造一个指向不存在端口的通道模拟传输失败）。
    let dead = CfClient::new(
        "http://127.0.0.1:1".to_owned(),
        "cf-api",
        Arc::new(
            |_: fg_cloudflared::cf_api::FetchRequest| -> BoxFut<'static, anyhow::Result<FetchResponse>> {
                Box::pin(async { Err(anyhow::anyhow!("连接失败")) })
            },
        ),
    );
    let error = dead.get_config("acc", "tid").await.expect_err("dead");
    assert!(
        matches!(error, fg_cloudflared::CfError::Network(_)),
        "{error}"
    );
    cf.stop().await;
}

#[tokio::test]
async fn dns_sync_creates_proxied_cname() {
    // 目标 `<隧道ID>.cfargotunnel.com`，开启代理。
    let cf = FakeCf::start(json!({})).await;
    let client = client_for(&cf, "cf-api");
    let info = parsed_info();
    let rules = vec![fg_cloudflared::ingress::Rule {
        hostname: "new.example.com".into(),
        path: None,
        service: fg_cloudflared::ingress::Service::Url("http://localhost:8080".into()),
        origin_request: None,
    }];
    let results = client.sync_dns(&info, &rules).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, DnsStatus::Created, "{results:?}");

    let records = cf.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["type"], "CNAME");
    assert_eq!(records[0]["name"], "new.example.com");
    assert_eq!(records[0]["content"], "tid.cfargotunnel.com");
    assert_eq!(records[0]["proxied"], true);
    // 域名查找带账号限定（最长后缀先试 new.example.com，再试 example.com）。
    let zone_queries: Vec<_> = cf
        .requests()
        .into_iter()
        .filter(|request| request.path == "/zones")
        .collect();
    assert!(zone_queries.len() >= 2, "{zone_queries:?}");
    let matched = zone_queries
        .iter()
        .find(|request| request.query.contains("name=example.com"))
        .expect("zone lookup for the zone itself");
    assert!(
        matched.query.contains("account.id=acc"),
        "只在隧道所属账号下查找：{}",
        matched.query
    );
    cf.stop().await;
}

#[tokio::test]
async fn dns_sync_keeps_existing_records() {
    // 已有其他记录；已有未开代理的 CNAME；已是指向隧道的开启代理 CNAME。
    let cf = FakeCf::start_with(json!({}), "cloudflare", "cf-api").await;
    cf.set_records(vec![
        json!({"type": "A", "name": "busy.example.com", "content": "1.2.3.4", "proxied": false}),
        json!({"type": "CNAME", "name": "plain.example.com", "content": "tid.cfargotunnel.com", "proxied": false}),
        json!({"type": "CNAME", "name": "old.example.com", "content": "tid.cfargotunnel.com", "proxied": true}),
    ]);
    let client = client_for(&cf, "cf-api");
    let info = parsed_info();
    let rule = |hostname: &str| fg_cloudflared::ingress::Rule {
        hostname: hostname.into(),
        path: None,
        service: fg_cloudflared::ingress::Service::Url("http://localhost:8080".into()),
        origin_request: None,
    };
    let rules = vec![
        rule("busy.example.com"),
        rule("plain.example.com"),
        rule("old.example.com"),
    ];
    let results = client.sync_dns(&info, &rules).await;
    let status_of = |hostname: &str| {
        results
            .iter()
            .find(|result| result.hostname == hostname)
            .map(|result| result.status)
            .unwrap_or(DnsStatus::Failed)
    };
    assert_eq!(status_of("busy.example.com"), DnsStatus::Conflict);
    assert_eq!(status_of("plain.example.com"), DnsStatus::Conflict);
    assert_eq!(status_of("old.example.com"), DnsStatus::Unchanged);
    // 冲突的记录不被修改；已有记录保持原样。
    assert_eq!(cf.records().len(), 3, "冲突记录不修改");
    let busy = results
        .iter()
        .find(|result| result.hostname == "busy.example.com")
        .expect("busy");
    assert_eq!(busy.existing.as_deref(), Some("A 1.2.3.4"));
    let plain = results
        .iter()
        .find(|result| result.hostname == "plain.example.com")
        .expect("plain");
    assert_eq!(
        plain.existing.as_deref(),
        Some("CNAME tid.cfargotunnel.com (DNS only)"),
        "未开代理的 CNAME 按冲突报告"
    );
    cf.stop().await;
}

#[tokio::test]
async fn dns_sync_only_searches_own_account() {
    // 跨账号的域名找不到 zone：结果 failed，不创建记录。
    let cf = FakeCf::start(json!({})).await;
    let client = client_for(&cf, "cf-api");
    let info = parsed_info();
    let rules = vec![fg_cloudflared::ingress::Rule {
        hostname: "other.example.net".into(),
        path: None,
        service: fg_cloudflared::ingress::Service::Url("http://localhost:8080".into()),
        origin_request: None,
    }];
    let results = client.sync_dns(&info, &rules).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, DnsStatus::Failed);
    assert!(
        results[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("other.example.net"),
        "{results:?}"
    );
    assert!(cf.records().is_empty(), "没有 zone 时不会创建记录");
    cf.stop().await;
}

#[tokio::test]
async fn cf_client_timeout_and_dedup_in_sync() {
    // sync_dns：同一主机名只处理一次。
    let cf = FakeCf::start(json!({})).await;
    let client = client_for(&cf, "cf-api");
    let info = parsed_info();
    let rule = |hostname: &str| fg_cloudflared::ingress::Rule {
        hostname: hostname.into(),
        path: None,
        service: fg_cloudflared::ingress::Service::Url("http://localhost:8080".into()),
        origin_request: None,
    };
    let rules = vec![rule("dup.example.com"), rule("dup.example.com")];
    let results = client.sync_dns(&info, &rules).await;
    assert_eq!(results.len(), 1, "同一主机名只同步一次");
    cf.stop().await;
}
