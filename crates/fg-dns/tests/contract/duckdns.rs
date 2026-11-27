//! DuckDNS 契约测试（对照上游 providers_test.go::TestDuckDNSAndCallback）。

mod fake;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{ProviderErrorKind, RecordType, UpsertAction, providers::duckdns::DuckDns};

#[tokio::test]
async fn duckdns_upsert_request_contract() {
    let srv = FakeServer::start(|_req| FakeResponse::json(200, "OK")).await;
    let p = DuckDns::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    // AAAA 走 ipv6 参数。
    p.upsert(&rec(
        "duckdns.org",
        "myhome",
        RecordType::AAAA,
        "2001:db8::1",
    ))
    .await
    .expect("upsert aaaa");
    // A 走 ip 参数。
    p.upsert(&rec("duckdns.org", "myhome", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert a");
    // 断言块先释放锁，再做下一次请求（假服务器在推送记录时也要拿锁）。
    {
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].query_param("domains").as_deref(), Some("myhome"));
        assert_eq!(reqs[0].query_param("token").as_deref(), Some("tok"));
        assert_eq!(reqs[0].query_param("ipv6").as_deref(), Some("2001:db8::1"));
        assert_eq!(reqs[1].query_param("ip").as_deref(), Some("203.0.113.1"));
    }
    // 带子域的 FQDN：去掉 .duckdns.org 后缀。
    p.upsert(&rec("duckdns.org", "a.b", RecordType::A, "203.0.113.2"))
        .await
        .expect("upsert subdomain");
    let reqs = srv.requests();
    assert_eq!(reqs[2].query_param("domains").as_deref(), Some("a.b"));
}

#[tokio::test]
async fn duckdns_upsert_response_parsed() {
    let srv = FakeServer::start(|_req| FakeResponse::json(200, "OK")).await;
    let p = DuckDns::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let action = p
        .upsert(&rec("duckdns.org", "myhome", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert");
    // DuckDNS 不提供查询，重复提交由调用方的缓存避免，响应固定为 updated。
    assert_eq!(action, UpsertAction::Updated);
}

#[tokio::test]
async fn duckdns_ko_response_reports_failure() {
    let srv = FakeServer::start(|_req| FakeResponse::json(200, "KO")).await;
    let p = DuckDns::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("duckdns.org", "myhome", RecordType::A, "203.0.113.1"))
        .await
        .expect_err("KO");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("KO"), "{}", err.detail);
    assert!(!err.detail.contains("tok"), "令牌不应出现在错误信息里");
}

#[test]
fn duckdns_missing_token_rejected() {
    assert!(DuckDns::new(creds("", ""), http()).is_err());
}
