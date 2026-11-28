//! Dynadot 契约测试（对照上游 dynadot_test.go::TestDynadot）。

mod fake;

use std::sync::Arc;
use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{ProviderErrorKind, RecordType, UpsertAction, providers::dynadot::Dynadot};

type Query = Vec<(String, String)>;

fn param(query: &Query, key: &str) -> String {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// set_ddns 假服务器：pwd 正确返回 success，否则返回 error。
async fn start_dynadot_fake(last: Arc<Mutex<Query>>) -> FakeServer {
    FakeServer::start(move |req| {
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/set_ddns");
        let query = req.query_pairs();
        *last.lock().expect("last") = query.clone();
        if param(&query, "pwd") != "ddnspw" {
            return FakeResponse::json(
                200,
                r#"{"status":"error","error_code":-1,"content":["invalid password"]}"#,
            );
        }
        FakeResponse::json(
            200,
            r#"{"status":"success","error_code":0,"content":["ok"]}"#,
        )
    })
    .await
}

/// 子域名与根域名的请求参数契约；成功一律返回 updated。
#[tokio::test]
async fn dynadot_upsert_request_contract() {
    let last = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let srv = start_dynadot_fake(last.clone()).await;
    let p = Dynadot::with_endpoint(
        creds("", "ddnspw"),
        http(),
        &format!("{}/set_ddns", srv.url()),
    )
    .expect("provider");

    // 子域名：未指定 TTL 取 600，containRoot 为 false。
    assert_eq!(
        p.upsert(&rec(
            "example.com",
            "home.lab",
            RecordType::A,
            "203.0.113.1"
        ))
        .await
        .expect("subdomain update"),
        UpsertAction::Updated,
        "接口无查询，成功一律返回 updated"
    );
    let query = last.lock().expect("last").clone();
    assert_eq!(param(&query, "domain"), "example.com");
    assert_eq!(param(&query, "subDomain"), "home.lab");
    assert_eq!(param(&query, "type"), "A");
    assert_eq!(param(&query, "ip"), "203.0.113.1");
    assert_eq!(param(&query, "ttl"), "600");
    assert_eq!(param(&query, "containRoot"), "false");

    // 根域名：subDomain 为 "@"，containRoot 为 true；自定义 TTL 原样提交。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 300;
    p.upsert(&r).await.expect("root update");
    let query = last.lock().expect("last").clone();
    assert_eq!(param(&query, "subDomain"), "@");
    assert_eq!(param(&query, "containRoot"), "true");
    assert_eq!(param(&query, "type"), "AAAA");
    assert_eq!(param(&query, "ttl"), "300");
}

/// TTL 取整到文档列出的可选值；不支持的类型报错；密码错误透出服务商错误。
#[tokio::test]
async fn dynadot_ttl_steps_type_check_and_errors() {
    let last = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let srv = start_dynadot_fake(last.clone()).await;
    let p = Dynadot::with_endpoint(
        creds("", "ddnspw"),
        http(),
        &format!("{}/set_ddns", srv.url()),
    )
    .expect("provider");
    // TTL 取整（上游 TestDynadot 的表）。
    for (input, want) in [
        (60u32, "300"),
        (301, "600"),
        (3600, "3600"),
        (5000, "7200"),
        (86_400, "28800"),
    ] {
        let mut r = rec("example.com", "a", RecordType::A, "1.1.1.1");
        r.ttl = input;
        p.upsert(&r).await.expect("ttl upsert");
        let query = last.lock().expect("last").clone();
        assert_eq!(param(&query, "ttl"), want, "TTL {input} 应提交 {want}");
    }

    // 不支持的类型。
    let err = p
        .upsert(&rec("example.com", "a", RecordType::TXT, "x"))
        .await
        .expect_err("TXT should be rejected");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);

    // 密码错误透出服务商错误。
    let bad = Dynadot::with_endpoint(
        creds("", "wrongpw"),
        http(),
        &format!("{}/set_ddns", srv.url()),
    )
    .expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("invalid password");
    assert!(err.detail.contains("invalid password"), "{}", err.detail);

    // 缺少密码构造失败。
    assert!(Dynadot::new(creds("", ""), http()).is_err());
}
