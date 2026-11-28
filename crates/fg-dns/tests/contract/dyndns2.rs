//! DynDNS2 协议契约测试（对照上游 more_test.go::TestDynDNS2 与响应码语义）。

mod fake;

use std::sync::Arc;
use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, creds_with_extra, http, rec},
};
use fg_dns::{ProviderErrorKind, RecordType, UpsertAction, providers::dyndns2::Dyndns2};

/// good / nochg 的响应语义与 Basic 认证、请求参数契约。
#[tokio::test]
async fn dyndns2_good_nochg_contract() {
    let last = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let last_in_handler = last.clone();
    let current = Mutex::new(String::new());
    let current_in_handler = Arc::new(current);
    let srv = FakeServer::start(move |req| {
        // Basic 认证：user:pw。
        let want = format!("Basic {}", fg_dns::sign::base64_std(b"user:pw"));
        if req.header("authorization") != Some(want.as_str()) {
            return FakeResponse {
                status: 401,
                body: Vec::new(),
            };
        }
        *last_in_handler.lock().expect("last") = req.query_pairs();
        let ip = req.query_param("myip").unwrap_or_default();
        let mut cur = current_in_handler.lock().expect("cur");
        if *cur == ip {
            return FakeResponse::json(200, format!("nochg {ip}"));
        }
        *cur = ip.clone();
        FakeResponse::json(200, format!("good {ip}"))
    })
    .await;
    let p = Dyndns2::with_endpoint(
        creds_with_extra("user", "pw", &[("server", &srv.url())]),
        http(),
        &srv.url(),
    )
    .expect("provider");
    let r = rec("example.com", "home", RecordType::A, "203.0.113.1");
    assert_eq!(p.upsert(&r).await.expect("first"), UpsertAction::Updated);
    let query = last.lock().expect("last").clone();
    let get = |k: &str| {
        query
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(get("hostname"), "home.example.com", "hostname 是完整域名");
    assert_eq!(get("myip"), "203.0.113.1");
    assert_eq!(
        p.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
            .await
            .expect("second"),
        UpsertAction::Unchanged
    );

    // 用户名或密码错误：401。
    let bad = Dyndns2::with_endpoint(
        creds_with_extra("user", "x", &[("server", &srv.url())]),
        http(),
        &srv.url(),
    )
    .expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.2"))
        .await
        .expect_err("wrong password");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.contains("用户名或密码错误"), "{}", err.detail);
}

/// 其余响应码（nohost / badauth / abuse / 911）报错并透出原文；非法更新
/// 地址构造失败；默认地址构造成功。
#[tokio::test]
async fn dyndns2_response_codes_and_errors() {
    let code = Arc::new(Mutex::new("nohost".to_owned()));
    let code_in_handler = code.clone();
    let srv = FakeServer::start(move |_| {
        let body = code_in_handler.lock().expect("code").clone();
        FakeResponse::json(200, body)
    })
    .await;
    for (body, contains) in [
        ("nohost", "nohost"),
        ("abuse", "abuse"),
        ("911 service down", "911"),
    ] {
        *code.lock().expect("code") = body.to_owned();
        let p = Dyndns2::with_endpoint(
            creds_with_extra("u", "p", &[("server", &srv.url())]),
            http(),
            &srv.url(),
        )
        .expect("provider");
        let err = p
            .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
            .await
            .expect_err(body);
        assert!(
            err.detail.contains(contains),
            "{}: {}",
            contains,
            err.detail
        );
    }

    // 非法更新地址构造失败。
    assert!(
        Dyndns2::with_endpoint(
            creds_with_extra("u", "p", &[("server", "ftp://x")]),
            http(),
            "ftp://x"
        )
        .is_err()
    );
    // 默认更新地址构造成功。
    assert!(Dyndns2::new(creds("u", "p"), http()).is_ok());
    // 缺少凭据构造失败。
    assert!(Dyndns2::new(creds("", ""), http()).is_err());
}
