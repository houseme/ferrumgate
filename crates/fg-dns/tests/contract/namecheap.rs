//! Namecheap 契约测试（对照上游 more_test.go::TestNamecheap）。

mod fake;

use std::sync::Arc;
use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{ProviderErrorKind, RecordType, UpsertAction, providers::namecheap::Namecheap};

#[tokio::test]
async fn namecheap_upsert_request_contract() {
    let last = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let last_in_handler = last.clone();
    let srv = FakeServer::start(move |req| {
        *last_in_handler.lock().expect("last") = req.query_pairs();
        FakeResponse::json(
            200,
            r#"<?xml version="1.0"?><interface-response><ErrCount>0</ErrCount></interface-response>"#,
        )
    })
    .await;
    let p = Namecheap::with_endpoint(creds("", "pw"), http(), &srv.url()).expect("provider");
    assert_eq!(
        p.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
            .await
            .expect("update"),
        UpsertAction::Updated,
        "接口不返回旧值，成功一律返回 updated"
    );
    let query = last.lock().expect("last").clone();
    let get = |k: &str| {
        query
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(get("host"), "home");
    assert_eq!(get("domain"), "example.com");
    assert_eq!(get("password"), "pw");
    assert_eq!(get("ip"), "203.0.113.1");

    // 仅支持 A 记录。
    let err = p
        .upsert(&rec("example.com", "home", RecordType::AAAA, "::1"))
        .await
        .expect_err("AAAA should be rejected");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
}

/// 服务商错误（ErrCount>0）透出 Err1；缺密码构造失败；密码不进错误详情。
#[tokio::test]
async fn namecheap_error_classification() {
    let err_srv = FakeServer::start(|_| {
        FakeResponse::json(
            200,
            r#"<interface-response><ErrCount>1</ErrCount><errors><Err1>Passwords do not match</Err1></errors></interface-response>"#,
        )
    })
    .await;
    let p = Namecheap::with_endpoint(creds("", "pw"), http(), &err_srv.url()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("wrong password");
    assert!(
        err.detail.contains("Passwords do not match"),
        "{}",
        err.detail
    );
    assert!(
        !err.detail.contains("pw=\"pw\""),
        "查询串不应进入详情: {}",
        err.detail
    );

    // 无法解析的响应（缺少 interface-response）归类为 Parse；ErrCount 缺失
    // 按 0 处理视为成功。
    let junk = FakeServer::start(|_| FakeResponse::json(200, "<not-xml")).await;
    let p2 = Namecheap::with_endpoint(creds("", "pw"), http(), &junk.url()).expect("provider");
    let err = p2
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("unparseable");
    assert_eq!(err.kind, ProviderErrorKind::Parse, "{}", err.detail);
    let ok_srv = FakeServer::start(|_| {
        FakeResponse::json(
            200,
            r#"<interface-response><OtherField>1</OtherField></interface-response>"#,
        )
    })
    .await;
    let p3 = Namecheap::with_endpoint(creds("", "pw"), http(), &ok_srv.url()).expect("provider");
    assert_eq!(
        p3.upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
            .await
            .expect("missing ErrCount treated as success"),
        UpsertAction::Updated
    );

    // 缺少密码构造失败。
    assert!(Namecheap::new(creds("", ""), http()).is_err());
}
