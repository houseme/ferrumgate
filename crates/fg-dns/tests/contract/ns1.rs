//! NS1 契约测试（对照上游 more_test.go::TestNS1、keepttl_test.go 的
//! TestGandiKeepsTTLNS1DefaultTTLOnUpdate 与 delete.go 的 NS1 分节）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::ns1::Ns1,
};

#[tokio::test]
async fn ns1_upsert_request_contract() {
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("x-nsone-key"), Some("k"), "认证头");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones/example.com/home.example.com/A") => {
                match &*current_in_handler.lock().expect("cur") {
                    Some(v) => FakeResponse::json(200, v.to_string()),
                    None => FakeResponse::json(404, r#"{"message":"record not found"}"#),
                }
            }
            ("PUT", "/zones/example.com/home.example.com/A") => {
                let body = req.body_json();
                assert_eq!(body["zone"], "example.com", "PUT 创建带完整记录");
                assert_eq!(body["domain"], "home.example.com");
                assert_eq!(body["type"], "A");
                assert_eq!(body["ttl"], 3600, "新建未指定 TTL 用默认 3600");
                assert_eq!(body["answers"][0]["answer"][0], "203.0.113.1");
                *current_in_handler.lock().expect("cur") = Some(body);
                FakeResponse::json(200, "{}")
            }
            ("POST", "/zones/example.com/home.example.com/A") => {
                let body = req.body_json();
                assert!(body.get("zone").is_none(), "POST 更新只带 ttl 与 answers");
                assert_eq!(body["ttl"], 60, "更新未指定 TTL 用默认 60");
                let mut next = current_in_handler
                    .lock()
                    .expect("cur")
                    .clone()
                    .expect("cur");
                next["ttl"] = body["ttl"].clone();
                next["answers"] = body["answers"].clone();
                *current_in_handler.lock().expect("cur") = Some(next);
                FakeResponse::json(200, "{}")
            }
            other => panic!("意外请求 {other:?}"),
        }
    })
    .await;
    let p = Ns1::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");
    let steps = [
        ("203.0.113.1", UpsertAction::Created),
        ("203.0.113.1", UpsertAction::Unchanged),
        ("203.0.113.2", UpsertAction::Updated),
    ];
    for (v, want) in steps {
        let r = rec("example.com", "home", RecordType::A, v);
        let got = p.upsert(&r).await.expect("upsert");
        assert_eq!(got, want, "value={v}");
    }
}

/// 指定 TTL 时不变化判定与更新都按值；TXT 合并 answers，删除按值、全部
/// 移除时删除整个记录集。
#[tokio::test]
async fn ns1_ttl_handling_and_txt_add_delete() {
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", path)
            if path == "/zones/example.com/www.example.com/A"
                || path == "/zones/example.com/_acme-challenge.example.com/TXT" =>
        {
            match &*current_in_handler.lock().expect("cur") {
                Some(v) => FakeResponse::json(200, v.to_string()),
                None => FakeResponse::json(404, r#"{"message":"record not found"}"#),
            }
        }
        ("PUT", path) => {
            let body = req.body_json();
            if path.ends_with("/TXT") {
                assert_eq!(body["ttl"], 60, "TXT 新建 TTL 60");
            }
            *current_in_handler.lock().expect("cur") = Some(body);
            FakeResponse::json(200, "{}")
        }
        ("POST", _) => {
            let body = req.body_json();
            let mut next = current_in_handler
                .lock()
                .expect("cur")
                .clone()
                .expect("cur");
            next["answers"] = body["answers"].clone();
            next["ttl"] = body["ttl"].clone();
            *current_in_handler.lock().expect("cur") = Some(next);
            FakeResponse::json(200, "{}")
        }
        ("DELETE", _) => {
            *current_in_handler.lock().expect("cur") = None;
            FakeResponse::json(200, "{}")
        }
        other => panic!("意外请求 {other:?}"),
    })
    .await;
    let p = Ns1::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");

    // 指定 TTL 300：创建带 300；TTL 变化触发更新。
    let mut r = rec("example.com", "www", RecordType::A, "1.1.1.1");
    r.ttl = 300;
    assert_eq!(p.upsert(&r).await.expect("create"), UpsertAction::Created);
    assert_eq!(
        p.upsert(&r).await.expect("unchanged"),
        UpsertAction::Unchanged
    );
    r.ttl = 600;
    assert_eq!(
        p.upsert(&r).await.expect("ttl update"),
        UpsertAction::Updated
    );

    // TXT：合并 answers；删除按值；全部移除时整体删除。
    current.lock().expect("cur").take();
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let cur = current.lock().expect("cur").clone().expect("txt recordset");
        let answers = cur["answers"].as_array().expect("answers");
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0]["answer"][0], "v1");
        assert_eq!(answers[1]["answer"][0], "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let cur = current.lock().expect("cur").clone().expect("txt recordset");
        assert_eq!(cur["answers"][0]["answer"][0], "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("delete v2");
    assert!(current.lock().expect("cur").is_none(), "应整体删除");
}

/// 删除：记录集里有其他值时拒绝，单值时删除整个记录集；401 归类为认证失败。
#[tokio::test]
async fn ns1_delete_targets_and_error_classification() {
    let current = std::sync::Arc::new(Mutex::new(Some(serde_json::json!({
        "ttl": 300,
        "answers": [{"answer": ["1.1.1.1"]}, {"answer": ["2.2.2.2"]}],
    }))));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("x-nsone-key"), Some("k"));
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones/example.com/home.example.com/A") => FakeResponse::json(
                200,
                current_in_handler
                    .lock()
                    .expect("cur")
                    .clone()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| r#"{"message":"record not found"}"#.to_owned()),
            ),
            ("DELETE", "/zones/example.com/home.example.com/A") => {
                *current_in_handler.lock().expect("cur") = None;
                FakeResponse::json(200, "{}")
            }
            other => panic!("意外请求 {other:?}"),
        }
    })
    .await;
    let p = Ns1::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");
    // 记录集还有其他值：拒绝删除。
    let err = delete_records(&p, &rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("recordset has other values");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    // 单值记录集：删除。
    *current.lock().expect("cur") = Some(serde_json::json!({
        "ttl": 300,
        "answers": [{"answer": ["1.1.1.1"]}],
    }));
    let n = delete_records(&p, &rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect("delete");
    assert_eq!(n, 1);
    assert!(current.lock().expect("cur").is_none());

    // 认证失败：401。
    let err_srv =
        FakeServer::start(|_| FakeResponse::json(401, r#"{"message":"unauthorized"}"#)).await;
    let bad = Ns1::with_endpoint(creds("", "bad"), http(), &err_srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("unauthorized");
    assert_eq!(err.kind, ProviderErrorKind::Auth);

    // 服务端错误：500。
    let err_srv = FakeServer::start(|_| text(500, "boom")).await;
    let bad = Ns1::with_endpoint(creds("", "k"), http(), &err_srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("server error");
    assert_eq!(err.kind, ProviderErrorKind::Server);
}
