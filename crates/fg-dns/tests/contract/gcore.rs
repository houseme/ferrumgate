//! Gcore DNS 契约测试（对照上游 gcore_test.go::TestGcore）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::gcore::Gcore,
};

#[tokio::test]
async fn gcore_upsert_request_contract() {
    // 记录集按路径（zone/name/type）存放，同名不同类型互不干扰。
    let current = std::sync::Arc::new(Mutex::new(std::collections::HashMap::<
        String,
        serde_json::Value,
    >::new()));
    let methods = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
    let current_in_handler = current.clone();
    let methods_in_handler = methods.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("authorization"), Some("APIKey tok"), "认证头");
        assert!(
            req.path.starts_with("/zones/example.com/"),
            "路径错误 {}",
            req.path
        );
        methods_in_handler
            .lock()
            .expect("methods")
            .push(format!("{} {}", req.method, req.path));
        let mut rrsets = current_in_handler.lock().expect("cur");
        match req.method.as_str() {
            "GET" => match rrsets.get(&req.path) {
                Some(v) => FakeResponse::json(200, v.to_string()),
                None => FakeResponse::json(404, r#"{"error":"rrset not found"}"#),
            },
            "POST" | "PUT" => {
                let body = req.body_json();
                assert!(body.get("ttl").is_some(), "请求体应有 ttl: {body}");
                assert!(
                    body.get("resource_records").is_some(),
                    "请求体应有 resource_records"
                );
                let mut body = body;
                body["id"] = "meta-id".into();
                rrsets.insert(req.path.clone(), body);
                FakeResponse::json(200, "{}")
            }
            "DELETE" => {
                rrsets.remove(&req.path);
                FakeResponse::json(200, "{}")
            }
            _ => panic!("意外方法 {}", req.method),
        }
    })
    .await;
    let p = Gcore::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
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
    {
        let methods = methods.lock().expect("methods");
        assert_eq!(methods[0], "GET /zones/example.com/home.example.com/A");
        assert_eq!(methods[1], "POST /zones/example.com/home.example.com/A");
    }
    let cur = current
        .lock()
        .expect("cur")
        .get("/zones/example.com/home.example.com/A")
        .cloned()
        .expect("rrset");
    assert_eq!(cur["ttl"], 120, "未指定 TTL 时新建用 120（免费版最小值）");
    assert_eq!(cur["resource_records"][0]["content"][0], "203.0.113.2");
    assert_eq!(cur["resource_records"][0]["enabled"], true);
    // 根域名使用完整域名作为记录集名称。
    let mut r = rec("example.com", "@", RecordType::AAAA, "::1");
    r.ttl = 300;
    let got = p.upsert(&r).await.expect("upsert root");
    assert_eq!(got, UpsertAction::Created);
    let cur = current
        .lock()
        .expect("cur")
        .get("/zones/example.com/example.com/AAAA")
        .cloned()
        .expect("rrset");
    assert_eq!(cur["ttl"], 300);
    let methods = methods.lock().expect("methods");
    assert!(
        methods
            .iter()
            .any(|m| m == "POST /zones/example.com/example.com/AAAA")
    );
}

/// TXT：两个值共存，逐个删除（全部移除时 DELETE 整个记录集）。
#[tokio::test]
async fn gcore_txt_add_delete() {
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("authorization"), Some("APIKey tok"));
        match req.method.as_str() {
            "GET" => {
                let cur = current_in_handler.lock().expect("cur").clone();
                match cur {
                    Some(v) => FakeResponse::json(200, v.to_string()),
                    None => FakeResponse::json(404, r#"{"error":"rrset not found"}"#),
                }
            }
            "POST" | "PUT" => {
                *current_in_handler.lock().expect("cur") = Some(req.body_json());
                FakeResponse::json(200, "{}")
            }
            "DELETE" => {
                *current_in_handler.lock().expect("cur") = None;
                FakeResponse::json(200, "{}")
            }
            _ => panic!("意外方法 {}", req.method),
        }
    })
    .await;
    let p = Gcore::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    {
        let cur = current.lock().expect("cur").clone().expect("rrset");
        assert_eq!(cur["ttl"], 600, "新建 TXT 记录集使用 600");
        assert_eq!(
            cur["resource_records"][0]["content"][0],
            "\"v1\"".trim_matches('"')
        );
    }
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let cur = current.lock().expect("cur").clone().expect("rrset");
        assert_eq!(
            cur["resource_records"].as_array().expect("records").len(),
            2
        );
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let cur = current.lock().expect("cur").clone().expect("rrset");
        let values: Vec<&serde_json::Value> = cur["resource_records"]
            .as_array()
            .expect("records")
            .iter()
            .map(|rr| &rr["content"][0])
            .collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("delete v2");
    assert!(current.lock().expect("cur").is_none(), "应整体删除");
}

/// 删除解析（记录集整体删除）；错误响应按状态归类。
#[tokio::test]
async fn gcore_delete_and_errors() {
    let current = std::sync::Arc::new(Mutex::new(Some(serde_json::json!({
        "ttl": 120,
        "resource_records": [{"content": ["203.0.113.9"], "enabled": true}],
    }))));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("authorization"), Some("APIKey tok"));
        match req.method.as_str() {
            "GET" => {
                let cur = current_in_handler.lock().expect("cur").clone();
                match cur {
                    Some(v) => FakeResponse::json(200, v.to_string()),
                    None => FakeResponse::json(404, r#"{"error":"rrset not found"}"#),
                }
            }
            "DELETE" => {
                *current_in_handler.lock().expect("cur") = None;
                FakeResponse::json(200, "{}")
            }
            _ => panic!("意外方法 {}", req.method),
        }
    })
    .await;
    let p = Gcore::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    // 记录集里还有其他值时通用流程会拒绝；单值直接删除。
    let n = delete_records(
        &p,
        &rec("example.com", "home", RecordType::A, "203.0.113.9"),
    )
    .await
    .expect("delete");
    assert_eq!(n, 1);
    assert!(current.lock().expect("cur").is_none());

    // 认证失败按 Auth 归类。
    let err_srv =
        FakeServer::start(|_| FakeResponse::json(401, r#"{"error":"unauthorized"}"#)).await;
    let bad = Gcore::with_endpoint(creds("", "x"), http(), &err_srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("unauthorized");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
}
