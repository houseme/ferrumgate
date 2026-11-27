//! Bunny DNS 契约测试（对照上游 more_test.go::TestBunny、txt_test.go、
//! delete_test.go）。JSON 字段为 PascalCase；记录类型 A=0、AAAA=1、TXT=3。

mod fake;

use std::sync::{Arc, Mutex};

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::bunny::Bunny,
};

/// 假 Bunny 区域：记录列表由测试直接操作。
type Records = Arc<Mutex<Vec<serde_json::Value>>>;

fn zone_handler(records: Records) -> impl Fn(&fake::RecordedRequest) -> FakeResponse + Send + Sync {
    move |req| {
        assert_eq!(req.header("accesskey"), Some("k"), "AccessKey 认证头");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/dnszone") => {
                assert_eq!(req.query_param("search").as_deref(), Some("example.com"));
                FakeResponse::json(200, r#"{"Items":[{"Id":7,"Domain":"example.com"}]}"#)
            }
            ("GET", "/dnszone/7") => {
                let recs = records.lock().expect("records");
                FakeResponse::json(200, serde_json::json!({ "Records": &*recs }).to_string())
            }
            ("PUT", "/dnszone/7/records") => {
                let mut rec = req.body_json();
                assert!(rec.get("Id").is_none(), "创建请求不应带 Id");
                rec["Id"] = serde_json::json!(100);
                records.lock().expect("records").push(rec);
                FakeResponse::json(201, "{}")
            }
            ("POST", path) if path.starts_with("/dnszone/7/records/") => {
                let rec = req.body_json();
                let id = rec["Id"].as_i64().expect("id");
                let mut recs = records.lock().expect("records");
                for existing in recs.iter_mut() {
                    if existing["Id"].as_i64() == Some(id) {
                        *existing = rec.clone();
                    }
                }
                FakeResponse::json(204, "{}")
            }
            ("DELETE", path) if path.starts_with("/dnszone/7/records/") => {
                let id: i64 = path.rsplit('/').next().expect("id").parse().expect("num");
                records
                    .lock()
                    .expect("records")
                    .retain(|r| r["Id"].as_i64() != Some(id));
                FakeResponse::json(204, "{}")
            }
            _ => text(500, "unexpected"),
        }
    }
}

#[tokio::test]
async fn bunny_upsert_request_contract() {
    let records: Records = Arc::new(Mutex::new(Vec::new()));
    let srv = FakeServer::start(zone_handler(records.clone())).await;
    let p = Bunny::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");
    // 创建：PUT /dnszone/7/records，名称根域名 "@" → ""，TTL 0 → 300。
    let action = p
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect("create");
    assert_eq!(action, UpsertAction::Created);
    let put = srv
        .requests()
        .iter()
        .find(|r| r.method == "PUT")
        .expect("put")
        .body_json();
    assert_eq!(put["Type"], 0, "A 记录编号 0");
    assert_eq!(put["Ttl"], 300);
    assert_eq!(put["Value"], "203.0.113.1");
    assert_eq!(put["Name"], "home");
    // 更新：POST /dnszone/7/records/{id}，带 Id 的整体更新。
    let action = p
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.2"))
        .await
        .expect("update");
    assert_eq!(action, UpsertAction::Updated);
    let post = srv
        .requests()
        .iter()
        .find(|r| r.method == "POST")
        .expect("post")
        .body_json();
    assert_eq!(post["Id"], 100);
    assert_eq!(post["Value"], "203.0.113.2");
}

#[tokio::test]
async fn bunny_creates_then_updates() {
    let records: Records = Arc::new(Mutex::new(Vec::new()));
    let srv = FakeServer::start(zone_handler(records.clone())).await;
    let p = Bunny::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");
    let steps = [
        ("203.0.113.1", UpsertAction::Created),
        ("203.0.113.1", UpsertAction::Unchanged),
        ("203.0.113.2", UpsertAction::Updated),
    ];
    for (value, want) in steps {
        let action = p
            .upsert(&rec("example.com", "home", RecordType::A, value))
            .await
            .expect("upsert");
        assert_eq!(action, want, "value={value}");
    }
}

#[tokio::test]
async fn bunny_ttl_zero_keeps_existing() {
    // 未指定 TTL 时沿用记录现有值（上游 rec.TTL > 0 时 ttl = rec.TTL）。
    let records: Records = Arc::new(Mutex::new(vec![serde_json::json!({
        "Id": 100, "Type": 0, "Ttl": 900, "Value": "1.1.1.1", "Name": "www"
    })]));
    let srv = FakeServer::start(zone_handler(records.clone())).await;
    let p = Bunny::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");
    // 值相同且 TTL 未知：沿用现有值 → 不变。
    let action = p
        .upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect("unchanged");
    assert_eq!(action, UpsertAction::Unchanged);
    // 值变化：更新沿用现有 TTL 900。
    let action = p
        .upsert(&rec("example.com", "www", RecordType::A, "2.2.2.2"))
        .await
        .expect("update");
    assert_eq!(action, UpsertAction::Updated);
    let recs = records.lock().expect("records");
    assert_eq!(recs[0]["Ttl"], 900);
    assert_eq!(recs[0]["Value"], "2.2.2.2");
}

#[tokio::test]
async fn bunny_error_classification() {
    // 认证失败（AccessKey 错误 → 401）。
    let records: Records = Arc::new(Mutex::new(Vec::new()));
    let srv = FakeServer::start(move |req| {
        if req.header("accesskey") != Some("wrong") {
            return FakeResponse::json(401, "unauthorized");
        }
        zone_handler(records.clone())(req)
    })
    .await;
    let p = Bunny::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.starts_with("Bunny:"), "{}", err.detail);

    // 不支持的记录类型按无效输入归类。
    let err = p
        .upsert(&rec(
            "example.com",
            "home",
            RecordType::MX,
            "mail.example.com",
        ))
        .await
        .expect_err("unsupported type");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
}

#[tokio::test]
async fn bunny_txt_add_delete() {
    let records: Records = Arc::new(Mutex::new(Vec::new()));
    let srv = FakeServer::start(zone_handler(records.clone())).await;
    let p = Bunny::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["Type"], 3, "TXT 记录编号 3");
        assert_eq!(recs[0]["Ttl"], 60);
        assert_eq!(recs[0]["Name"], "_acme-challenge");
    }
    // 按值删除。
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    assert!(records.lock().expect("records").is_empty());
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");
}

#[tokio::test]
async fn bunny_delete_targets() {
    let records: Records = Arc::new(Mutex::new(vec![
        serde_json::json!({"Id": 1, "Type": 0, "Ttl": 300, "Value": "1.1.1.1", "Name": "www"}),
        serde_json::json!({"Id": 2, "Type": 0, "Ttl": 300, "Value": "2.2.2.2", "Name": "www"}),
        serde_json::json!({"Id": 3, "Type": 1, "Ttl": 300, "Value": "2001:db8::1", "Name": "www"}),
    ]));
    let srv = FakeServer::start(zone_handler(records.clone())).await;
    let p = Bunny::with_endpoint(creds("", "k"), http(), &srv.url()).expect("provider");
    let mut r = rec("example.com", "www", RecordType::A, "");
    // 值未知：拒绝。
    assert!(delete_records(&p, &r).await.is_err());
    r.value = "2.2.2.2".into();
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    let recs = records.lock().expect("records");
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|r| r["Id"].as_i64() != Some(2)));
}
