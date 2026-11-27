//! Porkbun 契约测试（对照上游 providers_test.go::TestPorkbun、
//! porkbun_test.go 三个用例、txt_test.go、delete_test.go）。

mod fake;

use std::sync::{Arc, Mutex};

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::porkbun::Porkbun,
};

/// 模拟 Porkbun 接口（issue #99）：保存时名称转小写；retrieveByNameType 按
/// 名称区分大小写；同值记录已存在时 create 返回 400 与固定消息。
/// hideByName / hideList 用于模拟「按名称/整域查询都查不到」的情况。
struct Fake {
    records: Mutex<Vec<serde_json::Value>>,
    hide_by_name: Mutex<bool>,
    hide_list: Mutex<bool>,
}

impl Fake {
    fn new(records: Vec<serde_json::Value>) -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(records),
            hide_by_name: Mutex::new(false),
            hide_list: Mutex::new(false),
        })
    }

    fn into_handler(
        self: Arc<Self>,
    ) -> impl Fn(&fake::RecordedRequest) -> FakeResponse + Send + Sync + 'static {
        move |req| self.handle(req)
    }

    fn handle(&self, req: &fake::RecordedRequest) -> FakeResponse {
        let body = req.body_json();
        assert_eq!(body["apikey"], "k", "凭据必须随每个请求提交");
        assert_eq!(body["secretapikey"], "s");
        let path = req.path.trim_start_matches("/dns/").to_owned();
        let parts: Vec<&str> = path.split('/').collect();
        let fqdn = |zone: &str, sub: &str| {
            if sub.is_empty() {
                zone.to_owned()
            } else {
                format!("{sub}.{zone}")
            }
        };
        match parts[0] {
            "retrieveByNameType" => {
                if *self.hide_by_name.lock().expect("hide") {
                    return FakeResponse::json(200, r#"{"status":"SUCCESS","records":[]}"#);
                }
                let sub = if parts.len() > 3 { parts[3] } else { "" };
                let recs = self.records.lock().expect("records");
                // 区分大小写：带大写字母的主机记录查不到小写保存的记录。
                let out: Vec<&serde_json::Value> = recs
                    .iter()
                    .filter(|r| {
                        r["name"].as_str() == Some(fqdn(parts[1], sub).as_str())
                            && r["type"].as_str() == Some(parts[2])
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    format!(r#"{{"status":"SUCCESS","records":[{}]}}"#, list_json(&out)),
                )
            }
            "retrieve" => {
                let recs = self.records.lock().expect("records");
                let out: Vec<&serde_json::Value> = if *self.hide_list.lock().expect("hide list") {
                    Vec::new()
                } else {
                    recs.iter().collect()
                };
                FakeResponse::json(
                    200,
                    format!(r#"{{"status":"SUCCESS","records":[{}]}}"#, list_json(&out)),
                )
            }
            "create" => {
                if parts[1] == "invalid" {
                    return FakeResponse::json(
                        400,
                        r#"{"status":"ERROR","message":"Invalid domain."}"#,
                    );
                }
                let name =
                    fqdn(parts[1], body["name"].as_str().expect("name")).to_ascii_lowercase();
                let mut recs = self.records.lock().expect("records");
                if recs.iter().any(|r| {
                    r["name"].as_str() == Some(name.as_str())
                        && r["type"].as_str() == Some(body["type"].as_str().unwrap_or(""))
                        && r["content"].as_str() == Some(body["content"].as_str().unwrap_or(""))
                }) {
                    return FakeResponse::json(
                        400,
                        r#"{"status":"ERROR","message":"A DNS record with this name, type, and content already exists."}"#,
                    );
                }
                // ID 唯一（同名多条记录各自一条）。
                let id = format!("n{}-{name}", recs.len());
                recs.push(serde_json::json!({
                    "id": id,
                    "name": name,
                    "type": body["type"],
                    "content": body["content"],
                    "ttl": body["ttl"],
                }));
                FakeResponse::json(200, r#"{"status":"SUCCESS"}"#)
            }
            "editByNameType" => {
                let sub = if parts.len() > 3 { parts[3] } else { "" };
                let mut recs = self.records.lock().expect("records");
                for r in recs.iter_mut() {
                    if r["name"].as_str() == Some(fqdn(parts[1], sub).as_str())
                        && r["type"].as_str() == Some(parts[2])
                    {
                        r["content"] = body["content"].clone();
                    }
                }
                FakeResponse::json(200, r#"{"status":"SUCCESS"}"#)
            }
            "delete" => {
                let mut recs = self.records.lock().expect("records");
                recs.retain(|r| r["id"].as_str() != Some(parts[2]));
                FakeResponse::json(200, r#"{"status":"SUCCESS"}"#)
            }
            _ => text(500, "unexpected path"),
        }
    }
}

fn list_json(items: &[&serde_json::Value]) -> String {
    items
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn provider(fake_url: &str) -> Porkbun {
    Porkbun::with_endpoint(creds("k", "s"), http(), fake_url).expect("provider")
}

#[tokio::test]
async fn porkbun_upsert_request_contract() {
    let f = Fake::new(vec![]);
    let srv = FakeServer::start(f.clone().into_handler()).await;
    let p = provider(&srv.url());
    let action = p
        .upsert(&rec("example.com", "vpn", RecordType::A, "203.0.113.1"))
        .await
        .expect("create");
    assert_eq!(action, UpsertAction::Created);
    // 锁守卫在块内释放，避免与后续请求互相等待造成死锁。
    {
        let reqs = srv.requests();
        // 凭据放在每个请求体里；Content-Type 为 JSON。
        assert_eq!(reqs[0].path, "/dns/retrieveByNameType/example.com/A/vpn");
        assert_eq!(reqs[0].header("content-type"), Some("application/json"));
        assert_eq!(reqs[0].body_json()["apikey"], "k");
        assert_eq!(reqs[0].body_json()["secretapikey"], "s");
        // 创建：TTL 0 发送最小值 600，name 只传主机记录。
        let create = reqs
            .iter()
            .find(|r| r.path == "/dns/create/example.com")
            .expect("create");
        let body = create.body_json();
        assert_eq!(body["name"], "vpn");
        assert_eq!(body["type"], "A");
        assert_eq!(body["content"], "203.0.113.1");
        assert_eq!(body["ttl"], "600");
    }
    // 值变化：editByNameType 只更新 content 与 ttl。
    let action = p
        .upsert(&rec("example.com", "vpn", RecordType::A, "203.0.113.2"))
        .await
        .expect("update");
    assert_eq!(action, UpsertAction::Updated);
    let edit = srv
        .requests()
        .iter()
        .find(|r| r.path == "/dns/editByNameType/example.com/A/vpn")
        .expect("edit")
        .body_json();
    assert_eq!(edit["content"], "203.0.113.2");
    assert_eq!(edit["ttl"], "600");
}

#[tokio::test]
async fn porkbun_upsert_response_parsed() {
    let f = Fake::new(vec![]);
    let srv = FakeServer::start(f.clone().into_handler()).await;
    let p = provider(&srv.url());
    let action = p
        .upsert(&rec("example.com", "vpn", RecordType::AAAA, "2001:db8::1"))
        .await
        .expect("create");
    assert_eq!(action, UpsertAction::Created);
}

#[tokio::test]
async fn porkbun_creates_then_updates() {
    let f = Fake::new(vec![]);
    let srv = FakeServer::start(f.clone().into_handler()).await;
    let p = provider(&srv.url());
    let steps = [
        ("203.0.113.1", UpsertAction::Created),
        ("203.0.113.1", UpsertAction::Unchanged),
        ("203.0.113.2", UpsertAction::Updated),
    ];
    for (value, want) in steps {
        let action = p
            .upsert(&rec("example.com", "vpn", RecordType::A, value))
            .await
            .expect("upsert");
        assert_eq!(action, want, "value={value}");
    }
}

#[tokio::test]
async fn porkbun_mixed_case_sub_matches_lowercase_record() {
    let f = Fake::new(vec![serde_json::json!({
        "id": "1", "name": "nas.example.xyz", "type": "AAAA",
        "content": "2001:db8::1", "ttl": "600"
    })]);
    let srv = FakeServer::start(f.clone().into_handler()).await;
    let p = provider(&srv.url());
    // 带大写字母的主机记录：服务商保存为小写，按值比较后无需更新。
    let mut r = rec("example.xyz", "NAS", RecordType::AAAA, "2001:db8::1");
    for i in 0..3 {
        let action = p.upsert(&r).await.expect("upsert");
        assert_eq!(action, UpsertAction::Unchanged, "第 {i} 轮");
    }
    // 值变化时按小写名称原地更新。
    r.value = "2001:db8::2".into();
    let action = p.upsert(&r).await.expect("update");
    assert_eq!(action, UpsertAction::Updated);
    let recs = f.records.lock().expect("records");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["content"], "2001:db8::2");
}

#[tokio::test]
async fn porkbun_fallback_list_and_ipv6_form() {
    let f = Fake::new(vec![
        serde_json::json!({"id": "1", "name": "example.xyz", "type": "AAAA", "content": "2001:db8::9", "ttl": "600"}),
        serde_json::json!({"id": "2", "name": "nas.example.xyz", "type": "A", "content": "203.0.113.1", "ttl": "600"}),
        // IPv6 以展开大写写法返回。
        serde_json::json!({"id": "3", "name": "nas.example.xyz", "type": "AAAA", "content": "2001:0DB8:0000:0000:0000:0000:0000:0001", "ttl": "600"}),
    ]);
    *f.hide_by_name.lock().expect("hide") = true;
    let srv = FakeServer::start(f.clone().into_handler()).await;
    let p = provider(&srv.url());
    // retrieveByNameType 查不到时列出整个域名按名称核对；展开写法视为相同。
    let action = p
        .upsert(&rec("example.xyz", "nas", RecordType::AAAA, "2001:db8::1"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Unchanged);
    // 删除时同样能找到这条记录。
    let mut r = rec("example.xyz", "nas", RecordType::AAAA, "2001:db8::1");
    r.value = "2001:db8::1".into();
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    assert_eq!(f.records.lock().expect("records").len(), 2);
}

#[tokio::test]
async fn porkbun_create_duplicate_is_unchanged() {
    let f = Fake::new(vec![]);
    let srv = FakeServer::start(f.clone().into_handler()).await;
    let p = provider(&srv.url());
    let r = rec("example.xyz", "nas", RecordType::AAAA, "2001:db8::1");
    let action = p.upsert(&r).await.expect("create");
    assert_eq!(action, UpsertAction::Created);
    // 两种查询都看不到记录（服务商列表延迟），创建时提示已存在：按无需更新。
    *f.hide_by_name.lock().expect("hide") = true;
    *f.hide_list.lock().expect("hide") = true;
    let action = p.upsert(&r).await.expect("duplicate");
    assert_eq!(action, UpsertAction::Unchanged);
    assert_eq!(f.records.lock().expect("records").len(), 1);
    // 其他创建错误照常返回。
    let err = p
        .upsert(&rec("invalid", "nas", RecordType::AAAA, "2001:db8::3"))
        .await
        .expect_err("other create error");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("Invalid domain"), "{}", err.detail);
}

#[tokio::test]
async fn porkbun_error_classification() {
    // 业务层非 SUCCESS（200）按无效输入归类。
    let srv = FakeServer::start(|_| {
        FakeResponse::json(200, r#"{"status":"ERROR","message":"Invalid domain."}"#)
    })
    .await;
    let p = provider(&srv.url());
    let err = p
        .upsert(&rec("example.com", "nas", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("business");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("Invalid domain"), "{}", err.detail);

    // 网关层 401 / 500 按状态归类；错误体里的 message 优先透出。
    let status = Mutex::new(401u16);
    let srv2 = FakeServer::start(move |_| {
        let mut st = status.lock().expect("status");
        let current = *st;
        *st = 500;
        FakeResponse::json(current, r#"{"status":"ERROR","message":"no permission"}"#)
    })
    .await;
    let p2 = provider(&srv2.url());
    let err = p2
        .upsert(&rec("example.com", "nas", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.contains("no permission"));
    let err = p2
        .upsert(&rec("example.com", "nas", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("server");
    assert_eq!(err.kind, ProviderErrorKind::Server);
}

#[tokio::test]
async fn porkbun_txt_add_delete() {
    let f = Fake::new(vec![]);
    let srv = FakeServer::start(f.clone().into_handler()).await;
    let p = provider(&srv.url());
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    assert_eq!(f.records.lock().expect("records").len(), 2);
    let create = srv
        .requests()
        .iter()
        .find(|r| r.path == "/dns/create/example.com")
        .expect("create")
        .body_json();
    assert_eq!(create["ttl"], "600");
    assert_eq!(create["name"], "_acme-challenge");
    // 按值删除。
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    let recs = f.records.lock().expect("records");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["content"], "v2");
}

#[tokio::test]
async fn porkbun_delete_targets() {
    let f = Fake::new(vec![
        serde_json::json!({"id": "1", "name": "nas.example.com", "type": "A", "content": "1.1.1.1", "ttl": "600"}),
        serde_json::json!({"id": "2", "name": "nas.example.com", "type": "A", "content": "2.2.2.2", "ttl": "600"}),
    ]);
    let srv = FakeServer::start(f.clone().into_handler()).await;
    let p = provider(&srv.url());
    let mut r = rec("example.com", "nas", RecordType::A, "");
    assert!(delete_records(&p, &r).await.is_err());
    r.value = "2.2.2.2".into();
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    let recs = f.records.lock().expect("records");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["id"], "1");
}
