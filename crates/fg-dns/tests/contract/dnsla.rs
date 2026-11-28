//! DNS.LA 契约测试（对照上游 dnsla_test.go::TestDnsla、TestDnslaAuthError、
//! TestDnslaTXT、TestDnslaDelete）。

mod fake;

use std::sync::Mutex;

use base64::Engine as _;
use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::dnsla::Dnsla,
};

fn basic_auth(id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

#[tokio::test]
async fn dnsla_upsert_request_contract() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let last_body = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let last_body_in_handler = last_body.clone();
    let next = Mutex::new(100i64);
    let srv = FakeServer::start(move |req| {
        // Basic 认证：APIID:APISecret。
        let want_auth = basic_auth("apiid", "apisecret");
        if req.header("authorization") != Some(want_auth.as_str()) {
            return FakeResponse {
                status: 401,
                body: Vec::new(),
            };
        }
        let mut recs = records_in_handler.lock().expect("records");
        let mut last = last_body_in_handler.lock().expect("last");
        let reply = |data: serde_json::Value| {
            FakeResponse::json(
                200,
                serde_json::json!({"code": 200, "msg": "", "data": data}).to_string(),
            )
        };
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domain") => {
                let domain = req.query_param("domain").unwrap_or_default();
                if domain != "example.com" {
                    return FakeResponse::json(200, r#"{"code":404,"msg":"域名不存在"}"#);
                }
                reply(serde_json::json!({"id": "D1", "domain": "example.com"}))
            }
            ("GET", "/recordList") => {
                assert_eq!(req.query_param("domainId").as_deref(), Some("D1"));
                assert!(
                    req.query_param("pageIndex").is_some() && req.query_param("pageSize").is_some()
                );
                let host = req.query_param("host").unwrap_or_default();
                let typ = req.query_param("type").unwrap_or_default();
                let typ_num: i64 = typ.parse().unwrap_or(0);
                let out: Vec<&serde_json::Value> = recs
                    .iter()
                    .filter(|r| {
                        r["type"].as_i64() == Some(typ_num)
                            && r["host"].as_str() == Some(host.as_str())
                    })
                    .collect();
                reply(serde_json::json!({"total": out.len(), "results": out}))
            }
            ("POST", "/record") => {
                let body = req.body_json();
                *last = Some(body.clone());
                assert_eq!(body["domainId"], "D1");
                for r in recs.iter() {
                    if r["host"] == body["host"]
                        && r["type"] == body["type"]
                        && r["data"] == body["data"]
                    {
                        return FakeResponse::json(200, r#"{"code":600,"msg":"与已有记录冲突"}"#);
                    }
                }
                let mut id = next.lock().expect("next");
                *id += 1;
                let id = id.to_string();
                recs.push(serde_json::json!({
                    "id": id, "host": body["host"], "type": body["type"],
                    "data": body["data"], "ttl": body["ttl"],
                }));
                reply(serde_json::json!({"id": id}))
            }
            ("PUT", "/record") => {
                let body = req.body_json();
                *last = Some(body.clone());
                let id = body["id"].as_str().expect("id").to_owned();
                let Some(pos) = recs.iter().position(|r| r["id"] == id) else {
                    return FakeResponse::json(200, r#"{"code":404,"msg":"记录不存在"}"#);
                };
                recs[pos]["data"] = body["data"].clone();
                recs[pos]["ttl"] = body["ttl"].clone();
                reply(serde_json::json!({"id": id}))
            }
            ("DELETE", "/record") => {
                let id = req.query_param("id").unwrap_or_default();
                recs.retain(|r| r["id"] != id);
                reply(serde_json::Value::Null)
            }
            _ => panic!("未预期的请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p =
        Dnsla::with_endpoint(creds("apiid", "apisecret"), http(), &srv.url()).expect("provider");
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
    // 创建时使用默认 TTL 与类型枚举 1；之后更新沿用服务商处的 TTL（600）。
    for r in records.lock().expect("records").iter() {
        assert_eq!(r["type"], 1, "A 记录类型应为 1");
        assert_eq!(r["ttl"], 600, "默认 TTL 应为 600");
    }
    // IPv6 使用类型 28，根域名主机记录为 @。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 300;
    let got = p.upsert(&r).await.expect("upsert aaaa");
    assert_eq!(got, UpsertAction::Created);
    {
        let last = last_body.lock().expect("last").clone().expect("last body");
        assert_eq!(last["type"], 28);
        assert_eq!(last["host"], "@");
        assert_eq!(last["ttl"], 300);
    }
    // TTL 变化也触发更新。
    r.ttl = 600;
    let got = p.upsert(&r).await.expect("upsert ttl change");
    assert_eq!(got, UpsertAction::Updated);
}

/// 认证失败返回 401；不支持的记录类型与业务错误透出。
#[tokio::test]
async fn dnsla_error_classification() {
    let srv = FakeServer::start(move |req| {
        let want = basic_auth("apiid", "apisecret");
        if req.header("authorization") != Some(want.as_str()) {
            return FakeResponse {
                status: 401,
                body: Vec::new(),
            };
        }
        if req.path == "/domain" {
            let domain = req.query_param("domain").unwrap_or_default();
            if domain != "example.com" {
                return FakeResponse::json(200, r#"{"code":404,"msg":"域名不存在"}"#);
            }
            return FakeResponse::json(
                200,
                r#"{"code":200,"msg":"","data":{"id":"D1","domain":"example.com"}}"#,
            );
        }
        text(500, "unexpected")
    })
    .await;
    let bad = Dnsla::with_endpoint(creds("apiid", "bad"), http(), &srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert_eq!(err.message_key, fg_dns::msg::AUTH_FAILED);

    let p =
        Dnsla::with_endpoint(creds("apiid", "apisecret"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("other.com", "x", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("domain missing");
    assert!(err.detail.contains("域名不存在"), "{}", err.detail);

    // 不支持的记录类型。
    let err = p
        .upsert(&rec("example.com", "x", RecordType::MX, "1"))
        .await
        .expect_err("unsupported type");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("MX"), "{}", err.detail);
}

/// TXT：POST type 16 TTL 600；重复添加同值按成功处理；按值删除。
#[tokio::test]
async fn dnsla_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(100i64);
    let srv = FakeServer::start(move |req| {
        let want = basic_auth("apiid", "apisecret");
        if req.header("authorization") != Some(want.as_str()) {
            return FakeResponse {
                status: 401,
                body: Vec::new(),
            };
        }
        let mut recs = records_in_handler.lock().expect("records");
        let reply = |data: serde_json::Value| {
            FakeResponse::json(
                200,
                serde_json::json!({"code": 200, "msg": "", "data": data}).to_string(),
            )
        };
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domain") => reply(serde_json::json!({"id": "D1", "domain": "example.com"})),
            ("GET", "/recordList") => {
                let host = req.query_param("host").unwrap_or_default();
                let typ = req.query_param("type").unwrap_or_default();
                let typ_num: i64 = typ.parse().unwrap_or(0);
                let out: Vec<&serde_json::Value> = recs
                    .iter()
                    .filter(|r| {
                        r["type"].as_i64() == Some(typ_num)
                            && r["host"].as_str() == Some(host.as_str())
                    })
                    .collect();
                reply(serde_json::json!({"total": out.len(), "results": out}))
            }
            ("POST", "/record") => {
                let body = req.body_json();
                assert_eq!(body["type"], 16, "TXT 类型应为 16");
                assert_eq!(body["ttl"], 600);
                assert_eq!(body["host"], "_acme-challenge");
                for r in recs.iter() {
                    if r["host"] == body["host"]
                        && r["type"] == body["type"]
                        && r["data"] == body["data"]
                    {
                        return FakeResponse::json(200, r#"{"code":600,"msg":"与已有记录冲突"}"#);
                    }
                }
                let mut id = next.lock().expect("next");
                *id += 1;
                let id = id.to_string();
                recs.push(serde_json::json!({
                    "id": id, "host": body["host"], "type": body["type"],
                    "data": body["data"], "ttl": body["ttl"],
                }));
                reply(serde_json::json!({"id": id}))
            }
            ("DELETE", "/record") => {
                let id = req.query_param("id").unwrap_or_default();
                recs.retain(|r| r["id"] != id);
                reply(serde_json::Value::Null)
            }
            _ => panic!("未预期的请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p =
        Dnsla::with_endpoint(creds("apiid", "apisecret"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "tok1")
        .await
        .expect("add tok1");
    p.add_txt("example.com", "_acme-challenge", "tok2")
        .await
        .expect("add tok2");
    // 重复添加同值：服务商返回冲突，按成功处理。
    p.add_txt("example.com", "_acme-challenge", "tok2")
        .await
        .expect("conflict ok");
    assert_eq!(records.lock().expect("records").len(), 2);
    p.delete_txt("example.com", "_acme-challenge", "tok1")
        .await
        .expect("delete tok1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["data"], "tok2", "误删了其他值");
    }
    // 值不存在时不报错。
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");
}

/// 删除：按值挑选；值与服务商处不一致时不删除。
#[tokio::test]
async fn dnsla_delete_targets() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(100i64);
    let srv = FakeServer::start(move |req| {
        let want = basic_auth("apiid", "apisecret");
        if req.header("authorization") != Some(want.as_str()) {
            return FakeResponse {
                status: 401,
                body: Vec::new(),
            };
        }
        let mut recs = records_in_handler.lock().expect("records");
        let reply = |data: serde_json::Value| {
            FakeResponse::json(
                200,
                serde_json::json!({"code": 200, "msg": "", "data": data}).to_string(),
            )
        };
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domain") => reply(serde_json::json!({"id": "D1", "domain": "example.com"})),
            ("GET", "/recordList") => {
                let host = req.query_param("host").unwrap_or_default();
                let typ = req.query_param("type").unwrap_or_default();
                let typ_num: i64 = typ.parse().unwrap_or(0);
                let out: Vec<&serde_json::Value> = recs
                    .iter()
                    .filter(|r| {
                        r["type"].as_i64() == Some(typ_num)
                            && r["host"].as_str() == Some(host.as_str())
                    })
                    .collect();
                reply(serde_json::json!({"total": out.len(), "results": out}))
            }
            ("POST", "/record") => {
                let body = req.body_json();
                let mut id = next.lock().expect("next");
                *id += 1;
                let id = id.to_string();
                recs.push(serde_json::json!({
                    "id": id, "host": body["host"], "type": body["type"],
                    "data": body["data"], "ttl": body["ttl"],
                }));
                reply(serde_json::json!({"id": id}))
            }
            ("DELETE", "/record") => {
                let id = req.query_param("id").unwrap_or_default();
                recs.retain(|r| r["id"] != id);
                reply(serde_json::Value::Null)
            }
            _ => panic!("未预期的请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p =
        Dnsla::with_endpoint(creds("apiid", "apisecret"), http(), &srv.url()).expect("provider");
    let r = rec("example.com", "home", RecordType::A, "203.0.113.1");
    p.upsert(&r).await.expect("upsert");
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    assert!(records.lock().expect("records").is_empty());
    // 值与服务商处不一致时不删除。
    p.upsert(&r).await.expect("upsert again");
    let mut changed = r.clone();
    changed.value = "198.51.100.9".into();
    let err = delete_records(&p, &changed)
        .await
        .expect_err("value mismatch");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert_eq!(records.lock().expect("records").len(), 1);
}
