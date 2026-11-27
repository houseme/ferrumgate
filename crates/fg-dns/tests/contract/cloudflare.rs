//! Cloudflare 契约测试（对照上游 providers_test.go::TestCloudflare、
//! cloudflare_proxied_test.go、txt_test.go::TestTXTCloudflare、
//! delete_test.go::TestCloudflareDelete）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, creds_with_extra, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::cloudflare::Cloudflare,
};

struct State {
    value: String,
}

#[tokio::test]
async fn cloudflare_upsert_request_contract() {
    let state = Mutex::new(State {
        value: String::new(),
    });
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones") => {
                FakeResponse::json(200, r#"{"success":true,"result":[{"id":"z1","name":"example.com"}]}"#)
            }
            ("GET", "/zones/z1/dns_records") => {
                if st.value.is_empty() {
                    FakeResponse::json(200, r#"{"success":true,"result":[]}"#)
                } else {
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"success":true,"result":[{{"id":"r1","type":"A","name":"home.example.com","content":"{}","ttl":1,"proxied":true}}]}}"#,
                            st.value
                        ),
                    )
                }
            }
            ("POST", "/zones/z1/dns_records") => {
                st.value = req.body_json()["content"].as_str().expect("content").to_owned();
                FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Cloudflare::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let action = p
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Created);

    let reqs = srv.requests();
    assert_eq!(reqs.len(), 3);
    // 区域定位：GET /zones?name=example.com，Bearer 认证。
    assert_eq!(
        (reqs[0].method.as_str(), reqs[0].path.as_str()),
        ("GET", "/zones")
    );
    assert_eq!(reqs[0].query_param("name").as_deref(), Some("example.com"));
    assert_eq!(reqs[0].header("authorization"), Some("Bearer tok"));
    assert_eq!(reqs[0].header("content-type"), Some("application/json"));
    // 记录定位：GET /zones/z1/dns_records?type=A&name=home.example.com。
    assert_eq!(reqs[1].path, "/zones/z1/dns_records");
    assert_eq!(reqs[1].query_param("type").as_deref(), Some("A"));
    assert_eq!(
        reqs[1].query_param("name").as_deref(),
        Some("home.example.com")
    );
    // 创建：POST，请求体与上游测试一致；TTL 0 发送 1（自动）。
    assert_eq!(reqs[2].method, "POST");
    let body = reqs[2].body_json();
    assert_eq!(body["type"], "A");
    assert_eq!(body["name"], "home.example.com");
    assert_eq!(body["content"], "203.0.113.1");
    assert_eq!(body["ttl"], 1);
    assert_eq!(body["proxied"], false);
}

#[tokio::test]
async fn cloudflare_global_api_key_uses_email_headers() {
    let state = Mutex::new(State {
        value: String::new(),
    });
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones") => {
                // 邮箱 ID 必须用 X-Auth-Email / X-Auth-Key 认证。
                assert_eq!(req.header("x-auth-email"), Some("admin@example.com"));
                assert_eq!(req.header("x-auth-key"), Some("gk"));
                assert_eq!(req.header("authorization"), None);
                FakeResponse::json(
                    200,
                    r#"{"success":true,"result":[{"id":"z1","name":"example.com"}]}"#,
                )
            }
            ("GET", "/zones/z1/dns_records") => {
                FakeResponse::json(200, r#"{"success":true,"result":[]}"#)
            }
            ("POST", "/zones/z1/dns_records") => {
                st.value = "1.1.1.1".to_owned();
                FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Cloudflare::with_endpoint(creds("admin@example.com", "gk"), http(), &srv.url())
        .expect("provider");
    p.upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect("upsert with global key");
}

#[tokio::test]
async fn cloudflare_upsert_response_parsed() {
    let state = Mutex::new(State {
        value: String::new(),
    });
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones") => FakeResponse::json(
                200,
                r#"{"success":true,"result":[{"id":"z1","name":"example.com"}]}"#,
            ),
            ("GET", "/zones/z1/dns_records") => {
                FakeResponse::json(200, r#"{"success":true,"result":[]}"#)
            }
            ("POST", "/zones/z1/dns_records") => {
                st.value = "203.0.113.1".to_owned();
                FakeResponse::json(200, r#"{"success":true,"result":{"id":"new1"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Cloudflare::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let action = p
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Created);
}

#[tokio::test]
async fn cloudflare_creates_then_updates() {
    let state = Mutex::new(State {
        value: String::new(),
    });
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones") => {
                FakeResponse::json(200, r#"{"success":true,"result":[{"id":"z1","name":"example.com"}]}"#)
            }
            ("GET", "/zones/z1/dns_records") => {
                if st.value.is_empty() {
                    FakeResponse::json(200, r#"{"success":true,"result":[]}"#)
                } else {
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"success":true,"result":[{{"id":"r1","type":"A","name":"home.example.com","content":"{}","ttl":1,"proxied":true}}]}}"#,
                            st.value
                        ),
                    )
                }
            }
            ("POST", "/zones/z1/dns_records") => {
                st.value = req.body_json()["content"].as_str().expect("content").to_owned();
                FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
            }
            ("PATCH", "/zones/z1/dns_records/r1") => {
                let body = req.body_json();
                // PATCH 不带 proxied：服务商处的代理状态保持不变。
                assert!(body.get("proxied").is_none(), "不应改动代理状态: {body}");
                st.value = body["content"].as_str().expect("content").to_owned();
                FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Cloudflare::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let steps = [
        ("203.0.113.1", UpsertAction::Created),
        ("203.0.113.1", UpsertAction::Unchanged),
        ("203.0.113.2", UpsertAction::Updated),
    ];
    for (value, want) in steps {
        let mut r = rec("example.com", "home", RecordType::A, value);
        r.ttl = 300;
        let action = p.upsert(&r).await.expect("upsert");
        assert_eq!(action, want, "value={value}");
    }
}

#[tokio::test]
async fn cloudflare_error_classification() {
    // 认证失败：403 + 信封错误，透出 Cloudflare 的错误消息。
    let srv = FakeServer::start(|req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/zones") => FakeResponse::json(
            403,
            r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}"#,
        ),
        _ => text(500, "unexpected"),
    })
    .await;
    let p = Cloudflare::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(
        err.detail.contains("Invalid access token"),
        "{}",
        err.detail
    );

    // 限速与服务器错误按 HTTP 状态归类。
    let status = Mutex::new(429u16);
    let srv2 = FakeServer::start(move |_| {
        let mut st = status.lock().expect("status");
        let current = *st;
        *st = 500;
        FakeResponse::json(
            current,
            r#"{"success":false,"errors":[{"code":0,"message":"slow down"}]}"#,
        )
    })
    .await;
    let p2 = Cloudflare::with_endpoint(creds("", "tok"), http(), &srv2.url()).expect("provider");
    let err = p2
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("rate limited");
    assert_eq!(err.kind, ProviderErrorKind::RateLimited);
    let err = p2
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("server");
    assert_eq!(err.kind, ProviderErrorKind::Server);
}

#[tokio::test]
async fn cloudflare_ttl_zero_and_line_default() {
    let state = Mutex::new(State {
        value: String::new(),
    });
    let posted = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let posted_in_handler = posted.clone();
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones") => {
                FakeResponse::json(200, r#"{"success":true,"result":[{"id":"z1","name":"example.com"}]}"#)
            }
            ("GET", "/zones/z1/dns_records") => {
                if st.value.is_empty() {
                    FakeResponse::json(200, r#"{"success":true,"result":[]}"#)
                } else {
                    // 已有代理记录读回 TTL 恒为 1。
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"success":true,"result":[{{"id":"r1","type":"A","name":"home.example.com","content":"{}","ttl":1,"proxied":true}}]}}"#,
                            st.value
                        ),
                    )
                }
            }
            ("POST", "/zones/z1/dns_records") => {
                posted_in_handler.lock().expect("posted").push(req.body_json());
                st.value = req.body_json()["content"].as_str().expect("content").to_owned();
                FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
            }
            ("PATCH", "/zones/z1/dns_records/r1") => {
                st.value = req.body_json()["content"].as_str().expect("content").to_owned();
                FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    // 配置了代理状态：代理记录 TTL 只能是自动（1），指定 TTL 也必须发送 1。
    let p = Cloudflare::with_endpoint(
        creds_with_extra("", "tok", &[("proxied", "true")]),
        http(),
        &srv.url(),
    )
    .expect("provider");
    let mut r = rec("example.com", "home", RecordType::A, "1.1.1.1");
    r.ttl = 300;
    let action = p.upsert(&r).await.expect("create");
    assert_eq!(action, UpsertAction::Created);
    {
        let posts = posted.lock().expect("posted");
        assert_eq!(posts[0]["ttl"], 1);
        assert_eq!(posts[0]["proxied"], true);
    }
    // 已有代理记录且值相同：不因 TTL 差异反复更新。
    let action = p.upsert(&r).await.expect("unchanged");
    assert_eq!(action, UpsertAction::Unchanged);
    // 值变化时 TTL 仍固定为 1。
    r.value = "2.2.2.2".into();
    let action = p.upsert(&r).await.expect("update");
    assert_eq!(action, UpsertAction::Updated);
    let reqs = srv.requests();
    let patch = reqs
        .iter()
        .rev()
        .find(|q| q.method == "PATCH")
        .expect("patch");
    assert_eq!(patch.body_json()["ttl"], 1);
}

#[tokio::test]
async fn cloudflare_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<(String, String)>::new())); // (id, 带引号的 content)
    let records_in_handler = records.clone();
    let next = Mutex::new(0i64);
    let srv = FakeServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/zones") => FakeResponse::json(
            200,
            r#"{"success":true,"result":[{"id":"z1","name":"example.com"}]}"#,
        ),
        ("POST", "/zones/z1/dns_records") => {
            let body = req.body_json();
            let mut id = next.lock().expect("next");
            *id += 1;
            records_in_handler.lock().expect("records").push((
                id.to_string(),
                format!("\"{}\"", body["content"].as_str().expect("content")),
            ));
            FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
        }
        ("GET", "/zones/z1/dns_records") => {
            let recs = records_in_handler.lock().expect("records");
            let list: Vec<serde_json::Value> = recs
                .iter()
                .map(|(id, content)| {
                    serde_json::json!({
                        "id": id,
                        "type": "TXT",
                        "name": "_acme-challenge.example.com",
                        "content": content,
                    })
                })
                .collect();
            FakeResponse::json(
                200,
                serde_json::json!({"success": true, "result": list}).to_string(),
            )
        }
        ("DELETE", path) if path.starts_with("/zones/z1/dns_records/") => {
            let id = path.rsplit('/').next().expect("id").to_owned();
            records_in_handler
                .lock()
                .expect("records")
                .retain(|(rid, _)| rid != &id);
            FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
        }
        _ => text(500, "unexpected"),
    })
    .await;
    let p = Cloudflare::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    // 同一主机名的两个验证值：总是新增。
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    assert_eq!(records.lock().expect("records").len(), 2);
    let create = srv
        .requests()
        .iter()
        .find(|q| q.method == "POST")
        .expect("create")
        .body_json();
    assert_eq!(create["ttl"], 120, "TXT 记录使用 120");
    assert_eq!(create["name"], "_acme-challenge.example.com");
    // 按值删除：服务商返回的值带引号，去引号后比较。
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].1, r#""v2""#);
    }
    // 删除不存在的值不报错。
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");
}

#[tokio::test]
async fn cloudflare_delete_targets() {
    let records = std::sync::Arc::new(Mutex::new(vec![
        ("a".to_owned(), "1.1.1.1".to_owned()),
        ("b".to_owned(), "2.2.2.2".to_owned()),
    ]));
    let records_in_handler = records.clone();
    let deleted = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
    let deleted_in_handler = deleted.clone();
    let srv = FakeServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/zones") => FakeResponse::json(
            200,
            r#"{"success":true,"result":[{"id":"z1","name":"example.com"}]}"#,
        ),
        ("GET", "/zones/z1/dns_records") => {
            let recs = records_in_handler.lock().expect("records");
            let list: Vec<serde_json::Value> = recs
                .iter()
                .map(|(id, content)| {
                    serde_json::json!({
                        "id": id,
                        "type": "A",
                        "name": "home.example.com",
                        "content": content,
                    })
                })
                .collect();
            FakeResponse::json(
                200,
                serde_json::json!({"success": true, "result": list}).to_string(),
            )
        }
        ("DELETE", path) if path.starts_with("/zones/z1/dns_records/") => {
            let id = path.rsplit('/').next().expect("id").to_owned();
            records_in_handler
                .lock()
                .expect("records")
                .retain(|(rid, _)| rid != &id);
            deleted_in_handler.lock().expect("deleted").push(id);
            FakeResponse::json(200, r#"{"success":true,"result":{}}"#)
        }
        _ => text(500, "unexpected"),
    })
    .await;
    let p = Cloudflare::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let mut r = rec("example.com", "home", RecordType::A, "");
    // 值未知且有多条：拒绝删除，一条不动。
    let err = delete_records(&p, &r).await.expect_err("unknown value");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(deleted.lock().expect("deleted").is_empty());
    // 按最近同步的值挑选。
    r.value = "2.2.2.2".into();
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    assert_eq!(*deleted.lock().expect("deleted"), vec!["b".to_owned()]);
    // 记录不存在时返回 0。
    records.lock().expect("records").clear();
    let n = delete_records(&p, &r).await.expect("delete empty");
    assert_eq!(n, 0);
}
