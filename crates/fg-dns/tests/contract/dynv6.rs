//! dynv6 契约测试（对照上游 providers_test.go::TestDynv6、TestDynv6Root、
//! TestDynv6RootTXT、TestDynv6ZoneFallback、txt_test.go、delete_test.go）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::dynv6::Dynv6,
};

#[tokio::test]
async fn dynv6_upsert_request_contract() {
    let value = Mutex::new(String::new());
    let srv = FakeServer::start(move |req| {
        let mut v = value.lock().expect("value");
        match (req.method.as_str(), req.path.as_str()) {
            // 鉴权头与 Accept 与上游一致。
            ("GET", "/zones/by-name/my.dynv6.net") => {
                assert_eq!(req.header("authorization"), Some("Bearer tok"));
                assert_eq!(req.header("accept"), Some("application/json"));
                FakeResponse::json(200, r#"{"id":7,"ipv4address":"","ipv6prefix":""}"#)
            }
            ("GET", "/zones/7/records") => {
                if v.is_empty() {
                    FakeResponse::json(200, "[]")
                } else {
                    FakeResponse::json(
                        200,
                        format!(r#"[{{"id":3,"name":"www","type":"A","data":"{v}"}}]"#),
                    )
                }
            }
            ("POST", "/zones/7/records") => {
                let body = req.body_json();
                assert_eq!(body["name"], "www");
                assert_eq!(body["type"], "A");
                *v = body["data"].as_str().expect("data").to_owned();
                FakeResponse::json(200, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Dynv6::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let action = p
        .upsert(&rec("my.dynv6.net", "www", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Created);
}

#[tokio::test]
async fn dynv6_creates_then_updates() {
    let value = Mutex::new(String::new());
    let srv = FakeServer::start(move |req| {
        let mut v = value.lock().expect("value");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones/by-name/my.dynv6.net") => {
                FakeResponse::json(200, r#"{"id":7,"ipv4address":"","ipv6prefix":""}"#)
            }
            ("GET", "/zones/7/records") => {
                if v.is_empty() {
                    FakeResponse::json(200, "[]")
                } else {
                    FakeResponse::json(
                        200,
                        format!(r#"[{{"id":3,"name":"www","type":"A","data":"{v}"}}]"#),
                    )
                }
            }
            ("POST", "/zones/7/records") => {
                let body = req.body_json();
                *v = body["data"].as_str().expect("data").to_owned();
                FakeResponse::json(200, "{}")
            }
            ("PATCH", "/zones/7/records/3") => {
                // 更新只发 data 字段。
                let body = req.body_json();
                assert!(body.get("name").is_none() && body.get("type").is_none());
                *v = body["data"].as_str().expect("data").to_owned();
                FakeResponse::json(200, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Dynv6::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let steps = [
        ("203.0.113.1", UpsertAction::Created),
        ("203.0.113.1", UpsertAction::Unchanged),
        ("203.0.113.2", UpsertAction::Updated),
    ];
    for (value, want) in steps {
        let action = p
            .upsert(&rec("my.dynv6.net", "www", RecordType::A, value))
            .await
            .expect("upsert");
        assert_eq!(action, want, "value={value}");
    }
}

#[tokio::test]
async fn dynv6_root_address_patches_zone() {
    let zone = std::sync::Arc::new(Mutex::new((7i64, String::new(), String::new()))); // (id, ipv4, ipv6)
    let patched = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let zone_in_handler = zone.clone();
    let patched_in_handler = patched.clone();
    let srv = FakeServer::start(move |req| {
        let mut z = zone_in_handler.lock().expect("zone");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones/by-name/my.dynv6.net") => FakeResponse::json(
                200,
                format!(
                    r#"{{"id":{},"ipv4address":"{}","ipv6prefix":"{}"}}"#,
                    z.0, z.1, z.2
                ),
            ),
            ("PATCH", "/zones/7") => {
                let body = req.body_json();
                patched_in_handler
                    .lock()
                    .expect("patched")
                    .push(body.clone());
                if let Some(v) = body["ipv4address"].as_str() {
                    z.1 = v.to_owned();
                }
                if let Some(v) = body["ipv6prefix"].as_str() {
                    z.2 = v.to_owned();
                }
                FakeResponse::json(200, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Dynv6::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    // 根域名 A 通过 PATCH zone 的 ipv4address 更新。
    let action = p
        .upsert(&rec("my.dynv6.net", "@", RecordType::A, "203.0.113.1"))
        .await
        .expect("a");
    assert_eq!(action, UpsertAction::Updated);
    assert_eq!(
        patched.lock().expect("patched").last().expect("patch")["ipv4address"],
        "203.0.113.1"
    );
    // 相同地址不再 PATCH。
    let action = p
        .upsert(&rec("my.dynv6.net", "@", RecordType::A, "203.0.113.1"))
        .await
        .expect("a same");
    assert_eq!(action, UpsertAction::Unchanged);
    assert_eq!(patched.lock().expect("patched").len(), 1);
    // AAAA 走 ipv6prefix；接口返回展开写法或带前缀长度时按地址比较视为不变。
    let action = p
        .upsert(&rec("my.dynv6.net", "@", RecordType::AAAA, "2001:db8::1"))
        .await
        .expect("aaaa");
    assert_eq!(action, UpsertAction::Updated);
    {
        let mut z = zone.lock().expect("zone");
        z.2 = "2001:0db8:0000:0000:0000:0000:0000:0001/64".to_owned();
    }
    let action = p
        .upsert(&rec("my.dynv6.net", "@", RecordType::AAAA, "2001:db8::1"))
        .await
        .expect("aaaa expanded");
    assert_eq!(action, UpsertAction::Unchanged);
    assert_eq!(patched.lock().expect("patched").len(), 2);
}

#[tokio::test]
async fn dynv6_root_txt_uses_records_endpoint() {
    let created = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let created_in_handler = created.clone();
    let srv = FakeServer::start(move |req| {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones/by-name/my.dynv6.net") => FakeResponse::json(
                200,
                r#"{"id":7,"ipv4address":"203.0.113.1","ipv6prefix":""}"#,
            ),
            ("GET", "/zones/7/records") => FakeResponse::json(200, "[]"),
            ("POST", "/zones/7/records") => {
                // 根域名的 TXT 仍走 records 接口，name 为空串。
                *created_in_handler.lock().expect("created") = Some(req.body_json());
                FakeResponse::json(200, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Dynv6::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let action = p
        .upsert(&rec("my.dynv6.net", "@", RecordType::TXT, "hello"))
        .await
        .expect("txt");
    assert_eq!(action, UpsertAction::Created);
    let body = created
        .lock()
        .expect("created")
        .clone()
        .expect("created body");
    assert_eq!(body["name"], "");
    assert_eq!(body["type"], "TXT");
    assert_eq!(body["data"], "hello");
}

#[tokio::test]
async fn dynv6_zone_fallback_recovers_longer_zone() {
    let value = Mutex::new(String::new());
    let srv = FakeServer::start(move |req| {
        let mut v = value.lock().expect("value");
        match (req.method.as_str(), req.path.as_str()) {
            // 主域名误填 dynv6.net：zone 查询 404，逐级回退到 my.dynv6.net。
            ("GET", "/zones/by-name/dynv6.net") | ("GET", "/zones/by-name/a.my.dynv6.net") => {
                FakeResponse::json(404, r#"{"message":"Not Found"}"#)
            }
            ("GET", "/zones/by-name/my.dynv6.net") => {
                FakeResponse::json(200, r#"{"id":7,"ipv4address":"","ipv6prefix":""}"#)
            }
            ("GET", "/zones/7/records") => {
                if v.is_empty() {
                    FakeResponse::json(200, "[]")
                } else {
                    FakeResponse::json(
                        200,
                        format!(r#"[{{"id":3,"name":"a","type":"AAAA","data":"{v}"}}]"#),
                    )
                }
            }
            ("POST", "/zones/7/records") => {
                let body = req.body_json();
                assert_eq!(body["name"], "a");
                *v = body["data"].as_str().expect("data").to_owned();
                FakeResponse::json(200, "{}")
            }
            ("PATCH", "/zones/7/records/3") => {
                let body = req.body_json();
                *v = body["data"].as_str().expect("data").to_owned();
                FakeResponse::json(200, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Dynv6::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let steps = [
        ("2001:db8::1", UpsertAction::Created),
        ("2001:db8::1", UpsertAction::Unchanged),
        ("2001:db8::2", UpsertAction::Updated),
    ];
    for (value, want) in steps {
        let action = p
            .upsert(&rec("dynv6.net", "a.my", RecordType::AAAA, value))
            .await
            .expect("upsert");
        assert_eq!(action, want, "value={value}");
    }
}

#[tokio::test]
async fn dynv6_error_classification() {
    // 认证失败。
    let srv = FakeServer::start(|req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/zones/by-name/my.dynv6.net") => FakeResponse::json(401, "unauthorized"),
        _ => text(500, "unexpected"),
    })
    .await;
    let p = Dynv6::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("my.dynv6.net", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(!err.detail.contains("tok"), "令牌不应出现在错误信息里");

    // zone 不存在且没有可回退的子域名标签：未找到。
    let srv2 = FakeServer::start(|req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/zones/by-name/other.net") => {
            FakeResponse::json(404, r#"{"message":"Not Found"}"#)
        }
        _ => text(500, "unexpected"),
    })
    .await;
    let p2 = Dynv6::with_endpoint(creds("", "tok"), http(), &srv2.url()).expect("provider");
    let err = p2
        .upsert(&rec("other.net", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("not found");
    assert_eq!(err.kind, ProviderErrorKind::NotFound);
}

#[tokio::test]
async fn dynv6_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<(i64, String, String)>::new())); // (id, name, data)
    let records_in_handler = records.clone();
    let next = Mutex::new(0i64);
    let srv = FakeServer::start(move |req| {
        let mut id = next.lock().expect("next");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/zones/by-name/example.com") => {
                FakeResponse::json(200, r#"{"id":1,"ipv4address":"","ipv6prefix":""}"#)
            }
            ("POST", "/zones/1/records") => {
                let body = req.body_json();
                *id += 1;
                records_in_handler.lock().expect("records").push((
                    *id,
                    body["name"].as_str().expect("name").to_owned(),
                    body["data"].as_str().expect("data").to_owned(),
                ));
                FakeResponse::json(200, "{}")
            }
            ("GET", "/zones/1/records") => {
                let recs = records_in_handler.lock().expect("records");
                let list: Vec<String> = recs
                    .iter()
                    .map(|(rid, name, data)| {
                        format!(r#"{{"id":{rid},"name":"{name}","type":"TXT","data":"{data}"}}"#)
                    })
                    .collect();
                FakeResponse::json(200, format!("[{}]", list.join(",")))
            }
            ("DELETE", path) if path.starts_with("/zones/1/records/") => {
                let rid: i64 = path
                    .rsplit('/')
                    .next()
                    .expect("id")
                    .parse()
                    .expect("id num");
                records_in_handler
                    .lock()
                    .expect("records")
                    .retain(|(k, _, _)| k != &rid);
                FakeResponse::json(200, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Dynv6::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    assert_eq!(records.lock().expect("records").len(), 2);
    // 按值删除。
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].2, "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");
}

#[tokio::test]
async fn dynv6_delete_targets() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<(i64, String, String, String)>::new())); // (id, name, type, data)
    let records_in_handler = records.clone();
    let srv = FakeServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/zones/by-name/my.dynv6.net") => {
            FakeResponse::json(200, r#"{"id":7,"ipv4address":"","ipv6prefix":""}"#)
        }
        ("GET", "/zones/7/records") => {
            let recs = records_in_handler.lock().expect("records");
            let list: Vec<String> = recs
                .iter()
                .map(|(rid, name, typ, data)| {
                    format!(r#"{{"id":{rid},"name":"{name}","type":"{typ}","data":"{data}"}}"#)
                })
                .collect();
            FakeResponse::json(200, format!("[{}]", list.join(",")))
        }
        ("DELETE", path) if path.starts_with("/zones/7/records/") => {
            let rid: i64 = path
                .rsplit('/')
                .next()
                .expect("id")
                .parse()
                .expect("id num");
            records_in_handler
                .lock()
                .expect("records")
                .retain(|(k, _, _, _)| k != &rid);
            FakeResponse::json(200, "{}")
        }
        _ => text(500, "unexpected"),
    })
    .await;
    let p = Dynv6::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    {
        let mut recs = records.lock().expect("records");
        recs.push((3, "www".into(), "A".into(), "1.1.1.1".into()));
        recs.push((4, "www".into(), "A".into(), "2.2.2.2".into()));
        recs.push((5, "www".into(), "AAAA".into(), "2001:db8::1".into()));
    }
    let mut r = rec("my.dynv6.net", "www", RecordType::A, "");
    // 值未知：拒绝。
    assert!(delete_records(&p, &r).await.is_err());
    r.value = "2.2.2.2".into();
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    let recs = records.lock().expect("records");
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|(id, _, _, _)| id != &4));
}
