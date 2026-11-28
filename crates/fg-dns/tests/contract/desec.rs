//! deSEC 契约测试（对照上游 desec_test.go::TestDeSEC 与 TestDeSECMinimumTTL）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::desec::Desec,
};

#[tokio::test]
async fn desec_upsert_request_contract() {
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("authorization"), Some("Token tok"), "认证头");
        let mut cur = current_in_handler.lock().expect("cur");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domains/example.com/rrsets/home/A/") => match cur.clone() {
                Some(v) => FakeResponse::json(200, v.to_string()),
                None => FakeResponse::json(404, r#"{"detail":"Not found."}"#),
            },
            ("POST", "/domains/example.com/rrsets/") => {
                *cur = Some(req.body_json());
                FakeResponse::json(201, cur.clone().unwrap().to_string())
            }
            ("PUT", "/domains/example.com/rrsets/home/A/") => {
                *cur = Some(req.body_json());
                FakeResponse::json(200, cur.clone().unwrap().to_string())
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = Desec::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
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
        let cur = current.lock().expect("cur").clone().expect("rrset");
        assert_eq!(cur["ttl"], 3600, "未指定 TTL 时新建用保守下限 3600");
        assert_eq!(cur["subname"], "home");
        assert_eq!(cur["records"][0], "203.0.113.2");
    }
}

/// 根域名 subname 为空、路径用 @；TTL 上限 86400。
#[tokio::test]
async fn desec_root_subname_and_ttl_clamp() {
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        let mut cur = current_in_handler.lock().expect("cur");
        match (req.method.as_str(), req.path.as_str()) {
            // 根域名的 @ 在路径里被编码为 %40。
            ("GET", "/domains/example.com/rrsets/%40/AAAA/") => match cur.clone() {
                Some(v) => FakeResponse::json(200, v.to_string()),
                None => FakeResponse::json(404, r#"{"detail":"Not found."}"#),
            },
            ("POST", "/domains/example.com/rrsets/") => {
                *cur = Some(req.body_json());
                FakeResponse::json(201, cur.clone().unwrap().to_string())
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = Desec::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    let mut r = rec("example.com", "@", RecordType::AAAA, "::1");
    r.ttl = 999_999;
    let got = p.upsert(&r).await.expect("upsert");
    assert_eq!(got, UpsertAction::Created);
    let cur = current.lock().expect("cur").clone().expect("rrset");
    assert_eq!(cur["subname"], "", "根域名的 subname 是空字符串");
    assert_eq!(cur["ttl"], 86_400, "TTL 上限 86400");
}

/// TXT 值带引号；多值合并；重复添加不重复；全部移除时删除整个记录集；
/// TXT 类型的 upsert 自动补引号。
#[tokio::test]
async fn desec_txt_add_delete() {
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        let mut cur = current_in_handler.lock().expect("cur");
        match (req.method.as_str(), req.path.as_str()) {
            // subname 路径：_acme-challenge 与 t（TXT upsert 用）。
            ("GET", path)
                if path.starts_with("/domains/example.com/rrsets/_acme-challenge/TXT/")
                    || path.starts_with("/domains/example.com/rrsets/t/TXT/") =>
            {
                match cur.clone() {
                    Some(v) => FakeResponse::json(200, v.to_string()),
                    None => FakeResponse::json(404, r#"{"detail":"Not found."}"#),
                }
            }
            ("POST", "/domains/example.com/rrsets/") => {
                *cur = Some(req.body_json());
                FakeResponse::json(200, cur.clone().unwrap().to_string())
            }
            ("PUT", "/domains/example.com/rrsets/_acme-challenge/TXT/")
            | ("PUT", "/domains/example.com/rrsets/t/TXT/") => {
                *cur = Some(req.body_json());
                FakeResponse::json(200, cur.clone().unwrap().to_string())
            }
            ("DELETE", "/domains/example.com/rrsets/_acme-challenge/TXT/") => {
                *cur = None;
                FakeResponse::json(204, "")
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = Desec::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    {
        let cur = current.lock().expect("cur").clone().expect("rrset");
        assert_eq!(cur["records"][0], "\"v1\"", "TXT 值需带引号");
        assert_eq!(cur["ttl"], 3600, "新建 TXT 记录集使用 3600");
    }
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2 again");
    {
        let cur = current.lock().expect("cur").clone().expect("rrset");
        let records = cur["records"].as_array().expect("records");
        assert_eq!(records.len(), 2, "重复添加不应重复");
        assert_eq!(records[1], "\"v2\"");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let cur = current.lock().expect("cur").clone().expect("rrset");
        assert_eq!(cur["records"][0], "\"v2\"");
    }
    p.delete_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("delete v2");
    assert!(current.lock().expect("cur").is_none(), "应整体删除");

    // TXT 类型的 Upsert 自动补引号，引号值与原值视为未变化。
    let got = p
        .upsert(&rec("example.com", "t", RecordType::TXT, "hello"))
        .await
        .expect("upsert txt");
    assert_eq!(got, UpsertAction::Created);
    let cur = current.lock().expect("cur").clone().expect("rrset");
    assert_eq!(cur["records"][0], "\"hello\"");
    let got = p
        .upsert(&rec("example.com", "t", RecordType::TXT, "hello"))
        .await
        .expect("upsert txt unchanged");
    assert_eq!(got, UpsertAction::Unchanged);
}

/// 指定的 TTL 低于 3600 时按域名的 minimum_ttl 取下限，读取失败时退回
/// 3600；未指定 TTL 时沿用记录集现有 TTL。
#[tokio::test]
async fn desec_minimum_ttl_handling() {
    let minimum = std::sync::Arc::new(Mutex::new(60i64));
    let domain_fail = std::sync::Arc::new(Mutex::new(false));
    let minimum_in_handler = minimum.clone();
    let domain_fail_in_handler = domain_fail.clone();
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        let mut cur = current_in_handler.lock().expect("cur");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domains/example.dedyn.io/") => {
                if *domain_fail_in_handler.lock().expect("fail") {
                    return FakeResponse::json(500, "boom");
                }
                FakeResponse::json(
                    200,
                    format!(
                        r#"{{"name":"example.dedyn.io","minimum_ttl":{}}}"#,
                        minimum_in_handler.lock().expect("min")
                    ),
                )
            }
            ("GET", "/domains/example.dedyn.io/rrsets/home/A/") => match cur.clone() {
                Some(v) => FakeResponse::json(200, v.to_string()),
                None => FakeResponse::json(404, r#"{"detail":"Not found."}"#),
            },
            ("POST", "/domains/example.dedyn.io/rrsets/")
            | ("PUT", "/domains/example.dedyn.io/rrsets/home/A/") => {
                *cur = Some(req.body_json());
                FakeResponse::json(200, cur.clone().unwrap().to_string())
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = Desec::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    // 域名允许 60 秒：120 原样使用。
    let mut r = rec("example.dedyn.io", "home", RecordType::A, "203.0.113.1");
    r.ttl = 120;
    let got = p.upsert(&r).await.expect("upsert");
    assert_eq!(got, UpsertAction::Created);
    assert_eq!(
        current.lock().expect("cur").clone().expect("rrset")["ttl"],
        120
    );
    // 低于 minimum_ttl 时取 minimum_ttl。
    *minimum.lock().expect("min") = 300;
    r.ttl = 60;
    let got = p.upsert(&r).await.expect("upsert");
    assert_eq!(got, UpsertAction::Updated);
    assert_eq!(
        current.lock().expect("cur").clone().expect("rrset")["ttl"],
        300
    );
    // 未指定 TTL：值变化时沿用现有 300。
    r.ttl = 0;
    r.value = "203.0.113.2".into();
    let got = p.upsert(&r).await.expect("upsert");
    assert_eq!(got, UpsertAction::Updated);
    assert_eq!(
        current.lock().expect("cur").clone().expect("rrset")["ttl"],
        300
    );
    // 读不到 minimum_ttl 时退回 3600。
    *domain_fail.lock().expect("fail") = true;
    r.ttl = 60;
    let got = p.upsert(&r).await.expect("upsert");
    assert_eq!(got, UpsertAction::Updated);
    assert_eq!(
        current.lock().expect("cur").clone().expect("rrset")["ttl"],
        3600
    );
}

/// 删除解析：多值记录集拒绝删除，单值删除；认证失败按 Auth 归类。
#[tokio::test]
async fn desec_delete_and_errors() {
    let current = std::sync::Arc::new(Mutex::new(Some(serde_json::json!({
        "subname": "home", "type": "A",
        "records": ["1.1.1.1", "2.2.2.2"], "ttl": 3600,
    }))));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("authorization"), Some("Token tok"));
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domains/example.com/rrsets/home/A/") => {
                let cur = current_in_handler.lock().expect("cur").clone();
                FakeResponse::json(200, cur.unwrap().to_string())
            }
            ("DELETE", "/domains/example.com/rrsets/home/A/") => {
                *current_in_handler.lock().expect("cur") = None;
                FakeResponse::json(204, "")
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = Desec::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    // 记录集有其他值时应拒绝删除。
    let err = delete_records(&p, &rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("recordset has other values");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    // 单值时删除。
    *current.lock().expect("cur") = Some(serde_json::json!({
        "subname": "home", "type": "A", "records": ["1.1.1.1"], "ttl": 3600,
    }));
    let n = delete_records(&p, &rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect("delete");
    assert_eq!(n, 1);
    assert!(current.lock().expect("cur").is_none());

    // 认证失败：401。
    let err_srv =
        FakeServer::start(|_| FakeResponse::json(401, r#"{"detail":"Invalid token."}"#)).await;
    let bad = Desec::with_endpoint(creds("", "x"), http(), &err_srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("unauthorized");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
}
