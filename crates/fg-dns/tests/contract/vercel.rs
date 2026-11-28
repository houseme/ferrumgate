//! Vercel DNS 契约测试（对照上游 vercel_test.go::TestVercelUpsert、
//! TestVercelTeamAndPagination、TestVercelTXTAndDelete、TestVercelErrors）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, creds_with_extra, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::vercel::Vercel,
};

#[tokio::test]
async fn vercel_upsert_request_contract() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(0i64);
    let srv = FakeServer::start(move |req| {
        if req.header("authorization") != Some("Bearer tok") {
            return FakeResponse::json(
                403,
                r#"{"error":{"code":"forbidden","message":"Not authorized"}}"#,
            );
        }
        // 个人账号不带 teamId。
        assert_eq!(req.query_param("teamId"), None);
        let mut recs = records_in_handler.lock().expect("records");
        let mut id = next.lock().expect("next");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/v5/domains/example.com/records") => {
                let count = recs.len();
                FakeResponse::json(
                    200,
                    serde_json::json!({
                        "records": recs.clone(),
                        "pagination": {"count": count, "next": serde_json::Value::Null, "prev": serde_json::Value::Null},
                    })
                    .to_string(),
                )
            }
            ("POST", "/v2/domains/example.com/records") => {
                let mut body = req.body_json();
                *id += 1;
                body["id"] = format!("rec_{id}").into();
                if body.get("ttl").is_none() {
                    body["ttl"] = 60.into();
                }
                recs.push(body.clone());
                FakeResponse::json(200, format!(r#"{{"uid":"{}"}}"#, body["id"].as_str().unwrap()))
            }
            ("PATCH", path) if path.starts_with("/v1/domains/records/") => {
                let rid = path.trim_start_matches("/v1/domains/records/").to_owned();
                let body = req.body_json();
                for r in recs.iter_mut() {
                    if r["id"] == rid {
                        for (k, v) in body.as_object().expect("body") {
                            r[k.as_str()] = v.clone();
                        }
                        return FakeResponse::json(200, format!(r#"{{"id":"{rid}"}}"#));
                    }
                }
                FakeResponse::json(404, r#"{"error":{"code":"not_found","message":"no record"}}"#)
            }
            ("DELETE", path) if path.starts_with("/v2/domains/example.com/records/") => {
                let rid = path.trim_start_matches("/v2/domains/example.com/records/").to_owned();
                recs.retain(|r| r["id"] != rid);
                FakeResponse::json(200, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Vercel::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
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
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["name"], "home");
        assert_eq!(recs[0]["value"], "203.0.113.2");
        assert_eq!(recs[0]["ttl"], 60, "未指定 TTL 时不发送（服务商默认 60）");
        assert_eq!(recs[0]["comment"], "Created by FerrumGate");
    }
    // 根域名名称为空字符串；TTL 取最小 60。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 30;
    let got = p.upsert(&r).await.expect("upsert root");
    assert_eq!(got, UpsertAction::Created);
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs[1]["name"], "");
        assert_eq!(recs[1]["ttl"], 60, "TTL 取最小 60");
    }
    // 值大小写不同视为相同。
    r.ttl = 60;
    let got = p.upsert(&r).await.expect("upsert unchanged");
    assert_eq!(got, UpsertAction::Unchanged);
    // TTL 变化触发更新。
    r.ttl = 300;
    let got = p.upsert(&r).await.expect("upsert ttl change");
    assert_eq!(got, UpsertAction::Updated);
    let recs = records.lock().expect("records");
    assert_eq!(recs[1]["ttl"], 300, "ttl 未更新");
}

/// 团队 ID 附加到查询串；按 pagination.next 时间戳翻页。
#[tokio::test]
async fn vercel_team_and_pagination() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    {
        let mut recs = records.lock().expect("records");
        for i in 0..5 {
            recs.push(serde_json::json!({
                "id": format!("rec_{}", i + 1),
                "name": format!("h{i}"),
                "type": "A",
                "value": format!("10.0.0.{i}"),
                "ttl": 60,
            }));
        }
    }
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("authorization"), Some("Bearer tok"));
        assert_eq!(req.query_param("teamId").as_deref(), Some("team_abc"), "团队 ID 应附加到查询串");
        let recs = records_in_handler.lock().expect("records");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/v5/domains/example.com/records") => {
                // 每页 2 条，按 until 时间戳翻页。
                let start: usize = req
                    .query_param("until")
                    .and_then(|u| u.parse().ok())
                    .unwrap_or(0);
                let page_size = 2;
                let end = (start + page_size).min(recs.len());
                let has_more = start + page_size < recs.len();
                let next = if has_more {
                    serde_json::json!(end as i64)
                } else {
                    serde_json::Value::Null
                };
                FakeResponse::json(
                    200,
                    serde_json::json!({
                        "records": &recs[start..end],
                        "pagination": {"count": end - start, "next": next, "prev": serde_json::Value::Null},
                    })
                    .to_string(),
                )
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Vercel::with_endpoint(
        creds_with_extra("", "tok", &[("teamId", "team_abc")]),
        http(),
        &srv.url(),
    )
    .expect("provider");
    // 目标记录在第三页，翻页后应识别为未变化。
    let got = p
        .upsert(&rec("example.com", "h4", RecordType::A, "10.0.0.4"))
        .await
        .expect("upsert");
    assert_eq!(got, UpsertAction::Unchanged);
    assert_eq!(records.lock().expect("records").len(), 5);
}

/// TXT 与删除：POST 创建（ttl 600）；按值删除；动态域名记录按条删除。
#[tokio::test]
async fn vercel_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(0i64);
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("authorization"), Some("Bearer tok"));
        let mut recs = records_in_handler.lock().expect("records");
        let mut id = next.lock().expect("next");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/v5/domains/example.com/records") => {
                let count = recs.len();
                FakeResponse::json(
                    200,
                    serde_json::json!({
                        "records": recs.clone(),
                        "pagination": {"count": count, "next": serde_json::Value::Null, "prev": serde_json::Value::Null},
                    })
                    .to_string(),
                )
            }
            ("POST", "/v2/domains/example.com/records") => {
                let mut body = req.body_json();
                *id += 1;
                body["id"] = format!("rec_{id}").into();
                recs.push(body);
                FakeResponse::json(200, r#"{"uid":"x"}"#)
            }
            ("DELETE", path) if path.starts_with("/v2/domains/example.com/records/") => {
                let rid = path.trim_start_matches("/v2/domains/example.com/records/").to_owned();
                recs.retain(|r| r["id"] != rid);
                FakeResponse::json(200, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Vercel::with_endpoint(creds("", "tok"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0]["type"], "TXT");
        assert_eq!(recs[0]["ttl"], 600, "TXT 使用 600");
        assert_eq!(recs[0]["name"], "_acme-challenge");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["value"], "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "none")
        .await
        .expect("delete none");

    // 按条删除 A 记录。
    let r = rec("example.com", "home", RecordType::A, "203.0.113.1");
    p.upsert(&r).await.expect("upsert");
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    assert_eq!(records.lock().expect("records").len(), 1);
}

/// 错误：透出服务商错误消息并按状态归类；缺少 Token 构造时拒绝。
#[tokio::test]
async fn vercel_error_classification() {
    let srv = FakeServer::start(|_| {
        FakeResponse::json(
            403,
            r#"{"error":{"code":"forbidden","message":"Not authorized"}}"#,
        )
    })
    .await;
    let bad = Vercel::with_endpoint(creds("", "bad"), http(), &srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("forbidden");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.contains("Not authorized"), "{}", err.detail);
    assert!(err.detail.contains("forbidden"), "{}", err.detail);

    // 缺少 Token。
    let http = http();
    assert!(Vercel::new(creds("", ""), http).is_err());
}
