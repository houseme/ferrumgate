//! ClouDNS 契约测试（对照上游 cloudns_test.go::TestClouDNSUpsertAndTXT 与
//! TestClouDNSDefaultAuthAndRoot）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, creds_with_extra, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::cloudns::Cloudns,
};

type Rec = (String, String, String, String, String); // id, type, host, record, ttl

fn auth_failed() -> FakeResponse {
    FakeResponse::json(
        200,
        r#"{"status":"Failed","statusDescription":"Invalid authentication, incorrect auth-id or auth-password."}"#,
    )
}

fn success(description: &str) -> FakeResponse {
    FakeResponse::json(
        200,
        format!(r#"{{"status":"Success","statusDescription":"{description}"}}"#),
    )
}

#[tokio::test]
async fn cloudns_upsert_request_contract() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<Rec>::new()));
    let last_add = std::sync::Arc::new(Mutex::new(None::<Vec<(String, String)>>));
    let records_in_handler = records.clone();
    let last_add_in_handler = last_add.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("content-type"), Some("application/x-www-form-urlencoded"));
        let form = req.form();
        let get = |k: &str| form.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        if get("sub-auth-user").as_deref() != Some("bob") || get("auth-password").as_deref() != Some("pw") {
            return auth_failed();
        }
        assert_eq!(get("domain-name").as_deref(), Some("example.com"));
        match req.path.as_str() {
            "/dns/records.json" => {
                assert_eq!(get("host").as_deref(), Some("home"), "列表按 host 过滤");
                assert_eq!(get("type").as_deref(), Some("A"));
                let records = records_in_handler.lock().expect("records");
                if records.is_empty() {
                    return FakeResponse::json(200, "[]");
                }
                let mut out = serde_json::Map::new();
                for (id, typ, host, value, ttl) in records.iter() {
                    out.insert(
                        id.clone(),
                        serde_json::json!({"id": id, "type": typ, "host": host, "record": value, "ttl": ttl, "status": "1"}),
                    );
                }
                FakeResponse::json(200, serde_json::Value::Object(out).to_string())
            }
            "/dns/add-record.json" => {
                let (typ, host, ttl) = (
                    get("type").unwrap_or_default(),
                    get("host").unwrap_or_default(),
                    get("ttl").unwrap_or_default(),
                );
                assert_eq!(
                    get("record-type").as_deref(),
                    Some(typ.as_str()),
                    "add-record 应同时带 record-type 与 type"
                );
                *last_add_in_handler.lock().expect("last add") =
                    Some(vec![
                        ("type".to_owned(), typ.clone()),
                        ("host".to_owned(), host),
                        ("ttl".to_owned(), ttl.clone()),
                    ]);
                let new_id = format!("10{}", records_in_handler.lock().expect("records").len());
                records_in_handler.lock().expect("records").push((
                    new_id,
                    typ,
                    get("host").unwrap_or_default(),
                    get("record").unwrap_or_default(),
                    ttl,
                ));
                FakeResponse::json(
                    200,
                    r#"{"status":"Success","statusDescription":"The record was added successfully.","data":{"id":1}}"#,
                )
            }
            "/dns/mod-record.json" => {
                let id = get("record-id").unwrap_or_default();
                let mut records = records_in_handler.lock().expect("records");
                for r in records.iter_mut() {
                    if r.0 == id {
                        r.3 = get("record").unwrap_or_default();
                        r.4 = get("ttl").unwrap_or_default();
                    }
                }
                drop(records);
                success("The record was modified successfully.")
            }
            "/dns/delete-record.json" => {
                let id = get("record-id").unwrap_or_default();
                records_in_handler
                    .lock()
                    .expect("records")
                    .retain(|r| r.0 != id);
                success("The record was deleted successfully.")
            }
            other => panic!("意外请求 {other}"),
        }
    })
    .await;
    let p = Cloudns::with_endpoint(
        creds_with_extra("bob", "pw", &[("authType", "sub-auth-user")]),
        http(),
        &format!("{}/dns/", srv.url()),
    )
    .expect("provider");
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
    assert_eq!(
        last_add.lock().expect("last add").clone().expect("add"),
        vec![
            ("type".to_owned(), "A".to_owned()),
            ("host".to_owned(), "home".to_owned()),
            ("ttl".to_owned(), "3600".to_owned()),
        ],
        "新建未指定 TTL 用默认 3600"
    );
    // 自定义 TTL 取整到允许档位：100 → 300。
    let mut r = rec("example.com", "home", RecordType::A, "203.0.113.2");
    r.ttl = 100;
    assert_eq!(
        p.upsert(&r).await.expect("ttl update"),
        UpsertAction::Updated
    );
    let records = records.lock().expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].4, "300", "TTL 应取整到 300");
}

/// 根域名 host 写 "@"，列表参数 host=@；默认认证参数是 auth-id；TXT
/// 新增 TTL 60、按值删除；按条删除解析。
#[tokio::test]
async fn cloudns_root_host_and_txt_and_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<Rec>::new()));
    let records_in_handler = records.clone();
    let srv = FakeServer::start(move |req| {
        let form = req.form();
        let get = |k: &str| form.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        if get("auth-id").as_deref() != Some("42") || get("auth-password").as_deref() != Some("pw") {
            return auth_failed();
        }
        match req.path.as_str() {
            "/dns/records.json" => {
                let want_host = get("host").unwrap_or_default();
                let want_type = get("type").unwrap_or_default();
                assert!(
                    want_host == "@" || want_host == "_acme-challenge" || want_host == "home",
                    "列表的 host 参数: {want_host}"
                );
                let records = records_in_handler.lock().expect("records");
                let mut out = serde_json::Map::new();
                for (id, typ, host, value, ttl) in records.iter() {
                    if typ == &want_type && host == &want_host {
                        out.insert(
                            id.clone(),
                            serde_json::json!({"id": id, "type": typ, "host": host, "record": value, "ttl": ttl}),
                        );
                    }
                }
                if out.is_empty() {
                    FakeResponse::json(200, "[]")
                } else {
                    FakeResponse::json(200, serde_json::Value::Object(out).to_string())
                }
            }
            "/dns/add-record.json" => {
                let id = format!(
                    "id{}_{}",
                    get("host").unwrap_or_default(),
                    records_in_handler.lock().expect("records").len()
                );
                records_in_handler.lock().expect("records").push((
                    id,
                    get("type").unwrap_or_default(),
                    get("host").unwrap_or_default(),
                    get("record").unwrap_or_default(),
                    get("ttl").unwrap_or_default(),
                ));
                success("added")
            }
            "/dns/delete-record.json" => {
                let id = get("record-id").unwrap_or_default();
                records_in_handler
                    .lock()
                    .expect("records")
                    .retain(|r| r.0 != id);
                success("deleted")
            }
            other => panic!("意外请求 {other}"),
        }
    })
    .await;
    let p = Cloudns::with_endpoint(creds("42", "pw"), http(), &format!("{}/dns/", srv.url()))
        .expect("provider");
    // 根域名：add-record 的 host 是 "@"。
    assert_eq!(
        p.upsert(&rec("example.com", "@", RecordType::A, "1.1.1.1"))
            .await
            .expect("root create"),
        UpsertAction::Created
    );
    assert_eq!(
        records.lock().expect("records")[0].2,
        "@",
        "根域名 host 应写 @"
    );

    // TXT：TTL 60；按值删除。
    records.lock().expect("records").clear();
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let records = records.lock().expect("records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].4, "60", "TXT 验证记录 TTL 60");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let records = records.lock().expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].3, "v2");
    }

    // 删除：单值记录逐条删除。
    *records.lock().expect("records") = vec![(
        "500".to_owned(),
        "A".to_owned(),
        "home".to_owned(),
        "203.0.113.9".to_owned(),
        "3600".to_owned(),
    )];
    let n = delete_records(
        &p,
        &rec("example.com", "home", RecordType::A, "203.0.113.9"),
    )
    .await
    .expect("delete");
    assert_eq!(n, 1);
    assert!(records.lock().expect("records").is_empty());
}

/// 认证失败（HTTP 200 + status=Failed）按 Auth 归类；非法认证类型构造失败。
#[tokio::test]
async fn cloudns_error_classification() {
    let srv = FakeServer::start(move |req| {
        let form = req.form();
        let get = |k: &str| {
            form.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        if get("sub-auth-user").as_deref() != Some("bob")
            || get("auth-password").as_deref() != Some("pw")
        {
            return auth_failed();
        }
        FakeResponse::json(
            200,
            r#"{"status":"Failed","statusDescription":"Missing domain-name parameter."}"#,
        )
    })
    .await;
    let bad = Cloudns::with_endpoint(
        creds_with_extra("bob", "x", &[("authType", "sub-auth-user")]),
        http(),
        &format!("{}/dns/", srv.url()),
    )
    .expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("invalid auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(
        err.detail.contains("Invalid authentication"),
        "{}",
        err.detail
    );

    // 业务失败（非认证）按无效输入归类。
    let p = Cloudns::with_endpoint(
        creds_with_extra("bob", "pw", &[("authType", "sub-auth-user")]),
        http(),
        &format!("{}/dns/", srv.url()),
    )
    .expect("provider");
    let err = p
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("business failure");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);

    // 非法认证类型。
    let bad_type = Cloudns::with_endpoint(
        creds_with_extra("1", "p", &[("authType", "bogus")]),
        http(),
        "https://api.cloudns.net/dns/",
    );
    assert!(bad_type.is_err(), "非法认证类型应报错");
    // 缺少密码。
    assert!(
        Cloudns::with_endpoint(creds("1", ""), http(), "https://api.cloudns.net/dns/").is_err()
    );
}
