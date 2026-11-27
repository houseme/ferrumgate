//! Gandi LiveDNS 契约测试（对照上游 more_test.go::TestGandi、
//! keepttl_test.go::TestGandiKeepsTTLNS1DefaultTTLOnUpdate、delete_test.go）。

mod fake;

use std::sync::{Arc, Mutex};

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::gandi::Gandi,
};

#[tokio::test]
async fn gandi_upsert_request_contract() {
    let values = Arc::new(Mutex::new(Vec::<String>::new()));
    let values_in_handler = values.clone();
    let srv = FakeServer::start(move |req| {
        assert_eq!(req.header("authorization"), Some("Bearer pat"));
        assert_eq!(req.header("content-type"), Some("application/json"));
        assert!(
            req.path.starts_with("/domains/example.com/records/"),
            "{}",
            req.path
        );
        match req.method.as_str() {
            "GET" => {
                let vals = values_in_handler.lock().expect("values");
                if vals.is_empty() {
                    FakeResponse::json(404, r#"{"message":"not found"}"#)
                } else {
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"rrset_values":{}, "rrset_ttl":300}}"#,
                            vals_json(&vals)
                        ),
                    )
                }
            }
            "PUT" => {
                let body = req.body_json();
                *values_in_handler.lock().expect("values") = body["rrset_values"]
                    .as_array()
                    .expect("values")
                    .iter()
                    .map(|v| v.as_str().expect("str").to_owned())
                    .collect();
                FakeResponse::json(201, r#"{"message":"ok"}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Gandi::with_endpoint(creds("", "pat"), http(), &srv.url()).expect("provider");
    // 记录不存在（404）→ 创建。
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
    // TTL 0 → 最小值 300。
    assert_eq!(put["rrset_values"][0], "203.0.113.1");
    assert_eq!(put["rrset_ttl"], 300);
    // 值相同 → 不动；值变化 → 更新。
    let action = p
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect("unchanged");
    assert_eq!(action, UpsertAction::Unchanged);
    let action = p
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.2"))
        .await
        .expect("update");
    assert_eq!(action, UpsertAction::Updated);
}

#[tokio::test]
async fn gandi_ttl_zero_keeps_existing() {
    // 未指定 TTL 时沿用记录现有值 900（keepttl_test）。
    let values = Arc::new(Mutex::new(vec!["1.1.1.1".to_owned()]));
    let values_in_handler = values.clone();
    let srv = FakeServer::start(move |req| match req.method.as_str() {
        "GET" => {
            let vals = values_in_handler.lock().expect("values");
            FakeResponse::json(
                200,
                format!(
                    r#"{{"rrset_values":{}, "rrset_ttl":900}}"#,
                    vals_json(&vals)
                ),
            )
        }
        "PUT" => {
            let body = req.body_json();
            *values_in_handler.lock().expect("values") = body["rrset_values"]
                .as_array()
                .expect("values")
                .iter()
                .map(|v| v.as_str().expect("str").to_owned())
                .collect();
            FakeResponse::json(201, "{}")
        }
        _ => text(500, "unexpected"),
    })
    .await;
    let p = Gandi::with_endpoint(creds("", "pat"), http(), &srv.url()).expect("provider");
    let action = p
        .upsert(&rec("example.com", "www", RecordType::A, "2.2.2.2"))
        .await
        .expect("update");
    assert_eq!(action, UpsertAction::Updated);
    let put = srv
        .requests()
        .iter()
        .find(|r| r.method == "PUT")
        .expect("put")
        .body_json();
    assert_eq!(put["rrset_ttl"], 900, "Gandi 应沿用 TTL 900");
}

#[tokio::test]
async fn gandi_error_classification() {
    // 认证失败。
    let srv = FakeServer::start(|req| match req.method.as_str() {
        "GET" => FakeResponse::json(401, r#"{"message":"invalid token"}"#),
        _ => text(500, "unexpected"),
    })
    .await;
    let p = Gandi::with_endpoint(creds("", "pat"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);

    // 服务器错误。
    let srv2 = FakeServer::start(|_| FakeResponse::json(500, "boom")).await;
    let p2 = Gandi::with_endpoint(creds("", "pat"), http(), &srv2.url()).expect("provider");
    let err = p2
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("server");
    assert_eq!(err.kind, ProviderErrorKind::Server);
}

#[tokio::test]
async fn gandi_txt_add_delete() {
    // TXT：新增两个带引号的值，删除其一后仍保留另一个；删空后整体删除。
    let values = Arc::new(Mutex::new(Vec::<String>::new()));
    let values_in_handler = values.clone();
    let srv = FakeServer::start(move |req| {
        assert!(
            req.path
                .starts_with("/domains/example.com/records/_acme-challenge/TXT"),
            "{}",
            req.path
        );
        match req.method.as_str() {
            "GET" => {
                let vals = values_in_handler.lock().expect("values");
                if vals.is_empty() {
                    FakeResponse::json(404, r#"{"message":"not found"}"#)
                } else {
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"rrset_values":{}, "rrset_ttl":300}}"#,
                            vals_json(&vals)
                        ),
                    )
                }
            }
            "PUT" => {
                let body = req.body_json();
                *values_in_handler.lock().expect("values") = body["rrset_values"]
                    .as_array()
                    .expect("values")
                    .iter()
                    .map(|v| v.as_str().expect("str").to_owned())
                    .collect();
                FakeResponse::json(201, "{}")
            }
            "DELETE" => {
                values_in_handler.lock().expect("values").clear();
                FakeResponse::json(204, "{}")
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Gandi::with_endpoint(creds("", "pat"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let vals = values.lock().expect("values");
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0], r#""v1""#, "TXT 值写入时带引号");
    }
    // 按值删除（去引号比较）。
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    assert_eq!(*values.lock().expect("values"), vec![r#""v2""#]);
    // 最后一个值：整体删除记录集。
    p.delete_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("delete v2");
    assert!(values.lock().expect("values").is_empty());
}

#[tokio::test]
async fn gandi_delete_targets() {
    let values = Arc::new(Mutex::new(vec!["1.1.1.1".to_owned(), "3.3.3.3".to_owned()]));
    let values_in_handler = values.clone();
    let srv = FakeServer::start(move |req| match req.method.as_str() {
        "GET" => {
            let vals = values_in_handler.lock().expect("values");
            if vals.is_empty() {
                FakeResponse::json(404, r#"{"message":"not found"}"#)
            } else {
                FakeResponse::json(
                    200,
                    format!(
                        r#"{{"rrset_values":{}, "rrset_ttl":300}}"#,
                        vals_json(&vals)
                    ),
                )
            }
        }
        "DELETE" => {
            values_in_handler.lock().expect("values").clear();
            FakeResponse::json(204, "{}")
        }
        _ => text(500, "unexpected"),
    })
    .await;
    let p = Gandi::with_endpoint(creds("", "pat"), http(), &srv.url()).expect("provider");
    // 记录集里还有其他值：不删除。
    let r = rec("example.com", "home", RecordType::A, "1.1.1.1");
    let err = delete_records(&p, &r).await.expect_err("recordset");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert_eq!(values.lock().expect("values").len(), 2);
    // 只剩目标值：整体删除记录集。
    *values.lock().expect("values") = vec!["1.1.1.1".to_owned()];
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    assert!(values.lock().expect("values").is_empty());
    // 记录不存在：删除 0 条。
    let n = delete_records(&p, &r).await.expect("empty");
    assert_eq!(n, 0);
}

fn vals_json(values: &[String]) -> String {
    let items = values
        .iter()
        .map(|v| serde_json::json!(v).to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}
