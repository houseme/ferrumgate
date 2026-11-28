//! 华为云 DNS 契约测试（对照上游 providers_test.go::TestHuaweiCloud、
//! keepttl_test.go::TestHuaweiCloudDefaultTTLOnUpdate、remark_test.go::
//! TestHuaweiCloudDescription、txt.go 的华为云分节、delete_test.go::
//! TestHuaweiCloudDelete）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::huaweicloud::HuaweiCloud,
};

/// 用请求头里的 X-Sdk-Date 按同一算法重算签名并比对（上游用固定前缀断言 +
/// 同法重算）。
fn verify_hw_auth(req: &fake::RecordedRequest, body: &[u8]) {
    let x_sdk_date = req.header("x-sdk-date").expect("X-Sdk-Date").to_owned();
    let host = req.header("host").expect("Host").to_owned();
    let pairs: Vec<(String, String)> = req.query_pairs();
    let want = fg_dns::sign::huawei::authorization(
        "ak",
        "sk",
        &req.method,
        &req.path,
        &pairs,
        &host,
        &x_sdk_date,
        body,
    );
    assert_eq!(
        req.header("authorization"),
        Some(want.as_str()),
        "华为云签名不一致"
    );
}

#[tokio::test]
async fn huaweicloud_upsert_request_contract() {
    let value = Mutex::new(String::new());
    let srv = FakeServer::start(move |req| {
        let mut st = value.lock().expect("state");
        verify_hw_auth(req, &req.body);
        assert!(
            req.header("authorization")
                .expect("auth")
                .starts_with("SDK-HMAC-SHA256 Access=ak, SignedHeaders=host;x-sdk-date, Signature=")
        );
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/v2/zones") => {
                assert_eq!(req.query_param("name").as_deref(), Some("example.com."));
                assert_eq!(req.query_param("search_mode").as_deref(), Some("equal"));
                FakeResponse::json(200, r#"{"zones":[{"id":"z1","name":"example.com."}]}"#)
            }
            ("GET", "/v2/zones/z1/recordsets") => {
                assert_eq!(req.query_param("name").as_deref(), Some("www.example.com."));
                assert_eq!(req.query_param("type").as_deref(), Some("A"));
                if st.is_empty() {
                    return FakeResponse::json(200, r#"{"recordsets":[]}"#);
                }
                FakeResponse::json(
                    200,
                    format!(
                        r#"{{"recordsets":[{{"id":"rs1","name":"www.example.com.","type":"A","ttl":300,"records":["{st}"]}}]}}"#
                    ),
                )
            }
            ("POST", "/v2/zones/z1/recordsets") | ("PUT", "/v2/zones/z1/recordsets/rs1") => {
                let body = req.body_json();
                *st = body["records"][0].as_str().expect("record").to_owned();
                FakeResponse::json(200, r#"{}"#)
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = HuaweiCloud::with_endpoint(creds("ak", "sk"), http(), &srv.url()).expect("provider");
    let steps = [
        ("203.0.113.1", UpsertAction::Created),
        ("203.0.113.1", UpsertAction::Unchanged),
        ("203.0.113.2", UpsertAction::Updated),
    ];
    for (v, want) in steps {
        let r = rec("example.com", "www", RecordType::A, v);
        let got = p.upsert(&r).await.expect("upsert");
        assert_eq!(got, want, "value={v}");
    }
}

/// 未指定 TTL 时 PUT 更新为 300（keepttl 契约）。
#[tokio::test]
async fn huaweicloud_ttl_zero_update_uses_default_300() {
    let put_body = std::sync::Arc::new(Mutex::new(None));
    let put_body_in_handler = put_body.clone();
    let srv = FakeServer::start(move |req| {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/v2/zones") => {
                FakeResponse::json(200, r#"{"zones":[{"id":"z1","name":"example.com."}]}"#)
            }
            ("GET", "/v2/zones/z1/recordsets") => FakeResponse::json(
                200,
                r#"{"recordsets":[{"id":"rs1","name":"www.example.com.","type":"A","ttl":120,"records":["1.1.1.1"]}]}"#,
            ),
            ("PUT", "/v2/zones/z1/recordsets/rs1") => {
                *put_body_in_handler.lock().expect("put") = Some(req.body_json());
                FakeResponse::json(200, r#"{}"#)
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = HuaweiCloud::with_endpoint(creds("ak", "sk"), http(), &srv.url()).expect("provider");
    let got = p
        .upsert(&rec("example.com", "www", RecordType::A, "2.2.2.2"))
        .await
        .expect("upsert");
    assert_eq!(got, UpsertAction::Updated);
    let body = put_body.lock().expect("put").clone().expect("put body");
    assert_eq!(body["ttl"], 300, "未指定 TTL 应更新为 300");
    assert_eq!(body["name"], "www.example.com.");
}

/// 备注（REMARK）：写在记录集的 description。
#[tokio::test]
async fn huaweicloud_remark_written_to_description() {
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v2/zones") => {
            FakeResponse::json(200, r#"{"zones":[{"id":"z1","name":"example.com."}]}"#)
        }
        ("GET", "/v2/zones/z1/recordsets") => {
            let list = current_in_handler
                .lock()
                .expect("cur")
                .clone()
                .map(|c| vec![c])
                .unwrap_or_default();
            FakeResponse::json(200, serde_json::json!({"recordsets": list}).to_string())
        }
        (_, path) if path.starts_with("/v2/zones/z1/recordsets") => {
            let mut body = req.body_json();
            body["id"] = "rs1".into();
            *current_in_handler.lock().expect("cur") = Some(body);
            FakeResponse::json(200, r#"{}"#)
        }
        _ => panic!("意外请求 {} {}", req.method, req.path),
    })
    .await;
    let p = HuaweiCloud::with_endpoint(creds("ak", "sk"), http(), &srv.url()).expect("provider");
    for (remark, want) in [
        ("a", UpsertAction::Created),
        ("a", UpsertAction::Unchanged),
        ("b", UpsertAction::Updated),
    ] {
        let mut r = rec("example.com", "www", RecordType::A, "1.1.1.1");
        r.remark = remark.to_owned();
        let got = p.upsert(&r).await.expect("upsert");
        assert_eq!(got, want, "remark={remark}");
        let cur = current.lock().expect("cur").clone().expect("recordset");
        assert_eq!(
            cur["description"].as_str(),
            Some(remark),
            "备注应写入 description"
        );
    }
}

/// TXT：值必须带引号；两个验证值合并进同一个记录集；按值删除（全部移除后
/// 删除整个记录集）。
#[tokio::test]
async fn huaweicloud_txt_add_delete() {
    let current = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let current_in_handler = current.clone();
    let srv = FakeServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v2/zones") => {
            FakeResponse::json(200, r#"{"zones":[{"id":"z1","name":"example.com."}]}"#)
        }
        ("GET", "/v2/zones/z1/recordsets") => {
            if req.query_param("type").as_deref() != Some("TXT") {
                panic!("TXT 操作应查询 TXT 类型");
            }
            let list = current_in_handler
                .lock()
                .expect("cur")
                .clone()
                .map(|c| vec![c])
                .unwrap_or_default();
            FakeResponse::json(200, serde_json::json!({"recordsets": list}).to_string())
        }
        ("POST", "/v2/zones/z1/recordsets") | ("PUT", "/v2/zones/z1/recordsets/rs1") => {
            let mut body = req.body_json();
            body["id"] = "rs1".into();
            *current_in_handler.lock().expect("cur") = Some(body);
            FakeResponse::json(200, r#"{}"#)
        }
        ("DELETE", "/v2/zones/z1/recordsets/rs1") => {
            *current_in_handler.lock().expect("cur") = None;
            FakeResponse::json(200, r#"{}"#)
        }
        _ => panic!("意外请求 {} {}", req.method, req.path),
    })
    .await;
    let p = HuaweiCloud::with_endpoint(creds("ak", "sk"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    {
        let cur = current.lock().expect("cur").clone().expect("recordset");
        assert_eq!(cur["records"][0].as_str(), Some("\"v1\""), "TXT 值需带引号");
        assert_eq!(cur["ttl"], 600);
    }
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let cur = current.lock().expect("cur").clone().expect("recordset");
        assert_eq!(cur["records"].as_array().expect("records").len(), 2);
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let cur = current.lock().expect("cur").clone().expect("recordset");
        assert_eq!(cur["records"][0].as_str(), Some("\"v2\""));
    }
    p.delete_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("delete v2");
    assert!(
        current.lock().expect("cur").is_none(),
        "全部移除后应删除记录集"
    );
}

/// 删除：整个记录集删除（记录集里还有其他值时通用流程会拒绝）。
#[tokio::test]
async fn huaweicloud_delete_targets() {
    let deleted = std::sync::Arc::new(Mutex::new(String::new()));
    let deleted_in_handler = deleted.clone();
    let srv = FakeServer::start(move |req| {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/v2/zones") => {
                FakeResponse::json(200, r#"{"zones":[{"id":"z1","name":"example.com."}]}"#)
            }
            ("GET", _) => FakeResponse::json(
                200,
                r#"{"recordsets":[{"id":"rs1","name":"www.example.com.","type":"A","records":["1.1.1.1"]}]}"#,
            ),
            ("DELETE", path) => {
                *deleted_in_handler.lock().expect("deleted") = path.to_owned();
                FakeResponse::json(200, r#"{}"#)
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = HuaweiCloud::with_endpoint(creds("ak", "sk"), http(), &srv.url()).expect("provider");
    let n = delete_records(&p, &rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect("delete");
    assert_eq!(n, 1);
    assert_eq!(
        *deleted.lock().expect("deleted"),
        "/v2/zones/z1/recordsets/rs1"
    );
}

/// 业务错误透出 {code, message}；账号下没有该域名时按区域未找到归类。
#[tokio::test]
async fn huaweicloud_error_classification() {
    let srv = FakeServer::start(|req| match req.path.as_str() {
        "/v2/zones" => FakeResponse::json(
            400,
            r#"{"code":"DNS.001000025","message":"The DNS service is abnormal"}"#,
        ),
        _ => panic!("意外请求 {} {}", req.method, req.path),
    })
    .await;
    let p = HuaweiCloud::with_endpoint(creds("ak", "sk"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("server error");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("DNS.001000025"), "{}", err.detail);

    // 区域未找到：zones 为空时按 ZoneNotFound 归类。
    let srv2 = FakeServer::start(|req| match req.path.as_str() {
        "/v2/zones" => FakeResponse::json(200, r#"{"zones":[]}"#),
        _ => panic!("意外请求 {} {}", req.method, req.path),
    })
    .await;
    let p2 = HuaweiCloud::with_endpoint(creds("ak", "sk"), http(), &srv2.url()).expect("provider");
    let err = p2
        .upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("zone not found");
    assert_eq!(err.kind, ProviderErrorKind::ZoneNotFound);
}
