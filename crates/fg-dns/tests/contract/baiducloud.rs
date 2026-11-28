//! 百度智能云 DNS 契约测试（对照上游 baiducloud_test.go::TestBaiduCloudUpsert、
//! TestBaiduCloudPaging、TestBaiduCloudTXTAndDelete、TestBaiduCloudErrors；
//! BCE 认证用官方文档示例向量锁定，见 baiducloud.rs 的单元测试）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::baiducloud::BaiduCloud,
};

/// 假服务器状态：记录表与最近一次各路径的请求体。
struct BcState {
    records: Vec<serde_json::Value>,
    next: i64,
    last_edit: Option<serde_json::Value>,
}

#[tokio::test]
async fn baiducloud_upsert_request_contract() {
    let state = std::sync::Arc::new(Mutex::new(BcState {
        records: Vec::new(),
        next: 0,
        last_edit: None,
    }));
    let state_in_handler = state.clone();
    let srv = FakeServer::start(move |req| {
        let mut st = state_in_handler.lock().expect("state");
        assert_eq!(req.method, "POST");
        assert_eq!(req.header("content-type"), Some("application/json; charset=utf-8"));
        // 认证字符串格式：bce-auth-v1/{ak}/{时间戳}/1800/host/{签名}，不发 x-bce-date。
        let auth = req.header("authorization").expect("auth");
        let parts: Vec<&str> = auth.split('/').collect();
        assert_eq!(parts[0], "bce-auth-v1", "{auth}");
        assert_eq!(parts[1], "AK", "{auth}");
        assert_eq!(parts[4], "host", "只签名 host: {auth}");
        assert_eq!(parts[5].len(), 64, "签名为 SHA-256 hex: {auth}");
        assert_eq!(req.header("x-bce-date"), None, "不应发送 x-bce-date 头");
        let body = req.body_json();
        match req.path.as_str() {
            "/v1/domain/resolve/list" => {
                if body["domain"] != "example.com" {
                    return FakeResponse::json(
                        400,
                        r#"{"code":"DomainNotExists","message":"domain not found","requestId":"x"}"#,
                    );
                }
                // 两套页码参数都发送且一致。
                assert_eq!(body["pageNum"], body["pageNo"]);
                assert_eq!(body["pageSize"], 1000);
                FakeResponse::json(
                    200,
                    serde_json::json!({
                        "pageNo": body["pageNum"], "pageSize": body["pageSize"],
                        "totalCount": st.records.len(), "result": st.records,
                    })
                    .to_string(),
                )
            }
            "/v1/domain/resolve/add" => {
                st.next += 1;
                let id = st.next;
                st.records.push(serde_json::json!({
                    "recordId": id,
                    "domain": body["domain"],
                    "view": "DEFAULT",
                    "rdtype": body["rdType"],
                    "ttl": body["ttl"],
                    "rdata": body["rdata"],
                    "zoneName": body["zoneName"],
                    "status": "RUNNING",
                }));
                FakeResponse::json(200, r#"{}"#)
            }
            "/v1/domain/resolve/edit" => {
                let id = body["recordId"].as_i64().expect("recordId");
                for r in st.records.iter_mut() {
                    if r["recordId"].as_i64() == Some(id) {
                        r["rdata"] = body["rdata"].clone();
                        r["ttl"] = body["ttl"].clone();
                    }
                }
                st.last_edit = Some(body);
                FakeResponse::json(200, r#"{}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = BaiduCloud::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
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
        let st = state.lock().expect("state");
        assert_eq!(st.records.len(), 1);
        assert_eq!(st.records[0]["rdata"], "203.0.113.2");
        assert_eq!(st.records[0]["ttl"], 300, "未指定 TTL 时新建用 300");
        assert_eq!(st.records[0]["domain"], "home");
        let edit = st.last_edit.clone().expect("edit body");
        assert_eq!(edit["rdType"], "A");
        assert_eq!(edit["zoneName"], "example.com");
        assert_eq!(edit["view"], "DEFAULT", "编辑请求需回传原线路");
        assert_eq!(edit["domain"], "home");
    }
}

/// 根域名主机记录为 @；TTL 限制在 60 以上；非默认线路的同名记录不被改动。
#[tokio::test]
async fn baiducloud_root_host_ttl_clamp_and_lines() {
    let state = std::sync::Arc::new(Mutex::new(BcState {
        records: Vec::new(),
        next: 0,
        last_edit: None,
    }));
    let state_in_handler = state.clone();
    let srv = FakeServer::start(move |req| {
        let mut st = state_in_handler.lock().expect("state");
        let body = req.body_json();
        match req.path.as_str() {
            "/v1/domain/resolve/list" => {
                FakeResponse::json(200, serde_json::json!({"result": st.records}).to_string())
            }
            "/v1/domain/resolve/add" => {
                st.next += 1;
                let id = st.next;
                st.records.push(serde_json::json!({
                    "recordId": id,
                    "domain": body["domain"],
                    "view": "DEFAULT",
                    "rdtype": body["rdType"],
                    "ttl": body["ttl"],
                    "rdata": body["rdata"],
                    "zoneName": body["zoneName"],
                }));
                FakeResponse::json(200, r#"{}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = BaiduCloud::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
    // 根域名主机记录为 @，TTL 被限制到 60 以上。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 5;
    let got = p.upsert(&r).await.expect("upsert");
    assert_eq!(got, UpsertAction::Created);
    {
        let st = state.lock().expect("state");
        assert_eq!(st.records[0]["domain"], "@");
        assert_eq!(st.records[0]["ttl"], 60);
        assert_eq!(st.records[0]["rdtype"], "AAAA");
    }
    // 非默认线路的同名记录不被改动：ISP 记录存在时应新建默认线路记录。
    {
        let mut st = state.lock().expect("state");
        st.records.push(serde_json::json!({
            "recordId": 900, "domain": "isp", "view": "CNC", "rdtype": "A",
            "ttl": 600, "rdata": "1.1.1.1", "zoneName": "example.com",
        }));
    }
    let got = p
        .upsert(&rec("example.com", "isp", RecordType::A, "2.2.2.2"))
        .await
        .expect("upsert isp");
    assert_eq!(got, UpsertAction::Created);
    let st = state.lock().expect("state");
    assert_eq!(st.records[1]["rdata"], "1.1.1.1", "联通线路记录被改动");
    assert_eq!(st.records[2]["rdata"], "2.2.2.2", "默认线路应新建记录");
}

/// TXT 与删除：按值删除；值不一致时拒绝删除动态域名记录。
#[tokio::test]
async fn baiducloud_txt_add_delete() {
    let state = std::sync::Arc::new(Mutex::new(BcState {
        records: Vec::new(),
        next: 0,
        last_edit: None,
    }));
    let state_in_handler = state.clone();
    let srv = FakeServer::start(move |req| {
        let mut st = state_in_handler.lock().expect("state");
        let body = req.body_json();
        match req.path.as_str() {
            "/v1/domain/resolve/list" => {
                FakeResponse::json(200, serde_json::json!({"result": st.records}).to_string())
            }
            "/v1/domain/resolve/add" => {
                st.next += 1;
                let id = st.next;
                st.records.push(serde_json::json!({
                    "recordId": id,
                    "domain": body["domain"],
                    "view": "DEFAULT",
                    "rdtype": body["rdType"],
                    "ttl": body["ttl"],
                    "rdata": body["rdata"],
                    "zoneName": body["zoneName"],
                }));
                FakeResponse::json(200, r#"{}"#)
            }
            "/v1/domain/resolve/delete" => {
                assert_eq!(body["zoneName"], "example.com", "delete 需带 zoneName");
                let id = body["recordId"].as_i64().expect("recordId");
                st.records.retain(|r| r["recordId"].as_i64() != Some(id));
                FakeResponse::json(200, r#"{}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = BaiduCloud::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let st = state.lock().expect("state");
        assert_eq!(st.records.len(), 2);
        assert_eq!(st.records[0]["rdtype"], "TXT");
        assert_eq!(st.records[0]["ttl"], 600);
        assert_eq!(st.records[0]["domain"], "_acme-challenge");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let st = state.lock().expect("state");
        assert_eq!(st.records.len(), 1);
        assert_eq!(st.records[0]["rdata"], "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "none")
        .await
        .expect("delete none");

    // 删除动态域名记录：值需与最近同步一致。
    let r = rec("example.com", "home", RecordType::A, "203.0.113.1");
    p.upsert(&r).await.expect("upsert");
    let err = delete_records(&p, &rec("example.com", "home", RecordType::A, "9.9.9.9"))
        .await
        .expect_err("value mismatch");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    assert_eq!(state.lock().expect("state").records.len(), 1);
}

/// 业务错误透出 {code, message}。
#[tokio::test]
async fn baiducloud_error_classification() {
    let srv = FakeServer::start(move |req| match req.path.as_str() {
        "/v1/domain/resolve/list" => {
            if req.body_json()["domain"] != "example.com" {
                FakeResponse::json(
                    400,
                    r#"{"code":"DomainNotExists","message":"domain not found","requestId":"x"}"#,
                )
            } else {
                FakeResponse::json(200, r#"{"result":[]}"#)
            }
        }
        _ => panic!("意外请求 {}", req.path),
    })
    .await;
    let p = BaiduCloud::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("missing.org", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("domain not exists");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("DomainNotExists"), "{}", err.detail);
    assert!(err.detail.contains("domain not found"), "{}", err.detail);
}
