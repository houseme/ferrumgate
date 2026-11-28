//! 雨云契约测试（对照上游 rainyun_test.go 的 TestRainyun、TestRainyunPaging、
//! TestRainyunErrors 与 TestRainyunTXTAndDelete）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::rainyun::Rainyun,
};

/// 内存状态：记录列表（record_id/host/type/value/line/ttl/level）与最近一次
/// 写入请求体。
type State = (Vec<serde_json::Value>, serde_json::Value);

fn rainyun_fake(
    state: std::sync::Arc<Mutex<State>>,
) -> impl Fn(&fake::RecordedRequest) -> FakeResponse + Send + Sync + 'static {
    move |req| {
        assert_eq!(req.header("x-api-key"), Some("key"), "认证头");
        let base = "/product";
        let mut recs = state.lock().expect("state").0.clone();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", p) if p == format!("{base}/domain") => {
                let options = req.query_param("options").expect("options");
                assert!(
                    options.contains(r#""domains.Domain":"#),
                    "域名列表应按名称过滤: {options}"
                );
                // 主测试断言按 example.com 过滤；这里取过滤值动态应答。
                let zone = options
                    .split(r#""domains.Domain":"#)
                    .nth(1)
                    .and_then(|rest| rest.split('"').nth(1))
                    .unwrap_or("")
                    .to_owned();
                if zone == "example.com" {
                    return FakeResponse::json(
                        200,
                        r#"{"code":200,"message":"","data":{"TotalRecords":2,"Records":[{"id":7,"domain":"other.com"},{"id":42,"domain":"example.com"}]}}"#,
                    );
                }
                FakeResponse::json(
                    200,
                    r#"{"code":200,"message":"","data":{"TotalRecords":0,"Records":[]}}"#,
                )
            }
            ("GET", p) if p == format!("{base}/domain/42/dns/") => {
                let limit: usize = req
                    .query_param("limit")
                    .and_then(|v| v.parse().ok())
                    .expect("limit");
                let page: usize = req
                    .query_param("page_no")
                    .and_then(|v| v.parse().ok())
                    .expect("page_no");
                assert!(limit > 0 && page > 0, "缺少分页参数");
                let start = ((page - 1) * limit).min(recs.len());
                let end = (start + limit).min(recs.len());
                FakeResponse::json(
                    200,
                    serde_json::json!({"code":200,"message":"","data":{"TotalRecords": recs.len(), "Records": recs[start..end]}}).to_string(),
                )
            }
            ("POST", p) if p == format!("{base}/domain/42/dns") => {
                let body = req.body_json();
                // record_id 唯一：取现有 ID 最大值加一（删除后不复用）。
                let next_id = recs
                    .iter()
                    .map(|r| r["record_id"].as_i64().unwrap_or(0))
                    .max()
                    .unwrap_or(1000)
                    + 1;
                recs.push(serde_json::json!({
                    "record_id": next_id,
                    "host": body["host"],
                    "type": body["type"],
                    "value": body["value"],
                    "line": body["line"],
                    "ttl": body["ttl"],
                    "level": body["level"],
                }));
                *state.lock().expect("state") = (recs, body);
                FakeResponse::json(200, r#"{"code":200,"message":"","data":null}"#)
            }
            ("PATCH", p) if p == format!("{base}/domain/42/dns") => {
                let body = req.body_json();
                let mut updated = false;
                for r in recs.iter_mut() {
                    if r["record_id"] == body["record_id"] {
                        r["value"] = body["value"].clone();
                        r["ttl"] = body["ttl"].clone();
                        updated = true;
                        break;
                    }
                }
                *state.lock().expect("state") = (recs, body);
                if updated {
                    FakeResponse::json(200, r#"{"code":200,"message":"","data":null}"#)
                } else {
                    FakeResponse::json(200, r#"{"code":404,"message":"记录不存在","data":null}"#)
                }
            }
            ("DELETE", p) if p == format!("{base}/domain/42/dns") => {
                let id = req.query_param("record_id").expect("record_id");
                if let Some(pos) = recs.iter().position(|r| {
                    r["record_id"].as_i64().map(|v| v.to_string()).as_deref() == Some(id.as_str())
                }) {
                    recs.remove(pos);
                    *state.lock().expect("state") = (recs, serde_json::Value::Null);
                    FakeResponse::json(200, r#"{"code":200,"message":"","data":null}"#)
                } else {
                    FakeResponse::json(200, r#"{"code":404,"message":"记录不存在","data":null}"#)
                }
            }
            other => panic!("未预期的请求 {other:?}"),
        }
    }
}

fn endpoint_of(srv: &FakeServer) -> String {
    format!("{}/product", srv.url())
}

/// 创建/未变化/更新的请求体契约；域名按名称过滤查得；线路与 TTL 自定义。
#[tokio::test]
async fn rainyun_upsert_request_contract() {
    let state = std::sync::Arc::new(Mutex::new((
        Vec::<serde_json::Value>::new(),
        serde_json::Value::Null,
    )));
    let srv = FakeServer::start(rainyun_fake(state.clone())).await;
    let p = Rainyun::with_endpoint(creds("", "key"), http(), &endpoint_of(&srv)).expect("provider");
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
    let (recs, last) = state.lock().expect("state").clone();
    assert_eq!(recs.len(), 1);
    assert_eq!(last["host"], "home");
    assert_eq!(last["line"], "DEFAULT", "空线路对应默认线路 DEFAULT");
    assert_eq!(last["level"], 10);
    assert_eq!(last["ttl"], 600, "未指定 TTL 更新沿用/取默认 600");
    assert!(last.get("record_id").is_some(), "更新应带 record_id");

    // 根域名 IPv6，线路与 TTL 自定义：线路统一大写。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 300;
    r.line = "ltel".into();
    assert_eq!(
        p.upsert(&r).await.expect("line create"),
        UpsertAction::Created
    );
    let (_, last) = state.lock().expect("state").clone();
    assert_eq!(last["host"], "@");
    assert_eq!(last["line"], "LTEL");
    assert_eq!(last["ttl"], 300);

    // 同名同类型但线路不同视为另一条记录。
    assert_eq!(
        p.upsert(&rec("example.com", "@", RecordType::AAAA, "2001:db8::1"))
            .await
            .expect("default line create"),
        UpsertAction::Created
    );

    // 未知域名报错。
    let err = p
        .upsert(&rec("nope.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("unknown zone");
    assert_eq!(err.kind, ProviderErrorKind::ZoneNotFound);
    assert!(err.detail.contains("未找到域名"), "{}", err.detail);
}

/// 目标记录排在第 2 页，验证翻页能找到它而不是重复创建。
#[tokio::test]
async fn rainyun_paging_finds_second_page() {
    let mut recs = Vec::<serde_json::Value>::new();
    for i in 0..100 {
        recs.push(serde_json::json!({
            "record_id": i + 1, "host": format!("h{i}"), "type": "A",
            "value": "10.0.0.1", "line": "DEFAULT", "ttl": 600, "level": 10,
        }));
    }
    recs.push(serde_json::json!({
        "record_id": 500, "host": "home", "type": "A",
        "value": "203.0.113.1", "line": "DEFAULT", "ttl": 600, "level": 10,
    }));
    let state = std::sync::Arc::new(Mutex::new((recs, serde_json::Value::Null)));
    let srv = FakeServer::start(rainyun_fake(state.clone())).await;
    let p = Rainyun::with_endpoint(creds("", "key"), http(), &endpoint_of(&srv)).expect("provider");
    assert_eq!(
        p.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
            .await
            .expect("paged upsert"),
        UpsertAction::Unchanged,
        "翻页后应识别为未变化而不是重复创建"
    );
    // 列表恰好分两页（100 条/页）。
    let (_, last) = state.lock().expect("state").clone();
    assert!(last.is_null(), "不应有写入请求");
}

/// TXT 新增（TTL 600、默认线路）与按值删除；删除解析按主机/类型/线路匹配。
#[tokio::test]
async fn rainyun_txt_add_delete_and_delete_targets() {
    let state = std::sync::Arc::new(Mutex::new((
        Vec::<serde_json::Value>::new(),
        serde_json::Value::Null,
    )));
    let srv = FakeServer::start(rainyun_fake(state.clone())).await;
    let p = Rainyun::with_endpoint(creds("", "key"), http(), &endpoint_of(&srv)).expect("provider");

    p.add_txt("example.com", "_acme-challenge", "tok1")
        .await
        .expect("add tok1");
    let (_, last) = state.lock().expect("state").clone();
    assert_eq!(last["type"], "TXT");
    assert_eq!(last["host"], "_acme-challenge");
    assert_eq!(last["value"], "tok1");
    assert_eq!(last["ttl"], 600);
    assert_eq!(last["line"], "DEFAULT");
    p.add_txt("example.com", "_acme-challenge", "tok2")
        .await
        .expect("add tok2");
    p.delete_txt("example.com", "_acme-challenge", "tok1")
        .await
        .expect("delete tok1");
    {
        let (recs, _) = state.lock().expect("state").clone();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["value"], "tok2");
    }
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");

    // 删除动态域名解析。
    p.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert");
    let n = delete_records(
        &p,
        &rec("example.com", "home", RecordType::A, "203.0.113.1"),
    )
    .await
    .expect("delete");
    assert_eq!(n, 1);
    let (recs, _) = state.lock().expect("state").clone();
    assert!(recs.iter().all(|r| r["host"] != "home"), "记录应已删除");
}

/// 错误分类：HTTP 401 认证失败；HTTP 200 但业务 code 非 200 透出消息。
#[tokio::test]
async fn rainyun_error_classification() {
    let srv = FakeServer::start(|_| {
        FakeResponse::json(
            401,
            r#"{"code":401,"message":"invalid api key","data":null}"#,
        )
    })
    .await;
    let bad =
        Rainyun::with_endpoint(creds("", "bad"), http(), &endpoint_of(&srv)).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("invalid api key");
    assert_eq!(err.kind, ProviderErrorKind::Auth);

    let biz =
        FakeServer::start(|_| FakeResponse::json(200, r#"{"code":30001,"message":"余额不足"}"#))
            .await;
    let p = Rainyun::with_endpoint(creds("", "key"), http(), &format!("{}/product", biz.url()))
        .expect("provider");
    let err = p
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("business failure");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("余额不足"), "{}", err.detail);
}
