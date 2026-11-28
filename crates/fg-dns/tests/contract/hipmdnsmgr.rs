//! HiPM DNSMgr 契约测试（对照上游 hipmdnsmgr_test.go 的 TestHipmDnsMgr、
//! TestHipmDnsMgrErrors 与 TestHipmDnsMgrTXTAndDelete）。

mod fake;

use std::sync::Arc;
use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::hipmdnsmgr::HipmDnsMgr,
};

/// 内存中的记录：id/name/type/value/ttl（面板保留的 line 不参与比较）。
type Rec = (String, String, String, String, i64);

#[derive(Clone, Default)]
struct State {
    recs: Vec<Rec>,
    last_body: serde_json::Value,
    last_query: std::collections::BTreeMap<String, String>,
    wrap_domains: bool,
    next_id: i64,
}

fn hipm_fake(
    state: Arc<Mutex<State>>,
    token: String,
) -> impl Fn(&fake::RecordedRequest) -> FakeResponse + Send + Sync + 'static {
    move |req| {
        let ok = req.header("authorization") == Some(format!("Bearer {token}").as_str());
        let code = if ok { 0 } else { 401 };
        let msg = if ok { "success" } else { "Unauthorized" };
        let mut st = state.lock().expect("state").clone();
        let reply = match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/domains") => {
                let domains = serde_json::json!([
                    {"id": 3, "name": "other.com"},
                    {"id": 5, "name": "example.com"},
                ]);
                if st.wrap_domains {
                    FakeResponse::json(
                        200,
                        serde_json::json!({"code": code, "msg": msg, "data": {"list": domains, "total": 2}}).to_string(),
                    )
                } else {
                    FakeResponse::json(
                        200,
                        serde_json::json!({"code": code, "msg": msg, "data": domains}).to_string(),
                    )
                }
            }
            ("GET", "/api/domains/5/records") => {
                let query = req.query_pairs();
                st.last_query = query.iter().cloned().collect();
                let typ = req.query_param("type").unwrap_or_default();
                let list: Vec<serde_json::Value> = st
                    .recs
                    .iter()
                    .filter(|(_, _, t, _, _)| t == &typ)
                    .map(|(id, name, t, value, ttl)| {
                        serde_json::json!({"id": id, "name": name, "type": t, "value": value, "ttl": ttl, "line": "default"})
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    serde_json::json!({"code": code, "msg": msg, "data": {"total": list.len(), "list": list}}).to_string(),
                )
            }
            ("POST", "/api/domains/5/records") => {
                let body = req.body_json();
                st.last_body = body.clone();
                st.next_id += 1;
                st.recs.push((
                    st.next_id.to_string(),
                    body["name"].as_str().unwrap_or_default().to_owned(),
                    body["type"].as_str().unwrap_or_default().to_owned(),
                    body["value"].as_str().unwrap_or_default().to_owned(),
                    body["ttl"].as_i64().unwrap_or(0),
                ));
                FakeResponse::json(
                    200,
                    serde_json::json!({"code": code, "msg": msg, "data": null}).to_string(),
                )
            }
            ("PUT", p) if p.starts_with("/api/domains/5/records/") => {
                let id = p.trim_start_matches("/api/domains/5/records/").to_owned();
                let body = req.body_json();
                st.last_body = body.clone();
                let mut found = false;
                for r in st.recs.iter_mut() {
                    if r.0 == id {
                        r.3 = body["value"].as_str().unwrap_or_default().to_owned();
                        r.4 = body["ttl"].as_i64().unwrap_or(0);
                        found = true;
                    }
                }
                let reply = if found {
                    FakeResponse::json(
                        200,
                        serde_json::json!({"code": code, "msg": msg, "data": null}).to_string(),
                    )
                } else {
                    FakeResponse::json(
                        200,
                        r#"{"code":400,"msg":"Failed to update record","data":null}"#,
                    )
                };
                *state.lock().expect("state") = st;
                return reply;
            }
            ("DELETE", p) if p.starts_with("/api/domains/5/records/") => {
                let id = p.trim_start_matches("/api/domains/5/records/").to_owned();
                let found = st.recs.iter().any(|r| r.0 == id);
                st.recs.retain(|r| r.0 != id);
                let reply = if found {
                    FakeResponse::json(
                        200,
                        serde_json::json!({"code": code, "msg": msg, "data": null}).to_string(),
                    )
                } else {
                    FakeResponse::json(
                        200,
                        r#"{"code":400,"msg":"Failed to delete record","data":null}"#,
                    )
                };
                *state.lock().expect("state") = st;
                return reply;
            }
            other => panic!("未预期的请求 {other:?}"),
        };
        *state.lock().expect("state") = st;
        reply
    }
}

/// 创建/未变化/更新的请求体契约；域名列表兼容裸数组与 {list,total} 包装；
/// 根域名不传主机过滤；TTL 变化触发更新。
#[tokio::test]
async fn hipmdnsmgr_upsert_request_contract() {
    let state = Arc::new(Mutex::new(State {
        next_id: 100,
        ..State::default()
    }));
    let srv = FakeServer::start(hipm_fake(state.clone(), "tok".to_owned())).await;
    // 面板地址带 /api 与结尾斜杠时自动规范化。
    let p = HipmDnsMgr::with_endpoint(
        creds(&srv.url(), "tok"),
        http(),
        &format!("{}/api/", srv.url()),
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
    let st = state.lock().expect("state").clone();
    assert_eq!(st.recs.len(), 1);
    assert_eq!(st.last_body["name"], "home");
    assert_eq!(st.last_body["type"], "A");
    assert_eq!(st.last_body["value"], "203.0.113.2");
    assert_eq!(st.last_body["ttl"], 600, "未指定 TTL 更新取 600");
    assert!(st.last_body.get("line").is_none(), "更新不应传线路");
    assert_eq!(
        st.last_query.get("subdomain").map(String::as_str),
        Some("home")
    );
    assert_eq!(st.last_query.get("type").map(String::as_str), Some("A"));

    // 根域名不传主机过滤；TTL 变化触发更新。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 300;
    assert_eq!(
        p.upsert(&r).await.expect("root create"),
        UpsertAction::Created
    );
    let st = state.lock().expect("state").clone();
    assert_eq!(st.last_body["name"], "@");
    assert_eq!(st.last_body["ttl"], 300);
    assert_eq!(
        st.last_query.get("subdomain").map(String::as_str),
        None,
        "根域名不应带主机过滤"
    );
    assert_eq!(
        p.upsert(&r).await.expect("unchanged"),
        UpsertAction::Unchanged
    );
    r.ttl = 600;
    assert_eq!(
        p.upsert(&r).await.expect("ttl update"),
        UpsertAction::Updated
    );

    // 域名列表使用 {list,total} 包装时同样能解析。
    state.lock().expect("state").wrap_domains = true;
    r.ttl = 600;
    assert_eq!(
        p.upsert(&r).await.expect("wrapped domains"),
        UpsertAction::Unchanged,
        "包装格式应能解析"
    );
    state.lock().expect("state").wrap_domains = false;

    // 未知域名报错。
    let err = p
        .upsert(&rec("nope.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("unknown zone");
    assert_eq!(err.kind, ProviderErrorKind::ZoneNotFound);
    assert!(err.detail.contains("未找到域名"), "{}", err.detail);
}

/// TXT 新增（TTL 600）与按值删除；删除解析：值一致才删除。
#[tokio::test]
async fn hipmdnsmgr_txt_add_delete_and_delete_targets() {
    let state = Arc::new(Mutex::new(State {
        next_id: 100,
        ..State::default()
    }));
    let srv = FakeServer::start(hipm_fake(state.clone(), "tok".to_owned())).await;
    let p =
        HipmDnsMgr::with_endpoint(creds(&srv.url(), "tok"), http(), &srv.url()).expect("provider");

    p.add_txt("example.com", "_acme-challenge", "tok1")
        .await
        .expect("add tok1");
    let st = state.lock().expect("state").clone();
    assert_eq!(st.last_body["type"], "TXT");
    assert_eq!(st.last_body["name"], "_acme-challenge");
    assert_eq!(st.last_body["value"], "tok1");
    assert_eq!(st.last_body["ttl"], 600);
    p.add_txt("example.com", "_acme-challenge", "tok2")
        .await
        .expect("add tok2");
    p.delete_txt("example.com", "_acme-challenge", "tok1")
        .await
        .expect("delete tok1");
    {
        let st = state.lock().expect("state").clone();
        assert_eq!(st.recs.len(), 1, "应只删除 tok1");
        assert_eq!(st.recs[0].3, "tok2");
    }
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");

    // 删除动态域名解析：值一致才删除。
    p.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert");
    let wrong = rec("example.com", "home", RecordType::A, "198.51.100.9");
    let err = delete_records(&p, &wrong)
        .await
        .expect_err("value mismatch");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert_eq!(
        state.lock().expect("state").recs.len(),
        2,
        "值不一致不应删除"
    );
    let n = delete_records(
        &p,
        &rec("example.com", "home", RecordType::A, "203.0.113.1"),
    )
    .await
    .expect("delete");
    assert_eq!(n, 1);
    {
        let st = state.lock().expect("state").clone();
        assert_eq!(st.recs.len(), 1, "A 记录应已删除");
        assert_eq!(st.recs[0].3, "tok2");
    }
}

/// 错误分类：401 认证失败；业务 code 非 0 透出；非法面板地址构造失败。
#[tokio::test]
async fn hipmdnsmgr_error_classification() {
    let state = Arc::new(Mutex::new(State::default()));
    let srv = FakeServer::start(hipm_fake(state, "tok".to_owned())).await;
    let bad =
        HipmDnsMgr::with_endpoint(creds(&srv.url(), "bad"), http(), &srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("unauthorized");
    assert_eq!(err.kind, ProviderErrorKind::Auth);

    // 业务 code 非 0：401/403 归类认证失败，其余无效输入。
    let biz =
        FakeServer::start(|_| FakeResponse::json(200, r#"{"code":403,"msg":"Permission denied"}"#))
            .await;
    let p =
        HipmDnsMgr::with_endpoint(creds(&biz.url(), "tok"), http(), &biz.url()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("permission denied");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.contains("Permission denied"), "{}", err.detail);

    // 构造校验：缺少协议的面板地址应报错；缺少令牌应报错。
    assert!(
        HipmDnsMgr::with_endpoint(
            creds("dnsmgr.example.com", "x"),
            http(),
            "dnsmgr.example.com"
        )
        .is_err()
    );
    assert!(
        HipmDnsMgr::with_endpoint(creds("https://a.com", ""), http(), "https://a.com").is_err()
    );
}
