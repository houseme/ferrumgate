//! OVHcloud 契约测试（对照上游 more_test.go::TestOVH、ovh.go 的 TXT 分节与
//! delete.go 的 OVH 分节）。签名在假服务器端按同一算法重算比对。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds_with_extra, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction,
    delete::delete_records,
    providers::ovh::{META, Ovh},
};

/// 服务器时间固定值（上游测试同样用 1700000000）：客户端会先 GET /auth/time
/// 校准时间差，之后请求头 X-Ovh-Timestamp 恒等于该值。
const SERVER_TIME: i64 = 1_700_000_000;

/// 测试注入的固定时钟（上游 nowForSig 注入的等价物，避免跨秒抖动）。
fn fixed_now() -> i64 {
    SERVER_TIME
}

fn make_provider(srv: &FakeServer) -> Ovh {
    Ovh::with_endpoint_and_clock(
        creds_with_extra(
            "app",
            "sec",
            &[("consumerKey", "ck"), ("endpoint", &srv.url())],
        ),
        http(),
        &srv.url(),
        fixed_now,
    )
    .expect("provider")
}

/// 按同一算法重算 OVH 签名：$1$ + SHA1(secret+ck+method+full_url+body+ts)。
fn verify_ovh_signature(req: &fake::RecordedRequest, payload: &[u8]) {
    assert_eq!(req.header("x-ovh-application"), Some("app"));
    assert_eq!(req.header("x-ovh-consumer"), Some("ck"));
    assert_eq!(
        req.header("x-ovh-timestamp"),
        Some(SERVER_TIME.to_string().as_str()),
        "时间戳应等于服务器时间"
    );
    let host = req.header("host").expect("Host").to_owned();
    let full = if req.query.is_empty() {
        format!("http://{}{}", host, req.path)
    } else {
        format!("http://{}{}?{}", host, req.path, req.query)
    };
    let want = fg_dns::sign::ovh::signature(
        "sec",
        "ck",
        &req.method,
        &full,
        std::str::from_utf8(payload).expect("utf8 body"),
        SERVER_TIME,
    );
    assert_eq!(
        req.header("x-ovh-signature"),
        Some(want.as_str()),
        "OVH 签名不一致"
    );
}

#[tokio::test]
async fn ovh_upsert_contract_creates_updates_and_refreshes() {
    type State = (Option<(i64, String, u32)>, usize);
    let state_in_handler = std::sync::Arc::new(Mutex::new(None::<State>));
    let srv_state = state_in_handler.clone();
    let srv = FakeServer::start(move |req| {
        if req.method == "GET" && req.path == "/auth/time" {
            return FakeResponse::json(200, SERVER_TIME.to_string());
        }
        verify_ovh_signature(req, &req.body);
        let body = req.body_json();
        let mut st = srv_state.lock().expect("state").take().unwrap_or_default();
        let reply = match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domain/zone/example.com/record") => {
                assert_eq!(req.query_param("fieldType").as_deref(), Some("A"));
                assert_eq!(req.query_param("subDomain").as_deref(), Some("home"));
                if st.0.is_none() {
                    FakeResponse::json(200, "[]")
                } else {
                    FakeResponse::json(200, "[1]")
                }
            }
            ("GET", "/domain/zone/example.com/record/1") => FakeResponse::json(
                200,
                format!(
                    r#"{{"id":1,"fieldType":"A","subDomain":"home","target":"{}","ttl":{}}}"#,
                    st.0.as_ref().map(|r| r.1.clone()).unwrap_or_default(),
                    st.0.as_ref().map(|r| r.2).unwrap_or(0)
                ),
            ),
            ("POST", "/domain/zone/example.com/record") => {
                assert_eq!(body["fieldType"], "A");
                assert_eq!(body["subDomain"], "home");
                let target = body["target"].as_str().expect("target").to_owned();
                let ttl = body.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                st.0 = Some((1, target, ttl));
                FakeResponse::json(200, "{}")
            }
            ("PUT", "/domain/zone/example.com/record/1") => {
                let target = body["target"].as_str().expect("target").to_owned();
                let ttl = body.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                st.0 = Some((1, target, ttl));
                FakeResponse::json(200, "{}")
            }
            ("POST", "/domain/zone/example.com/refresh") => {
                st.1 += 1;
                FakeResponse::json(200, "{}")
            }
            other => panic!("意外请求 {other:?}"),
        };
        *srv_state.lock().expect("state") = Some(st);
        reply
    })
    .await;
    let p = make_provider(&srv);
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
    // 创建与更新后各刷新一次区域。
    let st = state_in_handler
        .lock()
        .expect("state")
        .clone()
        .expect("state");
    assert_eq!(st.1, 2, "创建和更新后各应刷新一次");
    assert_eq!(st.0.expect("record").1, "203.0.113.2");
}

/// TTL：未指定时不发送 ttl（用服务商默认值）；TXT 新增带引号与 TTL 60，
/// 删除按值；签名覆盖带请求体与带查询串的请求。
#[tokio::test]
async fn ovh_txt_add_delete_and_ttl_default() {
    let txts = std::sync::Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
    let next = std::sync::Arc::new(Mutex::new(10i64));
    let srv_txts = txts.clone();
    let srv_next = next.clone();
    let srv = FakeServer::start(move |req| {
        if req.method == "GET" && req.path == "/auth/time" {
            return FakeResponse::json(200, SERVER_TIME.to_string());
        }
        verify_ovh_signature(req, &req.body);
        let body = req.body_json();
        match (req.method.as_str(), req.path.as_str()) {
            ("POST", "/domain/zone/example.com/record") => {
                assert_eq!(body["fieldType"], "TXT");
                assert_eq!(body["subDomain"], "_acme-challenge");
                assert_eq!(body["ttl"], 60, "TXT 验证记录 TTL 60");
                let target = body["target"].as_str().expect("target");
                assert!(target.starts_with('"') && target.ends_with('"'), "TXT 值需带引号");
                let mut id = srv_next.lock().expect("next");
                *id += 1;
                srv_txts.lock().expect("txts").push((*id, target.to_owned()));
                FakeResponse::json(200, "{}")
            }
            ("GET", "/domain/zone/example.com/record") => {
                assert_eq!(req.query_param("fieldType").as_deref(), Some("TXT"));
                assert_eq!(req.query_param("subDomain").as_deref(), Some("_acme-challenge"));
                let list: Vec<i64> = srv_txts.lock().expect("txts").iter().map(|(id, _)| *id).collect();
                FakeResponse::json(200, serde_json::json!(list).to_string())
            }
            ("GET", path) if path.starts_with("/domain/zone/example.com/record/") => {
                let id: i64 = path.rsplit('/').next().expect("id").parse().expect("int");
                let txts = srv_txts.lock().expect("txts");
                let (_, target) = txts.iter().find(|(tid, _)| *tid == id).expect("record");
                FakeResponse::json(
                    200,
                    serde_json::json!({"id": id, "fieldType": "TXT", "subDomain": "_acme-challenge", "target": target, "ttl": 60})
                        .to_string(),
                )
            }
            ("DELETE", path) if path.starts_with("/domain/zone/example.com/record/") => {
                let id: i64 = path.rsplit('/').next().expect("id").parse().expect("int");
                srv_txts.lock().expect("txts").retain(|(tid, _)| *tid != id);
                FakeResponse::json(200, "{}")
            }
            ("POST", "/domain/zone/example.com/refresh") => FakeResponse::json(200, "{}"),
            other => panic!("意外请求 {other:?}"),
        }
    })
    .await;
    let p = make_provider(&srv);
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    assert_eq!(txts.lock().expect("txts").len(), 2, "AddTXT 总是新增");
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let left = txts.lock().expect("txts");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].1, "\"v2\"");
    }
    // 删除不存在的值不报错。
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");

    // A 记录未指定 TTL：创建请求体不带 ttl 字段。
    let seen = std::sync::Arc::new(Mutex::new(None));
    let seen_in_handler = seen.clone();
    let srv2 = FakeServer::start(move |req| {
        if req.method == "GET" && req.path == "/auth/time" {
            return FakeResponse::json(200, SERVER_TIME.to_string());
        }
        verify_ovh_signature(req, &req.body);
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domain/zone/example.com/record") => FakeResponse::json(200, "[]"),
            ("POST", "/domain/zone/example.com/record") => {
                *seen_in_handler.lock().expect("seen") = Some(req.body_json());
                FakeResponse::json(200, "{}")
            }
            ("POST", "/domain/zone/example.com/refresh") => FakeResponse::json(200, "{}"),
            other => panic!("意外请求 {other:?}"),
        }
    })
    .await;
    let p2 = make_provider(&srv2);
    assert_eq!(
        p2.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.7"))
            .await
            .expect("upsert"),
        UpsertAction::Created
    );
    let body = seen.lock().expect("seen").clone().expect("body");
    assert!(body.get("ttl").is_none(), "未指定 TTL 时不应发送 ttl");
}

/// 删除：按值匹配的记录逐条删除；认证失败（时间接口失败/401）归类。
#[tokio::test]
async fn ovh_delete_targets_and_error_classification() {
    let recs = std::sync::Arc::new(Mutex::new(vec![
        (1i64, "1.1.1.1".to_owned()),
        (2i64, "2.2.2.2".to_owned()),
    ]));
    let srv_recs = recs.clone();
    let srv = FakeServer::start(move |req| {
        if req.method == "GET" && req.path == "/auth/time" {
            return FakeResponse::json(200, SERVER_TIME.to_string());
        }
        verify_ovh_signature(req, &req.body);
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/domain/zone/example.com/record") => {
                let list: Vec<i64> = srv_recs.lock().expect("recs").iter().map(|(id, _)| *id).collect();
                FakeResponse::json(200, serde_json::json!(list).to_string())
            }
            ("GET", path) if path.starts_with("/domain/zone/example.com/record/") => {
                let id: i64 = path.rsplit('/').next().expect("id").parse().expect("int");
                let recs = srv_recs.lock().expect("recs");
                let (_, target) = recs.iter().find(|(tid, _)| *tid == id).expect("record");
                FakeResponse::json(
                    200,
                    format!(r#"{{"id":{id},"fieldType":"A","subDomain":"home","target":"{target}","ttl":600}}"#),
                )
            }
            ("DELETE", path) if path.starts_with("/domain/zone/example.com/record/") => {
                let id: i64 = path.rsplit('/').next().expect("id").parse().expect("int");
                srv_recs.lock().expect("recs").retain(|(tid, _)| *tid != id);
                FakeResponse::json(200, "{}")
            }
            ("POST", "/domain/zone/example.com/refresh") => FakeResponse::json(200, "{}"),
            other => panic!("意外请求 {other:?}"),
        }
    })
    .await;
    let p = make_provider(&srv);
    let n = delete_records(&p, &rec("example.com", "home", RecordType::A, "2.2.2.2"))
        .await
        .expect("delete");
    assert_eq!(n, 1);
    {
        let left = recs.lock().expect("recs");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].0, 1);
    }

    // 时间接口失败：传输/服务端错误。
    let dead = FakeServer::start(|_| FakeResponse::json(500, "boom")).await;
    let bad = Ovh::with_endpoint_and_clock(
        creds_with_extra(
            "app",
            "sec",
            &[("consumerKey", "ck"), ("endpoint", &dead.url())],
        ),
        http(),
        &dead.url(),
        fixed_now,
    )
    .expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("time failure");
    assert_eq!(err.kind, ProviderErrorKind::Server);

    // 缺少 Consumer Key 构造失败。
    let missing = match Ovh::with_endpoint(
        creds_with_extra("app", "sec", &[]),
        http(),
        "https://eu.api.ovh.com/1.0",
    ) {
        Err(e) => e,
        Ok(_) => panic!("missing consumer key should be rejected"),
    };
    assert_eq!(missing.message_key, fg_dns::msg::CREDS_MISSING);
    assert!(META.supports_delete);
}
