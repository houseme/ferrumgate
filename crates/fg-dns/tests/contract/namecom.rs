//! Name.com 契约测试（对照上游 name_com_test.go 的 TestNameComUpsert、
//! TestNameComPaginationTXTDelete 与 TestNameComErrors）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::namecom::NameCom,
};

/// 内存中的记录：id, host, type, answer, ttl。
type Rec = (i64, String, String, String, i64);

fn namecom_fake(
    state: std::sync::Arc<Mutex<(Vec<Rec>, i64, usize)>>,
) -> impl Fn(&fake::RecordedRequest) -> FakeResponse + Send + Sync + 'static {
    move |req| {
        let base = "/core/v1/domains/example.com/records";
        // Basic 认证：user:tok。
        let want_auth = format!("Basic {}", fg_dns::sign::base64_std(b"user:tok"));
        assert_eq!(
            req.header("authorization"),
            Some(want_auth.as_str()),
            "Basic 认证头"
        );
        let (mut recs, mut next, per_page) = state.lock().expect("state").clone();
        let reply = match (req.method.as_str(), req.path.as_str()) {
            ("GET", p) if p == base => {
                let page: usize = req
                    .query_param("page")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1);
                assert_eq!(req.query_param("perPage").as_deref(), Some("1000"));
                let start = ((page - 1) * per_page).min(recs.len());
                let end = (start + per_page).min(recs.len());
                let slice: Vec<serde_json::Value> = recs[start..end]
                    .iter()
                    .map(|(id, host, typ, answer, ttl)| {
                        serde_json::json!({"id": id, "host": host, "type": typ, "answer": answer, "ttl": ttl})
                    })
                    .collect();
                let mut resp = serde_json::json!({"records": slice});
                if end < recs.len() {
                    resp["nextPage"] = serde_json::json!((page + 1) as i64);
                }
                FakeResponse::json(200, resp.to_string())
            }
            ("POST", p) if p == base => {
                let body = req.body_json();
                next += 1;
                recs.push((
                    next,
                    body["host"].as_str().unwrap_or_default().to_owned(),
                    body["type"].as_str().unwrap_or_default().to_owned(),
                    body["answer"].as_str().unwrap_or_default().to_owned(),
                    body["ttl"].as_i64().unwrap_or(0),
                ));
                FakeResponse::json(200, "{}")
            }
            ("PUT", p) if p.starts_with(&format!("{base}/")) => {
                let id: i64 = p
                    .trim_start_matches(&format!("{base}/"))
                    .parse()
                    .expect("id");
                let body = req.body_json();
                for r in recs.iter_mut() {
                    if r.0 == id {
                        r.1 = body["host"].as_str().unwrap_or_default().to_owned();
                        r.2 = body["type"].as_str().unwrap_or_default().to_owned();
                        r.3 = body["answer"].as_str().unwrap_or_default().to_owned();
                        r.4 = body["ttl"].as_i64().unwrap_or(0);
                    }
                }
                FakeResponse::json(200, "{}")
            }
            ("DELETE", p) if p.starts_with(&format!("{base}/")) => {
                let id: i64 = p
                    .trim_start_matches(&format!("{base}/"))
                    .parse()
                    .expect("id");
                recs.retain(|r| r.0 != id);
                FakeResponse::json(200, "{}")
            }
            other => panic!("意外请求 {other:?}"),
        };
        *state.lock().expect("state") = (recs, next, per_page);
        reply
    }
}

#[tokio::test]
async fn namecom_upsert_request_contract() {
    let state = std::sync::Arc::new(Mutex::new((Vec::<Rec>::new(), 100i64, 1000usize)));
    let srv = FakeServer::start(namecom_fake(state.clone())).await;
    let p = NameCom::with_endpoint(creds("user", "tok"), http(), &srv.url()).expect("provider");
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
    let (recs, _, _) = state.lock().expect("state").clone();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].1, "home");
    assert_eq!(recs[0].3, "203.0.113.2");

    // 根域名主机为空；TTL 低于下限抬到 300。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 60;
    assert_eq!(
        p.upsert(&r).await.expect("root create"),
        UpsertAction::Created
    );
    {
        let (recs, ..) = state.lock().expect("state").clone();
        assert_eq!(recs[1].1, "", "根域名 host 为空字符串");
        assert_eq!(recs[1].4, 300, "TTL 60 应抬到下限 300");
    }
    r.ttl = 300;
    assert_eq!(
        p.upsert(&r).await.expect("unchanged"),
        UpsertAction::Unchanged
    );
    r.ttl = 600;
    assert_eq!(
        p.upsert(&r).await.expect("ttl update"),
        UpsertAction::Updated
    );
    let (recs, ..) = state.lock().expect("state").clone();
    assert_eq!(recs[1].4, 600);
}

/// 翻页后能找到目标记录；TXT 新增 TTL 600、删除按值；按条删除解析。
#[tokio::test]
async fn namecom_pagination_txt_and_delete() {
    // 每页 2 条，制造 3 页。
    let mut recs = Vec::<Rec>::new();
    for i in 0..5 {
        recs.push((
            i + 1,
            format!("h{i}"),
            "A".to_owned(),
            format!("10.0.0.{i}"),
            300,
        ));
    }
    let state = std::sync::Arc::new(Mutex::new((recs, 100i64, 2usize)));
    let srv = FakeServer::start(namecom_fake(state.clone())).await;
    let p = NameCom::with_endpoint(creds("user", "tok"), http(), &srv.url()).expect("provider");
    assert_eq!(
        p.upsert(&rec("example.com", "h4", RecordType::A, "10.0.0.4"))
            .await
            .expect("paged upsert"),
        UpsertAction::Unchanged,
        "翻页后应识别为未变化"
    );

    // TXT：新增两个值（TTL 600），删除其一。
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let (recs, ..) = state.lock().expect("state").clone();
        let last = recs.last().expect("last");
        assert_eq!(last.2, "TXT");
        assert_eq!(last.3, "v2");
        assert_eq!(last.4, 600, "TXT 验证记录 TTL 600");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let (recs, ..) = state.lock().expect("state").clone();
        assert_eq!(recs.len(), 6, "5 条初始记录 + v2，v1 应已删除");
        assert_eq!(recs.last().expect("last").3, "v2", "应只删除 v1");
    }

    // 删除解析：按值匹配。
    let n = delete_records(&p, &rec("example.com", "h2", RecordType::A, "10.0.0.2"))
        .await
        .expect("delete");
    assert_eq!(n, 1);
    let (recs, ..) = state.lock().expect("state").clone();
    assert_eq!(recs.len(), 5, "h2 应已删除");
    assert!(recs.iter().all(|r| r.1 != "h2"), "h2 应已删除");
}

/// 错误：401 认证失败；服务端错误按 Server 归类。
#[tokio::test]
async fn namecom_error_classification() {
    let err_srv = FakeServer::start(|_| {
        FakeResponse::json(
            401,
            r#"{"message":"Unauthorized","details":"Authentication Error - Invalid Credentials"}"#,
        )
    })
    .await;
    let bad =
        NameCom::with_endpoint(creds("user", "bad"), http(), &err_srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("invalid credentials");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.contains("Invalid Credentials"), "{}", err.detail);

    let dead = FakeServer::start(|_| FakeResponse::json(500, "boom")).await;
    let p = NameCom::with_endpoint(creds("user", "tok"), http(), &dead.url()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("server error");
    assert_eq!(err.kind, ProviderErrorKind::Server);
}
