//! NameSilo 契约测试（对照上游 namesilo_test.go 的 TestNameSiloUpsert、
//! TestNameSiloTXTAndDelete 与 TestNameSiloErrors）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::namesilo::NameSilo,
};

/// 内存中的记录：id, type, host, value, ttl。
type Rec = (String, String, String, String, u32);

fn xml(records: &[Rec], code: u32, detail: &str) -> FakeResponse {
    let mut inner = format!("<code>{code}</code><detail>{detail}</detail>");
    if code == 300 {
        for (id, typ, host, value, ttl) in records {
            inner.push_str(&format!(
                "<resource_record><record_id>{id}</record_id><type>{typ}</type><host>{host}</host><value>{value}</value><ttl>{ttl}</ttl><distance>0</distance></resource_record>"
            ));
        }
    }
    FakeResponse::json(
        200,
        format!(
            r#"<?xml version="1.0"?><namesilo><request><operation>x</operation></request><reply>{inner}</reply></namesilo>"#
        ),
    )
}

/// full_host 为 true 时列表返回完整域名写法（带结尾点），验证 hostMatches。
fn namesilo_fake(
    records: std::sync::Arc<Mutex<Vec<Rec>>>,
    full_host: bool,
    bad_key: bool,
) -> impl Fn(&fake::RecordedRequest) -> FakeResponse + Send + Sync + 'static {
    move |req| {
        let query = req.query_pairs();
        let get = |k: &str| {
            query
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("version").as_deref(), Some("1"));
        assert_eq!(get("type").as_deref(), Some("xml"));
        assert_eq!(get("domain").as_deref(), Some("example.com"));
        if bad_key || get("key").as_deref() != Some("k123") {
            return xml(&[], 280, "Invalid API Key");
        }
        let op = req.path.trim_start_matches("/api/");
        let mut recs = records.lock().expect("records").clone();
        match op {
            "dnsListRecords" => {
                if full_host {
                    let full: Vec<Rec> = recs
                        .iter()
                        .map(|(id, typ, host, value, ttl)| {
                            let host = if host == "@" || host.is_empty() {
                                "example.com.".to_owned()
                            } else {
                                format!("{host}.example.com.")
                            };
                            (id.clone(), typ.clone(), host, value.clone(), *ttl)
                        })
                        .collect();
                    return xml(&full, 300, "success");
                }
                xml(&recs, 300, "success")
            }
            "dnsAddRecord" => {
                // ID 唯一：取现有编号的最大值加一（删除后不复用）。
                let next = recs
                    .iter()
                    .map(|(id, ..)| id.trim_start_matches("id").parse::<usize>().unwrap_or(0))
                    .max()
                    .unwrap_or(0)
                    + 1;
                recs.push((
                    format!("id{next}"),
                    get("rrtype").unwrap_or_default(),
                    get("rrhost").unwrap_or_default(),
                    get("rrvalue").unwrap_or_default(),
                    get("rrttl").and_then(|v| v.parse().ok()).unwrap_or(0),
                ));
                *records.lock().expect("records") = recs.clone();
                xml(&recs, 300, "success")
            }
            "dnsUpdateRecord" => {
                let id = get("rrid").unwrap_or_default();
                if let Some(r) = recs.iter_mut().find(|r| r.0 == id) {
                    r.2 = get("rrhost").unwrap_or_default();
                    r.3 = get("rrvalue").unwrap_or_default();
                    r.4 = get("rrttl").and_then(|v| v.parse().ok()).unwrap_or(0);
                    *records.lock().expect("records") = recs.clone();
                    xml(&recs, 300, "success")
                } else {
                    xml(&recs, 280, "Invalid record")
                }
            }
            "dnsDeleteRecord" => {
                let id = get("rrid").unwrap_or_default();
                if recs.iter().any(|r| r.0 == id) {
                    recs.retain(|r| r.0 != id);
                    *records.lock().expect("records") = recs.clone();
                    xml(&recs, 300, "success")
                } else {
                    xml(&recs, 280, "Invalid record")
                }
            }
            other => panic!("意外操作 {other}"),
        }
    }
}

fn endpoint_of(srv: &FakeServer) -> String {
    format!("{}/api", srv.url())
}

/// 相对名与完整域名两种列表写法都要能定位记录；TTL 下限 3600；根域名
/// rrhost 为 "@"；多级子域名。
#[tokio::test]
async fn namesilo_upsert_contract_host_forms() {
    for full_host in [false, true] {
        let records = std::sync::Arc::new(Mutex::new(Vec::<Rec>::new()));
        let srv = FakeServer::start(namesilo_fake(records.clone(), full_host, false)).await;
        let p = NameSilo::with_endpoint(creds("", "k123"), http(), &endpoint_of(&srv))
            .expect("provider");
        let steps = [
            ("203.0.113.1", UpsertAction::Created),
            ("203.0.113.1", UpsertAction::Unchanged),
            ("203.0.113.2", UpsertAction::Updated),
        ];
        for (v, want) in steps {
            let r = rec("example.com", "home", RecordType::A, v);
            let got = p.upsert(&r).await.expect("upsert");
            assert_eq!(got, want, "full={full_host} value={v}");
        }
        {
            let recs = records.lock().expect("records");
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].2, "home");
            assert_eq!(recs[0].3, "203.0.113.2");
            assert_eq!(recs[0].4, 3600, "未指定 TTL 时新建用下限 3600");
        }
        // 根域名：rrhost 为 "@"；TTL 低于下限取 3600。
        let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
        r.ttl = 120;
        assert_eq!(
            p.upsert(&r).await.expect("root create"),
            UpsertAction::Created
        );
        {
            let recs = records.lock().expect("records");
            assert_eq!(recs[1].2, "@");
            assert_eq!(recs[1].4, 3600);
        }
        assert_eq!(
            p.upsert(&rec("example.com", "@", RecordType::AAAA, "2001:db8::1"))
                .await
                .expect("root unchanged"),
            UpsertAction::Unchanged
        );
        // 多级子域名。
        assert_eq!(
            p.upsert(&rec("example.com", "a.b", RecordType::A, "1.1.1.1"))
                .await
                .expect("sub create"),
            UpsertAction::Created
        );
        assert_eq!(
            p.upsert(&rec("example.com", "a.b", RecordType::A, "1.1.1.1"))
                .await
                .expect("sub unchanged"),
            UpsertAction::Unchanged
        );
    }
}

/// TXT 新增与按值删除；删除解析按值匹配。
#[tokio::test]
async fn namesilo_txt_and_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<Rec>::new()));
    let srv = FakeServer::start(namesilo_fake(records.clone(), true, false)).await;
    let p =
        NameSilo::with_endpoint(creds("", "k123"), http(), &endpoint_of(&srv)).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].1, "TXT");
        assert_eq!(recs[0].2, "_acme-challenge", "TXT 的 rrhost 是主机记录");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].3, "v2");
    }

    // 删除动态域名解析：值一致才删除。
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
    let recs = records.lock().expect("records");
    assert_eq!(recs.len(), 1, "A 记录应已删除，只剩 TXT");
    assert_eq!(recs[0].1, "TXT");
}

/// 错误：Invalid API Key 归类为认证失败且不泄露 key；业务错误按无效输入。
#[tokio::test]
async fn namesilo_error_classification() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<Rec>::new()));
    let srv = FakeServer::start(namesilo_fake(records.clone(), false, true)).await;
    let bad =
        NameSilo::with_endpoint(creds("", "wrong"), http(), &endpoint_of(&srv)).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("invalid api key");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.contains("Invalid API Key"), "{}", err.detail);
    assert!(
        !err.detail.contains("wrong"),
        "错误信息不得泄露 key: {}",
        err.detail
    );

    // 非 300 业务码按无效输入归类。
    let biz = FakeServer::start(|_| xml(&[], 261, "Domain name not found")).await;
    let p =
        NameSilo::with_endpoint(creds("", "k123"), http(), &endpoint_of(&biz)).expect("provider");
    let err = p
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("business failure");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(
        err.detail.contains("Domain name not found"),
        "{}",
        err.detail
    );
}
