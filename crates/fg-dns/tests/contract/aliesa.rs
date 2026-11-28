//! 阿里云 ESA 契约测试（对照上游 aliesa_test.go::TestAliESAUpsert、
//! TestAliESATXTAndDelete、TestAliESAErrors）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::aliesa::AliEsa,
};

/// 重算查询串签名（写入动作用 POST 方法签名）并比对。
fn verify_esa_query(req: &fake::RecordedRequest, secret: &str) {
    let params: Vec<(String, String)> = req
        .query_pairs()
        .into_iter()
        .filter(|(k, _)| k != "Signature")
        .collect();
    let want = fg_dns::sign::aliyun::signed_query(&req.method, &params, secret);
    assert_eq!(req.query, want, "ESA 签名不一致");
}

async fn spawn_esa(records: std::sync::Arc<Mutex<Vec<serde_json::Value>>>) -> FakeServer {
    let next = Mutex::new(0i64);
    FakeServer::start(move |req| {
        verify_esa_query(req, "SK");
        let params: Vec<(String, String)> = req.query_pairs();
        let get = |k: &str| {
            params
                .iter()
                .find(|(pk, _)| pk == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let mut recs = records.lock().expect("records");
        match get("Action").as_str() {
            "ListSites" => {
                assert_eq!(&req.method, "GET");
                if get("SiteName") == "example.com" {
                    FakeResponse::json(
                        200,
                        r#"{"TotalCount":1,"Sites":[{"SiteId":77,"SiteName":"Example.com","AccessType":"NS"}]}"#,
                    )
                } else {
                    FakeResponse::json(200, r#"{"TotalCount":0,"Sites":[]}"#)
                }
            }
            "ListRecords" => {
                assert_eq!(get("SiteId"), "77");
                let out: Vec<&serde_json::Value> = recs
                    .iter()
                    .filter(|r| {
                        r["RecordName"].as_str() == Some(get("RecordName").as_str())
                            && r["RecordType"].as_str() == Some(get("Type").as_str())
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    serde_json::json!({"TotalCount": out.len(), "Records": out}).to_string(),
                )
            }
            "CreateRecord" => {
                assert_eq!(&req.method, "POST");
                let mut id = next.lock().expect("next");
                *id += 1;
                let data: serde_json::Value = serde_json::from_str(&get("Data")).expect("data");
                let value = data["Value"].as_str().expect("value").to_owned();
                recs.push(serde_json::json!({
                    "RecordId": *id,
                    "RecordName": get("RecordName"),
                    "RecordType": get("Type"),
                    "Ttl": get("Ttl").parse::<i64>().unwrap_or(0),
                    "Data": {"Value": value},
                }));
                FakeResponse::json(200, format!(r#"{{"RecordId":{}}}"#, id))
            }
            "UpdateRecord" => {
                assert_eq!(&req.method, "POST");
                let id: i64 = get("RecordId").parse().expect("id");
                let data: serde_json::Value = serde_json::from_str(&get("Data")).expect("data");
                for r in recs.iter_mut() {
                    if r["RecordId"].as_i64() == Some(id) {
                        r["Data"]["Value"] = data["Value"].clone();
                        r["Ttl"] = get("Ttl").parse::<i64>().unwrap_or(0).into();
                    }
                }
                FakeResponse::json(200, r#"{"RequestId":"x"}"#)
            }
            "DeleteRecord" => {
                assert_eq!(&req.method, "POST");
                let id: i64 = get("RecordId").parse().expect("id");
                recs.retain(|r| r["RecordId"].as_i64() != Some(id));
                FakeResponse::json(200, r#"{"RequestId":"x"}"#)
            }
            other => panic!("意外动作 {other}"),
        }
    })
    .await
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn aliesa_upsert_request_contract() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let srv = spawn_esa(records.clone()).await;
    let p = AliEsa::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
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
        assert_eq!(recs[0]["RecordType"], "A/AAAA", "A 记录使用合并类型");
        assert_eq!(recs[0]["Data"]["Value"], "203.0.113.2");
        assert_eq!(recs[0]["Ttl"], 600, "未指定 TTL 时新建用 600");
        assert_eq!(recs[0]["RecordName"], "home.example.com");
    }
}

/// 同名 IPv6 并入同一条记录，IPv4 保持不变；IPv6 展开写法视为相同。
#[tokio::test]
async fn aliesa_merges_address_families() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let srv = spawn_esa(records.clone()).await;
    let p = AliEsa::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
    p.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.2"))
        .await
        .expect("upsert v4");
    let got = p
        .upsert(&rec("example.com", "home", RecordType::AAAA, "2001:db8::1"))
        .await
        .expect("upsert v6");
    assert_eq!(got, UpsertAction::Updated);
    {
        let recs = records.lock().expect("records");
        assert_eq!(
            recs[0]["Data"]["Value"], "203.0.113.2,2001:db8::1",
            "IPv4 在前"
        );
        assert_eq!(recs.len(), 1, "应并入同一条记录");
    }
    // IPv6 写法不同但等价应为未变化。
    let got = p
        .upsert(&rec(
            "example.com",
            "home",
            RecordType::AAAA,
            "2001:0db8:0:0:0:0:0:1",
        ))
        .await
        .expect("upsert v6 expanded");
    assert_eq!(got, UpsertAction::Unchanged);
    // 更新 IPv4 时保留 IPv6。
    let mut r = rec("example.com", "home", RecordType::A, "203.0.113.3");
    r.ttl = 120;
    let got = p.upsert(&r).await.expect("upsert v4 new");
    assert_eq!(got, UpsertAction::Updated);
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs[0]["Data"]["Value"], "203.0.113.3,2001:db8::1");
        assert_eq!(recs[0]["Ttl"], 120);
    }
    // 根域名记录名为站点名。
    p.upsert(&rec("example.com", "@", RecordType::A, "1.1.1.1"))
        .await
        .expect("upsert root");
    let recs = records.lock().expect("records");
    assert_eq!(recs[1]["RecordName"], "example.com");
}

/// TXT 与删除：动态域名删除时只去掉本记录的地址族，保留另一族。
#[tokio::test]
async fn aliesa_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let srv = spawn_esa(records.clone()).await;
    let p = AliEsa::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0]["RecordType"], "TXT");
        assert_eq!(recs[0]["Ttl"], 600);
        assert_eq!(recs[0]["RecordName"], "_acme-challenge.example.com");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["Data"]["Value"], "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "none")
        .await
        .expect("delete none");

    // 动态域名删除：IPv4 与 IPv6 共用一条记录，只去掉本记录的地址。
    {
        records.lock().expect("records").clear();
    }
    let v4 = rec("example.com", "home", RecordType::A, "203.0.113.1");
    let v6 = rec("example.com", "home", RecordType::AAAA, "2001:db8::1");
    p.upsert(&v4).await.expect("upsert v4");
    p.upsert(&v6).await.expect("upsert v6");
    let err = delete_records(&p, &rec("example.com", "home", RecordType::A, "9.9.9.9"))
        .await
        .expect_err("value mismatch");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    let n = delete_records(&p, &v4).await.expect("delete v4");
    assert_eq!(n, 1);
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1, "应保留 IPv6");
        assert_eq!(recs[0]["Data"]["Value"], "2001:db8::1");
    }
    let n = delete_records(&p, &v6).await.expect("delete v6");
    assert_eq!(n, 1);
    assert!(records.lock().expect("records").is_empty());
}

/// 错误：站点未找到与业务错误码。
#[tokio::test]
async fn aliesa_error_classification() {
    let srv = FakeServer::start(move |req| {
        let params: Vec<(String, String)> = req.query_pairs();
        let action = params
            .iter()
            .find(|(k, _)| k == "Action")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        match action.as_str() {
            "ListSites" => FakeResponse::json(200, r#"{"TotalCount":0,"Sites":[]}"#),
            "Boom" => FakeResponse::json(
                400,
                r#"{"Code":"Record.TTLExceedLimit","Message":"ttl bad","RequestId":"x"}"#,
            ),
            _ => panic!("意外动作 {action}"),
        }
    })
    .await;
    let p = AliEsa::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("missing.org", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("site not found");
    assert_eq!(err.kind, ProviderErrorKind::ZoneNotFound);
    assert!(err.detail.contains("未找到站点"), "{}", err.detail);
}
