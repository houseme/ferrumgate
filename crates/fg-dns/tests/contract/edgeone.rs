//! 腾讯云 EdgeOne 契约测试（对照上游 edgeone_test.go::TestEdgeOneUpsert、
//! TestEdgeOneTXTAndDelete、TestEdgeOneErrors）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::edgeone::EdgeOne,
};

/// 重算 TC3 签名（服务 teo）并校验；校验 X-TC-Version 与 Content-Type。
fn verify_tc3(req: &fake::RecordedRequest) {
    let action = req.header("x-tc-action").expect("action").to_owned();
    let ts: i64 = req
        .header("x-tc-timestamp")
        .expect("ts")
        .parse()
        .expect("timestamp");
    let host = req.header("host").expect("Host").to_owned();
    let want =
        fg_dns::sign::tc3::authorization("AKID", "SKEY", "teo", &host, &action, &req.body, ts);
    assert_eq!(req.header("authorization"), Some(want.as_str()));
    assert_eq!(req.header("x-tc-version"), Some("2022-09-01"));
    assert_eq!(
        req.header("content-type"),
        Some("application/json; charset=utf-8")
    );
}

/// 假站点列表（目标站点在第二页，验证翻页与忽略大小写）。
fn zones_page(offset: usize, limit: usize) -> (i64, Vec<serde_json::Value>) {
    let mut zones: Vec<serde_json::Value> = (0..150)
        .map(|i| {
            serde_json::json!({"ZoneId": format!("zone-x{i}"), "ZoneName": format!("other{i}.com")})
        })
        .collect();
    zones[120] = serde_json::json!({"ZoneId": "zone-1", "ZoneName": "Example.com"});
    let end = (offset + limit).min(zones.len());
    let start = offset.min(zones.len());
    (zones.len() as i64, zones[start..end].to_vec())
}

#[tokio::test]
async fn edgeone_upsert_request_contract() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(0i64);
    let last_create = std::sync::Arc::new(Mutex::new(None::<serde_json::Value>));
    let last_create_in_handler = last_create.clone();
    let srv = FakeServer::start(move |req| {
        verify_tc3(req);
        let action = req.header("x-tc-action").expect("action").to_owned();
        let params = req.body_json();
        let mut recs = records_in_handler.lock().expect("records");
        match action.as_str() {
            "DescribeZones" => {
                let offset = params["Offset"].as_u64().expect("offset") as usize;
                let limit = params["Limit"].as_u64().expect("limit") as usize;
                assert!(limit <= 100, "DescribeZones Limit 超过 100");
                let (total, page) = zones_page(offset, limit);
                FakeResponse::json(
                    200,
                    serde_json::json!({"Response": {"TotalCount": total, "Zones": page}}).to_string(),
                )
            }
            "DescribeDnsRecords" => {
                assert_eq!(params["ZoneId"], "zone-1");
                FakeResponse::json(
                    200,
                    serde_json::json!({"Response": {"TotalCount": recs.len(), "DnsRecords": *recs}}).to_string(),
                )
            }
            "CreateDnsRecord" => {
                *last_create_in_handler.lock().expect("last") = Some(params.clone());
                let mut id = next.lock().expect("next");
                *id += 1;
                let mut item = params.clone();
                item["RecordId"] = format!("record-{id}").into();
                item["Location"] = "Default".into();
                item["Status"] = "enable".into();
                recs.push(item.clone());
                FakeResponse::json(
                    200,
                    serde_json::json!({"Response": {"RecordId": item["RecordId"]}}).to_string(),
                )
            }
            "ModifyDnsRecords" => {
                assert_eq!(params["ZoneId"], "zone-1");
                for it in params["DnsRecords"].as_array().expect("items") {
                    for r in recs.iter_mut() {
                        if r["RecordId"] == it["RecordId"] {
                            r["Content"] = it["Content"].clone();
                            if let Some(ttl) = it.get("TTL") {
                                r["TTL"] = ttl.clone();
                            }
                        }
                    }
                }
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            "DeleteDnsRecords" => {
                let ids = params["RecordIds"].as_array().expect("ids");
                recs.retain(|r| !ids.contains(&r["RecordId"]));
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = EdgeOne::with_endpoint(creds("AKID", "SKEY"), http(), &srv.url()).expect("provider");
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
    assert_eq!(records.lock().expect("records").len(), 1);
    let created = last_create
        .lock()
        .expect("last")
        .clone()
        .expect("create body");
    assert_eq!(created["Name"], "home.example.com");
    assert_eq!(created["TTL"], 600, "未指定 TTL 时新建用 600");
    assert!(created.get("Location").is_none(), "默认线路不应传 Location");
    assert_eq!(
        created["Content"], "203.0.113.1",
        "创建请求携带首次同步的值"
    );
    // 三步之后记录集里的值是更新后的值。
    let recs = records.lock().expect("records");
    assert_eq!(recs[0]["Content"], "203.0.113.2");
    drop(recs);
}

/// 根域名记录名与 IPv6 记录；TTL 限制在 60 以上。
#[tokio::test]
async fn edgeone_root_record_and_ttl_clamp() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let srv = FakeServer::start(move |req| {
        let action = req.header("x-tc-action").expect("action").to_owned();
        let params = req.body_json();
        let mut recs = records_in_handler.lock().expect("records");
        match action.as_str() {
            "DescribeZones" => {
                let offset = params["Offset"].as_u64().expect("offset") as usize;
                let limit = params["Limit"].as_u64().expect("limit") as usize;
                let (total, page) = zones_page(offset, limit);
                FakeResponse::json(
                    200,
                    serde_json::json!({"Response": {"TotalCount": total, "Zones": page}})
                        .to_string(),
                )
            }
            "DescribeDnsRecords" => FakeResponse::json(
                200,
                serde_json::json!({"Response": {"TotalCount": recs.len(), "DnsRecords": *recs}})
                    .to_string(),
            ),
            "CreateDnsRecord" => {
                let mut item = params.clone();
                item["RecordId"] = format!("record-{}", recs.len() + 1).into();
                item["Location"] = "Default".into();
                item["Status"] = "enable".into();
                recs.push(item);
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            "ModifyDnsRecords" => {
                for it in params["DnsRecords"].as_array().expect("items") {
                    for r in recs.iter_mut() {
                        if r["RecordId"] == it["RecordId"] {
                            r["Content"] = it["Content"].clone();
                            if let Some(ttl) = it.get("TTL") {
                                r["TTL"] = ttl.clone();
                            }
                        }
                    }
                }
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = EdgeOne::with_endpoint(creds("AKID", "SKEY"), http(), &srv.url()).expect("provider");
    // 根域名记录名是站点名本身。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 30;
    let got = p.upsert(&r).await.expect("upsert");
    assert_eq!(got, UpsertAction::Created);
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs[0]["Name"], "example.com");
        assert_eq!(recs[0]["TTL"], 60, "TTL 低于下限时取 60");
    }
    // TTL 变化触发更新，且沿用现有值时不再传 TTL。
    r.ttl = 0;
    r.value = "2001:db8::2".into();
    let got = p.upsert(&r).await.expect("upsert");
    assert_eq!(got, UpsertAction::Updated);
    let recs = srv
        .requests()
        .iter()
        .rev()
        .find(|q| q.header("x-tc-action") == Some("ModifyDnsRecords"))
        .expect("modify")
        .body_json();
    assert_eq!(recs["DnsRecords"][0]["TTL"], 60, "未指定 TTL 时沿用现有值");
}

/// TXT 与删除：按值删除；值不一致时拒绝删除动态域名记录。
#[tokio::test]
async fn edgeone_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(0i64);
    let srv = FakeServer::start(move |req| {
        let action = req.header("x-tc-action").expect("action").to_owned();
        let params = req.body_json();
        let mut recs = records_in_handler.lock().expect("records");
        match action.as_str() {
            "DescribeZones" => {
                let offset = params["Offset"].as_u64().expect("offset") as usize;
                let limit = params["Limit"].as_u64().expect("limit") as usize;
                let (total, page) = zones_page(offset, limit);
                FakeResponse::json(
                    200,
                    serde_json::json!({"Response": {"TotalCount": total, "Zones": page}})
                        .to_string(),
                )
            }
            "DescribeDnsRecords" => FakeResponse::json(
                200,
                serde_json::json!({"Response": {"TotalCount": recs.len(), "DnsRecords": *recs}})
                    .to_string(),
            ),
            "CreateDnsRecord" => {
                let mut id = next.lock().expect("next");
                *id += 1;
                let mut item = params.clone();
                item["RecordId"] = format!("record-{id}").into();
                item["Location"] = "Default".into();
                item["Status"] = "enable".into();
                recs.push(item);
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            "DeleteDnsRecords" => {
                let ids = params["RecordIds"].as_array().expect("ids");
                recs.retain(|r| !ids.contains(&r["RecordId"]));
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = EdgeOne::with_endpoint(creds("AKID", "SKEY"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0]["Name"], "_acme-challenge.example.com");
        assert_eq!(recs[0]["TTL"], 600, "TXT 使用 600");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["Content"], "v2");
    }
    // 值不存在时不报错也不删除。
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");
    // 动态域名删除：值需与最近同步一致。
    let r = rec("example.com", "home", RecordType::A, "203.0.113.1");
    p.upsert(&r).await.expect("upsert");
    let err = delete_records(
        &p,
        &rec("example.com", "home", RecordType::A, "203.0.113.9"),
    )
    .await
    .expect_err("value mismatch");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    assert_eq!(records.lock().expect("records").len(), 1);
}

/// 错误：站点未找到（提示 NS 接入）与业务错误码。
#[tokio::test]
async fn edgeone_error_classification() {
    let fail_code = std::sync::Arc::new(Mutex::new(String::new()));
    let fail_code_in_handler = fail_code.clone();
    let srv = FakeServer::start(move |req| {
        let fail = fail_code_in_handler.lock().expect("fail").clone();
        if !fail.is_empty() {
            return FakeResponse::json(
                200,
                format!(r#"{{"Response":{{"Error":{{"Code":"{fail}","Message":"boom"}}}}}}"#),
            );
        }
        let action = req.header("x-tc-action").expect("action").to_owned();
        if action == "DescribeZones" {
            FakeResponse::json(200, r#"{"Response":{"TotalCount":0,"Zones":[]}}"#)
        } else {
            text(500, "unexpected")
        }
    })
    .await;
    let p = EdgeOne::with_endpoint(creds("AKID", "SKEY"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("missing.org", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("zone not found");
    assert_eq!(err.kind, ProviderErrorKind::ZoneNotFound);
    assert!(err.detail.contains("NS 方式接入"), "{}", err.detail);

    // 业务错误带错误码。
    *fail_code.lock().expect("fail") = "AuthFailure.SignatureFailure".to_owned();
    let err = p
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth failure");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(
        err.detail.contains("AuthFailure.SignatureFailure"),
        "{}",
        err.detail
    );
}
