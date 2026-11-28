//! 火山引擎 DNS 契约测试（对照上游 trafficroute_test.go::TestTrafficRouteUpsert、
//! TestTrafficRouteTXTAndDelete、TestTrafficRouteErrors；签名由假服务器重算比对）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::trafficroute::TrafficRoute,
};

/// 用请求头里的 X-Date 与请求体按同一算法重算签名并比对（上游假服务器同法）。
fn verify_volc_auth(req: &fake::RecordedRequest) {
    let x_date = req.header("x-date").expect("X-Date").to_owned();
    let host = req.header("host").expect("Host").to_owned();
    let content_type = req.header("content-type").expect("Content-Type").to_owned();
    let body_hash = fg_dns::sign::sha256_hex(&req.body);
    let want = trafficroute_auth(
        "AK",
        "SK",
        &req.method,
        &host,
        &req.query,
        &content_type,
        &body_hash,
        &x_date,
    );
    assert_eq!(
        req.header("authorization"),
        Some(want.as_str()),
        "火山引擎签名不一致"
    );
    // 凭证范围服务名为大写 DNS。
    assert!(req.header("authorization").unwrap_or_default().contains(
        "/cn-north-1/DNS/request, SignedHeaders=content-type;host;x-content-sha256;x-date,"
    ));
    assert_eq!(req.header("x-content-sha256"), Some(body_hash.as_str()));
    assert_eq!(req.query_param("Version").as_deref(), Some("2018-08-01"));
}

#[allow(clippy::too_many_arguments)]
fn trafficroute_auth(
    ak: &str,
    sk: &str,
    method: &str,
    host: &str,
    query: &str,
    content_type: &str,
    body_hash: &str,
    x_date: &str,
) -> String {
    // 与 providers/trafficroute.rs 的签名算法一致（重算比对）。
    let short = &x_date[..8];
    let signed_headers = "content-type;host;x-content-sha256;x-date";
    let canonical = format!(
        "{method}\n/\n{query}\ncontent-type:{content_type}\nhost:{host}\nx-content-sha256:{body_hash}\nx-date:{x_date}\n\n{signed_headers}\n{body_hash}"
    );
    let scope = format!("{short}/cn-north-1/DNS/request");
    let string_to_sign = format!(
        "HMAC-SHA256\n{x_date}\n{scope}\n{}",
        fg_dns::sign::sha256_hex(canonical.as_bytes())
    );
    let mut key = fg_dns::sign::hmac_sha256(sk.as_bytes(), short.as_bytes());
    key = fg_dns::sign::hmac_sha256(&key, b"cn-north-1");
    key = fg_dns::sign::hmac_sha256(&key, b"DNS");
    key = fg_dns::sign::hmac_sha256(&key, b"request");
    let signature: String = fg_dns::sign::hmac_sha256(&key, string_to_sign.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

#[tokio::test]
async fn trafficroute_upsert_request_contract() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(1000i64);
    let srv = FakeServer::start(move |req| {
        verify_volc_auth(req);
        let action = req.query_param("Action").expect("action").to_owned();
        let params = req.body_json();
        // 读取类动作用 GET 且参数在查询串中，写入类动作用 POST JSON。
        let is_read = action == "ListZones" || action == "ListRecords";
        assert_eq!(
            (req.method == "GET"),
            is_read,
            "{action} 使用了 {}",
            req.method
        );
        let mut recs = records_in_handler.lock().expect("records");
        match action.as_str() {
            "ListZones" => {
                assert!(
                    req.query_param("SearchMode").is_none(),
                    "ListZones 不应带 SearchMode"
                );
                if req.query_param("Key").as_deref() == Some("example.com") {
                    FakeResponse::json(
                        200,
                        r#"{"ResponseMetadata":{"RequestId":"x"},"Result":{"Total":2,"Zones":[{"ZID":11,"ZoneName":"example.com.cn"},{"ZID":12,"ZoneName":"Example.com"}]}}"#,
                    )
                } else {
                    FakeResponse::json(
                        200,
                        r#"{"ResponseMetadata":{"RequestId":"x"},"Result":{"Total":0,"Zones":[]}}"#,
                    )
                }
            }
            "ListRecords" => {
                assert_eq!(req.query_param("ZID").as_deref(), Some("12"));
                assert_eq!(req.query_param("SearchMode").as_deref(), Some("exact"));
                let out: Vec<&serde_json::Value> = recs
                    .iter()
                    .filter(|r| {
                        r["Host"].as_str() == req.query_param("Host").as_deref()
                            && r["Type"].as_str() == req.query_param("Type").as_deref()
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    serde_json::json!({"ResponseMetadata": {"RequestId": "x"}, "Result": {"TotalCount": out.len(), "Records": out}}).to_string(),
                )
            }
            "CreateRecord" => {
                let mut id = next.lock().expect("next");
                *id += 1;
                let mut item = params.clone();
                item["RecordID"] = format!("{id}").into();
                recs.push(item);
                FakeResponse::json(
                    200,
                    serde_json::json!({"ResponseMetadata": {"RequestId": "x"}, "Result": {"RecordID": id.to_string()}}).to_string(),
                )
            }
            "UpdateRecord" => {
                let id = params["RecordID"].as_str().expect("record id").to_owned();
                for r in recs.iter_mut() {
                    if r["RecordID"] == id {
                        r["Value"] = params["Value"].clone();
                        if let Some(ttl) = params.get("TTL") {
                            r["TTL"] = ttl.clone();
                        }
                    }
                }
                FakeResponse::json(200, r#"{"ResponseMetadata":{"RequestId":"x"},"Result":{}}"#)
            }
            "DeleteRecord" => {
                let id = params["RecordID"].as_str().expect("record id").to_owned();
                recs.retain(|r| r["RecordID"] != id);
                FakeResponse::json(200, r#"{"ResponseMetadata":{"RequestId":"x"},"Result":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = TrafficRoute::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
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
        assert_eq!(recs[0]["Value"], "203.0.113.2");
        assert_eq!(recs[0]["Line"], "default", "创建时默认线路写 default");
        assert_eq!(recs[0]["Host"], "home");
        assert_eq!(recs[0]["TTL"], 600, "创建始终携带 TTL，未指定时 600");
        assert_eq!(recs[0]["ZID"], 12);
    }
    // 更新请求必须带主机记录与线路，且始终携带 TTL。
    let update = srv
        .requests()
        .iter()
        .rev()
        .find(|q| q.query_param("Action").as_deref() == Some("UpdateRecord"))
        .expect("update")
        .body_json();
    assert_eq!(update["Host"], "home");
    assert_eq!(update["Line"], "default");
    assert_eq!(update["Type"], "A");
    assert_eq!(update["TTL"], 600);
    // 根域名主机记录为 @。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 600;
    let got = p.upsert(&r).await.expect("upsert root");
    assert_eq!(got, UpsertAction::Created);
    let recs = records.lock().expect("records");
    assert_eq!(recs[1]["Host"], "@");
    assert_eq!(recs[1]["TTL"], 600);
}

/// TXT 与删除。
#[tokio::test]
async fn trafficroute_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(2000i64);
    let srv = FakeServer::start(move |req| {
        let action = req.query_param("Action").expect("action").to_owned();
        let params = req.body_json();
        let mut recs = records_in_handler.lock().expect("records");
        match action.as_str() {
            "ListZones" => FakeResponse::json(
                200,
                r#"{"ResponseMetadata":{"RequestId":"x"},"Result":{"Total":1,"Zones":[{"ZID":12,"ZoneName":"example.com"}]}}"#,
            ),
            "ListRecords" => {
                let out: Vec<&serde_json::Value> = recs
                    .iter()
                    .filter(|r| {
                        r["Host"].as_str() == req.query_param("Host").as_deref()
                            && r["Type"].as_str() == req.query_param("Type").as_deref()
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    serde_json::json!({"ResponseMetadata": {"RequestId": "x"}, "Result": {"TotalCount": out.len(), "Records": out}}).to_string(),
                )
            }
            "CreateRecord" => {
                let mut id = next.lock().expect("next");
                *id += 1;
                let mut item = params.clone();
                item["RecordID"] = format!("{id}").into();
                recs.push(item);
                FakeResponse::json(200, r#"{"ResponseMetadata":{"RequestId":"x"},"Result":{}}"#)
            }
            "DeleteRecord" => {
                let id = params["RecordID"].as_str().expect("id").to_owned();
                recs.retain(|r| r["RecordID"] != id);
                FakeResponse::json(200, r#"{"ResponseMetadata":{"RequestId":"x"},"Result":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = TrafficRoute::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0]["Type"], "TXT");
        assert_eq!(recs[0]["TTL"], 600);
        assert_eq!(recs[0]["Host"], "_acme-challenge");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["Value"], "v2");
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
    assert_eq!(records.lock().expect("records").len(), 1);
}

/// 错误：域名未找到与 ResponseMetadata.Error 业务错误。
#[tokio::test]
async fn trafficroute_error_classification() {
    let srv = FakeServer::start(move |req| {
        if req.query_param("Action").as_deref() == Some("ListZones") {
            return FakeResponse::json(
                200,
                r#"{"ResponseMetadata":{"RequestId":"x"},"Result":{"Total":0,"Zones":[]}}"#,
            );
        }
        FakeResponse::json(
            400,
            r#"{"ResponseMetadata":{"RequestId":"x","Error":{"Code":"ErrZoneNotFound","Message":"zone missing"}}}"#,
        )
    })
    .await;
    let p = TrafficRoute::with_endpoint(creds("AK", "SK"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("missing.org", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("zone not found");
    assert_eq!(err.kind, ProviderErrorKind::ZoneNotFound);
    assert!(err.detail.contains("未找到域名"), "{}", err.detail);
}
