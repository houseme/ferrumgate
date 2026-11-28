//! 阿里云云解析 DNS 契约测试（对照上游 alidns_test.go::TestAliDNSUpsert、
//! alidns_line_test.go::TestAliDNSDefaultLineAndTTL、remark_test.go::
//! TestAliDNSRemark、delete_test.go::TestAliDNSDelete）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records, providers::alidns::AliDns,
};

/// 重新计算查询串签名并比对（去掉 Signature 参数后按同一算法重算）。
fn verify_ali_query(req: &fake::RecordedRequest, secret: &str) {
    let params: Vec<(String, String)> = req
        .query_pairs()
        .into_iter()
        .filter(|(k, _)| k != "Signature")
        .collect();
    let want = fg_dns::sign::aliyun::signed_query("GET", &params, secret);
    assert_eq!(req.query, want, "阿里云签名不一致");
}

#[tokio::test]
async fn alidns_upsert_request_contract() {
    let existing = std::sync::Arc::new(Mutex::new(String::new()));
    let srv = FakeServer::start(move |req| {
        verify_ali_query(req, "sk");
        let params: Vec<(String, String)> = req.query_pairs();
        let get = |k: &str| {
            params
                .iter()
                .find(|(pk, _)| pk == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        if get("AccessKeyId") != "ak" {
            return FakeResponse::json(
                400,
                r#"{"Code":"SignatureDoesNotMatch","Message":"bad"}"#,
            );
        }
        match get("Action").as_str() {
            "DescribeSubDomainRecords" => {
                assert_eq!(get("SubDomain"), "www.example.com");
                assert_eq!(get("Type"), "A");
                let cur = existing.lock().expect("state");
                if cur.is_empty() {
                    return FakeResponse::json(
                        200,
                        r#"{"TotalCount":0,"DomainRecords":{"Record":[]}}"#,
                    );
                }
                FakeResponse::json(
                    200,
                    format!(
                        r#"{{"TotalCount":1,"DomainRecords":{{"Record":[{{"RecordId":"r1","RR":"www","Type":"A","Value":"{cur}","TTL":600,"Line":"default"}}]}}}}"#
                    ),
                )
            }
            "AddDomainRecord" => {
                assert_eq!(get("DomainName"), "example.com");
                assert_eq!(get("RR"), "www");
                assert_eq!(get("Value"), "1.1.1.1");
                assert_eq!(get("TTL"), "600");
                *existing.lock().expect("state") = get("Value");
                FakeResponse::json(200, r#"{"RecordId":"r1"}"#)
            }
            "UpdateDomainRecord" => {
                assert_eq!(get("RecordId"), "r1");
                *existing.lock().expect("state") = get("Value");
                FakeResponse::json(200, r#"{"RecordId":"r1"}"#)
            }
            other => panic!("意外动作 {other}"),
        }
    })
    .await;
    let p = AliDns::with_endpoint(creds("ak", "sk"), http(), &format!("{}/", srv.url()))
        .expect("provider");
    let steps = [
        ("1.1.1.1", UpsertAction::Created),
        ("1.1.1.1", UpsertAction::Unchanged),
        ("2.2.2.2", UpsertAction::Updated),
    ];
    for (v, want) in steps {
        let mut r = rec("example.com", "www", RecordType::A, v);
        r.ttl = 600;
        let got = p.upsert(&r).await.expect("upsert");
        assert_eq!(got, want, "value={v}");
    }
    // 认证失败：SignatureDoesNotMatch 按认证失败归类。
    let bad = AliDns::with_endpoint(creds("wrong", "sk"), http(), &format!("{}/", srv.url()))
        .expect("provider");
    let mut r = rec("example.com", "www", RecordType::A, "1.1.1.1");
    r.ttl = 600;
    let err = bad.upsert(&r).await.expect_err("auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(
        err.detail.contains("SignatureDoesNotMatch"),
        "{}",
        err.detail
    );
}

/// 未指定线路时只更新默认线路记录；未指定 TTL 时更新为 600（上游
/// TestAliDNSDefaultLineAndTTL）。
#[tokio::test]
async fn alidns_ttl_zero_and_line_default() {
    let updated = std::sync::Arc::new(Mutex::new(None));
    let updated_in_handler = updated.clone();
    let srv = FakeServer::start(move |req| {
        let params: Vec<(String, String)> = req.query_pairs();
        let get = |k: &str| {
            params
                .iter()
                .find(|(pk, _)| pk == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        match get("Action").as_str() {
            "DescribeSubDomainRecords" => FakeResponse::json(
                200,
                r#"{"TotalCount":2,"DomainRecords":{"Record":[
                    {"RecordId":"tel","RR":"www","Type":"A","Value":"9.9.9.9","TTL":600,"Line":"telecom"},
                    {"RecordId":"def","RR":"www","Type":"A","Value":"1.1.1.1","TTL":300,"Line":"default"}]}}"#,
            ),
            "UpdateDomainRecord" => {
                *updated_in_handler.lock().expect("updated") = Some(params);
                FakeResponse::json(200, r#"{"RecordId":"def"}"#)
            }
            other => panic!("意外动作 {other}"),
        }
    })
    .await;
    let p = AliDns::with_endpoint(creds("ak", "sk"), http(), &format!("{}/", srv.url()))
        .expect("provider");
    let got = p
        .upsert(&rec("example.com", "www", RecordType::A, "2.2.2.2"))
        .await
        .expect("upsert");
    assert_eq!(got, UpsertAction::Updated);
    let params = updated.lock().expect("updated").clone().expect("update");
    let get = |k: &str| {
        params
            .iter()
            .find(|(pk, _)| pk == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(get("RecordId"), "def", "应更新默认线路记录");
    assert_eq!(get("TTL"), "600", "未指定 TTL 应更新为 600");
}

/// 备注：新增接口不接受备注，创建后单独设置；只改备注不调 UpdateDomainRecord；
/// 备注格式受限（空格换成下划线）；未填备注时不动服务商已有的备注。
#[tokio::test]
async fn alidns_remark_flow() {
    let (value, remark) = (
        std::sync::Arc::new(Mutex::new(String::new())),
        std::sync::Arc::new(Mutex::new(String::new())),
    );
    let value_in_handler = value.clone();
    let remark_in_handler = remark.clone();
    let srv = FakeServer::start(move |req| {
        let params: Vec<(String, String)> = req.query_pairs();
        let get = |k: &str| {
            params
                .iter()
                .find(|(pk, _)| pk == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        match get("Action").as_str() {
            "DescribeSubDomainRecords" => {
                let cur = value_in_handler.lock().expect("v");
                if cur.is_empty() {
                    return FakeResponse::json(200, r#"{"DomainRecords":{"Record":[]}}"#);
                }
                let remark = remark_in_handler.lock().expect("r").clone();
                FakeResponse::json(
                    200,
                    format!(
                        r#"{{"DomainRecords":{{"Record":[{{"RecordId":"r1","RR":"www","Type":"A","Value":"{cur}","TTL":600,"Line":"default","Remark":"{remark}"}}]}}}}"#
                    ),
                )
            }
            "AddDomainRecord" => {
                assert_eq!(get("Remark"), "", "新增接口不接受备注参数");
                *value_in_handler.lock().expect("v") = get("Value");
                FakeResponse::json(200, r#"{"RecordId":"r1"}"#)
            }
            "UpdateDomainRecord" => {
                *value_in_handler.lock().expect("v") = get("Value");
                FakeResponse::json(200, r#"{"RecordId":"r1"}"#)
            }
            "UpdateDomainRecordRemark" => {
                assert_eq!(get("RecordId"), "r1");
                *remark_in_handler.lock().expect("r") = get("Remark");
                FakeResponse::json(200, r#"{}"#)
            }
            other => panic!("意外动作 {other}"),
        }
    })
    .await;
    let p = AliDns::with_endpoint(creds("ak", "sk"), http(), &format!("{}/", srv.url()))
        .expect("provider");
    let steps = [
        ("1.1.1.1", "家里 NAS", UpsertAction::Created),
        ("1.1.1.1", "家里 NAS", UpsertAction::Unchanged),
        ("1.1.1.1", "书房 NAS", UpsertAction::Updated),
    ];
    for (v, remark_text, want) in steps {
        let mut r = rec("example.com", "www", RecordType::A, v);
        r.remark = remark_text.to_owned();
        let got = p.upsert(&r).await.expect("upsert");
        assert_eq!(got, want, "{v}/{remark_text}");
    }
    // 阿里云不接受空格，写入时换成下划线。
    assert_eq!(*remark.lock().expect("r"), "书房_NAS");
    // 未填备注：服务商处已有的备注保持不变，也不算作变化。
    let r = rec("example.com", "www", RecordType::A, "1.1.1.1");
    let got = p.upsert(&r).await.expect("unchanged");
    assert_eq!(got, UpsertAction::Unchanged);
    assert_eq!(*remark.lock().expect("r"), "书房_NAS");
}

/// TXT：AddTXT 总是新增（TTL 600）；DeleteTXT 按值（去引号）删除。
#[tokio::test]
async fn alidns_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(100i64);
    let srv = FakeServer::start(move |req| {
        let params: Vec<(String, String)> = req.query_pairs();
        let get = |k: &str| {
            params
                .iter()
                .find(|(pk, _)| pk == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        match get("Action").as_str() {
            "AddDomainRecord" => {
                assert_eq!(get("Type"), "TXT");
                assert_eq!(get("TTL"), "600");
                let mut id = next.lock().expect("next");
                *id += 1;
                records_in_handler
                    .lock()
                    .expect("records")
                    .push((id.to_string(), get("Value")));
                FakeResponse::json(200, r#"{}"#)
            }
            "DescribeSubDomainRecords" => {
                let recs = records_in_handler.lock().expect("records");
                let list: Vec<serde_json::Value> = recs
                    .iter()
                    .map(|(id, v)| {
                        serde_json::json!({"RecordId": id, "Value": format!("\"{v}\""), "Type": "TXT"})
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    serde_json::json!({"DomainRecords": {"Record": list}}).to_string(),
                )
            }
            "DeleteDomainRecord" => {
                let id = get("RecordId");
                records_in_handler
                    .lock()
                    .expect("records")
                    .retain(|(rid, _)| rid != &id);
                FakeResponse::json(200, r#"{}"#)
            }
            other => panic!("意外动作 {other}"),
        }
    })
    .await;
    let p = AliDns::with_endpoint(creds("a", "b"), http(), &format!("{}/", srv.url()))
        .expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    assert_eq!(records.lock().expect("records").len(), 2);
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    let left = records.lock().expect("records");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].1, "v2");
}

/// 删除：只删默认线路上值相同的记录；指定线路时删对应线路。
#[tokio::test]
async fn alidns_delete_targets() {
    let deleted = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
    let deleted_in_handler = deleted.clone();
    let srv = FakeServer::start(move |req| {
        let params: Vec<(String, String)> = req.query_pairs();
        let get = |k: &str| {
            params
                .iter()
                .find(|(pk, _)| pk == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        match get("Action").as_str() {
            "DescribeSubDomainRecords" => FakeResponse::json(
                200,
                r#"{"DomainRecords":{"Record":[
                    {"RecordId":"r1","RR":"www","Type":"A","Value":"1.1.1.1","Line":"default"},
                    {"RecordId":"r2","RR":"www","Type":"A","Value":"2.2.2.2","Line":"telecom"}]}}"#,
            ),
            "DeleteDomainRecord" => {
                deleted_in_handler
                    .lock()
                    .expect("deleted")
                    .push(get("RecordId"));
                FakeResponse::json(200, r#"{}"#)
            }
            other => panic!("意外动作 {other}"),
        }
    })
    .await;
    let p = AliDns::with_endpoint(creds("ak", "sk"), http(), &format!("{}/", srv.url()))
        .expect("provider");
    let n = delete_records(&p, &rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect("delete default line");
    assert_eq!(n, 1);
    assert_eq!(*deleted.lock().expect("deleted"), vec!["r1".to_owned()]);
    deleted.lock().expect("deleted").clear();
    let mut r = rec("example.com", "www", RecordType::A, "2.2.2.2");
    r.line = "telecom".into();
    let n = delete_records(&p, &r).await.expect("delete telecom line");
    assert_eq!(n, 1);
    assert_eq!(*deleted.lock().expect("deleted"), vec!["r2".to_owned()]);
}
