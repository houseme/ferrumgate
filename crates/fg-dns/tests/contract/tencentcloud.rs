//! 腾讯云 DNSPod API 3.0 契约测试（对照上游 providers_test.go::TestTencentCloud、
//! keepttl_test.go::TestTencentCloudDefaultTTLOnUpdate、txt.go 的腾讯云分节、
//! delete_test.go::TestTencentCloudDelete）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::tencentcloud::TencentCloud,
};

/// 用请求头里的时间戳按同一算法重算签名，校验 TC3 授权头（上游假服务器同法）。
fn verify_tc3_auth(req: &fake::RecordedRequest, payload: &[u8], sid: &str, skey: &str) {
    let action = req.header("x-tc-action").expect("X-TC-Action").to_owned();
    let ts: i64 = req
        .header("x-tc-timestamp")
        .expect("X-TC-Timestamp")
        .parse()
        .expect("timestamp");
    let host = req.header("host").expect("Host").to_owned();
    let want = fg_dns::sign::tc3::authorization(sid, skey, "dnspod", &host, &action, payload, ts);
    assert_eq!(
        req.header("authorization"),
        Some(want.as_str()),
        "TC3 签名不一致"
    );
}

#[tokio::test]
async fn tencentcloud_upsert_request_contract() {
    let value = Mutex::new(String::new());
    let srv = FakeServer::start(move |req| {
        let mut st = value.lock().expect("state");
        verify_tc3_auth(req, &req.body, "sid", "skey");
        assert_eq!(req.header("content-type"), Some("application/json; charset=utf-8"));
        assert_eq!(req.header("x-tc-version"), Some("2021-03-23"));
        let action = req.header("x-tc-action").expect("action").to_owned();
        let params = req.body_json();
        match action.as_str() {
            "DescribeRecordList" => {
                if st.is_empty() {
                    return FakeResponse::json(
                        200,
                        r#"{"Response":{"Error":{"Code":"ResourceNotFound.NoDataOfRecord","Message":"no"}}}"#,
                    );
                }
                FakeResponse::json(
                    200,
                    format!(
                        r#"{{"Response":{{"RecordList":[{{"RecordId":12,"Value":"{st}","Type":"A","Name":"@","Line":"默认","TTL":600}}]}}}}"#
                    ),
                )
            }
            "CreateRecord" => {
                assert_eq!(params["SubDomain"], "@");
                assert_eq!(params["RecordLine"], "默认");
                assert_eq!(params["Domain"], "example.com");
                *st = params["Value"].as_str().expect("value").to_owned();
                FakeResponse::json(200, r#"{"Response":{"RecordId":12}}"#)
            }
            "ModifyRecord" => {
                assert_eq!(params["RecordId"], 12);
                *st = params["Value"].as_str().expect("value").to_owned();
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p =
        TencentCloud::with_endpoint(creds("sid", "skey"), http(), &srv.url()).expect("provider");
    let steps = [
        ("203.0.113.1", UpsertAction::Created),
        ("203.0.113.1", UpsertAction::Unchanged),
        ("203.0.113.2", UpsertAction::Updated),
    ];
    for (v, want) in steps {
        let r = rec("example.com", "@", RecordType::A, v);
        let got = p.upsert(&r).await.expect("upsert");
        assert_eq!(got, want, "value={v}");
    }
}

/// 未指定 TTL 时更新为默认的 600（keepttl 契约）。
#[tokio::test]
async fn tencentcloud_ttl_zero_update_uses_default_600() {
    let modified = std::sync::Arc::new(Mutex::new(None));
    let modified_in_handler = modified.clone();
    let srv = FakeServer::start(move |req| {
        let action = req.header("x-tc-action").expect("action").to_owned();
        match action.as_str() {
            "DescribeRecordList" => FakeResponse::json(
                200,
                r#"{"Response":{"RecordList":[{"RecordId":12,"Value":"1.1.1.1","Type":"A","Name":"@","Line":"默认","TTL":180}]}}"#,
            ),
            "ModifyRecord" => {
                *modified_in_handler.lock().expect("modified") = Some(req.body_json());
                FakeResponse::json(200, r#"{"Response":{"RequestId":"x"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = TencentCloud::with_endpoint(creds("id", "key"), http(), &srv.url()).expect("provider");
    let got = p
        .upsert(&rec("example.com", "@", RecordType::A, "2.2.2.2"))
        .await
        .expect("upsert");
    assert_eq!(got, UpsertAction::Updated);
    let body = modified
        .lock()
        .expect("modified")
        .clone()
        .expect("modify body");
    assert_eq!(body["TTL"], 600, "未指定 TTL 应更新为 600");
    assert_eq!(body["RecordId"], 12);
}

/// 只改备注时调用 ModifyRecordRemark，不重复提交记录值；值与备注都相同时不变。
#[tokio::test]
async fn tencentcloud_remark_only_change_uses_remark_api() {
    let (value, remark) = (
        std::sync::Arc::new(Mutex::new(String::new())),
        std::sync::Arc::new(Mutex::new(String::new())),
    );
    let value_in_handler = value.clone();
    let remark_in_handler = remark.clone();
    let srv = FakeServer::start(move |req| {
        let action = req.header("x-tc-action").expect("action").to_owned();
        let params = req.body_json();
        match action.as_str() {
            "DescribeRecordList" => {
                let st = value_in_handler.lock().expect("v");
                if st.is_empty() {
                    return FakeResponse::json(
                        200,
                        r#"{"Response":{"Error":{"Code":"ResourceNotFound.NoDataOfRecord","Message":"no"}}}"#,
                    );
                }
                let remark = remark_in_handler.lock().expect("r").clone();
                FakeResponse::json(
                    200,
                    format!(
                        r#"{{"Response":{{"RecordList":[{{"RecordId":12,"Value":"{st}","Type":"A","Name":"www","Line":"默认","TTL":600,"Remark":"{remark}"}}]}}}}"#
                    ),
                )
            }
            "CreateRecord" | "ModifyRecord" => {
                *value_in_handler.lock().expect("v") = params["Value"].as_str().expect("value").to_owned();
                if let Some(r) = params.get("Remark").and_then(|x| x.as_str()) {
                    *remark_in_handler.lock().expect("r") = r.to_owned();
                }
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            "ModifyRecordRemark" => {
                assert_eq!(params["RecordId"], 12);
                assert_eq!(params["Domain"], "example.com");
                *remark_in_handler.lock().expect("r") = params["Remark"].as_str().expect("remark").to_owned();
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p =
        TencentCloud::with_endpoint(creds("sid", "skey"), http(), &srv.url()).expect("provider");
    let mut r = rec("example.com", "www", RecordType::A, "1.1.1.1");
    r.remark = "a".into();
    assert!(matches!(
        p.upsert(&r).await,
        Ok(UpsertAction::Created) | Ok(UpsertAction::Updated)
    ));
    assert_eq!(*remark.lock().expect("r"), "a");
    // 值与备注一致：不再调用。
    assert_eq!(
        p.upsert(&r).await.expect("unchanged"),
        UpsertAction::Unchanged
    );
    // 只改备注：ModifyRecordRemark。
    r.remark = "b".into();
    assert_eq!(
        p.upsert(&r).await.expect("remark update"),
        UpsertAction::Updated
    );
    assert_eq!(*remark.lock().expect("r"), "b");
    assert_eq!(*value.lock().expect("v"), "1.1.1.1");
}

/// TXT：CreateRecord 总是新增（TTL 600、默认线路）；DeleteTXT 按值删除。
#[tokio::test]
async fn tencentcloud_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(100i64);
    let srv = FakeServer::start(move |req| {
        let action = req.header("x-tc-action").expect("action").to_owned();
        let params = req.body_json();
        match action.as_str() {
            "CreateRecord" => {
                assert_eq!(params["RecordType"], "TXT");
                assert_eq!(params["RecordLine"], "默认");
                assert_eq!(params["TTL"], 600);
                let mut id = next.lock().expect("next");
                *id += 1;
                records_in_handler.lock().expect("records").push((
                    id.to_string(),
                    params["Value"].as_str().expect("value").to_owned(),
                ));
                FakeResponse::json(200, format!(r#"{{"Response":{{"RecordId":{}}}}}"#, id))
            }
            "DescribeRecordList" => {
                let recs = records_in_handler.lock().expect("records");
                let list: Vec<serde_json::Value> = recs
                    .iter()
                    .map(|(id, v)| {
                        serde_json::json!({"RecordId": id, "Value": format!("\"{v}\""), "Type": "TXT", "Name": "_acme-challenge", "Line": "默认", "TTL": 600})
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    serde_json::json!({"Response": {"RecordList": list}}).to_string(),
                )
            }
            "DeleteRecord" => {
                let id = params["RecordId"].to_string();
                records_in_handler
                    .lock()
                    .expect("records")
                    .retain(|(rid, _)| rid != &id);
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p =
        TencentCloud::with_endpoint(creds("sid", "skey"), http(), &srv.url()).expect("provider");
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
    {
        let left = records.lock().expect("records");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].1, "v2");
    }
    // 删除不存在的值不报错。
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");
}

/// 删除：主机记录模糊匹配返回的其他记录不会被删除（精确过滤 Name）。
#[tokio::test]
async fn tencentcloud_delete_targets() {
    let deleted = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
    let deleted_in_handler = deleted.clone();
    let srv = FakeServer::start(move |req| {
        let action = req.header("x-tc-action").expect("action").to_owned();
        match action.as_str() {
            "DescribeRecordList" => FakeResponse::json(
                200,
                r#"{"Response":{"RecordList":[
                    {"RecordId":1,"Value":"1.1.1.1","Type":"A","Name":"www","Line":"默认","TTL":600},
                    {"RecordId":2,"Value":"1.1.1.1","Type":"A","Name":"www2","Line":"默认","TTL":600}]}}"#,
            ),
            "DeleteRecord" => {
                deleted_in_handler
                    .lock()
                    .expect("deleted")
                    .push(
                        req.body_json()["RecordId"]
                            .as_u64()
                            .expect("numeric record id")
                            .to_string(),
                    );
                FakeResponse::json(200, r#"{"Response":{}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p =
        TencentCloud::with_endpoint(creds("sid", "skey"), http(), &srv.url()).expect("provider");
    let n = delete_records(&p, &rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect("delete");
    assert_eq!(n, 1);
    assert_eq!(*deleted.lock().expect("deleted"), vec!["1".to_owned()]);
}

/// 业务错误按错误码归类：认证失败、限速、无效输入。
#[tokio::test]
async fn tencentcloud_error_classification() {
    let code = std::sync::Arc::new(Mutex::new("AuthFailure.SignatureFailure"));
    let code_in_handler = code.clone();
    let srv = FakeServer::start(move |_| {
        let current = *code_in_handler.lock().expect("code");
        FakeResponse::json(
            200,
            format!(r#"{{"Response":{{"Error":{{"Code":"{current}","Message":"boom"}}}}}}"#),
        )
    })
    .await;
    let p =
        TencentCloud::with_endpoint(creds("sid", "skey"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth failure");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(
        err.detail.contains("AuthFailure.SignatureFailure"),
        "{}",
        err.detail
    );

    *code.lock().expect("code") = "RequestLimitExceeded";
    let err = p
        .upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("rate limited");
    assert_eq!(err.kind, ProviderErrorKind::RateLimited);

    *code.lock().expect("code") = "InvalidParameter.DomainInvalid";
    let err = p
        .upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("invalid input");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
}
