//! Amazon Route 53 契约测试（对照上游 more_test.go::TestRoute53 与
//! TestSignV4Vector 的向量）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{RecordType, UpsertAction, providers::route53::Route53};

/// 校验 Authorization 前缀（签名由 sigv4 官方向量测试锁定，这里校验头部
/// 形状与关键头存在）。
fn assert_sigv4_headers(req: &fake::RecordedRequest) {
    let auth = req.header("authorization").expect("Authorization");
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/")
            && auth.contains("/us-east-1/route53/aws4_request"),
        "{auth}"
    );
    assert!(req.header("x-amz-date").is_some());
    assert!(req.header("x-amz-content-sha256").is_some());
}

#[tokio::test]
async fn route53_upsert_request_contract() {
    let value = Mutex::new(String::new());
    let srv = FakeServer::start(move |req| {
        assert_sigv4_headers(req);
        let mut st = value.lock().expect("state");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/2013-04-01/hostedzonesbyname") => {
                assert_eq!(req.query_param("dnsname").as_deref(), Some("example.com."));
                FakeResponse::json(
                    200,
                    r#"<ListHostedZonesByNameResponse><HostedZones><HostedZone><Id>/hostedzone/ZZ1</Id><Name>example.com.</Name></HostedZone></HostedZones></ListHostedZonesByNameResponse>"#,
                )
            }
            ("GET", "/2013-04-01/hostedzone/ZZ1/rrset") => {
                let name = req.query_param("name").expect("name");
                let typ = req.query_param("type").expect("type");
                let vals: Vec<String> = if typ == "A" {
                    let cur = st.clone();
                    if cur.is_empty() {
                        Vec::new()
                    } else {
                        vec![cur]
                    }
                } else {
                    Vec::new()
                };
                if vals.is_empty() {
                    return FakeResponse::json(
                        200,
                        r#"<ListResourceRecordSetsResponse><ResourceRecordSets></ResourceRecordSets></ListResourceRecordSetsResponse>"#,
                    );
                }
                let records = vals
                    .iter()
                    .map(|v| format!("<ResourceRecord><Value>{v}</Value></ResourceRecord>"))
                    .collect::<String>();
                FakeResponse::json(
                    200,
                    format!(
                        r#"<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>{name}</Name><Type>{typ}</Type><TTL>300</TTL><ResourceRecords>{records}</ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"#
                    ),
                )
            }
            ("POST", "/2013-04-01/hostedzone/ZZ1/rrset") => {
                let body = String::from_utf8_lossy(&req.body).into_owned();
                assert!(body.contains("<Action>UPSERT</Action>"), "{body}");
                assert!(body.contains("<Name>home.example.com.</Name>"), "{body}");
                assert!(body.contains("<Type>A</Type>"), "{body}");
                assert!(body.contains("<TTL>300</TTL>"), "{body}");
                assert_eq!(
                    req.header("content-type"),
                    Some("text/xml"),
                    "带请求体时应发送 Content-Type"
                );
                let v = body
                    .split("<Value>")
                    .nth(1)
                    .expect("value")
                    .split("</Value>")
                    .next()
                    .expect("value end")
                    .to_owned();
                *st = v;
                FakeResponse::json(200, r#"<ChangeResourceRecordSetsResponse/>"#)
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = Route53::with_endpoint(creds("AKID", "SK"), http(), &srv.url()).expect("provider");
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
}

/// TXT：值带引号；两个验证值合并进同一记录集（UPSERT 整体替换）；按值删除
/// （全部移除后用 DELETE 提交与现有记录集一致的内容）。
#[tokio::test]
async fn route53_txt_add_delete() {
    let txt_vals = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
    let txt_vals_in_handler = txt_vals.clone();
    let srv = FakeServer::start(move |req| {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/2013-04-01/hostedzonesbyname") => FakeResponse::json(
                200,
                r#"<ListHostedZonesByNameResponse><HostedZones><HostedZone><Id>/hostedzone/ZZ1</Id><Name>example.com.</Name></HostedZone></HostedZones></ListHostedZonesByNameResponse>"#,
            ),
            ("GET", "/2013-04-01/hostedzone/ZZ1/rrset") => {
                let typ = req.query_param("type").expect("type");
                let vals: Vec<String> = if typ == "TXT" {
                    txt_vals_in_handler.lock().expect("txt").clone()
                } else {
                    Vec::new()
                };
                if vals.is_empty() {
                    return FakeResponse::json(
                        200,
                        r#"<ListResourceRecordSetsResponse><ResourceRecordSets></ResourceRecordSets></ListResourceRecordSetsResponse>"#,
                    );
                }
                let records = vals
                    .iter()
                    .map(|v| format!("<ResourceRecord><Value>{}</Value></ResourceRecord>", v.replace('"', "&quot;")))
                    .collect::<String>();
                FakeResponse::json(
                    200,
                    format!(
                        r#"<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords>{records}</ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"#
                    ),
                )
            }
            ("POST", "/2013-04-01/hostedzone/ZZ1/rrset") => {
                let body = String::from_utf8_lossy(&req.body).into_owned();
                let mut st = txt_vals_in_handler.lock().expect("txt");
                if body.contains("<Action>DELETE</Action>") {
                    st.clear();
                } else {
                    // 请求体里的值经过 XML 转义，存回原始写法。
                    *st = body
                        .split("<Value>")
                        .skip(1)
                        .map(|rest| {
                            rest.split("</Value>")
                                .next()
                                .expect("value")
                                .replace("&quot;", "\"")
                        })
                        .collect();
                }
                FakeResponse::json(200, r#"<ChangeResourceRecordSetsResponse/>"#)
            }
            _ => panic!("意外请求 {} {}", req.method, req.path),
        }
    })
    .await;
    let p = Route53::with_endpoint(creds("AKID", "SK"), http(), &srv.url()).expect("provider");
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let st = txt_vals.lock().expect("txt");
        assert_eq!(st.len(), 2);
        assert_eq!(st[0], "\"v1\"", "已有值在前，新值追加在记录集末尾");
        assert_eq!(st[1], "\"v2\"");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let st = txt_vals.lock().expect("txt");
        assert_eq!(st.len(), 1);
        assert_eq!(st[0], "\"v2\"");
    }
    p.delete_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("delete v2");
    assert!(txt_vals.lock().expect("txt").is_empty(), "应整体删除");
}

/// extra 指定 hostedZoneId 时跳过区域查找；错误响应透出 XML 的 Error>Code。
#[tokio::test]
async fn route53_hosted_zone_id_extra_and_error() {
    let srv = FakeServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/2013-04-01/hostedzone/ZZ9/rrset") => FakeResponse::json(
            200,
            r#"<ListResourceRecordSetsResponse><ResourceRecordSets></ResourceRecordSets></ListResourceRecordSetsResponse>"#,
        ),
        ("POST", "/2013-04-01/hostedzone/ZZ9/rrset") => {
            FakeResponse::json(200, r#"<ChangeResourceRecordSetsResponse/>"#)
        }
        _ => panic!("意外请求 {} {}", req.method, req.path),
    })
    .await;
    let p = Route53::with_endpoint(
        fake::util::creds_with_extra("AKID", "SK", &[("hostedZoneId", "/hostedzone/ZZ9")]),
        http(),
        &srv.url(),
    )
    .expect("provider");
    let action = p
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert with explicit zone id");
    assert_eq!(action, UpsertAction::Created);
    // 假服务器只看到 rrset 请求，没有 hostedzonesbyname。
    {
        let reqs = srv.requests();
        assert!(reqs.iter().all(|r| !r.path.contains("hostedzonesbyname")));
    }

    // 错误响应：XML 的 Error>Code/Message 透出。
    let err_srv = FakeServer::start(|_| {
        FakeResponse::json(
            403,
            r#"<ErrorResponse><Error><Code>AccessDenied</Code><Message>denied</Message></Error></ErrorResponse>"#,
        )
    })
    .await;
    let bad =
        Route53::with_endpoint(creds("AKID", "SK"), http(), &err_srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect_err("denied");
    assert!(err.detail.contains("AccessDenied"), "{}", err.detail);
    assert!(err.detail.contains("denied"), "{}", err.detail);
}
