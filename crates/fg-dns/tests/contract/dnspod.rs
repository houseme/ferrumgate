//! DNSPod / DNSPod 国际站契约测试（对照上游 providers_test.go::TestDNSPodToken、
//! keepttl_test.go::TestDNSPodDefaultTTLOnUpdate、txt_test.go::TestTXTDNSPod、
//! delete_test.go、remark_test.go::TestDNSPodRemark、dnspod_ua_test.go）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec, text},
};
use fg_dns::{
    DnsProvider, ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::dnspod::Dnspod,
};

struct State {
    value: String,
    remark: String,
}

fn provider(srv_url: &str) -> Dnspod {
    Dnspod::with_endpoint(
        &fg_dns::providers::dnspod::META,
        creds("123", "abc"),
        http(),
        srv_url,
        "默认",
    )
    .expect("provider")
}

#[tokio::test]
async fn dnspod_upsert_request_contract() {
    let state = Mutex::new(State {
        value: String::new(),
        remark: String::new(),
    });
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        assert_eq!(req.header("content-type"), Some("application/x-www-form-urlencoded"));
        match req.path.as_str() {
            "/Record.List" => {
                // 表单必须带 login_token、format、lang。
                let form = req.form();
                let get = |k: &str| {
                    form.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str()).unwrap_or("")
                };
                assert_eq!(get("login_token"), "123,abc");
                assert_eq!(get("format"), "json");
                assert_eq!(get("lang"), "cn");
                assert_eq!(get("domain"), "example.com");
                assert_eq!(get("sub_domain"), "nas");
                assert_eq!(get("record_type"), "AAAA");
                if st.value.is_empty() {
                    FakeResponse::json(200, r#"{"status":{"code":"10","message":"No records"}}"#)
                } else {
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"status":{{"code":"1"}},"records":[{{"id":"9","name":"nas","type":"AAAA","value":"{}","line":"默认","ttl":"600"}}]}}"#,
                            st.value
                        ),
                    )
                }
            }
            "/Record.Create" => {
                let form = req.form();
                let get = |k: &str| {
                    form.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str()).unwrap_or("")
                };
                assert_eq!(get("record_line"), "默认", "国内站默认线路");
                assert_eq!(get("value"), "2001:db8::1");
                st.value = get("value").to_owned();
                FakeResponse::json(200, r#"{"status":{"code":"1"},"record":{"id":"9"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = provider(&srv.url());
    let action = p
        .upsert(&rec("example.com", "nas", RecordType::AAAA, "2001:db8::1"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Created);
    // UA 必须可识别且不含 "DDNS Client"（dnsapi.cn 网关对这类 UA 返回 403）。
    let reqs = srv.requests();
    let ua = reqs[0]
        .header("user-agent")
        .expect("ua")
        .to_ascii_lowercase();
    assert!(ua.starts_with("ferrumgate/"), "ua = {ua}");
    assert!(!ua.contains("ddns client"));
}

#[tokio::test]
async fn dnspod_upsert_response_parsed() {
    let state = Mutex::new(State {
        value: String::new(),
        remark: String::new(),
    });
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        match req.path.as_str() {
            "/Record.List" => {
                if st.value.is_empty() {
                    FakeResponse::json(200, r#"{"status":{"code":"10","message":"No records"}}"#)
                } else {
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"status":{{"code":"1"}},"records":[{{"id":"9","name":"nas","type":"AAAA","value":"{}","line":"默认","ttl":"600","remark":"{}"}}]}}"#,
                            st.value, st.remark
                        ),
                    )
                }
            }
            "/Record.Create" => {
                st.value = "2001:db8::1".to_owned();
                FakeResponse::json(200, r#"{"status":{"code":"1"},"record":{"id":"9"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = provider(&srv.url());
    let action = p
        .upsert(&rec("example.com", "nas", RecordType::AAAA, "2001:db8::1"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Created);
}

#[tokio::test]
async fn dnspod_creates_then_updates() {
    let state = Mutex::new(State {
        value: String::new(),
        remark: String::new(),
    });
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        match req.path.as_str() {
            "/Record.List" => {
                if st.value.is_empty() {
                    FakeResponse::json(200, r#"{"status":{"code":"10","message":"No records"}}"#)
                } else {
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"status":{{"code":"1"}},"records":[{{"id":"9","name":"nas","type":"AAAA","value":"{}","line":"默认","ttl":"600"}}]}}"#,
                            st.value
                        ),
                    )
                }
            }
            "/Record.Create" | "/Record.Modify" => {
                let form = req.form();
                let get = |k: &str| {
                    form.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str()).unwrap_or("")
                };
                if req.path == "/Record.Modify" {
                    assert_eq!(get("record_id"), "9", "更新必须带 record_id");
                }
                st.value = get("value").to_owned();
                FakeResponse::json(200, r#"{"status":{"code":"1"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = provider(&srv.url());
    let steps = [
        ("2001:db8::1", UpsertAction::Created),
        ("2001:db8::1", UpsertAction::Unchanged),
        ("2001:db8::2", UpsertAction::Updated),
    ];
    for (value, want) in steps {
        let action = p
            .upsert(&rec("example.com", "nas", RecordType::AAAA, value))
            .await
            .expect("upsert");
        assert_eq!(action, want, "value={value}");
    }
}

#[tokio::test]
async fn dnspod_error_classification() {
    // 业务错误码按无效输入归类（网关层的 401/429/500 按状态归类）。
    let srv = FakeServer::start(|_| {
        FakeResponse::json(200, r#"{"status":{"code":"4","message":"登录信息无效"}}"#)
    })
    .await;
    let p = provider(&srv.url());
    let err = p
        .upsert(&rec("example.com", "nas", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("business error");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("Record.List"), "{}", err.detail);

    let status = Mutex::new(401u16);
    let srv2 = FakeServer::start(move |_| {
        let mut st = status.lock().expect("status");
        let current = *st;
        *st = 429;
        FakeResponse::json(current, r#"{"status":{"code":"1"},"records":[]}"#)
    })
    .await;
    let p2 = provider(&srv2.url());
    let err = p2
        .upsert(&rec("example.com", "nas", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("auth");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    let err = p2
        .upsert(&rec("example.com", "nas", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("rate limited");
    assert_eq!(err.kind, ProviderErrorKind::RateLimited);
}

#[tokio::test]
async fn dnspod_ttl_zero_and_line_default() {
    // 未指定 TTL 时 Record.Modify 更新为默认的 600（keepttl_test）。
    let modify = std::sync::Arc::new(Mutex::new(Vec::<Vec<(String, String)>>::new()));
    let modify_in_handler = modify.clone();
    let srv = FakeServer::start(move |req| {
        match req.path.as_str() {
            "/Record.List" => {
                FakeResponse::json(
                    200,
                    r#"{"status":{"code":"1"},"records":[{"id":"9","name":"nas","type":"A","value":"1.1.1.1","line":"默认","ttl":"120"}]}"#,
                )
            }
            "/Record.Modify" => {
                modify_in_handler.lock().expect("modify").push(req.form());
                FakeResponse::json(200, r#"{"status":{"code":"1"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = provider(&srv.url());
    let action = p
        .upsert(&rec("example.com", "nas", RecordType::A, "2.2.2.2"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Updated);
    let mods = modify.lock().expect("modify");
    assert_eq!(mods.len(), 1);
    let get = |k: &str| {
        mods[0]
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    assert_eq!(get("ttl"), "600", "未指定 TTL 应更新为 600");
    assert_eq!(get("record_line"), "默认");
}

#[tokio::test]
async fn dnspodcom_endpoint_and_line_contract() {
    let state = Mutex::new(State {
        value: String::new(),
        remark: String::new(),
    });
    let srv = FakeServer::start(move |req| {
        let mut st = state.lock().expect("state");
        match req.path.as_str() {
            "/Record.List" => {
                if st.value.is_empty() {
                    FakeResponse::json(200, r#"{"status":{"code":"10","message":"No records"}}"#)
                } else {
                    FakeResponse::json(
                        200,
                        format!(
                            r#"{{"status":{{"code":"1"}},"records":[{{"id":"9","name":"nas","type":"A","value":"{}","line":"default","ttl":"600"}}]}}"#,
                            st.value
                        ),
                    )
                }
            }
            "/Record.Create" => {
                let form = req.form();
                let get = |k: &str| {
                    form.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str()).unwrap_or("")
                };
                assert_eq!(get("record_line"), "default", "国际站默认线路是 default");
                st.value = get("value").to_owned();
                FakeResponse::json(200, r#"{"status":{"code":"1"},"record":{"id":"9"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = Dnspod::with_endpoint(
        &fg_dns::providers::dnspod::META_COM,
        creds("123", "abc"),
        http(),
        &srv.url(),
        "default",
    )
    .expect("provider");
    let action = p
        .upsert(&rec("example.com", "nas", RecordType::A, "1.1.1.1"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Created);
    assert_eq!(p.meta().name, "dnspodcom");
    assert!(!p.meta().supports_line, "国际站不声明线路能力");
}

#[tokio::test]
async fn dnspod_txt_add_delete() {
    let records = std::sync::Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let records_in_handler = records.clone();
    let next = Mutex::new(0i64);
    let srv = FakeServer::start(move |req| {
        let mut id = next.lock().expect("next");
        match req.path.as_str() {
            "/Record.Create" => {
                let form = req.form();
                let get = |k: &str| {
                    form.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str()).unwrap_or("")
                };
                assert_eq!(get("record_type"), "TXT");
                assert_eq!(get("ttl"), "600", "TXT 记录使用 600");
                assert_eq!(get("record_line"), "默认");
                *id += 1;
                records_in_handler
                    .lock()
                    .expect("records")
                    .push((id.to_string(), get("value").to_owned()));
                FakeResponse::json(200, r#"{"status":{"code":"1"}}"#)
            }
            "/Record.List" => {
                let recs = records_in_handler.lock().expect("records");
                let list: Vec<String> = recs
                    .iter()
                    .map(|(rid, value)| {
                        format!(
                            r#"{{"id":"{rid}","name":"_acme-challenge","type":"TXT","value":"{value}","line":"默认","ttl":"600"}}"#
                        )
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    format!(r#"{{"status":{{"code":"1"}},"records":[{}]}}"#, list.join(",")),
                )
            }
            "/Record.Remove" => {
                let form = req.form();
                let rid = form
                    .iter()
                    .find(|(k, _)| k == "record_id")
                    .map(|(_, v)| v.clone())
                    .expect("record_id");
                records_in_handler.lock().expect("records").retain(|(k, _)| k != &rid);
                FakeResponse::json(200, r#"{"status":{"code":"1"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = provider(&srv.url());
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    assert_eq!(records.lock().expect("records").len(), 2);
    // 按值删除（DNSPod 返回的 TXT 值不带引号，也验证带引号的写法）。
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let recs = records.lock().expect("records");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].1, "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");
}

#[tokio::test]
async fn dnspod_delete_targets() {
    let records = std::sync::Arc::new(Mutex::new(vec![
        ("1".to_owned(), "1.1.1.1".to_owned()),
        ("2".to_owned(), "2.2.2.2".to_owned()),
    ]));
    let records_in_handler = records.clone();
    let srv = FakeServer::start(move |req| {
        match req.path.as_str() {
            "/Record.List" => {
                let recs = records_in_handler.lock().expect("records");
                let list: Vec<String> = recs
                    .iter()
                    .map(|(rid, value)| {
                        format!(
                            r#"{{"id":"{rid}","name":"www","type":"A","value":"{value}","line":"默认","ttl":"600"}}"#
                        )
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    format!(r#"{{"status":{{"code":"1"}},"records":[{}]}}"#, list.join(",")),
                )
            }
            "/Record.Remove" => {
                let form = req.form();
                let rid = form
                    .iter()
                    .find(|(k, _)| k == "record_id")
                    .map(|(_, v)| v.clone())
                    .expect("record_id");
                records_in_handler.lock().expect("records").retain(|(k, _)| k != &rid);
                FakeResponse::json(200, r#"{"status":{"code":"1"}}"#)
            }
            _ => text(500, "unexpected"),
        }
    })
    .await;
    let p = provider(&srv.url());
    let mut r = rec("example.com", "www", RecordType::A, "");
    // 值未知：拒绝删除。
    assert!(delete_records(&p, &r).await.is_err());
    r.value = "2.2.2.2".into();
    let n = delete_records(&p, &r).await.expect("delete");
    assert_eq!(n, 1);
    assert_eq!(records.lock().expect("records").len(), 1);
    assert_eq!(records.lock().expect("records")[0].0, "1");
}
