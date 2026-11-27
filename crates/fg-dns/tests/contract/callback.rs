//! 自定义回调契约测试（对照上游 providers_test.go::TestDuckDNSAndCallback、
//! callback_timestamp_test.go、webhook 的 render_json_test.go）。

mod fake;

use fake::{
    FakeResponse, FakeServer,
    util::{creds_with_extra, http, rec},
};
use fg_dns::{ProviderErrorKind, RecordType, UpsertAction, callback::Callback};

#[tokio::test]
async fn callback_upsert_request_contract() {
    let srv = FakeServer::start(|_req| FakeResponse::json(200, "OK")).await;
    let p = Callback::new(
        creds_with_extra(
            "",
            "",
            &[(
                "url",
                &format!("{}/?d={{domain}}&ip={{ip}}&t={{recordType}}", srv.url()),
            )],
        ),
        http(),
    )
    .expect("provider");
    let action = p
        .upsert(&rec("example.com", "a", RecordType::A, "1.2.3.4"))
        .await
        .expect("upsert");
    assert_eq!(action, UpsertAction::Updated);
    let reqs = srv.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    // 地址中的变量已替换（domain 为完整域名）。
    assert_eq!(reqs[0].query_param("d").as_deref(), Some("a.example.com"));
    assert_eq!(reqs[0].query_param("ip").as_deref(), Some("1.2.3.4"));
    assert_eq!(reqs[0].query_param("t").as_deref(), Some("A"));
}

#[tokio::test]
async fn callback_url_vars_are_query_escaped() {
    let srv = FakeServer::start(|_req| FakeResponse::json(200, "ok")).await;
    let p = Callback::new(
        creds_with_extra(
            "",
            "",
            &[("url", &format!("{}/?ip={{ip}}&s={{subDomain}}", srv.url()))],
        ),
        http(),
    )
    .expect("provider");
    let r = rec("example.com", "a b&c", RecordType::A, "1 2&x");
    p.upsert(&r).await.expect("upsert");
    let req = &srv.requests()[0];
    // 空格转 +、& 转 %26（Go url.QueryEscape 语义），解码后值不变。
    assert_eq!(req.query_param("ip").as_deref(), Some("1 2&x"));
    assert_eq!(req.query_param("s").as_deref(), Some("a b&c"));
    assert_eq!(r.value, "1 2&x");
}

#[tokio::test]
async fn callback_post_body_and_headers() {
    let got = std::sync::Arc::new(Mutex::new(Vec::<fake::RecordedRequest>::new()));
    let got_in_handler = got.clone();
    let srv = FakeServer::start(move |req| {
        got_in_handler.lock().expect("got").push(req.clone());
        FakeResponse::json(200, r#"{"ok":true}"#)
    })
    .await;
    let p = Callback::new(
        creds_with_extra(
            "uid",
            "usec",
            &[
                ("url", &srv.url()),
                ("method", "POST"),
                (
                    "headers",
                    &format!(
                        "X-Auth: secret-{0}\nContent-Type: application/json",
                        "fixed"
                    ),
                ),
                ("body", r#"{"msg":"{ip} {zone}","ip":"{ip}","port":8443}"#),
            ],
        ),
        http(),
    )
    .expect("provider");
    p.upsert(&rec("example.com", "www", RecordType::AAAA, "2001:db8::1"))
        .await
        .expect("upsert");
    let reqs = got.lock().expect("got");
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].header("x-auth"), Some("secret-fixed"));
    assert_eq!(reqs[0].header("content-type"), Some("application/json"));
    // JSON 模板中字符串内的变量转义；字符串外（数字）原样；id/secret 可用。
    assert_eq!(
        reqs[0].body_json(),
        serde_json::json!({"msg": "2001:db8::1 example.com", "ip": "2001:db8::1", "port": 8443})
    );
}

#[tokio::test]
async fn callback_ttl_default_and_timestamp() {
    let got = std::sync::Arc::new(Mutex::new(Vec::<fake::RecordedRequest>::new()));
    let got_in_handler = got.clone();
    let srv = FakeServer::start(move |req| {
        got_in_handler.lock().expect("got").push(req.clone());
        FakeResponse::json(200, "ok")
    })
    .await;
    let p = Callback::new(
        creds_with_extra(
            "",
            "",
            &[("url", &format!("{}/?a={{ttl}}&t={{timestamp}}", srv.url()))],
        ),
        http(),
    )
    .expect("provider");
    // 未配置 TTL：{ttl} 取 600。
    p.upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect("upsert");
    // 配置了 TTL：取配置值。
    let mut r = rec("example.com", "www", RecordType::A, "1.1.1.1");
    r.ttl = 120;
    p.upsert(&r).await.expect("upsert ttl");
    let reqs = got.lock().expect("got");
    assert_eq!(reqs[0].query_param("a").as_deref(), Some("600"));
    assert_eq!(reqs[1].query_param("a").as_deref(), Some("120"));
    // {timestamp} 为当前 Unix 秒（合理范围）。
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let ts: u64 = reqs[1]
        .query_param("t")
        .as_deref()
        .expect("ts")
        .parse()
        .expect("ts num");
    assert!(
        ts >= before.saturating_sub(5) && ts <= before + 60,
        "ts={ts}"
    );
}

#[tokio::test]
async fn callback_success_content_required() {
    // 配置了成功标识：响应包含任意一项即成功。
    let srv = FakeServer::start(|_| FakeResponse::json(200, "status=GOOD all fine")).await;
    let p = Callback::new(
        creds_with_extra(
            "",
            "",
            &[("url", &srv.url()), ("successContent", "BAD\nGOOD")],
        ),
        http(),
    )
    .expect("provider");
    p.upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect("success marker");

    // 不包含成功标识：报错。
    let srv2 = FakeServer::start(|_| FakeResponse::json(200, "status=BAD")).await;
    let p2 = Callback::new(
        creds_with_extra("", "", &[("url", &srv2.url()), ("successContent", "GOOD")]),
        http(),
    )
    .expect("provider");
    let err = p2
        .upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("missing marker");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    assert!(err.detail.contains("成功标识"), "{}", err.detail);
}

#[tokio::test]
async fn callback_error_classification() {
    // 非 2xx 按状态归类。
    let srv = FakeServer::start(|_| FakeResponse::json(500, "boom")).await;
    let p =
        Callback::new(creds_with_extra("", "", &[("url", &srv.url())]), http()).expect("provider");
    let err = p
        .upsert(&rec("example.com", "www", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("server");
    assert_eq!(err.kind, ProviderErrorKind::Server);

    // 无效配置在构造时报错（地址、方法）。
    let bad = Callback::new(
        creds_with_extra("", "", &[("url", "ftp://example.com/x")]),
        http(),
    );
    assert!(bad.is_err());
    let bad_method = Callback::new(
        creds_with_extra(
            "",
            "",
            &[("url", "http://example.com"), ("method", "TRACE")],
        ),
        http(),
    );
    assert!(bad_method.is_err());
}

#[test]
fn callback_hash_prefix_syntax() {
    // #{name} 写法（导入配置常用）与 {name} 等价。
    let mut vars = std::collections::BTreeMap::new();
    vars.insert("ttl".to_owned(), "600".to_owned());
    assert_eq!(
        fg_dns::render("a={ttl}&b=#{ttl}", &vars, None),
        "a=600&b=600"
    );
}

use std::sync::Mutex;
