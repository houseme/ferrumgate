//! 时代互联 Now.cn 契约测试（对照上游 nowcn_test.go 的 TestNowcn 与
//! TestNowcnSignature；eranet.rs 与 tnethk.rs 复用同一套接口的家族用例）。

mod fake;
mod family;

use std::sync::{Arc, Mutex};

use fake::{
    FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{Credentials, ProviderErrorKind, RecordType, providers::nowcn::Nowcn};

fn wrap_nowcn(c: Credentials, h: Arc<fg_dns::http::OutboundHttp>, url: &str) -> Box<Nowcn> {
    Box::new(Nowcn::with_endpoint(c, h, url).expect("nowcn"))
}

#[tokio::test]
async fn nowcn_family_upsert_txt_delete_contract() {
    family::run_family("nowcn", wrap_nowcn).await;
}

/// 签名算法：参数排序、RFC3986 编码与 HMAC-SHA1（密钥为 Secret 加 "&"），
/// 假服务器按同一算法重算比对（上游 TestNowcnSignature 的语义）。
#[test]
fn nowcn_signature_matches_recomputed_vector() {
    let params = vec![
        ("Domain".to_owned(), "example.com".to_owned()),
        ("Host".to_owned(), "a b*".to_owned()),
        ("AccessInstanceID".to_owned(), "inst".to_owned()),
    ];
    let got = family::nowcn_sign("sk", &params);
    // 与参数顺序无关。
    let reordered = vec![
        ("AccessInstanceID".to_owned(), "inst".to_owned()),
        ("Host".to_owned(), "a b*".to_owned()),
        ("Domain".to_owned(), "example.com".to_owned()),
    ];
    assert_eq!(got, family::nowcn_sign("sk", &reordered));
    // 密钥不同签名不同。
    assert_ne!(got, family::nowcn_sign("other", &params));
    // RFC3986：空格 %20、* %2A、保留 ~。
    assert_eq!(family::percent_encode("a b*~/"), "a%20b%2A~%2F");
}

/// 签名错误：服务端返回 200 空响应体，应按认证失败处理；缺少凭据构造失败；
/// 默认端点构造成功。
#[tokio::test]
async fn nowcn_bad_signature_returns_empty_body_error() {
    let state = Arc::new(Mutex::new(family::FamilyState::default()));
    let srv = FakeServer::start(family::family_fake(state, "sk".to_owned())).await;
    let bad = Nowcn::with_endpoint(creds("inst", "wrong"), http(), &srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("bad signature");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.contains("响应为空"), "{}", err.detail);

    assert!(Nowcn::with_endpoint(Credentials::default(), http(), &srv.url()).is_err());
    assert!(Nowcn::new(creds("i", "s"), http()).is_ok());
}
