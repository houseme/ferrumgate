//! Tnet.hk 契约测试（对照上游 tnethk_test.go::TestTnethk 与
//! TestTnethkEndpoint；共用接口的完整家族用例见 nowcn.rs / family 模块）。

mod fake;
mod family;

use std::sync::{Arc, Mutex};

use fake::{
    FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{Credentials, RecordType, providers::tnethk::Tnethk};

fn wrap_tnethk(c: Credentials, h: Arc<fg_dns::http::OutboundHttp>, url: &str) -> Box<Tnethk> {
    Box::new(Tnethk::with_endpoint(c, h, url).expect("tnethk"))
}

/// 与时代互联同一套接口：家族用例（创建/未变化/更新、TXT、删除）。
#[tokio::test]
async fn tnethk_family_upsert_txt_delete_contract() {
    family::run_family("tnethk", wrap_tnethk).await;
}

/// 默认端点构造校验（上游 TestTnethkEndpoint）。
#[tokio::test]
async fn tnethk_default_endpoint_and_error_surface() {
    let state = Arc::new(Mutex::new(family::FamilyState::default()));
    let srv = FakeServer::start(family::family_fake(state, "sk".to_owned())).await;
    let p = Tnethk::with_endpoint(creds("inst", "sk"), http(), &srv.url()).expect("provider");
    let err = p
        .upsert(&rec("other.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("business failure");
    assert!(err.detail.contains("域名不存在"), "{}", err.detail);

    assert!(Tnethk::new(creds("i", "s"), http()).is_ok());
    assert!(Tnethk::new(Credentials::default(), http()).is_err());
}
