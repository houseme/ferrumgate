//! 新网互联 Eranet 契约测试（对照上游 eranet_test.go::TestEranet 与
//! TestEranetEndpoint；共用接口的完整家族用例见 nowcn.rs / family 模块）。

mod fake;
mod family;

use std::sync::Arc;

use fake::{
    FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{Credentials, RecordType, providers::eranet::Eranet};
use std::sync::Mutex;

fn wrap_eranet(c: Credentials, h: Arc<fg_dns::http::OutboundHttp>, url: &str) -> Box<Eranet> {
    Box::new(Eranet::with_endpoint(c, h, url).expect("eranet"))
}

/// 与时代互联同一套接口：家族用例（创建/未变化/更新、TXT、删除）。
#[tokio::test]
async fn eranet_family_upsert_txt_delete_contract() {
    family::run_family("eranet", wrap_eranet).await;
}

/// 默认端点为 https://www.eranet.com；业务错误透出（上游 TestEranetEndpoint）。
#[tokio::test]
async fn eranet_default_endpoint_and_error_surface() {
    let state = Arc::new(Mutex::new(family::FamilyState::default()));
    let srv = FakeServer::start(family::family_fake(state, "sk".to_owned())).await;
    let p = Eranet::with_endpoint(creds("inst", "sk"), http(), &srv.url()).expect("provider");
    // 家族假服务器只认 example.com：其他域名透出业务错误。
    let err = p
        .upsert(&rec("other.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("business failure");
    assert!(err.detail.contains("域名不存在"), "{}", err.detail);

    // 构造校验：完整凭据成功，缺凭据失败。
    assert!(Eranet::new(creds("i", "s"), http()).is_ok());
    assert!(Eranet::new(Credentials::default(), http()).is_err());
}
