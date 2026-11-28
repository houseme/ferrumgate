//! 新网互联 Eranet（上游 eranet.go）：与时代互联共用同一套「域名独立解析
//! API」，接口地址为 `https://www.eranet.com`，签名与各接口的参数见
//! `nowcn.rs`（凭据 ID 为 AccessInstanceID，Secret 为 AccessKeySecret）。

use std::sync::Arc;

use crate::providers::nowcn::NowcnApi;
use crate::{Credentials, Meta, ProviderError, Record, RemoteRecord, UpsertAction};

pub static META: Meta = Meta::new("eranet", "新网互联 (Eranet)")
    .labels("AccessInstanceID", "AccessKeySecret")
    .doc("https://help.eranet.com/domain/resolve/20260407145050/")
    .acme()
    .delete();

pub struct Eranet(NowcnApi);

impl Eranet {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://www.eranet.com")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        Ok(Self(NowcnApi::new(creds, http, endpoint)?))
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        self.0.upsert(&META, rec).await
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.0.add_txt(&META, zone, sub, value).await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        self.0.delete_txt(&META, zone, sub, value).await
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        self.0.find_records(&META, rec).await
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.0.remove_record(&META, rec, remote).await
    }
}

crate::impl_provider!(Eranet, META);
crate::impl_txt!(Eranet);
crate::impl_deleter!(Eranet);
