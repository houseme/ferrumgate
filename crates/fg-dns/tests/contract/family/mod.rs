//! 时代互联 / 新网互联 / Tnet.hk 三家共用的假服务器与签名重算（上游
//! testNowcnFamily 对三家跑同一组用例；nowcn.rs、eranet.rs、tnethk.rs 复用）。

use std::sync::{Arc, Mutex};

use crate::fake::{FakeResponse, FakeServer};
use fg_dns::Credentials;

/// RFC3986 百分号编码（空格 %20、保留 ~），与提供商实现一致。
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// 按同一算法重算签名：HMAC-SHA1(secret + "&", "GET&%2F&<编码后的规范化查询串>")。
pub fn nowcn_sign(secret: &str, params: &[(String, String)]) -> String {
    let mut sorted = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let joined = sorted
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let to_sign = format!("GET&{}&{}", percent_encode("/"), percent_encode(&joined));
    fg_dns::sign::base64_std(&fg_dns::sign::hmac_sha1(
        format!("{secret}&").as_bytes(),
        to_sign.as_bytes(),
    ))
}

/// 内存中的记录：id/Domain/Host/Type/Value/Ttl；另存最近一次写入与列表参数。
#[derive(Clone, Default)]
pub struct FamilyState {
    pub recs: Vec<serde_json::Value>,
    pub last: std::collections::BTreeMap<String, String>,
    pub last_list: std::collections::BTreeMap<String, String>,
    pub next_id: i64,
}

pub fn family_fake(
    state: Arc<Mutex<FamilyState>>,
    secret: String,
) -> impl Fn(&crate::fake::RecordedRequest) -> FakeResponse + Send + Sync + 'static {
    move |req| {
        assert_eq!(req.method, "GET", "接口应使用 GET");
        let mut params: Vec<(String, String)> = req.query_pairs();
        let sig = params
            .iter()
            .find(|(k, _)| k == "Signature")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        params.retain(|(k, _)| k != "Signature");
        let get = |k: &str| {
            params
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        // 公共参数（对照上游 nowcnMock.serve）。
        assert_eq!(get("AccessInstanceID"), "inst");
        assert_eq!(get("SignatureMethod"), "HMAC-SHA1");
        assert!(get("SignatureNonce").len() >= 8, "SignatureNonce 太短");
        assert!(!get("Timestamp").is_empty());
        // 鉴权失败时真实服务返回 200 与空响应体。
        if nowcn_sign(&secret, &params) != sig {
            return FakeResponse {
                status: 200,
                body: Vec::new(),
            };
        }
        let mut st = state.lock().expect("state").clone();
        let action = req.path.trim_start_matches("/api/dns/").to_owned();
        if get("Domain") != "example.com" {
            return FakeResponse::json(200, r#"{"RequestId":"r","error":"域名不存在"}"#);
        }
        let reply = match action.as_str() {
            "DescribeRecordIndex" => {
                st.last_list = params.iter().cloned().collect();
                let mut data: Vec<serde_json::Value> = st
                    .recs
                    .iter()
                    .filter(|r| {
                        r["Host"] == get("Host").as_str() && r["Type"] == get("Type").as_str()
                    })
                    .cloned()
                    .collect();
                // 服务端过滤不精确时多返回一条无关记录，覆盖客户端的精确过滤。
                data.push(serde_json::json!({
                    "id": 1, "Domain": "example.com",
                    "Host": format!("{}x", get("Host")),
                    "Type": get("Type"), "Value": "9.9.9.9", "State": 0,
                }));
                FakeResponse::json(
                    200,
                    serde_json::json!({"RequestId": "r", "Data": data}).to_string(),
                )
            }
            "AddDomainRecord" => {
                st.last = params.iter().cloned().collect();
                st.next_id += 1;
                st.recs.push(serde_json::json!({
                    "id": st.next_id,
                    "Domain": get("Domain"),
                    "Host": get("Host"),
                    "Type": get("Type"),
                    "Value": get("Value"),
                    "Ttl": get("Ttl"),
                    "State": 0,
                }));
                FakeResponse::json(200, format!(r#"{{"RequestId":"r","Id":"{}"}}"#, st.next_id))
            }
            "UpdateDomainRecord" => {
                st.last = params.iter().cloned().collect();
                let id = get("Id");
                if let Some(r) = st
                    .recs
                    .iter_mut()
                    .find(|r| fg_dns::simple::value_str(&r["id"]) == id)
                {
                    r["Value"] = serde_json::json!(get("Value"));
                    r["Ttl"] = serde_json::json!(get("Ttl"));
                    FakeResponse::json(200, format!(r#"{{"RequestId":"r","Id":"{id}"}}"#))
                } else {
                    FakeResponse::json(200, r#"{"RequestId":"r","error":"记录不存在"}"#)
                }
            }
            "DeleteDomainRecord" => {
                st.last = params.iter().cloned().collect();
                let id = get("Id");
                if let Some(pos) = st
                    .recs
                    .iter()
                    .position(|r| fg_dns::simple::value_str(&r["id"]) == id)
                {
                    st.recs.remove(pos);
                    FakeResponse::json(200, r#"{"RequestId":"r"}"#)
                } else {
                    FakeResponse::json(200, r#"{"RequestId":"r","error":"记录不存在"}"#)
                }
            }
            other => panic!("未预期的路径 {other}"),
        };
        *state.lock().expect("state") = st;
        reply
    }
}

/// 三家服务商都同时实现 upsert / TXT / 删除。
pub trait FamilyProvider: fg_dns::DnsProvider + fg_dns::TxtRecords + fg_dns::Deleter {}
impl FamilyProvider for fg_dns::providers::nowcn::Nowcn {}
impl FamilyProvider for fg_dns::providers::eranet::Eranet {}
impl FamilyProvider for fg_dns::providers::tnethk::Tnethk {}

/// 对共用同一套接口的三家服务商跑同一组用例（上游 testNowcnFamily）。
pub async fn run_family<P: FamilyProvider>(
    name: &str,
    wrap: fn(Credentials, Arc<fg_dns::http::OutboundHttp>, &str) -> Box<P>,
) {
    use crate::fake::util::{creds, http, rec};
    use fg_dns::{RecordType, UpsertAction, delete::delete_records};

    let state = Arc::new(Mutex::new(FamilyState {
        next_id: 100,
        ..FamilyState::default()
    }));
    let srv = FakeServer::start(family_fake(state.clone(), "sk".to_owned())).await;
    let p = wrap(creds("inst", "sk"), http(), &srv.url());

    // 创建 / 未变化 / 更新。
    let steps = [
        ("203.0.113.1", UpsertAction::Created),
        ("203.0.113.1", UpsertAction::Unchanged),
        ("203.0.113.2", UpsertAction::Updated),
    ];
    for (v, want) in steps {
        let r = rec("example.com", "home", RecordType::A, v);
        let got = p.upsert(&r).await.expect("upsert");
        assert_eq!(got, want, "{name} value={v}");
    }
    let st = state.lock().expect("state").clone();
    assert_eq!(st.recs.len(), 1, "{name} 应只有 1 条记录");
    assert_eq!(
        st.last.get("Domain").map(String::as_str),
        Some("example.com")
    );
    assert_eq!(st.last.get("Host").map(String::as_str), Some("home"));
    assert_eq!(st.last.get("Type").map(String::as_str), Some("A"));
    assert_eq!(
        st.last.get("Value").map(String::as_str),
        Some("203.0.113.2")
    );
    assert_eq!(
        st.last.get("Ttl").map(String::as_str),
        Some("600"),
        "{name} 未指定 TTL 更新取 600"
    );
    assert!(
        !st.last.get("Id").cloned().unwrap_or_default().is_empty(),
        "更新应带 Id"
    );
    assert_eq!(st.last_list.get("Host").map(String::as_str), Some("home"));
    assert_eq!(st.last_list.get("Type").map(String::as_str), Some("A"));

    // 根域名 AAAA，自定义 TTL；TTL 变化触发更新。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 300;
    assert_eq!(
        p.upsert(&r).await.expect("root create"),
        UpsertAction::Created
    );
    let st = state.lock().expect("state").clone();
    assert_eq!(st.last.get("Host").map(String::as_str), Some("@"));
    assert_eq!(st.last.get("Ttl").map(String::as_str), Some("300"));
    assert_eq!(
        p.upsert(&r).await.expect("root unchanged"),
        UpsertAction::Unchanged
    );
    r.ttl = 600;
    assert_eq!(
        p.upsert(&r).await.expect("ttl update"),
        UpsertAction::Updated
    );

    // 业务错误（域名不存在）。
    let err = p
        .upsert(&rec("other.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("business failure");
    assert!(err.detail.contains("域名不存在"), "{}", err.detail);

    // TXT：新增两个值，删除其一后保留另一个；删除不存在的值不报错。
    state.lock().expect("state").recs.clear();
    p.add_txt("example.com", "_acme-challenge", "tok1")
        .await
        .expect("add tok1");
    let st = state.lock().expect("state").clone();
    assert_eq!(st.last.get("Type").map(String::as_str), Some("TXT"));
    assert_eq!(
        st.last.get("Host").map(String::as_str),
        Some("_acme-challenge")
    );
    assert_eq!(st.last.get("Value").map(String::as_str), Some("tok1"));
    p.add_txt("example.com", "_acme-challenge", "tok2")
        .await
        .expect("add tok2");
    p.delete_txt("example.com", "_acme-challenge", "tok1")
        .await
        .expect("delete tok1");
    let st = state.lock().expect("state").clone();
    assert_eq!(st.recs.len(), 1, "{name} 应只删除 tok1");
    assert_eq!(st.recs[0]["Value"], "tok2");
    p.delete_txt("example.com", "_acme-challenge", "nope")
        .await
        .expect("delete nope");

    // 删除动态域名解析。
    state.lock().expect("state").recs.clear();
    p.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.1"))
        .await
        .expect("upsert for delete");
    let n = delete_records(
        &*p,
        &rec("example.com", "home", RecordType::A, "203.0.113.1"),
    )
    .await
    .expect("delete");
    assert_eq!(n, 1);
    let st = state.lock().expect("state").clone();
    assert!(st.recs.is_empty(), "{name} 删除后应没有记录");
    assert_eq!(
        st.last.get("Domain").map(String::as_str),
        Some("example.com")
    );
    assert!(!st.last.get("Id").cloned().unwrap_or_default().is_empty());
}
