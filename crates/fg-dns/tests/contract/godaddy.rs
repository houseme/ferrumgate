//! GoDaddy 契约测试（对照上游 providers_test.go::TestGoDaddy、txt_test.go 的
//! GoDaddy 分节与 delete.go 的 GoDaddy 分节）。

mod fake;

use std::sync::Arc;
use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::godaddy::GoDaddy,
};

/// 按名称管理的记录集：type/rr → [{data, ttl}]。
type Store = std::collections::BTreeMap<(String, String), Vec<(String, i64)>>;

fn key_of(typ: &str, rr: &str) -> (String, String) {
    (typ.to_owned(), rr.to_owned())
}

fn godaddy_fake(
    store: Arc<Mutex<Store>>,
) -> impl Fn(&fake::RecordedRequest) -> FakeResponse + Send + Sync + 'static {
    move |req| {
        assert_eq!(
            req.header("authorization"),
            Some("sso-key gdkey:gdsecret"),
            "sso-key 认证头"
        );
        let path = req.path.to_owned();
        let prefix = "/v1/domains/example.com/records/";
        let rest = path.trim_start_matches(prefix);
        assert!(path.starts_with(prefix), "路径错误 {path}");
        let (typ, rr) = match rest.split_once('/') {
            Some((t, r)) => (t.to_owned(), r.to_owned()),
            None => (rest.to_owned(), "@".to_owned()),
        };
        let mut st = store.lock().expect("store").clone();
        let key = key_of(&typ, &rr);
        let reply = match req.method.as_str() {
            "GET" => {
                let values = st.get(&key).cloned().unwrap_or_default();
                let arr: Vec<serde_json::Value> = values
                    .iter()
                    .map(|(data, ttl)| serde_json::json!({"data": data, "ttl": ttl}))
                    .collect();
                FakeResponse::json(200, serde_json::Value::Array(arr).to_string())
            }
            "PUT" => {
                assert_eq!(req.header("content-type"), Some("application/json"));
                let mut values = Vec::new();
                for v in req.body_json().as_array().expect("array") {
                    values.push((
                        v["data"].as_str().unwrap_or_default().to_owned(),
                        v["ttl"].as_i64().unwrap_or(0),
                    ));
                }
                st.insert(key, values);
                FakeResponse::json(200, "")
            }
            "DELETE" => {
                st.remove(&key);
                FakeResponse::json(200, "")
            }
            other => panic!("意外方法 {other}"),
        };
        *store.lock().expect("store") = st;
        reply
    }
}

/// 创建/未变化/更新的请求体契约（PUT 整体替换、最小 TTL 600）；TXT 追加与
/// 按值删除；删除解析：记录集有其他值拒绝、单值删除。
#[tokio::test]
async fn godaddy_upsert_txt_and_delete_contract() {
    let store = Arc::new(Mutex::new(Store::new()));
    let srv = FakeServer::start(godaddy_fake(store.clone())).await;
    let p =
        GoDaddy::with_endpoint(creds("gdkey", "gdsecret"), http(), &srv.url()).expect("provider");
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
    {
        let st = store.lock().expect("store");
        let values = st.get(&key_of("A", "home")).expect("recordset");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, "203.0.113.2");
        assert_eq!(values[0].1, 600, "未指定 TTL 用最小值 600");
    }

    // TXT：GET 后 PUT 追加（新值 TTL 600，旧值保持原 TTL）；按值删除。
    p.add_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("add v1");
    {
        let mut st = store.lock().expect("store");
        st.get_mut(&key_of("TXT", "_acme-challenge"))
            .expect("txt recordset")[0]
            .1 = 3600; // 手动改成非 600，验证追加时旧值保持原 TTL
    }
    p.add_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("add v2");
    {
        let st = store.lock().expect("store");
        let values = st.get(&key_of("TXT", "_acme-challenge")).expect("txt");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].0, "v1");
        assert_eq!(values[0].1, 3600, "追加不应改旧值的 TTL");
        assert_eq!(values[1].1, 600, "新验证值 TTL 600");
    }
    p.delete_txt("example.com", "_acme-challenge", "v1")
        .await
        .expect("delete v1");
    {
        let st = store.lock().expect("store");
        let values = st.get(&key_of("TXT", "_acme-challenge")).expect("txt");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, "v2");
    }
    p.delete_txt("example.com", "_acme-challenge", "v2")
        .await
        .expect("delete v2");
    assert!(
        !store
            .lock()
            .expect("store")
            .contains_key(&key_of("TXT", "_acme-challenge")),
        "全部移除时应删除整个路径"
    );

    // 删除解析：记录集有其他值时拒绝；单值时删除。
    p.upsert(&rec("example.com", "home", RecordType::A, "203.0.113.2"))
        .await
        .expect("upsert");
    store
        .lock()
        .expect("store")
        .get_mut(&key_of("A", "home"))
        .expect("recordset")
        .push(("9.9.9.9".to_owned(), 3600));
    let err = delete_records(
        &p,
        &rec("example.com", "home", RecordType::A, "203.0.113.2"),
    )
    .await
    .expect_err("recordset has other values");
    assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
    store
        .lock()
        .expect("store")
        .get_mut(&key_of("A", "home"))
        .expect("recordset")
        .retain(|(data, _)| data == "203.0.113.2");
    let n = delete_records(
        &p,
        &rec("example.com", "home", RecordType::A, "203.0.113.2"),
    )
    .await
    .expect("delete");
    assert_eq!(n, 1);
    assert!(
        !store
            .lock()
            .expect("store")
            .contains_key(&key_of("A", "home")),
        "单值记录集应整体删除"
    );
}

/// 指定 TTL 时未变化判定与更新；401 认证失败归类。
#[tokio::test]
async fn godaddy_ttl_handling_and_errors() {
    let store = Arc::new(Mutex::new(Store::new()));
    let srv = FakeServer::start(godaddy_fake(store.clone())).await;
    let p =
        GoDaddy::with_endpoint(creds("gdkey", "gdsecret"), http(), &srv.url()).expect("provider");
    let mut r = rec("example.com", "www", RecordType::AAAA, "2001:db8::1");
    r.ttl = 1800;
    assert_eq!(p.upsert(&r).await.expect("create"), UpsertAction::Created);
    assert_eq!(
        p.upsert(&r).await.expect("unchanged"),
        UpsertAction::Unchanged
    );
    {
        let st = store.lock().expect("store");
        assert_eq!(st.get(&key_of("AAAA", "www")).expect("set")[0].1, 1800);
    }
    r.ttl = 120;
    assert_eq!(p.upsert(&r).await.expect("low ttl"), UpsertAction::Updated);
    assert_eq!(
        store
            .lock()
            .expect("store")
            .get(&key_of("AAAA", "www"))
            .expect("set")[0]
            .1,
        600,
        "低于下限的 TTL 取 600"
    );

    // 认证失败：401。
    let err_srv = FakeServer::start(|_| {
        FakeResponse::json(401, r#"{"code":"UNAUTHORIZED","message":"bad key"}"#)
    })
    .await;
    let bad = GoDaddy::with_endpoint(creds("k", "x"), http(), &err_srv.url()).expect("provider");
    let err = bad
        .upsert(&rec("example.com", "home", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("unauthorized");
    assert_eq!(err.kind, ProviderErrorKind::Auth);

    // 缺少凭据构造失败。
    assert!(GoDaddy::new(creds("", "s"), http()).is_err());
    assert!(GoDaddy::new(creds("k", ""), http()).is_err());
}
