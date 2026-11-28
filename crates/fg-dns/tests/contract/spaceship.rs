//! Spaceship 契约测试（对照上游 spaceship_test.go 的 TestSpaceshipUpsert、
//! TestSpaceshipPaginationTXTDelete、TestSpaceshipErrors 与
//! TestSpaceshipCNAME）。

mod fake;

use std::sync::Mutex;

use fake::{
    FakeResponse, FakeServer,
    util::{creds, http, rec},
};
use fg_dns::{
    ProviderErrorKind, RecordType, UpsertAction, delete::delete_records,
    providers::spaceship::Spaceship,
};

/// 内存中的记录条目：type, name, address, cname, value, ttl。
#[derive(Clone)]
struct Item {
    typ: String,
    name: String,
    address: String,
    cname: String,
    value: String,
    ttl: u32,
}

impl Item {
    fn new(typ: &str, name: &str, content: &str, ttl: u32) -> Self {
        Self {
            typ: typ.to_owned(),
            name: name.to_owned(),
            address: if typ == "TXT" || typ == "CNAME" {
                String::new()
            } else {
                content.to_owned()
            },
            cname: if typ == "CNAME" {
                content.to_owned()
            } else {
                String::new()
            },
            value: if typ == "TXT" {
                content.to_owned()
            } else {
                String::new()
            },
            ttl,
        }
    }

    fn content(&self) -> String {
        match self.typ.as_str() {
            "TXT" => self.value.clone(),
            "CNAME" => self.cname.clone(),
            _ => self.address.clone(),
        }
    }
}

fn spaceship_fake(
    state: std::sync::Arc<Mutex<Vec<Item>>>,
    page_cap: usize,
) -> impl Fn(&fake::RecordedRequest) -> FakeResponse + Send + Sync + 'static {
    move |req| {
        assert_eq!(req.header("x-api-key"), Some("key"), "认证头");
        assert_eq!(req.header("x-api-secret"), Some("sec"), "认证头");
        assert_eq!(
            req.path, "/api/v1/dns/records/example.com",
            "路径按域名整体操作"
        );
        let mut items = state.lock().expect("items").clone();
        match req.method.as_str() {
            "GET" => {
                let take: usize = req
                    .query_param("take")
                    .and_then(|v| v.parse().ok())
                    .expect("take");
                assert!((1..=500).contains(&take), "take 越界: {take}");
                let skip: usize = req
                    .query_param("skip")
                    .and_then(|v| v.parse().ok())
                    .expect("skip");
                let take = take.min(page_cap.max(1));
                let start = skip.min(items.len());
                let end = (start + take).min(items.len());
                let slice: Vec<serde_json::Value> = items[start..end]
                    .iter()
                    .map(|it| {
                        let mut v =
                            serde_json::json!({"type": it.typ, "name": it.name, "ttl": it.ttl});
                        if !it.address.is_empty() {
                            v["address"] = serde_json::json!(it.address);
                        }
                        if !it.cname.is_empty() {
                            v["cname"] = serde_json::json!(it.cname);
                        }
                        if !it.value.is_empty() {
                            v["value"] = serde_json::json!(it.value);
                        }
                        v
                    })
                    .collect();
                FakeResponse::json(
                    200,
                    serde_json::json!({"items": slice, "total": items.len()}).to_string(),
                )
            }
            "PUT" => {
                let body = req.body_json();
                let force = body.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
                for it in body["items"].as_array().expect("items") {
                    let typ = it["type"].as_str().unwrap_or_default();
                    // A / AAAA 的 PUT 带 force=true，TXT 不带。
                    if typ == "TXT" {
                        assert!(!force, "TXT 的 PUT 不应带 force");
                    } else {
                        assert!(force, "A/AAAA 的 PUT 应带 force=true");
                    }
                    let new_item = Item::new(
                        typ,
                        it["name"].as_str().unwrap_or_default(),
                        it.get("value").and_then(|v| v.as_str()).unwrap_or_else(|| {
                            it.get("cname")
                                .and_then(|v| v.as_str())
                                .unwrap_or_else(|| it["address"].as_str().unwrap_or_default())
                        }),
                        it.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    );
                    // 与上游假服务器一致：同 type+name+content 的条目被替换，
                    // 否则新增。
                    match items.iter().position(|x| {
                        x.typ == new_item.typ
                            && x.name == new_item.name
                            && x.content() == new_item.content()
                    }) {
                        Some(pos) => items[pos] = new_item,
                        None => items.push(new_item),
                    }
                }
                *state.lock().expect("items") = items.clone();
                FakeResponse::json(204, "")
            }
            "DELETE" => {
                for d in req.body_json().as_array().expect("items") {
                    assert!(d.get("ttl").is_none(), "删除请求不应带 ttl: {d}");
                    let typ = d["type"].as_str().unwrap_or_default();
                    let name = d["name"].as_str().unwrap_or_default();
                    let content = d.get("value").and_then(|v| v.as_str()).unwrap_or_else(|| {
                        d.get("cname")
                            .and_then(|v| v.as_str())
                            .unwrap_or_else(|| d["address"].as_str().unwrap_or_default())
                    });
                    if let Some(pos) = items
                        .iter()
                        .position(|it| it.typ == typ && it.name == name && it.content() == content)
                    {
                        items.remove(pos);
                    }
                }
                *state.lock().expect("items") = items.clone();
                FakeResponse::json(204, "")
            }
            other => panic!("意外方法 {other}"),
        }
    }
}

fn endpoint_of(srv: &FakeServer) -> String {
    format!("{}/api/v1", srv.url())
}

#[tokio::test]
async fn spaceship_upsert_request_contract() {
    let state = std::sync::Arc::new(Mutex::new(vec![
        Item::new("A", "other", "9.9.9.9", 3600),
        Item::new("TXT", "home", "keep", 600),
    ]));
    let srv = FakeServer::start(spaceship_fake(state.clone(), 0)).await;
    let p = Spaceship::with_endpoint(creds("key", "sec"), http(), &endpoint_of(&srv))
        .expect("provider");
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
    let items = state.lock().expect("items").clone();
    assert_eq!(items.len(), 3, "其他记录必须保持不变");
    assert_eq!(items[0].address, "9.9.9.9");
    assert_eq!(items[1].value, "keep");
    assert_eq!(items[2].address, "203.0.113.2");
    assert_eq!(items[2].ttl, 600, "未指定 TTL 新建取 600");

    // 根域名用 @；TTL 超出上限取 3600。
    let mut r = rec("example.com", "@", RecordType::AAAA, "2001:db8::1");
    r.ttl = 86_400;
    assert_eq!(
        p.upsert(&r).await.expect("root create"),
        UpsertAction::Created
    );
    let items = state.lock().expect("items");
    let last = items.last().expect("last");
    assert_eq!(last.name, "@");
    assert_eq!(last.ttl, 3600, "TTL 86400 应压到上限 3600");
}

/// 同名同类型多条时收敛为一条；翻页后能找到目标；TXT 按值增删；删除解析。
#[tokio::test]
async fn spaceship_converge_pagination_txt_and_delete() {
    let mut initial = vec![
        Item::new("A", "multi", "1.1.1.1", 600),
        Item::new("A", "multi", "2.2.2.2", 600),
    ];
    for i in 0..5 {
        initial.push(Item::new(
            "A",
            &format!("h{i}"),
            &format!("10.0.0.{i}"),
            600,
        ));
    }
    // 每页最多 2 条，验证翻页。
    let state = std::sync::Arc::new(Mutex::new(initial));
    let srv = FakeServer::start(spaceship_fake(state.clone(), 2)).await;
    let p = Spaceship::with_endpoint(creds("key", "sec"), http(), &endpoint_of(&srv))
        .expect("provider");

    // multi：目标值 2.2.2.2，收敛后只剩一条。
    assert_eq!(
        p.upsert(&rec("example.com", "multi", RecordType::A, "2.2.2.2"))
            .await
            .expect("converge"),
        UpsertAction::Updated
    );
    {
        let items = state.lock().expect("items").clone();
        let multi: Vec<&Item> = items.iter().filter(|it| it.name == "multi").collect();
        assert_eq!(multi.len(), 1, "multi 应只剩一条");
        assert_eq!(multi[0].address, "2.2.2.2", "不应保留旧值");
    }

    // 翻页后 h4 应识别为未变化。
    assert_eq!(
        p.upsert(&rec("example.com", "h4", RecordType::A, "10.0.0.4"))
            .await
            .expect("paged upsert"),
        UpsertAction::Unchanged
    );

    // TXT：多级主机名，PUT 保存 TTL 600；按值删除。
    p.add_txt("example.com", "_acme-challenge.www", "v1")
        .await
        .expect("add v1");
    p.add_txt("example.com", "_acme-challenge.www", "v2")
        .await
        .expect("add v2");
    {
        let items = state.lock().expect("items").clone();
        let last = items.last().expect("last");
        assert_eq!(last.typ, "TXT");
        assert_eq!(last.name, "_acme-challenge.www");
        assert_eq!(last.value, "v2");
        assert_eq!(last.ttl, 600, "TXT 验证记录 TTL 600");
    }
    p.delete_txt("example.com", "_acme-challenge.www", "v1")
        .await
        .expect("delete v1");
    {
        let items = state.lock().expect("items").clone();
        assert!(items.iter().all(|it| it.value != "v1"), "应只删除 v1");
    }

    // 删除解析：按内容删除，不影响其他记录。
    let n = delete_records(&p, &rec("example.com", "h1", RecordType::A, "10.0.0.1"))
        .await
        .expect("delete");
    assert_eq!(n, 1);
    let items = state.lock().expect("items").clone();
    assert!(items.iter().all(|it| it.name != "h1"), "h1 应已删除");
}

/// CNAME 用接口要求的 cname 字段读写，不能写进 address；401 归类认证失败。
#[tokio::test]
async fn spaceship_cname_field_and_errors() {
    let state = std::sync::Arc::new(Mutex::new(vec![Item::new(
        "CNAME",
        "www",
        "old.example.net",
        600,
    )]));
    let last_put = std::sync::Arc::new(Mutex::new(String::new()));
    let last_put_in_handler = last_put.clone();
    let inner = spaceship_fake(state.clone(), 0);
    let srv = FakeServer::start(move |req| {
        if req.method == "PUT" {
            *last_put_in_handler.lock().expect("put") =
                String::from_utf8_lossy(&req.body).into_owned();
        }
        inner(req)
    })
    .await;
    let p = Spaceship::with_endpoint(creds("key", "sec"), http(), &endpoint_of(&srv))
        .expect("provider");
    // 值相同：识别为未变化。
    assert_eq!(
        p.upsert(&rec(
            "example.com",
            "www",
            RecordType::CNAME,
            "old.example.net"
        ))
        .await
        .expect("cname unchanged"),
        UpsertAction::Unchanged
    );
    // 值变化：写入 cname 字段并删除旧值。
    assert_eq!(
        p.upsert(&rec(
            "example.com",
            "www",
            RecordType::CNAME,
            "new.example.net"
        ))
        .await
        .expect("cname update"),
        UpsertAction::Updated
    );
    let put = last_put.lock().expect("put").clone();
    assert!(put.contains(r#""cname":"new.example.net""#), "{put}");
    assert!(!put.contains("address"), "CNAME 不能写进 address: {put}");
    let items = state.lock().expect("items").clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].cname, "new.example.net");

    // 认证失败：401 problem+json。
    let err_srv =
        FakeServer::start(|_| FakeResponse::json(401, r#"{"detail":"Invalid credentials"}"#)).await;
    let bad = Spaceship::with_endpoint(creds("key", "bad"), http(), &endpoint_of(&err_srv))
        .expect("provider");
    let err = bad
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("invalid credentials");
    assert_eq!(err.kind, ProviderErrorKind::Auth);
    assert!(err.detail.contains("Invalid credentials"), "{}", err.detail);

    // 服务端错误。
    let dead = FakeServer::start(|_| FakeResponse::json(500, "boom")).await;
    let p2 = Spaceship::with_endpoint(creds("key", "sec"), http(), &endpoint_of(&dead))
        .expect("provider");
    let err = p2
        .upsert(&rec("example.com", "a", RecordType::A, "1.1.1.1"))
        .await
        .expect_err("server error");
    assert_eq!(err.kind, ProviderErrorKind::Server);
}
