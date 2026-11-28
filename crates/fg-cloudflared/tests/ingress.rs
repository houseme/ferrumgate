//! Ingress route tests (WP-46 §6): reading the remote rules, saving with
//! the version check and preserved remote fields, the guards (missing
//! rules field, local-managed source, missing API token, wrong tunnel
//! kind) and the DNS sync results.

mod common;

use serde_json::json;

use common::{FakeCf, TUNNEL_TOKEN, deps_with_cf, token_config_json};

/// A tunnel `k` (token + API token) plus a quick tunnel, wired to a fake
/// Cloudflare API server that starts at version 3.
async fn harness(cf: &FakeCf) -> common::Harness {
    let config = token_config_json(TUNNEL_TOKEN, "cf-api");
    common::harness_with_deps(&config, deps_with_cf(cf)).await
}

fn remote_config() -> serde_json::Value {
    json!({
        "ingress": [
            {"hostname": "old.example.com", "service": "http://localhost:80",
             "originRequest": {"noTLSVerify": true}},
            {"service": "http_status:404", "originRequest": {"connectTimeout": 10}}
        ],
        "warp-routing": {"enabled": true}
    })
}

#[tokio::test]
async fn ingress_read_returns_rules_catch_all_and_version() {
    let cf = FakeCf::start(remote_config()).await;
    let app = harness(&cf).await;
    let (status, view) = app
        .send("GET", "/api/cloudflared/tunnels/k/ingress", None)
        .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["tunnelId"], "tid");
    assert_eq!(view["version"], 3);
    assert_eq!(view["source"], "cloudflare");
    assert_eq!(view["rules"].as_array().expect("rules").len(), 1);
    assert_eq!(view["rules"][0]["hostname"], "old.example.com");
    assert_eq!(
        view["rules"][0]["originRequest"],
        json!({"noTLSVerify": true}),
        "回源设置原样返回"
    );
    assert_eq!(view["catchAll"], "http_status:404");
    cf.stop().await;
    app.shutdown().await;
}

#[tokio::test]
async fn ingress_read_on_fresh_tunnel_returns_empty_rules_and_default_catch_all() {
    let cf = FakeCf::start(json!(null)).await;
    let app = harness(&cf).await;
    let (status, view) = app
        .send("GET", "/api/cloudflared/tunnels/k/ingress", None)
        .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["rules"], json!([]), "新建隧道返回空规则数组");
    assert_eq!(view["catchAll"], "http_status:404");
    cf.stop().await;
    app.shutdown().await;
}

#[tokio::test]
async fn ingress_save_keeps_other_remote_fields_and_normalizes() {
    let cf = FakeCf::start(remote_config()).await;
    cf.set_records(vec![json!({
        "type": "CNAME", "name": "old.example.com",
        "content": "tid.cfargotunnel.com", "proxied": true
    })]);
    let app = harness(&cf).await;
    let (status, saved) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/k/ingress",
            Some(json!({
                "version": 3,
                "rules": [
                    {"hostname": "Old.Example.com", "service": "http://localhost:80"},
                    {"hostname": "New.Example.com", "service": "ssh://localhost:22"},
                    {"hostname": "new.example.com", "path": "^/a", "service": "http://localhost:83/"}
                ],
                "catchAll": "http_status:503",
                "syncDns": true
            })),
        )
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["version"], 4);
    let rules = saved["rules"].as_array().expect("rules");
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0]["hostname"], "old.example.com", "主机名规范化");
    assert_eq!(rules[2]["service"], "http://localhost:83", "末尾斜杠去掉");
    assert_eq!(saved["catchAll"], "http_status:503");

    // 远程配置里 ingress 以外的字段保留；兜底规则的回源设置沿用旧值。
    let stored = cf.config();
    assert_eq!(stored["warp-routing"], json!({"enabled": true}));
    let ingress = stored["ingress"].as_array().expect("ingress");
    let last = ingress.last().expect("catch-all");
    assert_eq!(last["service"], "http_status:503");
    assert_eq!(
        last["originRequest"],
        json!({"connectTimeout": 10}),
        "兜底回源设置沿用旧值"
    );
    assert!(last.get("hostname").is_none(), "兜底规则不带主机名");

    // DNS 同步：old 未变、new 新建（同名去重后两条规则一个主机名只查一次）。
    let dns = saved["dns"].as_array().expect("dns");
    let status_of = |hostname: &str| {
        dns.iter()
            .find(|result| result["hostname"] == hostname)
            .map(|result| result["status"].clone())
            .expect("result")
    };
    assert_eq!(status_of("old.example.com"), "unchanged");
    assert_eq!(status_of("new.example.com"), "created");
    let created = cf.records().last().expect("created record").clone();
    assert_eq!(created["type"], "CNAME");
    assert_eq!(created["content"], "tid.cfargotunnel.com");
    assert_eq!(created["proxied"], true);
    cf.stop().await;
    app.shutdown().await;
}

#[tokio::test]
async fn ingress_save_detects_concurrent_modification() {
    // 版本不一致时返回冲突，不写入。
    let cf = FakeCf::start(remote_config()).await;
    let app = harness(&cf).await;
    // 先读到当前版本 3，然后假服务器上的配置被别处修改。
    let (_, view) = app
        .send("GET", "/api/cloudflared/tunnels/k/ingress", None)
        .await;
    assert_eq!(view["version"], 3);
    cf.bump_version();
    let (status, body) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/k/ingress",
            Some(json!({
                "version": 3,
                "rules": [{"hostname": "a.example.com", "service": "http://localhost:80"}]
            })),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    assert!(body["error"].as_str().unwrap().contains("其他地方修改"));
    assert_eq!(cf.puts(), 0, "冲突时不写入");
    assert_eq!(cf.version(), 4, "版本未被覆盖");
    cf.stop().await;
    app.shutdown().await;
}

#[tokio::test]
async fn ingress_save_requires_rules_field_and_validates_before_saving() {
    let cf = FakeCf::start(remote_config()).await;
    let app = harness(&cf).await;
    // 缺少 rules 字段：拒绝，不清空规则。
    let (status, body) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/k/ingress",
            Some(json!({"version": 3, "catchAll": "http_status:503"})),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().unwrap().contains("rules"));
    assert_eq!(cf.puts(), 0);

    // 规则无效：400，且不访问 Cloudflare。
    let (status, body) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/k/ingress",
            Some(json!({
                "version": 3,
                "rules": [{"service": "http://a:1"}]
            })),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(cf.puts(), 0, "无效规则不访问 Cloudflare");
    assert!(body["error"].as_str().unwrap().contains("主机名"), "{body}");
    cf.stop().await;
    app.shutdown().await;
}

#[tokio::test]
async fn ingress_local_source_requires_force() {
    // 本地配置文件管理的隧道：不带 force 拒绝写入，带 force 成功。
    let cf = FakeCf::start_with(remote_config(), "local", "cf-api").await;
    let app = harness(&cf).await;
    let (status, body) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/k/ingress",
            Some(json!({
                "version": 3,
                "rules": [{"hostname": "b.example.com", "service": "http://localhost:81"}]
            })),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    assert!(body["error"].as_str().unwrap().contains("本地配置文件"));
    assert_eq!(cf.puts(), 0, "不带 force 不写入");

    let (status, saved) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/k/ingress",
            Some(json!({
                "version": 3,
                "rules": [{"hostname": "b.example.com", "service": "http://localhost:81"}],
                "force": true
            })),
        )
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(cf.puts(), 1);
    // 读取接口返回来源供界面判断。
    let (_, view) = app
        .send("GET", "/api/cloudflared/tunnels/k/ingress", None)
        .await;
    assert_eq!(view["source"], "local", "GET 显示来源");
    cf.stop().await;
    app.shutdown().await;
}

#[tokio::test]
async fn ingress_guards_missing_tunnel_and_missing_api_token_and_quick_kind() {
    let cf = FakeCf::start(json!({})).await;
    let config = format!(
        r#"{{"settings":{{"binPath":""}},"install":{{"proxy":""}},"tunnels":[
            {{"key":"noapi","name":"b","group":"","enable":false,"mode":"token","token":"{}","remark":""}},
            {{"key":"badapi","name":"c","group":"","enable":false,"mode":"token","token":"{}","apiToken":"wrong","remark":""}},
            {{"key":"quick","name":"q","group":"","enable":false,"mode":"quick","token":"","service":"http://localhost:1","remark":""}}
        ]}}"#,
        TUNNEL_TOKEN, TUNNEL_TOKEN
    );
    let app = common::harness_with_deps(&config, deps_with_cf(&cf)).await;
    let cases = [("missing", 404u16), ("noapi", 400), ("quick", 400)];
    for (key, want) in cases {
        let (status, body) = app
            .send(
                "GET",
                &format!("/api/cloudflared/tunnels/{key}/ingress"),
                None,
            )
            .await;
        assert_eq!(status, want, "{key}: {body}");
    }
    // API 令牌错误时返回 Cloudflare 的错误信息（认证失败，502）。
    let (status, body) = app
        .send("GET", "/api/cloudflared/tunnels/badapi/ingress", None)
        .await;
    assert_eq!(status, 502, "{body}");
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("Authentication error"),
        "{body}"
    );
    cf.stop().await;
    app.shutdown().await;
}
