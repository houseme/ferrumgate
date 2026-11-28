//! Token secrecy end to end (WP-46 §6, `TestTunnelSecrets` analog): the
//! list and every read-only view mask the tunnel token and the API token,
//! the secrets endpoint returns the plaintext (404 for unknown keys), and
//! submitting the mask keeps the stored values. The parse-token variants
//! and malformed inputs are covered by the unit tests in `src/token.rs`.

mod common;

use serde_json::json;

use common::{TUNNEL_TOKEN, TUNNEL_TOKEN_NO_SECRET, harness, token_config_json};

#[tokio::test]
async fn list_and_views_mask_tokens_but_secrets_endpoint_returns_plaintext() {
    let app = harness(&token_config_json(TUNNEL_TOKEN, "cf-api")).await;

    let (status, body) = app.send("GET", "/api/cloudflared/tunnels", None).await;
    assert_eq!(status, 200, "{body}");
    let text = body.to_string();
    assert!(
        !text.contains("sec") && !text.contains("cf-api"),
        "令牌与 API 令牌不得出现在列表：{text}"
    );
    assert_eq!(body[0]["token"], "********");
    assert_eq!(body[0]["apiToken"], "********");
    assert_eq!(body[0]["tunnelId"], "tid", "隧道 ID 从令牌解析并返回");
    assert_eq!(body[0]["mode"], "token");

    // 查看明文：真实令牌与 API 令牌。
    let (status, secrets) = app
        .send("GET", "/api/cloudflared/tunnels/k/secrets", None)
        .await;
    assert_eq!(status, 200, "{secrets}");
    assert_eq!(secrets["token"], TUNNEL_TOKEN);
    assert_eq!(secrets["apiToken"], "cf-api");

    // 隧道不存在：404。
    let (status, body) = app
        .send("GET", "/api/cloudflared/tunnels/missing/secrets", None)
        .await;
    assert_eq!(status, 404);
    assert_eq!(body["error"], "item not found");
    app.shutdown().await;
}

#[tokio::test]
async fn update_with_masked_secrets_keeps_stored_values() {
    let app = harness(&token_config_json(TUNNEL_TOKEN, "cf-api")).await;
    // 提交脱敏占位符：沿用原值。
    let (status, saved) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/k",
            Some(json!({
                "key": "k",
                "name": "renamed",
                "mode": "token",
                "token": "********",
                "apiToken": "********",
                "enable": false,
                "remark": ""
            })),
        )
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["token"], "********", "响应仍是脱敏值");
    let stored = app.state.config.read().await.clone();
    assert_eq!(stored.tunnels[0].token, TUNNEL_TOKEN, "占位符沿用原令牌");
    assert_eq!(stored.tunnels[0].api_token.as_deref(), Some("cf-api"));
    assert_eq!(stored.tunnels[0].name, "renamed");
    // 提交新的明文令牌：覆盖。
    let (status, _) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/k",
            Some(json!({
                "key": "k",
                "name": "renamed",
                "mode": "token",
                "token": TUNNEL_TOKEN_NO_SECRET,
                "apiToken": "",
                "enable": false,
                "remark": ""
            })),
        )
        .await;
    assert_eq!(status, 200);
    let stored = app.state.config.read().await.clone();
    assert_eq!(stored.tunnels[0].token, TUNNEL_TOKEN_NO_SECRET);
    assert_eq!(stored.tunnels[0].api_token, None, "空值清空 API 令牌");
    app.shutdown().await;
}

#[tokio::test]
async fn copy_follows_template_secrets_and_gets_fresh_key() {
    let app = harness(&token_config_json(TUNNEL_TOKEN, "cf-api")).await;
    let (status, copied) = app
        .send(
            "POST",
            "/api/cloudflared/tunnels/k/copy",
            Some(json!({
                "key": "ignored",
                "name": "nas copy",
                "mode": "token",
                "token": "********",
                "apiToken": "********",
                "enable": false,
                "remark": ""
            })),
        )
        .await;
    assert_eq!(status, 200, "{copied}");
    let new_key = copied["key"].as_str().expect("fresh key").to_owned();
    assert!(
        new_key != "k" && new_key.len() == 12,
        "复制的条目得到新的随机 key：{new_key}"
    );
    let stored = app.state.config.read().await.clone();
    let copy = stored
        .tunnels
        .iter()
        .find(|tunnel| tunnel.key == new_key)
        .expect("copied tunnel");
    assert_eq!(copy.token, TUNNEL_TOKEN, "占位符沿用模板令牌");
    assert_eq!(copy.api_token.as_deref(), Some("cf-api"));
    assert_eq!(copy.name, "nas copy");
    // 复制的条目插在模板之后。
    assert_eq!(stored.tunnels[0].key, "k");
    assert_eq!(stored.tunnels[1].key, new_key);
    app.shutdown().await;
}

#[tokio::test]
async fn quick_tunnel_clears_tokens_and_rejects_api_token() {
    let app = harness("").await;
    // 临时隧道带残留令牌与 API 令牌：静默清空（上游 Validate 口径）。
    let (status, created) = app
        .send(
            "POST",
            "/api/cloudflared/tunnels",
            Some(json!({
                "name": "quick",
                "mode": "quick",
                "token": "leftover",
                "apiToken": "cf-api",
                "service": " http://localhost:8080 ",
                "enable": false,
                "remark": ""
            })),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["token"], serde_json::Value::Null, "临时隧道无令牌");
    assert_eq!(
        created["apiToken"],
        serde_json::Value::Null,
        "临时隧道无 API 令牌"
    );
    let stored = app.state.config.read().await.clone();
    assert_eq!(stored.tunnels[0].token, "");
    assert_eq!(stored.tunnels[0].api_token, None);
    assert_eq!(
        stored.tunnels[0].quick_url.as_deref(),
        Some("http://localhost:8080")
    );
    // 本地服务地址格式不正确：400 + problems。
    let (status, body) = app
        .send(
            "POST",
            "/api/cloudflared/tunnels",
            Some(json!({
                "name": "quick2",
                "mode": "quick",
                "service": "ftp://x",
                "enable": false,
                "remark": ""
            })),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    let problems = body["problems"].as_array().expect("problems");
    assert!(
        problems
            .iter()
            .any(|problem| problem["field"].as_str().unwrap().contains("quickUrl")),
        "{problems:?}"
    );
    app.shutdown().await;
}
