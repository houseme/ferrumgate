use anyhow::Context;
use fg_auth::{
    AccountManager,
    token::{TokenError, TokenManager},
};

use super::*;

const JSON_HEADER: (&str, &str) = ("content-type", "application/json");

#[tokio::test]
async fn token_management_routes_preserve_scope_and_secret_boundaries() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let password = "fixture-administrator-password";
    let viewer = "fixture-viewer-password";
    store.save("account", &json!({
        "username":"operator", "passwordHash":bcrypt::hash(password, 4)?,
        "sessionSecret":"fixture-session-key-for-tests-only",
        "users":[{"username":"viewer","passwordHash":bcrypt::hash(viewer, 4)?,"role":"readonly"}],
    }))?;
    let (accounts, _) = AccountManager::open(store.clone(), None)?;
    let accounts = Arc::new(accounts);
    let tokens = Arc::new(TokenManager::open(store, [], std::time::Instant::now())?);
    let registry = Registry::new(&["webservice", "portforward"]);
    let enabled = registry.resolve_enabled(&["portforward".into()], false);
    let admin = ApiRouter::new(|headers| {
        (headers.get("authorization")?.to_str().ok()? == "Bearer fixture-token").then(|| {
            Principal::Token {
                scopes: vec!["*".into()],
            }
        })
    })
    .with_modules(registry, enabled)
    .with_accounts(accounts.clone(), "", false)?
    .with_token_management(tokens.clone())
    .finish();
    let operations: Vec<_> = admin.document()["paths"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(path, _)| path.starts_with("/api/tokens"))
        .flat_map(|(_, methods)| methods.as_object().unwrap().values())
        .collect();
    assert_eq!(operations.len(), 8);
    assert!(operations.iter().all(|operation| {
        operation["x-token-allowed"] == false && operation["x-required-scope"] == "!denied"
    }));
    let server = Server::start(admin.router).await?;
    let issued = accounts
        .login("operator", password)?
        .context("administrator session")?;
    let readonly = accounts
        .login("viewer", viewer)?
        .context("read-only session")?;
    let admin_cookie = format!("gately_token={}", issued.token);
    let viewer_cookie = format!("gately_token={}", readonly.token);
    let auth = [("cookie", admin_cookie.as_str())];
    let edit = [JSON_HEADER, auth[0]];
    let path = "/api/tokens";
    let viewer_auth = [("cookie", viewer_cookie.as_str())];
    let token_auth = [("authorization", "Bearer fixture-token")];
    assert_eq!(
        server.call("GET", path, &[], Body::empty()).await?.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .call("GET", path, &viewer_auth, Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call("GET", path, &token_auth, Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call(
                "POST",
                path,
                &[JSON_HEADER, token_auth[0]],
                r#"{"name":"x","scopes":["*"]}"#
            )
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, _, domains) = server
        .call("GET", "/api/tokens/scopes", &auth, Body::empty())
        .await?;
    assert_eq!(status, StatusCode::OK);
    let domains = domains.as_array().unwrap();
    assert!(
        domains
            .iter()
            .any(|domain| domain["id"] == "webservice" && domain["canFiles"] == true)
    );
    assert!(domains.iter().any(|domain| domain["id"] == "portforward"));
    assert!(
        domains
            .iter()
            .any(|domain| domain["id"] == "logs" && domain["builtin"] == true)
    );
    assert!(!domains.iter().any(|domain| domain["id"] == "ddns"));

    assert_eq!(
        server
            .call(
                "POST",
                path,
                &edit,
                r#"{"name":"invalid","scopes":["ddns:read"]}"#
            )
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let create = |name| json!({"name":name,"scopes":["webservice:read","logs:read"]}).to_string();
    let (status, headers, alpha) = server.call("POST", path, &edit, create("Alpha")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    let alpha_id = alpha["token"]["id"].as_str().unwrap();
    let original = alpha["secret"].as_str().unwrap();
    let (_, _, beta) = server.call("POST", path, &edit, create("Beta")).await?;
    let beta_id = beta["token"]["id"].as_str().unwrap();
    let other = beta["secret"].as_str().unwrap();
    let (_, _, list) = server.call("GET", path, &auth, Body::empty()).await?;
    assert_eq!(list.as_array().unwrap().len(), 2);
    let encoded = list.to_string();
    for forbidden in [original, other, "\"hash\"", "\"secret\""] {
        assert!(!encoded.contains(forbidden));
    }

    let (status, _, _) = server
        .call(
            "PUT",
            "/api/tokens/order",
            &edit,
            json!({"keys":[alpha_id,alpha_id]}).to_string(),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        server
            .call(
                "PUT",
                "/api/tokens/order",
                &edit,
                json!({"keys":[alpha_id,beta_id]}).to_string()
            )
            .await?
            .0,
        StatusCode::OK
    );
    let group = |key| json!({"keys":[alpha_id,key],"group":"jobs"}).to_string();
    assert_eq!(
        server
            .call("PUT", "/api/tokens/group", &edit, group("missing"))
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server.call("GET", path, &auth, Body::empty()).await?.2[0]["group"],
        ""
    );
    assert_eq!(
        server
            .call("PUT", "/api/tokens/group", &edit, group(beta_id))
            .await?
            .0,
        StatusCode::OK
    );
    let list = server.call("GET", path, &auth, Body::empty()).await?.2;
    assert_eq!(list[0]["id"], alpha_id);
    assert_eq!(list[1]["id"], beta_id);
    assert_eq!(list[0]["group"], "jobs");
    assert_eq!(list[1]["group"], "jobs");

    let beta_path = format!("{path}/{beta_id}");
    let update = json!({"name":"Beta paused","scopes":["logs:read"],"disabled":true}).to_string();
    let (status, _, view) = server.call("PUT", &beta_path, &edit, update).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["disabled"], true);
    assert_eq!(view["group"], "jobs");
    assert!(matches!(
        tokens.authenticate(other, time::OffsetDateTime::now_utc(), None),
        Err(TokenError::Disabled)
    ));

    tokens.authenticate(
        original,
        time::OffsetDateTime::now_utc(),
        Some("192.0.2.4".parse()?),
    )?;
    let regenerate = format!("{path}/{alpha_id}/regenerate");
    let (status, headers, rotated) = server
        .call("POST", &regenerate, &auth, Body::empty())
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(rotated["token"]["id"], alpha_id);
    assert_eq!(rotated["token"]["group"], "jobs");
    assert!(rotated["token"]["lastUsedAt"].is_null());
    let fresh = rotated["secret"].as_str().unwrap();
    assert!(matches!(
        tokens.authenticate(original, time::OffsetDateTime::now_utc(), None),
        Err(TokenError::Invalid)
    ));
    assert!(
        tokens
            .authenticate(fresh, time::OffsetDateTime::now_utc(), None)
            .is_ok()
    );
    assert_eq!(
        server
            .call("DELETE", &beta_path, &auth, Body::empty())
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .call("DELETE", &beta_path, &auth, Body::empty())
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    let (_, _, list) = server.call("GET", path, &auth, Body::empty()).await?;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains(fresh));
    Ok(())
}
