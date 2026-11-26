use anyhow::Context;
use fg_auth::{AccountManager, LoginLimits};

use super::*;

const JSON: (&str, &str) = ("content-type", "application/json");

fn cookie_header(headers: &HeaderMap) -> Result<&str> {
    Ok(headers
        .get("set-cookie")
        .context("session cookie")?
        .to_str()?)
}

fn cookie_pair(cookie: &str) -> &str {
    cookie.split_once(';').unwrap().0
}

fn credentials(username: &str, password: &str) -> String {
    json!({"username": username, "password": password}).to_string()
}

#[tokio::test]
async fn login_initial_password_flow_uses_scoped_secure_cookies() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let (accounts, initial) = AccountManager::open(store, None)?;
    let initial = initial.context("initial administrator password")?;
    let registry = Registry::new(&["ddns", "portforward"]);
    let enabled = registry.resolve_enabled(&["portforward".into()], false);
    let admin = ApiRouter::new(|headers| {
        (headers.get("authorization")?.to_str().ok()? == "Bearer fixture-token").then_some(
            Principal::Token {
                scopes: vec!["ddns:read".into()],
            },
        )
    })
    .with_modules(registry, enabled)
    .with_accounts(Arc::new(accounts), "/gateway/manage/", true)?
    .route(
        Method::POST,
        "/api/ddns/fixture",
        "Protected fixture write",
        || async { Json(json!({"saved": true})) },
    )
    .finish();
    assert!(admin.document()["paths"]["/api/login"].is_null());
    let session_doc = &admin.document()["paths"]["/api/session"]["get"];
    assert_eq!(session_doc["x-token-allowed"], true);
    let revoke_doc = &admin.document()["paths"]["/api/account/sessions/revoke"]["post"];
    assert_eq!(revoke_doc["x-token-allowed"], false);
    assert_eq!(
        admin.document()["components"]["securitySchemes"]["sessionCookie"]["name"],
        "gately_token"
    );

    let server = Server::start(admin.router).await?;
    assert_eq!(
        server
            .call("GET", "/api/session", &[], Body::empty())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let login = credentials("admin", &initial);
    assert_eq!(
        server
            .call(
                "POST",
                "/api/login",
                &[JSON, ("origin", "https://other.test")],
                login.clone()
            )
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, headers, body) = server
        .call(
            "POST",
            "/api/login",
            &[JSON, ("x-forwarded-proto", "http")],
            login,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "admin");
    assert!(body["expires"].as_str().context("expiry")?.ends_with('Z'));
    assert!(body.get("token").is_none());
    assert_eq!(headers["cache-control"], "no-store");
    let session = cookie_header(&headers)?;
    assert!(session.contains("; Path=/gateway/manage/; HttpOnly; SameSite=Strict; Secure"));
    assert!(session.contains("; Max-Age="));
    let pair = cookie_pair(session);
    let auth = [("cookie", pair)];
    let (status, _, details) = server
        .call("GET", "/api/session", &auth, Body::empty())
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(details["role"], "admin");
    assert_eq!(details["passwordIssue"], "default");
    assert_eq!(details["defaultPassword"], true);
    assert_eq!(details["disabledModules"], json!(["portforward"]));
    assert!(
        details["absentModules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "ssl")
    );
    assert_eq!(
        server
            .call(
                "GET",
                "/api/session",
                &[("cookie", &format!("{pair}; {pair}"))],
                Body::empty()
            )
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let bearer = format!("Bearer {}", pair.split_once('=').unwrap().1);
    assert_eq!(
        server
            .call(
                "GET",
                "/api/session",
                &[("authorization", &bearer)],
                Body::empty()
            )
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .call("POST", "/api/ddns/fixture", &auth, Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    let token = [("authorization", "Bearer fixture-token")];
    assert_eq!(
        server
            .call("GET", "/api/session", &token, Body::empty())
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .call(
                "POST",
                "/api/account/sessions/revoke",
                &token,
                Body::empty()
            )
            .await?
            .0,
        StatusCode::FORBIDDEN
    );

    let (_, _, feedback) = server
        .call(
            "POST",
            "/api/account/password-check",
            &[JSON, auth[0]],
            r#"{"password":"Password2024!"}"#,
        )
        .await?;
    assert_eq!(feedback, json!({"ok":false, "code":"common"}));
    let next_password = "Cd7$mh3=YW";
    let change =
        json!({"username":"admin", "oldPassword":initial, "newPassword":next_password}).to_string();
    let account_file = dir.path().join("account.json");
    let backup = dir.path().join("account-fixture-backup");
    fs::rename(&account_file, &backup)?;
    fs::create_dir(&account_file)?;
    let (status, headers, body) = server
        .call("PUT", "/api/account", &[JSON, auth[0]], change.clone())
        .await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(headers.get("set-cookie").is_none());
    assert_eq!(body, json!({"error":"configuration operation failed"}));
    assert_eq!(
        server
            .call("GET", "/api/session", &auth, Body::empty())
            .await?
            .0,
        StatusCode::OK
    );
    fs::remove_dir(&account_file)?;
    fs::rename(&backup, &account_file)?;
    let (status, headers, _) = server
        .call("PUT", "/api/account", &[JSON, auth[0]], change)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        cookie_header(&headers)?
            .contains("; Max-Age=0; Path=/gateway/manage/; HttpOnly; SameSite=Strict; Secure")
    );
    assert_eq!(
        server
            .call("GET", "/api/session", &auth, Body::empty())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, headers, _) = server
        .call(
            "POST",
            "/api/login",
            &[JSON],
            credentials("admin", next_password),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let auth = [("cookie", cookie_pair(cookie_header(&headers)?))];
    let (_, _, details) = server
        .call("GET", "/api/session", &auth, Body::empty())
        .await?;
    assert_eq!(details["passwordIssue"], "");
    assert_eq!(
        server
            .call("POST", "/api/ddns/fixture", &auth, Body::empty())
            .await?
            .2,
        json!({"saved": true})
    );
    Ok(())
}

#[tokio::test]
async fn login_http_limits_use_the_peer_and_logout_revokes_live_sessions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let password = "zPw9xK!m7Zr3";
    let (accounts, _) = AccountManager::open(store, Some(password))?;
    accounts.configure_login_limits(LoginLimits {
        max_failures: 2,
        ..LoginLimits::default()
    })?;
    let accounts = Arc::new(accounts);
    assert!(
        ApiRouter::default()
            .with_accounts(accounts.clone(), "/x; Secure", false)
            .is_err()
    );
    let server = Server::start(
        ApiRouter::default()
            .with_accounts(accounts, "", false)?
            .finish()
            .router,
    )
    .await?;
    let mut sessions = Vec::new();
    for _ in 0..3 {
        let (status, headers, _) = server
            .call(
                "POST",
                "/api/login",
                &[JSON, ("x-forwarded-proto", "https")],
                credentials("admin", password),
            )
            .await?;
        assert_eq!(status, StatusCode::OK);
        let cookie = cookie_header(&headers)?;
        assert!(cookie.contains("; Path=/; HttpOnly; SameSite=Strict"));
        assert!(!cookie.contains("; Secure"));
        sessions.push(cookie_pair(cookie).to_owned());
    }
    let mut first_failure = None;
    for (username, header) in [("admin", "192.0.2.1"), ("other", "198.51.100.1")] {
        let (status, headers, body) = server
            .call(
                "POST",
                "/api/login",
                &[JSON, ("x-forwarded-for", header)],
                credentials(username, "wrong"),
            )
            .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.get("set-cookie").is_none());
        if let Some(first) = &first_failure {
            assert_eq!(first, &body);
        }
        first_failure = Some(body);
    }
    let (status, headers, _) = server
        .call(
            "POST",
            "/api/login",
            &[JSON],
            credentials("admin", password),
        )
        .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers["retry-after"].to_str()?.parse::<u64>()? > 0);
    let (status, headers, _) = server
        .call(
            "POST",
            "/api/logout",
            &[("cookie", &sessions[0])],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(cookie_header(&headers)?.contains("; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"));
    assert_eq!(
        server
            .call(
                "GET",
                "/api/session",
                &[("cookie", &sessions[0])],
                Body::empty()
            )
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .call(
                "GET",
                "/api/session",
                &[("cookie", &sessions[1])],
                Body::empty()
            )
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .call(
                "POST",
                "/api/account/sessions/revoke",
                &[("cookie", &sessions[1])],
                Body::empty()
            )
            .await?
            .0,
        StatusCode::OK
    );
    for cookie in &sessions[1..] {
        assert_eq!(
            server
                .call("GET", "/api/session", &[("cookie", cookie)], Body::empty())
                .await?
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}
