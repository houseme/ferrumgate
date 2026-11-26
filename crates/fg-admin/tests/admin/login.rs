use anyhow::Context;
use data_encoding::BASE32_NOPAD;
use fg_auth::{AccountManager, LoginLimits};
use ring::hmac;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

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
async fn login_passkey_http_uses_existing_session_and_cookie_boundaries() -> Result<()> {
    use fg_auth::passkey::{CreationChallengeResponse, RequestChallengeResponse, Url};

    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let password = "fixture-administrator-password";
    store.save(
        "account",
        &json!({
            "username":"operator",
            "passwordHash":bcrypt::hash(password, 4)?,
            "sessionSecret":"fixture-session-secret-for-tests-only",
        }),
    )?;
    let (accounts, _) = AccountManager::open(store, None)?;
    let origin = Url::parse("https://admin.test")?;
    let admin = ApiRouter::default()
        .with_passkey_accounts(Arc::new(accounts), "/panel", &origin)?
        .finish();
    assert_eq!(
        admin.document()["paths"]["/api/account/passkeys"]["post"]["x-token-allowed"],
        false
    );
    assert!(admin.document()["paths"]["/api/login/passkey/begin"].is_null());
    let server = Server::start(admin.router).await?;
    let login = credentials("operator", password);
    let (_, headers, _) = server
        .call("POST", "/api/login", &[JSON], login.clone())
        .await?;
    let first = [("cookie", cookie_pair(cookie_header(&headers)?))];
    let (status, _, options) = server
        .call("POST", "/api/account/passkeys/begin", &first, Body::empty())
        .await?;
    assert_eq!(status, StatusCode::OK);
    let challenge = options["challenge"]
        .as_str()
        .context("enrollment challenge")?
        .to_owned();
    let options: CreationChallengeResponse = serde_json::from_value(json!({"publicKey":options}))?;
    let mut authenticator = SoftPasskey::new(true);
    let proof = authenticator.do_registration(origin.clone(), options)?;
    let body = json!({"challenge":challenge, "password":password, "name":"Existing hardware", "credential":proof});
    let (status, _, passkeys) = server
        .call(
            "POST",
            "/api/account/passkeys",
            &[JSON, first[0]],
            body.to_string(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let id = passkeys[0]["id"].as_str().context("credential id")?;
    assert_eq!(passkeys[0]["name"], "Existing hardware");
    assert!(passkeys[0]["credential"].is_null());
    let (status, _, _) = server
        .call(
            "PUT",
            "/api/account/password-login",
            &[JSON, first[0]],
            json!({"password":password,"disabled":true}).to_string(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        server.call("POST", "/api/login", &[JSON], login).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, options) = server
        .call("POST", "/api/login/passkey/begin", &[], Body::empty())
        .await?;
    assert_eq!(status, StatusCode::OK);
    let challenge = options["challenge"]
        .as_str()
        .context("assertion challenge")?
        .to_owned();
    let options: RequestChallengeResponse = serde_json::from_value(json!({"publicKey":options}))?;
    let proof = authenticator.do_authentication(origin, options)?;
    let assertion = json!({"challenge":challenge,"credential":proof}).to_string();
    let (status, headers, info) = server
        .call(
            "POST",
            "/api/login/passkey/finish",
            &[JSON],
            assertion.clone(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["username"], "operator");
    let cookie = cookie_header(&headers)?;
    assert!(cookie.contains("Path=/panel/; HttpOnly; SameSite=Strict; Secure"));
    assert_eq!(
        server
            .call("POST", "/api/login/passkey/finish", &[JSON], assertion)
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let auth = [JSON, ("cookie", cookie_pair(cookie))];
    assert_eq!(
        server
            .call("GET", "/api/session", &auth, Body::empty())
            .await?
            .0,
        StatusCode::OK
    );
    let path = format!("/api/account/passkeys/{id}");
    let payload = json!({"password":password}).to_string();
    assert_eq!(
        server
            .call("DELETE", &path, &auth, payload.clone())
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, _, _) = server
        .call(
            "PUT",
            "/api/account/password-login",
            &auth,
            json!({"password":password,"disabled":false}).to_string(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, headers, response) = server.call("DELETE", &path, &auth, payload).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response, json!([]));
    assert!(cookie_header(&headers)?.contains("Max-Age=0"));
    assert_eq!(
        server
            .call("GET", "/api/session", &auth, Body::empty())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
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

#[tokio::test]
async fn login_totp_enrollment_and_disable_revoke_sessions() -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(dir.path())?;
    let password = "zPw9xK!m7Zr3";
    store.save(
        "account",
        &json!({
            "username": "admin",
            "passwordHash": bcrypt::hash(password, 4)?,
            "sessionSecret": "fixture-session-key-for-tests-only",
        }),
    )?;
    let (accounts, _) = AccountManager::open(store, None)?;
    let server = Server::start(
        ApiRouter::default()
            .with_accounts(Arc::new(accounts), "/panel", true)?
            .finish()
            .router,
    )
    .await?;
    let login = credentials("admin", password);
    let mut sessions = Vec::new();
    for _ in 0..2 {
        let (status, headers, _) = server
            .call("POST", "/api/login", &[JSON], login.clone())
            .await?;
        assert_eq!(status, StatusCode::OK);
        sessions.push(cookie_pair(cookie_header(&headers)?).to_owned());
    }
    let auth = [("cookie", sessions[0].as_str())];
    let (_, _, status) = server
        .call("GET", "/api/account/totp", &auth, Body::empty())
        .await?;
    assert_eq!(status, json!({"enabled":false}));
    let (status, headers, setup) = server
        .call("POST", "/api/account/totp/setup", &auth, Body::empty())
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    let secret = setup["secret"].as_str().context("TOTP secret")?;
    let uri = url::Url::parse(setup["url"].as_str().context("provisioning URI")?)?;
    assert_eq!(uri.scheme(), "otpauth");
    assert_eq!(uri.host_str(), Some("totp"));
    assert!(
        uri.query_pairs()
            .any(|(key, value)| key == "secret" && value == secret)
    );
    let key = hmac::Key::new(
        hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        &BASE32_NOPAD.decode(secret.as_bytes())?,
    );
    let code = |step: u64| {
        let digest = hmac::sign(&key, &step.to_be_bytes());
        let bytes = digest.as_ref();
        let offset = usize::from(bytes[19] & 15);
        let value = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        format!("{:06}", value % 1_000_000)
    };
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let until_rollover = Duration::from_secs((elapsed.as_secs() / 30 + 1) * 30) - elapsed;
    if until_rollover < Duration::from_secs(2) {
        tokio::time::sleep(until_rollover + Duration::from_millis(20)).await;
    }
    let step = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
    let proof = |step| json!({"password":password, "code":code(step)}).to_string();
    let enable = "/api/account/totp/enable";
    assert_eq!(
        server
            .call(
                "POST",
                enable,
                &[JSON, ("cookie", &sessions[1])],
                proof(step - 1)
            )
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, headers, _) = server
        .call("POST", enable, &[JSON, auth[0]], proof(step - 1))
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(cookie_header(&headers)?.contains("Max-Age=0; Path=/panel/"));
    for cookie in &sessions {
        assert_eq!(
            server
                .call("GET", "/api/session", &[("cookie", cookie)], Body::empty())
                .await?
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (status, headers, body) = server
        .call("POST", "/api/login", &[JSON], login.clone())
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["totpRequired"], true);
    assert!(headers.get("set-cookie").is_none());
    let (status, _, body) = server
        .call("POST", "/api/login", &[JSON], credentials("admin", "wrong"))
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.get("totpRequired").is_none());
    let with_code =
        |step| json!({"username":"admin", "password":password, "code":code(step)}).to_string();
    assert_eq!(
        server
            .call("POST", "/api/login", &[JSON], with_code(step - 1))
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, headers, _) = server
        .call("POST", "/api/login", &[JSON], with_code(step))
        .await?;
    assert_eq!(status, StatusCode::OK);
    let auth = [("cookie", cookie_pair(cookie_header(&headers)?))];
    let (_, _, details) = server
        .call("GET", "/api/account/totp", &auth, Body::empty())
        .await?;
    assert_eq!(details, json!({"enabled":true}));
    let disable = "/api/account/totp/disable";
    assert_eq!(
        server
            .call("POST", disable, &[JSON, auth[0]], proof(step))
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        server
            .call("POST", disable, &[JSON, auth[0]], proof(step + 1))
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .call("GET", "/api/session", &auth, Body::empty())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server.call("POST", "/api/login", &[JSON], login).await?.0,
        StatusCode::OK
    );
    Ok(())
}
