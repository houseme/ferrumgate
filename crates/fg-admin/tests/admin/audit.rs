use fg_admin::AuditLog;
use fg_auth::{AccountManager, token::TokenManager};

use super::*;

const JSON: (&str, &str) = ("content-type", "application/json");
const PASSWORD: &str = "fixture-password";

fn prepare_accounts(store: Arc<ConfigStore>, readonly: bool) -> Result<Arc<AccountManager>> {
    let mut account = json!({
        "username":"operator",
        "passwordHash":bcrypt::hash(PASSWORD, 4)?,
        "sessionSecret":"fixture-session-secret-for-tests-only",
    });
    if readonly {
        account["users"] = json!([{
            "username":"viewer",
            "passwordHash":bcrypt::hash("fixture-viewer-password", 4)?,
            "role":"readonly"
        }]);
    }
    store.save("account", &account)?;
    let (accounts, _) = AccountManager::open(store.clone(), None)?;
    Ok(Arc::new(accounts))
}

fn credentials(username: &str, password: &str) -> String {
    json!({"username": username, "password": password}).to_string()
}

fn session_cookie(headers: &HeaderMap) -> Result<String> {
    let cookie = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|cookie| cookie.to_str().ok())
        .find(|cookie| cookie.starts_with("gately_token="))
        .expect("session cookie");
    Ok(cookie
        .split_once(';')
        .expect("cookie attributes")
        .0
        .to_owned())
}

fn audited_router(
    store: Arc<ConfigStore>,
    accounts: Arc<AccountManager>,
    audit: Arc<AuditLog>,
    tokens: Option<Arc<TokenManager>>,
) -> Result<Router> {
    let registry = Registry::new(&["ddns"]);
    let enabled = registry.resolve_enabled(&[], false);
    let mut router = ApiRouter::default()
        .with_modules(registry, enabled)
        .with_audit(audit);
    if let Some(tokens) = tokens.as_ref() {
        router = router.with_token_authentication(tokens.clone());
    }
    let mut router = router.with_accounts(accounts, "", false)?;
    if let Some(tokens) = tokens {
        router = router.with_token_management(tokens);
    }
    let router = router.route(
        Method::GET,
        "/api/ddns/rules/export",
        "Export rules",
        || async { Json(json!([1, 2, 3])) },
    );
    attach_collection(router, store)
}

#[tokio::test]
async fn audit_records_logins_changes_and_sensitive_reads_without_bodies() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    store.save("ddns", &vec![rule("audited", "audited rule")])?;
    let accounts = prepare_accounts(store.clone(), false)?;
    let audit = AuditLog::open(store.dir())?;
    let server = Server::start(audited_router(
        store.clone(),
        accounts,
        audit.clone(),
        None,
    )?)
    .await?;

    assert_eq!(
        server
            .call(
                "POST",
                "/api/login",
                &[JSON],
                credentials("operator", "wrong-password")
            )
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (_, headers, _) = server
        .call(
            "POST",
            "/api/login",
            &[JSON],
            credentials("operator", PASSWORD),
        )
        .await?;
    let cookie = session_cookie(&headers)?;
    let auth = [("cookie", cookie.as_str())];
    let edit = [JSON, auth[0]];

    // A plain read is not audited.
    assert_eq!(
        server
            .call("GET", "/api/ddns/rules", &auth, Body::empty())
            .await?
            .0,
        StatusCode::OK
    );
    // A change and a sensitive read are.
    assert_eq!(
        server
            .call(
                "PUT",
                "/api/ddns/rules/audited",
                &edit,
                r#"{"name":"renamed","secret":"fixture-request-secret"}"#
            )
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .call("GET", "/api/ddns/rules/export", &auth, Body::empty())
            .await?
            .0,
        StatusCode::OK
    );
    audit.flush();

    // No request bodies, credentials or secrets reach the audit file.
    let log = fs::read_to_string(store.dir().join("audit.log"))?;
    for forbidden in ["wrong-password", PASSWORD, "fixture-request-secret"] {
        assert!(!log.contains(forbidden), "audit leaked {forbidden}");
    }
    assert!(log.contains("\"actor\":\"operator\""));

    let (_, headers, logins) = server
        .call("GET", "/api/audit?category=login", &auth, Body::empty())
        .await?;
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(logins["total"], 2);
    let entries = logins["entries"].as_array().unwrap();
    assert_eq!(entries[0]["status"], 200, "newest entry is the success");
    assert_eq!(entries[0]["detail"], Value::Null);
    assert_eq!(entries[1]["status"], 401);
    assert_eq!(entries[1]["detail"], "login.invalid-credentials");
    for entry in entries {
        assert_eq!(entry["actor"], "operator");
        assert_eq!(entry["category"], "login");
        assert!(entry["path"].as_str().unwrap().starts_with("/api/login"));
    }

    let (_, _, changes) = server
        .call("GET", "/api/audit?category=change", &auth, Body::empty())
        .await?;
    assert_eq!(changes["total"], 1);
    let change = &changes["entries"][0];
    assert_eq!(change["path"], "/api/ddns/rules/audited");
    assert_eq!(change["method"], "PUT");
    assert_eq!(change["module"], "ddns");
    assert_eq!(change["status"], 200);

    let (_, _, access) = server
        .call("GET", "/api/audit?category=access", &auth, Body::empty())
        .await?;
    assert_eq!(access["total"], 1);
    assert_eq!(access["entries"][0]["path"], "/api/ddns/rules/export");

    let (_, _, missing) = server
        .call("GET", "/api/audit?q=nothing-matches", &auth, Body::empty())
        .await?;
    assert_eq!(missing["total"], 0);
    assert_eq!(missing["entries"].as_array().unwrap().len(), 0);
    for query in ["category=bogus", "limit=1001", "from=2026"] {
        assert_eq!(
            server
                .call("GET", &format!("/api/audit?{query}"), &auth, Body::empty())
                .await?
                .0,
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn audit_names_tokens_and_denies_non_administrative_readers() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    store.save("ddns", &vec![rule("audited", "audited rule")])?;
    let accounts = prepare_accounts(store.clone(), true)?;
    let tokens = Arc::new(TokenManager::open(
        store.clone(),
        [],
        std::time::Instant::now(),
    )?);
    let audit = AuditLog::open(store.dir())?;
    let server = Server::start(audited_router(
        store.clone(),
        accounts.clone(),
        audit.clone(),
        Some(tokens),
    )?)
    .await?;
    let admin = accounts
        .login("operator", PASSWORD)?
        .expect("administrator session");
    let viewer = accounts
        .login("viewer", "fixture-viewer-password")?
        .expect("read-only session");
    let admin_cookie = format!("gately_token={}", admin.token);
    let viewer_cookie = format!("gately_token={}", viewer.token);
    let admin_auth = [("cookie", admin_cookie.as_str())];

    assert_eq!(
        server
            .call("GET", "/api/audit", &[], Body::empty())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .call(
                "GET",
                "/api/audit",
                &[("cookie", viewer_cookie.as_str())],
                Body::empty()
            )
            .await?
            .0,
        StatusCode::FORBIDDEN
    );

    let (status, _, issued) = server
        .call(
            "POST",
            "/api/tokens",
            &[JSON, admin_auth[0]],
            r#"{"name":"ops","scopes":["ddns:write"]}"#,
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "create the API token");
    let secret = issued["secret"].as_str().expect("token secret").to_owned();
    let bearer = format!("Bearer {secret}");
    let token_auth = [("authorization", bearer.as_str())];
    assert_eq!(
        server
            .call(
                "PUT",
                "/api/ddns/rules/audited",
                &[JSON, token_auth[0]],
                r#"{"name":"token-edit"}"#
            )
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .call("GET", "/api/audit", &token_auth, Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    audit.flush();
    let log = fs::read_to_string(store.dir().join("audit.log"))?;
    assert!(log.contains("\"actor\":\"api-token:ops\""), "token actor");

    let (_, _, matched) = server
        .call(
            "GET",
            "/api/audit?q=api-token:ops",
            &admin_auth,
            Body::empty(),
        )
        .await?;
    assert_eq!(matched["total"], 1);
    assert_eq!(matched["entries"][0]["actor"], "api-token:ops");
    assert_eq!(matched["entries"][0]["path"], "/api/ddns/rules/audited");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn audit_write_failures_never_fail_the_audited_request() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    store.save("ddns", &vec![rule("audited", "audited rule")])?;
    let accounts = prepare_accounts(store.clone(), false)?;
    let audit_dir = dir.path().join("audit-home");
    // A tiny cap forces rotation against the frozen directory later.
    let audit = AuditLog::open_with(&audit_dir, 200)?;
    let server = Server::start(audited_router(
        store.clone(),
        accounts.clone(),
        audit.clone(),
        None,
    )?)
    .await?;
    let session = accounts
        .login("operator", PASSWORD)?
        .expect("administrator session");
    let cookie = format!("gately_token={}", session.token);
    let auth = [("cookie", cookie.as_str())];
    let edit = [JSON, auth[0]];
    assert_eq!(
        server
            .call(
                "PUT",
                "/api/ddns/rules/audited",
                &edit,
                r#"{"name":"first"}"#
            )
            .await?
            .0,
        StatusCode::OK
    );
    audit.flush();
    assert_eq!(audit.failed(), 0);

    let permissions = fs::metadata(&audit_dir)?.permissions();
    fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o500))?;
    assert_eq!(
        server
            .call(
                "PUT",
                "/api/ddns/rules/audited",
                &edit,
                r#"{"name":"second"}"#
            )
            .await?
            .0,
        StatusCode::OK
    );
    audit.flush();
    assert!(audit.failed() >= 1, "the audit file is unwritable");
    fs::set_permissions(&audit_dir, permissions)?;
    let Loaded::Found(rows) = store.load::<Vec<Rule>>("ddns")? else {
        panic!("persisted collection")
    };
    assert_eq!(
        rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
        ["second"]
    );
    Ok(())
}
