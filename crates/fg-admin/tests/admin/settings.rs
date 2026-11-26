use anyhow::Context;
use fg_admin::SettingsState;
use fg_auth::AccountManager;

use super::*;

const PATH: &str = "/api/system/settings";
const SECRETS: &str = "/api/system/settings/secrets";
const REGISTRY: Registry = Registry::new(&["ssl", "webservice"]);

#[tokio::test]
async fn settings_routes_protect_secrets_validate_and_publish_only_saved_settings() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = ConfigStore::open(temp.path())?;
    let password = "fixture-admin-password";
    let viewer = "fixture-viewer-password";
    store.save("account", &json!({
        "username":"operator", "passwordHash":bcrypt::hash(password, 4)?,
        "sessionSecret":"fixture-session-secret-for-tests-only",
        "users":[{"username":"viewer","passwordHash":bcrypt::hash(viewer, 4)?,"role":"readonly"}],
    }))?;
    let (accounts, _) = AccountManager::open(store.clone(), None)?;
    let accounts = Arc::new(accounts);
    let admin = accounts
        .login("operator", password)?
        .context("administrator session")?;
    let readonly = accounts
        .login("viewer", viewer)?
        .context("viewer session")?;
    let admin = format!("gately_token={}", admin.token);
    let readonly = format!("gately_token={}", readonly.token);
    let auth = [("cookie", admin.as_str())];
    let edit = [auth[0], ("content-type", "application/json")];
    let raw_secret = "fixture-client-secret";
    let raw_proxy = "http://fixture-user:fixture-proxy-secret@proxy.test:8080";
    store.save("ferrumgate", &json!({
        "disabledModules":["waf"], "uiLanguage":"en",
        "thirdLogin":{"providers":[{"key":"github","type":"github","clientId":"fixture","clientSecret":raw_secret,"proxy":raw_proxy}]},
    }))?;
    let state = Arc::new(SettingsState::open(store.clone(), REGISTRY)?);
    let mut updates = state.subscribe();
    let providers = state.subscribe_third_login();
    let admin = ApiRouter::new(|headers| {
        (headers.get("authorization")?.to_str().ok()? == "Bearer fixture-token").then(|| {
            Principal::Token {
                scopes: vec!["*".into()],
            }
        })
    })
    .with_accounts(accounts.clone(), "", false)?
    .with_settings(state, accounts)
    .finish();
    let schema = admin.document();
    let operation = &schema["paths"][PATH]["put"];
    assert_eq!(operation["x-token-allowed"], false);
    assert!(
        operation["requestBody"]["content"]["application/json"]["schema"]["properties"]
            .get("listen")
            .is_some()
    );
    let server = Server::start(admin.router).await?;
    for (method, path) in [("GET", PATH), ("PUT", PATH), ("GET", SECRETS)] {
        assert_eq!(
            server.call(method, path, &[], Body::empty()).await?.0,
            StatusCode::UNAUTHORIZED
        );
        for header in [
            ("cookie", readonly.as_str()),
            ("authorization", "Bearer fixture-token"),
        ] {
            assert_eq!(
                server.call(method, path, &[header], Body::empty()).await?.0,
                StatusCode::FORBIDDEN
            );
        }
    }

    let (status, headers, view) = server.call("GET", PATH, &auth, Body::empty()).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(view["listen"], ":16680");
    assert_eq!(view["sessionHours"], 72);
    assert_eq!(view["restartRequired"], false);
    assert_eq!(view["effects"]["listen"], "needsRestart");
    assert_eq!(view["modules"].as_array().unwrap().len(), 2);
    assert_eq!(
        view["thirdLogin"]["providers"][0]["clientSecret"],
        SECRET_MASK
    );
    assert!(!view.to_string().contains(raw_secret));
    assert_eq!(view["thirdLogin"]["providers"][0]["proxy"], SECRET_MASK);
    let (status, headers, secrets) = server.call("GET", SECRETS, &auth, Body::empty()).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(secrets, json!({"github":raw_secret}));

    let before = store.load_raw("ferrumgate")?;
    let mut rebound = view.clone();
    rebound["thirdLogin"]["providers"][0]["clientId"] = json!("replacement-client");
    let (status, _, error) = server.call("PUT", PATH, &edit, rebound.to_string()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["fields"][0]["field"], "thirdLogin.providers");
    assert_eq!(store.load_raw("ferrumgate")?, before);
    assert!(!providers.has_changed()?);

    let mut invalid = view.clone();
    invalid["logLines"] = json!(20_001);
    invalid["disabledModules"] = json!(["ssl"]);
    let (status, _, error) = server.call("PUT", PATH, &edit, invalid.to_string()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["fields"][0]["field"], "logLines");
    assert_eq!(error["fields"][1]["field"], "disabledModules");
    let mut typo = view.clone();
    typo["logLins"] = json!(42);
    assert_eq!(
        server.call("PUT", PATH, &edit, typo.to_string()).await?.0,
        StatusCode::BAD_REQUEST
    );
    let mut bad_hours = view.clone();
    bad_hours["sessionHours"] = json!(8761);
    assert_eq!(
        server
            .call("PUT", PATH, &edit, bad_hours.to_string())
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        server
            .call(
                "PUT",
                PATH,
                &edit,
                r#"{"listen":":16680","listen":":16681"}"#
            )
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut bad_path = view.clone();
    bad_path["logDir"] = json!(temp.path());
    assert_eq!(
        server
            .call("PUT", PATH, &edit, bad_path.to_string())
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(store.load_raw("ferrumgate")?, before);
    assert!(!updates.has_changed()?);

    let log_dir = temp.path().join("logs");
    let mut desired = view;
    desired["logLevel"] = json!(" WARN ");
    desired["listen"] = json!(":16681");
    desired["logDir"] = json!(log_dir);
    desired["apiToken"] = json!("ignored-token");
    desired["uiLanguage"] = json!("fr");
    desired["disabledModules"] = json!([]);
    let (status, _, saved) = server.call("PUT", PATH, &edit, desired.to_string()).await?;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["restartRequired"], true);
    assert_eq!(saved["logLevel"], "warn");
    assert_eq!(saved["uiLanguage"], "en");
    assert_eq!(saved["disabledModules"], json!(["waf"]));
    assert_eq!(
        saved["thirdLogin"]["providers"][0]["clientSecret"],
        SECRET_MASK
    );
    assert!(!saved.to_string().contains(raw_secret));
    assert!(saved.get("apiToken").is_none());
    assert!(log_dir.is_dir());
    assert_eq!(fs::read_dir(&log_dir)?.count(), 0);
    assert!(updates.has_changed()?);
    assert!(!providers.has_changed()?);
    assert_eq!(updates.borrow_and_update().log_level, "warn");
    let Loaded::Found(persisted) = store.load::<Value>("ferrumgate")? else {
        anyhow::bail!("settings were not persisted");
    };
    assert_eq!(
        persisted["thirdLogin"]["providers"][0]["clientSecret"],
        raw_secret
    );
    assert!(persisted.get("apiToken").is_none());
    assert_eq!(persisted["thirdLogin"]["providers"][0]["proxy"], raw_proxy);

    assert_eq!(
        server.call("PUT", PATH, &edit, saved.to_string()).await?.0,
        StatusCode::OK
    );
    assert!(!updates.has_changed()?);
    let target = store.dir().join("ferrumgate.json");
    let original = store.dir().join("prior.json");
    fs::rename(&target, &original)?;
    fs::create_dir(&target)?;
    let mut failing = saved;
    failing["logLevel"] = json!("debug");
    failing["sessionHours"] = json!(48);
    assert_eq!(
        server
            .call("PUT", PATH, &edit, failing.to_string())
            .await?
            .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(!updates.has_changed()?);
    let current = server.call("GET", PATH, &auth, Body::empty()).await?.2;
    assert_eq!(current["logLevel"], "warn");
    assert_eq!(current["sessionHours"], 72);
    fs::remove_dir(&target)?;
    fs::rename(original, target)?;
    let account = store.dir().join("account.json");
    let original = store.dir().join("prior-account.json");
    fs::rename(&account, &original)?;
    fs::create_dir(&account)?;
    let (status, _, error) = server.call("PUT", PATH, &edit, failing.to_string()).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        error["error"],
        "global settings saved; sessionHours update failed"
    );
    assert!(updates.has_changed()?);
    assert_eq!(updates.borrow_and_update().log_level, "debug");
    assert_eq!(
        server.call("GET", PATH, &auth, Body::empty()).await?.2["sessionHours"],
        72
    );
    fs::remove_dir(&account)?;
    fs::rename(original, account)?;
    let (status, _, saved) = server.call("PUT", PATH, &edit, failing.to_string()).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(saved["sessionHours"], 48);
    assert!(!updates.has_changed()?);
    Ok(())
}
