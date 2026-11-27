use std::{
    net::SocketAddr,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result};
use http_body_util::BodyExt;
use hyper::{Method, StatusCode, header};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStderr, Command},
    time::timeout,
};

use super::common::{
    DEADLINE, Origin, config, connect, full, get, http_client, request, route, send, serve_http,
};

#[tokio::test]
async fn management_delivers_the_initial_password_when_legacy_migration_fails() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let accounts = directory.path().join("accounts");
    let store = fg_config::ConfigStore::open(&accounts)?;
    store.save("ferrumgate", &json!({"apiToken":17}))?;
    std::fs::write(&config_path, config("", "", ""))?;
    let failed = timeout(
        DEADLINE,
        Command::new(env!("CARGO_BIN_EXE_fgate"))
            .args(["serve", "--config"])
            .arg(&config_path)
            .args(["--admin-listen", "127.0.0.1:0", "--admin-dir"])
            .arg(&accounts)
            .env_remove("FERRUMGATE_INITIAL_PASSWORD")
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    assert!(!failed.status.success());
    let output = String::from_utf8(failed.stderr)?;
    assert!(output.contains("legacy API token must be a string"));
    let initial = output
        .lines()
        .find_map(|line| line.strip_prefix("Initial administrator password: "))
        .context("initial password on failed management startup")?;
    let (accounts, generated) = fg_auth::AccountManager::open(store, None)?;
    assert!(generated.is_none());
    assert!(accounts.login("admin", initial)?.is_some());
    Ok(())
}

#[tokio::test]
async fn management_bootstrap_login_change_logout_and_online_reset() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let accounts = directory.path().join("accounts");
    let legacy = "fixture-legacy-bootstrap-token";
    let store = fg_config::ConfigStore::open(&accounts)?;
    store.save("ferrumgate", &json!({"apiToken":legacy, "language":"en"}))?;
    let backend = Origin::http("bootstrap fixture").await?;
    std::fs::write(
        &config_path,
        config(&route("app.test", backend.addr, "/"), "", ""),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .args(["--admin-listen", "127.0.0.1:0", "--admin-dir"])
        .arg(&accounts)
        .env_remove("FERRUMGATE_INITIAL_PASSWORD")
        .env_remove("FERRUMGATE_LOG_LEVEL")
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stderr.take().context("bootstrap output")?).lines();
    let (initial, address) = timeout(DEADLINE, async {
        let mut password = None;
        while let Some(line) = lines.next_line().await? {
            if let Some(secret) = line.strip_prefix("Initial administrator password: ") {
                password = Some(secret.to_owned());
            }
            if line.contains("management ready") {
                let addr = line
                    .split_whitespace()
                    .find_map(|word| word.strip_prefix("listen="))
                    .context("management address")?
                    .parse()?;
                return Ok::<_, anyhow::Error>((
                    password.context("generated initial password")?,
                    addr,
                ));
            }
        }
        anyhow::bail!("management listener did not start")
    })
    .await??;
    let settings: Value =
        serde_json::from_slice(&store.load_raw("ferrumgate")?.context("migrated settings")?)?;
    assert!(settings.get("apiToken").is_none());
    assert_eq!(settings["language"], "en");
    let mut client = http_client(connect(address).await?).await?;
    let mut login = request(
        Method::POST,
        "/api/login",
        "localhost",
        full(json!({"username":"admin","password":initial}).to_string()),
    );
    login
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse()?);
    let response = send(&mut client, login).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let first = response.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut session = request(Method::GET, "/api/session", "localhost", full(""));
    session.headers_mut().insert(header::COOKIE, first.parse()?);
    let body: Value = serde_json::from_slice(
        &send(&mut client, session)
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes(),
    )?;
    assert_eq!(body["defaultPassword"], true);

    let password = "Lk8$yN3-pv";
    let mut change = request(
        Method::PUT,
        "/api/account",
        "localhost",
        full(
            json!({
                "username":"operator","oldPassword":initial,"newPassword":password
            })
            .to_string(),
        ),
    );
    change.headers_mut().insert(header::COOKIE, first.parse()?);
    change
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse()?);
    assert_eq!(send(&mut client, change).await?.status(), StatusCode::OK);
    let login = || {
        let mut request = request(
            Method::POST,
            "/api/login",
            "localhost",
            full(json!({"username":"operator","password":password}).to_string()),
        );
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        request
    };
    let response = send(&mut client, login()).await?;
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut score = request(Method::GET, "/api/system/security", "localhost", full(""));
    score.headers_mut().insert(header::COOKIE, cookie.parse()?);
    let body: Value = serde_json::from_slice(
        &send(&mut client, score)
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes(),
    )?;
    assert_eq!(body["score"], 90);
    let mut list = request(Method::GET, "/api/tokens", "localhost", full(""));
    list.headers_mut().insert(header::COOKIE, cookie.parse()?);
    let listed: Value = serde_json::from_slice(
        &send(&mut client, list)
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes(),
    )?;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["legacy"], true);
    assert!(listed[0].get("hash").is_none());

    let bearer = |path, raw: &str| {
        let mut request = request(Method::GET, path, "localhost", full(""));
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("bEaReR {raw}").parse().unwrap(),
        );
        request
    };
    let mut create = request(
        Method::POST,
        "/api/tokens",
        "localhost",
        full(r#"{"name":"collector","scopes":["logs:read"]}"#),
    );
    create.headers_mut().insert(header::COOKIE, cookie.parse()?);
    create
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse()?);
    let response = send(&mut client, create).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let created: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    let token = created["secret"].as_str().context("issued API token")?;
    let session_token = cookie.split_once('=').context("session cookie")?.1;
    for (path, raw, status) in [
        ("/api/logs/sources", token, StatusCode::OK),
        ("/api/system/security", token, StatusCode::FORBIDDEN),
        ("/api/tokens", legacy, StatusCode::FORBIDDEN),
        ("/api/tokens", session_token, StatusCode::OK),
        ("/api/session", "gtl_invalid", StatusCode::UNAUTHORIZED),
    ] {
        assert_eq!(send(&mut client, bearer(path, raw)).await?.status(), status);
    }
    let mut session = bearer("/api/session", token);
    session
        .headers_mut()
        .insert("x-forwarded-for", "192.0.2.8".parse()?);
    let response = send(&mut client, session).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let identity: Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(identity["username"], "api-token:collector");
    let response = send(&mut client, bearer("/api/session", legacy)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let raw = store.load_raw("tokens")?.context("persisted token file")?;
    let on_disk: Value = serde_json::from_slice(&raw)?;
    let collector_on_disk = on_disk["tokens"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["id"] == created["token"]["id"])
        })
        .context("collector persisted by create")?;
    assert!(collector_on_disk["lastUsedAt"].is_null());

    let mut logout = request(Method::POST, "/api/logout", "localhost", full(""));
    logout.headers_mut().insert(header::COOKIE, cookie.parse()?);
    assert_eq!(send(&mut client, logout).await?.status(), StatusCode::OK);
    let mut check = request(Method::GET, "/api/session", "localhost", full(""));
    check.headers_mut().insert(header::COOKIE, cookie.parse()?);
    assert_eq!(
        send(&mut client, check).await?.status(),
        StatusCode::UNAUTHORIZED
    );

    let response = send(&mut client, login()).await?;
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut reset = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["reset-totp", "--admin-dir"])
        .arg(&accounts)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    reset
        .stdin
        .take()
        .context("reset confirmation input")?
        .write_all(b"yes\n")
        .await?;
    let result = timeout(DEADLINE, reset.wait_with_output()).await??;
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout)?.contains("queued"));
    timeout(DEADLINE, async {
        loop {
            let mut check = request(Method::GET, "/api/session", "localhost", full(""));
            check.headers_mut().insert(header::COOKIE, cookie.parse()?);
            if send(&mut client, check).await?.status() == StatusCode::UNAUTHORIZED {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await??;
    drop(client);
    let id = child.id().context("gateway PID")?;
    assert!(
        Command::new("kill")
            .args(["-INT", &id.to_string()])
            .status()
            .await?
            .success()
    );
    assert!(timeout(DEADLINE, child.wait()).await??.success());
    while let Some(line) = lines.next_line().await? {
        assert!(!line.contains(token));
        assert!(!line.contains(legacy));
    }
    let tokens = fg_auth::token::TokenManager::open(store, [], std::time::Instant::now())?;
    let persisted = tokens.list(time::OffsetDateTime::now_utc());
    let collector = persisted
        .iter()
        .find(|entry| entry.name == "collector")
        .context("collector restored after shutdown")?;
    assert!(collector.last_used_at.is_some());
    assert_eq!(collector.last_used_ip, "127.0.0.1");
    assert_eq!(
        tokens
            .authenticate(legacy, time::OffsetDateTime::now_utc(), None)?
            .scopes(),
        ["*"]
    );
    Ok(())
}

#[tokio::test]
async fn management_applies_settings_live_and_restarts_with_saved_listener_and_modules()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let accounts = directory.path().join("accounts");
    let store = fg_config::ConfigStore::open(&accounts)?;
    store.save("ferrumgate", &json!({"listen":"127.0.0.1:1"}))?;
    let initial = "Fixture-initial$23";
    let password = "Lk8$yN3-pv";
    let (manager, _) = fg_auth::AccountManager::open(store.clone(), Some(initial))?;
    manager.change_credentials(initial, "operator", password)?;
    let session = manager
        .login("operator", password)?
        .context("fixture session")?;
    let cookie = format!("gately_token={}", session.token);
    drop(manager);

    let backend = Origin::http("settings fixture").await?;
    let broken = Origin::spawn(|_| async { Ok(()) }).await?;
    let routes = route("app.test", backend.addr, "/") + &route("broken.test", broken.addr, "/");
    std::fs::write(&config_path, config(&routes, "", ""))?;
    let start = |override_listener| -> Result<Child> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fgate"));
        command
            .args(["serve", "--config"])
            .arg(&config_path)
            .arg("--admin-dir")
            .arg(&accounts);
        if override_listener {
            command.args(["--admin-listen", "127.0.0.1:0"]);
        }
        Ok(command
            .env_remove("FERRUMGATE_LOG_LEVEL")
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()?)
    };
    let mut child = start(true)?;
    let mut lines = BufReader::new(child.stderr.take().context("bootstrap output")?).lines();
    let gateway = wait_listener(&mut lines, "gateway ready").await?;
    let admin = wait_listener(&mut lines, "management ready").await?;
    assert_ne!(admin.port(), 1);
    let mut client = http_client(connect(admin).await?).await?;
    let mut proxy = http_client(connect(gateway).await?).await?;
    assert_eq!(get(&mut proxy, "app.test", "/").await?.0, 200);
    let (status, view) = get_admin_settings(&mut client, &cookie).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["listen"], "127.0.0.1:1");
    assert_eq!(view["restartRequired"], false);

    let mut put = request(
        Method::PUT,
        "/api/system/settings",
        "localhost",
        full(
            json!({
                "listen":":0", "disabledModules":["webservice"], "logLevel":"debug",
                "maxLoginFailures":1, "lockMinutes":10080, "sessionHours":48,
            })
            .to_string(),
        ),
    );
    put.headers_mut().insert(header::COOKIE, cookie.parse()?);
    put.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse()?);
    let response = send(&mut client, put).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let saved: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(saved["restartRequired"], true);
    assert_eq!(saved["sessionHours"], 48);
    assert_eq!(get(&mut proxy, "app.test", "/").await?.0, 200);
    timeout(DEADLINE, async {
        loop {
            assert_eq!(get(&mut proxy, "broken.test", "/").await?.0, 502);
            if let Ok(Ok(Some(line))) =
                timeout(std::time::Duration::from_millis(100), lines.next_line()).await
                && line.contains("upstream request failed")
                && line.contains("DEBUG")
            {
                return Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;
    let login = |password| {
        let mut request = request(
            Method::POST,
            "/api/login",
            "localhost",
            full(json!({"username":"operator","password":password}).to_string()),
        );
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        request
    };
    assert_eq!(
        send(&mut client, login("wrong")).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let blocked = send(&mut client, login("wrong")).await?;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        blocked.headers()[header::RETRY_AFTER]
            .to_str()?
            .parse::<u64>()?
            > 6 * 86_400
    );

    drop(proxy);
    drop(client);
    stop_management(&mut child).await?;
    let mut restarted = start(false)?;
    let mut lines = BufReader::new(restarted.stderr.take().context("restart output")?).lines();
    let admin = wait_listener(&mut lines, "management ready").await?;
    assert!(admin.ip().is_loopback());
    let mut client = http_client(connect(admin).await?).await?;
    let (status, view) = get_admin_settings(&mut client, &cookie).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["listen"], ":0");
    assert_eq!(view["logLevel"], "debug");
    assert_eq!(view["sessionHours"], 48);
    assert_eq!(view["restartRequired"], false);
    let mut req = request(Method::GET, "/api/session", "localhost", full(""));
    req.headers_mut().insert(header::COOKIE, cookie.parse()?);
    let session = send(&mut client, req).await?;
    let session: Value = serde_json::from_slice(&session.into_body().collect().await?.to_bytes())?;
    assert_eq!(session["disabledModules"], json!(["webservice"]));
    let fresh = send(&mut client, login(password)).await?;
    assert_eq!(fresh.status(), StatusCode::OK);
    let max_age = fresh.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix("Max-Age="))
        .context("session age")?
        .parse::<u64>()?;
    assert!((172_795..=172_800).contains(&max_age));
    drop(client);
    stop_management(&mut restarted).await?;

    store.save("ferrumgate", &json!({"listen":":0", "lockMinutes":10081}))?;
    let mut invalid = start(false)?;
    let output = timeout(DEADLINE, invalid.wait()).await??;
    assert!(!output.success());
    let mut lines =
        BufReader::new(invalid.stderr.take().context("invalid settings output")?).lines();
    let mut diagnostic = false;
    while let Some(line) = lines.next_line().await? {
        assert!(!line.contains("gateway ready"));
        diagnostic |= line.contains("lockMinutes");
    }
    assert!(diagnostic);
    Ok(())
}

async fn get_admin_settings(
    client: &mut hyper::client::conn::http1::SendRequest<super::common::TestBody>,
    cookie: &str,
) -> Result<(StatusCode, Value)> {
    let mut req = request(Method::GET, "/api/system/settings", "localhost", full(""));
    req.headers_mut().insert(header::COOKIE, cookie.parse()?);
    let response = send(client, req).await?;
    let status = response.status();
    let body = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    Ok((status, body))
}

#[tokio::test]
async fn management_switches_log_directories_and_keeps_memory_when_persistence_is_disabled()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let assets = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let store = fg_config::ConfigStore::open(&directory.path().join("management"))?;
    store.save("ferrumgate", &json!({"listen":":0", "logLevel":"debug"}))?;
    let initial = "Fixture-initial$23";
    let password = "Lk8$yN3-pv";
    let (manager, _) = fg_auth::AccountManager::open(store.clone(), Some(initial))?;
    manager.change_credentials(initial, "operator", password)?;
    let session = manager
        .login("operator", password)?
        .context("fixture session")?;
    let cookie = format!("gately_token={}", session.token);
    drop(manager);
    let backend = Origin::spawn(|_| async { Ok(()) }).await?;
    let routes = route("broken.test", backend.addr, "/")
        + &format!(
            "\n[[routes]]\nhost = 'assets.test'\n[routes.response]\ntype = 'static'\nroot = '{}'\n",
            assets.path().display(),
        );
    std::fs::write(&config_path, config(&routes, "", ""))?;
    std::fs::write(assets.path().join("index.html"), "static fixture")?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .arg("--admin-dir")
        .arg(store.dir())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stderr.take().context("management logs")?).lines();
    let gateway = wait_listener(&mut lines, "gateway ready").await?;
    let admin = wait_listener(&mut lines, "management ready").await?;
    let mut client = http_client(connect(admin).await?).await?;
    let mut proxy = http_client(connect(gateway).await?).await?;
    assert_eq!(
        get(&mut proxy, "assets.test", "/").await?.1,
        "static fixture"
    );
    assert_eq!(get(&mut proxy, "broken.test", "/").await?.0, 502);

    let put = |body: Value| {
        let mut req = request(
            Method::PUT,
            "/api/system/settings",
            "localhost",
            full(body.to_string()),
        );
        req.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        req.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        req
    };
    let unsafe_dir = assets.path().join("private-logs");
    let rejected = send(
        &mut client,
        put(json!({"listen":":0", "logLevel":"debug", "logDir":unsafe_dir})),
    )
    .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(!unsafe_dir.exists());
    assert_eq!(
        get_admin_settings(&mut client, &cookie).await?.1["logDir"],
        ""
    );

    let new_dir = directory.path().join("other-logs");
    std::fs::create_dir(&new_dir)?;
    let competing = std::fs::File::create(new_dir.join(".ferrumgate-log.lock"))?;
    competing.try_lock()?;
    let mut competing = Some(competing);
    for disable in [false, true, false] {
        let result = send(
            &mut client,
            put(json!({
                "listen":":0", "logLevel":"debug", "logLines":2, "logFileMB":1,
                "logDir":new_dir, "disableLogPersist":disable, "accessLogDays":1, "accessLogMB":4,
            })),
        )
        .await?;
        assert_eq!(result.status(), StatusCode::OK);
        result.into_body().collect().await?;
        if let Some(lock) = competing.take() {
            wait_log_message(&mut lines, "runtime logging options could not be applied").await?;
            assert!(!new_dir.join("webservice.log").exists());
            drop(lock);
        }
        wait_log_message(&mut lines, "runtime logging options applied").await?;
        if disable {
            let path = new_dir.join("webservice.log");
            let before = std::fs::read(&path)?;
            for _ in 0..4 {
                assert_eq!(get(&mut proxy, "broken.test", "/").await?.0, 502);
            }
            let mut req = request(Method::GET, "/api/webservice/logs", "localhost", full(""));
            req.headers_mut().insert(header::COOKIE, cookie.parse()?);
            let response = send(&mut client, req).await?;
            assert_eq!(response.status(), StatusCode::OK);
            let live: Vec<fg_logging::Entry> =
                serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
            assert_eq!(live.len(), 2);
            assert!(
                live.iter()
                    .all(|entry| entry.message == "upstream request failed")
            );
            assert_eq!(std::fs::read(path)?, before);
        } else {
            assert_eq!(get(&mut proxy, "broken.test", "/").await?.0, 502);
        }
    }
    drop(proxy);
    drop(client);
    stop_management(&mut child).await?;
    let read = |path| -> Result<Vec<fg_logging::Entry>> {
        let rows = std::fs::read_to_string(path)?;
        rows.lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
    };
    let original = read(store.dir().join("logs/webservice.log"))?;
    let switched = read(new_dir.join("webservice.log"))?;
    assert_eq!(original.len(), 1);
    assert_eq!(switched.len(), 2);
    assert!(original[0].seq < switched[0].seq && switched[1].seq > switched[0].seq + 1);
    Ok(())
}

async fn wait_log_message(lines: &mut Lines<BufReader<ChildStderr>>, message: &str) -> Result<()> {
    timeout(DEADLINE, async {
        while let Some(line) = lines.next_line().await? {
            if line.contains(message) {
                return Ok(());
            }
        }
        anyhow::bail!("management log did not contain {message}")
    })
    .await?
}

#[tokio::test]
async fn management_switches_third_login_from_legacy_and_disables_pending_flows() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let store = fg_config::ConfigStore::open(&directory.path().join("management"))?;
    store.save("ferrumgate", &json!({"listen":":0"}))?;
    store.save("third-login", &json!({
        "providers":[{"key":"legacy","name":"Legacy","type":"github","clientId":"legacy-client","clientSecret":"legacy-secret"}],
        "allowed":["legacy:100"],
    }))?;
    let initial = "Fixture-initial$23";
    let password = "Lk8$yN3-pv";
    let (manager, _) = fg_auth::AccountManager::open(store.clone(), Some(initial))?;
    manager.change_credentials(initial, "operator", password)?;
    let session = manager
        .login("operator", password)?
        .context("fixture session")?;
    let admin_cookie = format!("gately_token={}", session.token);
    drop(manager);

    let exchanges = Arc::new(AtomicUsize::new(0));
    let counter = exchanges.clone();
    let provider = Origin::spawn(move |stream| {
        let counter = counter.clone();
        async move {
            let issuer = format!("http://{}", stream.local_addr()?);
            serve_http(stream, move |request| {
                let response = if request.uri().path() == "/.well-known/openid-configuration" {
                    hyper::Response::new(full(json!({
                        "issuer":issuer, "authorization_endpoint":format!("{issuer}/authorize"),
                        "token_endpoint":format!("{issuer}/token"), "jwks_uri":format!("{issuer}/keys"),
                    }).to_string()))
                } else {
                    counter.fetch_add(1, Ordering::Relaxed);
                    hyper::Response::builder().status(StatusCode::BAD_REQUEST).body(full("{}")).unwrap()
                };
                std::future::ready(response)
            }).await
        }
    }).await?;
    std::fs::write(
        &config_path,
        config(&route("app.test", provider.addr, "/"), "", ""),
    )?;
    let start = || -> Result<Child> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fgate"))
            .args(["serve", "--config"])
            .arg(&config_path)
            .arg("--admin-dir")
            .arg(store.dir())
            .args([
                "--admin-origin",
                "https://admin.test",
                "--admin-prefix",
                "/panel",
                "--log-level",
                "info",
            ])
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()?)
    };
    let mut child = start()?;
    let mut lines = BufReader::new(child.stderr.take().context("management output")?).lines();
    let address = wait_listener(&mut lines, "management ready").await?;
    let mut client = http_client(connect(address).await?).await?;
    wait_provider(&mut client, "legacy").await?;
    assert_eq!(
        get_admin_settings(&mut client, &admin_cookie).await?.1["thirdLogin"]["enable"],
        true
    );

    let save = |origin, enable| {
        let mut req = request(Method::PUT, "/api/system/settings", "admin.test", full(json!({
            "listen":":0", "thirdLogin":{
                "enable":enable, "callbackBase":origin,
                "providers":[{"key":"local","name":"Local","type":"oidc","issuer":format!("http://{}",provider.addr),
                    "clientId":"test-client","clientSecret":"fixture-client-secret"}],
                "allowed":["local:fixture # exact subject"]
            }
        }).to_string()));
        req.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        req.headers_mut()
            .insert(header::COOKIE, admin_cookie.parse().unwrap());
        req
    };
    let wrong_origin = send(&mut client, save("https://wrong.test", true)).await?;
    assert_eq!(wrong_origin.status(), StatusCode::BAD_REQUEST);
    wrong_origin.into_body().collect().await?;
    wait_provider(&mut client, "legacy").await?;
    let saved = send(&mut client, save("https://admin.test", true)).await?;
    assert_eq!(saved.status(), StatusCode::OK);
    let saved: Value = serde_json::from_slice(&saved.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        saved["thirdLogin"]["providers"][0]["clientSecret"],
        "********"
    );
    wait_provider(&mut client, "local").await?;

    let location = send(
        &mut client,
        request(
            Method::GET,
            "/api/login/oauth/start?p=local",
            "admin.test",
            full(""),
        ),
    )
    .await?;
    assert_eq!(location.status(), StatusCode::SEE_OTHER);
    let target = fg_auth::passkey::Url::parse(location.headers()[header::LOCATION].to_str()?)?;
    assert_eq!(target.authority(), provider.addr.to_string());
    let pairs: std::collections::HashMap<_, _> = target.query_pairs().collect();
    assert_eq!(
        pairs["redirect_uri"],
        "https://admin.test/panel/api/login/oauth/callback"
    );
    assert_eq!(pairs["code_challenge_method"], "S256");
    assert!(pairs.contains_key("nonce"));
    let browser = location.headers()[header::SET_COOKIE].to_str()?;
    assert!(browser.contains("Path=/panel/api/login/oauth") && browser.contains("; Secure"));
    let browser = browser
        .split(';')
        .next()
        .context("OAuth browser cookie")?
        .to_owned();
    location.into_body().collect().await?;

    let disabled = send(&mut client, save("https://admin.test", false)).await?;
    assert_eq!(disabled.status(), StatusCode::OK);
    disabled.into_body().collect().await?;
    let (status, body) = get(&mut client, "admin.test", "/api/login/providers").await?;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?["providers"],
        json!([])
    );
    let callback = format!(
        "/api/login/oauth/callback?state={}&code=fixture",
        pairs["state"]
    );
    let mut req = request(Method::GET, &callback, "admin.test", full(""));
    req.headers_mut().insert(header::COOKIE, browser.parse()?);
    let refused = send(&mut client, req).await?;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(!refused.headers().contains_key(header::SET_COOKIE));
    assert_eq!(exchanges.load(Ordering::Relaxed), 0);
    drop(client);
    stop_management(&mut child).await?;

    let mut restarted = start()?;
    let mut lines = BufReader::new(restarted.stderr.take().context("restart output")?).lines();
    let address = wait_listener(&mut lines, "management ready").await?;
    let mut client = http_client(connect(address).await?).await?;
    let (status, body) = get(&mut client, "admin.test", "/api/login/providers").await?;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?["providers"],
        json!([])
    );
    assert_eq!(
        get_admin_settings(&mut client, &admin_cookie).await?.1["thirdLogin"]["enable"],
        false
    );
    drop(client);
    stop_management(&mut restarted).await?;
    Ok(())
}

async fn wait_provider(
    client: &mut hyper::client::conn::http1::SendRequest<super::common::TestBody>,
    key: &str,
) -> Result<()> {
    timeout(DEADLINE, async {
        loop {
            let (status, body) = get(client, "admin.test", "/api/login/providers").await?;
            assert_eq!(status, 200);
            let body: Value = serde_json::from_slice(&body)?;
            if body["providers"][0]["key"] == key {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await?
}

async fn wait_listener(
    lines: &mut Lines<BufReader<ChildStderr>>,
    marker: &str,
) -> Result<SocketAddr> {
    timeout(DEADLINE, async {
        while let Some(line) = lines.next_line().await? {
            if line.contains(marker)
                && let Some(address) = line
                    .split_whitespace()
                    .find_map(|word| word.strip_prefix("listen="))
            {
                return Ok(address.parse()?);
            }
        }
        anyhow::bail!("listener did not start")
    })
    .await?
}

async fn stop_management(child: &mut Child) -> Result<()> {
    let id = child.id().context("gateway PID")?;
    assert!(
        Command::new("kill")
            .args(["-INT", &id.to_string()])
            .status()
            .await?
            .success()
    );
    assert!(timeout(DEADLINE, child.wait()).await??.success());
    Ok(())
}

#[tokio::test]
async fn management_restart_reexeces_with_same_pid_and_listener() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let accounts = directory.path().join("accounts");
    let backend = Origin::http("restart fixture").await?;
    let initial = "Fixture-initial$23";
    let password = "Lk8$yN3-pv";
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        let (manager, _) = fg_auth::AccountManager::open(store, Some(initial))?;
        manager.change_credentials(initial, "operator", password)?;
    }
    std::fs::write(
        &config_path,
        config(&route("app.test", backend.addr, "/"), "", ""),
    )?;
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let admin = probe.local_addr()?;
    drop(probe);
    let mut child = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .args(["--admin-listen", &admin.to_string(), "--admin-dir"])
        .arg(&accounts)
        .env_remove("FERRUMGATE_LOG_LEVEL")
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let pid = child.id();
    let mut lines = BufReader::new(child.stderr.take().context("bootstrap output")?).lines();
    wait_listener(&mut lines, "management ready").await?;
    let login = |password: &str| {
        let mut request = request(
            Method::POST,
            "/api/login",
            "localhost",
            full(json!({"username":"operator","password":password}).to_string()),
        );
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        request
    };
    let mut client = http_client(connect(admin).await?).await?;
    let response = send(&mut client, login(password)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut restart = request(Method::POST, "/api/system/restart", "localhost", full(""));
    restart
        .headers_mut()
        .insert(header::COOKIE, cookie.parse()?);
    let response = send(&mut client, restart).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(body["ok"], true, "the response is written before re-exec");
    // The old image keeps serving until exec; wait for the restarted
    // process to announce the same listener instead of racing a connect.
    let restarted = timeout(std::time::Duration::from_secs(20), async {
        loop {
            let address = wait_listener(&mut lines, "management ready").await?;
            if address == admin {
                return Ok::<_, anyhow::Error>(address);
            }
        }
    })
    .await??;
    assert_eq!(restarted, admin);
    assert_eq!(child.id(), pid, "exec replaces the image, not the process");
    assert!(child.try_wait()?.is_none(), "service keeps running");
    let mut client = http_client(connect(admin).await?).await?;
    assert_eq!(
        send(&mut client, login(password)).await?.status(),
        StatusCode::OK,
        "credentials survive the restart"
    );
    stop_management(&mut child).await?;
    Ok(())
}

#[tokio::test]
async fn management_takes_offline_rollback_requests_while_running() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let accounts = directory.path().join("accounts");
    let backend = Origin::http("rollback fixture").await?;
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        store.enable_history(20, &[]);
        store.save("ferrumgate", &json!({"language":"en"}))?;
        store.save("ferrumgate", &json!({"language":"zh"}))?;
    }
    std::fs::write(
        &config_path,
        config(&route("app.test", backend.addr, "/"), "", ""),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .args(["--admin-listen", "127.0.0.1:0", "--admin-dir"])
        .arg(&accounts)
        .env_remove("FERRUMGATE_LOG_LEVEL")
        .env_remove("FERRUMGATE_INITIAL_PASSWORD")
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stderr.take().context("bootstrap output")?).lines();
    wait_listener(&mut lines, "management ready").await?;
    let request = fg_config::rollback::RollbackRequest {
        config: String::new(),
        version: None,
        last: true,
        pending: false,
        created_at: time::OffsetDateTime::now_utc(),
    };
    fg_config::rollback::write_request(&accounts, &request)?;
    timeout(std::time::Duration::from_secs(10), async {
        loop {
            if !accounts.join("rollback-request.state").exists()
                && let Some(bytes) =
                    fg_config::ConfigStore::open(&accounts)?.load_raw("ferrumgate")?
                && let Ok(view) = serde_json::from_slice::<Value>(&bytes)
                && view["language"] == "en"
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    })
    .await??;
    stop_management(&mut child).await?;
    Ok(())
}

#[tokio::test]
async fn management_applies_declarative_directory_before_config_load() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let accounts = directory.path().join("accounts");
    let apply = tempfile::tempdir()?;
    let backend = Origin::http("apply fixture").await?;
    std::fs::write(apply.path().join("ferrumgate.json"), r#"{"language":"zh"}"#)?;
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        store.enable_history(20, &[]);
        store.save("ferrumgate", &json!({"language":"en"}))?;
    }
    std::fs::write(
        &config_path,
        config(&route("app.test", backend.addr, "/"), "", ""),
    )?;
    let start = || {
        Command::new(env!("CARGO_BIN_EXE_fgate"))
            .args(["serve", "--config"])
            .arg(&config_path)
            .args(["--admin-listen", "127.0.0.1:0", "--admin-dir"])
            .arg(&accounts)
            .args(["--apply"])
            .arg(apply.path())
            .env_remove("FERRUMGATE_LOG_LEVEL")
            .env_remove("FERRUMGATE_INITIAL_PASSWORD")
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
    };
    let mut child = start()?;
    let mut lines = BufReader::new(child.stderr.take().context("bootstrap output")?).lines();
    // The apply log line precedes the management listener announcement.
    wait_log_message(&mut lines, "declarative configuration applied").await?;
    wait_listener(&mut lines, "management ready").await?;
    let mut expected = br#"{"language":"zh"}"#.to_vec();
    expected.push(b'\n');
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        assert_eq!(
            store.load_raw("ferrumgate")?.as_deref(),
            Some(expected.as_slice()),
            "the declarative file replaced the saved settings"
        );
        assert_eq!(
            store.versions("ferrumgate")?.len(),
            1,
            "the replaced content is rollback-readable"
        );
    }
    stop_management(&mut child).await?;

    // A second start applies identical content without touching history.
    let mut child = start()?;
    let mut lines = BufReader::new(child.stderr.take().context("bootstrap output")?).lines();
    wait_listener(&mut lines, "management ready").await?;
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        assert_eq!(
            store.versions("ferrumgate")?.len(),
            1,
            "unchanged declarative files do not rewrite or re-archive"
        );
        assert_eq!(
            store.load_raw("ferrumgate")?.as_deref(),
            Some(expected.as_slice())
        );
    }
    stop_management(&mut child).await?;
    Ok(())
}

#[tokio::test]
async fn demo_mode_refuses_writes_and_sensitive_reads_for_everyone() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let accounts = directory.path().join("accounts");
    let backend = Origin::http("demo fixture").await?;
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        let (manager, _) = fg_auth::AccountManager::open(store, Some("Fixture-initial$23"))?;
        manager.change_credentials("Fixture-initial$23", "operator", "Lk8$yN3-pv")?;
    }
    std::fs::write(
        &config_path,
        config(&route("app.test", backend.addr, "/"), "", ""),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .args(["--admin-listen", "127.0.0.1:0", "--admin-dir"])
        .arg(&accounts)
        .arg("--demo")
        .env_remove("FERRUMGATE_LOG_LEVEL")
        .env_remove("FERRUMGATE_INITIAL_PASSWORD")
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stderr.take().context("bootstrap output")?).lines();
    let admin = wait_listener(&mut lines, "management ready").await?;
    let login = |password: &str| {
        let mut request = request(
            Method::POST,
            "/api/login",
            "localhost",
            full(json!({"username":"operator","password":password}).to_string()),
        );
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        request
    };
    let mut client = http_client(connect(admin).await?).await?;
    let response = send(&mut client, login("Lk8$yN3-pv")).await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "demo still allows sign-in"
    );
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    // Session-backed writes are refused with the demo message.
    let mut put = request(
        Method::PUT,
        "/api/system/settings",
        "localhost",
        full(json!({"logLevel":"debug"}).to_string()),
    );
    put.headers_mut().insert(header::COOKIE, cookie.parse()?);
    put.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse()?);
    let response = send(&mut client, put).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(body["error"], "演示模式下不可用");
    // Sensitive reads are refused; ordinary reads pass.
    let mut read = request(
        Method::GET,
        "/api/system/diagnostics",
        "localhost",
        full(""),
    );
    read.headers_mut().insert(header::COOKIE, cookie.parse()?);
    assert_eq!(
        send(&mut client, read).await?.status(),
        StatusCode::FORBIDDEN
    );
    let mut session = request(Method::GET, "/api/session", "localhost", full(""));
    session
        .headers_mut()
        .insert(header::COOKIE, cookie.parse()?);
    assert_eq!(send(&mut client, session).await?.status(), StatusCode::OK);
    stop_management(&mut child).await?;
    Ok(())
}

#[tokio::test]
async fn safe_entry_and_lan_only_enforced_over_real_process() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("gateway.toml");
    let accounts = directory.path().join("accounts");
    let store = fg_config::ConfigStore::open(&accounts)?;
    let initial = "Fixture-initial$23";
    let password = "Lk8$yN3-pv";
    {
        let (manager, _) = fg_auth::AccountManager::open(store.clone(), Some(initial))?;
        manager.change_credentials(initial, "operator", password)?;
    }
    let backend = Origin::http("safe entry fixture").await?;
    std::fs::write(
        &config_path,
        config(&route("app.test", backend.addr, "/"), "", ""),
    )?;
    let start = || -> Result<Child> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fgate"))
            .args(["serve", "--config"])
            .arg(&config_path)
            .args(["--admin-listen", "127.0.0.1:0", "--admin-dir"])
            .arg(&accounts)
            .env_remove("FERRUMGATE_LOG_LEVEL")
            .env_remove("FERRUMGATE_INITIAL_PASSWORD")
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()?)
    };
    async fn page(response: hyper::Response<hyper::body::Incoming>) -> Result<String> {
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok(String::from_utf8(bytes.to_vec())?)
    }
    async fn entry_session(
        client: &mut hyper::client::conn::http1::SendRequest<super::common::TestBody>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        send(
            client,
            request(Method::GET, "/api/session", "localhost", full("")),
        )
        .await
    }

    // Run 1: the safe-entry gate answers credential requests with the
    // guard's minimal 404 page before authentication ever sees them.
    store.save(
        "ferrumgate",
        &json!({
            "listen":"127.0.0.1:0", "safePath":"/hidden-entry",
            "lanOnly":true, "denyMode":""
        }),
    )?;
    let mut child = start()?;
    let mut lines = BufReader::new(child.stderr.take().context("bootstrap output")?).lines();
    let admin = wait_listener(&mut lines, "management ready").await?;
    let mut client = http_client(connect(admin).await?).await?;
    let response = entry_session(&mut client).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let text = page(response).await?;
    assert!(text.contains("noindex"), "guard entry 404 page: {text}");
    // The entry path itself stays reachable and shows the API fallback,
    // not the guard page (which also says 404 Not Found).
    let response = send(
        &mut client,
        request(Method::GET, "/hidden-entry", "localhost", full("")),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // Visiting the entry path plants the signed marker; the planted
    // cookie opens the gate for the following request.
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("gately_entry="))
        .and_then(|value| value.split(';').next())
        .expect("the entry visit plants the marker cookie")
        .to_owned();
    let text = page(response).await?;
    assert!(
        text.contains("API route not found"),
        "entry path falls through: {text}"
    );
    assert!(
        !text.contains("noindex"),
        "entry path is not denied: {text}"
    );
    let mut session = request(Method::GET, "/api/session", "localhost", full(""));
    session
        .headers_mut()
        .insert(header::COOKIE, cookie.parse()?);
    let response = send(&mut client, session).await?;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the gate opened: authentication answers instead of the guard"
    );
    drop(client);
    stop_management(&mut child).await?;

    // Run 2: without a safe path the entry gate disappears; the loopback
    // peer is internal, so LAN-only still lets authentication answer.
    store.save(
        "ferrumgate",
        &json!({"listen":"127.0.0.1:0", "lanOnly":true}),
    )?;
    let mut child = start()?;
    let mut lines = BufReader::new(child.stderr.take().context("lan-only output")?).lines();
    let admin = wait_listener(&mut lines, "management ready").await?;
    let mut client = http_client(connect(admin).await?).await?;
    let response = entry_session(&mut client).await?;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "guard did not fire for an internal peer"
    );
    drop(client);
    stop_management(&mut child).await?;

    // Run 3: the stealth mode answers the entry denial with a generic
    // stock 404 that reveals nothing about the product.
    store.save(
        "ferrumgate",
        &json!({
            "listen":"127.0.0.1:0", "safePath":"/hidden-entry",
            "lanOnly":true, "denyMode":"notfound"
        }),
    )?;
    let mut child = start()?;
    let mut lines = BufReader::new(child.stderr.take().context("notfound output")?).lines();
    let admin = wait_listener(&mut lines, "management ready").await?;
    let mut client = http_client(connect(admin).await?).await?;
    let response = entry_session(&mut client).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let text = page(response).await?;
    let stock = "<html>\r\n<head><title>404 Not Found</title></head>\r\n\
                 <body>\r\n<center><h1>404 Not Found</h1></center>\r\n\
                 <hr><center>web server</center>\r\n</body>\r\n</html>\r\n";
    assert_eq!(text, stock, "stealth denial is the stock 404 page");
    let lower = text.to_lowercase();
    assert!(!lower.contains("gately") && !lower.contains("ferrumgate"));
    assert!(!lower.contains("noindex"));
    drop(client);
    stop_management(&mut child).await?;
    Ok(())
}
