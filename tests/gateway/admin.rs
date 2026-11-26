use std::process::Stdio;

use anyhow::{Context, Result};
use http_body_util::BodyExt;
use hyper::{Method, StatusCode, header};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    time::timeout,
};

use super::common::{DEADLINE, Origin, config, connect, full, http_client, request, route, send};

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
    store.save(
        "ferrumgate",
        &json!({"apiToken":legacy, "otherSetting":true}),
    )?;
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
    assert_eq!(settings["otherSetting"], true);
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
    let tokens = fg_auth::token::TokenManager::open(store, [], std::time::Instant::now())?;
    assert_eq!(
        tokens
            .authenticate(legacy, time::OffsetDateTime::now_utc(), None)?
            .scopes(),
        ["*"]
    );
    Ok(())
}
