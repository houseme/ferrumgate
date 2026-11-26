use std::{path::PathBuf, process::Stdio, time::Duration};

use anyhow::Result;
use serde_json::json;
use tokio::process::Command;

const DEADLINE: Duration = Duration::from_secs(30);

struct Instance {
    child: tokio::process::Child,
    url: String,
    token: String,
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Boots a real fgate serve instance with one ddns write-scope API token.
async fn start() -> Result<Instance> {
    let directory = tempfile::tempdir()?;
    let accounts = directory.path().join("accounts");
    let config_path = directory.path().join("gateway.toml");
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        store.save(
            "account",
            &json!({
                "username":"operator",
                "passwordHash":bcrypt::hash("Fixture-initial$23", 4)?,
                "sessionSecret":"fixture-session-secret-for-ctl-tests",
            }),
        )?;
        store.save(
            "tokens",
            &json!({"tokens":[{
                "id":"abc123def456","name":"ops","group":"","hash":token_hash()?,
                "hint":"ctl","scopes":["ddns:write"],"legacy":false,"disabled":false,
                "createdAt":"2026-11-27T00:00:00Z",
            }]}),
        )?;
        store.save("ferrumgate", &json!({"language":"en"}))?;
    }
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend.local_addr()?;
    tokio::spawn(async move {
        loop {
            let _ = backend.accept().await;
        }
    });
    std::fs::write(
        &config_path,
        format!(
            "schema_version = 1\n\n[server]\nlisten = \"127.0.0.1:0\"\n\n\
             [[routes]]\nhost = \"app.test\"\npath_prefix = \"/\"\n\
             upstream = \"http://{backend_addr}\"\n"
        ),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .args(["--admin-listen", "127.0.0.1:0", "--admin-dir"])
        .arg(&accounts)
        .env_remove("FERRUMGATE_LOG_LEVEL")
        .env_remove("FERRUMGATE_INITIAL_PASSWORD")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stderr = child.stderr.take().expect("management output");
    let address = tokio::time::timeout(DEADLINE, async {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut lines = BufReader::new(&mut stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains("management ready")
                && let Some(address) = line
                    .split_whitespace()
                    .find_map(|word| word.strip_prefix("listen="))
            {
                return Ok::<_, anyhow::Error>(address.to_owned());
            }
        }
        anyhow::bail!("management listener did not start")
    })
    .await??;
    Ok(Instance {
        child,
        url: format!("http://{address}"),
        token: token_secret(),
    })
}

/// A modern token: `gtl_` plus 48 hex digits, hashed into the store.
fn token_secret() -> String {
    format!("gtl_{}", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f")
}

fn token_hash() -> Result<String> {
    use ring::digest::{SHA256, digest};
    let hash = digest(&SHA256, token_secret().as_bytes());
    Ok(data_encoding::HEXLOWER.encode(hash.as_ref()))
}

/// A ctl invocation with an isolated user configuration directory.
async fn ctl(args: &[&str], url: &str, token: &str, home: &tempfile::TempDir) -> Result<Output> {
    let mut home_dir = home.path().to_path_buf();
    home_dir.push("config");
    let output = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .arg("ctl")
        .arg("--url")
        .arg(url)
        .arg("--token")
        .arg(token)
        .args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", &home_dir)
        .env_remove("FERRUMGATE_URL")
        .env_remove("FERRUMGATE_TOKEN")
        .stdin(Stdio::null())
        .output()
        .await?;
    Ok(Output {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[tokio::test]
async fn ctl_exit_codes_and_formatted_output() -> Result<()> {
    let instance = start().await?;
    let home = tempfile::tempdir()?;
    let ok = ctl(
        &["get", "/api/session"],
        &instance.url,
        &instance.token,
        &home,
    )
    .await?;
    assert_eq!(ok.code, Some(0), "{}{}", ok.stdout, ok.stderr);
    let value: serde_json::Value = serde_json::from_str(ok.stdout.trim())?;
    assert_eq!(value["username"], "api-token:ops");

    let missing = ctl(
        &["get", "/api/ddns/rules/missing"],
        &instance.url,
        &instance.token,
        &home,
    )
    .await?;
    assert_eq!(missing.code, Some(1));
    assert!(
        missing.stdout.contains("错误: HTTP 404"),
        "{}",
        missing.stdout
    );

    let usage = ctl(
        &["get", "/other/path"],
        &instance.url,
        &instance.token,
        &home,
    )
    .await?;
    assert_eq!(usage.code, Some(2));
    assert!(usage.stderr.contains("/api/"), "{}", usage.stderr);

    let bad_body = ctl(
        &["post", "/api/ddns/tasks", "not-json"],
        &instance.url,
        &instance.token,
        &home,
    )
    .await?;
    assert_eq!(bad_body.code, Some(2));
    assert!(bad_body.stderr.contains("JSON"), "{}", bad_body.stderr);
    Ok(())
}

#[tokio::test]
async fn ctl_ls_lists_only_token_visible_operations() -> Result<()> {
    let instance = start().await?;
    let home = tempfile::tempdir()?;
    let listing = ctl(&["ls"], &instance.url, &instance.token, &home).await?;
    assert_eq!(
        listing.code,
        Some(0),
        "{}{}",
        listing.stdout,
        listing.stderr
    );
    // Built-in log operations and the schema are visible to any token.
    assert!(
        listing.stdout.contains("/api/session"),
        "{}",
        listing.stdout
    );
    assert!(
        listing.stdout.contains("/api/webservice/logs"),
        "{}",
        listing.stdout
    );
    // Session-only operations stay hidden from tokens.
    assert!(
        !listing.stdout.contains("/api/account"),
        "{}",
        listing.stdout
    );
    assert!(!listing.stdout.contains("/api/audit"), "{}", listing.stdout);

    let filtered = ctl(&["ls", "logs"], &instance.url, &instance.token, &home).await?;
    assert!(
        filtered.stdout.contains("/api/webservice/logs"),
        "{}",
        filtered.stdout
    );
    let nothing = ctl(
        &["ls", "nothing-matches-this"],
        &instance.url,
        &instance.token,
        &home,
    )
    .await?;
    assert!(
        nothing.stdout.contains("没有匹配的接口"),
        "{}",
        nothing.stdout
    );
    Ok(())
}

#[tokio::test]
async fn ctl_login_verifies_before_saving() -> Result<()> {
    let instance = start().await?;
    let home = tempfile::tempdir()?;
    let candidates = [
        home.path()
            .join("Library/Application Support/ferrumgate/ctl.json"), // macOS
        home.path().join("config/ferrumgate/ctl.json"), // XDG
    ];

    let rejected = ctl(
        &["login", &instance.url, "wrong-token"],
        &instance.url,
        "wrong-token",
        &home,
    )
    .await?;
    assert_eq!(
        rejected.code,
        Some(1),
        "{}{}",
        rejected.stdout,
        rejected.stderr
    );
    assert!(
        candidates.iter().all(|path| !path.exists()),
        "an invalid token must not be persisted"
    );

    let accepted = ctl(
        &["login", &instance.url, &instance.token],
        &instance.url,
        &instance.token,
        &home,
    )
    .await?;
    assert_eq!(
        accepted.code,
        Some(0),
        "{}{}",
        accepted.stdout,
        accepted.stderr
    );
    let saved = candidates
        .iter()
        .find(|path| path.is_file())
        .expect("the connection was saved");
    let raw = std::fs::read(saved)?;
    let stored: serde_json::Value = serde_json::from_slice(&raw)?;
    assert_eq!(stored["url"], instance.url);
    assert_eq!(stored["token"], instance.token);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(saved)?.permissions().mode() & 0o777,
            0o600
        );
    }
    let _ = PathBuf::new();
    Ok(())
}

#[tokio::test]
async fn ctl_env_and_config_file_feed_the_connection() -> Result<()> {
    let instance = start().await?;
    let home = tempfile::tempdir()?;
    let payload = serde_json::to_vec_pretty(&json!({
        "url": instance.url,
        "token": instance.token,
        "insecure": false
    }))?;
    // Write the config into every platform's user configuration directory.
    for relative in [
        "Library/Application Support/ferrumgate/ctl.json", // macOS
        "config/ferrumgate/ctl.json",                      // XDG
    ] {
        let path = home.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, &payload)?;
    }
    // No --url/--token flags: the config file carries the connection.
    let output = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["ctl", "get", "/api/session"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env_remove("FERRUMGATE_URL")
        .env_remove("FERRUMGATE_TOKEN")
        .stdin(Stdio::null())
        .output()
        .await?;
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("api-token:ops"), "{stdout}");
    let _ = PathBuf::new();
    Ok(())
}
