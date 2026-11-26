use std::{process::Stdio, time::Duration};

use tokio::process::Command;

use anyhow::Result;
use serde_json::json;

const DEADLINE: Duration = Duration::from_secs(30);

fn rollback_command(dir: &std::path::Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fgate"));
    command
        .arg("rollback")
        .arg("--admin-dir")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn seed_history(
    dir: &std::path::Path,
    name: &str,
) -> Result<std::sync::Arc<fg_config::ConfigStore>> {
    let store = fg_config::ConfigStore::open(dir)?;
    store.enable_history(20, &[]);
    store.save(name, &json!({"step": 1}))?;
    store.save(name, &json!({"step": 2}))?;
    Ok(store)
}

#[tokio::test]
async fn rollback_offline_rewrites_files_and_keeps_history() -> Result<()> {
    let directory = tempfile::tempdir()?;
    // A marker file proves this is a configuration directory.
    std::fs::write(directory.path().join("ferrumgate.json"), "{}\n")?;
    let store = seed_history(directory.path(), "ddns")?;
    let output = rollback_command(directory.path(), &["--last", "--yes"])
        .output()
        .await
        .expect("run fgate rollback");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("已直接改写配置文件"), "{stdout}");
    let mut expected = serde_json::to_vec_pretty(&json!({"step": 1}))?;
    expected.push(b'\n');
    assert_eq!(
        store.load_raw("ddns")?.as_deref(),
        Some(expected.as_slice())
    );
    let versions = store.versions("ddns")?;
    assert_eq!(versions.len(), 1, "the replaced content was archived");
    Ok(())
}

#[tokio::test]
async fn rollback_refuses_foreign_directory() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = rollback_command(directory.path(), &["--last", "--yes"])
        .output()
        .await
        .expect("run fgate rollback");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("不是 FerrumGate 的配置目录"), "{stderr}");
    assert!(
        !directory.path().join("rollback-request.state").exists(),
        "nothing is written into a foreign directory"
    );
    Ok(())
}

#[tokio::test]
async fn rollback_requires_yes_or_a_terminal() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("ferrumgate.json"), "{}\n")?;
    let store = seed_history(directory.path(), "ddns")?;
    let output = rollback_command(directory.path(), &["--last"])
        .output()
        .await
        .expect("run fgate rollback");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("已取消"), "{stdout}");
    let mut current = serde_json::to_vec_pretty(&json!({"step": 2}))?;
    current.push(b'\n');
    assert_eq!(
        store
            .load_raw("ddns")?
            .as_deref()
            .map(|bytes| bytes.to_vec()),
        Some(current),
        "nothing changed without confirmation"
    );
    assert!(!directory.path().join("rollback-request.state").exists());
    Ok(())
}

#[tokio::test]
async fn rollback_delegates_to_running_instance() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let accounts = directory.path().join("accounts");
    let config_path = directory.path().join("gateway.toml");
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        store.enable_history(20, &[]);
        store.save("ferrumgate", &json!({"language":"en"}))?;
        store.save("ferrumgate", &json!({"language":"zh"}))?;
    }
    // A dummy peer so the data-plane configuration has one valid route.
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
    tokio::time::timeout(DEADLINE, async {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut lines = BufReader::new(&mut stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains("management ready") {
                return Ok::<(), anyhow::Error>(());
            }
        }
        anyhow::bail!("management listener did not start")
    })
    .await??;

    let output = tokio::time::timeout(
        DEADLINE,
        rollback_command(&accounts, &["--last", "--yes"]).output(),
    )
    .await??;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("已交给运行中的实例处理"), "{stdout}");

    let reverted = tokio::time::timeout(DEADLINE, async {
        loop {
            let store = fg_config::ConfigStore::open(&accounts)?;
            if let Some(bytes) = store.load_raw("ferrumgate")? {
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                if value["language"] == "en" {
                    return Ok::<_, anyhow::Error>(());
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    assert!(
        reverted.is_ok(),
        "the running instance applied the rollback"
    );

    let id = child.id().expect("gateway PID");
    nix_kill(id).await?;
    let _ = tokio::time::timeout(DEADLINE, child.wait()).await?;
    Ok(())
}

#[cfg(unix)]
async fn nix_kill(id: u32) -> Result<()> {
    let status = Command::new("kill")
        .args(["-INT", &id.to_string()])
        .status()
        .await?;
    anyhow::ensure!(status.success(), "SIGINT the gateway");
    Ok(())
}

#[cfg(not(unix))]
async fn nix_kill(_id: u32) -> Result<()> {
    Ok(())
}

#[tokio::test]
async fn unconfirmed_save_restores_on_next_start() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let accounts = directory.path().join("accounts");
    let config_path = directory.path().join("gateway.toml");
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
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        store.enable_history(20, &[]);
        store.save("ferrumgate", &json!({"language":"en"}))?;
    }
    // Forge a pending-confirm state whose deadline already passed, as if a
    // save went unconfirmed and the process died before rolling back.
    let expired = fg_config::confirm::PendingConfirm {
        id: "fixture000000000001".to_owned(),
        created: time::OffsetDateTime::now_utc().into(),
        deadline: std::time::SystemTime::now() - std::time::Duration::from_secs(5),
        timeout: 90,
        wait_restart: false,
        rollback: false,
        hold: false,
        applied: std::time::SystemTime::now(),
        errors: Vec::new(),
        boots: 0,
        files: std::collections::BTreeMap::from([(
            "ferrumgate".to_owned(),
            Some("{\"language\":\"zh\"}\n".to_owned()),
        )]),
    };
    fg_config::confirm::write_state(&accounts, &expired)?;
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
    tokio::time::timeout(DEADLINE, async {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut lines = BufReader::new(&mut stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains("management ready") {
                return Ok::<(), anyhow::Error>(());
            }
        }
        anyhow::bail!("management listener did not start")
    })
    .await??;
    // The rollback already happened before the listener came up.
    let store = fg_config::ConfigStore::open(&accounts)?;
    let raw = store.load_raw("ferrumgate")?.expect("restored settings");
    let value: serde_json::Value = serde_json::from_slice(&raw)?;
    assert_eq!(value["language"], "zh", "the pre-save content won");
    assert!(
        !accounts.join("pending-confirm.state").exists(),
        "state removed after rollback"
    );
    let id = child.id().expect("gateway PID");
    nix_kill(id).await?;
    let _ = tokio::time::timeout(DEADLINE, child.wait()).await?;
    Ok(())
}
