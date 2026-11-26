use anyhow::Result;

use super::common::*;

#[cfg(unix)]
#[tokio::test]
async fn fgate_persists_and_restores_runtime_logs_across_restart() -> Result<()> {
    use std::ffi::OsStr;

    let backend = Origin::http("logging smoke test").await?;
    let log_root = tempfile::tempdir()?;
    let logs = log_root.path().join("logs");
    let args = [OsStr::new("--log-dir"), logs.as_os_str()];
    let routes = format!(
        "[[routes]]\nhost = 'app.test'\nupstream = 'http://{}'\n",
        backend.addr
    );
    let config = config(&routes, "", "");
    let mut last_seq = 0;
    for _ in 0..2 {
        let mut gateway = Gateway::with_args(&config, tempfile::tempdir()?, &args).await?;
        let mut client = http_client(connect(gateway.addr).await?).await?;
        assert_eq!(
            get(&mut client, "app.test", "/").await?.1,
            "logging smoke test"
        );
        drop(client);
        gateway.signal("-INT").await?;
        gateway.wait_exit().await?;
        let file = std::fs::read_to_string(logs.join("gately.log"))?;
        let entries: Vec<fg_logging::Entry> = file
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        let newer: Vec<_> = entries
            .iter()
            .filter(|entry| entry.seq > last_seq)
            .collect();
        assert!(newer.iter().any(|entry| entry.message == "gateway ready"));
        assert!(
            newer
                .iter()
                .any(|entry| entry.message == "gateway draining connections")
        );
        assert!(entries.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        last_seq = entries.last().unwrap().seq;
    }
    Ok(())
}

#[tokio::test]
async fn fgate_rejects_a_static_root_that_contains_the_log_directory() -> Result<()> {
    let assets = tempfile::tempdir()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("fgate.toml");
    let routes = format!(
        "[[routes]]\nhost = 'app.test'\n[routes.response]\ntype = 'static'\nroot = '{}'\n",
        assets.path().display()
    );
    std::fs::write(&config_path, config(&routes, "", ""))?;
    let result = tokio::time::timeout(
        DEADLINE,
        tokio::process::Command::new(env!("CARGO_BIN_EXE_fgate"))
            .args(["serve", "--config"])
            .arg(config_path)
            .arg("--log-dir")
            .arg(assets.path().join("logs"))
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    assert!(!result.status.success());
    let error = String::from_utf8(result.stderr)?;
    assert!(
        error.contains("protected configuration directory"),
        "{error}"
    );
    Ok(())
}
