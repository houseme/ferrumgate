use anyhow::Result;
use tokio::{net::TcpListener, process::Command, time::timeout};

use super::{common::*, tcp::forwarding};

#[tokio::test]
async fn disabled_forwarding_leaves_its_listener_unused_and_web_serves() -> Result<()> {
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let upstream = Origin::http("web stays active").await?;
    let routes = format!(
        "[[routes]]\nhost = 'app.test'\nupstream = 'http://{}'\n",
        upstream.addr
    ) + &forwarding(&occupied.local_addr()?.to_string(), &[upstream.addr], "");
    let switches = "disabled_modules = ['portforward', 'waf']";
    let manifest = config(&routes, "", switches);
    let gateway = Gateway::spawn(&manifest).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    assert_eq!(
        get(&mut client, "app.test", "/").await?.1,
        "web stays active"
    );

    assert!(Gateway::check(gateway.dir.path(), &manifest).await?);
    assert!(
        !Gateway::check(
            gateway.dir.path(),
            &config(&routes, "", "disabled_modules = ['ssl']")
        )
        .await?
    );
    assert!(
        !Gateway::check(
            gateway.dir.path(),
            &config(&routes, "", "disabled_modules = ['unknown']")
        )
        .await?
    );

    #[cfg(unix)]
    {
        let mut gateway = gateway;
        gateway.replace(&config(&routes, "", "disabled_modules = ['waf']"))?;
        gateway.signal("-HUP").await?;
        let rejected = gateway.wait_log("configuration reload rejected").await?;
        assert!(rejected.contains("require restart"));
        assert_eq!(
            get(&mut client, "app.test", "/").await?.1,
            "web stays active"
        );
    }
    Ok(())
}

#[tokio::test]
async fn listener_preparation_failure_exits_without_starting_the_other_modules() -> Result<()> {
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("fgate.toml");
    let target = "127.0.0.1:9000".parse()?;
    let routes = "[[routes]]\nhost = 'app.test'\nupstream = 'http://127.0.0.1:9000'\n".to_owned()
        + &forwarding(&occupied.local_addr()?.to_string(), &[target], "");
    std::fs::write(&config_path, config(&routes, "", ""))?;
    let result = timeout(
        DEADLINE,
        Command::new(env!("CARGO_BIN_EXE_fgate"))
            .args(["serve", "--config"])
            .arg(config_path)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr)?;
    assert!(stderr.contains("prepare portforward"), "{stderr}");
    assert!(!stderr.contains("gateway ready"), "{stderr}");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn sigint_enforces_one_deadline_for_in_flight_connections() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = Origin::spawn(|mut socket| async move {
        socket.write_all(b"ready").await?;
        std::future::pending::<Result<()>>().await
    })
    .await?;
    let rule = forwarding("127.0.0.1:0", &[upstream.addr], "");
    let mut gateway = Gateway::spawn(&config(
        &rule,
        "http_enabled = false\nshutdown_timeout_ms = 150",
        "",
    ))
    .await?;
    let mut stream = connect(gateway.addr).await?;
    let mut ready = [0; 5];
    timeout(DEADLINE, stream.read_exact(&mut ready)).await??;
    assert_eq!(&ready, b"ready");
    gateway.signal("-INT").await?;
    gateway.wait_log("drain deadline expired").await?;
    gateway.wait_exit().await?;
    assert_eq!(timeout(DEADLINE, stream.read(&mut ready)).await??, 0);
    Ok(())
}
