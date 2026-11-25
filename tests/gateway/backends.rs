use anyhow::Result;

use super::common::*;

fn backend(port: u16, weight: u16, backup: bool) -> String {
    format!(
        "\n[[routes.backends]]\nupstream = \"http://127.0.0.1:{port}\"\nweight = {weight}\nbackup = {backup}\n"
    )
}

#[tokio::test]
async fn selects_weighted_backends_and_switches_after_connect_failures() -> Result<()> {
    let a = Origin::http("a").await?;
    let b = Origin::http("b").await?;
    let dead = std::net::TcpListener::bind("127.0.0.1:0")?;
    let dead_port = dead.local_addr()?.port();
    drop(dead);
    let routes = "\n[[routes]]\nhost = \"app.test\"\n".to_owned()
        + &backend(a.addr.port(), 2, false)
        + &backend(b.addr.port(), 1, false)
        + "\n[[routes]]\nhost = \"app.test\"\npath_prefix = \"/backup\"\n"
        + &backend(dead_port, 1, false)
        + &backend(b.addr.port(), 1, true);
    let gateway = Gateway::spawn(&config(&routes, "", "")).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    let mut hits = [0, 0];
    for _ in 0..9 {
        let (status, body) = get(&mut client, "app.test", "/").await?;
        assert_eq!(status, 200);
        match body.as_ref() {
            b"a" => hits[0] += 1,
            b"b" => hits[1] += 1,
            body => panic!("unexpected backend: {body:?}"),
        }
    }
    assert_eq!(hits, [6, 3]);
    for _ in 0..3 {
        assert_eq!(get(&mut client, "app.test", "/backup").await?.0, 502);
    }
    let (status, content) = get(&mut client, "app.test", "/backup").await?;
    assert_eq!(status, 200);
    assert_eq!(content, "b");
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_backend_pools() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let base = "\n[[routes]]\nhost = \"app.test\"\n";
    for invalid in [
        base.to_owned(),
        base.to_owned() + &backend(9001, 0, false),
        base.to_owned() + &backend(9001, 1, true),
        base.to_owned() + &backend(9001, 1, false).repeat(2),
        base.to_owned() + "upstream = \"http://127.0.0.1:9001\"\n" + &backend(9002, 1, false),
    ] {
        assert!(
            !Gateway::check(dir.path(), &config(&invalid, "", "")).await?,
            "{invalid}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn active_http_checks_fail_over_and_recover_after_the_configured_streak() -> Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
    };

    let is_healthy = Arc::new(AtomicBool::new(false));
    let passed = Arc::new(tokio::sync::Notify::new());
    let primary = Origin::spawn({
        let (is_healthy, passed) = (is_healthy.clone(), passed.clone());
        move |socket| {
            let (is_healthy, passed) = (is_healthy.clone(), passed.clone());
            async move {
                serve_http(socket, move |request| {
                    let passed = passed.clone();
                    let healthy = is_healthy.load(Relaxed);
                    async move {
                        if request.uri().path() == "/ready" {
                            assert_eq!(request.uri().query(), Some("probe=1"));
                            assert!(!request.headers().contains_key("x-forwarded-for"));
                            if healthy {
                                passed.notify_one();
                                hyper::Response::builder()
                                    .status(204)
                                    .body(full(""))
                                    .unwrap()
                            } else {
                                hyper::Response::builder()
                                    .status(503)
                                    .body(full(""))
                                    .unwrap()
                            }
                        } else {
                            response("primary")
                        }
                    }
                })
                .await
            }
        }
    })
    .await?;
    let standby = Origin::http("standby").await?;
    let routes = "\n[[routes]]\nhost = \"app.test\"\n".to_owned()
        + "[routes.health]\npath = \"/ready?probe=1\"\ninterval_secs = 1\nfails = 1\npasses = 2\n"
        + &backend(primary.addr.port(), 1, false)
        + &backend(standby.addr.port(), 1, true);
    let mut gateway = Gateway::spawn(&config(&routes, "", "")).await?;
    gateway.wait_log("upstream unavailable").await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    assert_eq!(get(&mut client, "app.test", "/").await?.1, "standby");

    is_healthy.store(true, Relaxed);
    tokio::time::timeout(DEADLINE, passed.notified()).await?;
    assert_eq!(get(&mut client, "app.test", "/").await?.1, "standby");
    gateway.wait_log("upstream recovered").await?;
    assert_eq!(get(&mut client, "app.test", "/").await?.1, "primary");
    Ok(())
}

#[tokio::test]
async fn active_tcp_check_can_disable_a_single_backend() -> Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let routes = route("app.test", address, "/")
        + "[routes.health]\nmode = \"tcp\"\ninterval_secs = 1\ntimeout_secs = 1\nfails = 1\n";
    let mut gateway = Gateway::spawn(&config(&routes, "", "")).await?;
    gateway.wait_log("upstream unavailable").await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    assert_eq!(get(&mut client, "app.test", "/").await?.0, 503);
    assert!(
        !Gateway::check(
            gateway.dir.path(),
            &config(&(routes + "path = \"/ignored\"\n"), "", "")
        )
        .await?
    );
    Ok(())
}
