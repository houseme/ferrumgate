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
