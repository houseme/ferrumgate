use anyhow::Result;
use hyper::{Method, body::Bytes};

use super::common::*;

#[tokio::test]
async fn validates_tls_sni_origin_identity_and_trust() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let ca = Ca::new()?;
    ca.write(dir.path())?;
    ca.identity("app.test")?.write(dir.path(), "app")?;
    ca.identity("site2.test")?.write(dir.path(), "site2")?;
    let backend = Origin::spawn({
        let acceptor = ca.identity("localhost")?.acceptor(b"http/1.1")?;
        move |socket| {
            let acceptor = acceptor.clone();
            async move {
                let stream = acceptor.accept(socket).await?;
                serve_http(stream, |request| async move {
                    assert_eq!(request.headers()["x-forwarded-proto"], "https");
                    response("secure")
                })
                .await
            }
        }
    })
    .await?;
    let routes = format!(
        "\n[[routes]]\nhost = \"app.test\"\nupstream = \"https://localhost:{}\"\n",
        backend.addr.port()
    ) + &route("site2.test", backend.addr, "/").replace("http://", "https://")
        + &certificate("app.test", "app")
        + &certificate("site2.test", "site2");
    let gateway = Gateway::with_dir(
        &config(&routes, "tls = true", "upstream_ca_file = \"ca.pem\""),
        dir,
    )
    .await?;
    let mut good = http_client(ca.connect(gateway.addr, "app.test", b"http/1.1").await?).await?;
    assert_eq!(get(&mut good, "app.test", "/").await?.1, "secure");
    assert_eq!(get(&mut good, "site2.test", "/").await?.0, 421);
    let mut wrong_origin =
        http_client(ca.connect(gateway.addr, "site2.test", b"http/1.1").await?).await?;
    assert_eq!(get(&mut wrong_origin, "site2.test", "/").await?.0, 502);
    assert!(
        ca.connect(gateway.addr, "unknown.test", b"http/1.1")
            .await
            .is_err()
    );

    let head = send(
        &mut good,
        request(Method::HEAD, "/", "app.test", full(Bytes::new())),
    )
    .await?;
    assert_eq!(head.status(), 200);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn rotates_leaf_and_rejects_mismatched_key() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let ca = Ca::new()?;
    let original = ca.identity("app.test")?;
    let next = ca.identity("app.test")?;
    original.write(dir.path(), "original")?;
    next.write(dir.path(), "next")?;
    let backend = Origin::http("ok").await?;
    let route = route("app.test", backend.addr, "/");
    let settings = |certificate: String| config(&(route.clone() + &certificate), "tls = true", "");
    let mut gateway =
        Gateway::with_dir(&settings(certificate("app.test", "original")), dir).await?;
    let before = ca.connect(gateway.addr, "app.test", b"http/1.1").await?;
    assert_eq!(
        before.get_ref().1.peer_certificates().unwrap()[0],
        *original.cert.der()
    );
    gateway.replace(&settings(
        certificate("app.test", "next").replace("next.key", "original.key"),
    ))?;
    gateway.signal("-HUP").await?;
    gateway.wait_log("configuration reload rejected").await?;
    let unchanged = ca.connect(gateway.addr, "app.test", b"http/1.1").await?;
    assert_eq!(
        unchanged.get_ref().1.peer_certificates().unwrap()[0],
        *original.cert.der()
    );
    gateway.replace(&settings(certificate("app.test", "next")))?;
    gateway.signal("-HUP").await?;
    gateway.wait_log("configuration reloaded").await?;
    let rotated = ca.connect(gateway.addr, "app.test", b"http/1.1").await?;
    assert_eq!(
        rotated.get_ref().1.peer_certificates().unwrap()[0],
        *next.cert.der()
    );
    Ok(())
}
