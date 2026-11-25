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

#[tokio::test]
async fn selects_wildcard_certificate_and_prefers_exact_sni() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let ca = Ca::new()?;
    let wildcard = ca.identity("*.example.test")?;
    let exact = ca.identity("app.example.test")?;
    wildcard.write(dir.path(), "wildcard")?;
    exact.write(dir.path(), "exact")?;
    let backend = Origin::http("covered").await?;
    let routes = route("*.example.test", backend.addr, "/")
        + &route("strict.example.test", backend.addr, "/")
        + &certificate("*.example.test", "wildcard")
        + &certificate("app.example.test", "exact");
    let settings = config(&routes, "tls = true", "");
    assert!(
        !Gateway::check(
            dir.path(),
            &settings
                .replace("wildcard.pem", "exact.pem")
                .replace("wildcard.key", "exact.key")
        )
        .await?
    );
    let gateway = Gateway::with_dir(&settings, dir).await?;
    for (host, certificate) in [
        ("app.example.test", &exact.cert),
        ("other.example.test", &wildcard.cert),
        ("strict.example.test", &wildcard.cert),
    ] {
        let stream = ca.connect(gateway.addr, host, b"http/1.1").await?;
        assert_eq!(
            stream.get_ref().1.peer_certificates().unwrap()[0],
            *certificate.der()
        );
        assert_eq!(
            get(&mut http_client(stream).await?, host, "/").await?.1,
            "covered"
        );
    }
    assert!(
        ca.connect(gateway.addr, "two.deep.example.test", b"http/1.1")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn ip_tls_uses_the_local_listener_address_and_restricts_http_authority() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let ca = Ca::new()?;
    let local = ca.identity("127.0.0.1")?;
    let unrelated = ca.identity("10.0.0.1")?;
    local.write(dir.path(), "local")?;
    unrelated.write(dir.path(), "unrelated")?;
    let backend = Origin::spawn(|socket| async move {
        serve_http(socket, |request| async move {
            assert_eq!(request.headers()["x-forwarded-proto"], "https");
            response("IP TLS")
        })
        .await
    })
    .await?;
    let routes = route("127.0.0.1", backend.addr, "/")
        + &route("10.0.0.1", backend.addr, "/")
        + &certificate("127.0.0.1", "local")
        + &certificate("10.0.0.1", "unrelated");
    let settings = config(&routes, "tls = true", "");
    let missing = settings
        .replace("local.pem", "unrelated.pem")
        .replace("local.key", "unrelated.key");
    assert!(!Gateway::check(dir.path(), &missing).await?);

    let gateway = Gateway::with_dir(&settings, dir).await?;
    let stream = ca.connect(gateway.addr, "127.0.0.1", b"http/1.1").await?;
    assert_eq!(
        stream.get_ref().1.peer_certificates().unwrap()[0],
        *local.cert.der()
    );
    let mut client = http_client(stream).await?;
    assert_eq!(get(&mut client, "127.0.0.1", "/").await?.1, "IP TLS");
    assert_eq!(get(&mut client, "10.0.0.1", "/").await?.0, 421);
    Ok(())
}

#[tokio::test]
async fn ip_tls_uses_latest_expiring_certificate_when_no_local_ip_matches() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let ca = Ca::new()?;
    let mut earlier = rcgen::CertificateParams::new(vec!["192.0.2.1".to_owned()])?;
    earlier.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
    ca.identity_with_params(earlier)?
        .write(dir.path(), "earlier")?;
    let latest = ca.identity("2001:db8::1")?;
    latest.write(dir.path(), "latest")?;
    let origin = Origin::http("fallback").await?;
    let routes = route("192.0.2.1", origin.addr, "/")
        + &route("2001:db8::1", origin.addr, "/")
        + &certificate("192.0.2.1", "earlier")
        + &certificate("[2001:db8::1]", "latest");
    let gateway = Gateway::with_dir(&config(&routes, "tls = true", ""), dir).await?;
    let stream = ca.connect(gateway.addr, "2001:db8::1", b"http/1.1").await?;
    assert_eq!(
        stream.get_ref().1.peer_certificates().unwrap()[0],
        *latest.cert.der()
    );
    assert_eq!(
        get(&mut http_client(stream).await?, "[2001:db8::1]", "/")
            .await?
            .1,
        "fallback"
    );
    Ok(())
}
