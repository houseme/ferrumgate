use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    process::Command,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;

use super::common::*;

const EAB_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[tokio::test]
async fn rejects_invalid_acme_settings_at_config_check() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("private");
    std::fs::create_dir(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    let valid = format!(
        r#"
[acme]
domains = ["app.test"]
email = "ops@app.test"
accept_terms = true
state_dir = "{}"
challenge_listen = "127.0.0.1:0"
"#,
        state.display()
    );
    let routes = route("app.test", "127.0.0.1:8000".parse()?, "/");
    assert!(Gateway::check(directory.path(), &config(&routes, "tls = true", &valid)).await?);
    for rejected in [
        valid.replace("app.test", "*.app.test"),
        valid.replace("accept_terms = true", "accept_terms = false"),
        valid.replace("127.0.0.1:0", "127.0.0.1:8080"),
        format!("{valid}\ndirectory = \"http://ca.test/directory\"\n"),
    ] {
        let text = config(&routes, "tls = true", &rejected).replace(
            "\nlisten = \"127.0.0.1:0\"",
            "\nlisten = \"127.0.0.1:8080\"",
        );
        assert!(!Gateway::check(directory.path(), &text).await?);
    }
    assert!(!Gateway::check(directory.path(), &config(&routes, "", &valid)).await?);
    Ok(())
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_validates_http01_issues_restores_and_renews() -> Result<()> {
    pebble_lifecycle(false).await
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_requires_eab_then_reuses_the_account() -> Result<()> {
    pebble_lifecycle(true).await
}

async fn pebble_lifecycle(eab: bool) -> Result<()> {
    let files = tempfile::tempdir()?;
    let api = free_tcp()?;
    let management = free_tcp()?;
    let challenge = free_tcp()?;
    let dns = UdpSocket::bind("127.0.0.1:0").await?.local_addr()?;
    let ca = Ca::new()?;
    ca.write(files.path())?;
    ca.identity("localhost")?.write(files.path(), "api")?;
    let mut dns_server =
        Command::new(std::env::var_os("FGATE_PEBBLE_DNS").unwrap_or("pebble-challtestsrv".into()))
            .arg("-dnsserver")
            .arg(dns.to_string())
            .arg("-defaultIPv6=")
            .arg("-http01=")
            .arg("-https01=")
            .arg("-tlsalpn01=")
            .arg("-doh=")
            .arg("-management")
            .arg(free_tcp()?.to_string())
            .kill_on_drop(true)
            .spawn()?;
    let pebble_file = files.path().join("pebble.json");
    let eab_key_file = files.path().join("binding.key");
    let eab_registration = if eab {
        std::fs::write(&eab_key_file, format!("{EAB_KEY}\n"))?;
        std::fs::set_permissions(&eab_key_file, std::fs::Permissions::from_mode(0o600))?;
        format!(
            ",\"externalAccountBindingRequired\": true, \"externalAccountMACKeys\": {{\"fixture\": \"{EAB_KEY}\"}}"
        )
    } else {
        String::new()
    };
    std::fs::write(
        &pebble_file,
        format!(
            r#"{{"pebble": {{
        "listenAddress": "{api}",
        "managementListenAddress": "{management}",
        "certificate": "{}",
        "privateKey": "{}",
        "httpPort": {},
        "tlsPort": 5001{eab_registration}
    }}}}"#,
            files.path().join("api.pem").display(),
            files.path().join("api.key").display(),
            challenge.port()
        ),
    )?;
    let mut pebble = Command::new(std::env::var_os("FGATE_PEBBLE").unwrap_or("pebble".into()))
        .arg("-config")
        .arg(&pebble_file)
        .arg("-dnsserver")
        .arg(dns.to_string())
        .env("PEBBLE_VA_NOSLEEP", "1")
        .env("PEBBLE_WFE_NONCEREJECT", "0")
        .env("PEBBLE_AUTHZREUSE", "0")
        .env_remove("PEBBLE_VA_ALWAYS_VALID")
        .kill_on_drop(true)
        .spawn()?;
    wait_listener(management).await?;
    ensure!(
        pebble.try_wait()?.is_none() && dns_server.try_wait()?.is_none(),
        "Pebble processes must remain alive"
    );

    let api_ca = CertificateDer::from_pem_file(files.path().join("ca.pem"))?;
    let trust = connect_tls(management, "localhost", api_ca).await?;
    let (status, bytes) = get(&mut http_client(trust).await?, "localhost", "/roots/0").await?;
    assert_eq!(status, 200);
    let root = CertificateDer::from_pem_slice(&bytes)?;

    let state = files.path().join("state");
    std::fs::create_dir(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    let origin = Origin::http("secured").await?;
    let routes = route("acme.example.test", origin.addr, "/");
    let settings = config(
        &routes,
        "tls = true",
        &format!(
            r#"
[acme]
domains = ["acme.example.test"]
email = "ops@example.test"
accept_terms = true
state_dir = "{}"
directory = "https://localhost:{}/dir"
ca_file = "{}"
challenge_listen = "{challenge}"
"#,
            state.display(),
            api.port(),
            files.path().join("ca.pem").display()
        ),
    );
    let with_binding = if eab {
        let table = format!(
            "\n[acme.eab]\nkey_id = \"fixture\"\nhmac_key_file = \"{}\"\n",
            eab_key_file.display()
        );
        settings.replacen("\n[server]", &(table + "\n[server]"), 1)
    } else {
        settings.clone()
    };
    let mut gateway = Gateway::spawn(&with_binding).await?;
    gateway.wait_log("ACME certificate installed").await?;
    let initial = presented_certificate(gateway.addr, root.clone()).await?;
    let account = std::fs::read(state.join("account.json"))?;
    if eab {
        assert!(!String::from_utf8_lossy(&account).contains(EAB_KEY));
    }
    assert!(
        !Gateway::spawn(&settings).await.is_ok(),
        "shared state directory must be locked"
    );
    let (status, _) = get(
        &mut http_client(connect(challenge).await?).await?,
        "acme.example.test",
        "/.well-known/acme-challenge/not-an-active-token",
    )
    .await?;
    assert_eq!(status, 404);
    gateway.signal("-TERM").await?;
    gateway.wait_exit().await?;

    if eab {
        std::fs::remove_file(&eab_key_file)?;
    }
    let mut restored = Gateway::spawn(&settings).await?;
    assert_eq!(
        presented_certificate(restored.addr, root.clone()).await?,
        initial
    );
    restored.signal("-TERM").await?;
    restored.wait_exit().await?;
    install_near_expiry_fixture(&state.join("identity.pem"))?;

    let mut renewed = Gateway::spawn(&settings).await?;
    renewed.wait_log("ACME certificate installed").await?;
    assert_ne!(presented_certificate(renewed.addr, root).await?, initial);
    assert_eq!(std::fs::read(state.join("account.json"))?, account);
    Ok(())
}

fn free_tcp() -> Result<SocketAddr> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}

async fn wait_listener(addr: SocketAddr) -> Result<()> {
    timeout(DEADLINE, async {
        loop {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("Pebble listener readiness")?;
    Ok(())
}

async fn connect_tls(
    addr: SocketAddr,
    name: &'static str,
    root: CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = RootCertStore::empty();
    roots.add(root)?;
    let client = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(timeout(
        DEADLINE,
        TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from(name)?, connect(addr).await?),
    )
    .await??)
}

async fn presented_certificate(
    addr: SocketAddr,
    root: CertificateDer<'static>,
) -> Result<CertificateDer<'static>> {
    let stream = connect_tls(addr, "acme.example.test", root).await?;
    let certificate = stream.get_ref().1.peer_certificates().unwrap()[0].clone();
    assert_eq!(
        get(&mut http_client(stream).await?, "acme.example.test", "/")
            .await?
            .1,
        "secured"
    );
    Ok(certificate)
}

fn install_near_expiry_fixture(path: &Path) -> Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let mut params = rcgen::CertificateParams::new(vec!["acme.example.test".to_owned()])?;
    params.not_before = now - time::Duration::days(2);
    params.not_after = now + time::Duration::hours(1);
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    std::fs::write(path, format!("{}\n{}", cert.pem(), key.serialize_pem()))?;
    Ok(())
}

#[tokio::test]
async fn validates_private_eab_key_file_before_binding() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let secret = dir.path().join("binding.key");
    let routes = route("app.test", "127.0.0.1:9000".parse()?, "/");
    let settings = config(
        &routes,
        "tls = true",
        &format!(
            r#"
[acme]
domains = ["app.test"]
email = "ops@app.test"
accept_terms = true
state_dir = "{}"

[acme.eab]
key_id = "test"
hmac_key_file = "{}"
"#,
            dir.path().display(),
            secret.display()
        ),
    );
    assert!(!Gateway::check(dir.path(), &settings).await?);
    std::fs::write(&secret, EAB_KEY)?;
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644))?;
    assert!(!Gateway::check(dir.path(), &settings).await?);
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600))?;
    assert!(Gateway::check(dir.path(), &settings).await?);
    std::fs::write(&secret, "short")?;
    assert!(!Gateway::check(dir.path(), &settings).await?);
    Ok(())
}
