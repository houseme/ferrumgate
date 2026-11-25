use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use http_body_util::BodyExt;
use hyper::{Method, Response, body::Incoming};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use tokio::sync::{Mutex, Notify};
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
        format!("{valid}\nprofile = \"invalid name\"\n"),
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
    pebble_lifecycle(false, false).await
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_requires_eab_then_reuses_the_account() -> Result<()> {
    pebble_lifecycle(true, false).await
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_switches_from_default_to_short_lived_profile() -> Result<()> {
    pebble_lifecycle(false, true).await
}

async fn pebble_lifecycle(eab: bool, switch_profile: bool) -> Result<()> {
    let Pebble {
        files,
        api,
        challenge,
        root,
        eab_key_file,
        _pebble,
        _dns_server,
        ..
    } = pebble(eab).await?;

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
    let renewed_settings = if switch_profile {
        settings.replacen("\n[acme]\n", "\n[acme]\nprofile = \"shortlived\"\n", 1)
    } else {
        install_near_expiry_fixture(&state.join("identity.pem"))?;
        settings
    };

    let mut renewed = Gateway::spawn(&renewed_settings).await?;
    renewed.wait_log("ACME certificate installed").await?;
    let updated = presented_certificate(renewed.addr, root.clone()).await?;
    assert_ne!(updated, initial);
    assert_eq!(std::fs::read(state.join("account.json"))?, account);
    if switch_profile {
        use x509_parser::prelude::{FromDer, X509Certificate};
        let (_, leaf) = X509Certificate::from_der(updated.as_ref())
            .map_err(|_| anyhow::anyhow!("read short-lived certificate"))?;
        let lifetime =
            leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp();
        assert!(
            lifetime.abs_diff(6 * 24 * 3600) <= 2,
            "expected a six-day certificate, got {lifetime} seconds"
        );
        renewed.signal("-TERM").await?;
        renewed.wait_exit().await?;
        let gateway = Gateway::spawn(&renewed_settings).await?;
        assert_eq!(presented_certificate(gateway.addr, root).await?, updated);
    }
    Ok(())
}

struct Pebble {
    files: tempfile::TempDir,
    api: SocketAddr,
    dns: SocketAddr,
    dns_admin: SocketAddr,
    challenge: SocketAddr,
    root: CertificateDer<'static>,
    eab_key_file: std::path::PathBuf,
    _pebble: tokio::process::Child,
    _dns_server: tokio::process::Child,
}

async fn pebble(eab: bool) -> Result<Pebble> {
    let files = tempfile::tempdir()?;
    let api = free_tcp()?;
    let management = free_tcp()?;
    let challenge = free_tcp()?;
    let dns = UdpSocket::bind("127.0.0.1:0").await?.local_addr()?;
    let ca = Ca::new()?;
    ca.write(files.path())?;
    ca.identity("localhost")?.write(files.path(), "api")?;
    let dns_admin = free_tcp()?;
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
            .arg(dns_admin.to_string())
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
        "tlsPort": 5001,
        "profiles": {{
            "default": {{"description":"standard", "validityPeriod":7776000}},
            "shortlived": {{"description":"short-lived", "validityPeriod":518400}}
        }}{eab_registration}
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

    wait_listener(dns_admin).await?;
    Ok(Pebble {
        files,
        api,
        dns,
        dns_admin,
        challenge,
        root,
        eab_key_file,
        _pebble: pebble,
        _dns_server: dns_server,
    })
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

const CF_ZONE: &str = "11111111111111111111111111111111";
const ACTUAL_RECORD: &str = "22222222222222222222222222222222";
const ORPHAN_RECORD: &str = "33333333333333333333333333333333";
const FOREIGN_RECORD: &str = "44444444444444444444444444444444";
const DNS_HOST: &str = "_acme-challenge.example.test";
const ORPHAN_TAG: &str = "ferrumgate-AAAAAAAAAAAAAAAAAAAAAA";
static TOKEN: &str = "cloudflare-fixture";

struct CloudflareFixture {
    records: Mutex<Vec<Value>>,
    refuse_delete: AtomicBool,
    retired_new_record: Notify,
    dns_admin: SocketAddr,
    owner: &'static str,
    zone_name: &'static str,
    zone_reads: AtomicUsize,
}

impl CloudflareFixture {
    async fn handle(&self, request: hyper::Request<Incoming>) -> Result<Response<TestBody>> {
        let (head, body) = request.into_parts();
        assert_eq!(head.headers["authorization"], format!("Bearer {TOKEN}"));
        if head.method == Method::GET && head.uri.path() == "/client/v4/zones" {
            assert_eq!(
                head.uri.query(),
                Some(format!("name={}&status=active&per_page=50", self.zone_name).as_str())
            );
            self.zone_reads.fetch_add(1, Relaxed);
            return Ok(cf_response(
                200,
                json!([{"id": CF_ZONE, "name": self.zone_name, "status": "active"}]),
            ));
        }
        let expected = format!("/client/v4/zones/{CF_ZONE}/dns_records");
        let suffix = head
            .uri
            .path()
            .strip_prefix(&expected)
            .expect("provider endpoint");
        match (head.method, suffix) {
            (Method::POST, "") => {
                let bytes = body.collect().await?.to_bytes();
                let mut record: Value = serde_json::from_slice(&bytes)?;
                assert_eq!(record["type"], "TXT");
                assert_eq!(record["name"], self.owner);
                assert!(
                    record["comment"]
                        .as_str()
                        .unwrap()
                        .starts_with("ferrumgate-")
                );
                dns_admin(
                    self.dns_admin,
                    "/set-txt",
                    json!({
                        "host": format!("{}.", self.owner),
                        "value": record["content"],
                    }),
                )
                .await?;
                record["id"] = Value::String(ACTUAL_RECORD.into());
                self.records.lock().await.push(record.clone());
                Ok(cf_response(200, record))
            }
            (Method::GET, "") => {
                let query = head.uri.query().context("record list query")?;
                assert!(query.contains(&format!("name.exact={}", self.owner)));
                assert!(query.contains(&format!("comment.exact={ORPHAN_TAG}")));
                Ok(cf_response(
                    200,
                    Value::Array(self.records.lock().await.clone()),
                ))
            }
            (Method::GET, suffix) => {
                let id = suffix.strip_prefix('/').context("read record ID")?;
                let records = self.records.lock().await;
                let record = records.iter().find(|record| record["id"] == id);
                Ok(match record {
                    Some(record) => cf_response(200, record.clone()),
                    None => cf_response(404, Value::Null),
                })
            }
            (Method::DELETE, suffix) => {
                let id = suffix.strip_prefix('/').context("delete record ID")?;
                assert_ne!(id, FOREIGN_RECORD, "only owned records may be removed");
                if id == ACTUAL_RECORD && self.refuse_delete.swap(false, Relaxed) {
                    return Ok(cf_response(502, Value::Null));
                }
                dns_admin(
                    self.dns_admin,
                    "/clear-txt",
                    json!({"host": format!("{}.", self.owner)}),
                )
                .await?;
                self.records
                    .lock()
                    .await
                    .retain(|record| record["id"] != id);
                if id == ACTUAL_RECORD {
                    self.retired_new_record.notify_one();
                }
                Ok(cf_response(200, json!({"id": id})))
            }
            _ => Ok(cf_response(400, Value::Null)),
        }
    }
}

fn cf_response(status: u16, data: Value) -> Response<TestBody> {
    Response::builder()
        .status(status)
        .body(full(
            json!({"success": status == 200, "result": data}).to_string(),
        ))
        .unwrap()
}

async fn dns_admin(address: SocketAddr, path: &str, payload: Value) -> Result<()> {
    let mut client = http_client(connect(address).await?).await?;
    let result = send(
        &mut client,
        request(Method::POST, path, "localhost", full(payload.to_string())),
    )
    .await?;
    ensure!(
        result.status().is_success(),
        "Pebble challenge service request failed"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_dns01_issues_a_wildcard_and_recovers_failed_provider_cleanup() -> Result<()> {
    pebble_dns01_lifecycle(false, false).await
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_dns01_follows_cross_zone_cname_and_cleans_the_original_target() -> Result<()> {
    pebble_dns01_lifecycle(true, false).await
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_dns01_discovers_the_soa_zone_after_cname() -> Result<()> {
    pebble_dns01_lifecycle(true, true).await
}

async fn pebble_dns01_lifecycle(delegated: bool, automatic: bool) -> Result<()> {
    let pebble = pebble(false).await?;
    let (zone, owner) = match (delegated, automatic) {
        (true, true) => ("sub.validation.test", "proof.sub.validation.test"),
        (true, false) => ("validation.test", "proof.validation.test"),
        _ => ("example.test", DNS_HOST),
    };
    if delegated {
        dns_admin(
            pebble.dns_admin,
            "/set-cname",
            json!({
                "host": format!("{DNS_HOST}."), "target": format!("{owner}."),
            }),
        )
        .await?;
    }
    let resolver = if automatic {
        dns_with_soa(pebble.dns, zone).await?
    } else {
        pebble.dns
    };
    let ca = Ca::new()?;
    let acceptor = ca.identity("localhost")?.acceptor(b"http/1.1")?;
    let cf_ca = pebble.files.path().join("provider");
    std::fs::create_dir(&cf_ca)?;
    ca.write(&cf_ca)?;
    let foreign = json!({
        "id": FOREIGN_RECORD, "type": "TXT", "name": owner,
        "content": "preserved", "comment": "external",
    });
    let orphan = json!({
        "id": ORPHAN_RECORD, "type": "TXT", "name": owner,
        "content": "previous-proof", "comment": ORPHAN_TAG,
    });
    let provider = Arc::new(CloudflareFixture {
        records: Mutex::new(vec![foreign, orphan]),
        refuse_delete: AtomicBool::new(true),
        retired_new_record: Notify::new(),
        dns_admin: pebble.dns_admin,
        owner,
        zone_name: zone,
        zone_reads: AtomicUsize::new(0),
    });
    let cloudflare = Origin::spawn({
        let provider = provider.clone();
        move |socket| {
            let (provider, acceptor) = (provider.clone(), acceptor.clone());
            async move {
                let socket = acceptor.accept(socket).await?;
                serve_http(socket, move |request| {
                    let provider = provider.clone();
                    async move {
                        provider
                            .handle(request)
                            .await
                            .expect("Cloudflare fixture request")
                    }
                })
                .await
            }
        }
    })
    .await?;
    let api_base = format!("https://localhost:{}/client/v4", cloudflare.addr.port());

    let state = pebble.files.path().join("state");
    std::fs::create_dir(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    let journal = state.join("dns-cleanup.json");
    std::fs::write(
        &journal,
        json!({
            "zone_id": CF_ZONE, "api_base": api_base,
            "records": [{"name": owner, "content": "previous-proof", "comment": ORPHAN_TAG,
                "record_id": null, "created_at": 1,
                "zone": automatic.then(|| json!({"id": CF_ZONE, "name": zone}))}],
        })
        .to_string(),
    )?;
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600))?;

    let token_file = cf_ca.join("token");
    std::fs::write(&token_file, TOKEN)?;
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))?;
    let origin = Origin::http("secured").await?;
    let zone_fields = if automatic {
        String::new()
    } else {
        format!("zone = \"{zone}\"\nzone_id = \"{CF_ZONE}\"")
    };
    let settings = config(
        &route("acme.example.test", origin.addr, "/"),
        "tls = true",
        &format!(
            r#"
[acme]
domains = ["*.example.test"]
email = "ops@example.test"
accept_terms = true
state_dir = "{}"
directory = "https://localhost:{}/dir"
ca_file = "{}"

[acme.dns01]
{zone_fields}
token_file = "{}"
api_base = "{api_base}"
api_ca_file = "{}"
resolver = "{}"
propagation_timeout_secs = 10
"#,
            state.display(),
            pebble.api.port(),
            pebble.files.path().join("ca.pem").display(),
            token_file.display(),
            cf_ca.join("ca.pem").display(),
            resolver
        ),
    );
    if !automatic {
        let missing_id = settings.replace(&format!("zone_id = \"{CF_ZONE}\""), "");
        assert!(!Gateway::check(pebble.files.path(), &missing_id).await?);
        let legacy_to_auto = settings.replace(&zone_fields, "");
        assert!(!Gateway::check(pebble.files.path(), &legacy_to_auto).await?);
    }
    if delegated && !automatic {
        let overridden = settings.replace("[acme.dns01]", "[acme.dns01]\nfollow_cname = false");
        assert!(!Gateway::check(pebble.files.path(), &overridden).await?);
    }
    let mut gateway = Gateway::spawn(&settings).await?;
    gateway.wait_log("ACME certificate installed").await?;
    let issued = presented_certificate(gateway.addr, pebble.root.clone()).await?;
    gateway.wait_log("ACME DNS cleanup will retry").await?;
    assert!(
        !provider
            .records
            .lock()
            .await
            .iter()
            .any(|record| record["id"] == ORPHAN_RECORD)
    );
    assert!(std::fs::read_to_string(&journal)?.contains(ACTUAL_RECORD));
    gateway.signal("-TERM").await?;
    gateway.wait_exit().await?;

    if delegated {
        dns_admin(
            pebble.dns_admin,
            "/set-cname",
            json!({"host": format!("{DNS_HOST}."), "target": "moved.validation.test."}),
        )
        .await?;
    }
    let mut restored = Gateway::spawn(&settings).await?;
    assert_eq!(
        presented_certificate(restored.addr, pebble.root.clone()).await?,
        issued
    );
    timeout(DEADLINE, provider.retired_new_record.notified()).await?;
    timeout(DEADLINE, async {
        loop {
            let current: Value = serde_json::from_slice(&std::fs::read(&journal)?)?;
            if current["records"] == json!([]) {
                break Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    restored.signal("-TERM").await?;
    restored.wait_exit().await?;
    let files = std::fs::read(&journal)?;
    assert_eq!(
        serde_json::from_slice::<Value>(&files)?["records"],
        json!([])
    );
    let records = provider.records.lock().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["id"], FOREIGN_RECORD);
    assert_eq!(provider.zone_reads.load(Relaxed), usize::from(automatic));
    Ok(())
}

async fn dns_with_soa(upstream: SocketAddr, zone: &str) -> Result<SocketAddr> {
    use hickory_proto::{
        op::{Message, OpCode},
        rr::{Name, RData, Record, RecordType, rdata::SOA},
    };
    let incoming = UdpSocket::bind("127.0.0.1:0").await?;
    let address = incoming.local_addr()?;
    let outgoing = UdpSocket::bind("127.0.0.1:0").await?;
    outgoing.connect(upstream).await?;
    let zone = Name::from_ascii(format!("{zone}."))?;
    tokio::spawn(async move {
        let mut request = [0; 4096];
        let mut answer = [0; 4096];
        while let Ok((length, peer)) = incoming.recv_from(&mut request).await {
            let message = Message::from_vec(&request[..length])?;
            if message.queries[0].query_type == RecordType::SOA {
                let mut response = Message::response(message.metadata.id, OpCode::Query);
                response.metadata.recursion_available = true;
                response.metadata.authoritative = true;
                response.queries = message.queries;
                response.authorities.push(Record::from_rdata(
                    zone.clone(),
                    10,
                    RData::SOA(SOA::new(zone.clone(), zone.clone(), 1, 60, 60, 60, 10)),
                ));
                incoming.send_to(&response.to_vec()?, peer).await?;
            } else {
                outgoing.send(&request[..length]).await?;
                let length = timeout(DEADLINE, outgoing.recv(&mut answer)).await??;
                incoming.send_to(&answer[..length], peer).await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    Ok(address)
}

#[tokio::test]
async fn acme_ip_configuration_requires_shortlived_http01() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let routes = route("::1", "127.0.0.1:9000".parse()?, "/");
    let globals = format!(
        r#"
[acme]
domains = ["::1"]
email = "ops@example.test"
accept_terms = true
state_dir = "{}"
challenge_listen = "127.0.0.1:0"
"#,
        dir.path().display()
    );
    assert!(!Gateway::check(dir.path(), &config(&routes, "tls = true", &globals)).await?);
    let shortlived = format!("{globals}\nprofile = \"shortlived\"\n");
    assert!(Gateway::check(dir.path(), &config(&routes, "tls = true", &shortlived)).await?);
    for invalid in [
        shortlived.replace("\"::1\"", "\"::\""),
        shortlived.replace("\"::1\"", "\"::ffff:127.0.0.1\""),
        format!(
            "{shortlived}\n[acme.dns01]\nzone = \"example.test\"\nzone_id = \"{CF_ZONE}\"\ntoken_file = \"unused\"\nresolver = \"127.0.0.1:53\"\n"
        ),
    ] {
        assert!(!Gateway::check(dir.path(), &config(&routes, "tls = true", &invalid)).await?);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_issues_and_serves_mixed_dns_and_ipv4_certificates() -> Result<()> {
    pebble_ip_lifecycle("127.0.0.1", true).await
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries and IPv6 loopback"]
async fn pebble_issues_and_serves_ipv6_certificates() -> Result<()> {
    pebble_ip_lifecycle("::1", false).await
}

async fn pebble_ip_lifecycle(ip: &'static str, mixed_dns: bool) -> Result<()> {
    let pebble = pebble(false).await?;
    let state = pebble.files.path().join("state-ip");
    std::fs::create_dir(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    let origin = Origin::http("IP certificate").await?;
    let mut routes = route(ip, origin.addr, "/");
    let mut identifiers = vec![ip];
    if mixed_dns {
        identifiers.push("acme.example.test");
        routes.push_str(&route("acme.example.test", origin.addr, "/"));
    }
    let address = SocketAddr::new(ip.parse()?, pebble.challenge.port());
    let settings = config(
        &routes,
        "tls = true",
        &format!(
            r#"
[acme]
domains = {}
email = "ops@example.test"
accept_terms = true
profile = "shortlived"
state_dir = "{}"
directory = "https://localhost:{}/dir"
ca_file = "{}"
challenge_listen = "{address}"
"#,
            json!(identifiers),
            state.display(),
            pebble.api.port(),
            pebble.files.path().join("ca.pem").display()
        ),
    );
    let mut gateway = Gateway::spawn(&settings).await?;
    gateway.wait_log("ACME certificate installed").await?;

    let tls = connect_tls(gateway.addr, ip, pebble.root.clone()).await?;
    let identity = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let host = if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_owned()
    };
    let mut client = http_client(tls).await?;
    assert_eq!(get(&mut client, &host, "/").await?.1, "IP certificate");
    assert_eq!(get(&mut client, "acme.example.test", "/").await?.0, 421);

    if mixed_dns {
        let dns = connect_tls(gateway.addr, "acme.example.test", pebble.root.clone()).await?;
        assert_eq!(dns.get_ref().1.peer_certificates().unwrap()[0], identity);
        assert_eq!(
            get(&mut http_client(dns).await?, "acme.example.test", "/")
                .await?
                .1,
            "IP certificate"
        );
    }
    gateway.signal("-TERM").await?;
    gateway.wait_exit().await?;
    let restored = Gateway::spawn(&settings).await?;
    let after = connect_tls(restored.addr, ip, pebble.root.clone()).await?;
    assert_eq!(after.get_ref().1.peer_certificates().unwrap()[0], identity);
    Ok(())
}

#[tokio::test]
#[ignore = "requires the Pebble and pebble-challtestsrv binaries"]
async fn pebble_deploys_a_key_pair_atomically_and_repairs_missing_files() -> Result<()> {
    let pebble = pebble(false).await?;
    let state = pebble.files.path().join("deploy-state");
    let deployed = pebble.files.path().join("deployed");
    for directory in [&state, &deployed] {
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let origin = Origin::http("secured").await?;
    let settings = config(
        &route("acme.example.test", origin.addr, "/"),
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
challenge_listen = "{}"

[[acme.deploy]]
directory = "{}"
fullchain_name = "chain.pem"
key_name = "private.pem"
"#,
            state.display(),
            pebble.api.port(),
            pebble.files.path().join("ca.pem").display(),
            pebble.challenge,
            deployed.display()
        ),
    );
    let forbidden = settings.replace("private.pem", "../private.pem");
    assert!(!Gateway::check(pebble.files.path(), &forbidden).await?);

    let current = deployed.join("current");
    std::fs::write(&current, "external ownership")?;
    let mut issuing = Gateway::spawn(&settings).await?;
    issuing.wait_log("ACME certificate installed").await?;
    let issued = presented_certificate(issuing.addr, pebble.root.clone()).await?;
    issuing
        .wait_log("ACME certificate deployment will retry")
        .await?;
    assert_eq!(std::fs::read_to_string(&current)?, "external ownership");
    issuing.signal("-TERM").await?;
    issuing.wait_exit().await?;
    std::fs::remove_file(&current)?;

    let mut first = Gateway::spawn(&settings).await?;
    first.wait_log("ACME certificate deployed").await?;
    let first_path = std::fs::canonicalize(&current)?;
    assert_deployed_pair(&current, &issued)?;
    first.signal("-TERM").await?;
    first.wait_exit().await?;

    std::fs::remove_file(first_path.join("chain.pem"))?;
    let mut repaired = Gateway::spawn(&settings).await?;
    repaired.wait_log("ACME certificate deployed").await?;
    let repaired_path = std::fs::canonicalize(&current)?;
    assert_ne!(repaired_path, first_path);
    assert!(
        first_path.is_dir(),
        "previous generation must remain available"
    );
    assert_deployed_pair(&current, &issued)?;
    repaired.signal("-TERM").await?;
    repaired.wait_exit().await?;
    install_near_expiry_fixture(&state.join("identity.pem"))?;

    let mut renewed = Gateway::spawn(&settings).await?;
    renewed.wait_log("ACME certificate installed").await?;
    let rotated = presented_certificate(renewed.addr, pebble.root.clone()).await?;
    assert_ne!(rotated, issued);
    // The export worker can briefly publish the restored near-expiry identity first.
    timeout(DEADLINE, async {
        loop {
            if assert_deployed_pair(&current, &rotated).is_ok() {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    assert_ne!(std::fs::canonicalize(&current)?, repaired_path);
    Ok(())
}

fn assert_deployed_pair(current: &Path, expected: &CertificateDer<'_>) -> Result<()> {
    use rustls::{pki_types::PrivateKeyDer, sign::CertifiedKey};
    let pinned = std::fs::canonicalize(current)?;
    let chain = CertificateDer::pem_file_iter(pinned.join("chain.pem"))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        chain.first().is_some_and(|leaf| leaf == expected),
        "deployed certificate has not switched"
    );
    let key_file = pinned.join("private.pem");
    let key = PrivateKeyDer::from_pem_file(&key_file)?;
    assert_eq!(key_file.metadata()?.permissions().mode() & 0o777, 0o600);
    CertifiedKey::from_der(chain, key, &ring::default_provider())?.keys_match()?;
    Ok(())
}
