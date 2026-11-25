use std::{
    collections::HashMap,
    convert::Infallible,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwapOption;
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode, Uri, Version,
    body::Bytes,
    header::{CACHE_CONTROL, CONTENT_TYPE, HOST, HeaderValue},
    http::uri::{Authority, Scheme},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, ExternalAccountKey,
    Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::{
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::ResolvesServerCertUsingSni,
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    task::JoinSet,
    time::{sleep, timeout},
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    cert_deploy::DeployTarget,
    config::{canonical_host, read_file, valid_authority},
    dns01::{Dns01, RawDns01},
    tls,
};

const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";
const STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const ACCOUNT_FILE: &str = "account.json";
const IDENTITY_FILE: &str = "identity.pem";
const PROFILE_MARKER: &str = "# ferrumgate-acme-profile=";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawAcme {
    domains: Vec<String>,
    email: String,
    #[serde(default)]
    accept_terms: bool,
    state_dir: PathBuf,
    directory: Option<String>,
    ca_file: Option<PathBuf>,
    challenge_listen: Option<SocketAddr>,
    renew_before_hours: Option<u32>,
    profile: Option<String>,
    eab: Option<ExternalBinding>,
    dns01: Option<RawDns01>,
    #[serde(default)]
    deploy: Vec<DeployTarget>,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExternalBinding {
    key_id: String,
    hmac_key_file: PathBuf,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AcmeConfig {
    pub domains: Vec<String>,
    pub challenge_listen: Option<SocketAddr>,
    pub state_dir: PathBuf,
    email: String,
    directory: String,
    pub ca_file: Option<PathBuf>,
    renew_before_hours: u32,
    profile: Option<String>,
    eab: Option<ExternalBinding>,
    dns01: Option<Dns01>,
    deploy: Vec<DeployTarget>,
}

#[derive(Default)]
pub(crate) struct Managed {
    pub certificate: ArcSwapOption<ManagedCertificate>,
    #[cfg(unix)]
    deployment_changed: tokio::sync::Notify,
    challenges: RwLock<HashMap<String, (String, Bytes)>>,
}

pub(crate) struct ManagedCertificate {
    pub key: Arc<CertifiedKey>,
    pub starts: i64,
    pub expires: i64,
}

#[derive(Serialize, Deserialize)]
struct StoredAccount {
    directory: String,
    email: String,
    credentials: AccountCredentials,
}

struct OrderChallenges<'a>(&'a Managed);

impl Drop for OrderChallenges<'_> {
    fn drop(&mut self) {
        self.0
            .challenges
            .write()
            .expect("ACME challenge lock")
            .clear();
    }
}

impl AcmeConfig {
    pub async fn compile(raw: RawAcme, dir: &Path) -> Result<Self> {
        ensure!(raw.accept_terms, "ACME requires accept_terms = true");
        ensure!(
            raw.email.is_ascii()
                && !raw.email.bytes().any(|byte| byte.is_ascii_whitespace()
                    || byte.is_ascii_control()
                    || matches!(byte, b'?' | b'#'))
                && raw
                    .email
                    .split_once('@')
                    .is_some_and(|(name, domain)| !name.is_empty()
                        && !domain.is_empty()
                        && !domain.contains('@')),
            "ACME email must be a valid mail address"
        );
        ensure!(
            (1..=20).contains(&raw.domains.len()),
            "ACME supports 1..=20 identifiers"
        );
        let mut domains = Vec::with_capacity(raw.domains.len());
        for name in raw.domains {
            let wildcard = name.strip_prefix("*.");
            ensure!(
                wildcard.is_none() || raw.dns01.is_some(),
                "ACME wildcard requires DNS-01"
            );
            let host = canonical_host(wildcard.unwrap_or(&name))
                .context("ACME needs a DNS name or an IP address")?;
            if let Some(ip) = tls::ip_literal(&host) {
                ensure!(
                    wildcard.is_none() && raw.dns01.is_none(),
                    "ACME IP addresses require HTTP-01"
                );
                ensure!(
                    !ip.is_unspecified()
                        && !ip.is_multicast()
                        && ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
                    "invalid ACME IP address"
                );
                ensure!(
                    ip.to_canonical() == ip,
                    "ACME IP addresses must not use mapped IPv6 notation"
                );
                ensure!(
                    raw.profile.as_deref() == Some("shortlived"),
                    "ACME IP addresses require profile = shortlived"
                );
            } else {
                ensure!(host.contains('.'), "invalid ACME DNS name");
            }
            domains.push(if wildcard.is_some() {
                format!("*.{host}")
            } else {
                host.into_owned()
            });
        }
        domains.sort_unstable();
        ensure!(
            domains.windows(2).all(|names| names[0] != names[1]),
            "duplicate ACME domain"
        );
        let directory = raw
            .directory
            .unwrap_or_else(|| STAGING_DIRECTORY.to_owned());
        let uri: Uri = directory
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid ACME directory URL"))?;
        ensure!(
            uri.scheme() == Some(&Scheme::HTTPS)
                && uri.authority().is_some_and(valid_authority)
                && !directory.contains('#'),
            "ACME directory requires a valid HTTPS URL"
        );
        let default_lead = if raw.profile.as_deref() == Some("shortlived") {
            24
        } else {
            720
        };
        let renew_before_hours = raw.renew_before_hours.unwrap_or(default_lead);
        if let Some(profile) = &raw.profile {
            ensure!(
                (1..=64).contains(&profile.len())
                    && profile
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'-' | b'_' | b'.')),
                "invalid ACME profile name"
            );
        }
        ensure!(
            (1..=720).contains(&renew_before_hours),
            "ACME renew_before_hours must be in 1..=720"
        );
        ensure!(
            !raw.state_dir.as_os_str().is_empty(),
            "ACME state directory is required"
        );
        let state_dir = dir.join(raw.state_dir);
        let state_info = tokio::fs::symlink_metadata(&state_dir)
            .await
            .context("read ACME state directory")?;
        ensure!(
            state_info.is_dir(),
            "ACME state directory must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                state_info.permissions().mode() & 0o077 == 0,
                "ACME state directory must be private (mode 0700)"
            );
        }
        let state_dir = tokio::fs::canonicalize(state_dir)
            .await
            .context("resolve ACME state directory")?;
        let ca_file = raw.ca_file.map(|file| dir.join(file));
        if let Some(file) = &ca_file {
            let bytes = read_file(file).await.context("read ACME CA file")?;
            CertificateDer::from_pem_slice(&bytes).context("parse ACME CA certificate")?;
        }
        let eab = if let Some(mut eab) = raw.eab {
            ensure!(
                (1..=256).contains(&eab.key_id.len())
                    && eab.key_id.bytes().all(|byte| byte.is_ascii_graphic()),
                "invalid ACME EAB key ID"
            );
            ensure!(
                !eab.hmac_key_file.as_os_str().is_empty(),
                "ACME EAB HMAC key file is required"
            );
            eab.hmac_key_file = dir.join(eab.hmac_key_file);
            eab.key().await?;
            eab.hmac_key_file = tokio::fs::canonicalize(eab.hmac_key_file)
                .await
                .context("resolve EAB secret file")?;
            Some(eab)
        } else {
            None
        };
        let (challenge_listen, dns01) = if let Some(raw_dns) = raw.dns01 {
            ensure!(
                raw.challenge_listen.is_none(),
                "challenge_listen is only for HTTP-01"
            );
            (None, Some(Dns01::compile(raw_dns, dir, &domains).await?))
        } else {
            (
                Some(
                    raw.challenge_listen
                        .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 80))),
                ),
                None,
            )
        };
        crate::dns01::validate_journal(dns01.as_ref(), &state_dir).await?;
        ensure!(
            raw.deploy.len() <= 16,
            "ACME supports up to 16 deployment targets"
        );
        let mut deploy = Vec::<DeployTarget>::with_capacity(raw.deploy.len());
        for target in raw.deploy {
            let target = target.compile(dir, &state_dir).await?;
            ensure!(
                deploy
                    .iter()
                    .all(|old| !old.directory.starts_with(&target.directory)
                        && !target.directory.starts_with(&old.directory)),
                "ACME deployment directories must be separate"
            );
            deploy.push(target);
        }
        Ok(Self {
            domains,
            challenge_listen,
            dns01,
            state_dir,
            email: raw.email,
            directory,
            ca_file,
            renew_before_hours,
            profile: raw.profile,
            eab,
            deploy,
        })
    }

    pub fn protected_paths(&self) -> impl Iterator<Item = &PathBuf> {
        std::iter::once(&self.state_dir)
            .chain(self.eab.iter().map(|eab| &eab.hmac_key_file))
            .chain(self.dns01.iter().map(|dns| &dns.token_file))
            .chain(self.deploy.iter().map(|target| &target.directory))
    }

    pub async fn restore(&self, managed: &Managed) -> Result<(std::fs::File, i64)> {
        let lock_path = self.state_dir.join("lock");
        let lock = tokio::task::spawn_blocking(move || {
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true).write(true).create(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let lock = opts.open(lock_path).context("open ACME state lock")?;
            lock.try_lock().context("ACME state directory is in use")?;
            Ok::<_, anyhow::Error>(lock)
        })
        .await??;

        let path = self.state_dir.join(IDENTITY_FILE);
        let renew_at = match read_saved(&path).await? {
            Some(bytes) => match self.parse_identity(&bytes) {
                Ok((key, renew_at)) => {
                    managed.certificate.store(Some(Arc::new(key)));
                    if stored_profile(&bytes) == self.profile.as_deref() {
                        renew_at
                    } else {
                        0
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "stored ACME identity rejected");
                    0
                }
            },
            None => 0,
        };
        Ok((lock, renew_at))
    }

    pub async fn run(self, managed: Arc<Managed>, lock: Arc<std::fs::File>, mut renew_at: i64) {
        let mut delay = Duration::from_secs(30);
        loop {
            if !self.cleanup_dns(&lock).await {
                sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(3600));
                continue;
            }
            let remaining = renew_at.saturating_sub(unix_now());
            if remaining > 0 {
                sleep(Duration::from_secs((remaining as u64).min(3600))).await;
                continue;
            }
            match timeout(Duration::from_secs(360), self.issue(&managed, &lock)).await {
                Ok(Ok(next)) => {
                    renew_at = next.max(unix_now().saturating_add(60));
                    delay = Duration::from_secs(30);
                    tracing::info!(domains = self.domains.len(), "ACME certificate installed");
                    continue;
                }
                Ok(Err(error)) => tracing::warn!(%error, "ACME issuance failed"),
                Err(_) => tracing::warn!("ACME issuance deadline elapsed"),
            }
            self.cleanup_dns(&lock).await;
            sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(3600));
        }
    }

    #[cfg(unix)]
    pub async fn run_deployments(self, managed: Arc<Managed>, lock: Arc<std::fs::File>) {
        if self.deploy.is_empty() {
            return;
        }
        loop {
            if let Err(error) = self.reconcile_deployments(&managed, &lock).await {
                tracing::warn!(%error, "ACME certificate deployment will retry");
            }
            tokio::select! {
                _ = managed.deployment_changed.notified() => {},
                _ = sleep(Duration::from_secs(3600)) => {},
            }
        }
    }

    #[cfg(unix)]
    async fn reconcile_deployments(
        &self,
        managed: &Managed,
        lock: &Arc<std::fs::File>,
    ) -> Result<()> {
        let Some(installed) = managed.certificate.load_full() else {
            return Ok(());
        };
        let bundle = read_saved(&self.state_dir.join(IDENTITY_FILE))
            .await?
            .context("missing installed ACME identity")?;
        let (candidate, _) = self.parse_identity(&bundle)?;
        // A newer issuance can become durable while the worker is reading.
        if candidate.key.cert != installed.key.cert {
            return Ok(());
        }
        let material = crate::cert_deploy::Materials::from_bundle(&bundle)?;
        let targets = self.deploy.clone();
        let state_dir = self.state_dir.clone();
        let lock = lock.clone();
        tokio::task::spawn_blocking(move || {
            let _lock = lock;
            for (index, target) in targets.iter().enumerate() {
                match target.deploy(&material, &state_dir) {
                    Ok(true) => tracing::info!(target = index, "ACME certificate deployed"),
                    Ok(false) => {},
                    Err(error) => tracing::warn!(target = index, %error, "ACME certificate deployment will retry"),
                }
            }
        }).await.context("ACME deployment worker")?;
        Ok(())
    }

    async fn cleanup_dns(&self, lock: &Arc<std::fs::File>) -> bool {
        let Some(dns) = &self.dns01 else { return true };
        match timeout(Duration::from_secs(60), dns.cleanup(&self.state_dir, lock)).await {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                tracing::warn!(%error, "ACME DNS cleanup will retry");
                false
            }
            Err(_) => {
                tracing::warn!("ACME DNS cleanup deadline elapsed");
                false
            }
        }
    }

    async fn account(&self, lock: &Arc<std::fs::File>) -> Result<Account> {
        let builder = match &self.ca_file {
            Some(root) => Account::builder_with_root(root)?,
            None => Account::builder()?,
        };
        if let Some(bytes) = read_saved(&self.state_dir.join(ACCOUNT_FILE)).await? {
            let account: StoredAccount =
                serde_json::from_slice(&bytes).context("read saved ACME account")?;
            ensure!(
                account.directory == self.directory && account.email == self.email,
                "saved ACME account belongs to another directory or email; select a separate state directory"
            );
            return Ok(builder.from_credentials(account.credentials).await?);
        }
        let external = if let Some(eab) = &self.eab {
            Some(eab.key().await?)
        } else {
            None
        };
        let contact = format!("mailto:{}", self.email);
        let (account, credentials) = builder
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory.clone(),
                external.as_ref(),
            )
            .await?;
        persist_private(
            &self.state_dir,
            ACCOUNT_FILE,
            lock,
            serde_json::to_vec(&StoredAccount {
                directory: self.directory.clone(),
                email: self.email.clone(),
                credentials,
            })?,
        )
        .await?;
        Ok(account)
    }

    async fn issue(&self, managed: &Managed, lock: &Arc<std::fs::File>) -> Result<i64> {
        let account = self.account(lock).await?;
        let mut dns = match &self.dns01 {
            Some(dns) => Some(dns.order(&self.state_dir, lock).await?),
            None => None,
        };
        let names: Vec<_> = self
            .domains
            .iter()
            .map(|name| match tls::ip_literal(name) {
                Some(ip) => Identifier::Ip(ip),
                None => Identifier::Dns(name.clone()),
            })
            .collect();
        let request = NewOrder::new(&names);
        let request = if let Some(profile) = &self.profile {
            request.profile(profile)
        } else {
            request
        };
        let mut order = account.new_order(&request).await?;
        if let Some(profile) = &self.profile {
            ensure!(
                order.state().profile.as_deref() == Some(profile.as_str()),
                "ACME order did not confirm the configured profile"
            );
        }
        let challenges = OrderChallenges(managed);
        let mut authorizations = order.authorizations();
        while let Some(auth) = authorizations.next().await {
            let mut auth = auth?;
            match auth.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => anyhow::bail!("ACME authorization is not pending or valid"),
            }
            let mut challenge = auth
                .challenge(if dns.is_some() {
                    ChallengeType::Dns01
                } else {
                    ChallengeType::Http01
                })
                .context("ACME server did not offer the configured challenge type")?;
            let identifier = challenge.identifier();
            let authorized = match identifier.identifier {
                Identifier::Ip(ip) if !identifier.wildcard => match ip {
                    IpAddr::V4(ip) => ip.to_string(),
                    IpAddr::V6(ip) => format!("[{ip}]"),
                },
                Identifier::Dns(name) if tls::ip_literal(name).is_none() => identifier.to_string(),
                _ => anyhow::bail!("unexpected ACME identifier type"),
            };
            ensure!(
                self.domains.contains(&authorized) && valid_token(&challenge.token),
                "unexpected ACME challenge host or token"
            );
            if let Some(dns) = dns.as_mut() {
                dns.provision(&authorized, challenge.key_authorization().dns_value())
                    .await?;
            } else {
                challenges
                    .0
                    .challenges
                    .write()
                    .expect("ACME challenge lock")
                    .insert(
                        challenge.token.clone(),
                        (
                            authorized,
                            Bytes::copy_from_slice(
                                challenge.key_authorization().as_str().as_bytes(),
                            ),
                        ),
                    );
            }
            challenge.set_ready().await?;
        }
        let policy = RetryPolicy::new().timeout(Duration::from_secs(120));
        ensure!(
            order.poll_ready(&policy).await? == OrderStatus::Ready,
            "ACME order could not become ready"
        );
        drop(challenges);
        let key = order.finalize().await?;
        let chain = order.poll_certificate(&policy).await?;
        let bundle = match self.profile.as_deref() {
            Some(profile) => format!("{PROFILE_MARKER}{profile}\n{}\n{key}", chain.trim_end()),
            None => format!("{}\n{key}", chain.trim_end()),
        };
        let (certificate, renew_at) = self.parse_identity(bundle.as_bytes())?;
        persist_private(&self.state_dir, IDENTITY_FILE, lock, bundle.into_bytes()).await?;
        managed.certificate.store(Some(Arc::new(certificate)));
        #[cfg(unix)]
        managed.deployment_changed.notify_one();
        Ok(renew_at)
    }

    fn parse_identity(&self, bytes: &[u8]) -> Result<(ManagedCertificate, i64)> {
        let chain =
            CertificateDer::pem_slice_iter(bytes).collect::<std::result::Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(bytes)?;
        let key = CertifiedKey::from_der(chain, key, &ring::default_provider())?;
        key.keys_match()?;
        let mut verifier = ResolvesServerCertUsingSni::new();
        for domain in &self.domains {
            if let Some(ip) = tls::ip_literal(domain) {
                tls::verify_ip(&key, ip)
                    .context("ACME certificate does not cover a configured IP")?;
            } else if domain.starts_with("*.") {
                tls::verify_wildcard(&key, domain)
                    .context("ACME certificate does not cover a configured wildcard")?;
            } else {
                verifier
                    .add(domain, key.clone())
                    .context("ACME certificate does not cover a configured domain")?;
            }
        }
        let (_, leaf) = X509Certificate::from_der(key.end_entity_cert()?.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid ACME leaf certificate"))?;
        let start = leaf.validity().not_before.timestamp();
        let end = leaf.validity().not_after.timestamp();
        let now = unix_now();
        ensure!(
            start <= now && end > now,
            "ACME certificate is outside its validity period"
        );
        let lead = i64::from(self.renew_before_hours) * 3600;
        Ok((
            ManagedCertificate {
                key: Arc::new(key),
                starts: start,
                expires: end,
            },
            end - lead.min((end - start) / 3),
        ))
    }
}

pub(crate) async fn persist_private(
    state_dir: &Path,
    name: &'static str,
    lock: &Arc<std::fs::File>,
    bytes: Vec<u8>,
) -> Result<()> {
    let dir = state_dir.to_owned();
    let lock = lock.clone();
    tokio::task::spawn_blocking(move || {
        let _lock = lock;
        let mut file = tempfile::NamedTempFile::new_in(&dir)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist(dir.join(name))?;
        #[cfg(unix)]
        std::fs::File::open(&dir)?.sync_all()?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

impl ExternalBinding {
    async fn key(&self) -> Result<ExternalAccountKey> {
        let bytes = read_saved(&self.hmac_key_file)
            .await
            .context("read ACME EAB HMAC key file")?
            .context("missing ACME EAB HMAC key file")?;
        let encoded = std::str::from_utf8(&bytes)
            .context("ACME EAB key must be base64url")?
            .trim();
        ensure!(
            !encoded.is_empty() && encoded.len() <= 4096,
            "invalid ACME EAB HMAC key length"
        );
        let key = URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| URL_SAFE.decode(encoded))
            .map_err(|_| anyhow::anyhow!("invalid ACME EAB base64url key"))?;
        ensure!(
            key.len() >= 32,
            "ACME EAB HS256 key needs at least 32 bytes"
        );
        Ok(ExternalAccountKey::new(self.key_id.clone(), &key))
    }
}

pub(crate) async fn read_saved(path: &Path) -> Result<Option<Vec<u8>>> {
    match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(info) => {
            ensure!(info.is_file(), "ACME state must be a regular file");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    info.permissions().mode() & 0o077 == 0,
                    "ACME state files must be private"
                );
            }
            read_file(path).await.map(Some)
        }
    }
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn stored_profile(bytes: &[u8]) -> Option<&str> {
    let line = bytes.split(|byte| *byte == b'\n').next()?;
    std::str::from_utf8(line.strip_prefix(PROFILE_MARKER.as_bytes())?).ok()
}

fn valid_token(token: &str) -> bool {
    (1..=128).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) async fn serve_challenges(listener: TcpListener, managed: Arc<Managed>) {
    let mut connections = JoinSet::new();
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .keep_alive(false);
    loop {
        tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => {},
            socket = listener.accept(), if connections.len() < 64 => {
                let Ok((socket, _)) = socket else {
                    sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let managed = managed.clone();
                let http = http.clone();
                connections.spawn(async move {
                    let service = service_fn(|request| std::future::ready(Ok::<_, Infallible>(challenge_response(&managed, &request))));
                    let _ = timeout(Duration::from_secs(5), http.serve_connection(TokioIo::new(socket), service)).await;
                });
            }
        }
    }
}

fn challenge_response<B>(managed: &Managed, request: &Request<B>) -> Response<Full<Bytes>> {
    let value = (|| {
        if request.method() != Method::GET
            || request.version() != Version::HTTP_11
            || request.uri().authority().is_some()
            || request.uri().scheme().is_some()
            || request.uri().query().is_some()
        {
            return None;
        }
        let token = request
            .uri()
            .path()
            .strip_prefix(CHALLENGE_PATH)
            .filter(|token| valid_token(token))?;
        let mut fields = request.headers().get_all(HOST).iter();
        let host: Authority = fields.next()?.to_str().ok()?.parse().ok()?;
        if fields.next().is_some() || !valid_authority(&host) {
            return None;
        }
        let host = canonical_host(host.host())?;
        let challenges = managed.challenges.read().expect("ACME challenge lock");
        challenges
            .get(token)
            .filter(|(domain, _)| domain == host.as_ref())
            .map(|(_, value)| value.clone())
    })();
    let mut response = Response::builder().header(CACHE_CONTROL, "no-store");
    if let Some(value) = value {
        response = response.header(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        response
            .body(Full::new(value))
            .expect("ACME challenge response")
    } else {
        response
            .status(StatusCode::NOT_FOUND)
            .body(Full::default())
            .expect("ACME challenge response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_matches_the_exact_host_and_token_and_is_removed() {
        let managed = Managed::default();
        let guard = OrderChallenges(&managed);
        managed.challenges.write().unwrap().insert(
            "token-01".into(),
            ("app.test".into(), Bytes::from_static(b"proof")),
        );
        let check = |host: &str, path: &str| {
            let req = Request::builder()
                .uri(path)
                .header(HOST, host)
                .body(())
                .unwrap();
            challenge_response(&managed, &req).status()
        };
        assert_eq!(
            check("APP.TEST:80", "/.well-known/acme-challenge/token-01"),
            StatusCode::OK
        );
        assert_eq!(
            check("other.test", "/.well-known/acme-challenge/token-01"),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            check("app.test", "/.well-known/acme-challenge/token-01?query"),
            StatusCode::NOT_FOUND
        );
        drop(guard);
        assert_eq!(
            check("app.test", "/.well-known/acme-challenge/token-01"),
            StatusCode::NOT_FOUND
        );
    }
}
