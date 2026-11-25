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
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
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

use crate::config::{canonical_host, read_file, valid_authority};

const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";
const STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const ACCOUNT_FILE: &str = "account.json";
const IDENTITY_FILE: &str = "identity.pem";

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
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AcmeConfig {
    pub domains: Vec<String>,
    pub challenge_listen: SocketAddr,
    pub state_dir: PathBuf,
    email: String,
    directory: String,
    pub ca_file: Option<PathBuf>,
    renew_before_hours: u32,
}

#[derive(Default)]
pub(crate) struct Managed {
    pub certificate: ArcSwapOption<CertifiedKey>,
    challenges: RwLock<HashMap<String, (String, Bytes)>>,
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
            "ACME supports 1..=20 exact DNS names"
        );
        let mut domains = Vec::with_capacity(raw.domains.len());
        for name in raw.domains {
            let host = canonical_host(&name)
                .filter(|host| {
                    host.contains('.') && !host.starts_with('[') && host.parse::<IpAddr>().is_err()
                })
                .context("ACME HTTP-01 requires exact DNS names")?;
            domains.push(host.into_owned());
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
        let renew_before_hours = raw.renew_before_hours.unwrap_or(720);
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
        let ca_file = raw.ca_file.map(|file| dir.join(file));
        if let Some(file) = &ca_file {
            let bytes = read_file(file).await.context("read ACME CA file")?;
            CertificateDer::from_pem_slice(&bytes).context("parse ACME CA certificate")?;
        }
        Ok(Self {
            domains,
            challenge_listen: raw
                .challenge_listen
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 80))),
            state_dir,
            email: raw.email,
            directory,
            ca_file,
            renew_before_hours,
        })
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
                    renew_at
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
            sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(3600));
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
        let contact = format!("mailto:{}", self.email);
        let (account, credentials) = builder
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory.clone(),
                None,
            )
            .await?;
        self.persist(
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
        let names: Vec<_> = self.domains.iter().cloned().map(Identifier::Dns).collect();
        let mut order = account.new_order(&NewOrder::new(&names)).await?;
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
                .challenge(ChallengeType::Http01)
                .context("ACME server did not offer HTTP-01")?;
            let authorized = challenge.identifier().to_string();
            ensure!(
                self.domains.contains(&authorized) && valid_token(&challenge.token),
                "unexpected ACME challenge host or token"
            );
            challenges
                .0
                .challenges
                .write()
                .expect("ACME challenge lock")
                .insert(
                    challenge.token.clone(),
                    (
                        authorized,
                        Bytes::copy_from_slice(challenge.key_authorization().as_str().as_bytes()),
                    ),
                );
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
        let bundle = format!("{}\n{}", chain.trim_end(), key);
        let (certificate, renew_at) = self.parse_identity(bundle.as_bytes())?;
        self.persist(IDENTITY_FILE, lock, bundle.into_bytes())
            .await?;
        managed.certificate.store(Some(Arc::new(certificate)));
        Ok(renew_at)
    }

    fn parse_identity(&self, bytes: &[u8]) -> Result<(CertifiedKey, i64)> {
        let chain =
            CertificateDer::pem_slice_iter(bytes).collect::<std::result::Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(bytes)?;
        let key = CertifiedKey::from_der(chain, key, &ring::default_provider())?;
        key.keys_match()?;
        let mut verifier = ResolvesServerCertUsingSni::new();
        for domain in &self.domains {
            verifier
                .add(domain, key.clone())
                .context("ACME certificate does not cover a configured domain")?;
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
        Ok((key, end - lead.min((end - start) / 3)))
    }

    async fn persist(
        &self,
        name: &'static str,
        lock: &Arc<std::fs::File>,
        bytes: Vec<u8>,
    ) -> Result<()> {
        let dir = self.state_dir.clone();
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
}

async fn read_saved(path: &Path) -> Result<Option<Vec<u8>>> {
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

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
