use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RData,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, StatusCode, Uri,
    body::Bytes,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
    http::uri::Scheme,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, timeout};

use crate::{
    acme::{persist_private, read_saved, unix_now},
    config::{canonical_host, read_file, valid_authority},
};

const JOURNAL_FILE: &str = "dns-cleanup.json";
const DEFAULT_API: &str = "https://api.cloudflare.com/client/v4";
const API_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawDns01 {
    zone: String,
    zone_id: String,
    token_file: PathBuf,
    resolver: SocketAddr,
    api_base: Option<String>,
    api_ca_file: Option<PathBuf>,
    propagation_timeout_secs: Option<u32>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Dns01 {
    zone: String,
    zone_id: String,
    api_base: String,
    api_ca_file: Option<PathBuf>,
    pub token_file: PathBuf,
    resolver: SocketAddr,
    propagation_timeout: Duration,
}

#[derive(Serialize, Deserialize)]
struct Journal {
    zone_id: String,
    api_base: String,
    records: Vec<Pending>,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    name: String,
    content: String,
    comment: String,
    record_id: Option<String>,
    created_at: i64,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    result: Option<T>,
}

#[derive(Deserialize)]
struct DnsRecord {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    name: String,
    content: String,
    comment: Option<String>,
}

struct Cloudflare {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    authorization: HeaderValue,
    path: String,
}

pub(crate) struct OrderDns<'a> {
    cf: Cloudflare,
    resolver: TokioResolver,
    journal: Journal,
    config: &'a Dns01,
    state_dir: &'a Path,
    lock: &'a Arc<std::fs::File>,
}

impl Dns01 {
    pub async fn compile(raw: RawDns01, dir: &Path, domains: &[String]) -> Result<Self> {
        let zone = canonical_host(&raw.zone)
            .filter(|zone| zone.contains('.') && zone.parse::<IpAddr>().is_err())
            .context("DNS-01 zone must be a DNS name")?
            .into_owned();
        ensure!(
            domains
                .iter()
                .all(|domain| in_zone(domain.strip_prefix("*.").unwrap_or(domain), &zone)),
            "DNS-01 domains must be within the configured zone"
        );
        ensure!(
            valid_id(&raw.zone_id),
            "DNS-01 zone_id must be a 32-character Cloudflare ID"
        );
        ensure!(
            !raw.resolver.ip().is_unspecified() && raw.resolver.port() != 0,
            "DNS-01 resolver must be a DNS server address with a nonzero port"
        );
        ensure!(
            !raw.token_file.as_os_str().is_empty(),
            "DNS-01 token_file is required"
        );
        let propagation_timeout = raw.propagation_timeout_secs.unwrap_or(120);
        ensure!(
            (1..=240).contains(&propagation_timeout),
            "DNS-01 propagation_timeout_secs must be in 1..=240"
        );

        let api_base = raw.api_base.unwrap_or_else(|| DEFAULT_API.into());
        let uri: Uri = api_base.parse().context("invalid DNS provider API URL")?;
        ensure!(
            uri.scheme() == Some(&Scheme::HTTPS)
                && uri.authority().is_some_and(valid_authority)
                && uri.query().is_none()
                && !api_base.contains('#'),
            "DNS provider API base must be an HTTPS URL"
        );
        let mut cfg = Self {
            zone,
            zone_id: raw.zone_id.to_ascii_lowercase(),
            api_base: api_base.trim_end_matches('/').to_owned(),
            api_ca_file: raw.api_ca_file.map(|path| dir.join(path)),
            token_file: dir.join(raw.token_file),
            resolver: raw.resolver,
            propagation_timeout: Duration::from_secs(u64::from(propagation_timeout)),
        };
        cfg.authorization().await?;
        cfg.token_file = tokio::fs::canonicalize(cfg.token_file)
            .await
            .context("resolve DNS provider token file")?;
        cfg.roots().await?;
        Ok(cfg)
    }

    pub async fn order<'a>(
        &'a self,
        state_dir: &'a Path,
        lock: &'a Arc<std::fs::File>,
    ) -> Result<OrderDns<'a>> {
        let mut server = NameServerConfig::udp_and_tcp(self.resolver.ip());
        for connection in &mut server.connections {
            connection.port = self.resolver.port();
        }
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::from_name_servers(vec![server]),
            TokioRuntimeProvider::default(),
        );
        builder.options_mut().cache_size = 0;
        let resolver = builder.build()?;
        Ok(OrderDns {
            cf: self.client().await?,
            resolver,
            journal: Journal {
                zone_id: self.zone_id.clone(),
                api_base: self.api_base.clone(),
                records: Vec::new(),
            },
            config: self,
            state_dir,
            lock,
        })
    }

    pub async fn cleanup(&self, state_dir: &Path, lock: &Arc<std::fs::File>) -> Result<()> {
        let Some(bytes) = read_saved(&state_dir.join(JOURNAL_FILE)).await? else {
            return Ok(());
        };
        let mut journal: Journal =
            serde_json::from_slice(&bytes).context("read DNS-01 cleanup journal")?;
        if journal.records.is_empty() {
            return Ok(());
        }
        ensure!(
            journal.zone_id == self.zone_id && journal.api_base == self.api_base,
            "DNS-01 cleanup journal belongs to another zone or API"
        );
        let client = self.client().await?;
        while let Some(record) = journal.records.last() {
            ensure!(
                record
                    .name
                    .strip_prefix("_acme-challenge.")
                    .is_some_and(|name| in_zone(name, &self.zone))
                    && safe_piece(&record.name)
                    && record
                        .comment
                        .strip_prefix("ferrumgate-")
                        .is_some_and(|tag| tag.len() == 22 && safe_piece(tag)),
                "invalid record in DNS-01 cleanup journal"
            );
            client.retire(record).await?;
            journal.records.pop();
            persist_private(state_dir, JOURNAL_FILE, lock, serde_json::to_vec(&journal)?).await?;
        }
        Ok(())
    }

    async fn roots(&self) -> Result<rustls::RootCertStore> {
        let mut roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &self.api_ca_file {
            use rustls::pki_types::{CertificateDer, pem::PemObject};
            let pem = read_file(path).await.context("read DNS provider CA file")?;
            roots.add(
                CertificateDer::from_pem_slice(&pem)
                    .context("parse DNS provider CA certificate")?,
            )?;
        }
        Ok(roots)
    }

    async fn authorization(&self) -> Result<HeaderValue> {
        let bytes = read_saved(&self.token_file)
            .await
            .context("read private DNS provider token file")?
            .context("missing DNS provider token file")?;
        let token = std::str::from_utf8(&bytes)
            .context("DNS provider token must be UTF-8")?
            .trim();
        ensure!(
            (1..=1024).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid DNS provider token"
        );
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| anyhow::anyhow!("invalid DNS provider authorization"))?;
        value.set_sensitive(true);
        Ok(value)
    }

    async fn client(&self) -> Result<Cloudflare> {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(self.roots().await?)
        .with_no_client_auth();
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .build();
        Ok(Cloudflare {
            client: Client::builder(TokioExecutor::new())
                .retry_canceled_requests(false)
                .build(https),
            authorization: self.authorization().await?,
            path: format!("{}/zones/{}/dns_records", self.api_base, self.zone_id),
        })
    }
}

impl OrderDns<'_> {
    pub async fn provision(&mut self, domain: &str, content: String) -> Result<()> {
        let domain = domain.strip_prefix("*.").unwrap_or(domain);
        let name = format!("_acme-challenge.{domain}");
        ensure!(
            in_zone(domain, &self.config.zone) && name.len() <= 253,
            "DNS-01 challenge name is outside the zone"
        );
        let mut random = [0; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| anyhow::anyhow!("generate DNS-01 record tag"))?;
        let comment = format!("ferrumgate-{}", URL_SAFE_NO_PAD.encode(random));
        self.journal.records.push(Pending {
            name,
            content,
            comment,
            record_id: None,
            created_at: unix_now(),
        });
        self.save().await?;
        let record = self
            .journal
            .records
            .last_mut()
            .expect("created journal record");
        let created = self.cf.create(record).await?;
        record.record_id = Some(created.id);
        self.save().await?;
        let record = self.journal.records.last().expect("saved journal record");
        let fqdn = format!("{}.", record.name);
        timeout(self.config.propagation_timeout, async {
            loop {
                if let Ok(reply) = self.resolver.txt_lookup(fqdn.as_str()).await
                    && reply.answers().iter().any(|answer| match &answer.data {
                        RData::TXT(value) => value
                            .txt_data
                            .iter()
                            .flat_map(|part| part.iter().copied())
                            .eq(record.content.bytes()),
                        _ => false,
                    })
                {
                    break;
                }
                sleep(Duration::from_secs(2)).await;
            }
        })
        .await
        .context("wait for DNS-01 TXT propagation")?;
        Ok(())
    }

    async fn save(&self) -> Result<()> {
        persist_private(
            self.state_dir,
            JOURNAL_FILE,
            self.lock,
            serde_json::to_vec(&self.journal)?,
        )
        .await
    }
}

impl Cloudflare {
    async fn create(&self, record: &Pending) -> Result<DnsRecord> {
        let body = serde_json::to_vec(&serde_json::json!({
            "type": "TXT",
            "name": record.name,
            "content": record.content,
            "ttl": 120,
            "comment": record.comment,
        }))?;
        let response: DnsRecord = self
            .request(Method::POST, "", body)
            .await?
            .context("missing DNS provider record")?;
        ensure!(
            valid_id(&response.id) && same_record(&response, record),
            "DNS provider returned an unexpected record"
        );
        Ok(response)
    }

    async fn retire(&self, record: &Pending) -> Result<()> {
        if let Some(id) = &record.record_id {
            ensure!(valid_id(id), "invalid DNS record ID in cleanup journal");
            return self.remove_if_owned(id, record).await;
        }
        let query = format!(
            "?type=TXT&name.exact={}&comment.exact={}&per_page=100",
            record.name, record.comment
        );
        let records: Vec<DnsRecord> = self
            .request(Method::GET, &query, Vec::new())
            .await?
            .context("missing DNS provider record list")?;
        let possibly_truncated = records.len() >= 100;
        let mut found = false;
        for entry in records
            .into_iter()
            .filter(|entry| same_record(entry, record))
        {
            ensure!(
                valid_id(&entry.id),
                "invalid DNS record ID recovered from provider"
            );
            self.remove_if_owned(&entry.id, record).await?;
            found = true;
        }
        ensure!(
            found || !possibly_truncated,
            "DNS provider record list was incomplete"
        );
        ensure!(
            found || unix_now().saturating_sub(record.created_at) >= 60,
            "awaiting read-back of a DNS record with an uncertain creation outcome"
        );
        Ok(())
    }

    async fn remove_if_owned(&self, id: &str, record: &Pending) -> Result<()> {
        let suffix = format!("/{id}");
        let current: Option<DnsRecord> = self.request(Method::GET, &suffix, Vec::new()).await?;
        if current.is_some_and(|current| current.id == id && same_record(&current, record)) {
            let _: Option<serde_json::Value> =
                self.request(Method::DELETE, &suffix, Vec::new()).await?;
        }
        Ok(())
    }

    async fn request<T: for<'a> Deserialize<'a>>(
        &self,
        method: Method,
        suffix: &str,
        body: Vec<u8>,
    ) -> Result<Option<T>> {
        let allow_missing = !suffix.is_empty() && suffix.starts_with('/');
        let request = Request::builder()
            .method(method)
            .uri(format!("{}{suffix}", self.path))
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))?;
        timeout(API_TIMEOUT, async {
            let response = self
                .client
                .request(request)
                .await
                .context("DNS provider HTTPS request failed")?;
            let status = response.status();
            if allow_missing && status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            ensure!(status.is_success(), "DNS provider returned HTTP {status}");
            let bytes = Limited::new(response.into_body(), 64 * 1024)
                .collect()
                .await
                .map_err(|_| anyhow::anyhow!("invalid DNS provider response body"))?
                .to_bytes();
            let response: Envelope<T> = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid DNS provider response"))?;
            ensure!(
                response.success,
                "DNS provider reported an unsuccessful operation"
            );
            Ok(response.result)
        })
        .await
        .context("DNS provider request timed out")?
    }
}

fn same_record(entry: &DnsRecord, pending: &Pending) -> bool {
    let content = entry
        .content
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(&entry.content);
    entry.kind == "TXT"
        && entry
            .name
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&pending.name)
        && content == pending.content
        && entry.comment.as_deref() == Some(pending.comment.as_str())
}

fn in_zone(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_piece(input: &str) -> bool {
    input
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

pub(crate) async fn validate_journal(config: Option<&Dns01>, state_dir: &Path) -> Result<()> {
    let Some(bytes) = read_saved(&state_dir.join(JOURNAL_FILE)).await? else {
        return Ok(());
    };
    let journal: Journal = serde_json::from_slice(&bytes).context("read DNS-01 cleanup journal")?;
    ensure!(
        journal.records.is_empty()
            || config.is_some_and(|config| {
                config.zone_id == journal.zone_id && config.api_base == journal.api_base
            }),
        "pending DNS-01 records require the original zone and API settings"
    );
    Ok(())
}
