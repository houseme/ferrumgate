use std::{
    collections::HashSet,
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
    net::{DnsError, NetError, runtime::TokioRuntimeProvider},
    proto::{
        op::ResponseCode,
        rr::{RData, RecordType},
    },
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
#[derive(serde::Serialize)]
pub struct RawDns01 {
    zone: Option<String>,
    zone_id: Option<String>,
    token_file: PathBuf,
    resolver: SocketAddr,
    api_base: Option<String>,
    api_ca_file: Option<PathBuf>,
    propagation_timeout_secs: Option<u32>,
    follow_cname: Option<bool>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Dns01 {
    zone: Option<Zone>,
    api_base: String,
    api_ca_file: Option<PathBuf>,
    pub token_file: PathBuf,
    resolver: SocketAddr,
    propagation_timeout: Duration,
    follow_cname: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Zone {
    name: String,
    id: String,
}

#[derive(Serialize, Deserialize)]
struct Journal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zone_id: Option<String>,
    api_base: String,
    records: Vec<Pending>,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    name: String,
    content: String,
    comment: String,
    record_id: Option<String>,
    #[serde(default)]
    zone: Option<Zone>,
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
    api_base: String,
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
        let follow_cname = raw.follow_cname.unwrap_or(true);
        let zone = match (raw.zone, raw.zone_id) {
            (None, None) => None,
            (Some(name), Some(id)) => {
                let name = canonical_host(&name)
                    .filter(|name| name.contains('.') && name.parse::<IpAddr>().is_err())
                    .context("DNS-01 zone must be a DNS name")?
                    .into_owned();
                ensure!(
                    valid_id(&id),
                    "DNS-01 zone_id must be a 32-character Cloudflare ID"
                );
                ensure!(
                    follow_cname
                        || domains.iter().all(|domain| {
                            in_zone(domain.strip_prefix("*.").unwrap_or(domain), &name)
                        }),
                    "DNS-01 domains must be within the configured zone"
                );
                Some(Zone {
                    name,
                    id: id.to_ascii_lowercase(),
                })
            }
            _ => anyhow::bail!("provide both DNS-01 zone and zone_id, or omit both for discovery"),
        };
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
            api_base: api_base.trim_end_matches('/').to_owned(),
            api_ca_file: raw.api_ca_file.map(|path| dir.join(path)),
            token_file: dir.join(raw.token_file),
            resolver: raw.resolver,
            propagation_timeout: Duration::from_secs(u64::from(propagation_timeout)),
            follow_cname,
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
                zone_id: None,
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
            journal.api_base == self.api_base,
            "DNS-01 cleanup journal belongs to another zone or API"
        );
        let client = self.client().await?;
        while let Some(record) = journal.records.last() {
            let zone = self.record_zone(&journal, record)?;
            ensure!(
                valid_owner(&record.name)
                    && in_zone(&record.name, &zone.name)
                    && record
                        .comment
                        .strip_prefix("ferrumgate-")
                        .is_some_and(|tag| tag.len() == 22 && safe_piece(tag)),
                "invalid record in DNS-01 cleanup journal"
            );
            client.retire(zone, record).await?;
            journal.records.pop();
            persist_private(state_dir, JOURNAL_FILE, lock, serde_json::to_vec(&journal)?).await?;
        }
        Ok(())
    }

    fn record_zone<'a>(&'a self, journal: &Journal, record: &'a Pending) -> Result<&'a Zone> {
        if let Some(zone) = &record.zone {
            ensure!(
                valid_id(&zone.id)
                    && valid_owner(&zone.name)
                    && self
                        .zone
                        .as_ref()
                        .is_none_or(|configured| configured == zone),
                "DNS-01 cleanup record belongs to another zone"
            );
            return Ok(zone);
        }
        self.zone
            .as_ref()
            .filter(|zone| journal.zone_id.as_deref() == Some(zone.id.as_str()))
            .context("legacy DNS-01 cleanup journal needs its original explicit zone")
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
            api_base: self.api_base.clone(),
        })
    }
}

impl OrderDns<'_> {
    pub async fn provision(&mut self, domain: &str, content: String) -> Result<()> {
        let domain = domain.strip_prefix("*.").unwrap_or(domain);
        let source = format!("_acme-challenge.{domain}");
        ensure!(valid_owner(&source), "invalid DNS-01 challenge owner");
        let name = if self.config.follow_cname {
            delegated_owner(&self.resolver, &source).await?
        } else {
            source.clone()
        };
        let zone = match &self.config.zone {
            Some(zone) => zone.clone(),
            None => {
                let name = authority_zone(&self.resolver, &name).await?;
                self.cf.find_zone(&name).await?
            }
        };
        ensure!(
            in_zone(&name, &zone.name),
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
            zone: Some(zone.clone()),
            created_at: unix_now(),
        });
        self.save().await?;
        let record = self
            .journal
            .records
            .last_mut()
            .expect("created journal record");
        let created = self.cf.create(&zone, record).await?;
        record.record_id = Some(created.id);
        self.save().await?;
        let record = self.journal.records.last().expect("saved journal record");
        let fqdn = format!("{source}.");
        timeout(self.config.propagation_timeout, async {
            loop {
                if let Ok(reply) = self.resolver.txt_lookup(fqdn.as_str()).await
                    && reply
                        .answers()
                        .iter()
                        .filter(|answer| {
                            answer
                                .name
                                .to_ascii()
                                .trim_end_matches('.')
                                .eq_ignore_ascii_case(&record.name)
                        })
                        .any(|answer| match &answer.data {
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
    async fn find_zone(&self, name: &str) -> Result<Zone> {
        let uri = format!("/zones?name={name}&status=active&per_page=50");
        let zones: Vec<ProviderZone> = self
            .request(Method::GET, &uri, Vec::new(), false)
            .await?
            .context("missing Cloudflare zone list")?;
        ensure!(
            zones.len() < 50,
            "Cloudflare zone results may be incomplete"
        );
        let mut zones = zones
            .into_iter()
            .filter(|zone| zone.name.eq_ignore_ascii_case(name) && zone.status == "active");
        let found = zones
            .next()
            .context("authoritative DNS zone is unavailable in Cloudflare")?;
        ensure!(
            zones.next().is_none(),
            "Cloudflare returned multiple active zones with the same name"
        );
        ensure!(
            valid_id(&found.id),
            "Cloudflare returned an invalid zone ID"
        );
        Ok(Zone {
            name: name.to_owned(),
            id: found.id.to_ascii_lowercase(),
        })
    }

    async fn create(&self, zone: &Zone, record: &Pending) -> Result<DnsRecord> {
        let body = serde_json::to_vec(&serde_json::json!({
            "type": "TXT",
            "name": record.name,
            "content": record.content,
            "ttl": 120,
            "comment": record.comment,
        }))?;
        let response: DnsRecord = self
            .request(Method::POST, &zone.records_path(), body, false)
            .await?
            .context("missing DNS provider record")?;
        ensure!(
            valid_id(&response.id) && same_record(&response, record),
            "DNS provider returned an unexpected record"
        );
        Ok(response)
    }

    async fn retire(&self, zone: &Zone, record: &Pending) -> Result<()> {
        if let Some(id) = &record.record_id {
            ensure!(valid_id(id), "invalid DNS record ID in cleanup journal");
            return self.remove_if_owned(zone, id, record).await;
        }
        let query = format!(
            "{}?type=TXT&name.exact={}&comment.exact={}&per_page=100",
            zone.records_path(),
            record.name,
            record.comment
        );
        let records: Vec<DnsRecord> = self
            .request(Method::GET, &query, Vec::new(), false)
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
            self.remove_if_owned(zone, &entry.id, record).await?;
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

    async fn remove_if_owned(&self, zone: &Zone, id: &str, record: &Pending) -> Result<()> {
        let uri = format!("{}/{id}", zone.records_path());
        let current: Option<DnsRecord> = self.request(Method::GET, &uri, Vec::new(), true).await?;
        if current.is_some_and(|current| current.id == id && same_record(&current, record)) {
            let _: Option<serde_json::Value> =
                self.request(Method::DELETE, &uri, Vec::new(), true).await?;
        }
        Ok(())
    }

    async fn request<T: for<'a> Deserialize<'a>>(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
        allow_missing: bool,
    ) -> Result<Option<T>> {
        let request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.api_base))
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

#[derive(Deserialize)]
struct ProviderZone {
    id: String,
    name: String,
    status: String,
}

impl Zone {
    fn records_path(&self) -> String {
        format!("/zones/{}/dns_records", self.id)
    }
}

async fn authority_zone(resolver: &TokioResolver, owner: &str) -> Result<String> {
    let mut candidate = owner;
    loop {
        let name = format!("{candidate}.");
        let soa = match resolver.lookup(name.as_str(), RecordType::SOA).await {
            Ok(answer) => answer
                .answers()
                .iter()
                .chain(answer.authorities())
                .filter(|record| matches!(record.data, RData::SOA(_)))
                .map(|record| record.name.to_ascii())
                .max_by_key(|name| name.len()),
            Err(error) if dns_absence(&error) => {
                error.into_soa().map(|record| record.name.to_ascii())
            }
            Err(error) => return Err(error).context("look up DNS-01 authoritative zone"),
        };
        if let Some(soa) = soa {
            let zone = canonical_host(&soa)
                .filter(|zone| in_zone(owner, zone) && valid_owner(zone))
                .context("DNS SOA does not cover the challenge name")?;
            return Ok(zone.into_owned());
        }
        candidate = candidate
            .split_once('.')
            .map(|(_, suffix)| suffix)
            .filter(|suffix| suffix.contains('.'))
            .context("cannot discover authoritative DNS-01 zone; configure zone and zone_id")?;
    }
}

async fn delegated_owner(resolver: &TokioResolver, source: &str) -> Result<String> {
    let mut owner = source.to_owned();
    let mut visited = HashSet::from([owner.clone()]);
    for depth in 0..=8 {
        let Some(target) = cname(resolver, &owner).await? else {
            return Ok(owner);
        };
        if depth == 0 {
            let (_, parent) = owner.split_once('.').expect("challenge owner has a parent");
            let mut random = [0; 4];
            SystemRandom::new()
                .fill(&mut random)
                .map_err(|_| anyhow::anyhow!("generate CNAME probe label"))?;
            let sibling = format!(
                "fgate-{}.{parent}",
                random
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            if cname(resolver, &sibling).await?.as_deref() == Some(target.as_str()) {
                return Ok(owner);
            }
        }
        ensure!(
            depth < 8 && visited.insert(target.clone()),
            "DNS-01 CNAME chain is cyclic or too long"
        );
        owner = target;
    }
    unreachable!("CNAME chain limit")
}

async fn cname(resolver: &TokioResolver, owner: &str) -> Result<Option<String>> {
    let fqdn = format!("{owner}.");
    let answer = match resolver.lookup(fqdn.as_str(), RecordType::CNAME).await {
        Ok(answer) => answer,
        Err(error) if dns_absence(&error) => return Ok(None),
        Err(error) => return Err(error).context("lookup DNS-01 CNAME"),
    };
    let mut names = answer.answers().iter().filter_map(|record| {
        if let RData::CNAME(name) = &record.data
            && record
                .name
                .to_ascii()
                .trim_end_matches('.')
                .eq_ignore_ascii_case(owner)
        {
            return Some(name.0.to_ascii().trim_end_matches('.').to_ascii_lowercase());
        }
        None
    });
    let Some(target) = names.next() else {
        return Ok(None);
    };
    ensure!(
        names.next().is_none() && valid_owner(&target),
        "invalid DNS-01 CNAME target"
    );
    Ok(Some(target))
}

fn dns_absence(error: &NetError) -> bool {
    matches!(error, NetError::Dns(DnsError::NoRecordsFound(result))
        if matches!(result.response_code, ResponseCode::NoError | ResponseCode::NXDomain))
}

fn valid_owner(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && safe_piece(name)
        && name.split('.').all(|label| (1..=63).contains(&label.len()))
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
    if journal.records.is_empty() {
        return Ok(());
    }
    let config = config.context("pending DNS-01 records require the original API settings")?;
    ensure!(
        config.api_base == journal.api_base,
        "pending DNS-01 records require the original API settings"
    );
    for record in &journal.records {
        config.record_zone(&journal, record)?;
    }
    Ok(())
}
