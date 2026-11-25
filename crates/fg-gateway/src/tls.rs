use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{
        Acceptor, ClientHello, NoServerSessionStorage, ResolvesServerCert,
        ResolvesServerCertUsingSni,
    },
    sign::{CertifiedKey, SingleCertAndKey},
};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio_rustls::{LazyConfigAcceptor, server::TlsStream};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::{
    acme::Managed,
    config::{canonical_host, read_file},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertificateFiles {
    host: String,
    pub(crate) cert_file: PathBuf,
    pub(crate) key_file: PathBuf,
}

pub(crate) struct Tls {
    pub server: Option<ServerTls>,
    pub client: ClientConfig,
}

struct Resolver {
    exact: ResolvesServerCertUsingSni,
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    ip: HashMap<IpAddr, IpCertificate>,
    managed: Option<ManagedNames>,
}

struct ManagedNames {
    dns: Vec<String>,
    ips: Arc<[IpAddr]>,
    store: Arc<Managed>,
}

#[derive(Clone)]
pub(crate) struct ServerTls {
    base: Arc<ServerConfig>,
    resolver: Arc<Resolver>,
}

#[derive(Clone)]
pub(crate) enum ConnectionIdentity {
    Dns(Arc<str>),
    Ip(Arc<[IpAddr]>),
}

impl ConnectionIdentity {
    pub fn matches(&self, host: &str) -> bool {
        match self {
            Self::Dns(name) => name.as_ref() == host,
            Self::Ip(names) => ip_literal(host).is_some_and(|host| names.contains(&host)),
        }
    }
}

struct IpCertificate {
    key: Arc<CertifiedKey>,
    starts: i64,
    expires: i64,
    hosts: Arc<[IpAddr]>,
}

impl ServerTls {
    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> io::Result<(TlsStream<TcpStream>, ConnectionIdentity)> {
        let local = stream.local_addr()?.ip();
        let handshake = LazyConfigAcceptor::new(Acceptor::default(), stream).await?;
        let (config, identity) = if let Some(name) = handshake.client_hello().server_name() {
            (self.base.clone(), ConnectionIdentity::Dns(Arc::from(name)))
        } else {
            let (key, hosts) = self.resolver.ip_certificate(local).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no valid IP certificate for a TLS connection without SNI",
                )
            })?;
            let mut config = (*self.base).clone();
            config.cert_resolver = Arc::new(SingleCertAndKey::from(key));
            // IP identities share no SNI name on which to bind resumed sessions.
            config.session_storage = Arc::new(NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
            (Arc::new(config), ConnectionIdentity::Ip(hosts))
        };
        Ok((handshake.into_stream(config).await?, identity))
    }
}

impl Resolver {
    fn ip_certificate(&self, local: IpAddr) -> Option<(Arc<CertifiedKey>, Arc<[IpAddr]>)> {
        let now = crate::acme::unix_now();
        let mapped = match local {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4),
            IpAddr::V4(_) => None,
        };
        let managed = self
            .managed
            .as_ref()
            .filter(|entry| !entry.ips.is_empty())
            .and_then(|entry| {
                let certificate = entry.store.certificate.load_full()?;
                Some(IpCertificate {
                    key: certificate.key.clone(),
                    starts: certificate.starts,
                    expires: certificate.expires,
                    hosts: entry.ips.clone(),
                })
            });
        let valid = |entry: &&IpCertificate| entry.starts <= now && entry.expires > now;
        let match_ip = |ip| {
            self.ip.get(&ip).filter(valid).or_else(|| {
                managed
                    .as_ref()
                    .filter(valid)
                    .filter(|entry| entry.hosts.contains(&ip))
            })
        };
        let preferred = match_ip(local).or_else(|| mapped.and_then(match_ip));
        preferred
            .or_else(|| {
                self.ip
                    .values()
                    .chain(managed.as_ref())
                    .filter(valid)
                    .max_by_key(|entry| (entry.expires, std::cmp::Reverse(entry.hosts[0])))
            })
            .map(|entry| (entry.key.clone(), entry.hosts.clone()))
    }
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let managed = self.managed.as_ref().filter(|names| {
            hello
                .server_name()
                .is_some_and(|host| managed_covers(&names.dns, host))
        });
        let wildcard = hello
            .server_name()
            .and_then(|name| name.split_once('.'))
            .and_then(|(_, suffix)| self.wildcard.get(suffix));
        self.exact
            .resolve(hello)
            .or_else(|| {
                managed
                    .and_then(|names| names.store.certificate.load_full())
                    .map(|cert| cert.key.clone())
            })
            .or_else(|| wildcard.cloned())
    }
}

pub(crate) async fn load<'a>(
    dir: &Path,
    enabled: bool,
    certificates: Vec<CertificateFiles>,
    upstream_ca_file: Option<&Path>,
    route_hosts: impl Iterator<Item = &'a String>,
    managed: Option<(Vec<String>, Arc<Managed>)>,
) -> Result<Tls> {
    ensure!(
        enabled == (!certificates.is_empty() || managed.is_some()) && certificates.len() <= 1024,
        "server.tls requires manual or managed certificates; HTTP requires an empty certificate list"
    );
    let provider = Arc::new(ring::default_provider());
    let server = if enabled {
        let mut names: HashSet<String> = managed
            .iter()
            .flat_map(|(domains, _)| domains.iter().cloned())
            .collect();
        let mut resolver = Resolver {
            exact: ResolvesServerCertUsingSni::new(),
            wildcard: HashMap::new(),
            ip: HashMap::new(),
            managed: managed.map(|(domains, store)| {
                let ips = domains
                    .iter()
                    .filter_map(|name| ip_literal(name))
                    .collect::<Vec<_>>();
                let dns = domains
                    .into_iter()
                    .filter(|name| ip_literal(name).is_none())
                    .collect();
                ManagedNames {
                    dns,
                    ips: Arc::from(ips),
                    store,
                }
            }),
        };
        for (index, entry) in certificates.into_iter().enumerate() {
            let load = async {
                let wildcard = entry.host.strip_prefix("*.");
                let domain = canonical_host(wildcard.unwrap_or(&entry.host))
                    .context("expected a DNS name, *.suffix, or IP address")?;
                let ip = ip_literal(&domain);
                ensure!(
                    wildcard.is_none() || ip.is_none(),
                    "IP wildcard certificates are invalid"
                );
                let name = if wildcard.is_some() {
                    format!("*.{domain}")
                } else {
                    domain.to_string()
                };
                ensure!(names.insert(name.clone()), "duplicate certificate host");
                let chain = read_certificates(&dir.join(entry.cert_file)).await?;
                let key_bytes = read_file(&dir.join(entry.key_file))
                    .await
                    .context("read key file")?;
                let mut keys = PrivateKeyDer::pem_slice_iter(&key_bytes);
                let key = keys
                    .next()
                    .context("missing PEM private key")?
                    .context("invalid PEM private key")?;
                ensure!(keys.next().is_none(), "expected one PEM private key");
                let key = CertifiedKey::from_der(chain, key, &provider)
                    .context("could not load certificate and key")?;
                key.keys_match()
                    .context("verify certificate and private key match")?;
                if let Some(ip) = ip {
                    verify_ip(&key, ip)?;
                    let (starts, expires) = validity(&key)?;
                    resolver.ip.insert(
                        ip,
                        IpCertificate {
                            key: Arc::new(key),
                            starts,
                            expires,
                            hosts: Arc::from([ip]),
                        },
                    );
                } else if wildcard.is_some() {
                    verify_wildcard(&key, &name)?;
                    resolver.wildcard.insert(domain.into_owned(), Arc::new(key));
                } else {
                    resolver
                        .exact
                        .add(&name, key)
                        .context("verify certificate DNS name")?;
                }
                Ok::<_, anyhow::Error>(())
            };
            load.await
                .with_context(|| format!("invalid certificates[{index}]"))?;
        }
        ensure!(
            route_hosts.into_iter().all(|host| {
                host.contains('*')
                    || names.contains(host)
                    || resolver
                        .managed
                        .as_ref()
                        .is_some_and(|names| managed_covers(&names.dns, host))
                    || host
                        .split_once('.')
                        .is_some_and(|(_, suffix)| resolver.wildcard.contains_key(suffix))
            }),
            "every exact HTTPS route host requires a covering certificate entry"
        );
        let resolver = Arc::new(resolver);
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Some(ServerTls {
            base: Arc::new(server),
            resolver,
        })
    } else {
        None
    };

    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(file) = upstream_ca_file {
        for cert in read_certificates(&dir.join(file))
            .await
            .context("load upstream_ca_file")?
        {
            roots.add(cert).context("invalid upstream trust anchor")?;
        }
    }
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(Tls { server, client })
}

fn managed_covers(domains: &[String], host: &str) -> bool {
    domains
        .binary_search_by(|name| name.as_str().cmp(host))
        .is_ok()
        || host.split_once('.').is_some_and(|(_, suffix)| {
            domains
                .iter()
                .any(|name| name.strip_prefix("*.") == Some(suffix))
        })
}

pub(crate) fn ip_literal(host: &str) -> Option<IpAddr> {
    match host.strip_prefix('[').and_then(|ip| ip.strip_suffix(']')) {
        Some(ip) => ip.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6),
        None => host.parse().ok(),
    }
}

fn validity(key: &CertifiedKey) -> Result<(i64, i64)> {
    let (_, leaf) = X509Certificate::from_der(key.end_entity_cert()?.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid leaf certificate"))?;
    let validity = leaf.validity();
    Ok((
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    ))
}

pub(crate) fn verify_ip(key: &CertifiedKey, ip: IpAddr) -> Result<()> {
    let (_, leaf) = X509Certificate::from_der(key.end_entity_cert()?.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid leaf certificate"))?;
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| anyhow::anyhow!("invalid certificate SAN"))?
        .context("IP certificate needs SAN")?;
    ensure!(
        san.value.general_names.iter().any(|entry| match entry {
            GeneralName::IPAddress(bytes) => match ip {
                IpAddr::V4(ip) => *bytes == ip.octets(),
                IpAddr::V6(ip) => *bytes == ip.octets(),
            },
            _ => false,
        }),
        "certificate SAN does not include the configured IP address"
    );
    Ok(())
}

pub(crate) fn verify_wildcard(key: &CertifiedKey, name: &str) -> Result<()> {
    let (_, leaf) = X509Certificate::from_der(key.end_entity_cert()?.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid leaf certificate"))?;
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| anyhow::anyhow!("invalid certificate SAN"))?
        .context("wildcard certificate needs SAN")?;
    ensure!(
        san.value.general_names.iter().any(
            |entry| matches!(entry, GeneralName::DNSName(value) if value.eq_ignore_ascii_case(name))
        ),
        "certificate SAN does not include the wildcard name"
    );
    Ok(())
}

async fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = read_file(path).await.context("read certificate PEM")?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .context("invalid certificate PEM")?;
    ensure!(!certs.is_empty(), "missing PEM certificate");
    Ok(certs)
}
