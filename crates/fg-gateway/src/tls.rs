use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni},
    sign::CertifiedKey,
};
use serde::Deserialize;
use tokio_rustls::TlsAcceptor;
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
    pub server: Option<TlsAcceptor>,
    pub client: ClientConfig,
}

struct Resolver {
    exact: ResolvesServerCertUsingSni,
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    managed: Option<(Vec<String>, Arc<Managed>)>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let managed = self.managed.as_ref().filter(|(domains, _)| {
            hello
                .server_name()
                .is_some_and(|host| managed_covers(domains, host))
        });
        let wildcard = hello
            .server_name()
            .and_then(|name| name.split_once('.'))
            .and_then(|(_, suffix)| self.wildcard.get(suffix));
        self.exact
            .resolve(hello)
            .or_else(|| managed.and_then(|(_, store)| store.certificate.load_full()))
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
        let mut resolver = Resolver {
            exact: ResolvesServerCertUsingSni::new(),
            wildcard: HashMap::new(),
            managed,
        };
        let mut names: HashSet<String> = resolver
            .managed
            .iter()
            .flat_map(|(domains, _)| domains.iter().cloned())
            .collect();
        for (index, entry) in certificates.into_iter().enumerate() {
            let load = async {
                let wildcard = entry.host.strip_prefix("*.");
                let domain = canonical_host(wildcard.unwrap_or(&entry.host))
                    .filter(|name| !name.starts_with('[') && name.parse::<IpAddr>().is_err())
                    .context("expected a DNS name or *.suffix")?;
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
                if wildcard.is_some() {
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
                        .is_some_and(|(names, _)| managed_covers(names, host))
                    || host
                        .split_once('.')
                        .is_some_and(|(_, suffix)| resolver.wildcard.contains_key(suffix))
            }),
            "every exact HTTPS route host requires a covering certificate entry"
        );
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Some(TlsAcceptor::from(Arc::new(server)))
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
