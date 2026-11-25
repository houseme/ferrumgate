use std::{
    collections::HashSet,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::ResolvesServerCertUsingSni,
    sign::CertifiedKey,
};
use serde::Deserialize;
use tokio_rustls::TlsAcceptor;

use crate::config::{canonical_host, read_file};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertificateFiles {
    host: String,
    cert_file: PathBuf,
    key_file: PathBuf,
}

pub(crate) struct Tls {
    pub server: Option<TlsAcceptor>,
    pub client: ClientConfig,
}

pub(crate) async fn load<'a>(
    dir: &Path,
    enabled: bool,
    certificates: Vec<CertificateFiles>,
    upstream_ca_file: Option<&Path>,
    route_hosts: impl Iterator<Item = &'a String>,
) -> Result<Tls> {
    ensure!(
        enabled != certificates.is_empty() && certificates.len() <= 1024,
        "server.tls requires 1..=1024 certificates; HTTP requires an empty certificate list"
    );
    let provider = Arc::new(ring::default_provider());
    let server = if enabled {
        let mut resolver = ResolvesServerCertUsingSni::new();
        let mut names = HashSet::new();
        for (index, entry) in certificates.into_iter().enumerate() {
            let load = async {
                let name = canonical_host(&entry.host)
                    .filter(|name| !name.starts_with('[') && name.parse::<IpAddr>().is_err())
                    .context("expected an exact DNS name")?;
                ensure!(names.insert(name.to_string()), "duplicate certificate host");
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
                resolver
                    .add(&name, key)
                    .context("verify certificate DNS name")?;
                Ok::<_, anyhow::Error>(())
            };
            load.await
                .with_context(|| format!("invalid certificates[{index}]"))?;
        }
        ensure!(
            route_hosts.into_iter().all(|host| names.contains(host)),
            "every HTTPS route host requires a certificate entry"
        );
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
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

async fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = read_file(path).await.context("read certificate PEM")?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .context("invalid certificate PEM")?;
    ensure!(!certs.is_empty(), "missing PEM certificate");
    Ok(certs)
}
