//! Default public-address lookup: try each public echo service for the
//! family until one answers with a parseable address.

use std::{net::IpAddr, pin::Pin, sync::Arc, time::Duration};

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;

use fg_admin::publicip::{Family, Lookup};

/// Third-party echo services, mirroring the upstream defaults; users can
/// point these elsewhere once the settings surface them.
const IPV4_URLS: [&str; 4] = [
    "https://ipv4.ddnspod.com",
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://myip.ipip.net",
];
const IPV6_URLS: [&str; 4] = [
    "https://ipv6.ddnspod.com",
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
    "https://v6.ident.me",
];

/// Builds the probe's HEAD lookup: a pooled client that accepts any
/// certificate, reporting only the status code.
pub fn probe_head() -> Result<fg_admin::probe::HeadLookup> {
    let client = fg_gateway_client()?;
    Ok(Arc::new(move |hostport: String, https: bool| {
        let client = client.clone();
        let authority = format!("{}://{hostport}/", if https { "https" } else { "http" });
        Box::pin(async move {
            let uri =
                hyper::Uri::try_from(authority.as_str()).map_err(|error| error.to_string())?;
            let request = hyper::Request::builder()
                .method(hyper::Method::HEAD)
                .uri(uri)
                .body(Full::new(Bytes::new()))
                .map_err(|error| error.to_string())?;
            let response = tokio::time::timeout(Duration::from_secs(10), client.request(request))
                .await
                .map_err(|_| "operation timed out".to_owned())?
                .map_err(|error| error.to_string())?;
            Ok(response.status().as_u16())
        }) as Pin<Box<dyn std::future::Future<Output = Result<u16, String>> + Send>>
    }))
}

/// Builds the production lookup used by the management process.
pub fn lookup() -> Result<Lookup> {
    let client = fg_gateway_client()?;
    Ok(Arc::new(move |family: Family| {
        let client = client.clone();
        Box::pin(async move {
            let urls = match family {
                Family::Ipv4 => IPV4_URLS,
                Family::Ipv6 => IPV6_URLS,
            };
            let mut last_error = String::from("没有可用的查询地址");
            for url in urls {
                match fetch(&client, url).await {
                    Ok(address) => {
                        if matches_family(address, family) {
                            return Ok(address);
                        }
                        last_error = format!("{url} 返回了错误地址族的地址 {address}");
                    }
                    Err(error) => last_error = format!("{url}: {error}"),
                }
            }
            Err(last_error)
        }) as Pin<Box<dyn std::future::Future<Output = _> + Send>>
    }))
}

fn matches_family(address: IpAddr, family: Family) -> bool {
    match family {
        Family::Ipv4 => address.is_ipv4(),
        Family::Ipv6 => address.is_ipv6(),
    }
}

type HttpClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

fn fg_gateway_client() -> Result<HttpClient> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    Ok(
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .retry_canceled_requests(false)
            .build(https),
    )
}

async fn fetch(client: &HttpClient, url: &str) -> Result<IpAddr> {
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.get(hyper::Uri::try_from(url)?),
    )
    .await??;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        anyhow::bail!("HTTP {status}");
    }
    let text = String::from_utf8_lossy(&body);
    // Services answer with the bare address, sometimes with a trailing
    // newline or a sentence; find the address token within.
    let address = text
        .split_whitespace()
        .find_map(|token| token.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow::anyhow!("响应不含地址"))?;
    Ok(address)
}
