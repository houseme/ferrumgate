use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use hyper::http::uri::{Authority, PathAndQuery};
use serde::Deserialize;
use tokio::{fs, io::AsyncReadExt};

use crate::{
    acme::{AcmeConfig, Managed, RawAcme},
    backend::{BackendPool, RawBackend},
    domains,
    forward_ports::MAX_LISTENERS,
    health::{HealthCheck, RawHealthCheck},
    site::{RawResponse, SiteResponse},
    tcp_forward::{RawForward, TcpForward},
    tls::{self, CertificateFiles, Tls},
    udp_forward::{RawUdpForward, UdpForward},
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ROUTES: usize = 1024;
const MAX_BACKENDS: usize = 2048;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u32,
    #[serde(default)]
    server: Settings,
    #[serde(default)]
    routes: Vec<RawRoute>,
    #[serde(default)]
    tcp_forward: Vec<RawForward>,
    #[serde(default)]
    udp_forward: Vec<RawUdpForward>,
    #[serde(default)]
    certificates: Vec<CertificateFiles>,
    upstream_ca_file: Option<PathBuf>,
    acme: Option<RawAcme>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Settings {
    pub listen: SocketAddr,
    pub http_enabled: bool,
    pub tls: bool,
    pub tls_handshake_timeout_ms: u64,
    pub max_connections: usize,
    pub header_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub response_header_timeout_ms: u64,
    pub connection_lifetime_ms: u64,
    pub shutdown_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            http_enabled: true,
            tls: false,
            tls_handshake_timeout_ms: 5_000,
            max_connections: 1024,
            header_timeout_ms: 5_000,
            connect_timeout_ms: 2_000,
            response_header_timeout_ms: 30_000,
            connection_lifetime_ms: 300_000,
            shutdown_timeout_ms: 10_000,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    host: String,
    path_prefix: Option<String>,
    upstream: Option<String>,
    #[serde(default)]
    backends: Vec<RawBackend>,
    #[serde(default)]
    websocket: bool,
    #[serde(default)]
    upstream_h2c: bool,
    health: Option<RawHealthCheck>,
    response: Option<RawResponse>,
}

pub(crate) struct Config {
    pub settings: Settings,
    pub routes: Routes,
    pub tls: Tls,
    pub acme: Option<AcmeConfig>,
    pub tcp_forward: Vec<TcpForward>,
    pub udp_forward: Vec<UdpForward>,
}

pub(crate) struct Routes {
    by_host: HashMap<String, Vec<Route>>,
    wildcards: Vec<String>,
}

pub(crate) struct Route {
    pub prefix: String,
    pub action: RouteAction,
}

pub(crate) enum RouteAction {
    Proxy(ProxyRoute),
    Response(SiteResponse),
}

pub(crate) struct ProxyRoute {
    pub backends: BackendPool,
    pub websocket: bool,
    pub upstream_h2c: bool,
    pub health: Option<HealthCheck>,
}

impl Routes {
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Route)> {
        self.by_host
            .iter()
            .flat_map(|(host, routes)| routes.iter().map(|route| (host.as_str(), route)))
    }

    pub fn find(&self, host: &str, path: &str) -> Option<&Route> {
        let routes = self.by_host.get(host).or_else(|| {
            let matching = self
                .wildcards
                .iter()
                .find(|pattern| domains::matches(pattern, host))?;
            self.by_host.get(matching)
        })?;
        routes.iter().find(|route| {
            route.prefix == "/"
                || path
                    .strip_prefix(&route.prefix)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    }
}

pub(crate) async fn read_file(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        fs::metadata(path).await.context("inspect file")?.is_file(),
        "expected a regular file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)
        .await
        .context("open file")?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .context("read file")?;
    ensure!(bytes.len() as u64 <= MAX_CONFIG_BYTES, "file exceeds 1 MiB");
    Ok(bytes)
}

pub(crate) async fn load(path: &Path, managed: Arc<Managed>) -> Result<Config> {
    let bytes = read_file(path).await.context("read configuration")?;
    let input = std::str::from_utf8(&bytes).context("config must be UTF-8")?;
    let dir = path.parent().context("configuration must name a file")?;
    let raw: RawConfig = toml::from_str(input).map_err(|error| {
        let offset = error.span().map_or(0, |span| span.start);
        let line = input.as_bytes()[..offset]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count()
            + 1;
        anyhow::anyhow!("invalid configuration schema or TOML near line {line}")
    })?;
    ensure!(raw.schema_version == 1, "schema_version must be 1");
    let settings = raw.server;
    ensure!(
        (1..=65_535).contains(&settings.max_connections),
        "max_connections must be in 1..=65535"
    );
    for (field, value, max) in [
        ("header_timeout_ms", settings.header_timeout_ms, 300_000),
        (
            "tls_handshake_timeout_ms",
            settings.tls_handshake_timeout_ms,
            300_000,
        ),
        ("connect_timeout_ms", settings.connect_timeout_ms, 300_000),
        (
            "response_header_timeout_ms",
            settings.response_header_timeout_ms,
            300_000,
        ),
        (
            "connection_lifetime_ms",
            settings.connection_lifetime_ms,
            86_400_000,
        ),
        ("shutdown_timeout_ms", settings.shutdown_timeout_ms, 300_000),
    ] {
        ensure!((1..=max).contains(&value), "{field} must be in 1..={max}");
    }
    if settings.http_enabled {
        ensure!(
            (1..=MAX_ROUTES).contains(&raw.routes.len()),
            "routes must contain 1..={MAX_ROUTES} entries"
        );
    } else {
        ensure!(
            raw.routes.is_empty()
                && !settings.tls
                && raw.certificates.is_empty()
                && raw.upstream_ca_file.is_none(),
            "HTTP and TLS route configuration requires server.http_enabled"
        );
        ensure!(
            !raw.tcp_forward.is_empty() || !raw.udp_forward.is_empty(),
            "enable HTTP or configure TCP/UDP forwarding"
        );
    }
    ensure!(
        raw.tcp_forward.len() <= MAX_LISTENERS,
        "tcp_forward supports up to {MAX_LISTENERS} listeners"
    );
    let mut listens = HashSet::new();
    if settings.http_enabled && settings.listen.port() != 0 {
        listens.insert(settings.listen);
    }
    let mut tcp_forward = Vec::with_capacity(raw.tcp_forward.len());
    for (index, raw) in raw.tcp_forward.into_iter().enumerate() {
        let rules =
            TcpForward::compile(raw).with_context(|| format!("invalid tcp_forward[{index}]"))?;
        ensure!(
            tcp_forward.len() + rules.len() <= MAX_LISTENERS,
            "tcp_forward supports up to {MAX_LISTENERS} listeners"
        );
        for rule in rules {
            ensure!(
                rule.listen.port() == 0 || listens.insert(rule.listen),
                "duplicate TCP listener at tcp_forward[{index}]"
            );
            tcp_forward.push(rule);
        }
    }

    ensure!(
        raw.udp_forward.len() <= MAX_LISTENERS,
        "udp_forward supports up to {MAX_LISTENERS} listeners"
    );
    let mut udp_listens = HashSet::new();
    let mut udp_forward = Vec::with_capacity(raw.udp_forward.len());
    let mut udp_sessions = 0;
    for (index, raw) in raw.udp_forward.into_iter().enumerate() {
        let rules =
            UdpForward::compile(raw).with_context(|| format!("invalid udp_forward[{index}]"))?;
        ensure!(
            udp_forward.len() + rules.len() <= MAX_LISTENERS,
            "udp_forward supports up to {MAX_LISTENERS} listeners"
        );
        for rule in rules {
            ensure!(
                rule.listen.port() == 0 || udp_listens.insert(rule.listen),
                "duplicate UDP listener at udp_forward[{index}]"
            );
            udp_sessions += rule.max_sessions;
            ensure!(
                udp_sessions <= 4096,
                "udp_forward supports up to 4096 total sessions"
            );
            udp_forward.push(rule);
        }
    }
    let acme = if let Some(acme) = raw.acme {
        ensure!(
            settings.http_enabled && settings.tls,
            "ACME requires the TLS business listener"
        );
        let acme = AcmeConfig::compile(acme, dir).await?;
        ensure!(
            acme.challenge_listen
                .is_none_or(|listen| listen.port() == 0 || listens.insert(listen)),
            "duplicate ACME HTTP challenge listener"
        );
        Some(acme)
    } else {
        None
    };
    let protected: Vec<_> = raw
        .certificates
        .iter()
        .flat_map(|entry| [&entry.cert_file, &entry.key_file])
        .chain(raw.upstream_ca_file.iter())
        .chain(acme.iter().flat_map(AcmeConfig::protected_paths))
        .cloned()
        .collect();
    let mut by_host: HashMap<String, Vec<Route>> = HashMap::new();
    let mut backend_count = 0;
    let mut wildcards = Vec::new();
    for (index, route) in raw.routes.into_iter().enumerate() {
        let host = domains::normalize(&route.host)
            .with_context(|| format!("invalid routes[{index}].host"))?;
        if host.contains('*') && !by_host.contains_key(&host) {
            wildcards.push(host.clone());
        }
        let prefix = route.path_prefix.unwrap_or_else(|| "/".into());
        ensure!(
            prefix.starts_with('/')
                && (prefix == "/" || !prefix.ends_with('/'))
                && prefix
                    .parse::<PathAndQuery>()
                    .is_ok_and(|value| value.path() == prefix),
            "invalid routes[{index}].path_prefix"
        );
        let action = if let Some(response) = route.response {
            ensure!(
                route.upstream.is_none()
                    && route.backends.is_empty()
                    && route.health.is_none()
                    && !route.websocket
                    && !route.upstream_h2c,
                "routes[{index}].response cannot have proxy settings"
            );
            RouteAction::Response(
                SiteResponse::compile(response, dir, &protected)
                    .await
                    .with_context(|| format!("invalid routes[{index}].response"))?,
            )
        } else {
            let health = route
                .health
                .map(HealthCheck::compile)
                .transpose()
                .with_context(|| format!("invalid routes[{index}].health"))?;
            let backends = BackendPool::compile(route.upstream, route.backends, route.upstream_h2c)
                .with_context(|| format!("invalid routes[{index}] backend pool"))?;
            backend_count += backends.len();
            ensure!(
                backend_count <= MAX_BACKENDS,
                "expected at most {MAX_BACKENDS} backends"
            );
            RouteAction::Proxy(ProxyRoute {
                backends,
                websocket: route.websocket,
                upstream_h2c: route.upstream_h2c,
                health,
            })
        };
        let list = by_host.entry(host).or_default();
        ensure!(
            !list.iter().any(|entry| entry.prefix == prefix),
            "duplicate host and path_prefix at routes[{index}]"
        );
        list.push(Route { prefix, action });
    }
    for list in by_host.values_mut() {
        list.sort_unstable_by_key(|route| std::cmp::Reverse(route.prefix.len()));
    }
    wildcards.sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
    let tls = tls::load(
        dir,
        settings.tls,
        raw.certificates,
        raw.upstream_ca_file.as_deref(),
        by_host.keys(),
        acme.as_ref().map(|acme| (acme.domains.clone(), managed)),
    )
    .await?;
    Ok(Config {
        tls,
        acme,
        tcp_forward,
        udp_forward,
        settings,
        routes: Routes { by_host, wildcards },
    })
}

pub(crate) fn valid_authority(authority: &Authority) -> bool {
    let text = authority.as_str();
    let host = authority.host();
    canonical_host(host).is_some()
        && (text == host
            || text.strip_prefix(host).is_some_and(|port| {
                port.starts_with(':') && authority.port_u16().is_some_and(|port| port != 0)
            }))
}

pub(crate) fn canonical_host(host: &str) -> Option<Cow<'_, str>> {
    if let Some(ipv6) = host.strip_prefix('[').and_then(|ip| ip.strip_suffix(']')) {
        let ip = ipv6.parse::<std::net::Ipv6Addr>().ok()?;
        return Some(Cow::Owned(format!("[{ip}]")));
    }
    if let Ok(IpAddr::V6(ip)) = host.parse() {
        return Some(Cow::Owned(format!("[{ip}]")));
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.len() > 253
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Some(Cow::Owned(host.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(host))
    }
}

pub(crate) fn milliseconds(value: u64) -> Duration {
    Duration::from_millis(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_the_routing_hostname() {
        assert_eq!(canonical_host("APP.Test.").as_deref(), Some("app.test"));
        assert_eq!(
            canonical_host("2001:0DB8::1").as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(
            canonical_host("[2001:db8::1]").as_deref(),
            Some("[2001:db8::1]")
        );
        assert!(canonical_host("app.test..").is_none());
        assert!(canonical_host("*.app.test").is_none());
    }

    #[test]
    fn accepts_only_host_and_optional_nonzero_port_as_authority() {
        for input in ["app.test", "app.test:8080", "[2001:db8::1]:8080"] {
            assert!(valid_authority(&input.parse().unwrap()), "{input}");
        }
        for input in ["user@app.test", "app.test:", "app.test:0", "app.test:65536"] {
            assert!(
                !input.parse().is_ok_and(|value| valid_authority(&value)),
                "{input}"
            );
        }
    }
}
