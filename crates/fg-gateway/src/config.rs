use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use hyper::http::uri::{Authority, PathAndQuery};
use tokio::{fs, io::AsyncReadExt};

use crate::{
    acme::{AcmeConfig, Managed},
    backend::BackendPool,
    domains,
    forward_ports::MAX_LISTENERS,
    health::HealthCheck,
    l4::portforward::bridge,
    site::SiteResponse,
    tcp_forward::TcpForward,
    tls::{self, Tls},
    udp_forward::UdpForward,
    web::{
        identity::IdentityHeader,
        proxy::{cors::Cors, headers::HeaderEdit, rewrite::Rewrite},
        upstream::Policy,
    },
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ROUTES: usize = 1024;
const MAX_BACKENDS: usize = 2048;

// The legacy TOML shapes live in `legacy_config` (WP-39 step 1) so the
// migration tool shares exactly what this loader validated.
use crate::legacy_config::RawConfig;
pub(crate) use crate::legacy_config::Settings;

pub(crate) struct Config {
    pub disabled_modules: Vec<String>,
    pub settings: Settings,
    pub routes: Routes,
    pub tls: Tls,
    pub acme: Option<AcmeConfig>,
    pub tcp_forward: Vec<TcpForward>,
    pub udp_forward: Vec<UdpForward>,
    /// WP-31 ssl.json certificate state (empty provider when the file is
    /// absent); the renewal scheduler keeps the live generation current.
    pub certs: Arc<crate::certs::SslState>,
}

pub(crate) struct Routes {
    // `pub(crate)` so `web::bridge` can assemble the table for the
    // webservice model (WP-20 step 5); `load` remains the other
    // constructor.
    pub(crate) by_host: HashMap<String, Vec<Route>>,
    pub(crate) wildcards: Vec<String>,
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
    /// WP-23 per-site options. The TOML path uses the legacy behavior:
    /// always send the target host, always forward, nothing else.
    pub options: Box<SiteProxyOptions>,
}

/// The WP-23 per-site reverse-proxy options, compiled once per site.
pub(crate) struct SiteProxyOptions {
    /// Send the target address as `Host` (legacy behavior) instead of
    /// keeping the client's `Host`.
    pub use_target_host: bool,
    /// Write X-Forwarded-* / X-Real-IP to the backend.
    pub forwarded_headers: bool,
    /// Per-site response header deadline; None falls back to the
    /// settings-level timeout.
    pub response_header_timeout: Option<Duration>,
    /// Stripped from every request on this site (forgery guard).
    pub identity: Vec<IdentityHeader>,
    pub rewrites: Vec<Rewrite>,
    pub request_headers: Vec<HeaderEdit>,
    pub response_headers: Vec<HeaderEdit>,
    pub cors: Option<Cors>,
    /// Retry the next backend on a connection failure (WP-23). The TOML
    /// path keeps the legacy single-attempt behavior; the webservice
    /// model enables it for multi-backend proxy sites.
    pub retry: bool,
    /// WP-24: HTTP basic authentication on this site. The TOML path
    /// never enables it (no auth users there), keeping legacy behavior.
    pub basic_auth: bool,
    /// WP-24: web authentication (login page + signed session cookie).
    pub web_auth: bool,
    /// WP-24: the site's `name:password` user entries, verbatim (the
    /// auth dispatch verifies against them).
    pub site_users: Vec<String>,
    /// WP-24: shared users may authenticate here (TOTP users via the
    /// web flow only).
    pub shared_users: bool,
    /// WP-24: per-site login page style override (`loginStyle`).
    pub login_style: String,
    /// WP-24: the signed session cookie name for this site
    /// (`gately_site_<hash>`), compiled by the webservice bridge. Empty
    /// on the TOML path (no web auth there).
    pub cookie_name: String,
    /// WP-25: forward authentication — a bodyless sub-request per
    /// authenticated request; the visitor's 401 answers come straight
    /// from the auth service. None = not configured.
    pub forward_auth: Option<crate::web::auth::forward_auth::ForwardAuth>,
    /// WP-25: verified Gately credentials skip the WAF (the credential
    /// classes and the basic-auth cache live in web::auth::trust).
    /// Compiled now; the WAF consumption point arrives with WP-52/55.
    #[allow(dead_code)]
    pub trust_auth_users: bool,
}

impl Default for SiteProxyOptions {
    fn default() -> Self {
        Self {
            use_target_host: true,
            forwarded_headers: true,
            response_header_timeout: None,
            identity: Vec::new(),
            rewrites: Vec::new(),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            cors: None,
            retry: false,
            basic_auth: false,
            web_auth: false,
            site_users: Vec::new(),
            shared_users: false,
            login_style: String::new(),
            cookie_name: String::new(),
            forward_auth: None,
            trust_auth_users: false,
        }
    }
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

/// Loads an optional `portforward.json` sibling of the TOML configuration
/// and bridges it onto the legacy forward rules. Returns `None` when the
/// file is absent; a present but invalid file propagates the error.
pub(crate) async fn load_portforward_json(
    config_dir: &Path,
) -> Result<Option<(Vec<TcpForward>, Vec<UdpForward>)>> {
    let path = config_dir.join("portforward.json");
    match fs::metadata(&path).await {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => anyhow::bail!("portforward.json must be a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect portforward.json"),
    }
    let bytes = read_file(&path)
        .await
        .with_context(|| format!("read {path:?}"))?;
    let json = std::str::from_utf8(&bytes).context("portforward.json must be UTF-8")?;
    bridge::compile_from_json(json)
        .with_context(|| format!("invalid {}", path.display()))
        .map(Some)
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
    let mut disabled_modules = raw.disabled_modules;
    disabled_modules.sort_unstable();
    disabled_modules.dedup();
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
    // A portforward.json next to the TOML adds forwarding rules (WP-34
    // step 7-10); both sources feed the same listener checks below.
    let (json_tcp, json_udp) = load_portforward_json(dir).await?.unwrap_or_default();
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
        let forwarding_configured = !raw.tcp_forward.is_empty()
            || !raw.udp_forward.is_empty()
            || !json_tcp.is_empty()
            || !json_udp.is_empty();
        ensure!(
            forwarding_configured,
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
    if let Some(metrics) = settings.metrics_listen {
        ensure!(
            metrics.ip().is_loopback(),
            "server.metrics_listen must use a loopback address"
        );
        ensure!(
            metrics.port() == 0 || listens.insert(metrics),
            "duplicate metrics listener"
        );
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
        tcp_forward.len() + json_tcp.len() <= MAX_LISTENERS,
        "tcp_forward supports up to {MAX_LISTENERS} listeners"
    );
    for rule in json_tcp {
        ensure!(
            rule.listen.port() == 0 || listens.insert(rule.listen),
            "duplicate TCP listener in portforward.json rule {}",
            rule.listen
        );
        tcp_forward.push(rule);
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

    ensure!(
        udp_forward.len() + json_udp.len() <= MAX_LISTENERS,
        "udp_forward supports up to {MAX_LISTENERS} listeners"
    );
    for rule in json_udp {
        ensure!(
            rule.listen.port() == 0 || udp_listens.insert(rule.listen),
            "duplicate UDP listener in portforward.json rule {}",
            rule.listen
        );
        udp_sessions += rule.max_sessions;
        ensure!(
            udp_sessions <= 4096,
            "udp_forward supports up to 4096 total sessions"
        );
        udp_forward.push(rule);
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
            let backends = BackendPool::compile(
                route.upstream,
                route.backends,
                route.upstream_h2c,
                Policy::default(),
            )
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
                // Legacy behavior: Host is the target authority and the
                // forwarding headers are always written.
                options: Box::default(),
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
    let certs = Arc::new(
        crate::certs::load(dir)
            .await
            .context("prepare certificates (ssl.json)")?,
    );
    let tls = tls::load(
        dir,
        settings.tls,
        raw.certificates,
        raw.upstream_ca_file.as_deref(),
        by_host.keys(),
        acme.as_ref().map(|acme| (acme.domains.clone(), managed)),
        Some(certs.provider()),
    )
    .await?;
    Ok(Config {
        disabled_modules,
        tls,
        acme,
        tcp_forward,
        udp_forward,
        settings,
        routes: Routes { by_host, wildcards },
        certs,
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
