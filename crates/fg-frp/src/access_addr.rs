//! Visitor access addresses for proxies (WP-44 §3.3 "访问地址"): a pure
//! computation over the proxy, its owning frpc instance (whose `access`
//! block carries the visitor-facing scheme / ports / subdomain root) and —
//! as a fallback when the access block is empty — the frps instance.
//!
//! | type | address |
//! |---|---|
//! | `tcp` / `udp` | `<serverAddr>:<remotePort>` |
//! | `http` | `http://<domain>[:<httpPort>]` |
//! | `https` | `https://<domain>[:<httpsPort>]` |
//! | `stcp` / `xtcp` | none (no directly reachable public address) |
//!
//! Only used to render clickable links / copyable text; changing it never
//! restarts frpc.

use crate::model::{Client, Proxy, ProxyType, Server};

/// One access address: `kind` is the proxy-facing scheme, `display` the
/// short text for a list row, `full` the clickable URL (None when the
/// display is already the whole address, e.g. `host:port`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyUrl {
    pub kind: UrlKind,
    pub display: String,
    pub full: Option<String>,
}

/// The visitor-facing scheme family of the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlKind {
    Tcp,
    Udp,
    Http,
    Https,
}

/// All access addresses of one proxy (empty for stcp / xtcp and disabled
/// proxies).
pub fn proxy_urls(proxy: &Proxy, client: &Client, server_access: Option<&Server>) -> Vec<ProxyUrl> {
    if !proxy.enable || !client.enable {
        return Vec::new();
    }
    match proxy.typ {
        ProxyType::Tcp | ProxyType::Udp => {
            let addr = format!("{}:{}", client.server_addr, proxy.remote_port);
            vec![ProxyUrl {
                kind: if proxy.typ == ProxyType::Tcp {
                    UrlKind::Tcp
                } else {
                    UrlKind::Udp
                },
                display: addr.clone(),
                full: Some(format!(
                    "{}://{addr}",
                    if proxy.typ == ProxyType::Tcp {
                        "tcp"
                    } else {
                        "udp"
                    }
                )),
            }]
        }
        ProxyType::Http | ProxyType::Https => {
            let https = proxy.typ == ProxyType::Https;
            let mut urls = Vec::new();
            let (scheme, port) = visitor_scheme_port(https, &client.access, server_access);
            for domain in domains(proxy, &client.access, server_access) {
                urls.push(ProxyUrl {
                    kind: if https { UrlKind::Https } else { UrlKind::Http },
                    display: domain.clone(),
                    full: Some(with_port(&format!("{scheme}://{domain}"), port, scheme)),
                });
            }
            urls
        }
        ProxyType::Stcp | ProxyType::Xtcp => Vec::new(),
    }
}

/// The visitor scheme and port: the instance access block wins, then the
/// frps vhost ports. Within the access block the port of the matching
/// side wins, falling back to the other side; 0 = scheme default (no
/// port suffix; http → 80, https → 443).
fn visitor_scheme_port(
    https: bool,
    access: &crate::model::ClientAccess,
    server: Option<&Server>,
) -> (&'static str, u16) {
    if https {
        let scheme = if access.http_scheme == "http" {
            "http"
        } else {
            "https"
        };
        let mut port = access.https_port;
        if port == 0 {
            port = access.http_port;
        }
        if port == 0 {
            port = server.map_or(0, |server| server.vhost_https_port);
        }
        (scheme, port)
    } else {
        let scheme = if access.http_scheme == "https" {
            "https"
        } else {
            "http"
        };
        let mut port = access.http_port;
        if port == 0 {
            port = access.https_port;
        }
        if port == 0 {
            port = server.map_or(0, |server| server.vhost_http_port);
        }
        (scheme, port)
    }
}

/// The full domains of a vhost proxy: custom domains first, then the
/// subdomain joined under the visitor subdomain root (instance access
/// block, falling back to the frps `subDomainHost`).
fn domains(
    proxy: &Proxy,
    access: &crate::model::ClientAccess,
    server: Option<&Server>,
) -> Vec<String> {
    let mut domains: Vec<String> = proxy.custom_domains.clone();
    if !proxy.subdomain.is_empty() {
        let root = if access.subdomain_host.is_empty() {
            server
                .map(|server| server.subdomain_host.as_str())
                .unwrap_or("")
        } else {
            access.subdomain_host.as_str()
        };
        if !root.is_empty() {
            domains.push(format!("{}.{}", proxy.subdomain, root));
        }
    }
    domains
}

/// Appends `:<port>` unless the port is 0 or the scheme default.
fn with_port(url: &str, port: u16, scheme: &str) -> String {
    let default = match scheme {
        "https" => 443,
        _ => 80,
    };
    if port == 0 || port == default {
        url.to_owned()
    } else {
        format!("{url}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ClientAccess;

    fn client() -> Client {
        Client {
            key: "c1".into(),
            name: "home".into(),
            enable: true,
            server_addr: "pub.example.com".into(),
            ..Client::default()
        }
    }

    fn tcp() -> Proxy {
        Proxy {
            key: "p1".into(),
            name: "ssh".into(),
            enable: true,
            typ: ProxyType::Tcp,
            local_port: 22,
            remote_port: 6022,
            client: "c1".into(),
            ..Proxy::default()
        }
    }

    #[test]
    fn proxy_urls_by_type() {
        let base = client();
        // tcp / udp: host:port from the frpc server address.
        let urls = proxy_urls(&tcp(), &base, None);
        assert_eq!(
            urls,
            vec![ProxyUrl {
                kind: UrlKind::Tcp,
                display: "pub.example.com:6022".into(),
                full: Some("tcp://pub.example.com:6022".into()),
            }]
        );
        let mut udp = tcp();
        udp.typ = ProxyType::Udp;
        let urls = proxy_urls(&udp, &base, None);
        assert_eq!(urls[0].kind, UrlKind::Udp);
        assert_eq!(urls[0].full.as_deref(), Some("udp://pub.example.com:6022"));

        // stcp / xtcp: no directly reachable address.
        let mut stcp = tcp();
        stcp.typ = ProxyType::Stcp;
        stcp.remote_port = 0;
        stcp.secret_key = "s".into();
        assert!(proxy_urls(&stcp, &base, None).is_empty());

        // http with a custom domain and default port: no port suffix.
        let mut http = tcp();
        http.typ = ProxyType::Http;
        http.remote_port = 0;
        http.local_port = 80;
        http.custom_domains = vec!["app.example.com".into()];
        let urls = proxy_urls(&http, &base, None);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].kind, UrlKind::Http);
        assert_eq!(urls[0].full.as_deref(), Some("http://app.example.com"));

        // https with a non-default access port: suffix appended.
        let mut https = http.clone();
        https.typ = ProxyType::Https;
        let mut access_client = client();
        access_client.access = ClientAccess {
            http_scheme: "https".into(),
            http_port: 8443,
            https_port: 0,
            subdomain_host: "tunnel.example.com".into(),
        };
        let urls = proxy_urls(&https, &access_client, None);
        assert_eq!(urls[0].kind, UrlKind::Https);
        assert_eq!(
            urls[0].full.as_deref(),
            Some("https://app.example.com:8443")
        );

        // Subdomain joined under the access subdomain root.
        let mut sub = http;
        sub.custom_domains = Vec::new();
        sub.subdomain = "web".into();
        let urls = proxy_urls(&sub, &access_client, None);
        assert_eq!(urls[0].display, "web.tunnel.example.com");

        // Disabled proxies have no addresses.
        let mut off = tcp();
        off.enable = false;
        assert!(proxy_urls(&off, &base, None).is_empty());
    }

    #[test]
    fn proxy_urls_fall_back_to_server_vhost() {
        let base = client();
        let mut http = tcp();
        http.typ = ProxyType::Http;
        http.local_port = 80;
        http.subdomain = "web".into();
        let server = Server {
            key: "s1".into(),
            name: "main".into(),
            vhost_http_port: 8080,
            vhost_https_port: 8443,
            subdomain_host: "srv.example.com".into(),
            ..Server::default()
        };
        let urls = proxy_urls(&http, &base, Some(&server));
        assert_eq!(urls[0].display, "web.srv.example.com");
        assert_eq!(
            urls[0].full.as_deref(),
            Some("http://web.srv.example.com:8080")
        );
        // The access block wins when filled.
        let mut access_client = client();
        access_client.access.subdomain_host = "acc.example.com".into();
        access_client.access.http_port = 80;
        let urls = proxy_urls(&http, &access_client, Some(&server));
        assert_eq!(urls[0].display, "web.acc.example.com");
        assert_eq!(urls[0].full.as_deref(), Some("http://web.acc.example.com"));
    }
}
