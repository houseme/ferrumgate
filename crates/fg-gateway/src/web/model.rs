//! The webservice.json serde model (WP-20 step 2): listeners carrying
//! sites, settings, and the shared site field groups. Field names follow
//! the upstream model (camelCase).

use serde::{Deserialize, Serialize};

/// webservice.json top level.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
    pub listeners: Vec<Listener>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    /// Module switch; false stops all listeners.
    pub enable: bool,
    /// Default response header timeout milliseconds for proxy sites.
    pub response_header_timeout_ms: u64,
    /// WP-24: HMAC key for session cookies; empty = generated at first
    /// startup (redacted in API responses).
    pub auth_secret: String,
    /// WP-24: shared authentication users (`authUsers`).
    pub auth_users: Vec<AuthUserSite>,
    /// WP-24: single-sign-on parent domains.
    pub sso_domains: Vec<String>,
    /// WP-24: automatic ban seconds after repeated auth failures
    /// (0 = rate-limit only).
    pub auto_ban_seconds: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable: false,
            response_header_timeout_ms: 30_000,
            auth_secret: String::new(),
            auth_users: Vec::new(),
            sso_domains: Vec::new(),
            auto_ban_seconds: 0,
        }
    }
}

/// One shared authentication user (WP-24): the password is bcrypt (a
/// submitted plaintext is hashed on save; responses show `********`)
/// and the TOTP secret is Base32 (empty = disabled).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthUserSite {
    pub id: String,
    pub name: String,
    pub password: String,
    pub totp_secret: String,
    pub email: String,
    pub display_name: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub remark: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Listener {
    pub key: String,
    pub name: String,
    pub enable: bool,
    /// `tcp` (dual-stack) for now; upstream also knows `udp` variants.
    pub network: String,
    /// Empty = all addresses.
    pub listen_ip: String,
    pub port: u16,
    pub tls: bool,
    /// Minimum TLS version: "" | "1.2" | "1.3".
    pub min_tls: String,
    /// Serve plain HTTP on the same port alongside TLS.
    pub plain_http: bool,
    /// Extra plain HTTP port ("" disables).
    pub http_port: String,
    pub accept_proxy_protocol: bool,
    /// Access scheme the interface uses to build links: "" | http | https.
    pub access_scheme: String,
    /// Access port for interface links (0 = the listener port).
    pub access_port: u16,
    pub auto_firewall: bool,
    pub sites: Vec<Site>,
    /// This listener is the default site target.
    pub default: bool,
    pub remark: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Site {
    pub key: String,
    pub name: String,
    /// Upstream semantics: sites default to enabled.
    #[serde(default = "Site::default_true")]
    pub enable: bool,
    pub group: String,
    /// Domain rules; at most one `*` per entry.
    pub domains: Vec<String>,
    /// proxy | redirect | static | text.
    pub site_type: String,
    /// Reverse-proxy fields (site_type = proxy).
    pub targets: Vec<String>,
    /// Load policy: "" | round_robin | random | ip_hash | least_conn.
    pub lb_policy: String,
    pub upstream_h2c: bool,
    /// WP-23 transport options (proxy sites).
    pub use_target_host: bool,
    /// Forward X-Forwarded-* / X-Real-IP to the backend (default true).
    #[serde(default = "Site::default_true")]
    pub forwarded_headers: bool,
    pub insecure_skip_verify: bool,
    pub disable_keep_alives: bool,
    /// Send PROXY protocol v2 to the backend.
    pub send_proxy_protocol: bool,
    /// Use the visitor's hostname as SNI (and verify against it) toward
    /// HTTPS backends.
    pub upstream_sni_from_host: bool,
    pub pass_auth_cookies: bool,
    /// Backend timeouts; 0 = the default (connect/TLS 10s, header
    /// unlimited).
    pub timeouts_connect_secs: u32,
    pub timeouts_tls_secs: u32,
    /// 0 = unlimited.
    pub timeouts_response_secs: u32,
    /// Visitor idle timeouts; 0 = the default 60s.
    pub client_idle_read_secs: u32,
    pub client_idle_write_secs: u32,
    /// WP-23 traffic features.
    pub rewrites: Vec<RewriteSite>,
    /// `Key: Value` lines; an empty value deletes.
    pub request_headers: Vec<String>,
    pub response_headers: Vec<String>,
    /// Empty allow list = CORS disabled.
    pub cors: CorsSite,
    /// At most 16 entries.
    pub identity_headers: Vec<IdentitySite>,
    /// Per-user routes (require authentication, WP-24).
    pub user_routes: Vec<UserRouteSite>,
    /// Redirect fields (site_type = redirect).
    pub redirect_to: String,
    pub redirect_code: u16,
    /// Static-file fields (site_type = static).
    pub root: String,
    /// Fixed-text fields (site_type = text).
    pub text_body: String,
    pub text_content_type: String,
    /// 0 = the default 200 (upstream statusCode).
    pub text_status_code: u16,
    /// Health check (proxy sites): mode "" | http | tcp.
    pub health_mode: String,
    pub health_path: String,
    pub health_interval_secs: u32,
    pub health_timeout_secs: u32,
    pub health_fails: u32,
    pub health_passes: u32,
    /// Source access lists (WP-36 shape, validated in WP-24/26).
    pub access_allow: Vec<String>,
    pub access_deny: Vec<String>,
    /// WP-24 authentication (site-level).
    pub basic_auth: bool,
    pub web_auth: bool,
    /// `name:password` lines; plaintext is hashed on save.
    pub users: Vec<String>,
    /// Shared users may authenticate here (TOTP users via web flow only).
    pub shared_users: bool,
    /// Login page style override (loginStyle).
    pub login_style: String,
    /// WP-25: forward authentication (Authelia-style); mutually
    /// exclusive with basicAuth/webAuth.
    pub forward_auth: Option<ForwardAuthSite>,
    /// WP-25: verified Gately credentials skip the WAF (consumed by
    /// WP-52/55; the credential classes live in auth::trust).
    pub trust_auth_users: bool,
    pub remark: String,
}

/// Forward-auth configuration (WP-25): the bodyless GET goes to `url`;
/// 401 answers either redirect to `loginUrl` or — with
/// `loginFromLocation` — to the Location the auth service itself sent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ForwardAuthSite {
    pub url: String,
    pub login_url: String,
    pub login_from_location: bool,
    #[serde(default)]
    pub copy_headers: Vec<String>,
}

impl Default for Site {
    /// The upstream semantics the serde defaults express: sites start
    /// enabled with forwarding headers on. A manual impl keeps the Rust
    /// `Site::default()` (used by the migration and the UI) consistent
    /// with what a JSON document without those fields deserializes to.
    fn default() -> Self {
        Self {
            enable: true,
            forwarded_headers: true,
            key: String::new(),
            name: String::new(),
            group: String::new(),
            domains: Vec::new(),
            site_type: String::new(),
            targets: Vec::new(),
            lb_policy: String::new(),
            upstream_h2c: false,
            use_target_host: false,
            insecure_skip_verify: false,
            disable_keep_alives: false,
            send_proxy_protocol: false,
            upstream_sni_from_host: false,
            pass_auth_cookies: false,
            timeouts_connect_secs: 0,
            timeouts_tls_secs: 0,
            timeouts_response_secs: 0,
            client_idle_read_secs: 0,
            client_idle_write_secs: 0,
            rewrites: Vec::new(),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            cors: Default::default(),
            identity_headers: Vec::new(),
            user_routes: Vec::new(),
            redirect_to: String::new(),
            redirect_code: 0,
            root: String::new(),
            text_body: String::new(),
            text_content_type: String::new(),
            text_status_code: 0,
            health_mode: String::new(),
            health_path: String::new(),
            health_interval_secs: 0,
            health_timeout_secs: 0,
            health_fails: 0,
            health_passes: 0,
            access_allow: Vec::new(),
            access_deny: Vec::new(),
            basic_auth: false,
            web_auth: false,
            users: Vec::new(),
            shared_users: false,
            login_style: String::new(),
            forward_auth: None,
            trust_auth_users: false,
            remark: String::new(),
        }
    }
}

impl Site {
    /// Serde field default: forwarding headers stay on unless disabled.
    fn default_true() -> bool {
        true
    }
}

/// One rewrite rule: internal rewrite (`redirect = false`, `to` starts
/// with `/`) or redirect (`code` 0 = 302).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RewriteSite {
    pub pattern: String,
    pub to: String,
    pub redirect: bool,
    pub code: u16,
}

/// CORS configuration; empty `allow_origins` disables it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CorsSite {
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_secs: u32,
}

/// One identity header: `header` + `field` (user/email/name/groups).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentitySite {
    pub header: String,
    pub field: String,
}

/// One per-user route: `users` (names or `provider:id`) to `targets`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct UserRouteSite {
    pub users: Vec<String>,
    pub targets: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic upstream-style webservice.json: two listeners, one site of
    /// each type (proxy / redirect / static / text), all camelCase.
    const WEBSERVICE_JSON: &str = r#"{
        "settings": { "enable": true, "responseHeaderTimeoutMs": 15000 },
        "listeners": [
            {
                "key": "web",
                "name": "Public Web",
                "enable": true,
                "network": "tcp",
                "listenIp": "0.0.0.0",
                "port": 443,
                "tls": true,
                "minTls": "1.2",
                "plainHttp": false,
                "httpPort": "80",
                "acceptProxyProtocol": true,
                "accessScheme": "https",
                "accessPort": 0,
                "autoFirewall": true,
                "default": true,
                "remark": "edge entry",
                "sites": [
                    {
                        "key": "api",
                        "name": "API Gateway",
                        "enable": true,
                        "group": "backend",
                        "domains": ["api.example.com", "*.api.example.com"],
                        "siteType": "proxy",
                        "targets": ["127.0.0.1:8080", "127.0.0.1:8081"],
                        "upstreamH2c": true,
                        "healthMode": "http",
                        "healthPath": "/healthz",
                        "healthIntervalSecs": 10,
                        "healthTimeoutSecs": 3,
                        "healthFails": 3,
                        "healthPasses": 2,
                        "accessAllow": ["10.0.0.0/8", "192.168.1.1"],
                        "accessDeny": ["203.0.113.0/24"],
                        "remark": "reverse proxy"
                    },
                    {
                        "key": "old",
                        "name": "Legacy Redirect",
                        "enable": true,
                        "group": "",
                        "domains": ["old.example.com"],
                        "siteType": "redirect",
                        "redirectTo": "https://example.com/",
                        "redirectCode": 301,
                        "remark": ""
                    },
                    {
                        "key": "docs",
                        "name": "Static Docs",
                        "enable": true,
                        "group": "",
                        "domains": ["docs.example.com"],
                        "siteType": "static",
                        "root": "/var/www/docs",
                        "remark": ""
                    },
                    {
                        "key": "maintenance",
                        "name": "Maintenance Notice",
                        "enable": false,
                        "group": "",
                        "domains": ["status.example.com"],
                        "siteType": "text",
                        "textBody": "Under maintenance",
                        "textContentType": "text/plain",
                        "remark": ""
                    }
                ]
            },
            {
                "key": "admin",
                "name": "Admin Panel",
                "enable": false,
                "network": "tcp",
                "listenIp": "127.0.0.1",
                "port": 8443,
                "tls": true,
                "minTls": "1.3",
                "plainHttp": false,
                "httpPort": "",
                "acceptProxyProtocol": false,
                "accessScheme": "",
                "accessPort": 8443,
                "autoFirewall": false,
                "default": false,
                "remark": "loopback only",
                "sites": []
            }
        ]
    }"#;

    #[test]
    fn deserializes_upstream_style_config() {
        let config: FileConfig = serde_json::from_str(WEBSERVICE_JSON).expect("valid config");

        assert!(config.settings.enable);
        assert_eq!(config.settings.response_header_timeout_ms, 15_000);
        assert_eq!(config.listeners.len(), 2);

        let web = &config.listeners[0];
        assert_eq!(web.key, "web");
        assert_eq!(web.name, "Public Web");
        assert!(web.enable);
        assert_eq!(web.network, "tcp");
        assert_eq!(web.listen_ip, "0.0.0.0");
        assert_eq!(web.port, 443);
        assert!(web.tls);
        assert_eq!(web.min_tls, "1.2");
        assert!(!web.plain_http);
        assert_eq!(web.http_port, "80");
        assert!(web.accept_proxy_protocol);
        assert_eq!(web.access_scheme, "https");
        assert_eq!(web.access_port, 0);
        assert!(web.auto_firewall);
        assert!(web.default);
        assert_eq!(web.remark, "edge entry");
        assert_eq!(web.sites.len(), 4);

        // proxy site
        let proxy = &web.sites[0];
        assert_eq!(proxy.key, "api");
        assert_eq!(proxy.site_type, "proxy");
        assert_eq!(proxy.domains, vec!["api.example.com", "*.api.example.com"]);
        assert_eq!(proxy.targets, vec!["127.0.0.1:8080", "127.0.0.1:8081"]);
        assert!(proxy.upstream_h2c);
        assert_eq!(proxy.health_mode, "http");
        assert_eq!(proxy.health_path, "/healthz");
        assert_eq!(proxy.health_interval_secs, 10);
        assert_eq!(proxy.health_timeout_secs, 3);
        assert_eq!(proxy.health_fails, 3);
        assert_eq!(proxy.health_passes, 2);

        // redirect site
        let redirect = &web.sites[1];
        assert_eq!(redirect.site_type, "redirect");
        assert_eq!(redirect.redirect_to, "https://example.com/");
        assert_eq!(redirect.redirect_code, 301);

        // static site
        let static_site = &web.sites[2];
        assert_eq!(static_site.site_type, "static");
        assert_eq!(static_site.root, "/var/www/docs");

        // text site
        let text = &web.sites[3];
        assert_eq!(text.site_type, "text");
        assert_eq!(text.text_body, "Under maintenance");
        assert_eq!(text.text_content_type, "text/plain");
        assert!(!text.enable);

        // second listener
        let admin = &config.listeners[1];
        assert_eq!(admin.key, "admin");
        assert_eq!(admin.listen_ip, "127.0.0.1");
        assert_eq!(admin.port, 8443);
        assert_eq!(admin.min_tls, "1.3");
        assert_eq!(admin.access_port, 8443);
        assert!(!admin.default);
        assert!(admin.sites.is_empty());
    }

    #[test]
    fn unknown_fields_rejected() {
        // unknown field on a listener
        let listener = r#"{
            "key": "web",
            "bogusField": 1,
            "sites": []
        }"#;
        let err =
            serde_json::from_str::<Listener>(listener).expect_err("must reject unknown field");
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );

        // unknown field on a site
        let site = r#"{
            "key": "api",
            "siteType": "proxy",
            "bogusField": 1,
            "targets": ["127.0.0.1:8080"]
        }"#;
        let err = serde_json::from_str::<Site>(site).expect_err("must reject unknown field");
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn defaults_applied_on_empty() {
        let config: FileConfig = serde_json::from_str("{}").expect("empty object parses");
        assert_eq!(config, FileConfig::default());
        assert!(!config.settings.enable);
        assert_eq!(config.settings.response_header_timeout_ms, 30_000);
        assert!(config.listeners.is_empty());

        // Partial settings fall back to per-field defaults too.
        let config: FileConfig =
            serde_json::from_str(r#"{ "settings": { "enable": true } }"#).expect("parses");
        assert!(config.settings.enable);
        assert_eq!(config.settings.response_header_timeout_ms, 30_000);
    }

    #[test]
    fn roundtrip_preserves_fields() {
        let original = FileConfig {
            settings: Settings {
                enable: true,
                response_header_timeout_ms: 45_000,
                auth_secret: String::new(),
                auth_users: Vec::new(),
                sso_domains: Vec::new(),
                auto_ban_seconds: 0,
            },
            listeners: vec![
                Listener {
                    key: "web".into(),
                    name: "Public Web".into(),
                    enable: true,
                    network: "tcp".into(),
                    listen_ip: "0.0.0.0".into(),
                    port: 443,
                    tls: true,
                    min_tls: "1.2".into(),
                    plain_http: true,
                    http_port: "80".into(),
                    accept_proxy_protocol: true,
                    access_scheme: "https".into(),
                    access_port: 8443,
                    auto_firewall: true,
                    sites: vec![Site {
                        key: "api".into(),
                        name: "API Gateway".into(),
                        enable: true,
                        group: "backend".into(),
                        domains: vec!["api.example.com".into()],
                        site_type: "proxy".into(),
                        targets: vec!["127.0.0.1:8080".into()],
                        upstream_h2c: true,
                        health_mode: "tcp".into(),
                        health_interval_secs: 5,
                        health_timeout_secs: 2,
                        health_fails: 2,
                        health_passes: 1,
                        access_allow: vec!["10.0.0.0/8".into()],
                        access_deny: vec!["203.0.113.0/24".into()],
                        remark: "primary api".into(),
                        ..Site::default()
                    }],
                    default: true,
                    remark: "edge".into(),
                },
                Listener::default(),
            ],
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: FileConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, original);
    }

    #[test]
    fn proxy_protocol_and_access_lists() {
        // Rule-level access lists are Site fields renamed to accessAllow /
        // accessDeny; verify the camelCase JSON roundtrips through them.
        let site: Site = serde_json::from_str(
            r#"{
                "key": "api",
                "siteType": "proxy",
                "accessAllow": ["10.0.0.0/8", "192.168.1.1"],
                "accessDeny": ["203.0.113.0/24"]
            }"#,
        )
        .expect("parses");
        assert_eq!(site.access_allow, vec!["10.0.0.0/8", "192.168.1.1"]);
        assert_eq!(site.access_deny, vec!["203.0.113.0/24"]);

        // And listener-level acceptProxyProtocol keeps its camelCase name.
        let listener: Listener =
            serde_json::from_str(r#"{ "acceptProxyProtocol": true }"#).expect("parses");
        assert!(listener.accept_proxy_protocol);

        // Roundtrip through a full listener keeps the lists intact.
        let listener = Listener {
            key: "web".into(),
            accept_proxy_protocol: true,
            sites: vec![site],
            ..Listener::default()
        };
        let json = serde_json::to_string(&listener).expect("serialize");
        assert!(json.contains(r#""accessAllow":["10.0.0.0/8","192.168.1.1"]"#));
        assert!(json.contains(r#""accessDeny":["203.0.113.0/24"]"#));
        assert!(json.contains(r#""acceptProxyProtocol":true"#));
        let decoded: Listener = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, listener);
    }
}
