//! WP-20 step 5: bridges the webservice model (`web::model`) onto the
//! legacy serving pipeline. The pipeline in `proxy.rs` serves from
//! `config::Routes`, whose handlers (`ProxyRoute`, `SiteResponse`) are
//! normally produced by `config::load` from the TOML schema. This module
//! synthesizes those raw schema values (`RawBackend`, `RawHealthCheck`,
//! `RawResponse`) from a `Site` — exactly what the serde loader would
//! build from TOML — and calls the existing `compile` functions, so
//! validation, behavior and error paths stay identical to the legacy
//! configuration path.

use std::{collections::HashMap, path::Path};

use serde_json::{Map, Value, json};

use std::time::Duration;

use crate::{
    backend::{BackendPool, RawBackend},
    config::{ProxyRoute, Route, RouteAction, Routes},
    domains::normalize as legacy_normalize,
    health::{HealthCheck, RawHealthCheck},
    site::{RawResponse, SiteResponse},
    static_files::RawStatic,
    web::{
        identity,
        model::{Listener, Site},
        proxy::{
            cors::Cors,
            headers::{self, HeaderEdit},
            rewrite::{Rewrite, RewriteError},
        },
        upstream::{Policy, parse_target},
    },
};

/// A site compiled for the legacy serving pipeline: either a reverse
/// proxy route or one of the direct response sites (redirect, static,
/// text).
pub enum CompiledSiteHandler {
    Proxy(ProxyRoute),
    Response(SiteResponse),
}

/// Compiles one webservice model site into the handler shape the legacy
/// pipeline consumes:
///
/// - `proxy`: `targets` become HTTP backends (weight 1, no backups) in a
///   `BackendPool`; health fields go through `HealthCheck::compile`
///   (`health_mode` `""` disables the check, `http`/`tcp` map to the
///   legacy modes; zero numeric health fields fall back to the legacy
///   defaults).
/// - `redirect`: `SiteResponse::Redirect` from `redirect_to` and
///   `redirect_code` (0 = legacy default 302).
/// - `text`: `SiteResponse::Text` from `text_body` and
///   `text_content_type` (empty = legacy default `text/plain;
///   charset=utf-8`).
/// - `static`: `SiteResponse::Static` rooted at `root`.
///
/// The compile of static sites touches the filesystem (canonicalizing
/// and opening the root), so — like `SiteResponse::compile` itself —
/// this function is async. Unknown `site_type` values are rejected.
pub async fn compile_site_handler(site: &Site) -> Result<CompiledSiteHandler, Vec<String>> {
    let label = site_label(site);
    match site.site_type.as_str() {
        "proxy" => compile_proxy_site(site, &label),
        "redirect" => {
            let response = RawResponse::Redirect {
                target: site.redirect_to.clone(),
                status: (site.redirect_code != 0).then_some(site.redirect_code),
                keep_path: false,
            };
            compile_response(response, &label).await
        }
        "text" => {
            let response = RawResponse::Text {
                body: site.text_body.clone(),
                status: (site.text_status_code != 0).then_some(site.text_status_code),
                content_type: (!site.text_content_type.is_empty())
                    .then_some(site.text_content_type.clone()),
            };
            compile_response(response, &label).await
        }
        "static" => {
            let raw =
                raw_static(&site.root).map_err(|error| vec![format!("site {label}: {error}")])?;
            compile_response(RawResponse::Static(raw), &label).await
        }
        other => Err(vec![format!(
            "site {label}: unknown site_type {other:?} (expected proxy, redirect, static or text)"
        )]),
    }
}

/// Compiles the WP-23 per-site options (identity headers, rewrites,
/// header edits, CORS, response header deadline) from the model. Every
/// problem lands in `errors` with the site label; when that list ends up
/// non-empty the caller aborts the site.
fn compile_wp23_options(
    site: &Site,
    label: &str,
    errors: &mut Vec<String>,
) -> crate::config::SiteProxyOptions {
    let identity = match identity::compile(&site.identity_headers) {
        Ok(headers) => headers,
        Err(error) => {
            errors.push(format!("site {label}: identityHeaders: {error}"));
            Vec::new()
        }
    };
    let rewrites = site
        .rewrites
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            let redirect = rule
                .redirect
                .then_some(if rule.code == 0 { 302 } else { rule.code });
            match Rewrite::compile(&rule.pattern, &rule.to, redirect) {
                Ok(rewrite) => Some(rewrite),
                Err(RewriteError::BadRegex(_)) => {
                    errors.push(format!(
                        "site {label}: rewrites[{index}].pattern is not a valid regex"
                    ));
                    None
                }
                Err(RewriteError::BadTarget(_)) => {
                    errors.push(format!(
                        "site {label}: rewrites[{index}].to must start with '/' for internal rewrites"
                    ));
                    None
                }
                Err(RewriteError::BadCode(code)) => {
                    errors.push(format!(
                        "site {label}: rewrites[{index}].code must be 301/302/307/308 (got {code})"
                    ));
                    None
                }
            }
        })
        .collect();
    let mut header_edits = |lines: &[String], field: &str| -> Vec<HeaderEdit> {
        match headers::parse_edits(lines) {
            Ok(edits) => edits,
            Err(error) => {
                errors.push(format!("site {label}: {field}: {error}"));
                Vec::new()
            }
        }
    };
    let request_headers = header_edits(&site.request_headers, "requestHeaders");
    let response_headers = header_edits(&site.response_headers, "responseHeaders");
    let cors = (!site.cors.allow_origins.is_empty()).then(|| Cors {
        allow_origins: site.cors.allow_origins.clone(),
        allow_methods: site.cors.allow_methods.clone(),
        allow_headers: site.cors.allow_headers.clone(),
        allow_credentials: site.cors.allow_credentials,
        max_age_secs: site.cors.max_age_secs,
    });
    let response_header_timeout = (site.timeouts_response_secs != 0)
        .then(|| Duration::from_secs(u64::from(site.timeouts_response_secs)));
    // WP-24 site authentication (§3.4): basic auth needs at least one
    // user; web auth needs one user or an enabled shared-user pool.
    if site.basic_auth && site.users.is_empty() {
        errors.push(format!(
            "site {label}: basicAuth 需要至少一个用户（users）"
        ));
    }
    if site.web_auth && site.users.is_empty() && !site.shared_users {
        errors.push(format!(
            "site {label}: webAuth 需要至少一个用户（users）或开启共享用户（sharedUsers）"
        ));
    }
    crate::config::SiteProxyOptions {
        use_target_host: site.use_target_host,
        forwarded_headers: site.forwarded_headers,
        response_header_timeout,
        identity,
        rewrites,
        request_headers,
        response_headers,
        cors,
        // Dial-failure retry only makes sense with somewhere to go; a
        // lone backend never retries (same bound as MAX_ATTEMPTS).
        retry: site.targets.len() > 1,
        // WP-24 authentication. The cookie name binds the session to
        // the listener/site pair; the listener key is not threaded
        // through the compile bridge yet, so "main" stands in for it
        // (the session payload itself stays host-bound, and a later
        // batch passes the real listener key through).
        basic_auth: site.basic_auth,
        web_auth: site.web_auth,
        site_users: site.users.clone(),
        shared_users: site.shared_users,
        login_style: site.login_style.clone(),
        cookie_name: crate::web::auth::session::cookie_name("main", &site.key),
    }
}

/// Converts a Listener's sites into a legacy-compatible Routes structure
/// that the existing proxy pipeline can serve from. Disabled sites are
/// skipped. Each enabled site is compiled once per domain (the legacy
/// `Route` values are not `Clone`, and per-host pools mirror the TOML
/// schema where every `[[routes]]` entry compiles its own backend pool).
/// A site without domains is the listener's default fallback in the
/// webservice model; the legacy table expresses that as the catch-all
/// wildcard host `*`. Every problem is collected and returned as a
/// non-empty error list.
pub async fn compile_routes(listener: &Listener) -> Result<Routes, Vec<String>> {
    let mut errors = Vec::new();
    let mut by_host: HashMap<String, Vec<Route>> = HashMap::new();
    let mut wildcards: Vec<String> = Vec::new();
    let catch_all = "*".to_owned();

    for site in &listener.sites {
        if !site.enable {
            continue;
        }
        let label = site_label(site);
        let mut domains: Vec<&String> = site.domains.iter().collect();
        if site.domains.is_empty() {
            domains.push(&catch_all);
        }
        for domain in domains {
            let Some(host) = legacy_normalize(domain) else {
                errors.push(format!("site {label}: invalid domain {domain:?}"));
                continue;
            };
            if by_host
                .get(&host)
                .is_some_and(|routes| routes.iter().any(|route| route.prefix == "/"))
            {
                errors.push(format!(
                    "site {label}: duplicate domain {domain:?} in listener {:?}",
                    listener.key
                ));
                continue;
            }
            if host.contains('*') && !by_host.contains_key(&host) {
                wildcards.push(host.clone());
            }
            let action = match compile_site_handler(site).await {
                Ok(CompiledSiteHandler::Proxy(route)) => RouteAction::Proxy(route),
                Ok(CompiledSiteHandler::Response(response)) => RouteAction::Response(response),
                Err(site_errors) => {
                    errors.extend(
                        site_errors
                            .into_iter()
                            .map(|error| format!("{domain}: {error}")),
                    );
                    continue;
                }
            };
            by_host.entry(host).or_default().push(Route {
                prefix: "/".to_owned(),
                action,
            });
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    for routes in by_host.values_mut() {
        routes.sort_unstable_by_key(|route| std::cmp::Reverse(route.prefix.len()));
    }
    wildcards.sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
    Ok(Routes { by_host, wildcards })
}

/// Builds the proxy handler: one primary backend per target (the
/// webservice model has no weights or backups) plus the optional health
/// check. Backend-pool and health errors are collected together.
fn compile_proxy_site(site: &Site, label: &str) -> Result<CompiledSiteHandler, Vec<String>> {
    let mut errors = Vec::new();
    if site.targets.is_empty() {
        errors.push(format!(
            "site {label}: a proxy site requires at least one target"
        ));
    }
    let mut backends = Vec::with_capacity(site.targets.len());
    for (index, target) in site.targets.iter().enumerate() {
        match raw_backend(target) {
            Ok(backend) => backends.push(backend),
            Err(error) => {
                errors.push(format!(
                    "site {label}: targets[{index}] {target:?}: {error}"
                ));
            }
        }
    }
    let health = match site.health_mode.as_str() {
        "" => None,
        "http" | "tcp" => match raw_health(site) {
            Ok(check) => Some(check),
            Err(error) => {
                errors.push(format!("site {label}: health: {error}"));
                None
            }
        },
        other => {
            errors.push(format!(
                "site {label}: unknown health_mode {other:?} (expected \"\", \"http\" or \"tcp\")"
            ));
            None
        }
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    let pool = match BackendPool::compile(
        None,
        backends,
        site.upstream_h2c,
        // An unknown policy is a validate-time error (`web::validate`);
        // the bridge stays lenient and keeps the default rotation.
        Policy::parse(&site.lb_policy).unwrap_or_default(),
    ) {
        Ok(pool) => Some(pool),
        Err(error) => {
            errors.push(format!("site {label}: {error:#}"));
            None
        }
    };
    let health = match health.map(HealthCheck::compile) {
        Some(Ok(check)) => Some(check),
        Some(Err(error)) => {
            errors.push(format!("site {label}: health: {error:#}"));
            None
        }
        None => None,
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    let options = compile_wp23_options(site, label, &mut errors);
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(CompiledSiteHandler::Proxy(ProxyRoute {
        // Checked non-empty above, so the pool compiled.
        backends: pool.expect("backend pool compiled"),
        // The new model has no websocket switch: upgrades are always
        // allowed (WP-23; the legacy `websocket = false` reject semantics
        // was dropped by the migration mapping).
        websocket: true,
        upstream_h2c: site.upstream_h2c,
        health,
        options: Box::new(options),
    }))
}

/// Compiles a redirect / static / text site through the legacy
/// `SiteResponse::compile`.
async fn compile_response(
    response: RawResponse,
    label: &str,
) -> Result<CompiledSiteHandler, Vec<String>> {
    SiteResponse::compile(response, Path::new(""), &[])
        .await
        .map(CompiledSiteHandler::Response)
        .map_err(|error| vec![format!("site {label}: {error:#}")])
}

/// Synthesizes the raw backend from one `site.targets` line (WP-23 3b):
/// the line is parsed as a target (`URL [weight=N] [backup]`), a bare
/// `host:port` line without parameters defaults to plain HTTP, and the
/// legacy schema origin is rebuilt from the parsed target (credentials
/// dropped, origin path) together with its weight and backup flag.
fn raw_backend(line: &str) -> Result<RawBackend, String> {
    let trimmed = line.trim();
    let normalized =
        if trimmed.is_empty() || trimmed.contains("://") || trimmed.contains(char::is_whitespace) {
            trimmed.to_owned()
        } else {
            format!("http://{trimmed}")
        };
    let target = parse_target(&normalized).map_err(|error| error.to_string())?;
    let scheme = target.uri.scheme_str().unwrap_or("http");
    let authority = target
        .uri
        .authority()
        .expect("parse_target validated the authority")
        .as_str();
    // Credentials never reach the legacy pool: its compile rejects
    // user-info authorities.
    let host_port = match authority.rsplit_once('@') {
        Some((_userinfo, rest)) => rest,
        None => authority,
    };
    serde_json::from_value(json!({
        "upstream": format!("{scheme}://{host_port}/"),
        "weight": target.weight,
        "backup": target.backup,
    }))
    .map_err(|error| error.to_string())
}

/// A label for error messages: the site key, falling back to its name.
fn site_label(site: &Site) -> String {
    let label = if site.key.is_empty() {
        site.name.as_str()
    } else {
        site.key.as_str()
    };
    if label.is_empty() {
        "<unnamed>".to_owned()
    } else {
        label.to_owned()
    }
}

/// Synthesizes the raw static response for a site root.
fn raw_static(root: &str) -> serde_json::Result<RawStatic> {
    serde_json::from_value(json!({ "root": root }))
}

/// Synthesizes the raw health check from the site's health fields. Zero
/// numeric values mean "legacy default" (the webservice model defaults
/// them to 0), so the fields are omitted and `RawHealthCheck`'s serde
/// defaults apply: 10s interval, 3s timeout, 3 fails, 2 passes.
fn raw_health(site: &Site) -> serde_json::Result<RawHealthCheck> {
    let mut raw = Map::new();
    raw.insert("mode".to_owned(), json!(site.health_mode));
    if !site.health_path.is_empty() {
        raw.insert("path".to_owned(), json!(site.health_path));
    }
    insert_positive(&mut raw, "interval_secs", site.health_interval_secs);
    insert_positive(&mut raw, "timeout_secs", site.health_timeout_secs);
    insert_positive(&mut raw, "fails", site.health_fails);
    insert_positive(&mut raw, "passes", site.health_passes);
    serde_json::from_value(Value::Object(raw))
}

fn insert_positive(map: &mut Map<String, Value>, key: &str, value: u32) {
    if value != 0 {
        map.insert(key.to_owned(), Value::from(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::{
        HeaderMap, Method, StatusCode,
        body::Bytes,
        header::{CONTENT_TYPE, LOCATION},
        http::uri::PathAndQuery,
    };
    use tempfile::tempdir;

    fn site(site_type: &str) -> Site {
        Site {
            site_type: site_type.to_owned(),
            enable: true,
            ..Site::default()
        }
    }

    #[tokio::test]
    async fn compile_proxy_site_with_health() {
        let mut proxy = site("proxy");
        proxy.targets = vec!["127.0.0.1:8080".into(), "127.0.0.1:8081".into()];
        proxy.upstream_h2c = true;
        proxy.health_mode = "http".into();
        proxy.health_path = "/healthz".into();
        proxy.health_interval_secs = 5;
        proxy.health_timeout_secs = 2;
        proxy.health_fails = 2;
        proxy.health_passes = 1;

        let CompiledSiteHandler::Proxy(route) = compile_site_handler(&proxy).await.unwrap() else {
            panic!("proxy site must compile to a proxy handler");
        };
        assert_eq!(route.backends.len(), 2);
        assert!(route.upstream_h2c);
        // The new model always allows upgrades (WP-23 dropped the switch).
        assert!(route.websocket);
        assert!(route.health.is_some());
        let ports: Vec<_> = route
            .backends
            .iter()
            .map(|backend| backend.authority.port_u16())
            .collect();
        assert_eq!(ports, vec![Some(8080), Some(8081)]);

        // An empty health mode compiles to a proxy without a check.
        let mut plain = site("proxy");
        plain.targets = vec!["127.0.0.1:8080".into()];
        let CompiledSiteHandler::Proxy(route) = compile_site_handler(&plain).await.unwrap() else {
            panic!("proxy site must compile to a proxy handler");
        };
        assert!(route.health.is_none());
        assert!(!route.upstream_h2c);
        assert_eq!(route.backends.len(), 1);
    }

    #[tokio::test]
    async fn compile_redirect_site() {
        let mut redirect = site("redirect");
        redirect.redirect_to = "https://example.com/landing".into();
        redirect.redirect_code = 301;
        let CompiledSiteHandler::Response(response) =
            compile_site_handler(&redirect).await.unwrap()
        else {
            panic!("redirect site must compile to a response handler");
        };
        let SiteResponse::Redirect {
            status, keep_path, ..
        } = &response
        else {
            panic!("expected the redirect variant");
        };
        assert_eq!(*status, StatusCode::MOVED_PERMANENTLY);
        assert!(!keep_path);
        let reply = response
            .serve(
                &Method::GET,
                "old.test",
                &"/gone/page?q=1".parse::<PathAndQuery>().unwrap(),
                "/",
                &HeaderMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            reply.headers().get(LOCATION).unwrap(),
            "https://example.com/landing"
        );

        // redirect_code 0 falls back to the legacy default 302.
        let mut plain = site("redirect");
        plain.redirect_to = "https://example.com/".into();
        let CompiledSiteHandler::Response(response) = compile_site_handler(&plain).await.unwrap()
        else {
            panic!("redirect site must compile to a response handler");
        };
        let reply = response
            .serve(
                &Method::GET,
                "old.test",
                &"/".parse::<PathAndQuery>().unwrap(),
                "/",
                &HeaderMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn compile_text_site() {
        let mut text = site("text");
        text.text_body = "Under maintenance".into();
        text.text_content_type = "text/plain".into();
        let CompiledSiteHandler::Response(response) = compile_site_handler(&text).await.unwrap()
        else {
            panic!("text site must compile to a response handler");
        };
        let reply = response
            .serve(
                &Method::GET,
                "status.test",
                &"/".parse::<PathAndQuery>().unwrap(),
                "/",
                &HeaderMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers().get(CONTENT_TYPE).unwrap(), "text/plain");
        let body = BodyExt::collect(reply.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(body, Bytes::from_static(b"Under maintenance"));
    }

    #[tokio::test]
    async fn compile_static_site() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<h1>static-ok</h1>").unwrap();
        let mut static_site = site("static");
        static_site.root = dir.path().to_string_lossy().into_owned();
        let CompiledSiteHandler::Response(response) =
            compile_site_handler(&static_site).await.unwrap()
        else {
            panic!("static site must compile to a response handler");
        };
        let reply = response
            .serve(
                &Method::GET,
                "docs.test",
                &"/".parse::<PathAndQuery>().unwrap(),
                "/",
                &HeaderMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers().get(CONTENT_TYPE).unwrap(), "text/html");
        let body = BodyExt::collect(reply.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(body, Bytes::from_static(b"<h1>static-ok</h1>"));
    }

    #[tokio::test]
    async fn compile_routes_from_listener() {
        let mut api = site("proxy");
        api.domains = vec!["api.example.com".into()];
        api.targets = vec!["127.0.0.1:9001".into()];
        let mut old = site("redirect");
        old.domains = vec!["old.example.com".into(), "*.wild.test".into()];
        old.redirect_to = "https://example.com/".into();
        old.redirect_code = 302;
        let listener = Listener {
            key: "web".into(),
            enable: true,
            sites: vec![api, old],
            ..Listener::default()
        };

        let routes = compile_routes(&listener).await.unwrap();
        let route = routes.find("api.example.com", "/").expect("api route");
        assert!(matches!(route.action, RouteAction::Proxy(_)));
        let route = routes
            .find("old.example.com", "/x")
            .expect("redirect route");
        assert!(matches!(route.action, RouteAction::Response(_)));
        assert!(
            routes.find("sub.wild.test", "/").is_some(),
            "wildcard domain resolves"
        );
        assert!(
            routes.find("unknown.test", "/").is_none(),
            "unmatched host falls through"
        );
    }

    #[tokio::test]
    async fn site_type_validation() {
        let unknown = site("loadbalance");
        let Err(errors) = compile_site_handler(&unknown).await else {
            panic!("an unknown site_type must fail to compile");
        };
        assert!(
            errors.iter().any(|error| error.contains("site_type")),
            "unexpected errors: {errors:?}"
        );

        // The listener bridge surfaces the same failure.
        let listener = Listener {
            sites: vec![unknown],
            ..Listener::default()
        };
        let Err(errors) = compile_routes(&listener).await else {
            panic!("a listener with an unknown site_type must fail to compile");
        };
        assert!(
            errors.iter().any(|error| error.contains("site_type")),
            "unexpected errors: {errors:?}"
        );
    }
}
