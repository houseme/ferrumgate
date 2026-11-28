//! Site-level Prometheus 0.0.4 text-format metrics with `ferrumgate_` prefix
//! (WP-28 §3.3, decision D12).
//!
//! All label dimensions are fixed-cardinality (`listener`, `site`, `class`,
//! `reason`, `upstream`, `route`, `action`). Visitor IPs, raw request paths,
//! headers, query strings, and backend credentials are never emitted as labels.

use std::fmt::Write as _;

use hyper::Uri;

use super::{
    latency::PrometheusHistogram,
    recorder::{DENY_KIND_COUNT, DenyKind, STATUS_CLASS_LABELS},
};

/// Prometheus 0.0.4 Content-Type header value.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Snapshot of one upstream backend for Prometheus export.
#[derive(Clone, Debug)]
pub struct UpstreamMetricRow {
    /// Display URL (credentials, query, fragment, and default ports stripped).
    pub upstream: String,
    /// Route label for path-split or per-user split backends (`""` for default pool).
    pub route: String,
    pub up: bool,
    pub requests_total: u64,
    pub response_bytes_total: u64,
}

/// Snapshot of one site for Prometheus export.
#[derive(Clone, Debug)]
pub struct SiteMetricRow {
    pub listener: String,
    pub site: String,
    pub requests_total: u64,
    pub errors_total: u64,
    pub active_requests: u32,
    pub response_bytes_total: u64,
    /// `[2xx, 3xx, 4xx, 5xx]`.
    pub responses_by_class: [u64; 4],
    /// `[ban, ip, country, rateLimit, waf]`.
    pub blocked_by_reason: [u64; DENY_KIND_COUNT],
    pub duration_hist: PrometheusHistogram,
    pub upstreams: Vec<UpstreamMetricRow>,
}

/// Snapshot of listener-level action counters for Prometheus export.
#[derive(Clone, Debug)]
pub struct ListenerActionMetricRow {
    pub listener: String,
    pub https_redirect_total: u64,
    pub not_found_total: u64,
}

/// Complete input for [`render_prometheus`].
#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    pub sites: Vec<SiteMetricRow>,
    pub listeners: Vec<ListenerActionMetricRow>,
}

/// Formats the `listener` label: `"{name}#{key}"` (or `key` if `name` is empty).
pub fn listener_label(name: &str, key: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        key.to_owned()
    } else if key.is_empty() {
        trimmed.to_owned()
    } else {
        format!("{trimmed}#{key}")
    }
}

/// Formats the `site` label: `name` if non-empty, otherwise the first domain,
/// otherwise `key`.
pub fn site_label(name: &str, domains: &[String], key: &str) -> String {
    let trimmed = name.trim();
    if !trimmed.is_empty() {
        return trimmed.to_owned();
    }
    if let Some(first) = domains.iter().find(|d| !d.trim().is_empty()) {
        return first.trim().to_owned();
    }
    key.to_owned()
}

/// Formats a backend URL for Prometheus `upstream` labels, logs, and topology:
/// strips userinfo (`user:pass@`), query string, fragment, and default ports
/// (80 for `http`, 443 for `https`).
pub fn upstream_display_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(target) = crate::web::upstream::parse_target(trimmed) {
        return crate::web::upstream::display_url(&target);
    }
    // Strip fragment and query first so URIs with query params still sanitize cleanly.
    let no_frag = trimmed.split('#').next().unwrap_or(trimmed);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    let Ok(uri) = no_query.parse::<Uri>() else {
        // Fallback: manually strip credentials if `scheme://user:pass@host...`.
        if let Some((scheme, rest)) = no_query.split_once("://") {
            let host_part = rest.split('/').next().unwrap_or(rest);
            let stripped = match host_part.rsplit_once('@') {
                Some((_, hp)) => hp,
                None => host_part,
            };
            return format!("{scheme}://{stripped}");
        }
        return no_query.to_owned();
    };
    let scheme = uri.scheme_str().unwrap_or("http");
    let Some(authority) = uri.authority() else {
        return no_query.to_owned();
    };
    let host_port = match authority.as_str().rsplit_once('@') {
        Some((_, hp)) => hp,
        None => authority.as_str(),
    };
    let (host, explicit_port) = split_host_port(host_port);
    let port = explicit_port.unwrap_or(if scheme == "https" { 443 } else { 80 });
    let is_default = matches!((scheme, port), ("http", 80) | ("https", 443));
    if is_default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

fn split_host_port(host_port: &str) -> (&str, Option<u16>) {
    match host_port.rfind(']') {
        Some(close) => {
            let (host, rest) = host_port.split_at(close + 1);
            (host, rest.strip_prefix(':').and_then(|p| p.parse().ok()))
        }
        None => match host_port.split_once(':') {
            Some((host, port)) => (host, port.parse().ok()),
            None => (host_port, None),
        },
    }
}

/// Renders all 11 WP-28 Prometheus metric families in Prometheus 0.0.4 text
/// format, sorted alphabetically by family name with `# HELP` and `# TYPE`
/// emitted once per family.
pub fn render_prometheus(snapshot: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(4096);

    // 1. ferrumgate_listener_requests_total
    emit_header(
        &mut out,
        "ferrumgate_listener_requests_total",
        "Listener-level action requests (https_redirect, not_found).",
        "counter",
    );
    for l in &snapshot.listeners {
        let listener = escape_label(&l.listener);
        let _ = writeln!(
            out,
            "ferrumgate_listener_requests_total{{action=\"https_redirect\",listener=\"{listener}\"}} {}",
            l.https_redirect_total
        );
        let _ = writeln!(
            out,
            "ferrumgate_listener_requests_total{{action=\"not_found\",listener=\"{listener}\"}} {}",
            l.not_found_total
        );
    }

    // 2. ferrumgate_site_active_requests
    emit_header(
        &mut out,
        "ferrumgate_site_active_requests",
        "Current in-flight HTTP requests per site.",
        "gauge",
    );
    for s in &snapshot.sites {
        let _ = writeln!(
            out,
            "ferrumgate_site_active_requests{{listener=\"{}\",site=\"{}\"}} {}",
            escape_label(&s.listener),
            escape_label(&s.site),
            s.active_requests
        );
    }

    // 3. ferrumgate_site_blocked_total
    emit_header(
        &mut out,
        "ferrumgate_site_blocked_total",
        "Blocked requests per site by deny reason.",
        "counter",
    );
    for s in &snapshot.sites {
        let listener = escape_label(&s.listener);
        let site = escape_label(&s.site);
        for (idx, kind) in DenyKind::ALL_REASONS.iter().enumerate() {
            let _ = writeln!(
                out,
                "ferrumgate_site_blocked_total{{listener=\"{listener}\",reason=\"{}\",site=\"{site}\"}} {}",
                kind.as_str(),
                s.blocked_by_reason[idx]
            );
        }
    }

    // 4. ferrumgate_site_errors_total
    emit_header(
        &mut out,
        "ferrumgate_site_errors_total",
        "Total 5xx and closed (444) error responses per site.",
        "counter",
    );
    for s in &snapshot.sites {
        let _ = writeln!(
            out,
            "ferrumgate_site_errors_total{{listener=\"{}\",site=\"{}\"}} {}",
            escape_label(&s.listener),
            escape_label(&s.site),
            s.errors_total
        );
    }

    // 5. ferrumgate_site_request_duration_seconds (histogram)
    emit_header(
        &mut out,
        "ferrumgate_site_request_duration_seconds",
        "First-byte request duration in seconds per site.",
        "histogram",
    );
    for s in &snapshot.sites {
        let listener = escape_label(&s.listener);
        let site = escape_label(&s.site);
        for (le, cum) in &s.duration_hist.buckets {
            let _ = writeln!(
                out,
                "ferrumgate_site_request_duration_seconds_bucket{{le=\"{}\",listener=\"{listener}\",site=\"{site}\"}} {cum}",
                format_float(*le)
            );
        }
        let _ = writeln!(
            out,
            "ferrumgate_site_request_duration_seconds_bucket{{le=\"+Inf\",listener=\"{listener}\",site=\"{site}\"}} {}",
            s.duration_hist.count
        );
        let _ = writeln!(
            out,
            "ferrumgate_site_request_duration_seconds_sum{{listener=\"{listener}\",site=\"{site}\"}} {}",
            format_float(s.duration_hist.sum_seconds)
        );
        let _ = writeln!(
            out,
            "ferrumgate_site_request_duration_seconds_count{{listener=\"{listener}\",site=\"{site}\"}} {}",
            s.duration_hist.count
        );
    }

    // 6. ferrumgate_site_requests_total
    emit_header(
        &mut out,
        "ferrumgate_site_requests_total",
        "Total HTTP requests served per site.",
        "counter",
    );
    for s in &snapshot.sites {
        let _ = writeln!(
            out,
            "ferrumgate_site_requests_total{{listener=\"{}\",site=\"{}\"}} {}",
            escape_label(&s.listener),
            escape_label(&s.site),
            s.requests_total
        );
    }

    // 7. ferrumgate_site_response_bytes_total
    emit_header(
        &mut out,
        "ferrumgate_site_response_bytes_total",
        "Total response bytes written to visitors per site.",
        "counter",
    );
    for s in &snapshot.sites {
        let _ = writeln!(
            out,
            "ferrumgate_site_response_bytes_total{{listener=\"{}\",site=\"{}\"}} {}",
            escape_label(&s.listener),
            escape_label(&s.site),
            s.response_bytes_total
        );
    }

    // 8. ferrumgate_site_responses_total
    emit_header(
        &mut out,
        "ferrumgate_site_responses_total",
        "Total HTTP responses per site by status class.",
        "counter",
    );
    for s in &snapshot.sites {
        let listener = escape_label(&s.listener);
        let site = escape_label(&s.site);
        for (idx, class) in STATUS_CLASS_LABELS.iter().enumerate() {
            let _ = writeln!(
                out,
                "ferrumgate_site_responses_total{{class=\"{class}\",listener=\"{listener}\",site=\"{site}\"}} {}",
                s.responses_by_class[idx]
            );
        }
    }

    // 9. ferrumgate_upstream_requests_total
    emit_header(
        &mut out,
        "ferrumgate_upstream_requests_total",
        "Total forwarded requests per upstream backend.",
        "counter",
    );
    for s in &snapshot.sites {
        let listener = escape_label(&s.listener);
        let site = escape_label(&s.site);
        for u in &s.upstreams {
            let _ = writeln!(
                out,
                "ferrumgate_upstream_requests_total{{listener=\"{listener}\",route=\"{}\",site=\"{site}\",upstream=\"{}\"}} {}",
                escape_label(&u.route),
                escape_label(&u.upstream),
                u.requests_total
            );
        }
    }

    // 10. ferrumgate_upstream_response_bytes_total
    emit_header(
        &mut out,
        "ferrumgate_upstream_response_bytes_total",
        "Total response bytes received from each upstream backend.",
        "counter",
    );
    for s in &snapshot.sites {
        let listener = escape_label(&s.listener);
        let site = escape_label(&s.site);
        for u in &s.upstreams {
            let _ = writeln!(
                out,
                "ferrumgate_upstream_response_bytes_total{{listener=\"{listener}\",route=\"{}\",site=\"{site}\",upstream=\"{}\"}} {}",
                escape_label(&u.route),
                escape_label(&u.upstream),
                u.response_bytes_total
            );
        }
    }

    // 11. ferrumgate_upstream_up
    emit_header(
        &mut out,
        "ferrumgate_upstream_up",
        "Whether an upstream backend is currently healthy (1) or unavailable (0).",
        "gauge",
    );
    for s in &snapshot.sites {
        let listener = escape_label(&s.listener);
        let site = escape_label(&s.site);
        // Deduplicate upstream URLs per site for the upstream_up gauge.
        let mut seen = std::collections::HashSet::new();
        for u in &s.upstreams {
            if !seen.insert(&u.upstream) {
                continue;
            }
            let _ = writeln!(
                out,
                "ferrumgate_upstream_up{{listener=\"{listener}\",site=\"{site}\",upstream=\"{}\"}} {}",
                escape_label(&u.upstream),
                if u.up { 1 } else { 0 }
            );
        }
    }

    out
}

fn emit_header(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn escape_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn format_float(v: f64) -> String {
    if !v.is_finite() {
        if v.is_nan() {
            "NaN".to_owned()
        } else if v > 0.0 {
            "+Inf".to_owned()
        } else {
            "-Inf".to_owned()
        }
    } else if v == 0.0 {
        "0".to_owned()
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        // Trim trailing noise while preserving microsecond precision.
        let s = format!("{v:.6}");
        let trimmed = s.trim_end_matches('0').trim_end_matches('.');
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_upstream_label_is_display_url() {
        assert_eq!(
            upstream_display_url("http://user:s3cr3t@10.0.0.5:8080/api?token=abc#frag"),
            "http://10.0.0.5:8080"
        );
        assert_eq!(
            upstream_display_url("https://admin:pw@backend.internal:443?k=v"),
            "https://backend.internal"
        );
        assert_eq!(
            upstream_display_url("http://backend.internal:80"),
            "http://backend.internal"
        );
        assert_eq!(
            upstream_display_url("https://[::1]:8443/path?x=1"),
            "https://[::1]:8443"
        );
    }

    #[test]
    fn label_helpers_follow_wp28_conventions() {
        assert_eq!(listener_label("main", "abc123"), "main#abc123");
        assert_eq!(listener_label("", "abc123"), "abc123");
        assert_eq!(
            site_label("", &["app.example.com".into()], "site1"),
            "app.example.com"
        );
        assert_eq!(
            site_label("My App", &["app.example.com".into()], "site1"),
            "My App"
        );
    }
}
