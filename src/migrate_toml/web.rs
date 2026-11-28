//! WP-39 step 2: the web-service mapping — legacy `server` section and
//! `[[routes]]` entries into `webservice.json` (spec:
//! docs/plan/WP-39-migrate-toml.md §3.3). Pure function; every decision
//! lands in the report.
#![allow(dead_code)]

use super::report::{DefaultChange, DroppedField, FieldMap, MigrateReport};
use fg_gateway::legacy_config::RawConfig;
use fg_gateway::web::model::{FileConfig, Listener, Site};

fn map(from: &str, report: &mut MigrateReport, to: &str) {
    report.mapped.push(FieldMap {
        from: from.to_owned(),
        to: to.to_owned(),
    });
}

fn drop_field(report: &mut MigrateReport, field: &str, reason: &str, hint: &str) {
    report.dropped.push(DroppedField {
        field: field.to_owned(),
        reason_key: reason.to_owned(),
        hint_key: hint.to_owned(),
    });
}

fn default_change(report: &mut MigrateReport, field: &str, old: &str, new: &str) {
    report.defaults_changed.push(DefaultChange {
        field: field.to_owned(),
        old_effective: old.to_owned(),
        new_effective: new.to_owned(),
    });
}

/// Backend timeout mapping: explicitly configured legacy values are kept
/// per site; unconfigured ones take the new default (connect) or keep
/// the conservative 30s (response header — the new default "unlimited"
/// would let a stuck backend hold connections forever).
fn timeout_fields(config: &RawConfig, report: &mut MigrateReport) -> (u32, u32) {
    let server = &config.server;
    let connect = if server.connect_timeout_ms != 2_000 {
        map(
            "server.connect_timeout_ms",
            report,
            "sites[].timeoutsConnectSecs",
        );
        ((server.connect_timeout_ms / 1000).max(1)) as u32
    } else {
        default_change(
            report,
            "server.connect_timeout_ms",
            "2 秒（旧默认）",
            "10 秒（新默认，站点字段 0 = 默认）",
        );
        0
    };
    let response = if server.response_header_timeout_ms != 30_000 {
        map(
            "server.response_header_timeout_ms",
            report,
            "sites[].timeoutsResponseSecs",
        );
        ((server.response_header_timeout_ms / 1000).max(1)) as u32
    } else {
        default_change(
            report,
            "server.response_header_timeout_ms",
            "30 秒（旧默认）",
            "迁移保守保留 30 秒（新模型默认不限）",
        );
        30
    };
    (connect, response)
}

fn server_drops(server: &fg_gateway::legacy_config::Settings, report: &mut MigrateReport) {
    drop_field(
        report,
        "server.tls_handshake_timeout_ms",
        "新模型固定 5 秒握手保护",
        "确认默认保护值可接受",
    );
    drop_field(
        report,
        "server.max_connections",
        "新模型没有监听器级总连接上限",
        "见 docs/DESIGN.md 的默认保护值",
    );
    drop_field(
        report,
        "server.connection_lifetime_ms",
        "新模型没有总寿命限制",
        "确认默认保护值可接受",
    );
    if server.metrics_listen.is_some() {
        drop_field(
            report,
            "server.metrics_listen",
            "旧独立回环指标监听不再提供",
            "改用管理 API 的 GET /api/metrics（需 metrics:read 令牌）",
        );
    }
}

fn convert_route(
    host: &str,
    route: &fg_gateway::legacy_config::RawRoute,
    timeouts: (u32, u32),
    report: &mut MigrateReport,
) -> Result<Site, String> {
    let mut site = Site {
        domains: vec![host.to_owned()],
        site_type: "proxy".to_owned(),
        timeouts_connect_secs: timeouts.0,
        timeouts_response_secs: timeouts.1,
        ..Site::default()
    };
    if let Some(prefix) = &route.path_prefix
        && prefix != "/"
    {
        drop_field(
            report,
            "routes[].path_prefix",
            "新模型尚未包含 locations 分路径规则",
            "该路由按独立站点迁移，前缀语义暂失；locations 落地后重新映射",
        );
    }
    if let Some(upstream) = &route.upstream {
        site.targets.push(normalize_target(upstream));
        map("routes[].upstream", report, "sites[].targets");
    }
    for backend in &route.backends {
        // RawBackend's fields are private to the legacy module; the serde
        // view is the shared contract.
        let Ok(value) = serde_json::to_value(backend) else {
            continue;
        };
        let Some(upstream) = value.get("upstream").and_then(|u| u.as_str()) else {
            continue;
        };
        let mut line = normalize_target(upstream);
        if let Some(weight) = value.get("weight").and_then(|w| w.as_u64())
            && weight != 1
        {
            line.push_str(&format!(" weight={weight}"));
        }
        if value
            .get("backup")
            .and_then(|b| b.as_bool())
            .unwrap_or(false)
        {
            line.push_str(" backup");
        }
        site.targets.push(line);
    }
    if route.response.is_none() && site.targets.is_empty() {
        return Err(format!("routes[{host}] 没有上游或后端"));
    }
    if route.websocket {
        map("routes[].websocket", report, "新模型自动支持升级");
    } else {
        drop_field(
            report,
            "routes[].websocket = false",
            "新模型没有「禁止升级」开关",
            "改用访问控制或站点类型替代",
        );
    }
    if route.upstream_h2c {
        site.upstream_h2c = true;
        map("routes[].upstream_h2c", report, "sites[].upstreamH2c");
    }
    if let Some(health) = &route.health {
        // RawHealthCheck fields are module-private; serde is the contract.
        if let Ok(value) = serde_json::to_value(health) {
            site.health_mode = value
                .get("mode")
                .and_then(|m| m.as_str())
                .unwrap_or("http")
                .to_owned();
            site.health_path = value
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or("/")
                .to_owned();
            site.health_interval_secs = value
                .get("interval_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(10) as u32;
            site.health_timeout_secs = value
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(3) as u32;
            site.health_fails = value.get("fails").and_then(|v| v.as_u64()).unwrap_or(3) as u32;
            site.health_passes = value.get("passes").and_then(|v| v.as_u64()).unwrap_or(2) as u32;
            map(
                "routes[].health",
                report,
                "sites[].health{mode,path,interval,timeout,fails,passes}",
            );
        }
    }
    if let Some(response) = &route.response {
        let Ok(value) = serde_json::to_value(response) else {
            return Err(format!("routes[{host}] response 无法读取"));
        };
        // The legacy enum serializes with an internal `type` tag.
        let kind = value
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or_default()
            .to_owned();
        if kind == "redirect" {
            site.site_type = "redirect".to_owned();
            site.redirect_to = value
                .get("target")
                .and_then(|t| t.as_str())
                .unwrap_or_default()
                .to_owned();
            site.redirect_code = value
                .get("status")
                .and_then(|s| s.as_u64())
                .map(|s| s as u16)
                .unwrap_or(302);
        } else if kind == "text" {
            site.site_type = "text".to_owned();
            site.text_body = value
                .get("body")
                .and_then(|b| b.as_str())
                .unwrap_or_default()
                .to_owned();
            site.text_content_type = value
                .get("content_type")
                .and_then(|c| c.as_str())
                .unwrap_or_default()
                .to_owned();
        } else if kind == "static" {
            site.site_type = "static".to_owned();
            site.root = value
                .get("root")
                .and_then(|r| r.as_str())
                .unwrap_or_default()
                .to_owned();
        } else {
            return Err(format!("routes[{host}] response 变体无法识别"));
        }
        map("routes[].response", report, "sites[].type 与对应字段");
    }
    Ok(site)
}

fn normalize_target(upstream: &str) -> String {
    let trimmed = upstream.trim();
    if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("http://{trimmed}")
    }
}

/// Converts the server section and every route into the webservice
/// document. Route order is preserved; each `[[routes]]` entry becomes
/// its own site (domains = [host]).
pub fn convert(config: &RawConfig, report: &mut MigrateReport) -> Result<FileConfig, String> {
    let mut file = FileConfig::default();
    file.settings.enable = config.server.http_enabled;
    let timeouts = timeout_fields(config, report);
    let mut listener = Listener {
        key: "main".to_owned(),
        name: "Migrated listener".to_owned(),
        enable: true,
        listen_ip: config.server.listen.ip().to_string(),
        port: config.server.listen.port(),
        tls: config.server.tls,
        ..Listener::default()
    };
    map("server.listen", report, "listeners[0].listenIp + port");
    server_drops(&config.server, report);
    for route in &config.routes {
        listener
            .sites
            .push(convert_route(&route.host, route, timeouts, report)?);
    }
    file.listeners.push(listener);
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;


    fn config(toml_text: &str) -> RawConfig {
        toml::from_str::<RawConfig>(toml_text).expect("fixture parses")
    }

    const FIXTURE: &str = include_str!("../../tests/fixtures/toml/basic.toml");

    #[test]
    fn server_section_becomes_listener_and_routes_become_sites() {
        let mut report = MigrateReport::default();
        let file = convert(&config(FIXTURE), &mut report).expect("converts");
        let listener = &file.listeners[0];
        assert_eq!(listener.listen_ip, "127.0.0.1");
        assert_eq!(listener.port, 8080);
        let site = &listener.sites[0];
        assert_eq!(site.domains, vec!["app.test".to_owned()]);
        assert_eq!(site.targets, vec![
            "http://10.0.0.2:8080 weight=3".to_owned(),
            "http://10.0.0.3:8081 backup".to_owned(),
        ]);
        // connect_timeout_ms = 3000 was explicit → kept per site in seconds.
        assert_eq!(site.timeouts_connect_secs, 3);
        // response header was not configured → conservative 30s kept.
        assert_eq!(site.timeouts_response_secs, 30);
        assert!(report
            .mapped
            .iter()
            .any(|m| m.from == "server.listen" && m.to == "listeners[0].listenIp + port"));
    }

    #[test]
    fn unconfigured_timeouts_report_the_new_defaults() {
        let text = concat!(
            "schema_version = 1\n",
            "[server]\nlisten = \"127.0.0.1:8080\"\n",
            "[[routes]]\nhost = \"app.test\"\n",
            "upstream = \"http://127.0.0.1:9001\"\n",
        );
        let mut report = MigrateReport::default();
        let file = convert(&config(text), &mut report).expect("converts");
        let site = &file.listeners[0].sites[0];
        // Zero keeps the new model default (10s via compile), 30 stays.
        assert_eq!(site.timeouts_connect_secs, 0);
        assert_eq!(site.timeouts_response_secs, 30);
        assert!(report.defaults_changed.iter().any(|change| {
            change.field == "server.connect_timeout_ms"
                && change.new_effective.contains("10 秒")
        }));
        assert!(report.defaults_changed.iter().any(|change| {
            change.field == "server.response_header_timeout_ms" && change.old_effective.contains("30")
        }));
    }

    #[test]
    fn protection_only_fields_are_dropped_with_hints() {
        let text = concat!(
            "schema_version = 1\n",
            "[server]\n",
            "listen = \"127.0.0.1:8080\"\n",
            "max_connections = 512\n",
            "connection_lifetime_ms = 60000\n",
            "metrics_listen = \"127.0.0.1:9090\"\n",
        );
        let mut report = MigrateReport::default();
        convert(&config(text), &mut report).expect("converts");
        for field in [
            "server.tls_handshake_timeout_ms",
            "server.max_connections",
            "server.connection_lifetime_ms",
            "server.metrics_listen",
        ] {
            assert!(
                report.dropped.iter().any(|d| d.field == field && !d.hint_key.is_empty()),
                "{field} should be dropped with a hint"
            );
        }
    }

    #[test]
    fn response_routes_map_to_site_types() {
        let text = concat!(
            "schema_version = 1\n",
            "[server]\nlisten = \"127.0.0.1:8080\"\n",
            "[[routes]]\nhost = \"old.test\"\n",
            "response = { type = \"redirect\", target = \"https://new.test/\", status = 301 }\n",
        );
        let mut report = MigrateReport::default();
        let file = convert(&config(text), &mut report).expect("converts");
        let site = &file.listeners[0].sites[0];
        assert_eq!(site.site_type, "redirect");
        assert_eq!(site.redirect_to, "https://new.test/");
        assert_eq!(site.redirect_code, 301);
    }

    #[test]
    fn websocket_disabled_is_dropped() {
        let text = concat!(
            "schema_version = 1\n",
            "[server]\nlisten = \"127.0.0.1:8080\"\n",
            "[[routes]]\nhost = \"app.test\"\n",
            "websocket = false\n",
            "upstream = \"http://127.0.0.1:9001\"\n",
        );
        let mut report = MigrateReport::default();
        convert(&config(text), &mut report).expect("converts");
        assert!(report.dropped.iter().any(|d| d.field.contains("websocket")));
    }

}
