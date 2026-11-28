//! The FileBrowser Quantum config renderer (WP-66 step 2): one instance →
//! the JSON document Quantum loads via `--config`. Field names are
//! verified against Quantum v2.1.0-stable's `backend/pkg/settings`
//! structs (`http.listen/port/baseURL/externalUrl/disableWebDAV/
//! trustProxyHeaders`, `auth.tokenExpirationHours/adminUsername/
//! adminPassword/methods.{proxy.header,noauth}`, `server.sources[].{path,
//! name,config.readOnly}`). The file is JSON — valid YAML — and Quantum
//! expands `${VAR}` references in string scalars from the process
//! environment, so the admin password is rendered as an env reference and
//! never touches the file.

use std::net::IpAddr;

use serde_json::{Value, json};

use crate::model::{AuthMethod, Instance};

/// The admin password reference written into the config file; the real
/// value travels in [`limits::PASSWORD_ENV`] (see `instance.rs`).
const PASSWORD_ENV_REFERENCE: &str = "${FILEBROWSER_ADMIN_PASSWORD}";

/// Renders the Quantum config for one instance. `data_dir` is the
/// instance's own directory (`<config>/filebrowser/<key>/`), currently
/// informational — Quantum stores its database next to the config file.
pub fn render_config(instance: &Instance, _data_dir: &std::path::Path) -> Value {
    let http = json!({
        "listen": instance.listen_ip.map(|ip: IpAddr| ip.to_string()).unwrap_or_default(),
        "port": instance.effective_port(),
        "baseURL": instance.base_url,
        // Share links use the first access URL; Quantum falls back to the
        // listen address when empty.
        "externalUrl": instance.access_urls.first().cloned().unwrap_or_default(),
        "disableWebDAV": instance.disable_web_dav,
        "trustProxyHeaders": instance.trust_proxy_headers,
    });
    // `auth.methods` carries the active method: `noauth` overrides
    // everything, `proxy` needs its header, `password` is the default and
    // needs no block.
    let methods = match instance.auth_method {
        AuthMethod::NoAuth => json!({ "noauth": true }),
        AuthMethod::Proxy => json!({ "proxy": { "header": instance.proxy_header } }),
        AuthMethod::Password => json!({}),
    };
    let auth = json!({
        "tokenExpirationHours": instance.effective_token_hours(),
        "adminUsername": instance.admin_user,
        "adminPassword": PASSWORD_ENV_REFERENCE,
        "methods": methods,
    });
    let sources: Vec<Value> = instance
        .sources
        .iter()
        .map(|source| {
            json!({
                "path": source.path,
                "name": source.name,
                "config": { "readOnly": source.read_only },
            })
        })
        .collect();
    json!({
        "http": http,
        "auth": auth,
        "server": { "sources": sources },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;
    use crate::model::limits;

    fn instance() -> Instance {
        Instance {
            key: "abc123def456".to_string(),
            name: "files".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "super-secret-password".to_string(),
            ..Instance::default()
        }
    }

    #[test]
    fn render_config_snapshot() {
        let mut instance = instance();
        instance.port = 0; // normalizes to 8080 in the output
        instance
            .access_urls
            .push("https://files.example.com/".to_string());
        instance.listen_ip = Some("127.0.0.1".parse().unwrap());
        instance.sources.push(Source {
            path: "/srv/files".to_string(),
            name: String::new(),
            read_only: true,
        });
        instance.auth_method = AuthMethod::Proxy;
        instance.proxy_header = "Remote-User".to_string();

        let rendered = render_config(&instance, std::path::Path::new("/tmp/data"));
        let http = &rendered["http"];
        assert_eq!(http["listen"], "127.0.0.1");
        assert_eq!(http["port"], limits::DEFAULT_PORT);
        assert_eq!(http["externalUrl"], "https://files.example.com/");
        assert_eq!(http["trustProxyHeaders"], false);
        let auth = &rendered["auth"];
        assert_eq!(auth["tokenExpirationHours"], limits::DEFAULT_TOKEN_HOURS);
        assert_eq!(auth["adminUsername"], "admin");
        assert_eq!(auth["methods"]["proxy"]["header"], "Remote-User");
        let sources = &rendered["server"]["sources"];
        assert_eq!(sources.as_array().expect("sources").len(), 1);
        assert_eq!(sources[0]["path"], "/srv/files");
        assert_eq!(sources[0]["config"]["readOnly"], true);
    }

    #[test]
    fn render_never_writes_password_to_file() {
        let instance = instance();
        let rendered = render_config(&instance, std::path::Path::new("/tmp/data")).to_string();
        assert!(
            !rendered.contains("super-secret-password"),
            "the password must only travel through the environment: {rendered}"
        );
        assert!(rendered.contains(limits::PASSWORD_ENV));
        // The noauth method flips the switch instead of a password block.
        let mut open = instance;
        open.auth_method = AuthMethod::NoAuth;
        let rendered = render_config(&open, std::path::Path::new("/tmp/data"));
        assert_eq!(rendered["auth"]["methods"]["noauth"], true);
    }
}
