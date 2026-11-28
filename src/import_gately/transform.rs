//! Module migration trait and pure transformers for WP-38.
//!
//! Core principle (WP-38 §3.3 & §8): **never drop upstream fields** other than
//! explicitly excluded Go runtime tuning knobs (`gcPercent`, `maxProcs`).
//! Unimplemented or newer-version upstream fields are preserved verbatim in the
//! output JSON so configs can round-trip between Gately and FerrumGate, while
//! strict FerrumGate model validation runs against the known subset.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::report::{FieldChange, Warning, summarize_value};
use super::scan::is_valid_config_name;

/// Upstream baseline commit documented in WP-38 §3.3.
pub const UPSTREAM_BASELINE: &str = "442162e4d0b6";

/// FerrumGate listener cap for `webservice.json` (matches `portforward` 64-listener limit).
pub const WEBSERVICE_MAX_LISTENERS: usize = 64;

/// Context passed into pure [`MigrateModule::transform`] calls.
#[derive(Clone, Debug)]
pub struct MigrateCtx {
    /// Module IDs compiled into this binary.
    pub built_modules: Vec<&'static str>,
}

impl Default for MigrateCtx {
    fn default() -> Self {
        Self {
            built_modules: fg_core::features::built_modules(),
        }
    }
}

/// Detailed output of transforming a single upstream JSON document.
#[derive(Clone, Debug)]
pub struct TransformOutput {
    pub value: Value,
    pub changed_fields: Vec<FieldChange>,
    pub warnings: Vec<Warning>,
    pub newer_version_detected: bool,
}

/// Pure JSON-to-JSON module migrator (WP-38 §3.2).
pub trait MigrateModule: Send + Sync {
    /// Module or configuration identifier (`"gately"`, `"webservice"`, `"ssl"`, `"portforward"`, ...).
    fn id(&self) -> &'static str;

    /// Converts an upstream Gately JSON value to a FerrumGate JSON value.
    fn transform(&self, input: &Value, ctx: &MigrateCtx) -> Result<Value, Vec<Warning>> {
        self.transform_detailed(input, ctx).map(|out| out.value)
    }

    /// Runs the module's own validator against the transformed JSON value.
    fn validate(&self, value: &Value) -> Result<(), Vec<String>>;

    /// Transforms an upstream JSON value while returning non-fatal warnings,
    /// transformation-level field changes, and whether unknown newer-version
    /// fields were spotted.
    fn transform_detailed(
        &self,
        input: &Value,
        ctx: &MigrateCtx,
    ) -> Result<TransformOutput, Vec<Warning>>;
}

// ---------------------------------------------------------------------------
// Global settings: gately.json -> ferrumgate.json
// ---------------------------------------------------------------------------

const SETTINGS_KNOWN_FIELDS: &[&str] = &[
    "listen",
    "httpsListen",
    "forceHTTPS",
    "safePath",
    "lanOnly",
    "denyMode",
    "denyStatus",
    "denyPage",
    "gatewaySSO",
    "disableProxyHeaders",
    "trustedProxies",
    "maxLoginFailures",
    "lockMinutes",
    "loginGlobalLimit",
    "confirmTimeout",
    "apiToken",
    "language",
    "uiLanguage",
    "timeZone",
    "dnsServers",
    "updateProxy",
    "restrictOutbound",
    "disableUpdateCheck",
    "logLevel",
    "logLines",
    "disableLogPersist",
    "logFileMB",
    "accessLogDays",
    "accessLogMB",
    "logDir",
    "thirdLogin",
    "disabledModules",
    "shutdownTimeoutMs",
    "upstreamCaFile",
];

const THIRD_LOGIN_KNOWN_FIELDS: &[&str] =
    &["enable", "callbackBase", "providers", "allowed", "skipTotp"];

const IDENTITY_PROVIDER_KNOWN_FIELDS: &[&str] = &[
    "key",
    "name",
    "type",
    "clientId",
    "clientSecret",
    "issuer",
    "proxy",
];

const GO_RUNTIME_TUNING_FIELDS: &[&str] = &["gcPercent", "maxProcs"];

/// Migrator for `gately.json` -> `ferrumgate.json`.
pub struct SettingsMigrator;

impl MigrateModule for SettingsMigrator {
    fn id(&self) -> &'static str {
        "gately"
    }

    fn transform_detailed(
        &self,
        input: &Value,
        _ctx: &MigrateCtx,
    ) -> Result<TransformOutput, Vec<Warning>> {
        let Some(src) = input.as_object() else {
            return Err(vec![Warning::new(
                "$",
                "InvalidType",
                "import.gately.expected_json_object",
                "gately.json root must be a JSON object",
            )]);
        };

        let mut out = Map::new();
        let mut changed_fields = Vec::new();
        let mut warnings = Vec::new();
        let mut newer_version_detected = false;

        for (key, value) in src {
            if GO_RUNTIME_TUNING_FIELDS.contains(&key.as_str()) {
                changed_fields.push(FieldChange {
                    path: key.clone(),
                    from: summarize_value(key, value),
                    to: "<removed>".to_owned(),
                });
                warnings.push(Warning::new(
                    key.clone(),
                    "UnsupportedField",
                    "import.gately.go_runtime_tuning_dropped",
                    format!(
                        "Go runtime tuning field '{key}' is not applicable to FerrumGate and was not imported."
                    ),
                ));
                continue;
            }

            if !SETTINGS_KNOWN_FIELDS.contains(&key.as_str()) {
                newer_version_detected = true;
                warnings.push(Warning::new(
                    key.clone(),
                    "UnknownField",
                    "import.gately.newer_version_field_preserved",
                    format!(
                        "Unrecognized settings field '{key}' was preserved in ferrumgate.json."
                    ),
                ));
            }

            out.insert(key.clone(), value.clone());
        }

        // Inspect nested thirdLogin for unknown fields while preserving them.
        if let Some(Value::Object(third)) = out.get("thirdLogin") {
            for key in third.keys() {
                if !THIRD_LOGIN_KNOWN_FIELDS.contains(&key.as_str()) {
                    newer_version_detected = true;
                    warnings.push(Warning::new(
                        format!("thirdLogin.{key}"),
                        "UnknownField",
                        "import.gately.newer_version_field_preserved",
                        format!("Unrecognized field 'thirdLogin.{key}' was preserved."),
                    ));
                }
            }
            if let Some(Value::Array(providers)) = third.get("providers") {
                for (idx, provider) in providers.iter().enumerate() {
                    if let Some(obj) = provider.as_object() {
                        for key in obj.keys() {
                            if !IDENTITY_PROVIDER_KNOWN_FIELDS.contains(&key.as_str()) {
                                newer_version_detected = true;
                                warnings.push(Warning::new(
                                    format!("thirdLogin.providers[{idx}].{key}"),
                                    "UnknownField",
                                    "import.gately.newer_version_field_preserved",
                                    format!(
                                        "Unrecognized field 'thirdLogin.providers[{idx}].{key}' was preserved."
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // WP-38 §3.3: always remind about GATELY_* -> FERRUMGATE_* env vars.
        warnings.push(Warning::new(
            "$env",
            "EnvVarRename",
            "import.gately.env_var_rename",
            "Environment variables are not stored in the config directory; rename GATELY_* variables to FERRUMGATE_* before starting fgate.",
        ));

        Ok(TransformOutput {
            value: Value::Object(out),
            changed_fields,
            warnings,
            newer_version_detected,
        })
    }

    fn validate(&self, value: &Value) -> Result<(), Vec<String>> {
        let known = strip_settings_unknown(value);
        let mut settings: fg_core::settings::Settings = serde_json::from_value(known)
            .map_err(|err| vec![format!("gately.json schema error: {err}")])?;
        settings.normalize();
        settings.validate(&fg_gateway::REGISTRY).map_err(|errors| {
            errors
                .into_iter()
                .map(|err| format!("{}: {}", err.field, err.message))
                .collect()
        })
    }
}

fn strip_settings_unknown(value: &Value) -> Value {
    let Some(obj) = value.as_object() else {
        return value.clone();
    };
    let mut clean = Map::new();
    for (key, val) in obj {
        if !SETTINGS_KNOWN_FIELDS.contains(&key.as_str()) {
            continue;
        }
        if key == "thirdLogin"
            && let Some(third) = val.as_object()
        {
            let mut clean_third = Map::new();
            for (tk, tv) in third {
                if !THIRD_LOGIN_KNOWN_FIELDS.contains(&tk.as_str()) {
                    continue;
                }
                if tk == "providers"
                    && let Some(providers) = tv.as_array()
                {
                    let clean_providers = providers
                        .iter()
                        .map(|provider| {
                            filter_object_keys(provider, IDENTITY_PROVIDER_KNOWN_FIELDS)
                        })
                        .collect();
                    clean_third.insert(tk.clone(), Value::Array(clean_providers));
                } else {
                    clean_third.insert(tk.clone(), tv.clone());
                }
            }
            clean.insert(key.clone(), Value::Object(clean_third));
        } else {
            clean.insert(key.clone(), val.clone());
        }
    }
    Value::Object(clean)
}

// ---------------------------------------------------------------------------
// Core module 1: webservice.json
// ---------------------------------------------------------------------------

const WEBSERVICE_ROOT_KNOWN: &[&str] = &["settings", "listeners"];
const WEBSERVICE_SETTINGS_KNOWN: &[&str] = &[
    "enable",
    "responseHeaderTimeoutMs",
    "authSecret",
    "authUsers",
    "ssoDomains",
    "autoBanSeconds",
];
const WEBSERVICE_AUTH_USER_KNOWN: &[&str] = &[
    "id",
    "name",
    "password",
    "totpSecret",
    "email",
    "displayName",
    "groups",
    "remark",
];
const WEBSERVICE_LISTENER_KNOWN: &[&str] = &[
    "key",
    "name",
    "enable",
    "network",
    "listenIp",
    "port",
    "tls",
    "minTls",
    "plainHttp",
    "httpPort",
    "acceptProxyProtocol",
    "accessScheme",
    "accessPort",
    "autoFirewall",
    "sites",
    "default",
    "remark",
];
const WEBSERVICE_SITE_KNOWN: &[&str] = &[
    "key",
    "name",
    "enable",
    "group",
    "domains",
    "siteType",
    "targets",
    "lbPolicy",
    "upstreamH2c",
    "useTargetHost",
    "forwardedHeaders",
    "insecureSkipVerify",
    "disableKeepAlives",
    "sendProxyProtocol",
    "upstreamSniFromHost",
    "passAuthCookies",
    "timeoutsConnectSecs",
    "timeoutsTlsSecs",
    "timeoutsResponseSecs",
    "clientIdleReadSecs",
    "clientIdleWriteSecs",
    "rewrites",
    "requestHeaders",
    "responseHeaders",
    "cors",
    "identityHeaders",
    "userRoutes",
    "redirectTo",
    "redirectCode",
    "root",
    "textBody",
    "textContentType",
    "textStatusCode",
    "healthMode",
    "healthPath",
    "healthIntervalSecs",
    "healthTimeoutSecs",
    "healthFails",
    "healthPasses",
    "accessAllow",
    "accessDeny",
    "basicAuth",
    "webAuth",
    "users",
    "sharedUsers",
    "loginStyle",
    "forwardAuth",
    "trustAuthUsers",
    "remark",
];
const WEBSERVICE_REWRITE_KNOWN: &[&str] = &["pattern", "to", "redirect", "code"];
const WEBSERVICE_CORS_KNOWN: &[&str] = &[
    "allowOrigins",
    "allowMethods",
    "allowHeaders",
    "allowCredentials",
    "maxAgeSecs",
];
const WEBSERVICE_IDENTITY_KNOWN: &[&str] = &["header", "field"];
const WEBSERVICE_USER_ROUTE_KNOWN: &[&str] = &["users", "targets"];
const WEBSERVICE_FORWARD_AUTH_KNOWN: &[&str] =
    &["url", "loginUrl", "loginFromLocation", "copyHeaders"];

/// Upstream Gately webservice fields that exist in upstream snapshots but are
/// not yet implemented in FerrumGate; preserved verbatim for round-trip safety.
const WEBSERVICE_UNIMPLEMENTED_UPSTREAM: &[&str] = &[
    "locations",
    "waf",
    "wafEnabled",
    "wafProfile",
    "wafPolicy",
    "rateLimit",
    "ipLists",
    "rules",
    "compress",
    "gzip",
    "brotli",
    "http3",
    "quic",
    "accessLog",
    "customErrorPages",
    "maxBodySize",
    "websocket",
    "hsts",
    "bufferSize",
    "crowdsec",
    "geoAllow",
    "geoDeny",
    "tlsCert",
    "certKey",
];

/// Migrator for `webservice.json`.
pub struct WebserviceMigrator;

impl MigrateModule for WebserviceMigrator {
    fn id(&self) -> &'static str {
        "webservice"
    }

    fn transform_detailed(
        &self,
        input: &Value,
        _ctx: &MigrateCtx,
    ) -> Result<TransformOutput, Vec<Warning>> {
        let Some(root) = input.as_object() else {
            return Err(vec![Warning::new(
                "$",
                "InvalidType",
                "import.gately.expected_json_object",
                "webservice.json root must be a JSON object",
            )]);
        };

        let mut warnings = Vec::new();
        let mut newer_version_detected = false;

        inspect_unknown_keys(
            root,
            "",
            WEBSERVICE_ROOT_KNOWN,
            WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
            &mut warnings,
            &mut newer_version_detected,
        );

        if let Some(Value::Object(settings)) = root.get("settings") {
            inspect_unknown_keys(
                settings,
                "settings",
                WEBSERVICE_SETTINGS_KNOWN,
                WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                &mut warnings,
                &mut newer_version_detected,
            );
            if let Some(Value::Array(users)) = settings.get("authUsers") {
                for (idx, user) in users.iter().enumerate() {
                    if let Some(obj) = user.as_object() {
                        inspect_unknown_keys(
                            obj,
                            &format!("settings.authUsers[{idx}]"),
                            WEBSERVICE_AUTH_USER_KNOWN,
                            WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                            &mut warnings,
                            &mut newer_version_detected,
                        );
                    }
                }
            }
        }

        if let Some(Value::Array(listeners)) = root.get("listeners") {
            for (l_idx, listener) in listeners.iter().enumerate() {
                let Some(l_obj) = listener.as_object() else {
                    continue;
                };
                let l_path = format!("listeners[{l_idx}]");
                inspect_unknown_keys(
                    l_obj,
                    &l_path,
                    WEBSERVICE_LISTENER_KNOWN,
                    WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                    &mut warnings,
                    &mut newer_version_detected,
                );
                if let Some(Value::Array(sites)) = l_obj.get("sites") {
                    for (s_idx, site) in sites.iter().enumerate() {
                        let Some(s_obj) = site.as_object() else {
                            continue;
                        };
                        let s_path = format!("{l_path}.sites[{s_idx}]");
                        inspect_unknown_keys(
                            s_obj,
                            &s_path,
                            WEBSERVICE_SITE_KNOWN,
                            WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                            &mut warnings,
                            &mut newer_version_detected,
                        );

                        // Inspect nested site structures.
                        if let Some(Value::Array(rewrites)) = s_obj.get("rewrites") {
                            for (r_idx, rw) in rewrites.iter().enumerate() {
                                if let Some(obj) = rw.as_object() {
                                    inspect_unknown_keys(
                                        obj,
                                        &format!("{s_path}.rewrites[{r_idx}]"),
                                        WEBSERVICE_REWRITE_KNOWN,
                                        WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                                        &mut warnings,
                                        &mut newer_version_detected,
                                    );
                                }
                            }
                        }
                        if let Some(Value::Object(cors)) = s_obj.get("cors") {
                            inspect_unknown_keys(
                                cors,
                                &format!("{s_path}.cors"),
                                WEBSERVICE_CORS_KNOWN,
                                WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                                &mut warnings,
                                &mut newer_version_detected,
                            );
                        }
                        if let Some(Value::Array(ids)) = s_obj.get("identityHeaders") {
                            for (i_idx, item) in ids.iter().enumerate() {
                                if let Some(obj) = item.as_object() {
                                    inspect_unknown_keys(
                                        obj,
                                        &format!("{s_path}.identityHeaders[{i_idx}]"),
                                        WEBSERVICE_IDENTITY_KNOWN,
                                        WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                                        &mut warnings,
                                        &mut newer_version_detected,
                                    );
                                }
                            }
                        }
                        if let Some(Value::Array(routes)) = s_obj.get("userRoutes") {
                            for (u_idx, item) in routes.iter().enumerate() {
                                if let Some(obj) = item.as_object() {
                                    inspect_unknown_keys(
                                        obj,
                                        &format!("{s_path}.userRoutes[{u_idx}]"),
                                        WEBSERVICE_USER_ROUTE_KNOWN,
                                        WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                                        &mut warnings,
                                        &mut newer_version_detected,
                                    );
                                }
                            }
                        }
                        if let Some(Value::Object(fa)) = s_obj.get("forwardAuth") {
                            inspect_unknown_keys(
                                fa,
                                &format!("{s_path}.forwardAuth"),
                                WEBSERVICE_FORWARD_AUTH_KNOWN,
                                WEBSERVICE_UNIMPLEMENTED_UPSTREAM,
                                &mut warnings,
                                &mut newer_version_detected,
                            );
                        }

                        // WP-38 §3.3 default value difference: proxy connect timeout
                        // (upstream default 2s vs FerrumGate default 10s).
                        let is_proxy = s_obj
                            .get("siteType")
                            .and_then(Value::as_str)
                            .is_some_and(|t| t == "proxy");
                        if is_proxy {
                            let explicit_connect = s_obj
                                .get("timeoutsConnectSecs")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            if explicit_connect == 0 {
                                warnings.push(Warning::new(
                                    format!("{s_path}.timeoutsConnectSecs"),
                                    "DefaultValueChanged",
                                    "import.gately.default_value_differs",
                                    "Field omitted or 0: default backend connect timeout differs (upstream 2s vs FerrumGate 10s); set explicitly to keep 2s.",
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Preserve all upstream fields verbatim (round-trip safe).
        Ok(TransformOutput {
            value: input.clone(),
            changed_fields: Vec::new(),
            warnings,
            newer_version_detected,
        })
    }

    fn validate(&self, value: &Value) -> Result<(), Vec<String>> {
        let known = strip_webservice_unknown(value);
        let config: fg_gateway::web::model::FileConfig = serde_json::from_value(known)
            .map_err(|err| vec![format!("webservice.json schema error: {err}")])?;

        let mut errors = Vec::new();
        if config.listeners.len() > WEBSERVICE_MAX_LISTENERS {
            errors.push(format!(
                "listeners: count {} exceeds FerrumGate limit of {} (not truncated)",
                config.listeners.len(),
                WEBSERVICE_MAX_LISTENERS
            ));
        }

        for problem in fg_gateway::web::validate::validate(&config) {
            errors.push(format!("{}: {}", problem.field, problem.reason));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn strip_webservice_unknown(value: &Value) -> Value {
    let Some(root) = value.as_object() else {
        return value.clone();
    };
    let mut clean = Map::new();
    if let Some(settings) = root.get("settings") {
        let mut s = filter_object_keys(settings, WEBSERVICE_SETTINGS_KNOWN);
        if let Some(Value::Array(users)) = s.as_object().and_then(|o| o.get("authUsers")).cloned() {
            let clean_users: Vec<Value> = users
                .iter()
                .map(|u| filter_object_keys(u, WEBSERVICE_AUTH_USER_KNOWN))
                .collect();
            if let Some(obj) = s.as_object_mut() {
                obj.insert("authUsers".to_owned(), Value::Array(clean_users));
            }
        }
        clean.insert("settings".to_owned(), s);
    }
    if let Some(Value::Array(listeners)) = root.get("listeners") {
        let clean_listeners: Vec<Value> = listeners
            .iter()
            .map(|listener| {
                let mut l = filter_object_keys(listener, WEBSERVICE_LISTENER_KNOWN);
                if let Some(Value::Array(sites)) =
                    l.as_object().and_then(|o| o.get("sites")).cloned()
                {
                    let clean_sites: Vec<Value> = sites.iter().map(strip_site_unknown).collect();
                    if let Some(obj) = l.as_object_mut() {
                        obj.insert("sites".to_owned(), Value::Array(clean_sites));
                    }
                }
                l
            })
            .collect();
        clean.insert("listeners".to_owned(), Value::Array(clean_listeners));
    }
    Value::Object(clean)
}

fn strip_site_unknown(site: &Value) -> Value {
    let mut s = filter_object_keys(site, WEBSERVICE_SITE_KNOWN);
    let Some(obj) = s.as_object_mut() else {
        return s;
    };
    if let Some(Value::Array(rewrites)) = obj.get("rewrites").cloned() {
        obj.insert(
            "rewrites".to_owned(),
            Value::Array(
                rewrites
                    .iter()
                    .map(|r| filter_object_keys(r, WEBSERVICE_REWRITE_KNOWN))
                    .collect(),
            ),
        );
    }
    if let Some(cors) = obj.get("cors").cloned() {
        obj.insert(
            "cors".to_owned(),
            filter_object_keys(&cors, WEBSERVICE_CORS_KNOWN),
        );
    }
    if let Some(Value::Array(ids)) = obj.get("identityHeaders").cloned() {
        obj.insert(
            "identityHeaders".to_owned(),
            Value::Array(
                ids.iter()
                    .map(|i| filter_object_keys(i, WEBSERVICE_IDENTITY_KNOWN))
                    .collect(),
            ),
        );
    }
    if let Some(Value::Array(routes)) = obj.get("userRoutes").cloned() {
        obj.insert(
            "userRoutes".to_owned(),
            Value::Array(
                routes
                    .iter()
                    .map(|r| filter_object_keys(r, WEBSERVICE_USER_ROUTE_KNOWN))
                    .collect(),
            ),
        );
    }
    if let Some(fa) = obj.get("forwardAuth").cloned()
        && !fa.is_null()
    {
        obj.insert(
            "forwardAuth".to_owned(),
            filter_object_keys(&fa, WEBSERVICE_FORWARD_AUTH_KNOWN),
        );
    }
    s
}

// ---------------------------------------------------------------------------
// Core module 2: ssl.json
// ---------------------------------------------------------------------------

const SSL_ROOT_KNOWN: &[&str] = &["settings", "certs", "accounts"];
const SSL_SETTINGS_KNOWN: &[&str] = &[
    "enable",
    "renewBeforeDays",
    "shortLivedRenewHours",
    "defaultEmail",
];
const SSL_CERT_KNOWN: &[&str] = &[
    "key",
    "remark",
    "group",
    "enable",
    "source",
    "acme",
    "certFile",
    "keyFile",
    "fnosDomain",
    "certPem",
    "keyPem",
    "issuerPem",
    "mapping",
    "deploys",
    "updatedAt",
    "issuedProfile",
];
const SSL_DEPLOY_KNOWN: &[&str] = &["key", "enable"];
const SSL_ACCOUNT_KNOWN: &[&str] = &["email", "directoryUrl", "keyPem", "registration"];

/// Upstream SSL fields inside `mapping` / `deploys` (WP-33 placeholders) or
/// cert entries that are not yet implemented in FerrumGate.
const SSL_UNIMPLEMENTED_UPSTREAM: &[&str] = &[
    "domains",
    "listeners",
    "type",
    "name",
    "host",
    "port",
    "username",
    "password",
    "sshKey",
    "certPath",
    "keyPath",
    "fullchainPath",
    "command",
    "reloadCmd",
    "webhookUrl",
    "dir",
    "autoDeploy",
    "ocspStapling",
];

/// Migrator for `ssl.json`.
pub struct SslMigrator;

impl MigrateModule for SslMigrator {
    fn id(&self) -> &'static str {
        "ssl"
    }

    fn transform_detailed(
        &self,
        input: &Value,
        _ctx: &MigrateCtx,
    ) -> Result<TransformOutput, Vec<Warning>> {
        let Some(root) = input.as_object() else {
            return Err(vec![Warning::new(
                "$",
                "InvalidType",
                "import.gately.expected_json_object",
                "ssl.json root must be a JSON object",
            )]);
        };

        let mut warnings = Vec::new();
        let mut newer_version_detected = false;

        inspect_unknown_keys(
            root,
            "",
            SSL_ROOT_KNOWN,
            SSL_UNIMPLEMENTED_UPSTREAM,
            &mut warnings,
            &mut newer_version_detected,
        );

        if let Some(Value::Object(settings)) = root.get("settings") {
            inspect_unknown_keys(
                settings,
                "settings",
                SSL_SETTINGS_KNOWN,
                SSL_UNIMPLEMENTED_UPSTREAM,
                &mut warnings,
                &mut newer_version_detected,
            );
            if let Some(hours) = settings.get("shortLivedRenewHours").and_then(Value::as_u64)
                && hours > 80
            {
                warnings.push(Warning::new(
                    "settings.shortLivedRenewHours",
                    "DefaultValueChanged",
                    "import.gately.default_value_differs",
                    format!(
                        "shortLivedRenewHours={hours} exceeds FerrumGate runtime cap (80h) and will be clamped to 80 at load time."
                    ),
                ));
            }
        }

        if let Some(Value::Array(certs)) = root.get("certs") {
            for (idx, cert) in certs.iter().enumerate() {
                let Some(c_obj) = cert.as_object() else {
                    continue;
                };
                let c_path = format!("certs[{idx}]");
                inspect_unknown_keys(
                    c_obj,
                    &c_path,
                    SSL_CERT_KNOWN,
                    SSL_UNIMPLEMENTED_UPSTREAM,
                    &mut warnings,
                    &mut newer_version_detected,
                );
                // `mapping` is a WP-33 placeholder (empty struct in FerrumGate).
                if let Some(Value::Object(mapping)) = c_obj.get("mapping") {
                    inspect_unknown_keys(
                        mapping,
                        &format!("{c_path}.mapping"),
                        &[],
                        SSL_UNIMPLEMENTED_UPSTREAM,
                        &mut warnings,
                        &mut newer_version_detected,
                    );
                }
                // `deploys[]` is a WP-33 placeholder (only `key` + `enable` in FerrumGate).
                if let Some(Value::Array(deploys)) = c_obj.get("deploys") {
                    for (d_idx, deploy) in deploys.iter().enumerate() {
                        if let Some(d_obj) = deploy.as_object() {
                            inspect_unknown_keys(
                                d_obj,
                                &format!("{c_path}.deploys[{d_idx}]"),
                                SSL_DEPLOY_KNOWN,
                                SSL_UNIMPLEMENTED_UPSTREAM,
                                &mut warnings,
                                &mut newer_version_detected,
                            );
                        }
                    }
                }
            }
        }

        if let Some(Value::Object(accounts)) = root.get("accounts") {
            for (acct_key, acct) in accounts {
                if let Some(a_obj) = acct.as_object() {
                    inspect_unknown_keys(
                        a_obj,
                        &format!("accounts.{acct_key}"),
                        SSL_ACCOUNT_KNOWN,
                        SSL_UNIMPLEMENTED_UPSTREAM,
                        &mut warnings,
                        &mut newer_version_detected,
                    );
                }
            }
        }

        Ok(TransformOutput {
            value: input.clone(),
            changed_fields: Vec::new(),
            warnings,
            newer_version_detected,
        })
    }

    fn validate(&self, value: &Value) -> Result<(), Vec<String>> {
        let known = strip_ssl_unknown(value);
        let mut config: fg_gateway::certs::model::FileConfig = serde_json::from_value(known)
            .map_err(|err| vec![format!("ssl.json schema error: {err}")])?;
        fg_gateway::certs::validate::normalize(&mut config)
            .map_err(|err| vec![format!("ssl.json validation error: {err}")])
    }
}

fn strip_ssl_unknown(value: &Value) -> Value {
    let Some(root) = value.as_object() else {
        return value.clone();
    };
    let mut clean = Map::new();
    if let Some(settings) = root.get("settings") {
        clean.insert(
            "settings".to_owned(),
            filter_object_keys(settings, SSL_SETTINGS_KNOWN),
        );
    }
    if let Some(Value::Array(certs)) = root.get("certs") {
        let clean_certs: Vec<Value> = certs
            .iter()
            .map(|cert| {
                let mut c = filter_object_keys(cert, SSL_CERT_KNOWN);
                if let Some(obj) = c.as_object_mut() {
                    if obj.contains_key("mapping") {
                        obj.insert("mapping".to_owned(), Value::Object(Map::new()));
                    }
                    if let Some(Value::Array(deploys)) = obj.get("deploys").cloned() {
                        obj.insert(
                            "deploys".to_owned(),
                            Value::Array(
                                deploys
                                    .iter()
                                    .map(|d| filter_object_keys(d, SSL_DEPLOY_KNOWN))
                                    .collect(),
                            ),
                        );
                    }
                }
                c
            })
            .collect();
        clean.insert("certs".to_owned(), Value::Array(clean_certs));
    }
    if let Some(Value::Object(accounts)) = root.get("accounts") {
        let mut clean_accounts = Map::new();
        for (k, v) in accounts {
            clean_accounts.insert(k.clone(), filter_object_keys(v, SSL_ACCOUNT_KNOWN));
        }
        clean.insert("accounts".to_owned(), Value::Object(clean_accounts));
    }
    Value::Object(clean)
}

// ---------------------------------------------------------------------------
// Core module 3: portforward.json
// ---------------------------------------------------------------------------

const PORTFORWARD_ROOT_KNOWN: &[&str] = &["settings", "rules"];

const PORTFORWARD_SETTINGS_RENAMES: &[(&str, &str)] = &[
    ("defaultMaxConnections", "default_max_connections"),
    ("defaultMaxConnsPerSource", "default_max_conns_per_source"),
    ("perSourceExempt", "per_source_exempt"),
    ("defaultUdpSessionTimeout", "default_udp_session_timeout"),
    ("maxUdpSessions", "max_udp_sessions"),
    ("dialTimeout", "dial_timeout"),
    ("firstDataTimeout", "first_data_timeout"),
];

const PORTFORWARD_SETTINGS_KNOWN: &[&str] = &[
    "enable",
    "default_max_connections",
    "default_max_conns_per_source",
    "per_source_exempt",
    "default_udp_session_timeout",
    "max_udp_sessions",
    "dial_timeout",
    "first_data_timeout",
];

const PORTFORWARD_RULE_RENAMES: &[(&str, &str)] = &[
    ("listenAddress", "listen_address"),
    ("listenPorts", "listen_ports"),
    ("autoFirewall", "auto_firewall"),
    ("targetAddresses", "target_addresses"),
    ("targetPorts", "target_ports"),
    ("maxConnections", "max_connections"),
    ("maxConnsPerSource", "max_conns_per_source"),
    ("udpSessionTimeout", "udp_session_timeout"),
    ("proxyProtocol", "proxy_protocol"),
];

const PORTFORWARD_RULE_KNOWN: &[&str] = &[
    "key",
    "name",
    "enable",
    "group",
    "protocols",
    "listen_address",
    "listen_ports",
    "auto_firewall",
    "target_addresses",
    "target_ports",
    "max_connections",
    "max_conns_per_source",
    "udp_session_timeout",
    "proxy_protocol",
    "allow",
    "deny",
    "remark",
];

const PORTFORWARD_UNIMPLEMENTED_UPSTREAM: &[&str] = &[
    "rateLimit",
    "bandwidthLimit",
    "schedule",
    "knock",
    "geoAllow",
    "geoDeny",
    "ipLists",
];

/// Migrator for `portforward.json`.
///
/// Upstream Gately uses camelCase JSON keys while FerrumGate's `portforward.json`
/// model (`fg_gateway::l4::portforward::model`) uses snake_case keys. This
/// migrator accepts either spelling, normalizes known keys to snake_case for
/// `fgate check` / runtime loading, preserves any unimplemented or unknown
/// upstream fields, and validates FerrumGate limits (<= 64 listen ports and
/// <= 8 target addresses per rule) without truncating.
pub struct PortforwardMigrator;

impl MigrateModule for PortforwardMigrator {
    fn id(&self) -> &'static str {
        "portforward"
    }

    fn transform_detailed(
        &self,
        input: &Value,
        _ctx: &MigrateCtx,
    ) -> Result<TransformOutput, Vec<Warning>> {
        let Some(root) = input.as_object() else {
            return Err(vec![Warning::new(
                "$",
                "InvalidType",
                "import.gately.expected_json_object",
                "portforward.json root must be a JSON object",
            )]);
        };

        let mut out = root.clone();
        let mut changed_fields = Vec::new();
        let mut warnings = Vec::new();
        let mut newer_version_detected = false;

        inspect_unknown_keys(
            root,
            "",
            PORTFORWARD_ROOT_KNOWN,
            PORTFORWARD_UNIMPLEMENTED_UPSTREAM,
            &mut warnings,
            &mut newer_version_detected,
        );

        if let Some(Value::Object(settings)) = out.get_mut("settings") {
            rename_keys(
                settings,
                "settings",
                PORTFORWARD_SETTINGS_RENAMES,
                &mut changed_fields,
            );
            inspect_unknown_keys(
                settings,
                "settings",
                PORTFORWARD_SETTINGS_KNOWN,
                PORTFORWARD_UNIMPLEMENTED_UPSTREAM,
                &mut warnings,
                &mut newer_version_detected,
            );
        }

        if let Some(Value::Array(rules)) = out.get_mut("rules") {
            for (idx, rule) in rules.iter_mut().enumerate() {
                let Some(r_obj) = rule.as_object_mut() else {
                    continue;
                };
                let r_path = format!("rules[{idx}]");
                rename_keys(
                    r_obj,
                    &r_path,
                    PORTFORWARD_RULE_RENAMES,
                    &mut changed_fields,
                );
                inspect_unknown_keys(
                    r_obj,
                    &r_path,
                    PORTFORWARD_RULE_KNOWN,
                    PORTFORWARD_UNIMPLEMENTED_UPSTREAM,
                    &mut warnings,
                    &mut newer_version_detected,
                );
            }
        }

        Ok(TransformOutput {
            value: Value::Object(out),
            changed_fields,
            warnings,
            newer_version_detected,
        })
    }

    fn validate(&self, value: &Value) -> Result<(), Vec<String>> {
        let known = strip_portforward_unknown(value);
        let config: fg_gateway::l4::portforward::model::FileConfig = serde_json::from_value(known)
            .map_err(|err| vec![format!("portforward.json schema error: {err}")])?;
        let problems = fg_gateway::l4::portforward::validate::validate(&config);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems
                .into_iter()
                .map(|p| format!("{}: {}", p.field, p.reason))
                .collect())
        }
    }
}

fn rename_keys(
    obj: &mut Map<String, Value>,
    prefix: &str,
    renames: &[(&str, &str)],
    changed_fields: &mut Vec<FieldChange>,
) {
    for &(from_key, to_key) in renames {
        if let Some(val) = obj.remove(from_key) {
            if !obj.contains_key(to_key) {
                let from_path = if prefix.is_empty() {
                    from_key.to_owned()
                } else {
                    format!("{prefix}.{from_key}")
                };
                let to_path = if prefix.is_empty() {
                    to_key.to_owned()
                } else {
                    format!("{prefix}.{to_key}")
                };
                changed_fields.push(FieldChange {
                    path: format!("{from_path} -> {to_path}"),
                    from: summarize_value(&from_path, &val),
                    to: summarize_value(&to_path, &val),
                });
                obj.insert(to_key.to_owned(), val);
            }
        }
    }
}

fn strip_portforward_unknown(value: &Value) -> Value {
    let Some(root) = value.as_object() else {
        return value.clone();
    };
    let mut clean = Map::new();
    if let Some(settings) = root.get("settings") {
        clean.insert(
            "settings".to_owned(),
            filter_object_keys(settings, PORTFORWARD_SETTINGS_KNOWN),
        );
    }
    if let Some(Value::Array(rules)) = root.get("rules") {
        clean.insert(
            "rules".to_owned(),
            Value::Array(
                rules
                    .iter()
                    .map(|r| filter_object_keys(r, PORTFORWARD_RULE_KNOWN))
                    .collect(),
            ),
        );
    }
    Value::Object(clean)
}

// ---------------------------------------------------------------------------
// Generic built optional module pass-through validator
// ---------------------------------------------------------------------------

/// Pass-through migrator for built optional modules that share upstream's JSON
/// schema verbatim and do not yet require bespoke field migration.
pub struct PassthroughMigrator {
    module_id: &'static str,
}

impl PassthroughMigrator {
    pub const fn new(module_id: &'static str) -> Self {
        Self { module_id }
    }
}

impl MigrateModule for PassthroughMigrator {
    fn id(&self) -> &'static str {
        self.module_id
    }

    fn transform_detailed(
        &self,
        input: &Value,
        _ctx: &MigrateCtx,
    ) -> Result<TransformOutput, Vec<Warning>> {
        if !input.is_object() {
            return Err(vec![Warning::new(
                "$",
                "InvalidType",
                "import.gately.expected_json_object",
                format!("{}.json root must be a JSON object", self.module_id),
            )]);
        }
        Ok(TransformOutput {
            value: input.clone(),
            changed_fields: Vec::new(),
            warnings: Vec::new(),
            newer_version_detected: false,
        })
    }

    fn validate(&self, value: &Value) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if !is_valid_config_name(self.module_id) {
            errors.push(format!("invalid configuration name: {}", self.module_id));
        }
        if !value.is_object() {
            errors.push(format!(
                "{}.json root must be a JSON object",
                self.module_id
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Resolves the [`MigrateModule`] implementation for a built catalog module ID.
pub fn migrator_for_module(id: &str) -> Option<Box<dyn MigrateModule>> {
    match id {
        "webservice" => Some(Box::new(WebserviceMigrator)),
        "ssl" => Some(Box::new(SslMigrator)),
        "portforward" => Some(Box::new(PortforwardMigrator)),
        other => fg_core::features::CATALOG_IDS
            .iter()
            .copied()
            .find(|&candidate| candidate == other)
            .map(|static_id| {
                Box::new(PassthroughMigrator::new(static_id)) as Box<dyn MigrateModule>
            }),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn inspect_unknown_keys(
    obj: &Map<String, Value>,
    prefix: &str,
    known: &[&str],
    unimplemented_upstream: &[&str],
    warnings: &mut Vec<Warning>,
    newer_version_detected: &mut bool,
) {
    let mut keys: BTreeSet<&str> = BTreeSet::new();
    for key in obj.keys() {
        keys.insert(key.as_str());
    }
    for key in keys {
        if known.contains(&key) {
            continue;
        }
        let path = if prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{prefix}.{key}")
        };
        if unimplemented_upstream.contains(&key) {
            warnings.push(Warning::new(
                path.clone(),
                "UnsupportedField",
                "import.gately.unimplemented_field_preserved",
                format!(
                    "Upstream field '{path}' is not yet implemented in FerrumGate; preserved in JSON and will take effect once implemented."
                ),
            ));
        } else {
            *newer_version_detected = true;
            warnings.push(Warning::new(
                path.clone(),
                "UnknownField",
                "import.gately.newer_version_field_preserved",
                format!(
                    "Unrecognized field '{path}' (possible newer source version beyond baseline {UPSTREAM_BASELINE}); preserved in JSON."
                ),
            ));
        }
    }
}

fn filter_object_keys(value: &Value, allowed: &[&str]) -> Value {
    let Some(obj) = value.as_object() else {
        return value.clone();
    };
    let mut out = Map::new();
    for (key, val) in obj {
        if allowed.contains(&key.as_str()) {
            out.insert(key.clone(), val.clone());
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn settings_field_mapping() {
        let input: Value = serde_json::from_str(
            r#"{
                "listen": ":16680",
                "httpsListen": ":16443",
                "forceHTTPS": true,
                "safePath": "/admin-gate",
                "lanOnly": true,
                "denyMode": "custom",
                "denyStatus": 403,
                "denyPage": "<h1>Denied</h1>",
                "gatewaySSO": true,
                "disableProxyHeaders": false,
                "trustedProxies": ["10.0.0.0/8", "127.0.0.1"],
                "maxLoginFailures": 5,
                "lockMinutes": 15,
                "loginGlobalLimit": 20,
                "confirmTimeout": 90,
                "apiToken": "legacy-secret-token-value",
                "language": "zh-CN",
                "uiLanguage": "en",
                "timeZone": "Asia/Shanghai",
                "dnsServers": ["1.1.1.1", "8.8.8.8:53"],
                "updateProxy": "http://127.0.0.1:7890",
                "restrictOutbound": true,
                "disableUpdateCheck": true,
                "logLevel": "info",
                "logLines": 2000,
                "disableLogPersist": false,
                "logFileMB": 4,
                "accessLogDays": 7,
                "accessLogMB": 64,
                "logDir": "/var/log/ferrumgate",
                "gcPercent": 50,
                "maxProcs": 4,
                "thirdLogin": {
                    "enable": true,
                    "callbackBase": "https://panel.example.com",
                    "providers": [{
                        "key": "gh",
                        "name": "GitHub",
                        "type": "github",
                        "clientId": "cid-1",
                        "clientSecret": "super-secret-oauth",
                        "issuer": "",
                        "proxy": ""
                    }],
                    "allowed": ["gh:alice"],
                    "skipTotp": false
                },
                "disabledModules": ["portforward", "ddns", "docker"]
            }"#,
        )
        .expect("parse fixture json");

        let migrator = SettingsMigrator;
        let out = migrator
            .transform_detailed(&input, &MigrateCtx::default())
            .expect("transform");
        migrator.validate(&out.value).expect("validate");

        let obj = out.value.as_object().expect("object");
        assert!(!obj.contains_key("gcPercent"));
        assert!(!obj.contains_key("maxProcs"));
        assert_eq!(obj["listen"], json!(":16680"));
        assert_eq!(obj["httpsListen"], json!(":16443"));
        assert_eq!(obj["forceHTTPS"], json!(true));
        assert_eq!(obj["safePath"], json!("/admin-gate"));
        assert_eq!(obj["lanOnly"], json!(true));
        assert_eq!(obj["denyMode"], json!("custom"));
        assert_eq!(obj["denyStatus"], json!(403));
        assert_eq!(obj["denyPage"], json!("<h1>Denied</h1>"));
        assert_eq!(obj["gatewaySSO"], json!(true));
        assert_eq!(obj["disableProxyHeaders"], json!(false));
        assert_eq!(obj["trustedProxies"], json!(["10.0.0.0/8", "127.0.0.1"]));
        assert_eq!(obj["maxLoginFailures"], json!(5));
        assert_eq!(obj["lockMinutes"], json!(15));
        assert_eq!(obj["loginGlobalLimit"], json!(20));
        assert_eq!(obj["confirmTimeout"], json!(90));
        assert_eq!(obj["apiToken"], json!("legacy-secret-token-value"));
        assert_eq!(obj["language"], json!("zh-CN"));
        assert_eq!(obj["uiLanguage"], json!("en"));
        assert_eq!(obj["timeZone"], json!("Asia/Shanghai"));
        assert_eq!(obj["dnsServers"], json!(["1.1.1.1", "8.8.8.8:53"]));
        assert_eq!(obj["updateProxy"], json!("http://127.0.0.1:7890"));
        assert_eq!(obj["restrictOutbound"], json!(true));
        assert_eq!(obj["disableUpdateCheck"], json!(true));
        assert_eq!(obj["logLevel"], json!("info"));
        assert_eq!(obj["logLines"], json!(2000));
        assert_eq!(obj["disableLogPersist"], json!(false));
        assert_eq!(obj["logFileMB"], json!(4));
        assert_eq!(obj["accessLogDays"], json!(7));
        assert_eq!(obj["accessLogMB"], json!(64));
        assert_eq!(obj["logDir"], json!("/var/log/ferrumgate"));
        assert_eq!(obj["thirdLogin"], input["thirdLogin"]);
        assert_eq!(
            obj["disabledModules"],
            json!(["portforward", "ddns", "docker"])
        );

        for dropped in ["gcPercent", "maxProcs"] {
            assert!(
                out.warnings
                    .iter()
                    .any(|w| w.path == dropped && w.reason_key == "UnsupportedField"),
                "missing UnsupportedField warning for {dropped}"
            );
        }
    }

    #[test]
    fn settings_env_var_hint_in_report() {
        let out = SettingsMigrator
            .transform_detailed(&json!({ "listen": ":16680" }), &MigrateCtx::default())
            .expect("transform");
        let hint = out
            .warnings
            .iter()
            .find(|w| w.reason_key == "EnvVarRename")
            .expect("env var rename warning");
        assert!(hint.message.contains("GATELY_*"));
        assert!(hint.message.contains("FERRUMGATE_*"));
    }

    #[test]
    fn disabled_modules_switches_kept_for_unbuilt() {
        let input = json!({
            "listen": ":16680",
            "disabledModules": ["portforward", "waf", "docker", "backup"]
        });
        let ctx = MigrateCtx {
            built_modules: vec!["portforward", "ssl", "webservice"],
        };
        let out = SettingsMigrator
            .transform_detailed(&input, &ctx)
            .expect("transform");
        SettingsMigrator.validate(&out.value).expect("valid");
        assert_eq!(
            out.value["disabledModules"],
            json!(["portforward", "waf", "docker", "backup"])
        );
    }
}
