//! The built-in jail presets (WP-52 §3.3, upstream `presets.go`): ready
//! to use templates the admin API lists under `GET /api/guard/presets`
//! and the interface clones into a jail (the `preset` field records the
//! id for display). Filter texts are RE2 regexes with `<HOST>`; path
//! presets use the glob form, TLS presets list failure-kind tags.

use std::sync::LazyLock;

use serde::Serialize;

use crate::jail::{Jail, JailSource};

/// One built-in template.
#[derive(Clone, Debug, Serialize)]
pub struct Preset {
    pub id: &'static str,
    #[serde(flatten)]
    pub jail: Jail,
}

impl Preset {
    fn jail(
        id: &'static str,
        name: &'static str,
        source: JailSource,
        build: impl FnOnce(Jail) -> Jail,
    ) -> Self {
        Self {
            id,
            jail: build(Jail {
                key: String::new(),
                name: name.to_owned(),
                enable: true,
                source,
                preset: id.to_owned(),
                ..Jail::default()
            }),
        }
    }
}

/// The built-in presets. The WP-52 doc's preset table is authoritative
/// for ids, names, sources and thresholds; the filter texts follow the
/// fail2ban-style conventions the upstream filters use.
pub static PRESETS: LazyLock<Vec<Preset>> = LazyLock::new(|| {
    vec![
        Preset::jail("sshd", "SSH", JailSource::File, |jail| Jail {
            target: "/var/log/auth.log".to_owned(),
            filter: SSHD_FILTER.to_owned(),
            ..jail
        }),
        Preset::jail(
            "sshd-journal",
            "SSH (journald)",
            JailSource::Journal,
            |jail| Jail {
                target: "ssh.service\nsshd.service".to_owned(),
                filter: SSHD_FILTER.to_owned(),
                ..jail
            },
        ),
        Preset::jail("dropbear", "Dropbear", JailSource::Command, |jail| Jail {
            target: "logread -f".to_owned(),
            filter: DROPBEAR_FILTER.to_owned(),
            ..jail
        }),
        Preset::jail(
            "nginx-http-auth",
            "Nginx Basic Auth",
            JailSource::File,
            |jail| Jail {
                target: "/var/log/nginx/error.log".to_owned(),
                filter: NGINX_AUTH_FILTER.to_owned(),
                ..jail
            },
        ),
        Preset::jail(
            "nginx-botsearch",
            "Nginx Bot Search",
            JailSource::File,
            |jail| Jail {
                target: "/var/log/nginx/access.log".to_owned(),
                filter: NGINX_BOTSEARCH_FILTER.to_owned(),
                ..jail
            },
        ),
        Preset::jail("vaultwarden", "Vaultwarden", JailSource::Docker, |jail| {
            Jail {
                target: "vaultwarden".to_owned(),
                filter: VAULTWARDEN_FILTER.to_owned(),
                ..jail
            }
        }),
        Preset::jail(
            "homeassistant",
            "Home Assistant",
            JailSource::Docker,
            |jail| Jail {
                target: "homeassistant".to_owned(),
                filter: HOMEASSISTANT_FILTER.to_owned(),
                ..jail
            },
        ),
        Preset::jail("proxmox", "Proxmox VE", JailSource::Journal, |jail| Jail {
            target: "pvedaemon.service".to_owned(),
            filter: PROXMOX_FILTER.to_owned(),
            ..jail
        }),
        Preset::jail(
            "gately-admin",
            "管理后台登录失败",
            JailSource::Event,
            |jail| Jail {
                target: "auth.failed".to_owned(),
                ..jail
            },
        ),
        Preset::jail("gately-waf", "WAF 拦截", JailSource::Event, |jail| Jail {
            target: "waf.blocked".to_owned(),
            ..jail
        }),
        Preset::jail(
            "gately-knock",
            "端口敲门失败",
            JailSource::Event,
            |jail| Jail {
                target: "knock.failed".to_owned(),
                ..jail
            },
        ),
        // 默认 10 分钟 10 次。
        Preset::jail(
            "gately-files",
            "文件服务登录失败",
            JailSource::Event,
            |jail| Jail {
                target: "fileauth.failed".to_owned(),
                max_retry: 10,
                find_time: 600,
                ..jail
            },
        ),
        // 诱饵路径：任意状态码 1 次，封禁 1 天。
        Preset::jail("web-decoy", "Web 诱饵路径", JailSource::Web, |jail| {
            Jail {
                filter: WEB_DECOY_PATHS.to_owned(),
                any_status: true,
                max_retry: 1,
                find_time: 600,
                ban_time: 24 * 3600,
                ..jail
            }
        }),
        // 未知域名扫描：1 分钟 5 次，封禁 1 天。
        Preset::jail(
            "web-unknown-host",
            "未知域名扫描",
            JailSource::Web,
            |jail| Jail {
                unknown_host: true,
                max_retry: 5,
                find_time: 60,
                ban_time: 24 * 3600,
                ..jail
            },
        ),
        // Web 404 探测：全部路径，1 分钟 10 次，排除浏览器常请求的路径。
        Preset::jail("web-404", "Web 404 探测", JailSource::Web, |jail| Jail {
            filter: WEB_404_IGNORES.to_owned(),
            ignore: WEB_404_EXCLUDES.to_owned(),
            max_retry: 10,
            find_time: 60,
            ..jail
        }),
        // TLS 异常握手：非 TLS 或协议错误、无法协商参数，1 分钟 5 次，封禁 1 天。
        Preset::jail("tls-probe", "TLS 异常握手", JailSource::Tls, |jail| {
            Jail {
                filter: "not_tls\nno_shared_params".to_owned(),
                max_retry: 5,
                find_time: 60,
                ban_time: 24 * 3600,
                ..jail
            }
        }),
        // TLS 握手中断：EOF、重置、超时，1 分钟 20 次，默认封禁时长。
        Preset::jail("tls-abort", "TLS 握手中断", JailSource::Tls, |jail| {
            Jail {
                filter: "eof\nreset\ntimeout".to_owned(),
                max_retry: 20,
                find_time: 60,
                ..jail
            }
        }),
    ]
});

const SSHD_FILTER: &str = "Failed password for .* from <HOST>\n\
     Invalid user .* from <HOST>\n\
     authentication failure; rhost=<HOST>";
const DROPBEAR_FILTER: &str = "Bad password attempt for '.*' from <HOST>\n\
     Login attempt for nonexistent user .* from <HOST>";
const NGINX_AUTH_FILTER: &str = "user \".*\" was not found in \".*\", client: <HOST>\n\
     password mismatch, client: <HOST>\n\
     no user/password was provided for basic authentication, client: <HOST>";
const NGINX_BOTSEARCH_FILTER: &str =
    "<HOST> .* \"(?:GET|POST|HEAD) .*\" (?:400|401|403|404|443|444) ";
const VAULTWARDEN_FILTER: &str = "Username or password is incorrect\\. Try again\\. IP: <HOST>\n\
     Invalid password for .* IP: <HOST>";
const HOMEASSISTANT_FILTER: &str =
    "Login attempt or request with invalid authentication from .* \\(<HOST>\\)";
const PROXMOX_FILTER: &str = "authentication failure; rhost=<HOST>\n\
     Auth failure for user .* from <HOST>";
const WEB_DECOY_PATHS: &str = "*/.env\n\
     */.env.*\n\
     */.git\n\
     */.git/*\n\
     */wp-login.php\n\
     */phpinfo.php\n\
     */phpmyadmin\n\
     */phpmyadmin/*\n\
     */xmlrpc.php\n\
     */.aws/*";
const WEB_404_IGNORES: &str = "";
const WEB_404_EXCLUDES: &str = "*/favicon.ico\n\
     */robots.txt\n\
     */sitemap.xml\n\
     */ads.txt\n\
     */apple-touch-icon*\n\
     *.map\n\
     *.js.map";

/// Looks up a preset by id.
pub fn find(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|preset| preset.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jail::validate::{jail_problems, normalize_jail};

    #[tokio::test]
    async fn presets_compile_and_validate() {
        // Every preset passes normalization, validation and a full
        // compile check, so cloning one into a jail can never fail.
        assert!(
            PRESETS.len() >= 17,
            "the documented preset table lists 17 templates, found {}",
            PRESETS.len()
        );
        for preset in PRESETS.iter() {
            let mut jail = normalize_jail(preset.jail.clone());
            // Presets are templates: the collection generates the key on
            // create, so validation runs with a filled-in one.
            jail.key = format!(
                "preset{:06}",
                PRESETS
                    .iter()
                    .position(|p| p.id == preset.id)
                    .expect("index")
            );
            let problems = jail_problems(&jail);
            assert!(
                problems.is_empty(),
                "preset {} has problems: {problems:?}",
                preset.id
            );
            let compiled = crate::model::FileConfig {
                settings: crate::model::Settings::default(),
                jails: vec![jail],
            };
            let service = crate::bans::GuardService::open_memory(
                &crate::model::Settings::default(),
                fg_core::events::EventBus::default(),
            );
            let engine = crate::jail::JailEngine::new(service, fg_net::banlist::system_clock());
            engine.reload(&compiled).expect("preset compiles");
        }
    }

    #[test]
    fn presets_carry_ids_names_and_thresholds() {
        let sshd = find("sshd").expect("sshd preset");
        assert_eq!(sshd.jail.name, "SSH");
        assert_eq!(sshd.jail.source, JailSource::File);
        assert_eq!(sshd.jail.target, "/var/log/auth.log");

        let files = find("gately-files").expect("files preset");
        assert_eq!(files.jail.target, "fileauth.failed");
        assert_eq!(files.jail.max_retry, 10);
        assert_eq!(files.jail.find_time, 600);

        let decoy = find("web-decoy").expect("decoy preset");
        assert!(decoy.jail.any_status && decoy.jail.max_retry == 1);
        assert_eq!(decoy.jail.ban_time, 24 * 3600);

        let unknown = find("web-unknown-host").expect("unknown host preset");
        assert!(unknown.jail.unknown_host);
        assert_eq!(unknown.jail.max_retry, 5);
        assert_eq!(unknown.jail.find_time, 60);

        let abort = find("tls-abort").expect("tls abort preset");
        assert_eq!(abort.jail.filter, "eof\nreset\ntimeout");
        assert_eq!(abort.jail.ban_time, 0, "the default ban duration");

        // Presets serialize with the id plus the jail fields (flattened).
        let json = serde_json::to_value(&*PRESETS).expect("serialize");
        let first = &json[0];
        assert_eq!(first["id"], "sshd");
        assert_eq!(first["source"], "file");
        assert_eq!(first["maxRetry"], 0, "defaults apply after normalization");
    }

    #[test]
    fn presets_are_unique_and_event_targets_valid() {
        let mut ids: Vec<&str> = PRESETS.iter().map(|preset| preset.id).collect();
        ids.sort_unstable();
        let unique = ids.windows(2).all(|pair| pair[0] != pair[1]);
        assert!(unique, "preset ids are unique: {ids:?}");
        for preset in PRESETS.iter() {
            if preset.jail.source == JailSource::Event {
                assert!(
                    crate::jail::model::EVENT_TARGETS.contains(&preset.jail.target.as_str()),
                    "{} targets an unknown event kind",
                    preset.id
                );
            }
        }
    }
}
