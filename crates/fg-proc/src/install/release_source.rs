//! 发布元数据解析（WP-43 §3.3）：GitHub Releases（跳过预发布、支持指定
//! 版本降级、按平台匹配资产、按程序规格确定校验值来源）与 Tailscale 静
//! 态包清单（仅 Linux）。解析是纯函数，测试用夹具 JSON；上游真的会改
//! 字段，各托管模块接入时按发布页复核。

use std::collections::BTreeMap;

use serde::Deserialize;
use url::Url;

use super::{
    InstallError, InstallTarget, Platform,
    spec::{ChecksumSource, ProgramSpec, ReleaseSource, archive_kind, match_asset},
    swap,
    verify::parse_digest,
};

/// Tailscale 静态包清单地址（仅 Linux；WP-45 接入时复核清单格式）。
pub const TAILSCALE_MANIFEST_URL: &str =
    "https://pkgs.tailscale.com/stable/tailscale-versions.json";
/// Tailscale 静态包的下载基地址。
pub const TAILSCALE_PKGS_BASE: &str = "https://pkgs.tailscale.com/stable/";
/// GitHub 发布列表一次取多少条（足够覆盖「最新正式版」与常见降级）。
pub const GITHUB_RELEASES_LIMIT: usize = 30;

/// 选中的一次发布：版本、资产与校验值。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selected {
    pub version: String,
    pub asset_name: String,
    pub asset_url: Url,
    /// 已知校验值（摘要或清单给出）。
    pub sha256: Option<[u8; 32]>,
    /// 校验和文件的地址（下载后按资产名查条目）。
    pub checksum_url: Option<Url>,
    pub kind: super::ArchiveKind,
}

#[derive(Deserialize)]
struct GithubRelease {
    #[serde(rename = "tag_name")]
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    #[serde(rename = "browser_download_url")]
    url: String,
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Deserialize)]
struct TailscaleRelease {
    version: String,
    #[serde(default)]
    files: BTreeMap<String, TailscaleFile>,
}

#[derive(Deserialize)]
struct TailscaleFile {
    path: String,
    #[serde(default)]
    sha256: Option<String>,
}

/// GitHub 仓库的发布列表地址。
pub fn github_releases_url(repo: &str) -> Url {
    // repo 来自静态 ProgramSpec，不会含非法字符。
    Url::parse(&format!(
        "https://api.github.com/repos/{repo}/releases?per_page={GITHUB_RELEASES_LIMIT}"
    ))
    .expect("static repo name yields a valid URL")
}

/// 解析 GitHub 发布列表并选中一次发布。`Latest` 跳过草稿与预发布；
/// 指定版本按「忽略 v 前缀与大小写」的口径匹配（可用于降级）。资产按
/// 规格的命名规则匹配当前平台；上游没有该平台的程序时返回
/// [`InstallError::Unsupported`]。
pub fn select_github(
    body: &str,
    spec: &ProgramSpec,
    target: &InstallTarget,
    platform: &Platform,
) -> Result<Selected, InstallError> {
    let Some(pattern) = spec.asset_pattern() else {
        return Err(InstallError::Resolve("程序规格不是 GitHub 发布源".into()));
    };
    let releases: Vec<GithubRelease> = serde_json::from_str(body)
        .map_err(|error| InstallError::Resolve(format!("解析 GitHub 发布列表失败：{error}")))?;
    let picked = releases
        .iter()
        .find(|release| {
            if release.draft {
                return false;
            }
            match target {
                InstallTarget::Latest => !release.prerelease,
                InstallTarget::Version(want) => swap::version_eq(&release.tag_name, want),
            }
        })
        .ok_or_else(|| match target {
            InstallTarget::Latest => InstallError::Resolve("仓库没有正式发布版本".into()),
            InstallTarget::Version(version) => {
                InstallError::Resolve(format!("没有找到版本 {version} 的发布"))
            }
        })?;
    let version = swap::normalize_version(&picked.tag_name);
    let checksum = match &spec.source {
        ReleaseSource::Github { checksum, .. } => checksum,
        _ => &ChecksumSource::None,
    };
    for asset in &picked.assets {
        if !match_asset(pattern, &asset.name, platform, &version) {
            continue;
        }
        let asset_url = Url::parse(&asset.url)
            .map_err(|_| InstallError::Resolve(format!("资产地址无效：{}", asset.url)))?;
        let (sha256, checksum_url) = match checksum {
            ChecksumSource::AssetDigest => (asset.digest.as_deref().and_then(parse_digest), None),
            ChecksumSource::File(name) => {
                let checksum_url = picked
                    .assets
                    .iter()
                    .find(|candidate| candidate.name == *name)
                    .and_then(|candidate| Url::parse(&candidate.url).ok());
                (None, checksum_url)
            }
            ChecksumSource::None => (None, None),
        };
        return Ok(Selected {
            version: version.clone(),
            asset_name: asset.name.clone(),
            asset_url,
            sha256,
            checksum_url,
            kind: archive_kind(&asset.name),
        });
    }
    Err(InstallError::Unsupported(platform.clone()))
}

/// 解析 Tailscale 静态包清单并选中一次发布（仅 Linux）。
pub fn select_tailscale(
    body: &str,
    target: &InstallTarget,
    platform: &Platform,
) -> Result<Selected, InstallError> {
    if platform.os() != "linux" {
        return Err(InstallError::Unsupported(platform.clone()));
    }
    let releases: Vec<TailscaleRelease> = match serde_json::from_str(body) {
        Ok(releases) => releases,
        Err(_) => {
            // 容忍包了一层的清单：{"releases": [...]}
            #[derive(Deserialize)]
            struct Wrapped {
                #[serde(default)]
                releases: Vec<TailscaleRelease>,
            }
            serde_json::from_str::<Wrapped>(body)
                .map_err(|error| {
                    InstallError::Resolve(format!("解析 Tailscale 包清单失败：{error}"))
                })?
                .releases
        }
    };
    let picked = releases
        .iter()
        .find(|release| match target {
            InstallTarget::Latest => true,
            InstallTarget::Version(want) => swap::version_eq(&release.version, want),
        })
        .ok_or_else(|| match target {
            InstallTarget::Latest => InstallError::Resolve("包清单没有版本".into()),
            InstallTarget::Version(version) => {
                InstallError::Resolve(format!("没有找到版本 {version} 的静态包"))
            }
        })?;
    let file = picked
        .files
        .get(platform.as_str())
        .ok_or_else(|| InstallError::Unsupported(platform.clone()))?;
    let asset_name = file
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&file.path)
        .to_owned();
    let asset_url = Url::parse(&format!("{TAILSCALE_PKGS_BASE}{}", file.path))
        .map_err(|_| InstallError::Resolve(format!("静态包地址无效：{}", file.path)))?;
    Ok(Selected {
        version: swap::normalize_version(&picked.version),
        kind: archive_kind(&asset_name),
        asset_name,
        asset_url,
        sha256: file.sha256.as_deref().and_then(parse_digest),
        checksum_url: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::spec::{CLOUDFLARED, FRPC};

    struct Rel<'a> {
        tag: &'a str,
        prerelease: bool,
        draft: bool,
        assets: Vec<Asset<'a>>,
    }

    struct Asset<'a> {
        name: &'a str,
        url: &'a str,
        digest: Option<&'a str>,
    }

    fn asset(name: &'static str, url: &'static str) -> Asset<'static> {
        Asset {
            name,
            url,
            digest: None,
        }
    }

    fn releases_json(entries: &[Rel]) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|rel| {
                let assets: Vec<String> = rel
                    .assets
                    .iter()
                    .map(|asset| {
                        let digest = asset
                            .digest
                            .map(|d| format!(r#", "digest": "sha256:{d}""#))
                            .unwrap_or_default();
                        format!(
                            r#"{{ "name": "{}", "browser_download_url": "{}"{digest} }}"#,
                            asset.name, asset.url
                        )
                    })
                    .collect::<Vec<_>>();
                format!(
                    r#"{{ "tag_name": "{}", "prerelease": {}, "draft": {}, "assets": [{}] }}"#,
                    rel.tag,
                    rel.prerelease,
                    rel.draft,
                    assets.join(", ")
                )
            })
            .collect();
        format!("[{}]", items.join(", "))
    }

    fn digest_hex(first: u8) -> String {
        let mut hex = String::new();
        for i in 0..32 {
            let byte = first.wrapping_add(i as u8);
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }

    #[test]
    fn release_skips_prerelease() {
        let digest = digest_hex(0x10);
        // cloudflared 的校验值来自资产摘要（AssetDigest）；资产名不含
        // 版本（上游就是这样）。
        let body = releases_json(&[
            Rel {
                tag: "v2.0.0-rc1",
                prerelease: true,
                draft: false,
                assets: vec![asset("cloudflared-linux-amd64", "https://x/2rc")],
            },
            Rel {
                tag: "v1.9.0",
                prerelease: false,
                draft: false,
                assets: vec![Asset {
                    name: "cloudflared-linux-amd64",
                    url: "https://x/19",
                    digest: Some(&digest),
                }],
            },
            Rel {
                tag: "v1.8.0",
                prerelease: false,
                draft: true,
                assets: vec![asset("cloudflared-linux-amd64", "https://x/18")],
            },
        ]);
        let platform = Platform::from_parts("linux", "x86_64");
        let selected = select_github(&body, &CLOUDFLARED, &InstallTarget::Latest, &platform)
            .expect("latest stable picked");
        assert_eq!(selected.version, "1.9.0", "预发布与草稿被跳过");
        assert_eq!(selected.kind, super::super::ArchiveKind::Raw);
        assert_eq!(selected.sha256, parse_digest(&format!("sha256:{digest}")));
        // frp 的校验值来自校验和文件（ChecksumSource::File）：找到该资产
        // 的地址，摘要留到下载后再查。
        let body = releases_json(&[Rel {
            tag: "v1.9.0",
            prerelease: false,
            draft: false,
            assets: vec![
                asset("frp_1.9.0_linux_amd64.tar.gz", "https://x/19"),
                asset("frp_sha256_checksums.txt", "https://x/checksums"),
            ],
        }]);
        let selected = select_github(&body, &FRPC, &InstallTarget::Latest, &platform)
            .expect("selected with checksum file");
        assert_eq!(selected.kind, super::super::ArchiveKind::TarGz);
        assert_eq!(selected.sha256, None);
        assert_eq!(
            selected.checksum_url.as_ref().map(Url::as_str),
            Some("https://x/checksums")
        );
    }

    #[test]
    fn release_specific_version_for_downgrade() {
        let body = releases_json(&[
            Rel {
                tag: "v1.9.0",
                prerelease: false,
                draft: false,
                assets: vec![asset("frp_1.9.0_linux_amd64.tar.gz", "https://x/19")],
            },
            Rel {
                tag: "v1.8.0",
                prerelease: false,
                draft: false,
                assets: vec![asset("frp_1.8.0_linux_amd64.tar.gz", "https://x/18")],
            },
        ]);
        let platform = Platform::from_parts("linux", "x86_64");
        let selected = select_github(
            &body,
            &FRPC,
            &InstallTarget::Version("V1.8.0".into()),
            &platform,
        )
        .expect("specific version picked");
        assert_eq!(selected.version, "1.8.0", "指定版本用于降级");
        assert!(selected.asset_url.as_str().ends_with("/18"));

        let error = select_github(
            &body,
            &FRPC,
            &InstallTarget::Version("1.0.0".into()),
            &platform,
        )
        .expect_err("missing version fails");
        assert!(matches!(error, InstallError::Resolve(_)));
    }

    #[test]
    fn release_unsupported_platform_error() {
        let body = releases_json(&[Rel {
            tag: "v1.9.0",
            prerelease: false,
            draft: false,
            assets: vec![asset("frp_1.9.0_linux_amd64.tar.gz", "https://x/19")],
        }]);
        let platform = Platform::from_parts("linux", "mips64");
        let error = select_github(&body, &FRPC, &InstallTarget::Latest, &platform)
            .expect_err("unsupported platform fails");
        assert_eq!(error, InstallError::Unsupported(platform.clone()));

        // Tailscale 静态包只有 Linux。
        let manifest = r#"[{ "version": "1.80.0", "files": { "linux/arm64": { "path": "stable/tailscale_1.80.0_linux_arm64.tgz", "sha256": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" } } }]"#;
        let darwin = Platform::from_parts("darwin", "aarch64");
        let error = select_tailscale(manifest, &InstallTarget::Latest, &darwin)
            .expect_err("tailscale static packages are linux only");
        assert!(matches!(error, InstallError::Unsupported(_)));
        let linux_arm64 = Platform::from_parts("linux", "aarch64");
        let selected = select_tailscale(manifest, &InstallTarget::Latest, &linux_arm64)
            .expect("linux manifest entry picked");
        assert_eq!(selected.version, "1.80.0");
        assert_eq!(selected.asset_name, "tailscale_1.80.0_linux_arm64.tgz");
        assert!(selected.asset_url.as_str().starts_with(TAILSCALE_PKGS_BASE));
        assert!(selected.sha256.is_some());
    }
}
