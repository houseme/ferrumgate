//! 程序规格（WP-43 §3.2）：每个托管程序的发布源、要安装的文件与版本
//! 探测参数。各上游的资产命名规则会变：规则全部集中在 [`ProgramSpec`]，
//! 每个程序的匹配规则用 [`match_asset`] 做夹具测试；各托管模块接入时
//! （WP-44/45/46/66）按上游最新发布复核一次这里的命名与校验值来源。

use super::ArchiveKind;
use super::platform::Platform;

/// 要安装的程序规格。
#[derive(Debug)]
pub struct ProgramSpec {
    /// 程序名（`frpc`、`tailscaled`、`cloudflared`、`filebrowser` …）。
    pub name: &'static str,
    /// 要安装的可执行文件与随附依赖（如 Windows 的 `wintun.dll`）。
    /// 第一个是主程序（版本探测的对象）。
    pub files: &'static [&'static str],
    pub source: &'static ReleaseSource,
    /// 探测版本的参数（如 `-v`、`--version`）。
    pub version_args: &'static [&'static str],
}

/// 发布源。
#[derive(Debug)]
pub enum ReleaseSource {
    /// GitHub Releases：仓库、资产命名规则与校验值来源。
    Github {
        repo: &'static str,
        asset_pattern: &'static str,
        checksum: ChecksumSource,
    },
    /// Tailscale 的静态包（`pkgs.tailscale.com`，仅 Linux），读它的包清单。
    TailscaleStaticPkgs,
}

/// 发布元数据中 SHA-256 校验值的来源。
#[derive(Debug)]
pub enum ChecksumSource {
    /// 资产自带的摘要（GitHub 的 `digest` 字段，形如 `sha256:<hex>`）。
    AssetDigest,
    /// 发布中的校验和文件（内容形如 `<sha256>  <文件名>`）。
    File(&'static str),
    /// 上游没有提供校验值；安装时会记录一条警告并在界面提示。
    None,
}

impl ProgramSpec {
    /// 主程序文件名（`files` 的第一个）。
    pub fn main_file(&self) -> &'static str {
        self.files.first().copied().unwrap_or(self.name)
    }

    /// GitHub 发布源的资产命名模式；非 GitHub 源返回 None。
    pub fn asset_pattern(&self) -> Option<&'static str> {
        match self.source {
            ReleaseSource::Github { asset_pattern, .. } => Some(asset_pattern),
            ReleaseSource::TailscaleStaticPkgs => None,
        }
    }
}

// 静态占位符：{version} {os} {arch} {platform} {exe}（Windows 的 .exe）与
// {pkg}（unix 的 tar.gz / windows 的 zip）。各模块接入时复核。

/// frp 客户端（WP-44）。
pub static FRPC: ProgramSpec = ProgramSpec {
    name: "frpc",
    files: &["frpc"],
    source: &ReleaseSource::Github {
        repo: "fatedier/frp",
        asset_pattern: "frp_{version}_{os}_{arch}.{pkg}",
        checksum: ChecksumSource::File("frp_sha256_checksums.txt"),
    },
    version_args: &["-v"],
};

/// frp 服务端（WP-44）。
pub static FRPS: ProgramSpec = ProgramSpec {
    name: "frps",
    files: &["frps"],
    source: &ReleaseSource::Github {
        repo: "fatedier/frp",
        asset_pattern: "frp_{version}_{os}_{arch}.{pkg}",
        checksum: ChecksumSource::File("frp_sha256_checksums.txt"),
    },
    version_args: &["-v"],
};

/// Cloudflare Tunnel（WP-46）。
pub static CLOUDFLARED: ProgramSpec = ProgramSpec {
    name: "cloudflared",
    files: &["cloudflared"],
    source: &ReleaseSource::Github {
        repo: "cloudflare/cloudflared",
        asset_pattern: "cloudflared-{os}-{arch}{exe}",
        checksum: ChecksumSource::AssetDigest,
    },
    version_args: &["--version"],
};

/// NetBird（WP-45）。
pub static NETBIRD: ProgramSpec = ProgramSpec {
    name: "netbird",
    files: &["netbird"],
    source: &ReleaseSource::Github {
        repo: "netbirdio/netbird",
        asset_pattern: "netbird_{version}_{os}_{arch}.{pkg}",
        checksum: ChecksumSource::File("checksums.txt"),
    },
    version_args: &["version"],
};

/// EasyTier（WP-45）。
pub static EASYTIER: ProgramSpec = ProgramSpec {
    name: "easytier-core",
    files: &["easytier-core", "easytier-cli"],
    source: &ReleaseSource::Github {
        repo: "EasyTier/EasyTier",
        asset_pattern: "easytier-{os}-{arch}-v{version}.{pkg}",
        checksum: ChecksumSource::None,
    },
    version_args: &["--version"],
};

/// File Browser（WP-66）：托管的是仍在维护的 FileBrowser **Quantum** 分支
/// （原版 filebrowser/filebrowser 已归档）。资产为裸二进制
/// `linux-amd64-filebrowser`，无打包后缀，Windows 资产是裸
/// `filebrowser.exe`（单模式无法同时表达，Windows 安装待 WP-92 扩展）。
/// 校验值取 GitHub 资产自带的摘要。2026-11-28 对照 v2.1.0-stable 复核。
pub static FILEBROWSER: ProgramSpec = ProgramSpec {
    name: "filebrowser",
    files: &["filebrowser"],
    source: &ReleaseSource::Github {
        repo: "gtsteffaniak/filebrowser",
        asset_pattern: "{os}-{arch}-filebrowser",
        checksum: ChecksumSource::AssetDigest,
    },
    version_args: &["version"],
};

/// Tailscale（WP-45）：静态包需要同时提供 `tailscale` 与 `tailscaled`。
pub static TAILSCALE: ProgramSpec = ProgramSpec {
    name: "tailscale",
    files: &["tailscale", "tailscaled"],
    source: &ReleaseSource::TailscaleStaticPkgs,
    version_args: &["version"],
};

/// 把模式中的占位符替换后与资产名精确比较。
pub fn match_asset(pattern: &str, asset_name: &str, platform: &Platform, version: &str) -> bool {
    let exe = if platform.os() == "windows" {
        ".exe"
    } else {
        ""
    };
    let pkg = if platform.os() == "windows" {
        "zip"
    } else {
        "tar.gz"
    };
    let filled = pattern
        .replace("{version}", version)
        .replace("{os}", platform.os())
        .replace("{arch}", platform.arch())
        .replace("{platform}", platform.as_str())
        .replace("{exe}", exe)
        .replace("{pkg}", pkg);
    filled == asset_name
}

/// 按资产名判断归档类型。
pub fn archive_kind(asset_name: &str) -> ArchiveKind {
    let lower = asset_name.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        ArchiveKind::TarGz
    } else if lower.ends_with(".zip") {
        ArchiveKind::Zip
    } else {
        ArchiveKind::Raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_matches_platform() {
        let linux_arm64 = Platform::from_parts("linux", "aarch64");
        let linux_amd64 = Platform::from_parts("linux", "x86_64");
        let windows_amd64 = Platform::from_parts("windows", "x86_64");
        // frp：frp_{version}_{os}_{arch}.{pkg}
        assert!(match_asset(
            FRPC.asset_pattern().expect("frpc has a pattern"),
            "frp_0.61.1_linux_arm64.tar.gz",
            &linux_arm64,
            "0.61.1"
        ));
        assert!(match_asset(
            FRPC.asset_pattern().expect("frpc has a pattern"),
            "frp_0.61.1_windows_amd64.zip",
            &windows_amd64,
            "0.61.1"
        ));
        assert!(
            !match_asset(
                FRPC.asset_pattern().expect("frpc has a pattern"),
                "frp_0.61.1_linux_amd64.tar.gz",
                &linux_arm64,
                "0.61.1"
            ),
            "不同架构的资产不匹配"
        );
        assert!(
            !match_asset(
                FRPC.asset_pattern().expect("frpc has a pattern"),
                "frp_0.61.1_linux_arm64.tar.gz",
                &linux_amd64,
                "0.61.1"
            ),
            "不同架构的资产不匹配"
        );
        // cloudflared：裸二进制带 {exe} 占位符。
        assert!(match_asset(
            CLOUDFLARED
                .asset_pattern()
                .expect("cloudflared has a pattern"),
            "cloudflared-linux-arm64",
            &linux_arm64,
            "2024.10.0"
        ));
        assert!(match_asset(
            CLOUDFLARED
                .asset_pattern()
                .expect("cloudflared has a pattern"),
            "cloudflared-windows-amd64.exe",
            &windows_amd64,
            "2024.10.0"
        ));
        // 归档类型按扩展名判断。
        assert_eq!(
            archive_kind("frp_0.61.1_linux_arm64.tar.gz"),
            ArchiveKind::TarGz
        );
        assert_eq!(
            archive_kind("tailscale_1.80.0_linux_arm64.tgz"),
            ArchiveKind::TarGz
        );
        assert_eq!(archive_kind("windows_amd64_zip.zip"), ArchiveKind::Zip);
        assert_eq!(archive_kind("cloudflared-linux-arm64"), ArchiveKind::Raw);
    }

    #[test]
    fn spec_main_file_is_first_entry() {
        assert_eq!(FRPC.main_file(), "frpc");
        assert_eq!(TAILSCALE.main_file(), "tailscale");
        assert_eq!(CLOUDFLARED.version_args, &["--version"]);
        assert!(TAILSCALE.asset_pattern().is_none());
        assert_eq!(
            FILEBROWSER.asset_pattern(),
            Some("{os}-{arch}-filebrowser")
        );
    }
}
