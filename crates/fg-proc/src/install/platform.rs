//! 平台标识（WP-43 §3.3）：`linux/arm64`、`linux/armv7`、`darwin/arm64`、
//! `windows/amd64` 这样的文本形式。托管程序与 Gately 使用相同的系统与
//! 架构；资产命名用上游的 Go 风格名字（`darwin`、`amd64`、`armv7`）。

use std::fmt;

/// 当前平台，如 `linux/arm64`。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Platform(String);

impl Platform {
    pub fn current() -> Self {
        Self::from_parts(std::env::consts::OS, std::env::consts::ARCH)
    }

    /// 由系统与架构名构造（先归一为 Go 风格名字）。
    pub fn from_parts(os: &str, arch: &str) -> Self {
        Self(format!("{}/{}", go_os(os), go_arch(arch)))
    }

    /// 原样采用文本形式（接口输入）。
    pub fn from_text(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    pub fn os(&self) -> &str {
        self.0.split('/').next().unwrap_or_default()
    }

    pub fn arch(&self) -> &str {
        self.0.split('/').nth(1).unwrap_or_default()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 上游资产的 OS 名：macOS 叫 `darwin`，其余保持不变。
pub fn go_os(os: &str) -> &str {
    match os {
        "macos" => "darwin",
        other => other,
    }
}

/// 上游资产的架构名：Go 风格的 `amd64` / `arm64` / `armv7` / `386`。
pub fn go_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "armv7",
        "x86" | "i686" => "386",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_names() {
        assert_eq!(
            Platform::from_parts("linux", "arm").as_str(),
            "linux/armv7",
            "32 位 ARM 上游叫 armv7"
        );
        assert_eq!(
            Platform::from_parts("darwin", "aarch64").as_str(),
            "darwin/arm64"
        );
        assert_eq!(
            Platform::from_parts("macos", "x86_64").as_str(),
            "darwin/amd64"
        );
        assert_eq!(
            Platform::from_parts("linux", "x86_64").as_str(),
            "linux/amd64"
        );
        assert_eq!(
            Platform::from_parts("windows", "aarch64").as_str(),
            "windows/arm64"
        );
        let current = Platform::current();
        assert_eq!(
            current.os(),
            go_os(std::env::consts::OS),
            "当前平台 OS 与常量一致"
        );
        assert_eq!(
            current.arch(),
            go_arch(std::env::consts::ARCH),
            "当前平台架构与常量一致"
        );
        assert_eq!(Platform::from_text("linux/mips64").as_str(), "linux/mips64");
    }
}
