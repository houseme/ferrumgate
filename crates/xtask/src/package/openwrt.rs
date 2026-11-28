//! OpenWrt `.ipk` (opkg, <= 24.10) and `.apk` (apk-tools v3, >= 25.12)
//! packaging metadata, version conversion, `DISTRIB_ARCH` guard, procd init
//! script, sysupgrade `keep.d` file, and Alpine container invocation
//! (WP-92 §2, §3.3, §3.4, §8).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

use crate::package::tools::openwrt_packager_image_ref;

/// Description of one OpenWrt target architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OpenwrtArch {
    pub target_id: &'static str,
    pub arch_id: &'static str,
    pub triple: &'static str,
    /// Shell glob matched against `DISTRIB_ARCH` in `/etc/openwrt_release`.
    pub distrib_arch_glob: &'static str,
    pub hardware_note: Option<&'static str>,
}

/// All 6 OpenWrt architectures supported by the target matrix.
pub const OPENWRT_ARCHES: &[OpenwrtArch] = &[
    OpenwrtArch {
        target_id: "openwrt-amd64",
        arch_id: "amd64",
        triple: "x86_64-unknown-linux-musl",
        distrib_arch_glob: "x86_64",
        hardware_note: None,
    },
    OpenwrtArch {
        target_id: "openwrt-arm64",
        arch_id: "arm64",
        triple: "aarch64-unknown-linux-musl",
        distrib_arch_glob: "aarch64_*",
        hardware_note: None,
    },
    OpenwrtArch {
        target_id: "openwrt-arm",
        arch_id: "arm",
        triple: "armv7-unknown-linux-musleabihf",
        distrib_arch_glob: "arm_cortex-a*_*",
        hardware_note: Some(
            "Requires ARMv7 with hardware FPU (VFPv3/NEON); non-FPU arm_cortex-a9 devices cannot run this build",
        ),
    },
    OpenwrtArch {
        target_id: "openwrt-mipsle",
        arch_id: "mipsle",
        triple: "mipsel-unknown-linux-musl",
        distrib_arch_glob: "mipsel_*",
        hardware_note: Some("Soft-float MIPS little-endian"),
    },
    OpenwrtArch {
        target_id: "openwrt-mips",
        arch_id: "mips",
        triple: "mips-unknown-linux-musl",
        distrib_arch_glob: "mips_*",
        hardware_note: Some("Soft-float MIPS big-endian"),
    },
    OpenwrtArch {
        target_id: "openwrt-riscv64",
        arch_id: "riscv64",
        triple: "riscv64gc-unknown-linux-musl",
        distrib_arch_glob: "riscv64_*",
        hardware_note: None,
    },
];

pub fn find_openwrt_arch(target_id: &str) -> Option<&'static OpenwrtArch> {
    OPENWRT_ARCHES
        .iter()
        .find(|arch| arch.target_id == target_id || arch.arch_id == target_id)
}

/// Converted package versions for opkg (`.ipk`) and apk-tools v3 (`.apk`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OpenwrtVersion {
    /// opkg version string (e.g. `0.5.4-r1` or `0.5.4~rc1-r1`).
    pub ipk: String,
    /// apk-tools v3 version string (e.g. `0.5.4-r1` or `0.5.4_rc1-r1`).
    pub apk: String,
}

/// Converts a FerrumGate release tag into OpenWrt `.ipk` and `.apk` versions
/// (WP-92 §3.3).
///
/// Examples:
/// - `v0.5.4` -> `ipk: "0.5.4-r1"`, `apk: "0.5.4-r1"`
/// - `v0.5.4-rc.1` -> `ipk: "0.5.4~rc1-r1"`, `apk: "0.5.4_rc1-r1"`
/// - `v0.5.4-beta.2` -> `ipk: "0.5.4~beta2-r1"`, `apk: "0.5.4_beta2-r1"`
/// - `v0.5.4-alpha.1` -> `ipk: "0.5.4~alpha1-r1"`, `apk: "0.5.4_alpha1-r1"`
pub fn convert_version(version: &str) -> Result<OpenwrtVersion> {
    let raw = version.trim();
    let stripped = raw.strip_prefix('v').unwrap_or(raw);
    ensure!(!stripped.is_empty(), "OpenWrt version must not be empty");

    let (base, prerelease) = match stripped.split_once('-') {
        Some((b, pre)) => (b, Some(pre)),
        None => (stripped, None),
    };

    let parts: Vec<&str> = base.split('.').collect();
    ensure!(
        (2..=4).contains(&parts.len())
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "invalid base version `{version}`: expected 2 to 4 numeric dot-separated parts"
    );

    match prerelease {
        None => Ok(OpenwrtVersion {
            ipk: format!("{base}-r1"),
            apk: format!("{base}-r1"),
        }),
        Some(pre) => {
            let normalized = normalize_prerelease(pre)?;
            Ok(OpenwrtVersion {
                ipk: format!("{base}~{normalized}-r1"),
                apk: format!("{base}_{normalized}-r1"),
            })
        }
    }
}

fn normalize_prerelease(pre: &str) -> Result<String> {
    let compact: String = pre
        .chars()
        .filter(|c| *c != '.' && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    ensure!(
        !compact.is_empty() && compact.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invalid prerelease tag `{pre}`"
    );
    Ok(compact)
}

/// Content installed at `/lib/upgrade/keep.d/ferrumgate` so OpenWrt sysupgrade
/// preserves the FerrumGate configuration directory and UCI file.
pub const KEEP_D_CONTENT: &str = "/etc/ferrumgate/\n/etc/config/ferrumgate\n";

/// Default UCI configuration installed at `/etc/config/ferrumgate`.
pub const DEFAULT_UCI_CONFIG: &str = "\
config main 'main'
\toption enabled '1'
\toption port ''
";

/// Procd init script installed at `/etc/init.d/ferrumgate` (and committed as
/// `deploy/openwrt/ferrumgate.init`).
///
/// Key guarantees (WP-92 §2 / §3.3 / §8):
/// - `START=99`, `STOP=10`, `USE_PROCD=1`
/// - `respawn 3600 5 5` and `nofile 65535`
/// - UCI `main.port` replaces ONLY the listening port while preserving the
///   host part (`127.0.0.1:16680`, `[::1]:16680`, `:16680`), and ignores any
///   port outside `1..=65535`
/// - `service_triggers` reloads when `/etc/config/ferrumgate` changes
pub const PROCD_INIT_SCRIPT: &str = r#"#!/bin/sh /etc/rc.common
# FerrumGate OpenWrt procd init script (WP-92)

START=99
STOP=10
USE_PROCD=1

PROG=/usr/bin/fgate
CONF_DIR=/etc/ferrumgate
DEFAULT_LISTEN=":16680"

is_valid_port() {
	case "$1" in
		''|*[!0-9]*) return 1 ;;
	esac
	case "$1" in
		0*) return 1 ;;
	esac
	[ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# Replaces ONLY the port portion of a listen address, preserving the host part
# so changing UCI main.port never widens a loopback/LAN listener to 0.0.0.0.
replace_listen_port() {
	addr="$1"
	new_port="$2"
	if ! is_valid_port "$new_port"; then
		printf '%s\n' "$addr"
		return 0
	fi
	case "$addr" in
		\[*\]:*)
			host="${addr%\]:*}]"
			printf '%s:%s\n' "$host" "$new_port"
			;;
		*:*)
			host="${addr%:*}"
			printf '%s:%s\n' "$host" "$new_port"
			;;
		*)
			printf ':%s\n' "$new_port"
			;;
	esac
}

current_listen_addr() {
	if [ -r "$CONF_DIR/ferrumgate.json" ]; then
		found="$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONF_DIR/ferrumgate.json" | head -n 1)"
		if [ -n "$found" ]; then
			printf '%s\n' "$found"
			return 0
		fi
	fi
	printf '%s\n' "$DEFAULT_LISTEN"
}

start_service() {
	config_load ferrumgate
	config_get_bool enabled main enabled 1
	[ "$enabled" -eq 1 ] || return 0

	config_get uci_port main port ""

	mkdir -p "$CONF_DIR"
	chmod 0700 "$CONF_DIR" 2>/dev/null || true

	procd_open_instance ferrumgate
	procd_set_param env FERRUMGATE_CONFIG_DIR="$CONF_DIR"
	if is_valid_port "$uci_port"; then
		base_listen="$(current_listen_addr)"
		effective_listen="$(replace_listen_port "$base_listen" "$uci_port")"
		procd_set_param command "$PROG" serve --config "$CONF_DIR" --admin-listen "$effective_listen"
	else
		procd_set_param command "$PROG" serve --config "$CONF_DIR"
	fi
	procd_set_param respawn 3600 5 5
	procd_set_param limits nofile="65535 65535"
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}

service_triggers() {
	procd_add_reload_trigger "ferrumgate"
}

reload_service() {
	stop
	start
}
"#;

/// Renders the opkg `.ipk` `control` metadata file.
/// Static musl binaries do not depend on OpenWrt's libc, so `Architecture` is
/// deliberately `all` and wrong-architecture installs are blocked in `preinst`.
pub fn render_ipk_control(version: &OpenwrtVersion, arch: &OpenwrtArch) -> String {
    format!(
        "Package: ferrumgate\n\
         Version: {}\n\
         Architecture: all\n\
         Maintainer: FerrumGate <https://github.com/houseme/ferrumgate>\n\
         Section: net\n\
         Priority: optional\n\
         Description: FerrumGate reverse proxy and network gateway ({} static musl)\n",
        version.ipk, arch.arch_id
    )
}

/// Renders the apk-tools v3 `.apk` package info metadata.
/// Uses `arch = noarch` paired with the `DISTRIB_ARCH` pre-install guard.
pub fn render_apk_pkginfo(version: &OpenwrtVersion, arch: &OpenwrtArch) -> String {
    format!(
        "pkgname = ferrumgate\n\
         pkgver = {}\n\
         pkgdesc = FerrumGate reverse proxy and network gateway ({} static musl)\n\
         url = https://github.com/houseme/ferrumgate\n\
         arch = noarch\n\
         license = Apache-2.0\n",
        version.apk, arch.arch_id
    )
}

/// Renders the POSIX `preinst` script that inspects `/etc/openwrt_release`
/// (`DISTRIB_ARCH`) and rejects installation on mismatched architectures.
pub fn render_preinst_script(arch: &OpenwrtArch) -> String {
    format!(
        "#!/bin/sh\n\
         set -eu\n\
         \n\
         RELEASE_FILE=\"${{IPKG_INSTROOT:-}}/etc/openwrt_release\"\n\
         if [ -r \"$RELEASE_FILE\" ]; then\n\
         \tDISTRIB_ARCH=\"\"\n\
         \t. \"$RELEASE_FILE\"\n\
         \tcase \"${{DISTRIB_ARCH:-}}\" in\n\
         \t\t{glob})\n\
         \t\t\t;;\n\
         \t\t*)\n\
         \t\t\techo \"ferrumgate: package is built for {arch_id} ({glob}), refusing to install on DISTRIB_ARCH=${{DISTRIB_ARCH:-unknown}}\" >&2\n\
         \t\t\texit 1\n\
         \t\t\t;;\n\
         \tesac\n\
         fi\n\
         exit 0\n",
        glob = arch.distrib_arch_glob,
        arch_id = arch.arch_id,
    )
}

/// Renders the POSIX `postinst` script.
/// When running under ImageBuilder (`IPKG_INSTROOT` is non-empty), it enables
/// boot-time startup links without trying to start the daemon on the build host.
pub fn render_postinst_script() -> &'static str {
    "#!/bin/sh\n\
     set -eu\n\
     \n\
     if [ -n \"${IPKG_INSTROOT:-}\" ]; then\n\
     \tif [ -x \"${IPKG_INSTROOT}/etc/init.d/ferrumgate\" ]; then\n\
     \t\tIPKG_INSTROOT=\"$IPKG_INSTROOT\" \"${IPKG_INSTROOT}/etc/init.d/ferrumgate\" enable 2>/dev/null || true\n\
     \tfi\n\
     else\n\
     \t/etc/init.d/ferrumgate enable\n\
     \t/etc/init.d/ferrumgate restart || /etc/init.d/ferrumgate start\n\
     fi\n\
     exit 0\n"
}

/// Filenames produced for one OpenWrt target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenwrtPackageNames {
    pub ipk: String,
    pub apk: String,
}

pub fn package_filenames(version: &OpenwrtVersion, arch: &OpenwrtArch) -> OpenwrtPackageNames {
    OpenwrtPackageNames {
        ipk: format!("ferrumgate_{}_{}.ipk", version.ipk, arch.arch_id),
        apk: format!("ferrumgate-{}-{}.apk", version.apk, arch.arch_id),
    }
}

/// Stages the OpenWrt rootfs payload and control scripts for `.ipk` / `.apk`
/// creation.
pub fn stage_openwrt_tree(
    binary: &Path,
    version: &str,
    arch: &OpenwrtArch,
    staging_dir: &Path,
) -> Result<OpenwrtVersion> {
    ensure!(
        binary.is_file(),
        "OpenWrt source binary does not exist: {}",
        binary.display()
    );
    let parsed_ver = convert_version(version)?;

    if staging_dir.exists() {
        std::fs::remove_dir_all(staging_dir)
            .with_context(|| format!("failed to clean {}", staging_dir.display()))?;
    }

    let rootfs = staging_dir.join("rootfs");
    let control = staging_dir.join("control");
    let apk_meta = staging_dir.join("apk");

    for dir in [
        rootfs.join("usr/bin"),
        rootfs.join("etc/init.d"),
        rootfs.join("etc/config"),
        rootfs.join("lib/upgrade/keep.d"),
        control.clone(),
        apk_meta.clone(),
    ] {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }

    let bin_dest = rootfs.join("usr/bin/fgate");
    std::fs::copy(binary, &bin_dest).with_context(|| {
        format!(
            "failed to copy binary {} to {}",
            binary.display(),
            bin_dest.display()
        )
    })?;
    let init_dest = rootfs.join("etc/init.d/ferrumgate");
    std::fs::write(&init_dest, PROCD_INIT_SCRIPT)?;
    std::fs::write(rootfs.join("etc/config/ferrumgate"), DEFAULT_UCI_CONFIG)?;
    std::fs::write(rootfs.join("lib/upgrade/keep.d/ferrumgate"), KEEP_D_CONTENT)?;

    std::fs::write(
        control.join("control"),
        render_ipk_control(&parsed_ver, arch),
    )?;
    let preinst_dest = control.join("preinst");
    std::fs::write(&preinst_dest, render_preinst_script(arch))?;
    let postinst_dest = control.join("postinst");
    std::fs::write(&postinst_dest, render_postinst_script())?;

    std::fs::write(
        apk_meta.join("PKGINFO"),
        render_apk_pkginfo(&parsed_ver, arch),
    )?;
    let apk_pre = apk_meta.join("pre-install");
    std::fs::write(&apk_pre, render_preinst_script(arch))?;
    let apk_post = apk_meta.join("post-install");
    std::fs::write(&apk_post, render_postinst_script())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for exec_file in [
            &bin_dest,
            &init_dest,
            &preinst_dest,
            &postinst_dest,
            &apk_pre,
            &apk_post,
        ] {
            std::fs::set_permissions(exec_file, std::fs::Permissions::from_mode(0o755))
                .with_context(|| format!("failed to chmod 0755 {}", exec_file.display()))?;
        }
    }

    Ok(parsed_ver)
}

/// Argument array to run the pinned Alpine 3.24 root packager container to emit
/// `.ipk` and `.apk` from a staged directory (no shell interpolation in Rust).
pub fn docker_packager_args(
    staging_dir: &Path,
    out_dir: &Path,
    version: &OpenwrtVersion,
    arch: &OpenwrtArch,
) -> Vec<String> {
    let names = package_filenames(version, arch);
    vec![
        "run".to_string(),
        "--rm".to_string(),
        "--user".to_string(),
        "0:0".to_string(),
        "-v".to_string(),
        format!("{}:/work/stage:ro", staging_dir.display()),
        "-v".to_string(),
        format!("{}:/work/out:rw", out_dir.display()),
        "-e".to_string(),
        format!("IPK_NAME={}", names.ipk),
        "-e".to_string(),
        format!("APK_NAME={}", names.apk),
        "-e".to_string(),
        format!("PKG_VER={}", version.apk),
        openwrt_packager_image_ref().to_string(),
        "/bin/sh".to_string(),
        "-eu".to_string(),
        "-c".to_string(),
        CONTAINER_PACK_SCRIPT.to_string(),
    ]
}

const CONTAINER_PACK_SCRIPT: &str = r#"
mkdir -p /tmp/pkg/data /tmp/pkg/control
cp -a /work/stage/rootfs/. /tmp/pkg/data/
cp -a /work/stage/control/. /tmp/pkg/control/
chown -R 0:0 /tmp/pkg
printf '2.0\n' > /tmp/pkg/debian-binary
tar -czf /tmp/pkg/data.tar.gz -C /tmp/pkg/data .
tar -czf /tmp/pkg/control.tar.gz -C /tmp/pkg/control .
tar -czf "/work/out/${IPK_NAME}" -C /tmp/pkg debian-binary control.tar.gz data.tar.gz
if command -v apk >/dev/null 2>&1; then
    apk mkpkg --info "name:ferrumgate" --info "version:${PKG_VER}" --info "arch:noarch" \
        --info "description:FerrumGate reverse proxy and network gateway" \
        --info "license:Apache-2.0" \
        --script "pre-install:/work/stage/apk/pre-install" \
        --script "post-install:/work/stage/apk/post-install" \
        --files /tmp/pkg/data \
        --output "/work/out/${APK_NAME}"
fi
"#;

/// Executes the pinned Alpine container packager to build `.ipk` and `.apk`.
pub fn build_openwrt_packages(
    staging_dir: &Path,
    out_dir: &Path,
    version: &OpenwrtVersion,
    arch: &OpenwrtArch,
) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let args = docker_packager_args(staging_dir, out_dir, version, arch);
    let status = Command::new("docker")
        .args(&args)
        .status()
        .context("failed to spawn `docker` for OpenWrt packaging")?;
    if !status.success() {
        bail!("OpenWrt container packager failed with {status}");
    }
    let names = package_filenames(version, arch);
    Ok((out_dir.join(names.ipk), out_dir.join(names.apk)))
}
