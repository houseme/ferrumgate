//! WP-92 packaging, manifest, script, Dockerfile, Compose, Grafana dashboard,
//! and release workflow verification tests.

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;
use xtask::modules::manifest::Manifest;
use xtask::modules::resolve::{ResolveOptions, resolve};
use xtask::package::build::{BuildSpec, cargo_build_args, cargo_env, rustflags_env_key};
use xtask::package::docker::{DockerBuildArgs, DockerBuildSpec, docker_buildx_args, image_tags};
use xtask::package::fpk::{FpkPlatform, fnpack_args, render_manifest, stage_fpk_project};
use xtask::package::luci::stage_luci_tree;
use xtask::package::openwrt::{
    KEEP_D_CONTENT, OPENWRT_ARCHES, PROCD_INIT_SCRIPT, convert_version, docker_packager_args,
    find_openwrt_arch, render_apk_pkginfo, render_ipk_control, render_preinst_script,
    stage_openwrt_tree,
};
use xtask::package::tar::{build_tar_gz, inspect_tar_gz};
use xtask::package::targets::{
    DOCKER_PLATFORMS, Kind, Runner, TARGETS, find_target, local_asset_name, tar_asset_name,
};
use xtask::package::tools::{
    FNPACK_TOOL, PINNED_TOOLS, ToolKind, is_valid_sha256, sha256_bytes, verify_and_stage_tool,
    verify_file_sha256,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask lives at crates/xtask")
        .to_path_buf()
}

fn repo_manifest() -> Manifest {
    Manifest::load(&repo_root().join("features.toml")).expect("features.toml parses")
}

fn all_optional(manifest: &Manifest) -> Vec<String> {
    manifest.optional().map(|m| m.id.clone()).collect()
}

#[test]
fn targets_cover_upstream_matrix() {
    let manifest = repo_manifest();
    let manifest_ids: Vec<&str> = manifest.target_ids().collect();
    let package_ids: Vec<&str> = TARGETS.iter().map(|t| t.id).collect();

    assert_eq!(TARGETS.len(), 19);
    assert_eq!(package_ids, manifest_ids);

    assert_eq!(TARGETS.iter().filter(|t| t.kind == Kind::Docker).count(), 1);
    assert_eq!(TARGETS.iter().filter(|t| t.kind == Kind::Tar).count(), 10);
    assert_eq!(TARGETS.iter().filter(|t| t.kind == Kind::Fpk).count(), 2);
    assert_eq!(
        TARGETS.iter().filter(|t| t.kind == Kind::Openwrt).count(),
        6
    );

    // macOS targets run on macOS runners; everything else builds on Linux.
    let macos_ids: Vec<&str> = TARGETS
        .iter()
        .filter(|t| t.runner == Runner::Macos)
        .map(|t| t.id)
        .collect();
    assert_eq!(macos_ids, ["darwin-amd64", "darwin-arm64"]);

    // WP-92 §8: the 6 mips/mipsle/riscv64 targets are flagged as ring-incompatible.
    let ring_unsupported: Vec<&str> = TARGETS
        .iter()
        .filter(|t| !t.ring_supported)
        .map(|t| t.id)
        .collect();
    assert_eq!(
        ring_unsupported,
        [
            "linux-mipsle",
            "linux-mips",
            "linux-riscv64",
            "openwrt-mipsle",
            "openwrt-mips",
            "openwrt-riscv64",
        ]
    );
    for target in TARGETS.iter().filter(|t| !t.ring_supported) {
        let note = target
            .crypto_note
            .expect("ring-unsupported target must carry an explanatory note");
        assert!(
            note.contains("ring"),
            "note for {} should mention ring: {note}",
            target.id
        );
    }

    // Spot-check key Rust target triples.
    assert_eq!(
        find_target("linux-amd64").unwrap().triple,
        "x86_64-unknown-linux-musl"
    );
    assert_eq!(
        find_target("linux-arm").unwrap().triple,
        "armv7-unknown-linux-musleabihf"
    );
    assert_eq!(
        find_target("windows-amd64").unwrap().exe_name(),
        "fgate.exe"
    );
    assert_eq!(find_target("linux-arm64").unwrap().exe_name(), "fgate");
}

#[test]
fn asset_names_follow_convention() {
    assert_eq!(
        tar_asset_name("v0.5.4", "linux-amd64"),
        "fgate_v0.5.4_linux_amd64.tar.gz"
    );
    assert_eq!(
        tar_asset_name("v0.5.4", "windows-amd64"),
        "fgate_v0.5.4_windows_amd64.tar.gz"
    );
    assert_eq!(
        tar_asset_name("v0.5.4", "darwin-arm64"),
        "fgate_v0.5.4_darwin_arm64.tar.gz"
    );
    assert_eq!(
        tar_asset_name("v0.5.4", "freebsd-amd64"),
        "fgate_v0.5.4_freebsd_amd64.tar.gz"
    );

    assert_eq!(
        local_asset_name("v0.5.4", "38c0084cbdde", "linux-arm64"),
        "fgate_v0.5.4_38c0084cbdde_linux-arm64.tar.gz"
    );
    assert_eq!(
        local_asset_name("v0.5.4", "38c0084cbdde", "fnos-arm"),
        "fgate_v0.5.4_38c0084cbdde_fnos-arm.fpk"
    );
    assert_eq!(
        local_asset_name("v0.5.4", "38c0084cbdde", "fnos-x86"),
        "fgate_v0.5.4_38c0084cbdde_fnos-x86.fpk"
    );
}

#[test]
fn cargo_env_and_build_args_inject_metadata_and_static_flags() {
    let manifest = repo_manifest();
    let implemented = all_optional(&manifest);
    let resolved = resolve(
        &manifest,
        &ResolveOptions {
            modules: Some("guard,cron".to_string()),
            lang: Some("cjk-en".to_string()),
            ..ResolveOptions::default()
        },
        &implemented,
    )
    .expect("resolve succeeds");

    let spec = BuildSpec {
        version: "v0.5.4".to_string(),
        commit: "abc1234".to_string(),
        build_date: "2026-11-28T00:00:00Z".to_string(),
        profile: Some(resolved.profile.clone()),
        resolved,
    };

    let arm64 = find_target("linux-arm64").unwrap();
    let env = cargo_env(&spec, arm64);
    assert!(env.contains(&("FERRUMGATE_VERSION".to_string(), "v0.5.4".to_string())));
    assert!(env.contains(&("FERRUMGATE_COMMIT".to_string(), "abc1234".to_string())));
    assert!(env.contains(&(
        "FERRUMGATE_BUILD_DATE".to_string(),
        "2026-11-28T00:00:00Z".to_string()
    )));
    assert!(env.contains(&(
        rustflags_env_key("aarch64-unknown-linux-musl"),
        "-C target-feature=+crt-static".to_string()
    )));

    let mipsle = find_target("linux-mipsle").unwrap();
    let mips_env = cargo_env(&spec, mipsle);
    assert!(mips_env.contains(&(
        "CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_RUSTFLAGS".to_string(),
        "-C target-feature=+crt-static,+soft-float".to_string()
    )));

    let args = cargo_build_args(&spec, arm64).expect("cargo args");
    assert_eq!(
        args,
        [
            "build",
            "--release",
            "--locked",
            "--bin",
            "fgate",
            "--target",
            "aarch64-unknown-linux-musl",
            "--no-default-features",
            "--features",
            "mod-guard,mod-cron,lang-cjk-en",
        ]
    );

    let docker = find_target("docker").unwrap();
    assert!(cargo_build_args(&spec, docker).is_err());
}

#[test]
fn tar_contains_exe_license_readme_in_order() {
    let temp = TempDir::new().expect("tempdir");
    let bin = temp.path().join("fgate-bin");
    let license = temp.path().join("LICENSE");
    let readme = temp.path().join("README.md");
    std::fs::write(&bin, b"#!/bin/sh\necho fgate\n").unwrap();
    std::fs::write(&license, b"Apache-2.0\n").unwrap();
    std::fs::write(&readme, b"# FerrumGate\n").unwrap();

    let out_dir = temp.path().join("dist");
    let linux_target = find_target("linux-amd64").unwrap();
    let archive = build_tar_gz(
        &bin,
        &license,
        &readme,
        "v0.5.4",
        linux_target,
        None,
        &out_dir,
    )
    .expect("build linux tar.gz");
    assert_eq!(
        archive.file_name().unwrap().to_str().unwrap(),
        "fgate_v0.5.4_linux_amd64.tar.gz"
    );

    let entries = inspect_tar_gz(&archive).expect("inspect linux tar.gz");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["fgate", "LICENSE", "README.md"]);
    #[cfg(unix)]
    assert!(
        entries[0].mode.contains("rwxr-xr-x"),
        "fgate must have mode 0755, got {}",
        entries[0].mode
    );

    let win_target = find_target("windows-amd64").unwrap();
    let win_archive = build_tar_gz(
        &bin,
        &license,
        &readme,
        "v0.5.4",
        win_target,
        Some("38c0084cbdde"),
        &out_dir,
    )
    .expect("build windows tar.gz");
    assert_eq!(
        win_archive.file_name().unwrap().to_str().unwrap(),
        "fgate_v0.5.4_38c0084cbdde_windows-amd64.tar.gz"
    );
    let win_entries = inspect_tar_gz(&win_archive).expect("inspect windows tar.gz");
    let win_names: Vec<&str> = win_entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(win_names, ["fgate.exe", "LICENSE", "README.md"]);
}

#[test]
fn fpk_manifest_matches_version_and_platform() {
    let x86 = render_manifest("v0.5.4", FpkPlatform::X86).expect("x86 manifest");
    assert!(x86.contains("appname               = ferrumgate\n"));
    assert!(x86.contains("version               = 0.5.4\n"));
    assert!(x86.contains("platform              = x86\n"));
    assert!(x86.contains("service_port          = 16680\n"));

    let arm = render_manifest("v0.5.4", FpkPlatform::Arm).expect("arm manifest");
    assert!(arm.contains("version               = 0.5.4\n"));
    assert!(arm.contains("platform              = arm\n"));

    assert_eq!(FpkPlatform::X86.binary_source_target(), "linux-amd64");
    assert_eq!(FpkPlatform::Arm.binary_source_target(), "linux-arm64");

    // Reject control-character injection in version.
    assert!(render_manifest("v0.5.4\nplatform = evil", FpkPlatform::X86).is_err());

    // Committed template matches rendered default manifest.
    let template = std::fs::read_to_string(repo_root().join("deploy/fnos/manifest"))
        .expect("deploy/fnos/manifest exists");
    assert_eq!(
        template,
        render_manifest("v0.1.0", FpkPlatform::X86).expect("default manifest")
    );

    // Verify project staging and fnpack argument array.
    let temp = TempDir::new().expect("tempdir");
    let bin = temp.path().join("fgate");
    std::fs::write(&bin, b"elf").unwrap();
    let stage = temp.path().join("stage-arm");
    stage_fpk_project(
        Some(&repo_root().join("deploy/fnos")),
        &bin,
        "v0.5.4",
        FpkPlatform::Arm,
        &stage,
    )
    .expect("stage fpk");
    assert_eq!(
        std::fs::read_to_string(stage.join("manifest")).unwrap(),
        arm
    );
    assert!(stage.join("app/server/fgate").is_file());

    let args = fnpack_args(&stage, &temp.path().join("out.fpk"));
    assert_eq!(args[0], "build");
    assert_eq!(args[1], "--directory");
    assert_eq!(args[3], "--output");
}

#[test]
fn openwrt_packages_arch_all_with_arch_check() {
    // Version conversion: release and prerelease mappings for opkg vs apk-tools v3.
    let rel = convert_version("v0.5.4").expect("release version");
    assert_eq!(rel.ipk, "0.5.4-r1");
    assert_eq!(rel.apk, "0.5.4-r1");

    let rc = convert_version("v0.5.4-rc.1").expect("rc version");
    assert_eq!(rc.ipk, "0.5.4~rc1-r1");
    assert_eq!(rc.apk, "0.5.4_rc1-r1");

    let beta = convert_version("v1.2.3-beta.2").expect("beta version");
    assert_eq!(beta.ipk, "1.2.3~beta2-r1");
    assert_eq!(beta.apk, "1.2.3_beta2-r1");

    assert_eq!(OPENWRT_ARCHES.len(), 6);
    for arch in OPENWRT_ARCHES {
        let control = render_ipk_control(&rel, arch);
        assert!(
            control.contains("Architecture: all\n"),
            "{} control must be Architecture: all",
            arch.target_id
        );
        let pkginfo = render_apk_pkginfo(&rel, arch);
        assert!(
            pkginfo.contains("arch = noarch\n"),
            "{} PKGINFO must be arch = noarch",
            arch.target_id
        );
    }

    // Verify preinst DISTRIB_ARCH guard accepts matching arch and blocks mismatched arch.
    let cases = [
        ("openwrt-amd64", "x86_64", "aarch64_cortex-a53"),
        ("openwrt-arm64", "aarch64_cortex-a53", "mipsel_24kc"),
        ("openwrt-arm", "arm_cortex-a7_neon-vfpv4", "x86_64"),
        ("openwrt-mipsle", "mipsel_24kc", "mips_24kc"),
        ("openwrt-mips", "mips_24kc", "mipsel_24kc"),
        ("openwrt-riscv64", "riscv64_riscv64", "aarch64_generic"),
    ];
    let temp = TempDir::new().expect("tempdir");
    for (target_id, good_arch, bad_arch) in cases {
        let arch = find_openwrt_arch(target_id).unwrap();
        let preinst_path = temp.path().join(format!("preinst-{target_id}.sh"));
        std::fs::write(&preinst_path, render_preinst_script(arch)).unwrap();

        let good_root = temp.path().join(format!("good-{target_id}"));
        std::fs::create_dir_all(good_root.join("etc")).unwrap();
        std::fs::write(
            good_root.join("etc/openwrt_release"),
            format!("DISTRIB_ARCH='{good_arch}'\n"),
        )
        .unwrap();
        let ok = Command::new("/bin/sh")
            .arg(&preinst_path)
            .env("IPKG_INSTROOT", &good_root)
            .output()
            .expect("run preinst");
        assert!(
            ok.status.success(),
            "{target_id} should accept {good_arch}: {}",
            String::from_utf8_lossy(&ok.stderr)
        );

        let bad_root = temp.path().join(format!("bad-{target_id}"));
        std::fs::create_dir_all(bad_root.join("etc")).unwrap();
        std::fs::write(
            bad_root.join("etc/openwrt_release"),
            format!("DISTRIB_ARCH='{bad_arch}'\n"),
        )
        .unwrap();
        let rejected = Command::new("/bin/sh")
            .arg(&preinst_path)
            .env("IPKG_INSTROOT", &bad_root)
            .output()
            .expect("run preinst mismatch");
        assert!(
            !rejected.status.success(),
            "{target_id} must reject mismatched arch {bad_arch}"
        );
        let stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            stderr.contains("refusing to install"),
            "expected clear error for {target_id}, got: {stderr}"
        );
    }

    // Verify container packager args use pinned alpine:3.24@sha256:... image.
    let arm64 = find_openwrt_arch("openwrt-arm64").unwrap();
    let docker_args = docker_packager_args(temp.path(), temp.path(), &rel, arm64);
    assert!(
        docker_args
            .iter()
            .any(|arg| arg.starts_with("docker.io/library/alpine:3.24@sha256:")),
        "OpenWrt packager must pin alpine:3.24 by digest: {docker_args:?}"
    );

    // Verify LuCI staging produces arch-independent metadata + valid JSON.
    let luci_stage = temp.path().join("luci");
    stage_luci_tree("v0.5.4", &luci_stage).expect("stage luci");
    let luci_control = std::fs::read_to_string(luci_stage.join("control/control")).unwrap();
    assert!(luci_control.contains("Architecture: all\n"));
    let luci_apk = std::fs::read_to_string(luci_stage.join("apk/PKGINFO")).unwrap();
    assert!(luci_apk.contains("arch = noarch\n"));
    let menu: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            luci_stage.join("rootfs/usr/share/luci/menu.d/luci-app-ferrumgate.json"),
        )
        .unwrap(),
    )
    .expect("LuCI menu JSON parses");
    assert!(menu.get("admin/services/ferrumgate").is_some());
    let acl: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            luci_stage.join("rootfs/usr/share/rpcd/acl.d/luci-app-ferrumgate.json"),
        )
        .unwrap(),
    )
    .expect("LuCI ACL JSON parses");
    assert!(acl.get("luci-app-ferrumgate").is_some());
}

#[test]
fn openwrt_keep_d_preserves_config_dir() {
    let temp = TempDir::new().expect("tempdir");
    let bin = temp.path().join("fgate");
    std::fs::write(&bin, b"elf").unwrap();
    let stage = temp.path().join("openwrt-stage");
    let arch = find_openwrt_arch("openwrt-arm64").unwrap();

    stage_openwrt_tree(&bin, "v0.5.4", arch, &stage).expect("stage openwrt");

    let keep_d = std::fs::read_to_string(stage.join("rootfs/lib/upgrade/keep.d/ferrumgate"))
        .expect("keep.d file exists");
    assert_eq!(keep_d, KEEP_D_CONTENT);
    assert!(keep_d.lines().any(|line| line == "/etc/ferrumgate/"));
    assert!(keep_d.lines().any(|line| line == "/etc/config/ferrumgate"));
    assert!(stage.join("rootfs/usr/bin/fgate").is_file());
    assert!(stage.join("rootfs/etc/init.d/ferrumgate").is_file());
}

#[test]
fn procd_init_script_ignores_invalid_port_keeps_host() {
    let committed = std::fs::read_to_string(repo_root().join("deploy/openwrt/ferrumgate.init"))
        .expect("deploy/openwrt/ferrumgate.init exists");
    assert_eq!(
        committed, PROCD_INIT_SCRIPT,
        "deploy/openwrt/ferrumgate.init must stay byte-identical to openwrt::PROCD_INIT_SCRIPT"
    );

    // Snapshot invariants (WP-92 §2 / §3.4).
    for expected in [
        "#!/bin/sh /etc/rc.common",
        "START=99",
        "STOP=10",
        "USE_PROCD=1",
        "procd_set_param respawn 3600 5 5",
        "procd_set_param limits nofile=\"65535 65535\"",
        "procd_add_reload_trigger \"ferrumgate\"",
    ] {
        assert!(
            committed.contains(expected),
            "procd init script missing `{expected}`"
        );
    }

    // Extract helper functions and verify actual POSIX sh behavior on port rewriting.
    let helper_end = committed
        .find("start_service()")
        .expect("start_service marker");
    let helpers = &committed[..helper_end];
    let temp = TempDir::new().expect("tempdir");
    let harness = temp.path().join("harness.sh");
    std::fs::write(
        &harness,
        format!("{helpers}\nreplace_listen_port \"$1\" \"$2\"\n"),
    )
    .unwrap();

    let run = |addr: &str, port: &str| -> String {
        let out = Command::new("/bin/sh")
            .arg(&harness)
            .arg(addr)
            .arg(port)
            .output()
            .expect("run sh harness");
        assert!(
            out.status.success(),
            "harness failed for ({addr}, {port}): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout)
            .unwrap()
            .trim_end_matches('\n')
            .to_string()
    };

    // Valid ports replace ONLY the port and preserve the host part.
    assert_eq!(run("127.0.0.1:16680", "8080"), "127.0.0.1:8080");
    assert_eq!(run("192.168.1.1:16680", "1"), "192.168.1.1:1");
    assert_eq!(run("192.168.1.1:16680", "65535"), "192.168.1.1:65535");
    assert_eq!(run("[::1]:16680", "8443"), "[::1]:8443");
    assert_eq!(run(":16680", "9000"), ":9000");

    // Invalid ports are ignored completely, keeping the original listen address.
    for bad_port in [
        "",
        "0",
        "080",
        "-1",
        "65536",
        "99999",
        "999999999999999999999",
        "abc",
        "8080;id",
    ] {
        assert_eq!(
            run("127.0.0.1:16680", bad_port),
            "127.0.0.1:16680",
            "invalid port `{bad_port}` must be ignored"
        );
    }
}

#[test]
fn docker_custom_build_args_trim_packages() {
    let manifest = repo_manifest();
    let implemented = all_optional(&manifest);

    let resolve_mods = |mods: &str, lang: &str| {
        let resolved = resolve(
            &manifest,
            &ResolveOptions {
                modules: Some(mods.to_string()),
                lang: Some(lang.to_string()),
                ..ResolveOptions::default()
            },
            &implemented,
        )
        .expect("resolve");
        DockerBuildArgs::from_resolved(
            &manifest,
            &resolved,
            "v0.5.4",
            "deadbeef",
            "2026-11-28T00:00:00Z",
        )
    };

    let minimal = resolve_mods("", "zh");
    assert!(!minimal.with_docker_cli);
    assert!(!minimal.with_nftables);
    assert_eq!(minimal.ferrumgate_features, "lang-zh-cn");
    assert_eq!(minimal.ferrumgate_lang, "zh");
    assert_eq!(minimal.ferrumgate_locales, "zh-CN");

    let guard_only = resolve_mods("guard", "cjk-en");
    assert!(!guard_only.with_docker_cli);
    assert!(guard_only.with_nftables);

    let stun_only = resolve_mods("stun", "all");
    assert!(!stun_only.with_docker_cli);
    assert!(stun_only.with_nftables);

    let docker_only = resolve_mods("docker", "all");
    assert!(docker_only.with_docker_cli);
    assert!(!docker_only.with_nftables);

    let both = resolve_mods("docker,guard", "all");
    assert!(both.with_docker_cli);
    assert!(both.with_nftables);

    let tags = image_tags("v0.5.4", &["ghcr.io/houseme/ferrumgate"], true);
    assert_eq!(
        tags,
        [
            "ghcr.io/houseme/ferrumgate:0.5.4",
            "ghcr.io/houseme/ferrumgate:latest"
        ]
    );
    let rc_tags = image_tags("v0.5.4-rc.1", &["ghcr.io/houseme/ferrumgate"], true);
    assert_eq!(rc_tags, ["ghcr.io/houseme/ferrumgate:0.5.4-rc.1"]);

    let spec = DockerBuildSpec::new(minimal, tags, true);
    assert_eq!(spec.platforms, DOCKER_PLATFORMS);
    let args = docker_buildx_args(&spec);
    assert!(args.contains(&"linux/amd64,linux/arm64,linux/arm/v7".to_string()));
    assert!(args.contains(&"WITH_DOCKER_CLI=0".to_string()));
    assert!(args.contains(&"WITH_NFTABLES=0".to_string()));
    assert!(args.contains(&"--sbom=true".to_string()));
    assert!(args.contains(&"--provenance=mode=max".to_string()));
    assert!(args.contains(&"--push".to_string()));
}

#[test]
fn docker_nftables_pinned_to_1_1_1() {
    let dockerfile = std::fs::read_to_string(repo_root().join("deploy/Dockerfile"))
        .expect("deploy/Dockerfile exists");

    assert!(
        dockerfile.contains("FROM alpine:3.23"),
        "runtime image must be alpine:3.23"
    );
    assert!(
        dockerfile.contains("alpine/v3.21/main"),
        "nftables must be pulled from Alpine 3.21 repository"
    );
    assert!(
        dockerfile.contains("nftables=1.1.1"),
        "nftables must be pinned to 1.1.1 to avoid host nft list ruleset crash (WP-92 §2/§8)"
    );
    assert!(
        dockerfile.contains("iptables-legacy") && dockerfile.contains("ipset"),
        "fallback firewall tools must be installed with WITH_NFTABLES"
    );
    assert!(
        dockerfile.contains("/usr/sbin/iptables") && dockerfile.contains("rm -f"),
        "un-suffixed nf_tables iptables symlinks must be removed"
    );
    assert!(dockerfile.contains("ARG WITH_DOCKER_CLI"));
    assert!(dockerfile.contains("ARG WITH_NFTABLES"));
    assert!(dockerfile.contains("ENV FERRUMGATE_CONFIG_DIR=/etc/ferrumgate"));
    assert!(dockerfile.contains("VOLUME [\"/etc/ferrumgate\"]"));
    assert!(dockerfile.contains("EXPOSE 16680"));
}

#[test]
fn compose_example_parses() {
    let compose = std::fs::read_to_string(repo_root().join("deploy/docker-compose.yml"))
        .expect("deploy/docker-compose.yml exists");

    // Basic structural YAML sanity: no tabs, non-empty, valid key/list lines.
    assert!(
        !compose.contains('\t'),
        "docker-compose.yml must not contain tab characters"
    );
    for (lineno, raw) in compose.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        assert!(
            trimmed.starts_with("- ") || trimmed.contains(':'),
            "unexpected YAML syntax at line {}: `{raw}`",
            lineno + 1
        );
    }

    for required in [
        "services:",
        "ferrumgate:",
        "network_mode: host",
        "- NET_ADMIN",
        "- ./data:/etc/ferrumgate",
        "- /var/run/docker.sock:/var/run/docker.sock",
        "TZ=",
        "FERRUMGATE_LOG_LEVEL",
        "driver: json-file",
        "max-size: \"10m\"",
        "max-file: \"3\"",
    ] {
        assert!(
            compose.contains(required),
            "deploy/docker-compose.yml missing `{required}`"
        );
    }

    // Verify systemd unit file matches WP-95 requirements.
    let unit = std::fs::read_to_string(repo_root().join("deploy/systemd/ferrumgate.service"))
        .expect("deploy/systemd/ferrumgate.service exists");
    for required in [
        "After=network-online.target",
        "Wants=network-online.target",
        "Type=simple",
        "Restart=on-failure",
        "RestartSec=3",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN",
        "LimitNOFILE=1048576",
        "WantedBy=multi-user.target",
    ] {
        assert!(
            unit.contains(required),
            "deploy/systemd/ferrumgate.service missing `{required}`"
        );
    }
}

#[test]
fn external_tools_are_pinned_and_hash_checked() {
    assert!(!PINNED_TOOLS.is_empty());
    for tool in PINNED_TOOLS {
        assert!(!tool.name.is_empty(), "tool name must not be empty");
        assert!(!tool.version.is_empty(), "tool version must not be empty");
        assert!(!tool.source.is_empty(), "tool source must not be empty");
        assert!(
            is_valid_sha256(tool.sha256),
            "tool `{}` has invalid SHA-256: `{}`",
            tool.name,
            tool.sha256
        );
        if tool.kind == ToolKind::ContainerImage {
            let expected_suffix = format!("@sha256:{}", tool.sha256);
            assert!(
                tool.source.ends_with(&expected_suffix),
                "container image `{}` must pin its digest in source: {}",
                tool.name,
                tool.source
            );
        }
    }

    // Verify hash-check succeeds for matching payload and rejects tampered payload before staging.
    let temp = TempDir::new().expect("tempdir");
    let payload = b"fake-fnpack-binary-content";
    let digest = sha256_bytes(payload);
    let downloaded = temp.path().join("fnpack-download");
    std::fs::write(&downloaded, payload).unwrap();

    verify_file_sha256(&downloaded, &digest).expect("matching digest passes");
    assert!(verify_file_sha256(&downloaded, &"0".repeat(64)).is_err());

    let tool_root = temp.path().join("isolated-tools");
    let staged = verify_and_stage_tool(&FNPACK_TOOL, &downloaded, &tool_root, &digest)
        .expect("stage verified tool");
    assert!(staged.is_file());
    assert!(
        staged.starts_with(tool_root.join(format!("{}-{}", FNPACK_TOOL.name, FNPACK_TOOL.version)))
    );

    // Tampered download must fail before touching the isolated tool directory.
    let bad_download = temp.path().join("fnpack-tampered");
    std::fs::write(&bad_download, b"tampered-binary").unwrap();
    let bad_root = temp.path().join("isolated-bad");
    assert!(verify_and_stage_tool(&FNPACK_TOOL, &bad_download, &bad_root, &digest).is_err());
    assert!(!bad_root.exists());
}

#[test]
fn grafana_dashboard_uses_ferrumgate_prefix() {
    let raw = std::fs::read_to_string(repo_root().join("deploy/grafana/ferrumgate-dashboard.json"))
        .expect("deploy/grafana/ferrumgate-dashboard.json exists");
    assert!(
        !raw.contains("gately_"),
        "Grafana dashboard must not contain legacy gately_ metric prefix"
    );

    let dashboard: serde_json::Value =
        serde_json::from_str(&raw).expect("Grafana dashboard must be valid JSON");
    let panels = dashboard
        .get("panels")
        .and_then(|v| v.as_array())
        .expect("dashboard has panels array");
    assert!(!panels.is_empty(), "dashboard must define panels");

    let mut expr_count = 0usize;
    for panel in panels {
        let targets = panel
            .get("targets")
            .and_then(|v| v.as_array())
            .expect("panel has targets");
        for target in targets {
            let expr = target
                .get("expr")
                .and_then(|v| v.as_str())
                .expect("target has PromQL expr");
            assert!(
                expr.contains("ferrumgate_"),
                "PromQL expr must use ferrumgate_ prefix (D12): `{expr}`"
            );
            expr_count += 1;
        }
    }
    assert!(expr_count >= 10, "expected >= 10 metric expressions");
}

#[test]
fn release_workflow_triggers_on_tags_and_has_provenance() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/release.yml"))
        .expect(".github/workflows/release.yml exists");

    // Triggers on v* tags.
    assert!(workflow.contains("tags:"));
    assert!(workflow.contains("\"v*\""));

    // Has binaries and image jobs.
    assert!(workflow.contains("\n  binaries:\n"));
    assert!(workflow.contains("\n  image:\n"));

    // Minimal default permissions + checkout without persisting credentials.
    assert!(workflow.contains("\npermissions:\n  contents: read\n"));
    assert!(workflow.contains("persist-credentials: false"));

    // Multi-platform image with SBOM, max provenance, GHCR + optional Docker Hub login.
    assert!(workflow.contains("platforms: linux/amd64,linux/arm64,linux/arm/v7"));
    assert!(workflow.contains("sbom: true"));
    assert!(workflow.contains("provenance: mode=max"));
    assert!(workflow.contains("registry: ghcr.io"));
    assert!(workflow.contains("DOCKERHUB_USERNAME"));
    assert!(workflow.contains("DOCKERHUB_TOKEN"));

    // Every action reference is pinned to a version tag or SHA (never floating).
    for line in workflow
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("uses:") || line.starts_with("- uses:"))
    {
        let reference = line.trim_start_matches("- ").trim();
        let Some((_, version)) = reference.split_once('@') else {
            panic!("action reference must be pinned with @: {line}");
        };
        assert!(
            !matches!(version, "main" | "master" | ""),
            "action must not use floating ref: {line}"
        );
    }
}
