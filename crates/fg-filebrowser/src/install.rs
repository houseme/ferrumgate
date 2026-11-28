//! Online install integration (WP-66 step 4). The authoritative
//! [`fg_proc::install::FILEBROWSER`] spec was corrected to the maintained
//! FileBrowser **Quantum** fork (`gtsteffaniak/filebrowser`) during this
//! module's landing — this file documents the corrected contract and
//! keeps the asset-matching tests next to the module that depends on it.

pub use fg_proc::install::FILEBROWSER as SPEC;

#[cfg(test)]
mod tests {
    use super::*;
    use fg_proc::Platform;
    use fg_proc::install::ChecksumSource;
    use fg_proc::install::spec::match_asset;

    #[test]
    fn spec_targets_the_quantum_fork() {
        assert_eq!(SPEC.name, "filebrowser");
        assert_eq!(SPEC.main_file(), "filebrowser");
        let pattern = SPEC.asset_pattern().expect("github source");
        assert!(
            pattern.ends_with("-filebrowser"),
            "quantum assets are bare binaries: {pattern}"
        );
        assert!(matches!(
            SPEC.source,
            fg_proc::install::ReleaseSource::Github {
                repo: "gtsteffaniak/filebrowser",
                checksum: ChecksumSource::AssetDigest,
                ..
            }
        ));
    }

    #[test]
    fn asset_names_match_quantum_releases() {
        // Verified against the v2.1.0-stable release assets.
        for (os, arch, asset) in [
            ("linux", "amd64", "linux-amd64-filebrowser"),
            ("linux", "arm64", "linux-arm64-filebrowser"),
            ("darwin", "arm64", "darwin-arm64-filebrowser"),
        ] {
            let platform = Platform::from_parts(os, arch);
            assert!(
                match_asset(SPEC.asset_pattern().unwrap(), asset, &platform, "2.1.0"),
                "{asset} must match"
            );
        }
    }

    #[test]
    fn windows_bare_exe_is_explicitly_unmatched() {
        // Quantum ships `filebrowser.exe` (no platform prefix); the single
        // pattern cannot express both shapes, so Windows installs fail
        // loudly until WP-92 extends the matcher.
        let platform = Platform::from_parts("windows", "amd64");
        assert!(!match_asset(
            SPEC.asset_pattern().unwrap(),
            "filebrowser.exe",
            &platform,
            "2.1.0"
        ));
    }
}
