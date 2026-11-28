//! WP-94: Update checking, advisory evaluation, caching, notification
//! deduplication, online self-upgrade, and manual binary upload upgrade.

pub mod advisories;
pub mod cache;
pub mod check;
pub mod programs;
pub mod upgrade;
pub mod version;

pub use advisories::{
    DEFAULT_REPO_BASE, GhAdvisory, GhAdvisoryPackage, GhAdvisoryVulnerability, GhAsset, GhRelease,
    MAX_ADVISORY_SUMMARY, MAX_NOTES_BYTES, ReleaseBrief, SecurityAdvisory, affects,
    has_security_section, parse_advisories, parse_advisories_for_repo, parse_releases,
    parse_releases_for_repo, sanitize_repo_url,
};
pub use cache::{
    CACHE_FILE, CHECK_DELAY, CHECK_INTERVAL, CHECK_RETRY, PendingNotification, ProgramUpdate,
    UpdateCache, UpdateView, compute_view, load_cache, next_check, pending_notifications,
    save_cache,
};
pub use check::{
    CHECK_TIMEOUT, DEFAULT_API_BASE, DEFAULT_SELF_PACKAGE, FetchFn, FetchFuture, FetchRequest,
    FetchResponse, MANUAL_CHECK_MIN_GAP, MAX_ADVISORIES_BODY, MAX_RELEASES_BODY, UpdateChecker,
    UpdateCheckerConfig, UpdateSettingsSnapshot,
};
pub use programs::{PROGRAM_CHECK_TIMEOUT, ProgramCheckFuture, ProgramCheckResult, ProgramChecker};
pub use upgrade::{
    UPGRADE_TIMEOUT, UpgradeManager, UpgradeManagerConfig,
    download::{
        FIRST_SIGNED_RELEASE, KeyVerifyFn, MAX_CHECKSUMS_BODY, MAX_SIGNATURE_BODY,
        MAX_UPGRADE_ARCHIVE, MAX_UPGRADE_BINARY, SignatureVerifier, checksum_for, extract_binary,
        release_requires_signature, verify_release_signature, verify_sha256,
    },
    install::{PROBE_TIMEOUT, install_binary, probe_binary},
    mount_update_routes,
    status::{CancelOutcome, UpgradeState, UpgradeStatus, UpgradeTracker},
    support::{
        DeployEnv, UpgradeReason, UpgradeSupport, deploy_upgrade_support, detect_upgrade_support,
        executable_dir_writable,
    },
};
pub use version::{
    ParsedVersion, compare_version, parse_loose_version, parse_version, release_base,
    version_comparable, version_in_range, version_newer,
};

/// RFC 3339 serde helpers backed by `time::format_description::well_known::Rfc3339`
/// so `fg-admin` does not depend on `time`'s optional `serde` crate feature.
pub(crate) mod rfc3339 {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    pub mod option {
        use super::*;
        use serde::{Deserialize, Deserializer, Serializer, de};

        pub fn serialize<S: Serializer>(
            value: &Option<OffsetDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(dt) => {
                    let formatted = dt.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
                    serializer.serialize_some(&formatted)
                }
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<OffsetDateTime>, D::Error> {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(s) if !s.trim().is_empty() => OffsetDateTime::parse(s.trim(), &Rfc3339)
                    .map(Some)
                    .map_err(de::Error::custom),
                _ => Ok(None),
            }
        }
    }

    pub mod map {
        use super::*;
        use serde::{Deserialize, Deserializer, Serializer, de, ser::SerializeMap};
        use std::collections::HashMap;

        pub fn serialize<S: Serializer>(
            value: &HashMap<String, OffsetDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(value.len()))?;
            for (k, dt) in value {
                let formatted = dt.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
                map.serialize_entry(k, &formatted)?;
            }
            map.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<HashMap<String, OffsetDateTime>, D::Error> {
            let raw = HashMap::<String, String>::deserialize(deserializer)?;
            let mut out = HashMap::with_capacity(raw.len());
            for (k, s) in raw {
                let dt = OffsetDateTime::parse(s.trim(), &Rfc3339).map_err(de::Error::custom)?;
                out.insert(k, dt);
            }
            Ok(out)
        }
    }
}
