//! Parsing GitHub Releases and Security Advisories, detecting security-fix
//! sections in release notes, sanitizing repository URLs, and evaluating
//! whether an advisory affects a given version.

use std::cmp::Ordering;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use super::{
    rfc3339,
    version::{
        ParsedVersion, compare_version, parse_loose_version, parse_version, version_in_range,
    },
};

/// Default repository URL used for sanitizing release and advisory links.
pub const DEFAULT_REPO_BASE: &str = "https://github.com/houseme/ferrumgate";

/// Maximum cached release notes size (64 KiB).
pub const MAX_NOTES_BYTES: usize = 64 << 10;

/// Maximum advisory summary length in Unicode scalar values (300 chars).
pub const MAX_ADVISORY_SUMMARY: usize = 300;

/// GitHub Release asset entry returned by `/releases`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhAsset {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
}

/// GitHub Release object returned by `/releases?per_page=100`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhRelease {
    #[serde(default)]
    pub tag_name: String,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default, with = "rfc3339::option")]
    pub published_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub assets: Vec<GhAsset>,
}

/// Package metadata inside a GitHub Security Advisory vulnerability entry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhAdvisoryPackage {
    #[serde(default)]
    pub ecosystem: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Vulnerability entry inside a GitHub Security Advisory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhAdvisoryVulnerability {
    #[serde(default)]
    pub package: Option<GhAdvisoryPackage>,
    #[serde(default)]
    pub vulnerable_version_range: Option<String>,
    #[serde(default)]
    pub first_patched_version: Option<String>,
    #[serde(default)]
    pub patched_versions: Option<String>,
}

/// GitHub Repository Security Advisory returned by
/// `/security-advisories?state=published&per_page=100`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhAdvisory {
    #[serde(default)]
    pub ghsa_id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub state: String,
    #[serde(default, with = "rfc3339::option")]
    pub withdrawn_at: Option<OffsetDateTime>,
    #[serde(default, with = "rfc3339::option")]
    pub published_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub vulnerabilities: Vec<GhAdvisoryVulnerability>,
}

/// Cached summary of a single release.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseBrief {
    pub tag: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    #[schemars(with = "Option<String>")]
    pub published_at: Option<OffsetDateTime>,
}

/// Cached published security advisory relevant to this package.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecurityAdvisory {
    pub ghsa_id: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub url: String,
    pub vulnerable_version_range: String,
    pub patched_versions: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    #[schemars(with = "Option<String>")]
    pub published_at: Option<OffsetDateTime>,
}

/// Parses GitHub releases using [`DEFAULT_REPO_BASE`] for URL sanitization.
///
/// Returns `(latest_release, latest_notes, security_releases)`. Drafts,
/// pre-releases, and releases with unparseable tags are ignored.
pub fn parse_releases(list: &[GhRelease]) -> (Option<ReleaseBrief>, String, Vec<ReleaseBrief>) {
    parse_releases_for_repo(list, DEFAULT_REPO_BASE)
}

/// Parses GitHub releases, sanitizing links against `repo_base`.
pub fn parse_releases_for_repo(
    list: &[GhRelease],
    repo_base: &str,
) -> (Option<ReleaseBrief>, String, Vec<ReleaseBrief>) {
    let mut latest: Option<(ParsedVersion, ReleaseBrief, String)> = None;
    let mut security_releases: Vec<(ParsedVersion, ReleaseBrief)> = Vec::new();

    for release in list {
        if release.draft || release.prerelease {
            continue;
        }
        let tag = release.tag_name.trim();
        let Some(parsed) = parse_version(tag) else {
            continue;
        };
        let url = sanitize_repo_url(&release.html_url, repo_base, &format!("releases/tag/{tag}"));
        let notes = truncate_utf8_bytes(&release.body, MAX_NOTES_BYTES);

        let is_newer = latest
            .as_ref()
            .is_none_or(|(best, _, _)| compare_version(&parsed, best) == Ordering::Greater);
        if is_newer {
            latest = Some((
                parsed.clone(),
                ReleaseBrief {
                    tag: tag.to_owned(),
                    url: url.clone(),
                    notes: String::new(),
                    published_at: release.published_at,
                },
                notes,
            ));
        }

        if has_security_section(&release.body) {
            security_releases.push((
                parsed,
                ReleaseBrief {
                    tag: tag.to_owned(),
                    url,
                    notes: String::new(),
                    published_at: release.published_at,
                },
            ));
        }
    }

    security_releases.sort_by(|(a, _), (b, _)| compare_version(b, a));
    let security_releases = security_releases
        .into_iter()
        .map(|(_, brief)| brief)
        .collect();

    match latest {
        Some((_, brief, notes)) => (Some(brief), notes, security_releases),
        None => (None, String::new(), security_releases),
    }
}

/// Returns `true` if `body` contains a Markdown heading announcing security
/// fixes, updates, hardening, advisories, patches, issues, or vulnerabilities.
///
/// Fenced code blocks (` ``` ` and `~~~`) are skipped. Feature headings like
/// `安全入口` are ignored.
pub fn has_security_section(body: &str) -> bool {
    let mut in_fence: Option<(char, usize)> = None;

    for raw_line in body.lines() {
        let trimmed_start = raw_line.trim_start_matches(' ');
        let leading_spaces = raw_line.len() - trimmed_start.len();

        if let Some((fence_char, fence_len)) = in_fence {
            if leading_spaces <= 3 {
                let count = trimmed_start
                    .chars()
                    .take_while(|&c| c == fence_char)
                    .count();
                if count >= fence_len && trimmed_start[count..].trim().is_empty() {
                    in_fence = None;
                }
            }
            continue;
        }

        if leading_spaces <= 3
            && let Some(first) = trimmed_start.chars().next()
            && (first == '`' || first == '~')
        {
            let count = trimmed_start.chars().take_while(|&c| c == first).count();
            if count >= 3 {
                // Backtick info strings may not contain backticks (CommonMark).
                let info = &trimmed_start[count..];
                if first == '~' || !info.contains('`') {
                    in_fence = Some((first, count));
                    continue;
                }
            }
        }

        if leading_spaces > 3 {
            continue;
        }

        let hashes = trimmed_start.bytes().take_while(|&b| b == b'#').count();
        if !(1..=6).contains(&hashes) {
            continue;
        }
        let rest = &trimmed_start[hashes..];
        if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
            continue;
        }
        let heading = clean_heading(rest);
        if is_security_heading(&heading) {
            return true;
        }
    }
    false
}

fn clean_heading(raw: &str) -> String {
    // Strip optional closing ATX hashes and surrounding whitespace.
    let s = raw.trim().trim_end_matches('#').trim();
    // Strip leading formatting / emoji / punctuation until first alphanumeric or CJK char.
    let stripped = s.trim_start_matches(|c: char| !c.is_alphanumeric());
    stripped.trim_matches(['*', '_', '`']).trim().to_owned()
}

fn is_security_heading(heading: &str) -> bool {
    if heading.is_empty() {
        return false;
    }

    const ZH_PREFIXES: &[&str] = &[
        "安全修复",
        "安全更新",
        "安全加固",
        "安全问题",
        "安全公告",
        "安全补丁",
        "安全漏洞",
    ];
    if ZH_PREFIXES.iter().any(|prefix| heading.starts_with(prefix)) {
        return true;
    }

    let lower = heading.to_ascii_lowercase();
    if let Some(after) = lower.strip_prefix("security") {
        // Must be followed by a separator and one of the security-fix nouns.
        let mut chars = after.chars();
        let Some(sep) = chars.next() else {
            return false;
        };
        if sep.is_ascii_alphanumeric() {
            return false;
        }
        let next_word = after
            .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap_or("");
        const EN_KEYWORDS: &[&str] = &[
            "fix",
            "fixes",
            "fixed",
            "update",
            "updates",
            "updated",
            "harden",
            "hardened",
            "hardening",
            "advisory",
            "advisories",
            "patch",
            "patches",
            "patched",
            "issue",
            "issues",
            "vulnerability",
            "vulnerabilities",
        ];
        return EN_KEYWORDS.contains(&next_word);
    }

    false
}

/// Parses published, non-withdrawn GitHub security advisories affecting
/// `self_package`, sanitizing links against [`DEFAULT_REPO_BASE`].
pub fn parse_advisories(list: &[GhAdvisory], self_package: &str) -> Vec<SecurityAdvisory> {
    parse_advisories_for_repo(list, self_package, DEFAULT_REPO_BASE)
}

/// Parses published, non-withdrawn GitHub security advisories affecting
/// `self_package`, sanitizing links against `repo_base`.
pub fn parse_advisories_for_repo(
    list: &[GhAdvisory],
    self_package: &str,
    repo_base: &str,
) -> Vec<SecurityAdvisory> {
    let mut result = Vec::new();
    for adv in list {
        if !adv.state.eq_ignore_ascii_case("published") || adv.withdrawn_at.is_some() {
            continue;
        }
        let ghsa_id = adv.ghsa_id.trim();
        if ghsa_id.is_empty() {
            continue;
        }
        let Some(vuln) = adv
            .vulnerabilities
            .iter()
            .find(|v| vulnerability_matches_package(v, self_package))
        else {
            continue;
        };
        let range = vuln
            .vulnerable_version_range
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_owned();
        let patched = vuln
            .first_patched_version
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                vuln.patched_versions
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or("")
            .to_owned();
        let summary = truncate_chars(adv.summary.trim(), MAX_ADVISORY_SUMMARY);
        let url = sanitize_repo_url(
            &adv.html_url,
            repo_base,
            &format!("security/advisories/{ghsa_id}"),
        );
        let severity = adv
            .severity
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase());
        result.push(SecurityAdvisory {
            ghsa_id: ghsa_id.to_owned(),
            summary,
            severity,
            url,
            vulnerable_version_range: range,
            patched_versions: patched,
            published_at: adv.published_at,
        });
    }
    result
}

fn vulnerability_matches_package(vuln: &GhAdvisoryVulnerability, self_package: &str) -> bool {
    let target = self_package.trim();
    if target.is_empty() {
        return true;
    }
    let Some(name) = vuln
        .package
        .as_ref()
        .and_then(|pkg| pkg.name.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return false;
    };
    if name.eq_ignore_ascii_case(target) {
        return true;
    }
    // Support full module paths like `github.com/houseme/ferrumgate`.
    name.rsplit_once('/')
        .is_some_and(|(_, tail)| tail.eq_ignore_ascii_case(target))
}

/// Evaluates whether `adv` affects `cur`.
///
/// Uses [`version_in_range`] on `adv.vulnerable_version_range`. If the range is
/// empty or unparseable, falls back to comparing `cur < patched_versions`.
pub fn affects(adv: &SecurityAdvisory, cur: &ParsedVersion) -> bool {
    let (matched, parsed) = version_in_range(cur, &adv.vulnerable_version_range);
    if parsed {
        return matched;
    }
    parse_patched_version(&adv.patched_versions)
        .is_some_and(|patched| compare_version(cur, &patched) == Ordering::Less)
}

fn parse_patched_version(raw: &str) -> Option<ParsedVersion> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let token = s.split(',').next()?.trim();
    let stripped = token
        .strip_prefix(">=")
        .or_else(|| token.strip_prefix("=="))
        .or_else(|| token.strip_prefix('='))
        .unwrap_or(token)
        .trim();
    parse_loose_version(stripped)
}

/// Ensures `raw` points inside `repo_base` over HTTPS; otherwise constructs a
/// canonical link under `repo_base` using `fallback_path`.
pub fn sanitize_repo_url(raw: &str, repo_base: &str, fallback_path: &str) -> String {
    let fallback = format!(
        "{}/{}",
        repo_base.trim_end_matches('/'),
        fallback_path.trim_start_matches('/')
    );
    let (Ok(candidate), Ok(base)) = (Url::parse(raw.trim()), Url::parse(repo_base.trim())) else {
        return fallback;
    };
    let same_host = match (candidate.host_str(), base.host_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    };
    let base_path = base.path().trim_end_matches('/');
    let cand_path = candidate.path();
    let path_inside = cand_path == base_path
        || cand_path
            .strip_prefix(base_path)
            .is_some_and(|rest| rest.starts_with('/'));
    if candidate.scheme() == "https"
        && same_host
        && candidate.port() == base.port()
        && candidate.username().is_empty()
        && candidate.password().is_none()
        && path_inside
    {
        candidate.to_string()
    } else {
        fallback
    }
}

pub(crate) fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_owned();
    }
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_releases_ignores_drafts_and_prereleases() {
        let releases = vec![
            GhRelease {
                tag_name: "v0.9.0".into(),
                html_url: "https://github.com/houseme/ferrumgate/releases/tag/v0.9.0".into(),
                body: "## Security Fixes\n- fix".into(),
                draft: true,
                prerelease: false,
                ..Default::default()
            },
            GhRelease {
                tag_name: "v0.8.0-rc.1".into(),
                html_url: "https://github.com/houseme/ferrumgate/releases/tag/v0.8.0-rc.1".into(),
                body: "## 安全修复\n- fix".into(),
                draft: false,
                prerelease: true,
                ..Default::default()
            },
            GhRelease {
                tag_name: "nightly".into(),
                html_url: "https://github.com/houseme/ferrumgate/releases/tag/nightly".into(),
                body: "nightly".into(),
                ..Default::default()
            },
            GhRelease {
                tag_name: "v0.6.2".into(),
                html_url: "https://evil.example/phish".into(),
                body: "## Features\n- normal".into(),
                ..Default::default()
            },
            GhRelease {
                tag_name: "v0.7.0".into(),
                html_url: "https://github.com/houseme/ferrumgate/releases/tag/v0.7.0".into(),
                body: format!("## 安全修复\n{}", "a".repeat(MAX_NOTES_BYTES + 100)),
                ..Default::default()
            },
        ];

        let (latest, notes, sec) = parse_releases(&releases);
        let latest = latest.expect("latest release");
        assert_eq!(latest.tag, "v0.7.0");
        assert_eq!(
            latest.url,
            "https://github.com/houseme/ferrumgate/releases/tag/v0.7.0"
        );
        assert_eq!(notes.len(), MAX_NOTES_BYTES);
        assert_eq!(sec.len(), 1);
        assert_eq!(sec[0].tag, "v0.7.0");

        // Verify external URL sanitization falls back to canonical repo URL.
        let (latest_only, _, _) = parse_releases(&releases[3..4]);
        assert_eq!(
            latest_only.unwrap().url,
            "https://github.com/houseme/ferrumgate/releases/tag/v0.6.2"
        );
    }

    #[test]
    fn has_security_section_skips_code_blocks() {
        // Code blocks must be ignored.
        let in_backticks = "Intro\n```markdown\n## Security Fixes\n- inside fence\n```\nDone";
        assert!(!has_security_section(in_backticks));

        let in_tildes = "Intro\n~~~\n### 安全修复\n~~~\n";
        assert!(!has_security_section(in_tildes));

        // Feature names must not trigger false positives.
        assert!(!has_security_section("## 安全入口\n新增安全入口设置"));
        assert!(!has_security_section("## Security Entry\nAdded safe path"));
        assert!(!has_security_section("## Security Score\nAdded scoring"));

        // Matching Chinese and English security headings.
        for heading in [
            "## 安全修复\n- 修复越权",
            "### 安全更新",
            "## 🔒 安全加固",
            "## 安全问题",
            "## Security Fixes",
            "### Security Update",
            "## Security Hardening",
            "## Security Advisory",
            "## Security Patch",
            "## Security Issues",
            "## Security Vulnerability",
            "## Security: Fix auth bypass",
        ] {
            assert!(
                has_security_section(heading),
                "expected security section match for: {heading:?}"
            );
        }
    }

    #[test]
    fn parse_advisories_filters_withdrawn_and_other_packages() {
        let long_summary = "x".repeat(MAX_ADVISORY_SUMMARY + 50);
        let list = vec![
            GhAdvisory {
                ghsa_id: "GHSA-1111-1111-1111".into(),
                summary: long_summary,
                severity: Some("HIGH".into()),
                html_url: "https://evil.example/ghsa".into(),
                state: "published".into(),
                vulnerabilities: vec![GhAdvisoryVulnerability {
                    package: Some(GhAdvisoryPackage {
                        ecosystem: Some("cargo".into()),
                        name: Some("ferrumgate".into()),
                    }),
                    vulnerable_version_range: Some("< 0.6.2".into()),
                    first_patched_version: Some("0.6.2".into()),
                    patched_versions: None,
                }],
                ..Default::default()
            },
            GhAdvisory {
                ghsa_id: "GHSA-2222-2222-2222".into(),
                summary: "withdrawn".into(),
                state: "published".into(),
                withdrawn_at: Some(OffsetDateTime::UNIX_EPOCH),
                vulnerabilities: vec![GhAdvisoryVulnerability {
                    package: Some(GhAdvisoryPackage {
                        ecosystem: None,
                        name: Some("ferrumgate".into()),
                    }),
                    vulnerable_version_range: Some("< 0.6.2".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            GhAdvisory {
                ghsa_id: "GHSA-3333-3333-3333".into(),
                summary: "draft".into(),
                state: "draft".into(),
                vulnerabilities: vec![GhAdvisoryVulnerability {
                    package: Some(GhAdvisoryPackage {
                        ecosystem: None,
                        name: Some("ferrumgate".into()),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
            GhAdvisory {
                ghsa_id: "GHSA-4444-4444-4444".into(),
                summary: "other package".into(),
                state: "published".into(),
                vulnerabilities: vec![GhAdvisoryVulnerability {
                    package: Some(GhAdvisoryPackage {
                        ecosystem: None,
                        name: Some("unrelated-pkg".into()),
                    }),
                    vulnerable_version_range: Some("< 1.0.0".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ];

        let parsed = parse_advisories(&list, "ferrumgate");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ghsa_id, "GHSA-1111-1111-1111");
        assert_eq!(parsed[0].summary.chars().count(), MAX_ADVISORY_SUMMARY);
        assert_eq!(parsed[0].severity.as_deref(), Some("high"));
        assert_eq!(
            parsed[0].url,
            "https://github.com/houseme/ferrumgate/security/advisories/GHSA-1111-1111-1111"
        );
    }

    #[test]
    fn advisory_affects_falls_back_to_patched_version() {
        let cur = parse_version("v0.6.0").unwrap();

        // Parseable range takes precedence over patched_versions.
        let ranged = SecurityAdvisory {
            vulnerable_version_range: ">= 0.5.0, < 0.6.0".into(),
            patched_versions: "0.7.0".into(),
            ..Default::default()
        };
        assert!(!affects(&ranged, &cur));

        // Unparseable range falls back to `< patched_versions`.
        let fallback_affected = SecurityAdvisory {
            vulnerable_version_range: "unparseable range".into(),
            patched_versions: "0.6.1".into(),
            ..Default::default()
        };
        assert!(affects(&fallback_affected, &cur));

        let fallback_patched = SecurityAdvisory {
            vulnerable_version_range: "".into(),
            patched_versions: "0.6.0".into(),
            ..Default::default()
        };
        assert!(!affects(&fallback_patched, &cur));

        let neither = SecurityAdvisory {
            vulnerable_version_range: "bad".into(),
            patched_versions: "bad".into(),
            ..Default::default()
        };
        assert!(!affects(&neither, &cur));
    }
}
