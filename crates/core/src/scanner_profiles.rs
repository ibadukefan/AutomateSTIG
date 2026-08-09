//! Immutable metadata for scanner profiles shipped with this release.
//!
//! The catalog is built entirely from content compiled into `automatestig-core`.
//! Listing it never reads or mutates a local STIG library. Construction fails
//! closed when supported-target metadata, an embedded check pack, or its
//! coverage manifest no longer agree.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::check_packs::{
    canonical_json_sha256, embedded_check_pack_bytes, embedded_check_pack_paths, validate_pack,
};
use crate::checks::{CheckPack, CheckPlatform};
use crate::coverage::{
    parse_coverage_manifest, validate_coverage_manifest, CoverageManifest, CoverageStatus,
    RuleCoverageClassification,
};

const SUPPORTED_TARGETS_SCHEMA: &str = "../schemas/supported-targets.schema.json";
const SUPPORTED_TARGETS_SCHEMA_VERSION: u32 = 1;
const SUPPORTED_RELEASE_LINE: &str = "0.3";
const EXPECTED_TARGET_KEYS: [&str; 3] =
    ["netapp_ontap9", "freebsd_gpos", "cisco_ios_xe_router_ndm"];

const SUPPORTED_TARGETS_JSON: &[u8] = include_bytes!("../../../content/supported-targets.json");
const NETAPP_COVERAGE_JSON: &[u8] =
    include_bytes!("../../../content/coverage/current-checkpacks/netapp_ontap9.current.json");
const FREEBSD_COVERAGE_JSON: &[u8] =
    include_bytes!("../../../content/coverage/current-checkpacks/freebsd_gpos.current.json");
const CISCO_COVERAGE_JSON: &[u8] = include_bytes!(
    "../../../content/coverage/current-checkpacks/cisco_ios_xe_router_ndm.current.json"
);

const BUNDLED_COVERAGE_PATHS: [&str; 3] = [
    "content/coverage/current-checkpacks/netapp_ontap9.current.json",
    "content/coverage/current-checkpacks/freebsd_gpos.current.json",
    "content/coverage/current-checkpacks/cisco_ios_xe_router_ndm.current.json",
];

static BUNDLED_CATALOG: OnceLock<std::result::Result<ScannerProfileCatalog, String>> =
    OnceLock::new();

/// How a profile obtains the evidence consumed by its checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerEvidenceMode {
    SshTranscript,
    RunningConfiguration,
}

/// Live-acceptance family that must validate a profile before promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerAcceptanceGate {
    Ontap,
    Freebsd,
    CiscoIosXe,
}

/// Release readiness copied from the reviewed coverage manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerProfileReadiness {
    Experimental,
    Supported,
    Production,
}

impl From<CoverageStatus> for ScannerProfileReadiness {
    fn from(value: CoverageStatus) -> Self {
        match value {
            CoverageStatus::Experimental => Self::Experimental,
            CoverageStatus::Supported => Self::Supported,
            CoverageStatus::Production => Self::Production,
        }
    }
}

/// Coverage counts retained separately so callers never confuse reviewed
/// benchmark scope with the automated subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScannerCoverageCounts {
    benchmark_rules: usize,
    reviewed_rules: usize,
    automated_checks: usize,
    manual_rules: usize,
    not_applicable_rules: usize,
    unsupported_rules: usize,
}

impl ScannerCoverageCounts {
    pub fn benchmark_rules(&self) -> usize {
        self.benchmark_rules
    }

    pub fn reviewed_rules(&self) -> usize {
        self.reviewed_rules
    }

    pub fn automated_checks(&self) -> usize {
        self.automated_checks
    }

    pub fn manual_rules(&self) -> usize {
        self.manual_rules
    }

    pub fn not_applicable_rules(&self) -> usize {
        self.not_applicable_rules
    }

    pub fn unsupported_rules(&self) -> usize {
        self.unsupported_rules
    }
}

/// Semantic digests for the executable pack, reviewed coverage, and their
/// fully bound scanner profile.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ScannerProfileDigests {
    check_pack_sha256: Box<str>,
    coverage_manifest_sha256: Box<str>,
    profile_sha256: Box<str>,
}

impl ScannerProfileDigests {
    /// Matches the digest produced when this single embedded pack is the
    /// effective check-pack set (including its embedded priority of zero).
    pub fn check_pack_sha256(&self) -> &str {
        &self.check_pack_sha256
    }

    pub fn coverage_manifest_sha256(&self) -> &str {
        &self.coverage_manifest_sha256
    }

    pub fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }
}

/// One release-bundled, scanner-capable target profile.
///
/// Fields are private and the catalog returns shared static references, making
/// the release contract immutable to callers while remaining serializable.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ScannerProfile {
    target_key: Box<str>,
    display_name: Box<str>,
    platform: CheckPlatform,
    stig_id: Box<str>,
    stig_release: Box<str>,
    evidence_mode: ScannerEvidenceMode,
    check_pack_path: Box<str>,
    coverage_manifest_path: Box<str>,
    coverage: ScannerCoverageCounts,
    digests: ScannerProfileDigests,
    readiness: ScannerProfileReadiness,
    acceptance_gate: ScannerAcceptanceGate,
}

impl ScannerProfile {
    pub fn target_key(&self) -> &str {
        &self.target_key
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn platform(&self) -> CheckPlatform {
        self.platform
    }

    pub fn stig_id(&self) -> &str {
        &self.stig_id
    }

    pub fn stig_release(&self) -> &str {
        &self.stig_release
    }

    pub fn evidence_mode(&self) -> ScannerEvidenceMode {
        self.evidence_mode
    }

    pub fn check_pack_path(&self) -> &str {
        &self.check_pack_path
    }

    pub fn coverage_manifest_path(&self) -> &str {
        &self.coverage_manifest_path
    }

    pub fn coverage(&self) -> ScannerCoverageCounts {
        self.coverage
    }

    pub fn digests(&self) -> &ScannerProfileDigests {
        &self.digests
    }

    pub fn readiness(&self) -> ScannerProfileReadiness {
        self.readiness
    }

    pub fn acceptance_gate(&self) -> ScannerAcceptanceGate {
        self.acceptance_gate
    }
}

/// Release-level wrapper around the immutable profiles and their source
/// manifest provenance.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ScannerProfileCatalog {
    schema_version: u32,
    release_line: Box<str>,
    supported_targets_sha256: Box<str>,
    profiles: Box<[ScannerProfile]>,
}

impl ScannerProfileCatalog {
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn release_line(&self) -> &str {
        &self.release_line
    }

    pub fn supported_targets_sha256(&self) -> &str {
        &self.supported_targets_sha256
    }

    pub fn profiles(&self) -> &[ScannerProfile] {
        &self.profiles
    }

    pub fn profile(&self, target_key: &str) -> Option<&ScannerProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.target_key() == target_key)
    }
}

/// Return the validated catalog compiled into this release.
///
/// This operation has no filesystem or mutable-library dependency. Any drift
/// between the three bundled contracts is returned as an integrity error and
/// cached for the lifetime of the process.
pub fn bundled_scanner_profile_catalog() -> crate::Result<&'static ScannerProfileCatalog> {
    match BUNDLED_CATALOG.get_or_init(build_bundled_catalog) {
        Ok(catalog) => Ok(catalog),
        Err(message) => Err(crate::Error::Other(message.clone())),
    }
}

/// Convenience view over [`bundled_scanner_profile_catalog`].
pub fn bundled_scanner_profiles() -> crate::Result<&'static [ScannerProfile]> {
    Ok(bundled_scanner_profile_catalog()?.profiles())
}

/// Look up one bundled profile without opening a local STIG library.
pub fn bundled_scanner_profile(target_key: &str) -> crate::Result<Option<&'static ScannerProfile>> {
    Ok(bundled_scanner_profile_catalog()?.profile(target_key))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportedTargetsManifest {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u32,
    release_line: String,
    targets: BTreeMap<String, SupportedTarget>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportedTarget {
    display_name: String,
    stig_id: String,
    stig_release: String,
    platform: CheckPlatform,
    evidence_mode: ScannerEvidenceMode,
    expected_benchmark_rules: usize,
    expected_automated_checks: usize,
    expected_reviewed_rules: usize,
    check_pack: String,
    coverage_manifest: String,
    acceptance_gate: ScannerAcceptanceGate,
}

#[derive(Serialize)]
struct ProfileDigestBinding<'a> {
    target_key: &'a str,
    display_name: &'a str,
    platform: CheckPlatform,
    stig_id: &'a str,
    stig_release: &'a str,
    evidence_mode: ScannerEvidenceMode,
    check_pack_path: &'a str,
    coverage_manifest_path: &'a str,
    coverage: ScannerCoverageCounts,
    check_pack_sha256: &'a str,
    coverage_manifest_sha256: &'a str,
    readiness: ScannerProfileReadiness,
    acceptance_gate: ScannerAcceptanceGate,
}

fn build_bundled_catalog() -> std::result::Result<ScannerProfileCatalog, String> {
    let embedded_paths = embedded_check_pack_paths();
    build_catalog_from_sources(
        SUPPORTED_TARGETS_JSON,
        &embedded_paths,
        embedded_check_pack_bytes,
        |path| bundled_coverage_bytes(path).map(<[u8]>::to_vec),
    )
}

fn bundled_coverage_bytes(path: &str) -> Option<&'static [u8]> {
    match path {
        "content/coverage/current-checkpacks/netapp_ontap9.current.json" => {
            Some(NETAPP_COVERAGE_JSON)
        }
        "content/coverage/current-checkpacks/freebsd_gpos.current.json" => {
            Some(FREEBSD_COVERAGE_JSON)
        }
        "content/coverage/current-checkpacks/cisco_ios_xe_router_ndm.current.json" => {
            Some(CISCO_COVERAGE_JSON)
        }
        _ => None,
    }
}

fn build_catalog_from_sources<CheckPackBytes, CoverageBytes>(
    supported_targets_json: &[u8],
    embedded_pack_paths: &[String],
    mut check_pack_bytes: CheckPackBytes,
    mut coverage_bytes: CoverageBytes,
) -> std::result::Result<ScannerProfileCatalog, String>
where
    CheckPackBytes: FnMut(&str) -> Option<Vec<u8>>,
    CoverageBytes: FnMut(&str) -> Option<Vec<u8>>,
{
    let manifest: SupportedTargetsManifest = serde_json::from_slice(supported_targets_json)
        .map_err(|error| drift(format!("supported-targets JSON is invalid: {error}")))?;
    validate_manifest_header(&manifest)?;
    validate_target_keys(&manifest.targets)?;

    let referenced_pack_paths: BTreeSet<_> = manifest
        .targets
        .values()
        .map(|target| embedded_pack_path(&target.check_pack).map(str::to_owned))
        .collect::<std::result::Result<_, _>>()?;
    let actual_pack_paths: BTreeSet<_> = embedded_pack_paths.iter().cloned().collect();
    if referenced_pack_paths != actual_pack_paths {
        return Err(drift(format!(
            "supported target check packs {referenced_pack_paths:?} do not match embedded check packs {actual_pack_paths:?}"
        )));
    }

    let referenced_coverage_paths: BTreeSet<_> = manifest
        .targets
        .values()
        .map(|target| target.coverage_manifest.as_str())
        .collect();
    let bundled_coverage_paths: BTreeSet<_> = BUNDLED_COVERAGE_PATHS.into_iter().collect();
    if referenced_coverage_paths != bundled_coverage_paths {
        return Err(drift(format!(
            "supported target coverage manifests {referenced_coverage_paths:?} do not match bundled coverage manifests {bundled_coverage_paths:?}"
        )));
    }

    let supported_targets_sha256 = canonical_json_sha256(&manifest)
        .map_err(|error| drift(format!("cannot digest supported-targets metadata: {error}")))?;
    let mut profiles = Vec::with_capacity(EXPECTED_TARGET_KEYS.len());

    for target_key in EXPECTED_TARGET_KEYS {
        let target = manifest
            .targets
            .get(target_key)
            .ok_or_else(|| drift(format!("missing target {target_key}")))?;
        validate_target_paths_and_gate(target_key, target)?;

        let pack_path = embedded_pack_path(&target.check_pack)?;
        let pack_json = check_pack_bytes(pack_path).ok_or_else(|| {
            drift(format!(
                "{} references missing embedded check pack {}",
                target_key, target.check_pack
            ))
        })?;
        let mut check_pack: CheckPack = serde_json::from_slice(&pack_json).map_err(|error| {
            drift(format!(
                "embedded check pack {} is invalid JSON: {error}",
                target.check_pack
            ))
        })?;
        validate_pack(&check_pack).map_err(|error| {
            drift(format!(
                "embedded check pack {} is invalid: {error}",
                target.check_pack
            ))
        })?;
        // `CheckPackRegistry::load_embedded` assigns this source tier. Digest
        // the same effective value used by evaluator provenance.
        check_pack.priority = 0;

        let coverage_json = coverage_bytes(&target.coverage_manifest).ok_or_else(|| {
            drift(format!(
                "{} references missing bundled coverage manifest {}",
                target_key, target.coverage_manifest
            ))
        })?;
        let coverage_manifest =
            parse_coverage_manifest(std::str::from_utf8(&coverage_json).map_err(|error| {
                drift(format!(
                    "coverage manifest {} is not UTF-8: {error}",
                    target.coverage_manifest
                ))
            })?)
            .map_err(|error| {
                drift(format!(
                    "coverage manifest {} is invalid JSON: {error}",
                    target.coverage_manifest
                ))
            })?;

        let profile = build_profile(target_key, target, &check_pack, &coverage_manifest)?;
        profiles.push(profile);
    }

    Ok(ScannerProfileCatalog {
        schema_version: manifest.schema_version,
        release_line: manifest.release_line.into_boxed_str(),
        supported_targets_sha256: supported_targets_sha256.into_boxed_str(),
        profiles: profiles.into_boxed_slice(),
    })
}

fn build_profile(
    target_key: &str,
    target: &SupportedTarget,
    check_pack: &CheckPack,
    coverage_manifest: &CoverageManifest,
) -> std::result::Result<ScannerProfile, String> {
    if check_pack.stig_id != target.stig_id
        || check_pack.version != target.stig_release
        || check_pack.platform != target.platform
    {
        return Err(drift(format!(
            "{target_key} target identity ({}/{}/{:?}) does not match check pack ({}/{}/{:?})",
            target.stig_id,
            target.stig_release,
            target.platform,
            check_pack.stig_id,
            check_pack.version,
            check_pack.platform
        )));
    }
    if coverage_manifest.stig_id != target.stig_id
        || coverage_manifest.version != target.stig_release
    {
        return Err(drift(format!(
            "{target_key} target identity ({}/{}) does not match coverage manifest ({}/{})",
            target.stig_id,
            target.stig_release,
            coverage_manifest.stig_id,
            coverage_manifest.version
        )));
    }

    let report = validate_coverage_manifest(coverage_manifest);
    if !report.is_valid() {
        let issues = report
            .issues
            .iter()
            .map(|issue| format!("{}: {}", issue.field, issue.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(drift(format!(
            "{} coverage manifest failed validation: {issues}",
            target.coverage_manifest
        )));
    }
    if check_pack.checks.len() != target.expected_automated_checks
        || report.automated != target.expected_automated_checks
    {
        return Err(drift(format!(
            "{target_key} declares {} automated checks but the embedded pack has {} and coverage has {}",
            target.expected_automated_checks,
            check_pack.checks.len(),
            report.automated
        )));
    }
    if report.total_rules != target.expected_reviewed_rules {
        return Err(drift(format!(
            "{target_key} declares {} reviewed rules but coverage has {}",
            target.expected_reviewed_rules, report.total_rules
        )));
    }
    if target.expected_benchmark_rules < target.expected_reviewed_rules {
        return Err(drift(format!(
            "{target_key} full benchmark has {} rules but reviewed scope declares {}",
            target.expected_benchmark_rules, target.expected_reviewed_rules
        )));
    }

    validate_automated_rule_bindings(target_key, check_pack, coverage_manifest)?;

    let coverage = ScannerCoverageCounts {
        benchmark_rules: target.expected_benchmark_rules,
        reviewed_rules: report.total_rules,
        automated_checks: report.automated,
        manual_rules: report.manual,
        not_applicable_rules: report.not_applicable,
        unsupported_rules: report.unsupported,
    };
    let readiness = ScannerProfileReadiness::from(coverage_manifest.status);
    let check_pack_sha256 = canonical_json_sha256(&[check_pack]).map_err(|error| {
        drift(format!(
            "cannot digest embedded check pack {}: {error}",
            target.check_pack
        ))
    })?;
    let coverage_manifest_sha256 = canonical_json_sha256(coverage_manifest).map_err(|error| {
        drift(format!(
            "cannot digest coverage manifest {}: {error}",
            target.coverage_manifest
        ))
    })?;
    let profile_sha256 = canonical_json_sha256(&ProfileDigestBinding {
        target_key,
        display_name: &target.display_name,
        platform: target.platform,
        stig_id: &target.stig_id,
        stig_release: &target.stig_release,
        evidence_mode: target.evidence_mode,
        check_pack_path: &target.check_pack,
        coverage_manifest_path: &target.coverage_manifest,
        coverage,
        check_pack_sha256: &check_pack_sha256,
        coverage_manifest_sha256: &coverage_manifest_sha256,
        readiness,
        acceptance_gate: target.acceptance_gate,
    })
    .map_err(|error| drift(format!("cannot digest {target_key} profile: {error}")))?;

    Ok(ScannerProfile {
        target_key: target_key.into(),
        display_name: target.display_name.clone().into_boxed_str(),
        platform: target.platform,
        stig_id: target.stig_id.clone().into_boxed_str(),
        stig_release: target.stig_release.clone().into_boxed_str(),
        evidence_mode: target.evidence_mode,
        check_pack_path: target.check_pack.clone().into_boxed_str(),
        coverage_manifest_path: target.coverage_manifest.clone().into_boxed_str(),
        coverage,
        digests: ScannerProfileDigests {
            check_pack_sha256: check_pack_sha256.into_boxed_str(),
            coverage_manifest_sha256: coverage_manifest_sha256.into_boxed_str(),
            profile_sha256: profile_sha256.into_boxed_str(),
        },
        readiness,
        acceptance_gate: target.acceptance_gate,
    })
}

fn validate_manifest_header(
    manifest: &SupportedTargetsManifest,
) -> std::result::Result<(), String> {
    if manifest.schema != SUPPORTED_TARGETS_SCHEMA {
        return Err(drift(format!(
            "supported-targets schema must be {SUPPORTED_TARGETS_SCHEMA}, got {}",
            manifest.schema
        )));
    }
    if manifest.schema_version != SUPPORTED_TARGETS_SCHEMA_VERSION {
        return Err(drift(format!(
            "supported-targets schema version must be {SUPPORTED_TARGETS_SCHEMA_VERSION}, got {}",
            manifest.schema_version
        )));
    }
    if manifest.release_line != SUPPORTED_RELEASE_LINE {
        return Err(drift(format!(
            "supported-targets release line must be {SUPPORTED_RELEASE_LINE}, got {}",
            manifest.release_line
        )));
    }
    Ok(())
}

fn validate_target_keys(
    targets: &BTreeMap<String, SupportedTarget>,
) -> std::result::Result<(), String> {
    let expected: BTreeSet<_> = EXPECTED_TARGET_KEYS.into_iter().collect();
    let actual: BTreeSet<_> = targets.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(drift(format!(
            "supported target keys {actual:?} do not match release contract {expected:?}"
        )));
    }
    Ok(())
}

fn validate_target_paths_and_gate(
    target_key: &str,
    target: &SupportedTarget,
) -> std::result::Result<(), String> {
    let expected_pack = format!("content/check_packs/{target_key}.json");
    let expected_coverage =
        format!("content/coverage/current-checkpacks/{target_key}.current.json");
    if target.check_pack != expected_pack {
        return Err(drift(format!(
            "{target_key} check-pack path must be {expected_pack}, got {}",
            target.check_pack
        )));
    }
    if target.coverage_manifest != expected_coverage {
        return Err(drift(format!(
            "{target_key} coverage path must be {expected_coverage}, got {}",
            target.coverage_manifest
        )));
    }

    let (expected_platform, expected_mode, expected_gate) = match target_key {
        "netapp_ontap9" => (
            CheckPlatform::Ontap,
            ScannerEvidenceMode::SshTranscript,
            ScannerAcceptanceGate::Ontap,
        ),
        "freebsd_gpos" => (
            CheckPlatform::Bsd,
            ScannerEvidenceMode::SshTranscript,
            ScannerAcceptanceGate::Freebsd,
        ),
        "cisco_ios_xe_router_ndm" => (
            CheckPlatform::CiscoIos,
            ScannerEvidenceMode::RunningConfiguration,
            ScannerAcceptanceGate::CiscoIosXe,
        ),
        _ => return Err(drift(format!("unexpected target key {target_key}"))),
    };
    if target.platform != expected_platform
        || target.evidence_mode != expected_mode
        || target.acceptance_gate != expected_gate
    {
        return Err(drift(format!(
            "{target_key} platform/evidence/gate ({:?}/{:?}/{:?}) does not match release contract ({expected_platform:?}/{expected_mode:?}/{expected_gate:?})",
            target.platform, target.evidence_mode, target.acceptance_gate
        )));
    }
    if target.display_name.trim().is_empty()
        || target.stig_id.trim().is_empty()
        || target.stig_release.trim().is_empty()
    {
        return Err(drift(format!(
            "{target_key} display name, STIG ID, and release must be non-empty"
        )));
    }
    Ok(())
}

fn validate_automated_rule_bindings(
    target_key: &str,
    check_pack: &CheckPack,
    coverage_manifest: &CoverageManifest,
) -> std::result::Result<(), String> {
    let pack_vulns: BTreeSet<_> = check_pack
        .checks
        .iter()
        .map(|check| check.vuln_id.as_str())
        .collect();
    let mut coverage_vulns = BTreeSet::new();
    for rule in coverage_manifest
        .rules
        .iter()
        .filter(|rule| rule.classification == RuleCoverageClassification::Automated)
    {
        if rule.check_pack.as_deref() != Some(target_key)
            || rule.check_id.as_deref() != Some(rule.vuln_id.as_str())
        {
            return Err(drift(format!(
                "{target_key} automated coverage rule {} must bind check_pack={target_key} and check_id={}",
                rule.vuln_id, rule.vuln_id
            )));
        }
        coverage_vulns.insert(rule.vuln_id.as_str());
    }
    if coverage_vulns != pack_vulns {
        return Err(drift(format!(
            "{target_key} automated coverage IDs {coverage_vulns:?} do not match embedded check IDs {pack_vulns:?}"
        )));
    }
    Ok(())
}

fn embedded_pack_path(path: &str) -> std::result::Result<&str, String> {
    path.strip_prefix("content/check_packs/")
        .filter(|relative| {
            !relative.is_empty()
                && !relative.contains('/')
                && !relative.contains('\\')
                && relative.ends_with(".json")
        })
        .ok_or_else(|| drift(format!("invalid embedded check-pack path {path}")))
}

fn drift(message: impl Into<String>) -> String {
    format!("bundled scanner profile contract drift: {}", message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_for_test(
        supported_targets_json: &[u8],
        check_pack_override: Option<(&str, Vec<u8>)>,
        coverage_override: Option<(&str, Vec<u8>)>,
    ) -> std::result::Result<ScannerProfileCatalog, String> {
        let embedded_paths = embedded_check_pack_paths();
        build_catalog_from_sources(
            supported_targets_json,
            &embedded_paths,
            |path| {
                check_pack_override
                    .as_ref()
                    .filter(|(override_path, _)| *override_path == path)
                    .map(|(_, bytes)| bytes.clone())
                    .or_else(|| embedded_check_pack_bytes(path))
            },
            |path| {
                coverage_override
                    .as_ref()
                    .filter(|(override_path, _)| *override_path == path)
                    .map(|(_, bytes)| bytes.clone())
                    .or_else(|| bundled_coverage_bytes(path).map(<[u8]>::to_vec))
            },
        )
    }

    #[test]
    fn validates_all_three_release_bundled_profiles() {
        let catalog = bundled_scanner_profile_catalog().unwrap();
        assert_eq!(catalog.schema_version(), 1);
        assert_eq!(catalog.release_line(), "0.3");
        assert_sha256(catalog.supported_targets_sha256());

        let expected = [
            (
                "netapp_ontap9",
                "NetApp ONTAP 9.x",
                CheckPlatform::Ontap,
                "NetApp_ONTAP_DSC_9-x_STIG",
                "V2R4",
                ScannerEvidenceMode::SshTranscript,
                29,
                15,
                22,
                7,
            ),
            (
                "freebsd_gpos",
                "FreeBSD / DISA GPOS",
                CheckPlatform::Bsd,
                "General_Purpose_Operating_System",
                "V3R3",
                ScannerEvidenceMode::SshTranscript,
                203,
                6,
                30,
                24,
            ),
            (
                "cisco_ios_xe_router_ndm",
                "Cisco IOS-XE Router NDM",
                CheckPlatform::CiscoIos,
                "Cisco_IOS-XE_Router_NDM_STIG",
                "V3R7",
                ScannerEvidenceMode::RunningConfiguration,
                42,
                33,
                42,
                9,
            ),
        ];
        assert_eq!(catalog.profiles().len(), expected.len());

        for (
            profile,
            (
                key,
                display_name,
                platform,
                stig_id,
                release,
                evidence_mode,
                benchmark_rules,
                automated,
                reviewed,
                manual,
            ),
        ) in catalog.profiles().iter().zip(expected)
        {
            assert_eq!(profile.target_key(), key);
            assert_eq!(profile.display_name(), display_name);
            assert_eq!(profile.platform(), platform);
            assert_eq!(profile.stig_id(), stig_id);
            assert_eq!(profile.stig_release(), release);
            assert_eq!(profile.evidence_mode(), evidence_mode);
            assert_eq!(profile.coverage().benchmark_rules(), benchmark_rules);
            assert_eq!(profile.coverage().automated_checks(), automated);
            assert_eq!(profile.coverage().reviewed_rules(), reviewed);
            assert_eq!(profile.coverage().manual_rules(), manual);
            assert_eq!(profile.coverage().not_applicable_rules(), 0);
            assert_eq!(profile.coverage().unsupported_rules(), 0);
            assert_eq!(profile.readiness(), ScannerProfileReadiness::Experimental);
            assert_sha256(profile.digests().check_pack_sha256());
            assert_sha256(profile.digests().coverage_manifest_sha256());
            assert_sha256(profile.digests().profile_sha256());
            assert!(std::ptr::eq(
                bundled_scanner_profile(key).unwrap().unwrap(),
                profile
            ));
        }
        assert!(bundled_scanner_profile("unsupported").unwrap().is_none());
    }

    #[test]
    fn profile_pack_digests_match_effective_embedded_evaluator_inputs() {
        let mut registry = crate::check_packs::CheckPackRegistry::new();
        assert_eq!(registry.load_embedded().unwrap(), 3);

        for profile in bundled_scanner_profiles().unwrap() {
            let effective =
                registry.check_packs_for_stig_release(profile.stig_id(), profile.stig_release());
            assert_eq!(effective.len(), 1, "{}", profile.target_key());
            assert_eq!(
                canonical_json_sha256(&effective).unwrap(),
                profile.digests().check_pack_sha256(),
                "{}",
                profile.target_key()
            );
        }
    }

    #[test]
    fn rejects_supported_target_count_and_coverage_drift() {
        let mut targets: serde_json::Value =
            serde_json::from_slice(SUPPORTED_TARGETS_JSON).unwrap();
        targets["targets"]["netapp_ontap9"]["expected_automated_checks"] = serde_json::json!(14);
        let error = build_for_test(&serde_json::to_vec(&targets).unwrap(), None, None).unwrap_err();
        assert!(error.contains("declares 14 automated checks"), "{error}");

        let mut coverage: serde_json::Value = serde_json::from_slice(NETAPP_COVERAGE_JSON).unwrap();
        coverage["version"] = serde_json::json!("V2R1");
        let error = build_for_test(
            SUPPORTED_TARGETS_JSON,
            None,
            Some((
                "content/coverage/current-checkpacks/netapp_ontap9.current.json",
                serde_json::to_vec(&coverage).unwrap(),
            )),
        )
        .unwrap_err();
        assert!(
            error.contains("does not match coverage manifest"),
            "{error}"
        );
    }

    #[test]
    fn rejects_embedded_pack_and_automated_rule_binding_drift() {
        let mut pack: serde_json::Value =
            serde_json::from_slice(&embedded_check_pack_bytes("freebsd_gpos.json").unwrap())
                .unwrap();
        pack["version"] = serde_json::json!("V3R2");
        let error = build_for_test(
            SUPPORTED_TARGETS_JSON,
            Some(("freebsd_gpos.json", serde_json::to_vec(&pack).unwrap())),
            None,
        )
        .unwrap_err();
        assert!(error.contains("embedded check pack"), "{error}");

        let mut coverage: serde_json::Value = serde_json::from_slice(CISCO_COVERAGE_JSON).unwrap();
        let automated = coverage["rules"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|rule| rule["classification"] == "automated")
            .unwrap();
        automated["check_id"] = serde_json::json!("V-DRIFT");
        let error = build_for_test(
            SUPPORTED_TARGETS_JSON,
            None,
            Some((
                "content/coverage/current-checkpacks/cisco_ios_xe_router_ndm.current.json",
                serde_json::to_vec(&coverage).unwrap(),
            )),
        )
        .unwrap_err();
        assert!(error.contains("must bind check_pack"), "{error}");
    }

    fn assert_sha256(value: &str) {
        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
