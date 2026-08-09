//! Exact benchmark subsets compiled into scanner-capable releases.
//!
//! These models contain every rule declared by the matching reviewed coverage
//! manifest, including the revision-specific DISA `SV-..._rule` identity used
//! by STIG Manager. They deliberately do not expose a general benchmark
//! library or runtime downloader.

use std::collections::HashSet;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::models::stig::StigBenchmark;

const ONTAP_BENCHMARK: &[u8] =
    include_bytes!("../../../content/scanner_profiles/netapp_ontap9.benchmark.json");
const ONTAP_SOURCE: &[u8] =
    include_bytes!("../../../content/scanner_profiles/netapp_ontap9.source.json");
const FREEBSD_BENCHMARK: &[u8] =
    include_bytes!("../../../content/scanner_profiles/freebsd_gpos.benchmark.json");
const FREEBSD_SOURCE: &[u8] =
    include_bytes!("../../../content/scanner_profiles/freebsd_gpos.source.json");
const CISCO_BENCHMARK: &[u8] =
    include_bytes!("../../../content/scanner_profiles/cisco_ios_xe_router_ndm.benchmark.json");
const CISCO_SOURCE: &[u8] =
    include_bytes!("../../../content/scanner_profiles/cisco_ios_xe_router_ndm.source.json");

static BUNDLED_BENCHMARKS: OnceLock<Result<Box<[BundledScannerBenchmark]>, String>> =
    OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerBenchmarkSource {
    pub schema_version: u32,
    pub target_key: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub source_url: String,
    pub source_archive_sha256: String,
    pub source_member: String,
    pub source_xccdf_sha256: String,
    pub coverage_manifest: String,
    pub coverage_manifest_sha256: String,
    pub rule_count: usize,
    pub benchmark_model_sha256: String,
}

/// One integrity-checked benchmark subset shipped for a scanner target.
#[derive(Debug)]
pub struct BundledScannerBenchmark {
    target_key: Box<str>,
    benchmark: StigBenchmark,
    source: ScannerBenchmarkSource,
}

impl BundledScannerBenchmark {
    pub fn target_key(&self) -> &str {
        &self.target_key
    }

    pub fn benchmark(&self) -> &StigBenchmark {
        &self.benchmark
    }

    pub fn source(&self) -> &ScannerBenchmarkSource {
        &self.source
    }
}

/// Return every exact benchmark subset compiled into this scanner release.
pub fn bundled_scanner_benchmarks() -> crate::Result<&'static [BundledScannerBenchmark]> {
    match BUNDLED_BENCHMARKS.get_or_init(build_bundled_benchmarks) {
        Ok(benchmarks) => Ok(benchmarks),
        Err(message) => Err(crate::Error::IntegrityError {
            expected: "valid release-bundled scanner benchmark models".to_string(),
            actual: message.clone(),
        }),
    }
}

/// Resolve one exact benchmark subset by scanner target key.
pub fn bundled_scanner_benchmark(
    target_key: &str,
) -> crate::Result<Option<&'static BundledScannerBenchmark>> {
    Ok(bundled_scanner_benchmarks()?
        .iter()
        .find(|item| item.target_key() == target_key))
}

fn build_bundled_benchmarks() -> Result<Box<[BundledScannerBenchmark]>, String> {
    let sources = [
        ("netapp_ontap9", ONTAP_BENCHMARK, ONTAP_SOURCE),
        ("freebsd_gpos", FREEBSD_BENCHMARK, FREEBSD_SOURCE),
        ("cisco_ios_xe_router_ndm", CISCO_BENCHMARK, CISCO_SOURCE),
    ];
    sources
        .into_iter()
        .map(|(target_key, benchmark_bytes, source_bytes)| {
            parse_bundled_benchmark(target_key, benchmark_bytes, source_bytes)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn parse_bundled_benchmark(
    expected_target_key: &str,
    benchmark_bytes: &[u8],
    source_bytes: &[u8],
) -> Result<BundledScannerBenchmark, String> {
    let benchmark: StigBenchmark = serde_json::from_slice(benchmark_bytes)
        .map_err(|error| format!("{expected_target_key}: invalid benchmark model: {error}"))?;
    let source: ScannerBenchmarkSource = serde_json::from_slice(source_bytes)
        .map_err(|error| format!("{expected_target_key}: invalid source manifest: {error}"))?;
    if source.schema_version != 1 {
        return Err(format!(
            "{expected_target_key}: unsupported source schema {}",
            source.schema_version
        ));
    }
    if source.target_key != expected_target_key {
        return Err(format!(
            "{expected_target_key}: source target is {}",
            source.target_key
        ));
    }
    if benchmark.id != source.stig_id || benchmark.version_string() != source.stig_revision {
        return Err(format!(
            "{expected_target_key}: benchmark identity {} {} does not match source {} {}",
            benchmark.id,
            benchmark.version_string(),
            source.stig_id,
            source.stig_revision
        ));
    }
    if benchmark.rules.len() != source.rule_count {
        return Err(format!(
            "{expected_target_key}: source declares {} rules but model contains {}",
            source.rule_count,
            benchmark.rules.len()
        ));
    }
    let actual_sha256 = format!("{:x}", Sha256::digest(benchmark_bytes));
    if actual_sha256 != source.benchmark_model_sha256 {
        return Err(format!(
            "{expected_target_key}: benchmark digest {actual_sha256} does not match {}",
            source.benchmark_model_sha256
        ));
    }
    for (label, digest) in [
        ("source archive", source.source_archive_sha256.as_str()),
        ("source XCCDF", source.source_xccdf_sha256.as_str()),
        (
            "coverage manifest",
            source.coverage_manifest_sha256.as_str(),
        ),
    ] {
        if !is_sha256(digest) {
            return Err(format!("{expected_target_key}: invalid {label} SHA-256"));
        }
    }
    if !source.source_url.starts_with("https://dl.dod.cyber.mil/") {
        return Err(format!(
            "{expected_target_key}: source is not an official DISA HTTPS URL"
        ));
    }
    let mut vuln_ids = HashSet::new();
    let mut rule_ids = HashSet::new();
    for rule in &benchmark.rules {
        if !rule.vuln_id.starts_with("V-") || !vuln_ids.insert(rule.vuln_id.as_str()) {
            return Err(format!(
                "{expected_target_key}: invalid or duplicate Vuln ID {}",
                rule.vuln_id
            ));
        }
        if !rule.rule_id.starts_with("SV-")
            || !rule.rule_id.ends_with("_rule")
            || !rule_ids.insert(rule.rule_id.as_str())
        {
            return Err(format!(
                "{expected_target_key}: invalid or duplicate revision-specific Rule ID {}",
                rule.rule_id
            ));
        }
    }
    Ok(BundledScannerBenchmark {
        target_key: expected_target_key.into(),
        benchmark,
        source,
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_bundled_benchmark_subsets_have_exact_official_rule_identity() {
        let benchmarks = bundled_scanner_benchmarks().unwrap();
        assert_eq!(benchmarks.len(), 3);
        assert_eq!(benchmarks[0].benchmark().rules.len(), 22);
        assert_eq!(benchmarks[1].benchmark().rules.len(), 30);
        assert_eq!(benchmarks[2].benchmark().rules.len(), 42);
        for item in benchmarks {
            assert_eq!(
                item.benchmark().version_string(),
                item.source().stig_revision
            );
            assert!(item
                .benchmark()
                .rules
                .iter()
                .all(|rule| rule.rule_id.starts_with("SV-") && rule.rule_id.ends_with("_rule")));
        }
    }

    #[test]
    fn lookup_is_target_scoped_and_has_no_general_catalog_fallback() {
        assert!(bundled_scanner_benchmark("netapp_ontap9")
            .unwrap()
            .is_some());
        assert!(bundled_scanner_benchmark("Windows_Server_2022_STIG")
            .unwrap()
            .is_none());
    }
}
