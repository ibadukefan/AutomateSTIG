//! Scanner-only deterministic evaluation helpers.
//!
//! This module deliberately consumes only release-bundled scanner content. It
//! does not open the mutable STIG library, apply answer files, or carry forward
//! human review state. A caller supplies adapter-normalized observations and
//! receives a revision-bound checklist plus, only for a complete evaluation,
//! the sparse scanner-owned reviews that may be delivered to STIG Manager.

#[cfg(test)]
use std::collections::HashMap;

use automatestig_core::check_packs::{
    canonical_json_sha256, check_pack_vuln_ids_missing_from_benchmark, evaluation_plan_sha256,
    CheckPackRegistry,
};
use automatestig_core::checks::{executor::execute_check, CheckPack, SystemData};
use automatestig_core::engine::EvaluationEngine;
use automatestig_core::models::asset::Asset;
use automatestig_core::models::checklist::{
    EvaluationOrigin, EvaluationProvenance, OrganizationPolicyProvenance,
};
use automatestig_core::models::finding::{FindingSource, FindingStatus};
use automatestig_core::models::Checklist;
use automatestig_core::remote::is_openssh_sha256_fingerprint;
use automatestig_core::scanner_benchmarks::bundled_scanner_benchmark;
use automatestig_core::scanner_profiles::bundled_scanner_profile;
use automatestig_core::target_adapters::DeviceFingerprint;
use automatestig_integrations::stig_manager::{sparse_scanner_reviews, ScannerReview};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg(test)]
const RUNNING_CONFIG_KEY: &str = "running_config";

/// Every in-memory input which can affect a scanner determination.
///
/// `SystemData::organization_policy` is intentionally skipped by serde in the
/// core model. Deserializing this type can therefore never self-assert a
/// trusted organization policy; the verified value must be attached in memory
/// after signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvaluationInput {
    pub profile_id: String,
    pub device: DeviceFingerprint,
    pub system_data: SystemData,
    pub origin: EvaluationOrigin,
    pub evidence_sha256: String,
    pub plan_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_key_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_version: Option<String>,
    pub collected_at: String,
    /// A durable projection of the verified policy carried by `system_data`.
    /// It is checked against that non-deserializable trusted value; it cannot
    /// independently enable policy-dependent checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_policy: Option<OrganizationPolicyProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScannerEvaluationDigests {
    pub profile_sha256: String,
    /// Semantic digest of the parsed benchmark used by the evaluator.
    pub benchmark_sha256: String,
    /// Digest of the exact bundled JSON model retained by its source manifest.
    pub benchmark_model_sha256: String,
    pub check_pack_sha256: String,
    pub evaluation_plan_sha256: String,
    pub evidence_sha256: String,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScannerEvaluationSummary {
    pub benchmark_rules: usize,
    pub checks_planned: usize,
    pub checks_assessed: usize,
    pub checks_passed: usize,
    pub checks_failed: usize,
    pub checks_errored: usize,
    pub manual_not_reviewed: usize,
    pub sparse_review_count: usize,
    pub benchmark_coverage_pct: f64,
    pub assessed_pass_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScannerEvaluation {
    pub checklist: Checklist,
    pub collection_complete: bool,
    pub collection_errors: Vec<String>,
    pub digests: ScannerEvaluationDigests,
    pub summary: ScannerEvaluationSummary,
    /// Canonical scanner-owned STIG Manager payload. This is always empty for
    /// an incomplete evaluation.
    pub sparse_reviews: Vec<ScannerReview>,
}

/// Convert adapter observations into the executor's established system-data
/// model without adding aliases or heuristically interpreting keys.
///
/// Every observation remains available as a command output. The one reviewed
/// offline configuration key is additionally exposed through `network_config`
/// for the Cisco typed checks.
#[cfg(test)]
fn system_data_from_normalized(
    observations: HashMap<String, String>,
    collection_complete: bool,
    collection_errors: HashMap<String, String>,
) -> SystemData {
    let network_config = observations.get(RUNNING_CONFIG_KEY).cloned();
    SystemData {
        collection_complete,
        collection_errors,
        network_config,
        command_outputs: observations,
        organization_policy: None,
    }
}

/// Evaluate one target against its exact release-bundled scanner contract.
///
/// Successful check results become scanner-owned findings. Missing or invalid
/// observations remain Not Reviewed with a collection-error source. Benchmark
/// rules without executable checks are left exactly as the engine initialized
/// them: manual and Not Reviewed.
pub(crate) fn evaluate_profile(input: EvaluationInput) -> Result<ScannerEvaluation, String> {
    validate_input(&input)?;

    let profile = bundled_scanner_profile(input.profile_id.trim())
        .map_err(|error| format!("failed to load bundled scanner profiles: {error}"))?
        .ok_or_else(|| {
            format!(
                "scanner profile '{}' is not bundled",
                input.profile_id.trim()
            )
        })?;
    let bundled_benchmark = bundled_scanner_benchmark(profile.target_key())
        .map_err(|error| format!("failed to load bundled scanner benchmark: {error}"))?
        .ok_or_else(|| {
            format!(
                "scanner profile '{}' has no bundled benchmark",
                profile.target_key()
            )
        })?;
    let benchmark = bundled_benchmark.benchmark();

    if benchmark.id != profile.stig_id() || benchmark.version_string() != profile.stig_release() {
        return Err(format!(
            "bundled benchmark {} {} does not match profile {} {}",
            benchmark.id,
            benchmark.version_string(),
            profile.stig_id(),
            profile.stig_release()
        ));
    }
    if benchmark.rules.len() != profile.coverage().reviewed_rules() {
        return Err(format!(
            "bundled benchmark rule count {} does not match profile coverage {}",
            benchmark.rules.len(),
            profile.coverage().reviewed_rules()
        ));
    }

    let check_packs = exact_check_packs(profile.stig_id(), profile.stig_release())?;
    let unknown_vuln_ids = check_pack_vuln_ids_missing_from_benchmark(benchmark, &check_packs);
    if !unknown_vuln_ids.is_empty() {
        return Err(format!(
            "bundled check pack contains rules outside the exact benchmark: {}",
            unknown_vuln_ids.join(", ")
        ));
    }
    let checks: Vec<_> = check_packs
        .iter()
        .flat_map(|pack| pack.checks.iter())
        .collect();
    if checks.len() != profile.coverage().automated_checks() {
        return Err(format!(
            "bundled check count {} does not match profile coverage {}",
            checks.len(),
            profile.coverage().automated_checks()
        ));
    }

    let check_pack_sha256 = canonical_json_sha256(&check_packs)
        .map_err(|error| format!("failed to digest bundled check pack: {error}"))?;
    if check_pack_sha256 != profile.digests().check_pack_sha256() {
        return Err("bundled check-pack digest does not match the scanner profile".to_string());
    }
    let benchmark_sha256 = canonical_json_sha256(benchmark)
        .map_err(|error| format!("failed to digest bundled benchmark: {error}"))?;

    let organization_policy = verified_policy_projection(&input)?;
    let organization_policy_sha256 = organization_policy
        .as_ref()
        .map(|policy| policy.policy_sha256.as_str());
    let evaluation_plan_sha256 = evaluation_plan_sha256(
        &benchmark.id,
        &benchmark.version_string(),
        &benchmark_sha256,
        &check_pack_sha256,
        organization_policy_sha256,
    )
    .map_err(|error| format!("failed to bind evaluation plan: {error}"))?;

    let evaluated_at = DateTime::parse_from_rfc3339(&input.collected_at)
        .map_err(|_| "collected_at must be RFC 3339".to_string())?
        .with_timezone(&Utc);
    let finding_source = match input.origin {
        EvaluationOrigin::LiveSsh => FindingSource::Automated,
        EvaluationOrigin::EvidenceFile | EvaluationOrigin::ConfigFile => FindingSource::Evidence,
        EvaluationOrigin::ImportedChecklist => {
            return Err("imported checklists are outside the scanner run engine".to_string())
        }
    };

    let mut checklist = EvaluationEngine::with_defaults()
        .evaluate(benchmark, &Asset::new(input.device.hostname.trim()), &[])
        .map_err(|error| format!("failed to initialize scanner checklist: {error}"))?;
    // The collection timestamp, rather than wall-clock time spent executing
    // these pure predicates, anchors the result and all scanner-owned rows.
    checklist.created_at = evaluated_at;
    checklist.modified_at = evaluated_at;

    let mut check_errors = Vec::new();
    let mut checks_passed = 0usize;
    let mut checks_failed = 0usize;
    let mut checks_errored = 0usize;
    for definition in &checks {
        let result = execute_check(definition, &input.system_data);
        let finding = checklist
            .find_by_vuln_id_mut(&result.vuln_id)
            .ok_or_else(|| format!("check {} has no exact benchmark finding", result.vuln_id))?;
        finding.evaluated_at = evaluated_at;
        finding.evaluated_by = format!("AutomateSTIG {}", env!("CARGO_PKG_VERSION"));
        let safe_detail = if result.error.is_some() {
            format!(
                "AutomateSTIG could not evaluate this rule because required collection evidence was unavailable. Diagnostic linkage is bound to replay-evidence SHA-256 {}; its current retention state is reported separately.",
                input.evidence_sha256
            )
        } else {
            format!(
                "AutomateSTIG evaluated the release-bundled predicate for {}. Condition satisfied: {}. Observation linkage is bound to replay-evidence SHA-256 {}; its current retention state is reported separately.",
                result.vuln_id, result.passed, input.evidence_sha256
            )
        };
        finding.finding_details = safe_detail.clone();
        finding.evidence = Some(safe_detail);

        if let Some(error) = result.error.as_ref() {
            // Keep the status fail-closed. A collection failure is not an Open
            // finding and is never eligible for sparse delivery.
            finding.status = FindingStatus::NotReviewed;
            finding.source = FindingSource::CollectionError;
            check_errors.push(format!(
                "{}: {}",
                result.vuln_id,
                safe_collection_error_message(error)
            ));
            checks_errored += 1;
        } else {
            finding.status = result.to_finding_status();
            finding.source = finding_source;
            match finding.status {
                FindingStatus::NotAFinding => checks_passed += 1,
                FindingStatus::Open => checks_failed += 1,
                FindingStatus::NotApplicable | FindingStatus::NotReviewed => {}
            }
            if finding_source == FindingSource::Evidence {
                finding.comments = format!(
                    "Supplied evidence evaluated by AutomateSTIG; SHA-256: {}",
                    input.evidence_sha256
                );
            }
        }
    }

    let mut collection_errors: Vec<String> = input
        .system_data
        .collection_errors
        .iter()
        .map(|(key, error)| format!("{key}: {}", safe_collection_error_message(error)))
        .chain(check_errors)
        .collect();
    collection_errors.sort();
    collection_errors.dedup();
    if !input.system_data.collection_complete && collection_errors.is_empty() {
        collection_errors.push("adapter marked collection incomplete".to_string());
    }
    let collection_complete = input.system_data.collection_complete
        && collection_errors.is_empty()
        && checks_errored == 0;

    checklist.evaluation_provenance = Some(EvaluationProvenance {
        origin: input.origin,
        collection_complete,
        collection_errors: collection_errors.clone(),
        evidence_sha256: Some(input.evidence_sha256.clone()),
        claimed_hostname: Some(input.device.hostname.trim().to_string()),
        collector_version: input.collector_version.clone(),
        collected_at: Some(input.collected_at.clone()),
        plan_sha256: Some(input.plan_sha256.clone()),
        server_key_fingerprint: input.server_key_fingerprint.clone(),
        benchmark_sha256: Some(benchmark_sha256.clone()),
        check_pack_sha256: Some(check_pack_sha256.clone()),
        evaluation_plan_sha256: Some(evaluation_plan_sha256.clone()),
        organization_policy,
        answer_file: None,
        answer_files: Vec::new(),
        unsafe_legacy_evidence: false,
    });

    let sparse_reviews = if collection_complete {
        if let Some(reason) = checklist.external_export_block_reason() {
            return Err(format!(
                "completed scanner result is not deliverable: {reason}"
            ));
        }
        sparse_scanner_reviews(&checklist)
    } else {
        Vec::new()
    };
    let finding_summary = checklist.summary();
    let manual_not_reviewed = checklist
        .findings
        .iter()
        .filter(|finding| {
            finding.status == FindingStatus::NotReviewed && finding.source == FindingSource::Manual
        })
        .count();
    let summary = ScannerEvaluationSummary {
        benchmark_rules: checklist.findings.len(),
        checks_planned: checks.len(),
        checks_assessed: checks_passed + checks_failed,
        checks_passed,
        checks_failed,
        checks_errored,
        manual_not_reviewed,
        sparse_review_count: sparse_reviews.len(),
        benchmark_coverage_pct: finding_summary.benchmark_coverage_pct(),
        assessed_pass_pct: finding_summary.assessed_pass_pct_opt(),
    };

    Ok(ScannerEvaluation {
        checklist,
        collection_complete,
        collection_errors,
        digests: ScannerEvaluationDigests {
            profile_sha256: profile.digests().profile_sha256().to_string(),
            benchmark_sha256,
            benchmark_model_sha256: bundled_benchmark.source().benchmark_model_sha256.clone(),
            check_pack_sha256,
            evaluation_plan_sha256,
            evidence_sha256: input.evidence_sha256,
            plan_sha256: input.plan_sha256,
        },
        summary,
        sparse_reviews,
    })
}

/// Map untrusted transport/command diagnostics to a small operator-facing
/// vocabulary. Full stderr and adapter error text remain in the encrypted
/// replay artifact; they must not be duplicated into immutable result JSON.
fn safe_collection_error_message(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("permission") || lower.contains("authoriz") {
        "permission denied while collecting required evidence"
    } else if lower.contains("authenticat") {
        "device authentication failed"
    } else if lower.contains("timeout") || lower.contains("timed out") {
        "collection timed out"
    } else if lower.contains("truncat") || lower.contains("output limit") {
        "collection output exceeded its safe completeness limit"
    } else if lower.contains("missing") || lower.contains("not found") {
        "required evidence was missing"
    } else if lower.contains("transport") || lower.contains("connection") {
        "device transport failed"
    } else {
        "collection or evaluation failed; details are retained in encrypted evidence"
    }
}

fn exact_check_packs(stig_id: &str, stig_release: &str) -> Result<Vec<CheckPack>, String> {
    let mut registry = CheckPackRegistry::new();
    registry
        .load_embedded()
        .map_err(|error| format!("failed to load embedded check packs: {error}"))?;
    let packs: Vec<_> = registry
        .check_packs_for_stig_release(stig_id, stig_release)
        .into_iter()
        .cloned()
        .collect();
    match packs.len() {
        1 => Ok(packs),
        0 => Err(format!(
            "no embedded check pack matches {stig_id} {stig_release}"
        )),
        count => Err(format!(
            "expected one embedded check pack for {stig_id} {stig_release}, found {count}"
        )),
    }
}

fn verified_policy_projection(
    input: &EvaluationInput,
) -> Result<Option<OrganizationPolicyProvenance>, String> {
    let verified = input
        .system_data
        .organization_policy
        .as_ref()
        .map(|policy| OrganizationPolicyProvenance {
            policy_id: policy.document().policy_id.clone(),
            policy_version: policy.document().policy_version.clone(),
            policy_sha256: policy.sha256().to_string(),
            signer_fingerprint: policy.signer_fingerprint().to_string(),
            signature_verified: true,
        });
    match (&input.organization_policy, &verified) {
        (Some(claimed), Some(actual)) if claimed != actual => {
            Err("organization-policy provenance does not match the verified policy".to_string())
        }
        (Some(_), None) => Err(
            "organization-policy provenance cannot enable checks without a verified policy"
                .to_string(),
        ),
        (_, Some(actual)) => {
            let document = input
                .system_data
                .organization_policy
                .as_ref()
                .expect("verified projection was created from this value")
                .document();
            if document.stig_id
                != bundled_scanner_profile(input.profile_id.trim())
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "scanner profile is not bundled".to_string())?
                    .stig_id()
                || !document
                    .asset_hostname
                    .trim()
                    .eq_ignore_ascii_case(input.device.hostname.trim())
            {
                return Err(
                    "verified organization policy is not bound to this profile and device"
                        .to_string(),
                );
            }
            Ok(Some(actual.clone()))
        }
        (None, None) => Ok(None),
    }
}

fn validate_input(input: &EvaluationInput) -> Result<(), String> {
    let hostname = input.device.hostname.trim();
    if hostname.is_empty() || hostname.len() > 255 || hostname.chars().any(char::is_control) {
        return Err("device hostname must be non-empty, bounded, and printable".to_string());
    }
    input
        .device
        .sha256()
        .map_err(|error| format!("invalid device fingerprint: {error}"))?;
    for (label, digest) in [
        ("evidence_sha256", input.evidence_sha256.as_str()),
        ("plan_sha256", input.plan_sha256.as_str()),
    ] {
        if !is_lowercase_sha256(digest) {
            return Err(format!("{label} must be a lowercase SHA-256 digest"));
        }
    }
    if input.origin == EvaluationOrigin::LiveSsh
        && !input
            .server_key_fingerprint
            .as_deref()
            .is_some_and(is_openssh_sha256_fingerprint)
    {
        return Err(
            "live SSH evaluation requires a valid verified server-key fingerprint".to_string(),
        );
    }
    if let Some(fingerprint) = input.server_key_fingerprint.as_deref() {
        if !is_openssh_sha256_fingerprint(fingerprint) {
            return Err("server_key_fingerprint is malformed".to_string());
        }
    }
    DateTime::parse_from_rfc3339(&input.collected_at)
        .map_err(|_| "collected_at must be RFC 3339".to_string())?;
    if input
        .collector_version
        .as_deref()
        .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
    {
        return Err("collector_version must be printable when provided".to_string());
    }
    if input.origin == EvaluationOrigin::ImportedChecklist {
        return Err("imported checklists are outside the scanner run engine".to_string());
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::models::finding::FindingSource;

    const PROFILE: &str = "freebsd_gpos";

    fn complete_freebsd_observations() -> HashMap<String, String> {
        HashMap::from([
            (
                "service auditd onestatus".to_string(),
                "auditd is running as pid 123.".to_string(),
            ),
            (
                "cat /etc/security/audit_control".to_string(),
                "flags:all\nnaflags:all\n".to_string(),
            ),
            (
                "cat /etc/security/audit_user".to_string(),
                "# no per-user exclusions\n".to_string(),
            ),
            (
                "sha256 -q /etc/security/audit_class".to_string(),
                "834a1fde758a45269874a5c0655046ca7354a7afa3cf9aee8d29bbfe5d8ab2fd".to_string(),
            ),
            (
                "sha256 -q /etc/security/audit_event".to_string(),
                "124c60b738ec9eb36e497213fded40a7ed9023dc7854258f9c17d5cbcfffcff2".to_string(),
            ),
            (
                "service pf onestatus".to_string(),
                "Status: Enabled for 1 day 00:00:00\n".to_string(),
            ),
        ])
    }

    fn input(system_data: SystemData) -> EvaluationInput {
        EvaluationInput {
            profile_id: PROFILE.to_string(),
            device: DeviceFingerprint::new("freebsd-test", "FreeBSD", "FreeBSD", "14.3"),
            system_data,
            origin: EvaluationOrigin::EvidenceFile,
            evidence_sha256: "a".repeat(64),
            plan_sha256: "b".repeat(64),
            server_key_fingerprint: None,
            collector_version: Some("test-collector/1".to_string()),
            collected_at: "2026-08-08T12:00:00Z".to_string(),
            organization_policy: None,
        }
    }

    #[test]
    fn normalized_running_configuration_uses_the_reviewed_exact_key() {
        let observations = HashMap::from([
            (
                RUNNING_CONFIG_KEY.to_string(),
                "hostname router-1".to_string(),
            ),
            ("unrelated_observation".to_string(), "retained".to_string()),
        ]);
        let data = system_data_from_normalized(observations, true, HashMap::new());

        assert_eq!(data.network_config.as_deref(), Some("hostname router-1"));
        assert_eq!(
            data.command_outputs
                .get("unrelated_observation")
                .map(String::as_str),
            Some("retained")
        );
    }

    #[test]
    fn completed_passes_produce_only_sparse_scanner_reviews() {
        let result = evaluate_profile(input(system_data_from_normalized(
            complete_freebsd_observations(),
            true,
            HashMap::new(),
        )))
        .unwrap();

        assert!(result.collection_complete);
        assert!(result.collection_errors.is_empty());
        assert_eq!(result.summary.checks_planned, 6);
        assert_eq!(result.summary.checks_passed, 6);
        assert_eq!(result.summary.checks_failed, 0);
        assert_eq!(result.sparse_reviews.len(), 6);
        assert!(result
            .sparse_reviews
            .iter()
            .all(|review| review.rule_id.starts_with("SV-")));
        assert!(result.checklist.external_export_block_reason().is_none());
    }

    #[test]
    fn deterministic_failure_is_an_open_scanner_owned_review() {
        let mut observations = complete_freebsd_observations();
        observations.insert(
            "service pf onestatus".to_string(),
            "Status: Disabled".to_string(),
        );
        let result = evaluate_profile(input(system_data_from_normalized(
            observations,
            true,
            HashMap::new(),
        )))
        .unwrap();

        assert!(result.collection_complete);
        assert_eq!(result.summary.checks_passed, 5);
        assert_eq!(result.summary.checks_failed, 1);
        let finding = result.checklist.find_by_vuln_id("V-203784").unwrap();
        assert_eq!(finding.status, FindingStatus::Open);
        assert_eq!(finding.source, FindingSource::Evidence);
        assert_eq!(result.sparse_reviews.len(), 6);
    }

    #[test]
    fn incomplete_collection_never_emits_sparse_reviews_or_false_findings() {
        let mut observations = complete_freebsd_observations();
        observations.remove("service auditd onestatus");
        let errors = HashMap::from([(
            "service auditd onestatus".to_string(),
            "permission denied".to_string(),
        )]);
        let result = evaluate_profile(input(system_data_from_normalized(
            observations,
            false,
            errors,
        )))
        .unwrap();

        assert!(!result.collection_complete);
        assert!(result.sparse_reviews.is_empty());
        assert_eq!(result.summary.checks_errored, 5);
        let finding = result.checklist.find_by_vuln_id("V-203615").unwrap();
        assert_eq!(finding.status, FindingStatus::NotReviewed);
        assert_eq!(finding.source, FindingSource::CollectionError);
        assert!(result
            .collection_errors
            .iter()
            .any(|error| error.contains("permission denied")));
    }

    #[test]
    fn immutable_scanner_results_do_not_copy_raw_observations_or_diagnostics() {
        const RAW_OUTPUT: &str = "raw-device-output-account-SENTINEL";
        const RAW_ERROR: &str = "permission denied: raw-stderr-SENTINEL";
        let mut observations = complete_freebsd_observations();
        observations.insert("unrelated_observation".to_string(), RAW_OUTPUT.to_string());
        observations.remove("service auditd onestatus");
        let errors = HashMap::from([(
            "service auditd onestatus".to_string(),
            RAW_ERROR.to_string(),
        )]);

        let result = evaluate_profile(input(system_data_from_normalized(
            observations,
            false,
            errors,
        )))
        .unwrap();
        let stored_projection = serde_json::to_string(&result).unwrap();

        assert!(!stored_projection.contains(RAW_OUTPUT));
        assert!(!stored_projection.contains("raw-stderr-SENTINEL"));
        assert!(stored_projection.contains("permission denied while collecting"));
        assert!(stored_projection.contains(&"a".repeat(64)));
    }

    #[test]
    fn benchmark_rules_without_checks_remain_manual_and_not_reviewed() {
        let result = evaluate_profile(input(system_data_from_normalized(
            complete_freebsd_observations(),
            true,
            HashMap::new(),
        )))
        .unwrap();

        assert_eq!(result.summary.benchmark_rules, 30);
        assert_eq!(result.summary.manual_not_reviewed, 24);
        assert_eq!(
            result
                .checklist
                .findings
                .iter()
                .filter(|finding| finding.source == FindingSource::Manual)
                .count(),
            24
        );
        assert!(result.checklist.findings.iter().all(|finding| {
            finding.source != FindingSource::Manual || finding.status == FindingStatus::NotReviewed
        }));
    }

    #[test]
    fn claimed_policy_without_verified_system_data_is_rejected() {
        let mut evaluation = input(system_data_from_normalized(
            complete_freebsd_observations(),
            true,
            HashMap::new(),
        ));
        evaluation.organization_policy = Some(OrganizationPolicyProvenance {
            policy_id: "spoofed".to_string(),
            policy_version: "1".to_string(),
            policy_sha256: "c".repeat(64),
            signer_fingerprint: format!("SHA256:{}", "d".repeat(64)),
            signature_verified: true,
        });

        let error = evaluate_profile(evaluation).unwrap_err();
        assert!(error.contains("cannot enable checks"));
    }
}
