use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::asset::Asset;
use super::finding::{Finding, FindingSource, FindingStatus, FindingSummary};
use crate::check_packs::evaluation_plan_sha256;
use crate::remote::is_openssh_sha256_fingerprint;

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required_sha256_block_reason(label: &str, value: Option<&str>) -> Option<String> {
    match value {
        None => Some(format!(
            "evaluation provenance is missing its {label} SHA-256 binding"
        )),
        Some(value) if !is_lowercase_sha256(value) => Some(format!(
            "evaluation provenance contains a malformed {label} SHA-256 binding"
        )),
        Some(_) => None,
    }
}

/// How device data entered an evaluation. This is deliberately distinct from
/// a finding's result so imported/self-asserted evidence cannot be presented as
/// a locally observed live scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationOrigin {
    LiveSsh,
    EvidenceFile,
    ConfigFile,
    ImportedChecklist,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationPolicyProvenance {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_sha256: String,
    pub signer_fingerprint: String,
    pub signature_verified: bool,
}

/// Durable collection provenance retained with the checklist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationProvenance {
    pub origin: EvaluationOrigin,
    pub collection_complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collection_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_key_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_pack_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_plan_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_policy: Option<OrganizationPolicyProvenance>,
    #[serde(default)]
    pub unsafe_legacy_evidence: bool,
}

/// A STIG checklist — the core output artifact (.ckl / .cklb).
///
/// Represents the evaluation of one STIG benchmark against one asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checklist {
    /// Unique checklist identifier.
    pub id: Uuid,

    /// The asset being evaluated.
    pub asset: Asset,

    /// STIG benchmark metadata.
    pub stig_info: ChecklistStigInfo,

    /// Individual rule findings.
    pub findings: Vec<Finding>,

    /// When this checklist was created.
    pub created_at: DateTime<Utc>,

    /// When this checklist was last modified.
    pub modified_at: DateTime<Utc>,

    /// Tool that generated this checklist.
    pub generated_by: String,

    /// Format version of the checklist.
    pub format_version: String,

    /// Classification marking.
    pub classification: Classification,

    /// Collection provenance for evaluations which consumed device evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_provenance: Option<EvaluationProvenance>,
}

impl Checklist {
    /// Create a new empty checklist for the given asset and STIG.
    pub fn new(asset: Asset, stig_info: ChecklistStigInfo) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            asset,
            stig_info,
            findings: Vec::new(),
            created_at: now,
            modified_at: now,
            generated_by: format!("AutomateSTIG {}", env!("CARGO_PKG_VERSION")),
            format_version: "1".to_string(),
            classification: Classification::Unclassified,
            evaluation_provenance: None,
        }
    }

    /// Get a finding by Vuln ID, Group ID, or legacy ID.
    pub fn find_by_vuln_id(&self, vuln_id: &str) -> Option<&Finding> {
        self.findings.iter().find(|f| {
            f.vuln_id == vuln_id
                || f.group_id == vuln_id
                || f.legacy_ids.iter().any(|legacy_id| legacy_id == vuln_id)
        })
    }

    /// Get a mutable finding by Vuln ID, Group ID, or legacy ID.
    pub fn find_by_vuln_id_mut(&mut self, vuln_id: &str) -> Option<&mut Finding> {
        self.findings.iter_mut().find(|f| {
            f.vuln_id == vuln_id
                || f.group_id == vuln_id
                || f.legacy_ids.iter().any(|legacy_id| legacy_id == vuln_id)
        })
    }

    /// Get summary statistics.
    pub fn summary(&self) -> FindingSummary {
        FindingSummary::from_findings(&self.findings)
    }

    /// Get all open findings.
    pub fn open_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.status == FindingStatus::Open)
            .collect()
    }

    /// Mark this checklist as modified.
    pub fn touch(&mut self) {
        self.modified_at = Utc::now();
    }

    /// Explain why this checklist cannot cross an external compliance/export
    /// boundary. Imported manual checklists remain usable, but automated or
    /// supplied-evidence claims require complete, safe, durable provenance.
    pub fn external_export_block_reason(&self) -> Option<String> {
        let has_external_evaluation = self.findings.iter().any(|finding| {
            matches!(
                finding.source,
                FindingSource::Automated | FindingSource::Evidence
            )
        });

        if self
            .findings
            .iter()
            .any(|finding| finding.source == FindingSource::CollectionError)
        {
            return Some(
                "one or more rules have unresolved collection/evaluation errors".to_string(),
            );
        }

        if let Some(provenance) = &self.evaluation_provenance {
            match provenance.server_key_fingerprint.as_deref() {
                Some(fingerprint) if !is_openssh_sha256_fingerprint(fingerprint) => {
                    return Some(
                        "evaluation provenance contains a malformed SSH server-key fingerprint"
                            .to_string(),
                    );
                }
                None if provenance.origin == EvaluationOrigin::LiveSsh => {
                    return Some(
                        "live SSH evaluation provenance is missing its server-key fingerprint"
                            .to_string(),
                    );
                }
                _ => {}
            }
        }

        match &self.evaluation_provenance {
            Some(provenance) if provenance.unsafe_legacy_evidence => Some(
                "unsafe legacy evidence cannot be used for an external compliance result"
                    .to_string(),
            ),
            Some(provenance)
                if provenance.origin != EvaluationOrigin::ImportedChecklist
                    && (!provenance.collection_complete
                        || !provenance.collection_errors.is_empty()) =>
            {
                Some("device collection is incomplete".to_string())
            }
            Some(provenance)
                if provenance.origin == EvaluationOrigin::ImportedChecklist
                    && has_external_evaluation =>
            {
                Some("imported checklist contains unverified automation attribution".to_string())
            }
            None if has_external_evaluation => {
                Some("automated findings are missing durable evaluation provenance".to_string())
            }
            Some(provenance)
                if provenance.origin != EvaluationOrigin::ImportedChecklist
                    && has_external_evaluation =>
            {
                for (label, digest) in [
                    ("evidence", provenance.evidence_sha256.as_deref()),
                    ("benchmark", provenance.benchmark_sha256.as_deref()),
                    ("check-pack", provenance.check_pack_sha256.as_deref()),
                    (
                        "evaluation-plan",
                        provenance.evaluation_plan_sha256.as_deref(),
                    ),
                ] {
                    if let Some(reason) = required_sha256_block_reason(label, digest) {
                        return Some(reason);
                    }
                }

                if matches!(
                    provenance.origin,
                    EvaluationOrigin::LiveSsh | EvaluationOrigin::EvidenceFile
                ) {
                    if let Some(reason) = required_sha256_block_reason(
                        "collection-plan",
                        provenance.plan_sha256.as_deref(),
                    ) {
                        return Some(reason);
                    }
                }

                if let Some(policy) = &provenance.organization_policy {
                    if policy.policy_id.trim().is_empty() || policy.policy_version.trim().is_empty()
                    {
                        return Some(
                            "organization-policy provenance is missing its identity".to_string(),
                        );
                    }
                    if !is_lowercase_sha256(&policy.policy_sha256) {
                        return Some(
                            "organization-policy provenance contains a malformed policy SHA-256 binding"
                                .to_string(),
                        );
                    }
                    if !policy
                        .signer_fingerprint
                        .strip_prefix("SHA256:")
                        .is_some_and(is_lowercase_sha256)
                    {
                        return Some(
                            "organization-policy provenance contains a malformed signer fingerprint"
                                .to_string(),
                        );
                    }
                    if !policy.signature_verified {
                        return Some(
                            "organization-policy provenance does not retain a verified signature"
                                .to_string(),
                        );
                    }
                }

                let benchmark_sha256 = provenance.benchmark_sha256.as_deref().unwrap();
                let check_pack_sha256 = provenance.check_pack_sha256.as_deref().unwrap();
                let recorded_evaluation_plan_sha256 =
                    provenance.evaluation_plan_sha256.as_deref().unwrap();
                let stig_release =
                    format!("V{}R{}", self.stig_info.version, self.stig_info.release);
                let expected_evaluation_plan_sha256 = match evaluation_plan_sha256(
                    &self.stig_info.stig_id,
                    &stig_release,
                    benchmark_sha256,
                    check_pack_sha256,
                    provenance
                        .organization_policy
                        .as_ref()
                        .map(|policy| policy.policy_sha256.as_str()),
                ) {
                    Ok(digest) => digest,
                    Err(_) => {
                        return Some("evaluation-plan provenance could not be verified".to_string())
                    }
                };
                if recorded_evaluation_plan_sha256 != expected_evaluation_plan_sha256 {
                    return Some(
                        "evaluation-plan SHA-256 binding does not match the recorded evaluation inputs"
                            .to_string(),
                    );
                }

                None
            }
            _ => None,
        }
    }
}

/// STIG benchmark metadata stored in a checklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistStigInfo {
    /// STIG ID / filename.
    pub stig_id: String,

    /// STIG title (e.g., "Microsoft Windows Server 2022 Security Technical Implementation Guide").
    pub title: String,

    /// Version string (e.g., "1").
    pub version: String,

    /// Release (e.g., "4").
    pub release: String,

    /// Release date.
    pub release_date: Option<String>,

    /// UUID for STIG-Manager compatibility.
    pub uuid: Option<String>,

    /// Description.
    pub description: Option<String>,

    /// Filename of the source STIG.
    pub filename: Option<String>,
}

/// Classification marking for checklists and reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Classification {
    #[default]
    #[serde(rename = "UNCLASSIFIED")]
    Unclassified,
    #[serde(rename = "CUI")]
    Cui,
    #[serde(rename = "CONFIDENTIAL")]
    Confidential,
    #[serde(rename = "SECRET")]
    Secret,
    #[serde(rename = "TOP SECRET")]
    TopSecret,
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unclassified => write!(f, "UNCLASSIFIED"),
            Self::Cui => write!(f, "CUI"),
            Self::Confidential => write!(f, "CONFIDENTIAL"),
            Self::Secret => write!(f, "SECRET"),
            Self::TopSecret => write!(f, "TOP SECRET"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::asset::Asset;
    use crate::models::stig::Severity;

    fn make_stig_info() -> ChecklistStigInfo {
        ChecklistStigInfo {
            stig_id: "Windows_Server_2022_STIG".to_string(),
            title: "Microsoft Windows Server 2022 STIG".to_string(),
            version: "1".to_string(),
            release: "4".to_string(),
            release_date: Some("2024-07-24".to_string()),
            uuid: None,
            description: None,
            filename: None,
        }
    }

    fn repeated_sha256(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn valid_evaluation_provenance(
        stig_info: &ChecklistStigInfo,
        origin: EvaluationOrigin,
    ) -> EvaluationProvenance {
        let benchmark_sha256 = repeated_sha256('a');
        let check_pack_sha256 = repeated_sha256('b');
        let stig_release = format!("V{}R{}", stig_info.version, stig_info.release);
        let evaluation_plan_sha256 = evaluation_plan_sha256(
            &stig_info.stig_id,
            &stig_release,
            &benchmark_sha256,
            &check_pack_sha256,
            None,
        )
        .unwrap();
        EvaluationProvenance {
            origin,
            collection_complete: true,
            collection_errors: Vec::new(),
            evidence_sha256: Some(repeated_sha256('c')),
            claimed_hostname: Some("server01".to_string()),
            collector_version: Some("test".to_string()),
            collected_at: Some("2026-01-01T00:00:00Z".to_string()),
            plan_sha256: matches!(
                origin,
                EvaluationOrigin::LiveSsh | EvaluationOrigin::EvidenceFile
            )
            .then(|| repeated_sha256('d')),
            server_key_fingerprint: (origin == EvaluationOrigin::LiveSsh)
                .then(|| format!("SHA256:{}", "A".repeat(43))),
            benchmark_sha256: Some(benchmark_sha256),
            check_pack_sha256: Some(check_pack_sha256),
            evaluation_plan_sha256: Some(evaluation_plan_sha256),
            organization_policy: None,
            unsafe_legacy_evidence: false,
        }
    }

    fn automated_checklist() -> Checklist {
        let mut checklist = Checklist::new(Asset::new("server01"), make_stig_info());
        let mut finding = Finding::new_not_reviewed("V-1", "SV-1", "V-1", "Rule", Severity::High);
        finding.source = FindingSource::Automated;
        finding.status = FindingStatus::NotAFinding;
        checklist.findings.push(finding);
        checklist
    }

    #[test]
    fn test_new_checklist() {
        let cl = Checklist::new(Asset::new("server01"), make_stig_info());
        assert_eq!(cl.asset.hostname, "server01");
        assert_eq!(cl.stig_info.version, "1");
        assert!(cl.findings.is_empty());
    }

    #[test]
    fn test_find_by_vuln_id_matches_vuln_group_or_legacy_id() {
        let mut cl = Checklist::new(Asset::new("server01"), make_stig_info());
        let mut finding = Finding::new_not_reviewed("V-1", "SV-1", "G-1", "Rule 1", Severity::High);
        finding.legacy_ids = vec!["LEGACY-1".to_string()];
        cl.findings.push(finding);

        assert!(cl.find_by_vuln_id("V-1").is_some());
        assert!(cl.find_by_vuln_id("G-1").is_some());
        assert!(cl.find_by_vuln_id("LEGACY-1").is_some());
        assert!(cl.find_by_vuln_id("UNKNOWN").is_none());
    }

    #[test]
    fn test_checklist_summary() {
        let mut cl = Checklist::new(Asset::new("server01"), make_stig_info());
        cl.findings.push({
            let mut f = Finding::new_not_reviewed("V-1", "SV-1", "V-1", "R1", Severity::High);
            f.status = FindingStatus::Open;
            f
        });
        cl.findings.push({
            let mut f = Finding::new_not_reviewed("V-2", "SV-2", "V-2", "R2", Severity::Medium);
            f.status = FindingStatus::NotAFinding;
            f
        });

        let summary = cl.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.open, 1);
        assert_eq!(summary.not_a_finding, 1);
        assert_eq!(summary.cat_i_open, 1);
    }

    #[test]
    fn external_export_requires_complete_provenance_for_automated_results() {
        let mut cl = automated_checklist();
        assert!(cl.external_export_block_reason().is_some());

        cl.evaluation_provenance = Some(valid_evaluation_provenance(
            &cl.stig_info,
            EvaluationOrigin::LiveSsh,
        ));
        assert!(cl.external_export_block_reason().is_none());

        cl.evaluation_provenance
            .as_mut()
            .unwrap()
            .collection_complete = false;
        assert!(cl.external_export_block_reason().is_some());
    }

    #[test]
    fn external_export_requires_exact_universal_sha256_bindings() {
        let mut cl = automated_checklist();
        cl.evaluation_provenance = Some(valid_evaluation_provenance(
            &cl.stig_info,
            EvaluationOrigin::ConfigFile,
        ));
        assert!(cl.external_export_block_reason().is_none());

        for (index, label) in ["evidence", "benchmark", "check-pack", "evaluation-plan"]
            .into_iter()
            .enumerate()
        {
            let mut candidate = cl.clone();
            let provenance = candidate.evaluation_provenance.as_mut().unwrap();
            match index {
                0 => provenance.evidence_sha256 = None,
                1 => provenance.benchmark_sha256 = None,
                2 => provenance.check_pack_sha256 = None,
                3 => provenance.evaluation_plan_sha256 = None,
                _ => unreachable!(),
            }
            let reason = candidate
                .external_export_block_reason()
                .expect("missing digest must block export");
            assert!(reason.contains(label), "{reason}");

            let mut candidate = cl.clone();
            let provenance = candidate.evaluation_provenance.as_mut().unwrap();
            match index {
                0 => provenance.evidence_sha256 = Some("A".repeat(64)),
                1 => provenance.benchmark_sha256 = Some("A".repeat(64)),
                2 => provenance.check_pack_sha256 = Some("A".repeat(64)),
                3 => provenance.evaluation_plan_sha256 = Some("A".repeat(64)),
                _ => unreachable!(),
            }
            let reason = candidate
                .external_export_block_reason()
                .expect("non-lowercase digest must block export");
            assert!(reason.contains(label), "{reason}");
        }

        let provenance = cl.evaluation_provenance.as_mut().unwrap();
        provenance.evaluation_plan_sha256 = Some(repeated_sha256('f'));
        let reason = cl
            .external_export_block_reason()
            .expect("internally inconsistent evaluation plan must block export");
        assert!(reason.contains("does not match"), "{reason}");
    }

    #[test]
    fn external_export_requires_collection_plan_binding_for_collected_evidence() {
        let mut live = automated_checklist();
        live.evaluation_provenance = Some(valid_evaluation_provenance(
            &live.stig_info,
            EvaluationOrigin::LiveSsh,
        ));
        live.evaluation_provenance.as_mut().unwrap().plan_sha256 = None;
        let reason = live
            .external_export_block_reason()
            .expect("live evaluation without plan binding must be blocked");
        assert!(reason.contains("collection-plan"), "{reason}");

        live.evaluation_provenance.as_mut().unwrap().plan_sha256 = Some("A".repeat(64));
        let reason = live
            .external_export_block_reason()
            .expect("malformed live plan binding must be blocked");
        assert!(reason.contains("malformed collection-plan"), "{reason}");

        let mut evidence = automated_checklist();
        evidence.evaluation_provenance = Some(valid_evaluation_provenance(
            &evidence.stig_info,
            EvaluationOrigin::EvidenceFile,
        ));
        evidence.evaluation_provenance.as_mut().unwrap().plan_sha256 = None;
        assert!(evidence.external_export_block_reason().is_some());

        let mut config = automated_checklist();
        config.evaluation_provenance = Some(valid_evaluation_provenance(
            &config.stig_info,
            EvaluationOrigin::ConfigFile,
        ));
        assert!(config
            .evaluation_provenance
            .as_ref()
            .unwrap()
            .plan_sha256
            .is_none());
        assert!(config.external_export_block_reason().is_none());
    }

    #[test]
    fn external_export_validates_signed_organization_policy_provenance() {
        let mut cl = automated_checklist();
        let mut provenance =
            valid_evaluation_provenance(&cl.stig_info, EvaluationOrigin::ConfigFile);
        let policy_sha256 = repeated_sha256('e');
        provenance.organization_policy = Some(OrganizationPolicyProvenance {
            policy_id: "policy-1".to_string(),
            policy_version: "1".to_string(),
            policy_sha256: policy_sha256.clone(),
            signer_fingerprint: format!("SHA256:{}", repeated_sha256('f')),
            signature_verified: true,
        });
        provenance.evaluation_plan_sha256 = Some(
            evaluation_plan_sha256(
                &cl.stig_info.stig_id,
                &format!("V{}R{}", cl.stig_info.version, cl.stig_info.release),
                provenance.benchmark_sha256.as_deref().unwrap(),
                provenance.check_pack_sha256.as_deref().unwrap(),
                Some(&policy_sha256),
            )
            .unwrap(),
        );
        cl.evaluation_provenance = Some(provenance);
        assert!(cl.external_export_block_reason().is_none());

        let mut candidate = cl.clone();
        candidate
            .evaluation_provenance
            .as_mut()
            .unwrap()
            .organization_policy
            .as_mut()
            .unwrap()
            .signature_verified = false;
        let reason = candidate
            .external_export_block_reason()
            .expect("unverified policy signature must block export");
        assert!(reason.contains("verified signature"), "{reason}");

        let mut candidate = cl.clone();
        candidate
            .evaluation_provenance
            .as_mut()
            .unwrap()
            .organization_policy
            .as_mut()
            .unwrap()
            .policy_sha256 = "E".repeat(64);
        let reason = candidate
            .external_export_block_reason()
            .expect("malformed policy digest must block export");
        assert!(reason.contains("malformed policy"), "{reason}");

        let policy = cl
            .evaluation_provenance
            .as_mut()
            .unwrap()
            .organization_policy
            .as_mut()
            .unwrap();
        policy.signer_fingerprint = format!("SHA256:{}", "F".repeat(64));
        let reason = cl
            .external_export_block_reason()
            .expect("malformed policy signer fingerprint must block export");
        assert!(reason.contains("malformed signer"), "{reason}");
    }

    #[test]
    fn external_export_enforces_fingerprint_grammar_by_evaluation_origin() {
        let mut cl = Checklist::new(Asset::new("server01"), make_stig_info());
        cl.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::LiveSsh,
            collection_complete: true,
            collection_errors: Vec::new(),
            evidence_sha256: None,
            claimed_hostname: Some("server01".to_string()),
            collector_version: Some("test".to_string()),
            collected_at: Some("2026-01-01T00:00:00Z".to_string()),
            plan_sha256: Some("digest".to_string()),
            server_key_fingerprint: None,
            benchmark_sha256: None,
            check_pack_sha256: None,
            evaluation_plan_sha256: None,
            organization_policy: None,
            unsafe_legacy_evidence: false,
        });

        let reason = cl
            .external_export_block_reason()
            .expect("live SSH must retain its fingerprint");
        assert!(reason.contains("missing"));

        let provenance = cl.evaluation_provenance.as_mut().unwrap();
        provenance.server_key_fingerprint = Some("SHA256:not-a-real-fingerprint".to_string());
        let reason = cl
            .external_export_block_reason()
            .expect("malformed live fingerprint must block export");
        assert!(reason.contains("malformed"));

        let provenance = cl.evaluation_provenance.as_mut().unwrap();
        provenance.server_key_fingerprint = Some(format!("SHA256:{}", "A".repeat(43)));
        assert!(cl.external_export_block_reason().is_none());

        let provenance = cl.evaluation_provenance.as_mut().unwrap();
        provenance.origin = EvaluationOrigin::EvidenceFile;
        provenance.server_key_fingerprint = None;
        assert!(cl.external_export_block_reason().is_none());

        cl.evaluation_provenance
            .as_mut()
            .unwrap()
            .server_key_fingerprint = Some(format!("SHA256:{}=", "A".repeat(42)));
        let reason = cl
            .external_export_block_reason()
            .expect("malformed offline fingerprint must block export");
        assert!(reason.contains("malformed"));
    }
}
