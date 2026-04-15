//! Deterministic STIG rule evaluation engine.
//!
//! The engine takes a STIG benchmark, scan results (or device config), and answer files,
//! then produces a fully populated checklist with deterministic, reproducible results.

use crate::answer::AnswerFile;
use crate::models::*;
use crate::Result;

/// Configuration for an evaluation run.
#[derive(Debug, Clone)]
pub struct EvaluationConfig {
    /// Whether to apply answer file entries.
    pub apply_answer_files: bool,

    /// Whether to mark automated checks as "Automated" source.
    pub mark_automated: bool,

    /// Default evaluated_by string for automated checks.
    pub evaluated_by: String,

    /// Whether to overwrite existing findings (from a previous run).
    pub overwrite_existing: bool,
}

impl Default for EvaluationConfig {
    fn default() -> Self {
        Self {
            apply_answer_files: true,
            mark_automated: true,
            evaluated_by: format!("AutomateSTIG {}", env!("CARGO_PKG_VERSION")),
            overwrite_existing: true,
        }
    }
}

/// The core evaluation engine — fully deterministic, no AI, no heuristics.
pub struct EvaluationEngine {
    config: EvaluationConfig,
}

impl EvaluationEngine {
    pub fn new(config: EvaluationConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(EvaluationConfig::default())
    }

    /// Evaluate a STIG benchmark against scan results and answer files.
    ///
    /// This is the primary entry point. The process is:
    /// 1. Initialize a finding for every rule in the benchmark (Not_Reviewed).
    /// 2. Apply scan results — map each scan result to a rule and set status.
    /// 3. Apply answer file entries — override status/comments for matching rules.
    /// 4. Return the populated checklist.
    pub fn evaluate(
        &self,
        benchmark: &StigBenchmark,
        asset: &Asset,
        scan_results: Option<&ScanResultSet>,
        answer_files: &[AnswerFile],
    ) -> Result<Checklist> {
        let stig_info = ChecklistStigInfo {
            stig_id: benchmark.id.clone(),
            title: benchmark.title.clone(),
            version: benchmark.version.clone(),
            release: benchmark.release.clone(),
            release_date: benchmark.release_date.map(|d| d.to_string()),
            uuid: None,
            description: Some(benchmark.description.clone()),
            filename: None,
        };

        let mut checklist = Checklist::new(asset.clone(), stig_info);

        // Step 1: Initialize all findings as Not_Reviewed.
        for rule in &benchmark.rules {
            let mut finding = Finding::new_not_reviewed(
                &rule.vuln_id,
                &rule.rule_id,
                &rule.group_id,
                &rule.title,
                rule.severity,
            );
            finding.cci_refs = rule.cci_refs.clone();
            finding.legacy_ids = rule.legacy_ids.clone();
            checklist.findings.push(finding);
        }

        // Step 2: Apply scan results (if any).
        if let Some(results) = scan_results {
            self.apply_scan_results(&mut checklist, results, benchmark)?;
        }

        // Step 3: Apply answer files (if enabled).
        if self.config.apply_answer_files {
            for af in answer_files {
                self.apply_answer_file(&mut checklist, af)?;
            }
        }

        checklist.touch();
        Ok(checklist)
    }

    /// Map scan results to checklist findings.
    fn apply_scan_results(
        &self,
        checklist: &mut Checklist,
        results: &ScanResultSet,
        benchmark: &StigBenchmark,
    ) -> Result<()> {
        for result in &results.results {
            // Try to find the matching rule by various reference types.
            let idx = self.find_matching_finding_index(checklist, &result.rule_ref, benchmark);

            if let Some(idx) = idx {
                // Map the scan result to a finding status.
                // Check raw_result first for richer status (e.g., "notapplicable").
                let status = match result.raw_result.as_str() {
                    "notapplicable" | "not_applicable" => FindingStatus::NotApplicable,
                    _ => match result.passed {
                        Some(true) => FindingStatus::NotAFinding,
                        Some(false) => FindingStatus::Open,
                        None => FindingStatus::NotReviewed,
                    },
                };

                let finding = &mut checklist.findings[idx];

                if self.config.overwrite_existing || finding.status == FindingStatus::NotReviewed {
                    finding.status = status;
                    finding.source = match results.source.scanner {
                        ScannerType::Scc => FindingSource::SccScan,
                        ScannerType::Acas => FindingSource::AcasScan,
                        ScannerType::OpenScap => FindingSource::OpenScap,
                        _ => FindingSource::Automated,
                    };

                    if let Some(evidence) = &result.evidence {
                        finding.finding_details = evidence.clone();
                        finding.evidence = Some(evidence.clone());
                    }

                    if self.config.mark_automated {
                        finding.evaluated_by = self.config.evaluated_by.clone();
                    }

                    finding.evaluated_at = chrono::Utc::now();
                }
            }
        }
        Ok(())
    }

    /// Find the index of a finding in the checklist that matches a scan result reference.
    fn find_matching_finding_index(
        &self,
        checklist: &Checklist,
        rule_ref: &str,
        benchmark: &StigBenchmark,
    ) -> Option<usize> {
        // Direct match on Vuln ID.
        if let Some(idx) = checklist.findings.iter().position(|f| f.vuln_id == rule_ref) {
            return Some(idx);
        }

        // Match on Rule ID.
        if let Some(idx) = checklist.findings.iter().position(|f| f.rule_id == rule_ref) {
            return Some(idx);
        }

        // Match on Group ID.
        if let Some(idx) = checklist.findings.iter().position(|f| f.group_id == rule_ref) {
            return Some(idx);
        }

        // Match via legacy IDs in the benchmark.
        for rule in &benchmark.rules {
            if rule.legacy_ids.iter().any(|lid| lid == rule_ref) {
                if let Some(idx) = checklist.findings.iter().position(|f| f.vuln_id == rule.vuln_id) {
                    return Some(idx);
                }
            }
        }

        None
    }

    /// Apply an answer file to the checklist.
    fn apply_answer_file(&self, checklist: &mut Checklist, answer_file: &AnswerFile) -> Result<()> {
        // Check if this answer file applies to this STIG.
        if let Some(ref stig_id) = answer_file.stig_id {
            if *stig_id != checklist.stig_info.stig_id {
                return Ok(()); // Answer file is for a different STIG.
            }
        }

        for entry in &answer_file.entries {
            if let Some(finding) = checklist.find_by_vuln_id_mut(&entry.vuln_id) {
                // Only apply if the finding hasn't been set by a higher-priority source,
                // or if force_override is set.
                let should_apply = entry.force_override
                    || finding.status == FindingStatus::NotReviewed
                    || finding.source == FindingSource::Manual;

                if should_apply {
                    finding.status = entry.status;
                    finding.source = FindingSource::AnswerFile;

                    if let Some(ref details) = entry.finding_details {
                        finding.finding_details = details.clone();
                    }
                    if let Some(ref comments) = entry.comments {
                        finding.comments = comments.clone();
                    }
                    if let Some(ref sev) = entry.severity_override {
                        finding.severity_override = Some(*sev);
                        finding.severity_override_justification =
                            entry.severity_override_justification.clone();
                    }
                }
            }
        }
        Ok(())
    }

    /// Merge findings from a previous checklist into a new one.
    /// Used when re-evaluating — preserves manual overrides and comments.
    pub fn merge_previous(
        &self,
        current: &mut Checklist,
        previous: &Checklist,
    ) -> Result<()> {
        for prev_finding in &previous.findings {
            if let Some(curr_finding) = current.find_by_vuln_id_mut(&prev_finding.vuln_id) {
                // Keep the previous manual findings if current is still Not_Reviewed.
                if curr_finding.status == FindingStatus::NotReviewed
                    && prev_finding.source == FindingSource::Manual
                {
                    curr_finding.status = prev_finding.status;
                    curr_finding.source = FindingSource::Imported;
                    curr_finding.finding_details = prev_finding.finding_details.clone();
                    curr_finding.comments = prev_finding.comments.clone();
                    curr_finding.severity_override = prev_finding.severity_override;
                    curr_finding.severity_override_justification =
                        prev_finding.severity_override_justification.clone();
                }
            }
        }
        current.touch();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::stig::{CheckAutomation, Platform, Severity};

    fn make_benchmark() -> StigBenchmark {
        StigBenchmark {
            id: "Test_STIG".to_string(),
            title: "Test STIG".to_string(),
            description: "A test benchmark".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: Platform::default(),
            rules: vec![
                StigRule {
                    vuln_id: "V-100001".to_string(),
                    rule_id: "SV-100001r1_rule".to_string(),
                    group_id: "V-100001".to_string(),
                    title: "Test Rule 1".to_string(),
                    discussion: "Test discussion".to_string(),
                    severity: Severity::High,
                    check_content: "Check something".to_string(),
                    fix_text: "Fix something".to_string(),
                    cci_refs: vec!["CCI-000068".to_string()],
                    legacy_ids: vec!["SV-OLD-1".to_string()],
                    stig_ref: None,
                    weight: 10.0,
                    automatable: CheckAutomation::Manual,
                    automated_check: None,
                    remediation_ids: vec![],
                },
                StigRule {
                    vuln_id: "V-100002".to_string(),
                    rule_id: "SV-100002r1_rule".to_string(),
                    group_id: "V-100002".to_string(),
                    title: "Test Rule 2".to_string(),
                    discussion: "Test discussion 2".to_string(),
                    severity: Severity::Medium,
                    check_content: "Check something else".to_string(),
                    fix_text: "Fix something else".to_string(),
                    cci_refs: vec!["CCI-000069".to_string()],
                    legacy_ids: vec![],
                    stig_ref: None,
                    weight: 8.0,
                    automatable: CheckAutomation::Manual,
                    automated_check: None,
                    remediation_ids: vec![],
                },
            ],
        }
    }

    #[test]
    fn test_evaluate_empty_scan() {
        let engine = EvaluationEngine::with_defaults();
        let benchmark = make_benchmark();
        let asset = Asset::new("testhost");

        let checklist = engine.evaluate(&benchmark, &asset, None, &[]).unwrap();

        assert_eq!(checklist.findings.len(), 2);
        assert!(checklist
            .findings
            .iter()
            .all(|f| f.status == FindingStatus::NotReviewed));
    }

    #[test]
    fn test_evaluate_with_scan_results() {
        let engine = EvaluationEngine::with_defaults();
        let benchmark = make_benchmark();
        let asset = Asset::new("testhost");

        let scan = ScanResultSet {
            source: ScanSource {
                scanner: ScannerType::Scc,
                scanner_version: Some("5.7".to_string()),
                scan_date: None,
                source_file: None,
                target: Some("testhost".to_string()),
                profile: None,
            },
            results: vec![
                ScanResult {
                    rule_ref: "V-100001".to_string(),
                    passed: Some(false),
                    raw_result: "fail".to_string(),
                    evidence: Some("Registry value not set".to_string()),
                    benchmark_ref: None,
                },
                ScanResult {
                    rule_ref: "V-100002".to_string(),
                    passed: Some(true),
                    raw_result: "pass".to_string(),
                    evidence: Some("Setting configured correctly".to_string()),
                    benchmark_ref: None,
                },
            ],
        };

        let checklist = engine.evaluate(&benchmark, &asset, Some(&scan), &[]).unwrap();

        assert_eq!(checklist.find_by_vuln_id("V-100001").unwrap().status, FindingStatus::Open);
        assert_eq!(
            checklist.find_by_vuln_id("V-100002").unwrap().status,
            FindingStatus::NotAFinding
        );
    }

    #[test]
    fn test_evaluate_with_answer_file() {
        let engine = EvaluationEngine::with_defaults();
        let benchmark = make_benchmark();
        let asset = Asset::new("testhost");

        let answer = AnswerFile {
            name: "Test Answers".to_string(),
            description: None,
            stig_id: Some("Test_STIG".to_string()),
            version: "1.0".to_string(),
            entries: vec![crate::answer::AnswerEntry {
                vuln_id: "V-100001".to_string(),
                status: FindingStatus::NotApplicable,
                finding_details: Some("This system does not use this feature.".to_string()),
                comments: Some("Verified by admin".to_string()),
                severity_override: None,
                severity_override_justification: None,
                force_override: false,
            }],
        };

        let checklist = engine.evaluate(&benchmark, &asset, None, &[answer]).unwrap();

        let f = checklist.find_by_vuln_id("V-100001").unwrap();
        assert_eq!(f.status, FindingStatus::NotApplicable);
        assert_eq!(f.finding_details, "This system does not use this feature.");
    }

    #[test]
    fn test_evaluate_scan_overrides_answer_file() {
        // When both scan results and answer file exist, scan results take precedence
        // unless the finding is still Not_Reviewed.
        let engine = EvaluationEngine::with_defaults();
        let benchmark = make_benchmark();
        let asset = Asset::new("testhost");

        let scan = ScanResultSet {
            source: ScanSource {
                scanner: ScannerType::Scc,
                scanner_version: None,
                scan_date: None,
                source_file: None,
                target: None,
                profile: None,
            },
            results: vec![ScanResult {
                rule_ref: "V-100001".to_string(),
                passed: Some(false),
                raw_result: "fail".to_string(),
                evidence: None,
                benchmark_ref: None,
            }],
        };

        let answer = AnswerFile {
            name: "Test".to_string(),
            description: None,
            stig_id: Some("Test_STIG".to_string()),
            version: "1.0".to_string(),
            entries: vec![crate::answer::AnswerEntry {
                vuln_id: "V-100001".to_string(),
                status: FindingStatus::NotApplicable,
                finding_details: None,
                comments: None,
                severity_override: None,
                severity_override_justification: None,
                force_override: false, // Will NOT override scan result
            }],
        };

        let checklist = engine.evaluate(&benchmark, &asset, Some(&scan), &[answer]).unwrap();

        // Scan result (Open) should prevail because the answer file has force_override=false
        // and the finding was set by SCC scan (not Manual source).
        let f = checklist.find_by_vuln_id("V-100001").unwrap();
        assert_eq!(f.status, FindingStatus::Open);
    }

    #[test]
    fn test_evaluate_legacy_id_matching() {
        let engine = EvaluationEngine::with_defaults();
        let benchmark = make_benchmark();
        let asset = Asset::new("testhost");

        let scan = ScanResultSet {
            source: ScanSource {
                scanner: ScannerType::Scc,
                scanner_version: None,
                scan_date: None,
                source_file: None,
                target: None,
                profile: None,
            },
            results: vec![ScanResult {
                rule_ref: "SV-OLD-1".to_string(), // Legacy ID
                passed: Some(true),
                raw_result: "pass".to_string(),
                evidence: None,
                benchmark_ref: None,
            }],
        };

        let checklist = engine.evaluate(&benchmark, &asset, Some(&scan), &[]).unwrap();
        assert_eq!(
            checklist.find_by_vuln_id("V-100001").unwrap().status,
            FindingStatus::NotAFinding
        );
    }
}
