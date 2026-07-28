//! Deterministic STIG rule evaluation engine.
//!
//! The engine takes a STIG benchmark and answer files,
//! then produces a fully populated checklist with deterministic, reproducible results.

use crate::answer::AnswerFile;
use crate::models::*;
use crate::Result;

/// The core evaluation engine — fully deterministic, no AI, no heuristics.
pub struct EvaluationEngine;

impl EvaluationEngine {
    pub fn with_defaults() -> Self {
        Self
    }

    /// Create a checklist from a STIG benchmark and apply answer files.
    ///
    /// This is the primary entry point. The process is:
    /// 1. Initialize a finding for every rule in the benchmark (Not_Reviewed).
    /// 2. Apply answer file entries — override status/comments for matching rules.
    /// 3. Return the populated checklist.
    pub fn evaluate(
        &self,
        benchmark: &StigBenchmark,
        asset: &Asset,
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
            finding.group_title = if rule.group_title.is_empty() {
                rule.group_id.clone()
            } else {
                rule.group_title.clone()
            };
            finding.rule_version = rule.rule_version.clone();
            finding.weight = rule.weight;
            finding.discussion = rule.discussion.clone();
            finding.check_content = rule.check_content.clone();
            finding.fix_text = rule.fix_text.clone();
            finding.stig_ref = rule.stig_ref.clone();
            checklist.findings.push(finding);
        }

        // Step 2: Apply answer files.
        for af in answer_files {
            self.apply_answer_file(&mut checklist, af)?;
        }

        checklist.touch();
        Ok(checklist)
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
                let should_apply = finding.source != FindingSource::CollectionError
                    && (entry.force_override
                        || finding.status == FindingStatus::NotReviewed
                        || finding.source == FindingSource::Manual);

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
    /// Used by CLI merge workflows to preserve manual overrides and comments.
    pub fn merge_previous(&self, current: &mut Checklist, previous: &Checklist) -> Result<()> {
        for prev_finding in &previous.findings {
            if let Some(curr_finding) = current.find_by_vuln_id_mut(&prev_finding.vuln_id) {
                // Keep the previous manual findings if current is still Not_Reviewed.
                if curr_finding.source != FindingSource::CollectionError
                    && curr_finding.status == FindingStatus::NotReviewed
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
                    group_title: "SRG-TEST-1".to_string(),
                    title: "Test Rule 1".to_string(),
                    rule_version: "TEST-1".to_string(),
                    discussion: "Test discussion".to_string(),
                    severity: Severity::High,
                    check_content: "Check something".to_string(),
                    fix_text: "Fix something".to_string(),
                    cci_refs: vec!["CCI-000068".to_string()],
                    legacy_ids: vec!["SV-OLD-1".to_string()],
                    stig_ref: None,
                    weight: 10.0,
                    automatable: CheckAutomation::Manual,
                },
                StigRule {
                    vuln_id: "V-100002".to_string(),
                    rule_id: "SV-100002r1_rule".to_string(),
                    group_id: "V-100002".to_string(),
                    group_title: "SRG-TEST-2".to_string(),
                    title: "Test Rule 2".to_string(),
                    rule_version: "TEST-2".to_string(),
                    discussion: "Test discussion 2".to_string(),
                    severity: Severity::Medium,
                    check_content: "Check something else".to_string(),
                    fix_text: "Fix something else".to_string(),
                    cci_refs: vec!["CCI-000069".to_string()],
                    legacy_ids: vec![],
                    stig_ref: None,
                    weight: 8.0,
                    automatable: CheckAutomation::Manual,
                },
            ],
        }
    }

    #[test]
    fn test_evaluate_initializes_unreviewed_findings() {
        let engine = EvaluationEngine::with_defaults();
        let benchmark = make_benchmark();
        let asset = Asset::new("testhost");

        let checklist = engine.evaluate(&benchmark, &asset, &[]).unwrap();

        assert_eq!(checklist.findings.len(), 2);
        assert!(checklist
            .findings
            .iter()
            .all(|f| f.status == FindingStatus::NotReviewed));
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

        let checklist = engine.evaluate(&benchmark, &asset, &[answer]).unwrap();

        let f = checklist.find_by_vuln_id("V-100001").unwrap();
        assert_eq!(f.status, FindingStatus::NotApplicable);
        assert_eq!(f.finding_details, "This system does not use this feature.");
    }

    #[test]
    fn answer_and_merge_cannot_override_collection_errors() {
        let engine = EvaluationEngine::with_defaults();
        let benchmark = make_benchmark();
        let asset = Asset::new("test-host");
        let mut current = engine.evaluate(&benchmark, &asset, &[]).unwrap();
        current.findings[0].source = FindingSource::CollectionError;
        current.findings[0].status = FindingStatus::NotReviewed;
        current.findings[0].finding_details = "collection failed".to_string();

        let answer = AnswerFile {
            name: "forced".to_string(),
            description: None,
            stig_id: Some(benchmark.id.clone()),
            version: "1".to_string(),
            entries: vec![crate::answer::AnswerEntry {
                vuln_id: current.findings[0].vuln_id.clone(),
                status: FindingStatus::NotAFinding,
                finding_details: Some("claimed pass".to_string()),
                comments: None,
                severity_override: None,
                severity_override_justification: None,
                force_override: true,
            }],
        };
        engine.apply_answer_file(&mut current, &answer).unwrap();

        let mut previous = engine.evaluate(&benchmark, &asset, &[]).unwrap();
        previous.findings[0].source = FindingSource::Manual;
        previous.findings[0].status = FindingStatus::NotAFinding;
        engine.merge_previous(&mut current, &previous).unwrap();

        assert_eq!(current.findings[0].source, FindingSource::CollectionError);
        assert_eq!(current.findings[0].status, FindingStatus::NotReviewed);
        assert_eq!(current.findings[0].finding_details, "collection failed");
    }
}
