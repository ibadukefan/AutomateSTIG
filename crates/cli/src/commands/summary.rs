use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::models::checklist::{Checklist, EvaluationOrigin};
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::models::stig::Severity;
use automatestig_parsers::{ckl, cklb};

use crate::ui;

const IMPORTED_SCORE_REASON: &str = "imported checklist has unverified evaluation provenance";
const MISSING_PROVENANCE_SCORE_REASON: &str = "checklist has no verifiable evaluation provenance";

fn score_block_reason(checklist: &Checklist) -> Option<String> {
    match checklist.evaluation_provenance.as_ref() {
        Some(provenance) if provenance.origin == EvaluationOrigin::ImportedChecklist => {
            Some(IMPORTED_SCORE_REASON.to_string())
        }
        None => Some(MISSING_PROVENANCE_SCORE_REASON.to_string()),
        Some(_) => checklist.external_export_block_reason(),
    }
}

pub fn run(input: &str, open_only: bool, severity: Option<&str>) -> Result<()> {
    let path = Path::new(input);
    if !path.exists() {
        anyhow::bail!("File not found: {}", input);
    }

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let checklist = match ext {
        "ckl" => ckl::parse_ckl_file(path).context("Failed to parse CKL")?,
        "cklb" => cklb::parse_cklb_file(path).context("Failed to parse CKLB")?,
        "json" => {
            let content = std::fs::read_to_string(path)?;
            serde_json::from_str(&content)?
        }
        _ => anyhow::bail!("Unsupported format: .{}", ext),
    };

    let severity_filter = severity.and_then(Severity::from_cat_str);

    ui::print_banner();
    ui::section(&checklist.stig_info.title);
    ui::detail("Asset", &checklist.asset.hostname);
    ui::detail(
        "STIG",
        &format!(
            "{} V{}R{}",
            checklist.stig_info.stig_id, checklist.stig_info.version, checklist.stig_info.release,
        ),
    );
    ui::detail("Source", input);

    let summary = checklist.summary();
    let score_block_reason = score_block_reason(&checklist);
    let score_display = match score_block_reason.as_deref() {
        Some(reason) => ui::SummaryScoreDisplay::Withheld { reason },
        None => ui::SummaryScoreDisplay::Available {
            assessed_pass_pct: summary.assessed_pass_pct(),
            benchmark_coverage_pct: summary.benchmark_coverage_pct(),
        },
    };
    ui::print_summary_table(
        summary.total,
        summary.open,
        summary.not_a_finding,
        summary.not_applicable,
        summary.not_reviewed,
        summary.cat_i_open,
        summary.cat_ii_open,
        summary.cat_iii_open,
        score_display,
    );

    // Show findings list.
    let findings: Vec<_> = checklist
        .findings
        .iter()
        .filter(|f| {
            if open_only && f.status != FindingStatus::Open {
                return false;
            }
            if let Some(sev) = severity_filter {
                let effective_sev = f.severity_override.unwrap_or(f.severity);
                if effective_sev != sev {
                    return false;
                }
            }
            true
        })
        .collect();

    if open_only || severity.is_some() {
        ui::section(&format!("Filtered Findings ({})", findings.len()));
        ui::print_findings_header();

        for f in &findings {
            let sev = f.severity_override.unwrap_or(f.severity);
            ui::print_finding_row(
                &f.vuln_id,
                sev.as_cat_str(),
                &f.status.to_string(),
                &f.rule_title,
            );
        }
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use automatestig_core::check_packs::evaluation_plan_sha256;
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{
        ChecklistStigInfo, EvaluationOrigin, EvaluationProvenance,
    };

    use super::{score_block_reason, IMPORTED_SCORE_REASON, MISSING_PROVENANCE_SCORE_REASON};

    fn checklist() -> automatestig_core::models::checklist::Checklist {
        automatestig_core::models::checklist::Checklist::new(
            Asset::new("host"),
            ChecklistStigInfo {
                stig_id: "Example_STIG".to_string(),
                title: "Example".to_string(),
                version: "1".to_string(),
                release: "2".to_string(),
                release_date: None,
                uuid: None,
                description: None,
                filename: None,
            },
        )
    }

    fn trusted_provenance() -> EvaluationProvenance {
        let benchmark_sha256 = "11".repeat(32);
        let check_pack_sha256 = "22".repeat(32);
        let evaluation_plan_sha256 = evaluation_plan_sha256(
            "Example_STIG",
            "V1R2",
            &benchmark_sha256,
            &check_pack_sha256,
            None,
        )
        .unwrap();
        EvaluationProvenance {
            origin: EvaluationOrigin::ConfigFile,
            collection_complete: true,
            collection_errors: Vec::new(),
            evidence_sha256: Some("00".repeat(32)),
            claimed_hostname: Some("host".to_string()),
            collector_version: None,
            collected_at: None,
            plan_sha256: None,
            server_key_fingerprint: None,
            benchmark_sha256: Some(benchmark_sha256),
            check_pack_sha256: Some(check_pack_sha256),
            evaluation_plan_sha256: Some(evaluation_plan_sha256),
            organization_policy: None,
            unsafe_legacy_evidence: false,
        }
    }

    #[test]
    fn imported_and_missing_provenance_scores_are_withheld() {
        let unverified = checklist();
        assert_eq!(
            score_block_reason(&unverified).as_deref(),
            Some(MISSING_PROVENANCE_SCORE_REASON)
        );

        let mut imported = checklist();
        let mut provenance = trusted_provenance();
        provenance.origin = EvaluationOrigin::ImportedChecklist;
        imported.evaluation_provenance = Some(provenance);
        assert_eq!(
            score_block_reason(&imported).as_deref(),
            Some(IMPORTED_SCORE_REASON)
        );
    }

    #[test]
    fn central_block_reason_is_preserved_and_trusted_scores_are_available() {
        let mut checklist = checklist();
        checklist.evaluation_provenance = Some(trusted_provenance());
        assert_eq!(score_block_reason(&checklist), None);

        checklist
            .evaluation_provenance
            .as_mut()
            .unwrap()
            .collection_complete = false;
        let central_reason = checklist.external_export_block_reason().unwrap();
        assert_eq!(score_block_reason(&checklist), Some(central_reason));
    }
}
