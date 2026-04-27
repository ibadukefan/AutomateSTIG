use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::models::stig::Severity;
use automatestig_parsers::{ckl, cklb};

use crate::ui;

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
    ui::print_summary_table(
        summary.total,
        summary.open,
        summary.not_a_finding,
        summary.not_applicable,
        summary.not_reviewed,
        summary.cat_i_open,
        summary.cat_ii_open,
        summary.cat_iii_open,
        summary.compliance_pct(),
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
        eprintln!();
    }

    Ok(())
}
