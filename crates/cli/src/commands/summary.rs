use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::models::stig::Severity;
use automatestig_parsers::{ckl, cklb};

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

    println!("Checklist Summary: {}", checklist.stig_info.title);
    println!("  Asset: {}", checklist.asset.hostname);
    println!(
        "  STIG: {} {}",
        checklist.stig_info.stig_id,
        format!(
            "V{}R{}",
            checklist.stig_info.version, checklist.stig_info.release
        )
    );

    let summary = checklist.summary();
    println!("\n  ┌──────────────────────────────────────────┐");
    println!("  │ Total Rules:      {:>6}                 │", summary.total);
    println!(
        "  │ Open:             {:>6}  (I:{} II:{} III:{}) │",
        summary.open, summary.cat_i_open, summary.cat_ii_open, summary.cat_iii_open
    );
    println!("  │ Not a Finding:    {:>6}                 │", summary.not_a_finding);
    println!("  │ Not Applicable:   {:>6}                 │", summary.not_applicable);
    println!("  │ Not Reviewed:     {:>6}                 │", summary.not_reviewed);
    println!(
        "  │ Compliance:       {:>5.1}%                 │",
        summary.compliance_pct()
    );
    println!("  └──────────────────────────────────────────┘");

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
        println!("\n  Filtered Findings ({}):", findings.len());
        println!(
            "  {:<12} {:<8} {:<15} {}",
            "Vuln ID", "Sev", "Status", "Title"
        );
        println!("  {}", "-".repeat(70));

        for f in &findings {
            let sev = f.severity_override.unwrap_or(f.severity);
            let title: String = f.rule_title.chars().take(40).collect();
            println!(
                "  {:<12} {:<8} {:<15} {}",
                f.vuln_id,
                sev.as_cat_str(),
                f.status,
                title,
            );
        }
    }

    Ok(())
}
