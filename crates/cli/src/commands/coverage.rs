use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::coverage::{
    parse_coverage_manifest, validate_coverage_manifest_with_content_root,
};

use crate::ui;

pub fn validate(manifest_path: &str) -> Result<()> {
    let path = Path::new(manifest_path);
    if !path.exists() {
        anyhow::bail!("Coverage manifest not found: {}", manifest_path);
    }

    ui::print_banner();
    ui::section("Validate Coverage Manifest");
    ui::detail("File", manifest_path);
    println!();

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read coverage manifest: {}", manifest_path))?;
    let manifest =
        parse_coverage_manifest(&content).context("Failed to parse coverage manifest")?;
    let content_root = std::env::current_dir().context("Failed to determine content root")?;
    let report = validate_coverage_manifest_with_content_root(&manifest, &content_root);

    ui::info("STIG", &manifest.stig_id);
    ui::info("Version", &manifest.version);
    ui::info("Status", &format!("{:?}", manifest.status));
    ui::info("Rules", &report.total_rules.to_string());
    ui::info("Automated", &report.automated.to_string());
    ui::info("Scanner import", &report.scanner_import.to_string());
    ui::info("Manual", &report.manual.to_string());
    ui::info("Not applicable", &report.not_applicable.to_string());
    ui::info("Unsupported", &report.unsupported.to_string());

    if report.is_valid() {
        println!();
        ui::success("Coverage manifest is internally consistent");
        return Ok(());
    }

    println!();
    for issue in &report.issues {
        ui::error(&format!("{}: {}", issue.field, issue.message));
    }
    anyhow::bail!("Coverage manifest validation failed")
}
