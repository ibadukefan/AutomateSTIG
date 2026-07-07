use std::path::Path;

use anyhow::{Context, Result};
use automatestig_stigpack::builder::PackBuilder;

use crate::ui;

pub fn run(id: &str, name: &str, version: &str, source: &str, output: &str) -> Result<()> {
    let source_path = Path::new(source);
    let output_path = Path::new(output);

    if !source_path.exists() || !source_path.is_dir() {
        anyhow::bail!("Source directory not found: {}", source);
    }

    ui::print_banner();
    ui::section("Build Content Pack");
    ui::detail("Pack ID", id);
    ui::detail("Name", name);
    ui::detail("Version", version);
    ui::detail("Source", source);
    eprintln!();

    let mut builder = PackBuilder::new(id, name, version).author("AutomateSTIG CLI");
    let mut added_any = false;

    let benchmarks_dir = source_path.join("benchmarks");
    if benchmarks_dir.exists() {
        builder = builder
            .add_directory("benchmarks", &benchmarks_dir)
            .context("Failed to add benchmarks directory")?;
        ui::success("Added benchmarks/");
        added_any = true;
    }

    let templates_dir = source_path.join("answer_templates");
    if templates_dir.exists() {
        builder = builder
            .add_directory("answer_templates", &templates_dir)
            .context("Failed to add answer templates directory")?;
        ui::success("Added answer_templates/");
        added_any = true;
    }

    let remediation_dir = source_path.join("remediation");
    if remediation_dir.exists() {
        builder = builder
            .add_directory("remediation", &remediation_dir)
            .context("Failed to add remediation directory")?;
        ui::success("Added remediation/");
        added_any = true;
    }

    let custom_dir = source_path.join("custom_checks");
    if custom_dir.exists() {
        builder = builder
            .add_directory("custom_checks", &custom_dir)
            .context("Failed to add custom checks directory")?;
        ui::success("Added custom_checks/");
        added_any = true;
    }

    if !added_any {
        anyhow::bail!(
            "Source directory contains no pack content (expected at least one of benchmarks/, answer_templates/, remediation/, custom_checks/): {}",
            source
        );
    }

    builder.build(output_path)?;

    let metadata = std::fs::metadata(output_path)?;
    eprintln!();
    ui::success(&format!(
        "Pack built ({:.1} KB)",
        metadata.len() as f64 / 1024.0
    ));
    ui::output_file("Output", output, "stigpack");
    eprintln!();

    Ok(())
}
