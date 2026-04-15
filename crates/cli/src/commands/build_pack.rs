use std::path::Path;

use anyhow::{Context, Result};
use automatestig_stigpack::builder::PackBuilder;

pub fn run(id: &str, name: &str, version: &str, source: &str, output: &str) -> Result<()> {
    let source_path = Path::new(source);
    let output_path = Path::new(output);

    if !source_path.exists() || !source_path.is_dir() {
        anyhow::bail!("Source directory not found: {}", source);
    }

    println!("Building .stigpack:");
    println!("  ID: {}", id);
    println!("  Name: {}", name);
    println!("  Version: {}", version);
    println!("  Source: {}", source);

    let mut builder = PackBuilder::new(id, name, version)
        .author("AutomateSTIG CLI");

    // Add benchmarks directory if present.
    let benchmarks_dir = source_path.join("benchmarks");
    if benchmarks_dir.exists() {
        builder = builder
            .add_directory("benchmarks", &benchmarks_dir)
            .context("Failed to add benchmarks directory")?;
    }

    // Add answer templates directory if present.
    let templates_dir = source_path.join("answer_templates");
    if templates_dir.exists() {
        builder = builder
            .add_directory("answer_templates", &templates_dir)
            .context("Failed to add answer templates directory")?;
    }

    // Add remediation directory if present.
    let remediation_dir = source_path.join("remediation");
    if remediation_dir.exists() {
        builder = builder
            .add_directory("remediation", &remediation_dir)
            .context("Failed to add remediation directory")?;
    }

    // Add custom checks directory if present.
    let custom_dir = source_path.join("custom_checks");
    if custom_dir.exists() {
        builder = builder
            .add_directory("custom_checks", &custom_dir)
            .context("Failed to add custom checks directory")?;
    }

    builder.build(output_path)?;

    let metadata = std::fs::metadata(output_path)?;
    println!(
        "\n  Pack built successfully: {} ({:.1} KB)",
        output,
        metadata.len() as f64 / 1024.0
    );

    Ok(())
}
