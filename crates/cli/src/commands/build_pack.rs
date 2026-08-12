use std::path::Path;

use anyhow::{Context, Result};
use automatestig_stigpack::builder::PackBuilder;

use crate::ui;

pub fn generate_signing_key(output: &str) -> Result<()> {
    let private_path = std::path::PathBuf::from(output);
    let public_path = private_path.with_extension("pub");
    let (_, public_key) =
        automatestig_stigpack::signing::create_signing_key_pair(&private_path, &public_path)
            .context("Failed to create external content-signing key pair")?;

    ui::print_banner();
    ui::section("Generate Content-Signing Key");
    ui::output_file(
        "Private key",
        &private_path.display().to_string(),
        "Ed25519 seed — keep offline",
    );
    ui::output_file(
        "Public key",
        &public_path.display().to_string(),
        "Ed25519 trust anchor",
    );
    ui::detail(
        "Fingerprint",
        &automatestig_stigpack::signing::public_key_fingerprint(&public_key),
    );
    println!();
    Ok(())
}

pub fn run(
    id: &str,
    name: &str,
    version: &str,
    source: &str,
    output: &str,
    signing_key: &str,
) -> Result<()> {
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
    println!();

    let private_path = std::path::PathBuf::from(signing_key);
    let public_path = private_path.with_extension("pub");
    let (private_key, public_key) =
        automatestig_stigpack::signing::load_signing_key_pair(&private_path, &public_path)
            .context("Failed to load external content-signing key pair")?;
    ui::detail(
        "Signing key",
        &automatestig_stigpack::signing::public_key_fingerprint(&public_key),
    );

    let mut builder = PackBuilder::new(id, name, version)
        .author("AutomateSTIG CLI")
        .signing_key(private_key);
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

    let custom_dir = source_path.join("custom_checks");
    if custom_dir.exists() {
        builder = builder
            .add_directory("custom_checks", &custom_dir)
            .context("Failed to add custom checks directory")?;
        ui::success("Added custom_checks/");
        added_any = true;
    }

    let auto_dir = source_path.join("auto_check_packs");
    if auto_dir.exists() {
        builder = builder
            .add_directory("auto_check_packs", &auto_dir)
            .context("Failed to add generated check packs directory")?;
        ui::success("Added auto_check_packs/");
        added_any = true;
    }

    // Libraries store generated packs under a provenance-bearing directory
    // after trusted import. Preserve the wire format for compatibility when a
    // reviewed library is re-packed. PackBuilder rejects any duplicate archive
    // member deterministically if both source directories contain the same name.
    let reviewed_dir = source_path.join("reviewed_check_packs");
    if reviewed_dir.exists() {
        builder = builder
            .add_directory("auto_check_packs", &reviewed_dir)
            .context("Failed to add reviewed generated check packs directory")?;
        ui::success("Added reviewed_check_packs/ as auto_check_packs/");
        added_any = true;
    }

    if !added_any {
        anyhow::bail!(
            "Source directory contains no pack content (expected benchmarks/, answer_templates/, custom_checks/, auto_check_packs/, or reviewed_check_packs/): {}",
            source
        );
    }

    builder.build(output_path)?;

    let metadata = std::fs::metadata(output_path)?;
    println!();
    ui::success(&format!(
        "Pack built ({:.1} KB)",
        metadata.len() as f64 / 1024.0
    ));
    ui::output_file("Output", output, "stigpack");
    ui::output_file(
        "Trust key",
        &public_path.display().to_string(),
        "Ed25519 public key",
    );
    println!();

    Ok(())
}
