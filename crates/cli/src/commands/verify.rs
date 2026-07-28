use std::path::Path;

use anyhow::{Context, Result};
use automatestig_stigpack::verifier;
use console::style;

use crate::ui;

pub fn run(pack_path: &str) -> Result<()> {
    let path = Path::new(pack_path);
    if !path.exists() {
        anyhow::bail!("Pack file not found: {}", pack_path);
    }

    ui::print_banner();
    ui::section("Verify Content Pack");
    ui::detail("File", pack_path);
    println!();

    let trust_dir = std::env::var("AUTOMATESTIG_TRUSTED_KEYS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join(".automatestig/trusted_keys")
        });
    let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
    trust_store
        .load_from_directory(&trust_dir)
        .context("Failed to load trusted .stigpack keys")?;
    if trust_store.is_empty() {
        anyhow::bail!("No trusted .stigpack keys found in {}", trust_dir.display());
    }
    let result = verifier::verify_pack_with_trust(path, Some(&trust_store))
        .context("Failed to verify pack")?;

    // Manifest.
    if result.manifest_valid {
        ui::success("Manifest: valid");
    } else {
        ui::error("Manifest: INVALID");
    }

    // Integrity.
    if result.integrity_valid {
        ui::success("Integrity: all hashes match");
    } else {
        ui::error("Integrity: FAILED");
    }

    // Signature.
    match result.signature_valid {
        Some(true) => ui::success("Signature: verified"),
        Some(false) => ui::error("Signature: INVALID"),
        None if result.signature_present => ui::error("Signature: present but untrusted"),
        None => ui::error("Signature: not present"),
    }

    // File details.
    if !result.file_results.is_empty() {
        println!();
        ui::section(&format!("Files ({})", result.file_results.len()));
        for f in &result.file_results {
            if f.hash_match {
                println!("    {} {}", style("✓").green(), style(&f.path).dim(),);
            } else {
                println!("    {} {}", style("✗").red().bold(), style(&f.path).red(),);
            }
        }
    }

    if !result.issues.is_empty() {
        println!();
        for issue in &result.issues {
            ui::warn(issue);
        }
    }

    println!();

    if result.manifest_valid && result.integrity_valid && result.signature_valid == Some(true) {
        ui::success("Pack verification passed");
        println!();
        Ok(())
    } else {
        ui::error("Pack verification FAILED");
        println!();
        anyhow::bail!("Pack verification failed");
    }
}
