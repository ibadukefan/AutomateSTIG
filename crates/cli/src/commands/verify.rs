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

    let result = verifier::verify_pack(path).context("Failed to verify pack")?;

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
        None => ui::detail("Signature", "not present (unsigned pack)"),
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

    if result.manifest_valid && result.integrity_valid {
        ui::success("Pack verification passed");
        println!();
        Ok(())
    } else {
        ui::error("Pack verification FAILED");
        println!();
        anyhow::bail!("Pack verification failed");
    }
}
