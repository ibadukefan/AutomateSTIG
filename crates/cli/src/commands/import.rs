use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::library::StigLibrary;
use automatestig_stigpack::importer;

use super::library_path;
use crate::ui;

pub fn run(pack_path: &str, cli: &crate::Cli) -> Result<()> {
    let path = Path::new(pack_path);
    if !path.exists() {
        anyhow::bail!("Pack file not found: {}", pack_path);
    }

    ui::print_banner();
    ui::section("Import Content Pack");
    ui::detail("Source", pack_path);

    let lib_path = library_path(cli);
    let mut library =
        StigLibrary::open_or_init(&lib_path).context("Failed to open STIG library")?;

    ui::detail("Library", &lib_path.display().to_string());
    println!();

    let allow_unsigned = std::env::var("AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let result = if allow_unsigned {
        ui::warn(
            "SIGNATURE VERIFICATION BYPASSED (AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1). \
             This content pack is UNTRUSTED and unverified — lab/testing use only. \
             Do not use unsigned content for production compliance evaluations.",
        );
        importer::import_pack(path, &mut library).context("Failed to import pack")?
    } else {
        let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
        let trust_dir = std::env::var("AUTOMATESTIG_TRUSTED_KEYS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
                    .join(".automatestig")
                    .join("trusted_keys")
            });
        trust_store
            .load_from_directory(&trust_dir)
            .context("Failed to load trusted .stigpack keys")?;
        if trust_store.is_empty() {
            anyhow::bail!(
                "Trusted .stigpack signature required, but no trusted keys are configured. Add Ed25519 .pub files to AUTOMATESTIG_TRUSTED_KEYS_DIR or set AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1 for explicit lab-only import."
            );
        }
        importer::import_pack_trusted(path, &mut library, &trust_store)
            .context("Failed to import trusted pack")?
    };

    ui::success(&format!(
        "Pack imported: {} v{}",
        result.pack_id, result.pack_version
    ));
    ui::info("Benchmarks", &result.benchmarks_imported.to_string());
    ui::info(
        "Answer templates",
        &result.answer_templates_imported.to_string(),
    );
    ui::info(
        "Remediation scripts",
        &result.remediation_scripts_imported.to_string(),
    );

    if !result.warnings.is_empty() {
        println!();
        for w in &result.warnings {
            ui::warn(w);
        }
    }

    println!();

    Ok(())
}
