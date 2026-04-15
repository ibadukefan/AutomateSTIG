use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::library::StigLibrary;
use automatestig_stigpack::importer;

use super::library_path;

pub fn run(pack_path: &str, cli: &crate::Cli) -> Result<()> {
    let path = Path::new(pack_path);
    if !path.exists() {
        anyhow::bail!("Pack file not found: {}", pack_path);
    }

    let lib_path = library_path(cli);
    let mut library = StigLibrary::open_or_init(&lib_path)
        .context("Failed to open STIG library")?;

    println!("Importing content pack: {}", pack_path);
    println!("  Verifying integrity...");

    let result = importer::import_pack(path, &mut library)
        .context("Failed to import pack")?;

    println!("  Import complete!");
    println!("    Pack: {} v{}", result.pack_id, result.pack_version);
    println!("    Benchmarks imported: {}", result.benchmarks_imported);
    println!(
        "    Answer templates imported: {}",
        result.answer_templates_imported
    );
    println!(
        "    Remediation scripts imported: {}",
        result.remediation_scripts_imported
    );

    if !result.warnings.is_empty() {
        println!("\n  Warnings:");
        for w in &result.warnings {
            println!("    - {}", w);
        }
    }

    Ok(())
}
