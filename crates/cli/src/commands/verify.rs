use std::path::Path;

use anyhow::{Context, Result};
use automatestig_stigpack::verifier;

pub fn run(pack_path: &str) -> Result<()> {
    let path = Path::new(pack_path);
    if !path.exists() {
        anyhow::bail!("Pack file not found: {}", pack_path);
    }

    println!("Verifying pack: {}", pack_path);

    let result = verifier::verify_pack(path)
        .context("Failed to verify pack")?;

    println!("  Manifest valid: {}", if result.manifest_valid { "YES" } else { "NO" });
    println!("  Integrity valid: {}", if result.integrity_valid { "YES" } else { "NO" });

    match result.signature_valid {
        Some(true) => println!("  Signature valid: YES"),
        Some(false) => println!("  Signature valid: NO"),
        None => println!("  Signature: Not present (unsigned pack)"),
    }

    if !result.file_results.is_empty() {
        println!("\n  Files ({}):", result.file_results.len());
        for f in &result.file_results {
            let status = if f.hash_match { "OK" } else { "FAIL" };
            println!("    [{}] {}", status, f.path);
        }
    }

    if !result.issues.is_empty() {
        println!("\n  Issues:");
        for issue in &result.issues {
            println!("    - {}", issue);
        }
    }

    if result.manifest_valid && result.integrity_valid {
        println!("\n  Pack verification: PASSED");
        Ok(())
    } else {
        anyhow::bail!("Pack verification: FAILED");
    }
}
