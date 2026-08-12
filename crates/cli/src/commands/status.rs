use anyhow::{Context, Result};
use automatestig_core::scanner_profiles::{
    bundled_scanner_profile_catalog, ScannerEvidenceMode, ScannerProfileReadiness,
};
use console::style;

use crate::ui;

/// Report the immutable scanner contract compiled into this executable.
///
/// This intentionally does not open or initialize the retired mutable STIG
/// library and does not summarize legacy checklist portfolio state. Those
/// belong to release-maintainer and one-time migration tooling respectively.
pub fn run(_cli: &crate::Cli) -> Result<()> {
    ui::print_banner();

    let catalog = bundled_scanner_profile_catalog()
        .context("Release-bundled scanner content failed its integrity checks")?;
    ui::section("Scanner Content");
    ui::detail("Release line", catalog.release_line());
    ui::detail("Profiles", &catalog.profiles().len().to_string());
    ui::detail("Catalog SHA-256", catalog.supported_targets_sha256());
    println!();

    for profile in catalog.profiles() {
        let coverage = profile.coverage();
        let readiness = match profile.readiness() {
            ScannerProfileReadiness::Experimental => "experimental",
            ScannerProfileReadiness::Supported => "supported",
            ScannerProfileReadiness::Production => "production",
        };
        let collection = match profile.evidence_mode() {
            ScannerEvidenceMode::SshTranscript => "SSH evidence",
            ScannerEvidenceMode::RunningConfiguration => "running configuration",
        };
        println!(
            "    {} {} {} — {} — {}/{} automated — {}",
            style("•").dim(),
            style(profile.display_name()).cyan(),
            style(profile.stig_release()).dim(),
            collection,
            coverage.automated_checks(),
            coverage.benchmark_rules(),
            readiness,
        );
    }

    println!();
    ui::section("Operating Boundary");
    ui::detail("Role", "Difficult-device scanner and evidence producer");
    ui::detail("System of record", "STIG Manager");
    ui::detail("Evaluation", "Deterministic; no AI/ML");
    ui::detail(
        "Data directory",
        &super::default_data_dir().display().to_string(),
    );
    println!();

    Ok(())
}
