//! DISA XCCDF Import Pipeline.
//!
//! Imports raw DISA STIG XCCDF benchmark files (or ZIP archives from cyber.mil)
//! directly into the STIG library — no need to manually build a .stigpack.
//!
//! This is the fast path for getting new STIG content into AutomateSTIG:
//!   1. Download STIG ZIP from https://cyber.mil/stigs/downloads/
//!   2. Run: automatestig disa-import --input <path-to-zip-or-xccdf>

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::library::StigLibrary;
use automatestig_parsers::xccdf;

use super::library_path;
use crate::ui;

pub fn run(input: &str, cli: &crate::Cli) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        anyhow::bail!("Input file not found: {}", input);
    }

    ui::print_banner();
    ui::section("Import DISA STIG Content");
    ui::detail("Source", input);

    let lib_path = library_path(cli);
    let mut library =
        StigLibrary::open_or_init(&lib_path).context("Failed to open STIG library")?;

    ui::detail("Library", &lib_path.display().to_string());
    eprintln!();

    let ext = in_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "zip" => import_zip(in_path, &mut library)?,
        "xml" => import_xccdf_file(in_path, &mut library)?,
        _ => anyhow::bail!(
            "Unsupported format: .{}\n  Expected .zip (DISA STIG archive) or .xml (XCCDF benchmark)",
            ext
        ),
    }

    eprintln!();
    Ok(())
}

/// Import a DISA STIG ZIP archive (as downloaded from cyber.mil).
///
/// DISA ZIP structure typically contains:
///   U_<STIG_Name>_V<X>R<Y>_Manual-xccdf.xml
///   (and sometimes OVAL, CPE, readme files)
fn import_zip(zip_path: &Path, library: &mut StigLibrary) -> Result<()> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file).context("Failed to open ZIP archive")?;

    let mut imported = 0;
    let mut skipped = 0;

    // Scan all files in the ZIP for XCCDF benchmarks.
    let xccdf_files: Vec<String> = (0..archive.len())
        .filter_map(|i| {
            let file = archive.by_index(i).ok()?;
            let name = file.name().to_string();
            if is_xccdf_benchmark(&name) {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    if xccdf_files.is_empty() {
        ui::warn("No XCCDF benchmark files found in ZIP archive");
        ui::detail(
            "Hint",
            "DISA XCCDF files typically end in '-xccdf.xml' or '_Manual-xccdf.xml'",
        );
        return Ok(());
    }

    for xccdf_name in &xccdf_files {
        let mut file = archive
            .by_name(xccdf_name)
            .context(format!("Failed to read {} from ZIP", xccdf_name))?;

        let mut xml = String::new();
        file.read_to_string(&mut xml)?;

        match xccdf::parse_xccdf_benchmark_str(&xml) {
            Ok(benchmark) => {
                let id = benchmark.id.clone();
                let ver = benchmark.version_string();
                let rules = benchmark.rules.len();

                match library.add_benchmark(&benchmark) {
                    Ok(()) => {
                        let conv = automatestig_core::converter::convert_benchmark(&benchmark);
                        if conv.automated > 0 {
                            let packs_dir = library.root().join("auto_check_packs");
                            let _ = std::fs::create_dir_all(&packs_dir);
                            if let Ok(json) =
                                automatestig_core::converter::check_pack_to_json(&conv.check_pack)
                            {
                                if let Ok(dest) = automatestig_core::path_safety::safe_join_under(
                                    &packs_dir,
                                    &format!("{}.json", benchmark.id),
                                ) {
                                    let _ = std::fs::write(dest, &json);
                                }
                            }
                        }
                        ui::success(&format!(
                            "{} {} — {} rules ({} auto-checks)",
                            id, ver, rules, conv.automated
                        ));
                        imported += 1;
                    }
                    Err(e) => {
                        ui::warn(&format!("Failed to add {}: {}", id, e));
                        skipped += 1;
                    }
                }
            }
            Err(e) => {
                ui::warn(&format!("Failed to parse {}: {}", xccdf_name, e));
                skipped += 1;
            }
        }
    }

    ui::hr();
    ui::success(&format!(
        "{} benchmark(s) imported, {} skipped",
        imported, skipped
    ));

    Ok(())
}

/// Import a single XCCDF benchmark XML file.
fn import_xccdf_file(xml_path: &Path, library: &mut StigLibrary) -> Result<()> {
    let benchmark =
        xccdf::parse_xccdf_benchmark(xml_path).context("Failed to parse XCCDF benchmark")?;

    let id = benchmark.id.clone();
    let ver = benchmark.version_string();
    let rules = benchmark.rules.len();

    library
        .add_benchmark(&benchmark)
        .context(format!("Failed to add benchmark {}", id))?;

    let conv = automatestig_core::converter::convert_benchmark(&benchmark);
    if conv.automated > 0 {
        let packs_dir = library.root().join("auto_check_packs");
        let _ = std::fs::create_dir_all(&packs_dir);
        if let Ok(json) = automatestig_core::converter::check_pack_to_json(&conv.check_pack) {
            if let Ok(dest) = automatestig_core::path_safety::safe_join_under(
                &packs_dir,
                &format!("{}.json", benchmark.id),
            ) {
                let _ = std::fs::write(dest, &json);
            }
        }
    }

    ui::success(&format!(
        "{} {} — {} rules ({} auto-checks)",
        id, ver, rules, conv.automated
    ));

    Ok(())
}

/// Check if a filename looks like an XCCDF benchmark file.
fn is_xccdf_benchmark(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with("-xccdf.xml") || lower.ends_with("_xccdf.xml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_xccdf_benchmark() {
        assert!(is_xccdf_benchmark(
            "U_MS_Windows_Server_2022_V1R4_Manual-xccdf.xml"
        ));
        assert!(is_xccdf_benchmark("U_RHEL_9_V1R2_Manual-xccdf.xml"));
        assert!(is_xccdf_benchmark("some_stig_xccdf.xml"));
        assert!(!is_xccdf_benchmark("readme.txt"));
        assert!(!is_xccdf_benchmark("results-xccdf-results.xml"));
        assert!(!is_xccdf_benchmark("oval.xml"));
    }
}
