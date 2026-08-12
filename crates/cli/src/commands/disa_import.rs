//! DISA XCCDF Import Pipeline.
//!
//! Imports raw DISA STIG XCCDF benchmark files (or ZIP archives from cyber.mil)
//! directly into the STIG library — no need to manually build a .stigpack.
//!
//! This is the fast path for getting new STIG content into AutomateSTIG:
//!   1. Download STIG ZIP from https://cyber.mil/stigs/downloads/
//!   2. Run: automatestig disa-import --input <path-to-zip-or-xccdf>

use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::library::{BenchmarkImport, GeneratedCheckPackIntent, StigLibrary};
use automatestig_parsers::disa::{self, ParsedBenchmark};

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
    println!();

    let ext = in_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let parsed = match ext.as_str() {
        "zip" => disa::parse_disa_zip_path(in_path).context("DISA ZIP import rejected")?,
        "xml" => vec![disa::parse_xccdf_path(in_path).context("XCCDF import rejected")?],
        _ => anyhow::bail!(
            "Unsupported format: .{}\n  Expected .zip (DISA STIG archive) or .xml (XCCDF benchmark)",
            ext
        ),
    };

    import_parsed(parsed, &mut library)?;

    println!();
    Ok(())
}

fn import_parsed(parsed: Vec<ParsedBenchmark>, library: &mut StigLibrary) -> Result<()> {
    let imports: Vec<_> = parsed
        .iter()
        // Raw XCCDF is benchmark/reference content, never executable scanner
        // content. Purge any pre-v0.2 prose-generated pack while importing it.
        .map(|item| BenchmarkImport::new(&item.benchmark, GeneratedCheckPackIntent::Remove))
        .collect();

    let outcome = library
        .import_benchmarks(&imports)
        .context("Failed to commit DISA benchmark batch")?;

    for item in &parsed {
        ui::success(&format!(
            "{} {} — {} rules (reference content only; source {})",
            item.benchmark.id,
            item.benchmark.version_string(),
            item.benchmark.rules.len(),
            item.source_name
        ));
    }
    ui::hr();
    ui::success(&format!(
        "{} benchmark(s) committed atomically ({} new, {} updated)",
        parsed.len(),
        outcome.added_count(),
        outcome.updated_count()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::checks::{CheckPack, CheckPlatform};
    use automatestig_core::models::stig::{Platform, StigBenchmark};

    #[test]
    fn test_is_xccdf_benchmark() {
        assert!(disa::is_xccdf_benchmark(
            "U_MS_Windows_Server_2022_V1R4_Manual-xccdf.xml"
        ));
        assert!(disa::is_xccdf_benchmark("U_RHEL_9_V1R2_Manual-xccdf.xml"));
        assert!(disa::is_xccdf_benchmark("some_stig_xccdf.xml"));
        assert!(!disa::is_xccdf_benchmark("readme.txt"));
        assert!(!disa::is_xccdf_benchmark("results-xccdf-results.xml"));
        assert!(!disa::is_xccdf_benchmark("oval.xml"));
    }

    #[test]
    fn disa_reimport_removes_a_stale_prose_generated_pack() {
        let temporary = tempfile::TempDir::new().unwrap();
        let library_root = temporary.path().join("library");
        let mut library = StigLibrary::init(&library_root).unwrap();
        let benchmark = StigBenchmark {
            id: "General_Purpose_Operating_System".to_string(),
            title: "General Purpose Operating System".to_string(),
            description: "No safely generated checks".to_string(),
            version: "3".to_string(),
            release: "3".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: Platform {
                family: "network".to_string(),
                name: "Unsupported device".to_string(),
                cpe: vec![],
            },
            rules: vec![],
        };
        let stale_pack = CheckPack {
            stig_id: benchmark.id.clone(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![],
        };
        library
            .import_benchmarks(&[BenchmarkImport::new(
                &benchmark,
                GeneratedCheckPackIntent::Replace(&stale_pack),
            )])
            .unwrap();
        let stale_path =
            library_root.join("auto_check_packs/General_Purpose_Operating_System.json");
        assert!(stale_path.exists());

        import_parsed(
            vec![ParsedBenchmark {
                source_name: "manual-only-xccdf.xml".to_string(),
                benchmark,
            }],
            &mut library,
        )
        .unwrap();

        assert!(!stale_path.exists());
    }
}
