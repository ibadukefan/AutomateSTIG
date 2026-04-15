use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::answer::AnswerFile;
use automatestig_core::engine::EvaluationEngine;
use automatestig_core::library::StigLibrary;
use automatestig_core::models::asset::Asset;
use automatestig_parsers::ckl;
use automatestig_parsers::cklb;
use automatestig_parsers::xccdf;
use automatestig_storage::Database;

use super::{db_path, library_path};

pub fn run(
    stig_id: String,
    scan: Option<String>,
    answer_paths: Vec<String>,
    host: Option<String>,
    output: Option<String>,
    format: Option<String>,
    merge: Option<String>,
    cli: &crate::Cli,
) -> Result<()> {
    let lib_path = library_path(cli);
    let library = StigLibrary::open(&lib_path)
        .context("Failed to open STIG library. Run 'automatestig library init' first.")?;

    // Load the benchmark.
    let benchmark = library
        .load_benchmark(&stig_id)
        .context(format!("Failed to load STIG benchmark '{}'", stig_id))?;

    println!(
        "Evaluating: {} ({}) — {} rules",
        benchmark.title,
        benchmark.version_string(),
        benchmark.rules.len()
    );

    // Parse scan results if provided.
    let scan_results = if let Some(ref scan_path) = scan {
        let path = Path::new(scan_path);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "xml" => {
                println!("  Loading XCCDF results from: {}", scan_path);
                Some(xccdf::parse_xccdf_results(path)?)
            }
            _ => {
                println!("  Scan format not recognized: {}", scan_path);
                None
            }
        }
    } else {
        None
    };

    // Load answer files.
    let answer_files: Vec<AnswerFile> = answer_paths
        .iter()
        .map(|p| {
            println!("  Loading answer file: {}", p);
            AnswerFile::load(Path::new(p)).context(format!("Failed to load answer file: {}", p))
        })
        .collect::<Result<Vec<_>>>()?;

    // Determine asset info.
    let hostname = host
        .or_else(|| {
            scan_results
                .as_ref()
                .and_then(|s| s.source.target.clone())
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let asset = Asset::new(&hostname);

    // Run evaluation.
    let engine = EvaluationEngine::with_defaults();
    let mut checklist = engine.evaluate(
        &benchmark,
        &asset,
        scan_results.as_ref(),
        &answer_files,
    )?;

    // Merge with previous if requested.
    if let Some(ref merge_path) = merge {
        println!("  Merging with previous checklist: {}", merge_path);
        let path = Path::new(merge_path);
        let previous = load_checklist_from_file(path)?;
        engine.merge_previous(&mut checklist, &previous)?;
    }

    // Print summary.
    let summary = checklist.summary();
    println!("\n  Results for {} ({}):", hostname, stig_id);
    println!("  ┌─────────────────────────────────────┐");
    println!("  │ Total Rules:    {:>6}              │", summary.total);
    println!("  │ Open:           {:>6}  (CAT I: {})  │", summary.open, summary.cat_i_open);
    println!("  │ Not a Finding:  {:>6}              │", summary.not_a_finding);
    println!("  │ Not Applicable: {:>6}              │", summary.not_applicable);
    println!("  │ Not Reviewed:   {:>6}              │", summary.not_reviewed);
    println!("  │ Compliance:     {:>5.1}%              │", summary.compliance_pct());
    println!("  └─────────────────────────────────────┘");

    // Write output.
    let output_path = output.unwrap_or_else(|| {
        format!(
            "{}_{}.ckl",
            hostname.replace(' ', "_"),
            stig_id
        )
    });

    let out_format = format
        .as_deref()
        .or_else(|| {
            Path::new(&output_path)
                .extension()
                .and_then(|e| e.to_str())
        })
        .unwrap_or("ckl");

    match out_format {
        "ckl" => {
            ckl::write_ckl_file(&checklist, Path::new(&output_path))?;
            println!("\n  Output written to: {} (CKL format)", output_path);
        }
        "cklb" => {
            cklb::write_cklb_file(&checklist, Path::new(&output_path))?;
            println!("\n  Output written to: {} (CKLB format)", output_path);
        }
        "json" => {
            let json = serde_json::to_string_pretty(&checklist)?;
            std::fs::write(&output_path, json)?;
            println!("\n  Output written to: {} (JSON format)", output_path);
        }
        _ => {
            anyhow::bail!("Unsupported output format: {}", out_format);
        }
    }

    // Save to database.
    let db = Database::open(&db_path(cli))?;
    db.save_checklist(&checklist)?;
    db.log_evaluation(&checklist, "cli-evaluate", Some(&format!("scan={:?}", scan)))?;

    Ok(())
}

fn load_checklist_from_file(path: &Path) -> Result<automatestig_core::models::Checklist> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "ckl" => Ok(ckl::parse_ckl_file(path)?),
        "cklb" => Ok(cklb::parse_cklb_file(path)?),
        "json" => {
            let content = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        }
        _ => anyhow::bail!("Unsupported checklist format: {}", ext),
    }
}
