use std::path::Path;

use anyhow::{Context, Result};
use automatestig_integrations::emass;
use automatestig_integrations::stig_manager;
use automatestig_parsers::{ckl, cklb};

use crate::ui;

pub fn run(input: &str, output: &str, format: &str, collection: Option<&str>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        anyhow::bail!("Input file not found: {}", input);
    }

    ui::print_banner();
    ui::section("Export Checklist");

    let ext = in_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let checklist = match ext {
        "ckl" => ckl::parse_ckl_file(in_path).context("Failed to parse CKL")?,
        "cklb" => cklb::parse_cklb_file(in_path).context("Failed to parse CKLB")?,
        "json" => {
            let content = std::fs::read_to_string(in_path)?;
            serde_json::from_str(&content)?
        }
        _ => anyhow::bail!("Unsupported input format: .{}", ext),
    };

    ui::detail("Source", input);
    ui::detail("Format", format);

    match format {
        "stig-manager" => {
            let coll = collection.unwrap_or("Default Collection");
            ui::detail("Collection", coll);
            let json = stig_manager::export_to_stig_manager_json(&[checklist], coll)?;
            std::fs::write(output, &json)?;
            eprintln!();
            ui::success("Exported to STIG-Manager format");
            ui::output_file("Output", output, "STIG-Manager JSON");
        }
        "emass-csv" | "emass" => {
            let results = emass::export_to_emass(&checklist);
            let csv = emass::export_emass_csv(&results);
            std::fs::write(output, &csv)?;
            eprintln!();
            ui::success(&format!(
                "Exported {} test results to eMASS CSV",
                results.len()
            ));
            ui::output_file("Output", output, "eMASS CSV");
        }
        _ => anyhow::bail!("Unsupported export format: {}", format),
    }

    eprintln!();

    Ok(())
}
