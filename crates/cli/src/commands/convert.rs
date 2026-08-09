use std::path::Path;

use anyhow::{Context, Result};
use automatestig_parsers::{ckl, cklb};

use crate::ui;

pub fn run(input: &str, output: &str, format: Option<&str>, cli: &crate::Cli) -> Result<()> {
    let in_path = Path::new(input);
    let out_path = Path::new(output);

    if !in_path.exists() {
        anyhow::bail!("Input file not found: {}", input);
    }

    let in_ext = in_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let out_format = format
        .or_else(|| out_path.extension().and_then(|e| e.to_str()))
        .unwrap_or("ckl");

    ui::print_banner();
    ui::section("Convert Checklist");
    ui::detail("Input", input);
    ui::detail("Output format", out_format);

    // Load input.
    let checklist = match in_ext {
        "ckl" => ckl::parse_ckl_file(in_path).context("Failed to parse CKL file")?,
        "cklb" => cklb::parse_cklb_file(in_path).context("Failed to parse CKLB file")?,
        "json" => {
            let content = std::fs::read_to_string(in_path)?;
            serde_json::from_str(&content)?
        }
        _ => anyhow::bail!("Unsupported input format: .{}", in_ext),
    };

    // Serialize before committing so parse/serialization failures never
    // truncate an existing artifact.
    super::ensure_external_export_allowed(&checklist)?;
    let bytes = match out_format {
        "ckl" => ckl::write_ckl(&checklist)?.into_bytes(),
        "cklb" => cklb::write_cklb(&checklist)?.into_bytes(),
        "json" => serde_json::to_vec_pretty(&checklist)?,
        _ => anyhow::bail!("Unsupported output format: {}", out_format),
    };
    super::ensure_safe_artifact_output(out_path, &[in_path], cli)?;
    super::evaluate::write_evaluation_output_atomic(out_path, &bytes)?;

    println!();
    ui::success(&format!("Converted {} findings", checklist.findings.len()));
    ui::output_file("Output", output, out_format);
    println!();

    Ok(())
}
