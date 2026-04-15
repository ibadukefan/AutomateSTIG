use std::path::Path;

use anyhow::{Context, Result};
use automatestig_parsers::{ckl, cklb};

pub fn run(input: &str, output: &str, format: Option<&str>) -> Result<()> {
    let in_path = Path::new(input);
    let out_path = Path::new(output);

    if !in_path.exists() {
        anyhow::bail!("Input file not found: {}", input);
    }

    let in_ext = in_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let out_format = format
        .or_else(|| out_path.extension().and_then(|e| e.to_str()))
        .unwrap_or("ckl");

    println!("Converting: {} -> {} ({})", input, output, out_format);

    // Load input.
    let checklist = match in_ext {
        "ckl" => ckl::parse_ckl_file(in_path)
            .context("Failed to parse CKL file")?,
        "cklb" => cklb::parse_cklb_file(in_path)
            .context("Failed to parse CKLB file")?,
        "json" => {
            let content = std::fs::read_to_string(in_path)?;
            serde_json::from_str(&content)?
        }
        _ => anyhow::bail!("Unsupported input format: .{}", in_ext),
    };

    // Write output.
    match out_format {
        "ckl" => {
            ckl::write_ckl_file(&checklist, out_path)?;
        }
        "cklb" => {
            cklb::write_cklb_file(&checklist, out_path)?;
        }
        "json" => {
            let json = serde_json::to_string_pretty(&checklist)?;
            std::fs::write(out_path, json)?;
        }
        _ => anyhow::bail!("Unsupported output format: {}", out_format),
    }

    println!("  Converted {} findings.", checklist.findings.len());
    println!("  Output: {}", output);

    Ok(())
}
