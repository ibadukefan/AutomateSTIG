use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::answer::generate_answer_template;
use automatestig_parsers::{ckl, cklb};

pub fn run(input: &str, output: &str, include_unreviewed: bool) -> Result<()> {
    let in_path = Path::new(input);
    let out_path = Path::new(output);

    if !in_path.exists() {
        anyhow::bail!("Input file not found: {}", input);
    }

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

    let answer_file = generate_answer_template(&checklist, include_unreviewed);

    let out_ext = out_path.extension().and_then(|e| e.to_str()).unwrap_or("json");
    match out_ext {
        "json" => answer_file.save_json(out_path)?,
        "yaml" | "yml" => answer_file.save_yaml(out_path)?,
        _ => anyhow::bail!("Unsupported output format: .{}", out_ext),
    }

    println!("Generated answer file template:");
    println!("  Source: {} ({})", checklist.asset.hostname, checklist.stig_info.title);
    println!("  Entries: {}", answer_file.entries.len());
    println!("  Output: {}", output);

    let issues = answer_file.validate();
    if !issues.is_empty() {
        println!("\n  Validation warnings:");
        for issue in &issues {
            println!("    - {}", issue);
        }
    }

    Ok(())
}
