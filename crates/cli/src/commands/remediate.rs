use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::checks::{Check, ExpectedResult};
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::plugins::PluginRegistry;
use automatestig_parsers::{ckl, cklb};
use automatestig_remediation::ScriptFormat;

pub fn run(
    input: &Path,
    format: &str,
    output: &Path,
    all: bool,
    library_path: &Path,
) -> Result<()> {
    if !input.exists() {
        anyhow::bail!("Input file not found: {}", input.display());
    }

    let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
    let checklist = match ext {
        "ckl" => ckl::parse_ckl_file(input).context("Failed to parse CKL file")?,
        "cklb" => cklb::parse_cklb_file(input).context("Failed to parse CKLB file")?,
        "json" => {
            let content = std::fs::read_to_string(input)?;
            serde_json::from_str(&content).context("Failed to parse JSON checklist")?
        }
        _ => anyhow::bail!("Unsupported input format: .{}", ext),
    };

    let fmt = match format {
        "powershell" => ScriptFormat::PowerShell,
        "bash" => ScriptFormat::Bash,
        "ansible" => ScriptFormat::Ansible,
        other => anyhow::bail!("Unsupported remediation format: {}", other),
    };

    let mut registry = PluginRegistry::new();
    registry
        .load_from_directory(Path::new("content/check_packs"))
        .context("Failed to load content check packs")?;

    let auto_dir = library_path.join("auto_check_packs");
    registry
        .load_from_directory(&auto_dir)
        .with_context(|| format!("Failed to load check packs from {}", auto_dir.display()))?;

    let check_defs = registry.checks_for_stig(&checklist.stig_info.stig_id);
    let target_vuln_ids: HashSet<String> = if all {
        check_defs.iter().map(|cd| cd.vuln_id.clone()).collect()
    } else {
        checklist
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Open)
            .map(|f| f.vuln_id.clone())
            .collect()
    };
    let target_count = if all {
        target_vuln_ids.len()
    } else {
        checklist
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Open)
            .count()
    };

    let items: Vec<(String, String, Check, ExpectedResult)> = check_defs
        .into_iter()
        .filter(|cd| target_vuln_ids.contains(&cd.vuln_id))
        .map(|cd| {
            (
                cd.vuln_id.clone(),
                cd.description.clone().unwrap_or_default(),
                cd.check.clone(),
                cd.expected.clone(),
            )
        })
        .collect();

    let plan = automatestig_remediation::build_remediation_plan(
        &format!("Remediation for {}", checklist.asset.hostname),
        &checklist.asset.hostname,
        &items,
        fmt,
    );
    let addressed = plan.findings_addressed();
    let manual = target_count.saturating_sub(addressed);
    let combined_script = plan
        .scripts
        .iter()
        .map(|script| script.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    let script_count = plan.scripts.len();

    std::fs::write(output, combined_script)
        .with_context(|| format!("Failed to write {}", output.display()))?;

    println!("Scripts generated: {}", script_count);
    println!("Findings addressed: {}", addressed);
    println!("Manual review required: {}", manual);

    Ok(())
}
