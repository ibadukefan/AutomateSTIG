use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::answer::AnswerFile;
use automatestig_core::checks::{CheckPack, CheckPlatform, CheckResult, SystemData};
use automatestig_core::engine::EvaluationEngine;
use automatestig_core::library::StigLibrary;
use automatestig_core::models::asset::Asset;
use automatestig_core::models::finding::{FindingSource, FindingStatus};
use automatestig_core::models::{Checklist, StigBenchmark};
use automatestig_core::plugins::PluginRegistry;
use automatestig_parsers::ckl;
use automatestig_parsers::cklb;
use automatestig_parsers::evidence::{parse_evidence_transcript, EvidenceTranscript};
use automatestig_parsers::xccdf;
use automatestig_storage::Database;

use super::{db_path, library_path};
use crate::ui;

pub struct EvaluateArgs {
    pub stig_id: String,
    pub scan: Option<String>,
    pub evidence: Option<String>,
    pub config: Option<String>,
    pub answer_paths: Vec<String>,
    pub host: Option<String>,
    pub output: Option<String>,
    pub format: Option<String>,
    pub merge: Option<String>,
}

pub fn run(args: EvaluateArgs, cli: &crate::Cli) -> Result<()> {
    let EvaluateArgs {
        stig_id,
        scan,
        evidence,
        config,
        answer_paths,
        host,
        output,
        format,
        merge,
    } = args;

    ui::print_banner();

    let lib_path = library_path(cli);
    let library = StigLibrary::open(&lib_path)
        .context("Failed to open STIG library. Run 'automatestig library init' first.")?;

    let benchmark = library
        .load_benchmark(&stig_id)
        .context(format!("Failed to load STIG benchmark '{}'", stig_id))?;

    ui::section(&format!(
        "{} ({}) — {} rules",
        benchmark.title,
        benchmark.version_string(),
        benchmark.rules.len()
    ));

    // Parse scan results if provided.
    let scan_results = if let Some(ref scan_path) = scan {
        let path = Path::new(scan_path);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "xml" => {
                ui::detail("Scan source", scan_path);
                Some(xccdf::parse_xccdf_results(path)?)
            }
            _ => {
                ui::warn(&format!("Scan format not recognized: {}", scan_path));
                None
            }
        }
    } else {
        None
    };

    let evidence_transcript = if let Some(ref evidence_path) = evidence {
        ui::detail("Evidence source", evidence_path);
        let raw = std::fs::read_to_string(evidence_path)
            .context(format!("Failed to read evidence file: {}", evidence_path))?;
        Some(parse_evidence_transcript(&raw))
    } else {
        None
    };

    // Device running-config (evaluated via config_line checks).
    let config_text = if let Some(ref config_path) = config {
        ui::detail("Config source", config_path);
        Some(
            std::fs::read_to_string(config_path)
                .context(format!("Failed to read config file: {}", config_path))?,
        )
    } else {
        None
    };

    // Load answer files.
    let answer_files: Vec<AnswerFile> = answer_paths
        .iter()
        .map(|p| {
            ui::detail("Answer file", p);
            AnswerFile::load(Path::new(p)).context(format!("Failed to load answer file: {}", p))
        })
        .collect::<Result<Vec<_>>>()?;

    // Determine asset info.
    let hostname = host
        .clone()
        .or_else(|| scan_results.as_ref().and_then(|s| s.source.target.clone()))
        .or_else(|| {
            evidence_transcript
                .as_ref()
                .and_then(|transcript| transcript.hostname.clone())
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let asset = Asset::new(&hostname);
    ui::detail("Target", &hostname);

    // Run evaluation.
    let engine = EvaluationEngine::with_defaults();
    let mut checklist = if evidence_transcript.is_some() || config_text.is_some() {
        let mut checklist = engine.evaluate(&benchmark, &asset, scan_results.as_ref(), &[])?;
        let system_data = build_evidence_system_data(
            evidence_transcript.as_ref(),
            config_text,
            host.as_deref(),
            &hostname,
        );
        let check_results = execute_evidence_checks(&library, &benchmark, &system_data);
        apply_check_results_to_checklist(&mut checklist, &check_results);
        apply_answer_files_to_checklist(&mut checklist, &answer_files);
        checklist
    } else {
        engine.evaluate(&benchmark, &asset, scan_results.as_ref(), &answer_files)?
    };

    // Merge with previous if requested.
    if let Some(ref merge_path) = merge {
        ui::detail("Merging", merge_path);
        let path = Path::new(merge_path);
        let previous = load_checklist_from_file(path)?;
        engine.merge_previous(&mut checklist, &previous)?;
    }

    // Print summary.
    let summary = checklist.summary();
    ui::print_summary_table(
        summary.total,
        summary.open,
        summary.not_a_finding,
        summary.not_applicable,
        summary.not_reviewed,
        summary.cat_i_open,
        summary.cat_ii_open,
        summary.cat_iii_open,
        summary.compliance_pct(),
    );

    // Write output.
    let output_path =
        output.unwrap_or_else(|| format!("{}_{}.ckl", hostname.replace(' ', "_"), stig_id));

    let out_format = format
        .as_deref()
        .or_else(|| Path::new(&output_path).extension().and_then(|e| e.to_str()))
        .unwrap_or("ckl");

    match out_format {
        "ckl" => {
            ckl::write_ckl_file(&checklist, Path::new(&output_path))?;
            ui::output_file("Output", &output_path, "CKL");
        }
        "cklb" => {
            cklb::write_cklb_file(&checklist, Path::new(&output_path))?;
            ui::output_file("Output", &output_path, "CKLB");
        }
        "json" => {
            let json = serde_json::to_string_pretty(&checklist)?;
            std::fs::write(&output_path, json)?;
            ui::output_file("Output", &output_path, "JSON");
        }
        _ => {
            anyhow::bail!("Unsupported output format: {}", out_format);
        }
    }

    // Save to database.
    let db = Database::open(&db_path(cli))?;
    db.save_checklist(&checklist)?;
    let log_detail = if evidence.is_some() {
        format!("scan={:?}, evidence={:?}", scan, evidence)
    } else {
        format!("scan={:?}", scan)
    };
    db.log_evaluation(&checklist, "cli-evaluate", Some(&log_detail))?;

    ui::success("Evaluation complete");

    Ok(())
}

fn build_evidence_system_data(
    transcript: Option<&EvidenceTranscript>,
    network_config: Option<String>,
    host_arg: Option<&str>,
    default_hostname: &str,
) -> SystemData {
    SystemData {
        command_outputs: transcript.map(|t| t.outputs.clone()).unwrap_or_default(),
        network_config,
        hostname: host_arg
            .map(str::to_string)
            .or_else(|| transcript.and_then(|t| t.hostname.clone()))
            .unwrap_or_else(|| default_hostname.to_string()),
        ..Default::default()
    }
}

fn execute_evidence_checks(
    library: &StigLibrary,
    benchmark: &StigBenchmark,
    system_data: &SystemData,
) -> Vec<CheckResult> {
    let mut check_results: Vec<CheckResult> = load_matching_check_packs(library, &benchmark.id)
        .into_iter()
        .flat_map(|pack| {
            let mut pack_data = system_data.clone();
            pack_data.platform = check_platform_name(pack.platform).to_string();
            automatestig_core::checks::executor::execute_check_pack(&pack, &pack_data)
        })
        .collect();

    let mut seen_vuln_ids: HashSet<String> = HashSet::new();
    // Curated packs load before auto-generated ones; first result per vuln wins.
    check_results.retain(|cr| seen_vuln_ids.insert(cr.vuln_id.clone()));
    check_results
}

fn load_matching_check_packs(library: &StigLibrary, stig_id: &str) -> Vec<CheckPack> {
    let mut plugin_registry = PluginRegistry::new();
    let content_dir = Path::new("content/check_packs");
    let _ = plugin_registry.load_from_directory(content_dir);

    let custom_dir = library.root().join("custom_checks");
    let _ = plugin_registry.load_from_directory(&custom_dir);

    let auto_dir = library.root().join("auto_check_packs");
    let _ = plugin_registry.load_from_directory(&auto_dir);
    let _ = plugin_registry.load_embedded();

    plugin_registry
        .list()
        .iter()
        .flat_map(|plugin| plugin.check_packs.iter())
        .filter(|pack| pack.stig_id == stig_id)
        .cloned()
        .collect()
}

fn apply_check_results_to_checklist(checklist: &mut Checklist, check_results: &[CheckResult]) {
    for cr in check_results {
        if let Some(finding) = checklist.find_by_vuln_id_mut(&cr.vuln_id) {
            finding.status = cr.to_finding_status();
            finding.source = FindingSource::Automated;
            finding.finding_details = cr.evidence.clone();
            finding.evaluated_at = chrono::Utc::now();
            finding.evaluated_by = format!("AutomateSTIG {}", env!("CARGO_PKG_VERSION"));
        }
    }

    checklist.touch();
}

fn apply_answer_files_to_checklist(checklist: &mut Checklist, answer_files: &[AnswerFile]) {
    for answer_file in answer_files {
        if let Some(ref answer_stig_id) = answer_file.stig_id {
            if answer_stig_id != &checklist.stig_info.stig_id {
                continue;
            }
        }

        for entry in &answer_file.entries {
            if let Some(finding) = checklist.find_by_vuln_id_mut(&entry.vuln_id) {
                let should_apply = entry.force_override
                    || finding.status == FindingStatus::NotReviewed
                    || finding.source == FindingSource::Manual;

                if should_apply {
                    finding.status = entry.status;
                    finding.source = FindingSource::AnswerFile;

                    if let Some(ref details) = entry.finding_details {
                        finding.finding_details = details.clone();
                    }
                    if let Some(ref comments) = entry.comments {
                        finding.comments = comments.clone();
                    }
                    if let Some(ref severity_override) = entry.severity_override {
                        finding.severity_override = Some(*severity_override);
                        finding.severity_override_justification =
                            entry.severity_override_justification.clone();
                    }
                }
            }
        }
    }

    checklist.touch();
}

fn check_platform_name(platform: CheckPlatform) -> &'static str {
    match platform {
        CheckPlatform::Windows => "windows",
        CheckPlatform::Linux => "linux",
        CheckPlatform::CiscoIos => "cisco_ios",
        CheckPlatform::CiscoNxos => "cisco_nxos",
        CheckPlatform::CiscoAsa => "cisco_asa",
        CheckPlatform::Ontap => "ontap",
        CheckPlatform::Bsd => "bsd",
        CheckPlatform::Generic => "generic",
    }
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
