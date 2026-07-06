//! REST API endpoints for the GUI.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use axum::extract::{Multipart, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use automatestig_core::agent::{AgentConfig, MonitoredTarget, NotificationConfig};
use automatestig_core::checks::{Check, ExpectedResult};
use automatestig_core::engine::EvaluationEngine;
use automatestig_core::inventory::assets::{ManagedAsset, ScanProtocol};
use automatestig_core::inventory::credentials::CredentialType;
use automatestig_core::inventory::scheduler::{
    EvaluationSchedule, ScheduleRunStatus, SchedulerConfig,
};
use automatestig_core::models::asset::Asset;
use automatestig_core::models::checklist::Checklist;
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::models::stig::Severity;
use automatestig_parsers::{ckl, cklb, xccdf};
use automatestig_remediation::ScriptFormat;

use crate::state::AppState;

/// Build the API router.
pub fn routes() -> Router<AppState> {
    Router::new()
        // Status & info
        .route("/status", get(get_status))
        // Library
        .route("/library/benchmarks", get(list_benchmarks))
        .route("/library/benchmarks/{id}", get(get_benchmark))
        .route("/library/import-disa", post(import_disa))
        .route("/library/import-stigpack", post(import_stigpack))
        // Checklists
        .route("/checklists", get(list_checklists))
        .route("/checklists/{id}", get(get_checklist))
        .route("/checklists/{id}", axum::routing::delete(delete_checklist))
        .route("/checklists/import", post(import_checklist))
        // Evaluate
        .route("/evaluate", post(evaluate))
        .route("/remediation/{checklist_id}", get(generate_remediation))
        // Auto-generate check packs from imported benchmarks
        .route("/library/generate-checks/{id}", post(generate_checks))
        // DISA content fetching
        .route("/disa/available", get(disa_list_available))
        .route("/disa/fetch", post(disa_fetch))
        .route("/disa/fetch-all", post(disa_fetch_all))
        .route("/disa/check-updates", get(disa_check_updates))
        // Offline pack for air-gapped transfer
        .route("/offline-pack", get(generate_offline_pack))
        // STIG-Manager integration
        .route("/stigman/config", get(stigman_get_config))
        .route("/stigman/config", post(stigman_set_config))
        .route("/stigman/test", post(stigman_test_connection))
        .route("/stigman/collections", get(stigman_list_collections))
        .route(
            "/stigman/collections/{cid}/assets",
            get(stigman_list_assets),
        )
        .route("/stigman/sync/{cid}", post(stigman_sync_assets))
        .route("/stigman/diff/{cid}", get(stigman_diff_assets))
        .route("/stigman/push/{checklist_id}", post(stigman_push_checklist))
        // Batch evaluation
        .route("/evaluate/batch", post(evaluate_batch))
        // Finding editing
        .route(
            "/checklists/{id}/findings/{vuln_id}",
            axum::routing::patch(update_finding),
        )
        // Scan import (file upload -> evaluate)
        .route("/evaluate/with-scan", post(evaluate_with_scan))
        // Agent config
        .route("/agent/config", get(get_agent_config))
        .route("/agent/config", post(set_agent_config))
        .route("/agent/drift/{id}", get(get_drift_report))
        // Remote scanning
        .route("/scan/ssh", post(scan_ssh))
        .route("/scan/winrm", post(scan_winrm))
        // Asset inventory
        .route("/assets", get(list_assets_inv))
        .route("/assets", post(create_asset_inv))
        .route("/assets/{id}", get(get_asset_inv))
        .route("/assets/{id}", axum::routing::put(update_asset_inv))
        .route("/assets/{id}", axum::routing::delete(delete_asset_inv))
        // Credential vault
        .route("/credentials", get(list_credentials))
        .route("/credentials", post(create_credential))
        .route(
            "/credentials/{id}",
            axum::routing::delete(delete_credential),
        )
        // Schedules
        .route("/schedules", get(list_schedules))
        .route("/schedules", post(create_schedule))
        .route("/schedules/{id}", axum::routing::put(update_schedule))
        .route("/schedules/{id}", axum::routing::delete(delete_schedule))
        .route("/schedules/{id}/run", post(run_schedule_now))
        // Bulk operations
        .route("/assets/bulk-assign-stig", post(bulk_assign_stig))
        .route("/assets/bulk-update", post(bulk_update_assets))
        .route("/checklists/{id}/re-evaluate", post(re_evaluate))
        .route(
            "/checklists/{id}/findings/{vuln_id}/poam",
            axum::routing::patch(update_poam),
        )
        .route("/checklists/compare", post(compare_checklists))
        .route("/trends/{hostname}", get(compliance_trends))
        // Answer file management
        .route("/answer-files", get(list_answer_files))
        .route("/answer-files", post(save_answer_file))
        // Webhooks / notifications
        .route("/webhooks/test", post(test_webhook))
        // Export
        .route("/export/ckl/{id}", get(export_ckl))
        .route("/export/cklb/{id}", get(export_cklb))
        .route("/export/emass/{id}", get(export_emass))
        .route("/export/all-zip", get(export_all_zip))
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Sanitize a filename for Content-Disposition headers.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn api_ok(data: impl Serialize) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "success": true,
        "data": data,
        "error": null
    }))
}

fn api_error(msg: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "success": false,
        "data": null,
        "error": msg
    }))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    benchmark_count: usize,
    checklist_count: usize,
    library_path: String,
}

async fn get_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let benchmark_count = state
        .library()
        .map(|l| l.list_benchmarks().len())
        .unwrap_or(0);
    let checklist_count = state.db().list_checklists().map(|c| c.len()).unwrap_or(0);

    api_ok(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        benchmark_count,
        checklist_count,
        library_path: state.inner.library_path.display().to_string(),
    })
}

// ---------------------------------------------------------------------------
// Library
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BenchmarkInfo {
    id: String,
    title: String,
    version: String,
    platform: String,
    rule_count: usize,
    cat_i: usize,
    cat_ii: usize,
    cat_iii: usize,
}

async fn list_benchmarks(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.library() {
        Ok(library) => {
            let benchmarks: Vec<BenchmarkInfo> = library
                .list_benchmarks()
                .iter()
                .map(|b| {
                    let (cat_i, cat_ii, cat_iii) = library
                        .load_benchmark(&b.id)
                        .map(|full| {
                            (
                                full.rules_by_severity(Severity::High).len(),
                                full.rules_by_severity(Severity::Medium).len(),
                                full.rules_by_severity(Severity::Low).len(),
                            )
                        })
                        .unwrap_or((0, 0, 0));

                    BenchmarkInfo {
                        id: b.id.clone(),
                        title: b.title.clone(),
                        version: b.version.clone(),
                        platform: b.platform_family.clone(),
                        rule_count: b.rule_count,
                        cat_i,
                        cat_ii,
                        cat_iii,
                    }
                })
                .collect();
            api_ok(benchmarks)
        }
        Err(e) => api_error(&e.to_string()),
    }
}

#[derive(Serialize)]
struct BenchmarkDetail {
    id: String,
    title: String,
    description: String,
    version: String,
    release: String,
    platform: String,
    rule_count: usize,
    cat_i: usize,
    cat_ii: usize,
    cat_iii: usize,
    rules: Vec<RuleSummary>,
}

#[derive(Serialize)]
struct RuleSummary {
    vuln_id: String,
    title: String,
    severity: String,
    check_content: String,
}

async fn get_benchmark(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    match state
        .library()
        .and_then(|l| l.load_benchmark(&id).map_err(|e| anyhow::anyhow!("{}", e)))
    {
        Ok(b) => {
            let cat_i = b.rules_by_severity(Severity::High).len();
            let cat_ii = b.rules_by_severity(Severity::Medium).len();
            let cat_iii = b.rules_by_severity(Severity::Low).len();

            let rules: Vec<RuleSummary> = b
                .rules
                .iter()
                .map(|r| RuleSummary {
                    vuln_id: r.vuln_id.clone(),
                    title: r.title.clone(),
                    severity: r.severity.as_cat_str().to_string(),
                    check_content: r.check_content.chars().take(200).collect(),
                })
                .collect();

            api_ok(BenchmarkDetail {
                id: b.id,
                title: b.title,
                description: b.description,
                version: b.version,
                release: b.release,
                platform: b.platform.name,
                rule_count: b.rules.len(),
                cat_i,
                cat_ii,
                cat_iii,
                rules,
            })
        }
        Err(e) => api_error(&e.to_string()),
    }
}

#[derive(Serialize)]
struct ImportResult {
    imported: usize,
    skipped: usize,
    details: Vec<String>,
}

async fn import_disa(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Json<serde_json::Value> {
    let mut imported = 0;
    let mut skipped = 0;
    let mut details = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let filename = field.file_name().unwrap_or("upload").to_string();
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => {
                return api_error(&format!("Failed to read upload: {}", e));
            }
        };

        let mut library = match state.library() {
            Ok(l) => l,
            Err(e) => return api_error(&e.to_string()),
        };

        if filename.ends_with(".zip") {
            // Parse ZIP for XCCDF files.
            let cursor = std::io::Cursor::new(&data);
            match zip::ZipArchive::new(cursor) {
                Ok(mut archive) => {
                    for i in 0..archive.len() {
                        let mut file = match archive.by_index(i) {
                            Ok(f) => f,
                            Err(_) => continue,
                        };
                        let name = file.name().to_string();
                        let lower = name.to_lowercase();
                        if lower.ends_with("-xccdf.xml") || lower.ends_with("_xccdf.xml") {
                            let mut xml = String::new();
                            if file.read_to_string(&mut xml).is_ok() {
                                match xccdf::parse_xccdf_benchmark_str(&xml) {
                                    Ok(benchmark) => {
                                        let info = format!(
                                            "{} {} ({} rules)",
                                            benchmark.id,
                                            benchmark.version_string(),
                                            benchmark.rules.len()
                                        );
                                        match library.add_benchmark(&benchmark) {
                                            Ok(()) => {
                                                // Auto-generate check pack from check-content text.
                                                let conv =
                                                    automatestig_core::converter::convert_benchmark(
                                                        &benchmark,
                                                    );
                                                if conv.automated > 0 {
                                                    let packs_dir =
                                                        library.root().join("auto_check_packs");
                                                    let _ = std::fs::create_dir_all(&packs_dir);
                                                    if let Ok(json) = automatestig_core::converter::check_pack_to_json(&conv.check_pack) {
                                                        let _ = std::fs::write(packs_dir.join(format!("{}.json", benchmark.id)), &json);
                                                    }
                                                    details.push(format!(
                                                        "Imported: {} (auto-generated {} checks)",
                                                        info, conv.automated
                                                    ));
                                                } else {
                                                    details.push(format!("Imported: {}", info));
                                                }
                                                imported += 1;
                                            }
                                            Err(e) => {
                                                details.push(format!("Failed: {} - {}", info, e));
                                                skipped += 1;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        details.push(format!("Parse error in {}: {}", name, e));
                                        skipped += 1;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    return api_error(&format!("Invalid ZIP file: {}", e));
                }
            }
        } else if filename.ends_with(".xml") {
            let xml = String::from_utf8_lossy(&data);
            match xccdf::parse_xccdf_benchmark_str(&xml) {
                Ok(benchmark) => {
                    let info = format!(
                        "{} {} ({} rules)",
                        benchmark.id,
                        benchmark.version_string(),
                        benchmark.rules.len()
                    );
                    match library.add_benchmark(&benchmark) {
                        Ok(()) => {
                            let conv = automatestig_core::converter::convert_benchmark(&benchmark);
                            if conv.automated > 0 {
                                let packs_dir = library.root().join("auto_check_packs");
                                let _ = std::fs::create_dir_all(&packs_dir);
                                if let Ok(json) = automatestig_core::converter::check_pack_to_json(
                                    &conv.check_pack,
                                ) {
                                    let _ = std::fs::write(
                                        packs_dir.join(format!("{}.json", benchmark.id)),
                                        &json,
                                    );
                                }
                                details.push(format!(
                                    "Imported: {} (auto-generated {} checks)",
                                    info, conv.automated
                                ));
                            } else {
                                details.push(format!("Imported: {}", info));
                            }
                            imported += 1;
                        }
                        Err(e) => {
                            details.push(format!("Failed: {} - {}", info, e));
                            skipped += 1;
                        }
                    }
                }
                Err(e) => {
                    return api_error(&format!("Failed to parse XCCDF: {}", e));
                }
            }
        }
    }

    api_ok(ImportResult {
        imported,
        skipped,
        details,
    })
}

async fn import_stigpack(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Json<serde_json::Value> {
    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => return api_error("No file uploaded"),
        Err(e) => return api_error(&format!("Upload error: {}", e)),
    };
    {
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => return api_error(&format!("Failed to read upload: {}", e)),
        };

        // Write to temp file for the importer.
        let tmp = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => return api_error(&format!("Failed to create temp file: {}", e)),
        };
        if let Err(e) = std::fs::write(tmp.path(), &data) {
            return api_error(&format!("Failed to write temp file: {}", e));
        }

        let mut library = match state.library() {
            Ok(l) => l,
            Err(e) => return api_error(&e.to_string()),
        };

        let allow_unsigned = std::env::var("AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let import_result = if allow_unsigned {
            automatestig_stigpack::importer::import_pack(tmp.path(), &mut library)
        } else {
            let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
            let trust_dir = std::env::var("AUTOMATESTIG_TRUSTED_KEYS_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    std::env::var("HOME")
                        .or_else(|_| std::env::var("USERPROFILE"))
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|_| std::path::PathBuf::from("."))
                        .join(".automatestig")
                        .join("trusted_keys")
                });
            if let Err(e) = trust_store.load_from_directory(&trust_dir) {
                return api_error(&format!("Failed to load trusted .stigpack keys: {}", e));
            }
            if trust_store.is_empty() {
                return api_error(
                    "Trusted .stigpack signature required, but no trusted keys are configured. Add Ed25519 .pub files to AUTOMATESTIG_TRUSTED_KEYS_DIR or set AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1 for explicit lab-only import.",
                );
            }
            automatestig_stigpack::importer::import_pack_trusted(
                tmp.path(),
                &mut library,
                &trust_store,
            )
        };

        match import_result {
            Ok(result) => api_ok(ImportResult {
                imported: result.benchmarks_imported,
                skipped: 0,
                details: vec![format!(
                    "Pack {} v{}: {} benchmarks, {} templates",
                    result.pack_id,
                    result.pack_version,
                    result.benchmarks_imported,
                    result.answer_templates_imported
                )],
            }),
            Err(e) => api_error(&format!("Import failed: {}", e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Checklists
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ChecklistInfo {
    id: String,
    hostname: String,
    stig_id: String,
    stig_title: String,
    stig_version: String,
    created_at: String,
    modified_at: String,
    total: usize,
    open: usize,
    not_a_finding: usize,
    not_applicable: usize,
    not_reviewed: usize,
    compliance_pct: f64,
    cat_i_open: usize,
    cat_ii_open: usize,
    cat_iii_open: usize,
}

async fn list_checklists(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    match db.list_checklists() {
        Ok(rows) => {
            let mut infos = Vec::new();
            for row in &rows {
                // Load full checklist for summary stats.
                if let Ok(cl) = db.load_checklist(&row.id) {
                    let s = cl.summary();
                    infos.push(ChecklistInfo {
                        id: row.id.clone(),
                        hostname: row.asset_hostname.clone(),
                        stig_id: row.stig_id.clone(),
                        stig_title: row.stig_title.clone(),
                        stig_version: row.stig_version.clone(),
                        created_at: row.created_at.clone(),
                        modified_at: row.modified_at.clone(),
                        total: s.total,
                        open: s.open,
                        not_a_finding: s.not_a_finding,
                        not_applicable: s.not_applicable,
                        not_reviewed: s.not_reviewed,
                        compliance_pct: s.compliance_pct(),
                        cat_i_open: s.cat_i_open,
                        cat_ii_open: s.cat_ii_open,
                        cat_iii_open: s.cat_iii_open,
                    });
                }
            }
            api_ok(infos)
        }
        Err(e) => api_error(&e.to_string()),
    }
}

#[derive(Serialize)]
struct ChecklistDetail {
    id: String,
    hostname: String,
    stig_id: String,
    stig_title: String,
    stig_version: String,
    total: usize,
    open: usize,
    not_a_finding: usize,
    not_applicable: usize,
    not_reviewed: usize,
    compliance_pct: f64,
    cat_i_open: usize,
    cat_ii_open: usize,
    cat_iii_open: usize,
    findings: Vec<FindingInfo>,
}

#[derive(Serialize)]
struct FindingInfo {
    vuln_id: String,
    rule_id: String,
    title: String,
    severity: String,
    status: String,
    finding_details: String,
    comments: String,
    source: String,
}

async fn get_checklist(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    match db.load_checklist(&id) {
        Ok(cl) => {
            let s = cl.summary();
            let findings: Vec<FindingInfo> = cl
                .findings
                .iter()
                .map(|f| FindingInfo {
                    vuln_id: f.vuln_id.clone(),
                    rule_id: f.rule_id.clone(),
                    title: f.rule_title.clone(),
                    severity: f
                        .severity_override
                        .unwrap_or(f.severity)
                        .as_cat_str()
                        .to_string(),
                    status: f.status.to_string(),
                    finding_details: f.finding_details.clone(),
                    comments: f.comments.clone(),
                    source: format!("{:?}", f.source),
                })
                .collect();

            api_ok(ChecklistDetail {
                id: cl.id.to_string(),
                hostname: cl.asset.hostname,
                stig_id: cl.stig_info.stig_id,
                stig_title: cl.stig_info.title,
                stig_version: format!("V{}R{}", cl.stig_info.version, cl.stig_info.release),
                total: s.total,
                open: s.open,
                not_a_finding: s.not_a_finding,
                not_applicable: s.not_applicable,
                not_reviewed: s.not_reviewed,
                compliance_pct: s.compliance_pct(),
                cat_i_open: s.cat_i_open,
                cat_ii_open: s.cat_ii_open,
                cat_iii_open: s.cat_iii_open,
                findings,
            })
        }
        Err(e) => api_error(&e.to_string()),
    }
}

#[derive(Deserialize)]
struct RemediationQuery {
    format: Option<String>,
}

async fn generate_remediation(
    State(state): State<AppState>,
    axum::extract::Path(checklist_id): axum::extract::Path<String>,
    Query(query): Query<RemediationQuery>,
) -> Json<serde_json::Value> {
    let (format_name, fmt) = match query.format.as_deref().unwrap_or("powershell") {
        "powershell" => ("powershell", ScriptFormat::PowerShell),
        "bash" => ("bash", ScriptFormat::Bash),
        "ansible" => ("ansible", ScriptFormat::Ansible),
        other => return api_error(&format!("Unsupported remediation format: {}", other)),
    };

    let db = state.db();
    let checklist = match db.load_checklist(&checklist_id) {
        Ok(c) => c,
        Err(e) => return api_error(&e.to_string()),
    };

    let mut registry = automatestig_core::plugins::PluginRegistry::new();
    let plugins_dir = state.inner.data_dir.join("plugins");
    let _ = registry.load_from_directory(&plugins_dir);

    let content_dir = Path::new("content/check_packs");
    let _ = registry.load_from_directory(content_dir);

    let auto_dir = state.inner.library_path.join("auto_check_packs");
    let _ = registry.load_from_directory(&auto_dir);

    let open_finding_ids: HashSet<String> = checklist
        .findings
        .iter()
        .filter(|f| f.status == FindingStatus::Open)
        .map(|f| f.vuln_id.clone())
        .collect();
    let open_count = checklist
        .findings
        .iter()
        .filter(|f| f.status == FindingStatus::Open)
        .count();

    let items: Vec<(String, String, Check, ExpectedResult)> = registry
        .checks_for_stig(&checklist.stig_info.stig_id)
        .into_iter()
        .filter(|cd| open_finding_ids.contains(&cd.vuln_id))
        .map(|cd| {
            (
                cd.vuln_id.clone(),
                cd.description.clone().unwrap_or_default(),
                cd.check.clone(),
                cd.expected.clone(),
            )
        })
        .collect();

    let hostname = checklist.asset.hostname.clone();
    let plan = automatestig_remediation::build_remediation_plan(
        &format!("Remediation for {}", hostname),
        &hostname,
        &items,
        fmt,
    );
    let addressed = plan.findings_addressed();
    let manual = open_count.saturating_sub(addressed);
    let combined_script = plan
        .scripts
        .iter()
        .map(|script| script.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    api_ok(serde_json::json!({
        "hostname": hostname,
        "format": format_name,
        "open_findings": open_count,
        "automated_remediations": addressed,
        "manual_required": manual,
        "overall_risk": plan.overall_risk,
        "requires_reboot": plan.requires_reboot,
        "scripts": plan.scripts,
        "combined_script": combined_script,
    }))
}

async fn delete_checklist(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    match db.delete_checklist(&id) {
        Ok(deleted) => api_ok(deleted),
        Err(e) => api_error(&e.to_string()),
    }
}

async fn import_checklist(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Json<serde_json::Value> {
    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => return api_error("No file uploaded"),
        Err(e) => return api_error(&format!("Upload error: {}", e)),
    };
    {
        let filename = field.file_name().unwrap_or("upload").to_string();
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => return api_error(&format!("Failed to read upload: {}", e)),
        };

        let text = String::from_utf8_lossy(&data);
        let ext = Path::new(&filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let checklist = match ext {
            "ckl" => match ckl::parse_ckl(&text) {
                Ok(c) => c,
                Err(e) => return api_error(&format!("CKL parse error: {}", e)),
            },
            "cklb" | "json" => match serde_json::from_str(&text) {
                Ok(c) => c,
                Err(_) => match cklb::parse_cklb(&text) {
                    Ok(c) => c,
                    Err(e) => return api_error(&format!("Parse error: {}", e)),
                },
            },
            _ => return api_error(&format!("Unsupported format: .{}", ext)),
        };

        let s = checklist.summary();
        let info = ChecklistInfo {
            id: checklist.id.to_string(),
            hostname: checklist.asset.hostname.clone(),
            stig_id: checklist.stig_info.stig_id.clone(),
            stig_title: checklist.stig_info.title.clone(),
            stig_version: format!(
                "V{}R{}",
                checklist.stig_info.version, checklist.stig_info.release
            ),
            created_at: checklist.created_at.to_rfc3339(),
            modified_at: checklist.modified_at.to_rfc3339(),
            total: s.total,
            open: s.open,
            not_a_finding: s.not_a_finding,
            not_applicable: s.not_applicable,
            not_reviewed: s.not_reviewed,
            compliance_pct: s.compliance_pct(),
            cat_i_open: s.cat_i_open,
            cat_ii_open: s.cat_ii_open,
            cat_iii_open: s.cat_iii_open,
        };

        let db = state.db();
        if let Err(e) = db.save_checklist(&checklist) {
            return api_error(&format!("Failed to save: {}", e));
        }

        api_ok(info)
    }
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EvaluateRequest {
    stig_id: String,
    hostname: String,
    #[serde(default)]
    asset_id: Option<String>,
}

async fn evaluate(
    State(state): State<AppState>,
    Json(req): Json<EvaluateRequest>,
) -> Json<serde_json::Value> {
    let library = match state.library() {
        Ok(l) => l,
        Err(e) => return api_error(&e.to_string()),
    };

    let benchmark = match library.load_benchmark(&req.stig_id) {
        Ok(b) => b,
        Err(e) => return api_error(&format!("Benchmark not found: {}", e)),
    };

    let asset = Asset::new(&req.hostname);
    let engine = EvaluationEngine::with_defaults();

    match engine.evaluate(&benchmark, &asset, None, &[]) {
        Ok(checklist) => {
            let s = checklist.summary();
            let info = ChecklistInfo {
                id: checklist.id.to_string(),
                hostname: checklist.asset.hostname.clone(),
                stig_id: checklist.stig_info.stig_id.clone(),
                stig_title: checklist.stig_info.title.clone(),
                stig_version: format!(
                    "V{}R{}",
                    checklist.stig_info.version, checklist.stig_info.release
                ),
                created_at: checklist.created_at.to_rfc3339(),
                modified_at: checklist.modified_at.to_rfc3339(),
                total: s.total,
                open: s.open,
                not_a_finding: s.not_a_finding,
                not_applicable: s.not_applicable,
                not_reviewed: s.not_reviewed,
                compliance_pct: s.compliance_pct(),
                cat_i_open: s.cat_i_open,
                cat_ii_open: s.cat_ii_open,
                cat_iii_open: s.cat_iii_open,
            };

            let db = state.db();
            let _ = db.save_checklist(&checklist);
            let _ = db.log_evaluation(&checklist, "gui", None);
            if let Some(ref aid) = req.asset_id {
                update_asset_after_eval(
                    &db,
                    aid,
                    &req.stig_id,
                    s.compliance_pct(),
                    &checklist.id.to_string(),
                );
            }

            api_ok(info)
        }
        Err(e) => api_error(&format!("Evaluation failed: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// DISA Content Fetching
// ---------------------------------------------------------------------------

/// List available STIGs from DISA's public download page.
async fn disa_list_available() -> Json<serde_json::Value> {
    match crate::disa::list_available_stigs().await {
        Ok(stigs) => api_ok(stigs),
        Err(e) => api_error(&e),
    }
}

/// Fetch and import a specific STIG from DISA by URL.
#[derive(Deserialize)]
struct DisaFetchRequest {
    url: String,
}

async fn disa_fetch(
    State(state): State<AppState>,
    Json(req): Json<DisaFetchRequest>,
) -> Json<serde_json::Value> {
    match crate::disa::download_and_import(&req.url, &state).await {
        Ok(result) => api_ok(result),
        Err(e) => api_error(&e),
    }
}

/// Fetch all available STIGs from DISA.
async fn disa_fetch_all(State(state): State<AppState>) -> Json<serde_json::Value> {
    match crate::disa::fetch_all_content(&state).await {
        Ok(result) => api_ok(result),
        Err(e) => api_error(&e),
    }
}

/// Check for updates without downloading.
async fn disa_check_updates(State(state): State<AppState>) -> Json<serde_json::Value> {
    match crate::disa::check_for_updates(&state).await {
        Ok(result) => api_ok(result),
        Err(e) => api_error(&e),
    }
}

/// Generate an offline update package (.stigpack) from the current library
/// for transfer to air-gapped systems.
async fn generate_offline_pack(State(state): State<AppState>) -> impl IntoResponse {
    let library = match state.library() {
        Ok(l) => l,
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Library error: {}", e),
            )
                .into_response();
        }
    };

    let benchmarks = library.list_benchmarks();
    if benchmarks.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "No benchmarks in library to package",
        )
            .into_response();
    }

    // Build a stigpack with all current library content.
    let mut builder = automatestig_stigpack::builder::PackBuilder::new(
        &format!(
            "automatestig-offline-{}",
            chrono::Utc::now().format("%Y%m%d")
        ),
        "AutomateSTIG Offline Update",
        &chrono::Utc::now().format("%Y.%m.%d").to_string(),
    )
    .author("AutomateSTIG")
    .description("Offline update package for air-gapped AutomateSTIG installations");

    for entry in &benchmarks {
        match library.load_benchmark(&entry.id) {
            Ok(benchmark) => {
                if let Ok(json) = serde_json::to_string_pretty(&benchmark) {
                    let pack_path = format!("benchmarks/{}.json", entry.id);
                    builder = builder.add_file_bytes(&pack_path, json.as_bytes());
                }
            }
            Err(_) => continue,
        }
    }

    let tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create temp file: {}", e),
            )
                .into_response();
        }
    };
    if let Err(e) = builder.build(tmp.path()) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to build pack: {}", e),
        )
            .into_response();
    }

    let data = match std::fs::read(tmp.path()) {
        Ok(d) => d,
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read pack: {}", e),
            )
                .into_response();
        }
    };
    let filename = format!(
        "automatestig-offline-{}.stigpack",
        chrono::Utc::now().format("%Y%m%d")
    );

    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        data,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// STIG-Manager Integration
// ---------------------------------------------------------------------------

/// Get current STIG-Manager configuration.
async fn stigman_get_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    let config = load_stigman_config(&db);
    api_ok(serde_json::json!({
        "configured": config.is_configured(),
        "api_url": config.api_url,
        "token_url": config.token_url,
        "client_id": config.client_id,
        "has_secret": !config.client_secret.is_empty(),
        "default_collection_id": config.default_collection_id,
        "verify_tls": config.verify_tls,
    }))
}

/// Save STIG-Manager configuration.
async fn stigman_set_config(
    State(state): State<AppState>,
    Json(mut body): Json<crate::stigman::StigManagerConfig>,
) -> Json<serde_json::Value> {
    let db = state.db();

    // Encrypt the client secret before storing.
    if !body.client_secret.is_empty() {
        let key_material = db
            .get_config("_encryption_salt")
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                // Generate a random salt on first use.
                let salt = format!(
                    "{:x}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                );
                let _ = db.set_config("_encryption_salt", &salt);
                salt
            });

        match crate::secrets::encrypt_secret(&body.client_secret, &key_material) {
            Ok(encrypted) => {
                body.client_secret = format!("enc:{}", encrypted);
            }
            Err(e) => return api_error(&format!("Encryption failed: {}", e)),
        }
    }

    match serde_json::to_string(&body) {
        Ok(json) => {
            if let Err(e) = db.set_config("stigman_config", &json) {
                return api_error(&format!("Failed to save config: {}", e));
            }
            api_ok("Configuration saved")
        }
        Err(e) => api_error(&format!("Serialization error: {}", e)),
    }
}

/// Test STIG-Manager connection.
async fn stigman_test_connection(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config = {
        let db = state.db();
        load_stigman_config(&db)
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config) {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    match client.test_connection().await {
        Ok(msg) => api_ok(msg),
        Err(e) => api_error(&e),
    }
}

/// List collections from STIG-Manager.
async fn stigman_list_collections(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config = {
        let db = state.db();
        load_stigman_config(&db)
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config) {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    match client.list_collections().await {
        Ok(collections) => api_ok(collections),
        Err(e) => api_error(&e),
    }
}

/// List assets in a STIG-Manager collection.
async fn stigman_list_assets(
    State(state): State<AppState>,
    axum::extract::Path(cid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let config = {
        let db = state.db();
        load_stigman_config(&db)
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config) {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    match client.list_assets(&cid).await {
        Ok(assets) => api_ok(assets),
        Err(e) => api_error(&e),
    }
}

/// Sync assets from a STIG-Manager collection into local inventory.
async fn stigman_sync_assets(
    State(state): State<AppState>,
    axum::extract::Path(cid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let config = {
        let db = state.db();
        load_stigman_config(&db)
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config) {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    // Fetch assets from STIG-Manager.
    let sm_assets = match client.list_assets(&cid).await {
        Ok(a) => a,
        Err(e) => return api_error(&format!("Failed to fetch assets: {}", e)),
    };

    // Load local assets, then drop the DB lock before async work.
    let mut local_assets = {
        let db = state.db();
        load_assets(&db)
    };
    let mut synced = 0;
    let mut details = Vec::new();

    for sm_asset in &sm_assets {
        // Check if asset already exists locally (by name).
        let existing = local_assets.iter().position(|a| a.name == sm_asset.name);

        // Fetch STIGs assigned to this asset in STIG-Manager.
        let stig_ids: Vec<String> = match client.list_asset_stigs(&cid, &sm_asset.asset_id).await {
            Ok(stigs) => stigs.iter().map(|s| s.benchmark_id.clone()).collect(),
            Err(_) => Vec::new(),
        };

        if let Some(idx) = existing {
            // Update existing asset with STIG-Manager data.
            local_assets[idx].assigned_stigs = stig_ids.clone();
            if let Some(ref ip) = sm_asset.ip {
                if !ip.is_empty() {
                    local_assets[idx].address = ip.clone();
                }
            }
            details.push(format!(
                "Updated: {} ({} STIGs)",
                sm_asset.name,
                stig_ids.len()
            ));
        } else {
            // Create new local asset from STIG-Manager data.
            let mut asset = automatestig_core::inventory::assets::ManagedAsset::new(
                &sm_asset.name,
                sm_asset.ip.as_deref().unwrap_or(&sm_asset.name),
                automatestig_core::checks::CheckPlatform::Generic,
                automatestig_core::inventory::assets::ScanProtocol::Ssh,
            );
            asset.assigned_stigs = stig_ids.clone();
            if let Some(ref fqdn) = sm_asset.fqdn {
                if !fqdn.is_empty() {
                    asset.address = fqdn.clone();
                }
            }
            asset.notes = sm_asset.description.clone();
            asset.tags = vec!["stigman-sync".to_string()];
            details.push(format!(
                "Created: {} ({} STIGs)",
                sm_asset.name,
                stig_ids.len()
            ));
            local_assets.push(asset);
        }
        synced += 1;
    }

    {
        let db = state.db();
        save_assets(&db, &local_assets);
    }

    api_ok(serde_json::json!({
        "synced": synced,
        "total_assets": local_assets.len(),
        "details": details,
    }))
}

/// Check for differences between STIG-Manager and local inventory.
async fn stigman_diff_assets(
    State(state): State<AppState>,
    axum::extract::Path(cid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let config = {
        let db = state.db();
        load_stigman_config(&db)
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config) {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    let sm_assets = match client.list_assets(&cid).await {
        Ok(a) => a,
        Err(e) => return api_error(&format!("Failed to fetch: {}", e)),
    };

    let local_assets = {
        let db = state.db();
        load_assets(&db)
    };

    let local_names: std::collections::HashSet<String> =
        local_assets.iter().map(|a| a.name.clone()).collect();
    let sm_names: std::collections::HashSet<String> =
        sm_assets.iter().map(|a| a.name.clone()).collect();

    // Assets in SM but not local.
    let new_in_sm: Vec<&str> = sm_names
        .difference(&local_names)
        .map(|s| s.as_str())
        .collect();

    // Assets local but not in SM.
    let removed_from_sm: Vec<&str> = local_names
        .iter()
        .filter(|n| {
            !sm_names.contains(*n)
                && local_assets
                    .iter()
                    .any(|a| a.name == **n && a.tags.contains(&"stigman-sync".to_string()))
        })
        .map(|s| s.as_str())
        .collect();

    // Assets in both — check for STIG assignment changes.
    let mut stig_changes = Vec::new();
    for sm_asset in &sm_assets {
        if let Some(local) = local_assets.iter().find(|a| a.name == sm_asset.name) {
            let sm_stigs: Vec<String> =
                match client.list_asset_stigs(&cid, &sm_asset.asset_id).await {
                    Ok(stigs) => stigs.iter().map(|s| s.benchmark_id.clone()).collect(),
                    Err(_) => continue,
                };

            let local_set: std::collections::HashSet<&String> =
                local.assigned_stigs.iter().collect();
            let sm_set: std::collections::HashSet<&String> = sm_stigs.iter().collect();

            let added: Vec<&String> = sm_set.difference(&local_set).copied().collect();
            let removed: Vec<&String> = local_set.difference(&sm_set).copied().collect();

            if !added.is_empty() || !removed.is_empty() {
                stig_changes.push(serde_json::json!({
                    "asset": sm_asset.name,
                    "stigs_added": added,
                    "stigs_removed": removed,
                }));
            }
        }
    }

    let has_changes =
        !new_in_sm.is_empty() || !removed_from_sm.is_empty() || !stig_changes.is_empty();

    api_ok(serde_json::json!({
        "has_changes": has_changes,
        "new_assets_in_stigman": new_in_sm,
        "removed_from_stigman": removed_from_sm,
        "stig_assignment_changes": stig_changes,
        "local_count": local_assets.len(),
        "stigman_count": sm_assets.len(),
    }))
}

/// Push a checklist's results to STIG-Manager.
#[derive(Deserialize)]
struct PushRequest {
    collection_id: String,
    asset_id: Option<String>,
}

async fn stigman_push_checklist(
    State(state): State<AppState>,
    axum::extract::Path(checklist_id): axum::extract::Path<String>,
    Json(req): Json<PushRequest>,
) -> Json<serde_json::Value> {
    // Load the checklist.
    let checklist = {
        let db = state.db();
        match db.load_checklist(&checklist_id) {
            Ok(cl) => cl,
            Err(e) => return api_error(&format!("Checklist not found: {}", e)),
        }
    };

    let config = {
        let db = state.db();
        load_stigman_config(&db)
    };

    match push_checklist_to_stigman(
        config,
        &checklist,
        &req.collection_id,
        req.asset_id.as_deref(),
    )
    .await
    {
        Ok(result) => api_ok(result),
        Err(e) => api_error(&e),
    }
}

async fn push_checklist_to_stigman(
    config: crate::stigman::StigManagerConfig,
    checklist: &Checklist,
    collection_id: &str,
    asset_id: Option<&str>,
) -> Result<serde_json::Value, String> {
    if !config.is_configured() {
        return Err("STIG-Manager is not configured".to_string());
    }

    let client = crate::stigman::StigManagerClient::new(config)?;

    // If no asset_id provided, try to create the asset.
    let asset_id = match asset_id {
        Some(id) => id.to_string(),
        None => {
            client
                .create_asset(
                    collection_id,
                    &checklist.asset.hostname,
                    checklist.asset.fqdn.as_deref(),
                    checklist.asset.ip_address.as_deref(),
                )
                .await
                .map_err(|e| format!("Failed to create asset: {}", e))?
                .asset_id
        }
    };

    // Convert findings to STIG-Manager reviews.
    let reviews = crate::stigman::StigManagerClient::checklist_to_reviews(checklist);
    let review_count = reviews.len();

    // Push to STIG-Manager.
    let result = client
        .push_reviews(
            collection_id,
            &asset_id,
            &checklist.stig_info.stig_id,
            reviews,
        )
        .await
        .map_err(|e| format!("Push failed: {}", e))?;

    Ok(serde_json::json!({
        "pushed": review_count,
        "asset_id": asset_id,
        "collection_id": collection_id,
        "result": result,
    }))
}

/// Load STIG-Manager config from the database, decrypting the client secret.
fn load_stigman_config(db: &automatestig_storage::Database) -> crate::stigman::StigManagerConfig {
    let mut config: crate::stigman::StigManagerConfig = db
        .get_config("stigman_config")
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    // Decrypt client secret if it's encrypted.
    if config.client_secret.starts_with("enc:") {
        let encrypted = &config.client_secret[4..];
        let key_material = db
            .get_config("_encryption_salt")
            .ok()
            .flatten()
            .unwrap_or_default();

        match crate::secrets::decrypt_secret(encrypted, &key_material) {
            Ok(decrypted) => config.client_secret = decrypted,
            Err(_) => {
                tracing::warn!("Failed to decrypt STIG-Manager client secret");
                config.client_secret.clear();
            }
        }
    }

    config
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Auto-generate Check Packs from Benchmarks
// ---------------------------------------------------------------------------

async fn generate_checks(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let library = match state.library() {
        Ok(l) => l,
        Err(e) => return api_error(&e.to_string()),
    };

    let benchmark = match library.load_benchmark(&id) {
        Ok(b) => b,
        Err(e) => return api_error(&format!("Benchmark not found: {}", e)),
    };

    let result = automatestig_core::converter::convert_benchmark(&benchmark);

    // Save the generated check pack to disk.
    let packs_dir = state.inner.library_path.join("auto_check_packs");
    let _ = std::fs::create_dir_all(&packs_dir);

    let filename = format!("{}.json", id);
    let pack_path = packs_dir.join(&filename);

    match automatestig_core::converter::check_pack_to_json(&result.check_pack) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&pack_path, &json) {
                return api_error(&format!("Failed to save check pack: {}", e));
            }
        }
        Err(e) => return api_error(&format!("Serialization error: {}", e)),
    }

    api_ok(serde_json::json!({
        "stig_id": id,
        "automated": result.automated,
        "manual": result.manual,
        "total_rules": result.automated + result.manual,
        "automation_rate": format!("{:.0}%", if result.automated + result.manual > 0 {
            result.automated as f64 / (result.automated + result.manual) as f64 * 100.0
        } else { 0.0 }),
        "pack_path": pack_path.display().to_string(),
        "log": result.log,
    }))
}

// ---------------------------------------------------------------------------
// Batch Evaluation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BatchEvaluateRequest {
    stig_id: String,
    hostnames: Vec<String>,
}

async fn evaluate_batch(
    State(state): State<AppState>,
    Json(req): Json<BatchEvaluateRequest>,
) -> Json<serde_json::Value> {
    if req.hostnames.len() > 100 {
        return api_error("Batch limit exceeded: maximum 100 hostnames per request");
    }
    if req.hostnames.iter().any(|h| h.len() > 255) {
        return api_error("Hostname exceeds maximum length of 255 characters");
    }

    let library = match state.library() {
        Ok(l) => l,
        Err(e) => return api_error(&e.to_string()),
    };

    let benchmark = match library.load_benchmark(&req.stig_id) {
        Ok(b) => b,
        Err(e) => return api_error(&format!("Benchmark not found: {}", e)),
    };

    let engine = std::sync::Arc::new(automatestig_core::engine::EvaluationEngine::with_defaults());
    let benchmark = std::sync::Arc::new(benchmark);

    // Parallel evaluation with semaphore (max 10 concurrent).
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(10));
    let mut handles = Vec::new();

    for hostname in req.hostnames.clone() {
        let sem = sem.clone();
        let engine = engine.clone();
        let benchmark = benchmark.clone();
        let state = state.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let asset = Asset::new(&hostname);
            match engine.evaluate(&benchmark, &asset, None, &[]) {
                Ok(checklist) => {
                    let s = checklist.summary();
                    let db = state.db();
                    let _ = db.save_checklist(&checklist);
                    let _ = db.log_evaluation(&checklist, "gui-batch", None);
                    serde_json::json!({
                        "hostname": hostname,
                        "id": checklist.id.to_string(),
                        "total": s.total,
                        "open": s.open,
                        "compliance_pct": s.compliance_pct(),
                        "success": true,
                    })
                }
                Err(e) => {
                    serde_json::json!({
                        "hostname": hostname,
                        "error": e.to_string(),
                        "success": false,
                    })
                }
            }
        }));
    }

    // Collect results from all tasks.
    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    api_ok(serde_json::json!({
        "evaluated": results.len(),
        "results": results,
    }))
}

// ---------------------------------------------------------------------------
// Evaluate with Scan Upload
// ---------------------------------------------------------------------------

async fn evaluate_with_scan(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Json<serde_json::Value> {
    let mut stig_id = String::new();
    let mut hostname = String::new();
    let mut asset_id: Option<String> = None;
    let mut scan_data: Option<Vec<u8>> = None;
    let mut scan_filename = String::new();

    // Parse multipart fields.
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "stig_id" => {
                stig_id = field.text().await.unwrap_or_default();
            }
            "hostname" => {
                hostname = field.text().await.unwrap_or_default();
            }
            "asset_id" => {
                asset_id = Some(field.text().await.unwrap_or_default());
            }
            "scan" => {
                scan_filename = field.file_name().unwrap_or("scan").to_string();
                scan_data = field.bytes().await.ok().map(|b| b.to_vec());
            }
            _ => {}
        }
    }

    if stig_id.is_empty() {
        return api_error("stig_id is required");
    }

    let library = match state.library() {
        Ok(l) => l,
        Err(e) => return api_error(&e.to_string()),
    };

    let benchmark = match library.load_benchmark(&stig_id) {
        Ok(b) => b,
        Err(e) => return api_error(&format!("Benchmark not found: {}", e)),
    };

    // Parse scan results if uploaded.
    let scan_results = if let Some(data) = scan_data {
        let text = String::from_utf8_lossy(&data);
        let ext = std::path::Path::new(&scan_filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        match ext {
            "xml" => xccdf::parse_xccdf_results_str(&text).ok(),
            _ => None,
        }
    } else {
        None
    };

    // Detect hostname from scan if not provided.
    if hostname.is_empty() {
        hostname = scan_results
            .as_ref()
            .and_then(|s| s.source.target.clone())
            .unwrap_or_else(|| "Unknown".to_string());
    }

    let asset = Asset::new(&hostname);
    let engine = automatestig_core::engine::EvaluationEngine::with_defaults();

    match engine.evaluate(&benchmark, &asset, scan_results.as_ref(), &[]) {
        Ok(checklist) => {
            let s = checklist.summary();
            let db = state.db();
            let _ = db.save_checklist(&checklist);
            let _ = db.log_evaluation(&checklist, "gui-scan-import", None);
            if let Some(ref aid) = asset_id {
                update_asset_after_eval(
                    &db,
                    aid,
                    &stig_id,
                    s.compliance_pct(),
                    &checklist.id.to_string(),
                );
            }

            api_ok(serde_json::json!({
                "id": checklist.id.to_string(),
                "hostname": hostname,
                "stig_id": stig_id,
                "total": s.total,
                "open": s.open,
                "not_a_finding": s.not_a_finding,
                "compliance_pct": s.compliance_pct(),
            }))
        }
        Err(e) => api_error(&format!("Evaluation failed: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Finding Editing
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UpdateFindingRequest {
    status: Option<String>,
    finding_details: Option<String>,
    comments: Option<String>,
}

async fn update_finding(
    State(state): State<AppState>,
    axum::extract::Path((id, vuln_id)): axum::extract::Path<(String, String)>,
    Json(req): Json<UpdateFindingRequest>,
) -> Json<serde_json::Value> {
    let db = state.db();

    let mut checklist = match db.load_checklist(&id) {
        Ok(cl) => cl,
        Err(e) => return api_error(&format!("Checklist not found: {}", e)),
    };

    {
        let finding = match checklist.find_by_vuln_id_mut(&vuln_id) {
            Some(f) => f,
            None => return api_error(&format!("Finding not found: {}", vuln_id)),
        };

        if let Some(ref status_str) = req.status {
            if let Some(status) =
                automatestig_core::models::finding::FindingStatus::from_ckl_str(status_str)
            {
                finding.status = status;
                finding.source = automatestig_core::models::finding::FindingSource::Manual;
                finding.evaluated_at = chrono::Utc::now();
            }
        }
        if let Some(ref details) = req.finding_details {
            finding.finding_details = details.clone();
        }
        if let Some(ref comments) = req.comments {
            finding.comments = comments.clone();
        }
    }

    checklist.touch();

    let result_status = checklist
        .find_by_vuln_id(&vuln_id)
        .map(|f| f.status.to_string())
        .unwrap_or_default();

    if let Err(e) = db.save_checklist(&checklist) {
        return api_error(&format!("Failed to save: {}", e));
    }

    api_ok(serde_json::json!({
        "vuln_id": vuln_id,
        "status": result_status,
        "updated": true,
    }))
}

// ---------------------------------------------------------------------------
// Agent Configuration
// ---------------------------------------------------------------------------

async fn get_agent_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    api_ok(load_agent_config(&db))
}

pub(crate) fn load_agent_config(db: &automatestig_storage::Database) -> AgentConfig {
    db.get_config("agent_config")
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn load_agent_webhook_url(db: &automatestig_storage::Database) -> Option<String> {
    let raw = db.get_config("agent_config").ok().flatten()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let candidates = [
        value.pointer("/notifications/webhook_url"),
        value.pointer("/notifications/webhook"),
        value.get("webhook_url"),
        value.get("notification_webhook"),
    ];

    let webhook_url = candidates
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .map(str::trim)
        .find(|url| !url.is_empty())
        .map(str::to_string);

    webhook_url
}

fn save_agent_config(
    db: &automatestig_storage::Database,
    config: &AgentConfig,
) -> Result<(), String> {
    let json = serde_json::to_string(config).map_err(|e| e.to_string())?;
    db.set_config("agent_config", &json)
        .map_err(|e| e.to_string())
}

async fn set_agent_config(
    State(state): State<AppState>,
    Json(config): Json<AgentConfig>,
) -> Json<serde_json::Value> {
    let db = state.db();
    match save_agent_config(&db, &config) {
        Ok(()) => api_ok("Agent configuration saved"),
        Err(e) => api_error(&format!("Failed to save: {}", e)),
    }
}

pub(crate) async fn run_agent_cycle(state: &AppState) -> usize {
    let mut config = {
        let db = state.db();
        load_agent_config(&db)
    };

    if !config.enabled {
        return 0;
    }

    let assets = {
        let db = state.db();
        load_assets(&db)
    };
    let auto_push_stigman = config.auto_push_stigman;
    let alert_on_new_findings = config.alert_on_new_findings;
    let notifications = config.notifications.clone();
    let mut scanned_targets = 0;

    for target in &mut config.targets {
        if !target.enabled {
            continue;
        }

        let Some(asset) = resolve_agent_asset(&assets, target).cloned() else {
            tracing::warn!(
                "agent: no registered asset for target {}; cannot collect",
                target.hostname
            );
            continue;
        };

        let stig_ids: Vec<String> = target
            .stig_ids
            .iter()
            .map(|stig_id| stig_id.trim())
            .filter(|stig_id| !stig_id.is_empty())
            .map(str::to_string)
            .collect();

        if stig_ids.is_empty() {
            tracing::warn!("agent: target {} has no STIGs configured", target.hostname);
            continue;
        }

        let host_candidates = agent_host_candidates(target, &asset);
        let mut attempted = false;
        let mut last_success_compliance = None;

        for stig_id in &stig_ids {
            attempted = true;
            let previous = {
                let db = state.db();
                previous_agent_checklist(&db, &host_candidates, stig_id)
            };

            match scan_and_evaluate_asset(state, &asset, stig_id).await {
                Ok(checklist) => {
                    let summary = checklist.summary();
                    let compliance = summary.compliance_pct();
                    last_success_compliance = Some(compliance);

                    if alert_on_new_findings {
                        let alert_event = if let Some(previous) = previous.as_ref() {
                            if automatestig_core::agent::detect_drift(previous, &checklist)
                                .has_changes()
                            {
                                Some("agent_drift")
                            } else {
                                None
                            }
                        } else if summary.open > 0 {
                            Some("agent_findings")
                        } else {
                            None
                        };

                        if let Some(event) = alert_event {
                            send_agent_alert(
                                state,
                                &notifications,
                                event,
                                &target.hostname,
                                stig_id,
                                compliance,
                                summary.open,
                            )
                            .await;
                        }
                    }

                    if auto_push_stigman {
                        push_agent_checklist_to_stigman(state, &notifications, &checklist).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "agent: scan failed for target {} STIG {}: {}",
                        target.hostname,
                        stig_id,
                        e
                    );
                    append_agent_log(
                        &notifications,
                        &format!(
                            "{} agent_error hostname={} stig={} error={}",
                            Utc::now().to_rfc3339(),
                            target.hostname,
                            stig_id,
                            log_line_value(&e)
                        ),
                    );
                }
            }
        }

        if attempted {
            scanned_targets += 1;
            target.last_scan = Some(Utc::now());
            if let Some(compliance) = last_success_compliance {
                target.last_compliance_pct = Some(compliance);
            }
        }
    }

    {
        let db = state.db();
        if let Err(e) = save_agent_config(&db, &config) {
            tracing::warn!("agent: failed to persist agent config: {}", e);
        }
    }

    scanned_targets
}

fn resolve_agent_asset<'a>(
    assets: &'a [ManagedAsset],
    target: &MonitoredTarget,
) -> Option<&'a ManagedAsset> {
    assets
        .iter()
        .find(|asset| asset.name == target.hostname || asset.address == target.hostname)
}

fn agent_host_candidates(target: &MonitoredTarget, asset: &ManagedAsset) -> Vec<String> {
    let mut candidates = Vec::new();
    for hostname in [&target.hostname, &asset.name, &asset.address] {
        if !hostname.is_empty() && !candidates.iter().any(|existing| existing == hostname) {
            candidates.push(hostname.clone());
        }
    }
    candidates
}

fn previous_agent_checklist(
    db: &automatestig_storage::Database,
    hostnames: &[String],
    stig_id: &str,
) -> Option<Checklist> {
    db.list_checklists()
        .ok()?
        .iter()
        .find(|row| {
            row.stig_id == stig_id
                && hostnames
                    .iter()
                    .any(|hostname| row.asset_hostname == hostname.as_str())
        })
        .and_then(|row| db.load_checklist(&row.id).ok())
}

async fn send_agent_alert(
    state: &AppState,
    notifications: &NotificationConfig,
    event: &str,
    hostname: &str,
    stig_id: &str,
    compliance: f64,
    open: usize,
) {
    let data = serde_json::json!({
        "hostname": hostname,
        "stig": stig_id,
        "compliance": compliance,
        "open": open,
    });

    let webhook_url = {
        let db = state.db();
        load_agent_webhook_url(&db)
    };

    if let Some(url) = webhook_url {
        send_webhook_notification(&url, event, &data).await;
    }

    append_agent_log(
        notifications,
        &format!(
            "{} {} hostname={} stig={} compliance={:.2} open={}",
            Utc::now().to_rfc3339(),
            event,
            hostname,
            stig_id,
            compliance,
            open
        ),
    );
}

async fn push_agent_checklist_to_stigman(
    state: &AppState,
    notifications: &NotificationConfig,
    checklist: &Checklist,
) {
    let config = {
        let db = state.db();
        load_stigman_config(&db)
    };
    let Some(collection_id) = config.default_collection_id.clone() else {
        let message = "agent: auto-push requested but no default STIG-Manager collection is set";
        tracing::warn!("{}", message);
        append_agent_log(
            notifications,
            &format!("{} {}", Utc::now().to_rfc3339(), message),
        );
        return;
    };

    if let Err(e) = push_checklist_to_stigman(config, checklist, &collection_id, None).await {
        tracing::warn!(
            "agent: failed to push {} {} to STIG-Manager: {}",
            checklist.asset.hostname,
            checklist.stig_info.stig_id,
            e
        );
        append_agent_log(
            notifications,
            &format!(
                "{} agent_stigman_error hostname={} stig={} error={}",
                Utc::now().to_rfc3339(),
                checklist.asset.hostname,
                checklist.stig_info.stig_id,
                log_line_value(&e)
            ),
        );
    }
}

fn append_agent_log(notifications: &NotificationConfig, line: &str) {
    let Some(path) = notifications
        .log_file
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return;
    };

    let path = Path::new(path);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "agent: failed to create log directory {}: {}",
                parent.display(),
                e
            );
            return;
        }
    }

    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{}", line) {
                tracing::warn!("agent: failed to append log {}: {}", path.display(), e);
            }
        }
        Err(e) => tracing::warn!("agent: failed to open log {}: {}", path.display(), e),
    }
}

fn log_line_value(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

async fn get_drift_report(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();

    // Load current checklist.
    let current = match db.load_checklist(&id) {
        Ok(cl) => cl,
        Err(e) => return api_error(&format!("Checklist not found: {}", e)),
    };

    // Find the previous checklist for the same asset+STIG.
    let all = db.list_checklists().unwrap_or_default();
    let previous = all.iter().rfind(|row| {
        row.asset_hostname == current.asset.hostname
            && row.stig_id == current.stig_info.stig_id
            && row.id != id
    });

    match previous {
        Some(prev_row) => match db.load_checklist(&prev_row.id) {
            Ok(prev) => {
                let report = automatestig_core::agent::detect_drift(&prev, &current);
                api_ok(report)
            }
            Err(e) => api_error(&format!("Could not load previous checklist: {}", e)),
        },
        None => api_ok(serde_json::json!({
            "message": "No previous checklist found for comparison",
            "has_changes": false,
        })),
    }
}

// ---------------------------------------------------------------------------
// Asset Inventory
// ---------------------------------------------------------------------------

fn load_assets(
    db: &automatestig_storage::Database,
) -> Vec<automatestig_core::inventory::assets::ManagedAsset> {
    db.get_config("asset_inventory")
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn save_assets(
    db: &automatestig_storage::Database,
    assets: &[automatestig_core::inventory::assets::ManagedAsset],
) {
    if let Ok(json) = serde_json::to_string(assets) {
        let _ = db.set_config("asset_inventory", &json);
    }
}

/// After an evaluation, reflect the result on the linked asset (if any).
fn update_asset_after_eval(
    db: &automatestig_storage::Database,
    asset_id: &str,
    stig_id: &str,
    compliance_pct: f64,
    checklist_id: &str,
) {
    let mut assets = load_assets(db);
    if let Some(asset) = assets.iter_mut().find(|a| a.id == asset_id) {
        asset.last_evaluated = Some(chrono::Utc::now());
        asset.last_compliance_pct = Some(compliance_pct);
        if !asset.assigned_stigs.iter().any(|s| s == stig_id) {
            asset.assigned_stigs.push(stig_id.to_string());
        }
        if !asset.last_checklist_ids.iter().any(|c| c == checklist_id) {
            asset.last_checklist_ids.push(checklist_id.to_string());
        }
        save_assets(db, &assets);
    }
}

async fn list_assets_inv(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    api_ok(load_assets(&db))
}

async fn create_asset_inv(
    State(state): State<AppState>,
    Json(asset): Json<automatestig_core::inventory::assets::ManagedAsset>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut assets = load_assets(&db);
    assets.push(asset.clone());
    save_assets(&db, &assets);
    api_ok(asset)
}

async fn get_asset_inv(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let assets = load_assets(&db);
    match assets.into_iter().find(|a| a.id == id) {
        Some(asset) => api_ok(asset),
        None => api_error("Asset not found"),
    }
}

async fn update_asset_inv(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(updated): Json<automatestig_core::inventory::assets::ManagedAsset>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut assets = load_assets(&db);
    if let Some(asset) = assets.iter_mut().find(|a| a.id == id) {
        *asset = updated.clone();
        save_assets(&db, &assets);
        api_ok(updated)
    } else {
        api_error("Asset not found")
    }
}

async fn delete_asset_inv(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut assets = load_assets(&db);
    let len = assets.len();
    assets.retain(|a| a.id != id);
    save_assets(&db, &assets);
    api_ok(assets.len() < len)
}

// ---------------------------------------------------------------------------
// Credential Vault
// ---------------------------------------------------------------------------

fn save_vault(
    db: &automatestig_storage::Database,
    vault: &automatestig_core::inventory::credentials::CredentialVault,
) -> Result<(), String> {
    let key_material = db
        .get_config("_encryption_salt")
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| {
            let rng = ring::rand::SystemRandom::new();
            let mut bytes = [0u8; 32];
            ring::rand::SecureRandom::fill(&rng, &mut bytes)
                .expect("Failed to generate encryption salt");
            let salt: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let _ = db.set_config("_encryption_salt", &salt);
            salt
        });

    let json = serde_json::to_string(vault).map_err(|e| e.to_string())?;
    let encrypted = crate::secrets::encrypt_secret(&json, &key_material)?;
    db.set_config("credential_vault", &format!("enc:{}", encrypted))
        .map_err(|e| e.to_string())?;
    db.set_config("credential_vault_format", "encrypted-v1")
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn load_vault(
    db: &automatestig_storage::Database,
) -> Result<automatestig_core::inventory::credentials::CredentialVault, String> {
    let raw = db
        .get_config("credential_vault")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    if raw.is_empty() {
        return Ok(automatestig_core::inventory::credentials::CredentialVault::default());
    }

    let encrypted = raw.strip_prefix("enc:").ok_or_else(|| {
        "Credential vault is plaintext/legacy and must be migrated before use".to_string()
    })?;
    let key_material = db
        .get_config("_encryption_salt")
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Credential vault encryption salt is missing".to_string())?;
    let json = crate::secrets::decrypt_secret(encrypted, &key_material)?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

async fn list_credentials(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    let vault = match load_vault(&db) {
        Ok(vault) => vault,
        Err(e) => return api_error(&format!("Failed to load credential vault: {}", e)),
    };
    api_ok(vault.list_summary())
}

async fn create_credential(
    State(state): State<AppState>,
    Json(cred): Json<automatestig_core::inventory::credentials::StoredCredential>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut vault = match load_vault(&db) {
        Ok(vault) => vault,
        Err(e) => return api_error(&format!("Failed to load credential vault: {}", e)),
    };
    let summary = automatestig_core::inventory::credentials::CredentialSummary {
        id: cred.id.clone(),
        label: cred.label.clone(),
        credential_type: match &cred.credential {
            automatestig_core::inventory::credentials::CredentialType::Password { .. } => {
                "password".to_string()
            }
            automatestig_core::inventory::credentials::CredentialType::SshKey { .. } => {
                "ssh_key".to_string()
            }
            automatestig_core::inventory::credentials::CredentialType::SshCertificate {
                ..
            } => "ssh_certificate".to_string(),
            automatestig_core::inventory::credentials::CredentialType::Kerberos { .. } => {
                "kerberos".to_string()
            }
            automatestig_core::inventory::credentials::CredentialType::Token { .. } => {
                "token".to_string()
            }
            automatestig_core::inventory::credentials::CredentialType::ClientCertificate {
                ..
            } => "client_certificate".to_string(),
        },
        username: cred.username().map(|s| s.to_string()),
        is_expired: cred.is_expired(),
        last_used: cred.last_used,
    };
    vault.add(cred);
    if let Err(e) = save_vault(&db, &vault) {
        return api_error(&format!("Failed to save credential vault: {}", e));
    }
    api_ok(summary)
}

async fn delete_credential(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut vault = match load_vault(&db) {
        Ok(vault) => vault,
        Err(e) => return api_error(&format!("Failed to load credential vault: {}", e)),
    };
    let removed = vault.remove(&id);
    if let Err(e) = save_vault(&db, &vault) {
        return api_error(&format!("Failed to save credential vault: {}", e));
    }
    api_ok(removed)
}

// ---------------------------------------------------------------------------
// Schedules
// ---------------------------------------------------------------------------

pub(crate) fn load_schedules(db: &automatestig_storage::Database) -> SchedulerConfig {
    db.get_config("scheduler_config")
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

pub(crate) fn save_schedules(db: &automatestig_storage::Database, config: &SchedulerConfig) {
    if let Ok(json) = serde_json::to_string(config) {
        let _ = db.set_config("scheduler_config", &json);
    }
}

pub(crate) fn refresh_scheduler_enabled(config: &mut SchedulerConfig) {
    config.enabled = config.schedules.iter().any(|schedule| schedule.enabled);
}

pub(crate) fn schedule_is_due(schedule: &EvaluationSchedule, now: DateTime<Utc>) -> bool {
    schedule.enabled && schedule.next_run.is_some_and(|next_run| next_run <= now)
}

fn schedule_target_assets(
    schedule: &EvaluationSchedule,
    assets: &[ManagedAsset],
) -> Vec<ManagedAsset> {
    assets
        .iter()
        .filter(|asset| {
            schedule.asset_ids.contains(&asset.id)
                || schedule
                    .asset_tags
                    .iter()
                    .any(|tag| asset.tags.contains(tag))
        })
        .cloned()
        .collect()
}

async fn scan_and_evaluate_asset(
    state: &AppState,
    asset: &ManagedAsset,
    stig_id: &str,
) -> Result<Checklist, String> {
    let credential_id = asset
        .credential_id
        .as_deref()
        .ok_or_else(|| "no credential assigned".to_string())?;

    let credential = {
        let db = state.db();
        let vault = load_vault(&db)?;
        vault
            .get(credential_id)
            .cloned()
            .ok_or_else(|| format!("credential {} not found", credential_id))?
    };

    let checklist = match asset.protocol {
        ScanProtocol::Ssh => {
            let (username, auth) = match credential.credential {
                CredentialType::Password { username, password } => {
                    (username, crate::ssh::SshAuth::Password { password })
                }
                CredentialType::SshKey { .. } => {
                    return Err("ssh key auth not yet supported for scheduled scans".to_string());
                }
                _ => return Err("ssh scheduled scans require password credentials".to_string()),
            };

            let ssh_config = crate::ssh::SshConfig {
                host: asset.address.clone(),
                port: asset.port.unwrap_or(22),
                username,
                auth,
                timeout_secs: 30,
            };

            let raw_outputs = crate::ssh::collect_linux_data(&ssh_config)
                .await
                .map_err(|e| format!("SSH collection failed: {}", e))?;
            let hostname = raw_outputs
                .get("hostname")
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| asset.address.clone());
            let system_data = automatestig_core::remote::assemble_system_data(
                automatestig_core::checks::CheckPlatform::Linux,
                &hostname,
                &raw_outputs,
            );

            evaluate_system_data_core(state, stig_id, &hostname, &system_data)?
        }
        ScanProtocol::Winrm | ScanProtocol::WinrmHttps => {
            let (username, password) = match credential.credential {
                CredentialType::Password { username, password } => (username, password),
                _ => return Err("winrm scheduled scans require password credentials".to_string()),
            };
            let use_https = matches!(asset.protocol, ScanProtocol::WinrmHttps);
            let winrm_config = crate::winrm::WinrmConfig {
                host: asset.address.clone(),
                port: asset.port.unwrap_or(if use_https { 5986 } else { 5985 }),
                username,
                password,
                use_https,
                verify_tls: true,
                timeout_secs: 60,
            };

            let raw_outputs = crate::winrm::collect_windows_data(&winrm_config)
                .await
                .map_err(|e| format!("WinRM collection failed: {}", e))?;
            let hostname = raw_outputs
                .get("hostname")
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| asset.address.clone());
            let system_data = automatestig_core::remote::assemble_system_data(
                automatestig_core::checks::CheckPlatform::Windows,
                &hostname,
                &raw_outputs,
            );

            evaluate_system_data_core(state, stig_id, &hostname, &system_data)?
        }
        ScanProtocol::Local => return Err("local protocol not schedulable".to_string()),
    };

    {
        let db = state.db();
        let summary = checklist.summary();
        update_asset_after_eval(
            &db,
            &asset.id,
            stig_id,
            summary.compliance_pct(),
            &checklist.id.to_string(),
        );
    }

    Ok(checklist)
}

pub(crate) async fn execute_schedule(
    state: &AppState,
    schedule: &EvaluationSchedule,
) -> ScheduleRunStatus {
    let assets = {
        let db = state.db();
        load_assets(&db)
    };
    let target_assets = schedule_target_assets(schedule, &assets);

    let mut status = ScheduleRunStatus {
        completed_at: Utc::now(),
        assets_scanned: 0,
        assets_failed: 0,
        total_findings: 0,
        total_open: 0,
        avg_compliance: 0.0,
        errors: Vec::new(),
    };
    let mut compliance_sum = 0.0;
    let mut successful_checklists = Vec::new();

    if target_assets.is_empty() {
        status
            .errors
            .push("no matching assets found for this schedule".to_string());
    }

    for asset in &target_assets {
        if asset.assigned_stigs.is_empty() {
            status.assets_failed += 1;
            status
                .errors
                .push(format!("asset {} has no assigned STIGs", asset.name));
            continue;
        }

        for stig_id in &asset.assigned_stigs {
            match scan_and_evaluate_asset(state, asset, stig_id).await {
                Ok(checklist) => {
                    let summary = checklist.summary();
                    status.assets_scanned += 1;
                    status.total_findings += summary.total;
                    status.total_open += summary.open;
                    compliance_sum += summary.compliance_pct();
                    successful_checklists.push(checklist);
                }
                Err(e) => {
                    status.assets_failed += 1;
                    status.errors.push(format!(
                        "asset {} STIG {} failed: {}",
                        asset.name, stig_id, e
                    ));
                }
            }
        }
    }

    if status.assets_scanned > 0 {
        status.avg_compliance = compliance_sum / status.assets_scanned as f64;
    }

    apply_schedule_post_actions(state, schedule, &mut status, &successful_checklists).await;
    status.completed_at = Utc::now();
    status
}

async fn apply_schedule_post_actions(
    state: &AppState,
    schedule: &EvaluationSchedule,
    status: &mut ScheduleRunStatus,
    checklists: &[Checklist],
) {
    if checklists.is_empty() {
        return;
    }

    let drift_reports = if schedule.post_actions.alert_on_drift {
        collect_drift_reports(state, checklists)
    } else {
        Vec::new()
    };

    let cat_i_alert = schedule.post_actions.alert_on_cat_i
        && checklists
            .iter()
            .any(|checklist| checklist.summary().cat_i_open > 0);
    let compliance_alert = schedule
        .post_actions
        .alert_below_compliance
        .is_some_and(|threshold| status.avg_compliance < threshold);
    let drift_alert = schedule.post_actions.alert_on_drift
        && drift_reports.iter().any(|report| report.has_changes());

    if cat_i_alert || compliance_alert || drift_alert {
        let webhook_url = {
            let db = state.db();
            load_agent_webhook_url(&db)
        };

        if let Some(url) = webhook_url {
            let data = serde_json::json!({
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "status": status,
                "alerts": {
                    "cat_i": cat_i_alert,
                    "below_compliance": compliance_alert,
                    "drift": drift_alert,
                },
                "drift_reports": drift_reports,
            });
            send_webhook_notification(&url, "schedule_evaluation", &data).await;
        }
    }

    if schedule.post_actions.generate_report {
        let reports_dir = state.inner.data_dir.join("reports");
        if let Err(e) = std::fs::create_dir_all(&reports_dir) {
            status
                .errors
                .push(format!("failed to create reports directory: {}", e));
        } else {
            let date = Utc::now().format("%Y%m%d").to_string();
            for checklist in checklists {
                match ckl::write_ckl(checklist) {
                    Ok(xml) => {
                        let filename = format!(
                            "{}_{}_{}.ckl",
                            sanitize_report_component(&checklist.asset.hostname),
                            sanitize_report_component(&checklist.stig_info.stig_id),
                            date
                        );
                        let path = reports_dir.join(filename);
                        if let Err(e) = std::fs::write(&path, xml) {
                            status.errors.push(format!(
                                "failed to write report {}: {}",
                                path.display(),
                                e
                            ));
                        }
                    }
                    Err(e) => status.errors.push(format!(
                        "failed to generate CKL for {} {}: {}",
                        checklist.asset.hostname, checklist.stig_info.stig_id, e
                    )),
                }
            }
        }
    }

    if schedule.post_actions.push_to_stigman {
        if let Some(collection_id) = schedule.post_actions.stigman_collection_id.as_deref() {
            let config = {
                let db = state.db();
                load_stigman_config(&db)
            };

            for checklist in checklists {
                if let Err(e) =
                    push_checklist_to_stigman(config.clone(), checklist, collection_id, None).await
                {
                    status.errors.push(format!(
                        "failed to push {} {} to STIG-Manager: {}",
                        checklist.asset.hostname, checklist.stig_info.stig_id, e
                    ));
                }
            }
        }
    }
}

fn collect_drift_reports(
    state: &AppState,
    checklists: &[Checklist],
) -> Vec<automatestig_core::agent::DriftReport> {
    let db = state.db();
    let rows = db.list_checklists().unwrap_or_default();

    checklists
        .iter()
        .filter_map(|current| {
            rows.iter()
                .find(|row| {
                    row.asset_hostname == current.asset.hostname
                        && row.stig_id == current.stig_info.stig_id
                        && row.id != current.id.to_string()
                })
                .and_then(|row| db.load_checklist(&row.id).ok())
                .map(|previous| automatestig_core::agent::detect_drift(&previous, current))
        })
        .collect()
}

fn sanitize_report_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

async fn list_schedules(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    api_ok(load_schedules(&db))
}

async fn create_schedule(
    State(state): State<AppState>,
    Json(schedule): Json<EvaluationSchedule>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut config = load_schedules(&db);
    config.schedules.push(schedule.clone());
    refresh_scheduler_enabled(&mut config);
    save_schedules(&db, &config);
    api_ok(schedule)
}

async fn update_schedule(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(updated): Json<EvaluationSchedule>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut config = load_schedules(&db);
    if let Some(s) = config.schedules.iter_mut().find(|s| s.id == id) {
        *s = updated.clone();
        refresh_scheduler_enabled(&mut config);
        save_schedules(&db, &config);
        api_ok(updated)
    } else {
        api_error("Schedule not found")
    }
}

async fn delete_schedule(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut config = load_schedules(&db);
    let len = config.schedules.len();
    config.schedules.retain(|s| s.id != id);
    refresh_scheduler_enabled(&mut config);
    save_schedules(&db, &config);
    api_ok(config.schedules.len() < len)
}

async fn run_schedule_now(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let schedule = {
        let db = state.db();
        let config = load_schedules(&db);
        match config.schedules.iter().find(|s| s.id == id) {
            Some(s) => s.clone(),
            None => return api_error("Schedule not found"),
        }
    };

    let status = execute_schedule(&state, &schedule).await;

    {
        let db = state.db();
        let mut config = load_schedules(&db);
        if let Some(schedule) = config.schedules.iter_mut().find(|s| s.id == id) {
            schedule.mark_executed(status.clone());
            refresh_scheduler_enabled(&mut config);
            save_schedules(&db, &config);
        } else {
            return api_error("Schedule not found");
        }
    }

    api_ok(status)
}

// ---------------------------------------------------------------------------
// Bulk Asset Update
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BulkUpdateRequest {
    asset_ids: Vec<String>,
    credential_id: Option<String>,
    enabled: Option<bool>,
    add_tag: Option<String>,
    remove_tag: Option<String>,
}

async fn bulk_update_assets(
    State(state): State<AppState>,
    Json(req): Json<BulkUpdateRequest>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut assets = load_assets(&db);
    let mut count = 0;

    for asset in assets.iter_mut() {
        if req.asset_ids.contains(&asset.id) {
            if let Some(ref cid) = req.credential_id {
                asset.credential_id = Some(cid.clone());
            }
            if let Some(enabled) = req.enabled {
                asset.enabled = enabled;
            }
            if let Some(ref tag) = req.add_tag {
                if !asset.tags.contains(tag) {
                    asset.tags.push(tag.clone());
                }
            }
            if let Some(ref tag) = req.remove_tag {
                asset.tags.retain(|t| t != tag);
            }
            count += 1;
        }
    }

    save_assets(&db, &assets);
    api_ok(serde_json::json!({ "updated": count }))
}

// ---------------------------------------------------------------------------
// Answer File Management
// ---------------------------------------------------------------------------

async fn list_answer_files(State(state): State<AppState>) -> Json<serde_json::Value> {
    let lib_path = &state.inner.library_path;
    let templates_dir = lib_path.join("answer_templates");
    let mut files = Vec::new();

    if templates_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&templates_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "json" || ext == "yaml" || ext == "yml" {
                    if let Ok(af) = automatestig_core::answer::AnswerFile::load(&path) {
                        files.push(serde_json::json!({
                            "name": af.name,
                            "stig_id": af.stig_id,
                            "version": af.version,
                            "entries": af.entries.len(),
                            "path": path.display().to_string(),
                        }));
                    }
                }
            }
        }
    }

    api_ok(files)
}

async fn save_answer_file(
    State(state): State<AppState>,
    Json(af): Json<automatestig_core::answer::AnswerFile>,
) -> Json<serde_json::Value> {
    let lib_path = &state.inner.library_path;
    let templates_dir = lib_path.join("answer_templates");
    let _ = std::fs::create_dir_all(&templates_dir);

    let filename_base = match automatestig_core::path_safety::safe_filename(&af.name) {
        Ok(name) => name.to_lowercase(),
        Err(e) => return api_error(&format!("Unsafe answer file name: {}", e)),
    };
    let filename = format!("{}.json", filename_base);
    let path = match automatestig_core::path_safety::safe_join_under(&templates_dir, &filename) {
        Ok(path) => path,
        Err(e) => return api_error(&format!("Unsafe answer file path: {}", e)),
    };

    match af.save_json(&path) {
        Ok(()) => {
            let issues = af.validate();
            api_ok(serde_json::json!({
                "saved": true,
                "path": path.display().to_string(),
                "entries": af.entries.len(),
                "validation_issues": issues,
            }))
        }
        Err(e) => api_error(&format!("Failed to save: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Webhook Notifications
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WebhookTestRequest {
    url: String,
    message: Option<String>,
}

async fn test_webhook(Json(req): Json<WebhookTestRequest>) -> Json<serde_json::Value> {
    if let Err(e) = validate_webhook_url(&req.url) {
        return api_error(&e);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e));

    let client = match client {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    let payload = serde_json::json!({
        "source": "AutomateSTIG",
        "event": "test",
        "message": req.message.unwrap_or_else(|| "Test notification from AutomateSTIG".to_string()),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    match client.post(&req.url).json(&payload).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            api_ok(serde_json::json!({
                "sent": true,
                "status_code": status,
                "success": status < 400,
            }))
        }
        Err(e) => api_error(&format!("Webhook failed: {}", e)),
    }
}

/// Send a webhook notification (used internally by the scheduler).
pub async fn send_webhook_notification(url: &str, event: &str, data: &serde_json::Value) {
    if validate_webhook_url(url).is_err() {
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let payload = serde_json::json!({
        "source": "AutomateSTIG",
        "event": event,
        "data": data,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let _ = client.post(url).json(&payload).send().await;
}

fn validate_webhook_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("Invalid webhook URL: {}", e))?;
    if parsed.scheme() != "https" {
        return Err("Webhook URL must use HTTPS".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Webhook URL must not include embedded credentials".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "Webhook URL must include a host".to_string())?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err("Webhook URL must not target localhost".to_string());
    }
    if let Ok(ip) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
    {
        let allow_private = std::env::var("AUTOMATESTIG_ALLOW_PRIVATE_WEBHOOKS")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if !allow_private && !is_public_ip(ip) {
            return Err(
                "Webhook URL resolves to a non-public address; set AUTOMATESTIG_ALLOW_PRIVATE_WEBHOOKS only for trusted lab deployments"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.octets()[0] == 0)
        }
        std::net::IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
    }
}

// ---------------------------------------------------------------------------
// Remote Scanning
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SshScanRequest {
    host: String,
    port: Option<u16>,
    username: String,
    auth: crate::ssh::SshAuth,
    stig_id: String,
}

async fn scan_ssh(
    State(state): State<AppState>,
    Json(req): Json<SshScanRequest>,
) -> Json<serde_json::Value> {
    let ssh_config = crate::ssh::SshConfig {
        host: req.host.clone(),
        port: req.port.unwrap_or(22),
        username: req.username,
        auth: req.auth,
        timeout_secs: 30,
    };

    // Collect data via SSH.
    let raw_outputs = match crate::ssh::collect_linux_data(&ssh_config).await {
        Ok(data) => data,
        Err(e) => return api_error(&format!("SSH collection failed: {}", e)),
    };

    let hostname = raw_outputs
        .get("hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|| req.host.clone());

    // Assemble into SystemData.
    let system_data = automatestig_core::remote::assemble_system_data(
        automatestig_core::checks::CheckPlatform::Linux,
        &hostname,
        &raw_outputs,
    );

    // Load check pack and evaluate.
    evaluate_with_system_data(&state, &req.stig_id, &hostname, &system_data)
}

#[derive(Deserialize)]
struct WinrmScanRequest {
    host: String,
    port: Option<u16>,
    username: String,
    password: String,
    use_https: Option<bool>,
    stig_id: String,
}

async fn scan_winrm(
    State(state): State<AppState>,
    Json(req): Json<WinrmScanRequest>,
) -> Json<serde_json::Value> {
    let winrm_config = crate::winrm::WinrmConfig {
        host: req.host.clone(),
        port: req.port.unwrap_or(5986),
        username: req.username,
        password: req.password,
        use_https: req.use_https.unwrap_or(true),
        verify_tls: true,
        timeout_secs: 60,
    };

    let raw_outputs = match crate::winrm::collect_windows_data(&winrm_config).await {
        Ok(data) => data,
        Err(e) => return api_error(&format!("WinRM collection failed: {}", e)),
    };

    let hostname = raw_outputs
        .get("hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|| req.host.clone());

    let system_data = automatestig_core::remote::assemble_system_data(
        automatestig_core::checks::CheckPlatform::Windows,
        &hostname,
        &raw_outputs,
    );

    evaluate_with_system_data(&state, &req.stig_id, &hostname, &system_data)
}

fn evaluate_system_data_core(
    state: &AppState,
    stig_id: &str,
    hostname: &str,
    system_data: &automatestig_core::checks::SystemData,
) -> Result<Checklist, String> {
    // Load benchmark.
    let library = state.library().map_err(|e| e.to_string())?;

    let benchmark = library
        .load_benchmark(stig_id)
        .map_err(|e| format!("Benchmark not found: {}", e))?;

    // Load check packs from all sources: plugins, hand-written packs, and auto-generated.
    let mut plugin_registry = automatestig_core::plugins::PluginRegistry::new();
    let plugins_dir = state.inner.data_dir.join("plugins");
    let _ = plugin_registry.load_from_directory(&plugins_dir);

    let content_dir = std::path::Path::new("content/check_packs");
    let _ = plugin_registry.load_from_directory(content_dir);

    // Load auto-generated check packs from the converter.
    let auto_dir = state.inner.library_path.join("auto_check_packs");
    let _ = plugin_registry.load_from_directory(&auto_dir);

    // Execute checks.
    let check_results: Vec<automatestig_core::checks::CheckResult> = plugin_registry
        .checks_for_stig(stig_id)
        .iter()
        .map(|check_def| automatestig_core::checks::executor::execute_check(check_def, system_data))
        .collect();

    // Create checklist from benchmark + check results.
    let asset = Asset::new(hostname);
    let engine = automatestig_core::engine::EvaluationEngine::with_defaults();
    let mut checklist = engine
        .evaluate(&benchmark, &asset, None, &[])
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    // Apply check results to findings.
    for cr in &check_results {
        if let Some(finding) = checklist.find_by_vuln_id_mut(&cr.vuln_id) {
            finding.status = cr.to_finding_status();
            finding.source = automatestig_core::models::finding::FindingSource::Automated;
            finding.finding_details = cr.evidence.clone();
            finding.evaluated_at = chrono::Utc::now();
            finding.evaluated_by = format!("AutomateSTIG {}", env!("CARGO_PKG_VERSION"));
        }
    }

    checklist.touch();

    let db = state.db();
    db.save_checklist(&checklist)
        .map_err(|e| format!("Failed to save checklist: {}", e))?;
    db.log_evaluation(&checklist, "remote-scan", Some(hostname))
        .map_err(|e| format!("Failed to log evaluation: {}", e))?;

    Ok(checklist)
}

/// Evaluate collected SystemData against check packs and STIG benchmark.
fn evaluate_with_system_data(
    state: &AppState,
    stig_id: &str,
    hostname: &str,
    system_data: &automatestig_core::checks::SystemData,
) -> Json<serde_json::Value> {
    let checklist = match evaluate_system_data_core(state, stig_id, hostname, system_data) {
        Ok(checklist) => checklist,
        Err(e) => return api_error(&e),
    };

    let s = checklist.summary();
    let automated_findings: Vec<_> = checklist
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.source,
                automatestig_core::models::finding::FindingSource::Automated
            )
        })
        .collect();
    api_ok(serde_json::json!({
        "id": checklist.id.to_string(),
        "hostname": hostname,
        "stig_id": stig_id,
        "total": s.total,
        "open": s.open,
        "not_a_finding": s.not_a_finding,
        "not_reviewed": s.not_reviewed,
        "compliance_pct": s.compliance_pct(),
        "checks_executed": automated_findings.len(),
        "checks_passed": automated_findings
            .iter()
            .filter(|finding| finding.status != FindingStatus::Open)
            .count(),
    }))
}

// ---------------------------------------------------------------------------
// Bulk STIG Assignment
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BulkAssignRequest {
    asset_ids: Vec<String>,
    stig_id: String,
}

async fn bulk_assign_stig(
    State(state): State<AppState>,
    Json(req): Json<BulkAssignRequest>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut assets = load_assets(&db);
    let mut count = 0;
    for asset in assets.iter_mut() {
        if req.asset_ids.contains(&asset.id) && !asset.assigned_stigs.contains(&req.stig_id) {
            asset.assigned_stigs.push(req.stig_id.clone());
            count += 1;
        }
    }
    save_assets(&db, &assets);
    api_ok(serde_json::json!({ "assigned": count, "stig_id": req.stig_id }))
}

// ---------------------------------------------------------------------------
// Quick Re-evaluate
// ---------------------------------------------------------------------------

async fn re_evaluate(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let (hostname, stig_id) = {
        let db = state.db();
        match db.load_checklist(&id) {
            Ok(cl) => (cl.asset.hostname.clone(), cl.stig_info.stig_id.clone()),
            Err(e) => return api_error(&format!("Checklist not found: {}", e)),
        }
    };

    let library = match state.library() {
        Ok(l) => l,
        Err(e) => return api_error(&e.to_string()),
    };

    let benchmark = match library.load_benchmark(&stig_id) {
        Ok(b) => b,
        Err(e) => return api_error(&format!("Benchmark not found: {}", e)),
    };

    let asset = Asset::new(&hostname);
    let engine = automatestig_core::engine::EvaluationEngine::with_defaults();

    // Load previous checklist for merging manual findings.
    let previous = {
        let db = state.db();
        db.load_checklist(&id).ok()
    };

    match engine.evaluate(&benchmark, &asset, None, &[]) {
        Ok(mut checklist) => {
            // Merge manual findings from the previous checklist.
            if let Some(ref prev) = previous {
                let _ = engine.merge_previous(&mut checklist, prev);
            }

            let s = checklist.summary();
            let new_id = checklist.id.to_string();
            let db = state.db();
            let _ = db.save_checklist(&checklist);
            let _ = db.log_evaluation(&checklist, "re-evaluate", Some(&hostname));

            api_ok(serde_json::json!({
                "id": new_id,
                "hostname": hostname,
                "stig_id": stig_id,
                "total": s.total,
                "open": s.open,
                "compliance_pct": s.compliance_pct(),
            }))
        }
        Err(e) => api_error(&format!("Re-evaluation failed: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// POA&M Tracking
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PoamUpdate {
    poam_milestone: Option<String>,
    poam_date: Option<String>,
}

async fn update_poam(
    State(state): State<AppState>,
    axum::extract::Path((id, vuln_id)): axum::extract::Path<(String, String)>,
    Json(req): Json<PoamUpdate>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut checklist = match db.load_checklist(&id) {
        Ok(cl) => cl,
        Err(e) => return api_error(&format!("Checklist not found: {}", e)),
    };

    // Store POA&M data in the finding's comments field (prefixed for parsing).
    if let Some(finding) = checklist.find_by_vuln_id_mut(&vuln_id) {
        let poam_text = match (&req.poam_milestone, &req.poam_date) {
            (Some(milestone), Some(date)) => format!("[POA&M: {} by {}]", milestone, date),
            (Some(milestone), None) => format!("[POA&M: {}]", milestone),
            _ => String::new(),
        };

        // Append POA&M to comments, replacing any existing POA&M tag.
        let existing = finding.comments.clone();
        let cleaned = existing
            .lines()
            .filter(|l| !l.starts_with("[POA&M:"))
            .collect::<Vec<_>>()
            .join("\n");
        finding.comments = if poam_text.is_empty() {
            cleaned
        } else {
            format!("{}\n{}", poam_text, cleaned).trim().to_string()
        };
    }

    checklist.touch();
    let _ = db.save_checklist(&checklist);

    api_ok(serde_json::json!({ "vuln_id": vuln_id, "updated": true }))
}

// ---------------------------------------------------------------------------
// Checklist Comparison
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CompareRequest {
    checklist_a: String,
    checklist_b: String,
}

async fn compare_checklists(
    State(state): State<AppState>,
    Json(req): Json<CompareRequest>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let cl_a = match db.load_checklist(&req.checklist_a) {
        Ok(c) => c,
        Err(e) => return api_error(&format!("Checklist A not found: {}", e)),
    };
    let cl_b = match db.load_checklist(&req.checklist_b) {
        Ok(c) => c,
        Err(e) => return api_error(&format!("Checklist B not found: {}", e)),
    };

    let sum_a = cl_a.summary();
    let sum_b = cl_b.summary();

    // Find differences.
    let mut differences = Vec::new();
    for fa in &cl_a.findings {
        if let Some(fb) = cl_b.findings.iter().find(|f| f.vuln_id == fa.vuln_id) {
            if fa.status != fb.status {
                differences.push(serde_json::json!({
                    "vuln_id": fa.vuln_id,
                    "title": fa.rule_title,
                    "severity": fa.severity.as_cat_str(),
                    "status_a": fa.status.to_string(),
                    "status_b": fb.status.to_string(),
                }));
            }
        }
    }

    api_ok(serde_json::json!({
        "checklist_a": { "id": req.checklist_a, "hostname": cl_a.asset.hostname, "stig": cl_a.stig_info.stig_id, "compliance": sum_a.compliance_pct(), "open": sum_a.open },
        "checklist_b": { "id": req.checklist_b, "hostname": cl_b.asset.hostname, "stig": cl_b.stig_info.stig_id, "compliance": sum_b.compliance_pct(), "open": sum_b.open },
        "differences": differences,
        "total_differences": differences.len(),
    }))
}

// ---------------------------------------------------------------------------
// Compliance Trends
// ---------------------------------------------------------------------------

async fn compliance_trends(
    State(state): State<AppState>,
    axum::extract::Path(hostname): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let all = db.list_checklists().unwrap_or_default();

    // Find all checklists for this hostname, sorted by time.
    let mut points: Vec<serde_json::Value> = Vec::new();
    for row in &all {
        if row.asset_hostname == hostname {
            if let Ok(cl) = db.load_checklist(&row.id) {
                let s = cl.summary();
                points.push(serde_json::json!({
                    "date": row.modified_at,
                    "stig_id": row.stig_id,
                    "compliance_pct": s.compliance_pct(),
                    "open": s.open,
                    "total": s.total,
                }));
            }
        }
    }

    points.sort_by(|a, b| a["date"].as_str().cmp(&b["date"].as_str()));

    api_ok(serde_json::json!({
        "hostname": hostname,
        "data_points": points,
    }))
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

async fn export_ckl(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let db = state.db();
    match db.load_checklist(&id) {
        Ok(cl) => {
            let filename = sanitize_filename(&format!(
                "{}_{}.ckl",
                cl.asset.hostname, cl.stig_info.stig_id
            ));
            match ckl::write_ckl(&cl) {
                Ok(xml) => (
                    [
                        (
                            axum::http::header::CONTENT_TYPE,
                            "application/xml".to_string(),
                        ),
                        (
                            axum::http::header::CONTENT_DISPOSITION,
                            format!("attachment; filename=\"{}\"", filename),
                        ),
                    ],
                    xml,
                )
                    .into_response(),
                Err(e) => (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Export failed: {}", e),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            axum::http::StatusCode::NOT_FOUND,
            format!("Checklist not found: {}", e),
        )
            .into_response(),
    }
}

async fn export_cklb(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let db = state.db();
    match db.load_checklist(&id) {
        Ok(cl) => {
            let filename = sanitize_filename(&format!(
                "{}_{}.cklb",
                cl.asset.hostname, cl.stig_info.stig_id
            ));
            match cklb::write_cklb(&cl) {
                Ok(json) => (
                    [
                        (
                            axum::http::header::CONTENT_TYPE,
                            "application/json".to_string(),
                        ),
                        (
                            axum::http::header::CONTENT_DISPOSITION,
                            format!("attachment; filename=\"{}\"", filename),
                        ),
                    ],
                    json,
                )
                    .into_response(),
                Err(e) => (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Export failed: {}", e),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            axum::http::StatusCode::NOT_FOUND,
            format!("Checklist not found: {}", e),
        )
            .into_response(),
    }
}

async fn export_emass(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let db = state.db();
    match db.load_checklist(&id) {
        Ok(cl) => {
            let filename = sanitize_filename(&format!(
                "{}_{}_emass.csv",
                cl.asset.hostname, cl.stig_info.stig_id
            ));
            let body = automatestig_integrations::emass::export_emass_csv(
                &automatestig_integrations::emass::export_to_emass(&cl),
            );
            (
                [
                    (axum::http::header::CONTENT_TYPE, "text/csv".to_string()),
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", filename),
                    ),
                ],
                body,
            )
                .into_response()
        }
        Err(e) => (
            axum::http::StatusCode::NOT_FOUND,
            format!("Checklist not found: {}", e),
        )
            .into_response(),
    }
}

async fn export_all_zip(State(state): State<AppState>) -> impl IntoResponse {
    let db = state.db();
    let rows = db.list_checklists().unwrap_or_default();

    if rows.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "No checklists to export",
        )
            .into_response();
    }

    let mut zip_buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut zip_buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for row in &rows {
            if let Ok(cl) = db.load_checklist(&row.id) {
                let filename = sanitize_filename(&format!(
                    "{}_{}.ckl",
                    cl.asset.hostname, cl.stig_info.stig_id
                ));
                if let Ok(xml) = ckl::write_ckl(&cl) {
                    let _ = zip.start_file(&filename, options);
                    let _ = std::io::Write::write_all(&mut zip, xml.as_bytes());
                }
            }
        }
        let _ = zip.finish();
    }

    let data = zip_buffer.into_inner();
    let filename = format!(
        "automatestig-export-{}.zip",
        chrono::Utc::now().format("%Y%m%d-%H%M")
    );

    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/zip".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        data,
    )
        .into_response()
}

use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::inventory::scheduler::ScheduleFrequency;

    #[test]
    fn webhook_validation_rejects_ssrf_targets_by_default() {
        for url in [
            "http://example.com/hook",
            "https://localhost/hook",
            "https://127.0.0.1/hook",
            "https://10.0.0.1/hook",
            "https://[::1]/hook",
            "https://user:pass@example.com/hook",
        ] {
            assert!(
                validate_webhook_url(url).is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn webhook_validation_allows_https_public_hosts() {
        assert!(validate_webhook_url("https://example.com/hook").is_ok());
        assert!(validate_webhook_url("https://8.8.8.8/hook").is_ok());
    }

    #[test]
    fn schedule_is_due_for_enabled_past_next_run() {
        let now = Utc::now();
        let mut schedule = EvaluationSchedule::new("due", ScheduleFrequency::Daily);
        schedule.next_run = Some(now - chrono::Duration::minutes(1));

        assert!(schedule_is_due(&schedule, now));
    }

    #[test]
    fn schedule_is_not_due_when_disabled() {
        let now = Utc::now();
        let mut schedule = EvaluationSchedule::new("disabled", ScheduleFrequency::Daily);
        schedule.enabled = false;
        schedule.next_run = Some(now - chrono::Duration::minutes(1));

        assert!(!schedule_is_due(&schedule, now));
    }

    #[test]
    fn schedule_is_not_due_for_future_next_run() {
        let now = Utc::now();
        let mut schedule = EvaluationSchedule::new("future", ScheduleFrequency::Daily);
        schedule.next_run = Some(now + chrono::Duration::minutes(1));

        assert!(!schedule_is_due(&schedule, now));
    }
}
