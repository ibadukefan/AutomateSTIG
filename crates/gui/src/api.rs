//! REST API endpoints for the GUI.

use std::io::Read;
use std::path::Path;

use axum::extract::{Multipart, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use automatestig_core::engine::EvaluationEngine;
use automatestig_core::models::asset::Asset;
use automatestig_core::models::stig::Severity;
use automatestig_parsers::{ckl, cklb, xccdf};

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
                .map(|b| BenchmarkInfo {
                    id: b.id.clone(),
                    title: b.title.clone(),
                    version: b.version.clone(),
                    platform: b.platform_family.clone(),
                    rule_count: b.rule_count,
                    cat_i: 0,
                    cat_ii: 0,
                    cat_iii: 0,
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

    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config) {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    // If no asset_id provided, try to create the asset.
    let asset_id = match req.asset_id {
        Some(id) => id,
        None => {
            match client
                .create_asset(
                    &req.collection_id,
                    &checklist.asset.hostname,
                    checklist.asset.fqdn.as_deref(),
                    checklist.asset.ip_address.as_deref(),
                )
                .await
            {
                Ok(asset) => asset.asset_id,
                Err(e) => return api_error(&format!("Failed to create asset: {}", e)),
            }
        }
    };

    // Convert findings to STIG-Manager reviews.
    let reviews = crate::stigman::StigManagerClient::checklist_to_reviews(&checklist);
    let review_count = reviews.len();

    // Push to STIG-Manager.
    match client
        .push_reviews(
            &req.collection_id,
            &asset_id,
            &checklist.stig_info.stig_id,
            reviews,
        )
        .await
    {
        Ok(result) => api_ok(serde_json::json!({
            "pushed": review_count,
            "asset_id": asset_id,
            "collection_id": req.collection_id,
            "result": result,
        })),
        Err(e) => api_error(&format!("Push failed: {}", e)),
    }
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
    let config: automatestig_core::agent::AgentConfig = db
        .get_config("agent_config")
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();
    api_ok(config)
}

async fn set_agent_config(
    State(state): State<AppState>,
    Json(config): Json<automatestig_core::agent::AgentConfig>,
) -> Json<serde_json::Value> {
    let db = state.db();
    match serde_json::to_string(&config) {
        Ok(json) => {
            if let Err(e) = db.set_config("agent_config", &json) {
                return api_error(&format!("Failed to save: {}", e));
            }
            api_ok("Agent configuration saved")
        }
        Err(e) => api_error(&format!("Serialization error: {}", e)),
    }
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

fn load_schedules(
    db: &automatestig_storage::Database,
) -> automatestig_core::inventory::scheduler::SchedulerConfig {
    db.get_config("scheduler_config")
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn save_schedules(
    db: &automatestig_storage::Database,
    config: &automatestig_core::inventory::scheduler::SchedulerConfig,
) {
    if let Ok(json) = serde_json::to_string(config) {
        let _ = db.set_config("scheduler_config", &json);
    }
}

async fn list_schedules(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    api_ok(load_schedules(&db))
}

async fn create_schedule(
    State(state): State<AppState>,
    Json(schedule): Json<automatestig_core::inventory::scheduler::EvaluationSchedule>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut config = load_schedules(&db);
    config.schedules.push(schedule.clone());
    save_schedules(&db, &config);
    api_ok(schedule)
}

async fn update_schedule(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(updated): Json<automatestig_core::inventory::scheduler::EvaluationSchedule>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut config = load_schedules(&db);
    if let Some(s) = config.schedules.iter_mut().find(|s| s.id == id) {
        *s = updated.clone();
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
    save_schedules(&db, &config);
    api_ok(config.schedules.len() < len)
}

async fn run_schedule_now(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let config = load_schedules(&db);
    let schedule = match config.schedules.iter().find(|s| s.id == id) {
        Some(s) => s.clone(),
        None => return api_error("Schedule not found"),
    };
    drop(db);

    let assets = {
        let db = state.db();
        load_assets(&db)
    };

    // Resolve which assets to scan.
    let target_assets: Vec<_> = assets
        .iter()
        .filter(|a| {
            schedule.asset_ids.contains(&a.id)
                || schedule.asset_tags.iter().any(|t| a.tags.contains(t))
        })
        .collect();

    if target_assets.is_empty() {
        return api_error("No matching assets found for this schedule");
    }

    api_ok(serde_json::json!({
        "schedule_id": schedule.id,
        "schedule_name": schedule.name,
        "assets_matched": target_assets.len(),
        "message": "Schedule triggered. Evaluations will run in background.",
    }))
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
#[allow(dead_code)] // Called by scheduler when implemented.
pub async fn send_webhook_notification(url: &str, event: &str, data: &serde_json::Value) {
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
        port: req.port.unwrap_or(5985),
        username: req.username,
        password: req.password,
        use_https: req.use_https.unwrap_or(false),
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

/// Evaluate collected SystemData against check packs and STIG benchmark.
fn evaluate_with_system_data(
    state: &AppState,
    stig_id: &str,
    hostname: &str,
    system_data: &automatestig_core::checks::SystemData,
) -> Json<serde_json::Value> {
    // Load benchmark.
    let library = match state.library() {
        Ok(l) => l,
        Err(e) => return api_error(&e.to_string()),
    };

    let benchmark = match library.load_benchmark(stig_id) {
        Ok(b) => b,
        Err(e) => return api_error(&format!("Benchmark not found: {}", e)),
    };

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
    let mut checklist = match engine.evaluate(&benchmark, &asset, None, &[]) {
        Ok(cl) => cl,
        Err(e) => return api_error(&format!("Evaluation failed: {}", e)),
    };

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

    let s = checklist.summary();
    let db = state.db();
    let _ = db.save_checklist(&checklist);
    let _ = db.log_evaluation(&checklist, "remote-scan", Some(hostname));

    api_ok(serde_json::json!({
        "id": checklist.id.to_string(),
        "hostname": hostname,
        "stig_id": stig_id,
        "total": s.total,
        "open": s.open,
        "not_a_finding": s.not_a_finding,
        "not_reviewed": s.not_reviewed,
        "compliance_pct": s.compliance_pct(),
        "checks_executed": check_results.len(),
        "checks_passed": check_results.iter().filter(|r| r.passed).count(),
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
