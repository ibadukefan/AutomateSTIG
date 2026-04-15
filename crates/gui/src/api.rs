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
        .route("/stigman/collections/{cid}/assets", get(stigman_list_assets))
        .route("/stigman/push/{checklist_id}", post(stigman_push_checklist))
        // Export
        .route("/export/ckl/{id}", get(export_ckl))
        .route("/export/cklb/{id}", get(export_cklb))
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

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
    let checklist_count = state
        .db()
        .list_checklists()
        .map(|c| c.len())
        .unwrap_or(0);

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
    match state.library().and_then(|l| {
        l.load_benchmark(&id)
            .map_err(|e| anyhow::anyhow!("{}", e))
    }) {
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
                                                details.push(format!("Imported: {}", info));
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
                            details.push(format!("Imported: {}", info));
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
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &data).unwrap();

        let mut library = match state.library() {
            Ok(l) => l,
            Err(e) => return api_error(&e.to_string()),
        };

        match automatestig_stigpack::importer::import_pack(tmp.path(), &mut library) {
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
                    severity: f.severity_override.unwrap_or(f.severity).as_cat_str().to_string(),
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
async fn disa_fetch_all(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    match crate::disa::fetch_all_content(&state).await {
        Ok(result) => api_ok(result),
        Err(e) => api_error(&e),
    }
}

/// Check for updates without downloading.
async fn disa_check_updates(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    match crate::disa::check_for_updates(&state).await {
        Ok(result) => api_ok(result),
        Err(e) => api_error(&e),
    }
}

/// Generate an offline update package (.stigpack) from the current library
/// for transfer to air-gapped systems.
async fn generate_offline_pack(
    State(state): State<AppState>,
) -> impl IntoResponse {
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
        &format!("automatestig-offline-{}", chrono::Utc::now().format("%Y%m%d")),
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

    let tmp = tempfile::NamedTempFile::new().unwrap();
    if let Err(e) = builder.build(tmp.path()) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to build pack: {}", e),
        )
            .into_response();
    }

    let data = std::fs::read(tmp.path()).unwrap();
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
    Json(body): Json<crate::stigman::StigManagerConfig>,
) -> Json<serde_json::Value> {
    let db = state.db();
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

/// Load STIG-Manager config from the database.
fn load_stigman_config(db: &automatestig_storage::Database) -> crate::stigman::StigManagerConfig {
    db.get_config("stigman_config")
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
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
            let filename = format!("{}_{}.ckl", cl.asset.hostname, cl.stig_info.stig_id);
            match ckl::write_ckl(&cl) {
                Ok(xml) => (
                    [
                        (axum::http::header::CONTENT_TYPE, "application/xml".to_string()),
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
            let filename = format!("{}_{}.cklb", cl.asset.hostname, cl.stig_info.stig_id);
            match cklb::write_cklb(&cl) {
                Ok(json) => (
                    [
                        (axum::http::header::CONTENT_TYPE, "application/json".to_string()),
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

use axum::response::IntoResponse;
