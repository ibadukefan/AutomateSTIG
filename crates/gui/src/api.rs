//! REST API endpoints for the GUI.

use std::collections::HashSet;
use std::path::Path;

use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use automatestig_core::library::{BenchmarkImport, GeneratedCheckPackIntent};
use automatestig_core::models::asset::Asset;
use automatestig_core::models::checklist::{
    Checklist, EvaluationOrigin, EvaluationProvenance, OrganizationPolicyProvenance,
};
use automatestig_core::models::finding::{FindingSource, FindingStatus};
use automatestig_core::models::stig::Severity;
use automatestig_parsers::{ckl, cklb, disa};

use crate::state::AppState;

/// Build the API router.
pub fn routes() -> Router<AppState> {
    Router::new()
        // Status & info
        .route("/status", get(get_status))
        // Library
        .route("/library/benchmarks", get(list_benchmarks))
        .route("/library/benchmarks/{id}", get(get_benchmark))
        .route(
            "/library/import-disa",
            post(import_disa).layer(axum::extract::DefaultBodyLimit::max(
                (disa::MAX_DISA_ARCHIVE_BYTES + 1024 * 1024) as usize,
            )),
        )
        .route(
            "/library/import-stigpack",
            post(import_stigpack).layer(axum::extract::DefaultBodyLimit::max(257 * 1024 * 1024)),
        )
        // Checklists
        .route("/checklists", get(list_checklists))
        .route("/checklists/{id}", get(get_checklist))
        .route("/checklists/{id}", axum::routing::delete(delete_checklist))
        .route("/checklists/import", post(import_checklist))
        // DISA content fetching
        .route("/disa/available", get(disa_list_available))
        .route("/disa/fetch", post(disa_fetch))
        .route("/disa/fetch-all", post(disa_fetch_all))
        .route("/disa/check-updates", get(disa_check_updates))
        // Explicit external signing key required; no GUI key generation.
        .route("/offline-pack", get(generate_offline_pack))
        .route("/offline-pack/trust-key", get(download_offline_trust_key))
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
        // Finding editing
        .route(
            "/checklists/{id}/findings/{vuln_id}",
            axum::routing::patch(update_finding),
        )
        // Uploaded device evidence or running configuration
        .route("/evaluate/with-evidence", post(evaluate_with_evidence))
        // Remote scanning
        .route("/scan/ssh", post(scan_ssh))
        // Asset inventory
        .route("/assets", get(list_assets_inv))
        .route("/assets", post(create_asset_inv))
        .route("/assets/{id}", get(get_asset_inv))
        .route("/assets/{id}", axum::routing::put(update_asset_inv))
        .route("/assets/{id}", axum::routing::delete(delete_asset_inv))
        // Bulk operations
        .route("/assets/bulk-assign-stig", post(bulk_assign_stig))
        .route("/assets/bulk-update", post(bulk_update_assets))
        // Answer file management
        .route("/answer-files", get(list_answer_files))
        .route("/answer-files", post(save_answer_file))
        // Immutable checklist audit trail
        .route("/audit-log", get(list_audit_log))
        // Export
        .route("/export/ckl/{id}", get(export_ckl))
        .route("/export/cklb/{id}", get(export_cklb))
        .route("/export/all-zip", get(export_all_zip))
}

fn trusted_content_keys_dir() -> std::path::PathBuf {
    std::env::var("AUTOMATESTIG_TRUSTED_KEYS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join(".automatestig")
                .join("trusted_keys")
        })
}

fn organization_policy_keys_dir(state: &AppState) -> std::path::PathBuf {
    std::env::var("AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| state.inner.data_dir.join("organization_policy_keys"))
}

fn verify_organization_policy(
    state: &AppState,
    raw: &[u8],
    signature: &[u8],
    stig_id: &str,
    stig_release: &str,
    hostname: &str,
) -> Result<automatestig_core::organization_policy::VerifiedOrganizationPolicy, String> {
    verify_organization_policy_with_trust_dir(
        &organization_policy_keys_dir(state),
        raw,
        signature,
        stig_id,
        stig_release,
        hostname,
    )
}

fn verify_organization_policy_with_trust_dir(
    trust_dir: &Path,
    raw: &[u8],
    signature: &[u8],
    stig_id: &str,
    stig_release: &str,
    hostname: &str,
) -> Result<automatestig_core::organization_policy::VerifiedOrganizationPolicy, String> {
    const MAX_POLICY_BYTES: usize = 64 * 1024;
    if raw.is_empty() || raw.len() > MAX_POLICY_BYTES {
        return Err(format!(
            "organization policy must be 1..={MAX_POLICY_BYTES} bytes"
        ));
    }
    if signature.len() != 64 {
        return Err("organization policy signature must contain exactly 64 bytes".to_string());
    }
    let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
    let loaded = trust_store
        .load_from_directory(trust_dir)
        .map_err(|error| {
            format!(
                "Failed to load organization-policy trust anchors from {}: {error}",
                trust_dir.display()
            )
        })?;
    if loaded == 0 {
        return Err(format!(
            "no organization-policy trust anchors are installed in {}",
            trust_dir.display()
        ));
    }
    let trusted_public_keys = trust_store.public_keys();
    automatestig_core::organization_policy::VerifiedOrganizationPolicy::verify_and_parse(
        raw,
        signature,
        &trusted_public_keys,
        stig_id,
        stig_release,
        hostname,
        chrono::Utc::now(),
    )
}

fn load_external_offline_signing_key(state: &AppState) -> Result<([u8; 32], [u8; 32]), String> {
    let private_path = std::env::var("AUTOMATESTIG_OFFLINE_SIGNING_KEY")
        .map(std::path::PathBuf::from)
        .map_err(|_| {
            "GUI offline-pack export is disabled. Set AUTOMATESTIG_OFFLINE_SIGNING_KEY to an existing external key only for a controlled signing host, or use the CLI build-pack command offline."
                .to_string()
        })?;
    let canonical_private = private_path.canonicalize().map_err(|error| {
        format!(
            "Failed to resolve external offline signing key {}: {error}",
            private_path.display()
        )
    })?;
    if let Ok(canonical_data_dir) = state.inner.data_dir.canonicalize() {
        if canonical_private.starts_with(&canonical_data_dir) {
            return Err(format!(
                "Offline signing key must be outside the AutomateSTIG application data directory: {}",
                state.inner.data_dir.display()
            ));
        }
    }
    let public_path = private_path.with_extension("pub");
    automatestig_stigpack::signing::load_signing_key_pair(&private_path, &public_path)
        .map_err(|error| format!("Failed to load external offline signing key pair: {error}"))
}

fn add_trusted_executables_to_offline_pack(
    mut builder: automatestig_stigpack::builder::PackBuilder,
    library: &automatestig_core::library::StigLibrary,
    trusted_public_keys: &[[u8; 32]],
) -> Result<automatestig_stigpack::builder::PackBuilder, String> {
    let custom_checks = library
        .load_trusted_executable_files("custom_checks", trusted_public_keys)
        .map_err(|error| format!("Refusing to re-sign untrusted custom checks: {error}"))?;
    for file in custom_checks {
        let path = file.relative_path.to_string_lossy().replace('\\', "/");
        builder = builder.add_file_bytes(&path, &file.bytes);
    }

    // Never re-sign legacy local auto_check_packs. Only bytes whose retained
    // signed provenance still verifies are eligible for offline re-packaging.
    let reviewed = library
        .load_trusted_executable_files("reviewed_check_packs", trusted_public_keys)
        .map_err(|error| format!("Refusing to re-sign untrusted reviewed checks: {error}"))?;
    for file in reviewed {
        let filename = file
            .relative_path
            .strip_prefix("reviewed_check_packs")
            .map_err(|_| "Reviewed check path escaped its trusted directory".to_string())?;
        let archive_path = Path::new("auto_check_packs").join(filename);
        let archive_path = archive_path.to_string_lossy().replace('\\', "/");
        builder = builder.add_file_bytes(&archive_path, &file.bytes);
    }
    Ok(builder)
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Sanitize a filename for Content-Disposition headers.
fn sanitize_filename(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "_".to_string()
    } else {
        sanitized
    }
}

fn api_ok(data: impl Serialize) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "success": true,
        "data": data,
        "error": null
    }))
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn api_error(msg: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "success": false,
        "data": null,
        "error": msg
    }))
}

fn api_response(
    status: StatusCode,
    data: Option<serde_json::Value>,
    error: Option<&str>,
) -> Response {
    (
        status,
        Json(serde_json::json!({
            "success": status.is_success(),
            "data": data,
            "error": error
        })),
    )
        .into_response()
}

fn api_response_ok(data: impl Serialize) -> Response {
    let value = match serde_json::to_value(data) {
        Ok(value) => value,
        Err(error) => {
            return api_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                Some(&format!("Failed to serialize response: {error}")),
            )
        }
    };
    api_response(StatusCode::OK, Some(value), None)
}

fn api_response_error(status: StatusCode, message: impl AsRef<str>) -> Response {
    api_response(status, None, Some(message.as_ref()))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    benchmark_count: usize,
    checklist_count: usize,
}

async fn get_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let benchmark_count = match state.library() {
        Ok(library) => library.list_benchmarks().len(),
        Err(error) => return api_error(&error.to_string()),
    };
    let checklist_count = match state.db().list_checklists() {
        Ok(checklists) => checklists.len(),
        Err(error) => return api_error(&format!("Failed to read checklist database: {error}")),
    };

    api_ok(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        benchmark_count,
        checklist_count,
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
            let benchmarks = library
                .list_benchmarks()
                .iter()
                .map(|b| {
                    let full = library.load_benchmark(&b.id)?;
                    Ok(BenchmarkInfo {
                        id: b.id.clone(),
                        title: b.title.clone(),
                        version: b.version.clone(),
                        platform: b.platform_family.clone(),
                        rule_count: b.rule_count,
                        cat_i: full.rules_by_severity(Severity::High).len(),
                        cat_ii: full.rules_by_severity(Severity::Medium).len(),
                        cat_iii: full.rules_by_severity(Severity::Low).len(),
                    })
                })
                .collect::<automatestig_core::Result<Vec<_>>>();
            match benchmarks {
                Ok(benchmarks) => api_ok(benchmarks),
                Err(error) => api_error(&format!("Failed to load benchmark index: {error}")),
            }
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

async fn stream_single_upload(
    mut multipart: Multipart,
    max_bytes: u64,
) -> Result<(String, tempfile::NamedTempFile), (StatusCode, String)> {
    let mut field = multipart
        .next_field()
        .await
        .map_err(multipart_error)?
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "No file uploaded".to_owned()))?;
    let filename = field.file_name().unwrap_or("upload").to_owned();
    let mut temporary = tempfile::NamedTempFile::new().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create upload staging file: {error}"),
        )
    })?;
    let mut received = 0u64;
    while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
        received = received.checked_add(chunk.len() as u64).ok_or_else(|| {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload size overflow".to_owned(),
            )
        })?;
        if received > max_bytes {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Upload exceeds the {max_bytes}-byte limit"),
            ));
        }
        std::io::Write::write_all(temporary.as_file_mut(), &chunk).map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to stage upload: {error}"),
            )
        })?;
    }
    drop(field);
    std::io::Write::flush(temporary.as_file_mut()).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to flush upload staging file: {error}"),
        )
    })?;

    match multipart.next_field().await {
        Ok(None) => Ok((filename, temporary)),
        Ok(Some(_)) => Err((
            StatusCode::BAD_REQUEST,
            "Exactly one uploaded file is required".to_owned(),
        )),
        Err(error) => Err(multipart_error(error)),
    }
}

fn multipart_error(error: axum::extract::multipart::MultipartError) -> (StatusCode, String) {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    let status = if lower.contains("length limit") || lower.contains("too large") {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, format!("Invalid multipart upload: {message}"))
}

enum DisaTaskError {
    Input(disa::DisaImportError),
    Library(String),
}

async fn import_disa(State(state): State<AppState>, multipart: Multipart) -> Response {
    let (filename, temporary) =
        match stream_single_upload(multipart, disa::MAX_DISA_ARCHIVE_BYTES).await {
            Ok(upload) => upload,
            Err((status, error)) => return api_response_error(status, error),
        };
    let extension = Path::new(&filename)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if extension != "zip" && extension != "xml" {
        return api_response_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected a .zip DISA archive or .xml XCCDF benchmark",
        );
    }

    let permit = match state
        .inner
        .content_import_lock
        .clone()
        .acquire_owned()
        .await
    {
        Ok(permit) => permit,
        Err(_) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Content import coordinator is unavailable",
            )
        }
    };
    let task_state = state.clone();
    let task = tokio::task::spawn_blocking(move || {
        // spawn_blocking tasks continue after their waiting request is cancelled;
        // the worker must own the permit for exactly that lifetime.
        let _permit = permit;
        let parsed = if extension == "zip" {
            disa::parse_disa_zip_path(temporary.path())
        } else {
            disa::parse_xccdf_path(temporary.path()).map(|benchmark| vec![benchmark])
        }
        .map_err(DisaTaskError::Input)?;

        let imports: Vec<_> = parsed
            .iter()
            .map(|item| BenchmarkImport::new(&item.benchmark, GeneratedCheckPackIntent::Remove))
            .collect();
        let mut library = task_state
            .library()
            .map_err(|error| DisaTaskError::Library(error.to_string()))?;
        let outcome = library
            .import_benchmarks(&imports)
            .map_err(|error| DisaTaskError::Library(error.to_string()))?;
        let details = parsed
            .iter()
            .map(|item| {
                format!(
                    "{} {} ({} rules, reference content only; source {})",
                    item.benchmark.id,
                    item.benchmark.version_string(),
                    item.benchmark.rules.len(),
                    item.source_name
                )
            })
            .collect();
        Ok::<_, DisaTaskError>(ImportResult {
            imported: outcome.added_count() + outcome.updated_count(),
            skipped: 0,
            details,
        })
    })
    .await;

    match task {
        Ok(Ok(result)) => api_response_ok(result),
        Ok(Err(DisaTaskError::Input(error))) => {
            let status = match &error {
                disa::DisaImportError::Archive(archive) if !archive.is_resource_limit() => {
                    StatusCode::BAD_REQUEST
                }
                error if error.is_resource_limit() => StatusCode::PAYLOAD_TOO_LARGE,
                disa::DisaImportError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            api_response_error(status, error.to_string())
        }
        Ok(Err(DisaTaskError::Library(error))) => {
            api_response_error(StatusCode::INTERNAL_SERVER_ERROR, error)
        }
        Err(error) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Content import worker failed: {error}"),
        ),
    }
}

enum StigpackTaskError {
    Pack(automatestig_stigpack::StigpackError),
    Configuration(String),
    Library(String),
}

async fn import_stigpack(State(state): State<AppState>, multipart: Multipart) -> Response {
    let compressed_limit =
        automatestig_stigpack::verifier::stigpack_archive_policy().max_compressed_bytes;
    let (filename, temporary) = match stream_single_upload(multipart, compressed_limit).await {
        Ok(upload) => upload,
        Err((status, error)) => return api_response_error(status, error),
    };
    if !filename.to_ascii_lowercase().ends_with(".stigpack") {
        return api_response_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected a .stigpack file",
        );
    }
    let permit = match state
        .inner
        .content_import_lock
        .clone()
        .acquire_owned()
        .await
    {
        Ok(permit) => permit,
        Err(_) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Content import coordinator is unavailable",
            )
        }
    };
    let task_state = state.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut library = task_state
            .library()
            .map_err(|error| StigpackTaskError::Library(error.to_string()))?;
        let allow_unsigned = std::env::var("AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let result = if allow_unsigned {
            automatestig_stigpack::importer::import_pack_untrusted(
                temporary.path(),
                &mut library,
            )
        } else {
            let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
            let trust_dir = trusted_content_keys_dir();
            trust_store.load_from_directory(&trust_dir).map_err(|error| {
                StigpackTaskError::Configuration(format!(
                    "Failed to load trusted .stigpack keys: {error}"
                ))
            })?;
            if trust_store.is_empty() {
                return Err(StigpackTaskError::Configuration(
                    "Trusted .stigpack signature required, but no trusted keys are configured. Add Ed25519 .pub files to AUTOMATESTIG_TRUSTED_KEYS_DIR or set AUTOMATESTIG_ALLOW_UNSIGNED_STIGPACK=1 for explicit lab-only import."
                        .to_owned(),
                ));
            }
            automatestig_stigpack::importer::import_pack_trusted(
                temporary.path(),
                &mut library,
                &trust_store,
            )
        }
        .map_err(StigpackTaskError::Pack)?;

        Ok::<_, StigpackTaskError>(ImportResult {
                imported: result.benchmarks_imported,
                skipped: 0,
                details: vec![format!(
                    "Pack {} v{}: {} benchmarks, {} templates, {} custom checks, {} generated check packs",
                    result.pack_id,
                    result.pack_version,
                    result.benchmarks_imported,
                    result.answer_templates_imported,
                    result.custom_checks_imported,
                    result.auto_check_packs_imported,
                )],
            })
    })
    .await;

    match task {
        Ok(Ok(result)) => api_response_ok(result),
        Ok(Err(StigpackTaskError::Pack(error))) => {
            let status = match &error {
                automatestig_stigpack::StigpackError::Archive(archive)
                    if archive.is_resource_limit() =>
                {
                    StatusCode::PAYLOAD_TOO_LARGE
                }
                automatestig_stigpack::StigpackError::Archive(_)
                | automatestig_stigpack::StigpackError::Zip(_) => StatusCode::BAD_REQUEST,
                automatestig_stigpack::StigpackError::Io(_)
                | automatestig_stigpack::StigpackError::Library(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            api_response_error(status, format!("Import failed: {error}"))
        }
        Ok(Err(StigpackTaskError::Configuration(error))) => {
            api_response_error(StatusCode::UNPROCESSABLE_ENTITY, error)
        }
        Ok(Err(StigpackTaskError::Library(error))) => {
            api_response_error(StatusCode::INTERNAL_SERVER_ERROR, error)
        }
        Err(error) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Content import worker failed: {error}"),
        ),
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
    assessed_pass_pct: Option<f64>,
    benchmark_coverage_pct: Option<f64>,
    /// Deprecated compatibility alias for `assessed_pass_pct`.
    compliance_pct: Option<f64>,
    collection_complete: Option<bool>,
    evaluation_origin: Option<EvaluationOrigin>,
    cat_i_open: usize,
    cat_ii_open: usize,
    cat_iii_open: usize,
}

fn defensible_score(checklist: &Checklist, score: f64) -> Option<f64> {
    let is_unverified_import = checklist
        .evaluation_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.origin == EvaluationOrigin::ImportedChecklist);
    (checklist.external_export_block_reason().is_none() && !is_unverified_import).then_some(score)
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
                        assessed_pass_pct: defensible_score(&cl, s.assessed_pass_pct()),
                        benchmark_coverage_pct: defensible_score(&cl, s.benchmark_coverage_pct()),
                        compliance_pct: defensible_score(&cl, s.assessed_pass_pct()),
                        collection_complete: cl
                            .evaluation_provenance
                            .as_ref()
                            .map(|provenance| provenance.collection_complete),
                        evaluation_origin: cl
                            .evaluation_provenance
                            .as_ref()
                            .map(|provenance| provenance.origin),
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
    assessed_pass_pct: Option<f64>,
    benchmark_coverage_pct: Option<f64>,
    /// Deprecated compatibility alias for `assessed_pass_pct`.
    compliance_pct: Option<f64>,
    evaluation_provenance: Option<EvaluationProvenance>,
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
            let assessed_pass_pct = defensible_score(&cl, s.assessed_pass_pct());
            let benchmark_coverage_pct = defensible_score(&cl, s.benchmark_coverage_pct());
            let evaluation_provenance = cl.evaluation_provenance.clone();
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
                assessed_pass_pct,
                benchmark_coverage_pct,
                compliance_pct: assessed_pass_pct,
                evaluation_provenance,
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

        let mut checklist = match ext {
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

        if ext.eq_ignore_ascii_case("json") {
            let unsafe_or_incomplete =
                checklist
                    .evaluation_provenance
                    .as_ref()
                    .is_some_and(|provenance| {
                        !provenance.collection_complete
                            || !provenance.collection_errors.is_empty()
                            || provenance.unsafe_legacy_evidence
                    })
                    || checklist
                        .findings
                        .iter()
                        .any(|finding| finding.source == FindingSource::CollectionError);
            if unsafe_or_incomplete {
                return api_error(
                    "Incomplete or unsafe evaluation JSON cannot be imported as a checklist",
                );
            }
        }

        // Treat every uploaded checklist as an untrusted imported assertion.
        // In particular, JSON must not be able to forge `Automated` findings
        // which STIG Manager would publish as an AutomateSTIG autoResult.
        let claimed_generated_by = checklist.generated_by.clone();
        checklist.generated_by = format!("Imported by AutomateSTIG {}", env!("CARGO_PKG_VERSION"));
        for finding in &mut checklist.findings {
            finding.source = FindingSource::Imported;
            finding.evaluated_by = "Imported checklist (unverified provenance)".to_string();
        }
        checklist.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::ImportedChecklist,
            collection_complete: false,
            collection_errors: vec![
                "collection completeness is unknown for an imported checklist".to_string(),
            ],
            evidence_sha256: Some(sha256_hex(&data)),
            claimed_hostname: Some(checklist.asset.hostname.clone()),
            collector_version: None,
            collected_at: None,
            plan_sha256: None,
            server_key_fingerprint: None,
            benchmark_sha256: None,
            check_pack_sha256: None,
            evaluation_plan_sha256: None,
            organization_policy: None,
            unsafe_legacy_evidence: false,
        });

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
            assessed_pass_pct: defensible_score(&checklist, s.assessed_pass_pct()),
            benchmark_coverage_pct: defensible_score(&checklist, s.benchmark_coverage_pct()),
            compliance_pct: defensible_score(&checklist, s.assessed_pass_pct()),
            collection_complete: checklist
                .evaluation_provenance
                .as_ref()
                .map(|provenance| provenance.collection_complete),
            evaluation_origin: checklist
                .evaluation_provenance
                .as_ref()
                .map(|provenance| provenance.origin),
            cat_i_open: s.cat_i_open,
            cat_ii_open: s.cat_ii_open,
            cat_iii_open: s.cat_iii_open,
        };

        let db = state.db();
        if let Err(e) = db.save_checklist_with_audit(
            &checklist,
            "checklist.imported",
            "gui",
            Some(
                &serde_json::json!({
                    "filename": filename,
                    "sha256": sha256_hex(&data),
                    "claimed_generated_by": claimed_generated_by,
                    "automation_attribution_normalized": true
                })
                .to_string(),
            ),
        ) {
            return api_error(&format!("Failed to save: {}", e));
        }

        api_ok(info)
    }
}

// ---------------------------------------------------------------------------
// DISA Content Fetching
// ---------------------------------------------------------------------------

/// List available STIGs from DISA's public download page.
async fn disa_list_available() -> Response {
    match crate::disa::list_available_stigs().await {
        Ok(stigs) => api_response_ok(stigs),
        Err(error) => api_response_error(StatusCode::BAD_GATEWAY, error),
    }
}

/// Fetch and import a specific STIG from DISA by URL.
#[derive(Deserialize)]
struct DisaFetchRequest {
    url: String,
}

async fn disa_fetch(State(state): State<AppState>, Json(req): Json<DisaFetchRequest>) -> Response {
    match crate::disa::download_and_import(&req.url, &state).await {
        Ok(result) => api_response_ok(result),
        Err(error) => {
            let status = if error.is_invalid_request() {
                StatusCode::BAD_REQUEST
            } else if error.is_library_error() {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_GATEWAY
            };
            api_response_error(status, error.to_string())
        }
    }
}

/// Fetch all available STIGs from DISA.
async fn disa_fetch_all(State(state): State<AppState>) -> Response {
    match crate::disa::fetch_all_content(&state).await {
        Ok(result) if result.errors.is_empty() => api_response_ok(result),
        Ok(result) => api_response_error(StatusCode::BAD_GATEWAY, result.errors.join("; ")),
        Err(error) => api_response_error(StatusCode::BAD_GATEWAY, error),
    }
}

/// Check for updates without downloading.
async fn disa_check_updates(State(state): State<AppState>) -> Response {
    match crate::disa::check_for_updates(&state).await {
        Ok(result) => api_response_ok(result),
        Err(error) => api_response_error(StatusCode::BAD_GATEWAY, error),
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

    let (private_key, public_key) = match load_external_offline_signing_key(&state) {
        Ok(keys) => keys,
        Err(error) => {
            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, error).into_response();
        }
    };
    let trust_dir = trusted_content_keys_dir();
    let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
    if let Err(error) = trust_store.load_from_directory(&trust_dir) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Failed to load executable-content trust anchors from {}: {error}",
                trust_dir.display()
            ),
        )
            .into_response();
    }
    let trusted_public_keys = trust_store.public_keys();

    // Build a signed stigpack with all current library content.
    let mut builder = automatestig_stigpack::builder::PackBuilder::new(
        &format!(
            "automatestig-offline-{}",
            chrono::Utc::now().format("%Y%m%d")
        ),
        "AutomateSTIG Offline Update",
        &chrono::Utc::now().format("%Y.%m.%d").to_string(),
    )
    .author("AutomateSTIG")
    .description("Offline update package for air-gapped AutomateSTIG installations")
    .signing_key(private_key);

    for entry in &benchmarks {
        match library.load_benchmark(&entry.id) {
            Ok(benchmark) => match serde_json::to_string_pretty(&benchmark) {
                Ok(json) => {
                    let pack_path = format!("benchmarks/{}.json", entry.id);
                    builder = builder.add_file_bytes(&pack_path, json.as_bytes());
                }
                Err(error) => {
                    return (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to serialize benchmark {}: {error}", entry.id),
                    )
                        .into_response();
                }
            },
            Err(error) => {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to load benchmark {}: {error}", entry.id),
                )
                    .into_response();
            }
        }
    }

    let templates = library.root().join("answer_templates");
    if templates.exists() {
        builder = match builder.add_directory("answer_templates", &templates) {
            Ok(builder) => builder,
            Err(error) => {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to package answer_templates: {error}"),
                )
                    .into_response();
            }
        };
    }

    builder = match add_trusted_executables_to_offline_pack(builder, &library, &trusted_public_keys)
    {
        Ok(builder) => builder,
        Err(error) => {
            return (axum::http::StatusCode::CONFLICT, error).into_response();
        }
    };

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
    let key_fingerprint = automatestig_stigpack::signing::public_key_fingerprint(&public_key);

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
            (
                axum::http::HeaderName::from_static("x-automatestig-signing-key"),
                key_fingerprint,
            ),
        ],
        data,
    )
        .into_response()
}

async fn download_offline_trust_key(State(state): State<AppState>) -> impl IntoResponse {
    let (_, public_key) = match load_external_offline_signing_key(&state) {
        Ok(keys) => keys,
        Err(error) => {
            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, error).into_response();
        }
    };
    let key_fingerprint = automatestig_stigpack::signing::public_key_fingerprint(&public_key);
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=content-signing.pub".to_string(),
            ),
            (
                axum::http::HeaderName::from_static("x-automatestig-signing-key"),
                key_fingerprint,
            ),
        ],
        public_key.to_vec(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// STIG-Manager Integration
// ---------------------------------------------------------------------------

/// Get current STIG-Manager configuration.
async fn stigman_get_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    let config = match load_stigman_config(&db, &state.inner.data_dir) {
        Ok(config) => config,
        Err(error) => return api_error(&error),
    };
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

    // An empty secret means "keep the saved secret", matching the password
    // placeholder in the UI. Loading/decryption errors are fatal so a corrupt
    // secret cannot be silently replaced with an empty value.
    if body.client_secret.is_empty() {
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(existing) => {
                if body.api_url != existing.api_url
                    || body.token_url != existing.token_url
                    || body.client_id != existing.client_id
                {
                    return api_error(
                        "client_secret must be re-entered when an endpoint or client ID changes",
                    );
                }
                body.client_secret = existing.client_secret;
            }
            Err(error) => return api_error(&error),
        }
    }
    if let Err(error) = body.validate_urls() {
        return api_error(&error);
    }

    // Encrypt the client secret before storing.
    if !body.client_secret.is_empty() {
        let key_material = match crate::secrets::load_or_create_key_material(&state.inner.data_dir)
        {
            Ok(k) => k,
            Err(e) => return api_error(&format!("Key material error: {}", e)),
        };

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
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(config) => config,
            Err(error) => return api_error(&error),
        }
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config).await {
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
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(config) => config,
            Err(error) => return api_error(&error),
        }
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config).await {
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
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(config) => config,
            Err(error) => return api_error(&error),
        }
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config).await {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    match client.list_assets(&cid).await {
        Ok(assets) => api_ok(assets),
        Err(e) => api_error(&e),
    }
}

fn assigned_stig_ids(
    asset_name: &str,
    result: Result<Vec<crate::stigman::SmStig>, String>,
) -> Result<Vec<String>, String> {
    result
        .map(|stigs| stigs.into_iter().map(|stig| stig.benchmark_id).collect())
        .map_err(|error| format!("Failed to fetch assigned STIGs for asset {asset_name}: {error}"))
}

fn target_platform_for_stigs(
    asset_name: &str,
    stig_ids: &[String],
) -> Result<automatestig_core::checks::CheckPlatform, String> {
    use automatestig_core::checks::CheckPlatform;

    let mut platforms = std::collections::HashSet::new();
    for stig_id in stig_ids {
        let platform = match stig_id.as_str() {
            "NetApp_ONTAP_DSC_9-x_STIG" => CheckPlatform::Ontap,
            "General_Purpose_Operating_System" => CheckPlatform::Bsd,
            "Cisco_IOS-XE_Router_NDM_STIG" => CheckPlatform::CiscoIos,
            _ => {
                return Err(format!(
                    "Asset {asset_name} is assigned out-of-scope STIG {stig_id}"
                ))
            }
        };
        platforms.insert(platform);
    }
    if platforms.len() != 1 {
        return Err(format!(
            "Asset {asset_name} must have assignments for exactly one supported target platform"
        ));
    }
    Ok(*platforms.iter().next().expect("one platform"))
}

/// Sync assets from a STIG-Manager collection into local inventory.
async fn stigman_sync_assets(
    State(state): State<AppState>,
    axum::extract::Path(cid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let config = {
        let db = state.db();
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(config) => config,
            Err(error) => return api_error(&error),
        }
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config).await {
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
        match load_assets(&db) {
            Ok(assets) => assets,
            Err(error) => return api_error(&error),
        }
    };
    let mut synced = 0;
    let mut details = Vec::new();

    for sm_asset in &sm_assets {
        // Check if asset already exists locally (by name).
        let existing = local_assets.iter().position(|a| a.name == sm_asset.name);

        // Fetch STIGs assigned to this asset in STIG-Manager.
        let stig_ids = match assigned_stig_ids(
            &sm_asset.name,
            client.list_asset_stigs(&cid, &sm_asset.asset_id).await,
        ) {
            Ok(stig_ids) => stig_ids,
            Err(error) => return api_error(&error),
        };
        let target_platform = match target_platform_for_stigs(&sm_asset.name, &stig_ids) {
            Ok(platform) => platform,
            Err(error) => return api_error(&error),
        };

        if let Some(idx) = existing {
            // Update existing asset with STIG-Manager data.
            local_assets[idx].assigned_stigs = stig_ids.clone();
            local_assets[idx].platform = target_platform;
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
                target_platform,
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
        if let Err(error) = save_assets(&db, &local_assets) {
            return api_error(&error);
        }
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
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(config) => config,
            Err(error) => return api_error(&error),
        }
    };
    if !config.is_configured() {
        return api_error("STIG-Manager is not configured");
    }

    let client = match crate::stigman::StigManagerClient::new(config).await {
        Ok(c) => c,
        Err(e) => return api_error(&e),
    };

    let sm_assets = match client.list_assets(&cid).await {
        Ok(a) => a,
        Err(e) => return api_error(&format!("Failed to fetch: {}", e)),
    };

    let local_assets = {
        let db = state.db();
        match load_assets(&db) {
            Ok(assets) => assets,
            Err(error) => return api_error(&error),
        }
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
            let sm_stigs = match assigned_stig_ids(
                &sm_asset.name,
                client.list_asset_stigs(&cid, &sm_asset.asset_id).await,
            ) {
                Ok(stigs) => stigs,
                Err(error) => return api_error(&error),
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
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(config) => config,
            Err(error) => return api_error(&error),
        }
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
    if let Some(reason) = checklist.external_export_block_reason() {
        return Err(format!(
            "checklist cannot be pushed to STIG Manager: {reason}"
        ));
    }

    let client = crate::stigman::StigManagerClient::new(config).await?;

    // If no asset_id provided, try to find the asset by hostname before creating it.
    let asset_id = match asset_id {
        Some(id) => id.to_string(),
        None => match client
            .list_assets(collection_id)
            .await
            .map_err(|error| format!("Failed to list STIG-Manager assets: {error}"))?
            .into_iter()
            .find(|asset| asset.name.eq_ignore_ascii_case(&checklist.asset.hostname))
        {
            Some(asset) => {
                // Reviews still require the STIG to be assigned to a found asset.
                asset.asset_id
            }
            None => {
                client
                    .create_asset(
                        collection_id,
                        &checklist.asset.hostname,
                        checklist.asset.fqdn.as_deref(),
                        checklist.asset.ip_address.as_deref(),
                        &checklist.stig_info.stig_id,
                    )
                    .await
                    .map_err(|e| format!("Failed to create asset: {}", e))?
                    .asset_id
            }
        },
    };

    // Convert findings to STIG-Manager reviews.
    let reviews = crate::stigman::StigManagerClient::checklist_to_reviews(checklist);
    let review_count = reviews.len();

    // Push to STIG-Manager.
    let result = client
        .push_reviews(collection_id, &asset_id, reviews)
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
fn load_stigman_config(
    db: &automatestig_storage::Database,
    data_dir: &std::path::Path,
) -> Result<crate::stigman::StigManagerConfig, String> {
    let mut config: crate::stigman::StigManagerConfig = match db
        .get_config("stigman_config")
        .map_err(|error| format!("Failed to load STIG-Manager config: {error}"))?
    {
        Some(json) => serde_json::from_str(&json)
            .map_err(|error| format!("Failed to parse STIG-Manager config: {error}"))?,
        None => crate::stigman::StigManagerConfig::default(),
    };

    // Decrypt client secret if it's encrypted.
    if config.client_secret.starts_with("enc:") {
        let encrypted = &config.client_secret[4..];
        let decrypted = crate::secrets::load_or_create_key_material(data_dir)
            .and_then(|key_material| crate::secrets::decrypt_secret(encrypted, &key_material));

        match decrypted {
            Ok(decrypted) => config.client_secret = decrypted,
            Err(error) => {
                return Err(format!(
                    "Failed to decrypt STIG-Manager client secret: {error}"
                ))
            }
        }
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// Evaluate uploaded device evidence
// ---------------------------------------------------------------------------

fn bind_claimed_hostname(
    submitted_hostname: &mut String,
    claimed_hostname: &str,
    linked_asset_hostname: Option<&str>,
    source_label: &str,
) -> Result<(), String> {
    let claimed_hostname = claimed_hostname.trim();
    if claimed_hostname.is_empty() {
        return Err(format!("{source_label} does not identify a hostname"));
    }

    if submitted_hostname.is_empty() {
        *submitted_hostname = claimed_hostname.to_owned();
    } else if !submitted_hostname.eq_ignore_ascii_case(claimed_hostname) {
        return Err(format!(
            "submitted hostname does not match the hostname claimed by {source_label}"
        ));
    }

    if linked_asset_hostname
        .is_some_and(|asset_hostname| !asset_hostname.trim().eq_ignore_ascii_case(claimed_hostname))
    {
        return Err(format!(
            "linked asset hostname does not match the hostname claimed by {source_label}"
        ));
    }

    Ok(())
}

async fn evaluate_with_evidence(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Response {
    let mut stig_id = String::new();
    let mut hostname = String::new();
    let mut asset_id: Option<String> = None;
    let mut platform = String::new();
    let mut input_type = String::new();
    let mut evidence_data: Option<Vec<u8>> = None;
    let mut organization_policy_data: Option<Vec<u8>> = None;
    let mut organization_policy_signature: Option<Vec<u8>> = None;
    let mut seen_fields = HashSet::new();

    // Parse multipart fields without treating malformed or truncated uploads as
    // missing evidence.
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                let (status, message) = multipart_error(error);
                return api_response_error(status, message);
            }
        };
        let name = field.name().unwrap_or("").to_string();
        if !name.is_empty() && !seen_fields.insert(name.clone()) {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                format!("Duplicate multipart field: {name}"),
            );
        }
        match name.as_str() {
            "stig_id" => {
                stig_id = match field.text().await {
                    Ok(value) => value,
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Invalid stig_id field: {message}"),
                        );
                    }
                };
            }
            "hostname" => {
                hostname = match field.text().await {
                    Ok(value) => value,
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Invalid hostname field: {message}"),
                        );
                    }
                };
            }
            "asset_id" => {
                asset_id = match field.text().await {
                    Ok(value) if value.trim().is_empty() => None,
                    Ok(value) => Some(value.trim().to_owned()),
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Invalid asset_id field: {message}"),
                        );
                    }
                };
            }
            "platform" => {
                platform = match field.text().await {
                    Ok(value) => value,
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Invalid platform field: {message}"),
                        );
                    }
                };
            }
            "input_type" => {
                input_type = match field.text().await {
                    Ok(value) => value,
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Invalid input_type field: {message}"),
                        );
                    }
                };
            }
            "evidence" => {
                evidence_data = match field.bytes().await {
                    Ok(value) => Some(value.to_vec()),
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Failed to read evidence: {message}"),
                        );
                    }
                };
            }
            "organization_policy" => {
                organization_policy_data = match field.bytes().await {
                    Ok(value) if value.is_empty() || value.len() > 64 * 1024 => {
                        return api_response_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "organization policy must be 1..=65536 bytes",
                        )
                    }
                    Ok(value) => Some(value.to_vec()),
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Failed to read organization policy: {message}"),
                        );
                    }
                };
            }
            "organization_policy_signature" => {
                organization_policy_signature = match field.bytes().await {
                    Ok(value) if value.len() > 64 => {
                        return api_response_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "organization policy signature must contain exactly 64 bytes",
                        )
                    }
                    Ok(value) => Some(value.to_vec()),
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Failed to read organization policy signature: {message}"),
                        );
                    }
                };
            }
            _ => {}
        }
    }

    stig_id = stig_id.trim().to_owned();
    hostname = hostname.trim().to_owned();
    platform = platform.trim().to_owned();
    input_type = input_type.trim().to_ascii_lowercase();

    if stig_id.is_empty() {
        return api_response_error(StatusCode::BAD_REQUEST, "stig_id is required");
    }
    let data = match evidence_data {
        Some(data) => data,
        None => return api_response_error(StatusCode::BAD_REQUEST, "evidence file is required"),
    };
    let input_sha256 = sha256_hex(&data);
    let text = match String::from_utf8(data) {
        Ok(text) => text,
        Err(_) => {
            return api_response_error(StatusCode::BAD_REQUEST, "evidence file must be UTF-8 text")
        }
    };

    let check_platform = match parse_check_platform(&platform) {
        Some(platform) => platform,
        None => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "platform must be ontap, bsd, or cisco_ios",
            );
        }
    };
    let linked_asset_hostname = if let Some(ref linked_asset_id) = asset_id {
        let assets = match load_assets(&state.db()) {
            Ok(assets) => assets,
            Err(error) => return api_response_error(StatusCode::INTERNAL_SERVER_ERROR, error),
        };
        let Some(asset) = assets.iter().find(|asset| asset.id == *linked_asset_id) else {
            return api_response_error(StatusCode::NOT_FOUND, "Linked asset was not found");
        };
        let expected = match platform_for_supported_stig(&stig_id) {
            Ok(platform) => platform,
            Err(error) => return api_response_error(StatusCode::BAD_REQUEST, error),
        };
        if asset.platform != expected || check_platform != expected {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "linked asset, submitted platform, and target STIG platforms must match",
            );
        }
        Some(asset.name.clone())
    } else {
        None
    };

    let (system_data, mut provenance) = if input_type == "config" {
        if check_platform != automatestig_core::checks::CheckPlatform::CiscoIos {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "config input is supported only for Cisco platforms",
            );
        }
        if let Err(error) =
            automatestig_core::remote::validate_network_config(check_platform, &text)
        {
            return api_response_error(StatusCode::UNPROCESSABLE_ENTITY, error);
        }
        let claimed_hostname = match automatestig_core::remote::cisco_config_hostname(&text) {
            Ok(value) => value.trim().to_owned(),
            Err(error) => return api_response_error(StatusCode::UNPROCESSABLE_ENTITY, error),
        };
        if let Err(error) = bind_claimed_hostname(
            &mut hostname,
            &claimed_hostname,
            linked_asset_hostname.as_deref(),
            "configuration",
        ) {
            return api_response_error(StatusCode::UNPROCESSABLE_ENTITY, error);
        }
        let checks = match load_check_definitions(&state, &stig_id) {
            Ok(checks) => checks,
            Err(error) => return device_evaluation_error_response(error),
        };
        if checks.first().map(|check| check.platform) != Some(check_platform) {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "selected platform does not match the installed check pack",
            );
        }
        let benchmark = match load_evaluation_benchmark(&state, &stig_id) {
            Ok(benchmark) => benchmark,
            Err(error) => return device_evaluation_error_response(error),
        };
        let (policy_bytes, signature_bytes) = match (
            organization_policy_data.as_deref(),
            organization_policy_signature.as_deref(),
        ) {
            (Some(policy), Some(signature)) => (policy, signature),
            (None, None)
                if checks
                    .iter()
                    .any(|definition| definition.check.requires_organization_policy()) =>
            {
                return api_response_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "this Cisco check pack requires an organization policy and detached signature",
                )
            }
            (None, None) => (&[][..], &[][..]),
            _ => {
                return api_response_error(
                    StatusCode::BAD_REQUEST,
                    "organization policy and detached signature must be supplied together",
                )
            }
        };
        let organization_policy = if policy_bytes.is_empty() {
            None
        } else {
            match verify_organization_policy(
                &state,
                policy_bytes,
                signature_bytes,
                &benchmark.id,
                &benchmark.version_string(),
                &claimed_hostname,
            ) {
                Ok(policy) => Some(policy),
                Err(error) => return api_response_error(StatusCode::UNPROCESSABLE_ENTITY, error),
            }
        };
        (
            automatestig_core::checks::SystemData {
                collection_complete: true,
                network_config: Some(text),
                organization_policy,
                ..Default::default()
            },
            EvaluationProvenance {
                origin: EvaluationOrigin::ConfigFile,
                collection_complete: true,
                collection_errors: Vec::new(),
                evidence_sha256: Some(input_sha256.clone()),
                claimed_hostname: Some(claimed_hostname),
                collector_version: None,
                collected_at: None,
                plan_sha256: None,
                server_key_fingerprint: None,
                benchmark_sha256: None,
                check_pack_sha256: None,
                evaluation_plan_sha256: None,
                organization_policy: None,
                unsafe_legacy_evidence: false,
            },
        )
    } else if input_type == "transcript" {
        if organization_policy_data.is_some() || organization_policy_signature.is_some() {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "organization policy inputs are valid only for Cisco configuration evaluation",
            );
        }
        if check_platform == automatestig_core::checks::CheckPlatform::CiscoIos {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "Cisco IOS-XE is config-file-only; transcript input is unsupported",
            );
        }
        let transcript = match automatestig_parsers::evidence::parse_evidence(
            &text,
            automatestig_parsers::evidence::LegacyEvidencePolicy::Reject,
        ) {
            Ok(transcript) => transcript,
            Err(error) => {
                return api_response_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("Invalid evidence v2 document: {error}"),
                )
            }
        };
        let claimed_hostname = transcript
            .hostname
            .clone()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if let Err(error) = bind_claimed_hostname(
            &mut hostname,
            &claimed_hostname,
            linked_asset_hostname.as_deref(),
            "evidence",
        ) {
            return api_response_error(StatusCode::UNPROCESSABLE_ENTITY, error);
        }
        let checks = match load_check_definitions(&state, &stig_id) {
            Ok(checks) => checks,
            Err(error) => return device_evaluation_error_response(error),
        };
        if checks.first().map(|check| check.platform) != Some(check_platform) {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "selected platform does not match the installed check pack",
            );
        }
        let plan =
            match automatestig_core::remote::generate_collection_plan(check_platform, &checks) {
                Ok(plan) => plan,
                Err(error) => {
                    return api_response_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to generate collection plan: {error}"),
                    )
                }
            };
        let system_data =
            match automatestig_parsers::evidence::assemble_for_plan(&transcript, &plan) {
                Ok(system_data) => system_data,
                Err(error) => {
                    return api_response_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("Evidence does not match scan plan: {error}"),
                    )
                }
            };
        let mut errors: Vec<String> = system_data
            .collection_errors
            .iter()
            .map(|(key, error)| format!("{key}: {error}"))
            .collect();
        errors.sort();
        (
            system_data,
            EvaluationProvenance {
                origin: EvaluationOrigin::EvidenceFile,
                collection_complete: transcript.complete,
                collection_errors: errors,
                evidence_sha256: Some(input_sha256.clone()),
                claimed_hostname: Some(claimed_hostname),
                collector_version: transcript.collector_version.clone(),
                collected_at: transcript.collected_at.clone(),
                plan_sha256: transcript.plan_sha256.clone(),
                server_key_fingerprint: transcript.server_key_fingerprint.clone(),
                benchmark_sha256: None,
                check_pack_sha256: None,
                evaluation_plan_sha256: None,
                organization_policy: None,
                unsafe_legacy_evidence: transcript.legacy,
            },
        )
    } else {
        return api_response_error(
            StatusCode::BAD_REQUEST,
            "input_type must be config or transcript",
        );
    };

    if hostname.is_empty() {
        return api_response_error(
            StatusCode::BAD_REQUEST,
            "hostname is required when evidence does not identify the target",
        );
    }
    if provenance.claimed_hostname.is_none() {
        provenance.claimed_hostname = Some(hostname.clone());
    }

    let collection_errors = system_data.collection_errors.clone();
    let mut response = match evaluate_with_system_data(
        &state,
        &stig_id,
        &hostname,
        &system_data,
        FindingSource::Evidence,
        provenance,
    ) {
        Ok(response) => response,
        Err(error) => return device_evaluation_error_response(error),
    };
    if let Some(data) = response
        .get_mut("data")
        .and_then(serde_json::Value::as_object_mut)
    {
        data.insert(
            "collection_errors".to_owned(),
            serde_json::to_value(&collection_errors).unwrap_or(serde_json::Value::Null),
        );
    }
    let evaluation_complete = response
        .get("data")
        .and_then(|data| data.get("collection_complete"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // An incomplete attempt is audit-only and must not replace the asset's
    // last completed evaluation.
    if evaluation_complete {
        if let Some(ref aid) = asset_id {
            if let Some(data) = response.get("data") {
                if let (Some(assessed_pass_pct), Some(checklist_id)) = (
                    data.get("assessed_pass_pct").and_then(|v| v.as_f64()),
                    data.get("id").and_then(|v| v.as_str()),
                ) {
                    if let Err(error) = update_asset_after_eval(
                        &state.db(),
                        aid,
                        &stig_id,
                        &hostname,
                        assessed_pass_pct,
                        checklist_id,
                    ) {
                        return api_response_error(StatusCode::INTERNAL_SERVER_ERROR, error);
                    }
                }
            }
        }
    }
    let status = if evaluation_complete {
        StatusCode::OK
    } else {
        StatusCode::MULTI_STATUS
    };
    (status, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// Finding Editing
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
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
    let before = checklist.find_by_vuln_id(&vuln_id).cloned();

    {
        let finding = match checklist.find_by_vuln_id_mut(&vuln_id) {
            Some(f) => f,
            None => return api_error(&format!("Finding not found: {}", vuln_id)),
        };

        if let Some(ref status_str) = req.status {
            let Some(status) =
                automatestig_core::models::finding::FindingStatus::from_ckl_str(status_str)
            else {
                return api_error(&format!("Invalid finding status: {status_str}"));
            };
            finding.status = status;
        }
        if let Some(ref details) = req.finding_details {
            finding.finding_details = details.clone();
        }
        if let Some(ref comments) = req.comments {
            finding.comments = comments.clone();
        }
        if req.status.is_some() || req.finding_details.is_some() || req.comments.is_some() {
            finding.source = FindingSource::Manual;
            finding.evaluated_at = chrono::Utc::now();
            finding.evaluated_by = "Manual GUI edit".to_string();
        }
    }

    checklist.touch();

    let result_status = checklist
        .find_by_vuln_id(&vuln_id)
        .map(|f| f.status.to_string())
        .unwrap_or_default();

    let details = serde_json::json!({
        "vuln_id": vuln_id,
        "before": before,
        "requested_changes": req,
    })
    .to_string();
    if let Err(e) =
        db.save_checklist_with_audit(&checklist, "finding.updated", "gui", Some(&details))
    {
        return api_error(&format!("Failed to save: {}", e));
    }

    api_ok(serde_json::json!({
        "vuln_id": vuln_id,
        "status": result_status,
        "updated": true,
    }))
}

// ---------------------------------------------------------------------------
// Asset Inventory
// ---------------------------------------------------------------------------

fn load_assets(
    db: &automatestig_storage::Database,
) -> Result<Vec<automatestig_core::inventory::assets::ManagedAsset>, String> {
    match db
        .get_config("asset_inventory")
        .map_err(|error| error.to_string())?
    {
        Some(json) => serde_json::from_str(&json)
            .map_err(|error| format!("Failed to parse asset inventory: {error}")),
        None => Ok(Vec::new()),
    }
}

fn save_assets(
    db: &automatestig_storage::Database,
    assets: &[automatestig_core::inventory::assets::ManagedAsset],
) -> Result<(), String> {
    let json = serde_json::to_string(assets).map_err(|error| error.to_string())?;
    db.set_config("asset_inventory", &json)
        .map_err(|error| error.to_string())
}

fn platform_for_supported_stig(
    stig_id: &str,
) -> Result<automatestig_core::checks::CheckPlatform, String> {
    use automatestig_core::checks::CheckPlatform;
    match stig_id {
        "NetApp_ONTAP_DSC_9-x_STIG" => Ok(CheckPlatform::Ontap),
        "General_Purpose_Operating_System" => Ok(CheckPlatform::Bsd),
        "Cisco_IOS-XE_Router_NDM_STIG" => Ok(CheckPlatform::CiscoIos),
        _ => Err(format!(
            "STIG {stig_id} is outside the supported scanner targets"
        )),
    }
}

fn validate_asset_assignments(
    asset: &automatestig_core::inventory::assets::ManagedAsset,
) -> Result<(), String> {
    for stig_id in &asset.assigned_stigs {
        let expected = platform_for_supported_stig(stig_id)?;
        if asset.platform != expected {
            return Err(format!(
                "Asset {} platform {:?} does not match assigned STIG {} platform {:?}",
                asset.name, asset.platform, stig_id, expected
            ));
        }
    }
    Ok(())
}

/// After an evaluation, reflect the result on the linked asset (if any).
fn update_asset_after_eval(
    db: &automatestig_storage::Database,
    asset_id: &str,
    stig_id: &str,
    evaluated_hostname: &str,
    assessed_pass_pct: f64,
    checklist_id: &str,
) -> Result<(), String> {
    let mut assets = load_assets(db)?;
    if let Some(asset) = assets.iter_mut().find(|a| a.id == asset_id) {
        let expected = platform_for_supported_stig(stig_id)?;
        if asset.platform != expected {
            return Err(format!(
                "Asset {} platform {:?} does not match evaluation target {:?}",
                asset.name, asset.platform, expected
            ));
        }
        if !asset
            .name
            .trim()
            .eq_ignore_ascii_case(evaluated_hostname.trim())
        {
            return Err(format!(
                "Asset {} hostname does not match evaluated hostname {}",
                asset.name, evaluated_hostname
            ));
        }
        asset.last_evaluated = Some(chrono::Utc::now());
        // Retained under the legacy inventory field name for storage/API
        // compatibility. The value is the assessed-control pass rate.
        asset.last_compliance_pct = Some(assessed_pass_pct);
        if !asset.assigned_stigs.iter().any(|s| s == stig_id) {
            asset.assigned_stigs.push(stig_id.to_string());
        }
        if !asset.last_checklist_ids.iter().any(|c| c == checklist_id) {
            asset.last_checklist_ids.push(checklist_id.to_string());
        }
        save_assets(db, &assets)?;
    }
    Ok(())
}

async fn list_assets_inv(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    match load_assets(&db) {
        Ok(assets) => api_ok(assets),
        Err(error) => api_error(&error),
    }
}

async fn create_asset_inv(
    State(state): State<AppState>,
    Json(asset): Json<automatestig_core::inventory::assets::ManagedAsset>,
) -> Json<serde_json::Value> {
    if let Err(error) = validate_asset_assignments(&asset) {
        return api_error(&error);
    }
    let db = state.db();
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    assets.push(asset.clone());
    if let Err(error) = save_assets(&db, &assets) {
        return api_error(&error);
    }
    api_ok(asset)
}

async fn get_asset_inv(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
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
    if let Err(error) = validate_asset_assignments(&updated) {
        return api_error(&error);
    }
    let db = state.db();
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    if let Some(asset) = assets.iter_mut().find(|a| a.id == id) {
        *asset = updated.clone();
        if let Err(error) = save_assets(&db, &assets) {
            return api_error(&error);
        }
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
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    let len = assets.len();
    assets.retain(|a| a.id != id);
    if let Err(error) = save_assets(&db, &assets) {
        return api_error(&error);
    }
    api_ok(assets.len() < len)
}

// ---------------------------------------------------------------------------
// Bulk Asset Update
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BulkUpdateRequest {
    asset_ids: Vec<String>,
    enabled: Option<bool>,
    add_tag: Option<String>,
    remove_tag: Option<String>,
}

async fn bulk_update_assets(
    State(state): State<AppState>,
    Json(req): Json<BulkUpdateRequest>,
) -> Json<serde_json::Value> {
    let db = state.db();
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    let mut count = 0;

    for asset in assets.iter_mut() {
        if req.asset_ids.contains(&asset.id) {
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

    if let Err(error) = save_assets(&db, &assets) {
        return api_error(&error);
    }
    api_ok(serde_json::json!({ "updated": count }))
}

// ---------------------------------------------------------------------------
// Answer File Management
// ---------------------------------------------------------------------------

async fn list_answer_files(State(state): State<AppState>) -> Response {
    let permit = match state
        .inner
        .content_import_lock
        .clone()
        .acquire_owned()
        .await
    {
        Ok(permit) => permit,
        Err(_) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Content import coordinator is unavailable",
            )
        }
    };
    let library_path = state.inner.library_path.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let paths = automatestig_core::library_content::list_answer_template_files(&library_path)
            .map_err(|error| error.to_string())?;
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let af = automatestig_core::answer::AnswerFile::load(&path)
                .map_err(|error| format!("Failed to load {}: {error}", path.display()))?;
            files.push(serde_json::json!({
                "name": af.name,
                "stig_id": af.stig_id,
                "version": af.version,
                "entries": af.entries.len(),
                "path": path.display().to_string(),
            }));
        }
        Ok::<_, String>(files)
    })
    .await;

    match task {
        Ok(Ok(files)) => api_response_ok(files),
        Ok(Err(error)) => api_response_error(StatusCode::INTERNAL_SERVER_ERROR, error),
        Err(error) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Answer-template listing worker failed: {error}"),
        ),
    }
}

async fn save_answer_file(
    State(state): State<AppState>,
    Json(af): Json<automatestig_core::answer::AnswerFile>,
) -> Response {
    let filename_base = match automatestig_core::path_safety::safe_filename(&af.name) {
        Ok(name) => name.to_lowercase(),
        Err(error) => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                format!("Unsafe answer file name: {error}"),
            )
        }
    };
    let filename = format!("{}.json", filename_base);
    let bytes = match serde_json::to_vec_pretty(&af) {
        Ok(bytes) => bytes,
        Err(error) => {
            return api_response_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Failed to serialize answer file: {error}"),
            )
        }
    };
    let validation_issues = af.validate();
    let entry_count = af.entries.len();
    let permit = match state
        .inner
        .content_import_lock
        .clone()
        .acquire_owned()
        .await
    {
        Ok(permit) => permit,
        Err(_) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Content import coordinator is unavailable",
            )
        }
    };
    let library_path = state.inner.library_path.clone();
    let task_filename = filename.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        automatestig_core::library_content::write_answer_template_atomic(
            &library_path,
            &task_filename,
            &bytes,
        )
        .map_err(|error| error.to_string())
    })
    .await;

    match task {
        Ok(Ok(path)) => api_response_ok(serde_json::json!({
            "saved": true,
            "path": path.display().to_string(),
            "entries": entry_count,
            "validation_issues": validation_issues,
        })),
        Ok(Err(error)) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save answer file: {error}"),
        ),
        Err(error) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Answer-file save worker failed: {error}"),
        ),
    }
}

async fn list_audit_log(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.db().list_audit_events() {
        Ok(events) => api_ok(events),
        Err(error) => api_error(&format!("Failed to load audit log: {error}")),
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
    #[serde(default)]
    platform: Option<String>,
}

fn live_ssh_evidence_transcript(
    hostname: &str,
    platform: automatestig_core::checks::CheckPlatform,
    plan_sha256: String,
    report: automatestig_collector::CollectionReport,
) -> automatestig_parsers::evidence::EvidenceTranscript {
    let mut transcript = automatestig_parsers::evidence::EvidenceTranscript::new_v2(
        hostname,
        platform,
        plan_sha256,
        report.commands,
    );
    transcript.server_key_fingerprint = report.server_key_fingerprint;
    transcript
}

async fn scan_ssh(
    State(state): State<AppState>,
    request: Result<Json<SshScanRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(req) = match request {
        Ok(request) => request,
        Err(error) => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                format!("Invalid SSH scan request: {error}"),
            )
        }
    };
    if req.host.trim().is_empty() {
        return api_response_error(StatusCode::BAD_REQUEST, "host is required");
    }
    if req.username.trim().is_empty() {
        return api_response_error(StatusCode::BAD_REQUEST, "username is required");
    }
    if req.stig_id.trim().is_empty() {
        return api_response_error(StatusCode::BAD_REQUEST, "stig_id is required");
    }
    if req.port == Some(0) {
        return api_response_error(StatusCode::BAD_REQUEST, "port must be greater than zero");
    }

    let ssh_config = crate::ssh::SshConfig {
        host: req.host.trim().to_owned(),
        port: req.port.unwrap_or(22),
        username: req.username.trim().to_owned(),
        auth: req.auth,
        timeout_secs: 30,
    };
    let stig_id = req.stig_id.trim().to_owned();

    let check_platform = match req.platform.as_deref() {
        Some(value) => match parse_check_platform(value.trim()) {
            Some(platform) => platform,
            None => {
                return api_response_error(StatusCode::BAD_REQUEST, "unsupported SSH scan platform")
            }
        },
        None => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "SSH scan platform is required (ontap or bsd)",
            )
        }
    };
    if check_platform == automatestig_core::checks::CheckPlatform::CiscoIos {
        return api_response_error(
            StatusCode::BAD_REQUEST,
            "Cisco IOS-XE is config-file-only; SSH scanning is unsupported",
        );
    }
    let checks = match load_check_definitions(&state, &stig_id) {
        Ok(checks) => checks,
        Err(error) => return device_evaluation_error_response(error),
    };
    if checks.first().map(|check| check.platform) != Some(check_platform) {
        return api_response_error(
            StatusCode::BAD_REQUEST,
            "selected platform does not match the installed check pack",
        );
    }
    // A benchmark is also required to evaluate the collected evidence. Check
    // this before opening a network connection so missing local content cannot
    // turn into an unnecessary SSH attempt.
    if let Err(error) = load_evaluation_benchmark(&state, &stig_id) {
        return device_evaluation_error_response(error);
    }
    let plan = match automatestig_core::remote::generate_collection_plan(check_platform, &checks) {
        Ok(plan) => plan,
        Err(error) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate collection plan: {error}"),
            )
        }
    };
    if let Err(error) = crate::ssh::validate_scan_target(&ssh_config.host) {
        return api_response_error(StatusCode::BAD_REQUEST, error);
    }
    let report = automatestig_collector::collect_plan(&ssh_config, &plan).await;
    // The asset identity is the exact endpoint name/address whose host key the
    // collector verified. Supported plans do not observe an OS/device
    // hostname, so never relabel that endpoint with an uncorroborated value.
    let hostname = ssh_config.host.clone();
    let transcript = live_ssh_evidence_transcript(&hostname, check_platform, plan.digest(), report);
    let evidence_sha256 = match automatestig_core::check_packs::canonical_json_sha256(&transcript) {
        Ok(digest) => digest,
        Err(error) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to bind live SSH evidence provenance: {error}"),
            )
        }
    };
    let system_data =
        automatestig_core::remote::assemble_evidence_system_data(&plan, &transcript.commands);
    let collection_complete = system_data.collection_complete;
    let collection_errors = system_data.collection_errors.clone();
    let mut provenance_errors: Vec<String> = collection_errors
        .iter()
        .map(|(key, error)| format!("{key}: {error}"))
        .collect();
    provenance_errors.sort();
    let provenance = EvaluationProvenance {
        origin: EvaluationOrigin::LiveSsh,
        collection_complete,
        collection_errors: provenance_errors,
        evidence_sha256: Some(evidence_sha256),
        claimed_hostname: Some(hostname.clone()),
        collector_version: transcript.collector_version.clone(),
        collected_at: transcript.collected_at.clone(),
        plan_sha256: transcript.plan_sha256.clone(),
        server_key_fingerprint: transcript.server_key_fingerprint.clone(),
        benchmark_sha256: None,
        check_pack_sha256: None,
        evaluation_plan_sha256: None,
        organization_policy: None,
        unsafe_legacy_evidence: false,
    };

    // Load check pack and evaluate.
    let mut body = match evaluate_with_system_data(
        &state,
        &stig_id,
        &hostname,
        &system_data,
        FindingSource::Automated,
        provenance,
    ) {
        Ok(body) => body,
        Err(error) => return device_evaluation_error_response(error),
    };
    if let Some(data) = body
        .get_mut("data")
        .and_then(serde_json::Value::as_object_mut)
    {
        data.insert(
            "collection_errors".to_owned(),
            serde_json::to_value(&collection_errors).unwrap_or(serde_json::Value::Null),
        );
        data.insert(
            "server_key_fingerprint".to_owned(),
            serde_json::to_value(&transcript.server_key_fingerprint)
                .unwrap_or(serde_json::Value::Null),
        );
    }
    let evaluation_complete = body
        .get("data")
        .and_then(|data| data.get("collection_complete"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let status = if evaluation_complete {
        StatusCode::OK
    } else {
        StatusCode::MULTI_STATUS
    };
    (status, Json(body)).into_response()
}

fn parse_check_platform(value: &str) -> Option<automatestig_core::checks::CheckPlatform> {
    use automatestig_core::checks::CheckPlatform;
    match value.to_ascii_lowercase().as_str() {
        "cisco_ios" | "ciscoios" => Some(CheckPlatform::CiscoIos),
        "ontap" => Some(CheckPlatform::Ontap),
        "bsd" | "freebsd" => Some(CheckPlatform::Bsd),
        _ => None,
    }
}

fn evaluate_system_data_core(
    state: &AppState,
    stig_id: &str,
    hostname: &str,
    system_data: &automatestig_core::checks::SystemData,
    finding_source: FindingSource,
    mut provenance: EvaluationProvenance,
) -> Result<Checklist, DeviceEvaluationError> {
    // Load benchmark.
    let benchmark = load_evaluation_benchmark(state, stig_id)?;

    let loaded_check_packs = load_check_pack_set(state, stig_id)?;
    let check_definitions = &loaded_check_packs.definitions;
    let benchmark_sha256 = automatestig_core::check_packs::canonical_json_sha256(&benchmark)
        .map_err(|error| {
            DeviceEvaluationError::Internal(format!("Failed to bind benchmark provenance: {error}"))
        })?;
    let organization_policy =
        system_data
            .organization_policy
            .as_ref()
            .map(|policy| OrganizationPolicyProvenance {
                policy_id: policy.document().policy_id.clone(),
                policy_version: policy.document().policy_version.clone(),
                policy_sha256: policy.sha256().to_string(),
                signer_fingerprint: policy.signer_fingerprint().to_string(),
                signature_verified: true,
            });
    let evaluation_plan_sha256 = automatestig_core::check_packs::evaluation_plan_sha256(
        &benchmark.id,
        &benchmark.version_string(),
        &benchmark_sha256,
        &loaded_check_packs.sha256,
        organization_policy
            .as_ref()
            .map(|policy| policy.policy_sha256.as_str()),
    )
    .map_err(|error| {
        DeviceEvaluationError::Internal(format!(
            "Failed to bind evaluation-plan provenance: {error}"
        ))
    })?;
    provenance.benchmark_sha256 = Some(benchmark_sha256);
    provenance.check_pack_sha256 = Some(loaded_check_packs.sha256);
    provenance.evaluation_plan_sha256 = Some(evaluation_plan_sha256);
    provenance.organization_policy = organization_policy;

    // Execute checks.
    let mut check_results: Vec<automatestig_core::checks::CheckResult> = check_definitions
        .iter()
        .map(|check_def| automatestig_core::checks::executor::execute_check(check_def, system_data))
        .collect();
    let mut seen_vuln_ids: HashSet<String> = HashSet::new();
    // Curated packs load before reviewed imported ones; first result per vuln wins.
    check_results.retain(|cr| seen_vuln_ids.insert(cr.vuln_id.clone()));
    provenance.collection_complete &= system_data.collection_complete;
    provenance
        .collection_errors
        .extend(check_results.iter().filter_map(|result| {
            result
                .error
                .as_ref()
                .map(|error| format!("{}: {error}", result.vuln_id))
        }));
    provenance.collection_errors.sort();
    provenance.collection_errors.dedup();
    if !provenance.collection_errors.is_empty() || provenance.unsafe_legacy_evidence {
        provenance.collection_complete = false;
    }

    // Create checklist from benchmark + check results.
    let asset = Asset::new(hostname);
    let engine = automatestig_core::engine::EvaluationEngine::with_defaults();
    let mut checklist = engine
        .evaluate(&benchmark, &asset, &[])
        .map_err(|e| DeviceEvaluationError::Internal(format!("Evaluation failed: {e}")))?;

    // Apply check results to findings.
    for cr in &check_results {
        if let Some(finding) = checklist.find_by_vuln_id_mut(&cr.vuln_id) {
            finding.status = cr.to_finding_status();
            finding.source = if cr.error.is_some() {
                FindingSource::CollectionError
            } else {
                finding_source
            };
            finding.finding_details = cr.evidence.clone();
            finding.evaluated_at = chrono::Utc::now();
            finding.evaluated_by = format!("AutomateSTIG {}", env!("CARGO_PKG_VERSION"));
            if finding_source == FindingSource::Evidence {
                let digest = provenance
                    .evidence_sha256
                    .as_deref()
                    .unwrap_or("unavailable");
                finding.comments = format!(
                    "UNVERIFIED SUPPLIED EVIDENCE — not observed by this AutomateSTIG process. SHA-256: {digest}; claimed host: {}",
                    provenance.claimed_hostname.as_deref().unwrap_or("unknown")
                );
            }
        }
    }

    checklist.evaluation_provenance = Some(provenance.clone());
    checklist.touch();

    let db = state.db();
    let audit_details = serde_json::to_string(&provenance).map_err(|error| {
        DeviceEvaluationError::Internal(format!("Failed to serialize provenance: {error}"))
    })?;
    if provenance.collection_complete {
        db.save_evaluation(&checklist, "device-evaluation", Some(&audit_details))
            .map_err(|e| {
                DeviceEvaluationError::Internal(format!("Failed to save evaluation: {e}"))
            })?;
    } else {
        let details = serde_json::json!({
            "hostname": hostname,
            "stig_id": stig_id,
            "provenance": provenance,
            "artifact_written": false,
            "checklist_saved": false,
        });
        db.record_incomplete_evaluation("device-evaluation", &details.to_string())
            .map_err(|e| {
                DeviceEvaluationError::Internal(format!(
                    "Failed to record incomplete evaluation: {e}"
                ))
            })?;
    }

    Ok(checklist)
}

enum DeviceEvaluationError {
    MissingBenchmark(String),
    MissingCheckPack(String),
    Internal(String),
}

fn device_evaluation_error_response(error: DeviceEvaluationError) -> Response {
    match error {
        DeviceEvaluationError::MissingBenchmark(stig_id) => api_response_error(
            StatusCode::NOT_FOUND,
            format!("Benchmark not found: {stig_id}"),
        ),
        DeviceEvaluationError::MissingCheckPack(stig_id) => api_response_error(
            StatusCode::NOT_FOUND,
            format!("No check pack is installed for {stig_id}"),
        ),
        DeviceEvaluationError::Internal(message) => {
            api_response_error(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

fn load_evaluation_benchmark(
    state: &AppState,
    stig_id: &str,
) -> Result<automatestig_core::models::stig::StigBenchmark, DeviceEvaluationError> {
    let library = state.library().map_err(|error| {
        DeviceEvaluationError::Internal(format!("Failed to open STIG library: {error}"))
    })?;
    match library.load_benchmark(stig_id) {
        Ok(benchmark) => Ok(benchmark),
        Err(automatestig_core::Error::StigNotFound(_)) => {
            Err(DeviceEvaluationError::MissingBenchmark(stig_id.to_owned()))
        }
        Err(error) => Err(DeviceEvaluationError::Internal(format!(
            "Failed to load benchmark {stig_id}: {error}"
        ))),
    }
}

fn load_check_definitions(
    state: &AppState,
    stig_id: &str,
) -> Result<Vec<automatestig_core::checks::CheckDefinition>, DeviceEvaluationError> {
    Ok(load_check_pack_set(state, stig_id)?.definitions)
}

struct LoadedCheckPackSet {
    definitions: Vec<automatestig_core::checks::CheckDefinition>,
    sha256: String,
}

fn load_check_pack_set(
    state: &AppState,
    stig_id: &str,
) -> Result<LoadedCheckPackSet, DeviceEvaluationError> {
    let benchmark = load_evaluation_benchmark(state, stig_id)?;
    let release = benchmark.version_string();
    // Curated packs are compiled into the binary. Never trust an implicit
    // `content/check_packs` directory relative to the process working directory:
    // a writable launch directory must not be able to replace executable checks.
    let mut check_pack_registry = automatestig_core::check_packs::CheckPackRegistry::new();
    check_pack_registry.load_embedded().map_err(|error| {
        DeviceEvaluationError::Internal(format!("Failed to load embedded check packs: {error}"))
    })?;
    let trust_dir = trusted_content_keys_dir();
    let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
    trust_store
        .load_from_directory(&trust_dir)
        .map_err(|error| {
            DeviceEvaluationError::Internal(format!(
                "Failed to load executable-content trust anchors from {}: {error}",
                trust_dir.display()
            ))
        })?;
    let trusted_public_keys = trust_store.public_keys();
    let library = state.library().map_err(|error| {
        DeviceEvaluationError::Internal(format!("Failed to open STIG library: {error}"))
    })?;
    check_pack_registry
        .load_from_trusted_library_directory(&library, "custom_checks", 20, &trusted_public_keys)
        .map_err(|error| {
            DeviceEvaluationError::Internal(format!("Failed to load custom check packs: {error}"))
        })?;

    // Generated packs become executable only after trusted signed .stigpack
    // import promotes them into the reviewed directory. Legacy prose-generated
    // auto_check_packs are intentionally ignored.
    check_pack_registry
        .load_from_trusted_library_directory(
            &library,
            "reviewed_check_packs",
            30,
            &trusted_public_keys,
        )
        .map_err(|error| {
            DeviceEvaluationError::Internal(format!(
                "Failed to load reviewed generated check packs: {error}"
            ))
        })?;
    let packs: Vec<automatestig_core::checks::CheckPack> = check_pack_registry
        .check_packs_for_stig_release(stig_id, &release)
        .into_iter()
        .cloned()
        .collect();
    if packs.is_empty() {
        return Err(DeviceEvaluationError::MissingCheckPack(format!(
            "{stig_id} {release}"
        )));
    }
    let sha256 =
        automatestig_core::check_packs::canonical_json_sha256(&packs).map_err(|error| {
            DeviceEvaluationError::Internal(format!(
                "Failed to bind effective check-pack provenance: {error}"
            ))
        })?;
    let mut seen_vuln_ids = HashSet::new();
    let definitions = packs
        .iter()
        .flat_map(|pack| pack.checks.iter())
        .filter(|check| seen_vuln_ids.insert(check.vuln_id.clone()))
        .cloned()
        .collect();
    Ok(LoadedCheckPackSet {
        definitions,
        sha256,
    })
}

/// Evaluate collected SystemData against check packs and STIG benchmark.
fn evaluate_with_system_data(
    state: &AppState,
    stig_id: &str,
    hostname: &str,
    system_data: &automatestig_core::checks::SystemData,
    finding_source: FindingSource,
    provenance: EvaluationProvenance,
) -> Result<serde_json::Value, DeviceEvaluationError> {
    let checklist = evaluate_system_data_core(
        state,
        stig_id,
        hostname,
        system_data,
        finding_source,
        provenance,
    )?;

    let s = checklist.summary();
    let collection_complete = checklist
        .evaluation_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.collection_complete);
    let evaluation_errors = checklist
        .evaluation_provenance
        .as_ref()
        .map(|provenance| provenance.collection_errors.clone())
        .unwrap_or_default();
    let evaluated_findings: Vec<_> = checklist
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.source,
                FindingSource::Automated | FindingSource::Evidence | FindingSource::CollectionError
            )
        })
        .collect();
    Ok(serde_json::json!({
        "success": true,
        "data": {
            "id": collection_complete.then(|| checklist.id.to_string()),
            "hostname": hostname,
            "stig_id": stig_id,
            "total": s.total,
            "open": s.open,
            "not_a_finding": s.not_a_finding,
            "not_reviewed": s.not_reviewed,
            "assessed_pass_pct": defensible_score(&checklist, s.assessed_pass_pct()),
            "benchmark_coverage_pct": defensible_score(
                &checklist,
                s.benchmark_coverage_pct()
            ),
            // Deprecated compatibility alias for assessed_pass_pct.
            "compliance_pct": defensible_score(&checklist, s.assessed_pass_pct()),
            "collection_complete": collection_complete,
            "evaluation_errors": evaluation_errors,
            "persisted": collection_complete,
            "checks_executed": evaluated_findings.len(),
            "checks_passed": evaluated_findings
                .iter()
                .filter(|finding| finding.status == FindingStatus::NotAFinding)
                .count(),
        },
        "error": null,
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
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    let expected_platform = match platform_for_supported_stig(req.stig_id.trim()) {
        Ok(platform) => platform,
        Err(error) => return api_error(&error),
    };
    if let Some(asset) = assets
        .iter()
        .find(|asset| req.asset_ids.contains(&asset.id) && asset.platform != expected_platform)
    {
        return api_error(&format!(
            "Asset {} platform {:?} does not match STIG {} platform {:?}",
            asset.name, asset.platform, req.stig_id, expected_platform
        ));
    }
    let mut count = 0;
    for asset in assets.iter_mut() {
        if req.asset_ids.contains(&asset.id) && !asset.assigned_stigs.contains(&req.stig_id) {
            asset.assigned_stigs.push(req.stig_id.clone());
            count += 1;
        }
    }
    if let Err(error) = save_assets(&db, &assets) {
        return api_error(&error);
    }
    api_ok(serde_json::json!({ "assigned": count, "stig_id": req.stig_id }))
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

fn checklist_export_allowed(checklist: &Checklist) -> bool {
    checklist.external_export_block_reason().is_none()
}

async fn export_ckl(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let db = state.db();
    match db.load_checklist(&id) {
        Ok(cl) => {
            if !checklist_export_allowed(&cl) {
                return (
                    StatusCode::CONFLICT,
                    "Incomplete device evidence cannot be exported; recollect the target",
                )
                    .into_response();
            }
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
            if !checklist_export_allowed(&cl) {
                return (
                    StatusCode::CONFLICT,
                    "Incomplete device evidence cannot be exported; recollect the target",
                )
                    .into_response();
            }
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
    let rows = match db.list_checklists() {
        Ok(rows) => rows,
        Err(error) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to list checklists: {error}"),
            )
                .into_response();
        }
    };

    if rows.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "No checklists to export",
        )
            .into_response();
    }

    let data = match build_checklist_export_zip(&db, &rows) {
        Ok(data) => data,
        Err(error) => {
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, error).into_response();
        }
    };
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

fn build_checklist_export_zip(
    db: &automatestig_storage::Database,
    rows: &[automatestig_storage::ChecklistSummaryRow],
) -> Result<Vec<u8>, String> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for row in rows {
            let checklist = db
                .load_checklist(&row.id)
                .map_err(|error| format!("Failed to load checklist {}: {error}", row.id))?;
            if !checklist_export_allowed(&checklist) {
                return Err(format!(
                    "Checklist {} has incomplete device evidence and cannot be exported",
                    row.id
                ));
            }
            let filename = sanitize_filename(&format!(
                "{}_{}.ckl",
                checklist.asset.hostname, checklist.stig_info.stig_id
            ));
            let xml = ckl::write_ckl(&checklist)
                .map_err(|error| format!("Failed to serialize checklist {}: {error}", row.id))?;
            zip.start_file(&filename, options)
                .map_err(|error| format!("Failed to create ZIP entry: {error}"))?;
            std::io::Write::write_all(&mut zip, xml.as_bytes())
                .map_err(|error| format!("Failed to write ZIP entry: {error}"))?;
        }
        zip.finish()
            .map_err(|error| format!("Failed to finish export ZIP: {error}"))?;
    }
    Ok(buffer.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    use super::*;

    fn test_state() -> (tempfile::TempDir, AppState) {
        let temporary = tempfile::tempdir().unwrap();
        let library_path = temporary.path().join("library");
        automatestig_core::library::StigLibrary::init(&library_path).unwrap();
        let state = AppState {
            inner: Arc::new(crate::state::AppStateInner {
                db: Mutex::new(automatestig_storage::Database::in_memory().unwrap()),
                library_path,
                data_dir: temporary.path().to_path_buf(),
                content_import_lock: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            }),
        };
        (temporary, state)
    }

    #[test]
    fn offline_pack_refuses_to_launder_bare_executable_content() {
        let (_temporary, state) = test_state();
        std::fs::write(
            state.inner.library_path.join("custom_checks/bare.json"),
            br#"{"stig_id":"General_Purpose_Operating_System"}"#,
        )
        .unwrap();
        let library = state.library().unwrap();
        let builder = automatestig_stigpack::builder::PackBuilder::new("test", "Test", "1.0.0");
        let error = match add_trusted_executables_to_offline_pack(builder, &library, &[]) {
            Ok(_) => panic!("bare executable content must not be re-signed"),
            Err(error) => error,
        };
        assert!(error.contains("has no trusted signed provenance"));
    }

    fn multipart_part(boundary: &str, name: &str, value: &str) -> String {
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
    }

    fn multipart_evidence_part(boundary: &str, value: &str) -> String {
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"evidence\"; filename=\"evidence.json\"\r\nContent-Type: application/json\r\n\r\n{value}\r\n"
        )
    }

    async fn post_multipart(body: String, boundary: &str) -> Response {
        let (_temporary, state) = test_state();
        post_multipart_with_state(state, body, boundary).await
    }

    async fn post_multipart_with_state(state: AppState, body: String, boundary: &str) -> Response {
        routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/evaluate/with-evidence")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[test]
    fn test_sanitize_rejects_dot_components() {
        assert_ne!(sanitize_filename("."), ".");
        assert_ne!(sanitize_filename(".."), "..");
        assert_eq!(sanitize_filename("host.ckl"), "host.ckl");
    }

    #[test]
    fn stigman_assignment_failures_and_unsupported_targets_are_not_silenced() {
        let error =
            assigned_stig_ids("switch-01", Err("upstream timeout".to_string())).unwrap_err();
        assert!(error.contains("switch-01"));
        assert!(error.contains("upstream timeout"));

        assert!(target_platform_for_stigs(
            "switch-01",
            &["Cisco_IOS-XE_Router_NDM_STIG".to_string()]
        )
        .is_ok());
        assert!(target_platform_for_stigs("unknown-01", &["RHEL_9_STIG".to_string()]).is_err());
        assert!(target_platform_for_stigs("unassigned-01", &[]).is_err());
    }

    #[test]
    fn asset_assignments_are_bound_to_the_target_platform() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let mut asset = ManagedAsset::new("freebsd01", "192.0.2.10", CheckPlatform::Bsd);
        asset.assigned_stigs = vec!["General_Purpose_Operating_System".to_string()];
        assert!(validate_asset_assignments(&asset).is_ok());

        asset.assigned_stigs = vec!["NetApp_ONTAP_DSC_9-x_STIG".to_string()];
        assert!(validate_asset_assignments(&asset).is_err());
        asset.assigned_stigs = vec!["RHEL_9_STIG".to_string()];
        assert!(validate_asset_assignments(&asset).is_err());
    }

    #[test]
    fn claimed_hostname_binding_is_case_insensitive_and_asset_bound() {
        let mut submitted = "ACTUAL-ROUTER".to_string();
        assert!(bind_claimed_hostname(
            &mut submitted,
            "actual-router",
            Some("Actual-Router"),
            "configuration",
        )
        .is_ok());

        let error = bind_claimed_hostname(
            &mut submitted,
            "actual-router",
            Some("different-router"),
            "configuration",
        )
        .unwrap_err();
        assert!(error.contains("linked asset hostname"));
    }

    #[test]
    fn gui_policy_verification_is_signature_release_and_asset_bound() {
        let temporary = tempfile::tempdir().unwrap();
        let offline = temporary.path().join("offline");
        let trust = temporary.path().join("trust");
        std::fs::create_dir(&offline).unwrap();
        std::fs::create_dir(&trust).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&offline, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let private = offline.join("policy.key");
        let public = offline.join("policy.pub");
        let (private_key, _) =
            automatestig_stigpack::signing::create_signing_key_pair(&private, &public).unwrap();
        std::fs::copy(&public, trust.join("approver.pub")).unwrap();

        let now = chrono::Utc::now();
        let policy = serde_json::to_vec(&serde_json::json!({
            "schema": "automatestig-organization-policy/v1",
            "policy_id": "gui-test",
            "policy_version": "1",
            "stig_id": "Cisco_IOS-XE_Router_NDM_STIG",
            "stig_release": "V3R7",
            "asset_hostname": "router-01",
            "effective_from": (now - chrono::Duration::days(1)).to_rfc3339(),
            "expires_at": (now + chrono::Duration::days(1)).to_rfc3339(),
            "rules": {
                "V-215807": {"max_concurrent_management_sessions": 2},
                "V-215836": {"minimum_logging_buffer_bytes": 4096000}
            }
        }))
        .unwrap();
        let signature =
            automatestig_stigpack::signing::sign_manifest(&policy, &private_key).unwrap();
        let verified = verify_organization_policy_with_trust_dir(
            &trust,
            &policy,
            &signature,
            "Cisco_IOS-XE_Router_NDM_STIG",
            "V3R7",
            "ROUTER-01",
        )
        .unwrap();
        assert_eq!(verified.document().policy_id, "gui-test");

        let mut mutated = policy;
        mutated.push(b' ');
        assert!(verify_organization_policy_with_trust_dir(
            &trust,
            &mutated,
            &signature,
            "Cisco_IOS-XE_Router_NDM_STIG",
            "V3R7",
            "router-01",
        )
        .is_err());
    }

    #[test]
    fn imported_all_pass_checklist_scores_are_withheld() {
        let mut checklist = forged_automated_checklist();
        checklist.findings[0].source = FindingSource::Imported;
        checklist.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::ImportedChecklist,
            collection_complete: false,
            collection_errors: vec![
                "collection completeness is unknown for an imported checklist".to_string(),
            ],
            evidence_sha256: None,
            claimed_hostname: Some("device-01".to_string()),
            collector_version: None,
            collected_at: None,
            plan_sha256: None,
            server_key_fingerprint: None,
            benchmark_sha256: None,
            check_pack_sha256: None,
            evaluation_plan_sha256: None,
            organization_policy: None,
            unsafe_legacy_evidence: false,
        });

        let summary = checklist.summary();
        assert_eq!(summary.assessed_pass_pct(), 100.0);
        assert_eq!(summary.benchmark_coverage_pct(), 100.0);
        assert_eq!(
            defensible_score(&checklist, summary.assessed_pass_pct()),
            None
        );
        assert_eq!(
            defensible_score(&checklist, summary.benchmark_coverage_pct()),
            None
        );
    }

    #[tokio::test]
    async fn uploaded_evidence_missing_file_returns_bad_request() {
        let boundary = "automatestig-missing-evidence";
        let mut body = multipart_part(boundary, "stig_id", "TEST_STIG");
        body.push_str(&multipart_part(boundary, "hostname", "switch-01"));
        body.push_str(&multipart_part(boundary, "platform", "ontap"));
        body.push_str(&multipart_part(boundary, "input_type", "transcript"));
        body.push_str(&format!("--{boundary}--\r\n"));

        let response = post_multipart(body, boundary).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn uploaded_evidence_schema_failure_returns_unprocessable_entity() {
        let boundary = "automatestig-invalid-evidence";
        let mut body = multipart_part(boundary, "stig_id", "TEST_STIG");
        body.push_str(&multipart_part(boundary, "hostname", "switch-01"));
        body.push_str(&multipart_part(boundary, "platform", "ontap"));
        body.push_str(&multipart_part(boundary, "input_type", "transcript"));
        body.push_str(&multipart_evidence_part(boundary, "{}"));
        body.push_str(&format!("--{boundary}--\r\n"));

        let response = post_multipart(body, boundary).await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn uploaded_evidence_cannot_be_relabelled_to_another_host() {
        let boundary = "automatestig-host-mismatch";
        let mut body = multipart_part(boundary, "stig_id", "TEST_STIG");
        body.push_str(&multipart_part(boundary, "hostname", "different-device"));
        body.push_str(&multipart_part(boundary, "platform", "ontap"));
        body.push_str(&multipart_part(boundary, "input_type", "transcript"));
        body.push_str(&multipart_evidence_part(
            boundary,
            r#"{"schema":"automatestig-evidence/v2","hostname":"actual-device","platform":"ontap","collector_version":"test","collected_at":"2026-01-01T00:00:00Z","plan_sha256":"0000000000000000000000000000000000000000000000000000000000000000","complete":true,"commands":[{"data_key":"x","command":"x","status":"success","exit_code":0}]}"#,
        ));
        body.push_str(&format!("--{boundary}--\r\n"));

        let response = post_multipart(body, boundary).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn uploaded_configuration_cannot_be_relabelled_to_another_host() {
        let boundary = "automatestig-config-host-mismatch";
        let mut body = multipart_part(boundary, "stig_id", "Cisco_IOS-XE_Router_NDM_STIG");
        body.push_str(&multipart_part(boundary, "hostname", "different-router"));
        body.push_str(&multipart_part(boundary, "platform", "cisco_ios"));
        body.push_str(&multipart_part(boundary, "input_type", "config"));
        body.push_str(&multipart_evidence_part(
            boundary,
            "version 17.9\nhostname actual-router\nline vty 0 4\n transport input ssh\nend\n",
        ));
        body.push_str(&format!("--{boundary}--\r\n"));

        let response = post_multipart(body, boundary).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn uploaded_configuration_cannot_be_linked_to_another_asset_hostname() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let asset = ManagedAsset::new("inventory-router", "192.0.2.10", CheckPlatform::CiscoIos);
        let asset_id = asset.id.clone();
        save_assets(&state.db(), &[asset]).unwrap();

        let boundary = "automatestig-config-asset-host-mismatch";
        let mut body = multipart_part(boundary, "stig_id", "Cisco_IOS-XE_Router_NDM_STIG");
        body.push_str(&multipart_part(boundary, "hostname", "actual-router"));
        body.push_str(&multipart_part(boundary, "asset_id", &asset_id));
        body.push_str(&multipart_part(boundary, "platform", "cisco_ios"));
        body.push_str(&multipart_part(boundary, "input_type", "config"));
        body.push_str(&multipart_evidence_part(
            boundary,
            "version 17.9\nhostname actual-router\nline vty 0 4\n transport input ssh\nend\n",
        ));
        body.push_str(&format!("--{boundary}--\r\n"));

        let response = post_multipart_with_state(state.clone(), body, boundary).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(state.db().list_checklists().unwrap().is_empty());
        let assets = load_assets(&state.db()).unwrap();
        assert!(assets[0].last_evaluated.is_none());
        assert!(assets[0].last_checklist_ids.is_empty());
    }

    #[tokio::test]
    async fn uploaded_evidence_cannot_be_linked_to_another_asset_hostname() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let asset = ManagedAsset::new("inventory-node", "192.0.2.11", CheckPlatform::Ontap);
        let asset_id = asset.id.clone();
        save_assets(&state.db(), &[asset]).unwrap();

        let boundary = "automatestig-evidence-asset-host-mismatch";
        let mut body = multipart_part(boundary, "stig_id", "NetApp_ONTAP_DSC_9-x_STIG");
        body.push_str(&multipart_part(boundary, "hostname", "actual-node"));
        body.push_str(&multipart_part(boundary, "asset_id", &asset_id));
        body.push_str(&multipart_part(boundary, "platform", "ontap"));
        body.push_str(&multipart_part(boundary, "input_type", "transcript"));
        body.push_str(&multipart_evidence_part(
            boundary,
            r#"{"schema":"automatestig-evidence/v2","hostname":"actual-node","platform":"ontap","collector_version":"test","collected_at":"2026-01-01T00:00:00Z","plan_sha256":"0000000000000000000000000000000000000000000000000000000000000000","complete":true,"commands":[{"data_key":"x","command":"x","status":"success","exit_code":0}]}"#,
        ));
        body.push_str(&format!("--{boundary}--\r\n"));

        let response = post_multipart_with_state(state.clone(), body, boundary).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(state.db().list_checklists().unwrap().is_empty());
        let assets = load_assets(&state.db()).unwrap();
        assert!(assets[0].last_evaluated.is_none());
        assert!(assets[0].last_checklist_ids.is_empty());
    }

    #[tokio::test]
    async fn ssh_missing_json_field_returns_bad_request() {
        let (_temporary, state) = test_state();
        let response = routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scan/ssh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"host":"192.0.2.10","auth":{"type":"password","password":"secret"},"stig_id":"TEST_STIG"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ssh_missing_check_pack_returns_not_found_without_connecting() {
        let (_temporary, state) = test_state();
        let response = routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scan/ssh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"host":"192.0.2.10","username":"admin","auth":{"type":"password","password":"secret"},"stig_id":"NO_SUCH_TEST_STIG","platform":"ontap"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn ssh_rejects_cisco_ios_before_loading_content_or_connecting() {
        let (_temporary, state) = test_state();
        let response = routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scan/ssh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"host":"192.0.2.10","username":"admin","auth":{"type":"password","password":"secret"},"stig_id":"Cisco_IOS-XE_Router_NDM_STIG","platform":"cisco_ios"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn live_ssh_evidence_digest_binds_the_complete_canonical_transcript() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::remote::CommandEvidence;

        let report = automatestig_collector::CollectionReport {
            commands: vec![CommandEvidence::success(
                "system-data",
                "show system",
                "configured".to_string(),
                String::new(),
                0,
                12,
            )],
            server_key_fingerprint: Some(format!("SHA256:{}", "A".repeat(43))),
        };
        let transcript =
            live_ssh_evidence_transcript("device-01", CheckPlatform::Ontap, "a".repeat(64), report);
        assert_eq!(transcript.hostname.as_deref(), Some("device-01"));
        assert_eq!(transcript.platform, Some(CheckPlatform::Ontap));
        assert_eq!(transcript.plan_sha256, Some("a".repeat(64)));
        assert_eq!(
            transcript.server_key_fingerprint,
            Some(format!("SHA256:{}", "A".repeat(43)))
        );
        assert!(transcript.collected_at.is_some());

        let digest = automatestig_core::check_packs::canonical_json_sha256(&transcript).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            digest,
            automatestig_core::check_packs::canonical_json_sha256(&transcript).unwrap()
        );

        for mutation in 0..7 {
            let mut changed = transcript.clone();
            match mutation {
                0 => changed.hostname = Some("device-02".to_string()),
                1 => changed.platform = Some(CheckPlatform::Bsd),
                2 => changed.plan_sha256 = Some("b".repeat(64)),
                3 => changed.server_key_fingerprint = Some(format!("SHA256:{}", "B".repeat(43))),
                4 => changed.collected_at = Some("2026-01-01T00:00:00Z".to_string()),
                5 => changed.collector_version = Some("different-collector".to_string()),
                6 => changed.commands[0].stdout = "different observation".to_string(),
                _ => unreachable!(),
            }
            assert_ne!(
                digest,
                automatestig_core::check_packs::canonical_json_sha256(&changed).unwrap(),
                "mutation {mutation} was not bound"
            );
        }
    }

    fn forged_automated_checklist() -> Checklist {
        use automatestig_core::models::checklist::ChecklistStigInfo;
        use automatestig_core::models::finding::Finding;

        let mut checklist = Checklist::new(
            Asset::new("device-01"),
            ChecklistStigInfo {
                stig_id: "TEST_STIG".to_string(),
                title: "Test".to_string(),
                version: "1".to_string(),
                release: "1".to_string(),
                release_date: None,
                uuid: None,
                description: None,
                filename: None,
            },
        );
        checklist.generated_by = "Forged AutomateSTIG".to_string();
        let mut finding =
            Finding::new_not_reviewed("V-1", "SV-1r1_rule", "V-1", "Test", Severity::High);
        finding.status = FindingStatus::NotAFinding;
        finding.source = FindingSource::Automated;
        checklist.findings.push(finding);
        checklist
    }

    #[tokio::test]
    async fn json_import_cannot_forge_automated_attribution() {
        let (_temporary, state) = test_state();
        let checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        let boundary = "automatestig-forged-checklist";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"forged.json\"\r\nContent-Type: application/json\r\n\r\n{}\r\n--{boundary}--\r\n",
            serde_json::to_string(&checklist).unwrap()
        );
        let response = routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/checklists/import")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(payload["data"]["assessed_pass_pct"].is_null());
        assert!(payload["data"]["benchmark_coverage_pct"].is_null());
        assert!(payload["data"]["compliance_pct"].is_null());

        let stored = state.db().load_checklist(&id).unwrap();
        assert_eq!(stored.findings[0].source, FindingSource::Imported);
        assert_eq!(
            stored.evaluation_provenance.as_ref().unwrap().origin,
            EvaluationOrigin::ImportedChecklist
        );
        assert!(!crate::stigman::StigManagerClient::checklist_to_reviews(&stored)[0].auto_result);
    }

    #[tokio::test]
    async fn incomplete_evaluation_json_cannot_be_laundered_through_import() {
        let (_temporary, state) = test_state();
        let mut checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        checklist.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::EvidenceFile,
            collection_complete: false,
            collection_errors: vec!["show config: timeout".to_string()],
            evidence_sha256: Some("00".repeat(32)),
            claimed_hostname: Some("device-01".to_string()),
            collector_version: Some("test".to_string()),
            collected_at: Some("2026-01-01T00:00:00Z".to_string()),
            plan_sha256: Some("11".repeat(32)),
            server_key_fingerprint: None,
            benchmark_sha256: None,
            check_pack_sha256: None,
            evaluation_plan_sha256: None,
            organization_policy: None,
            unsafe_legacy_evidence: false,
        });
        let boundary = "automatestig-incomplete-checklist";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"incomplete.json\"\r\nContent-Type: application/json\r\n\r\n{}\r\n--{boundary}--\r\n",
            serde_json::to_string(&checklist).unwrap()
        );
        let response = routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/checklists/import")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload.get("success").and_then(|value| value.as_bool()),
            Some(false)
        );
        assert!(state.db().load_checklist(&id).is_err());
    }

    #[tokio::test]
    async fn evidence_only_manual_edit_clears_automated_attribution() {
        let (_temporary, state) = test_state();
        let checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        state
            .db()
            .save_evaluation(&checklist, "test", None)
            .unwrap();
        let response = routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/checklists/{id}/findings/V-1"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"finding_details":"reviewer changed evidence"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let stored = state.db().load_checklist(&id).unwrap();
        assert_eq!(stored.findings[0].source, FindingSource::Manual);
        assert!(!crate::stigman::StigManagerClient::checklist_to_reviews(&stored)[0].auto_result);
    }
}
