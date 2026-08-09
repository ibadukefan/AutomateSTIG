//! REST API endpoints for the GUI.

use std::collections::HashSet;
use std::path::Path;

use axum::body::Bytes;
use axum::extract::{Multipart, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use automatestig_core::library::{
    BenchmarkImport, GeneratedCheckPackIntent, OfflinePackContentSnapshot,
};
use automatestig_core::models::asset::Asset;
use automatestig_core::models::checklist::{
    AnswerFileProvenance, Checklist, EvaluationOrigin, EvaluationProvenance,
    OrganizationPolicyProvenance,
};
use automatestig_core::models::finding::{FindingSource, FindingStatus, FindingSummary};
use automatestig_core::models::stig::Severity;
use automatestig_parsers::{ckl, cklb, disa};

use crate::state::AppState;

/// Build the API router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/v1", crate::scanner_api::routes())
        .route("/status", get(get_status))
        .route("/auth/check", get(auth_check))
        .merge(retired_legacy_surface_routes())
}

/// Extraction-free tombstones for the known pre-scanner GUI API. These routes
/// are deliberately explicit: an unknown `/v1` scanner route must remain a 404
/// and must never be mistaken for a retired legacy surface.
fn retired_legacy_surface_routes() -> Router<AppState> {
    Router::new()
        // Broad content/library management is owned by scanner releases.
        .route("/library/benchmarks", any(retired_broad_content_management))
        .route(
            "/library/benchmarks/{id}",
            any(retired_broad_content_management),
        )
        .route(
            "/library/import-disa",
            any(retired_broad_content_management),
        )
        .route(
            "/library/import-stigpack",
            any(retired_broad_content_management),
        )
        .route("/disa/available", any(retired_broad_content_management))
        .route("/disa/fetch", any(retired_broad_content_management))
        .route("/disa/fetch-all", any(retired_broad_content_management))
        .route("/disa/check-updates", any(retired_broad_content_management))
        .route("/offline-pack", any(retired_broad_content_management))
        .route(
            "/offline-pack/trust-key",
            any(retired_broad_content_management),
        )
        // STIG Manager owns portfolio, review, and inventory state.
        .route("/checklists", any(retired_stig_manager_portfolio_mutation))
        .route(
            "/checklists/import",
            any(retired_stig_manager_portfolio_mutation),
        )
        .route(
            "/checklists/{id}",
            any(retired_stig_manager_portfolio_mutation),
        )
        .route(
            "/checklists/{id}/findings/{vuln_id}",
            any(retired_stig_manager_review_mutation),
        )
        .route("/assets", any(retired_stig_manager_inventory_mutation))
        .route(
            "/assets/bulk-assign-stig",
            any(retired_stig_manager_inventory_mutation),
        )
        .route(
            "/assets/bulk-update",
            any(retired_stig_manager_inventory_mutation),
        )
        .route("/assets/{id}", any(retired_stig_manager_inventory_mutation))
        .route("/answer-files", any(retired_stig_manager_review_mutation))
        .route(
            "/answer-files/{id}",
            any(retired_stig_manager_review_mutation),
        )
        .route("/audit-log", any(retired_stig_manager_portfolio_mutation))
        .route(
            "/export/ckl/{id}",
            any(retired_stig_manager_portfolio_mutation),
        )
        .route(
            "/export/cklb/{id}",
            any(retired_stig_manager_portfolio_mutation),
        )
        .route(
            "/export/all-zip",
            any(retired_stig_manager_portfolio_mutation),
        )
        // The old connection and scan paths bypassed the versioned contract.
        .route("/stigman/config", any(retired_scanner_v1_bypass))
        .route("/stigman/test", any(retired_scanner_v1_bypass))
        .route("/stigman/collections", any(retired_scanner_v1_bypass))
        .route(
            "/stigman/collections/{cid}/assets",
            any(retired_scanner_v1_bypass),
        )
        .route(
            "/stigman/sync/{cid}",
            any(retired_stig_manager_inventory_mutation),
        )
        .route(
            "/stigman/diff/{cid}",
            any(retired_stig_manager_inventory_mutation),
        )
        .route(
            "/stigman/push/{checklist_id}",
            any(retired_scanner_v1_bypass),
        )
        .route("/evaluate/with-evidence", any(retired_scanner_v1_bypass))
        .route("/scan/ssh", any(retired_scanner_v1_bypass))
}

/// Keep every retired implementation compiled behind an internal reference
/// router without exposing it from the application router. Unit tests use this
/// seam to preserve parser, migration, and export coverage while the runtime is
/// scanner-only.
#[allow(dead_code)]
fn legacy_reference_routes() -> Router<AppState> {
    Router::new()
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
        .route("/checklists", get(list_checklists))
        .route(
            "/checklists/{id}",
            get(get_checklist).delete(delete_checklist),
        )
        .route("/checklists/import", post(import_checklist))
        .route("/disa/available", get(disa_list_available))
        .route("/disa/fetch", post(disa_fetch))
        .route("/disa/fetch-all", post(disa_fetch_all))
        .route("/disa/check-updates", get(disa_check_updates))
        .route("/offline-pack", get(generate_offline_pack))
        .route("/offline-pack/trust-key", get(download_offline_trust_key))
        .route(
            "/stigman/config",
            get(stigman_get_config)
                .post(stigman_set_config)
                .delete(stigman_delete_config),
        )
        .route("/stigman/test", post(stigman_test_connection))
        .route("/stigman/collections", get(stigman_list_collections))
        .route(
            "/stigman/collections/{cid}/assets",
            get(stigman_list_assets),
        )
        .route("/stigman/sync/{cid}", post(stigman_sync_assets))
        .route("/stigman/diff/{cid}", get(stigman_diff_assets))
        .route("/stigman/push/{checklist_id}", post(stigman_push_checklist))
        .route("/evaluate/with-evidence", post(evaluate_with_evidence))
        .route("/scan/ssh", post(scan_ssh))
        .route(
            "/checklists/{id}/findings/{vuln_id}",
            axum::routing::patch(update_finding),
        )
        .route("/assets", get(list_assets_inv).post(create_asset_inv))
        .route(
            "/assets/{id}",
            get(get_asset_inv)
                .put(update_asset_inv)
                .delete(delete_asset_inv),
        )
        .route("/assets/bulk-assign-stig", post(bulk_assign_stig))
        .route("/assets/bulk-update", post(bulk_update_assets))
        .route(
            "/answer-files",
            get(list_answer_files).post(save_answer_file),
        )
        .route(
            "/answer-files/{id}",
            get(get_answer_file).put(replace_answer_file),
        )
        .route("/audit-log", get(list_audit_log))
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

pub(crate) fn verify_organization_policy(
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
    snapshot: &OfflinePackContentSnapshot,
) -> Result<automatestig_stigpack::builder::PackBuilder, String> {
    for file in snapshot.custom_checks() {
        let path = file.relative_path.to_string_lossy().replace('\\', "/");
        builder = builder.add_file_bytes(&path, &file.bytes);
    }

    // Never re-sign legacy local auto_check_packs. Only bytes whose retained
    // signed provenance still verifies are eligible for offline re-packaging.
    for file in snapshot.reviewed_check_packs() {
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

fn retired_surface_response(
    owner: &str,
    surface: &str,
    guidance: &str,
    read_only_migration_access: bool,
) -> Response {
    api_response(
        StatusCode::GONE,
        Some(serde_json::json!({
            "code": "legacy_surface_retired",
            "retired": true,
            "surface": surface,
            "owner": owner,
            "read_only_migration_access": read_only_migration_access,
            "guidance": guidance,
        })),
        Some(guidance),
    )
}

async fn retired_stig_manager_inventory_mutation() -> Response {
    retired_surface_response(
        "STIG Manager",
        "asset inventory and assignment management",
        "This legacy AutomateSTIG operation is retired. STIG Manager owns assets, assignments, labels, and inventory comparison. Select an existing STIG Manager asset with its exact assigned revision through /api/v1; AutomateSTIG will scan it without creating or synchronizing a local shadow inventory.",
        false,
    )
}

async fn retired_stig_manager_review_mutation() -> Response {
    retired_surface_response(
        "STIG Manager",
        "human review and answer management",
        "This legacy AutomateSTIG operation is retired. STIG Manager owns human findings, answers, comments, and review workflow. AutomateSTIG only delivers scanner-owned sparse results through /api/v1 and never overwrites human review content.",
        false,
    )
}

async fn retired_stig_manager_portfolio_mutation() -> Response {
    retired_surface_response(
        "STIG Manager",
        "checklist portfolio and reporting",
        "This legacy AutomateSTIG operation is retired. STIG Manager owns checklist portfolio lifecycle, history, dashboards, exports, and reporting. Use /api/v1/runs for scanner results and download a scanner handoff when remote state must be reconciled.",
        false,
    )
}

async fn retired_broad_content_management() -> Response {
    retired_surface_response(
        "AutomateSTIG scanner release process",
        "broad DISA catalog import and update",
        "This broad DISA catalog operation is retired. Scanner content is limited to pinned, reviewed target profiles exposed by /api/v1/profiles; use the signed scanner-content release process instead of importing or updating an unrestricted DISA portfolio in the GUI.",
        false,
    )
}

async fn retired_scanner_v1_bypass() -> Response {
    retired_surface_response(
        "AutomateSTIG scanner run service",
        "legacy connection, collection, evaluation, or STIG Manager push",
        "This legacy operation bypassed the versioned scanner contract, immutable runs, exact destination bindings, sparse ownership checks, or the durable delivery outbox, so it is retired. Use Scan or the /api/v1 connection, preflight, run, handoff, and delivery endpoints.",
        false,
    )
}

fn api_response_ok_with_etag(data: impl Serialize, etag: &str) -> Response {
    let mut response = api_response_ok(data);
    if let Ok(value) = HeaderValue::from_str(&format!("\"{etag}\"")) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    response
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    benchmark_count: usize,
    checklist_count: usize,
    offline_pack_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    offline_pack_unavailable_reason: Option<String>,
}

async fn get_status(State(state): State<AppState>) -> Response {
    let benchmark_count = match state.library() {
        Ok(library) => library.list_benchmarks().len(),
        Err(error) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read benchmark library: {error}"),
            )
        }
    };
    let checklist_count = match state.db().list_checklists() {
        Ok(checklists) => checklists.len(),
        Err(error) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read checklist database: {error}"),
            )
        }
    };

    let (offline_pack_available, offline_pack_unavailable_reason) = offline_pack_capability(&state);
    api_response_ok(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        benchmark_count,
        checklist_count,
        offline_pack_available,
        offline_pack_unavailable_reason,
    })
}

async fn auth_check() -> Response {
    api_response_ok(serde_json::json!({ "authenticated": true }))
}

/// Report whether the read-only GUI may invoke the external signing workflow
/// without disclosing key material or host filesystem paths through the
/// unauthenticated status endpoint.
fn offline_pack_capability(state: &AppState) -> (bool, Option<String>) {
    if std::env::var_os("AUTOMATESTIG_OFFLINE_SIGNING_KEY").is_none() {
        return (
            false,
            Some("External offline signing is not configured on this host.".to_string()),
        );
    }
    match load_external_offline_signing_key(state) {
        Ok(_) => (true, None),
        Err(_) => (
            false,
            Some("The configured external offline signing key could not be validated.".to_string()),
        ),
    }
}

// ---------------------------------------------------------------------------
// Library
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BenchmarkInfo {
    id: String,
    title: String,
    version: String,
    release: String,
    platform: String,
    rule_count: usize,
    imported_at: Option<String>,
    cat_i: usize,
    cat_ii: usize,
    cat_iii: usize,
    scanner_ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner_blocked_reason: Option<String>,
}

fn benchmark_scanner_readiness(
    benchmark: &automatestig_core::models::stig::StigBenchmark,
    registry: Option<&automatestig_core::check_packs::CheckPackRegistry>,
) -> (bool, Option<String>) {
    if platform_for_supported_stig(&benchmark.id).is_err() {
        return (
            false,
            Some("This benchmark is installed as reference content only.".to_string()),
        );
    }
    let Some(registry) = registry else {
        return (
            false,
            Some(
                "Scanner readiness could not be verified. Review the server logs and trusted content configuration."
                    .to_string(),
            ),
        );
    };
    match check_pack_set_for_benchmark(registry, benchmark) {
        Ok(pack) if !pack.definitions.is_empty() => (true, None),
        Ok(_) => (
            false,
            Some(format!(
                "No executable checks are available for {} {}.",
                benchmark.id,
                benchmark.version_string()
            )),
        ),
        Err(DeviceEvaluationError::MissingCheckPack(_)) => (
            false,
            Some(format!(
                "No trusted check pack matches exact release {} {}. This installed revision is reference-only.",
                benchmark.id,
                benchmark.version_string()
            )),
        ),
        Err(DeviceEvaluationError::IncompatibleCheckPack { .. }) => (
            false,
            Some(format!(
                "The trusted check pack does not match the rule set installed for {} {}. This revision is reference-only until matching content is installed.",
                benchmark.id,
                benchmark.version_string()
            )),
        ),
        Err(DeviceEvaluationError::MissingBenchmark(_)) => (
            false,
            Some("The benchmark content could not be loaded for assessment.".to_string()),
        ),
        Err(DeviceEvaluationError::Internal(_)) => (
            false,
            Some(
                "Scanner readiness could not be verified. Review the server logs and trusted content configuration."
                    .to_string(),
            ),
        ),
    }
}

async fn list_benchmarks(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.library() {
        Ok(library) => {
            // Trust-store and executable-content discovery are request-wide,
            // not repeated once per installed benchmark.
            let check_pack_registry = load_effective_check_pack_registry(&state).ok();
            let benchmarks = library
                .list_benchmarks()
                .iter()
                .map(|b| {
                    let full = library.load_benchmark(&b.id)?;
                    let imported_at = std::fs::metadata(library.root().join(&b.data_path))
                        .and_then(|metadata| metadata.modified())
                        .ok()
                        .map(chrono::DateTime::<chrono::Utc>::from)
                        .map(|timestamp| timestamp.to_rfc3339());
                    let (scanner_ready, scanner_blocked_reason) =
                        benchmark_scanner_readiness(&full, check_pack_registry.as_ref());
                    Ok(BenchmarkInfo {
                        id: b.id.clone(),
                        title: b.title.clone(),
                        version: full.version.clone(),
                        release: full.release.clone(),
                        platform: b.platform_family.clone(),
                        rule_count: b.rule_count,
                        imported_at,
                        cat_i: full.rules_by_severity(Severity::High).len(),
                        cat_ii: full.rules_by_severity(Severity::Medium).len(),
                        cat_iii: full.rules_by_severity(Severity::Low).len(),
                        scanner_ready,
                        scanner_blocked_reason,
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

fn defensible_scores(
    checklist: &Checklist,
    summary: &FindingSummary,
) -> (Option<f64>, Option<f64>) {
    let is_unverified_import = checklist
        .evaluation_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.origin == EvaluationOrigin::ImportedChecklist);
    if checklist.external_export_block_reason().is_some() || is_unverified_import {
        return (None, None);
    }

    (
        summary.assessed_pass_pct_opt(),
        Some(summary.benchmark_coverage_pct()),
    )
}

async fn list_checklists(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    match db.list_checklists() {
        Ok(rows) => {
            let mut infos = Vec::new();
            let mut warnings = Vec::new();
            for row in &rows {
                // Load full checklist for summary stats.
                match db.load_checklist(&row.id) {
                    Ok(cl) => {
                        let s = cl.summary();
                        let (assessed_pass_pct, benchmark_coverage_pct) =
                            defensible_scores(&cl, &s);
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
                        assessed_pass_pct,
                        benchmark_coverage_pct,
                        compliance_pct: assessed_pass_pct,
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
                    Err(error) => warnings.push(format!(
                        "Saved checklist {:?} for {:?} could not be loaded and remains preserved: {}",
                        row.id, row.asset_hostname, error
                    )),
                }
            }
            api_ok(serde_json::json!({
                "checklists": infos,
                "warnings": warnings,
            }))
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
    evaluated_at: String,
    evaluated_by: String,
}

async fn get_checklist(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let db = state.db();
    match db.load_checklist(&id) {
        Ok(cl) => {
            let s = cl.summary();
            let (assessed_pass_pct, benchmark_coverage_pct) = defensible_scores(&cl, &s);
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
                    evaluated_at: f.evaluated_at.to_rfc3339(),
                    evaluated_by: f.evaluated_by.clone(),
                })
                .collect();

            api_ok(ChecklistDetail {
                id: cl.id.to_string(),
                hostname: cl.asset.hostname,
                stig_id: cl.stig_info.stig_id,
                stig_title: cl.stig_info.title,
                stig_version: format!("V{}R{}", cl.stig_info.version, cl.stig_info.release),
                created_at: cl.created_at.to_rfc3339(),
                modified_at: cl.modified_at.to_rfc3339(),
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
) -> Response {
    let checklist_lock = state.inner.checklist_operation_locks.lock_for(&id);
    let _checklist_guard = checklist_lock.lock().await;
    let db = state.db();
    match db.delete_checklist(&id) {
        Ok(true) => match refresh_assets_after_checklist_deletion(&db, &id) {
            Ok(updated_assets) => api_response_ok(serde_json::json!({
                "deleted": true,
                "updated_assets": updated_assets,
            })),
            Err(error) => api_response(
                StatusCode::MULTI_STATUS,
                Some(serde_json::json!({
                    "deleted": true,
                    "updated_assets": 0,
                    "inventory_cleanup_warning": format!(
                        "Checklist {id} was deleted, but linked asset summaries could not be refreshed: {error}. The checklist is already deleted; do not retry deletion. Review the asset inventory before the next assessment."
                    ),
                })),
                None,
            ),
        },
        Ok(false) => api_response_error(
            StatusCode::NOT_FOUND,
            format!("Checklist {id} was not found"),
        ),
        Err(e) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete checklist: {e}"),
        ),
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
    let filename = field.file_name().unwrap_or("upload").to_string();
    let data = match field.bytes().await {
        Ok(data) => data,
        Err(error) => return api_error(&format!("Failed to read upload: {error}")),
    };
    let worker_state = state.clone();

    match tokio::task::spawn_blocking(move || {
        import_checklist_bytes(&worker_state, &filename, &data)
    })
    .await
    {
        Ok(response) => response,
        Err(error) => api_error(&format!("Checklist import worker failed: {error}")),
    }
}

fn import_checklist_bytes(
    state: &AppState,
    filename: &str,
    data: &[u8],
) -> Json<serde_json::Value> {
    let text = String::from_utf8_lossy(data);
    let ext = Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut checklist = match ext.as_str() {
        "ckl" => match ckl::parse_ckl(&text) {
            Ok(checklist) => checklist,
            Err(error) => return api_error(&format!("CKL parse error: {error}")),
        },
        "cklb" | "json" => match serde_json::from_str(&text) {
            Ok(checklist) => checklist,
            Err(_) => match cklb::parse_cklb(&text) {
                Ok(checklist) => checklist,
                Err(error) => return api_error(&format!("Parse error: {error}")),
            },
        },
        _ => return api_error(&format!("Unsupported format: .{ext}")),
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
    let claimed_checklist_id = checklist.id.to_string();
    checklist.id = uuid::Uuid::new_v4();
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
        evidence_sha256: Some(sha256_hex(data)),
        claimed_hostname: Some(checklist.asset.hostname.clone()),
        collector_version: None,
        collected_at: None,
        plan_sha256: None,
        server_key_fingerprint: None,
        benchmark_sha256: None,
        check_pack_sha256: None,
        evaluation_plan_sha256: None,
        organization_policy: None,
        answer_file: None,
        answer_files: Vec::new(),
        unsafe_legacy_evidence: false,
    });

    let summary = checklist.summary();
    let (assessed_pass_pct, benchmark_coverage_pct) = defensible_scores(&checklist, &summary);
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
        total: summary.total,
        open: summary.open,
        not_a_finding: summary.not_a_finding,
        not_applicable: summary.not_applicable,
        not_reviewed: summary.not_reviewed,
        assessed_pass_pct,
        benchmark_coverage_pct,
        compliance_pct: assessed_pass_pct,
        collection_complete: checklist
            .evaluation_provenance
            .as_ref()
            .map(|provenance| provenance.collection_complete),
        evaluation_origin: checklist
            .evaluation_provenance
            .as_ref()
            .map(|provenance| provenance.origin),
        cat_i_open: summary.cat_i_open,
        cat_ii_open: summary.cat_ii_open,
        cat_iii_open: summary.cat_iii_open,
    };

    let db = state.db();
    if let Err(error) = db.save_checklist_with_audit(
        &checklist,
        "checklist.imported",
        "gui",
        Some(
            &serde_json::json!({
                "filename": filename,
                "sha256": sha256_hex(data),
                "claimed_checklist_id": claimed_checklist_id,
                "assigned_checklist_id": checklist.id.to_string(),
                "claimed_generated_by": claimed_generated_by,
                "automation_attribution_normalized": true
            })
            .to_string(),
        ),
    ) {
        return api_error(&format!("Failed to save: {error}"));
    }

    api_ok(info)
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
        Ok(result) => disa_fetch_all_result_response(result),
        Err(error) => api_response_error(StatusCode::BAD_GATEWAY, error),
    }
}

fn disa_fetch_all_result_response(result: crate::disa::FetchResult) -> Response {
    let status = if result.errors.is_empty() {
        StatusCode::OK
    } else {
        // Individual package failures do not erase packages that were imported
        // successfully. Keep the full structured result available to the GUI.
        StatusCode::MULTI_STATUS
    };
    match serde_json::to_value(result) {
        Ok(value) => api_response(status, Some(value), None),
        Err(error) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to serialize DISA fetch result: {error}"),
        ),
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
struct OfflinePackSigningConfig {
    private_key: [u8; 32],
    public_key: [u8; 32],
    trusted_public_keys: Vec<[u8; 32]>,
}

struct GeneratedOfflinePack {
    bytes: Vec<u8>,
    filename: String,
    key_fingerprint: String,
}

type OfflinePackTaskResult<T> = Result<T, (StatusCode, String)>;

fn load_offline_pack_signing_config(
    state: &AppState,
) -> OfflinePackTaskResult<OfflinePackSigningConfig> {
    let (private_key, public_key) = load_external_offline_signing_key(state)
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error))?;
    let trust_dir = trusted_content_keys_dir();
    let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
    trust_store
        .load_from_directory(&trust_dir)
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to load executable-content trust anchors from {}: {error}",
                    trust_dir.display()
                ),
            )
        })?;
    Ok(OfflinePackSigningConfig {
        private_key,
        public_key,
        trusted_public_keys: trust_store.public_keys(),
    })
}

fn build_offline_pack(
    snapshot: &OfflinePackContentSnapshot,
    config: &OfflinePackSigningConfig,
    generated_at: chrono::DateTime<chrono::Utc>,
) -> OfflinePackTaskResult<GeneratedOfflinePack> {
    if snapshot.benchmarks().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "No benchmarks in library to package".to_string(),
        ));
    }

    let date = generated_at.format("%Y%m%d").to_string();
    let version = generated_at.format("%Y.%m.%d").to_string();

    // Build a signed stigpack with all current library content.
    let mut builder = automatestig_stigpack::builder::PackBuilder::new(
        &format!("automatestig-offline-{date}"),
        "AutomateSTIG Offline Update",
        &version,
    )
    .author("AutomateSTIG")
    .description("Offline update package for air-gapped AutomateSTIG installations")
    .signing_key(config.private_key);

    for benchmark in snapshot.benchmarks() {
        let json = serde_json::to_vec_pretty(benchmark).map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize benchmark {}: {error}", benchmark.id),
            )
        })?;
        let pack_path = format!("benchmarks/{}.json", benchmark.id);
        builder = builder.add_file_bytes(&pack_path, &json);
    }

    for file in snapshot.answer_templates() {
        let pack_path = file
            .relative_path()
            .to_str()
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Answer-template path is not UTF-8: {}",
                        file.relative_path().display()
                    ),
                )
            })?
            .replace('\\', "/");
        builder = builder.add_file_bytes(&pack_path, file.bytes());
    }

    builder = add_trusted_executables_to_offline_pack(builder, snapshot)
        .map_err(|error| (StatusCode::CONFLICT, error))?;

    let temporary = tempfile::NamedTempFile::new().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create temp file: {error}"),
        )
    })?;
    builder.build(temporary.path()).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to build pack: {error}"),
        )
    })?;
    let bytes = std::fs::read(temporary.path()).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to read pack: {error}"),
        )
    })?;
    Ok(GeneratedOfflinePack {
        bytes,
        filename: format!("automatestig-offline-{date}.stigpack"),
        key_fingerprint: automatestig_stigpack::signing::public_key_fingerprint(&config.public_key),
    })
}

async fn generate_offline_pack(State(state): State<AppState>) -> Response {
    let config_state = state.clone();
    let config =
        match tokio::task::spawn_blocking(move || load_offline_pack_signing_config(&config_state))
            .await
        {
            Ok(Ok(config)) => config,
            Ok(Err((status, error))) => return (status, error).into_response(),
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Offline-pack configuration worker failed: {error}"),
                )
                    .into_response()
            }
        };

    let permit = match state
        .inner
        .content_import_lock
        .clone()
        .acquire_owned()
        .await
    {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Content import coordinator is unavailable",
            )
                .into_response()
        }
    };
    let worker_state = state.clone();
    let generated = match tokio::task::spawn_blocking(move || {
        let snapshot = {
            // The application-level permit coordinates GUI imports while the
            // library guard inside the snapshot coordinates every process.
            // Drop both before the comparatively expensive ZIP/signing phase.
            let _permit = permit;
            let library = worker_state.library().map_err(|error| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Library error: {error}"),
                )
            })?;
            library
                .load_offline_pack_content_snapshot(&config.trusted_public_keys)
                .map_err(|error| {
                    (
                        StatusCode::CONFLICT,
                        format!("Failed to capture trusted offline content: {error}"),
                    )
                })?
        };
        build_offline_pack(&snapshot, &config, chrono::Utc::now())
    })
    .await
    {
        Ok(Ok(generated)) => generated,
        Ok(Err((status, error))) => return (status, error).into_response(),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Offline-pack build worker failed: {error}"),
            )
                .into_response()
        }
    };

    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", generated.filename),
            ),
            (
                axum::http::HeaderName::from_static("x-automatestig-signing-key"),
                generated.key_fingerprint,
            ),
        ],
        generated.bytes,
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
    Json(body): Json<crate::stigman::StigManagerConfig>,
) -> Json<serde_json::Value> {
    match persist_stigman_config(&state, body) {
        Ok(()) => api_ok("Configuration saved"),
        Err(error) => api_error(&error),
    }
}

/// Validate and encrypt a STIG Manager connection before persistence. The
/// scanner-first API and the transition endpoint share this exact secret
/// lifecycle so neither surface can accidentally serialize plaintext.
pub(crate) fn persist_stigman_config(
    state: &AppState,
    mut body: crate::stigman::StigManagerConfig,
) -> Result<(), String> {
    let db = state.db();
    normalize_stigman_config(&mut body);

    // An empty secret means "keep the saved secret", matching the password
    // placeholder in the UI. Loading/decryption errors are fatal so a corrupt
    // secret cannot be silently replaced with an empty value.
    if body.client_secret.is_empty() {
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(mut existing) => {
                normalize_stigman_config(&mut existing);
                if body.api_url != existing.api_url
                    || body.token_url != existing.token_url
                    || body.client_id != existing.client_id
                {
                    return Err(
                        "client_secret must be re-entered when an endpoint or client ID changes"
                            .to_string(),
                    );
                }
                body.client_secret = existing.client_secret;
            }
            Err(error) => return Err(error),
        }
    }
    body.validate_urls()?;

    // Encrypt the client secret before storing.
    if !body.client_secret.is_empty() {
        let key_material = match crate::secrets::load_or_create_key_material(&state.inner.data_dir)
        {
            Ok(k) => k,
            Err(e) => return Err(format!("Key material error: {e}")),
        };

        match crate::secrets::encrypt_secret(&body.client_secret, &key_material) {
            Ok(encrypted) => {
                body.client_secret = format!("enc:{}", encrypted);
            }
            Err(e) => return Err(format!("Encryption failed: {e}")),
        }
    }

    let json =
        serde_json::to_string(&body).map_err(|error| format!("Serialization error: {error}"))?;
    db.set_config("stigman_config", &json)
        .map_err(|error| format!("Failed to save config: {error}"))
}

/// Remove the saved STIG-Manager configuration, including its encrypted
/// client secret. This is deliberately idempotent so a repeated disconnect
/// request leaves the integration in the same unconfigured state.
async fn stigman_delete_config(State(state): State<AppState>) -> Response {
    let db = state.db();
    match db.delete_config("stigman_config") {
        Ok(deleted) => api_response_ok(serde_json::json!({
            "deleted": deleted,
            "configured": false,
        })),
        Err(error) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to remove STIG-Manager configuration: {error}"),
        ),
    }
}

pub(crate) fn normalize_stigman_config(config: &mut crate::stigman::StigManagerConfig) {
    config.api_url = config.api_url.trim().to_owned();
    config.token_url = config.token_url.trim().to_owned();
    config.client_id = config.client_id.trim().to_owned();
    config.default_collection_id = config
        .default_collection_id
        .take()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
}

/// Resolve either the saved configuration or an ephemeral, unsaved form value
/// for a connection test. A blank submitted secret may reuse the saved secret
/// only when the destination and OAuth client identity are unchanged.
pub(crate) fn resolve_stigman_test_config(
    state: &AppState,
    submitted: Option<crate::stigman::StigManagerConfig>,
) -> Result<crate::stigman::StigManagerConfig, String> {
    let saved = || load_stigman_config(&state.db(), &state.inner.data_dir);
    let Some(mut config) = submitted else {
        return saved();
    };

    normalize_stigman_config(&mut config);

    if config.client_secret.is_empty() {
        let saved = saved()?;
        let same_identity = config.api_url == saved.api_url.trim()
            && config.token_url == saved.token_url.trim()
            && config.client_id == saved.client_id.trim();
        if !same_identity || saved.client_secret.is_empty() {
            return Err(
                "client_secret is required to test unsaved endpoint or client-ID changes"
                    .to_string(),
            );
        }
        config.client_secret = saved.client_secret;
    }

    config.validate_endpoints()?;
    Ok(config)
}

/// Test STIG-Manager connection. An empty request body tests the saved
/// configuration; a JSON configuration body is tested in memory and is never
/// written to the database.
async fn stigman_test_connection(
    State(state): State<AppState>,
    body: Bytes,
) -> Json<serde_json::Value> {
    let submitted = if body.iter().all(u8::is_ascii_whitespace) {
        None
    } else {
        match serde_json::from_slice(&body) {
            Ok(config) => Some(config),
            Err(error) => {
                return api_error(&format!("Invalid STIG-Manager test configuration: {error}"))
            }
        }
    };
    let config = match resolve_stigman_test_config(&state, submitted) {
        Ok(config) => config,
        Err(error) => return api_error(&error),
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

    // Gather the complete remote update set before reading local inventory.
    // The network calls below may take long enough for a GUI edit to land, so
    // any snapshot taken here would be stale by the time it was saved.
    let mut updates = Vec::with_capacity(sm_assets.len());

    for sm_asset in &sm_assets {
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
        updates.push(StigmanAssetUpdate {
            name: sm_asset.name.clone(),
            ip: sm_asset.ip.clone(),
            fqdn: sm_asset.fqdn.clone(),
            description: sm_asset.description.clone(),
            assigned_stigs: stig_ids,
            platform: target_platform,
        });
    }

    let merge_result = {
        // Reload and merge while holding the same database guard through the
        // save. A concurrent GUI edit completed during remote I/O is therefore
        // part of this fresh inventory instead of being overwritten wholesale.
        let db = state.db();
        load_assets(&db).and_then(|mut local_assets| {
            let details = merge_stigman_asset_updates(&mut local_assets, &updates)?;
            save_assets(&db, &local_assets)?;
            Ok((local_assets.len(), details))
        })
    };
    let (total_assets, details) = match merge_result {
        Ok(result) => result,
        Err(error) => return api_error(&error),
    };

    api_ok(serde_json::json!({
        "synced": updates.len(),
        "total_assets": total_assets,
        "details": details,
    }))
}

#[derive(Debug)]
struct StigmanAssetUpdate {
    name: String,
    ip: Option<String>,
    fqdn: Option<String>,
    description: Option<String>,
    assigned_stigs: Vec<String>,
    platform: automatestig_core::checks::CheckPlatform,
}

fn nonempty_trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// STIG-Manager endpoint precedence is the same for new rows, updates, and
/// diff reporting: prefer its FQDN, then its IP, and otherwise retain/fall back
/// to the asset name.
fn stigman_preferred_address<'a>(fqdn: Option<&'a str>, ip: Option<&'a str>) -> Option<&'a str> {
    nonempty_trimmed(fqdn).or_else(|| nonempty_trimmed(ip))
}

fn stigman_asset_names_match(local: &str, remote: &str) -> bool {
    local.trim().eq_ignore_ascii_case(remote.trim())
}

fn merge_stigman_asset_updates(
    local_assets: &mut Vec<automatestig_core::inventory::assets::ManagedAsset>,
    updates: &[StigmanAssetUpdate],
) -> Result<Vec<String>, String> {
    let mut details = Vec::with_capacity(updates.len());

    for update in updates {
        let remote_name = update.name.trim();
        let existing = local_assets
            .iter()
            .position(|asset| stigman_asset_names_match(&asset.name, remote_name));

        if let Some(index) = existing {
            // Only STIG-Manager-owned fields are replaced. GUI-owned state such
            // as notes, tags, enablement, port, and evaluation history came
            // from the fresh inventory loaded under the database guard.
            let mut candidate = local_assets[index].clone();
            candidate.assigned_stigs = update.assigned_stigs.clone();
            candidate.platform = update.platform;
            if let Some(address) =
                stigman_preferred_address(update.fqdn.as_deref(), update.ip.as_deref())
            {
                candidate.address = address.to_string();
            }
            normalize_asset_for_write(&mut candidate);
            validate_asset_for_write(&candidate, local_assets, Some(&candidate.id))?;
            local_assets[index] = candidate;
            details.push(format!(
                "Updated: {} ({} STIGs)",
                remote_name,
                update.assigned_stigs.len()
            ));
        } else {
            let initial_address =
                stigman_preferred_address(update.fqdn.as_deref(), update.ip.as_deref())
                    .unwrap_or(remote_name);
            let mut candidate = automatestig_core::inventory::assets::ManagedAsset::new(
                remote_name,
                initial_address,
                update.platform,
            );
            candidate.assigned_stigs = update.assigned_stigs.clone();
            candidate.notes = update.description.clone();
            candidate.tags = vec!["stigman-sync".to_string()];
            normalize_asset_for_write(&mut candidate);
            validate_asset_for_write(&candidate, local_assets, None)?;
            local_assets.push(candidate);
            details.push(format!(
                "Created: {} ({} STIGs)",
                remote_name,
                update.assigned_stigs.len()
            ));
        }
    }

    Ok(details)
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

    // Asset names are the sync identity and are compared case-insensitively in
    // both diff and merge so a display-case change cannot appear as a delete +
    // create pair.
    let new_in_sm: Vec<&str> = sm_assets
        .iter()
        .filter(|remote| {
            !local_assets
                .iter()
                .any(|local| stigman_asset_names_match(&local.name, &remote.name))
        })
        .map(|asset| asset.name.as_str())
        .collect();

    // Assets local but not in SM.
    let removed_from_sm: Vec<&str> = local_assets
        .iter()
        .filter(|local| {
            local.tags.iter().any(|tag| tag == "stigman-sync")
                && !sm_assets
                    .iter()
                    .any(|remote| stigman_asset_names_match(&local.name, &remote.name))
        })
        .map(|asset| asset.name.as_str())
        .collect();

    // Assets in both — check for STIG assignment changes.
    let mut stig_changes = Vec::new();
    let mut address_changes = Vec::new();
    for sm_asset in &sm_assets {
        if let Some(local) = local_assets
            .iter()
            .find(|local| stigman_asset_names_match(&local.name, &sm_asset.name))
        {
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
            if let Some(stigman_address) =
                stigman_preferred_address(sm_asset.fqdn.as_deref(), sm_asset.ip.as_deref())
            {
                if !local.address.trim().eq_ignore_ascii_case(stigman_address) {
                    address_changes.push(serde_json::json!({
                        "asset": sm_asset.name,
                        "local_address": local.address,
                        "stigman_address": stigman_address,
                    }));
                }
            }
        }
    }

    let has_changes = !new_in_sm.is_empty()
        || !removed_from_sm.is_empty()
        || !stig_changes.is_empty()
        || !address_changes.is_empty();

    api_ok(serde_json::json!({
        "has_changes": has_changes,
        "new_assets_in_stigman": new_in_sm,
        "removed_from_stigman": removed_from_sm,
        "stig_assignment_changes": stig_changes,
        "address_changes": address_changes,
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

struct QueuedStigmanChecklistPush {
    checklist_id: String,
    hostname: String,
    revision: String,
}

struct LockedStigmanChecklistPush {
    checklist: Checklist,
    _remote_asset_guard: tokio::sync::OwnedMutexGuard<()>,
    _checklist_guard: tokio::sync::OwnedMutexGuard<()>,
}

fn checklist_revision(checklist: &Checklist) -> Result<String, String> {
    serde_json::to_vec(checklist)
        .map(|serialized| sha256_hex(&serialized))
        .map_err(|error| format!("Failed to calculate checklist revision: {error}"))
}

fn queue_stigman_checklist_push(
    state: &AppState,
    checklist_id: &str,
) -> Result<QueuedStigmanChecklistPush, String> {
    let checklist = state
        .db()
        .load_checklist(checklist_id)
        .map_err(|error| format!("Checklist not found: {error}"))?;
    Ok(QueuedStigmanChecklistPush {
        checklist_id: checklist_id.to_owned(),
        hostname: checklist.asset.hostname.clone(),
        revision: checklist_revision(&checklist)?,
    })
}

async fn lock_current_stigman_checklist_push(
    state: &AppState,
    collection_id: &str,
    queued: QueuedStigmanChecklistPush,
) -> Result<LockedStigmanChecklistPush, String> {
    // The remote lock comes first so local edits are not blocked behind another
    // potentially slow push to the same STIG Manager asset. Once that queue
    // clears, lock the checklist, reload it, and hold the guard until the
    // remote reviews have been written.
    let remote_asset_lock = state
        .inner
        .stigman_push_locks
        .lock_for(collection_id, &queued.hostname);
    let remote_asset_guard = remote_asset_lock.lock_owned().await;
    let checklist_lock = state
        .inner
        .checklist_operation_locks
        .lock_for(&queued.checklist_id);
    let checklist_guard = checklist_lock.lock_owned().await;
    let current = state
        .db()
        .load_checklist(&queued.checklist_id)
        .map_err(|error| {
            format!(
                "Checklist {} was deleted while its STIG-Manager push was queued: {error}",
                queued.checklist_id
            )
        })?;
    let current_revision = checklist_revision(&current)?;

    // Finding edits are safe: publish the freshly loaded revision while its
    // operation lock is held. A changed hostname would require a different
    // remote-asset lock, so fail closed and let the caller retry with that key.
    if current_revision != queued.revision
        && !current
            .asset
            .hostname
            .trim()
            .eq_ignore_ascii_case(queued.hostname.trim())
    {
        return Err(
            "Checklist asset identity changed while its STIG-Manager push was queued; retry the push"
                .to_string(),
        );
    }

    Ok(LockedStigmanChecklistPush {
        checklist: current,
        _remote_asset_guard: remote_asset_guard,
        _checklist_guard: checklist_guard,
    })
}

async fn stigman_push_checklist(
    State(state): State<AppState>,
    axum::extract::Path(checklist_id): axum::extract::Path<String>,
    Json(req): Json<PushRequest>,
) -> Json<serde_json::Value> {
    let queued = match queue_stigman_checklist_push(&state, &checklist_id) {
        Ok(queued) => queued,
        Err(error) => return api_error(&error),
    };

    let config = {
        let db = state.db();
        match load_stigman_config(&db, &state.inner.data_dir) {
            Ok(config) => config,
            Err(error) => return api_error(&error),
        }
    };

    let collection_id = req.collection_id.trim();
    if collection_id.is_empty() {
        return api_error("STIG-Manager collection ID is required");
    }

    // Keep the remote list-then-create sequence inside one per-asset critical
    // section. After that queue clears, refresh and lock the local checklist so
    // the published revision cannot race a finding edit or deletion.
    let locked = match lock_current_stigman_checklist_push(&state, collection_id, queued).await {
        Ok(locked) => locked,
        Err(error) => return api_error(&error),
    };

    match push_checklist_to_stigman(
        config,
        &locked.checklist,
        collection_id,
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

    // STIG Manager is the asset and assignment system of record. AutomateSTIG
    // never creates or implicitly selects an asset during result delivery.
    let asset_id = asset_id
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            "Select an existing STIG Manager asset. AutomateSTIG does not create or assign assets."
                .to_string()
        })?
        .to_string();

    let assigned = client
        .list_asset_stigs(collection_id, &asset_id)
        .await
        .map_err(|error| {
            format!("Failed to verify STIG assignments for asset {asset_id}: {error}")
        })?;
    let expected_revision = format!(
        "V{}R{}",
        checklist.stig_info.version, checklist.stig_info.release
    );
    ensure_stigman_asset_assignment(
        &asset_id,
        &checklist.stig_info.stig_id,
        &expected_revision,
        &assigned,
    )?;

    // Convert only scanner-owned determinations. Human, imported, answer-file,
    // collection-error, and untouched Not Reviewed rows stay in STIG Manager.
    let reviews = crate::stigman::StigManagerClient::checklist_to_reviews(checklist);
    if reviews.is_empty() {
        return Err(
            "This run contains no completed scanner-owned results to deliver to STIG Manager"
                .to_string(),
        );
    }
    let review_count = reviews.len();

    let existing = client
        .list_asset_reviews(collection_id, &asset_id)
        .await
        .map_err(|error| format!("Failed to inspect existing STIG Manager reviews: {error}"))?;
    let conflicts = crate::stigman::scanner_review_conflicts(&reviews, &existing);
    if !conflicts.is_empty() {
        let rule_ids = conflicts
            .iter()
            .take(10)
            .map(|conflict| conflict.rule_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "Delivery would overwrite {} human-owned or workflow-locked STIG Manager review(s): {rule_ids}. Resolve them in STIG Manager before retrying",
            conflicts.len()
        ));
    }

    // Push to STIG-Manager.
    let result = client
        .push_reviews(collection_id, &asset_id, reviews)
        .await
        .map_err(|error| stigman_review_push_error(&asset_id, &error))?;

    Ok(serde_json::json!({
        "pushed": review_count,
        "scanner_owned": review_count,
        "manual_untouched": checklist.findings.len().saturating_sub(review_count),
        "asset_id": asset_id,
        "collection_id": collection_id,
        "stig_id": checklist.stig_info.stig_id,
        "stig_revision": expected_revision,
        "result": result,
    }))
}

fn stigman_review_push_error(asset_id: &str, error: &str) -> String {
    format!(
        "Delivery failed for existing STIG Manager asset {asset_id}: {error}. The local scanner result is unchanged; retry delivery after the connection recovers"
    )
}

fn ensure_stigman_asset_assignment(
    asset_id: &str,
    stig_id: &str,
    expected_revision: &str,
    assigned: &[crate::stigman::SmStig],
) -> Result<(), String> {
    if let Some(assignment) = assigned.iter().find(|stig| stig.benchmark_id == stig_id) {
        match assignment.revision_str.as_deref() {
            Some(actual) if actual.eq_ignore_ascii_case(expected_revision) => return Ok(()),
            Some(actual) => {
                return Err(format!(
                    "STIG Manager asset {asset_id} is assigned {stig_id} {actual}, but this scanner result is {expected_revision}; align the exact revision in STIG Manager and retry"
                ))
            }
            None => {
                return Err(format!(
                    "STIG Manager did not report the assigned revision for {stig_id} on asset {asset_id}; delivery is blocked because exact content alignment cannot be verified"
                ))
            }
        }
    }
    Err(format!(
        "STIG-Manager asset {asset_id} is not assigned STIG {stig_id}; assign that STIG to the asset in this collection, then retry the push"
    ))
}

/// Load STIG-Manager config from the database, decrypting the client secret.
pub(crate) fn load_stigman_config(
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
    let mut answer_file_id: Option<String> = None;
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
            "answer_file_id" => {
                answer_file_id = match field.text().await {
                    Ok(value) if value.is_empty() => None,
                    Ok(value) => Some(value),
                    Err(error) => {
                        let (status, message) = multipart_error(error);
                        return api_response_error(
                            status,
                            format!("Invalid answer_file_id field: {message}"),
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
    answer_file_id = match canonical_answer_file_id(answer_file_id.as_deref()) {
        Ok(answer_file_id) => answer_file_id,
        Err(error) => return answer_file_selection_error_response(error),
    };
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
        if !asset.enabled {
            return api_response_error(StatusCode::CONFLICT, "Linked asset is disabled");
        }
        Some(asset.name.clone())
    } else {
        None
    };

    match input_type.as_str() {
        "config" if check_platform != automatestig_core::checks::CheckPlatform::CiscoIos => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "config input is supported only for Cisco platforms",
            );
        }
        "transcript" if check_platform == automatestig_core::checks::CheckPlatform::CiscoIos => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "Cisco IOS-XE is config-file-only; transcript input is unsupported",
            );
        }
        "config" | "transcript" => {}
        _ => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "input_type must be config or transcript",
            );
        }
    }
    let (system_data, mut provenance, evaluation_inputs) = if input_type == "config" {
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
        let evaluation_inputs =
            match load_evaluation_inputs(state.clone(), stig_id.clone(), answer_file_id.clone())
                .await
            {
                Ok(inputs) => inputs,
                Err(error) => return evaluation_input_load_error_response(error),
            };
        let checks = &evaluation_inputs.content.check_packs.definitions;
        if checks.first().map(|check| check.platform) != Some(check_platform) {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "selected platform does not match the installed check pack",
            );
        }
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
                &evaluation_inputs.content.benchmark.id,
                &evaluation_inputs.content.benchmark.version_string(),
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
                answer_file: None,
                answer_files: Vec::new(),
                unsafe_legacy_evidence: false,
            },
            evaluation_inputs,
        )
    } else if input_type == "transcript" {
        if organization_policy_data.is_some() || organization_policy_signature.is_some() {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "organization policy inputs are valid only for Cisco configuration evaluation",
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
        let evaluation_inputs =
            match load_evaluation_inputs(state.clone(), stig_id.clone(), answer_file_id.clone())
                .await
            {
                Ok(inputs) => inputs,
                Err(error) => return evaluation_input_load_error_response(error),
            };
        let checks = &evaluation_inputs.content.check_packs.definitions;
        if checks.first().map(|check| check.platform) != Some(check_platform) {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "selected platform does not match the installed check pack",
            );
        }
        let plan = match automatestig_core::remote::generate_collection_plan(check_platform, checks)
        {
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
                answer_file: None,
                answer_files: Vec::new(),
                unsafe_legacy_evidence: transcript.legacy,
            },
            evaluation_inputs,
        )
    } else {
        unreachable!("input type was validated before evidence processing")
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
        &evaluation_inputs.content,
        &hostname,
        &system_data,
        FindingSource::Evidence,
        provenance,
        evaluation_inputs.selected_answer_file.as_ref(),
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
            update_linked_asset_after_persist_or_warn(
                &mut response,
                &state.db(),
                aid,
                &stig_id,
                &hostname,
                AssetIdentityBinding::Name,
            );
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
    let checklist_lock = state.inner.checklist_operation_locks.lock_for(&id);
    let _checklist_guard = checklist_lock.lock().await;
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
        Some(json) => Ok(parse_asset_inventory(&json)?.assets),
        None => Ok(Vec::new()),
    }
}

#[derive(Debug, Default)]
struct ParsedAssetInventory {
    assets: Vec<automatestig_core::inventory::assets::ManagedAsset>,
    warnings: Vec<String>,
    quarantined: Vec<serde_json::Value>,
}

/// Decode inventory entries independently. Older releases supported platforms
/// which the hardened scanner intentionally no longer executes; those records
/// must not make every still-supported asset disappear from the GUI.
fn parse_asset_inventory(json: &str) -> Result<ParsedAssetInventory, String> {
    let records: Vec<serde_json::Value> = serde_json::from_str(json)
        .map_err(|error| format!("Failed to parse asset inventory: {error}"))?;
    let mut parsed = ParsedAssetInventory::default();

    for (index, original_record) in records.into_iter().enumerate() {
        // Alias migration is intentionally performed on a working copy. If a
        // later field fails to decode, quarantine the exact bytes-as-JSON
        // record the user had rather than a partially normalized derivative.
        let mut record = original_record.clone();
        let label = record
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| format!("asset {name:?}"))
            .unwrap_or_else(|| format!("inventory entry {}", index + 1));

        if let Some(platform) = record
            .get("platform")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .map(str::to_owned)
        {
            let canonical = match platform.to_ascii_lowercase().as_str() {
                "ontap" => Some("ontap"),
                "bsd" | "freebsd" => Some("bsd"),
                "cisco" | "cisco_ios" | "ciscoios" | "cisco-ios" => Some("cisco_ios"),
                _ => None,
            };
            let Some(canonical) = canonical else {
                parsed.warnings.push(format!(
                    "Ignored legacy {label}: platform {platform:?} is no longer a supported scanner target (supported: ontap, bsd, cisco_ios)."
                ));
                parsed.quarantined.push(original_record);
                continue;
            };
            record["platform"] = serde_json::Value::String(canonical.to_string());
        }

        match serde_json::from_value(record.clone()) {
            Ok(asset) => parsed.assets.push(asset),
            Err(error) => {
                parsed
                    .warnings
                    .push(format!("Ignored malformed {label}: {error}."));
                parsed.quarantined.push(original_record);
            }
        }
    }

    Ok(parsed)
}

fn save_assets(
    db: &automatestig_storage::Database,
    assets: &[automatestig_core::inventory::assets::ManagedAsset],
) -> Result<(), String> {
    let mut records = match serde_json::to_value(assets).map_err(|error| error.to_string())? {
        serde_json::Value::Array(records) => records,
        _ => return Err("Failed to serialize asset inventory as an array".to_string()),
    };
    // Preserve unsupported or malformed legacy records verbatim. They remain
    // quarantined from execution but recoverable for a future migration or
    // manual export instead of being silently destroyed by the next edit.
    if let Some(raw) = db
        .get_config("asset_inventory")
        .map_err(|error| error.to_string())?
    {
        records.extend(parse_asset_inventory(&raw)?.quarantined);
    }
    let json = serde_json::to_string(&records).map_err(|error| error.to_string())?;
    db.set_config("asset_inventory", &json)
        .map_err(|error| error.to_string())
}

/// Remove a deleted checklist from every linked inventory record and rebuild
/// the legacy latest-result fields from the newest checklist that remains.
/// The checklist deletion itself is durable before this repair begins, so any
/// error is surfaced to the caller as a partial success rather than inviting a
/// destructive retry.
fn refresh_assets_after_checklist_deletion(
    db: &automatestig_storage::Database,
    deleted_checklist_id: &str,
) -> Result<usize, String> {
    let mut assets = load_assets(db)?;
    let mut updated_assets = 0;

    for asset in &mut assets {
        if !asset
            .last_checklist_ids
            .iter()
            .any(|checklist_id| checklist_id == deleted_checklist_id)
        {
            continue;
        }

        let mut remaining_checklists = Vec::new();
        for checklist_id in std::mem::take(&mut asset.last_checklist_ids) {
            if checklist_id == deleted_checklist_id {
                continue;
            }
            match db.load_checklist(&checklist_id) {
                Ok(checklist) => remaining_checklists.push((checklist_id, checklist)),
                // Clean historical dangling references left by older versions
                // while this asset is already being repaired.
                Err(automatestig_storage::StorageError::NotFound(_)) => {}
                Err(error) => {
                    return Err(format!(
                        "remaining checklist {checklist_id:?} linked to asset {:?} could not be loaded: {error}",
                        asset.name
                    ))
                }
            }
        }
        remaining_checklists.sort_by(|(left_id, left), (right_id, right)| {
            left.modified_at
                .cmp(&right.modified_at)
                .then_with(|| left_id.cmp(right_id))
        });
        asset.last_checklist_ids = remaining_checklists
            .iter()
            .map(|(checklist_id, _)| checklist_id.clone())
            .collect();

        if let Some((_, latest)) = remaining_checklists.last() {
            asset.last_evaluated = Some(latest.modified_at);
            // Retained under the legacy field name for storage/API
            // compatibility; this is the assessed-control pass rate.
            asset.last_compliance_pct = latest.summary().assessed_pass_pct_opt();
        } else {
            asset.last_evaluated = None;
            asset.last_compliance_pct = None;
        }
        updated_assets += 1;
    }

    if updated_assets > 0 {
        save_assets(db, &assets)?;
    }
    Ok(updated_assets)
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

fn normalize_asset_for_write(asset: &mut automatestig_core::inventory::assets::ManagedAsset) {
    asset.id = asset.id.trim().to_owned();
    asset.name = asset.name.trim().to_owned();
    asset.address = asset.address.trim().to_owned();
    for tag in &mut asset.tags {
        *tag = tag.trim().to_owned();
    }
    asset.tags.retain(|tag| !tag.is_empty());
    asset.tags.sort();
    asset.tags.dedup();
    for stig_id in &mut asset.assigned_stigs {
        *stig_id = stig_id.trim().to_owned();
    }
    asset.assigned_stigs.retain(|stig_id| !stig_id.is_empty());
    asset.assigned_stigs.sort();
    asset.assigned_stigs.dedup();
}

fn validate_asset_for_write(
    candidate: &automatestig_core::inventory::assets::ManagedAsset,
    existing: &[automatestig_core::inventory::assets::ManagedAsset],
    replacing_id: Option<&str>,
) -> Result<(), String> {
    if candidate.id.is_empty() {
        return Err("Asset ID is required".to_string());
    }
    if candidate.name.is_empty() {
        return Err("Asset name is required".to_string());
    }
    if candidate.address.is_empty() {
        return Err("Asset address is required".to_string());
    }
    if candidate.port == Some(0) {
        return Err("Asset port must be between 1 and 65535".to_string());
    }
    validate_asset_assignments(candidate)?;

    let candidate_port = candidate.port.unwrap_or(22);
    for asset in existing
        .iter()
        .filter(|asset| replacing_id != Some(asset.id.as_str()))
    {
        if asset.id.eq_ignore_ascii_case(&candidate.id) {
            return Err(format!("An asset with ID {} already exists", candidate.id));
        }
        if asset.name.trim().eq_ignore_ascii_case(&candidate.name) {
            return Err(format!(
                "An asset named {:?} already exists",
                candidate.name
            ));
        }
        if asset
            .address
            .trim()
            .eq_ignore_ascii_case(&candidate.address)
            && asset.port.unwrap_or(22) == candidate_port
        {
            return Err(format!(
                "An asset already uses endpoint {}:{}",
                candidate.address, candidate_port
            ));
        }
    }
    Ok(())
}

/// After an evaluation, reflect the result on the linked asset (if any).
#[derive(Clone, Copy)]
enum AssetIdentityBinding {
    Name,
    Address,
}

fn update_asset_after_eval(
    db: &automatestig_storage::Database,
    asset_id: &str,
    stig_id: &str,
    evaluated_hostname: &str,
    identity_binding: AssetIdentityBinding,
    assessed_pass_pct: Option<f64>,
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
        let expected_identity = match identity_binding {
            AssetIdentityBinding::Name => &asset.name,
            AssetIdentityBinding::Address => &asset.address,
        };
        if !expected_identity
            .trim()
            .eq_ignore_ascii_case(evaluated_hostname.trim())
        {
            let label = match identity_binding {
                AssetIdentityBinding::Name => "hostname",
                AssetIdentityBinding::Address => "address",
            };
            return Err(format!(
                "Asset {} {label} does not match evaluated target {}",
                asset.name, evaluated_hostname,
            ));
        }
        asset.last_evaluated = Some(chrono::Utc::now());
        // Retained under the legacy inventory field name for storage/API
        // compatibility. The value is the assessed-control pass rate.
        asset.last_compliance_pct = assessed_pass_pct;
        if !asset.assigned_stigs.iter().any(|s| s == stig_id) {
            asset.assigned_stigs.push(stig_id.to_string());
        }
        if !asset.last_checklist_ids.iter().any(|c| c == checklist_id) {
            asset.last_checklist_ids.push(checklist_id.to_string());
        }
        save_assets(db, &assets)?;
        return Ok(());
    }
    Err(format!("Linked asset {asset_id} was not found"))
}

fn update_linked_asset_after_persist_or_warn(
    response: &mut serde_json::Value,
    db: &automatestig_storage::Database,
    asset_id: &str,
    stig_id: &str,
    evaluated_hostname: &str,
    identity_binding: AssetIdentityBinding,
) {
    let persisted_result = response.get("data").and_then(|data| {
        let assessed_pass_pct = match data.get("assessed_pass_pct")? {
            serde_json::Value::Null => None,
            value => Some(value.as_f64()?),
        };
        Some((assessed_pass_pct, data.get("id")?.as_str()?.to_owned()))
    });
    let Some((assessed_pass_pct, checklist_id)) = persisted_result else {
        return;
    };
    if let Err(error) = update_asset_after_eval(
        db,
        asset_id,
        stig_id,
        evaluated_hostname,
        identity_binding,
        assessed_pass_pct,
        &checklist_id,
    ) {
        if let Some(data) = response
            .get_mut("data")
            .and_then(serde_json::Value::as_object_mut)
        {
            data.insert(
                "asset_update_warning".to_owned(),
                serde_json::Value::String(format!(
                    "Checklist {checklist_id} was saved, but the linked asset summary could not be updated: {error}. Do not rerun the assessment solely for this warning."
                )),
            );
        }
    }
}

async fn list_assets_inv(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db();
    let raw = match db.get_config("asset_inventory") {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            return api_ok(serde_json::json!({
                "assets": [],
                "warnings": [],
            }))
        }
        Err(error) => return api_error(&error.to_string()),
    };
    match parse_asset_inventory(&raw) {
        Ok(parsed) => api_ok(serde_json::json!({
            "assets": parsed.assets,
            "warnings": parsed.warnings,
        })),
        Err(error) => api_error(&error),
    }
}

async fn create_asset_inv(
    State(state): State<AppState>,
    Json(mut asset): Json<automatestig_core::inventory::assets::ManagedAsset>,
) -> Json<serde_json::Value> {
    normalize_asset_for_write(&mut asset);
    let db = state.db();
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    if let Err(error) = validate_asset_for_write(&asset, &assets, None) {
        return api_error(&error);
    }
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
    Json(mut updated): Json<automatestig_core::inventory::assets::ManagedAsset>,
) -> Json<serde_json::Value> {
    normalize_asset_for_write(&mut updated);
    let id = id.trim();
    if updated.id != id {
        return api_error("Asset ID in the request body must match the URL");
    }
    let db = state.db();
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    if let Err(error) = validate_asset_for_write(&updated, &assets, Some(id)) {
        return api_error(&error);
    }
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
) -> Response {
    let db = state.db();
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => {
            return api_response_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to load asset inventory: {error}"),
            )
        }
    };
    if !assets.iter().any(|asset| asset.id == id) {
        return api_response_error(StatusCode::NOT_FOUND, format!("Asset {id} was not found"));
    }
    assets.retain(|a| a.id != id);
    if let Err(error) = save_assets(&db, &assets) {
        return api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save asset inventory: {error}"),
        );
    }
    api_response_ok(serde_json::json!({ "deleted": true }))
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

fn canonical_bulk_tag(value: Option<&str>, operation: &str) -> Result<Option<String>, String> {
    value
        .map(|tag| {
            let tag = tag.trim();
            if tag.is_empty() {
                Err(format!("{operation} tag cannot be blank"))
            } else {
                Ok(tag.to_string())
            }
        })
        .transpose()
}

async fn bulk_update_assets(
    State(state): State<AppState>,
    Json(req): Json<BulkUpdateRequest>,
) -> Json<serde_json::Value> {
    let add_tag = match canonical_bulk_tag(req.add_tag.as_deref(), "Added") {
        Ok(tag) => tag,
        Err(error) => return api_error(&error),
    };
    let remove_tag = match canonical_bulk_tag(req.remove_tag.as_deref(), "Removed") {
        Ok(tag) => tag,
        Err(error) => return api_error(&error),
    };
    let db = state.db();
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    let mut count = 0;

    for asset in assets.iter_mut() {
        if req.asset_ids.contains(&asset.id) {
            normalize_asset_for_write(asset);
            if let Some(enabled) = req.enabled {
                asset.enabled = enabled;
            }
            if let Some(ref tag) = add_tag {
                if !asset.tags.contains(tag) {
                    asset.tags.push(tag.clone());
                }
            }
            if let Some(ref tag) = remove_tag {
                asset.tags.retain(|t| t != tag);
            }
            normalize_asset_for_write(asset);
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

struct SelectedAnswerFile {
    id: String,
    answer_file: automatestig_core::answer::AnswerFile,
    sha256: String,
}

fn unknown_answer_vuln_ids(
    answer_file: &automatestig_core::answer::AnswerFile,
    benchmark: &automatestig_core::models::stig::StigBenchmark,
) -> Vec<String> {
    let benchmark_vuln_ids: HashSet<_> = benchmark
        .rules
        .iter()
        .map(|rule| rule.vuln_id.as_str())
        .collect();
    let mut unknown: Vec<_> = answer_file
        .entries
        .iter()
        .map(|entry| entry.vuln_id.as_str())
        .filter(|vuln_id| !benchmark_vuln_ids.contains(vuln_id))
        .map(str::to_owned)
        .collect();
    unknown.sort();
    unknown.dedup();
    unknown
}

#[derive(Debug)]
enum AnswerFileSelectionError {
    Invalid(String),
    NotFound(String),
    Internal(String),
}

fn answer_file_selection_error_response(error: AnswerFileSelectionError) -> Response {
    match error {
        AnswerFileSelectionError::Invalid(message) => {
            api_response_error(StatusCode::UNPROCESSABLE_ENTITY, message)
        }
        AnswerFileSelectionError::NotFound(message) => {
            api_response_error(StatusCode::NOT_FOUND, message)
        }
        AnswerFileSelectionError::Internal(message) => {
            api_response_error(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

/// Validate the untrusted identifier without touching the filesystem. Handlers
/// do this in their historical validation order, then defer all blocking
/// existence/content work to the coherent snapshot worker.
fn canonical_answer_file_id(
    answer_file_id: Option<&str>,
) -> Result<Option<String>, AnswerFileSelectionError> {
    let Some(answer_file_id) = answer_file_id else {
        return Ok(None);
    };
    if answer_file_id.is_empty() {
        return Ok(None);
    }
    if answer_file_id.trim() != answer_file_id {
        return Err(AnswerFileSelectionError::Invalid(
            "answer_file_id must be a canonical library filename".to_string(),
        ));
    }
    let safe_id =
        automatestig_core::path_safety::safe_filename(answer_file_id).map_err(|error| {
            AnswerFileSelectionError::Invalid(format!("Invalid answer_file_id: {error}"))
        })?;
    if safe_id != answer_file_id {
        return Err(AnswerFileSelectionError::Invalid(
            "answer_file_id must be a canonical library filename".to_string(),
        ));
    }
    Ok(Some(answer_file_id.to_string()))
}

fn selected_answer_file_from_snapshot(
    answer_file_id: &str,
    snapshot: &automatestig_core::library_content::AnswerTemplateSnapshot,
    benchmark: &automatestig_core::models::stig::StigBenchmark,
) -> Result<SelectedAnswerFile, AnswerFileSelectionError> {
    let extension = Path::new(answer_file_id)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    let answer_file = automatestig_core::answer::AnswerFile::from_bytes(&snapshot.bytes, extension)
        .map_err(|error| {
            AnswerFileSelectionError::Invalid(format!(
                "Failed to load answer file {answer_file_id:?}: {error}"
            ))
        })?;
    let validation_issues = answer_file.validate();
    if !validation_issues.is_empty() {
        return Err(AnswerFileSelectionError::Invalid(format!(
            "Answer file {answer_file_id:?} is invalid: {}",
            validation_issues.join("; ")
        )));
    }
    if answer_file
        .stig_id
        .as_deref()
        .is_some_and(|target| target != benchmark.id)
    {
        return Err(AnswerFileSelectionError::Invalid(format!(
            "Answer file {answer_file_id:?} targets {} rather than {}",
            answer_file.stig_id.as_deref().unwrap_or_default(),
            benchmark.id
        )));
    }
    let unknown_vuln_ids = unknown_answer_vuln_ids(&answer_file, benchmark);
    if !unknown_vuln_ids.is_empty() {
        return Err(AnswerFileSelectionError::Invalid(format!(
            "Answer file {answer_file_id:?} references unknown Vuln ID(s) for {}: {}",
            benchmark.id,
            unknown_vuln_ids.join(", ")
        )));
    }
    let sha256 =
        automatestig_core::check_packs::canonical_json_sha256(&answer_file).map_err(|error| {
            AnswerFileSelectionError::Internal(format!(
                "Failed to bind answer file {answer_file_id:?}: {error}"
            ))
        })?;
    Ok(SelectedAnswerFile {
        id: answer_file_id.to_string(),
        answer_file,
        sha256,
    })
}

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
        let mut warnings = Vec::new();
        for path in paths {
            let id = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| "Answer-template filename is not UTF-8".to_string())?;
            let snapshot =
                automatestig_core::library_content::read_answer_template_snapshot(
                    &library_path,
                    id,
                )
                .map_err(|error| {
                    format!("Failed to read answer template {id:?}: {error}")
                })?;
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            let af = match automatestig_core::answer::AnswerFile::from_bytes(
                &snapshot.bytes,
                extension,
            ) {
                Ok(answer_file) => answer_file,
                Err(error) => {
                    tracing::warn!("Failed to load answer template {}: {error}", path.display());
                    let replacement_name = path
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or(id);
                    let repairable = path.extension().and_then(|value| value.to_str())
                        == Some("json")
                        && automatestig_core::path_safety::safe_filename(replacement_name)
                            .ok()
                            .map(|name| format!("{}.json", name.to_lowercase()))
                            .as_deref()
                            == Some(id);
                    files.push(serde_json::json!({
                        "id": id,
                        "name": replacement_name,
                        "stig_id": serde_json::Value::Null,
                        "version": serde_json::Value::Null,
                        "entries": 0,
                        "editable": repairable,
                        "invalid": true,
                        "etag": snapshot.sha256,
                    }));
                    warnings.push(format!(
                        "Answer file {id:?} could not be loaded and remains preserved. {}",
                        if repairable {
                            "Select its Repair action to replace it with valid JSON, or review the server log."
                        } else {
                            "Repair this YAML template on the AutomateSTIG server filesystem or review the server log."
                        }
                    ));
                    continue;
                }
            };
            let editable = automatestig_core::path_safety::safe_filename(&af.name)
                .ok()
                .map(|name| format!("{}.json", name.to_lowercase()))
                .as_deref()
                == Some(id);
            files.push(serde_json::json!({
                "id": id,
                "name": af.name.clone(),
                "stig_id": af.stig_id.clone(),
                "version": af.version.clone(),
                "entries": af.entries.len(),
                "editable": editable,
                "invalid": false,
                "etag": snapshot.sha256,
            }));
        }
        Ok::<_, String>(serde_json::json!({
            "files": files,
            "warnings": warnings,
        }))
    })
    .await;

    match task {
        Ok(Ok(result)) => api_response_ok(result),
        Ok(Err(error)) => api_response_error(StatusCode::INTERNAL_SERVER_ERROR, error),
        Err(error) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Answer-template listing worker failed: {error}"),
        ),
    }
}

async fn get_answer_file(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let safe_id = match automatestig_core::path_safety::safe_filename(&id) {
        Ok(safe_id) if safe_id == id => safe_id,
        Ok(_) => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "Answer-file ID must be a canonical library filename",
            )
        }
        Err(error) => {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                format!("Invalid answer-file ID: {error}"),
            )
        }
    };
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
        let path = paths
            .into_iter()
            .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(safe_id.as_str()))
            .ok_or_else(|| format!("Answer file {safe_id:?} was not found"))?;
        let snapshot = automatestig_core::library_content::read_answer_template_snapshot(
            &library_path,
            &safe_id,
        )
        .map_err(|error| format!("Failed to read answer file {safe_id:?}: {error}"))?;
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let answer_file =
            automatestig_core::answer::AnswerFile::from_bytes(&snapshot.bytes, extension).map_err(
                |error| {
                    tracing::warn!("Failed to load answer template {}: {error}", path.display());
                    format!("Answer file {safe_id:?} could not be loaded; review the server log")
                },
            )?;
        Ok::<_, String>((answer_file, snapshot.sha256))
    })
    .await;

    match task {
        Ok(Ok((answer_file, etag))) => api_response_ok_with_etag(
            serde_json::json!({
                "answer_file": answer_file,
                "etag": etag,
            }),
            &etag,
        ),
        Ok(Err(error)) if error.contains("was not found") => {
            api_response_error(StatusCode::NOT_FOUND, error)
        }
        Ok(Err(error)) => api_response_error(StatusCode::UNPROCESSABLE_ENTITY, error),
        Err(error) => api_response_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Answer-file read worker failed: {error}"),
        ),
    }
}

async fn save_answer_file(
    State(state): State<AppState>,
    Json(af): Json<automatestig_core::answer::AnswerFile>,
) -> Response {
    persist_answer_file(state, af, None, None).await
}

async fn replace_answer_file(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(af): Json<automatestig_core::answer::AnswerFile>,
) -> Response {
    let expected_sha256 = match answer_file_if_match(&headers) {
        Ok(expected_sha256) => expected_sha256,
        Err((status, message)) => return api_response_error(status, message),
    };
    persist_answer_file(state, af, Some(id), Some(expected_sha256)).await
}

fn answer_file_if_match(headers: &HeaderMap) -> Result<String, (StatusCode, &'static str)> {
    let value = headers
        .get(axum::http::header::IF_MATCH)
        .ok_or((
            StatusCode::PRECONDITION_REQUIRED,
            "Answer-file replacement requires the current ETag. Close and reopen the editor to refresh the file before trying again.",
        ))?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "If-Match must contain one quoted SHA-256 ETag",
            )
        })?;
    let digest = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or((
            StatusCode::BAD_REQUEST,
            "If-Match must contain one quoted 64-character SHA-256 ETag",
        ))?;
    Ok(digest.to_ascii_lowercase())
}

async fn persist_answer_file(
    state: AppState,
    af: automatestig_core::answer::AnswerFile,
    replace_id: Option<String>,
    expected_sha256: Option<String>,
) -> Response {
    let validation_issues = af.validate();
    if !validation_issues.is_empty() {
        return api_response_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Invalid answer file: {}", validation_issues.join("; ")),
        );
    }
    if let Some(stig_id) = af.stig_id.as_deref() {
        let benchmark = match state
            .library()
            .and_then(|library| Ok(library.load_benchmark(stig_id)?))
        {
            Ok(benchmark) => benchmark,
            Err(error) => {
                return api_response_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("Cannot validate answer file against benchmark {stig_id}: {error}"),
                )
            }
        };
        let unknown_vuln_ids = unknown_answer_vuln_ids(&af, &benchmark);
        if !unknown_vuln_ids.is_empty() {
            return api_response_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "Answer file references unknown Vuln ID(s) for {stig_id}: {}",
                    unknown_vuln_ids.join(", ")
                ),
            );
        }
    }
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
    if let Some(id) = replace_id.as_deref() {
        let safe_id = match automatestig_core::path_safety::safe_filename(id) {
            Ok(safe_id) if safe_id == id => safe_id,
            Ok(_) => {
                return api_response_error(
                    StatusCode::BAD_REQUEST,
                    "Answer-file ID must be a canonical library filename",
                )
            }
            Err(error) => {
                return api_response_error(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid answer-file ID: {error}"),
                )
            }
        };
        if safe_id != filename {
            return api_response_error(
                StatusCode::CONFLICT,
                format!(
                    "The answer-file name maps to {filename:?}, not the selected file {safe_id:?}. Create a new file to use a different name."
                ),
            );
        }
    }
    let bytes = match serde_json::to_vec_pretty(&af) {
        Ok(bytes) => bytes,
        Err(error) => {
            return api_response_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Failed to serialize answer file: {error}"),
            )
        }
    };
    let saved_etag = sha256_hex(&bytes);
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
    let replace_existing = replace_id.is_some();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let result = if replace_existing {
            let expected_sha256 = expected_sha256.as_deref().ok_or_else(|| {
                (
                    StatusCode::PRECONDITION_REQUIRED,
                    "Answer-file replacement requires a current ETag; refresh the editor"
                        .to_string(),
                )
            })?;
            automatestig_core::library_content::replace_answer_template_atomic_if_match(
                &library_path,
                &task_filename,
                &bytes,
                expected_sha256,
            )
        } else {
            automatestig_core::library_content::write_answer_template_atomic_with_mode(
                &library_path,
                &task_filename,
                &bytes,
                automatestig_core::library_content::AnswerTemplateWriteMode::CreateNew,
            )
        };
        result.map_err(|error| {
            let status = match &error {
                automatestig_core::Error::Io(io_error)
                    if io_error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    StatusCode::CONFLICT
                }
                automatestig_core::Error::Io(io_error)
                    if io_error.kind() == std::io::ErrorKind::NotFound =>
                {
                    StatusCode::NOT_FOUND
                }
                automatestig_core::Error::IntegrityError { .. } => {
                    StatusCode::PRECONDITION_FAILED
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            let message = if status == StatusCode::CONFLICT {
                format!(
                    "Answer file {task_filename:?} already exists. Select it in Existing Files and confirm Replace instead."
                )
            } else if status == StatusCode::NOT_FOUND {
                format!("Answer file {task_filename:?} no longer exists; refresh the editor")
            } else if status == StatusCode::PRECONDITION_FAILED {
                format!(
                    "Answer file {task_filename:?} changed after you opened it. Close and reopen the editor, review the latest values, then apply your edits again; nothing was overwritten."
                )
            } else {
                error.to_string()
            };
            (status, message)
        })
    })
    .await;

    match task {
        Ok(Ok(_path)) => api_response_ok(serde_json::json!({
            "saved": true,
            "id": filename,
            "entries": entry_count,
            "etag": saved_etag,
            "validation_issues": validation_issues,
        })),
        Ok(Err((status, error))) => {
            api_response_error(status, format!("Failed to save answer file: {error}"))
        }
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
    asset_id: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    answer_file_id: Option<String>,
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
    let linked_asset_id = match req.asset_id.as_deref() {
        Some(value) if value.trim().is_empty() => {
            return api_response_error(StatusCode::BAD_REQUEST, "asset_id must not be blank")
        }
        Some(value) => Some(value.trim().to_owned()),
        None => None,
    };

    let ssh_config = crate::ssh::SshConfig {
        host: req.host.trim().to_owned(),
        port: req.port.unwrap_or(22),
        username: req.username.trim().to_owned(),
        auth: req.auth,
        timeout_secs: 30,
    };
    let stig_id = req.stig_id.trim().to_owned();
    let answer_file_id = match canonical_answer_file_id(req.answer_file_id.as_deref()) {
        Ok(answer_file_id) => answer_file_id,
        Err(error) => return answer_file_selection_error_response(error),
    };

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
    if let Some(ref asset_id) = linked_asset_id {
        let assets = match load_assets(&state.db()) {
            Ok(assets) => assets,
            Err(error) => return api_response_error(StatusCode::INTERNAL_SERVER_ERROR, error),
        };
        let Some(asset) = assets.iter().find(|asset| asset.id == asset_id.as_str()) else {
            return api_response_error(StatusCode::NOT_FOUND, "Linked asset was not found");
        };
        let expected_platform = match platform_for_supported_stig(&stig_id) {
            Ok(platform) => platform,
            Err(error) => return api_response_error(StatusCode::BAD_REQUEST, error),
        };
        if asset.platform != expected_platform || check_platform != expected_platform {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "linked asset, submitted platform, and target STIG platforms must match",
            );
        }
        if !asset.enabled {
            return api_response_error(StatusCode::CONFLICT, "Linked asset is disabled");
        }
        if !asset
            .address
            .trim()
            .eq_ignore_ascii_case(ssh_config.host.trim())
        {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "SSH host must match the linked asset address",
            );
        }
        if asset.port.unwrap_or(22) != ssh_config.port {
            return api_response_error(
                StatusCode::BAD_REQUEST,
                "SSH port must match the linked asset port",
            );
        }
    }
    let evaluation_inputs =
        match load_evaluation_inputs(state.clone(), stig_id.clone(), answer_file_id).await {
            Ok(inputs) => inputs,
            Err(error) => return evaluation_input_load_error_response(error),
        };
    let checks = &evaluation_inputs.content.check_packs.definitions;
    if checks.first().map(|check| check.platform) != Some(check_platform) {
        return api_response_error(
            StatusCode::BAD_REQUEST,
            "selected platform does not match the installed check pack",
        );
    }
    // The owned snapshot stays with this request across network collection, so
    // a concurrent content import cannot change the benchmark or checks used
    // to evaluate evidence collected for this exact plan.
    let plan = match automatestig_core::remote::generate_collection_plan(check_platform, checks) {
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
        answer_file: None,
        answer_files: Vec::new(),
        unsafe_legacy_evidence: false,
    };

    let mut body = match evaluate_with_system_data(
        &state,
        &evaluation_inputs.content,
        &hostname,
        &system_data,
        FindingSource::Automated,
        provenance,
        evaluation_inputs.selected_answer_file.as_ref(),
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
    if evaluation_complete {
        if let Some(ref asset_id) = linked_asset_id {
            update_linked_asset_after_persist_or_warn(
                &mut body,
                &state.db(),
                asset_id,
                &stig_id,
                &hostname,
                AssetIdentityBinding::Address,
            );
        }
    }
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
    content: &LoadedEvaluationContent,
    hostname: &str,
    system_data: &automatestig_core::checks::SystemData,
    finding_source: FindingSource,
    mut provenance: EvaluationProvenance,
    selected_answer_file: Option<&SelectedAnswerFile>,
) -> Result<(Checklist, usize, usize), DeviceEvaluationError> {
    let benchmark = &content.benchmark;
    let stig_id = &benchmark.id;
    let loaded_check_packs = &content.check_packs;
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
    let organization_policy_sha256 = organization_policy
        .as_ref()
        .map(|policy| policy.policy_sha256.as_str());
    let evaluation_plan_sha256 = match selected_answer_file {
        Some(selected) => {
            let bindings = [(selected.id.as_str(), selected.sha256.as_str())];
            automatestig_core::check_packs::evaluation_plan_sha256_with_answer_files(
                &benchmark.id,
                &benchmark.version_string(),
                &benchmark_sha256,
                &loaded_check_packs.sha256,
                organization_policy_sha256,
                &bindings,
            )
        }
        None => automatestig_core::check_packs::evaluation_plan_sha256(
            &benchmark.id,
            &benchmark.version_string(),
            &benchmark_sha256,
            &loaded_check_packs.sha256,
            organization_policy_sha256,
        ),
    }
    .map_err(|error| {
        DeviceEvaluationError::Internal(format!(
            "Failed to bind evaluation-plan provenance: {error}"
        ))
    })?;
    provenance.benchmark_sha256 = Some(benchmark_sha256);
    provenance.check_pack_sha256 = Some(loaded_check_packs.sha256.clone());
    provenance.evaluation_plan_sha256 = Some(evaluation_plan_sha256);
    provenance.organization_policy = organization_policy;
    provenance.answer_file = None;
    provenance.answer_files = selected_answer_file
        .map(|selected| {
            vec![AnswerFileProvenance {
                id: selected.id.clone(),
                sha256: selected.sha256.clone(),
            }]
        })
        .unwrap_or_default();

    // Execute checks.
    let mut check_results: Vec<automatestig_core::checks::CheckResult> = check_definitions
        .iter()
        .map(|check_def| automatestig_core::checks::executor::execute_check(check_def, system_data))
        .collect();
    let mut seen_vuln_ids: HashSet<String> = HashSet::new();
    // Curated packs load before reviewed imported ones; first result per vuln wins.
    check_results.retain(|cr| seen_vuln_ids.insert(cr.vuln_id.clone()));
    let checks_executed = check_results.len();
    let checks_passed = check_results
        .iter()
        .filter(|result| result.error.is_none())
        .filter(|result| result.to_finding_status() == FindingStatus::NotAFinding)
        .count();
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
    let answer_files = selected_answer_file
        .map(|selected| std::slice::from_ref(&selected.answer_file))
        .unwrap_or(&[]);
    let mut checklist = engine
        .evaluate(benchmark, &asset, answer_files)
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

    // Ordinary answer entries pre-populate only findings without a successful
    // automated determination. Explicit force overrides are applied after
    // observed checks, while collection errors remain immutable in the core
    // engine and therefore cannot be laundered into asserted results.
    if let Some(selected) = selected_answer_file {
        let mut forced = selected.answer_file.clone();
        forced.entries.retain(|entry| entry.force_override);
        if !forced.entries.is_empty() {
            engine
                .apply_answer_file(&mut checklist, &forced)
                .map_err(|error| {
                    DeviceEvaluationError::Internal(format!(
                        "Failed to apply forced answer-file overrides: {error}"
                    ))
                })?;
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

    Ok((checklist, checks_executed, checks_passed))
}

#[derive(Debug)]
enum DeviceEvaluationError {
    MissingBenchmark(String),
    MissingCheckPack(String),
    IncompatibleCheckPack {
        target: String,
        unknown_vuln_ids: Vec<String>,
    },
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
        DeviceEvaluationError::IncompatibleCheckPack {
            target,
            unknown_vuln_ids,
        } => api_response_error(
            StatusCode::CONFLICT,
            format!(
                "The trusted check pack for {target} references rule(s) absent from the installed benchmark: {}",
                unknown_vuln_ids.join(", ")
            ),
        ),
        DeviceEvaluationError::Internal(message) => {
            api_response_error(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

struct LoadedEvaluationContent {
    benchmark: automatestig_core::models::stig::StigBenchmark,
    check_packs: LoadedCheckPackSet,
}

struct LoadedEvaluationInputs {
    content: LoadedEvaluationContent,
    selected_answer_file: Option<SelectedAnswerFile>,
}

#[derive(Debug)]
enum EvaluationInputLoadError {
    Content(DeviceEvaluationError),
    AnswerFile(AnswerFileSelectionError),
}

fn evaluation_input_load_error_response(error: EvaluationInputLoadError) -> Response {
    match error {
        EvaluationInputLoadError::Content(error) => device_evaluation_error_response(error),
        EvaluationInputLoadError::AnswerFile(error) => answer_file_selection_error_response(error),
    }
}

async fn load_evaluation_inputs(
    state: AppState,
    stig_id: String,
    answer_file_id: Option<String>,
) -> Result<LoadedEvaluationInputs, EvaluationInputLoadError> {
    tokio::task::spawn_blocking(move || {
        load_evaluation_inputs_blocking(&state, &stig_id, answer_file_id.as_deref())
    })
    .await
    .map_err(|error| {
        EvaluationInputLoadError::Content(DeviceEvaluationError::Internal(format!(
            "Evaluation content worker failed: {error}"
        )))
    })?
}

fn load_evaluation_inputs_blocking(
    state: &AppState,
    stig_id: &str,
    answer_file_id: Option<&str>,
) -> Result<LoadedEvaluationInputs, EvaluationInputLoadError> {
    let answer_file_id =
        canonical_answer_file_id(answer_file_id).map_err(EvaluationInputLoadError::AnswerFile)?;
    let trusted_public_keys =
        load_trusted_content_public_keys().map_err(EvaluationInputLoadError::Content)?;
    let library = state.library().map_err(|error| {
        EvaluationInputLoadError::Content(DeviceEvaluationError::Internal(format!(
            "Failed to open STIG library: {error}"
        )))
    })?;
    let snapshot = match library.load_evaluation_content_snapshot(
        stig_id,
        answer_file_id.as_deref(),
        &trusted_public_keys,
    ) {
        Ok(snapshot) => snapshot,
        Err(automatestig_core::library::EvaluationContentSnapshotLoadError::Content(
            automatestig_core::Error::StigNotFound(_),
        )) => {
            return Err(EvaluationInputLoadError::Content(
                DeviceEvaluationError::MissingBenchmark(stig_id.to_owned()),
            ));
        }
        Err(automatestig_core::library::EvaluationContentSnapshotLoadError::Content(error)) => {
            return Err(EvaluationInputLoadError::Content(
                DeviceEvaluationError::Internal(format!(
                    "Failed to load evaluation content for {stig_id}: {error}"
                )),
            ));
        }
        Err(automatestig_core::library::EvaluationContentSnapshotLoadError::AnswerTemplate {
            filename,
            source,
        }) => {
            let not_found = match &source {
                automatestig_core::Error::Io(error) => error.kind() == std::io::ErrorKind::NotFound,
                automatestig_core::Error::LibraryError(message) => {
                    message.starts_with("unsupported answer-template extension:")
                        || message.contains("answer-template source is not a regular file")
                }
                _ => false,
            };
            let error = if not_found {
                AnswerFileSelectionError::NotFound(format!(
                    "Answer file {filename:?} is not installed"
                ))
            } else {
                AnswerFileSelectionError::Internal(format!(
                    "Failed to inspect answer file {filename:?}: {source}"
                ))
            };
            return Err(EvaluationInputLoadError::AnswerFile(error));
        }
    };
    let selected_answer_file = match (answer_file_id.as_deref(), snapshot.answer_template()) {
        (Some(answer_file_id), Some(answer_template)) => Some(
            selected_answer_file_from_snapshot(
                answer_file_id,
                answer_template,
                snapshot.benchmark(),
            )
            .map_err(EvaluationInputLoadError::AnswerFile)?,
        ),
        (None, None) => None,
        _ => {
            return Err(EvaluationInputLoadError::Content(
                DeviceEvaluationError::Internal(
                    "Evaluation content snapshot omitted the selected answer template".to_string(),
                ),
            ));
        }
    };
    let check_packs =
        check_pack_set_for_benchmark(snapshot.check_pack_registry(), snapshot.benchmark())
            .map_err(EvaluationInputLoadError::Content)?;
    Ok(LoadedEvaluationInputs {
        content: LoadedEvaluationContent {
            benchmark: snapshot.benchmark().clone(),
            check_packs,
        },
        selected_answer_file,
    })
}

struct LoadedCheckPackSet {
    definitions: Vec<automatestig_core::checks::CheckDefinition>,
    sha256: String,
}

fn load_trusted_content_public_keys() -> Result<Vec<[u8; 32]>, DeviceEvaluationError> {
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
    Ok(trust_store.public_keys())
}

fn load_effective_check_pack_registry(
    state: &AppState,
) -> Result<automatestig_core::check_packs::CheckPackRegistry, DeviceEvaluationError> {
    // Curated packs are compiled into the binary. Never trust an implicit
    // `content/check_packs` directory relative to the process working directory:
    // a writable launch directory must not be able to replace executable checks.
    let mut check_pack_registry = automatestig_core::check_packs::CheckPackRegistry::new();
    check_pack_registry.load_embedded().map_err(|error| {
        DeviceEvaluationError::Internal(format!("Failed to load embedded check packs: {error}"))
    })?;
    let trusted_public_keys = load_trusted_content_public_keys()?;
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
    Ok(check_pack_registry)
}

fn check_pack_set_for_benchmark(
    check_pack_registry: &automatestig_core::check_packs::CheckPackRegistry,
    benchmark: &automatestig_core::models::stig::StigBenchmark,
) -> Result<LoadedCheckPackSet, DeviceEvaluationError> {
    let stig_id = &benchmark.id;
    let release = benchmark.version_string();
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
    let unknown_vuln_ids =
        automatestig_core::check_packs::check_pack_vuln_ids_missing_from_benchmark(
            benchmark, &packs,
        );
    if !unknown_vuln_ids.is_empty() {
        return Err(DeviceEvaluationError::IncompatibleCheckPack {
            target: format!("{stig_id} {release}"),
            unknown_vuln_ids,
        });
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
    content: &LoadedEvaluationContent,
    hostname: &str,
    system_data: &automatestig_core::checks::SystemData,
    finding_source: FindingSource,
    provenance: EvaluationProvenance,
    selected_answer_file: Option<&SelectedAnswerFile>,
) -> Result<serde_json::Value, DeviceEvaluationError> {
    let (checklist, checks_executed, checks_passed) = evaluate_system_data_core(
        state,
        content,
        hostname,
        system_data,
        finding_source,
        provenance,
        selected_answer_file,
    )?;
    let stig_id = &content.benchmark.id;

    let s = checklist.summary();
    let (assessed_pass_pct, benchmark_coverage_pct) = defensible_scores(&checklist, &s);
    let collection_complete = checklist
        .evaluation_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.collection_complete);
    let evaluation_errors = checklist
        .evaluation_provenance
        .as_ref()
        .map(|provenance| provenance.collection_errors.clone())
        .unwrap_or_default();
    Ok(serde_json::json!({
        "success": true,
        "data": {
            "id": collection_complete.then(|| checklist.id.to_string()),
            "hostname": hostname,
            "stig_id": stig_id,
            "answer_file_id": checklist.evaluation_provenance
                .as_ref()
                .and_then(|provenance| {
                    provenance.answer_files.first().or(provenance.answer_file.as_ref())
                })
                .map(|answer_file| answer_file.id.clone()),
            "total": s.total,
            "open": s.open,
            "not_a_finding": s.not_a_finding,
            "not_reviewed": s.not_reviewed,
            "assessed_pass_pct": assessed_pass_pct,
            "benchmark_coverage_pct": benchmark_coverage_pct,
            // Deprecated compatibility alias for assessed_pass_pct.
            "compliance_pct": assessed_pass_pct,
            "collection_complete": collection_complete,
            "evaluation_errors": evaluation_errors,
            "persisted": collection_complete,
            "checks_executed": checks_executed,
            "checks_passed": checks_passed,
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
    let stig_id = req.stig_id.trim().to_owned();
    let db = state.db();
    let mut assets = match load_assets(&db) {
        Ok(assets) => assets,
        Err(error) => return api_error(&error),
    };
    let expected_platform = match platform_for_supported_stig(&stig_id) {
        Ok(platform) => platform,
        Err(error) => return api_error(&error),
    };
    if let Some(asset) = assets
        .iter()
        .find(|asset| req.asset_ids.contains(&asset.id) && asset.platform != expected_platform)
    {
        return api_error(&format!(
            "Asset {} platform {:?} does not match STIG {} platform {:?}",
            asset.name, asset.platform, stig_id, expected_platform
        ));
    }
    let mut count = 0;
    for asset in assets.iter_mut() {
        if req.asset_ids.contains(&asset.id) && !asset.assigned_stigs.contains(&stig_id) {
            asset.assigned_stigs.push(stig_id.clone());
            count += 1;
        }
    }
    if let Err(error) = save_assets(&db, &assets) {
        return api_error(&error);
    }
    api_ok(serde_json::json!({ "assigned": count, "stig_id": stig_id }))
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

fn checklist_export_block_message(checklist: &Checklist) -> Option<String> {
    checklist.external_export_block_reason().map(|reason| {
        let reason = reason.split_whitespace().collect::<Vec<_>>().join(" ");
        let reason: String = reason.chars().take(512).collect();
        format!("Checklist cannot be exported: {reason}")
    })
}

async fn export_ckl(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let db = state.db();
    match db.load_checklist(&id) {
        Ok(cl) => {
            if let Some(message) = checklist_export_block_message(&cl) {
                return (StatusCode::CONFLICT, message).into_response();
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
            if let Some(message) = checklist_export_block_message(&cl) {
                return (StatusCode::CONFLICT, message).into_response();
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
        Err(ChecklistZipError::Blocked(error)) => {
            return (StatusCode::CONFLICT, error).into_response()
        }
        Err(ChecklistZipError::Internal(error)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error).into_response()
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
) -> Result<Vec<u8>, ChecklistZipError> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for row in rows {
            let checklist = db.load_checklist(&row.id).map_err(|error| {
                ChecklistZipError::Internal(format!("Failed to load checklist {}: {error}", row.id))
            })?;
            if let Some(message) = checklist_export_block_message(&checklist) {
                return Err(ChecklistZipError::Blocked(format!(
                    "{message} (checklist {})",
                    row.id
                )));
            }
            let filename = sanitize_filename(&format!(
                "{}_{}_{}.ckl",
                checklist.asset.hostname, checklist.stig_info.stig_id, checklist.id
            ));
            let xml = ckl::write_ckl(&checklist).map_err(|error| {
                ChecklistZipError::Internal(format!(
                    "Failed to serialize checklist {}: {error}",
                    row.id
                ))
            })?;
            zip.start_file(&filename, options).map_err(|error| {
                ChecklistZipError::Internal(format!("Failed to create ZIP entry: {error}"))
            })?;
            std::io::Write::write_all(&mut zip, xml.as_bytes()).map_err(|error| {
                ChecklistZipError::Internal(format!("Failed to write ZIP entry: {error}"))
            })?;
        }
        zip.finish().map_err(|error| {
            ChecklistZipError::Internal(format!("Failed to finish export ZIP: {error}"))
        })?;
    }
    Ok(buffer.into_inner())
}

#[derive(Debug)]
enum ChecklistZipError {
    Blocked(String),
    Internal(String),
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
                stigman_push_locks: crate::state::StigManagerPushLocks::default(),
                checklist_operation_locks: crate::state::ChecklistOperationLocks::default(),
                scanner_preflights: Mutex::new(std::collections::HashMap::new()),
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
        let error = library
            .load_offline_pack_content_snapshot(&[])
            .expect_err("bare executable content must not be re-signed");
        assert!(error
            .to_string()
            .contains("has no trusted signed provenance"));
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
        legacy_reference_routes()
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

    #[tokio::test]
    async fn legacy_duplicate_surfaces_are_gone_before_request_extraction() {
        use axum::http::Method;

        let (_temporary, state) = test_state();
        let app = routes().with_state(state);
        let cases = [
            (
                Method::GET,
                "/library/benchmarks",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::GET,
                "/library/benchmarks/legacy",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::POST,
                "/library/import-stigpack",
                "AutomateSTIG scanner release process",
            ),
            (Method::GET, "/checklists", "STIG Manager"),
            (Method::GET, "/checklists/legacy", "STIG Manager"),
            (Method::POST, "/assets", "STIG Manager"),
            (Method::GET, "/assets", "STIG Manager"),
            (Method::GET, "/assets/legacy-asset", "STIG Manager"),
            (Method::PUT, "/assets/legacy-asset", "STIG Manager"),
            (Method::DELETE, "/assets/legacy-asset", "STIG Manager"),
            (Method::POST, "/assets/bulk-assign-stig", "STIG Manager"),
            (Method::POST, "/assets/bulk-update", "STIG Manager"),
            (
                Method::PATCH,
                "/checklists/legacy/findings/V-1",
                "STIG Manager",
            ),
            (Method::POST, "/answer-files", "STIG Manager"),
            (Method::GET, "/answer-files", "STIG Manager"),
            (Method::GET, "/answer-files/legacy.json", "STIG Manager"),
            (Method::PUT, "/answer-files/legacy.json", "STIG Manager"),
            (Method::DELETE, "/checklists/legacy", "STIG Manager"),
            (Method::POST, "/checklists/import", "STIG Manager"),
            (
                Method::GET,
                "/stigman/config",
                "AutomateSTIG scanner run service",
            ),
            (
                Method::POST,
                "/stigman/test",
                "AutomateSTIG scanner run service",
            ),
            (
                Method::GET,
                "/stigman/collections",
                "AutomateSTIG scanner run service",
            ),
            (
                Method::GET,
                "/stigman/collections/7/assets",
                "AutomateSTIG scanner run service",
            ),
            (Method::POST, "/stigman/sync/7", "STIG Manager"),
            (Method::GET, "/stigman/diff/7", "STIG Manager"),
            (
                Method::POST,
                "/stigman/push/legacy-checklist",
                "AutomateSTIG scanner run service",
            ),
            (
                Method::POST,
                "/evaluate/with-evidence",
                "AutomateSTIG scanner run service",
            ),
            (
                Method::POST,
                "/scan/ssh",
                "AutomateSTIG scanner run service",
            ),
            (
                Method::POST,
                "/library/import-disa",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::GET,
                "/disa/available",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::POST,
                "/disa/fetch",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::POST,
                "/disa/fetch-all",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::GET,
                "/disa/check-updates",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::GET,
                "/offline-pack",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::GET,
                "/offline-pack/trust-key",
                "AutomateSTIG scanner release process",
            ),
            (Method::GET, "/audit-log", "STIG Manager"),
            (Method::GET, "/export/ckl/legacy", "STIG Manager"),
            (Method::GET, "/export/cklb/legacy", "STIG Manager"),
            (Method::GET, "/export/all-zip", "STIG Manager"),
        ];

        for (method, uri, owner) in cases {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        // Invalid JSON/multipart must not mask the retirement contract.
                        .body(Body::from("{not-a-valid-request"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::GONE, "{uri}");
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(payload["success"].as_bool(), Some(false), "{uri}");
            assert_eq!(
                payload["data"]["code"].as_str(),
                Some("legacy_surface_retired"),
                "{uri}"
            );
            assert_eq!(payload["data"]["owner"].as_str(), Some(owner), "{uri}");
            assert_eq!(
                payload["data"]["read_only_migration_access"].as_bool(),
                Some(false),
                "{uri}"
            );
            assert!(
                payload["error"]
                    .as_str()
                    .is_some_and(|message| message.contains("retired")),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn legacy_read_only_views_are_internal_reference_only() {
        let (_temporary, state) = test_state();
        let public_app = routes().with_state(state.clone());
        let reference_app = legacy_reference_routes().with_state(state);

        for uri in ["/assets", "/checklists", "/answer-files"] {
            let response = public_app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::GONE, "{uri}");

            let response = reference_app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
        }

        let selected_export = reference_app
            .oneshot(
                Request::builder()
                    .uri("/export/cklb/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(selected_export.status(), StatusCode::GONE);

        let unknown_scanner_route = public_app
            .oneshot(
                Request::builder()
                    .uri("/v1/not-a-scanner-route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown_scanner_route.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn benchmark_list_exposes_separate_release_and_import_timestamp() {
        let (_temporary, state) = test_state();
        let benchmark = automatestig_core::models::stig::StigBenchmark {
            id: "TEST_STIG".to_string(),
            title: "Test STIG".to_string(),
            description: "Test benchmark".to_string(),
            version: "3".to_string(),
            release: "7".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: automatestig_core::models::stig::Platform {
                family: "test".to_string(),
                name: "Test".to_string(),
                cpe: Vec::new(),
            },
            rules: Vec::new(),
        };
        state.library().unwrap().add_benchmark(&benchmark).unwrap();

        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/library/benchmarks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["data"][0]["version"].as_str(), Some("3"));
        assert_eq!(payload["data"][0]["release"].as_str(), Some("7"));
        assert!(payload["data"][0]["imported_at"].as_str().is_some());
        assert_eq!(payload["data"][0]["scanner_ready"].as_bool(), Some(false));
        assert!(payload["data"][0]["scanner_blocked_reason"]
            .as_str()
            .unwrap()
            .contains("reference"));
    }

    #[test]
    fn scanner_readiness_is_bound_to_the_exact_installed_release() {
        let (_temporary, state) = test_state();
        let registry = load_effective_check_pack_registry(&state).unwrap();
        let mut benchmark = automatestig_core::models::stig::StigBenchmark {
            id: "NetApp_ONTAP_DSC_9-x_STIG".to_string(),
            title: "ONTAP".to_string(),
            description: "Test benchmark".to_string(),
            version: "99".to_string(),
            release: "99".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: automatestig_core::models::stig::Platform::default(),
            rules: Vec::new(),
        };
        state.library().unwrap().add_benchmark(&benchmark).unwrap();
        let (ready, reason) = benchmark_scanner_readiness(&benchmark, Some(&registry));
        assert!(!ready);
        assert!(reason.unwrap().contains("V99R99"));

        benchmark.version = "2".to_string();
        benchmark.release = "4".to_string();
        state.library().unwrap().add_benchmark(&benchmark).unwrap();
        assert!(matches!(
            check_pack_set_for_benchmark(&registry, &benchmark),
            Err(DeviceEvaluationError::IncompatibleCheckPack { .. })
        ));
        let (ready, reason) = benchmark_scanner_readiness(&benchmark, Some(&registry));
        assert!(!ready, "an empty same-release benchmark must fail closed");
        assert!(reason.unwrap().contains("does not match the rule set"));

        let mut seen = HashSet::new();
        benchmark.rules = registry
            .check_packs_for_stig_release(&benchmark.id, &benchmark.version_string())
            .into_iter()
            .flat_map(|pack| pack.checks.iter())
            .filter(|definition| seen.insert(definition.vuln_id.clone()))
            .map(|definition| automatestig_core::models::stig::StigRule {
                vuln_id: definition.vuln_id.clone(),
                rule_id: format!("{}r1_rule", definition.vuln_id),
                group_id: definition.vuln_id.clone(),
                group_title: definition.vuln_id.clone(),
                title: definition
                    .description
                    .clone()
                    .unwrap_or_else(|| definition.vuln_id.clone()),
                rule_version: "test".to_string(),
                discussion: "test".to_string(),
                severity: Severity::Medium,
                check_content: "test".to_string(),
                fix_text: "test".to_string(),
                cci_refs: Vec::new(),
                legacy_ids: Vec::new(),
                stig_ref: None,
                weight: 8.0,
                automatable: automatestig_core::models::stig::CheckAutomation::Full,
            })
            .collect();
        state.library().unwrap().add_benchmark(&benchmark).unwrap();
        let (ready, reason) = benchmark_scanner_readiness(&benchmark, Some(&registry));
        assert!(ready, "embedded V2R4 check pack should be scanner-ready");
        assert!(reason.is_none());
    }

    #[test]
    fn in_flight_evaluation_keeps_the_content_generation_used_for_its_plan() {
        let (_temporary, state) = test_state();
        let registry = load_effective_check_pack_registry(&state).unwrap();
        let stig_id = "NetApp_ONTAP_DSC_9-x_STIG";
        let mut seen = HashSet::new();
        let rules = registry
            .check_packs_for_stig_release(stig_id, "V2R4")
            .into_iter()
            .flat_map(|pack| pack.checks.iter())
            .filter(|definition| seen.insert(definition.vuln_id.clone()))
            .map(|definition| automatestig_core::models::stig::StigRule {
                vuln_id: definition.vuln_id.clone(),
                rule_id: format!("{}r1_rule", definition.vuln_id),
                group_id: definition.vuln_id.clone(),
                group_title: definition.vuln_id.clone(),
                title: definition.vuln_id.clone(),
                rule_version: "test".to_string(),
                discussion: "test".to_string(),
                severity: Severity::Medium,
                check_content: "test".to_string(),
                fix_text: "test".to_string(),
                cci_refs: Vec::new(),
                legacy_ids: Vec::new(),
                stig_ref: None,
                weight: 8.0,
                automatable: automatestig_core::models::stig::CheckAutomation::Full,
            })
            .collect();
        let generation_one = automatestig_core::models::stig::StigBenchmark {
            id: stig_id.to_string(),
            title: "ONTAP generation one".to_string(),
            description: "first committed generation".to_string(),
            version: "2".to_string(),
            release: "4".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: automatestig_core::models::stig::Platform::default(),
            rules,
        };
        state
            .library()
            .unwrap()
            .add_benchmark(&generation_one)
            .unwrap();
        let selected_vuln_id = generation_one.rules[0].vuln_id.clone();
        let mut answer_file =
            automatestig_core::answer::AnswerFile::new("generation one", Some(stig_id));
        answer_file
            .entries
            .push(automatestig_core::answer::AnswerEntry {
                vuln_id: selected_vuln_id.clone(),
                status: FindingStatus::Open,
                finding_details: Some("generation-one assertion".to_string()),
                comments: None,
                severity_override: None,
                severity_override_justification: None,
                force_override: false,
            });
        automatestig_core::library_content::write_answer_template_atomic(
            &state.inner.library_path,
            "generation-one.json",
            &serde_json::to_vec(&answer_file).unwrap(),
        )
        .unwrap();

        // This is the boundary used by both upload and live SSH: plan from an
        // owned benchmark/check/answer snapshot, then retain it until evaluation.
        let inputs =
            load_evaluation_inputs_blocking(&state, stig_id, Some("generation-one.json")).unwrap();
        let content = inputs.content;
        let selected_answer_file = inputs.selected_answer_file.unwrap();
        assert_eq!(
            selected_answer_file.answer_file.entries[0].vuln_id,
            selected_vuln_id
        );
        let plan = automatestig_core::remote::generate_collection_plan(
            automatestig_core::checks::CheckPlatform::Ontap,
            &content.check_packs.definitions,
        )
        .unwrap();
        let expected_benchmark_sha256 =
            automatestig_core::check_packs::canonical_json_sha256(&generation_one).unwrap();
        let expected_check_pack_sha256 = content.check_packs.sha256.clone();

        // Force a content import onto another worker after planning and before
        // evaluation, reproducing the old request/import interleaving.
        let mut generation_two = generation_one.clone();
        generation_two.title = "ONTAP generation two".to_string();
        generation_two.description = "concurrent replacement".to_string();
        generation_two
            .rules
            .retain(|rule| rule.vuln_id != selected_vuln_id);
        assert_eq!(
            unknown_answer_vuln_ids(&selected_answer_file.answer_file, &generation_two),
            vec![selected_vuln_id.clone()]
        );
        let import_state = state.clone();
        std::thread::spawn(move || {
            import_state
                .library()
                .unwrap()
                .add_benchmark(&generation_two)
                .unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(
            state
                .library()
                .unwrap()
                .load_benchmark(stig_id)
                .unwrap()
                .title,
            "ONTAP generation two"
        );

        let system_data = automatestig_core::checks::SystemData::default();
        let provenance = EvaluationProvenance {
            origin: EvaluationOrigin::LiveSsh,
            collection_complete: false,
            collection_errors: vec!["test collection intentionally incomplete".to_string()],
            evidence_sha256: Some("0".repeat(64)),
            claimed_hostname: Some("ontap.example.test".to_string()),
            collector_version: Some("test".to_string()),
            collected_at: Some("2026-01-01T00:00:00Z".to_string()),
            plan_sha256: Some(plan.digest()),
            server_key_fingerprint: Some(format!("SHA256:{}", "A".repeat(43))),
            benchmark_sha256: None,
            check_pack_sha256: None,
            evaluation_plan_sha256: None,
            organization_policy: None,
            answer_file: None,
            answer_files: Vec::new(),
            unsafe_legacy_evidence: false,
        };
        let (checklist, _, _) = evaluate_system_data_core(
            &state,
            &content,
            "ontap.example.test",
            &system_data,
            FindingSource::Automated,
            provenance,
            Some(&selected_answer_file),
        )
        .unwrap();

        assert_eq!(checklist.stig_info.title, "ONTAP generation one");
        let provenance = checklist.evaluation_provenance.unwrap();
        assert_eq!(
            provenance.benchmark_sha256.as_deref(),
            Some(expected_benchmark_sha256.as_str())
        );
        assert_eq!(
            provenance.check_pack_sha256.as_deref(),
            Some(expected_check_pack_sha256.as_str())
        );
        assert_eq!(provenance.answer_files[0].id, "generation-one.json");
    }

    #[tokio::test]
    async fn disa_fetch_all_partial_result_preserves_successes_and_errors() {
        let response = disa_fetch_all_result_response(crate::disa::FetchResult {
            new_benchmarks: 2,
            updated_benchmarks: 1,
            already_current: 3,
            details: vec!["New: TEST_STIG V1R1".to_string()],
            errors: vec!["Broken package: invalid ZIP".to_string()],
        });

        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["success"].as_bool(), Some(true));
        assert_eq!(payload["data"]["new_benchmarks"].as_u64(), Some(2));
        assert_eq!(payload["data"]["updated_benchmarks"].as_u64(), Some(1));
        assert_eq!(
            payload["data"]["errors"][0].as_str(),
            Some("Broken package: invalid ZIP")
        );
        assert!(payload["error"].is_null());
    }

    #[tokio::test]
    async fn retired_answer_file_implementation_rejects_invalid_content_before_writing() {
        let (_temporary, state) = test_state();
        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/answer-files")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{
                            "name":"Duplicate answers",
                            "description":null,
                            "stig_id":"TEST_STIG",
                            "version":"1",
                            "entries":[
                                {"vuln_id":"V-1","status":"Open","finding_details":null,"comments":null,"severity_override":null,"severity_override_justification":null,"force_override":false},
                                {"vuln_id":"V-1","status":"NotAFinding","finding_details":null,"comments":null,"severity_override":null,"severity_override_justification":null,"force_override":false}
                            ]
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            automatestig_core::library_content::list_answer_template_files(
                &state.inner.library_path
            )
            .unwrap()
            .is_empty()
        );
    }

    #[tokio::test]
    async fn retired_answer_file_implementation_returns_only_its_library_local_id() {
        let (_temporary, state) = test_state();
        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/answer-files")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"name":"Site baseline","description":null,"stig_id":null,"version":"1","entries":[]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["data"]["id"].as_str(), Some("site_baseline.json"));
        assert!(payload["data"].get("path").is_none());
        assert!(state
            .inner
            .library_path
            .join("answer_templates/site_baseline.json")
            .is_file());
    }

    #[tokio::test]
    async fn answer_file_replacement_requires_explicit_put() {
        let (_temporary, state) = test_state();
        let create_body = r#"{"name":"Site baseline","description":null,"stig_id":null,"version":"1","entries":[]}"#;

        let created = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/answer-files")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(create_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(created.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let original_etag = payload["data"]["etag"].as_str().unwrap().to_string();

        let duplicate = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/answer-files")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(create_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);

        let missing_precondition = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/answer-files/site_baseline.json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(create_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            missing_precondition.status(),
            StatusCode::PRECONDITION_REQUIRED
        );

        let replacement = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/answer-files/site_baseline.json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::IF_MATCH, format!("\"{original_etag}\""))
                    .body(Body::from(
                        r#"{"name":"Site baseline","description":"Reviewed replacement","stig_id":null,"version":"2","entries":[]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replacement.status(), StatusCode::OK);

        let saved = automatestig_core::answer::AnswerFile::load(
            &state
                .inner
                .library_path
                .join("answer_templates/site_baseline.json"),
        )
        .unwrap();
        assert_eq!(saved.version, "2");
        assert_eq!(saved.description.as_deref(), Some("Reviewed replacement"));

        let listing = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/answer-files")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(listing.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            payload["data"]["files"][0]["editable"].as_bool(),
            Some(true)
        );
        let current_etag = payload["data"]["files"][0]["etag"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(current_etag, original_etag);
        assert!(payload["data"]["warnings"].as_array().unwrap().is_empty());

        let detail = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/answer-files/site_baseline.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            detail.headers()[header::ETAG].to_str().unwrap(),
            format!("\"{current_etag}\"")
        );
        let bytes = axum::body::to_bytes(detail.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            payload["data"]["answer_file"]["version"].as_str(),
            Some("2")
        );
        assert_eq!(
            payload["data"]["etag"].as_str(),
            Some(current_etag.as_str())
        );

        let stale_replacement = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/answer-files/site_baseline.json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::IF_MATCH, format!("\"{original_etag}\""))
                    .body(Body::from(
                        r#"{"name":"Site baseline","description":"Stale overwrite","stig_id":null,"version":"3","entries":[]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale_replacement.status(), StatusCode::PRECONDITION_FAILED);
        let saved = automatestig_core::answer::AnswerFile::load(
            &state
                .inner
                .library_path
                .join("answer_templates/site_baseline.json"),
        )
        .unwrap();
        assert_eq!(saved.version, "2");
        assert_eq!(saved.description.as_deref(), Some("Reviewed replacement"));
    }

    #[tokio::test]
    async fn malformed_answer_file_repair_is_limited_and_revision_guarded() {
        let (_temporary, state) = test_state();
        for (filename, bytes) in [
            ("repairable.json", b"not json".as_slice()),
            ("Upper.json", b"not json".as_slice()),
            ("manual.yaml", b"not: [valid".as_slice()),
        ] {
            automatestig_core::library_content::write_answer_template_atomic_with_mode(
                &state.inner.library_path,
                filename,
                bytes,
                automatestig_core::library_content::AnswerTemplateWriteMode::CreateNew,
            )
            .unwrap();
        }

        let listing = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/answer-files")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listing.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(listing.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let files = payload["data"]["files"].as_array().unwrap();
        let repairable = files
            .iter()
            .find(|file| file["id"] == "repairable.json")
            .unwrap();
        assert_eq!(repairable["invalid"].as_bool(), Some(true));
        assert_eq!(repairable["editable"].as_bool(), Some(true));
        let etag = repairable["etag"].as_str().unwrap();
        assert_eq!(etag.len(), 64);
        for id in ["Upper.json", "manual.yaml"] {
            let file = files.iter().find(|file| file["id"] == id).unwrap();
            assert_eq!(file["invalid"].as_bool(), Some(true));
            assert_eq!(file["editable"].as_bool(), Some(false));
        }

        let repaired = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/answer-files/repairable.json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::IF_MATCH, format!("\"{etag}\""))
                    .body(Body::from(
                        r#"{"name":"repairable","description":"Recovered","stig_id":null,"version":"1","entries":[]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(repaired.status(), StatusCode::OK);
        let loaded = automatestig_core::answer::AnswerFile::load(
            &state
                .inner
                .library_path
                .join("answer_templates/repairable.json"),
        )
        .unwrap();
        assert_eq!(loaded.description.as_deref(), Some("Recovered"));
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

        let assigned = vec![crate::stigman::SmStig {
            benchmark_id: "OTHER_STIG".to_string(),
            title: None,
            revision_str: Some("V1R1".to_string()),
        }];
        let error =
            ensure_stigman_asset_assignment("asset-7", "TEST_STIG", "V1R1", &assigned).unwrap_err();
        assert!(error.contains("assign that STIG"), "{error}");
        assert!(
            ensure_stigman_asset_assignment("asset-7", "OTHER_STIG", "V1R1", &assigned).is_ok()
        );
        let mismatch = ensure_stigman_asset_assignment("asset-7", "OTHER_STIG", "V1R2", &assigned)
            .unwrap_err();
        assert!(mismatch.contains("exact revision") || mismatch.contains("align"));

        let retry = stigman_review_push_error("asset-8", "upstream timeout");
        assert!(
            retry.contains("existing STIG Manager asset asset-8"),
            "{retry}"
        );
        assert!(retry.contains("retry delivery"), "{retry}");
        assert!(!retry.contains("created and assigned"));
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
    fn legacy_inventory_is_isolated_migrated_and_preserved_on_write() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let bsd = ManagedAsset::new("freebsd-01", "192.0.2.10", CheckPlatform::Bsd);
        let cisco = ManagedAsset::new("router-01", "192.0.2.11", CheckPlatform::CiscoIos);
        let windows = ManagedAsset::new("windows-01", "192.0.2.12", CheckPlatform::Bsd);
        let mut bsd_value = serde_json::to_value(&bsd).unwrap();
        bsd_value["platform"] = serde_json::json!("freebsd");
        let mut cisco_value = serde_json::to_value(&cisco).unwrap();
        cisco_value["platform"] = serde_json::json!("Cisco");
        let mut windows_value = serde_json::to_value(&windows).unwrap();
        windows_value["platform"] = serde_json::json!("windows");
        let raw = serde_json::to_string(&vec![bsd_value, windows_value, cisco_value]).unwrap();
        state.db().set_config("asset_inventory", &raw).unwrap();

        let parsed = parse_asset_inventory(&raw).unwrap();
        assert_eq!(parsed.assets.len(), 2);
        assert_eq!(parsed.quarantined.len(), 1);
        assert_eq!(parsed.assets[0].platform, CheckPlatform::Bsd);
        assert_eq!(parsed.assets[1].platform, CheckPlatform::CiscoIos);
        assert!(parsed.warnings[0].contains("windows"));

        let mut supported = parsed.assets;
        supported.push(ManagedAsset::new(
            "filer-02",
            "192.0.2.13",
            CheckPlatform::Ontap,
        ));
        save_assets(&state.db(), &supported).unwrap();
        let stored = state.db().get_config("asset_inventory").unwrap().unwrap();
        let reparsed = parse_asset_inventory(&stored).unwrap();
        assert_eq!(reparsed.assets.len(), 3);
        assert_eq!(reparsed.quarantined.len(), 1);
        assert_eq!(reparsed.quarantined[0]["name"].as_str(), Some("windows-01"));
    }

    #[test]
    fn malformed_alias_migration_quarantines_the_exact_original_record() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let mut original = serde_json::to_value(ManagedAsset::new(
            "legacy-freebsd",
            "192.0.2.20",
            CheckPlatform::Bsd,
        ))
        .unwrap();
        original["platform"] = serde_json::json!("freebsd");
        original["enabled"] = serde_json::json!("definitely");
        let raw = serde_json::to_string(&vec![original.clone()]).unwrap();

        let parsed = parse_asset_inventory(&raw).unwrap();

        assert!(parsed.assets.is_empty());
        assert_eq!(parsed.quarantined, vec![original]);
        assert_eq!(parsed.quarantined[0]["platform"], "freebsd");
    }

    #[test]
    fn stigman_merge_uses_fresh_local_state_and_consistent_identity_and_address_rules() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let mut fresh = ManagedAsset::new("FILER-01", "old.example.mil", CheckPlatform::Ontap);
        fresh.notes = Some("concurrent GUI note".to_string());
        fresh.tags = vec!["operator-owned".to_string()];
        fresh.enabled = false;
        fresh.port = Some(2222);
        let original_id = fresh.id.clone();
        let mut assets = vec![fresh];
        let updates = vec![StigmanAssetUpdate {
            name: " filer-01 ".to_string(),
            ip: Some("192.0.2.50".to_string()),
            fqdn: Some("filer-01.example.mil".to_string()),
            description: Some("remote description must not replace GUI notes".to_string()),
            assigned_stigs: vec!["NetApp_ONTAP_DSC_9-x_STIG".to_string()],
            platform: CheckPlatform::Ontap,
        }];

        let details = merge_stigman_asset_updates(&mut assets, &updates).unwrap();

        assert_eq!(
            assets.len(),
            1,
            "case-only names must not create duplicates"
        );
        assert_eq!(assets[0].id, original_id);
        assert_eq!(assets[0].address, "filer-01.example.mil");
        assert_eq!(assets[0].notes.as_deref(), Some("concurrent GUI note"));
        assert_eq!(assets[0].tags, vec!["operator-owned"]);
        assert!(!assets[0].enabled);
        assert_eq!(assets[0].port, Some(2222));
        assert!(details[0].starts_with("Updated:"));
        assert!(stigman_asset_names_match("FILER-01", " filer-01 "));
        assert_eq!(
            stigman_preferred_address(Some(" host.example.mil "), Some("192.0.2.5")),
            Some("host.example.mil")
        );
    }

    #[test]
    fn asset_write_validation_rejects_blank_and_duplicate_identities() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let existing = ManagedAsset::new("filer-01", "192.0.2.10", CheckPlatform::Ontap);
        let mut candidate = ManagedAsset::new("candidate", "192.0.2.11", CheckPlatform::Ontap);

        candidate.name = "  ".to_string();
        normalize_asset_for_write(&mut candidate);
        assert_eq!(
            validate_asset_for_write(&candidate, std::slice::from_ref(&existing), None)
                .unwrap_err(),
            "Asset name is required"
        );

        candidate.name = "candidate".to_string();
        candidate.address = "  ".to_string();
        normalize_asset_for_write(&mut candidate);
        assert_eq!(
            validate_asset_for_write(&candidate, std::slice::from_ref(&existing), None)
                .unwrap_err(),
            "Asset address is required"
        );

        candidate.address = "192.0.2.11".to_string();
        candidate.port = Some(0);
        assert!(
            validate_asset_for_write(&candidate, std::slice::from_ref(&existing), None)
                .unwrap_err()
                .contains("port")
        );

        candidate.port = None;
        candidate.name = "FILER-01".to_string();
        assert!(
            validate_asset_for_write(&candidate, std::slice::from_ref(&existing), None)
                .unwrap_err()
                .contains("named")
        );

        candidate.name = "candidate".to_string();
        candidate.address = existing.address.clone();
        candidate.port = Some(22);
        assert!(
            validate_asset_for_write(&candidate, std::slice::from_ref(&existing), None)
                .unwrap_err()
                .contains("endpoint")
        );

        candidate.port = Some(2222);
        assert!(validate_asset_for_write(&candidate, &[existing], None).is_ok());

        assert_eq!(
            canonical_bulk_tag(Some("  production  "), "Added").unwrap(),
            Some("production".to_string())
        );
        assert!(canonical_bulk_tag(Some("  "), "Added").is_err());
    }

    #[tokio::test]
    async fn assets_api_returns_visible_legacy_warnings_with_supported_rows() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let supported = ManagedAsset::new("freebsd-01", "192.0.2.10", CheckPlatform::Bsd);
        let mut legacy = serde_json::to_value(ManagedAsset::new(
            "windows-01",
            "192.0.2.11",
            CheckPlatform::Bsd,
        ))
        .unwrap();
        legacy["platform"] = serde_json::json!("windows");
        state
            .db()
            .set_config(
                "asset_inventory",
                &serde_json::to_string(&vec![serde_json::to_value(supported).unwrap(), legacy])
                    .unwrap(),
            )
            .unwrap();

        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/assets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["data"]["assets"].as_array().unwrap().len(), 1);
        assert_eq!(payload["data"]["warnings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn selected_answer_files_are_library_local_validated_and_stig_bound() {
        let (_temporary, state) = test_state();
        let benchmark = automatestig_core::models::stig::StigBenchmark {
            id: "TEST_STIG".to_string(),
            title: "Test STIG".to_string(),
            description: "Test benchmark".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: automatestig_core::models::stig::Platform::default(),
            rules: Vec::new(),
        };
        state.library().unwrap().add_benchmark(&benchmark).unwrap();
        let mut answer_file =
            automatestig_core::answer::AnswerFile::new("Site baseline", Some("TEST_STIG"));
        let bytes = serde_json::to_vec(&answer_file).unwrap();
        automatestig_core::library_content::write_answer_template_atomic(
            &state.inner.library_path,
            "site-baseline.json",
            &bytes,
        )
        .unwrap();

        let snapshot = automatestig_core::library_content::read_answer_template_snapshot(
            &state.inner.library_path,
            "site-baseline.json",
        )
        .unwrap();
        let selected =
            selected_answer_file_from_snapshot("site-baseline.json", &snapshot, &benchmark)
                .unwrap();
        assert_eq!(selected.id, "site-baseline.json");
        assert_eq!(selected.sha256.len(), 64);
        assert!(matches!(
            canonical_answer_file_id(Some("../site-baseline.json")),
            Err(AnswerFileSelectionError::Invalid(_))
        ));
        assert!(matches!(
            load_evaluation_inputs_blocking(&state, "TEST_STIG", Some("missing.json")),
            Err(EvaluationInputLoadError::AnswerFile(
                AnswerFileSelectionError::NotFound(_)
            ))
        ));
        let mut other_benchmark = benchmark.clone();
        other_benchmark.id = "OTHER_STIG".to_string();
        assert!(matches!(
            selected_answer_file_from_snapshot("site-baseline.json", &snapshot, &other_benchmark),
            Err(AnswerFileSelectionError::Invalid(_))
        ));

        answer_file
            .entries
            .push(automatestig_core::answer::AnswerEntry {
                vuln_id: "V-UNKNOWN".to_string(),
                status: FindingStatus::Open,
                finding_details: None,
                comments: None,
                severity_override: None,
                severity_override_justification: None,
                force_override: false,
            });
        let bytes = serde_json::to_vec(&answer_file).unwrap();
        automatestig_core::library_content::write_answer_template_atomic(
            &state.inner.library_path,
            "site-baseline.json",
            &bytes,
        )
        .unwrap();
        let snapshot = automatestig_core::library_content::read_answer_template_snapshot(
            &state.inner.library_path,
            "site-baseline.json",
        )
        .unwrap();
        let error =
            match selected_answer_file_from_snapshot("site-baseline.json", &snapshot, &benchmark) {
                Err(AnswerFileSelectionError::Invalid(error)) => error,
                _ => panic!("unknown answer entries must be rejected"),
            };
        assert!(error.contains("V-UNKNOWN"), "{error}");
        assert!(matches!(
            load_evaluation_inputs_blocking(&state, "TEST_STIG", Some("site-baseline.json")),
            Err(EvaluationInputLoadError::AnswerFile(
                AnswerFileSelectionError::Invalid(_)
            ))
        ));
    }

    #[test]
    fn stigman_unsaved_test_config_is_ephemeral_and_secret_safe() {
        let (_temporary, state) = test_state();
        let saved = crate::stigman::StigManagerConfig {
            api_url: "https://stigman.example.mil/api".to_string(),
            token_url: "https://idp.example.mil/token".to_string(),
            client_id: "automatestig".to_string(),
            client_secret: "saved-secret".to_string(),
            default_collection_id: Some("1".to_string()),
            verify_tls: true,
        };
        let saved_json = serde_json::to_string(&saved).unwrap();
        state
            .db()
            .set_config("stigman_config", &saved_json)
            .unwrap();

        let mut same_identity = saved.clone();
        same_identity.api_url = format!("  {}  ", same_identity.api_url);
        same_identity.token_url = format!("\t{}\n", same_identity.token_url);
        same_identity.client_id = format!(" {} ", same_identity.client_id);
        same_identity.client_secret.clear();
        same_identity.default_collection_id = Some(" 2 ".to_string());
        let resolved = resolve_stigman_test_config(&state, Some(same_identity)).unwrap();
        assert_eq!(resolved.client_secret, "saved-secret");
        assert_eq!(resolved.default_collection_id.as_deref(), Some("2"));

        let mut changed_identity = saved.clone();
        changed_identity.api_url = "https://other.example.mil/api".to_string();
        changed_identity.client_secret.clear();
        assert!(resolve_stigman_test_config(&state, Some(changed_identity)).is_err());

        let stored = state.db().get_config("stigman_config").unwrap().unwrap();
        assert_eq!(stored, saved_json);

        let mut normalized = saved.clone();
        normalized.api_url = format!(" {} ", normalized.api_url);
        normalized.token_url = format!(" {} ", normalized.token_url);
        normalized.client_id = format!(" {} ", normalized.client_id);
        normalized.default_collection_id = Some("   ".to_string());
        normalize_stigman_config(&mut normalized);
        assert_eq!(normalized.api_url, saved.api_url);
        assert_eq!(normalized.token_url, saved.token_url);
        assert_eq!(normalized.client_id, saved.client_id);
        assert_eq!(normalized.default_collection_id, None);
    }

    #[tokio::test]
    async fn stigman_config_delete_removes_secret_and_is_idempotent() {
        let (_temporary, state) = test_state();
        state
            .db()
            .set_config(
                "stigman_config",
                r#"{"api_url":"https://stigman.example.mil/api","token_url":"https://idp.example.mil/token","client_id":"automatestig","client_secret":"enc:invalid-ciphertext","default_collection_id":"1","verify_tls":true}"#,
            )
            .unwrap();

        for expected_deleted in [true, false] {
            let response = legacy_reference_routes()
                .with_state(state.clone())
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/stigman/config")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(payload["success"].as_bool(), Some(true));
            assert_eq!(payload["data"]["deleted"].as_bool(), Some(expected_deleted));
            assert_eq!(payload["data"]["configured"].as_bool(), Some(false));
            assert!(state.db().get_config("stigman_config").unwrap().is_none());
        }

        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/stigman/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["data"]["configured"].as_bool(), Some(false));
        assert_eq!(payload["data"]["has_secret"].as_bool(), Some(false));
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
                "V-215836": {"minimum_logging_buffer_bytes": 4096000},
                "V-215838": {"approved_authoritative_ntp_sources": ["192.0.2.10", "192.0.2.11"]}
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
            answer_file: None,
            answer_files: Vec::new(),
            unsafe_legacy_evidence: false,
        });

        let summary = checklist.summary();
        assert_eq!(summary.assessed_pass_pct(), 100.0);
        assert_eq!(summary.benchmark_coverage_pct(), 100.0);
        assert_eq!(defensible_scores(&checklist, &summary), (None, None));
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
    async fn uploaded_evaluation_rejects_a_disabled_linked_asset() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let mut asset = ManagedAsset::new("actual-router", "192.0.2.10", CheckPlatform::CiscoIos);
        asset.enabled = false;
        let asset_id = asset.id.clone();
        save_assets(&state.db(), &[asset]).unwrap();

        let boundary = "automatestig-disabled-linked-asset";
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
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(state.db().list_checklists().unwrap().is_empty());
        let assets = load_assets(&state.db()).unwrap();
        assert!(assets[0].last_evaluated.is_none());
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
        let response = legacy_reference_routes()
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
        let response = legacy_reference_routes()
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
        let response = legacy_reference_routes()
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

    #[tokio::test]
    async fn ssh_linked_asset_must_exist_and_match_endpoint_and_platform() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let asset = ManagedAsset::new("filer-01", "192.0.2.50", CheckPlatform::Ontap);
        let asset_id = asset.id.clone();
        save_assets(&state.db(), &[asset]).unwrap();

        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scan/ssh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"host":"192.0.2.51","username":"admin","auth":{{"type":"password","password":"secret"}},"stig_id":"NetApp_ONTAP_DSC_9-x_STIG","platform":"ontap","asset_id":"{asset_id}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scan/ssh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"host":"192.0.2.50","username":"admin","auth":{"type":"password","password":"secret"},"stig_id":"NetApp_ONTAP_DSC_9-x_STIG","platform":"ontap","asset_id":"missing"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut wrong_platform = ManagedAsset::new("freebsd-01", "192.0.2.60", CheckPlatform::Bsd);
        wrong_platform.port = Some(2222);
        let wrong_platform_id = wrong_platform.id.clone();
        save_assets(&state.db(), &[wrong_platform]).unwrap();
        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scan/ssh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"host":"192.0.2.60","port":2222,"username":"admin","auth":{{"type":"password","password":"secret"}},"stig_id":"NetApp_ONTAP_DSC_9-x_STIG","platform":"ontap","asset_id":"{wrong_platform_id}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn completed_ssh_evaluation_updates_asset_by_verified_endpoint_address() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let asset = ManagedAsset::new("filer-display-name", "192.0.2.70", CheckPlatform::Ontap);
        let asset_id = asset.id.clone();
        save_assets(&state.db(), &[asset]).unwrap();

        update_asset_after_eval(
            &state.db(),
            &asset_id,
            "NetApp_ONTAP_DSC_9-x_STIG",
            "192.0.2.70",
            AssetIdentityBinding::Address,
            Some(97.5),
            "checklist-1",
        )
        .unwrap();
        let stored = load_assets(&state.db()).unwrap();
        assert_eq!(stored[0].last_compliance_pct, Some(97.5));
        assert_eq!(stored[0].last_checklist_ids, vec!["checklist-1"]);

        assert!(update_asset_after_eval(
            &state.db(),
            &asset_id,
            "NetApp_ONTAP_DSC_9-x_STIG",
            "192.0.2.70",
            AssetIdentityBinding::Name,
            Some(100.0),
            "checklist-2",
        )
        .is_err());
    }

    #[test]
    fn completed_all_not_applicable_evaluation_keeps_linked_asset_history() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let asset = ManagedAsset::new("filer-display-name", "192.0.2.70", CheckPlatform::Ontap);
        let asset_id = asset.id.clone();
        save_assets(&state.db(), &[asset]).unwrap();
        let mut response = serde_json::json!({
            "success": true,
            "data": {
                "id": "all-not-applicable-checklist",
                "assessed_pass_pct": null,
                "benchmark_coverage_pct": 100.0,
                "collection_complete": true
            },
            "error": null
        });

        update_linked_asset_after_persist_or_warn(
            &mut response,
            &state.db(),
            &asset_id,
            "NetApp_ONTAP_DSC_9-x_STIG",
            "192.0.2.70",
            AssetIdentityBinding::Address,
        );

        let stored = load_assets(&state.db()).unwrap();
        assert!(stored[0].last_evaluated.is_some());
        assert_eq!(stored[0].last_compliance_pct, None);
        assert_eq!(
            stored[0].last_checklist_ids,
            vec!["all-not-applicable-checklist"]
        );
        assert!(response["data"].get("asset_update_warning").is_none());
    }

    #[test]
    fn post_persist_asset_update_failure_is_returned_as_a_non_retry_warning() {
        let (_temporary, state) = test_state();
        let mut response = serde_json::json!({
            "success": true,
            "data": {
                "id": "saved-checklist-1",
                "assessed_pass_pct": 95.0,
                "collection_complete": true
            },
            "error": null
        });

        update_linked_asset_after_persist_or_warn(
            &mut response,
            &state.db(),
            "asset-removed-after-evaluation",
            "NetApp_ONTAP_DSC_9-x_STIG",
            "192.0.2.70",
            AssetIdentityBinding::Address,
        );

        assert_eq!(response["data"]["id"].as_str(), Some("saved-checklist-1"));
        let warning = response["data"]["asset_update_warning"]
            .as_str()
            .expect("the persisted success must carry an asset warning");
        assert!(warning.contains("was saved"));
        assert!(warning.contains("Do not rerun"));
        assert!(response["error"].is_null());
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
    async fn verified_all_not_applicable_checklist_has_null_pass_rate_and_full_coverage() {
        let (_temporary, state) = test_state();
        let mut checklist = forged_automated_checklist();
        checklist.findings[0].status = FindingStatus::NotApplicable;
        checklist.findings[0].source = FindingSource::Manual;
        let id = checklist.id.to_string();
        let summary = checklist.summary();
        assert_eq!(defensible_scores(&checklist, &summary), (None, Some(100.0)));
        state
            .db()
            .save_checklist_with_audit(&checklist, "checklist.saved", "test", None)
            .unwrap();

        let list_response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/checklists")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(list_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let listed = &payload["data"]["checklists"][0];
        assert!(listed["assessed_pass_pct"].is_null());
        assert!(listed["compliance_pct"].is_null());
        assert_eq!(listed["benchmark_coverage_pct"].as_f64(), Some(100.0));

        let detail_response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/checklists/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(detail_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(payload["data"]["assessed_pass_pct"].is_null());
        assert!(payload["data"]["compliance_pct"].is_null());
        assert_eq!(
            payload["data"]["benchmark_coverage_pct"].as_f64(),
            Some(100.0)
        );
    }

    #[tokio::test]
    async fn stigman_push_rejects_blank_collection_before_remote_io() {
        let (_temporary, state) = test_state();
        let checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        state
            .db()
            .save_checklist_with_audit(&checklist, "checklist.saved", "test", None)
            .unwrap();

        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/stigman/push/{id}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"collection_id":"   "}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["success"].as_bool(), Some(false));
        assert_eq!(
            payload["error"].as_str(),
            Some("STIG-Manager collection ID is required")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_stigman_push_refreshes_revision_and_serializes_deletion() {
        let (_temporary, state) = test_state();
        let checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        state
            .db()
            .save_checklist_with_audit(&checklist, "checklist.saved", "test", None)
            .unwrap();

        // Capture the same initial revision the HTTP push handler sees, then
        // hold the remote-asset queue so a finding edit can complete first.
        let queued = queue_stigman_checklist_push(&state, &id).unwrap();
        let remote_lock = state
            .inner
            .stigman_push_locks
            .lock_for("collection-7", &checklist.asset.hostname);
        let remote_blocker = remote_lock.lock().await;
        let push_state = state.clone();
        let push_task = tokio::spawn(async move {
            lock_current_stigman_checklist_push(&push_state, "collection-7", queued).await
        });

        let update_response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/checklists/{id}/findings/V-1"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"comments":"edited while the push was queued"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update_response.status(), StatusCode::OK);

        drop(remote_blocker);
        let locked = tokio::time::timeout(Duration::from_secs(1), push_task)
            .await
            .expect("queued push did not resume")
            .expect("queued push task panicked")
            .expect("queued push failed to refresh its checklist");
        assert_eq!(
            locked.checklist.findings[0].comments,
            "edited while the push was queued"
        );

        // The refreshed snapshot guard is retained for the whole remote push;
        // deletion must wait until the publisher releases it.
        let delete_state = state.clone();
        let delete_id = id.clone();
        let mut delete_task = tokio::spawn(async move {
            legacy_reference_routes()
                .with_state(delete_state)
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/checklists/{delete_id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut delete_task)
                .await
                .is_err(),
            "checklist deletion bypassed the active push snapshot"
        );
        assert!(state.db().load_checklist(&id).is_ok());

        drop(locked);
        let delete_response = tokio::time::timeout(Duration::from_secs(1), delete_task)
            .await
            .expect("checklist deletion stayed blocked")
            .expect("checklist deletion task panicked");
        assert_eq!(delete_response.status(), StatusCode::OK);
        assert!(state.db().load_checklist(&id).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_stigman_push_aborts_if_checklist_was_deleted() {
        let (_temporary, state) = test_state();
        let checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        state
            .db()
            .save_checklist_with_audit(&checklist, "checklist.saved", "test", None)
            .unwrap();

        let queued = queue_stigman_checklist_push(&state, &id).unwrap();
        let remote_lock = state
            .inner
            .stigman_push_locks
            .lock_for("collection-7", &checklist.asset.hostname);
        let remote_blocker = remote_lock.lock().await;
        let push_state = state.clone();
        let push_task = tokio::spawn(async move {
            lock_current_stigman_checklist_push(&push_state, "collection-7", queued).await
        });

        let delete_response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/checklists/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_response.status(), StatusCode::OK);

        drop(remote_blocker);
        let result = tokio::time::timeout(Duration::from_secs(1), push_task)
            .await
            .expect("queued push did not resume")
            .expect("queued push task panicked");
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("a deleted checklist must not be published"),
        };
        assert!(error.contains("was deleted while"), "{error}");
    }

    #[tokio::test]
    async fn json_import_cannot_forge_automated_attribution() {
        let (_temporary, state) = test_state();
        let checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        let boundary = "automatestig-forged-checklist";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"forged.JSON\"\r\nContent-Type: application/json\r\n\r\n{}\r\n--{boundary}--\r\n",
            serde_json::to_string(&checklist).unwrap()
        );
        let response = legacy_reference_routes()
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
        let assigned_id = payload["data"]["id"].as_str().unwrap();
        assert_ne!(assigned_id, id);

        let stored = state.db().load_checklist(assigned_id).unwrap();
        assert_eq!(stored.findings[0].source, FindingSource::Imported);
        assert_eq!(
            stored.evaluation_provenance.as_ref().unwrap().origin,
            EvaluationOrigin::ImportedChecklist
        );
        assert!(
            crate::stigman::StigManagerClient::checklist_to_reviews(&stored).is_empty(),
            "imported findings are not scanner-owned and must never enter sparse delivery"
        );
        assert!(state.db().load_checklist(&id).is_err());
    }

    #[tokio::test]
    async fn json_import_with_existing_id_gets_fresh_identity_without_overwrite() {
        let (_temporary, state) = test_state();
        let mut existing = forged_automated_checklist();
        existing.generated_by = "Existing trusted local row".to_string();
        existing.findings[0].source = FindingSource::Manual;
        let claimed_id = existing.id.to_string();
        state
            .db()
            .save_checklist_with_audit(&existing, "checklist.saved", "test", None)
            .unwrap();
        let existing_json = serde_json::to_value(&existing).unwrap();

        let mut imported = existing.clone();
        imported.asset.hostname = "imported-device".to_string();
        imported.generated_by = "Untrusted uploaded JSON".to_string();
        let boundary = "automatestig-colliding-checklist";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"collision.json\"\r\nContent-Type: application/json\r\n\r\n{}\r\n--{boundary}--\r\n",
            serde_json::to_string(&imported).unwrap()
        );
        let response = legacy_reference_routes()
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
        let assigned_id = payload["data"]["id"].as_str().unwrap();
        assert_ne!(assigned_id, claimed_id);

        let unchanged = state.db().load_checklist(&claimed_id).unwrap();
        assert_eq!(serde_json::to_value(unchanged).unwrap(), existing_json);
        let imported = state.db().load_checklist(assigned_id).unwrap();
        assert_eq!(imported.asset.hostname, "imported-device");
        assert_eq!(state.db().list_checklists().unwrap().len(), 2);

        let import_event = state
            .db()
            .list_audit_events()
            .unwrap()
            .into_iter()
            .find(|event| event.event_type == "checklist.imported")
            .unwrap();
        let details: serde_json::Value =
            serde_json::from_str(import_event.details_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            details["claimed_checklist_id"].as_str(),
            Some(claimed_id.as_str())
        );
        assert_eq!(details["assigned_checklist_id"].as_str(), Some(assigned_id));
    }

    #[tokio::test]
    async fn deleting_a_checklist_recomputes_and_then_clears_linked_asset_summary() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let mut older = forged_automated_checklist();
        older.findings[0].source = FindingSource::Manual;
        older.modified_at = chrono::Utc::now() - chrono::Duration::hours(2);

        let mut all_not_applicable = older.clone();
        all_not_applicable.id = uuid::Uuid::new_v4();
        all_not_applicable.modified_at = chrono::Utc::now() - chrono::Duration::minutes(90);
        all_not_applicable.findings[0].status = FindingStatus::NotApplicable;

        let mut newer = all_not_applicable.clone();
        newer.id = uuid::Uuid::new_v4();
        newer.modified_at = chrono::Utc::now() - chrono::Duration::hours(1);
        newer.findings[0].status = FindingStatus::Open;
        let older_id = older.id.to_string();
        let all_not_applicable_id = all_not_applicable.id.to_string();
        let newer_id = newer.id.to_string();
        for checklist in [&older, &all_not_applicable, &newer] {
            state
                .db()
                .save_checklist_with_audit(checklist, "checklist.saved", "test", None)
                .unwrap();
        }

        let mut asset = ManagedAsset::new("device-01", "192.0.2.80", CheckPlatform::Ontap);
        asset.last_checklist_ids = vec![
            all_not_applicable_id.clone(),
            older_id.clone(),
            "historically-deleted".to_string(),
            newer_id.clone(),
        ];
        asset.last_evaluated = Some(newer.modified_at);
        asset.last_compliance_pct = Some(0.0);
        save_assets(&state.db(), &[asset]).unwrap();

        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/checklists/{newer_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["data"]["deleted"].as_bool(), Some(true));
        assert_eq!(payload["data"]["updated_assets"].as_u64(), Some(1));

        let assets = load_assets(&state.db()).unwrap();
        assert_eq!(
            assets[0].last_checklist_ids,
            vec![older_id.clone(), all_not_applicable_id.clone()]
        );
        assert_eq!(
            assets[0].last_evaluated,
            Some(all_not_applicable.modified_at)
        );
        assert_eq!(assets[0].last_compliance_pct, None);

        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/checklists/{all_not_applicable_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let assets = load_assets(&state.db()).unwrap();
        assert_eq!(assets[0].last_checklist_ids, vec![older_id.clone()]);
        assert_eq!(assets[0].last_evaluated, Some(older.modified_at));
        assert_eq!(assets[0].last_compliance_pct, Some(100.0));

        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/checklists/{older_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let assets = load_assets(&state.db()).unwrap();
        assert!(assets[0].last_checklist_ids.is_empty());
        assert!(assets[0].last_evaluated.is_none());
        assert!(assets[0].last_compliance_pct.is_none());
    }

    #[tokio::test]
    async fn checklist_delete_reports_partial_success_when_inventory_cleanup_fails() {
        let (_temporary, state) = test_state();
        let checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        state
            .db()
            .save_checklist_with_audit(&checklist, "checklist.saved", "test", None)
            .unwrap();
        state
            .db()
            .set_config("asset_inventory", "not-json")
            .unwrap();

        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/checklists/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["success"].as_bool(), Some(true));
        assert_eq!(payload["data"]["deleted"].as_bool(), Some(true));
        let warning = payload["data"]["inventory_cleanup_warning"]
            .as_str()
            .unwrap();
        assert!(warning.contains("already deleted"), "{warning}");
        assert!(warning.contains("do not retry"), "{warning}");
        assert!(state.db().load_checklist(&id).is_err());
    }

    #[tokio::test]
    async fn deleting_a_missing_checklist_returns_not_found() {
        let (_temporary, state) = test_state();
        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/checklists/missing-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn asset_deletion_preserves_checklists_and_then_returns_not_found() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::ManagedAsset;

        let (_temporary, state) = test_state();
        let mut checklist = forged_automated_checklist();
        checklist.findings[0].source = FindingSource::Manual;
        let checklist_id = checklist.id.to_string();
        state
            .db()
            .save_checklist_with_audit(&checklist, "checklist.saved", "test", None)
            .unwrap();
        let mut asset = ManagedAsset::new("device-01", "192.0.2.80", CheckPlatform::Ontap);
        let asset_id = asset.id.clone();
        asset.last_checklist_ids = vec![checklist_id.clone()];
        save_assets(&state.db(), &[asset]).unwrap();

        let response = legacy_reference_routes()
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/assets/{asset_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["data"]["deleted"].as_bool(), Some(true));
        assert!(load_assets(&state.db()).unwrap().is_empty());
        assert!(state.db().load_checklist(&checklist_id).is_ok());

        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/assets/{asset_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["success"].as_bool(), Some(false));
        assert!(payload["error"].as_str().unwrap().contains(&asset_id));
    }

    #[test]
    fn zip_export_uses_unique_names_for_repeated_host_and_stig() {
        let (_temporary, state) = test_state();
        let mut first = forged_automated_checklist();
        first.findings[0].source = FindingSource::Manual;
        let mut second = first.clone();
        second.id = uuid::Uuid::new_v4();
        for checklist in [&first, &second] {
            state
                .db()
                .save_checklist_with_audit(checklist, "checklist.saved", "test", None)
                .unwrap();
        }
        let db = state.db();
        let rows = db.list_checklists().unwrap();
        let bytes = build_checklist_export_zip(&db, &rows).unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(archive.len(), 2);
        let names: Vec<_> = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect();
        assert_ne!(names[0], names[1]);
        assert!(names
            .iter()
            .any(|name| name.contains(&first.id.to_string())));
        assert!(names
            .iter()
            .any(|name| name.contains(&second.id.to_string())));
    }

    #[tokio::test]
    async fn export_returns_the_specific_sanitized_block_reason() {
        let (_temporary, state) = test_state();
        let checklist = forged_automated_checklist();
        let id = checklist.id.to_string();
        state
            .db()
            .save_checklist_with_audit(&checklist, "checklist.saved", "test", None)
            .unwrap();
        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/export/ckl/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let message = String::from_utf8(body.to_vec()).unwrap();
        assert!(message.starts_with("Checklist cannot be exported:"));
        assert!(message.contains("provenance"), "{message}");
        assert!(!message.contains('\n'));
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
            answer_file: None,
            answer_files: Vec::new(),
            unsafe_legacy_evidence: false,
        });
        let boundary = "automatestig-incomplete-checklist";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"incomplete.json\"\r\nContent-Type: application/json\r\n\r\n{}\r\n--{boundary}--\r\n",
            serde_json::to_string(&checklist).unwrap()
        );
        let response = legacy_reference_routes()
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
        let response = legacy_reference_routes()
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
        assert!(
            crate::stigman::StigManagerClient::checklist_to_reviews(&stored).is_empty(),
            "a human edit removes scanner ownership and must suppress sparse delivery"
        );
    }

    #[tokio::test]
    async fn checklist_detail_exposes_real_checklist_and_finding_timestamps() {
        let (_temporary, state) = test_state();
        let mut checklist = forged_automated_checklist();
        checklist.findings[0].evaluated_by = "AutomateSTIG test evaluator".to_string();
        let id = checklist.id.to_string();
        state
            .db()
            .save_evaluation(&checklist, "test", None)
            .unwrap();

        let response = legacy_reference_routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/checklists/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(payload["data"]["created_at"].as_str().is_some());
        assert!(payload["data"]["modified_at"].as_str().is_some());
        assert!(payload["data"]["findings"][0]["evaluated_at"]
            .as_str()
            .is_some());
        assert_eq!(
            payload["data"]["findings"][0]["evaluated_by"].as_str(),
            Some("AutomateSTIG test evaluator")
        );
    }
}
