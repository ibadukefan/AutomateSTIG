//! Versioned scanner-first API.
//!
//! This surface intentionally omits local asset, finding, answer-file,
//! checklist-portfolio, and general STIG-library management. STIG Manager is
//! authoritative; AutomateSTIG exposes scanner profiles, immutable runs, and
//! sparse delivery only.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Write};
use std::time::Duration;

use automatestig_core::models::checklist::EvaluationOrigin;
use automatestig_core::models::finding::{FindingSource, FindingStatus};
use automatestig_core::scanner_benchmarks::bundled_scanner_benchmark;
use automatestig_core::scanner_profiles::{
    bundled_scanner_profile, bundled_scanner_profiles, ScannerEvidenceMode, ScannerProfileReadiness,
};
use automatestig_core::selected_run_handoff as handoff;
use automatestig_core::target_adapters::{
    built_in_target_adapter, AdapterEvidenceEnvelope, AdapterOperationEvidence, AdapterRequest,
    BuiltInTargetAdapter, DeviceFingerprint, EvidenceTransportIdentity, ReadOnlyOperationPlan,
};
use automatestig_core::xccdf_results::{write_sparse_xccdf_1_2_results, XccdfResultsProvenance};
use automatestig_integrations::stig_manager::{
    classify_review_conflicts, scanner_review_is_exact_noop, ExistingMappedReview,
    ScannerDeliveryTarget, ScannerReview, ScannerReviewResult, StigManagerClient,
    StigManagerClientSecret, StigManagerConnection, StigManagerError, StigManagerErrorKind,
};
use automatestig_storage::{
    DeliveryReceipt, DeliveryRecord, DeliveryState, NewPendingDelivery, NewReconciliationReceipt,
    NewScanEvidenceArtifact, NewScanJob, NewScanOperationCheckpoint, NewScanRun,
    NewTargetConnectionProfile, RetainedScanEvidenceArtifact, RetainedScanOperationCheckpoint,
    ScanEvidenceArtifactMetadata, ScanEvidencePurgeReason, ScanEvidenceState, ScanJobRecord,
    ScanJobState, ScanRunRecord, StorageError, DEFAULT_OPERATIONAL_PAGE_SIZE,
    DEFAULT_OPERATIONAL_RETENTION_DAYS, DEFAULT_SCAN_EVIDENCE_RETENTION_DAYS,
    MAX_OPERATIONAL_PAGE_SIZE, MAX_OPERATIONAL_RETENTION_DAYS, MAX_SCAN_EVIDENCE_RETENTION_DAYS,
    MIN_OPERATIONAL_RETENTION_DAYS, MIN_SCAN_EVIDENCE_RETENTION_DAYS,
    SCAN_EVIDENCE_ENCRYPTION_ALGORITHM,
};
use axum::body::Bytes;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::AppState;

const PREFLIGHT_TTL_MINUTES: i64 = 10;
const MAX_PREFLIGHTS: usize = 256;
const EVIDENCE_RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(15 * 60);
const EVIDENCE_RETENTION_SWEEP_BATCH: usize = 256;
const CHECKPOINT_SCHEMA: &str = "automatestig.ssh-operation-checkpoint.v1";

/// Enforce scanner-evidence retention while a long-running GUI remains open.
/// Startup and every evidence read also enforce expiry; this low-frequency,
/// bounded worker closes the idle-run gap without blocking the async runtime.
pub fn start_evidence_retention_sweeper(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(EVIDENCE_RETENTION_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Database initialization already purges expired rows. Consume the
        // immediate first tick so the background worker starts after one full
        // interval instead of competing with startup migrations.
        interval.tick().await;
        loop {
            interval.tick().await;
            let sweep_state = state.clone();
            let result = tokio::task::spawn_blocking(move || {
                let evidence = sweep_state
                    .db()
                    .purge_expired_scan_evidence(EVIDENCE_RETENTION_SWEEP_BATCH)
                    .map(|purged| purged.len())?;
                let retention_days =
                    operational_retention_days(&sweep_state).map_err(StorageError::InvalidData)?;
                let history = sweep_state
                    .db()
                    .sweep_terminal_operational_history(
                        retention_days,
                        EVIDENCE_RETENTION_SWEEP_BATCH,
                    )?
                    .len();
                Ok::<_, StorageError>((evidence, history))
            })
            .await;
            match result {
                Ok(Ok((0, 0))) => {}
                Ok(Ok((evidence, history))) => tracing::info!(
                    purged_evidence_artifacts = evidence,
                    purged_operational_histories = history,
                    "Scanner retention sweep completed"
                ),
                Ok(Err(error)) => tracing::warn!(
                    error = %error,
                    "Scanner evidence retention sweep failed; it will retry on the next interval"
                ),
                Err(error) => tracing::warn!(
                    error = %error,
                    "Scanner evidence retention task failed; it will retry on the next interval"
                ),
            }
        }
    });
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/status", get(status))
        .route(
            "/stig-manager/connection",
            get(get_connection)
                .put(save_connection)
                .delete(delete_connection),
        )
        .route("/stig-manager/connection/test", post(test_connection))
        .route("/stig-manager/collections", get(list_collections))
        .route(
            "/stig-manager/collections/{collection_id}/assets",
            get(list_assets),
        )
        .route(
            "/stig-manager/collections/{collection_id}/assets/{asset_id}/assignments",
            get(list_assignments),
        )
        .route("/scanner/profiles", get(list_profiles))
        .route(
            "/scanner/retention",
            get(get_retention_policy).put(update_retention_policy),
        )
        .route(
            "/scanner/connection-profiles",
            get(list_target_connection_profiles).post(create_target_connection_profile),
        )
        .route(
            "/scanner/connection-profiles/{profile_id}",
            put(update_target_connection_profile).delete(delete_target_connection_profile),
        )
        .route("/runs/preflight", post(preflight))
        .route("/runs/ssh", post(enqueue_ssh_run))
        .route("/runs/evidence", post(run_evidence))
        .route("/runs/jobs", get(list_scan_jobs))
        .route("/runs/jobs/{job_id}", get(get_scan_job))
        .route("/runs/jobs/{job_id}/resume", post(resume_ssh_job))
        .route("/runs", get(list_runs))
        .route("/runs/purged", get(list_purged_runs))
        .route("/runs/{run_id}", get(get_run))
        .route(
            "/runs/{run_id}/delivery-attempts",
            get(list_delivery_attempts),
        )
        .route("/runs/{run_id}/deliver", post(deliver_run))
        .route("/runs/{run_id}/handoff", get(download_handoff))
        .route(
            "/runs/{run_id}/reconciliation-receipts",
            get(list_reconciliation_receipts).post(import_reconciliation_receipt),
        )
        .route("/runs/{run_id}/evidence/purge", post(purge_run_evidence))
}

#[derive(Serialize)]
struct ApiEnvelope<T> {
    success: bool,
    data: Option<T>,
    error: Option<ApiErrorBody>,
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: String,
}

fn ok(value: impl Serialize) -> Response {
    match serde_json::to_value(value) {
        Ok(value) => (
            StatusCode::OK,
            Json(ApiEnvelope {
                success: true,
                data: Some(value),
                error: None,
            }),
        )
            .into_response(),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialization_error",
            format!("Failed to serialize scanner response: {error}"),
        ),
    }
}

fn accepted(value: impl Serialize) -> Response {
    let response = ok(value);
    let (mut parts, body) = response.into_parts();
    parts.status = StatusCode::ACCEPTED;
    Response::from_parts(parts, body)
}

fn fail(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiEnvelope::<serde_json::Value> {
            success: false,
            data: None,
            error: Some(ApiErrorBody {
                code,
                message: message.into(),
            }),
        }),
    )
        .into_response()
}

async fn status() -> Response {
    let profiles = match bundled_scanner_profiles() {
        Ok(profiles) => profiles,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scanner_content_integrity",
                error.to_string(),
            )
        }
    };
    ok(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "scanner_version": env!("CARGO_PKG_VERSION"),
        "ready": !profiles.is_empty(),
        "profile_count": profiles.len(),
        "role": "difficult-device scanner and STIG Manager supplement",
    }))
}

#[derive(Serialize)]
struct SanitizedConnection {
    configured: bool,
    reachable: Option<bool>,
    api_url: String,
    token_url: String,
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gui_url: Option<String>,
    verify_tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stig_manager_version: Option<String>,
    capabilities: Vec<String>,
    privileges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tested_at: Option<String>,
}

impl SanitizedConnection {
    fn from_config(config: &crate::stigman::StigManagerConfig) -> Self {
        Self {
            configured: config.is_configured(),
            reachable: None,
            api_url: config.api_url.clone(),
            token_url: config.token_url.clone(),
            client_id: config.client_id.clone(),
            gui_url: config.gui_url.clone(),
            verify_tls: config.verify_tls,
            identity: None,
            stig_manager_version: None,
            capabilities: Vec::new(),
            privileges: Vec::new(),
            tested_at: None,
        }
    }
}

fn load_connection_config(state: &AppState) -> Result<crate::stigman::StigManagerConfig, String> {
    crate::api::load_stigman_config(&state.db(), &state.inner.data_dir)
}

fn configured_connection(
    state: &AppState,
) -> Result<crate::stigman::StigManagerConfig, Box<Response>> {
    let config = load_connection_config(state).map_err(|error| {
        Box::new(fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection_config_error",
            error,
        ))
    })?;
    if !config.is_configured() {
        return Err(Box::new(fail(
            StatusCode::PRECONDITION_REQUIRED,
            "stig_manager_not_configured",
            "Connect STIG Manager before selecting a remote destination.",
        )));
    }
    Ok(config)
}

fn stig_manager_destination_instance_id(config: &crate::stigman::StigManagerConfig) -> String {
    sha256_hex(config.api_url.as_bytes())
}

fn validate_delivery_destination_binding(
    expected_instance_id: &str,
    config: &crate::stigman::StigManagerConfig,
) -> Result<(), String> {
    if expected_instance_id == stig_manager_destination_instance_id(config) {
        return Ok(());
    }
    Err(
        "The configured STIG Manager instance changed after this run was preflighted. Restore the original connection or create a new scanner run for the current instance."
            .to_string(),
    )
}

fn allowed_stig_manager_destinations() -> Result<Vec<String>, String> {
    std::env::var("AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.len() > 255 || value.chars().any(char::is_control) {
                return Err(format!(
                    "AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST entry {value:?} is not a bounded printable hostname, IP, or CIDR"
                ));
            }
            Ok(value.to_string())
        })
        .collect()
}

async fn canonical_stig_manager_client(
    config: crate::stigman::StigManagerConfig,
) -> Result<StigManagerClient, String> {
    if !config.verify_tls {
        return Err(
            "The scanner API requires TLS certificate verification. Install the issuing CA instead of disabling verification."
                .to_string(),
        );
    }
    let connection = StigManagerConnection {
        api_url: config.api_url,
        token_url: config.token_url,
        client_id: config.client_id,
        allowed_private_addresses: Vec::new(),
    };
    StigManagerClient::new_with_destination_allowlist(
        connection,
        StigManagerClientSecret::new(config.client_secret),
        allowed_stig_manager_destinations()?,
    )
    .await
    .map_err(|error| error.to_string())
}

async fn get_connection(State(state): State<AppState>) -> Response {
    match load_connection_config(&state) {
        Ok(config) => ok(SanitizedConnection::from_config(&config)),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection_config_error",
            error,
        ),
    }
}

async fn save_connection(
    State(state): State<AppState>,
    request: Result<
        Json<crate::stigman::StigManagerConfig>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let Json(config) = match request {
        Ok(config) => config,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "invalid_connection",
                format!("Invalid connection settings: {error}"),
            )
        }
    };
    if !config.verify_tls {
        return fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "tls_verification_required",
            "Scanner connections require TLS certificate verification.",
        );
    }
    if let Err(error) = crate::api::persist_stigman_config(&state, config) {
        return fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connection_not_saved",
            error,
        );
    }
    match load_connection_config(&state) {
        Ok(config) => ok(SanitizedConnection::from_config(&config)),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection_config_error",
            error,
        ),
    }
}

async fn delete_connection(State(state): State<AppState>) -> Response {
    match state.db().delete_config("stigman_config") {
        Ok(deleted) => ok(serde_json::json!({
            "configured": false,
            "deleted": deleted,
        })),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection_delete_failed",
            error.to_string(),
        ),
    }
}

async fn test_connection(State(state): State<AppState>, body: Bytes) -> Response {
    let submitted = if body.iter().all(u8::is_ascii_whitespace) {
        None
    } else {
        match serde_json::from_slice(&body) {
            Ok(config) => Some(config),
            Err(error) => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "invalid_connection",
                    format!("Invalid connection settings: {error}"),
                )
            }
        }
    };
    let config = match crate::api::resolve_stigman_test_config(&state, submitted) {
        Ok(config) => config,
        Err(error) => {
            return fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "connection_test_failed",
                error,
            )
        }
    };
    let client = match canonical_stig_manager_client(config.clone()).await {
        Ok(client) => client,
        Err(error) => return fail(StatusCode::BAD_GATEWAY, "connection_test_failed", error),
    };
    let capabilities = match client.discover_capabilities().await {
        Ok(capabilities) => capabilities,
        Err(error) => {
            return fail(
                StatusCode::BAD_GATEWAY,
                "capability_discovery_failed",
                error.to_string(),
            )
        }
    };
    if let Err(error) = client.list_collections().await {
        return fail(
            StatusCode::BAD_GATEWAY,
            "authentication_test_failed",
            error.to_string(),
        );
    }
    ok(SanitizedConnection {
        configured: false,
        reachable: Some(true),
        api_url: config.api_url,
        token_url: config.token_url,
        client_id: config.client_id.clone(),
        gui_url: config.gui_url,
        verify_tls: config.verify_tls,
        identity: Some(config.client_id),
        stig_manager_version: Some(capabilities.server.version),
        capabilities: vec![
            "projected_asset_assignments".to_string(),
            "mapped_review_reads".to_string(),
            "sparse_review_writes".to_string(),
            "conditional_review_writes:unsupported".to_string(),
        ],
        privileges: vec!["collections:read confirmed".to_string()],
        tested_at: Some(Utc::now().to_rfc3339()),
    })
}

async fn list_collections(State(state): State<AppState>) -> Response {
    let config = match configured_connection(&state) {
        Ok(config) => config,
        Err(response) => return *response,
    };
    let client = match canonical_stig_manager_client(config).await {
        Ok(client) => client,
        Err(error) => return fail(StatusCode::BAD_GATEWAY, "connection_failed", error),
    };
    match client.list_collections().await {
        Ok(collections) => ok(serde_json::json!({ "collections": collections })),
        Err(error) => fail(
            StatusCode::BAD_GATEWAY,
            "collection_lookup_failed",
            error.to_string(),
        ),
    }
}

async fn list_assets(State(state): State<AppState>, Path(collection_id): Path<String>) -> Response {
    let config = match configured_connection(&state) {
        Ok(config) => config,
        Err(response) => return *response,
    };
    let client = match canonical_stig_manager_client(config).await {
        Ok(client) => client,
        Err(error) => return fail(StatusCode::BAD_GATEWAY, "connection_failed", error),
    };
    match client.list_assets(&collection_id).await {
        Ok(assets) => ok(serde_json::json!({ "assets": assets })),
        Err(error) => fail(
            StatusCode::BAD_GATEWAY,
            "asset_lookup_failed",
            error.to_string(),
        ),
    }
}

async fn list_assignments(
    State(state): State<AppState>,
    Path((collection_id, asset_id)): Path<(String, String)>,
) -> Response {
    let config = match configured_connection(&state) {
        Ok(config) => config,
        Err(response) => return *response,
    };
    let client = match canonical_stig_manager_client(config).await {
        Ok(client) => client,
        Err(error) => return fail(StatusCode::BAD_GATEWAY, "connection_failed", error),
    };
    let asset = match client.get_asset(&collection_id, &asset_id).await {
        Ok(asset) => asset,
        Err(error) => {
            return fail(
                StatusCode::BAD_GATEWAY,
                "assignment_lookup_failed",
                error.to_string(),
            )
        }
    };
    let assignments: Vec<_> = asset
        .stigs
        .into_iter()
        .map(|assignment| {
            let profile = bundled_scanner_profiles().ok().and_then(|profiles| {
                profiles.iter().find(|profile| {
                    profile.stig_id() == assignment.benchmark_id
                        && profile.stig_release() == assignment.revision
                })
            });
            let release_supported = profile.is_some_and(|profile| {
                profile.readiness() != ScannerProfileReadiness::Experimental
                    && built_in_target_adapter(profile.target_key()).is_some_and(|adapter| {
                        !adapter.compatibility().accepted_tested_versions.is_empty()
                    })
            });
            serde_json::json!({
                "assignment_id": format!("{}:{}", assignment.benchmark_id, assignment.revision),
                "stig_id": assignment.benchmark_id,
                "stig_revision": assignment.revision,
                "title": profile.map(|profile| profile.display_name()),
                "profile_id": profile.map(|profile| profile.target_key()),
                "scanner_ready": release_supported,
                "pilot_runnable": profile.is_some(),
                "release_supported": release_supported,
                "unsupported_reason": if profile.is_none() {
                    Some("No exact release-bundled scanner profile matches this assigned revision.")
                } else {
                    None
                },
                "rule_count": assignment.rule_count,
                "revision_pinned": assignment.revision_pinned,
            })
        })
        .collect();
    ok(serde_json::json!({
        "asset_id": asset.asset_id,
        "asset_name": asset.name,
        "assignments": assignments,
    }))
}

async fn list_profiles() -> Response {
    let profiles = match bundled_scanner_profiles() {
        Ok(profiles) => profiles,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scanner_content_integrity",
                error.to_string(),
            )
        }
    };
    let mut response = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let adapter = match built_in_target_adapter(profile.target_key()) {
            Some(adapter) => adapter,
            None => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "adapter_missing",
                    format!("No adapter is bundled for {}", profile.target_key()),
                )
            }
        };
        let descriptor = match adapter.descriptor() {
            Ok(descriptor) => descriptor,
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "adapter_integrity",
                    error.to_string(),
                )
            }
        };
        let benchmark = match bundled_scanner_benchmark(profile.target_key()) {
            Ok(Some(benchmark)) => benchmark,
            Ok(None) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "benchmark_missing",
                    format!(
                        "No benchmark subset is bundled for {}",
                        profile.target_key()
                    ),
                )
            }
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "benchmark_integrity",
                    error.to_string(),
                )
            }
        };
        let coverage = profile.coverage();
        let release_supported = profile.readiness() != ScannerProfileReadiness::Experimental
            && !descriptor.compatibility.accepted_tested_versions.is_empty();
        let methods: &[&str] = match profile.evidence_mode() {
            ScannerEvidenceMode::SshTranscript => &["ssh", "evidence"],
            ScannerEvidenceMode::RunningConfiguration => &["configuration"],
        };
        response.push(serde_json::json!({
            "profile_id": profile.target_key(),
            "stig_id": profile.stig_id(),
            "stig_revision": profile.stig_release(),
            "title": profile.display_name(),
            "target_name": profile.display_name(),
            "adapter_name": descriptor.adapter_id.clone(),
            "adapter_id": descriptor.adapter_id,
            "adapter_version": descriptor.adapter_version,
            "state": profile.readiness(),
            // Experimental profiles are runnable pilots, but their acceptance
            // state is explicit and cannot be mistaken for production support.
            "scanner_ready": release_supported,
            "pilot_runnable": true,
            "release_supported": release_supported,
            "automated_rules": coverage.automated_checks(),
            "manual_rules": coverage.manual_rules(),
            "full_benchmark_rules": coverage.benchmark_rules(),
            "reviewed_rules": coverage.reviewed_rules(),
            "total_rules": coverage.benchmark_rules(),
            "collection_methods": methods,
            "tested_versions": descriptor.compatibility.accepted_tested_versions,
            "compatibility": descriptor.compatibility,
            "content_sha256": benchmark.source().benchmark_model_sha256,
            "check_pack_sha256": profile.digests().check_pack_sha256(),
            "profile_sha256": profile.digests().profile_sha256(),
            "trust_state": "release_bundled",
            "acceptance_state": "experimental_live_acceptance_required",
            "validation": {
                "synthetic_fixture_requirements": {
                    "status": "required_inventory",
                    "required_rule_contract_count": coverage.automated_checks(),
                    "required_case_classes": ["positive", "negative", "collection_error"],
                    "required_fixture_case_count": coverage.automated_checks().saturating_mul(3),
                    "measured_fixture_case_count": null,
                    "measured_false_passes": null,
                    "reason": "The runtime profile reports the required synthetic inventory only; release test completion and false-pass measurements are not derived from coverage counts.",
                },
                "protected_live_device": {
                    "status": "not_run",
                    "authorized_device_sample_count": null,
                    "measured_false_passes": null,
                    "measured_false_pass_rate": null,
                    "reason": "Human-gated protected-device acceptance has not been attached to this release profile.",
                },
            },
            "source": benchmark.source(),
        }));
    }
    ok(serde_json::json!({ "profiles": response }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetConnectionProfileRequest {
    scanner_profile_id: String,
    adapter: String,
    endpoint: String,
    port: u16,
    #[serde(default)]
    credential_reference: Option<String>,
}

fn save_target_connection_profile_response(
    state: &AppState,
    id: String,
    request: TargetConnectionProfileRequest,
) -> Response {
    let scanner_profile_id = request.scanner_profile_id.trim();
    let profile = match bundled_scanner_profile(scanner_profile_id) {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "connection_profile_scanner_profile_unknown",
                "The selected scanner profile is not bundled in this release.",
            )
        }
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scanner_content_integrity",
                error.to_string(),
            )
        }
    };
    let Some(adapter) = built_in_target_adapter(profile.target_key()) else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection_profile_adapter_missing",
            "The selected scanner profile has no bundled adapter.",
        );
    };
    if request.adapter.trim() != adapter.adapter_id() {
        return fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connection_profile_adapter_mismatch",
            format!(
                "The selected scanner profile requires adapter {}.",
                adapter.adapter_id()
            ),
        );
    }
    let credential_reference = request
        .credential_reference
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let profile = NewTargetConnectionProfile {
        id,
        scanner_profile_id: scanner_profile_id.to_string(),
        adapter: adapter.adapter_id().to_string(),
        endpoint: request.endpoint.trim().to_string(),
        port: request.port,
        credential_reference,
    };
    match state.db().save_target_connection_profile(&profile) {
        Ok(profile) => ok(serde_json::json!({ "profile": profile })),
        Err(StorageError::InvalidData(error)) => fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connection_profile_invalid",
            error,
        ),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection_profile_save_failed",
            error.to_string(),
        ),
    }
}

async fn list_target_connection_profiles(State(state): State<AppState>) -> Response {
    match state.db().list_target_connection_profiles() {
        Ok(profiles) => ok(serde_json::json!({ "profiles": profiles })),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection_profile_list_failed",
            error.to_string(),
        ),
    }
}

async fn create_target_connection_profile(
    State(state): State<AppState>,
    request: Result<Json<TargetConnectionProfileRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "connection_profile_invalid",
                format!("Invalid target connection profile: {error}"),
            )
        }
    };
    save_target_connection_profile_response(&state, uuid::Uuid::new_v4().to_string(), request)
}

async fn update_target_connection_profile(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    request: Result<Json<TargetConnectionProfileRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "connection_profile_invalid",
                format!("Invalid target connection profile: {error}"),
            )
        }
    };
    match state.db().get_target_connection_profile(&profile_id) {
        Ok(_) => save_target_connection_profile_response(&state, profile_id, request),
        Err(StorageError::NotFound(_)) => fail(
            StatusCode::NOT_FOUND,
            "connection_profile_not_found",
            "Target connection profile was not found.",
        ),
        Err(error) => fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connection_profile_invalid",
            error.to_string(),
        ),
    }
}

async fn delete_target_connection_profile(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
) -> Response {
    match state.db().delete_target_connection_profile(&profile_id) {
        Ok(true) => ok(serde_json::json!({ "deleted": true, "id": profile_id })),
        Ok(false) | Err(StorageError::NotFound(_)) => fail(
            StatusCode::NOT_FOUND,
            "connection_profile_not_found",
            "Target connection profile was not found.",
        ),
        Err(StorageError::InvalidData(error)) => fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "connection_profile_invalid",
            error,
        ),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection_profile_delete_failed",
            error.to_string(),
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunMode {
    Connected,
    Disconnected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DestinationSelection {
    collection_id: String,
    asset_id: String,
    assignment_id: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TargetSelection {
    host: String,
    port: u16,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SubmittedCredential {
    Password {
        username: String,
        password: String,
    },
    KeyFile {
        username: String,
        path: String,
        passphrase: Option<String>,
    },
    Reference {
        #[serde(rename = "username")]
        _username: String,
        #[serde(rename = "reference")]
        _reference: String,
    },
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct InputMetadata {
    name: String,
    size: u64,
    #[serde(rename = "type")]
    media_type: String,
    sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CollectionMethod {
    Ssh,
    Evidence,
    Configuration,
}

impl CollectionMethod {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ssh" => Ok(Self::Ssh),
            "evidence" => Ok(Self::Evidence),
            "configuration" => Ok(Self::Configuration),
            _ => Err("collection method must be ssh, evidence, or configuration".to_string()),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Evidence => "evidence",
            Self::Configuration => "configuration",
        }
    }
}

impl<'de> Deserialize<'de> for CollectionMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
struct PreflightRequest {
    mode: RunMode,
    profile_id: String,
    #[serde(default)]
    connection_profile_id: Option<String>,
    collection_method: CollectionMethod,
    #[serde(default)]
    pilot_acknowledged: bool,
    destination: Option<DestinationSelection>,
    target: Option<TargetSelection>,
    credential: Option<SubmittedCredential>,
    input: Option<InputMetadata>,
    organization_policy: Option<InputMetadata>,
    organization_policy_signature: Option<InputMetadata>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredPreflight {
    expires_at: String,
    mode: RunMode,
    profile_id: String,
    connection_profile_id: Option<String>,
    collection_method: CollectionMethod,
    pilot_acknowledged: bool,
    destination: Option<DestinationSelection>,
    target: Option<TargetSelection>,
    input: Option<InputMetadata>,
    organization_policy: Option<InputMetadata>,
    organization_policy_signature: Option<InputMetadata>,
    device: DeviceFingerprint,
    plan: ReadOnlyOperationPlan,
    transport_identity: EvidenceTransportIdentity,
    destination_asset_name: Option<String>,
    destination_asset_fqdn: Option<String>,
    destination_asset_ip: Option<String>,
    destination_instance_id: Option<String>,
    remote_rule_count: Option<u64>,
}

impl StoredPreflight {
    fn expires_at(&self) -> Result<DateTime<Utc>, String> {
        DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|error| format!("Invalid preflight expiration: {error}"))
    }
}

fn expected_methods(adapter: BuiltInTargetAdapter) -> &'static [CollectionMethod] {
    match adapter {
        BuiltInTargetAdapter::NetAppOntap9 | BuiltInTargetAdapter::FreeBsdGpos => {
            &[CollectionMethod::Ssh, CollectionMethod::Evidence]
        }
        BuiltInTargetAdapter::CiscoIosXeRouterNdm => &[CollectionMethod::Configuration],
    }
}

fn synthetic_upload_fingerprint(adapter: BuiltInTargetAdapter) -> DeviceFingerprint {
    match adapter {
        BuiltInTargetAdapter::NetAppOntap9 => {
            DeviceFingerprint::new("pending-upload", "NetApp", "ONTAP", "9")
        }
        BuiltInTargetAdapter::FreeBsdGpos => {
            DeviceFingerprint::new("pending-upload", "FreeBSD", "FreeBSD", "14")
        }
        BuiltInTargetAdapter::CiscoIosXeRouterNdm => {
            DeviceFingerprint::new("pending-upload", "Cisco", "IOS-XE", "17")
        }
    }
}

fn operation_preview(plan: &ReadOnlyOperationPlan) -> Vec<serde_json::Value> {
    plan.operations
        .iter()
        .map(|operation| {
            let request = match &operation.request {
                AdapterRequest::SshCli { command } => command.clone(),
                AdapterRequest::OfflineConfiguration { document_kind } => document_kind.clone(),
                AdapterRequest::NetconfRpc { rpc } => rpc.clone(),
                AdapterRequest::RestconfGet { path } | AdapterRequest::HttpsApiGet { path } => {
                    path.clone()
                }
            };
            serde_json::json!({
                "name": operation.operation_id,
                "label": operation.data_key,
                "command": request,
                "purpose": operation.description,
                "privilege": operation.privilege,
                "read_only": true,
                "estimated_duration_ms": operation.estimated_duration_ms,
                "maximum_duration_ms": operation.maximum_duration_ms,
            })
        })
        .collect()
}

fn identity_matches_asset(
    observed: &str,
    name: &str,
    fqdn: Option<&str>,
    ip: Option<&str>,
) -> bool {
    [Some(name), fqdn, ip]
        .into_iter()
        .flatten()
        .any(|candidate| candidate.trim().eq_ignore_ascii_case(observed.trim()))
}

fn observed_hostname_matches_asset(observed: &str, name: &str, fqdn: Option<&str>) -> bool {
    let observed = observed.trim().trim_end_matches('.');
    let exact = [Some(name), fqdn]
        .into_iter()
        .flatten()
        .map(str::trim)
        .map(|value| value.trim_end_matches('.'))
        .any(|candidate| candidate.eq_ignore_ascii_case(observed));
    if exact {
        return true;
    }
    let name = name.trim().trim_end_matches('.');
    !name.contains('.')
        && observed
            .split_once('.')
            .is_some_and(|(short, _)| short.eq_ignore_ascii_case(name))
}

fn validate_sha256(label: &str, value: Option<&str>) -> Result<(), String> {
    let value = value.ok_or_else(|| format!("{label} SHA-256 is required"))?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} SHA-256 must contain 64 hexadecimal characters"
        ));
    }
    Ok(())
}

fn credential_to_ssh(
    credential: SubmittedCredential,
) -> Result<(String, automatestig_collector::SshAuth), String> {
    match credential {
        SubmittedCredential::Password { username, password } => {
            if username.trim().is_empty() || password.is_empty() {
                return Err("SSH username and one-time password are required".to_string());
            }
            Ok((
                username.trim().to_string(),
                automatestig_collector::SshAuth::password(password),
            ))
        }
        SubmittedCredential::KeyFile {
            username,
            path,
            passphrase,
        } => {
            if username.trim().is_empty() || path.trim().is_empty() {
                return Err("SSH username and private-key path are required".to_string());
            }
            Ok((
                username.trim().to_string(),
                automatestig_collector::SshAuth::key_file(
                    path.trim().to_string(),
                    passphrase,
                ),
            ))
        }
        SubmittedCredential::Reference { .. } => Err(
            "A managed credential reference cannot run because no server-side credential provider is configured"
                .to_string(),
        ),
    }
}

fn insert_preflight(state: &AppState, value: &StoredPreflight) -> Result<String, String> {
    let token = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let mut preflights = state
        .inner
        .scanner_preflights
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    preflights.retain(|_, item| item.expires_at().is_ok_and(|expires_at| expires_at > now));
    if preflights.len() >= MAX_PREFLIGHTS {
        return Err(
            "Too many active preflights; wait for an existing preflight to expire".to_string(),
        );
    }
    preflights.insert(token.clone(), value.clone());
    Ok(token)
}

fn consume_preflight(state: &AppState, token: &str) -> Result<StoredPreflight, String> {
    if token.trim().is_empty() {
        return Err("preflight_token is required".to_string());
    }
    let preflight = state
        .inner
        .scanner_preflights
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(token)
        .ok_or_else(|| "Preflight token was not found or was already used".to_string())?;
    if preflight.expires_at()? <= Utc::now() {
        return Err("Preflight token expired; run preflight again".to_string());
    }
    Ok(preflight)
}

async fn preflight(
    State(state): State<AppState>,
    request: Result<Json<PreflightRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "invalid_preflight",
                format!("Invalid preflight request: {error}"),
            )
        }
    };
    let profile = match bundled_scanner_profile(request.profile_id.trim()) {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "profile_not_found",
                "The selected scanner profile is not bundled in this release.",
            )
        }
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "profile_integrity",
                error.to_string(),
            )
        }
    };
    let Some(adapter) = built_in_target_adapter(profile.target_key()) else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "adapter_missing",
            "The selected scanner profile has no bundled adapter.",
        );
    };
    let connection_profile = match request.connection_profile_id.as_deref() {
        Some(id) => match state.db().get_target_connection_profile(id) {
            Ok(saved) => {
                if saved.scanner_profile_id != profile.target_key()
                    || saved.adapter != adapter.adapter_id()
                {
                    return fail(
                        StatusCode::CONFLICT,
                        "connection_profile_binding_changed",
                        "The saved target connection profile no longer matches the selected scanner profile and adapter.",
                    );
                }
                Some(saved)
            }
            Err(StorageError::NotFound(_)) => {
                return fail(
                    StatusCode::NOT_FOUND,
                    "connection_profile_not_found",
                    "The selected target connection profile no longer exists.",
                )
            }
            Err(error) => {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "connection_profile_invalid",
                    error.to_string(),
                )
            }
        },
        None => None,
    };
    let compatibility = adapter.compatibility();
    let release_supported = profile.readiness() != ScannerProfileReadiness::Experimental
        && !compatibility.accepted_tested_versions.is_empty();
    if !release_supported && !request.pilot_acknowledged {
        return fail(
            StatusCode::PRECONDITION_REQUIRED,
            "pilot_acknowledgement_required",
            "This profile is experimental and has no accepted live-device version attached. Explicitly acknowledge a pilot run before preflight.",
        );
    }
    let method = request.collection_method;
    if !expected_methods(adapter).contains(&method) {
        return fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_collection_method",
            format!(
                "{} supports {}.",
                profile.display_name(),
                expected_methods(adapter)
                    .iter()
                    .map(|method| method.as_str())
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
        );
    }
    if method != CollectionMethod::Ssh && connection_profile.is_some() {
        return fail(
            StatusCode::BAD_REQUEST,
            "connection_profile_not_applicable",
            "Saved target connection profiles apply only to live SSH collection.",
        );
    }
    let destination = match (&request.mode, request.destination.clone()) {
        (RunMode::Connected, Some(destination)) => Some(destination),
        (RunMode::Connected, None) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "destination_required",
                "Select a STIG Manager collection, existing asset, and exact assignment before collection.",
            )
        }
        (RunMode::Disconnected, None) => None,
        (RunMode::Disconnected, Some(_)) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "unexpected_destination",
                "Disconnected runs cannot include a remote destination.",
            )
        }
    };

    let mut destination_asset_name = None;
    let mut destination_asset_fqdn = None;
    let mut destination_asset_ip = None;
    let mut destination_instance_id = None;
    let mut remote_rule_count = None;
    if let Some(destination) = &destination {
        let expected_assignment_id = format!("{}:{}", profile.stig_id(), profile.stig_release());
        if destination.assignment_id != expected_assignment_id {
            return fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "exact_assignment_required",
                format!("Selected assignment must be the exact release {expected_assignment_id}."),
            );
        }
        let config = match configured_connection(&state) {
            Ok(config) => config,
            Err(response) => return *response,
        };
        destination_instance_id = Some(stig_manager_destination_instance_id(&config));
        let client = match canonical_stig_manager_client(config).await {
            Ok(client) => client,
            Err(error) => return fail(StatusCode::BAD_GATEWAY, "connection_failed", error),
        };
        let target = automatestig_integrations::stig_manager::ScannerDeliveryTarget {
            collection_id: destination.collection_id.clone(),
            asset_id: destination.asset_id.clone(),
            benchmark_id: profile.stig_id().to_string(),
            revision: profile.stig_release().to_string(),
        };
        let assignment = match client.require_exact_assignment(&target).await {
            Ok(assignment) => assignment,
            Err(error) => {
                return fail(
                    StatusCode::CONFLICT,
                    "exact_assignment_required",
                    error.to_string(),
                )
            }
        };
        let asset = match client
            .get_asset(&destination.collection_id, &destination.asset_id)
            .await
        {
            Ok(asset) => asset,
            Err(error) => {
                return fail(
                    StatusCode::BAD_GATEWAY,
                    "asset_lookup_failed",
                    error.to_string(),
                )
            }
        };
        destination_asset_name = Some(asset.name);
        destination_asset_fqdn = asset.fqdn;
        destination_asset_ip = asset.ip;
        remote_rule_count = assignment.rule_count;
    }

    let (device, plan, identity, privilege, mut warnings) = if method == CollectionMethod::Ssh {
        let target = match request.target.as_ref() {
            Some(target) => target,
            None => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "target_required",
                    "SSH target host and port are required.",
                )
            }
        };
        if connection_profile.as_ref().is_some_and(|saved| {
            !saved.endpoint.eq_ignore_ascii_case(target.host.trim()) || saved.port != target.port
        }) {
            return fail(
                StatusCode::CONFLICT,
                "connection_profile_target_changed",
                "The submitted SSH endpoint or port differs from the selected saved connection profile.",
            );
        }
        if let Some(asset_name) = destination_asset_name.as_deref() {
            if !identity_matches_asset(
                &target.host,
                asset_name,
                destination_asset_fqdn.as_deref(),
                destination_asset_ip.as_deref(),
            ) {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "target_asset_mismatch",
                    "SSH endpoint does not match the selected STIG Manager asset name, FQDN, or IP address.",
                );
            }
        }
        let credential = match request.credential {
            Some(credential) => credential,
            None => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "credential_required",
                    "A one-time SSH credential or configured credential reference is required.",
                )
            }
        };
        let (username, auth) = match credential_to_ssh(credential) {
            Ok(value) => value,
            Err(error) => return fail(StatusCode::BAD_REQUEST, "credential_invalid", error),
        };
        let ssh_config = automatestig_collector::SshConfig {
            host: target.host.trim().to_string(),
            port: target.port,
            username,
            auth,
            timeout_secs: 30,
        };
        let scanner_preflight =
            match automatestig_scanner::preflight_ssh(profile.target_key(), &ssh_config).await {
                Ok(value) => value,
                Err(error) => {
                    return fail(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "ssh_preflight_failed",
                        error,
                    )
                }
            };
        let device = scanner_preflight.device;
        let host_key = scanner_preflight.server_key_fingerprint;
        if let Some(saved) = connection_profile.as_ref() {
            if let Err(error) = state
                .db()
                .record_target_connection_observation(&saved.id, &host_key, "ready")
            {
                return fail(
                    StatusCode::CONFLICT,
                    "connection_profile_observation_failed",
                    error.to_string(),
                );
            }
        }
        if let Some(asset_name) = destination_asset_name.as_deref() {
            if !observed_hostname_matches_asset(
                &device.hostname,
                asset_name,
                destination_asset_fqdn.as_deref(),
            ) {
                return fail(
                    StatusCode::CONFLICT,
                    "observed_device_asset_mismatch",
                    format!(
                        "The device reported identity {:?}, which does not match the selected STIG Manager asset name or FQDN.",
                        device.hostname
                    ),
                );
            }
        }
        let plan = scanner_preflight.plan;
        let warnings = if adapter.compatibility().accepted_tested_versions.is_empty() {
            vec!["Adapter compatibility passed, but this experimental profile has no attached live acceptance version yet.".to_string()]
        } else {
            Vec::new()
        };
        (
            device,
            plan,
            serde_json::json!({ "hostname": target.host, "fingerprint": host_key }),
            serde_json::json!({ "summary": "SSH authentication succeeded; each read-only command remains fail-closed on authorization errors." }),
            warnings,
        )
    } else {
        let input = match request.input.as_ref() {
            Some(input) => input,
            None => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "input_required",
                    "Select an evidence or configuration file before preflight.",
                )
            }
        };
        if let Err(error) = validate_sha256("Input file", input.sha256.as_deref()) {
            return fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "input_digest_required",
                error,
            );
        }
        if method == CollectionMethod::Configuration {
            for (label, metadata) in [
                ("Organization policy", request.organization_policy.as_ref()),
                (
                    "Organization policy signature",
                    request.organization_policy_signature.as_ref(),
                ),
            ] {
                let Some(metadata) = metadata else {
                    return fail(
                        StatusCode::BAD_REQUEST,
                        "signed_policy_required",
                        "IOS-XE configuration evaluation requires a signed organization policy and detached signature.",
                    );
                };
                if let Err(error) = validate_sha256(label, metadata.sha256.as_deref()) {
                    return fail(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "input_digest_required",
                        error,
                    );
                }
            }
        }
        let device = synthetic_upload_fingerprint(adapter);
        let plan = match adapter.preview(&device) {
            Ok(plan) => plan,
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "adapter_integrity",
                    error.to_string(),
                )
            }
        };
        let warnings = vec![
            "File metadata is bound now; device identity, version, and artifact completeness are verified from the uploaded bytes before evaluation."
                .to_string(),
        ];
        (
            device,
            plan,
            serde_json::json!({ "hostname": "Verified from uploaded artifact during evaluation" }),
            serde_json::json!({ "summary": "Operator-provided artifact; file custody and digest will be verified." }),
            warnings,
        )
    };

    let expires_at = Utc::now() + ChronoDuration::minutes(PREFLIGHT_TTL_MINUTES);
    let transport_identity = if method == CollectionMethod::Ssh {
        let fingerprint = identity
            .get("fingerprint")
            .and_then(serde_json::Value::as_str)
            .expect("SSH identity always includes a host-key fingerprint")
            .to_string();
        EvidenceTransportIdentity::SshHostKey { fingerprint }
    } else {
        EvidenceTransportIdentity::OfflineArtifact {
            sha256: request
                .input
                .as_ref()
                .and_then(|input| input.sha256.clone())
                .expect("validated upload metadata always includes SHA-256"),
        }
    };
    let stored = StoredPreflight {
        expires_at: expires_at.to_rfc3339(),
        mode: request.mode,
        profile_id: profile.target_key().to_string(),
        connection_profile_id: request.connection_profile_id,
        collection_method: method,
        pilot_acknowledged: request.pilot_acknowledged,
        destination,
        target: request.target,
        input: request.input,
        organization_policy: request.organization_policy,
        organization_policy_signature: request.organization_policy_signature,
        device: device.clone(),
        plan: plan.clone(),
        transport_identity,
        destination_asset_name,
        destination_asset_fqdn,
        destination_asset_ip,
        destination_instance_id,
        remote_rule_count,
    };
    let token = match insert_preflight(&state, &stored) {
        Ok(token) => token,
        Err(error) => return fail(StatusCode::TOO_MANY_REQUESTS, "preflight_capacity", error),
    };
    warnings.sort();
    ok(serde_json::json!({
        "ready": true,
        "preflight_token": token,
        "expires_at": expires_at,
        "device_identity": {
            "hostname": device.hostname,
            "version": device.software_version,
            "vendor": device.vendor,
            "product_family": device.product_family,
            "fingerprint_schema": device.schema,
            "operating_context": device.operating_context,
            "ha_role": device.ha_role,
            "fingerprint": identity.get("fingerprint").cloned(),
            "transport": identity,
        },
        "compatibility": {
            "supported": release_supported,
            "release_supported": release_supported,
            "pilot_runnable": true,
            "version_grammar_matched": true,
            "observed_version": device.software_version,
            "message": if release_supported {
                "Observed identity matches an accepted live-device version."
            } else {
                "Observed identity satisfies only the experimental version grammar; live acceptance is not attached."
            },
        },
        "privilege": privilege,
        "operations": operation_preview(&plan),
        "total_expected_duration_ms": plan.total_expected_duration_ms,
        "plan_sha256": plan.plan_sha256,
        "warnings": warnings,
        "errors": [],
    }))
}

#[derive(Deserialize)]
struct SshRunRequest {
    preflight_token: String,
    mode: RunMode,
    profile_id: String,
    #[serde(default)]
    connection_profile_id: Option<String>,
    destination: Option<DestinationSelection>,
    target: TargetSelection,
    credential: SubmittedCredential,
}

fn validate_run_binding(
    preflight: &StoredPreflight,
    mode: RunMode,
    profile_id: &str,
    connection_profile_id: Option<&str>,
    destination: Option<&DestinationSelection>,
    target: Option<&TargetSelection>,
    method: CollectionMethod,
) -> Result<(), String> {
    if preflight.mode != mode
        || preflight.profile_id != profile_id.trim()
        || preflight.connection_profile_id.as_deref() != connection_profile_id
        || preflight.destination.as_ref() != destination
        || preflight.target.as_ref() != target
        || preflight.collection_method != method
    {
        return Err(
            "Run inputs differ from the reviewed preflight; run preflight again for these exact inputs."
                .to_string(),
        );
    }
    Ok(())
}

async fn revalidate_connected_destination(
    state: &AppState,
    preflight: &StoredPreflight,
) -> Result<(), String> {
    let Some(destination) = preflight.destination.as_ref() else {
        return Ok(());
    };
    let profile = bundled_scanner_profile(&preflight.profile_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "The preflight profile is no longer bundled".to_string())?;
    let target = ScannerDeliveryTarget {
        collection_id: destination.collection_id.clone(),
        asset_id: destination.asset_id.clone(),
        benchmark_id: profile.stig_id().to_string(),
        revision: profile.stig_release().to_string(),
    };
    let config = configured_connection(state)
        .map_err(|_| "STIG Manager connection is no longer configured".to_string())?;
    let client = canonical_stig_manager_client(config).await?;
    client
        .require_exact_assignment(&target)
        .await
        .map_err(|error| error.to_string())?;
    let asset = client
        .get_asset(&target.collection_id, &target.asset_id)
        .await
        .map_err(|error| error.to_string())?;
    if preflight
        .destination_asset_name
        .as_deref()
        .is_some_and(|name| !name.eq_ignore_ascii_case(&asset.name))
        || preflight.destination_asset_fqdn != asset.fqdn
        || preflight.destination_asset_ip != asset.ip
    {
        return Err(
            "The selected STIG Manager asset identity changed after preflight; select it again."
                .to_string(),
        );
    }
    Ok(())
}

fn revalidate_target_connection_profile(
    state: &AppState,
    preflight: &StoredPreflight,
) -> Result<(), String> {
    let Some(id) = preflight.connection_profile_id.as_deref() else {
        return Ok(());
    };
    let saved = state
        .db()
        .get_target_connection_profile(id)
        .map_err(|error| format!("Saved target connection profile is unavailable: {error}"))?;
    let target = preflight
        .target
        .as_ref()
        .ok_or_else(|| "Saved target connection profile has no SSH target binding".to_string())?;
    let adapter = built_in_target_adapter(&preflight.profile_id).ok_or_else(|| {
        "Saved target connection profile adapter is no longer bundled".to_string()
    })?;
    let expected_fingerprint = ssh_fingerprint(&preflight.transport_identity)
        .ok_or_else(|| "Saved target connection profile has no SSH host-key binding".to_string())?;
    if saved.scanner_profile_id != preflight.profile_id
        || saved.adapter != adapter.adapter_id()
        || !saved.endpoint.eq_ignore_ascii_case(target.host.trim())
        || saved.port != target.port
        || saved.last_observed_fingerprint.as_deref() != Some(expected_fingerprint)
    {
        return Err(
            "The saved target connection profile, endpoint, or last observed host key changed after preflight. Review it and preflight again."
                .to_string(),
        );
    }
    Ok(())
}

fn ssh_fingerprint(identity: &EvidenceTransportIdentity) -> Option<&str> {
    match identity {
        EvidenceTransportIdentity::SshHostKey { fingerprint } => Some(fingerprint),
        _ => None,
    }
}

/// The encrypted checkpoint intentionally contains only already-observed
/// read-only operation evidence. Credentials are never serialized here or in
/// the durable job request.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshOperationCheckpointPayload {
    schema: String,
    operations: Vec<AdapterOperationEvidence>,
}

fn validate_successful_checkpoint_prefix(
    plan: &ReadOnlyOperationPlan,
    operations: &[AdapterOperationEvidence],
) -> Result<(), String> {
    if operations.is_empty() {
        return Err("SSH checkpoint prefix must contain at least one operation".to_string());
    }
    if operations.len() > plan.operations.len() {
        return Err("SSH checkpoint contains more operations than its immutable plan".to_string());
    }
    for (index, (record, planned)) in operations.iter().zip(plan.operations.iter()).enumerate() {
        if record.operation_id != planned.operation_id || record.request != planned.request {
            return Err(format!(
                "SSH checkpoint operation {} is not the exact planned operation at prefix position {}",
                record.operation_id,
                index + 1
            ));
        }
        if record.status != automatestig_core::target_adapters::AdapterOperationStatus::Success {
            return Err(format!(
                "SSH checkpoint operation {} is not successful",
                record.operation_id
            ));
        }
        if record.truncated {
            return Err(format!(
                "SSH checkpoint operation {} has a truncated response",
                record.operation_id
            ));
        }
        if record.error.is_some() {
            return Err(format!(
                "SSH checkpoint operation {} reports an error",
                record.operation_id
            ));
        }
        let status_code = record.status_code.ok_or_else(|| {
            format!(
                "SSH checkpoint operation {} has no transport status code",
                record.operation_id
            )
        })?;
        if !planned.accepted_status_codes.contains(&status_code) {
            return Err(format!(
                "SSH checkpoint operation {} has unaccepted transport status code {}",
                record.operation_id, status_code
            ));
        }
        if record.redactions.iter().any(|redaction| {
            redaction.field == automatestig_core::target_adapters::EvidenceRedactionField::Response
        }) {
            return Err(format!(
                "SSH checkpoint operation {} has a redacted evaluation response",
                record.operation_id
            ));
        }
        for redaction in &record.redactions {
            if redaction.reason.trim().is_empty() || !is_lowercase_sha256(&redaction.removed_sha256)
            {
                return Err(format!(
                    "SSH checkpoint operation {} has invalid redaction metadata",
                    record.operation_id
                ));
            }
        }
        let response = record.response.as_deref().ok_or_else(|| {
            format!(
                "SSH checkpoint operation {} has no response",
                record.operation_id
            )
        })?;
        let response_sha256 = record.response_sha256.as_deref().ok_or_else(|| {
            format!(
                "SSH checkpoint operation {} has no response digest",
                record.operation_id
            )
        })?;
        if !is_lowercase_sha256(response_sha256)
            || sha256_hex(response.as_bytes()) != response_sha256
        {
            return Err(format!(
                "SSH checkpoint operation {} response digest does not match",
                record.operation_id
            ));
        }
    }
    Ok(())
}

/// Append one record without ever leaving a failed or non-prefix record in the
/// in-memory resume state. Persistence applies the same validation again.
fn append_successful_checkpoint_operation(
    plan: &ReadOnlyOperationPlan,
    operations: &mut Vec<AdapterOperationEvidence>,
    operation: AdapterOperationEvidence,
) -> Result<(), String> {
    operations.push(operation);
    if let Err(error) = validate_successful_checkpoint_prefix(plan, operations) {
        operations.pop();
        return Err(error);
    }
    Ok(())
}

fn checkpoint_aad(
    job_id: &str,
    preflight: &StoredPreflight,
    target: &TargetSelection,
    completed_operation_ids_json: &str,
    plaintext_sha256: &str,
    expires_at: &str,
) -> Result<Vec<u8>, String> {
    let device_fingerprint_sha256 = preflight
        .device
        .sha256()
        .map_err(|error| format!("Could not bind checkpoint device identity: {error}"))?;
    let host_key = ssh_fingerprint(&preflight.transport_identity)
        .ok_or_else(|| "SSH checkpoint has no preflight host-key binding".to_string())?;
    let mut aad = b"AutomateSTIG/scanner-ssh-operation-checkpoint/aad/v1".to_vec();
    for value in [
        job_id,
        preflight.profile_id.as_str(),
        preflight.plan.plan_sha256.as_str(),
        device_fingerprint_sha256.as_str(),
        host_key,
        target.host.trim(),
        &target.port.to_string(),
        completed_operation_ids_json,
        plaintext_sha256,
        expires_at,
    ] {
        aad.push(0);
        aad.extend_from_slice(value.as_bytes());
    }
    Ok(aad)
}

fn save_ssh_operation_checkpoint(
    state: &AppState,
    job_id: &str,
    preflight: &StoredPreflight,
    target: &TargetSelection,
    operations: &[AdapterOperationEvidence],
) -> Result<(), String> {
    validate_successful_checkpoint_prefix(&preflight.plan, operations)?;
    let completed_operation_ids = operations
        .iter()
        .map(|operation| operation.operation_id.clone())
        .collect::<Vec<_>>();
    let completed_operation_ids_json = serde_json::to_string(&completed_operation_ids)
        .map_err(|error| format!("Could not serialize SSH checkpoint operations: {error}"))?;
    let plaintext = serde_json::to_vec(&SshOperationCheckpointPayload {
        schema: CHECKPOINT_SCHEMA.to_string(),
        operations: operations.to_vec(),
    })
    .map_err(|error| format!("Could not serialize SSH checkpoint: {error}"))?;
    let plaintext_sha256 = sha256_hex(&plaintext);
    let expires_at = Utc::now() + ChronoDuration::days(i64::from(evidence_retention_days(state)?));
    let expires_at_text = expires_at.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let aad = checkpoint_aad(
        job_id,
        preflight,
        target,
        &completed_operation_ids_json,
        &plaintext_sha256,
        &expires_at_text,
    )?;
    let key_material = crate::secrets::load_or_create_key_material(&state.inner.data_dir)
        .map_err(|error| format!("Checkpoint encryption key is unavailable: {error}"))?;
    let sealed = crate::secrets::seal_evidence_artifact(&plaintext, &aad, &key_material)
        .map_err(|error| format!("Could not encrypt SSH operation checkpoint: {error}"))?;
    let host_key = ssh_fingerprint(&preflight.transport_identity)
        .ok_or_else(|| "SSH checkpoint has no preflight host-key binding".to_string())?;
    let device_fingerprint_sha256 = preflight
        .device
        .sha256()
        .map_err(|error| format!("Could not bind checkpoint device identity: {error}"))?;
    let checkpoint = NewScanOperationCheckpoint {
        job_id: job_id.to_string(),
        profile_id: preflight.profile_id.clone(),
        plan_sha256: preflight.plan.plan_sha256.clone(),
        device_fingerprint_sha256,
        host_key_fingerprint: host_key.to_string(),
        endpoint: target.host.trim().to_string(),
        port: target.port,
        completed_operation_ids_json,
        plaintext_sha256,
        ciphertext_sha256: sha256_hex(&sealed.ciphertext),
        algorithm: sealed.algorithm,
        key_id: sealed.key_id,
        wrapped_dek_sha256: sha256_hex(&sealed.wrapped_dek),
        ciphertext: sealed.ciphertext,
        wrapped_dek: sealed.wrapped_dek,
        expires_at,
    };
    state
        .db()
        .save_scan_operation_checkpoint(&checkpoint)
        .map(|_| ())
        .map_err(|error| format!("Could not save SSH operation checkpoint: {error}"))
}

fn load_ssh_operation_checkpoint(
    state: &AppState,
    job_id: &str,
    preflight: &StoredPreflight,
    target: &TargetSelection,
) -> Result<Vec<AdapterOperationEvidence>, String> {
    let retained: RetainedScanOperationCheckpoint = state
        .db()
        .load_scan_operation_checkpoint(job_id)
        .map_err(|error| format!("No retained SSH checkpoint is available: {error}"))?;
    let metadata = &retained.metadata;
    let device_fingerprint_sha256 = preflight
        .device
        .sha256()
        .map_err(|error| format!("Could not bind checkpoint device identity: {error}"))?;
    let host_key = ssh_fingerprint(&preflight.transport_identity)
        .ok_or_else(|| "SSH checkpoint has no preflight host-key binding".to_string())?;
    if metadata.job_id != job_id
        || metadata.profile_id != preflight.profile_id
        || metadata.plan_sha256 != preflight.plan.plan_sha256
        || metadata.device_fingerprint_sha256 != device_fingerprint_sha256
        || metadata.host_key_fingerprint != host_key
        || !metadata.endpoint.eq_ignore_ascii_case(target.host.trim())
        || metadata.port != target.port
        || metadata.algorithm != SCAN_EVIDENCE_ENCRYPTION_ALGORITHM
        || sha256_hex(&retained.ciphertext) != metadata.ciphertext_sha256
        || sha256_hex(&retained.wrapped_dek) != metadata.wrapped_dek_sha256
    {
        return Err("The retained checkpoint does not exactly match the fresh preflight, profile, plan, device, endpoint, or SSH host key.".to_string());
    }
    let operation_ids_json = serde_json::to_string(&metadata.completed_operation_ids)
        .map_err(|error| format!("Could not serialize checkpoint operation IDs: {error}"))?;
    let aad = checkpoint_aad(
        job_id,
        preflight,
        target,
        &operation_ids_json,
        &metadata.plaintext_sha256,
        &metadata.expires_at,
    )?;
    let key_material = crate::secrets::load_existing_key_material(&state.inner.data_dir)
        .map_err(|error| format!("Checkpoint encryption key is unavailable: {error}"))?;
    let plaintext = crate::secrets::open_evidence_artifact(
        &crate::secrets::SealedEvidenceArtifact {
            algorithm: metadata.algorithm.clone(),
            key_id: metadata.key_id.clone(),
            ciphertext: retained.ciphertext,
            wrapped_dek: retained.wrapped_dek,
        },
        &aad,
        &key_material,
    )
    .map_err(|error| format!("Retained SSH checkpoint failed authentication: {error}"))?;
    if sha256_hex(&plaintext) != metadata.plaintext_sha256 {
        return Err("Retained SSH checkpoint plaintext digest changed".to_string());
    }
    let payload: SshOperationCheckpointPayload = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("Retained SSH checkpoint is invalid: {error}"))?;
    let actual_ids = payload
        .operations
        .iter()
        .map(|operation| operation.operation_id.clone())
        .collect::<Vec<_>>();
    let expected_prefix = preflight
        .plan
        .operations
        .iter()
        .take(actual_ids.len())
        .map(|operation| operation.operation_id.clone())
        .collect::<Vec<_>>();
    if payload.schema != CHECKPOINT_SCHEMA
        || actual_ids != metadata.completed_operation_ids
        || actual_ids != expected_prefix
    {
        return Err(
            "Retained SSH checkpoint operations do not match the authenticated plan binding"
                .to_string(),
        );
    }
    validate_successful_checkpoint_prefix(&preflight.plan, &payload.operations)?;
    Ok(payload.operations)
}

fn submitted_credential_kind(credential: &SubmittedCredential) -> &'static str {
    match credential {
        SubmittedCredential::Password { .. } => "password",
        SubmittedCredential::KeyFile { .. } => "key_file",
        SubmittedCredential::Reference { .. } => "reference",
    }
}

fn scan_job_checkpoint_value(
    state: &AppState,
    job: &ScanJobRecord,
) -> Result<serde_json::Value, String> {
    let metadata = match state.db().get_scan_operation_checkpoint_metadata(&job.id) {
        Ok(metadata) => metadata,
        Err(StorageError::NotFound(_)) => {
            return Ok(serde_json::json!({
                "state": "not_available",
                "resumable": false,
                "reason": "No retained encrypted checkpoint is available. Start a new scan.",
            }))
        }
        Err(error) => {
            return Err(format!(
                "Could not inspect retained checkpoint metadata for scan job {}: {error}",
                job.id
            ))
        }
    };
    let expires_at = DateTime::parse_from_rfc3339(&metadata.expires_at)
        .map_err(|error| format!("Stored checkpoint expiry is invalid: {error}"))?
        .with_timezone(&Utc);
    let expired = expires_at <= Utc::now();
    let resumable = job.state == ScanJobState::Failed && !expired;
    let (checkpoint_state, reason) = if expired {
        (
            "expired",
            "The retained checkpoint expired. Start a new scan.",
        )
    } else if resumable {
        (
            "available",
            "Eligible for safe resume after a fresh preflight and fresh credential submission; endpoint, plan, device identity, and SSH host key must still match exactly.",
        )
    } else {
        (
            "retained_not_resumable",
            "A retained checkpoint exists, but only a failed job can be resumed.",
        )
    };
    Ok(serde_json::json!({
        "state": checkpoint_state,
        "resumable": resumable,
        "reason": reason,
        "expires_at": metadata.expires_at,
        "updated_at": metadata.updated_at,
        "completed_operation_count": metadata.completed_operation_ids.len(),
        "profile_id": metadata.profile_id,
        "plan_sha256": metadata.plan_sha256,
        "endpoint": metadata.endpoint,
        "port": metadata.port,
    }))
}

fn scan_job_value(state: &AppState, job: &ScanJobRecord) -> Result<serde_json::Value, String> {
    let request = serde_json::from_str::<serde_json::Value>(&job.sanitized_request_json)
        .map_err(|error| format!("Stored scan-job request is invalid: {error}"))?;
    let checkpoint = scan_job_checkpoint_value(state, job)?;
    let resumable = checkpoint
        .get("resumable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Ok(serde_json::json!({
        "kind": "scan_job",
        "id": job.id,
        "state": job.state,
        "request": request,
        "request_sha256": job.request_sha256,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "run_id": job.run_id,
        "error": job.error,
        "resumable": resumable,
        "checkpoint": checkpoint,
    }))
}

fn default_page_limit() -> usize {
    DEFAULT_OPERATIONAL_PAGE_SIZE
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_page_limit")]
    limit: usize,
}

fn validate_page_query(query: &PageQuery) -> Result<(), String> {
    if query.limit == 0 || query.limit > MAX_OPERATIONAL_PAGE_SIZE {
        return Err(format!(
            "limit must be between 1 and {MAX_OPERATIONAL_PAGE_SIZE}"
        ));
    }
    Ok(())
}

fn page_value(query: &PageQuery, returned: usize) -> serde_json::Value {
    serde_json::json!({
        "offset": query.offset,
        "limit": query.limit,
        "returned": returned,
        "next_offset": (returned == query.limit).then_some(query.offset.saturating_add(returned)),
    })
}

async fn list_scan_jobs(
    State(state): State<AppState>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "page_invalid",
                format!("Invalid scanner-job page: {error}"),
            )
        }
    };
    if let Err(error) = validate_page_query(&query) {
        return fail(StatusCode::BAD_REQUEST, "page_invalid", error);
    }
    match state
        .db()
        .list_scan_jobs_page(None, query.offset, query.limit)
    {
        Ok(jobs) => {
            let values = jobs
                .iter()
                .map(|job| scan_job_value(&state, job))
                .collect::<Result<Vec<_>, _>>();
            match values {
                Ok(values) => ok(serde_json::json!({
                    "jobs": values,
                    "page": page_value(&query, jobs.len()),
                })),
                Err(error) => fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "scan_job_status_failed",
                    error,
                ),
            }
        }
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "scan_job_list_failed",
            error.to_string(),
        ),
    }
}

async fn get_scan_job(State(state): State<AppState>, Path(job_id): Path<String>) -> Response {
    let job = match state.db().get_scan_job(&job_id) {
        Ok(job) => job,
        Err(StorageError::NotFound(_)) => {
            return fail(
                StatusCode::NOT_FOUND,
                "scan_job_not_found",
                "Scanner job was not found.",
            )
        }
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan_job_read_failed",
                error.to_string(),
            )
        }
    };
    let transitions = match state.db().list_scan_job_transitions(&job_id) {
        Ok(transitions) => transitions,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan_job_history_failed",
                error.to_string(),
            )
        }
    };
    let mut value = match scan_job_value(&state, &job) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan_job_status_failed",
                error,
            )
        }
    };
    value["transitions"] = serde_json::to_value(transitions).unwrap_or_default();
    ok(value)
}

fn safe_scan_job_failure(code: Option<&str>, status: StatusCode) -> String {
    let (code, message) = match code.unwrap_or_default() {
        "preflight_invalid" => (
            "preflight_invalid",
            "The bound preflight expired, was already consumed, or is no longer valid. Run preflight again and resubmit credentials.",
        ),
        "preflight_mismatch" => (
            "preflight_mismatch",
            "The submitted target differed from the reviewed preflight. Run preflight again for the exact target.",
        ),
        "destination_changed" => (
            "destination_changed",
            "The selected STIG Manager destination changed after preflight. Select it again before scanning.",
        ),
        "credential_invalid" => (
            "credential_invalid",
            "The ephemeral SSH credential could not be used. Resubmit a supported credential.",
        ),
        "collection_identity_missing" => (
            "collection_identity_missing",
            "SSH collection did not establish a server host-key fingerprint.",
        ),
        "ssh_host_key_changed" => (
            "ssh_host_key_changed",
            "The SSH host key changed after preflight. No evidence was evaluated.",
        ),
        "evidence_seal_failed" | "evidence_replay_failed" => (
            "evidence_invalid",
            "Collected evidence failed its immutable adapter contract and was not evaluated.",
        ),
        "evaluation_failed" => (
            "evaluation_failed",
            "Collected evidence could not be evaluated under the bound scanner profile.",
        ),
        "run_persistence_failed" | "stored_run_invalid" => (
            "run_persistence_failed",
            "The immutable scanner result could not be committed or verified.",
        ),
        _ => (
            "scan_job_failed",
            "The SSH scanner job failed. Review the server log, run preflight again, and resubmit credentials.",
        ),
    };
    format!("{code} (HTTP {}): {message}", status.as_u16())
}

async fn complete_ssh_job(
    state: AppState,
    job_id: String,
    request: SshRunRequest,
    resume_checkpoint: bool,
    already_running: bool,
) {
    let connection_profile_id = request.connection_profile_id.clone();
    if !already_running {
        if let Err(error) = state.db().mark_scan_job_running(&job_id) {
            tracing::error!(job_id = %job_id, %error, "could not start durable scanner job");
            return;
        }
    }
    if let Some(id) = connection_profile_id.as_deref() {
        if let Err(error) = state
            .db()
            .update_target_connection_operational_state(id, "running")
        {
            tracing::warn!(job_id = %job_id, connection_profile_id = id, %error, "could not update saved target operational state");
        }
    }
    let response = run_ssh(
        State(state.clone()),
        Ok(Json(request)),
        Some(&job_id),
        resume_checkpoint,
    )
    .await;
    let status = response.status();
    let body = match axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024).await {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(job_id = %job_id, %error, "could not read scanner job result");
            let _ = state.db().mark_scan_job_failed(
                &job_id,
                "scan_job_failed: The scanner response could not be verified. Run preflight again and resubmit credentials.",
            );
            return;
        }
    };
    let payload = serde_json::from_slice::<serde_json::Value>(&body).ok();
    let run_id = payload
        .as_ref()
        .and_then(|value| value.get("data"))
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str);
    if status.is_success() {
        if let Some(run_id) = run_id {
            if let Err(error) = state.db().mark_scan_job_completed(&job_id, run_id) {
                tracing::error!(job_id = %job_id, run_id, %error, "could not complete durable scanner job");
                let _ = state.db().mark_scan_job_failed(
                    &job_id,
                    "run_persistence_failed: The immutable run was saved but its job linkage could not be verified. Review the server log before rescanning.",
                );
            }
            if let Some(id) = connection_profile_id.as_deref() {
                if let Err(error) = state
                    .db()
                    .update_target_connection_operational_state(id, "completed")
                {
                    tracing::warn!(job_id = %job_id, connection_profile_id = id, %error, "could not update saved target operational state");
                }
            }
            return;
        }
    }
    let code = payload
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(|value| value.get("code"))
        .and_then(serde_json::Value::as_str);
    let failure = safe_scan_job_failure(code, status);
    if let Err(error) = state.db().mark_scan_job_failed(&job_id, &failure) {
        tracing::error!(job_id = %job_id, %error, "could not record durable scanner job failure");
    }
    if let Some(id) = connection_profile_id.as_deref() {
        if let Err(error) = state
            .db()
            .update_target_connection_operational_state(id, "failed")
        {
            tracing::warn!(job_id = %job_id, connection_profile_id = id, %error, "could not update saved target operational state");
        }
    }
}

async fn enqueue_ssh_run(
    State(state): State<AppState>,
    request: Result<Json<SshRunRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "invalid_run_request",
                format!("Invalid SSH run request: {error}"),
            )
        }
    };
    let job_id = uuid::Uuid::new_v4().to_string();
    let sanitized_request = match serde_json::to_string(&serde_json::json!({
        "schema": "automatestig.scan-job-request.v1",
        "mode": request.mode,
        "profile_id": request.profile_id,
        "connection_profile_id": request.connection_profile_id,
        "destination": request.destination,
        "target": request.target,
        "auth_kind": submitted_credential_kind(&request.credential),
        "ephemeral_auth_supplied": true,
        "preflight_binding_sha256": sha256_hex(request.preflight_token.as_bytes()),
    })) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan_job_serialization_failed",
                error.to_string(),
            )
        }
    };
    let job = NewScanJob::new(job_id.clone(), sanitized_request);
    let stored = match state.db().create_scan_job(&job) {
        Ok(stored) => stored,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan_job_persistence_failed",
                error.to_string(),
            )
        }
    };
    let task_state = state.clone();
    tokio::spawn(async move {
        complete_ssh_job(task_state, job_id, request, false, false).await;
    });
    match scan_job_value(&state, &stored) {
        Ok(value) => accepted(value),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "scan_job_status_failed",
            error,
        ),
    }
}

/// Resume only a failed SSH job that has a retained encrypted checkpoint.
/// The request deliberately repeats fresh credentials and a fresh short-lived
/// preflight; neither is written to the job row or checkpoint.
async fn resume_ssh_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    request: Result<Json<SshRunRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "invalid_resume_request",
                format!("Invalid SSH resume request: {error}"),
            )
        }
    };
    let job = match state.db().get_scan_job(&job_id) {
        Ok(job) => job,
        Err(StorageError::NotFound(_)) => {
            return fail(
                StatusCode::NOT_FOUND,
                "scan_job_not_found",
                "Scanner job was not found.",
            )
        }
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan_job_read_failed",
                error.to_string(),
            )
        }
    };
    if job.state != automatestig_storage::ScanJobState::Failed {
        return fail(
            StatusCode::CONFLICT,
            "resume_not_available",
            "Only a failed SSH job with a retained checkpoint can be resumed.",
        );
    }
    let saved: serde_json::Value = match serde_json::from_str(&job.sanitized_request_json) {
        Ok(value) => value,
        Err(_) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan_job_invalid",
                "Stored scanner job is invalid.",
            )
        }
    };
    let exact = |key: &str, value: serde_json::Value| saved.get(key) == Some(&value);
    if !exact(
        "mode",
        serde_json::to_value(request.mode).unwrap_or_default(),
    ) || !exact("profile_id", serde_json::json!(request.profile_id))
        || !exact(
            "connection_profile_id",
            serde_json::json!(request.connection_profile_id),
        )
        || !exact(
            "destination",
            serde_json::to_value(&request.destination).unwrap_or_default(),
        )
        || !exact(
            "target",
            serde_json::to_value(&request.target).unwrap_or_default(),
        )
    {
        return fail(
            StatusCode::CONFLICT,
            "resume_binding_changed",
            "The resume request does not match the durable job's exact target, profile, saved connection profile, or destination binding.",
        );
    }
    if let Err(error) = state.db().load_scan_operation_checkpoint(&job_id) {
        return fail(
            StatusCode::CONFLICT,
            "resume_not_available",
            format!("A retained encrypted checkpoint is required to resume: {error}"),
        );
    }
    // Atomically claim the failed job before returning 202. The append-only
    // failed -> running transition is the compare-and-set gate for resume.
    let resumed = match state.db().mark_scan_job_resuming(&job_id) {
        Ok(job) => job,
        Err(StorageError::InvalidScanJobState { .. }) => return fail(
            StatusCode::CONFLICT,
            "resume_in_progress",
            "This failed job was already claimed for resume or its checkpoint is no longer retained.",
        ),
        Err(error) => return fail(StatusCode::INTERNAL_SERVER_ERROR, "resume_claim_failed", error.to_string()),
    };
    let task_state = state.clone();
    let queued_job_id = job_id.clone();
    tokio::spawn(async move {
        complete_ssh_job(task_state, queued_job_id, request, true, true).await;
    });
    accepted(serde_json::json!({
        "kind": "scan_job",
        "id": job_id,
        "state": resumed.state,
        "message": "Resume started with fresh credentials. The encrypted checkpoint will be accepted only if the fresh preflight exactly matches its profile, plan, device, host key, and endpoint bindings.",
    }))
}

async fn run_ssh(
    State(state): State<AppState>,
    request: Result<Json<SshRunRequest>, axum::extract::rejection::JsonRejection>,
    job_id: Option<&str>,
    resume_checkpoint: bool,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "invalid_run_request",
                format!("Invalid SSH run request: {error}"),
            )
        }
    };
    let preflight = match consume_preflight(&state, &request.preflight_token) {
        Ok(preflight) => preflight,
        Err(error) => return fail(StatusCode::CONFLICT, "preflight_invalid", error),
    };
    if let Err(error) = validate_run_binding(
        &preflight,
        request.mode,
        &request.profile_id,
        request.connection_profile_id.as_deref(),
        request.destination.as_ref(),
        Some(&request.target),
        CollectionMethod::Ssh,
    ) {
        return fail(StatusCode::CONFLICT, "preflight_mismatch", error);
    }
    if let Err(error) = revalidate_target_connection_profile(&state, &preflight) {
        return fail(
            StatusCode::CONFLICT,
            "connection_profile_binding_changed",
            error,
        );
    }
    if let Err(error) = revalidate_connected_destination(&state, &preflight).await {
        return fail(StatusCode::CONFLICT, "destination_changed", error);
    }
    let (username, auth) = match credential_to_ssh(request.credential) {
        Ok(value) => value,
        Err(error) => return fail(StatusCode::BAD_REQUEST, "credential_invalid", error),
    };
    let config = automatestig_collector::SshConfig {
        host: request.target.host.clone(),
        port: request.target.port,
        username,
        auth,
        timeout_secs: 30,
    };
    let server_key_fingerprint = match ssh_fingerprint(&preflight.transport_identity) {
        Some(value) => value.to_string(),
        None => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "preflight_identity_missing",
                "The stored preflight has no SSH host-key fingerprint.",
            )
        }
    };
    let scanner_preflight = automatestig_scanner::SshScannerPreflight {
        profile_id: preflight.profile_id.clone(),
        device: preflight.device.clone(),
        plan: preflight.plan.clone(),
        server_key_fingerprint,
    };
    let envelope = if let Some(job_id) = job_id {
        let mut operations = if resume_checkpoint {
            match load_ssh_operation_checkpoint(&state, job_id, &preflight, &request.target) {
                Ok(operations) => operations,
                Err(error) => {
                    return fail(StatusCode::CONFLICT, "checkpoint_binding_changed", error)
                }
            }
        } else {
            Vec::new()
        };
        for planned in &scanner_preflight.plan.operations {
            if operations
                .iter()
                .any(|operation| operation.operation_id == planned.operation_id)
            {
                continue;
            }
            let operation = match automatestig_scanner::collect_ssh_operation(
                &config,
                &scanner_preflight,
                &planned.operation_id,
            )
            .await
            {
                Ok(operation) => operation,
                Err(error) => {
                    return fail(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "evidence_collection_failed",
                        error,
                    )
                }
            };
            if operation.status
                != automatestig_core::target_adapters::AdapterOperationStatus::Success
            {
                let error = operation.error.as_deref().unwrap_or(
                    "The read-only operation did not return complete successful evidence",
                );
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "evidence_collection_failed",
                    format!(
                        "Operation {} failed with {:?}: {error}. Only the preceding successful ordered prefix was checkpointed; run a fresh preflight and resume after correcting the target condition.",
                        operation.operation_id, operation.status
                    ),
                );
            }
            if let Err(error) = append_successful_checkpoint_operation(
                &scanner_preflight.plan,
                &mut operations,
                operation,
            ) {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "evidence_collection_failed",
                    format!(
                        "The collected operation was not eligible for a resume checkpoint: {error}"
                    ),
                );
            }
            if let Err(error) = save_ssh_operation_checkpoint(
                &state,
                job_id,
                &preflight,
                &request.target,
                &operations,
            ) {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "checkpoint_persistence_failed",
                    error,
                );
            }
        }
        match automatestig_scanner::seal_resumed_ssh_envelope(
            &scanner_preflight,
            Utc::now(),
            operations,
        ) {
            Ok(envelope) => envelope,
            Err(error) => {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "evidence_collection_failed",
                    error,
                )
            }
        }
    } else {
        match automatestig_scanner::collect_ssh_envelope(&config, &scanner_preflight).await {
            Ok(envelope) => envelope,
            Err(error) => {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "evidence_collection_failed",
                    error,
                )
            }
        }
    };
    let evaluation = match automatestig_scanner::evaluate_adapter_envelope(
        &preflight.profile_id,
        &envelope,
        EvaluationOrigin::LiveSsh,
        None,
    ) {
        Ok(evaluation) => evaluation,
        Err(error) => return fail(StatusCode::UNPROCESSABLE_ENTITY, "evaluation_failed", error),
    };
    let response = persist_scanner_run(
        &state,
        preflight,
        Some(request.target),
        envelope,
        evaluation,
    )
    .await;
    if response.status().is_success() {
        if let Some(job_id) = job_id {
            if let Err(error) = state.db().delete_scan_operation_checkpoint(job_id) {
                tracing::warn!(job_id, %error, "could not remove completed SSH checkpoint");
            }
        }
    }
    response
}

#[derive(Default)]
struct EvidenceRunUpload {
    preflight_token: String,
    mode: String,
    profile_id: String,
    input_type: String,
    collection_id: String,
    asset_id: String,
    assignment_id: String,
    evidence: Option<Vec<u8>>,
    organization_policy: Option<Vec<u8>>,
    organization_policy_signature: Option<Vec<u8>>,
}

fn parse_run_mode(value: &str) -> Result<RunMode, String> {
    match value.trim() {
        "connected" => Ok(RunMode::Connected),
        "disconnected" => Ok(RunMode::Disconnected),
        _ => Err("mode must be connected or disconnected".to_string()),
    }
}

fn verify_upload_metadata(
    label: &str,
    metadata: Option<&InputMetadata>,
    bytes: &[u8],
) -> Result<(), String> {
    let metadata = metadata.ok_or_else(|| format!("{label} was not bound by preflight"))?;
    if metadata.size != bytes.len() as u64 {
        return Err(format!(
            "{label} size changed after preflight (expected {}, received {})",
            metadata.size,
            bytes.len()
        ));
    }
    let actual = sha256_hex(bytes);
    if metadata
        .sha256
        .as_deref()
        .is_none_or(|expected| !expected.eq_ignore_ascii_case(&actual))
    {
        return Err(format!("{label} SHA-256 changed after preflight"));
    }
    Ok(())
}

fn uploaded_destination(upload: &EvidenceRunUpload, mode: RunMode) -> Option<DestinationSelection> {
    (mode == RunMode::Connected).then(|| DestinationSelection {
        collection_id: upload.collection_id.trim().to_string(),
        asset_id: upload.asset_id.trim().to_string(),
        assignment_id: upload.assignment_id.trim().to_string(),
    })
}

fn validate_evidence_freshness(envelope: &AdapterEvidenceEnvelope) -> Result<(), String> {
    let maximum_hours = std::env::var("AUTOMATESTIG_MAX_EVIDENCE_AGE_HOURS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|hours| (1..=720).contains(hours))
        .unwrap_or(168);
    automatestig_scanner::validate_evidence_age(envelope, Utc::now(), maximum_hours)
}

async fn run_evidence(State(state): State<AppState>, mut multipart: Multipart) -> Response {
    // Kept aligned with the browser's complete-file WebCrypto binding limit.
    const MAX_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;
    const MAX_POLICY_BYTES: usize = 64 * 1024;
    const MAX_TEXT_FIELD_BYTES: usize = 4096;
    let mut upload = EvidenceRunUpload::default();
    let mut seen = HashSet::new();
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "multipart_invalid",
                    format!("Could not read multipart upload: {error}"),
                )
            }
        };
        let name = field.name().unwrap_or_default().to_string();
        if name.is_empty() || !seen.insert(name.clone()) {
            return fail(
                StatusCode::BAD_REQUEST,
                "multipart_duplicate",
                format!("Multipart field {name:?} is missing or duplicated"),
            );
        }
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes.to_vec(),
            Err(error) => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "multipart_invalid",
                    format!("Could not read multipart field {name}: {error}"),
                )
            }
        };
        match name.as_str() {
            "evidence" => {
                if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
                    return fail(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "evidence_size_invalid",
                        format!("Evidence must be 1..={MAX_EVIDENCE_BYTES} bytes"),
                    );
                }
                upload.evidence = Some(bytes);
            }
            "organization_policy" => {
                if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
                    return fail(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "policy_size_invalid",
                        format!("Organization policy must be 1..={MAX_POLICY_BYTES} bytes"),
                    );
                }
                upload.organization_policy = Some(bytes);
            }
            "organization_policy_signature" => {
                if bytes.len() != 64 {
                    return fail(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "policy_signature_invalid",
                        "Organization policy signature must contain exactly 64 bytes.",
                    );
                }
                upload.organization_policy_signature = Some(bytes);
            }
            _ => {
                if bytes.len() > MAX_TEXT_FIELD_BYTES {
                    return fail(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "field_too_large",
                        format!("Multipart field {name} is too large"),
                    );
                }
                let text = match String::from_utf8(bytes) {
                    Ok(value) => value,
                    Err(_) => {
                        return fail(
                            StatusCode::BAD_REQUEST,
                            "field_not_utf8",
                            format!("Multipart field {name} must be UTF-8"),
                        )
                    }
                };
                match name.as_str() {
                    "preflight_token" => upload.preflight_token = text,
                    "mode" => upload.mode = text,
                    "profile_id" => upload.profile_id = text,
                    "input_type" => upload.input_type = text,
                    "collection_id" => upload.collection_id = text,
                    "asset_id" => upload.asset_id = text,
                    "assignment_id" => upload.assignment_id = text,
                    _ => {
                        return fail(
                            StatusCode::BAD_REQUEST,
                            "multipart_field_unknown",
                            format!("Unexpected multipart field {name}"),
                        )
                    }
                }
            }
        }
    }
    let mode = match parse_run_mode(&upload.mode) {
        Ok(mode) => mode,
        Err(error) => return fail(StatusCode::BAD_REQUEST, "mode_invalid", error),
    };
    let destination = uploaded_destination(&upload, mode);
    if mode == RunMode::Connected
        && destination.as_ref().is_some_and(|destination| {
            destination.collection_id.is_empty()
                || destination.asset_id.is_empty()
                || destination.assignment_id.is_empty()
        })
    {
        return fail(
            StatusCode::BAD_REQUEST,
            "destination_required",
            "Connected uploads require collection_id, asset_id, and assignment_id.",
        );
    }
    let input_type = match CollectionMethod::parse(&upload.input_type) {
        Ok(method @ (CollectionMethod::Evidence | CollectionMethod::Configuration)) => method,
        Ok(CollectionMethod::Ssh) | Err(_) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "input_type_invalid",
                "input_type must be evidence or configuration.",
            )
        }
    };
    let preflight = match consume_preflight(&state, &upload.preflight_token) {
        Ok(preflight) => preflight,
        Err(error) => return fail(StatusCode::CONFLICT, "preflight_invalid", error),
    };
    if let Err(error) = validate_run_binding(
        &preflight,
        mode,
        &upload.profile_id,
        None,
        destination.as_ref(),
        None,
        input_type,
    ) {
        return fail(StatusCode::CONFLICT, "preflight_mismatch", error);
    }
    if let Err(error) = revalidate_connected_destination(&state, &preflight).await {
        return fail(StatusCode::CONFLICT, "destination_changed", error);
    }
    let evidence_bytes = match upload.evidence.as_deref() {
        Some(bytes) => bytes,
        None => {
            return fail(
                StatusCode::BAD_REQUEST,
                "evidence_required",
                "Evidence or configuration file is required.",
            )
        }
    };
    if let Err(error) = verify_upload_metadata("Evidence", preflight.input.as_ref(), evidence_bytes)
    {
        return fail(StatusCode::CONFLICT, "upload_changed", error);
    }
    let Some(adapter) = built_in_target_adapter(&preflight.profile_id) else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "adapter_missing",
            "The preflight adapter is no longer bundled.",
        );
    };

    let (envelope, verified_policy) = if input_type == CollectionMethod::Evidence {
        if upload.organization_policy.is_some() || upload.organization_policy_signature.is_some() {
            return fail(
                StatusCode::BAD_REQUEST,
                "unexpected_policy",
                "Organization policy files are valid only with IOS-XE configuration input.",
            );
        }
        let envelope: AdapterEvidenceEnvelope = match serde_json::from_slice(evidence_bytes) {
            Ok(envelope) => envelope,
            Err(error) => {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "evidence_invalid",
                    format!("Evidence must be a native adapter envelope: {error}"),
                )
            }
        };
        if envelope.target_key != preflight.profile_id {
            return fail(
                StatusCode::CONFLICT,
                "evidence_profile_mismatch",
                "Evidence target profile differs from preflight.",
            );
        }
        if let Err(error) = validate_evidence_freshness(&envelope) {
            return fail(StatusCode::UNPROCESSABLE_ENTITY, "evidence_stale", error);
        }
        if let Some(asset_name) = preflight.destination_asset_name.as_deref() {
            if !identity_matches_asset(
                &envelope.device.hostname,
                asset_name,
                preflight.destination_asset_fqdn.as_deref(),
                preflight.destination_asset_ip.as_deref(),
            ) {
                return fail(
                    StatusCode::CONFLICT,
                    "evidence_asset_mismatch",
                    "Evidence device identity does not match the selected STIG Manager asset.",
                );
            }
        }
        match adapter.replay(&envelope) {
            Ok(_) => {}
            Err(error) => {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "evidence_replay_failed",
                    error.to_string(),
                )
            }
        }
        (envelope, None)
    } else {
        if adapter != BuiltInTargetAdapter::CiscoIosXeRouterNdm {
            return fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "configuration_profile_mismatch",
                "Running-configuration input is supported only for the IOS-XE router profile.",
            );
        }
        let envelope = match automatestig_scanner::configuration_envelope(
            &preflight.profile_id,
            evidence_bytes,
            Utc::now(),
        ) {
            Ok(envelope) => envelope,
            Err(error) => {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "configuration_invalid",
                    error,
                )
            }
        };
        let hostname = envelope.device.hostname.clone();
        if let Some(asset_name) = preflight.destination_asset_name.as_deref() {
            if !identity_matches_asset(
                &hostname,
                asset_name,
                preflight.destination_asset_fqdn.as_deref(),
                preflight.destination_asset_ip.as_deref(),
            ) {
                return fail(
                    StatusCode::CONFLICT,
                    "configuration_asset_mismatch",
                    "Configuration hostname does not match the selected STIG Manager asset.",
                );
            }
        }
        let policy_bytes = match upload.organization_policy.as_deref() {
            Some(bytes) => bytes,
            None => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "signed_policy_required",
                    "A signed organization policy is required for IOS-XE evaluation.",
                )
            }
        };
        let signature_bytes = match upload.organization_policy_signature.as_deref() {
            Some(bytes) => bytes,
            None => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "signed_policy_required",
                    "A detached organization-policy signature is required.",
                )
            }
        };
        for (label, metadata, bytes) in [
            (
                "Organization policy",
                preflight.organization_policy.as_ref(),
                policy_bytes,
            ),
            (
                "Organization policy signature",
                preflight.organization_policy_signature.as_ref(),
                signature_bytes,
            ),
        ] {
            if let Err(error) = verify_upload_metadata(label, metadata, bytes) {
                return fail(StatusCode::CONFLICT, "upload_changed", error);
            }
        }
        let profile = match bundled_scanner_profile(&preflight.profile_id) {
            Ok(Some(profile)) => profile,
            Ok(None) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "profile_missing",
                    "The scanner profile is no longer bundled.",
                )
            }
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "profile_integrity",
                    error.to_string(),
                )
            }
        };
        let verified = match crate::api::verify_organization_policy(
            &state,
            policy_bytes,
            signature_bytes,
            profile.stig_id(),
            profile.stig_release(),
            &hostname,
        ) {
            Ok(policy) => policy,
            Err(error) => {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "organization_policy_invalid",
                    error,
                )
            }
        };
        (envelope, Some(verified))
    };

    let origin = if input_type == CollectionMethod::Configuration {
        EvaluationOrigin::ConfigFile
    } else {
        EvaluationOrigin::EvidenceFile
    };
    let evaluation = match automatestig_scanner::evaluate_adapter_envelope(
        &preflight.profile_id,
        &envelope,
        origin,
        verified_policy,
    ) {
        Ok(evaluation) => evaluation,
        Err(error) => return fail(StatusCode::UNPROCESSABLE_ENTITY, "evaluation_failed", error),
    };
    persist_scanner_run(&state, preflight, None, envelope, evaluation).await
}

const EVIDENCE_RETENTION_CONFIG_KEY: &str = "scanner.evidence_retention_days";
const EVIDENCE_RETENTION_ENV: &str = "AUTOMATESTIG_EVIDENCE_RETENTION_DAYS";
const OPERATIONAL_RETENTION_CONFIG_KEY: &str = "scanner.operational_retention_days";
const OPERATIONAL_RETENTION_ENV: &str = "AUTOMATESTIG_OPERATIONAL_RETENTION_DAYS";

fn parse_evidence_retention_days(value: Option<&str>) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_SCAN_EVIDENCE_RETENTION_DAYS);
    };
    let days = value.trim().parse::<u32>().map_err(|_| {
        format!(
            "Evidence retention must be a whole number from {MIN_SCAN_EVIDENCE_RETENTION_DAYS} through {MAX_SCAN_EVIDENCE_RETENTION_DAYS} days"
        )
    })?;
    if !(MIN_SCAN_EVIDENCE_RETENTION_DAYS..=MAX_SCAN_EVIDENCE_RETENTION_DAYS).contains(&days) {
        return Err(format!(
            "Evidence retention must be from {MIN_SCAN_EVIDENCE_RETENTION_DAYS} through {MAX_SCAN_EVIDENCE_RETENTION_DAYS} days"
        ));
    }
    Ok(days)
}

fn evidence_retention_days(state: &AppState) -> Result<u32, String> {
    evidence_retention_setting(state).map(|(days, _)| days)
}

fn parse_operational_retention_days(value: Option<&str>) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_OPERATIONAL_RETENTION_DAYS);
    };
    let days = value.trim().parse::<u32>().map_err(|_| {
        format!(
            "Operational retention must be a whole number from {MIN_OPERATIONAL_RETENTION_DAYS} through {MAX_OPERATIONAL_RETENTION_DAYS} days"
        )
    })?;
    if !(MIN_OPERATIONAL_RETENTION_DAYS..=MAX_OPERATIONAL_RETENTION_DAYS).contains(&days) {
        return Err(format!(
            "Operational retention must be from {MIN_OPERATIONAL_RETENTION_DAYS} through {MAX_OPERATIONAL_RETENTION_DAYS} days"
        ));
    }
    Ok(days)
}

fn operational_retention_days(state: &AppState) -> Result<u32, String> {
    operational_retention_setting(state).map(|(days, _)| days)
}

fn evidence_retention_setting(state: &AppState) -> Result<(u32, &'static str), String> {
    if let Ok(environment) = std::env::var(EVIDENCE_RETENTION_ENV) {
        return resolve_evidence_retention_setting(Some(&environment), None);
    }
    let configured = state
        .db()
        .get_config(EVIDENCE_RETENTION_CONFIG_KEY)
        .map_err(|error| format!("Could not read evidence retention policy: {error}"))?;
    resolve_evidence_retention_setting(None, configured.as_deref())
}

fn operational_retention_setting(state: &AppState) -> Result<(u32, &'static str), String> {
    if let Ok(environment) = std::env::var(OPERATIONAL_RETENTION_ENV) {
        return resolve_operational_retention_setting(Some(&environment), None);
    }
    let configured = state
        .db()
        .get_config(OPERATIONAL_RETENTION_CONFIG_KEY)
        .map_err(|error| format!("Could not read operational retention policy: {error}"))?;
    resolve_operational_retention_setting(None, configured.as_deref())
}

fn resolve_evidence_retention_setting(
    environment: Option<&str>,
    configured: Option<&str>,
) -> Result<(u32, &'static str), String> {
    if let Some(environment) = environment {
        return parse_evidence_retention_days(Some(environment)).map(|days| (days, "environment"));
    }
    if let Some(configured) = configured {
        return parse_evidence_retention_days(Some(configured)).map(|days| (days, "stored"));
    }
    Ok((DEFAULT_SCAN_EVIDENCE_RETENTION_DAYS, "release_default"))
}

fn resolve_operational_retention_setting(
    environment: Option<&str>,
    configured: Option<&str>,
) -> Result<(u32, &'static str), String> {
    if let Some(environment) = environment {
        return parse_operational_retention_days(Some(environment))
            .map(|days| (days, "environment"));
    }
    if let Some(configured) = configured {
        return parse_operational_retention_days(Some(configured)).map(|days| (days, "stored"));
    }
    Ok((DEFAULT_OPERATIONAL_RETENTION_DAYS, "release_default"))
}

fn retention_policy_response(state: &AppState) -> Result<serde_json::Value, String> {
    let (evidence_days, evidence_source) = evidence_retention_setting(state)?;
    let (operational_days, operational_source) = operational_retention_setting(state)?;
    let generated_at = Utc::now();
    let next_sweep_not_later_than = generated_at
        + ChronoDuration::from_std(EVIDENCE_RETENTION_SWEEP_INTERVAL)
            .map_err(|error| format!("Retention sweep interval is invalid: {error}"))?;
    Ok(serde_json::json!({
        "schema": "automatestig.scanner-retention-policy.v1",
        "generated_at": generated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        "replay_evidence": {
            "effective_days": evidence_days,
            "source": evidence_source,
            "editable": evidence_source != "environment",
            "environment_variable": (evidence_source == "environment").then_some(EVIDENCE_RETENTION_ENV),
            "stored_value_preserved_while_overridden": evidence_source == "environment",
            "minimum_days": MIN_SCAN_EVIDENCE_RETENTION_DAYS,
            "maximum_days": MAX_SCAN_EVIDENCE_RETENTION_DAYS,
            "applies_to": "new replay evidence and SSH checkpoints sealed after the policy is saved",
            "existing_expirations_unchanged": true,
            "read_expiry_enforced_synchronously": true,
        },
        "operational_history": {
            "effective_days": operational_days,
            "source": operational_source,
            "editable": operational_source != "environment",
            "environment_variable": (operational_source == "environment").then_some(OPERATIONAL_RETENTION_ENV),
            "stored_value_preserved_while_overridden": operational_source == "environment",
            "minimum_days": MIN_OPERATIONAL_RETENTION_DAYS,
            "maximum_days": MAX_OPERATIONAL_RETENTION_DAYS,
            "applies_to": "receipt-gated terminal run, job, delivery, attempt, and reconciliation history at the next bounded sweep",
            "verified_receipt_required": true,
        },
        "sweeper": {
            "interval_seconds": EVIDENCE_RETENTION_SWEEP_INTERVAL.as_secs(),
            "next_sweep_not_later_than": next_sweep_not_later_than.to_rfc3339_opts(SecondsFormat::Secs, true),
            "condition": "while this AutomateSTIG server remains running",
            "batch_limit": EVIDENCE_RETENTION_SWEEP_BATCH,
        },
    }))
}

async fn get_retention_policy(State(state): State<AppState>) -> Response {
    match retention_policy_response(&state) {
        Ok(value) => ok(value),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "retention_policy_invalid",
            error,
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionPolicyUpdate {
    replay_evidence_days: u32,
    operational_history_days: u32,
}

async fn update_retention_policy(
    State(state): State<AppState>,
    request: Result<Json<RetentionPolicyUpdate>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "retention_policy_invalid",
                format!("Invalid retention policy: {error}"),
            )
        }
    };
    if let Err(error) =
        parse_evidence_retention_days(Some(&request.replay_evidence_days.to_string()))
    {
        return fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "retention_policy_invalid",
            error,
        );
    }
    if let Err(error) =
        parse_operational_retention_days(Some(&request.operational_history_days.to_string()))
    {
        return fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "retention_policy_invalid",
            error,
        );
    }
    let (effective_evidence_days, evidence_source) = match evidence_retention_setting(&state) {
        Ok(setting) => setting,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "retention_policy_invalid",
                error,
            )
        }
    };
    let (effective_operational_days, operational_source) =
        match operational_retention_setting(&state) {
            Ok(setting) => setting,
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "retention_policy_invalid",
                    error,
                )
            }
        };
    if evidence_source == "environment" && request.replay_evidence_days != effective_evidence_days {
        return fail(
            StatusCode::CONFLICT,
            "retention_policy_environment_override",
            format!(
                "Replay-evidence retention is fixed at {effective_evidence_days} days by {EVIDENCE_RETENTION_ENV}; change the deployment environment instead."
            ),
        );
    }
    if operational_source == "environment"
        && request.operational_history_days != effective_operational_days
    {
        return fail(
            StatusCode::CONFLICT,
            "retention_policy_environment_override",
            format!(
                "Operational-history retention is fixed at {effective_operational_days} days by {OPERATIONAL_RETENTION_ENV}; change the deployment environment instead."
            ),
        );
    }
    if let Err(error) = state.db().set_scanner_retention_policy_dimensions(
        (evidence_source != "environment").then_some(request.replay_evidence_days),
        (operational_source != "environment").then_some(request.operational_history_days),
    ) {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "retention_policy_save_failed",
            error.to_string(),
        );
    }
    match retention_policy_response(&state) {
        Ok(value) => ok(value),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "retention_policy_invalid",
            error,
        ),
    }
}

fn evidence_artifact_aad(
    run_id: &str,
    evidence_sha256: &str,
    plaintext_sha256: &str,
    sealed_at: &str,
    expires_at: &str,
) -> Vec<u8> {
    let mut aad = b"AutomateSTIG/scanner-evidence/artifact-aad/v1".to_vec();
    for value in [
        run_id,
        evidence_sha256,
        plaintext_sha256,
        sealed_at,
        expires_at,
    ] {
        aad.push(0);
        aad.extend_from_slice(value.as_bytes());
    }
    aad
}

fn seal_run_evidence(
    state: &AppState,
    run_id: &str,
    envelope: &AdapterEvidenceEnvelope,
) -> Result<(NewScanEvidenceArtifact, StoredEvidenceReference), String> {
    let plaintext = serde_json::to_vec(envelope)
        .map_err(|error| format!("Could not serialize replay evidence: {error}"))?;
    let plaintext_sha256 = sha256_hex(&plaintext);
    let sealed_at = Utc::now();
    let expires_at = sealed_at + ChronoDuration::days(i64::from(evidence_retention_days(state)?));
    let sealed_at_text = sealed_at.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let expires_at_text = expires_at.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let aad = evidence_artifact_aad(
        run_id,
        &envelope.evidence_sha256,
        &plaintext_sha256,
        &sealed_at_text,
        &expires_at_text,
    );
    let key_material = crate::secrets::load_or_create_key_material(&state.inner.data_dir)
        .map_err(|error| format!("Evidence encryption key is unavailable: {error}"))?;
    let sealed = crate::secrets::seal_evidence_artifact(&plaintext, &aad, &key_material)
        .map_err(|error| format!("Could not encrypt replay evidence: {error}"))?;
    if sealed.algorithm != SCAN_EVIDENCE_ENCRYPTION_ALGORITHM {
        return Err("Evidence encryption algorithm does not match storage policy".to_string());
    }
    let ciphertext_sha256 = sha256_hex(&sealed.ciphertext);
    let wrapped_dek_sha256 = sha256_hex(&sealed.wrapped_dek);
    let stored = NewScanEvidenceArtifact {
        run_id: run_id.to_string(),
        envelope_schema: envelope.schema.clone(),
        evidence_sha256: envelope.evidence_sha256.clone(),
        plaintext_sha256: plaintext_sha256.clone(),
        ciphertext_sha256,
        algorithm: sealed.algorithm,
        key_id: sealed.key_id,
        wrapped_dek_sha256,
        ciphertext: sealed.ciphertext,
        wrapped_dek: sealed.wrapped_dek,
        sealed_at,
        expires_at,
    };
    let reference = StoredEvidenceReference {
        envelope_schema: envelope.schema.clone(),
        evidence_sha256: envelope.evidence_sha256.clone(),
        envelope_json_sha256: plaintext_sha256,
        profile_sha256: envelope.profile_sha256.clone(),
        device_fingerprint_sha256: envelope.device_fingerprint_sha256.clone(),
        collection_plan_sha256: envelope.plan_sha256.clone(),
    };
    Ok((stored, reference))
}

fn load_and_replay_run_evidence(
    state: &AppState,
    record: &ScanRunRecord,
    artifact: &StoredRunArtifact,
) -> Result<AdapterEvidenceEnvelope, String> {
    let retained = state
        .db()
        .load_retained_scan_evidence(&record.id)
        .map_err(|error| error.to_string())?;
    validate_retained_evidence_bindings(record, artifact, &retained)?;
    let metadata = &retained.metadata;
    let aad = evidence_artifact_aad(
        &record.id,
        &metadata.evidence_sha256,
        &metadata.plaintext_sha256,
        &metadata.sealed_at,
        &metadata.expires_at,
    );
    let sealed = crate::secrets::SealedEvidenceArtifact {
        algorithm: metadata.algorithm.clone(),
        key_id: metadata.key_id.clone(),
        ciphertext: retained.ciphertext,
        wrapped_dek: retained.wrapped_dek,
    };
    let key_material = crate::secrets::load_existing_key_material(&state.inner.data_dir)
        .map_err(|error| format!("Evidence encryption key is unavailable: {error}"))?;
    let plaintext = crate::secrets::open_evidence_artifact(&sealed, &aad, &key_material)
        .map_err(|error| format!("Stored replay evidence failed authentication: {error}"))?;
    if sha256_hex(&plaintext) != metadata.plaintext_sha256 {
        return Err("Stored replay evidence plaintext digest changed".to_string());
    }
    let envelope: AdapterEvidenceEnvelope = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("Stored replay evidence is invalid JSON: {error}"))?;
    if envelope.schema != artifact.evidence.envelope_schema
        || envelope.evidence_sha256 != record.evidence_sha256
        || envelope.profile_sha256 != artifact.evidence.profile_sha256
        || envelope.check_pack_sha256 != record.check_pack_sha256
        || envelope.device_fingerprint_sha256 != artifact.evidence.device_fingerprint_sha256
        || envelope.plan_sha256 != artifact.evidence.collection_plan_sha256
        || envelope.device != artifact.device
    {
        return Err("Stored replay evidence no longer matches immutable run metadata".to_string());
    }
    let adapter = built_in_target_adapter(&artifact.profile_id).ok_or_else(|| {
        format!(
            "Stored run {} has no bundled adapter for {}",
            record.id, artifact.profile_id
        )
    })?;
    adapter
        .replay(&envelope)
        .map_err(|error| format!("Stored run {} evidence failed replay: {error}", record.id))?;
    Ok(envelope)
}

fn validate_retained_evidence_bindings(
    record: &ScanRunRecord,
    artifact: &StoredRunArtifact,
    retained: &RetainedScanEvidenceArtifact,
) -> Result<(), String> {
    let metadata = &retained.metadata;
    if metadata.run_id != record.id
        || metadata.state != ScanEvidenceState::Retained
        || metadata.envelope_schema != artifact.evidence.envelope_schema
        || metadata.evidence_sha256 != record.evidence_sha256
        || metadata.plaintext_sha256 != artifact.evidence.envelope_json_sha256
        || metadata.algorithm != SCAN_EVIDENCE_ENCRYPTION_ALGORITHM
        || sha256_hex(&retained.ciphertext) != metadata.ciphertext_sha256
        || sha256_hex(&retained.wrapped_dek) != metadata.wrapped_dek_sha256
    {
        return Err("Stored encrypted replay evidence bindings changed".to_string());
    }
    Ok(())
}

async fn persist_scanner_run(
    state: &AppState,
    preflight: StoredPreflight,
    endpoint: Option<TargetSelection>,
    evidence_envelope: AdapterEvidenceEnvelope,
    evaluation: automatestig_scanner::ScannerEvaluation,
) -> Response {
    let profile = match bundled_scanner_profile(&preflight.profile_id) {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "profile_missing",
                "The evaluated scanner profile is no longer bundled.",
            )
        }
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "profile_integrity",
                error.to_string(),
            )
        }
    };
    if evaluation.collection_complete && evaluation.sparse_reviews.is_empty() {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "empty_sparse_result",
            "A complete scanner evaluation produced no scanner-owned reviews.",
        );
    }
    if !evaluation.collection_complete && !evaluation.sparse_reviews.is_empty() {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unsafe_sparse_result",
            "An incomplete scanner evaluation attempted to create deliverable reviews.",
        );
    }

    let manual_untouched = evaluation.summary.manual_not_reviewed;
    let profile_out_of_scope = profile
        .coverage()
        .benchmark_rules()
        .saturating_sub(profile.coverage().reviewed_rules());
    let out_of_scope_untouched = Some(
        preflight
            .remote_rule_count
            .and_then(|count| usize::try_from(count).ok())
            .map(|count| count.saturating_sub(profile.coverage().reviewed_rules()))
            .map_or(profile_out_of_scope, |remote| {
                remote.max(profile_out_of_scope)
            }),
    );
    let target = preflight
        .destination
        .as_ref()
        .map(|destination| ScannerDeliveryTarget {
            collection_id: destination.collection_id.clone(),
            asset_id: destination.asset_id.clone(),
            benchmark_id: profile.stig_id().to_string(),
            revision: profile.stig_release().to_string(),
        });
    let delivery_preview = if evaluation.collection_complete {
        if let Some(target) = target.as_ref() {
            remote_delivery_preview(
                state,
                target,
                &evaluation.sparse_reviews,
                manual_untouched,
                out_of_scope_untouched,
            )
            .await
        } else {
            let mut preview = unverified_delivery_preview(
                &evaluation.sparse_reviews,
                manual_untouched,
                out_of_scope_untouched,
                "Disconnected handoff: ownership and change classification are checked at the destination before import."
                    .to_string(),
            );
            for row in &mut preview.reviews {
                row.change = "handoff".to_string();
            }
            preview
        }
    } else {
        DeliveryPreview {
            manual_untouched,
            out_of_scope_untouched,
            warning: Some(
                "Collection was incomplete; no sparse delivery payload was created.".to_string(),
            ),
            ..DeliveryPreview::default()
        }
    };
    let known_conflict_count = delivery_preview.counts.conflict;
    let run_id = uuid::Uuid::new_v4().to_string();
    let (stored_evidence, evidence_reference) =
        match seal_run_evidence(state, &run_id, &evidence_envelope) {
            Ok(value) => value,
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "evidence_encryption_failed",
                    error,
                )
            }
        };
    let artifact = StoredRunArtifact {
        schema: handoff::SCANNER_RUN_SCHEMA.to_string(),
        mode: preflight.mode,
        profile_id: preflight.profile_id.clone(),
        collection_method: preflight.collection_method.as_str().to_string(),
        destination: preflight.destination.clone(),
        destination_asset_name: preflight.destination_asset_name.clone(),
        endpoint: endpoint.clone(),
        device: evidence_envelope.device.clone(),
        collection_complete: evaluation.collection_complete,
        collection_errors: evaluation.collection_errors.clone(),
        manual_untouched,
        out_of_scope_untouched,
        checklist: evaluation.checklist,
        reviews: evaluation.sparse_reviews.clone(),
        decision_traces: evaluation.decision_traces,
        signed_policy_material: evaluation.signed_policy_material,
        delivery_preview,
        evidence: evidence_reference,
    };
    let source_artifact_sha256 = preflight
        .input
        .as_ref()
        .and_then(|metadata| metadata.sha256.clone());
    let run_request = handoff::HandoffRunRequest {
        collection_method: preflight.collection_method.as_str().to_string(),
        credential_persisted: false,
        destination: preflight.destination.as_ref().map(|destination| {
            handoff::HandoffDestination {
                asset_id: destination.asset_id.clone(),
                assignment_id: destination.assignment_id.clone(),
                collection_id: destination.collection_id.clone(),
            }
        }),
        device_fingerprint_sha256: artifact.evidence.device_fingerprint_sha256.clone(),
        endpoint: endpoint.as_ref().map(|target| handoff::HandoffEndpoint {
            host: target.host.clone(),
            port: target.port,
        }),
        mode: match preflight.mode {
            RunMode::Connected => "connected",
            RunMode::Disconnected => "disconnected",
        }
        .to_string(),
        pilot_acknowledged: preflight.pilot_acknowledged,
        plan_sha256: artifact.evidence.collection_plan_sha256.clone(),
        profile_id: preflight.profile_id.clone(),
        schema: handoff::RUN_REQUEST_SCHEMA_V1.to_string(),
        source_artifact_sha256,
    };
    let request_json = match serde_json::to_string(&run_request) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "run_serialization_failed",
                error.to_string(),
            )
        }
    };
    let result_json = match serde_json::to_string(&artifact) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "run_serialization_failed",
                error.to_string(),
            )
        }
    };
    let scan_source = match artifact.collection_method.as_str() {
        "ssh" => "live_ssh",
        "configuration" => "configuration_file",
        _ => "native_evidence_file",
    };
    let run = NewScanRun {
        id: run_id.clone(),
        checklist_id: Some(artifact.checklist.id.to_string()),
        asset_hostname: artifact.device.hostname.clone(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        scan_source: scan_source.to_string(),
        stig_id: profile.stig_id().to_string(),
        stig_revision: profile.stig_release().to_string(),
        benchmark_sha256: evaluation.digests.benchmark_sha256,
        check_pack_sha256: evaluation.digests.check_pack_sha256,
        evaluation_plan_sha256: evaluation.digests.evaluation_plan_sha256,
        evidence_sha256: evaluation.digests.evidence_sha256,
        request_json,
        result_json,
        completed_at: stored_evidence.sealed_at,
    };
    let stored = if evaluation.collection_complete && preflight.mode == RunMode::Connected {
        let Some(target) = target else {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "delivery_target_missing",
                "Connected run lost its exact destination binding.",
            );
        };
        let Some(destination_instance_id) = preflight.destination_instance_id else {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "delivery_instance_missing",
                "Connected run lost its STIG Manager instance binding.",
            );
        };
        let payload = StoredDeliveryPayload {
            target: target.clone(),
            reviews: evaluation.sparse_reviews,
        };
        let payload_json = match serde_json::to_string(&payload) {
            Ok(value) => value,
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "delivery_serialization_failed",
                    error.to_string(),
                )
            }
        };
        let delivery_request_json = match serde_json::to_string(&serde_json::json!({
            "schema": "automatestig.sparse-delivery-request.v1",
            "run_id": run_id,
            "target": target,
            "review_count": payload.reviews.len(),
        })) {
            Ok(value) => value,
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "delivery_serialization_failed",
                    error.to_string(),
                )
            }
        };
        let delivery = NewPendingDelivery {
            id: uuid::Uuid::new_v4().to_string(),
            destination_kind: "stig_manager".to_string(),
            destination_instance_id,
            destination_collection_id: payload.target.collection_id.clone(),
            destination_asset_id: Some(payload.target.asset_id.clone()),
            request_json: delivery_request_json,
            payload_json,
            not_before: None,
        };
        match state
            .db()
            .save_completed_scan_run_with_evidence_and_pending_delivery(
                &run,
                &stored_evidence,
                &delivery,
            ) {
            Ok((stored, _, delivery_record)) => {
                if known_conflict_count > 0 {
                    let claim_token = uuid::Uuid::new_v4().to_string();
                    let conflict_message = format!(
                        "Delivery preview found {known_conflict_count} review(s) owned by a human or controlled STIG Manager workflow"
                    );
                    let claimed = {
                        state.db().claim_delivery(
                            &delivery_record.id,
                            "ownership-preview",
                            &claim_token,
                            Duration::from_secs(30),
                        )
                    };
                    let recorded = match claimed {
                        Ok(_) => state.db().mark_delivery_conflicted(
                            &delivery_record.id,
                            &claim_token,
                            &conflict_message,
                            None,
                        ),
                        Err(error) => Err(error),
                    };
                    if recorded.is_err() {
                        tracing::warn!(
                            delivery_id = %delivery_record.id,
                            "failed to persist the known ownership conflict after atomic run creation"
                        );
                    }
                }
                stored
            }
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "run_persistence_failed",
                    error.to_string(),
                )
            }
        }
    } else {
        match state
            .db()
            .save_completed_scan_run_with_evidence(&run, &stored_evidence)
        {
            Ok((stored, _)) => stored,
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "run_persistence_failed",
                    error.to_string(),
                )
            }
        }
    };
    match run_response_value(state, &stored) {
        Ok(value) => accepted(value),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_run_invalid",
            error,
        ),
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredEvidenceReference {
    envelope_schema: String,
    evidence_sha256: String,
    envelope_json_sha256: String,
    profile_sha256: String,
    device_fingerprint_sha256: String,
    collection_plan_sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredRunArtifact {
    schema: String,
    mode: RunMode,
    profile_id: String,
    collection_method: String,
    destination: Option<DestinationSelection>,
    destination_asset_name: Option<String>,
    endpoint: Option<TargetSelection>,
    device: DeviceFingerprint,
    collection_complete: bool,
    collection_errors: Vec<String>,
    manual_untouched: usize,
    #[serde(default)]
    out_of_scope_untouched: Option<usize>,
    checklist: automatestig_core::models::checklist::Checklist,
    reviews: Vec<ScannerReview>,
    decision_traces: Vec<automatestig_scanner::DecisionTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed_policy_material: Option<automatestig_scanner::SignedPolicyReplayMaterial>,
    delivery_preview: DeliveryPreview,
    evidence: StoredEvidenceReference,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct DeliveryPreviewCounts {
    create: usize,
    update: usize,
    unchanged: usize,
    conflict: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct DeliveryPreviewReview {
    rule_id: String,
    result: ScannerReviewResult,
    change: String,
    evidence_summary: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct DeliveryPreview {
    counts: DeliveryPreviewCounts,
    reviews: Vec<DeliveryPreviewReview>,
    manual_untouched: usize,
    #[serde(default)]
    out_of_scope_untouched: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredDeliveryPayload {
    target: ScannerDeliveryTarget,
    reviews: Vec<ScannerReview>,
}

fn evidence_summary(review: &ScannerReview) -> String {
    let summary = review
        .detail
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("Evidence-bound scanner determination");
    summary.chars().take(240).collect()
}

fn classify_delivery_preview(
    reviews: &[ScannerReview],
    existing: &[ExistingMappedReview],
    manual_untouched: usize,
    out_of_scope_untouched: Option<usize>,
) -> DeliveryPreview {
    let conflicts = classify_review_conflicts(reviews, existing);
    let conflict_rules: HashSet<&str> = conflicts
        .iter()
        .map(|conflict| conflict.rule_id.as_str())
        .collect();
    let existing_by_rule: HashMap<&str, &ExistingMappedReview> = existing
        .iter()
        .map(|review| (review.rule_id.as_str(), review))
        .collect();
    let mut counts = DeliveryPreviewCounts::default();
    let rows = reviews
        .iter()
        .map(|review| {
            let change = if conflict_rules.contains(review.rule_id.as_str()) {
                counts.conflict += 1;
                "conflict"
            } else if let Some(current) = existing_by_rule.get(review.rule_id.as_str()) {
                if scanner_review_is_exact_noop(review, current) {
                    counts.unchanged += 1;
                    "unchanged"
                } else {
                    counts.update += 1;
                    "update"
                }
            } else {
                counts.create += 1;
                "create"
            };
            DeliveryPreviewReview {
                rule_id: review.rule_id.clone(),
                result: review.result,
                change: change.to_string(),
                evidence_summary: evidence_summary(review),
            }
        })
        .collect();
    DeliveryPreview {
        counts,
        reviews: rows,
        manual_untouched,
        out_of_scope_untouched,
        warning: None,
    }
}

fn unverified_delivery_preview(
    reviews: &[ScannerReview],
    manual_untouched: usize,
    out_of_scope_untouched: Option<usize>,
    warning: String,
) -> DeliveryPreview {
    DeliveryPreview {
        counts: DeliveryPreviewCounts::default(),
        reviews: reviews
            .iter()
            .map(|review| DeliveryPreviewReview {
                rule_id: review.rule_id.clone(),
                result: review.result,
                change: "ownership_check_pending".to_string(),
                evidence_summary: evidence_summary(review),
            })
            .collect(),
        manual_untouched,
        out_of_scope_untouched,
        warning: Some(warning),
    }
}

fn gate_preview_for_conditional_writes(mut preview: DeliveryPreview) -> DeliveryPreview {
    if preview.counts.create + preview.counts.update > 0 {
        preview.warning = Some(
            "Direct review changes are safety-gated: this STIG Manager API does not provide an atomic conditional-write contract. Download the selected-run handoff and reconcile it at the destination; exact remote no-ops can still be verified safely."
                .to_string(),
        );
    }
    preview
}

async fn remote_delivery_preview(
    state: &AppState,
    target: &ScannerDeliveryTarget,
    reviews: &[ScannerReview],
    manual_untouched: usize,
    out_of_scope_untouched: Option<usize>,
) -> DeliveryPreview {
    let config = match configured_connection(state) {
        Ok(config) => config,
        Err(_) => {
            return unverified_delivery_preview(
                reviews,
                manual_untouched,
                out_of_scope_untouched,
                "STIG Manager ownership could not be rechecked; delivery will fail closed and retry after the connection is restored."
                    .to_string(),
            )
        }
    };
    let client = match canonical_stig_manager_client(config).await {
        Ok(client) => client,
        Err(error) => {
            return unverified_delivery_preview(
                reviews,
                manual_untouched,
                out_of_scope_untouched,
                format!("STIG Manager ownership check is pending: {error}"),
            )
        }
    };
    match client
        .list_mapped_reviews(&target.collection_id, &target.asset_id)
        .await
    {
        Ok(existing) => gate_preview_for_conditional_writes(classify_delivery_preview(
            reviews,
            &existing,
            manual_untouched,
            out_of_scope_untouched,
        )),
        Err(error) => unverified_delivery_preview(
            reviews,
            manual_untouched,
            out_of_scope_untouched,
            format!("STIG Manager ownership check is pending: {error}"),
        ),
    }
}

fn parse_stored_artifact(record: &ScanRunRecord) -> Result<StoredRunArtifact, String> {
    if sha256_hex(record.request_json.as_bytes()) != record.request_sha256 {
        return Err(format!(
            "Stored run {} request digest does not match its immutable bytes",
            record.id
        ));
    }
    if sha256_hex(record.result_json.as_bytes()) != record.result_sha256 {
        return Err(format!(
            "Stored run {} result digest does not match its immutable bytes",
            record.id
        ));
    }
    let artifact: StoredRunArtifact = serde_json::from_str(&record.result_json)
        .map_err(|error| format!("Stored run {} is invalid: {error}", record.id))?;
    if artifact.schema != handoff::SCANNER_RUN_SCHEMA {
        return Err(format!(
            "Stored run {} uses unsupported schema {}",
            record.id, artifact.schema
        ));
    }
    let profile = bundled_scanner_profile(&artifact.profile_id)
        .map_err(|error| format!("Stored run {} profile is invalid: {error}", record.id))?
        .ok_or_else(|| {
            format!(
                "Stored run {} references unknown profile {}",
                record.id, artifact.profile_id
            )
        })?;
    if record.stig_id != profile.stig_id()
        || record.stig_revision != profile.stig_release()
        || record.check_pack_sha256 != profile.digests().check_pack_sha256()
        || artifact.evidence.profile_sha256 != profile.digests().profile_sha256()
        || artifact.evidence.evidence_sha256 != record.evidence_sha256
        || !is_lowercase_sha256(&artifact.evidence.envelope_json_sha256)
        || !is_lowercase_sha256(&artifact.evidence.device_fingerprint_sha256)
        || !is_lowercase_sha256(&artifact.evidence.collection_plan_sha256)
    {
        return Err(format!(
            "Stored run {} profile, content, revision, or evidence binding changed",
            record.id
        ));
    }
    if artifact.decision_traces.len() != profile.coverage().automated_checks()
        || artifact.decision_traces.iter().any(|trace| {
            !matches!(
                trace.schema.as_str(),
                automatestig_scanner::DECISION_TRACE_SCHEMA_V1
                    | automatestig_scanner::DECISION_TRACE_SCHEMA_V2
            ) || trace.profile_id != artifact.profile_id
                || trace.profile_sha256 != artifact.evidence.profile_sha256
                || trace.check_pack_sha256 != record.check_pack_sha256
                || trace.evaluation_plan_sha256 != record.evaluation_plan_sha256
                || trace.evidence_envelope_sha256 != record.evidence_sha256
                || trace.evidence_envelope_json_sha256 != artifact.evidence.envelope_json_sha256
                || trace.device != artifact.device
        })
        || (artifact.collection_complete
            && artifact.decision_traces.len() != artifact.reviews.len())
    {
        return Err(format!(
            "Stored run {} decision traces no longer match its immutable result bindings",
            record.id
        ));
    }
    let policy_provenance = artifact
        .checklist
        .evaluation_provenance
        .as_ref()
        .and_then(|provenance| provenance.organization_policy.as_ref());
    match (policy_provenance, artifact.signed_policy_material.as_ref()) {
        (Some(provenance), Some(material))
            if provenance.policy_sha256 == material.policy_sha256
                && provenance.signer_fingerprint == material.signer_fingerprint => {}
        (None, None) => {}
        _ => {
            return Err(format!(
                "Stored run {} signed policy replay material changed",
                record.id
            ))
        }
    }
    Ok(artifact)
}

fn delivery_attempt_values(receipts: Vec<DeliveryReceipt>) -> Vec<serde_json::Value> {
    receipts
        .into_iter()
        .map(|receipt| {
            serde_json::json!({
                "number": receipt.attempt_number,
                "state": receipt.outcome,
                "at": receipt.recorded_at,
                "error": receipt.error,
                "receipt": receipt.remote_receipt_json
                    .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok()),
            })
        })
        .collect()
}

fn delivery_attempts_page(
    state: &AppState,
    delivery: &DeliveryRecord,
) -> Result<(Vec<serde_json::Value>, serde_json::Value), String> {
    let query = PageQuery {
        offset: 0,
        limit: DEFAULT_OPERATIONAL_PAGE_SIZE,
    };
    let receipts = state
        .db()
        .list_delivery_receipts_page(&delivery.id, query.offset, query.limit)
        .map_err(|error| error.to_string())?;
    let page = page_value(&query, receipts.len());
    Ok((delivery_attempt_values(receipts), page))
}

fn run_response_value(
    state: &AppState,
    record: &ScanRunRecord,
) -> Result<serde_json::Value, String> {
    let artifact = parse_stored_artifact(record)?;
    let summary = artifact.checklist.summary();
    let profile = bundled_scanner_profile(&artifact.profile_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "Stored run references missing profile {}",
                artifact.profile_id
            )
        })?;
    let evidence_metadata = state
        .db()
        .get_scan_evidence_metadata(&record.id)
        .map_err(|error| error.to_string())?;
    if evidence_metadata.evidence_sha256 != record.evidence_sha256
        || evidence_metadata.plaintext_sha256 != artifact.evidence.envelope_json_sha256
        || evidence_metadata.envelope_schema != artifact.evidence.envelope_schema
    {
        return Err(format!(
            "Stored run {} evidence metadata no longer matches its immutable reference",
            record.id
        ));
    }
    let deliveries = state
        .db()
        .list_deliveries_for_run(&record.id)
        .map_err(|error| error.to_string())?;
    if deliveries.len() > 1 {
        return Err(format!(
            "Stored run {} has more than one scanner delivery",
            record.id
        ));
    }
    let delivery = if let Some(delivery) = deliveries.first() {
        let (attempts, attempts_page) = delivery_attempts_page(state, delivery)?;
        let receipt = delivery
            .remote_receipt_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
        let remote_url = receipt
            .as_ref()
            .and_then(|value| value.get("remote_url"))
            .and_then(serde_json::Value::as_str);
        serde_json::json!({
            "id": delivery.id,
            "state": delivery.state,
            "request_sha256": delivery.request_sha256,
            "payload_sha256": delivery.payload_sha256,
            "remote_asset_id": delivery.destination_asset_id,
            "remote_assignment_id": artifact.destination.as_ref().map(|value| &value.assignment_id),
            "delivered_at": delivery.delivered_at,
            "last_error": delivery.last_error,
            "receipt": receipt,
            "remote_url": remote_url,
            "attempts": attempts,
            "attempts_page": attempts_page,
            "preview": artifact.delivery_preview,
        })
    } else {
        serde_json::json!({
            "state": "not_started",
            "attempts": [],
            "attempts_page": page_value(
                &PageQuery { offset: 0, limit: DEFAULT_OPERATIONAL_PAGE_SIZE },
                0,
            ),
            "preview": artifact.delivery_preview,
        })
    };
    let state_name = if !artifact.collection_complete {
        "incomplete".to_string()
    } else if let Some(delivery) = deliveries.first() {
        match delivery.state {
            DeliveryState::Pending => "preview_ready",
            DeliveryState::Sending => "sending",
            DeliveryState::Delivered => "delivered",
            DeliveryState::Retryable => "retryable",
            DeliveryState::Conflicted => "conflicted",
            DeliveryState::Rejected => "rejected",
        }
        .to_string()
    } else {
        "preview_ready".to_string()
    };
    let destination = artifact.destination.as_ref().map(|selection| {
        serde_json::json!({
            "collection_id": selection.collection_id,
            "asset_id": selection.asset_id,
            "asset_name": artifact.destination_asset_name,
            "assignment_id": selection.assignment_id,
        })
    });
    let provenance = artifact
        .checklist
        .evaluation_provenance
        .as_ref()
        .and_then(|value| serde_json::to_value(value).ok())
        .unwrap_or(serde_json::Value::Null);
    let full_benchmark_rules = profile.coverage().benchmark_rules();
    let reviewed_rules = profile.coverage().reviewed_rules();
    let coverage = if full_benchmark_rules == 0 {
        0.0
    } else {
        summary.assessed() as f64 * 100.0 / full_benchmark_rules as f64
    };
    Ok(serde_json::json!({
        "id": record.id,
        "state": state_name,
        "stage": if artifact.collection_complete { "delivery" } else { "collect" },
        "created_at": record.created_at,
        "completed_at": record.completed_at,
        "updated_at": deliveries.first().map(|value| value.updated_at.as_str()).unwrap_or(&record.completed_at),
        "mode": artifact.mode,
        "profile": {
            "id": artifact.profile_id,
            "title": profile.display_name(),
            "stig_id": record.stig_id,
            "stig_revision": record.stig_revision,
        },
        "collection_method": artifact.collection_method,
        "destination": destination,
        "endpoint": artifact.endpoint,
        "device_identity": artifact.device,
        "steps": {
            "preflight": "complete",
            "collect": if artifact.collection_complete { "complete" } else { "failed" },
            "evaluate": if artifact.collection_complete { "complete" } else { "blocked" },
            "delivery": delivery.get("state").cloned().unwrap_or(serde_json::Value::Null),
        },
        "result": {
            "collection_complete": artifact.collection_complete,
            "collection_errors": artifact.collection_errors,
            "automated_count": artifact.reviews.len(),
            "passed_count": summary.not_a_finding,
            "open_count": summary.open,
            "not_applicable_count": summary.not_applicable,
            "executable_coverage_pct": coverage,
            "full_benchmark_rules": full_benchmark_rules,
            "reviewed_rules": reviewed_rules,
            "manual_untouched": artifact.manual_untouched,
            "out_of_scope_untouched": artifact.out_of_scope_untouched,
            "proposed_reviews": artifact.delivery_preview.reviews,
            // Decision traces are deliberately sanitized at creation: exact
            // release-reviewed requests and expectations, safe observation
            // classifications, and hashes/provenance only. Raw target output
            // remains in the encrypted evidence envelope.
            "decision_traces": &artifact.decision_traces,
            "evidence": [{
                "label": "Native adapter evidence envelope",
                "sha256": record.evidence_sha256,
                "collection_plan_sha256": artifact.evidence.collection_plan_sha256,
                "evaluation_plan_sha256": record.evaluation_plan_sha256,
                "retention": {
                    "state": evidence_metadata.state,
                    "sealed_at": evidence_metadata.sealed_at,
                    "expires_at": evidence_metadata.expires_at,
                    "purged_at": evidence_metadata.purged_at,
                    "purge_reason": evidence_metadata.purge_reason,
                },
            }],
            "provenance": provenance,
        },
        "delivery_preview": artifact.delivery_preview,
        "delivery": delivery,
        "handoff_url": if artifact.collection_complete {
            Some(format!("/api/v1/runs/{}/handoff", record.id))
        } else {
            None
        },
        "integrity": {
            "request_sha256": record.request_sha256,
            "result_sha256": record.result_sha256,
            "benchmark_sha256": record.benchmark_sha256,
            "check_pack_sha256": record.check_pack_sha256,
            "evaluation_plan_sha256": record.evaluation_plan_sha256,
            "evidence_sha256": record.evidence_sha256,
            "decision_traces_sha256": automatestig_core::check_packs::canonical_json_sha256(&artifact.decision_traces)
                .map_err(|error| format!("Could not bind decision traces: {error}"))?,
        },
    }))
}

async fn list_runs(
    State(state): State<AppState>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "page_invalid",
                format!("Invalid scanner-run page: {error}"),
            )
        }
    };
    if let Err(error) = validate_page_query(&query) {
        return fail(StatusCode::BAD_REQUEST, "page_invalid", error);
    }
    let records = match state.db().list_scan_runs_page(query.offset, query.limit) {
        Ok(records) => records,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "run_list_failed",
                error.to_string(),
            )
        }
    };
    let mut runs = Vec::with_capacity(records.len());
    for record in &records {
        match run_response_value(&state, record) {
            Ok(value) => runs.push(value),
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "stored_run_invalid",
                    error,
                )
            }
        }
    }
    ok(serde_json::json!({
        "runs": runs,
        "page": page_value(&query, records.len()),
    }))
}

fn operational_purge_tombstone_value(
    tombstone: &automatestig_storage::OperationalPurgeTombstone,
) -> serde_json::Value {
    serde_json::json!({
        "id": tombstone.id,
        "run_id": tombstone.run_id,
        "request_sha256": tombstone.request_sha256,
        "result_sha256": tombstone.result_sha256,
        "evidence_sha256": tombstone.evidence_sha256,
        "payload_sha256": tombstone.payload_sha256,
        "destination_kind": tombstone.destination_kind,
        "destination_instance_id": tombstone.destination_instance_id,
        "destination_collection_id": tombstone.destination_collection_id,
        "destination_asset_id": tombstone.destination_asset_id,
        "destination_assignment_id": tombstone.destination_assignment_id,
        "receipt_kind": tombstone.receipt_kind,
        "receipt_id": tombstone.receipt_id,
        "receipt_sha256": tombstone.receipt_sha256,
        "remote_url": tombstone.remote_url,
        "purged_at": tombstone.purged_at,
    })
}

async fn list_purged_runs(
    State(state): State<AppState>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "page_invalid",
                format!("Invalid purge-tombstone page: {error}"),
            )
        }
    };
    if let Err(error) = validate_page_query(&query) {
        return fail(StatusCode::BAD_REQUEST, "page_invalid", error);
    }
    match state
        .db()
        .list_operational_purge_tombstones_page(query.offset, query.limit)
    {
        Ok(tombstones) => ok(serde_json::json!({
            "purged_runs": tombstones
                .iter()
                .map(operational_purge_tombstone_value)
                .collect::<Vec<_>>(),
            "page": page_value(&query, tombstones.len()),
        })),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "purge_tombstone_list_failed",
            error.to_string(),
        ),
    }
}

fn load_run(state: &AppState, run_id: &str) -> Result<ScanRunRecord, Box<Response>> {
    state.db().get_scan_run(run_id).map_err(|error| {
        let status = if matches!(error, automatestig_storage::StorageError::NotFound(_)) {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        Box::new(fail(status, "run_not_found", error.to_string()))
    })
}

async fn get_run(State(state): State<AppState>, Path(run_id): Path<String>) -> Response {
    let record = match load_run(&state, &run_id) {
        Ok(record) => record,
        Err(response) => return *response,
    };
    match run_response_value(&state, &record) {
        Ok(value) => ok(value),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_run_invalid",
            error,
        ),
    }
}

async fn list_delivery_attempts(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "page_invalid",
                format!("Invalid delivery-attempt page: {error}"),
            )
        }
    };
    if let Err(error) = validate_page_query(&query) {
        return fail(StatusCode::BAD_REQUEST, "page_invalid", error);
    }
    if let Err(response) = load_run(&state, &run_id) {
        return *response;
    }
    let deliveries = match state.db().list_deliveries_for_run(&run_id) {
        Ok(deliveries) => deliveries,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "delivery_lookup_failed",
                error.to_string(),
            )
        }
    };
    if deliveries.len() > 1 {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_run_invalid",
            format!("Stored run {run_id} has more than one scanner delivery"),
        );
    }
    let receipts = if let Some(delivery) = deliveries.first() {
        match state
            .db()
            .list_delivery_receipts_page(&delivery.id, query.offset, query.limit)
        {
            Ok(receipts) => receipts,
            Err(error) => {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "delivery_attempt_list_failed",
                    error.to_string(),
                )
            }
        }
    } else {
        Vec::new()
    };
    let returned = receipts.len();
    ok(serde_json::json!({
        "attempts": delivery_attempt_values(receipts),
        "page": page_value(&query, returned),
    }))
}

async fn deliver_run(State(state): State<AppState>, Path(run_id): Path<String>) -> Response {
    let record = match load_run(&state, &run_id) {
        Ok(record) => record,
        Err(response) => return *response,
    };
    let artifact = match parse_stored_artifact(&record) {
        Ok(artifact) => artifact,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored_run_invalid",
                error,
            )
        }
    };
    if artifact.mode != RunMode::Connected || !artifact.collection_complete {
        return fail(
            StatusCode::CONFLICT,
            "run_not_deliverable",
            "Only a complete connected run can be delivered directly to STIG Manager.",
        );
    }
    if let Err(error) = load_and_replay_run_evidence(&state, &record, &artifact) {
        return fail(
            StatusCode::CONFLICT,
            "delivery_evidence_unavailable",
            format!("Direct delivery requires retained, authenticated replay evidence: {error}"),
        );
    }
    let deliveries = match state.db().list_deliveries_for_run(&run_id) {
        Ok(deliveries) => deliveries,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "delivery_lookup_failed",
                error.to_string(),
            )
        }
    };
    let Some(mut delivery) = deliveries.into_iter().next() else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "delivery_missing",
            "The connected run has no atomic delivery record.",
        );
    };
    if delivery.state == DeliveryState::Delivered {
        return get_run(State(state), Path(run_id)).await;
    }
    let partial_remote_acceptance = delivery
        .remote_receipt_json
        .as_deref()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        .and_then(|value| {
            value
                .get("partial_remote_acceptance")
                .and_then(|flag| flag.as_bool())
        })
        .unwrap_or(false);
    if delivery.state == DeliveryState::Rejected
        || (delivery.state == DeliveryState::Conflicted && partial_remote_acceptance)
    {
        return fail(
            StatusCode::CONFLICT,
            "operator_resolution_required",
            delivery.last_error.unwrap_or_else(|| {
                "Resolve the STIG Manager conflict or rejection before creating a new scanner run."
                    .to_string()
            }),
        );
    }
    // Resolve and bind the exact configured instance before claiming work or
    // constructing a client. The same cloned configuration is used for the
    // eventual write, so a connection edit cannot redirect a preflighted run.
    let config = match configured_connection(&state) {
        Ok(config) => config,
        Err(response) => return *response,
    };
    let remote_url = match config.gui_url.clone() {
        Some(url) => url,
        None => return fail(
            StatusCode::PRECONDITION_REQUIRED,
            "stig_manager_gui_url_required",
            "Configure the credential-free HTTPS STIG Manager GUI base URL before remote verification. STIG Manager 1.6.13+1 has no supported asset or review deep-link contract.",
        ),
    };
    if let Err(error) =
        validate_delivery_destination_binding(&delivery.destination_instance_id, &config)
    {
        return fail(StatusCode::CONFLICT, "delivery_destination_changed", error);
    }
    if matches!(
        delivery.state,
        DeliveryState::Retryable | DeliveryState::Conflicted
    ) {
        if let Err(error) = state.db().retry_delivery(&delivery.id, None) {
            return fail(
                StatusCode::CONFLICT,
                "delivery_retry_failed",
                error.to_string(),
            );
        }
    }
    let claim_token = uuid::Uuid::new_v4().to_string();
    delivery = match state.db().claim_delivery(
        &delivery.id,
        "interactive-scanner-delivery",
        &claim_token,
        Duration::from_secs(90),
    ) {
        Ok(delivery) => delivery,
        Err(StorageError::InvalidDeliveryState { actual, .. })
            if actual == DeliveryState::Sending.as_str() =>
        {
            return fail(
                StatusCode::CONFLICT,
                "delivery_in_progress",
                "This delivery already has an active worker lease.",
            )
        }
        Err(error) => {
            return fail(
                StatusCode::CONFLICT,
                "delivery_claim_failed",
                error.to_string(),
            )
        }
    };
    let payload: StoredDeliveryPayload = match serde_json::from_str(&delivery.payload_json) {
        Ok(payload) => payload,
        Err(error) => {
            let message = format!("Stored sparse delivery payload is invalid: {error}");
            let _ = state
                .db()
                .mark_delivery_rejected(&delivery.id, &claim_token, &message, None);
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "delivery_payload_invalid",
                message,
            );
        }
    };
    let client = match canonical_stig_manager_client(config).await {
        Ok(client) => client,
        Err(error) => {
            let _ =
                state
                    .db()
                    .mark_delivery_retryable(&delivery.id, &claim_token, &error, None, None);
            return fail(StatusCode::BAD_GATEWAY, "connection_failed", error);
        }
    };
    match client
        .deliver_scanner_reviews(&payload.target, &payload.reviews)
        .await
    {
        Ok(receipt) => {
            // This is intentionally stricter than a successful delivery.
            // Only the no-write path is a receipt-gated retention proof;
            // future conditional-write support must never be mislabeled as a
            // no-op merely because the transport succeeded.
            let exact_noop = receipt.collection_id == payload.target.collection_id
                && receipt.asset_id == payload.target.asset_id
                && receipt.benchmark_id == payload.target.benchmark_id
                && receipt.revision == payload.target.revision
                && receipt.reviews_considered == payload.reviews.len()
                && receipt.reviews_sent == 0
                && receipt.inserted == 0
                && receipt.updated == 0
                && receipt.unchanged == receipt.reviews_considered;
            if !exact_noop {
                let message = "STIG Manager response was not an exact no-op; preserve the handoff and reconcile at the receiver before retention or retry.";
                let _ =
                    state
                        .db()
                        .mark_delivery_conflicted(&delivery.id, &claim_token, message, None);
                return fail(StatusCode::CONFLICT, "delivery_not_exact_noop", message);
            }
            let receipt_json = match serde_json::to_string(&serde_json::json!({
                "verification": "exact_noop",
                "remote_assignment_id": artifact.destination.as_ref().map(|destination| destination.assignment_id.as_str()),
                "receipt": receipt,
                "remote_url": remote_url,
                "destination_collection_id": payload.target.collection_id,
                "destination_asset_id": payload.target.asset_id,
                "stig_id": payload.target.benchmark_id,
                "stig_revision": payload.target.revision,
            })) {
                Ok(value) => value,
                Err(error) => {
                    let message = format!("Could not serialize remote receipt: {error}");
                    let _ = state.db().mark_delivery_retryable(
                        &delivery.id,
                        &claim_token,
                        &message,
                        None,
                        None,
                    );
                    return fail(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "receipt_serialization_failed",
                        message,
                    );
                }
            };
            if let Err(error) = state.db().mark_delivery_delivered(
                &delivery.id,
                &claim_token,
                &receipt_json,
                Some(&payload.target.asset_id),
            ) {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "receipt_persistence_failed",
                    error.to_string(),
                );
            }
            get_run(State(state), Path(run_id)).await
        }
        Err(error) => {
            let mut message = error.to_string();
            let (partial_acceptance, remote_receipt_json) = match &error {
                StigManagerError::Rejected {
                    response: Some(response),
                    receipt,
                    ..
                } => {
                    let partial = response.affected.inserted + response.affected.updated > 0;
                    let serialized = serde_json::to_string(&serde_json::json!({
                        "schema": "automatestig.stig-manager-reconciliation.v1",
                        "partial_remote_acceptance": partial,
                        "response": response,
                        "receipt": receipt,
                    }))
                    .ok();
                    (partial, serialized)
                }
                _ => (false, None),
            };
            if partial_acceptance {
                message.push_str(
                    "; STIG Manager reported partial remote acceptance. Reconcile the preserved receipt against the destination before any retry",
                );
            }
            let storage_result = match error.kind() {
                StigManagerErrorKind::Transient | StigManagerErrorKind::Authentication => {
                    state.db().mark_delivery_retryable(
                        &delivery.id,
                        &claim_token,
                        &message,
                        remote_receipt_json.as_deref(),
                        None,
                    )
                }
                StigManagerErrorKind::Conflict => state.db().mark_delivery_conflicted(
                    &delivery.id,
                    &claim_token,
                    &message,
                    remote_receipt_json.as_deref(),
                ),
                StigManagerErrorKind::Rejected if partial_acceptance => {
                    state.db().mark_delivery_conflicted(
                        &delivery.id,
                        &claim_token,
                        &message,
                        remote_receipt_json.as_deref(),
                    )
                }
                StigManagerErrorKind::Rejected | StigManagerErrorKind::Contract => {
                    state.db().mark_delivery_rejected(
                        &delivery.id,
                        &claim_token,
                        &message,
                        remote_receipt_json.as_deref(),
                    )
                }
            };
            if let Err(storage_error) = storage_result {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "delivery_state_persistence_failed",
                    format!("{message}; additionally failed to record state: {storage_error}"),
                );
            }
            match run_response_value(&state, &record) {
                Ok(value) => ok(value),
                Err(view_error) => fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "stored_run_invalid",
                    view_error,
                ),
            }
        }
    }
}

fn build_handoff_zip(
    record: &ScanRunRecord,
    artifact: &StoredRunArtifact,
    evidence_metadata: &ScanEvidenceArtifactMetadata,
    evidence_envelope: Option<&AdapterEvidenceEnvelope>,
) -> Result<Vec<u8>, String> {
    let all_v1 = artifact
        .decision_traces
        .iter()
        .all(|trace| trace.schema == automatestig_scanner::DECISION_TRACE_SCHEMA_V1);
    let all_v2 = artifact
        .decision_traces
        .iter()
        .all(|trace| trace.schema == automatestig_scanner::DECISION_TRACE_SCHEMA_V2);
    if !all_v1 && !all_v2 {
        return Err("Stored scanner run mixes incompatible decision-trace schemas".to_string());
    }
    let current_contract = all_v2;
    let run_request_json = if current_contract {
        let run_request: handoff::HandoffRunRequest = serde_json::from_str(&record.request_json)
            .map_err(|error| format!("Stored scanner run request is invalid: {error}"))?;
        let bytes = serde_json::to_vec(&run_request)
            .map_err(|error| format!("Failed to serialize scanner run request: {error}"))?;
        if bytes != record.request_json.as_bytes() || sha256_hex(&bytes) != record.request_sha256 {
            return Err(
                "Stored scanner run request is not canonical or no longer matches its immutable digest"
                    .to_string(),
            );
        }
        Some(bytes)
    } else {
        None
    };
    let artifact_json = serde_json::to_vec_pretty(artifact)
        .map_err(|error| format!("Failed to serialize scanner run: {error}"))?;
    let reviews_json = serde_json::to_vec_pretty(&artifact.reviews)
        .map_err(|error| format!("Failed to serialize sparse reviews: {error}"))?;
    let scanner_owned_rule_ids: HashSet<&str> = artifact
        .reviews
        .iter()
        .map(|review| review.rule_id.as_str())
        .collect();
    let mut fallback_checklist = artifact.checklist.clone();
    fallback_checklist.findings.retain(|finding| {
        scanner_owned_rule_ids.contains(finding.rule_id.as_str())
            && finding.status != FindingStatus::NotReviewed
            && matches!(
                finding.source,
                FindingSource::Automated | FindingSource::Evidence
            )
    });
    let excluded_rule_count = artifact
        .checklist
        .findings
        .len()
        .saturating_sub(fallback_checklist.findings.len());
    let cklb = automatestig_parsers::cklb::write_cklb(&fallback_checklist)
        .map_err(|error| format!("Failed to serialize supplemental CKLB: {error}"))?
        .into_bytes();
    let benchmark = bundled_scanner_benchmark(&artifact.profile_id)
        .map_err(|error| format!("Failed to load XCCDF benchmark provenance: {error}"))?
        .ok_or_else(|| {
            format!(
                "Scanner profile {} has no release-bundled benchmark provenance",
                artifact.profile_id
            )
        })?;
    let source = benchmark.source();
    let evaluation_provenance = artifact
        .checklist
        .evaluation_provenance
        .as_ref()
        .ok_or_else(|| "Completed scanner checklist has no evaluation provenance".to_string())?;
    let xccdf_provenance = XccdfResultsProvenance {
        run_id: record.id.clone(),
        profile_id: artifact.profile_id.clone(),
        scanner_version: record.scanner_version.clone(),
        scan_source: record.scan_source.clone(),
        collection_method: artifact.collection_method.clone(),
        collection_complete: artifact.collection_complete,
        started_at: evaluation_provenance
            .collected_at
            .clone()
            .unwrap_or_else(|| record.completed_at.clone()),
        completed_at: record.completed_at.clone(),
        request_sha256: record.request_sha256.clone(),
        result_sha256: record.result_sha256.clone(),
        profile_sha256: artifact.evidence.profile_sha256.clone(),
        benchmark_sha256: record.benchmark_sha256.clone(),
        benchmark_model_sha256: source.benchmark_model_sha256.clone(),
        source_archive_sha256: source.source_archive_sha256.clone(),
        source_xccdf_sha256: source.source_xccdf_sha256.clone(),
        check_pack_sha256: record.check_pack_sha256.clone(),
        evaluation_plan_sha256: record.evaluation_plan_sha256.clone(),
        evidence_sha256: record.evidence_sha256.clone(),
        collection_plan_sha256: artifact.evidence.collection_plan_sha256.clone(),
        source_url: source.source_url.clone(),
        source_member: source.source_member.clone(),
        coverage_manifest: source.coverage_manifest.clone(),
        coverage_manifest_sha256: source.coverage_manifest_sha256.clone(),
    };
    let scanner_owned_rule_ids: Vec<String> = artifact
        .reviews
        .iter()
        .map(|review| review.rule_id.clone())
        .collect();
    let xccdf = write_sparse_xccdf_1_2_results(
        &artifact.checklist,
        &scanner_owned_rule_ids,
        &xccdf_provenance,
    )
    .map_err(|error| format!("Failed to serialize XCCDF 1.2 results: {error}"))?;
    let evidence_json = evidence_envelope
        .map(|envelope| {
            serde_json::to_vec_pretty(envelope)
                .map_err(|error| format!("Failed to serialize replay evidence: {error}"))
        })
        .transpose()?;
    let manifest = handoff::HandoffManifest {
        schema: if current_contract {
            handoff::HANDOFF_SCHEMA_V4
        } else {
            handoff::HANDOFF_SCHEMA_V3
        }
        .to_string(),
        run_id: record.id.clone(),
        created_at: record.created_at.clone(),
        scanner_version: record.scanner_version.clone(),
        stig_id: record.stig_id.clone(),
        stig_revision: record.stig_revision.clone(),
        files: handoff::HandoffFiles {
            run_request: run_request_json.as_deref().map(sha256_hex),
            scanner_run: sha256_hex(&artifact_json),
            sparse_reviews: sha256_hex(&reviews_json),
            fallback_cklb: sha256_hex(&cklb),
            results_xccdf: Some(sha256_hex(&xccdf)),
            evidence_envelope: evidence_json.as_deref().map(sha256_hex),
        },
        scope: handoff::HandoffScope {
            scanner_owned_reviews_included: fallback_checklist.findings.len(),
            unreviewed_and_non_scanner_rules_excluded: excluded_rule_count,
            ownership_safe_sparse_handoff: true,
        },
        evidence: handoff::HandoffEvidence {
            state: match evidence_metadata.state {
                ScanEvidenceState::Retained => handoff::EvidenceState::Retained,
                ScanEvidenceState::Purged => handoff::EvidenceState::Purged,
            },
            included: evidence_json.is_some(),
            sha256: record.evidence_sha256.clone(),
            expires_at: evidence_metadata.expires_at.clone(),
            purged_at: evidence_metadata.purged_at.clone(),
            purge_reason: evidence_metadata.purge_reason.map(|reason| match reason {
                ScanEvidencePurgeReason::RetentionExpired => {
                    handoff::EvidencePurgeReason::RetentionExpired
                }
                ScanEvidencePurgeReason::OperatorRequested => {
                    handoff::EvidencePurgeReason::OperatorRequested
                }
            }),
        },
        bindings: handoff::RunBindings {
            request_sha256: record.request_sha256.clone(),
            result_sha256: record.result_sha256.clone(),
            benchmark_sha256: record.benchmark_sha256.clone(),
            check_pack_sha256: record.check_pack_sha256.clone(),
            evaluation_plan_sha256: record.evaluation_plan_sha256.clone(),
            evidence_sha256: record.evidence_sha256.clone(),
            decision_traces_sha256: Some(
                automatestig_core::check_packs::canonical_json_sha256(&artifact.decision_traces)
                    .map_err(|error| format!("Failed to bind decision traces: {error}"))?,
            ),
        },
        note: handoff::HANDOFF_NOTE.to_string(),
    };
    let manifest = handoff::serialize_handoff_manifest(&manifest)
        .map_err(|error| format!("Failed to serialize handoff manifest: {error}"))?;
    let integrity = handoff::serialize_integrity_record(&handoff::IntegrityRecord {
        algorithm: handoff::INTEGRITY_ALGORITHM_SHA256.to_string(),
        manifest_sha256: sha256_hex(&manifest),
    })
    .map_err(|error| format!("Failed to serialize handoff integrity record: {error}"))?;
    let mut payload_files = vec![
        (handoff::SCANNER_RUN_ENTRY, artifact_json),
        (handoff::SPARSE_REVIEWS_ENTRY, reviews_json),
        (handoff::FALLBACK_CKLB_ENTRY, cklb),
        (handoff::XCCDF_ENTRY, xccdf),
    ];
    if let Some(run_request_json) = run_request_json {
        payload_files.push((handoff::RUN_REQUEST_ENTRY, run_request_json));
    }
    if let Some(evidence_json) = evidence_json {
        payload_files.push((handoff::EVIDENCE_ENTRY, evidence_json));
    }
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let mut archive_files = vec![
            (handoff::MANIFEST_ENTRY, manifest),
            (handoff::INTEGRITY_ENTRY, integrity),
        ];
        archive_files.extend(payload_files);
        for (name, bytes) in archive_files {
            archive
                .start_file(name, options)
                .map_err(|error| format!("Failed to create handoff entry {name}: {error}"))?;
            archive
                .write_all(&bytes)
                .map_err(|error| format!("Failed to write handoff entry {name}: {error}"))?;
        }
        archive
            .finish()
            .map_err(|error| format!("Failed to finalize handoff: {error}"))?;
    }
    Ok(cursor.into_inner())
}

async fn download_handoff(State(state): State<AppState>, Path(run_id): Path<String>) -> Response {
    let record = match load_run(&state, &run_id) {
        Ok(record) => record,
        Err(response) => return *response,
    };
    let artifact = match parse_stored_artifact(&record) {
        Ok(artifact) => artifact,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored_run_invalid",
                error,
            )
        }
    };
    if !artifact.collection_complete {
        return fail(
            StatusCode::CONFLICT,
            "handoff_not_available",
            "A handoff is available only after collection completes successfully.",
        );
    }
    let mut evidence_metadata = match state.db().get_scan_evidence_metadata(&run_id) {
        Ok(metadata) => metadata,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence_metadata_missing",
                error.to_string(),
            )
        }
    };
    let evidence_envelope = if evidence_metadata.state == ScanEvidenceState::Retained {
        match load_and_replay_run_evidence(&state, &record, &artifact) {
            Ok(envelope) => Some(envelope),
            Err(error) => match state.db().get_scan_evidence_metadata(&run_id) {
                Ok(metadata) if metadata.state == ScanEvidenceState::Purged => {
                    evidence_metadata = metadata;
                    None
                }
                _ => {
                    return fail(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "evidence_integrity_failed",
                        error,
                    )
                }
            },
        }
    } else {
        None
    };
    let bytes = match build_handoff_zip(
        &record,
        &artifact,
        &evidence_metadata,
        evidence_envelope.as_ref(),
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "handoff_generation_failed",
                error,
            )
        }
    };
    let safe_id: String = record
        .id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .take(64)
        .collect();
    let disposition = format!(
        "attachment; filename=\"automatestig-run-{}.zip\"",
        if safe_id.is_empty() {
            "selected"
        } else {
            &safe_id
        }
    );
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationReceiptImportRequest {
    id: String,
    schema: String,
    payload_sha256: String,
    destination_kind: String,
    destination_instance_id: String,
    destination_collection_id: String,
    destination_asset_id: String,
    destination_assignment_id: String,
    stig_id: String,
    stig_revision: String,
    received_rule_ids: Vec<String>,
    independent_readback_sha256: String,
    independent_readback_at: DateTime<Utc>,
    /// The receiver-provided document is retained verbatim after binding
    /// checks. It must repeat every exact coordinate and digest below.
    receipt: serde_json::Value,
    remote_url: String,
    #[serde(default)]
    operator_confirmed: bool,
}

async fn list_reconciliation_receipts(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "page_invalid",
                format!("Invalid receipt page: {error}"),
            )
        }
    };
    if let Err(error) = validate_page_query(&query) {
        return fail(StatusCode::BAD_REQUEST, "page_invalid", error);
    }
    match state
        .db()
        .list_reconciliation_receipts_for_run_page(&run_id, query.offset, query.limit)
    {
        Ok(receipts) => ok(serde_json::json!({
            "receipts": receipts,
            "page": page_value(&query, receipts.len()),
        })),
        Err(StorageError::NotFound(_)) => fail(
            StatusCode::NOT_FOUND,
            "run_not_found",
            "Scanner run was not found.",
        ),
        Err(StorageError::InvalidData(error)) => {
            fail(StatusCode::BAD_REQUEST, "receipt_list_invalid", error)
        }
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "receipt_list_failed",
            error.to_string(),
        ),
    }
}

async fn import_reconciliation_receipt(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    request: Result<
        Json<ReconciliationReceiptImportRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "receipt_invalid",
                format!("Invalid reconciliation receipt: {error}"),
            )
        }
    };
    let record = match load_run(&state, &run_id) {
        Ok(record) => record,
        Err(response) => return *response,
    };
    let artifact = match parse_stored_artifact(&record) {
        Ok(artifact) => artifact,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored_run_invalid",
                error,
            )
        }
    };
    let Some(destination) = artifact.destination.as_ref() else {
        return fail(
            StatusCode::CONFLICT,
            "receipt_destination_missing",
            "A reconciliation receipt requires a run bound to an exact STIG Manager destination.",
        );
    };
    let config = match configured_connection(&state) {
        Ok(config) => config,
        Err(response) => return *response,
    };
    let Some(gui_url) = config.gui_url.as_deref() else {
        return fail(StatusCode::PRECONDITION_REQUIRED, "stig_manager_gui_url_required", "Configure the credential-free HTTPS STIG Manager GUI base URL before importing a reconciliation receipt.");
    };
    let expected_instance = stig_manager_destination_instance_id(&config);
    let expected_rule_ids = {
        let mut ids = artifact
            .reviews
            .iter()
            .map(|review| review.rule_id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        ids
    };
    if request.schema != "automatestig.receiver-reconciliation.v1"
        || request.destination_kind != "stig_manager"
        || request.destination_instance_id != expected_instance
        || request.destination_collection_id != destination.collection_id
        || request.destination_asset_id != destination.asset_id
        || request.destination_assignment_id != destination.assignment_id
        || request.stig_id != record.stig_id
        || request.stig_revision != record.stig_revision
        || request.received_rule_ids != expected_rule_ids
        || request.remote_url != gui_url
    {
        return fail(
            StatusCode::CONFLICT,
            "receipt_binding_changed",
            "The receiver receipt must exactly match the run's destination, assignment, STIG release, scanner-owned rule set, and configured STIG Manager GUI base URL.",
        );
    }
    let deliveries = match state.db().list_deliveries_for_run(&run_id) {
        Ok(deliveries) => deliveries,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "delivery_lookup_failed",
                error.to_string(),
            )
        }
    };
    let expected_payload_sha256 = deliveries
        .first()
        .map(|delivery| delivery.payload_sha256.as_str());
    if expected_payload_sha256 != Some(request.payload_sha256.as_str()) {
        return fail(StatusCode::CONFLICT, "receipt_payload_mismatch", "The receipt payload digest does not match the selected run's exact sparse delivery payload.");
    }
    let receipt_json = match serde_json::to_string(&request.receipt) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "receipt_invalid",
                error.to_string(),
            )
        }
    };
    let received_rule_ids_json = match serde_json::to_string(&request.received_rule_ids) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "receipt_invalid",
                error.to_string(),
            )
        }
    };
    let receipt = NewReconciliationReceipt {
        id: request.id,
        schema: request.schema,
        run_id,
        payload_sha256: request.payload_sha256,
        destination_kind: request.destination_kind,
        destination_instance_id: request.destination_instance_id,
        destination_collection_id: request.destination_collection_id,
        destination_asset_id: request.destination_asset_id,
        destination_assignment_id: request.destination_assignment_id,
        stig_id: request.stig_id,
        stig_revision: request.stig_revision,
        received_rule_set_sha256: sha256_hex(received_rule_ids_json.as_bytes()),
        received_rule_ids_json,
        independent_readback_sha256: request.independent_readback_sha256,
        independent_readback_at: request.independent_readback_at,
        receipt_sha256: sha256_hex(receipt_json.as_bytes()),
        receipt_json,
        remote_url: request.remote_url,
        producer_authentication: "unavailable".to_string(),
        signer_fingerprint: None,
        detached_signature: None,
        operator_confirmed: request.operator_confirmed,
    };
    let operational_retention_days = match operational_retention_days(&state) {
        Ok(days) => days,
        Err(error) => {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "retention_policy_invalid",
                error,
            )
        }
    };
    match state
        .db()
        .import_reconciliation_receipt(&receipt, operational_retention_days)
    {
        Ok(receipt) => ok(serde_json::json!({ "receipt": receipt })),
        Err(StorageError::InvalidData(error)) => {
            fail(StatusCode::UNPROCESSABLE_ENTITY, "receipt_invalid", error)
        }
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "receipt_import_failed",
            error.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct PurgeEvidenceRequest {
    confirm_run_id: String,
}

async fn purge_run_evidence(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    Json(request): Json<PurgeEvidenceRequest>,
) -> Response {
    if request.confirm_run_id != run_id {
        return fail(
            StatusCode::BAD_REQUEST,
            "purge_confirmation_mismatch",
            "confirm_run_id must exactly match the run whose replay evidence will be purged.",
        );
    }
    let record = match load_run(&state, &run_id) {
        Ok(record) => record,
        Err(response) => return *response,
    };
    if let Err(error) = parse_stored_artifact(&record) {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_run_invalid",
            error,
        );
    }
    if let Err(error) = state
        .db()
        .purge_scan_evidence(&run_id, ScanEvidencePurgeReason::OperatorRequested)
    {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "evidence_purge_failed",
            error.to_string(),
        );
    }
    match run_response_value(&state, &record) {
        Ok(value) => ok(value),
        Err(error) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored_run_invalid",
            error,
        ),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::sync::{Arc, Mutex};

    use automatestig_core::target_adapters::AdapterOperationEvidence;
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn stored_preflight_for_test(
        collection_method: CollectionMethod,
        expires_at: DateTime<Utc>,
    ) -> StoredPreflight {
        let profile_id = "cisco_ios_xe_router_ndm";
        let adapter = built_in_target_adapter(profile_id).unwrap();
        let device = DeviceFingerprint::new("router-1", "Cisco", "IOS-XE", "17.9");
        let plan = adapter.preview(&device).unwrap();
        StoredPreflight {
            expires_at: expires_at.to_rfc3339(),
            mode: RunMode::Disconnected,
            profile_id: profile_id.to_string(),
            connection_profile_id: None,
            collection_method,
            pilot_acknowledged: true,
            destination: None,
            target: None,
            input: None,
            organization_policy: None,
            organization_policy_signature: None,
            device,
            plan,
            transport_identity: EvidenceTransportIdentity::offline_artifact(b"configuration"),
            destination_asset_name: None,
            destination_asset_fqdn: None,
            destination_asset_ip: None,
            destination_instance_id: None,
            remote_rule_count: None,
        }
    }

    #[test]
    fn failed_operation_is_never_appended_to_a_resume_checkpoint_prefix() {
        let preflight = stored_preflight_for_test(CollectionMethod::Ssh, Utc::now());
        let planned = preflight.plan.operations.first().unwrap();
        let failed = AdapterOperationEvidence::failed(
            planned,
            automatestig_core::target_adapters::AdapterOperationStatus::Timeout,
            "operation timed out",
            30_000,
        )
        .unwrap();
        let mut prefix = Vec::new();

        assert!(
            append_successful_checkpoint_operation(&preflight.plan, &mut prefix, failed).is_err()
        );
        assert!(prefix.is_empty(), "failed evidence mutated resume state");
    }

    #[test]
    fn checkpoint_append_accepts_only_the_next_exact_successful_operation() {
        let profile_id = "freebsd_gpos";
        let adapter = built_in_target_adapter(profile_id).unwrap();
        let device = DeviceFingerprint::new("host01", "FreeBSD", "FreeBSD", "14.3");
        let plan = adapter.preview(&device).unwrap();
        let first = AdapterOperationEvidence::success(&plan.operations[0], "observed", 1);
        let second = AdapterOperationEvidence::success(&plan.operations[1], "observed", 1);
        let mut prefix = Vec::new();

        assert!(append_successful_checkpoint_operation(&plan, &mut prefix, second).is_err());
        assert!(
            prefix.is_empty(),
            "out-of-order evidence mutated resume state"
        );
        append_successful_checkpoint_operation(&plan, &mut prefix, first).unwrap();
        assert_eq!(prefix.len(), 1);

        let failed_second = AdapterOperationEvidence::failed(
            &plan.operations[1],
            automatestig_core::target_adapters::AdapterOperationStatus::SemanticError,
            "unexpected response",
            1,
        )
        .unwrap();
        assert!(append_successful_checkpoint_operation(&plan, &mut prefix, failed_second).is_err());
        assert_eq!(
            prefix.len(),
            1,
            "failed evidence was retained in resume state"
        );
    }

    #[test]
    fn typed_preflight_collection_method_deserialization_is_closed_and_preserves_wire_values() {
        for (wire_value, expected) in [
            ("ssh", CollectionMethod::Ssh),
            ("evidence", CollectionMethod::Evidence),
            ("configuration", CollectionMethod::Configuration),
        ] {
            let method: CollectionMethod =
                serde_json::from_value(serde_json::json!(wire_value)).unwrap();
            assert_eq!(method, expected);
            assert_eq!(serde_json::to_value(method).unwrap(), wire_value);
        }

        for invalid in ["telnet", "config", "ssh+sudo", ""] {
            let request = serde_json::json!({
                "mode": "disconnected",
                "profile_id": "freebsd_gpos",
                "collection_method": invalid,
            });
            assert!(
                serde_json::from_value::<PreflightRequest>(request).is_err(),
                "unknown collection method {invalid:?} must fail deserialization"
            );
        }

        let normalized: CollectionMethod =
            serde_json::from_value(serde_json::json!(" SSH ")).unwrap();
        assert_eq!(normalized, CollectionMethod::Ssh);
    }

    #[tokio::test]
    async fn typed_preflight_adapter_method_mismatch_retains_the_existing_api_error_code() {
        let temporary = tempfile::tempdir().unwrap();
        let state = test_state_with_database(
            automatestig_storage::Database::in_memory().unwrap(),
            temporary.path(),
        );
        let response = preflight(
            State(state),
            Ok(Json(PreflightRequest {
                mode: RunMode::Disconnected,
                profile_id: "cisco_ios_xe_router_ndm".to_string(),
                connection_profile_id: None,
                collection_method: CollectionMethod::Evidence,
                pilot_acknowledged: true,
                destination: None,
                target: None,
                credential: None,
                input: None,
                organization_policy: None,
                organization_policy_signature: None,
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["error"]["code"].as_str(),
            Some("unsupported_collection_method")
        );
    }

    #[test]
    fn typed_preflight_tokens_are_one_use_and_expired_entries_are_pruned() {
        let temporary = tempfile::tempdir().unwrap();
        let state = test_state_with_database(
            automatestig_storage::Database::in_memory().unwrap(),
            temporary.path(),
        );
        let expired = stored_preflight_for_test(
            CollectionMethod::Configuration,
            Utc::now() - ChronoDuration::minutes(1),
        );
        let expired_token = insert_preflight(&state, &expired).unwrap();
        let current = stored_preflight_for_test(
            CollectionMethod::Configuration,
            Utc::now() + ChronoDuration::minutes(1),
        );
        let current_token = insert_preflight(&state, &current).unwrap();
        {
            let preflights = state
                .inner
                .scanner_preflights
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(!preflights.contains_key(&expired_token));
            assert!(preflights.contains_key(&current_token));
            assert_eq!(preflights.len(), 1);
        }

        let consumed = consume_preflight(&state, &current_token).unwrap();
        assert_eq!(consumed.collection_method, CollectionMethod::Configuration);
        let error = match consume_preflight(&state, &current_token) {
            Ok(_) => panic!("a consumed preflight token must not be reusable"),
            Err(error) => error,
        };
        assert!(error.contains("already used"));
    }

    #[test]
    fn typed_preflight_store_retains_the_existing_capacity_limit() {
        let temporary = tempfile::tempdir().unwrap();
        let state = test_state_with_database(
            automatestig_storage::Database::in_memory().unwrap(),
            temporary.path(),
        );
        let current = stored_preflight_for_test(
            CollectionMethod::Configuration,
            Utc::now() + ChronoDuration::minutes(1),
        );
        for _ in 0..MAX_PREFLIGHTS {
            insert_preflight(&state, &current).unwrap();
        }
        let error = insert_preflight(&state, &current).unwrap_err();
        assert!(error.contains("Too many active preflights"));
        assert_eq!(
            state
                .inner
                .scanner_preflights
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            MAX_PREFLIGHTS
        );
    }

    #[test]
    fn typed_preflight_collection_method_mismatches_are_rejected() {
        let preflight = stored_preflight_for_test(
            CollectionMethod::Configuration,
            Utc::now() + ChronoDuration::minutes(1),
        );
        assert!(validate_run_binding(
            &preflight,
            RunMode::Disconnected,
            "cisco_ios_xe_router_ndm",
            None,
            None,
            None,
            CollectionMethod::Configuration,
        )
        .is_ok());
        assert!(validate_run_binding(
            &preflight,
            RunMode::Disconnected,
            "cisco_ios_xe_router_ndm",
            None,
            None,
            None,
            CollectionMethod::Evidence,
        )
        .is_err());
    }

    #[test]
    fn evidence_retention_policy_defaults_and_enforces_release_bounds() {
        assert_eq!(
            parse_evidence_retention_days(None).unwrap(),
            DEFAULT_SCAN_EVIDENCE_RETENTION_DAYS
        );
        assert_eq!(
            parse_evidence_retention_days(Some("1")).unwrap(),
            MIN_SCAN_EVIDENCE_RETENTION_DAYS
        );
        assert_eq!(
            parse_evidence_retention_days(Some("365")).unwrap(),
            MAX_SCAN_EVIDENCE_RETENTION_DAYS
        );
        for invalid in ["", "0", "366", "30.5", "forever"] {
            assert!(
                parse_evidence_retention_days(Some(invalid)).is_err(),
                "retention value {invalid:?} must fail closed"
            );
        }
    }

    #[test]
    fn retention_policy_response_reports_stored_effective_values_and_semantics() {
        let temporary = tempfile::tempdir().unwrap();
        let state = test_state_with_database(
            automatestig_storage::Database::in_memory().unwrap(),
            temporary.path(),
        );
        state.db().set_scanner_retention_policy(14, 45).unwrap();
        let value = retention_policy_response(&state).unwrap();
        assert_eq!(value["replay_evidence"]["effective_days"], 14);
        assert_eq!(value["replay_evidence"]["source"], "stored");
        assert_eq!(value["replay_evidence"]["editable"], true);
        assert_eq!(
            value["replay_evidence"]["existing_expirations_unchanged"],
            true
        );
        assert_eq!(value["operational_history"]["effective_days"], 45);
        assert_eq!(value["operational_history"]["source"], "stored");
        assert_eq!(
            value["operational_history"]["verified_receipt_required"],
            true
        );
        assert!(value["sweeper"]["next_sweep_not_later_than"].is_string());
    }

    #[test]
    fn deployment_environment_retention_wins_over_stored_browser_policy() {
        assert_eq!(
            resolve_evidence_retention_setting(Some("7"), Some("120")).unwrap(),
            (7, "environment")
        );
        assert_eq!(
            resolve_operational_retention_setting(Some("21"), Some("180")).unwrap(),
            (21, "environment")
        );
        assert!(resolve_evidence_retention_setting(Some("0"), Some("30")).is_err());
        assert!(resolve_operational_retention_setting(Some("forever"), Some("30")).is_err());
    }

    #[test]
    fn purge_tombstone_projection_omits_exact_receipt_json() {
        let tombstone = automatestig_storage::OperationalPurgeTombstone {
            id: 1,
            run_id: "run-1".to_string(),
            request_sha256: "1".repeat(64),
            result_sha256: "2".repeat(64),
            evidence_sha256: "3".repeat(64),
            payload_sha256: "4".repeat(64),
            destination_kind: "stig_manager".to_string(),
            destination_instance_id: "instance".to_string(),
            destination_collection_id: "7".to_string(),
            destination_asset_id: "41".to_string(),
            destination_assignment_id: "RHEL_9_STIG:V2R4".to_string(),
            receipt_kind: "reconciliation_import".to_string(),
            receipt_id: "receipt-1".to_string(),
            receipt_sha256: "5".repeat(64),
            receipt_json: r#"{"secret-adjacent":"custody-only"}"#.to_string(),
            remote_url: "https://stigman.example.mil/".to_string(),
            purged_at: "2026-08-11T12:00:00Z".to_string(),
        };
        let value = operational_purge_tombstone_value(&tombstone);
        assert!(value.get("receipt_json").is_none());
        assert_eq!(value["receipt_sha256"], "5".repeat(64));
    }

    fn connection(api_url: &str) -> crate::stigman::StigManagerConfig {
        crate::stigman::StigManagerConfig {
            api_url: api_url.to_string(),
            gui_url: Some(format!("{}/", api_url.trim_end_matches("/api"))),
            token_url: "https://identity.example.mil/token".to_string(),
            client_id: "automatestig".to_string(),
            client_secret: "test-secret".to_string(),
            default_collection_id: Some("7".to_string()),
            verify_tls: true,
        }
    }

    #[test]
    fn delivery_destination_binding_rejects_a_rebound_stig_manager_instance() {
        let original = connection("https://stigman-a.example.mil/api");
        let expected_instance_id = stig_manager_destination_instance_id(&original);

        assert!(validate_delivery_destination_binding(&expected_instance_id, &original).is_ok());

        let mut rotated_credentials = original.clone();
        rotated_credentials.client_secret = "rotated-secret".to_string();
        assert!(
            validate_delivery_destination_binding(&expected_instance_id, &rotated_credentials)
                .is_ok(),
            "credential rotation on the same API instance must remain deliverable"
        );

        let rebound = connection("https://stigman-b.example.mil/api");
        let error = validate_delivery_destination_binding(&expected_instance_id, &rebound)
            .expect_err("a different API instance must fail closed");
        assert!(error.contains("changed after this run was preflighted"));
    }

    #[test]
    fn observed_device_names_bind_to_asset_names_not_transport_ips() {
        assert!(observed_hostname_matches_asset(
            "bsd-01.example.mil",
            "bsd-01",
            Some("bsd-01.example.mil")
        ));
        assert!(observed_hostname_matches_asset(
            "cluster-01",
            "cluster-01",
            None
        ));
        assert!(!observed_hostname_matches_asset(
            "other-device.example.mil",
            "bsd-01",
            Some("bsd-01.example.mil")
        ));
    }

    #[test]
    fn conditional_write_gate_blocks_changes_but_not_exact_noops() {
        let changed = gate_preview_for_conditional_writes(DeliveryPreview {
            counts: DeliveryPreviewCounts {
                create: 1,
                update: 1,
                unchanged: 0,
                conflict: 0,
            },
            ..DeliveryPreview::default()
        });
        assert!(changed.warning.as_deref().is_some_and(
            |message| message.contains("does not provide an atomic conditional-write contract")
        ));

        let unchanged = gate_preview_for_conditional_writes(DeliveryPreview {
            counts: DeliveryPreviewCounts {
                create: 0,
                update: 0,
                unchanged: 2,
                conflict: 0,
            },
            ..DeliveryPreview::default()
        });
        assert!(unchanged.warning.is_none());
    }

    #[tokio::test]
    async fn ssh_jobs_are_persisted_without_credentials_before_preflight_work() {
        let temporary = tempfile::tempdir().unwrap();
        let state = AppState {
            inner: Arc::new(crate::state::AppStateInner {
                db: Mutex::new(automatestig_storage::Database::in_memory().unwrap()),
                data_dir: temporary.path().to_path_buf(),
                scanner_preflights: Mutex::new(HashMap::new()),
            }),
        };
        let response = enqueue_ssh_run(
            State(state.clone()),
            Ok(Json(SshRunRequest {
                preflight_token: "already-expired-preflight-token".to_string(),
                mode: RunMode::Disconnected,
                profile_id: "freebsd_gpos".to_string(),
                connection_profile_id: None,
                destination: None,
                target: TargetSelection {
                    host: "192.0.2.10".to_string(),
                    port: 22,
                },
                credential: SubmittedCredential::Password {
                    username: "scanner".to_string(),
                    password: "do-not-persist-this-password".to_string(),
                },
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let job_id = payload["data"]["id"].as_str().unwrap();

        let mut job = state.db().get_scan_job(job_id).unwrap();
        assert!(!job
            .sanitized_request_json
            .contains("do-not-persist-this-password"));
        assert!(!job.sanitized_request_json.contains("scanner"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&job.sanitized_request_json).unwrap()
                ["auth_kind"],
            "password"
        );
        for _ in 0..100 {
            if job.state == automatestig_storage::ScanJobState::Failed {
                break;
            }
            tokio::task::yield_now().await;
            job = state.db().get_scan_job(job_id).unwrap();
        }
        assert_eq!(job.state, automatestig_storage::ScanJobState::Failed);
        assert!(job
            .error
            .as_deref()
            .is_some_and(|error| error.contains("preflight_invalid")));
        let transitions = state.db().list_scan_job_transitions(job_id).unwrap();
        assert_eq!(transitions.len(), 3);
        assert_eq!(
            transitions[0].state,
            automatestig_storage::ScanJobState::Queued
        );
        assert_eq!(
            transitions[1].state,
            automatestig_storage::ScanJobState::Running
        );
        assert_eq!(
            transitions[2].state,
            automatestig_storage::ScanJobState::Failed
        );
    }

    fn test_state_with_database(
        database: automatestig_storage::Database,
        data_dir: &std::path::Path,
    ) -> AppState {
        AppState {
            inner: Arc::new(crate::state::AppStateInner {
                db: Mutex::new(database),
                data_dir: data_dir.to_path_buf(),
                scanner_preflights: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn cisco_evidence_run(
        state: &AppState,
        run_id: &str,
        configuration: &str,
    ) -> (
        AdapterEvidenceEnvelope,
        StoredRunArtifact,
        NewScanRun,
        NewScanEvidenceArtifact,
    ) {
        let profile_id = "cisco_ios_xe_router_ndm";
        let profile = bundled_scanner_profile(profile_id).unwrap().unwrap();
        let adapter = built_in_target_adapter(profile_id).unwrap();
        let device = DeviceFingerprint::new("router-1", "Cisco", "IOS-XE", "17.9");
        let plan = adapter.preview(&device).unwrap();
        let envelope = AdapterEvidenceEnvelope::seal_now(
            &plan,
            device.clone(),
            EvidenceTransportIdentity::offline_artifact(configuration.as_bytes()),
            plan.operations
                .iter()
                .map(|operation| AdapterOperationEvidence::success(operation, configuration, 1))
                .collect(),
        )
        .unwrap();
        adapter.replay(&envelope).unwrap();
        let (stored_evidence, evidence_reference) =
            seal_run_evidence(state, run_id, &envelope).unwrap();
        let benchmark_sha256 = sha256_hex(b"benchmark");
        let check_pack_sha256 = profile.digests().check_pack_sha256().to_string();
        let evaluation_plan_sha256 = automatestig_core::check_packs::evaluation_plan_sha256(
            profile.stig_id(),
            profile.stig_release(),
            &benchmark_sha256,
            &check_pack_sha256,
            None,
        )
        .unwrap();
        let mut checklist = automatestig_core::models::checklist::Checklist::new(
            automatestig_core::models::asset::Asset::new("router-1"),
            automatestig_core::models::checklist::ChecklistStigInfo {
                stig_id: profile.stig_id().to_string(),
                title: profile.display_name().to_string(),
                version: "3".to_string(),
                release: "7".to_string(),
                release_date: None,
                uuid: None,
                description: None,
                filename: None,
            },
        );
        checklist.evaluation_provenance =
            Some(automatestig_core::models::checklist::EvaluationProvenance {
                origin: EvaluationOrigin::ConfigFile,
                collection_complete: true,
                collection_errors: Vec::new(),
                evidence_sha256: Some(envelope.evidence_sha256.clone()),
                claimed_hostname: Some("router-1".to_string()),
                collector_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                collected_at: Some(envelope.collected_at.clone()),
                plan_sha256: Some(plan.plan_sha256.clone()),
                server_key_fingerprint: None,
                benchmark_sha256: Some(benchmark_sha256.clone()),
                check_pack_sha256: Some(check_pack_sha256.clone()),
                evaluation_plan_sha256: Some(evaluation_plan_sha256.clone()),
                organization_policy: None,
                answer_file: None,
                answer_files: Vec::new(),
                unsafe_legacy_evidence: false,
            });
        let artifact = StoredRunArtifact {
            schema: handoff::SCANNER_RUN_SCHEMA.to_string(),
            mode: RunMode::Disconnected,
            profile_id: profile_id.to_string(),
            collection_method: "configuration".to_string(),
            destination: None,
            destination_asset_name: None,
            endpoint: None,
            device,
            collection_complete: true,
            collection_errors: Vec::new(),
            manual_untouched: 0,
            out_of_scope_untouched: Some(0),
            checklist,
            reviews: Vec::new(),
            decision_traces: Vec::new(),
            signed_policy_material: None,
            delivery_preview: DeliveryPreview::default(),
            evidence: evidence_reference,
        };
        let run = NewScanRun {
            id: run_id.to_string(),
            checklist_id: Some(artifact.checklist.id.to_string()),
            asset_hostname: "router-1".to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_source: "configuration_file".to_string(),
            stig_id: profile.stig_id().to_string(),
            stig_revision: profile.stig_release().to_string(),
            benchmark_sha256,
            check_pack_sha256,
            evaluation_plan_sha256,
            evidence_sha256: envelope.evidence_sha256.clone(),
            request_json: serde_json::to_string(&handoff::HandoffRunRequest {
                collection_method: "configuration".to_string(),
                credential_persisted: false,
                destination: None,
                device_fingerprint_sha256: artifact.evidence.device_fingerprint_sha256.clone(),
                endpoint: None,
                mode: "disconnected".to_string(),
                pilot_acknowledged: true,
                plan_sha256: artifact.evidence.collection_plan_sha256.clone(),
                profile_id: profile_id.to_string(),
                schema: handoff::RUN_REQUEST_SCHEMA_V1.to_string(),
                source_artifact_sha256: Some(sha256_hex(configuration.as_bytes())),
            })
            .unwrap(),
            result_json: serde_json::to_string(&artifact).unwrap(),
            completed_at: stored_evidence.sealed_at,
        };
        (envelope, artifact, run, stored_evidence)
    }

    #[test]
    fn scanner_evidence_is_encrypted_at_rest_and_replayable_only_with_its_bindings() {
        const RAW_SENTINEL: &str = "RAW-DEVICE-OUTPUT-DO-NOT-PERSIST-PLAINTEXT-9f87d7";
        let temporary = tempfile::tempdir().unwrap();
        let database_path = temporary.path().join("data.db");
        let database = automatestig_storage::Database::open(&database_path).unwrap();
        let state = test_state_with_database(database, temporary.path());
        let configuration = format!(
            "version 17.9\nhostname router-1\ninterface GigabitEthernet1\n description {RAW_SENTINEL}\n no shutdown\n!\nend\n"
        );
        let (_envelope, artifact, run, stored_evidence) =
            cisco_evidence_run(&state, "encrypted-at-rest-run", &configuration);

        assert!(!run.result_json.contains(RAW_SENTINEL));
        assert!(!run.result_json.contains("evidence_envelope"));
        let (record, _) = state
            .db()
            .save_completed_scan_run_with_evidence(&run, &stored_evidence)
            .unwrap();

        for entry in std::fs::read_dir(temporary.path()).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_type().unwrap().is_file() {
                continue;
            }
            let bytes = std::fs::read(entry.path()).unwrap();
            assert!(
                !bytes
                    .windows(RAW_SENTINEL.len())
                    .any(|window| window == RAW_SENTINEL.as_bytes()),
                "raw scanner output leaked into {}",
                entry.path().display()
            );
        }

        let replayed = load_and_replay_run_evidence(&state, &record, &artifact).unwrap();
        assert!(serde_json::to_string(&replayed)
            .unwrap()
            .contains(RAW_SENTINEL));

        let mut tampered = state.db().load_retained_scan_evidence(&record.id).unwrap();
        tampered.ciphertext[0] ^= 0x80;
        assert!(validate_retained_evidence_bindings(&record, &artifact, &tampered).is_err());
    }

    fn archive_names(bytes: &[u8]) -> HashSet<String> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect()
    }

    fn archive_member(bytes: &[u8], name: &str) -> Vec<u8> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut member = archive.by_name(name).unwrap();
        let mut output = Vec::new();
        member.read_to_end(&mut output).unwrap();
        output
    }

    #[test]
    fn handoff_producer_matches_shared_verifier_schema_after_evidence_purge() {
        use automatestig_core::models::finding::Finding;
        use automatestig_core::models::stig::Severity;
        use automatestig_integrations::stig_manager::ScannerEvidenceSource;

        let temporary = tempfile::tempdir().unwrap();
        let state = test_state_with_database(
            automatestig_storage::Database::in_memory().unwrap(),
            temporary.path(),
        );
        let configuration =
            "version 17.9\nhostname router-1\ninterface GigabitEthernet1\n no shutdown\n!\nend\n";
        let (envelope, mut artifact, mut run, stored_evidence) =
            cisco_evidence_run(&state, "sparse-handoff-run", configuration);

        let mut scanner_owned = Finding::new_not_reviewed(
            "V-100001",
            "SV-100001_rule",
            "V-100001",
            "Scanner-owned rule",
            Severity::Medium,
        );
        scanner_owned.status = FindingStatus::Open;
        scanner_owned.source = FindingSource::Automated;
        scanner_owned.finding_details = "Evidence-bound scanner determination".to_string();

        let mut manual = Finding::new_not_reviewed(
            "V-100002",
            "SV-100002_rule",
            "V-100002",
            "Manual rule",
            Severity::Medium,
        );
        manual.status = FindingStatus::Open;
        manual.source = FindingSource::Manual;
        manual.finding_details = "An analyst's separate manual determination".to_string();

        let mut not_reviewed = Finding::new_not_reviewed(
            "V-100003",
            "SV-100003_rule",
            "V-100003",
            "Unreviewed automated rule",
            Severity::Low,
        );
        not_reviewed.source = FindingSource::Automated;

        artifact.checklist.findings = vec![scanner_owned, manual, not_reviewed];
        artifact.reviews = vec![ScannerReview {
            rule_id: "SV-100001_rule".to_string(),
            result: ScannerReviewResult::Fail,
            detail: "Evidence-bound scanner determination".to_string(),
            comment: "AutomateSTIG sparse result".to_string(),
            evidence_source: ScannerEvidenceSource::LiveCollection,
            evaluated_at: Some(Utc::now().to_rfc3339()),
        }];
        run.result_json = serde_json::to_string(&artifact).unwrap();
        let (record, retained_metadata) = state
            .db()
            .save_completed_scan_run_with_evidence(&run, &stored_evidence)
            .unwrap();

        let retained =
            build_handoff_zip(&record, &artifact, &retained_metadata, Some(&envelope)).unwrap();
        assert_eq!(
            archive_names(&retained),
            HashSet::from([
                "manifest.json".to_string(),
                "integrity.json".to_string(),
                "run-request.json".to_string(),
                "scanner-run.json".to_string(),
                "sparse-reviews.json".to_string(),
                "fallback.cklb".to_string(),
                "results.xccdf.xml".to_string(),
                "evidence-envelope.json".to_string(),
            ])
        );
        let retained_manifest =
            handoff::parse_handoff_manifest(&archive_member(&retained, handoff::MANIFEST_ENTRY))
                .expect("GUI handoff must match the verifier's strict shared manifest schema");
        assert_eq!(retained_manifest.schema, handoff::HANDOFF_SCHEMA_V4);
        let request_member_sha256 =
            sha256_hex(&archive_member(&retained, handoff::RUN_REQUEST_ENTRY));
        assert_eq!(
            retained_manifest.files.run_request.as_deref(),
            Some(request_member_sha256.as_str())
        );
        assert!(retained_manifest.evidence.included);
        assert_eq!(retained_manifest.scope.scanner_owned_reviews_included, 1);
        assert_eq!(
            retained_manifest
                .scope
                .unreviewed_and_non_scanner_rules_excluded,
            2
        );
        assert!(retained_manifest
            .note
            .contains("manual, Not Reviewed, and outside-profile rules are excluded"));
        let fallback_text = String::from_utf8(archive_member(&retained, "fallback.cklb")).unwrap();
        let fallback = automatestig_parsers::cklb::parse_cklb(&fallback_text).unwrap();
        assert_eq!(fallback.findings.len(), 1);
        assert_eq!(fallback.findings[0].rule_id, "SV-100001_rule");
        let retained_xccdf = archive_member(&retained, "results.xccdf.xml");
        let validation =
            automatestig_core::xccdf_results::validate_xccdf_1_2_results(&retained_xccdf).unwrap();
        assert_eq!(validation.rule_result_ids.len(), 1);
        assert!(validation
            .rule_result_ids
            .contains("xccdf_mil.disa.stig_rule_SV-100001_rule"));
        assert!(!String::from_utf8(retained_xccdf)
            .unwrap()
            .contains("SV-100002_rule"));

        let purged_metadata = state
            .db()
            .purge_scan_evidence(&record.id, ScanEvidencePurgeReason::OperatorRequested)
            .unwrap();
        let results_only = build_handoff_zip(&record, &artifact, &purged_metadata, None).unwrap();
        assert_eq!(
            archive_names(&results_only),
            HashSet::from([
                "manifest.json".to_string(),
                "integrity.json".to_string(),
                "run-request.json".to_string(),
                "scanner-run.json".to_string(),
                "sparse-reviews.json".to_string(),
                "fallback.cklb".to_string(),
                "results.xccdf.xml".to_string(),
            ])
        );
        let purged_manifest = handoff::parse_handoff_manifest(&archive_member(
            &results_only,
            handoff::MANIFEST_ENTRY,
        ))
        .expect("results-only GUI handoff must match the verifier's strict shared schema");
        assert!(!purged_manifest.evidence.included);
        assert_eq!(
            purged_manifest.evidence.state,
            handoff::EvidenceState::Purged
        );
        assert!(purged_manifest.evidence.purged_at.is_some());
        assert!(purged_manifest.note.contains("results-only package"));
        let purged_fallback = automatestig_parsers::cklb::parse_cklb(
            &String::from_utf8(archive_member(&results_only, "fallback.cklb")).unwrap(),
        )
        .unwrap();
        assert_eq!(purged_fallback.findings.len(), 1);
        assert_eq!(purged_fallback.findings[0].rule_id, "SV-100001_rule");
    }

    fn delivery_test_state(
        configured: &crate::stigman::StigManagerConfig,
        bound: &crate::stigman::StigManagerConfig,
    ) -> (tempfile::TempDir, AppState) {
        let temporary = tempfile::tempdir().unwrap();
        let state = AppState {
            inner: Arc::new(crate::state::AppStateInner {
                db: Mutex::new(automatestig_storage::Database::in_memory().unwrap()),
                data_dir: temporary.path().to_path_buf(),
                scanner_preflights: Mutex::new(HashMap::new()),
            }),
        };
        state
            .db()
            .set_config(
                "stigman_config",
                &serde_json::to_string(configured).unwrap(),
            )
            .unwrap();

        let profile_id = "cisco_ios_xe_router_ndm";
        let profile = bundled_scanner_profile(profile_id).unwrap().unwrap();
        let adapter = built_in_target_adapter(profile_id).unwrap();
        let device = DeviceFingerprint::new("router-1", "Cisco", "IOS-XE", "17.9");
        let plan = adapter.preview(&device).unwrap();
        let configuration = concat!(
            "version 17.9\n",
            "hostname router-1\n",
            "interface GigabitEthernet1\n",
            " description uplink\n",
            " no shutdown\n",
            "!\n",
            "end\n",
        );
        let evidence_envelope = AdapterEvidenceEnvelope::seal_now(
            &plan,
            device.clone(),
            EvidenceTransportIdentity::offline_artifact(configuration.as_bytes()),
            plan.operations
                .iter()
                .map(|operation| AdapterOperationEvidence::success(operation, configuration, 1))
                .collect(),
        )
        .unwrap();
        adapter.replay(&evidence_envelope).unwrap();
        let now = Utc::now();
        let policy_bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "automatestig-organization-policy/v1",
            "policy_id": "delivery-lease-test",
            "policy_version": "1",
            "stig_id": profile.stig_id(),
            "stig_release": profile.stig_release(),
            "asset_hostname": "router-1",
            "effective_from": (now - ChronoDuration::days(1)).to_rfc3339(),
            "expires_at": (now + ChronoDuration::days(1)).to_rfc3339(),
            "rules": {
                "V-215807": { "max_concurrent_management_sessions": 2 },
                "V-215836": { "minimum_logging_buffer_bytes": 4_096_000 },
                "V-215838": {
                    "approved_authoritative_ntp_sources": ["10.10.1.10", "10.10.1.11"]
                }
            }
        }))
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let signature = signing_key.sign(&Sha256::digest(&policy_bytes)).to_bytes();
        let verified_policy =
            automatestig_core::organization_policy::VerifiedOrganizationPolicy::verify_and_parse(
                &policy_bytes,
                &signature,
                &[signing_key.verifying_key().to_bytes()],
                profile.stig_id(),
                profile.stig_release(),
                "router-1",
                now,
            )
            .unwrap();
        let mut evaluation = automatestig_scanner::evaluate_adapter_envelope(
            profile_id,
            &evidence_envelope,
            EvaluationOrigin::ConfigFile,
            Some(verified_policy),
        )
        .unwrap();
        // This fixture isolates durable delivery lease behavior. Preserve the
        // evaluator's exact traces, but make its synthetic sparse result
        // complete so the test reaches delivery rather than Cisco policy IO.
        evaluation.collection_complete = true;
        evaluation.collection_errors.clear();
        evaluation.sparse_reviews = evaluation
            .decision_traces
            .iter()
            .map(|trace| ScannerReview {
                rule_id: trace.rule_id.clone(),
                result: if trace.passed {
                    ScannerReviewResult::Pass
                } else {
                    ScannerReviewResult::Fail
                },
                detail: "Fixture scanner-owned review".to_string(),
                comment: "AutomateSTIG sparse result".to_string(),
                evidence_source:
                    automatestig_integrations::stig_manager::ScannerEvidenceSource::SuppliedEvidence,
                evaluated_at: Some(Utc::now().to_rfc3339()),
            })
            .collect();
        let (stored_evidence, evidence_reference) =
            seal_run_evidence(&state, "rebound-run", &evidence_envelope).unwrap();
        let destination = DestinationSelection {
            collection_id: "7".to_string(),
            asset_id: "42".to_string(),
            assignment_id: format!("{}:{}", profile.stig_id(), profile.stig_release()),
        };
        let artifact = StoredRunArtifact {
            schema: handoff::SCANNER_RUN_SCHEMA.to_string(),
            mode: RunMode::Connected,
            profile_id: profile_id.to_string(),
            collection_method: "configuration".to_string(),
            destination: Some(destination),
            destination_asset_name: Some("router-1".to_string()),
            endpoint: None,
            device: device.clone(),
            collection_complete: evaluation.collection_complete,
            collection_errors: evaluation.collection_errors,
            manual_untouched: 0,
            out_of_scope_untouched: Some(0),
            checklist: evaluation.checklist,
            reviews: evaluation.sparse_reviews,
            decision_traces: evaluation.decision_traces,
            signed_policy_material: evaluation.signed_policy_material,
            delivery_preview: DeliveryPreview::default(),
            evidence: evidence_reference,
        };
        let run = NewScanRun {
            id: "rebound-run".to_string(),
            checklist_id: Some(artifact.checklist.id.to_string()),
            asset_hostname: "router-1".to_string(),
            scanner_version: "test".to_string(),
            scan_source: "configuration_file".to_string(),
            stig_id: profile.stig_id().to_string(),
            stig_revision: profile.stig_release().to_string(),
            benchmark_sha256: evaluation.digests.benchmark_sha256.clone(),
            check_pack_sha256: evaluation.digests.check_pack_sha256.clone(),
            evaluation_plan_sha256: evaluation.digests.evaluation_plan_sha256.clone(),
            evidence_sha256: artifact.evidence.evidence_sha256.clone(),
            request_json: "{}".to_string(),
            result_json: serde_json::to_string(&artifact).unwrap(),
            completed_at: Utc::now(),
        };
        let pending = NewPendingDelivery {
            id: "rebound-delivery".to_string(),
            destination_kind: "stig_manager".to_string(),
            destination_instance_id: stig_manager_destination_instance_id(bound),
            destination_collection_id: "7".to_string(),
            destination_asset_id: Some("42".to_string()),
            request_json: "{}".to_string(),
            payload_json: "{}".to_string(),
            not_before: None,
        };
        state
            .db()
            .save_completed_scan_run_with_evidence_and_pending_delivery(
                &run,
                &stored_evidence,
                &pending,
            )
            .unwrap();
        (temporary, state)
    }

    #[tokio::test]
    async fn delivery_endpoint_rejects_rebinding_before_claiming_or_contacting_remote() {
        let original = connection("https://stigman-a.example.mil/api");
        let rebound = connection("https://stigman-b.example.mil/api");
        let (_temporary, state) = delivery_test_state(&rebound, &original);

        let response = deliver_run(State(state.clone()), Path("rebound-run".to_string())).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["error"]["code"].as_str(),
            Some("delivery_destination_changed")
        );
        let untouched = state.db().get_delivery("rebound-delivery").unwrap();
        assert_eq!(untouched.state, DeliveryState::Pending);
        assert_eq!(untouched.attempt_count, 0);
        assert!(untouched.claim_token.is_none());
    }

    #[tokio::test]
    async fn delivery_endpoint_reclaims_an_expired_sending_lease() {
        let original = connection("https://stigman-a.example.mil/api");
        let (_temporary, state) = delivery_test_state(&original, &original);
        let abandoned_at = Utc::now() - ChronoDuration::minutes(5);
        state
            .db()
            .claim_delivery_at(
                "rebound-delivery",
                "abandoned-worker",
                "abandoned-token",
                abandoned_at,
                Duration::from_secs(1),
            )
            .unwrap();

        let response = deliver_run(State(state.clone()), Path("rebound-run".to_string())).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["error"]["code"].as_str(),
            Some("delivery_payload_invalid")
        );

        let recovered = state.db().get_delivery("rebound-delivery").unwrap();
        assert_eq!(recovered.state, DeliveryState::Rejected);
        assert_eq!(recovered.attempt_count, 2);
        assert!(recovered.claim_token.is_none());
        let receipts = state
            .db()
            .list_delivery_receipts("rebound-delivery")
            .unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].attempt_number, 1);
        assert_eq!(receipts[0].outcome, DeliveryState::Retryable);
        assert_eq!(receipts[1].attempt_number, 2);
        assert_eq!(receipts[1].outcome, DeliveryState::Rejected);
    }
}
