//! Public HTTP surface for the scanner-first GUI.
//!
//! STIG Manager owns inventory, assignments, review workflow, reporting, and
//! long-term portfolio state. The GUI therefore exposes only the versioned
//! scanner API, two small service endpoints, and explicit tombstones for the
//! retired pre-scanner routes. Preserved legacy data is available through the
//! separate transition CLI, never through hidden HTTP handlers.

use std::path::Path;

use automatestig_integrations::stig_manager::StigManagerConfig;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;

/// Build the scanner-first API router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/v1", crate::scanner_api::routes())
        .route("/status", get(get_status))
        .route("/auth/check", get(auth_check))
        .merge(retired_legacy_surface_routes())
}

/// Extraction-free tombstones for every known pre-scanner GUI API path.
///
/// These routes deliberately use `any`: an obsolete client receives the same
/// migration contract even if its body or method no longer matches the former
/// handler. Unknown paths, including unknown `/v1` paths, remain ordinary 404s.
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

#[derive(Serialize)]
struct ServiceStatus {
    version: &'static str,
    api_version: &'static str,
    alive: bool,
    role: &'static str,
}

async fn get_status() -> Response {
    api_response_ok(ServiceStatus {
        version: env!("CARGO_PKG_VERSION"),
        api_version: "v1",
        alive: true,
        role: "difficult-device scanner and STIG Manager supplement",
    })
}

async fn auth_check() -> Response {
    api_response_ok(serde_json::json!({ "authenticated": true }))
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
            "error": error,
        })),
    )
        .into_response()
}

fn api_response_ok(data: impl Serialize) -> Response {
    match serde_json::to_value(data) {
        Ok(value) => api_response(StatusCode::OK, Some(value), None),
        Err(error) => api_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            Some(&format!("Failed to serialize response: {error}")),
        ),
    }
}

fn retired_surface_response(owner: &str, surface: &str, guidance: &str) -> Response {
    api_response(
        StatusCode::GONE,
        Some(serde_json::json!({
            "code": "legacy_surface_retired",
            "retired": true,
            "surface": surface,
            "owner": owner,
            "read_only_migration_access": false,
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
    )
}

async fn retired_stig_manager_review_mutation() -> Response {
    retired_surface_response(
        "STIG Manager",
        "human review and answer management",
        "This legacy AutomateSTIG operation is retired. STIG Manager owns human findings, answers, comments, and review workflow. AutomateSTIG only delivers scanner-owned sparse results through /api/v1 and never overwrites human review content.",
    )
}

async fn retired_stig_manager_portfolio_mutation() -> Response {
    retired_surface_response(
        "STIG Manager",
        "checklist portfolio and reporting",
        "This legacy AutomateSTIG operation is retired. STIG Manager owns checklist portfolio lifecycle, history, dashboards, exports, and reporting. Use /api/v1/runs for scanner results and download a scanner handoff when remote state must be reconciled.",
    )
}

async fn retired_broad_content_management() -> Response {
    retired_surface_response(
        "AutomateSTIG scanner release process",
        "broad DISA catalog import and update",
        "This broad DISA catalog operation is retired. Scanner content is limited to pinned, reviewed target profiles exposed by /api/v1/profiles; use the signed scanner-content release process instead of importing or updating an unrestricted DISA portfolio in the GUI.",
    )
}

async fn retired_scanner_v1_bypass() -> Response {
    retired_surface_response(
        "AutomateSTIG scanner run service",
        "legacy connection, collection, evaluation, or STIG Manager push",
        "This legacy operation bypassed the versioned scanner contract, immutable runs, exact destination bindings, sparse ownership checks, or the durable delivery outbox, so it is retired. Use Scan or the /api/v1 connection, preflight, run, handoff, and delivery endpoints.",
    )
}

fn organization_policy_keys_dir(state: &AppState) -> std::path::PathBuf {
    std::env::var("AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| state.inner.data_dir.join("organization_policy_keys"))
}

/// Verify a signed organization-policy document against locally installed
/// trust anchors and bind it to the exact STIG revision and target hostname.
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

    automatestig_core::organization_policy::VerifiedOrganizationPolicy::verify_and_parse(
        raw,
        signature,
        &trust_store.public_keys(),
        stig_id,
        stig_release,
        hostname,
        chrono::Utc::now(),
    )
}

/// Normalize fields whose surrounding whitespace has no semantic meaning.
pub(crate) fn normalize_stigman_config(config: &mut StigManagerConfig) {
    config.api_url = config.api_url.trim().to_owned();
    config.token_url = config.token_url.trim().to_owned();
    config.client_id = config.client_id.trim().to_owned();
    config.default_collection_id = config
        .default_collection_id
        .take()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
}

/// Load STIG Manager configuration and decrypt its client secret in memory.
pub(crate) fn load_stigman_config(
    db: &automatestig_storage::Database,
    data_dir: &Path,
) -> Result<StigManagerConfig, String> {
    let mut config: StigManagerConfig = match db
        .get_config("stigman_config")
        .map_err(|error| format!("Failed to load STIG-Manager config: {error}"))?
    {
        Some(json) => serde_json::from_str(&json)
            .map_err(|error| format!("Failed to parse STIG-Manager config: {error}"))?,
        None => StigManagerConfig::default(),
    };

    if let Some(encrypted) = config.client_secret.strip_prefix("enc:") {
        config.client_secret = crate::secrets::load_or_create_key_material(data_dir)
            .and_then(|key_material| crate::secrets::decrypt_secret(encrypted, &key_material))
            .map_err(|error| format!("Failed to decrypt STIG-Manager client secret: {error}"))?;
    }

    Ok(config)
}

/// Validate and encrypt a STIG Manager connection before persistence.
///
/// A blank submitted secret means "keep the saved secret" only when the API,
/// token endpoint, and OAuth client identity are unchanged. That prevents a
/// form edit from silently forwarding an existing secret to a new endpoint.
pub(crate) fn persist_stigman_config(
    state: &AppState,
    mut config: StigManagerConfig,
) -> Result<(), String> {
    normalize_stigman_config(&mut config);

    if config.client_secret.is_empty() {
        let mut saved = load_stigman_config(&state.db(), &state.inner.data_dir)?;
        normalize_stigman_config(&mut saved);
        if config.api_url != saved.api_url
            || config.token_url != saved.token_url
            || config.client_id != saved.client_id
        {
            return Err(
                "client_secret must be re-entered when an endpoint or client ID changes"
                    .to_string(),
            );
        }
        config.client_secret = saved.client_secret;
    }

    config.validate_urls()?;
    if !config.client_secret.is_empty() {
        let key_material = crate::secrets::load_or_create_key_material(&state.inner.data_dir)
            .map_err(|error| format!("Key material error: {error}"))?;
        let encrypted = crate::secrets::encrypt_secret(&config.client_secret, &key_material)
            .map_err(|error| format!("Encryption failed: {error}"))?;
        config.client_secret = format!("enc:{encrypted}");
    }

    let json =
        serde_json::to_string(&config).map_err(|error| format!("Serialization error: {error}"))?;
    state
        .db()
        .set_config("stigman_config", &json)
        .map_err(|error| format!("Failed to save config: {error}"))
}

/// Resolve a saved configuration or an ephemeral form value for a connection
/// test. Submitted values are never persisted by this function.
pub(crate) fn resolve_stigman_test_config(
    state: &AppState,
    submitted: Option<StigManagerConfig>,
) -> Result<StigManagerConfig, String> {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::http::{header, Method, Request};
    use tower::ServiceExt;

    use super::*;

    fn test_state() -> (tempfile::TempDir, AppState) {
        let temporary = tempfile::tempdir().unwrap();
        let state = AppState {
            inner: Arc::new(crate::state::AppStateInner {
                db: Mutex::new(automatestig_storage::Database::in_memory().unwrap()),
                data_dir: temporary.path().to_path_buf(),
                scanner_preflights: Mutex::new(HashMap::new()),
            }),
        };
        (temporary, state)
    }

    #[tokio::test]
    async fn service_endpoints_remain_available() {
        let (_temporary, state) = test_state();
        let app = routes().with_state(state);

        for uri in ["/status", "/auth/check"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
        }
    }

    #[tokio::test]
    async fn every_retired_route_is_an_extraction_free_tombstone() {
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
                "/library/import-disa",
                "AutomateSTIG scanner release process",
            ),
            (
                Method::POST,
                "/library/import-stigpack",
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
            (Method::GET, "/checklists", "STIG Manager"),
            (Method::POST, "/checklists/import", "STIG Manager"),
            (Method::DELETE, "/checklists/legacy", "STIG Manager"),
            (
                Method::PATCH,
                "/checklists/legacy/findings/V-1",
                "STIG Manager",
            ),
            (Method::GET, "/assets", "STIG Manager"),
            (Method::POST, "/assets", "STIG Manager"),
            (Method::PUT, "/assets/legacy", "STIG Manager"),
            (Method::POST, "/assets/bulk-assign-stig", "STIG Manager"),
            (Method::POST, "/assets/bulk-update", "STIG Manager"),
            (Method::GET, "/answer-files", "STIG Manager"),
            (Method::PUT, "/answer-files/legacy.json", "STIG Manager"),
            (Method::GET, "/audit-log", "STIG Manager"),
            (Method::GET, "/export/ckl/legacy", "STIG Manager"),
            (Method::GET, "/export/cklb/legacy", "STIG Manager"),
            (Method::GET, "/export/all-zip", "STIG Manager"),
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
                "/stigman/push/legacy",
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
        ];

        for (method, uri, owner) in cases {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{not-valid-json"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::GONE, "{uri}");
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(payload["data"]["code"], "legacy_surface_retired", "{uri}");
            assert_eq!(payload["data"]["owner"], owner, "{uri}");
            assert_eq!(
                payload["data"]["read_only_migration_access"], false,
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_routes_remain_404_not_legacy_tombstones() {
        let (_temporary, state) = test_state();
        let app = routes().with_state(state);

        for uri in ["/not-a-retired-route", "/v1/not-a-scanner-route"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    fn connection(api_url: &str, secret: &str) -> StigManagerConfig {
        StigManagerConfig {
            api_url: api_url.to_string(),
            gui_url: Some("https://stigman.example.mil/".to_string()),
            token_url: "https://idp.example.mil/token".to_string(),
            client_id: "automatestig".to_string(),
            client_secret: secret.to_string(),
            default_collection_id: Some(" 7 ".to_string()),
            verify_tls: true,
        }
    }

    #[test]
    fn persisted_connection_encrypts_and_round_trips_secret() {
        let (_temporary, state) = test_state();
        let submitted = connection("https://stigman.example.mil/api", "saved-secret");

        persist_stigman_config(&state, submitted.clone()).unwrap();

        let stored = state.db().get_config("stigman_config").unwrap().unwrap();
        assert!(!stored.contains("saved-secret"));
        let stored_json: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert!(stored_json["client_secret"]
            .as_str()
            .unwrap()
            .starts_with("enc:"));

        let loaded = load_stigman_config(&state.db(), &state.inner.data_dir).unwrap();
        assert_eq!(loaded.client_secret, "saved-secret");
        assert_eq!(loaded.default_collection_id.as_deref(), Some("7"));
        assert_eq!(loaded.api_url, submitted.api_url);
    }

    #[tokio::test]
    async fn connection_delete_removes_the_saved_secret_and_is_idempotent() {
        let (_temporary, state) = test_state();
        persist_stigman_config(
            &state,
            connection("https://stigman.example.mil/api", "saved-secret"),
        )
        .unwrap();
        let app = routes().with_state(state.clone());

        for expected_deleted in [true, false] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::DELETE)
                        .uri("/v1/stig-manager/connection")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(payload["data"]["configured"], false);
            assert_eq!(payload["data"]["deleted"], expected_deleted);
            assert!(state.db().get_config("stigman_config").unwrap().is_none());
        }
    }

    #[test]
    fn blank_secret_is_reused_only_for_an_unchanged_connection_identity() {
        let (_temporary, state) = test_state();
        let saved = connection("https://stigman.example.mil/api", "saved-secret");
        persist_stigman_config(&state, saved.clone()).unwrap();

        let mut same_identity = saved.clone();
        same_identity.api_url = format!("  {}  ", same_identity.api_url);
        same_identity.token_url = format!("\t{}\n", same_identity.token_url);
        same_identity.client_id = format!(" {} ", same_identity.client_id);
        same_identity.client_secret.clear();
        persist_stigman_config(&state, same_identity).unwrap();
        let stored_before_rejected_change = state.db().get_config("stigman_config").unwrap();

        let mut changed_identity = saved;
        changed_identity.api_url = "https://other.example.mil/api".to_string();
        changed_identity.client_secret.clear();
        let error = persist_stigman_config(&state, changed_identity).unwrap_err();
        assert!(error.contains("must be re-entered"), "{error}");
        assert_eq!(
            state.db().get_config("stigman_config").unwrap(),
            stored_before_rejected_change
        );

        let loaded = load_stigman_config(&state.db(), &state.inner.data_dir).unwrap();
        assert_eq!(loaded.client_secret, "saved-secret");
    }

    #[test]
    fn unsaved_test_connection_is_ephemeral_and_secret_safe() {
        let (_temporary, state) = test_state();
        let saved = connection("https://stigman.example.mil/api", "saved-secret");
        persist_stigman_config(&state, saved.clone()).unwrap();
        let stored_before_test = state.db().get_config("stigman_config").unwrap();

        let mut same_identity = saved.clone();
        same_identity.client_secret.clear();
        same_identity.default_collection_id = Some(" 9 ".to_string());
        let resolved = resolve_stigman_test_config(&state, Some(same_identity)).unwrap();
        assert_eq!(resolved.client_secret, "saved-secret");
        assert_eq!(resolved.default_collection_id.as_deref(), Some("9"));

        let mut changed_identity = saved;
        changed_identity.client_id = "different-client".to_string();
        changed_identity.client_secret.clear();
        assert!(resolve_stigman_test_config(&state, Some(changed_identity)).is_err());
        assert_eq!(
            state.db().get_config("stigman_config").unwrap(),
            stored_before_test
        );
    }

    #[test]
    fn organization_policy_is_signature_revision_and_asset_bound() {
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
                "V-215838": {
                    "approved_authoritative_ntp_sources": ["192.0.2.10", "192.0.2.11"]
                }
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

        for (stig_release, hostname) in [("V3R8", "router-01"), ("V3R7", "router-02")] {
            assert!(verify_organization_policy_with_trust_dir(
                &trust,
                &policy,
                &signature,
                "Cisco_IOS-XE_Router_NDM_STIG",
                stig_release,
                hostname,
            )
            .is_err());
        }

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
}
