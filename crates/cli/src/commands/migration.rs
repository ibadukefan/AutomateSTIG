//! Protected transition inventory, preservation export, and retained-run bind.
//!
//! Inventory and export open the database read-only and never change local or
//! STIG Manager records. `bind-run` performs one narrowly scoped append-only
//! local mapping after authoritative remote readback; it never creates or
//! changes STIG Manager assets, assignments, reviews, or collections.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::models::checklist::{Checklist, EvaluationOrigin};
use automatestig_core::models::finding::{FindingSource, FindingStatus};
use automatestig_core::selected_run_handoff::{SCANNER_RUN_SCHEMA_V2, SCANNER_RUN_SCHEMA_V3};
use automatestig_core::target_adapters::DeviceFingerprint;
use automatestig_integrations::stig_manager::{
    exact_assignment, StigManagerClient, StigManagerClientSecret, StigManagerConnection,
    StigManagerServerConfiguration, STIG_MANAGER_API_ADAPTER_ID,
};
use automatestig_storage::{
    AnswerFileRegistryRecord, AuditEvent, ChecklistSummaryRow, Database, DeliveryReceipt,
    DeliveryRecord, DeliveryState, EvaluationHistoryRecord, MigrationRunBindingRecord,
    NewMigrationRunBinding, OperationalPurgeTombstone, ReconciliationReceiptCustodyRecord,
    ScanEvidenceCustodyRecord, ScanEvidenceState, ScanJobRecord, ScanJobTransitionRecord,
    ScanOperationCheckpointCustodyRecord, ScanRunRecord, StorageError,
    TargetConnectionProfileRecord,
};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

use super::{db_path, ensure_safe_artifact_output, library_path};

const INVENTORY_SCHEMA: &str = "automatestig.migration-inventory.v1";
const BUNDLE_SCHEMA: &str = "automatestig.migration-bundle.v2";
const ENCRYPTED_CUSTODY_SCHEMA: &str = "automatestig.encrypted-custody.v1";
const RECEIPT_CUSTODY_SCHEMA: &str = "automatestig.reconciliation-receipt-custody.v1";
const RETENTION_CONFIG_SCHEMA: &str = "automatestig.scanner-retention-config.v1";
const LEGACY_SCANNER_RUN_SCHEMA: &str = "automatestig.scanner-run.v1";
const MIGRATION_BINDING_SCHEMA: &str = "automatestig.migration-run-binding.v1";
const MIGRATION_BINDING_RECEIPT_SCHEMA: &str = "automatestig.migration-run-binding-receipt.v1";
const MAX_ANSWER_TEMPLATE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BUNDLE_UNCOMPRESSED_BYTES: usize = 512 * 1024 * 1024;

/// Explicit inputs for the protected retained-run destination binding.
///
/// The OAuth secret is read from `client_secret_env`; it is never accepted as
/// a command-line value, serialized, logged, or persisted.
#[derive(Debug, Clone)]
pub struct BindRunArgs {
    pub run_id: String,
    pub api_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret_env: String,
    pub destination_allowlist: Vec<String>,
    pub collection_id: String,
    pub asset_id: String,
    pub operator_source: String,
    pub output: Option<String>,
}

#[derive(Debug, Clone)]
struct VerifiedRetainedRunIdentity {
    hostname: String,
    device_fingerprint_sha256: String,
}

#[derive(Debug, Serialize)]
struct MigrationRunBindingDocument<'a> {
    schema: &'static str,
    run_id: &'a str,
    destination_instance_id: &'a str,
    destination_collection_id: &'a str,
    destination_asset_id: &'a str,
    destination_assignment_id: &'a str,
    stig_id: &'a str,
    stig_revision: &'a str,
    observed_stig_manager_version: &'a str,
    observed_server_identity: &'a str,
    operator_source: &'a str,
    mapped_at: &'a str,
    api_adapter_id: &'static str,
    device_fingerprint_sha256: &'a str,
    asset_identity_match_sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct MigrationRunBindingReceipt {
    schema: &'static str,
    binding: MigrationRunBindingRecord,
    mapping: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordClassification {
    CompletedScannerOutput,
    IncompleteAuditOnly,
    ImportedUnverified,
    ManuallyEdited,
    AnswerFileDerived,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
struct FindingSourceCounts {
    automated: usize,
    evidence: usize,
    manual: usize,
    manual_reviewed: usize,
    imported: usize,
    answer_file: usize,
    collection_error: usize,
}

impl FindingSourceCounts {
    fn from_checklist(checklist: &Checklist) -> Self {
        let mut counts = Self::default();
        for finding in &checklist.findings {
            match finding.source {
                FindingSource::Automated => counts.automated += 1,
                FindingSource::Evidence => counts.evidence += 1,
                FindingSource::Manual => {
                    counts.manual += 1;
                    if finding.status != FindingStatus::NotReviewed
                        || !finding.finding_details.trim().is_empty()
                        || !finding.comments.trim().is_empty()
                        || !finding.evaluated_by.trim().is_empty()
                        || finding.severity_override.is_some()
                        || finding.severity_override_justification.is_some()
                    {
                        counts.manual_reviewed += 1;
                    }
                }
                FindingSource::Imported => counts.imported += 1,
                FindingSource::AnswerFile => counts.answer_file += 1,
                FindingSource::CollectionError => counts.collection_error += 1,
            }
        }
        counts
    }
}

#[derive(Debug, Clone, Serialize)]
struct ChecklistInventory {
    id: String,
    asset_hostname: String,
    stig_id: String,
    stig_revision: String,
    created_at: String,
    modified_at: String,
    classifications: Vec<RecordClassification>,
    finding_sources: Option<FindingSourceCounts>,
    evaluation_origin: Option<EvaluationOrigin>,
    collection_complete: Option<bool>,
    unsafe_legacy_evidence: Option<bool>,
    external_interop_export_allowed: bool,
    external_interop_export_block_reason: Option<String>,
    linked_scanner_run_ids: Vec<String>,
    parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ScannerRunInventory {
    id: String,
    asset_hostname: String,
    stig_id: String,
    stig_revision: String,
    scan_source: String,
    completed_at: String,
    classifications: Vec<RecordClassification>,
    finding_sources: Option<FindingSourceCounts>,
    collection_complete: Option<bool>,
    stored_json_digests_verified: bool,
    scanner_evidence_bindings_verified: bool,
    external_interop_export_allowed: bool,
    verification_errors: Vec<String>,
    delivery_states: Vec<String>,
    remote_receipt_verified: bool,
    retention_cleanup_eligible: bool,
}

#[derive(Debug, Clone, Serialize)]
struct AnswerTemplateInventory {
    filename: String,
    filename_is_utf8: bool,
    export_member: String,
    sha256: String,
    size_bytes: usize,
    valid_answer_file: bool,
    stig_id: Option<String>,
    entry_count: Option<usize>,
    validation_errors: Vec<String>,
    classification: RecordClassification,
}

#[derive(Debug, Clone, Serialize)]
struct LegacyAssetInventorySummary {
    present: bool,
    valid_json: bool,
    record_count: Option<usize>,
    sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DestinationBinding {
    delivery_id: String,
    scan_run_id: String,
    local_asset_hostname: Option<String>,
    destination_instance_id: String,
    collection_id: String,
    asset_id: Option<String>,
    stig_id: String,
    stig_revision: String,
    delivery_state: String,
    remote_receipt_present: bool,
    delivered_receipt_verified: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
struct InventorySummary {
    completed_scanner_output_records: usize,
    incomplete_audit_only_records: usize,
    imported_unverified_records: usize,
    manually_edited_records: usize,
    answer_file_derived_records: usize,
    local_checklists: usize,
    immutable_scanner_runs: usize,
    incomplete_audit_events: usize,
    evaluation_history_rows: usize,
    audit_events: usize,
    answer_templates: usize,
    legacy_answer_registry_rows: usize,
    destination_bindings: usize,
    retained_run_bindings: usize,
    deliveries_with_verified_receipts: usize,
}

struct InventorySummaryInput<'a> {
    checklists: &'a [ChecklistInventory],
    scanner_runs: &'a [ScannerRunInventory],
    incomplete_audit_events: usize,
    evaluation_history_rows: usize,
    audit_events: usize,
    answer_templates: usize,
    legacy_answer_registry_rows: usize,
    destination_bindings: &'a [DestinationBinding],
    retained_run_bindings: usize,
}

#[derive(Debug, Clone, Serialize)]
struct MigrationInventoryReport {
    schema: &'static str,
    generated_at: String,
    read_only: bool,
    database_schema_version: Option<i64>,
    attribution_policy: &'static str,
    summary: InventorySummary,
    checklists: Vec<ChecklistInventory>,
    scanner_runs: Vec<ScannerRunInventory>,
    incomplete_audit_events: Vec<AuditEvent>,
    answer_templates: Vec<AnswerTemplateInventory>,
    legacy_answer_registry: Vec<AnswerFileRegistryRecord>,
    legacy_asset_inventory: LegacyAssetInventorySummary,
    stig_manager_connection: Option<Value>,
    destination_bindings: Vec<DestinationBinding>,
    retained_run_bindings: Vec<MigrationRunBindingRecord>,
    warnings: Vec<String>,
}

struct LegacyChecklistSnapshot {
    row: ChecklistSummaryRow,
    raw_json: String,
    parsed: Option<Checklist>,
    parse_error: Option<String>,
}

struct DatabaseSnapshot {
    schema_version: Option<i64>,
    checklists: Vec<LegacyChecklistSnapshot>,
    scan_runs: Vec<ScanRunRecord>,
    deliveries: Vec<DeliveryRecord>,
    delivery_receipts: BTreeMap<String, Vec<DeliveryReceipt>>,
    migration_run_bindings: Vec<MigrationRunBindingRecord>,
    scan_evidence_custody: Vec<ScanEvidenceCustodyRecord>,
    scan_jobs: Vec<ScanJobRecord>,
    scan_job_transitions: Vec<ScanJobTransitionRecord>,
    target_connection_profiles: Vec<TargetConnectionProfileRecord>,
    scan_operation_checkpoint_custody: Vec<ScanOperationCheckpointCustodyRecord>,
    reconciliation_receipt_custody: Vec<ReconciliationReceiptCustodyRecord>,
    operational_purge_tombstones: Vec<OperationalPurgeTombstone>,
    evidence_retention_days_raw: Option<String>,
    operational_retention_days_raw: Option<String>,
    evaluation_history: Vec<EvaluationHistoryRecord>,
    audit_events: Vec<AuditEvent>,
    answer_registry: Vec<AnswerFileRegistryRecord>,
    asset_inventory_raw: Option<String>,
    stigman_config_raw: Option<String>,
}

struct AnswerTemplateSnapshot {
    inventory: AnswerTemplateInventory,
    bytes: Vec<u8>,
}

struct RunAnalysis {
    inventory: ScannerRunInventory,
    checklist: Option<Checklist>,
}

struct TransitionSnapshot {
    database: DatabaseSnapshot,
    answers: Vec<AnswerTemplateSnapshot>,
    report: MigrationInventoryReport,
    run_checklists: HashMap<String, Checklist>,
}

#[derive(Serialize)]
struct AttributionSidecar<'a> {
    schema: &'static str,
    checklist_id: &'a str,
    classifications: &'a [RecordClassification],
    finding_sources: &'a Option<FindingSourceCounts>,
    warning: &'static str,
}

#[derive(Serialize)]
struct BundleMember {
    path: String,
    sha256: String,
    size_bytes: usize,
}

#[derive(Serialize)]
struct BundleManifest<'a> {
    schema: &'static str,
    generated_at: &'a str,
    read_only_export: bool,
    sensitive_data: bool,
    attribution_policy: &'static str,
    retention_cleanup_performed: bool,
    summary: &'a InventorySummary,
    members: Vec<BundleMember>,
}

#[derive(Serialize)]
struct EncryptedCustodyDescriptor {
    schema: &'static str,
    object_kind: &'static str,
    object_id: String,
    metadata_member: String,
    ciphertext_member: Option<String>,
    ciphertext_sha256: Option<String>,
    ciphertext_size_bytes: Option<usize>,
    wrapped_dek_member: Option<String>,
    wrapped_dek_sha256: Option<String>,
    wrapped_dek_size_bytes: Option<usize>,
    stored_bindings_verified: bool,
    plaintext_exported: bool,
}

#[derive(Serialize)]
struct ReconciliationReceiptCustodyDescriptor {
    schema: &'static str,
    receipt_id: String,
    record_member: String,
    receipt_member: String,
    stored_receipt_sha256: String,
    archived_receipt_sha256: String,
    stored_binding_verified: bool,
    detached_signature_member: Option<String>,
    detached_signature_sha256: Option<String>,
    detached_signature_size_bytes: Option<usize>,
}

pub fn inventory(output: Option<&str>, cli: &crate::Cli) -> Result<()> {
    let snapshot = load_transition_snapshot(cli)?;
    let bytes = serde_json::to_vec_pretty(&snapshot.report)?;
    match output {
        None | Some("-") => println!("{}", String::from_utf8(bytes)?),
        Some(output) => {
            let output = Path::new(output);
            ensure_safe_artifact_output(output, &[], cli)?;
            super::evaluate::write_evaluation_output_atomic(output, &bytes)?;
            crate::ui::success("Read-only migration inventory written");
            crate::ui::output_file("Output", &output.display().to_string(), "JSON");
        }
    }
    Ok(())
}

pub fn export(output: &str, cli: &crate::Cli) -> Result<()> {
    let output = Path::new(output);
    if output.extension().and_then(|value| value.to_str()) != Some("zip") {
        anyhow::bail!("migration export output must use the .zip extension");
    }
    if output.exists() {
        anyhow::bail!(
            "migration export refuses to replace existing output {}; choose a new path",
            output.display()
        );
    }
    ensure_safe_artifact_output(output, &[], cli)?;

    let snapshot = load_transition_snapshot(cli)?;
    let bytes = build_bundle(&snapshot)?;
    super::evaluate::write_evaluation_output_atomic(output, &bytes)?;
    crate::ui::success("Read-only migration bundle created");
    crate::ui::output_file(
        "Output",
        &output.display().to_string(),
        "private transition ZIP",
    );
    Ok(())
}

/// Bind one immutable retained scanner run to an exact existing STIG Manager
/// asset and assignment after live authoritative readback.
///
/// This is deliberately a protected transition operation. It creates no
/// collection, asset, assignment, review, delivery, or checklist, and it does
/// not edit the retained run. The only database mutation is one append-only
/// `migration_run_bindings` row.
pub fn bind_run(args: BindRunArgs, cli: &crate::Cli) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not initialize the protected migration network runtime")?;
    runtime.block_on(bind_run_connected(args, cli))
}

async fn bind_run_connected(args: BindRunArgs, cli: &crate::Cli) -> Result<()> {
    validate_bind_run_args(&args)?;
    if let Some(output) = args.output.as_deref().filter(|value| *value != "-") {
        let output = Path::new(output);
        if output.exists() {
            anyhow::bail!(
                "migration binding receipt refuses to replace existing output {}; choose a new path",
                output.display()
            );
        }
        ensure_safe_artifact_output(output, &[], cli)?;
    }

    let database_path = db_path(cli);
    let database = Database::open_existing_for_transition_write(&database_path).with_context(|| {
        format!(
            "failed to open {} for an exact transition write; start the matching AutomateSTIG release once to finish schema migration, then stop it before binding a retained run",
            database_path.display()
        )
    })?;
    let retained_run = database.get_scan_run(args.run_id.trim()).with_context(|| {
        format!(
            "retained scanner run {:?} was not found",
            args.run_id.trim()
        )
    })?;
    match database.get_migration_run_binding(&retained_run.id) {
        Ok(existing) => anyhow::bail!(
            "retained run {} already has immutable migration binding {} (mapping {}); remapping is forbidden",
            retained_run.id,
            existing.id,
            existing.mapping_sha256
        ),
        Err(StorageError::NotFound(_)) => {}
        Err(error) => return Err(error).context("could not inspect existing migration bindings"),
    }
    let verified_identity = validate_retained_run_for_binding(&retained_run)?;

    let secret = std::env::var(args.client_secret_env.trim()).with_context(|| {
        format!(
            "OAuth client secret environment variable {:?} is not set",
            args.client_secret_env.trim()
        )
    })?;
    if secret.is_empty() {
        anyhow::bail!(
            "OAuth client secret environment variable {:?} is empty",
            args.client_secret_env.trim()
        );
    }
    let api_url = args.api_url.trim().to_string();
    let connection = StigManagerConnection {
        api_url: api_url.clone(),
        token_url: args.token_url.trim().to_string(),
        client_id: args.client_id.trim().to_string(),
        allowed_private_addresses: Vec::new(),
    };
    let client = StigManagerClient::new_with_destination_allowlist(
        connection,
        StigManagerClientSecret::new(secret),
        args.destination_allowlist.clone(),
    )
    .await
    .context("live STIG Manager capability and destination authorization failed")?;
    let capabilities = client
        .discover_capabilities()
        .await
        .context("could not confirm the exact tested STIG Manager API adapter")?;
    let collection_id = args.collection_id.trim().to_string();
    let asset_id = args.asset_id.trim().to_string();
    let asset = client
        .get_asset(&collection_id, &asset_id)
        .await
        .context("could not read the explicitly selected STIG Manager asset and assignments")?;
    let assignment = exact_assignment(&asset, &retained_run.stig_id, &retained_run.stig_revision)
        .context(
        "the selected asset does not have one unambiguous exact retained-run assignment",
    )?;
    let matched_remote_identity = exact_asset_identity_match(
        &verified_identity.hostname,
        &asset.name,
        asset.fqdn.as_deref(),
    )?;

    let destination_instance_id = sha256_hex(api_url.as_bytes());
    let destination_assignment_id = format!(
        "{}:{}",
        assignment.benchmark_id.trim(),
        assignment.revision.trim()
    );
    let observed_server_identity = server_identity_sha256(&capabilities.server)?;
    let mapped_at = Utc::now();
    let mapped_at_text = mapped_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let identity_match_sha256 = domain_sha256(
        b"AUTOMATESTIG-MIGRATION-ASSET-IDENTITY-V1\0",
        &[
            verified_identity.hostname.as_bytes(),
            matched_remote_identity.as_bytes(),
            verified_identity.device_fingerprint_sha256.as_bytes(),
        ],
    );
    let operator_source = args.operator_source.trim().to_string();
    let mapping_document = MigrationRunBindingDocument {
        schema: MIGRATION_BINDING_SCHEMA,
        run_id: &retained_run.id,
        destination_instance_id: &destination_instance_id,
        destination_collection_id: &collection_id,
        destination_asset_id: &asset_id,
        destination_assignment_id: &destination_assignment_id,
        stig_id: &retained_run.stig_id,
        stig_revision: &retained_run.stig_revision,
        observed_stig_manager_version: &capabilities.server.version,
        observed_server_identity: &observed_server_identity,
        operator_source: &operator_source,
        mapped_at: &mapped_at_text,
        api_adapter_id: STIG_MANAGER_API_ADAPTER_ID,
        device_fingerprint_sha256: &verified_identity.device_fingerprint_sha256,
        asset_identity_match_sha256: &identity_match_sha256,
    };
    let mapping_json = serde_json::to_string(&mapping_document)
        .context("could not serialize the immutable migration mapping")?;
    let mapping_sha256 = sha256_hex(mapping_json.as_bytes());
    let binding = NewMigrationRunBinding {
        id: uuid::Uuid::new_v4().to_string(),
        run_id: retained_run.id.clone(),
        destination_instance_id,
        destination_collection_id: collection_id,
        destination_asset_id: asset_id,
        destination_assignment_id,
        stig_id: retained_run.stig_id.clone(),
        stig_revision: retained_run.stig_revision.clone(),
        observed_stig_manager_version: capabilities.server.version,
        observed_server_identity,
        mapping_json: mapping_json.clone(),
        mapping_sha256,
        mapped_at,
        operator_source,
    };

    // Retain the same protected file-custody handle across authoritative
    // readback, then prove the exact immutable source row did not change before
    // committing the single append-only mapping. This also closes a pathname
    // replacement window between validation and commit.
    let current_run = database
        .get_scan_run(&retained_run.id)
        .context("retained scanner run disappeared before migration binding commit")?;
    if current_run != retained_run {
        anyhow::bail!(
            "retained scanner run identity changed during live destination validation; no mapping was written"
        );
    }
    let stored = database
        .create_migration_run_binding(&binding)
        .context("could not append the immutable retained-run destination binding")?;
    let mapping: Value = serde_json::from_str(&mapping_json)
        .expect("mapping JSON was serialized from a typed document");
    let receipt = MigrationRunBindingReceipt {
        schema: MIGRATION_BINDING_RECEIPT_SCHEMA,
        binding: stored,
        mapping,
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt)
        .context("could not serialize the migration binding receipt")?;
    match args.output.as_deref() {
        None | Some("-") => println!("{}", String::from_utf8(receipt_bytes)?),
        Some(output) => {
            let output = Path::new(output);
            super::evaluate::write_evaluation_output_atomic(output, &receipt_bytes).with_context(
                || {
                    format!(
                        "the immutable migration binding was committed, but its optional receipt could not be written to {}",
                        output.display()
                    )
                },
            )?;
            crate::ui::success("Immutable migration binding recorded");
            crate::ui::output_file("Receipt", &output.display().to_string(), "JSON");
        }
    }
    Ok(())
}

fn validate_bind_run_args(args: &BindRunArgs) -> Result<()> {
    for (label, value, maximum) in [
        ("run ID", args.run_id.as_str(), 256usize),
        ("STIG Manager API URL", args.api_url.as_str(), 2_048),
        ("OAuth token URL", args.token_url.as_str(), 2_048),
        ("OAuth client ID", args.client_id.as_str(), 256),
        ("collection ID", args.collection_id.as_str(), 32),
        ("asset ID", args.asset_id.as_str(), 32),
        ("operator source", args.operator_source.as_str(), 256),
    ] {
        require_bounded_printable(label, value, maximum)?;
    }
    let env_name = args.client_secret_env.trim();
    if env_name.is_empty()
        || env_name.len() > 128
        || !env_name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        anyhow::bail!(
            "client-secret environment variable name must contain 1-128 uppercase letters, digits, or underscores"
        );
    }
    reject_credential_looking_metadata("operator source", args.operator_source.trim())?;
    Ok(())
}

fn require_bounded_printable(label: &str, value: &str, maximum: usize) -> Result<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        anyhow::bail!("{label} must contain 1-{maximum} printable UTF-8 bytes");
    }
    Ok(())
}

fn reject_credential_looking_metadata(label: &str, value: &str) -> Result<()> {
    let lowercase = value.to_ascii_lowercase();
    if lowercase.starts_with("bearer ")
        || lowercase.starts_with("basic ")
        || [
            "authorization:",
            "password=",
            "passphrase=",
            "secret=",
            "token=",
            "api_key=",
            "apikey=",
        ]
        .iter()
        .any(|marker| lowercase.contains(marker))
        || value.contains("-----BEGIN ")
    {
        anyhow::bail!("{label} appears to contain credential material");
    }
    Ok(())
}

fn validate_retained_run_for_binding(run: &ScanRunRecord) -> Result<VerifiedRetainedRunIdentity> {
    if sha256_hex(run.request_json.as_bytes()) != run.request_sha256
        || sha256_hex(run.result_json.as_bytes()) != run.result_sha256
    {
        anyhow::bail!("retained scanner run JSON digest verification failed");
    }
    let artifact: Value = serde_json::from_str(&run.result_json)
        .context("retained scanner run result is not valid JSON")?;
    let schema = artifact
        .get("schema")
        .and_then(Value::as_str)
        .context("retained scanner run result has no schema")?;
    if schema == LEGACY_SCANNER_RUN_SCHEMA {
        anyhow::bail!(
            "legacy scanner-run.v1 is preserved by migration inventory/export but cannot be destination-bound because it lacks the sealed evidence-to-device fingerprint binding"
        );
    }
    if !matches!(schema, SCANNER_RUN_SCHEMA_V2 | SCANNER_RUN_SCHEMA_V3) {
        anyhow::bail!("retained scanner run schema {schema:?} is not eligible for binding");
    }

    let analysis = analyze_run(run, &[], &BTreeMap::new());
    if analysis.inventory.classifications != vec![RecordClassification::CompletedScannerOutput]
        || !analysis.inventory.stored_json_digests_verified
        || !analysis.inventory.scanner_evidence_bindings_verified
        || !analysis.inventory.external_interop_export_allowed
    {
        let detail = analysis.inventory.verification_errors.join("; ");
        anyhow::bail!(
            "retained scanner run is not a complete, provenance-bound external result: {detail}"
        );
    }
    let checklist = analysis
        .checklist
        .context("retained scanner run has no usable checklist")?;
    let checklist_revision = format!(
        "V{}R{}",
        checklist.stig_info.version, checklist.stig_info.release
    );
    if checklist.stig_info.stig_id != run.stig_id || checklist_revision != run.stig_revision {
        anyhow::bail!("retained scanner run checklist STIG identity or revision changed");
    }
    if checklist.generated_by != format!("AutomateSTIG {}", run.scanner_version) {
        anyhow::bail!("retained scanner run generator identity changed");
    }

    let device_value = artifact
        .get("device")
        .cloned()
        .context("retained scanner run has no collected device fingerprint")?;
    let device: DeviceFingerprint = serde_json::from_value(device_value)
        .context("retained scanner run device fingerprint is invalid")?;
    let device_fingerprint_sha256 = device
        .sha256()
        .context("retained scanner run device fingerprint could not be verified")?;
    let recorded_fingerprint = artifact
        .pointer("/evidence/device_fingerprint_sha256")
        .and_then(Value::as_str)
        .context("retained scanner run has no evidence-bound device fingerprint digest")?;
    if recorded_fingerprint != device_fingerprint_sha256 {
        anyhow::bail!("retained scanner run device fingerprint binding changed");
    }
    let recorded_evidence = artifact
        .pointer("/evidence/evidence_sha256")
        .and_then(Value::as_str)
        .context("retained scanner run has no evidence digest binding")?;
    if recorded_evidence != run.evidence_sha256 {
        anyhow::bail!("retained scanner run evidence binding changed");
    }
    let recorded_collection_plan = artifact
        .pointer("/evidence/collection_plan_sha256")
        .and_then(Value::as_str)
        .context("retained scanner run has no collection-plan digest binding")?;
    let provenance = checklist
        .evaluation_provenance
        .as_ref()
        .context("retained scanner run checklist has no evaluation provenance")?;
    if provenance.plan_sha256.as_deref() != Some(recorded_collection_plan) {
        anyhow::bail!("retained scanner run collection-plan binding changed");
    }
    let hostname = canonical_host_identity(&device.hostname)?;
    if hostname != canonical_host_identity(&run.asset_hostname)?
        || hostname != canonical_host_identity(&checklist.asset.hostname)?
        || provenance
            .claimed_hostname
            .as_deref()
            .map(canonical_host_identity)
            .transpose()?
            .as_deref()
            != Some(hostname.as_str())
    {
        anyhow::bail!(
            "retained scanner run asset, checklist, provenance, and collected device identities do not exactly match"
        );
    }
    if schema == SCANNER_RUN_SCHEMA_V3 {
        validate_v3_trace_bindings(&artifact, run, &device_fingerprint_sha256)?;
    }
    Ok(VerifiedRetainedRunIdentity {
        hostname,
        device_fingerprint_sha256,
    })
}

fn validate_v3_trace_bindings(
    artifact: &Value,
    run: &ScanRunRecord,
    device_fingerprint_sha256: &str,
) -> Result<()> {
    let reviews = artifact
        .get("reviews")
        .and_then(Value::as_array)
        .context("scanner-run.v3 has no sparse reviews")?;
    let traces = artifact
        .get("decision_traces")
        .and_then(Value::as_array)
        .context("scanner-run.v3 has no decision traces")?;
    if traces.is_empty() || traces.len() != reviews.len() {
        anyhow::bail!("scanner-run.v3 must retain exactly one decision trace per sparse review");
    }
    let profile_id = artifact
        .get("profile_id")
        .and_then(Value::as_str)
        .context("scanner-run.v3 has no profile identity")?;
    let profile_sha256 = artifact
        .pointer("/evidence/profile_sha256")
        .and_then(Value::as_str)
        .context("scanner-run.v3 has no profile digest")?;
    let envelope_json_sha256 = artifact
        .pointer("/evidence/envelope_json_sha256")
        .and_then(Value::as_str)
        .context("scanner-run.v3 has no evidence-envelope JSON digest")?;
    let collection_plan_sha256 = artifact
        .pointer("/evidence/collection_plan_sha256")
        .and_then(Value::as_str)
        .context("scanner-run.v3 has no collection-plan digest")?;
    for trace in traces {
        let exact = |field: &str, expected: &str| {
            trace.get(field).and_then(Value::as_str) == Some(expected)
        };
        let operations = trace.get("operations").and_then(Value::as_array);
        if !exact("schema", automatestig_scanner::DECISION_TRACE_SCHEMA)
            || !exact("stig_id", &run.stig_id)
            || !exact("stig_revision", &run.stig_revision)
            || !exact("profile_id", profile_id)
            || !exact("profile_sha256", profile_sha256)
            || !exact("check_pack_sha256", &run.check_pack_sha256)
            || !exact("evaluation_plan_sha256", &run.evaluation_plan_sha256)
            || !exact("collection_plan_sha256", collection_plan_sha256)
            || !exact("evidence_envelope_sha256", &run.evidence_sha256)
            || !exact("evidence_envelope_json_sha256", envelope_json_sha256)
            || !exact("device_fingerprint_sha256", device_fingerprint_sha256)
            || trace
                .get("evaluation_error_class")
                .is_some_and(|value| !value.is_null())
            || operations.is_none_or(|operations| operations.is_empty())
        {
            anyhow::bail!("scanner-run.v3 decision trace bindings changed");
        }
        if operations.is_some_and(|operations| {
            operations.iter().any(|operation| {
                operation.get("status").and_then(Value::as_str) != Some("success")
                    || operation.get("truncated").and_then(Value::as_bool) != Some(false)
                    || operation.get("error_present").and_then(Value::as_bool) != Some(false)
                    || operation
                        .get("error_class")
                        .is_some_and(|value| !value.is_null())
            })
        }) {
            anyhow::bail!("scanner-run.v3 decision trace contains incomplete operation linkage");
        }
    }
    Ok(())
}

fn exact_asset_identity_match(
    run_hostname: &str,
    asset_name: &str,
    asset_fqdn: Option<&str>,
) -> Result<String> {
    let expected = canonical_host_identity(run_hostname)?;
    let candidates = [Some(asset_name), asset_fqdn];
    let mut matches = candidates
        .into_iter()
        .flatten()
        .filter_map(|value| canonical_host_identity(value).ok())
        .filter(|value| value == &expected);
    let Some(matched) = matches.next() else {
        anyhow::bail!(
            "collected device identity {:?} does not exactly match the selected STIG Manager asset name or FQDN; no mapping was written",
            run_hostname
        );
    };
    Ok(matched)
}

fn canonical_host_identity(value: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        anyhow::bail!("device identity is not a bounded hostname or FQDN");
    }
    Ok(value)
}

fn server_identity_sha256(server: &StigManagerServerConfiguration) -> Result<String> {
    let bytes = serde_json::to_vec(server)
        .context("could not serialize the observed STIG Manager server identity")?;
    Ok(domain_sha256(
        b"AUTOMATESTIG-STIGMAN-SERVER-IDENTITY-V1\0",
        &[&bytes],
    ))
}

fn domain_sha256(domain: &[u8], values: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("{:x}", hasher.finalize())
}

fn load_transition_snapshot(cli: &crate::Cli) -> Result<TransitionSnapshot> {
    let database_path = db_path(cli);
    let database = Database::open_read_only(&database_path).with_context(|| {
        format!(
            "failed to open {} read-only; start AutomateSTIG once to finish schema migration, then stop it before taking the transition snapshot",
            database_path.display()
        )
    })?;
    let database = snapshot_database(&database)?;
    let (answers, answer_warnings) = snapshot_answer_templates(&library_path(cli))?;
    let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    Ok(assemble_transition_snapshot(
        database,
        answers,
        answer_warnings,
        generated_at,
    ))
}

fn snapshot_database(database: &Database) -> Result<DatabaseSnapshot> {
    database
        .read_snapshot::<_, StorageError, _>(|database| {
            let schema_version = database.schema_version()?;
            let mut checklists = Vec::new();
            for row in database.list_checklists()? {
                let raw_json = database.load_checklist_json(&row.id)?;
                let (parsed, parse_error) = match serde_json::from_str::<Checklist>(&raw_json) {
                    Ok(checklist) => (Some(checklist), None),
                    Err(error) => (None, Some(error.to_string())),
                };
                checklists.push(LegacyChecklistSnapshot {
                    row,
                    raw_json,
                    parsed,
                    parse_error,
                });
            }

            let (scan_runs, deliveries, delivery_receipts) =
                if schema_version.is_some_and(|version| version >= 4) {
                    let scan_runs = database.list_scan_runs()?;
                    let deliveries = database.list_deliveries(None)?;
                    let mut receipts = BTreeMap::new();
                    for delivery in &deliveries {
                        receipts.insert(
                            delivery.id.clone(),
                            database.list_delivery_receipts(&delivery.id)?,
                        );
                    }
                    (scan_runs, deliveries, receipts)
                } else {
                    (Vec::new(), Vec::new(), BTreeMap::new())
                };
            let mut migration_run_bindings = Vec::new();
            let mut scan_evidence_custody = Vec::new();
            let mut scan_jobs = Vec::new();
            let mut scan_job_transitions = Vec::new();
            let mut target_connection_profiles = Vec::new();
            let mut scan_operation_checkpoint_custody = Vec::new();
            let mut reconciliation_receipt_custody = Vec::new();
            let mut operational_purge_tombstones = Vec::new();
            if schema_version.is_some_and(|version| version >= 7) {
                for run in &scan_runs {
                    match database.get_migration_run_binding(&run.id) {
                        Ok(binding) => migration_run_bindings.push(binding),
                        Err(StorageError::NotFound(_)) => {}
                        Err(error) => return Err(error),
                    }
                }
                scan_evidence_custody = database.list_scan_evidence_custody_records()?;
                scan_jobs = database.list_scan_jobs(None)?;
                for job in &scan_jobs {
                    scan_job_transitions.extend(database.list_scan_job_transitions(&job.id)?);
                }
                target_connection_profiles =
                    database.list_target_connection_profiles_for_snapshot()?;
                scan_operation_checkpoint_custody =
                    database.list_scan_operation_checkpoint_custody_records()?;
                reconciliation_receipt_custody =
                    database.list_reconciliation_receipt_custody_records()?;
                operational_purge_tombstones = database.list_operational_purge_tombstones()?;
            }

            Ok(DatabaseSnapshot {
                schema_version,
                checklists,
                scan_runs,
                deliveries,
                delivery_receipts,
                migration_run_bindings,
                scan_evidence_custody,
                scan_jobs,
                scan_job_transitions,
                target_connection_profiles,
                scan_operation_checkpoint_custody,
                reconciliation_receipt_custody,
                operational_purge_tombstones,
                evidence_retention_days_raw: database
                    .get_config("scanner.evidence_retention_days")?,
                operational_retention_days_raw: database
                    .get_config("scanner.operational_retention_days")?,
                evaluation_history: database.list_evaluation_history()?,
                audit_events: database.list_audit_events()?,
                answer_registry: database.list_answer_file_registry()?,
                asset_inventory_raw: database.get_config("asset_inventory")?,
                stigman_config_raw: database.get_config("stigman_config")?,
            })
        })
        .map_err(anyhow::Error::from)
}

fn assemble_transition_snapshot(
    database: DatabaseSnapshot,
    answers: Vec<AnswerTemplateSnapshot>,
    mut warnings: Vec<String>,
    generated_at: String,
) -> TransitionSnapshot {
    let deliveries_by_run = deliveries_by_run(&database.deliveries);
    let run_hostname: HashMap<_, _> = database
        .scan_runs
        .iter()
        .map(|run| (run.id.as_str(), run.asset_hostname.as_str()))
        .collect();
    let mut run_analyses = Vec::new();
    let mut run_checklists = HashMap::new();
    for run in &database.scan_runs {
        let analysis = analyze_run(
            run,
            deliveries_by_run
                .get(run.id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default(),
            &database.delivery_receipts,
        );
        if let Some(checklist) = analysis.checklist.clone() {
            run_checklists.insert(run.id.clone(), checklist);
        }
        run_analyses.push(analysis);
    }

    let linked_runs = linked_runs_by_checklist(&database.scan_runs);
    let checklists: Vec<_> = database
        .checklists
        .iter()
        .map(|snapshot| checklist_inventory(snapshot, &linked_runs))
        .collect();
    let scanner_runs: Vec<_> = run_analyses
        .into_iter()
        .map(|analysis| analysis.inventory)
        .collect();

    let incomplete_audit_events: Vec<_> = database
        .audit_events
        .iter()
        .filter(|event| event.event_type == "evaluation.incomplete")
        .cloned()
        .collect();
    let destination_bindings = database
        .deliveries
        .iter()
        .map(|delivery| {
            let receipts = database
                .delivery_receipts
                .get(&delivery.id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            DestinationBinding {
                delivery_id: delivery.id.clone(),
                scan_run_id: delivery.scan_run_id.clone(),
                local_asset_hostname: run_hostname
                    .get(delivery.scan_run_id.as_str())
                    .map(|value| (*value).to_string()),
                destination_instance_id: delivery.destination_instance_id.clone(),
                collection_id: delivery.destination_collection_id.clone(),
                asset_id: delivery.destination_asset_id.clone(),
                stig_id: delivery.stig_id.clone(),
                stig_revision: delivery.stig_revision.clone(),
                delivery_state: delivery.state.to_string(),
                remote_receipt_present: delivery.remote_receipt_json.is_some(),
                delivered_receipt_verified: delivered_receipt_verified(delivery, receipts),
            }
        })
        .collect::<Vec<_>>();

    let (legacy_asset_inventory, asset_warning) =
        legacy_asset_inventory_summary(database.asset_inventory_raw.as_deref());
    if let Some(warning) = asset_warning {
        warnings.push(warning);
    }
    let (stig_manager_connection, config_warning) =
        sanitize_stigman_config(database.stigman_config_raw.as_deref());
    if let Some(warning) = config_warning {
        warnings.push(warning);
    }
    for checklist in &database.checklists {
        if let Some(error) = &checklist.parse_error {
            warnings.push(format!(
                "Checklist {} is preserved as raw JSON but cannot be parsed by this release: {error}",
                checklist.row.id
            ));
        }
    }

    let answer_inventory = answers
        .iter()
        .map(|answer| answer.inventory.clone())
        .collect::<Vec<_>>();
    let summary = inventory_summary(InventorySummaryInput {
        checklists: &checklists,
        scanner_runs: &scanner_runs,
        incomplete_audit_events: incomplete_audit_events.len(),
        evaluation_history_rows: database.evaluation_history.len(),
        audit_events: database.audit_events.len(),
        answer_templates: answer_inventory.len(),
        legacy_answer_registry_rows: database.answer_registry.len(),
        destination_bindings: &destination_bindings,
        retained_run_bindings: database.migration_run_bindings.len(),
    });
    let report = MigrationInventoryReport {
        schema: INVENTORY_SCHEMA,
        generated_at,
        read_only: true,
        database_schema_version: database.schema_version,
        attribution_policy: "Finding sources are preserved exactly; manual, imported, and answer-file-derived results are never represented as automated scanner results.",
        summary,
        checklists,
        scanner_runs,
        incomplete_audit_events,
        answer_templates: answer_inventory,
        legacy_answer_registry: database.answer_registry.clone(),
        legacy_asset_inventory,
        stig_manager_connection,
        destination_bindings,
        retained_run_bindings: database.migration_run_bindings.clone(),
        warnings,
    };

    TransitionSnapshot {
        database,
        answers,
        report,
        run_checklists,
    }
}

fn checklist_inventory(
    snapshot: &LegacyChecklistSnapshot,
    linked_runs: &HashMap<String, Vec<String>>,
) -> ChecklistInventory {
    match &snapshot.parsed {
        Some(checklist) => {
            let counts = FindingSourceCounts::from_checklist(checklist);
            let block_reason = checklist.external_export_block_reason();
            ChecklistInventory {
                id: snapshot.row.id.clone(),
                asset_hostname: snapshot.row.asset_hostname.clone(),
                stig_id: snapshot.row.stig_id.clone(),
                stig_revision: snapshot.row.stig_version.clone(),
                created_at: snapshot.row.created_at.clone(),
                modified_at: snapshot.row.modified_at.clone(),
                classifications: classify_checklist(checklist, &counts, block_reason.as_deref()),
                finding_sources: Some(counts),
                evaluation_origin: checklist
                    .evaluation_provenance
                    .as_ref()
                    .map(|value| value.origin),
                collection_complete: checklist
                    .evaluation_provenance
                    .as_ref()
                    .map(|value| value.collection_complete),
                unsafe_legacy_evidence: checklist
                    .evaluation_provenance
                    .as_ref()
                    .map(|value| value.unsafe_legacy_evidence),
                external_interop_export_allowed: block_reason.is_none(),
                external_interop_export_block_reason: block_reason,
                linked_scanner_run_ids: linked_runs
                    .get(&snapshot.row.id)
                    .cloned()
                    .unwrap_or_default(),
                parse_error: None,
            }
        }
        None => ChecklistInventory {
            id: snapshot.row.id.clone(),
            asset_hostname: snapshot.row.asset_hostname.clone(),
            stig_id: snapshot.row.stig_id.clone(),
            stig_revision: snapshot.row.stig_version.clone(),
            created_at: snapshot.row.created_at.clone(),
            modified_at: snapshot.row.modified_at.clone(),
            classifications: vec![RecordClassification::IncompleteAuditOnly],
            finding_sources: None,
            evaluation_origin: None,
            collection_complete: None,
            unsafe_legacy_evidence: None,
            external_interop_export_allowed: false,
            external_interop_export_block_reason: Some(
                "retained JSON cannot be parsed by this release".to_string(),
            ),
            linked_scanner_run_ids: linked_runs
                .get(&snapshot.row.id)
                .cloned()
                .unwrap_or_default(),
            parse_error: snapshot.parse_error.clone(),
        },
    }
}

fn classify_checklist(
    checklist: &Checklist,
    counts: &FindingSourceCounts,
    block_reason: Option<&str>,
) -> Vec<RecordClassification> {
    let mut classifications = Vec::new();
    let imported = checklist
        .evaluation_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.origin == EvaluationOrigin::ImportedChecklist)
        || counts.imported > 0;
    let answer_file = counts.answer_file > 0
        || checklist
            .evaluation_provenance
            .as_ref()
            .is_some_and(|value| value.answer_file.is_some() || !value.answer_files.is_empty());
    let manual = counts.manual_reviewed > 0;
    let scanner_owned = counts.automated > 0 || counts.evidence > 0;
    let incomplete = counts.collection_error > 0
        || checklist
            .evaluation_provenance
            .as_ref()
            .is_some_and(|value| {
                !value.collection_complete
                    || !value.collection_errors.is_empty()
                    || value.unsafe_legacy_evidence
            })
        || (scanner_owned && block_reason.is_some());

    if scanner_owned && !imported && !incomplete && block_reason.is_none() {
        classifications.push(RecordClassification::CompletedScannerOutput);
    }
    if incomplete {
        classifications.push(RecordClassification::IncompleteAuditOnly);
    }
    if imported {
        classifications.push(RecordClassification::ImportedUnverified);
    }
    if manual {
        classifications.push(RecordClassification::ManuallyEdited);
    }
    if answer_file {
        classifications.push(RecordClassification::AnswerFileDerived);
    }
    if classifications.is_empty() {
        // An untouched manual checklist shell is not a completed assessment.
        classifications.push(RecordClassification::IncompleteAuditOnly);
    }
    classifications
}

fn analyze_run(
    run: &ScanRunRecord,
    deliveries: &[&DeliveryRecord],
    receipts: &BTreeMap<String, Vec<DeliveryReceipt>>,
) -> RunAnalysis {
    let mut errors = Vec::new();
    let request_digest_valid = sha256_hex(run.request_json.as_bytes()) == run.request_sha256;
    let result_digest_valid = sha256_hex(run.result_json.as_bytes()) == run.result_sha256;
    if !request_digest_valid {
        errors.push("stored request JSON SHA-256 does not match".to_string());
    }
    if !result_digest_valid {
        errors.push("stored result JSON SHA-256 does not match".to_string());
    }
    if serde_json::from_str::<Value>(&run.request_json).is_err() {
        errors.push("stored request is not valid JSON".to_string());
    }

    let artifact = match serde_json::from_str::<Value>(&run.result_json) {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(format!("stored result is not valid JSON: {error}"));
            None
        }
    };
    let collection_complete = artifact
        .as_ref()
        .and_then(|value| value.get("collection_complete"))
        .and_then(Value::as_bool);
    let checklist = artifact
        .as_ref()
        .and_then(|value| value.get("checklist"))
        .and_then(
            |value| match serde_json::from_value::<Checklist>(value.clone()) {
                Ok(checklist) => Some(checklist),
                Err(error) => {
                    errors.push(format!(
                        "stored scanner checklist cannot be parsed: {error}"
                    ));
                    None
                }
            },
        );

    let mut evidence_bindings_verified = false;
    if let (Some(artifact), Some(checklist)) = (&artifact, &checklist) {
        let provenance = checklist.evaluation_provenance.as_ref();
        let checklist_id_matches = run
            .checklist_id
            .as_deref()
            .is_none_or(|expected| expected == checklist.id.to_string());
        evidence_bindings_verified = artifact_evidence_bindings_match(artifact, run)
            && provenance.and_then(|value| value.evidence_sha256.as_deref())
                == Some(run.evidence_sha256.as_str())
            && provenance.and_then(|value| value.benchmark_sha256.as_deref())
                == Some(run.benchmark_sha256.as_str())
            && provenance.and_then(|value| value.check_pack_sha256.as_deref())
                == Some(run.check_pack_sha256.as_str())
            && provenance.and_then(|value| value.evaluation_plan_sha256.as_deref())
                == Some(run.evaluation_plan_sha256.as_str())
            && checklist_id_matches;
        if !evidence_bindings_verified {
            errors.push(
                "stored scanner checklist/evidence bindings do not match the immutable run record"
                    .to_string(),
            );
        }
    } else {
        errors.push("stored result has no usable scanner checklist/evidence pair".to_string());
    }

    let block_reason = checklist
        .as_ref()
        .and_then(Checklist::external_export_block_reason);
    if let Some(reason) = &block_reason {
        errors.push(format!(
            "external interoperability export blocked: {reason}"
        ));
    }
    if collection_complete != Some(true) {
        errors
            .push("scanner collection is incomplete or missing its completion marker".to_string());
    }
    let stored_json_digests_verified = request_digest_valid && result_digest_valid;
    let complete = stored_json_digests_verified
        && evidence_bindings_verified
        && collection_complete == Some(true)
        && block_reason.is_none();
    let remote_receipt_verified = deliveries.iter().any(|delivery| {
        delivered_receipt_verified(
            delivery,
            receipts
                .get(&delivery.id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
        )
    });

    RunAnalysis {
        inventory: ScannerRunInventory {
            id: run.id.clone(),
            asset_hostname: run.asset_hostname.clone(),
            stig_id: run.stig_id.clone(),
            stig_revision: run.stig_revision.clone(),
            scan_source: run.scan_source.clone(),
            completed_at: run.completed_at.clone(),
            classifications: vec![if complete {
                RecordClassification::CompletedScannerOutput
            } else {
                RecordClassification::IncompleteAuditOnly
            }],
            finding_sources: checklist.as_ref().map(FindingSourceCounts::from_checklist),
            collection_complete,
            stored_json_digests_verified,
            scanner_evidence_bindings_verified: evidence_bindings_verified,
            external_interop_export_allowed: complete,
            verification_errors: errors,
            delivery_states: deliveries
                .iter()
                .map(|delivery| delivery.state.to_string())
                .collect(),
            remote_receipt_verified,
            // The report is advisory only. No cleanup is implemented here.
            retention_cleanup_eligible: complete && remote_receipt_verified,
        },
        checklist,
    }
}

/// Validate the evidence binding retained inside a stored scanner result.
///
/// `scanner-run.v2` deliberately replaced its embedded plaintext evidence
/// envelope with a sealed-evidence reference. Migration must understand both
/// layouts so older snapshots remain preservable, while never treating a v2
/// result containing the retired envelope (or an unknown future schema) as a
/// completed scanner output.
fn artifact_evidence_bindings_match(artifact: &Value, run: &ScanRunRecord) -> bool {
    let sealed_evidence = artifact
        .pointer("/evidence/evidence_sha256")
        .and_then(Value::as_str);
    let has_sealed_reference = artifact.get("evidence").is_some();
    let legacy_evidence = artifact
        .pointer("/evidence_envelope/evidence_sha256")
        .and_then(Value::as_str);
    let legacy_check_pack = artifact
        .pointer("/evidence_envelope/check_pack_sha256")
        .and_then(Value::as_str);
    let has_legacy_envelope = artifact.get("evidence_envelope").is_some();

    if matches!(
        artifact.get("schema").and_then(Value::as_str),
        Some(SCANNER_RUN_SCHEMA_V2 | SCANNER_RUN_SCHEMA_V3)
    ) {
        return has_sealed_reference
            && !has_legacy_envelope
            && sealed_evidence == Some(run.evidence_sha256.as_str());
    }

    // Early scanner records either carried the v1 marker or predated the
    // marker. Their embedded envelope bound both evidence and check-pack.
    let legacy_schema = match artifact.get("schema") {
        None => true,
        Some(Value::String(schema)) => schema == LEGACY_SCANNER_RUN_SCHEMA,
        Some(_) => false,
    };
    legacy_schema
        && !has_sealed_reference
        && has_legacy_envelope
        && legacy_evidence == Some(run.evidence_sha256.as_str())
        && legacy_check_pack == Some(run.check_pack_sha256.as_str())
}

fn delivered_receipt_verified(delivery: &DeliveryRecord, receipts: &[DeliveryReceipt]) -> bool {
    delivery.state == DeliveryState::Delivered
        && delivery.remote_receipt_json.is_some()
        && receipts.iter().any(|receipt| {
            receipt.outcome == DeliveryState::Delivered && receipt.remote_receipt_json.is_some()
        })
}

fn deliveries_by_run(deliveries: &[DeliveryRecord]) -> HashMap<&str, Vec<&DeliveryRecord>> {
    let mut result: HashMap<&str, Vec<&DeliveryRecord>> = HashMap::new();
    for delivery in deliveries {
        result
            .entry(delivery.scan_run_id.as_str())
            .or_default()
            .push(delivery);
    }
    result
}

fn linked_runs_by_checklist(scan_runs: &[ScanRunRecord]) -> HashMap<String, Vec<String>> {
    let mut result: HashMap<String, Vec<String>> = HashMap::new();
    for run in scan_runs {
        if let Some(checklist_id) = &run.checklist_id {
            result
                .entry(checklist_id.clone())
                .or_default()
                .push(run.id.clone());
        }
    }
    result
}

fn inventory_summary(input: InventorySummaryInput<'_>) -> InventorySummary {
    let mut summary = InventorySummary {
        local_checklists: input.checklists.len(),
        immutable_scanner_runs: input.scanner_runs.len(),
        incomplete_audit_events: input.incomplete_audit_events,
        evaluation_history_rows: input.evaluation_history_rows,
        audit_events: input.audit_events,
        answer_templates: input.answer_templates,
        legacy_answer_registry_rows: input.legacy_answer_registry_rows,
        destination_bindings: input.destination_bindings.len(),
        retained_run_bindings: input.retained_run_bindings,
        deliveries_with_verified_receipts: input
            .destination_bindings
            .iter()
            .filter(|binding| binding.delivered_receipt_verified)
            .count(),
        ..InventorySummary::default()
    };
    for classification in input
        .checklists
        .iter()
        .flat_map(|record| record.classifications.iter())
        .chain(
            input
                .scanner_runs
                .iter()
                .flat_map(|record| record.classifications.iter()),
        )
    {
        match classification {
            RecordClassification::CompletedScannerOutput => {
                summary.completed_scanner_output_records += 1
            }
            RecordClassification::IncompleteAuditOnly => summary.incomplete_audit_only_records += 1,
            RecordClassification::ImportedUnverified => summary.imported_unverified_records += 1,
            RecordClassification::ManuallyEdited => summary.manually_edited_records += 1,
            RecordClassification::AnswerFileDerived => summary.answer_file_derived_records += 1,
        }
    }
    summary.incomplete_audit_only_records += input.incomplete_audit_events;
    summary.answer_file_derived_records += input.answer_templates;
    summary
}

fn snapshot_answer_templates(
    library_root: &Path,
) -> Result<(Vec<AnswerTemplateSnapshot>, Vec<String>)> {
    let mut warnings = Vec::new();
    let root_metadata = match fs::symlink_metadata(library_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            warnings.push(format!(
                "STIG library {} does not exist; no answer templates were inventoried",
                library_root.display()
            ));
            return Ok((Vec::new(), warnings));
        }
        Err(error) => return Err(error.into()),
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        anyhow::bail!(
            "STIG library must be a real directory for read-only migration: {}",
            library_root.display()
        );
    }
    #[cfg(windows)]
    let _library_custody = automatestig_core::path_safety::validate_sensitive_directory(
        library_root,
        "migration library root",
    )
    .map_err(anyhow::Error::from)?;
    let answer_directory = library_root.join("answer_templates");
    let metadata = match fs::symlink_metadata(&answer_directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), warnings))
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "answer-template path must be a real directory: {}",
            answer_directory.display()
        );
    }
    #[cfg(windows)]
    let _answer_directory_custody = automatestig_core::path_safety::validate_sensitive_directory(
        &answer_directory,
        "migration answer-template directory",
    )
    .map_err(anyhow::Error::from)?;

    let mut paths = fs::read_dir(&answer_directory)?.collect::<std::io::Result<Vec<_>>>()?;
    paths.sort_by_key(|entry| entry.file_name());
    let mut snapshots = Vec::new();
    for (index, entry) in paths.into_iter().enumerate() {
        let path = entry.path();
        let entry_type = entry.file_type()?;
        if entry_type.is_symlink() {
            warnings.push(format!(
                "Skipped symlinked answer-template entry without following it: {}",
                path.display()
            ));
            continue;
        }
        if !entry_type.is_file() {
            warnings.push(format!(
                "Skipped non-file answer-template entry: {}",
                path.display()
            ));
            continue;
        }

        let filename_os = entry.file_name();
        let filename_is_utf8 = filename_os.to_str().is_some();
        let filename = filename_os.to_string_lossy().into_owned();
        let bytes = read_regular_file_no_follow(&path, MAX_ANSWER_TEMPLATE_BYTES)?;
        let sha256 = sha256_hex(&bytes);
        let export_member = format!(
            "answer-files/{}",
            artifact_component_with_extension(&filename, &sha256, index)
        );
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let (valid_answer_file, stig_id, entry_count, validation_errors) =
            match automatestig_core::answer::AnswerFile::from_bytes(&bytes, extension) {
                Ok(answer) => {
                    let issues = answer.validate();
                    (
                        issues.is_empty(),
                        answer.stig_id,
                        Some(answer.entries.len()),
                        issues,
                    )
                }
                Err(error) => (false, None, None, vec![error.to_string()]),
            };
        snapshots.push(AnswerTemplateSnapshot {
            inventory: AnswerTemplateInventory {
                filename,
                filename_is_utf8,
                export_member,
                sha256,
                size_bytes: bytes.len(),
                valid_answer_file,
                stig_id,
                entry_count,
                validation_errors,
                classification: RecordClassification::AnswerFileDerived,
            },
            bytes,
        });
    }
    Ok((snapshots, warnings))
}

fn read_regular_file_no_follow(path: &Path, limit: u64) -> Result<Vec<u8>> {
    #[cfg(windows)]
    let policy = automatestig_core::path_safety::SensitiveFilePolicy::IntegrityProtected;
    #[cfg(not(windows))]
    let policy = automatestig_core::path_safety::SensitiveFilePolicy::UntrustedInput;
    let file = automatestig_core::path_safety::open_sensitive_file(
        path,
        "migration answer template",
        policy,
    )
    .map_err(anyhow::Error::from)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        anyhow::bail!(
            "transition source is not a regular file: {}",
            path.display()
        );
    }
    if metadata.len() > limit {
        anyhow::bail!(
            "transition source exceeds the {} byte limit: {}",
            limit,
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        anyhow::bail!(
            "transition source grew beyond the {} byte limit while reading: {}",
            limit,
            path.display()
        );
    }
    Ok(bytes)
}

fn legacy_asset_inventory_summary(
    raw: Option<&str>,
) -> (LegacyAssetInventorySummary, Option<String>) {
    let Some(raw) = raw else {
        return (
            LegacyAssetInventorySummary {
                present: false,
                valid_json: true,
                record_count: Some(0),
                sha256: None,
            },
            None,
        );
    };
    match serde_json::from_str::<Value>(raw) {
        Ok(value) => (
            LegacyAssetInventorySummary {
                present: true,
                valid_json: true,
                record_count: value.as_array().map(Vec::len),
                sha256: Some(sha256_hex(raw.as_bytes())),
            },
            None,
        ),
        Err(error) => (
            LegacyAssetInventorySummary {
                present: true,
                valid_json: false,
                record_count: None,
                sha256: Some(sha256_hex(raw.as_bytes())),
            },
            Some(format!(
                "Legacy asset inventory is preserved as raw text because its JSON is invalid: {error}"
            )),
        ),
    }
}

fn sanitize_stigman_config(raw: Option<&str>) -> (Option<Value>, Option<String>) {
    let Some(raw) = raw else {
        return (None, None);
    };
    let value = match serde_json::from_str::<Value>(raw) {
        Ok(value) => value,
        Err(error) => {
            return (
                None,
                Some(format!(
                    "Saved STIG Manager configuration is invalid JSON and was omitted rather than risking secret disclosure: {error}"
                )),
            )
        }
    };
    let Some(object) = value.as_object() else {
        return (
            None,
            Some(
                "Saved STIG Manager configuration is not an object and was omitted rather than risking secret disclosure"
                    .to_string(),
            ),
        );
    };
    let has_secret = object
        .get("client_secret")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    (
        Some(json!({
            "api_url": object.get("api_url").cloned().unwrap_or(Value::Null),
            "token_url": object.get("token_url").cloned().unwrap_or(Value::Null),
            "gui_url": object.get("gui_url").cloned().unwrap_or(Value::Null),
            "client_id": object.get("client_id").cloned().unwrap_or(Value::Null),
            "default_collection_id": object.get("default_collection_id").cloned().unwrap_or(Value::Null),
            "verify_tls": object.get("verify_tls").cloned().unwrap_or(Value::Null),
            "has_secret": has_secret,
            "client_secret_exported": false,
        })),
        None,
    )
}

fn build_bundle(snapshot: &TransitionSnapshot) -> Result<Vec<u8>> {
    let mut entries = BTreeMap::<String, Vec<u8>>::new();
    add_member(
        &mut entries,
        "inventory-report.json",
        serde_json::to_vec_pretty(&snapshot.report)?,
    )?;
    add_member(
        &mut entries,
        "README.txt",
        b"AutomateSTIG scanner-first transition export\n\nThis archive is read-only output and contains sensitive target evidence. Store it as assessment material. Canonical checklist JSON and attribution sidecars are authoritative for finding source. CKL/CKLB formats do not encode AutomateSTIG finding-source provenance; Manual, Imported, and AnswerFile findings must never be reclassified as automated. Saved STIG Manager client secrets and ephemeral target credentials are intentionally excluded. Replay evidence and operation checkpoints are preserved only as ciphertext with wrapped data-encryption keys; restoration requires the matching external key-provider/master-key custody. This command performs no STIG Manager mutation and no local retention cleanup.\n".to_vec(),
    )?;

    add_member(
        &mut entries,
        "history/evaluation-history.json",
        serde_json::to_vec_pretty(&snapshot.database.evaluation_history)?,
    )?;
    add_member(
        &mut entries,
        "history/audit-log.json",
        serde_json::to_vec_pretty(&snapshot.database.audit_events)?,
    )?;
    add_member(
        &mut entries,
        "answer-files/legacy-registry.json",
        serde_json::to_vec_pretty(&snapshot.database.answer_registry)?,
    )?;
    add_member(
        &mut entries,
        "scanner/jobs.json",
        serde_json::to_vec_pretty(&snapshot.database.scan_jobs)?,
    )?;
    add_member(
        &mut entries,
        "scanner/job-transitions.json",
        serde_json::to_vec_pretty(&snapshot.database.scan_job_transitions)?,
    )?;
    add_member(
        &mut entries,
        "scanner/target-connection-profiles.json",
        serde_json::to_vec_pretty(&snapshot.database.target_connection_profiles)?,
    )?;
    add_member(
        &mut entries,
        "scanner/operational-purge-tombstones.json",
        serde_json::to_vec_pretty(&snapshot.database.operational_purge_tombstones)?,
    )?;
    add_member(
        &mut entries,
        "scanner/retention-config.json",
        serde_json::to_vec_pretty(&json!({
            "schema": RETENTION_CONFIG_SCHEMA,
            "scanner.evidence_retention_days": snapshot.database.evidence_retention_days_raw,
            "scanner.operational_retention_days": snapshot.database.operational_retention_days_raw,
        }))?,
    )?;
    add_scanner_custody_members(&mut entries, &snapshot.database)?;
    for answer in &snapshot.answers {
        add_member(
            &mut entries,
            &answer.inventory.export_member,
            answer.bytes.clone(),
        )?;
    }

    if let Some(raw) = &snapshot.database.asset_inventory_raw {
        let member = if serde_json::from_str::<Value>(raw).is_ok() {
            "legacy/asset-inventory.json"
        } else {
            "legacy/asset-inventory.invalid.txt"
        };
        add_member(&mut entries, member, raw.as_bytes().to_vec())?;
    }
    if let Some(config) = &snapshot.report.stig_manager_connection {
        add_member(
            &mut entries,
            "stig-manager/connection-without-secret.json",
            serde_json::to_vec_pretty(config)?,
        )?;
    }
    add_member(
        &mut entries,
        "stig-manager/destination-bindings.json",
        serde_json::to_vec_pretty(&snapshot.report.destination_bindings)?,
    )?;
    add_member(
        &mut entries,
        "stig-manager/retained-run-bindings.json",
        serde_json::to_vec_pretty(&snapshot.report.retained_run_bindings)?,
    )?;
    add_member(
        &mut entries,
        "stig-manager/delivery-records.json",
        serde_json::to_vec_pretty(&snapshot.database.deliveries)?,
    )?;
    add_member(
        &mut entries,
        "stig-manager/delivery-receipts.json",
        serde_json::to_vec_pretty(&snapshot.database.delivery_receipts)?,
    )?;

    let mut export_warnings = Vec::new();
    for (stored, inventory) in snapshot
        .database
        .checklists
        .iter()
        .zip(snapshot.report.checklists.iter())
    {
        let id = artifact_component(&stored.row.id);
        add_member(
            &mut entries,
            &format!("legacy/checklists/{id}/checklist.json"),
            stored.raw_json.as_bytes().to_vec(),
        )?;
        if let Some(checklist) = &stored.parsed {
            add_interop_checklist(
                &mut entries,
                &format!("legacy/checklists/{id}"),
                checklist,
                &inventory.id,
                &inventory.classifications,
                &inventory.finding_sources,
                inventory.external_interop_export_allowed,
                &mut export_warnings,
            )?;
        }
    }

    for (run, inventory) in snapshot
        .database
        .scan_runs
        .iter()
        .zip(snapshot.report.scanner_runs.iter())
    {
        let id = artifact_component(&run.id);
        let prefix = if inventory.external_interop_export_allowed {
            format!("verified-scanner-evidence/{id}")
        } else {
            format!("audit-only/scanner-runs/{id}")
        };
        add_member(
            &mut entries,
            &format!("{prefix}/record.json"),
            serde_json::to_vec_pretty(run)?,
        )?;
        add_member(
            &mut entries,
            &format!("{prefix}/request.json"),
            run.request_json.as_bytes().to_vec(),
        )?;
        add_member(
            &mut entries,
            &format!("{prefix}/result.json"),
            run.result_json.as_bytes().to_vec(),
        )?;
        if let Some(checklist) = snapshot.run_checklists.get(&run.id) {
            add_interop_checklist(
                &mut entries,
                &prefix,
                checklist,
                &checklist.id.to_string(),
                &inventory.classifications,
                &inventory.finding_sources,
                inventory.external_interop_export_allowed,
                &mut export_warnings,
            )?;
        }
    }
    add_member(
        &mut entries,
        "export-warnings.json",
        serde_json::to_vec_pretty(&export_warnings)?,
    )?;

    let member_manifest = entries
        .iter()
        .map(|(path, bytes)| BundleMember {
            path: path.clone(),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len(),
        })
        .collect();
    let manifest = BundleManifest {
        schema: BUNDLE_SCHEMA,
        generated_at: &snapshot.report.generated_at,
        read_only_export: true,
        sensitive_data: true,
        attribution_policy: snapshot.report.attribution_policy,
        retention_cleanup_performed: false,
        summary: &snapshot.report.summary,
        members: member_manifest,
    };
    add_member(
        &mut entries,
        "manifest.json",
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let checksums = entries
        .iter()
        .map(|(path, bytes)| format!("{}  {path}\n", sha256_hex(bytes)))
        .collect::<String>();
    add_member(&mut entries, "checksums.sha256", checksums.into_bytes())?;

    let total = entries.values().try_fold(0usize, |total, bytes| {
        total
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("migration bundle size overflow"))
    })?;
    if total > MAX_BUNDLE_UNCOMPRESSED_BYTES {
        anyhow::bail!(
            "migration bundle contains {total} uncompressed bytes, exceeding the {MAX_BUNDLE_UNCOMPRESSED_BYTES} byte safety limit"
        );
    }

    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o600);
    for (path, bytes) in entries {
        archive.start_file(path, options)?;
        archive.write_all(&bytes)?;
    }
    Ok(archive.finish()?.into_inner())
}

fn add_scanner_custody_members(
    entries: &mut BTreeMap<String, Vec<u8>>,
    database: &DatabaseSnapshot,
) -> Result<()> {
    for evidence in &database.scan_evidence_custody {
        let object_id = evidence.metadata.run_id.clone();
        let prefix = format!("scanner/replay-evidence/{}", artifact_component(&object_id));
        let metadata_member = format!("{prefix}/metadata.json");
        add_member(
            entries,
            &metadata_member,
            serde_json::to_vec_pretty(&evidence.metadata)?,
        )?;

        let retained = evidence.metadata.state == ScanEvidenceState::Retained;
        let has_complete_bytes = evidence.ciphertext.is_some() && evidence.wrapped_dek.is_some();
        if retained != has_complete_bytes
            || evidence.ciphertext.is_some() != evidence.wrapped_dek.is_some()
        {
            anyhow::bail!(
                "replay evidence custody row {} has an invalid lifecycle/blob shape",
                object_id
            );
        }

        let mut descriptor = EncryptedCustodyDescriptor {
            schema: ENCRYPTED_CUSTODY_SCHEMA,
            object_kind: "scan_replay_evidence",
            object_id,
            metadata_member,
            ciphertext_member: None,
            ciphertext_sha256: None,
            ciphertext_size_bytes: None,
            wrapped_dek_member: None,
            wrapped_dek_sha256: None,
            wrapped_dek_size_bytes: None,
            stored_bindings_verified: !retained,
            plaintext_exported: false,
        };
        if let (Some(ciphertext), Some(wrapped_dek)) = (&evidence.ciphertext, &evidence.wrapped_dek)
        {
            let ciphertext_member = format!("{prefix}/ciphertext.bin");
            let wrapped_dek_member = format!("{prefix}/wrapped-dek.bin");
            let ciphertext_sha256 = sha256_hex(ciphertext);
            let wrapped_dek_sha256 = sha256_hex(wrapped_dek);
            descriptor.stored_bindings_verified = ciphertext_sha256
                == evidence.metadata.ciphertext_sha256
                && wrapped_dek_sha256 == evidence.metadata.wrapped_dek_sha256
                && ciphertext.len() as u64 == evidence.metadata.ciphertext_size;
            descriptor.ciphertext_member = Some(ciphertext_member.clone());
            descriptor.ciphertext_sha256 = Some(ciphertext_sha256);
            descriptor.ciphertext_size_bytes = Some(ciphertext.len());
            descriptor.wrapped_dek_member = Some(wrapped_dek_member.clone());
            descriptor.wrapped_dek_sha256 = Some(wrapped_dek_sha256);
            descriptor.wrapped_dek_size_bytes = Some(wrapped_dek.len());
            add_member(entries, &ciphertext_member, ciphertext.clone())?;
            add_member(entries, &wrapped_dek_member, wrapped_dek.clone())?;
        }
        if !descriptor.stored_bindings_verified {
            anyhow::bail!(
                "replay evidence custody row {} does not match its stored ciphertext/key digests and size",
                descriptor.object_id
            );
        }
        add_member(
            entries,
            &format!("{prefix}/custody.json"),
            serde_json::to_vec_pretty(&descriptor)?,
        )?;
    }

    for checkpoint in &database.scan_operation_checkpoint_custody {
        let object_id = checkpoint.metadata.job_id.clone();
        let prefix = format!(
            "scanner/operation-checkpoints/{}",
            artifact_component(&object_id)
        );
        let metadata_member = format!("{prefix}/metadata.json");
        let ciphertext_member = format!("{prefix}/ciphertext.bin");
        let wrapped_dek_member = format!("{prefix}/wrapped-dek.bin");
        let ciphertext_sha256 = sha256_hex(&checkpoint.ciphertext);
        let wrapped_dek_sha256 = sha256_hex(&checkpoint.wrapped_dek);
        let descriptor = EncryptedCustodyDescriptor {
            schema: ENCRYPTED_CUSTODY_SCHEMA,
            object_kind: "scan_operation_checkpoint",
            object_id,
            metadata_member: metadata_member.clone(),
            ciphertext_member: Some(ciphertext_member.clone()),
            ciphertext_sha256: Some(ciphertext_sha256.clone()),
            ciphertext_size_bytes: Some(checkpoint.ciphertext.len()),
            wrapped_dek_member: Some(wrapped_dek_member.clone()),
            wrapped_dek_sha256: Some(wrapped_dek_sha256.clone()),
            wrapped_dek_size_bytes: Some(checkpoint.wrapped_dek.len()),
            stored_bindings_verified: ciphertext_sha256 == checkpoint.metadata.ciphertext_sha256
                && wrapped_dek_sha256 == checkpoint.metadata.wrapped_dek_sha256,
            plaintext_exported: false,
        };
        if !descriptor.stored_bindings_verified {
            anyhow::bail!(
                "operation checkpoint custody row {} does not match its stored ciphertext/key digests",
                descriptor.object_id
            );
        }
        add_member(
            entries,
            &metadata_member,
            serde_json::to_vec_pretty(&checkpoint.metadata)?,
        )?;
        add_member(entries, &ciphertext_member, checkpoint.ciphertext.clone())?;
        add_member(entries, &wrapped_dek_member, checkpoint.wrapped_dek.clone())?;
        add_member(
            entries,
            &format!("{prefix}/custody.json"),
            serde_json::to_vec_pretty(&descriptor)?,
        )?;
    }

    for receipt in &database.reconciliation_receipt_custody {
        let receipt_id = receipt.record.id.clone();
        let prefix = format!(
            "scanner/reconciliation-receipts/{}",
            artifact_component(&receipt_id)
        );
        let record_member = format!("{prefix}/record.json");
        let receipt_member = format!("{prefix}/receipt.json");
        let archived_receipt_sha256 = sha256_hex(receipt.receipt_json.as_bytes());
        let (detached_signature_member, detached_signature_sha256, detached_signature_size_bytes) =
            if let Some(signature) = &receipt.detached_signature {
                let member = format!("{prefix}/detached-signature.bin");
                let digest = sha256_hex(signature);
                let size = signature.len();
                add_member(entries, &member, signature.clone())?;
                (Some(member), Some(digest), Some(size))
            } else {
                (None, None, None)
            };
        let descriptor = ReconciliationReceiptCustodyDescriptor {
            schema: RECEIPT_CUSTODY_SCHEMA,
            receipt_id,
            record_member: record_member.clone(),
            receipt_member: receipt_member.clone(),
            stored_receipt_sha256: receipt.record.receipt_sha256.clone(),
            archived_receipt_sha256: archived_receipt_sha256.clone(),
            stored_binding_verified: archived_receipt_sha256 == receipt.record.receipt_sha256,
            detached_signature_member,
            detached_signature_sha256,
            detached_signature_size_bytes,
        };
        if !descriptor.stored_binding_verified {
            anyhow::bail!(
                "reconciliation receipt custody row {} does not match its stored receipt digest",
                descriptor.receipt_id
            );
        }
        add_member(
            entries,
            &record_member,
            serde_json::to_vec_pretty(&receipt.record)?,
        )?;
        add_member(
            entries,
            &receipt_member,
            receipt.receipt_json.as_bytes().to_vec(),
        )?;
        add_member(
            entries,
            &format!("{prefix}/custody.json"),
            serde_json::to_vec_pretty(&descriptor)?,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_interop_checklist(
    entries: &mut BTreeMap<String, Vec<u8>>,
    prefix: &str,
    checklist: &Checklist,
    checklist_id: &str,
    classifications: &[RecordClassification],
    finding_sources: &Option<FindingSourceCounts>,
    export_allowed: bool,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let canonical_json = serde_json::to_vec_pretty(checklist)?;
    add_member(
        entries,
        &format!("{prefix}/checklist-attributed.json"),
        canonical_json,
    )?;
    let sidecar = AttributionSidecar {
        schema: "automatestig.checklist-attribution.v1",
        checklist_id,
        classifications,
        finding_sources,
        warning: "CKL and CKLB do not carry AutomateSTIG finding-source attribution. Use this sidecar and checklist-attributed.json; never relabel Manual, Imported, or AnswerFile results as automated.",
    };
    add_member(
        entries,
        &format!("{prefix}/attribution.json"),
        serde_json::to_vec_pretty(&sidecar)?,
    )?;
    if !export_allowed {
        return Ok(());
    }
    match automatestig_parsers::ckl::write_ckl(checklist) {
        Ok(ckl) => add_member(entries, &format!("{prefix}/checklist.ckl"), ckl.into_bytes())?,
        Err(error) => warnings.push(format!(
            "CKL export failed for checklist {checklist_id}; attributed JSON remains preserved: {error}"
        )),
    }
    match automatestig_parsers::cklb::write_cklb(checklist) {
        Ok(cklb) => add_member(
            entries,
            &format!("{prefix}/checklist.cklb"),
            cklb.into_bytes(),
        )?,
        Err(error) => warnings.push(format!(
            "CKLB export failed for checklist {checklist_id}; attributed JSON remains preserved: {error}"
        )),
    }
    Ok(())
}

fn add_member(entries: &mut BTreeMap<String, Vec<u8>>, path: &str, bytes: Vec<u8>) -> Result<()> {
    if path.starts_with('/')
        || path.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.contains('\\')
        })
    {
        anyhow::bail!("unsafe migration bundle member path {path:?}");
    }
    if entries.insert(path.to_string(), bytes).is_some() {
        anyhow::bail!("duplicate migration bundle member {path:?}");
    }
    Ok(())
}

fn artifact_component(value: &str) -> String {
    let mut result = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    result = result.trim_matches('.').to_string();
    if result.contains("..") {
        result = result.replace('.', "_");
    }
    if result.is_empty() {
        result = "record".to_string();
    }
    if result != value || result.len() > 96 {
        result.truncate(80);
        result.push('-');
        result.push_str(&sha256_hex(value.as_bytes())[..12]);
    }
    result
}

fn artifact_component_with_extension(filename: &str, digest: &str, index: usize) -> String {
    let component = artifact_component(filename);
    if component == filename {
        component
    } else {
        let extension = Path::new(filename)
            .extension()
            .and_then(|value| value.to_str())
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 8
                    && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
            });
        match extension {
            Some(extension) => format!("answer-{index:04}-{}.{}", &digest[..16], extension),
            None => format!("answer-{index:04}-{}", &digest[..16]),
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::check_packs::evaluation_plan_sha256;
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{ChecklistStigInfo, EvaluationProvenance};
    use automatestig_core::models::finding::Finding;
    use automatestig_core::models::stig::Severity;
    use std::io::Read;

    fn sample_checklist() -> Checklist {
        let mut checklist = Checklist::new(
            Asset::new("router-1"),
            ChecklistStigInfo {
                stig_id: "ROUTER_STIG".to_string(),
                title: "Router STIG".to_string(),
                version: "1".to_string(),
                release: "2".to_string(),
                release_date: None,
                uuid: None,
                description: None,
                filename: None,
            },
        );
        let mut manual =
            Finding::new_not_reviewed("V-1", "SV-1", "V-1", "Manual", Severity::Medium);
        manual.status = FindingStatus::Open;
        manual.source = FindingSource::Manual;
        manual.evaluated_by = "Reviewer".to_string();
        let mut imported =
            Finding::new_not_reviewed("V-2", "SV-2", "V-2", "Imported", Severity::Medium);
        imported.status = FindingStatus::NotAFinding;
        imported.source = FindingSource::Imported;
        let mut answer = Finding::new_not_reviewed("V-3", "SV-3", "V-3", "Answer", Severity::Low);
        answer.status = FindingStatus::NotApplicable;
        answer.source = FindingSource::AnswerFile;
        checklist.findings = vec![manual, imported, answer];
        checklist.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::ImportedChecklist,
            collection_complete: true,
            collection_errors: Vec::new(),
            evidence_sha256: None,
            claimed_hostname: None,
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
        checklist
    }

    fn repeated_sha256(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn current_native_run(id: &str, collection_complete: bool) -> ScanRunRecord {
        let evidence_sha256 = repeated_sha256('e');
        let benchmark_sha256 = repeated_sha256('b');
        let check_pack_sha256 = repeated_sha256('c');
        let evaluation_plan_sha256 = evaluation_plan_sha256(
            "ROUTER_STIG",
            "V1R2",
            &benchmark_sha256,
            &check_pack_sha256,
            None,
        )
        .unwrap();
        let collection_errors = if collection_complete {
            Vec::new()
        } else {
            vec!["configuration collection stopped before evaluation".to_string()]
        };
        let mut checklist = Checklist::new(
            Asset::new("router-1"),
            ChecklistStigInfo {
                stig_id: "ROUTER_STIG".to_string(),
                title: "Router STIG".to_string(),
                version: "1".to_string(),
                release: "2".to_string(),
                release_date: None,
                uuid: None,
                description: None,
                filename: None,
            },
        );
        let mut automated =
            Finding::new_not_reviewed("V-10", "SV-10", "V-10", "Automated", Severity::Medium);
        automated.status = if collection_complete {
            FindingStatus::NotAFinding
        } else {
            FindingStatus::NotReviewed
        };
        automated.source = if collection_complete {
            FindingSource::Automated
        } else {
            FindingSource::CollectionError
        };
        automated.finding_details = if collection_complete {
            "Observed compliant configuration evidence".to_string()
        } else {
            collection_errors[0].clone()
        };
        checklist.findings = vec![automated];
        checklist.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::ConfigFile,
            collection_complete,
            collection_errors: collection_errors.clone(),
            evidence_sha256: Some(evidence_sha256.clone()),
            claimed_hostname: Some("router-1".to_string()),
            collector_version: Some("test-scanner".to_string()),
            collected_at: Some("2026-08-08T00:00:00Z".to_string()),
            plan_sha256: Some(repeated_sha256('1')),
            server_key_fingerprint: None,
            benchmark_sha256: Some(benchmark_sha256.clone()),
            check_pack_sha256: Some(check_pack_sha256.clone()),
            evaluation_plan_sha256: Some(evaluation_plan_sha256.clone()),
            organization_policy: None,
            answer_file: None,
            answer_files: Vec::new(),
            unsafe_legacy_evidence: false,
        });
        let checklist_id = checklist.id.to_string();
        let request_json = serde_json::to_string(&json!({
            "schema": "automatestig.scanner-run-request.v1",
            "profile_id": "cisco_ios_xe_router_ndm",
            "credential_persisted": false,
        }))
        .unwrap();
        let device = DeviceFingerprint::new("router-1", "Cisco", "IOS-XE", "17.9");
        let device_fingerprint_sha256 = device.sha256().unwrap();
        let result_json = serde_json::to_string(&json!({
            "schema": SCANNER_RUN_SCHEMA_V2,
            "mode": "disconnected",
            "profile_id": "cisco_ios_xe_router_ndm",
            "collection_method": "configuration",
            "destination": null,
            "destination_asset_name": null,
            "endpoint": null,
            "device": device,
            "collection_complete": collection_complete,
            "collection_errors": collection_errors,
            "manual_untouched": 0,
            "out_of_scope_untouched": 0,
            "checklist": checklist,
            "reviews": [],
            "delivery_preview": {
                "counts": { "create": 0, "update": 0, "unchanged": 0, "conflict": 0 },
                "reviews": [],
                "manual_untouched": 0,
                "out_of_scope_untouched": 0
            },
            "evidence": {
                "envelope_schema": "automatestig.target-adapter-evidence.v1",
                "evidence_sha256": evidence_sha256,
                "envelope_json_sha256": repeated_sha256('d'),
                "profile_sha256": repeated_sha256('a'),
                "device_fingerprint_sha256": device_fingerprint_sha256,
                "collection_plan_sha256": repeated_sha256('1')
            }
        }))
        .unwrap();

        ScanRunRecord {
            id: id.to_string(),
            checklist_id: Some(checklist_id),
            asset_hostname: "router-1".to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_source: "configuration_file".to_string(),
            stig_id: "ROUTER_STIG".to_string(),
            stig_revision: "V1R2".to_string(),
            benchmark_sha256,
            check_pack_sha256,
            evaluation_plan_sha256,
            evidence_sha256,
            request_sha256: sha256_hex(request_json.as_bytes()),
            result_sha256: sha256_hex(result_json.as_bytes()),
            request_json,
            result_json,
            completed_at: "2026-08-08T00:00:01Z".to_string(),
            created_at: "2026-08-08T00:00:00Z".to_string(),
        }
    }

    fn transition_snapshot_for_runs(runs: Vec<ScanRunRecord>) -> TransitionSnapshot {
        assemble_transition_snapshot(
            DatabaseSnapshot {
                schema_version: Some(6),
                checklists: Vec::new(),
                scan_runs: runs,
                deliveries: Vec::new(),
                delivery_receipts: BTreeMap::new(),
                migration_run_bindings: Vec::new(),
                scan_evidence_custody: Vec::new(),
                scan_jobs: Vec::new(),
                scan_job_transitions: Vec::new(),
                target_connection_profiles: Vec::new(),
                scan_operation_checkpoint_custody: Vec::new(),
                reconciliation_receipt_custody: Vec::new(),
                operational_purge_tombstones: Vec::new(),
                evidence_retention_days_raw: None,
                operational_retention_days_raw: None,
                evaluation_history: Vec::new(),
                audit_events: Vec::new(),
                answer_registry: Vec::new(),
                asset_inventory_raw: None,
                stigman_config_raw: None,
            },
            Vec::new(),
            Vec::new(),
            "2026-08-08T00:00:02Z".to_string(),
        )
    }

    fn bundle_member_names(snapshot: &TransitionSnapshot) -> Vec<String> {
        let bundle = build_bundle(snapshot).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(bundle)).unwrap();
        (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect()
    }

    fn extract_bundle(snapshot: &TransitionSnapshot) -> BTreeMap<String, Vec<u8>> {
        let bundle = build_bundle(snapshot).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(bundle)).unwrap();
        let mut extracted = BTreeMap::new();
        for index in 0..archive.len() {
            let mut member = archive.by_index(index).unwrap();
            let name = member.name().to_string();
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes).unwrap();
            extracted.insert(name, bytes);
        }
        extracted
    }

    #[test]
    fn transition_bundle_preserves_every_scanner_custody_record_exactly() {
        let run = current_native_run("custody-run", true);
        let run_evidence_sha256 = run.evidence_sha256.clone();
        let evidence_ciphertext = b"encrypted replay evidence bytes".to_vec();
        let evidence_wrapped_dek = b"wrapped replay evidence data-encryption key".to_vec();
        let checkpoint_ciphertext = b"encrypted operation checkpoint bytes".to_vec();
        let checkpoint_wrapped_dek = b"wrapped checkpoint data-encryption key".to_vec();
        let receipt_json = serde_json::to_string(&json!({
            "schema": "automatestig.receiver-reconciliation.v1",
            "run_id": "custody-run",
            "proof": "exact receiver readback"
        }))
        .unwrap();
        let detached_signature = b"detached-receiver-signature".to_vec();
        let mut snapshot = transition_snapshot_for_runs(vec![run]);
        snapshot.database.schema_version = Some(7);
        snapshot.database.scan_evidence_custody = vec![
            ScanEvidenceCustodyRecord {
                metadata: automatestig_storage::ScanEvidenceArtifactMetadata {
                    run_id: "custody-run".to_string(),
                    state: ScanEvidenceState::Retained,
                    envelope_schema: "automatestig.target-adapter-evidence.v1".to_string(),
                    evidence_sha256: run_evidence_sha256.clone(),
                    plaintext_sha256: repeated_sha256('7'),
                    ciphertext_sha256: sha256_hex(&evidence_ciphertext),
                    ciphertext_size: evidence_ciphertext.len() as u64,
                    algorithm: "AES-256-GCM+HKDF-SHA256-v1".to_string(),
                    key_id: repeated_sha256('8'),
                    wrapped_dek_sha256: sha256_hex(&evidence_wrapped_dek),
                    sealed_at: "2026-08-08T00:00:00Z".to_string(),
                    expires_at: "2026-09-07T00:00:00Z".to_string(),
                    purged_at: None,
                    purge_reason: None,
                },
                ciphertext: Some(evidence_ciphertext.clone()),
                wrapped_dek: Some(evidence_wrapped_dek.clone()),
            },
            ScanEvidenceCustodyRecord {
                metadata: automatestig_storage::ScanEvidenceArtifactMetadata {
                    run_id: "purged-custody-run".to_string(),
                    state: ScanEvidenceState::Purged,
                    envelope_schema: "automatestig.target-adapter-evidence.v1".to_string(),
                    evidence_sha256: repeated_sha256('a'),
                    plaintext_sha256: repeated_sha256('b'),
                    ciphertext_sha256: repeated_sha256('c'),
                    ciphertext_size: 8192,
                    algorithm: "AES-256-GCM+HKDF-SHA256-v1".to_string(),
                    key_id: repeated_sha256('d'),
                    wrapped_dek_sha256: repeated_sha256('e'),
                    sealed_at: "2026-07-01T00:00:00Z".to_string(),
                    expires_at: "2026-07-31T00:00:00Z".to_string(),
                    purged_at: Some("2026-08-01T00:00:00Z".to_string()),
                    purge_reason: Some(
                        automatestig_storage::ScanEvidencePurgeReason::RetentionExpired,
                    ),
                },
                ciphertext: None,
                wrapped_dek: None,
            },
        ];
        snapshot.database.scan_jobs = vec![ScanJobRecord {
            id: "custody-job".to_string(),
            state: automatestig_storage::ScanJobState::Failed,
            sanitized_request_json: r#"{"host":"router-1","credential_supplied":true}"#.to_string(),
            request_sha256: repeated_sha256('9'),
            created_at: "2026-08-08T00:00:00Z".to_string(),
            updated_at: "2026-08-08T00:02:00Z".to_string(),
            started_at: Some("2026-08-08T00:01:00Z".to_string()),
            finished_at: Some("2026-08-08T00:02:00Z".to_string()),
            run_id: None,
            error: Some("connection interrupted; resubmit credentials".to_string()),
        }];
        snapshot.database.scan_job_transitions = vec![
            ScanJobTransitionRecord {
                id: 1,
                job_id: "custody-job".to_string(),
                state: automatestig_storage::ScanJobState::Queued,
                occurred_at: "2026-08-08T00:00:00Z".to_string(),
                run_id: None,
                error: None,
            },
            ScanJobTransitionRecord {
                id: 2,
                job_id: "custody-job".to_string(),
                state: automatestig_storage::ScanJobState::Failed,
                occurred_at: "2026-08-08T00:02:00Z".to_string(),
                run_id: None,
                error: Some("connection interrupted; resubmit credentials".to_string()),
            },
        ];
        snapshot.database.target_connection_profiles = vec![TargetConnectionProfileRecord {
            id: "custody-profile".to_string(),
            scanner_profile_id: "cisco_ios_xe_router_ndm".to_string(),
            adapter: "ssh_cli".to_string(),
            endpoint: "router-1.example.mil".to_string(),
            port: 22,
            credential_reference: Some("keychain:router-1".to_string()),
            last_observed_fingerprint: Some("device-fingerprint".to_string()),
            recent_operational_state: Some("interrupted".to_string()),
            observed_at: Some("2026-08-08T00:02:00Z".to_string()),
            created_at: "2026-08-08T00:00:00Z".to_string(),
            updated_at: "2026-08-08T00:02:00Z".to_string(),
        }];
        snapshot.database.scan_operation_checkpoint_custody =
            vec![ScanOperationCheckpointCustodyRecord {
                metadata: automatestig_storage::ScanOperationCheckpointMetadata {
                    job_id: "custody-job".to_string(),
                    profile_id: "custody-profile".to_string(),
                    plan_sha256: repeated_sha256('1'),
                    device_fingerprint_sha256: repeated_sha256('2'),
                    host_key_fingerprint: "SHA256:host-key".to_string(),
                    endpoint: "router-1.example.mil".to_string(),
                    port: 22,
                    completed_operation_ids: vec!["show-running-config".to_string()],
                    plaintext_sha256: repeated_sha256('3'),
                    ciphertext_sha256: sha256_hex(&checkpoint_ciphertext),
                    algorithm: "AES-256-GCM+HKDF-SHA256-v1".to_string(),
                    key_id: repeated_sha256('4'),
                    wrapped_dek_sha256: sha256_hex(&checkpoint_wrapped_dek),
                    created_at: "2026-08-08T00:01:00Z".to_string(),
                    updated_at: "2026-08-08T00:01:30Z".to_string(),
                    expires_at: "2026-09-07T00:01:30Z".to_string(),
                },
                ciphertext: checkpoint_ciphertext.clone(),
                wrapped_dek: checkpoint_wrapped_dek.clone(),
            }];
        snapshot.database.reconciliation_receipt_custody =
            vec![ReconciliationReceiptCustodyRecord {
                record: automatestig_storage::ReconciliationReceiptRecord {
                    id: "custody-receipt".to_string(),
                    schema: "automatestig.receiver-reconciliation.v1".to_string(),
                    run_id: "custody-run".to_string(),
                    payload_sha256: repeated_sha256('5'),
                    destination_kind: "stig_manager".to_string(),
                    destination_instance_id: "instance".to_string(),
                    destination_collection_id: "7".to_string(),
                    destination_asset_id: "42".to_string(),
                    destination_assignment_id: "ROUTER_STIG:V1R2".to_string(),
                    stig_id: "ROUTER_STIG".to_string(),
                    stig_revision: "V1R2".to_string(),
                    received_rule_ids: vec!["SV-10".to_string()],
                    received_rule_set_sha256: repeated_sha256('6'),
                    independent_readback_sha256: repeated_sha256('7'),
                    independent_readback_at: "2026-08-08T00:03:00Z".to_string(),
                    receipt_sha256: sha256_hex(receipt_json.as_bytes()),
                    remote_url: "https://stigman.example.mil/".to_string(),
                    producer_authentication: "trusted_detached_signature".to_string(),
                    signer_fingerprint: Some(repeated_sha256('8')),
                    operator_confirmed: false,
                    imported_at: "2026-08-08T00:04:00Z".to_string(),
                },
                receipt_json: receipt_json.clone(),
                detached_signature: Some(detached_signature.clone()),
            }];
        snapshot.database.operational_purge_tombstones = vec![OperationalPurgeTombstone {
            id: 1,
            run_id: "previous-run".to_string(),
            request_sha256: repeated_sha256('1'),
            result_sha256: repeated_sha256('2'),
            evidence_sha256: repeated_sha256('3'),
            payload_sha256: repeated_sha256('4'),
            destination_kind: "stig_manager".to_string(),
            destination_instance_id: "instance".to_string(),
            destination_collection_id: "7".to_string(),
            destination_asset_id: "41".to_string(),
            destination_assignment_id: "ROUTER_STIG:V1R2".to_string(),
            receipt_kind: "reconciliation_import".to_string(),
            receipt_id: "previous-receipt".to_string(),
            receipt_sha256: repeated_sha256('5'),
            receipt_json: r#"{"receipt":"preserved"}"#.to_string(),
            remote_url: "https://stigman.example.mil/".to_string(),
            purged_at: "2026-08-08T00:05:00Z".to_string(),
        }];
        snapshot.database.evidence_retention_days_raw = Some("45".to_string());
        snapshot.database.operational_retention_days_raw = Some("90".to_string());

        let extracted = extract_bundle(&snapshot);
        assert_eq!(
            extracted
                .get("scanner/replay-evidence/custody-run/ciphertext.bin")
                .unwrap(),
            &evidence_ciphertext
        );
        assert_eq!(
            extracted
                .get("scanner/replay-evidence/custody-run/wrapped-dek.bin")
                .unwrap(),
            &evidence_wrapped_dek
        );
        assert_eq!(
            extracted
                .get("scanner/operation-checkpoints/custody-job/ciphertext.bin")
                .unwrap(),
            &checkpoint_ciphertext
        );
        assert_eq!(
            extracted
                .get("scanner/operation-checkpoints/custody-job/wrapped-dek.bin")
                .unwrap(),
            &checkpoint_wrapped_dek
        );
        assert_eq!(
            extracted
                .get("scanner/reconciliation-receipts/custody-receipt/receipt.json")
                .unwrap(),
            receipt_json.as_bytes()
        );
        assert_eq!(
            extracted
                .get("scanner/reconciliation-receipts/custody-receipt/detached-signature.bin")
                .unwrap(),
            &detached_signature
        );
        for required in [
            "scanner/jobs.json",
            "scanner/job-transitions.json",
            "scanner/target-connection-profiles.json",
            "scanner/operational-purge-tombstones.json",
            "scanner/retention-config.json",
            "scanner/replay-evidence/custody-run/metadata.json",
            "scanner/replay-evidence/custody-run/custody.json",
            "scanner/replay-evidence/purged-custody-run/metadata.json",
            "scanner/replay-evidence/purged-custody-run/custody.json",
            "scanner/operation-checkpoints/custody-job/metadata.json",
            "scanner/operation-checkpoints/custody-job/custody.json",
            "scanner/reconciliation-receipts/custody-receipt/record.json",
            "scanner/reconciliation-receipts/custody-receipt/custody.json",
        ] {
            assert!(extracted.contains_key(required), "missing {required}");
        }
        assert!(
            !extracted.contains_key("scanner/replay-evidence/purged-custody-run/ciphertext.bin")
        );
        assert!(
            !extracted.contains_key("scanner/replay-evidence/purged-custody-run/wrapped-dek.bin")
        );

        let retention: Value =
            serde_json::from_slice(extracted.get("scanner/retention-config.json").unwrap())
                .unwrap();
        assert_eq!(retention["scanner.evidence_retention_days"], "45");
        assert_eq!(retention["scanner.operational_retention_days"], "90");

        let manifest: Value =
            serde_json::from_slice(extracted.get("manifest.json").unwrap()).unwrap();
        assert_eq!(manifest["schema"], BUNDLE_SCHEMA);
        let listed = manifest["members"].as_array().unwrap();
        assert_eq!(listed.len(), extracted.len() - 2);
        for member in listed {
            let path = member["path"].as_str().unwrap();
            let bytes = extracted.get(path).unwrap();
            assert_eq!(member["sha256"], sha256_hex(bytes));
            assert_eq!(member["size_bytes"], bytes.len());
        }
        assert!(!extracted.keys().any(|path| path.contains("plaintext")));
        assert!(extracted
            .values()
            .all(|bytes| !String::from_utf8_lossy(bytes).contains("PLAINTEXT-REPLAY-EVIDENCE")));
    }

    #[test]
    fn retained_run_binding_uses_collected_fingerprint_not_only_checklist_hostname() {
        let valid = current_native_run("binding-source", true);
        let identity = validate_retained_run_for_binding(&valid).unwrap();
        assert_eq!(identity.hostname, "router-1");
        assert_eq!(identity.device_fingerprint_sha256.len(), 64);

        let mut relabeled = valid.clone();
        let mut artifact: Value = serde_json::from_str(&relabeled.result_json).unwrap();
        let replacement = DeviceFingerprint::new("router-2", "Cisco", "IOS-XE", "17.9");
        artifact["device"] = serde_json::to_value(&replacement).unwrap();
        artifact["evidence"]["device_fingerprint_sha256"] =
            Value::String(replacement.sha256().unwrap());
        relabeled.result_json = serde_json::to_string(&artifact).unwrap();
        relabeled.result_sha256 = sha256_hex(relabeled.result_json.as_bytes());

        let error = validate_retained_run_for_binding(&relabeled).unwrap_err();
        assert!(error
            .to_string()
            .contains("asset, checklist, provenance, and collected device identities"));

        let incomplete = current_native_run("incomplete-binding-source", false);
        assert!(validate_retained_run_for_binding(&incomplete).is_err());

        let mut legacy = valid.clone();
        let mut artifact: Value = serde_json::from_str(&legacy.result_json).unwrap();
        artifact["schema"] = Value::String(LEGACY_SCANNER_RUN_SCHEMA.to_string());
        legacy.result_json = serde_json::to_string(&artifact).unwrap();
        legacy.result_sha256 = sha256_hex(legacy.result_json.as_bytes());
        assert!(validate_retained_run_for_binding(&legacy)
            .unwrap_err()
            .to_string()
            .contains("cannot be destination-bound"));

        let mut v3_without_traces = valid;
        let mut artifact: Value = serde_json::from_str(&v3_without_traces.result_json).unwrap();
        artifact["schema"] = Value::String(SCANNER_RUN_SCHEMA_V3.to_string());
        v3_without_traces.result_json = serde_json::to_string(&artifact).unwrap();
        v3_without_traces.result_sha256 = sha256_hex(v3_without_traces.result_json.as_bytes());
        assert!(validate_retained_run_for_binding(&v3_without_traces)
            .unwrap_err()
            .to_string()
            .contains("decision traces"));
    }

    #[test]
    fn remote_asset_match_is_exact_case_insensitive_dns_identity() {
        assert_eq!(
            exact_asset_identity_match(
                "Router-1.Example.MIL.",
                "inventory-display-name",
                Some("router-1.example.mil")
            )
            .unwrap(),
            "router-1.example.mil"
        );
        assert!(exact_asset_identity_match(
            "router-1.example.mil",
            "router-10.example.mil",
            Some("router-1.example.mil.attacker.invalid")
        )
        .is_err());
    }

    #[test]
    fn protected_binding_arguments_never_accept_secret_values_on_the_command_line() {
        let mut args = BindRunArgs {
            run_id: "run-1".to_string(),
            api_url: "https://stigman.example.mil/api".to_string(),
            token_url: "https://identity.example.mil/token".to_string(),
            client_id: "automatestig".to_string(),
            client_secret_env: "AUTOMATESTIG_STIGMAN_CLIENT_SECRET".to_string(),
            destination_allowlist: Vec::new(),
            collection_id: "7".to_string(),
            asset_id: "42".to_string(),
            operator_source: "change-ticket-123".to_string(),
            output: None,
        };
        validate_bind_run_args(&args).unwrap();
        args.client_secret_env = "secret=value".to_string();
        assert!(validate_bind_run_args(&args).is_err());
        args.client_secret_env = "AUTOMATESTIG_STIGMAN_CLIENT_SECRET".to_string();
        args.operator_source = "ticket\nBearer secret".to_string();
        assert!(validate_bind_run_args(&args).is_err());
        args.operator_source = "change-ticket password=hunter2".to_string();
        assert!(validate_bind_run_args(&args).is_err());
    }

    #[test]
    fn classifications_never_collapse_manual_imported_or_answer_sources_into_automated() {
        let checklist = sample_checklist();
        let counts = FindingSourceCounts::from_checklist(&checklist);
        assert_eq!(counts.manual, 1);
        assert_eq!(counts.manual_reviewed, 1);
        assert_eq!(counts.imported, 1);
        assert_eq!(counts.answer_file, 1);
        assert_eq!(counts.automated, 0);
        let classes = classify_checklist(
            &checklist,
            &counts,
            checklist.external_export_block_reason().as_deref(),
        );
        assert!(classes.contains(&RecordClassification::ImportedUnverified));
        assert!(classes.contains(&RecordClassification::ManuallyEdited));
        assert!(classes.contains(&RecordClassification::AnswerFileDerived));
        assert!(!classes.contains(&RecordClassification::CompletedScannerOutput));
    }

    #[test]
    fn completed_current_native_run_is_classified_and_exported_as_verified() {
        let snapshot =
            transition_snapshot_for_runs(vec![current_native_run("current-native-run", true)]);
        let inventory = &snapshot.report.scanner_runs[0];

        assert_eq!(
            inventory.classifications,
            vec![RecordClassification::CompletedScannerOutput]
        );
        assert!(inventory.stored_json_digests_verified);
        assert!(inventory.scanner_evidence_bindings_verified);
        assert!(inventory.external_interop_export_allowed);
        assert!(inventory.verification_errors.is_empty());

        let names = bundle_member_names(&snapshot);
        let prefix = "verified-scanner-evidence/current-native-run";
        assert!(names.contains(&format!("{prefix}/record.json")));
        assert!(names.contains(&format!("{prefix}/result.json")));
        assert!(names.contains(&format!("{prefix}/checklist-attributed.json")));
        assert!(names.contains(&format!("{prefix}/checklist.ckl")));
        assert!(names.contains(&format!("{prefix}/checklist.cklb")));
        assert!(!names
            .iter()
            .any(|name| name.starts_with("audit-only/scanner-runs/current-native-run/")));
    }

    #[test]
    fn incomplete_and_tampered_current_runs_remain_audit_only() {
        let incomplete = current_native_run("incomplete-native-run", false);
        let mut tampered = current_native_run("tampered-native-run", true);
        let mut tampered_artifact: Value = serde_json::from_str(&tampered.result_json).unwrap();
        tampered_artifact["evidence"]["evidence_sha256"] = Value::String(repeated_sha256('9'));
        // Recalculate the outer JSON digest so this exercises the semantic
        // evidence binding rather than only the stored-byte digest check.
        tampered.result_json = serde_json::to_string(&tampered_artifact).unwrap();
        tampered.result_sha256 = sha256_hex(tampered.result_json.as_bytes());

        let snapshot = transition_snapshot_for_runs(vec![incomplete, tampered]);
        let incomplete_inventory = &snapshot.report.scanner_runs[0];
        assert_eq!(
            incomplete_inventory.classifications,
            vec![RecordClassification::IncompleteAuditOnly]
        );
        assert!(incomplete_inventory.scanner_evidence_bindings_verified);
        assert!(!incomplete_inventory.external_interop_export_allowed);

        let tampered_inventory = &snapshot.report.scanner_runs[1];
        assert_eq!(
            tampered_inventory.classifications,
            vec![RecordClassification::IncompleteAuditOnly]
        );
        assert!(tampered_inventory.stored_json_digests_verified);
        assert!(!tampered_inventory.scanner_evidence_bindings_verified);
        assert!(!tampered_inventory.external_interop_export_allowed);

        let names = bundle_member_names(&snapshot);
        for id in ["incomplete-native-run", "tampered-native-run"] {
            let audit_prefix = format!("audit-only/scanner-runs/{id}");
            assert!(names.contains(&format!("{audit_prefix}/record.json")));
            assert!(names.contains(&format!("{audit_prefix}/result.json")));
            assert!(!names
                .iter()
                .any(|name| name.starts_with(&format!("verified-scanner-evidence/{id}/"))));
            assert!(!names
                .iter()
                .any(|name| name == &format!("{audit_prefix}/checklist.ckl")));
            assert!(!names
                .iter()
                .any(|name| name == &format!("{audit_prefix}/checklist.cklb")));
        }
    }

    #[test]
    fn legacy_embedded_envelope_binding_remains_compatible() {
        let mut run = current_native_run("legacy-native-run", true);
        let mut artifact: Value = serde_json::from_str(&run.result_json).unwrap();
        artifact["schema"] = Value::String(LEGACY_SCANNER_RUN_SCHEMA.to_string());
        artifact.as_object_mut().unwrap().remove("evidence");
        artifact.as_object_mut().unwrap().insert(
            "evidence_envelope".to_string(),
            json!({
                "evidence_sha256": run.evidence_sha256,
                "check_pack_sha256": run.check_pack_sha256,
            }),
        );
        run.result_json = serde_json::to_string(&artifact).unwrap();
        run.result_sha256 = sha256_hex(run.result_json.as_bytes());

        let analysis = analyze_run(&run, &[], &BTreeMap::new());
        assert_eq!(
            analysis.inventory.classifications,
            vec![RecordClassification::CompletedScannerOutput]
        );
        assert!(analysis.inventory.scanner_evidence_bindings_verified);
        assert!(analysis.inventory.external_interop_export_allowed);
    }

    #[test]
    fn bundle_preserves_attribution_and_excludes_stig_manager_secret() {
        let temporary = tempfile::tempdir().unwrap();
        let database_path = temporary.path().join("data.db");
        let library_path = temporary.path().join("library");
        fs::create_dir_all(library_path.join("answer_templates")).unwrap();
        fs::write(
            library_path.join("answer_templates/site.json"),
            br#"{"name":"Site","version":"1","stig_id":"ROUTER_STIG","entries":[]}"#,
        )
        .unwrap();
        {
            let database = Database::open(&database_path).unwrap();
            let checklist = sample_checklist();
            database
                .save_checklist_with_audit(
                    &checklist,
                    "finding.updated",
                    "reviewer",
                    Some(r#"{"preserved":true}"#),
                )
                .unwrap();
            database
                .set_config("asset_inventory", r#"[{"id":"local-1","name":"router-1"}]"#)
                .unwrap();
            database
                .set_config(
                    "stigman_config",
                    r#"{"api_url":"https://stigman.example/api","token_url":"https://idp.example/token","gui_url":"https://stigman.example/","client_id":"scanner","client_secret":"enc:super-secret","default_collection_id":"7","verify_tls":true}"#,
                )
                .unwrap();
        }

        let database = Database::open_read_only(&database_path).unwrap();
        let database = snapshot_database(&database).unwrap();
        let (answers, warnings) = snapshot_answer_templates(&library_path).unwrap();
        let snapshot = assemble_transition_snapshot(
            database,
            answers,
            warnings,
            "2026-08-08T00:00:00Z".to_string(),
        );
        let bundle = build_bundle(&snapshot).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(bundle)).unwrap();
        let mut extracted = BTreeMap::new();
        for index in 0..archive.len() {
            let mut member = archive.by_index(index).unwrap();
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes).unwrap();
            extracted.insert(member.name().to_string(), bytes);
        }

        let connection: Value = serde_json::from_slice(
            extracted
                .get("stig-manager/connection-without-secret.json")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(connection["has_secret"], true);
        assert_eq!(connection["client_secret_exported"], false);
        assert_eq!(connection["gui_url"], "https://stigman.example/");
        assert!(connection.get("client_secret").is_none());
        assert!(extracted
            .values()
            .all(|bytes| !String::from_utf8_lossy(bytes).contains("super-secret")));

        let attributed_path = extracted
            .keys()
            .find(|path| path.ends_with("/checklist-attributed.json"))
            .unwrap();
        let checklist: Checklist =
            serde_json::from_slice(extracted.get(attributed_path).unwrap()).unwrap();
        assert_eq!(checklist.findings[0].source, FindingSource::Manual);
        assert_eq!(checklist.findings[1].source, FindingSource::Imported);
        assert_eq!(checklist.findings[2].source, FindingSource::AnswerFile);
        assert!(extracted.contains_key("checksums.sha256"));
        assert!(extracted.contains_key("manifest.json"));
    }

    #[test]
    fn unsafe_member_components_are_sanitized() {
        let component = artifact_component("../../outside/checklist");
        assert!(!component.contains('/'));
        assert!(!component.contains(".."));
        let mut entries = BTreeMap::new();
        assert!(add_member(&mut entries, "../escape", Vec::new()).is_err());
    }
}
