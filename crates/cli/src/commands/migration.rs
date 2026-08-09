//! Read-only transition inventory and one-time preservation export.
//!
//! This command is intentionally separate from the scanner GUI. It never
//! creates or changes STIG Manager assets, assignments, reviews, or local
//! records. Finding-source attribution is reported and exported exactly as it
//! was retained.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::models::checklist::{Checklist, EvaluationOrigin};
use automatestig_core::models::finding::{FindingSource, FindingStatus};
use automatestig_storage::{
    AnswerFileRegistryRecord, AuditEvent, ChecklistSummaryRow, Database, DeliveryReceipt,
    DeliveryRecord, DeliveryState, EvaluationHistoryRecord, ScanRunRecord,
};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

use super::{db_path, ensure_safe_artifact_output, library_path};

const INVENTORY_SCHEMA: &str = "automatestig.migration-inventory.v1";
const BUNDLE_SCHEMA: &str = "automatestig.migration-bundle.v1";
const MAX_ANSWER_TEMPLATE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BUNDLE_UNCOMPRESSED_BYTES: usize = 512 * 1024 * 1024;

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
    database.read_snapshot(|database| {
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

        Ok(DatabaseSnapshot {
            schema_version,
            checklists,
            scan_runs,
            deliveries,
            delivery_receipts,
            evaluation_history: database.list_evaluation_history()?,
            audit_events: database.list_audit_events()?,
            answer_registry: database.list_answer_file_registry()?,
            asset_inventory_raw: database.get_config("asset_inventory")?,
            stigman_config_raw: database.get_config("stigman_config")?,
        })
    })
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
        let envelope_evidence = artifact
            .pointer("/evidence_envelope/evidence_sha256")
            .and_then(Value::as_str);
        let envelope_check_pack = artifact
            .pointer("/evidence_envelope/check_pack_sha256")
            .and_then(Value::as_str);
        let provenance = checklist.evaluation_provenance.as_ref();
        let checklist_id_matches = run
            .checklist_id
            .as_deref()
            .is_none_or(|expected| expected == checklist.id.to_string());
        evidence_bindings_verified = envelope_evidence == Some(run.evidence_sha256.as_str())
            && envelope_check_pack == Some(run.check_pack_sha256.as_str())
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
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).with_context(|| {
        format!(
            "failed to open {} without following symlinks",
            path.display()
        )
    })?;
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
        b"AutomateSTIG scanner-first transition export\n\nThis archive is read-only output and contains sensitive target evidence. Store it as assessment material. Canonical checklist JSON and attribution sidecars are authoritative for finding source. CKL/CKLB formats do not encode AutomateSTIG finding-source provenance; Manual, Imported, and AnswerFile findings must never be reclassified as automated. The saved STIG Manager client secret is intentionally excluded. This command performs no STIG Manager mutation and no local retention cleanup.\n".to_vec(),
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
                    r#"{"api_url":"https://stigman.example/api","token_url":"https://idp.example/token","client_id":"scanner","client_secret":"enc:super-secret","default_collection_id":"7","verify_tls":true}"#,
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
