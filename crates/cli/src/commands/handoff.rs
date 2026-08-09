//! Offline verification for selected scanner-run handoff bundles.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use automatestig_archive_safety::{ArchivePolicy, SafeZipArchive};
use automatestig_core::models::checklist::Checklist;
use automatestig_core::models::finding::{FindingSource, FindingStatus};
use automatestig_core::target_adapters::{built_in_target_adapter, AdapterEvidenceEnvelope};
use automatestig_core::target_adapters::{DeviceFingerprint, TARGET_ADAPTER_EVIDENCE_SCHEMA};
use automatestig_core::xccdf_results::{
    validate_xccdf_1_2_results, XccdfRuleOutcome, XCCDF_OWNERSHIP_SCOPE, XCCDF_RESULTS_SCHEMA,
};
use automatestig_integrations::stig_manager::{
    sparse_scanner_reviews, ScannerReview, ScannerReviewResult,
};
use automatestig_parsers::cklb::CklbFile;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ui;

// v2 is the legacy CKLB-only bounded contract. v3 adds a required,
// standards-based sparse XCCDF 1.2 result member. Verification remains strict
// for both versions; the GUI emits v3 and a protected CLI ceremony can attest
// either exact ZIP without exposing a signing key to the GUI process.
const HANDOFF_SCHEMA_V2: &str = "automatestig.selected-run-handoff.v2";
const HANDOFF_SCHEMA_V3: &str = "automatestig.selected-run-handoff.v3";
const RUN_SCHEMA: &str = "automatestig.scanner-run.v2";
const HANDOFF_SIGNATURE_SCHEMA: &str = "automatestig.selected-run-handoff-signature.v1";
const HANDOFF_SIGNATURE_ALGORITHM: &str = "ed25519-sha256";
const HANDOFF_SIGNATURE_DOMAIN: &str = "AUTOMATESTIG-SELECTED-RUN-HANDOFF-SIGNATURE-V1";
const REQUIRED_ENTRIES_V2: [&str; 5] = [
    "manifest.json",
    "integrity.json",
    "scanner-run.json",
    "sparse-reviews.json",
    "fallback.cklb",
];
const XCCDF_ENTRY: &str = "results.xccdf.xml";
const REQUIRED_ENTRIES_V3: [&str; 6] = [
    "manifest.json",
    "integrity.json",
    "scanner-run.json",
    "sparse-reviews.json",
    "fallback.cklb",
    XCCDF_ENTRY,
];
const EVIDENCE_ENTRY: &str = "evidence-envelope.json";

// Retained adapter evidence can legitimately contain the collector's bounded
// aggregate command output. Keep the evidence ceiling aligned above that
// producer limit while applying much narrower limits to every result member.
const MAX_ARCHIVE_BYTES: u64 = 320 * 1024 * 1024;
const MAX_ARCHIVE_MEMBER_BYTES: u64 = 320 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 352 * 1024 * 1024;
const MAX_RESULT_MEMBER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 320 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const MAX_INTEGRITY_BYTES: u64 = 8 * 1024;
const MAX_REVIEWS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SIGNATURE_SIDECAR_BYTES: u64 = 16 * 1024;
const MAX_RULES: usize = 10_000;
const MAX_REVIEW_DETAIL_BYTES: usize = 256 * 1024;
const MAX_REVIEW_COMMENT_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffManifest {
    schema: String,
    run_id: String,
    created_at: String,
    scanner_version: String,
    stig_id: String,
    stig_revision: String,
    files: HandoffFiles,
    scope: HandoffScope,
    evidence: HandoffEvidence,
    bindings: RunBindings,
    note: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffFiles {
    #[serde(rename = "scanner-run.json")]
    scanner_run: String,
    #[serde(rename = "sparse-reviews.json")]
    sparse_reviews: String,
    #[serde(rename = "fallback.cklb")]
    fallback_cklb: String,
    #[serde(default, rename = "results.xccdf.xml")]
    results_xccdf: Option<String>,
    #[serde(default, rename = "evidence-envelope.json")]
    evidence_envelope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffScope {
    scanner_owned_reviews_included: usize,
    unreviewed_and_non_scanner_rules_excluded: usize,
    ownership_safe_sparse_handoff: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceState {
    Retained,
    Purged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EvidencePurgeReason {
    RetentionExpired,
    OperatorRequested,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffEvidence {
    state: EvidenceState,
    included: bool,
    sha256: String,
    expires_at: String,
    purged_at: Option<String>,
    purge_reason: Option<EvidencePurgeReason>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunBindings {
    request_sha256: String,
    result_sha256: String,
    benchmark_sha256: String,
    check_pack_sha256: String,
    evaluation_plan_sha256: String,
    evidence_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntegrityRecord {
    algorithm: String,
    manifest_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffSignatureEnvelope {
    schema: String,
    algorithm: String,
    handoff_schema: String,
    run_id: String,
    handoff_sha256: String,
    signing_key_fingerprint: String,
    signature: String,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TargetSelection {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEvidenceReference {
    envelope_schema: String,
    evidence_sha256: String,
    envelope_json_sha256: String,
    profile_sha256: String,
    device_fingerprint_sha256: String,
    collection_plan_sha256: String,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPreviewCounts {
    create: usize,
    update: usize,
    unchanged: usize,
    conflict: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPreviewReview {
    rule_id: String,
    result: ScannerReviewResult,
    change: String,
    evidence_summary: String,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPreview {
    counts: DeliveryPreviewCounts,
    reviews: Vec<DeliveryPreviewReview>,
    manual_untouched: usize,
    #[serde(default)]
    out_of_scope_untouched: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    checklist: Checklist,
    reviews: Vec<ScannerReview>,
    delivery_preview: DeliveryPreview,
    evidence: StoredEvidenceReference,
}

#[derive(Debug, PartialEq, Eq)]
pub struct HandoffVerification {
    pub handoff_schema: String,
    pub run_id: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub scanner_version: String,
    pub review_count: usize,
    pub evidence_included: bool,
    /// True only when a detached signature matches an explicitly trusted
    /// handoff-signing key and the signed identity matches this exact ZIP.
    pub producer_authenticity_verified: bool,
    pub producer_signer_label: Option<String>,
    pub producer_signer_fingerprint: Option<String>,
}

pub fn run(
    zip_path: &str,
    signature_path: Option<&str>,
    trust_dir_override: Option<&str>,
) -> Result<()> {
    let path = Path::new(zip_path);
    if !path.is_file() {
        bail!("Handoff ZIP not found or not a regular file: {zip_path}");
    }
    if signature_path.is_none() && trust_dir_override.is_some() {
        bail!("--trust-dir requires --signature; unsigned verification has no trust key");
    }

    ui::print_banner();
    ui::section("Verify Selected-Run Handoff");
    ui::detail("File", zip_path);
    let trust_dir = trust_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(super::handoff_trusted_keys_dir);
    if let Some(signature_path) = signature_path {
        ui::detail("Signature", signature_path);
        ui::detail("Handoff trust store", &trust_dir.display().to_string());
    }
    println!();

    let verified = match signature_path {
        Some(signature_path) => {
            verify_handoff_with_signature(path, Path::new(signature_path), trust_dir.as_path())
        }
        None => verify_handoff(path),
    }
    .context("Selected-run handoff verification failed")?;
    ui::success("Archive structure and bounded decompression: valid");
    ui::success("Manifest and file SHA-256 integrity: valid");
    ui::success("Run provenance and sparse ownership bindings: valid");
    ui::success("CKLB supplemental projection contains scanner-owned reviewed rows only");
    if verified.handoff_schema == HANDOFF_SCHEMA_V3 {
        ui::success("XCCDF 1.2 results contain the same sparse scanner-owned rows");
    }
    ui::detail("Handoff schema", &verified.handoff_schema);
    ui::detail("Run", &verified.run_id);
    ui::detail(
        "STIG",
        &format!("{} {}", verified.stig_id, verified.stig_revision),
    );
    ui::detail("Scanner", &verified.scanner_version);
    ui::detail("Sparse reviews", &verified.review_count.to_string());
    ui::detail(
        "Replay evidence",
        if verified.evidence_included {
            "included and replay-verified"
        } else {
            "purged; result-only handoff"
        },
    );
    println!();
    if verified.producer_authenticity_verified {
        ui::success(&format!(
            "Producer signature: verified with trusted handoff key {} ({})",
            verified
                .producer_signer_label
                .as_deref()
                .unwrap_or("unknown"),
            verified
                .producer_signer_fingerprint
                .as_deref()
                .unwrap_or("unknown")
        ));
    } else {
        ui::warn(
            "Producer authenticity: NOT VERIFIED. No detached handoff signature was supplied; hashes alone do not prove who created the bundle.",
        );
    }
    Ok(())
}

/// Create a dedicated external handoff-signing key pair. Key generation is an
/// explicit protected-host ceremony and is never performed by the GUI.
pub fn generate_signing_key(output_path: &str, cli: &crate::Cli) -> Result<()> {
    let private_path = PathBuf::from(output_path);
    let public_path = private_path.with_extension("pub");
    super::ensure_safe_artifact_output(&private_path, &[], cli)?;
    super::ensure_safe_artifact_output(&public_path, &[], cli)?;
    let (_, public_key) =
        automatestig_stigpack::signing::create_signing_key_pair(&private_path, &public_path)
            .context("Failed to create external handoff-signing key pair")?;

    ui::print_banner();
    ui::section("Generate Handoff-Signing Key");
    ui::output_file(
        "Private key",
        &private_path.display().to_string(),
        "Ed25519 seed — keep off the GUI host",
    );
    ui::output_file(
        "Public key",
        &public_path.display().to_string(),
        "install independently in the handoff trust store",
    );
    ui::detail(
        "Fingerprint",
        &automatestig_stigpack::signing::public_key_fingerprint(&public_key),
    );
    println!();
    Ok(())
}

/// Sign an already valid handoff on a protected CLI host. The detached
/// signature binds the exact compressed ZIP bytes; the GUI ZIP contract
/// remains unsigned and unchanged.
pub fn sign_handoff(
    zip_path: &str,
    signing_key_path: &str,
    output_path: &str,
    cli: &crate::Cli,
) -> Result<()> {
    let zip_path = Path::new(zip_path);
    let private_path = Path::new(signing_key_path);
    let public_path = private_path.with_extension("pub");
    let output_path = Path::new(output_path);
    super::ensure_safe_artifact_output(
        output_path,
        &[zip_path, private_path, public_path.as_path()],
        cli,
    )?;

    let (file, compressed_len, handoff_sha256) = open_and_hash_handoff(zip_path)?;
    let verified = (|| {
        let archive = SafeZipArchive::from_reader(file, compressed_len, handoff_policy())
            .with_context(|| format!("Unsafe or malformed ZIP {}", zip_path.display()))?;
        verify_handoff_archive(archive)
    })()
    .context("Refusing to sign a handoff that fails semantic verification")?;

    // Access private key material only after the handoff has passed every
    // structural, provenance, ownership, CKLB, and evidence-replay check.
    let (private_key, public_key) =
        automatestig_stigpack::signing::load_signing_key_pair(private_path, &public_path)
            .context("Failed to load external handoff-signing key pair")?;
    let signing_key_fingerprint =
        automatestig_stigpack::signing::public_key_fingerprint(&public_key);
    let mut envelope = HandoffSignatureEnvelope {
        schema: HANDOFF_SIGNATURE_SCHEMA.to_string(),
        algorithm: HANDOFF_SIGNATURE_ALGORITHM.to_string(),
        handoff_schema: verified.handoff_schema.clone(),
        run_id: verified.run_id.clone(),
        handoff_sha256,
        signing_key_fingerprint: signing_key_fingerprint.clone(),
        signature: String::new(),
    };
    let signature = automatestig_stigpack::signing::sign_manifest(
        &handoff_signature_statement(&envelope),
        &private_key,
    )
    .context("Failed to sign selected-run handoff identity")?;
    envelope.signature = lower_hex(&signature);
    let mut sidecar = serde_json::to_vec_pretty(&envelope)
        .context("Failed to serialize detached handoff signature")?;
    sidecar.push(b'\n');

    // The protected ceremony can be long enough for destination state to
    // change. Recheck aliases and managed roots immediately before create-new.
    super::ensure_safe_artifact_output(
        output_path,
        &[zip_path, private_path, public_path.as_path()],
        cli,
    )?;
    write_signature_create_new(output_path, &sidecar)?;

    ui::print_banner();
    ui::section("Sign Selected-Run Handoff");
    ui::detail("Run", &verified.run_id);
    ui::detail("Handoff SHA-256", &envelope.handoff_sha256);
    ui::detail("Signing key", &signing_key_fingerprint);
    ui::output_file(
        "Detached signature",
        &output_path.display().to_string(),
        "pair with the exact handoff ZIP",
    );
    println!();
    Ok(())
}

pub fn verify_handoff(path: &Path) -> Result<HandoffVerification> {
    let archive = SafeZipArchive::open_path(path, handoff_policy())
        .with_context(|| format!("Unsafe or malformed ZIP {}", path.display()))?;
    verify_handoff_archive(archive)
}

/// Verify a detached producer signature against a dedicated explicit trust
/// store before decompressing or semantically consuming the handoff payload.
pub fn verify_handoff_with_signature(
    path: &Path,
    signature_path: &Path,
    trust_dir: &Path,
) -> Result<HandoffVerification> {
    let sidecar_bytes = read_regular_file_bounded(
        signature_path,
        MAX_SIGNATURE_SIDECAR_BYTES,
        "handoff signature sidecar",
    )?;
    let envelope: HandoffSignatureEnvelope =
        parse_json(&sidecar_bytes, "handoff signature sidecar")?;
    validate_signature_envelope(&envelope)?;

    let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
    trust_store
        .load_from_directory(trust_dir)
        .with_context(|| format!("Failed to load handoff trust store {}", trust_dir.display()))?;
    if trust_store.is_empty() {
        bail!(
            "No trusted handoff-signing keys found in {}",
            trust_dir.display()
        );
    }

    let (file, compressed_len, handoff_sha256) = open_and_hash_handoff(path)?;
    if envelope.handoff_sha256 != handoff_sha256 {
        bail!(
            "Detached signature is bound to handoff SHA-256 {}, but this ZIP is {}",
            envelope.handoff_sha256,
            handoff_sha256
        );
    }
    let signature = decode_lower_hex(&envelope.signature, 64, "signature")?;
    let (signer_label, signer_fingerprint) = trust_store
        .verify_against_trusted_identity(&handoff_signature_statement(&envelope), &signature)
        .context("Handoff signature verification failed")?
        .context("Detached handoff signature does not match any explicitly trusted key")?;
    if signer_fingerprint != envelope.signing_key_fingerprint {
        bail!(
            "Detached signature key identity mismatch: sidecar {}, trusted key {}",
            envelope.signing_key_fingerprint,
            signer_fingerprint
        );
    }

    let archive = SafeZipArchive::from_reader(file, compressed_len, handoff_policy())
        .with_context(|| format!("Unsafe or malformed ZIP {}", path.display()))?;
    let mut verified = verify_handoff_archive(archive)?;
    if envelope.run_id != verified.run_id {
        bail!(
            "Detached signature run ID {} does not match handoff run ID {}",
            envelope.run_id,
            verified.run_id
        );
    }
    if envelope.handoff_schema != verified.handoff_schema {
        bail!(
            "Detached signature handoff schema {} does not match bundle schema {}",
            envelope.handoff_schema,
            verified.handoff_schema
        );
    }
    verified.producer_authenticity_verified = true;
    verified.producer_signer_label = Some(signer_label);
    verified.producer_signer_fingerprint = Some(signer_fingerprint);
    Ok(verified)
}

fn handoff_policy() -> ArchivePolicy {
    let mut policy = ArchivePolicy::strict(
        MAX_ARCHIVE_BYTES,
        REQUIRED_ENTRIES_V3.len() + 1,
        MAX_ARCHIVE_MEMBER_BYTES,
        MAX_TOTAL_BYTES,
    );
    policy.allow_directories = false;
    policy.max_compression_ratio = Some(200);
    policy.compression_ratio_grace_bytes = 64 * 1024;
    policy
}

fn verify_handoff_archive<R: Read + Seek>(
    mut archive: SafeZipArchive<R>,
) -> Result<HandoffVerification> {
    let actual_entries: HashSet<_> = archive
        .entries()
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    let bootstrap_entries: HashSet<_> = ["manifest.json", "integrity.json"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let mut allowed_entries: HashSet<_> = REQUIRED_ENTRIES_V3
        .into_iter()
        .map(str::to_string)
        .collect();
    allowed_entries.insert(EVIDENCE_ENTRY.to_string());
    if !bootstrap_entries.is_subset(&actual_entries) || !actual_entries.is_subset(&allowed_entries)
    {
        let mut missing: Vec<_> = bootstrap_entries
            .difference(&actual_entries)
            .map(String::as_str)
            .collect();
        let mut unexpected: Vec<_> = actual_entries
            .difference(&allowed_entries)
            .map(String::as_str)
            .collect();
        missing.sort_unstable();
        unexpected.sort_unstable();
        bail!(
            "handoff entries cannot match a supported contract (missing bootstrap entries: {}; unexpected: {})",
            display_names(&missing),
            display_names(&unexpected)
        );
    }

    let mut budget = archive.new_read_budget();
    let manifest_bytes = archive
        .read_named_with_limit("manifest.json", MAX_MANIFEST_BYTES, &mut budget)
        .context("Could not safely read manifest.json")?;
    let integrity_bytes = archive
        .read_named_with_limit("integrity.json", MAX_INTEGRITY_BYTES, &mut budget)
        .context("Could not safely read integrity.json")?;
    let scanner_run_bytes = archive
        .read_named_with_limit("scanner-run.json", MAX_RESULT_MEMBER_BYTES, &mut budget)
        .context("Could not safely read scanner-run.json")?;
    let reviews_bytes = archive
        .read_named_with_limit("sparse-reviews.json", MAX_REVIEWS_BYTES, &mut budget)
        .context("Could not safely read sparse-reviews.json")?;
    let cklb_bytes = archive
        .read_named_with_limit("fallback.cklb", MAX_RESULT_MEMBER_BYTES, &mut budget)
        .context("Could not safely read fallback.cklb")?;

    let integrity: IntegrityRecord = parse_json(&integrity_bytes, "integrity.json")?;
    if integrity.algorithm != "sha256" {
        bail!(
            "integrity.json uses unsupported algorithm {:?}",
            integrity.algorithm
        );
    }
    require_sha256("integrity manifest_sha256", &integrity.manifest_sha256)?;
    require_digest_match("manifest.json", &integrity.manifest_sha256, &manifest_bytes)?;

    let manifest: HandoffManifest = parse_json(&manifest_bytes, "manifest.json")?;
    validate_manifest_identity(&manifest)?;
    let required_entries: HashSet<_> = match manifest.schema.as_str() {
        HANDOFF_SCHEMA_V2 => REQUIRED_ENTRIES_V2.as_slice(),
        HANDOFF_SCHEMA_V3 => REQUIRED_ENTRIES_V3.as_slice(),
        _ => unreachable!("manifest schema was validated"),
    }
    .iter()
    .map(|name| (*name).to_string())
    .collect();
    let mut schema_allowed_entries = required_entries.clone();
    schema_allowed_entries.insert(EVIDENCE_ENTRY.to_string());
    if !required_entries.is_subset(&actual_entries)
        || !actual_entries.is_subset(&schema_allowed_entries)
    {
        let mut missing: Vec<_> = required_entries
            .difference(&actual_entries)
            .map(String::as_str)
            .collect();
        let mut unexpected: Vec<_> = actual_entries
            .difference(&schema_allowed_entries)
            .map(String::as_str)
            .collect();
        missing.sort_unstable();
        unexpected.sort_unstable();
        bail!(
            "handoff entries do not match the {} contract (missing: {}; unexpected: {})",
            manifest.schema,
            display_names(&missing),
            display_names(&unexpected)
        );
    }
    let archive_has_evidence = actual_entries.contains(EVIDENCE_ENTRY);
    if archive_has_evidence != manifest.evidence.included
        || archive_has_evidence != manifest.files.evidence_envelope.is_some()
    {
        bail!(
            "evidence-envelope.json presence does not match manifest files/evidence declarations"
        );
    }
    require_digest_match(
        "scanner-run.json",
        &manifest.files.scanner_run,
        &scanner_run_bytes,
    )?;
    require_digest_match(
        "sparse-reviews.json",
        &manifest.files.sparse_reviews,
        &reviews_bytes,
    )?;
    require_digest_match("fallback.cklb", &manifest.files.fallback_cklb, &cklb_bytes)?;
    let xccdf_bytes = if manifest.schema == HANDOFF_SCHEMA_V3 {
        let bytes = archive
            .read_named_with_limit(XCCDF_ENTRY, MAX_RESULT_MEMBER_BYTES, &mut budget)
            .context("Could not safely read results.xccdf.xml")?;
        require_digest_match(
            XCCDF_ENTRY,
            manifest
                .files
                .results_xccdf
                .as_deref()
                .context("v3 manifest omits results.xccdf.xml digest")?,
            &bytes,
        )?;
        Some(bytes)
    } else {
        None
    };
    let evidence_envelope_bytes = if archive_has_evidence {
        let bytes = archive
            .read_named_with_limit(EVIDENCE_ENTRY, MAX_EVIDENCE_BYTES, &mut budget)
            .context("Could not safely read evidence-envelope.json")?;
        require_digest_match(
            EVIDENCE_ENTRY,
            manifest
                .files
                .evidence_envelope
                .as_deref()
                .context("manifest omits evidence-envelope.json digest")?,
            &bytes,
        )?;
        Some(bytes)
    } else {
        None
    };

    let artifact: StoredRunArtifact = parse_json(&scanner_run_bytes, "scanner-run.json")?;
    let sparse_reviews: Vec<ScannerReview> = parse_json(&reviews_bytes, "sparse-reviews.json")?;
    validate_run_and_reviews(&manifest, &artifact, &sparse_reviews)?;

    let compact_run = serde_json::to_vec(&artifact)
        .context("Could not reconstruct immutable scanner-run result bytes")?;
    require_digest_match(
        "scanner-run immutable result binding",
        &manifest.bindings.result_sha256,
        &compact_run,
    )?;

    let cklb: CklbFile = parse_json(&cklb_bytes, "fallback.cklb")?;
    validate_cklb(&manifest, &artifact, &sparse_reviews, &cklb)?;
    if let Some(xccdf_bytes) = xccdf_bytes.as_deref() {
        validate_xccdf(&manifest, &artifact, &sparse_reviews, xccdf_bytes)?;
    }
    validate_evidence_envelope(&manifest, &artifact, evidence_envelope_bytes.as_deref())?;

    Ok(HandoffVerification {
        handoff_schema: manifest.schema,
        run_id: manifest.run_id,
        stig_id: manifest.stig_id,
        stig_revision: manifest.stig_revision,
        scanner_version: manifest.scanner_version,
        review_count: sparse_reviews.len(),
        evidence_included: manifest.evidence.included,
        producer_authenticity_verified: false,
        producer_signer_label: None,
        producer_signer_fingerprint: None,
    })
}

fn validate_manifest_identity(manifest: &HandoffManifest) -> Result<()> {
    if !matches!(
        manifest.schema.as_str(),
        HANDOFF_SCHEMA_V2 | HANDOFF_SCHEMA_V3
    ) {
        bail!("unsupported handoff schema {:?}", manifest.schema);
    }
    match (manifest.schema.as_str(), &manifest.files.results_xccdf) {
        (HANDOFF_SCHEMA_V2, None) | (HANDOFF_SCHEMA_V3, Some(_)) => {}
        (HANDOFF_SCHEMA_V2, Some(_)) => {
            bail!("v2 handoff manifest unexpectedly declares results.xccdf.xml")
        }
        (HANDOFF_SCHEMA_V3, None) => {
            bail!("v3 handoff manifest must declare results.xccdf.xml")
        }
        _ => unreachable!("supported schema was checked"),
    }
    let parsed_run_id =
        uuid::Uuid::parse_str(&manifest.run_id).context("manifest run_id is not a UUID")?;
    if parsed_run_id.hyphenated().to_string() != manifest.run_id {
        bail!("manifest run_id is not a canonical lowercase UUID");
    }
    DateTime::parse_from_rfc3339(&manifest.created_at)
        .context("manifest created_at is not RFC 3339")?;
    require_text("scanner_version", &manifest.scanner_version, 128)?;
    require_text("stig_id", &manifest.stig_id, 512)?;
    require_text("stig_revision", &manifest.stig_revision, 64)?;
    require_text("note", &manifest.note, 4_096)?;
    if !manifest.scope.ownership_safe_sparse_handoff {
        bail!("manifest does not assert an ownership-safe sparse handoff");
    }
    require_sha256("evidence.sha256", &manifest.evidence.sha256)?;
    if manifest.evidence.sha256 != manifest.bindings.evidence_sha256 {
        bail!("manifest evidence SHA-256 does not match its run binding");
    }
    DateTime::parse_from_rfc3339(&manifest.evidence.expires_at)
        .context("manifest evidence.expires_at is not RFC 3339")?;
    match manifest.evidence.state {
        EvidenceState::Retained => {
            if !manifest.evidence.included
                || manifest.evidence.purged_at.is_some()
                || manifest.evidence.purge_reason.is_some()
            {
                bail!("retained evidence metadata is internally inconsistent");
            }
        }
        EvidenceState::Purged => {
            if manifest.evidence.included
                || manifest.evidence.purged_at.is_none()
                || manifest.evidence.purge_reason.is_none()
            {
                bail!("purged evidence metadata is internally inconsistent");
            }
            DateTime::parse_from_rfc3339(
                manifest.evidence.purged_at.as_deref().unwrap_or_default(),
            )
            .context("manifest evidence.purged_at is not RFC 3339")?;
        }
    }
    for (label, digest) in [
        ("files.scanner-run.json", &manifest.files.scanner_run),
        ("files.sparse-reviews.json", &manifest.files.sparse_reviews),
        ("files.fallback.cklb", &manifest.files.fallback_cklb),
        ("bindings.request_sha256", &manifest.bindings.request_sha256),
        ("bindings.result_sha256", &manifest.bindings.result_sha256),
        (
            "bindings.benchmark_sha256",
            &manifest.bindings.benchmark_sha256,
        ),
        (
            "bindings.check_pack_sha256",
            &manifest.bindings.check_pack_sha256,
        ),
        (
            "bindings.evaluation_plan_sha256",
            &manifest.bindings.evaluation_plan_sha256,
        ),
        (
            "bindings.evidence_sha256",
            &manifest.bindings.evidence_sha256,
        ),
    ] {
        require_sha256(label, digest)?;
    }
    if let Some(digest) = &manifest.files.evidence_envelope {
        require_sha256("files.evidence-envelope.json", digest)?;
    }
    if let Some(digest) = &manifest.files.results_xccdf {
        require_sha256("files.results.xccdf.xml", digest)?;
    }
    Ok(())
}

fn validate_run_and_reviews(
    manifest: &HandoffManifest,
    artifact: &StoredRunArtifact,
    sparse_reviews: &[ScannerReview],
) -> Result<()> {
    if artifact.schema != RUN_SCHEMA {
        bail!("unsupported scanner-run schema {:?}", artifact.schema);
    }
    require_text("profile_id", &artifact.profile_id, 128)?;
    if !matches!(
        artifact.collection_method.as_str(),
        "ssh" | "evidence" | "configuration"
    ) {
        bail!(
            "scanner-run has unsupported collection_method {:?}",
            artifact.collection_method
        );
    }
    if artifact.mode == RunMode::Connected && artifact.destination.is_none() {
        bail!("connected scanner-run is missing its exact destination binding");
    }
    if artifact.mode == RunMode::Disconnected && artifact.destination.is_some() {
        bail!("disconnected scanner-run unexpectedly contains a destination binding");
    }
    if !artifact.collection_complete || !artifact.collection_errors.is_empty() {
        bail!("only a complete, error-free scanner-run can be a handoff");
    }
    if artifact.reviews.is_empty() || artifact.reviews.len() > MAX_RULES {
        bail!(
            "scanner-run sparse review count {} is outside 1..={MAX_RULES}",
            artifact.reviews.len()
        );
    }
    if artifact.checklist.findings.len() > MAX_RULES {
        bail!(
            "scanner-run checklist contains too many rules ({})",
            artifact.checklist.findings.len()
        );
    }
    if artifact.reviews != sparse_reviews {
        bail!("sparse-reviews.json does not exactly match scanner-run.json reviews");
    }
    if manifest.scope.scanner_owned_reviews_included != sparse_reviews.len() {
        bail!("manifest sparse review scope count does not match the payload");
    }
    let excluded = artifact
        .checklist
        .findings
        .len()
        .saturating_sub(sparse_reviews.len());
    if manifest.scope.unreviewed_and_non_scanner_rules_excluded != excluded {
        bail!("manifest excluded-rule scope count does not match scanner-run.json");
    }

    if artifact.checklist.stig_info.stig_id != manifest.stig_id {
        bail!("manifest STIG ID does not match the scanner-run checklist");
    }
    let checklist_revision = format!(
        "V{}R{}",
        artifact.checklist.stig_info.version, artifact.checklist.stig_info.release
    );
    if checklist_revision != manifest.stig_revision {
        bail!("manifest STIG revision does not match the scanner-run checklist");
    }
    if artifact.checklist.generated_by != format!("AutomateSTIG {}", manifest.scanner_version) {
        bail!("manifest scanner_version does not match checklist generator identity");
    }
    if artifact.device.hostname != artifact.checklist.asset.hostname {
        bail!("device hostname does not match checklist asset hostname");
    }
    let device_sha256 = artifact
        .device
        .sha256()
        .context("scanner-run device fingerprint is invalid")?;
    if device_sha256 != artifact.evidence.device_fingerprint_sha256 {
        bail!("scanner-run device fingerprint SHA-256 binding does not match");
    }
    if artifact.evidence.envelope_schema != TARGET_ADAPTER_EVIDENCE_SCHEMA {
        bail!(
            "scanner-run references unsupported evidence schema {:?}",
            artifact.evidence.envelope_schema
        );
    }
    for (label, digest) in [
        (
            "evidence.evidence_sha256",
            &artifact.evidence.evidence_sha256,
        ),
        (
            "evidence.envelope_json_sha256",
            &artifact.evidence.envelope_json_sha256,
        ),
        ("evidence.profile_sha256", &artifact.evidence.profile_sha256),
        (
            "evidence.device_fingerprint_sha256",
            &artifact.evidence.device_fingerprint_sha256,
        ),
        (
            "evidence.collection_plan_sha256",
            &artifact.evidence.collection_plan_sha256,
        ),
    ] {
        require_sha256(label, digest)?;
    }

    let provenance = artifact
        .checklist
        .evaluation_provenance
        .as_ref()
        .context("scanner-run checklist is missing evaluation provenance")?;
    if let Some(reason) = artifact.checklist.external_export_block_reason() {
        bail!("scanner-run checklist provenance is not exportable: {reason}");
    }
    if !provenance.collection_complete || !provenance.collection_errors.is_empty() {
        bail!("checklist provenance records incomplete collection");
    }
    require_binding(
        "evidence",
        provenance.evidence_sha256.as_deref(),
        &manifest.bindings.evidence_sha256,
    )?;
    require_binding(
        "benchmark",
        provenance.benchmark_sha256.as_deref(),
        &manifest.bindings.benchmark_sha256,
    )?;
    require_binding(
        "check-pack",
        provenance.check_pack_sha256.as_deref(),
        &manifest.bindings.check_pack_sha256,
    )?;
    require_binding(
        "evaluation-plan",
        provenance.evaluation_plan_sha256.as_deref(),
        &manifest.bindings.evaluation_plan_sha256,
    )?;
    require_binding(
        "collection-plan",
        provenance.plan_sha256.as_deref(),
        &artifact.evidence.collection_plan_sha256,
    )?;
    if artifact.evidence.evidence_sha256 != manifest.bindings.evidence_sha256 {
        bail!("scanner-run evidence reference does not match the manifest binding");
    }
    if provenance.claimed_hostname.as_deref() != Some(artifact.device.hostname.as_str()) {
        bail!("checklist claimed hostname does not match the device fingerprint");
    }

    let expected_reviews = sparse_scanner_reviews(&artifact.checklist);
    if expected_reviews != artifact.reviews {
        bail!(
            "scanner-run reviews are not the exact sparse projection of completed scanner-owned findings"
        );
    }
    validate_review_rows(sparse_reviews)?;

    let mut all_rule_ids = HashSet::with_capacity(artifact.checklist.findings.len());
    for finding in &artifact.checklist.findings {
        require_text("checklist finding rule_id", &finding.rule_id, 512)?;
        if !all_rule_ids.insert(finding.rule_id.as_str()) {
            bail!(
                "scanner-run checklist contains duplicate rule ID {}",
                finding.rule_id
            );
        }
    }
    let manual_count = artifact
        .checklist
        .findings
        .iter()
        .filter(|finding| {
            finding.source == FindingSource::Manual && finding.status == FindingStatus::NotReviewed
        })
        .count();
    if manual_count != artifact.manual_untouched {
        bail!("scanner-run manual_untouched count does not match its checklist");
    }
    validate_delivery_preview(artifact)?;
    Ok(())
}

fn validate_evidence_envelope(
    manifest: &HandoffManifest,
    artifact: &StoredRunArtifact,
    evidence_bytes: Option<&[u8]>,
) -> Result<()> {
    let Some(evidence_bytes) = evidence_bytes else {
        if manifest.evidence.state != EvidenceState::Purged {
            bail!("retained replay evidence is absent from the handoff");
        }
        return Ok(());
    };
    if manifest.evidence.state != EvidenceState::Retained {
        bail!("purged handoff unexpectedly contains replay evidence");
    }

    let envelope: AdapterEvidenceEnvelope = parse_json(evidence_bytes, "evidence-envelope.json")?;
    if envelope.schema != TARGET_ADAPTER_EVIDENCE_SCHEMA
        || envelope.evidence_sha256 != manifest.evidence.sha256
        || envelope.evidence_sha256 != artifact.evidence.evidence_sha256
        || envelope.profile_sha256 != artifact.evidence.profile_sha256
        || envelope.device_fingerprint_sha256 != artifact.evidence.device_fingerprint_sha256
        || envelope.plan_sha256 != artifact.evidence.collection_plan_sha256
        || envelope.check_pack_sha256 != manifest.bindings.check_pack_sha256
        || envelope.device != artifact.device
        || !envelope.complete
    {
        bail!("included replay evidence does not match immutable handoff bindings");
    }
    let compact = serde_json::to_vec(&envelope)
        .context("Could not reconstruct retained evidence envelope bytes")?;
    require_digest_match(
        "retained evidence plaintext binding",
        &artifact.evidence.envelope_json_sha256,
        &compact,
    )?;
    let adapter = built_in_target_adapter(&artifact.profile_id)
        .with_context(|| format!("unknown scanner adapter profile {}", artifact.profile_id))?;
    let replay = adapter
        .replay(&envelope)
        .context("Included replay evidence failed adapter integrity verification")?;
    if !replay.completeness.complete {
        bail!("included replay evidence does not reconstruct a complete collection");
    }
    Ok(())
}

fn validate_review_rows(reviews: &[ScannerReview]) -> Result<()> {
    let mut ids = HashSet::with_capacity(reviews.len());
    for review in reviews {
        require_text("sparse review rule_id", &review.rule_id, 512)?;
        if !ids.insert(review.rule_id.as_str()) {
            bail!("duplicate sparse review for rule {}", review.rule_id);
        }
        if review.detail.len() > MAX_REVIEW_DETAIL_BYTES {
            bail!("sparse review {} detail is oversized", review.rule_id);
        }
        if review.comment.len() > MAX_REVIEW_COMMENT_BYTES {
            bail!("sparse review {} comment is oversized", review.rule_id);
        }
        let evaluated_at = review
            .evaluated_at
            .as_deref()
            .context("sparse review is missing evaluated_at")?;
        DateTime::parse_from_rfc3339(evaluated_at)
            .with_context(|| format!("sparse review {} evaluated_at is invalid", review.rule_id))?;
    }
    Ok(())
}

fn validate_delivery_preview(artifact: &StoredRunArtifact) -> Result<()> {
    let preview = &artifact.delivery_preview;
    if preview.manual_untouched != artifact.manual_untouched
        || preview.out_of_scope_untouched != artifact.out_of_scope_untouched
    {
        bail!("delivery preview untouched counts do not match the scanner-run");
    }
    if preview.reviews.len() != artifact.reviews.len() {
        bail!("delivery preview does not cover every sparse review exactly once");
    }
    let mut observed_counts: HashMap<&str, usize> = HashMap::new();
    for (row, review) in preview.reviews.iter().zip(&artifact.reviews) {
        if row.rule_id != review.rule_id || row.result != review.result {
            bail!("delivery preview review order or result does not match sparse reviews");
        }
        if !matches!(
            row.change.as_str(),
            "create" | "update" | "unchanged" | "conflict" | "handoff" | "ownership_check_pending"
        ) {
            bail!(
                "delivery preview contains unsupported change {:?}",
                row.change
            );
        }
        let expected_summary = review
            .detail
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("Evidence-bound scanner determination")
            .chars()
            .take(240)
            .collect::<String>();
        if row.evidence_summary != expected_summary {
            bail!("delivery preview evidence summary does not match its sparse review");
        }
        *observed_counts.entry(row.change.as_str()).or_default() += 1;
    }
    for (name, expected) in [
        ("create", preview.counts.create),
        ("update", preview.counts.update),
        ("unchanged", preview.counts.unchanged),
        ("conflict", preview.counts.conflict),
    ] {
        if observed_counts.get(name).copied().unwrap_or_default() != expected {
            bail!("delivery preview {name} count does not match its rows");
        }
    }
    if let Some(warning) = &preview.warning {
        require_text("delivery preview warning", warning, 4_096)?;
    }
    Ok(())
}

fn validate_cklb(
    manifest: &HandoffManifest,
    artifact: &StoredRunArtifact,
    reviews: &[ScannerReview],
    cklb: &CklbFile,
) -> Result<()> {
    if cklb.stigs.len() != 1 {
        bail!("fallback.cklb must contain exactly one STIG");
    }
    if cklb.id.as_deref() != Some(&artifact.checklist.id.to_string()) {
        bail!("fallback.cklb checklist ID does not match scanner-run.json");
    }
    if cklb.target_data.host_name.as_deref() != Some(artifact.device.hostname.as_str()) {
        bail!("fallback.cklb target hostname does not match scanner-run.json");
    }
    let stig = &cklb.stigs[0];
    if stig.stig_id.as_deref() != Some(manifest.stig_id.as_str()) {
        bail!("fallback.cklb STIG ID does not match the manifest");
    }
    if stig.version.as_deref() != Some(artifact.checklist.stig_info.version.as_str()) {
        bail!("fallback.cklb STIG version does not match scanner-run.json");
    }
    let cklb_release = stig
        .release_info
        .as_deref()
        .and_then(release_number)
        .context("fallback.cklb release_info is missing a Release number")?;
    if cklb_release != artifact.checklist.stig_info.release {
        bail!("fallback.cklb release does not match scanner-run.json");
    }
    if stig.rules.len() != reviews.len() || stig.size != Some(reviews.len() as i32) {
        bail!(
            "fallback.cklb must contain exactly the {} sparse reviewed rows",
            reviews.len()
        );
    }

    let reviews_by_id: BTreeMap<_, _> = reviews
        .iter()
        .map(|review| (review.rule_id.as_str(), review))
        .collect();
    let mut seen = HashSet::with_capacity(stig.rules.len());
    for rule in &stig.rules {
        let rule_id = rule
            .rule_id_src
            .as_deref()
            .context("fallback.cklb rule is missing rule_id_src")?;
        require_text("fallback.cklb rule_id_src", rule_id, 512)?;
        if rule.rule_id.as_deref() != Some(rule_id) {
            bail!("fallback.cklb rule_id and rule_id_src do not match for {rule_id}");
        }
        if !seen.insert(rule_id) {
            bail!("fallback.cklb contains duplicate rule {rule_id}");
        }
        let status = rule.status.as_deref().unwrap_or("not_reviewed");
        if matches!(
            status,
            "not_reviewed" | "Not_Reviewed" | "NotReviewed" | "notchecked"
        ) {
            bail!(
                "fallback.cklb contains NotReviewed row {rule_id}; manual/unowned rows are forbidden"
            );
        }
        let review = reviews_by_id
            .get(rule_id)
            .with_context(|| format!("fallback.cklb rule {rule_id} is not scanner-owned"))?;
        let expected_status = match review.result {
            ScannerReviewResult::Pass => "not_a_finding",
            ScannerReviewResult::Fail => "open",
            ScannerReviewResult::NotApplicable => "not_applicable",
        };
        if status != expected_status {
            bail!("fallback.cklb status for {rule_id} does not match sparse-reviews.json");
        }
        if rule.finding_details.as_deref().unwrap_or_default() != review.detail
            || rule.comments.as_deref().unwrap_or_default() != review.comment
        {
            bail!("fallback.cklb evidence text for {rule_id} does not match sparse reviews");
        }
    }
    Ok(())
}

fn validate_xccdf(
    manifest: &HandoffManifest,
    artifact: &StoredRunArtifact,
    reviews: &[ScannerReview],
    xml: &[u8],
) -> Result<()> {
    let validation = validate_xccdf_1_2_results(xml)
        .context("results.xccdf.xml is not a structurally valid sparse XCCDF 1.2 result")?;
    let expected_benchmark = format!("xccdf_mil.disa.stig_benchmark_{}", manifest.stig_id);
    if validation.benchmark_id != expected_benchmark {
        bail!("results.xccdf.xml Benchmark id does not match the manifest STIG");
    }
    let expected_test_result = format!("xccdf_org.automatestig_testresult_{}", manifest.run_id);
    if validation.test_result_id != expected_test_result {
        bail!("results.xccdf.xml TestResult id does not match the immutable run");
    }
    if validation.target != artifact.device.hostname {
        bail!("results.xccdf.xml target does not match scanner-run.json");
    }

    let expected_results: BTreeMap<_, _> = reviews
        .iter()
        .map(|review| {
            let outcome = match review.result {
                ScannerReviewResult::Pass => XccdfRuleOutcome::Pass,
                ScannerReviewResult::Fail => XccdfRuleOutcome::Fail,
                ScannerReviewResult::NotApplicable => XccdfRuleOutcome::NotApplicable,
            };
            (
                format!("xccdf_mil.disa.stig_rule_{}", review.rule_id),
                outcome,
            )
        })
        .collect();
    if validation.rule_results != expected_results {
        bail!("results.xccdf.xml rule IDs/results do not exactly match sparse-reviews.json");
    }
    let reviews_by_id: BTreeMap<_, _> = reviews
        .iter()
        .map(|review| {
            (
                format!("xccdf_mil.disa.stig_rule_{}", review.rule_id),
                review,
            )
        })
        .collect();
    for (idref, review) in reviews_by_id {
        if validation.rule_details.get(&idref).map(String::as_str) != Some(review.detail.as_str())
            || validation.rule_comments.get(&idref).map(String::as_str)
                != Some(review.comment.as_str())
        {
            bail!(
                "results.xccdf.xml detail/comment for {} does not match sparse-reviews.json",
                review.rule_id
            );
        }
    }

    for (name, expected) in [
        ("run-id", manifest.run_id.as_str()),
        ("profile-id", artifact.profile_id.as_str()),
        ("scanner-version", manifest.scanner_version.as_str()),
        ("collection-method", artifact.collection_method.as_str()),
        ("request-sha256", manifest.bindings.request_sha256.as_str()),
        ("result-sha256", manifest.bindings.result_sha256.as_str()),
        ("profile-sha256", artifact.evidence.profile_sha256.as_str()),
        (
            "benchmark-sha256",
            manifest.bindings.benchmark_sha256.as_str(),
        ),
        (
            "check-pack-sha256",
            manifest.bindings.check_pack_sha256.as_str(),
        ),
        (
            "evaluation-plan-sha256",
            manifest.bindings.evaluation_plan_sha256.as_str(),
        ),
        (
            "evidence-sha256",
            manifest.bindings.evidence_sha256.as_str(),
        ),
        (
            "collection-plan-sha256",
            artifact.evidence.collection_plan_sha256.as_str(),
        ),
    ] {
        if validation.provenance_fields.get(name).map(String::as_str) != Some(expected) {
            bail!("results.xccdf.xml provenance field {name:?} does not match the handoff");
        }
    }
    if validation
        .provenance_fields
        .get("ownership")
        .is_some_and(|value| value != XCCDF_OWNERSHIP_SCOPE)
        || validation
            .provenance_fields
            .get("schema")
            .is_some_and(|value| value != XCCDF_RESULTS_SCHEMA)
    {
        bail!("results.xccdf.xml provenance declares an unsupported ownership/schema");
    }
    Ok(())
}

fn release_number(value: &str) -> Option<&str> {
    let position = value.find("Release:")?;
    value[position + "Release:".len()..]
        .split_whitespace()
        .next()
}

fn require_binding(label: &str, actual: Option<&str>, expected: &str) -> Result<()> {
    let actual =
        actual.with_context(|| format!("checklist provenance is missing {label} binding"))?;
    if actual != expected {
        bail!("checklist provenance {label} binding does not match the handoff");
    }
    Ok(())
}

fn require_text(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} must not be empty");
    }
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        bail!("{label} is oversized or contains control characters");
    }
    Ok(())
}

fn require_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not a lowercase SHA-256 digest");
    }
    Ok(())
}

fn require_digest_match(label: &str, expected: &str, bytes: &[u8]) -> Result<()> {
    require_sha256(label, expected)?;
    let actual = sha256_hex(bytes);
    if actual != expected {
        bail!("SHA-256 mismatch for {label}: expected {expected}, got {actual}");
    }
    Ok(())
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    serde_json::from_slice(bytes).with_context(|| format!("{label} is malformed JSON"))
}

fn validate_signature_envelope(envelope: &HandoffSignatureEnvelope) -> Result<()> {
    if envelope.schema != HANDOFF_SIGNATURE_SCHEMA {
        bail!("unsupported handoff signature schema {:?}", envelope.schema);
    }
    if envelope.algorithm != HANDOFF_SIGNATURE_ALGORITHM {
        bail!(
            "unsupported handoff signature algorithm {:?}",
            envelope.algorithm
        );
    }
    if !matches!(
        envelope.handoff_schema.as_str(),
        HANDOFF_SCHEMA_V2 | HANDOFF_SCHEMA_V3
    ) {
        bail!(
            "handoff signature is bound to unsupported handoff schema {:?}",
            envelope.handoff_schema
        );
    }
    let run_id = uuid::Uuid::parse_str(&envelope.run_id)
        .context("handoff signature run_id is not a UUID")?;
    if run_id.hyphenated().to_string() != envelope.run_id {
        bail!("handoff signature run_id is not a canonical lowercase UUID");
    }
    require_sha256("handoff signature handoff_sha256", &envelope.handoff_sha256)?;
    let fingerprint = envelope
        .signing_key_fingerprint
        .strip_prefix("SHA256:")
        .context("handoff signature key fingerprint must start with SHA256:")?;
    require_lower_hex("handoff signature key fingerprint", fingerprint, 32)?;
    decode_lower_hex(&envelope.signature, 64, "handoff signature")?;
    Ok(())
}

/// A fixed, domain-separated representation avoids JSON canonicalization and
/// cross-purpose signature reuse. Every variable field has strict grammar
/// before this statement is constructed.
fn handoff_signature_statement(envelope: &HandoffSignatureEnvelope) -> Vec<u8> {
    format!(
        "{HANDOFF_SIGNATURE_DOMAIN}\nsignature_schema={}\nalgorithm={}\nhandoff_schema={}\nrun_id={}\nhandoff_sha256={}\nsigning_key_fingerprint={}\n",
        envelope.schema,
        envelope.algorithm,
        envelope.handoff_schema,
        envelope.run_id,
        envelope.handoff_sha256,
        envelope.signing_key_fingerprint,
    )
    .into_bytes()
}

fn open_and_hash_handoff(path: &Path) -> Result<(File, u64, String)> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect handoff ZIP: {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        bail!("Handoff ZIP must be a regular, non-symlink file");
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("Failed to open handoff ZIP: {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect open handoff ZIP: {}", path.display()))?;
    if !metadata.is_file() {
        bail!("Handoff ZIP must be a regular file");
    }
    let compressed_len = metadata.len();
    if compressed_len > MAX_ARCHIVE_BYTES {
        bail!(
            "Handoff ZIP is {compressed_len} bytes, exceeding the {MAX_ARCHIVE_BYTES}-byte limit"
        );
    }

    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("Failed to hash handoff ZIP: {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .context("Handoff ZIP size overflowed while hashing")?;
        if total > MAX_ARCHIVE_BYTES {
            bail!("Handoff ZIP grew beyond the {MAX_ARCHIVE_BYTES}-byte limit while hashing");
        }
        hasher.update(&buffer[..read]);
    }
    if total != compressed_len {
        bail!("Handoff ZIP changed size while it was being opened for verification");
    }
    file.seek(SeekFrom::Start(0))
        .context("Failed to rewind handoff ZIP for semantic verification")?;
    Ok((file, compressed_len, format!("{:x}", hasher.finalize())))
}

fn read_regular_file_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect {label}: {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        bail!("{label} must be a regular, non-symlink file");
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Failed to open {label}: {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect open {label}: {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        bail!("{label} exceeds the {max_bytes}-byte regular-file limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read {label}: {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!("{label} exceeds the {max_bytes}-byte limit");
    }
    Ok(bytes)
}

fn write_signature_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("Failed to create signature output: {}", path.display()))?;
    file.write_all(bytes)
        .context("Failed to write detached handoff signature")?;
    file.sync_all()
        .context("Failed to persist detached handoff signature")?;
    Ok(())
}

fn require_lower_hex(label: &str, value: &str, expected_bytes: usize) -> Result<()> {
    let expected_len = expected_bytes
        .checked_mul(2)
        .context("hex length overflow")?;
    if value.len() != expected_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be exactly {expected_len} lowercase hexadecimal characters");
    }
    Ok(())
}

fn decode_lower_hex(value: &str, expected_bytes: usize, label: &str) -> Result<Vec<u8>> {
    require_lower_hex(label, value, expected_bytes)?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = lower_hex_nibble(pair[0]);
            let low = lower_hex_nibble(pair[1]);
            Ok((high << 4) | low)
        })
        .collect()
}

fn lower_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("lowercase hex grammar was checked before decoding"),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn display_names(names: &[&str]) -> String {
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use automatestig_core::check_packs::evaluation_plan_sha256;
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{
        ChecklistStigInfo, EvaluationOrigin, EvaluationProvenance,
    };
    use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
    use automatestig_core::models::stig::Severity;
    use automatestig_core::target_adapters::{
        AdapterEvidenceEnvelope, AdapterOperationEvidence, BuiltInTargetAdapter,
        EvidenceTransportIdentity,
    };
    use automatestig_core::xccdf_results::{
        write_sparse_xccdf_1_2_results, XccdfResultsProvenance,
    };
    use zip::write::SimpleFileOptions;

    use super::*;

    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn valid_bundle_entries() -> BTreeMap<String, Vec<u8>> {
        let stig_id = "General_Purpose_Operating_System";
        let revision = "V3R3";
        let benchmark_sha256 = digest('a');
        let adapter = BuiltInTargetAdapter::FreeBsdGpos;
        let device = DeviceFingerprint::new("device-1", "FreeBSD", "FreeBSD", "14.3-RELEASE-p1");
        let plan = adapter.preview(&device).unwrap();
        let outputs = BTreeMap::from([
            (
                "service auditd onestatus",
                "auditd is running as pid 123.\n",
            ),
            (
                "cat /etc/security/audit_control",
                "flags:all\nnaflags:all\n",
            ),
            ("cat /etc/security/audit_user", "# no per-user exclusions\n"),
            (
                "sha256 -q /etc/security/audit_class",
                "834a1fde758a45269874a5c0655046ca7354a7afa3cf9aee8d29bbfe5d8ab2fd\n",
            ),
            (
                "sha256 -q /etc/security/audit_event",
                "124c60b738ec9eb36e497213fded40a7ed9023dc7854258f9c17d5cbcfffcff2\n",
            ),
            (
                "service pf onestatus",
                "Status: Enabled for 1 day 00:00:00\n",
            ),
        ]);
        let records = plan
            .operations
            .iter()
            .map(|operation| {
                AdapterOperationEvidence::success(
                    operation,
                    outputs[operation.data_key.as_str()],
                    3,
                )
            })
            .collect();
        let collected_at = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .to_utc();
        let envelope = AdapterEvidenceEnvelope::seal(
            &plan,
            device.clone(),
            EvidenceTransportIdentity::SshHostKey {
                fingerprint: format!("SHA256:{}", "A".repeat(43)),
            },
            collected_at,
            records,
        )
        .unwrap();
        assert!(adapter.replay(&envelope).unwrap().completeness.complete);
        let check_pack_sha256 = plan.check_pack_sha256.clone();
        let evidence_sha256 = envelope.evidence_sha256.clone();
        let collection_plan_sha256 = plan.plan_sha256.clone();
        let evaluation_plan_sha256 = evaluation_plan_sha256(
            stig_id,
            revision,
            &benchmark_sha256,
            &check_pack_sha256,
            None,
        )
        .unwrap();

        let mut checklist = Checklist::new(
            Asset::new("device-1"),
            ChecklistStigInfo {
                stig_id: stig_id.to_string(),
                title: "General Purpose Operating System STIG".to_string(),
                version: "3".to_string(),
                release: "3".to_string(),
                release_date: Some("2026-01-01".to_string()),
                uuid: None,
                description: None,
                filename: None,
            },
        );
        checklist.generated_by = "AutomateSTIG 0.3.0".to_string();
        checklist.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::EvidenceFile,
            collection_complete: true,
            collection_errors: Vec::new(),
            evidence_sha256: Some(evidence_sha256.clone()),
            claimed_hostname: Some("device-1".to_string()),
            collector_version: Some("test".to_string()),
            collected_at: Some("2026-01-01T00:00:00Z".to_string()),
            plan_sha256: Some(collection_plan_sha256.clone()),
            server_key_fingerprint: None,
            benchmark_sha256: Some(benchmark_sha256.clone()),
            check_pack_sha256: Some(check_pack_sha256.clone()),
            evaluation_plan_sha256: Some(evaluation_plan_sha256.clone()),
            organization_policy: None,
            answer_file: None,
            answer_files: Vec::new(),
            unsafe_legacy_evidence: false,
        });
        let mut finding = Finding::new_not_reviewed(
            "V-1",
            "SV-1r1_rule",
            "V-1",
            "Example rule",
            Severity::Medium,
        );
        finding.status = FindingStatus::Open;
        finding.source = FindingSource::Evidence;
        finding.finding_details = "Condition satisfied: false".to_string();
        finding.comments = format!("Evidence SHA-256: {evidence_sha256}");
        finding.evaluated_at = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .to_utc();
        checklist.findings.push(finding);

        let reviews = sparse_scanner_reviews(&checklist);
        let envelope_compact = serde_json::to_vec(&envelope).unwrap();
        let envelope_pretty = serde_json::to_vec_pretty(&envelope).unwrap();
        let artifact = StoredRunArtifact {
            schema: RUN_SCHEMA.to_string(),
            mode: RunMode::Disconnected,
            profile_id: adapter.target_key().to_string(),
            collection_method: "evidence".to_string(),
            destination: None,
            destination_asset_name: None,
            endpoint: None,
            device: device.clone(),
            collection_complete: true,
            collection_errors: Vec::new(),
            manual_untouched: 0,
            out_of_scope_untouched: Some(0),
            checklist: checklist.clone(),
            reviews: reviews.clone(),
            delivery_preview: DeliveryPreview {
                counts: DeliveryPreviewCounts::default(),
                reviews: reviews
                    .iter()
                    .map(|review| DeliveryPreviewReview {
                        rule_id: review.rule_id.clone(),
                        result: review.result,
                        change: "handoff".to_string(),
                        evidence_summary: review.detail.clone(),
                    })
                    .collect(),
                manual_untouched: 0,
                out_of_scope_untouched: Some(0),
                warning: Some("Ownership is checked at the destination".to_string()),
            },
            evidence: StoredEvidenceReference {
                envelope_schema: TARGET_ADAPTER_EVIDENCE_SCHEMA.to_string(),
                evidence_sha256: evidence_sha256.clone(),
                envelope_json_sha256: sha256_hex(&envelope_compact),
                profile_sha256: plan.profile_sha256.clone(),
                device_fingerprint_sha256: device.sha256().unwrap(),
                collection_plan_sha256,
            },
        };
        let scanner_run = serde_json::to_vec_pretty(&artifact).unwrap();
        let compact_result = serde_json::to_vec(&artifact).unwrap();
        let sparse_reviews = serde_json::to_vec_pretty(&reviews).unwrap();
        let fallback = automatestig_parsers::cklb::write_cklb(&checklist)
            .unwrap()
            .into_bytes();
        let manifest = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": HANDOFF_SCHEMA_V2,
            "run_id": "11111111-2222-4333-8444-555555555555",
            "created_at": "2026-01-01T00:00:00Z",
            "scanner_version": "0.3.0",
            "stig_id": stig_id,
            "stig_revision": revision,
            "files": {
                "scanner-run.json": sha256_hex(&scanner_run),
                "sparse-reviews.json": sha256_hex(&sparse_reviews),
                "fallback.cklb": sha256_hex(&fallback),
                "evidence-envelope.json": sha256_hex(&envelope_pretty),
            },
            "scope": {
                "scanner_owned_reviews_included": reviews.len(),
                "unreviewed_and_non_scanner_rules_excluded": 0,
                "ownership_safe_sparse_handoff": true,
            },
            "evidence": {
                "state": "retained",
                "included": true,
                "sha256": evidence_sha256.clone(),
                "expires_at": "2027-01-01T00:00:00Z",
                "purged_at": null,
                "purge_reason": null,
            },
            "bindings": {
                "request_sha256": digest('1'),
                "result_sha256": sha256_hex(&compact_result),
                "benchmark_sha256": benchmark_sha256,
                "check_pack_sha256": check_pack_sha256,
                "evaluation_plan_sha256": evaluation_plan_sha256,
                "evidence_sha256": evidence_sha256,
            },
            "note": "Selected scanner-run handoff",
        }))
        .unwrap();
        let integrity = serde_json::to_vec_pretty(&serde_json::json!({
            "algorithm": "sha256",
            "manifest_sha256": sha256_hex(&manifest),
        }))
        .unwrap();

        BTreeMap::from([
            ("manifest.json".to_string(), manifest),
            ("integrity.json".to_string(), integrity),
            ("scanner-run.json".to_string(), scanner_run),
            ("sparse-reviews.json".to_string(), sparse_reviews),
            ("fallback.cklb".to_string(), fallback),
            (EVIDENCE_ENTRY.to_string(), envelope_pretty),
        ])
    }

    fn valid_purged_bundle_entries() -> BTreeMap<String, Vec<u8>> {
        let mut entries = valid_bundle_entries();
        entries.remove(EVIDENCE_ENTRY);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(entries.get("manifest.json").unwrap()).unwrap();
        manifest["files"]
            .as_object_mut()
            .unwrap()
            .remove(EVIDENCE_ENTRY);
        manifest["evidence"]["state"] = serde_json::json!("purged");
        manifest["evidence"]["included"] = serde_json::json!(false);
        manifest["evidence"]["purged_at"] = serde_json::json!("2026-06-01T00:00:00Z");
        manifest["evidence"]["purge_reason"] = serde_json::json!("retention_expired");
        let manifest = serde_json::to_vec_pretty(&manifest).unwrap();
        entries.insert("manifest.json".to_string(), manifest.clone());
        entries.insert(
            "integrity.json".to_string(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "algorithm": "sha256",
                "manifest_sha256": sha256_hex(&manifest),
            }))
            .unwrap(),
        );
        entries
    }

    fn valid_v3_bundle_entries() -> BTreeMap<String, Vec<u8>> {
        let mut entries = valid_bundle_entries();
        let artifact: StoredRunArtifact =
            serde_json::from_slice(entries.get("scanner-run.json").unwrap()).unwrap();
        let reviews: Vec<ScannerReview> =
            serde_json::from_slice(entries.get("sparse-reviews.json").unwrap()).unwrap();
        let mut manifest: serde_json::Value =
            serde_json::from_slice(entries.get("manifest.json").unwrap()).unwrap();
        let provenance = XccdfResultsProvenance {
            run_id: manifest["run_id"].as_str().unwrap().to_string(),
            profile_id: artifact.profile_id.clone(),
            scanner_version: manifest["scanner_version"].as_str().unwrap().to_string(),
            scan_source: "evidence".to_string(),
            collection_method: artifact.collection_method.clone(),
            collection_complete: true,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: "2026-01-01T00:00:00Z".to_string(),
            request_sha256: manifest["bindings"]["request_sha256"]
                .as_str()
                .unwrap()
                .to_string(),
            result_sha256: manifest["bindings"]["result_sha256"]
                .as_str()
                .unwrap()
                .to_string(),
            profile_sha256: artifact.evidence.profile_sha256.clone(),
            benchmark_sha256: manifest["bindings"]["benchmark_sha256"]
                .as_str()
                .unwrap()
                .to_string(),
            benchmark_model_sha256: digest('4'),
            source_archive_sha256: digest('5'),
            source_xccdf_sha256: digest('6'),
            check_pack_sha256: manifest["bindings"]["check_pack_sha256"]
                .as_str()
                .unwrap()
                .to_string(),
            evaluation_plan_sha256: manifest["bindings"]["evaluation_plan_sha256"]
                .as_str()
                .unwrap()
                .to_string(),
            evidence_sha256: manifest["bindings"]["evidence_sha256"]
                .as_str()
                .unwrap()
                .to_string(),
            collection_plan_sha256: artifact.evidence.collection_plan_sha256.clone(),
            source_url: "https://public.cyber.mil/example.zip".to_string(),
            source_member: "example-xccdf.xml".to_string(),
            coverage_manifest: "content/scanner_profiles/freebsd_gpos.coverage.json".to_string(),
            coverage_manifest_sha256: digest('7'),
        };
        let rule_ids: Vec<_> = reviews
            .iter()
            .map(|review| review.rule_id.clone())
            .collect();
        let xccdf =
            write_sparse_xccdf_1_2_results(&artifact.checklist, &rule_ids, &provenance).unwrap();
        entries.insert(XCCDF_ENTRY.to_string(), xccdf.clone());
        manifest["schema"] = serde_json::json!(HANDOFF_SCHEMA_V3);
        manifest["files"][XCCDF_ENTRY] = serde_json::json!(sha256_hex(&xccdf));
        let manifest = serde_json::to_vec_pretty(&manifest).unwrap();
        entries.insert("manifest.json".to_string(), manifest.clone());
        entries.insert(
            "integrity.json".to_string(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "algorithm": "sha256",
                "manifest_sha256": sha256_hex(&manifest),
            }))
            .unwrap(),
        );
        entries
    }

    fn zip_bytes(entries: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, bytes) in entries {
                writer.start_file(name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn verify_entries(entries: &BTreeMap<String, Vec<u8>>) -> Result<HandoffVerification> {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("handoff.zip");
        std::fs::write(&path, zip_bytes(entries)).unwrap();
        verify_handoff(&path)
    }

    fn verify_zip_bytes(bytes: &[u8]) -> Result<HandoffVerification> {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("handoff.zip");
        std::fs::write(&path, bytes).unwrap();
        verify_handoff(&path)
    }

    fn write_bundle(root: &Path, name: &str, entries: &BTreeMap<String, Vec<u8>>) -> PathBuf {
        let path = root.join(name);
        std::fs::write(&path, zip_bytes(entries)).unwrap();
        path
    }

    fn test_cli(root: &Path) -> crate::Cli {
        crate::Cli {
            verbose: false,
            library: Some(root.join("managed-library").display().to_string()),
            db: Some(root.join("managed-data.db").display().to_string()),
            command: crate::Commands::Status,
        }
    }

    fn signed_fixture(
        temporary: &tempfile::TempDir,
        prefix: &str,
        entries: &BTreeMap<String, Vec<u8>>,
    ) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = temporary.path();
        let zip_path = write_bundle(root, &format!("{prefix}.zip"), entries);
        let trust_dir = root.join(format!("{prefix}-handoff-trust"));
        std::fs::create_dir(&trust_dir).unwrap();
        let private_path = trust_dir.join(format!("{prefix}-producer.key"));
        let public_path = private_path.with_extension("pub");
        automatestig_stigpack::signing::create_signing_key_pair(&private_path, &public_path)
            .unwrap();
        let signature_path = root.join(format!("{prefix}.zip.signature.json"));
        sign_handoff(
            zip_path.to_str().unwrap(),
            private_path.to_str().unwrap(),
            signature_path.to_str().unwrap(),
            &test_cli(root),
        )
        .unwrap();
        (zip_path, signature_path, trust_dir, private_path)
    }

    fn rebind_manifest(entries: &mut BTreeMap<String, Vec<u8>>) {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(entries.get("manifest.json").unwrap()).unwrap();
        for name in [
            "scanner-run.json",
            "sparse-reviews.json",
            "fallback.cklb",
            XCCDF_ENTRY,
        ] {
            let Some(bytes) = entries.get(name) else {
                continue;
            };
            manifest["files"][name] = serde_json::Value::String(sha256_hex(bytes));
        }
        let manifest = serde_json::to_vec_pretty(&manifest).unwrap();
        let integrity = serde_json::to_vec_pretty(&serde_json::json!({
            "algorithm": "sha256",
            "manifest_sha256": sha256_hex(&manifest),
        }))
        .unwrap();
        entries.insert("manifest.json".to_string(), manifest);
        entries.insert("integrity.json".to_string(), integrity);
    }

    #[test]
    fn valid_bundle_verifies_integrity_but_not_authenticity() {
        let verified = verify_entries(&valid_bundle_entries()).unwrap();
        assert_eq!(verified.handoff_schema, HANDOFF_SCHEMA_V2);
        assert_eq!(verified.review_count, 1);
        assert_eq!(verified.stig_revision, "V3R3");
        assert!(verified.evidence_included);
        assert!(!verified.producer_authenticity_verified);
    }

    #[test]
    fn v3_bundle_verifies_sparse_xccdf_and_legacy_v2_remains_supported() {
        let verified = verify_entries(&valid_v3_bundle_entries()).unwrap();
        assert_eq!(verified.handoff_schema, HANDOFF_SCHEMA_V3);
        assert_eq!(verified.review_count, 1);

        let mut entries = valid_v3_bundle_entries();
        let xml = String::from_utf8(entries.remove(XCCDF_ENTRY).unwrap())
            .unwrap()
            .replace(
                "<cdf:result>fail</cdf:result>",
                "<cdf:result>pass</cdf:result>",
            );
        entries.insert(XCCDF_ENTRY.to_string(), xml.into_bytes());
        rebind_manifest(&mut entries);
        let error = verify_entries(&entries).unwrap_err().to_string();
        assert!(error.contains("rule IDs/results do not exactly match"));
    }

    #[test]
    fn purged_result_only_bundle_remains_verifiable() {
        let verified = verify_entries(&valid_purged_bundle_entries()).unwrap();
        assert_eq!(verified.review_count, 1);
        assert!(!verified.evidence_included);
        assert!(!verified.producer_authenticity_verified);
    }

    #[test]
    fn trusted_detached_signatures_authenticate_retained_and_purged_handoffs() {
        for (prefix, entries, evidence_included) in [
            ("retained", valid_bundle_entries(), true),
            ("purged", valid_purged_bundle_entries(), false),
            ("v3", valid_v3_bundle_entries(), true),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let (zip_path, signature_path, trust_dir, _) =
                signed_fixture(&temporary, prefix, &entries);
            let verified =
                verify_handoff_with_signature(&zip_path, &signature_path, &trust_dir).unwrap();
            assert!(verified.producer_authenticity_verified);
            assert_eq!(
                verified.producer_signer_label.as_deref(),
                Some(&format!("{prefix}-producer")[..])
            );
            assert!(verified
                .producer_signer_fingerprint
                .as_deref()
                .is_some_and(|value| value.starts_with("SHA256:")));
            assert_eq!(verified.evidence_included, evidence_included);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&signature_path)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn signed_verification_rejects_untrusted_keys_and_sidecar_substitution() {
        let temporary = tempfile::tempdir().unwrap();
        let (retained_zip, retained_signature, retained_trust, _) =
            signed_fixture(&temporary, "retained", &valid_bundle_entries());
        let (purged_zip, _, purged_trust, _) =
            signed_fixture(&temporary, "purged", &valid_purged_bundle_entries());

        let error =
            verify_handoff_with_signature(&retained_zip, &retained_signature, &purged_trust)
                .unwrap_err()
                .to_string();
        assert!(error.contains("does not match any explicitly trusted key"));

        let error =
            verify_handoff_with_signature(&purged_zip, &retained_signature, &retained_trust)
                .unwrap_err()
                .to_string();
        assert!(error.contains("bound to handoff SHA-256"));
    }

    #[test]
    fn signed_verification_rejects_malformed_or_rebound_signature_envelopes() {
        let temporary = tempfile::tempdir().unwrap();
        let (zip_path, signature_path, trust_dir, private_path) =
            signed_fixture(&temporary, "strict", &valid_bundle_entries());
        let original = std::fs::read(&signature_path).unwrap();

        let mut unknown: serde_json::Value = serde_json::from_slice(&original).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        std::fs::write(&signature_path, serde_json::to_vec(&unknown).unwrap()).unwrap();
        let error = verify_handoff_with_signature(&zip_path, &signature_path, &trust_dir)
            .unwrap_err()
            .to_string();
        assert!(error.contains("malformed JSON"));

        let mut short: HandoffSignatureEnvelope = serde_json::from_slice(&original).unwrap();
        short.signature = "00".to_string();
        std::fs::write(&signature_path, serde_json::to_vec(&short).unwrap()).unwrap();
        let error = verify_handoff_with_signature(&zip_path, &signature_path, &trust_dir)
            .unwrap_err()
            .to_string();
        assert!(error.contains("128 lowercase hexadecimal"));

        let mut rebound: HandoffSignatureEnvelope = serde_json::from_slice(&original).unwrap();
        rebound.run_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_string();
        let (private_key, _) = automatestig_stigpack::signing::load_signing_key_pair(
            &private_path,
            &private_path.with_extension("pub"),
        )
        .unwrap();
        rebound.signature = lower_hex(
            &automatestig_stigpack::signing::sign_manifest(
                &handoff_signature_statement(&rebound),
                &private_key,
            )
            .unwrap(),
        );
        std::fs::write(&signature_path, serde_json::to_vec(&rebound).unwrap()).unwrap();
        let error = verify_handoff_with_signature(&zip_path, &signature_path, &trust_dir)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match handoff run ID"));
    }

    #[test]
    fn cross_purpose_or_fingerprint_rebinding_signatures_are_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let (zip_path, signature_path, trust_dir, private_path) =
            signed_fixture(&temporary, "domain", &valid_bundle_entries());
        let original = std::fs::read(&signature_path).unwrap();
        let (private_key, _) = automatestig_stigpack::signing::load_signing_key_pair(
            &private_path,
            &private_path.with_extension("pub"),
        )
        .unwrap();

        let mut cross_purpose: HandoffSignatureEnvelope =
            serde_json::from_slice(&original).unwrap();
        cross_purpose.signature = lower_hex(
            &automatestig_stigpack::signing::sign_manifest(b"manifest.json", &private_key).unwrap(),
        );
        std::fs::write(&signature_path, serde_json::to_vec(&cross_purpose).unwrap()).unwrap();
        let error = verify_handoff_with_signature(&zip_path, &signature_path, &trust_dir)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match any explicitly trusted key"));

        let mut rebound: HandoffSignatureEnvelope = serde_json::from_slice(&original).unwrap();
        rebound.signing_key_fingerprint = format!("SHA256:{}", "0".repeat(64));
        rebound.signature = lower_hex(
            &automatestig_stigpack::signing::sign_manifest(
                &handoff_signature_statement(&rebound),
                &private_key,
            )
            .unwrap(),
        );
        std::fs::write(&signature_path, serde_json::to_vec(&rebound).unwrap()).unwrap();
        let error = verify_handoff_with_signature(&zip_path, &signature_path, &trust_dir)
            .unwrap_err()
            .to_string();
        assert!(error.contains("key identity mismatch"));
    }

    #[test]
    fn signing_refuses_invalid_input_overwrite_and_input_aliases() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let trust_dir = root.join("handoff-trust");
        std::fs::create_dir(&trust_dir).unwrap();
        let private_path = trust_dir.join("producer.key");
        automatestig_stigpack::signing::create_signing_key_pair(
            &private_path,
            &private_path.with_extension("pub"),
        )
        .unwrap();
        let invalid = root.join("invalid.zip");
        std::fs::write(&invalid, b"not a ZIP").unwrap();
        let output = root.join("invalid.signature.json");
        let error = sign_handoff(
            invalid.to_str().unwrap(),
            private_path.to_str().unwrap(),
            output.to_str().unwrap(),
            &test_cli(root),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("Refusing to sign"));
        assert!(!output.exists());

        let zip_path = write_bundle(root, "valid.zip", &valid_bundle_entries());
        let signature_path = root.join("valid.signature.json");
        sign_handoff(
            zip_path.to_str().unwrap(),
            private_path.to_str().unwrap(),
            signature_path.to_str().unwrap(),
            &test_cli(root),
        )
        .unwrap();
        let original = std::fs::read(&signature_path).unwrap();
        assert!(sign_handoff(
            zip_path.to_str().unwrap(),
            private_path.to_str().unwrap(),
            signature_path.to_str().unwrap(),
            &test_cli(root),
        )
        .is_err());
        assert_eq!(std::fs::read(&signature_path).unwrap(), original);

        let alias_error = sign_handoff(
            zip_path.to_str().unwrap(),
            private_path.to_str().unwrap(),
            zip_path.to_str().unwrap(),
            &test_cli(root),
        )
        .unwrap_err()
        .to_string();
        assert!(alias_error.contains("would replace consumed input"));
    }

    #[test]
    fn signing_key_generation_refuses_managed_state() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let cli = test_cli(root);
        let managed_library = root.join("managed-library");
        std::fs::create_dir(&managed_library).unwrap();
        let private_path = managed_library.join("producer.key");

        let error = generate_signing_key(private_path.to_str().unwrap(), &cli)
            .unwrap_err()
            .to_string();
        assert!(error.contains("inside the AutomateSTIG library"));
        assert!(!private_path.exists());
        assert!(!private_path.with_extension("pub").exists());
    }

    #[test]
    fn signed_verification_requires_a_nonempty_safe_handoff_trust_store() {
        let temporary = tempfile::tempdir().unwrap();
        let (zip_path, signature_path, _, _) =
            signed_fixture(&temporary, "trust", &valid_bundle_entries());
        let empty = temporary.path().join("empty-trust");
        std::fs::create_dir(&empty).unwrap();
        let error = verify_handoff_with_signature(&zip_path, &signature_path, &empty)
            .unwrap_err()
            .to_string();
        assert!(error.contains("No trusted handoff-signing keys"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o777)).unwrap();
            let error = verify_handoff_with_signature(&zip_path, &signature_path, &empty)
                .unwrap_err()
                .to_string();
            assert!(error.contains("Failed to load handoff trust store"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn signing_and_signed_verification_reject_symlink_artifacts() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let (zip_path, signature_path, trust_dir, private_path) =
            signed_fixture(&temporary, "symlink", &valid_bundle_entries());
        let signature_link = temporary.path().join("signature-link.json");
        symlink(&signature_path, &signature_link).unwrap();
        let error = verify_handoff_with_signature(&zip_path, &signature_link, &trust_dir)
            .unwrap_err()
            .to_string();
        assert!(error.contains("regular, non-symlink"));

        let zip_link = temporary.path().join("handoff-link.zip");
        symlink(&zip_path, &zip_link).unwrap();
        let linked_output = temporary.path().join("linked-input.signature.json");
        let error = sign_handoff(
            zip_link.to_str().unwrap(),
            private_path.to_str().unwrap(),
            linked_output.to_str().unwrap(),
            &test_cli(temporary.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("regular, non-symlink"));
        assert!(!linked_output.exists());

        let victim = temporary.path().join("victim.json");
        std::fs::write(&victim, b"preserve me").unwrap();
        let output_link = temporary.path().join("output-link.json");
        symlink(&victim, &output_link).unwrap();
        assert!(sign_handoff(
            zip_path.to_str().unwrap(),
            private_path.to_str().unwrap(),
            output_link.to_str().unwrap(),
            &test_cli(temporary.path()),
        )
        .is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve me");
    }

    #[test]
    fn tampered_file_fails_before_semantic_use() {
        let mut entries = valid_bundle_entries();
        entries.get_mut("sparse-reviews.json").unwrap().push(b' ');
        let error = verify_entries(&entries).unwrap_err().to_string();
        assert!(error.contains("SHA-256 mismatch for sparse-reviews.json"));
    }

    #[test]
    fn traversal_and_non_contract_entries_fail_closed() {
        let mut entries = valid_bundle_entries();
        let fallback = entries.remove("fallback.cklb").unwrap();
        entries.insert("../fallback.cklb".to_string(), fallback);
        let error = verify_entries(&entries).unwrap_err().to_string();
        assert!(error.contains("Unsafe or malformed ZIP"));
    }

    #[test]
    fn duplicate_archive_names_fail_closed() {
        let entries = valid_bundle_entries();
        let mut bytes = zip_bytes(&entries);
        let original = b"fallback.cklb";
        let duplicate = b"manifest.json";
        assert_eq!(original.len(), duplicate.len());
        let mut replacements = 0;
        for index in 0..=bytes.len() - original.len() {
            if &bytes[index..index + original.len()] == original {
                bytes[index..index + original.len()].copy_from_slice(duplicate);
                replacements += 1;
            }
        }
        assert_eq!(replacements, 2, "local and central names must be rewritten");
        let error = verify_zip_bytes(&bytes).unwrap_err().to_string();
        assert!(error.contains("Unsafe or malformed ZIP"));
    }

    #[test]
    fn per_file_size_limit_is_enforced_during_decompression() {
        let mut entries = valid_bundle_entries();
        entries.insert(
            "integrity.json".to_string(),
            vec![b' '; (MAX_INTEGRITY_BYTES + 1) as usize],
        );
        let error = verify_entries(&entries).unwrap_err().to_string();
        assert!(error.contains("Could not safely read integrity.json"));
    }

    #[test]
    fn fully_rehashed_not_reviewed_cklb_is_still_rejected() {
        let mut entries = valid_bundle_entries();
        let mut cklb: serde_json::Value =
            serde_json::from_slice(entries.get("fallback.cklb").unwrap()).unwrap();
        cklb["stigs"][0]["rules"][0]["status"] =
            serde_json::Value::String("not_reviewed".to_string());
        entries.insert(
            "fallback.cklb".to_string(),
            serde_json::to_vec_pretty(&cklb).unwrap(),
        );
        rebind_manifest(&mut entries);
        let error = verify_entries(&entries).unwrap_err().to_string();
        assert!(error.contains("manual/unowned rows are forbidden"));
    }

    #[test]
    fn fully_rehashed_manifest_rebinding_is_rejected() {
        let mut entries = valid_bundle_entries();
        let mut manifest: serde_json::Value =
            serde_json::from_slice(entries.get("manifest.json").unwrap()).unwrap();
        manifest["bindings"]["evidence_sha256"] = serde_json::Value::String(digest('9'));
        let manifest = serde_json::to_vec_pretty(&manifest).unwrap();
        let integrity = serde_json::to_vec_pretty(&serde_json::json!({
            "algorithm": "sha256",
            "manifest_sha256": sha256_hex(&manifest),
        }))
        .unwrap();
        entries.insert("manifest.json".to_string(), manifest);
        entries.insert("integrity.json".to_string(), integrity);
        let error = verify_entries(&entries).unwrap_err().to_string();
        assert!(error.contains("manifest evidence SHA-256 does not match"));
    }
}
