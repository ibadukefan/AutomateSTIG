//! Connected STIG Manager client for scanner-owned review delivery.
//!
//! This client deliberately exposes no asset creation, assignment mutation,
//! synchronization, or diff operations. STIG Manager remains authoritative for
//! collections, assets, assignments, and human review workflow.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use automatestig_core::models::checklist::Checklist;
use automatestig_core::models::finding::{FindingSource, FindingStatus};
use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

const AUTOMATESTIG_PRODUCT: &str = "AutomateSTIG";
const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_EXPIRY_SKEW: Duration = Duration::from_secs(30);
const MAX_COMMENTARY_CHARS: usize = 32_767;
const MAX_RULE_ID_CHARS: usize = 45;
/// Exact STIG Manager builds whose scanner lookup/readback contract has passed
/// the retained staging acceptance workflow. A nearby semantic version is not
/// silently treated as equivalent.
pub const TESTED_STIG_MANAGER_VERSIONS: &[&str] = &["1.6.13+1"];
pub const STIG_MANAGER_API_ADAPTER_ID: &str = "stig-manager-1.6-scanner-read-v1";

/// Non-secret connection settings safe to serialize, log, and return to a GUI.
///
/// `allowed_private_addresses` is retained as the exact-IP compatibility form
/// of the destination allowlist. When it is non-empty, it is a strict allowlist:
/// every address returned for both endpoints must match an entry. Use
/// [`StigManagerClient::new_with_destination_allowlist`] when exact hostnames or
/// CIDR ranges are required.
///
/// Without an allowlist, only ordinary globally routed addresses are accepted.
/// Invalid destinations always fail closed, and every private, special-use,
/// loopback, or link-local address requires an explicit IP/CIDR entry even when
/// its hostname is also allowlisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerConnection {
    /// STIG Manager API base URL, normally ending in `/api`.
    pub api_url: String,
    /// OAuth/OIDC client-credentials token endpoint.
    pub token_url: String,
    /// OAuth client identifier. This is not a client secret.
    pub client_id: String,
    /// Explicitly authorized non-global destination addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_private_addresses: Vec<IpAddr>,
}

impl StigManagerConnection {
    /// Validate the non-secret portion of a production connection.
    pub fn validate(&self) -> Result<(), StigManagerError> {
        validate_endpoint_url("STIG Manager API", &self.api_url)?;
        validate_endpoint_url("OAuth token", &self.token_url)?;
        if self.client_id.trim().is_empty() {
            return Err(StigManagerError::contract(
                "connection validation",
                "OAuth client_id must not be empty",
            ));
        }
        for address in &self.allowed_private_addresses {
            if automatestig_core::network_policy::classify_ip(*address)
                == automatestig_core::network_policy::IpScope::Invalid
            {
                return Err(StigManagerError::contract(
                    "connection validation",
                    format!("allowed destination address {address} is invalid or reserved"),
                ));
            }
        }
        Ok(())
    }
}

/// OAuth client secret that is redacted in debug output and zeroized on drop.
///
/// The type intentionally implements neither `Serialize` nor `Deserialize` so
/// it cannot accidentally become part of a persisted connection response.
pub struct StigManagerClientSecret(Zeroizing<String>);

impl StigManagerClientSecret {
    /// Wrap a client secret for use by [`StigManagerClient`].
    pub fn new(secret: impl Into<String>) -> Self {
        Self(Zeroizing::new(secret.into()))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for StigManagerClientSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StigManagerClientSecret([REDACTED])")
    }
}

/// Stable error categories callers can use to drive retry and user guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StigManagerErrorKind {
    /// Credentials, token acquisition, or authorization failed.
    Authentication,
    /// A network condition or server response may succeed on retry.
    Transient,
    /// Existing remote work prevents a safe scanner update.
    Conflict,
    /// STIG Manager explicitly rejected one or more review candidates.
    Rejected,
    /// The request, configuration, or server payload violates the API contract.
    Contract,
}

/// Whether the server exposes a review-write compare-and-swap primitive that
/// can atomically protect the ownership state observed during preflight.
///
/// STIG Manager 1.6.15 exposes unconditional merge writes and batch filters,
/// but no ETag, If-Match, review revision, or equivalent atomic precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionalReviewWriteSupport {
    /// No provable server-side conditional review-write contract is available.
    Unsupported,
}

/// A review candidate STIG Manager rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedReview {
    /// Rule identifier, when the server provided one.
    #[serde(rename = "ruleId", default)]
    pub rule_id: Option<String>,
    /// Server-provided rejection reason.
    #[serde(default)]
    pub reason: String,
}

/// Typed STIG Manager client failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StigManagerError {
    /// Authentication or authorization failed.
    #[error("STIG Manager authentication failed{status_suffix}: {message}", status_suffix = status_suffix(*.status))]
    Authentication {
        /// HTTP status when one was received.
        status: Option<u16>,
        /// Sanitized failure description.
        message: String,
    },
    /// Retryable transport or service failure.
    #[error("STIG Manager request is temporarily unavailable{status_suffix}: {message}", status_suffix = status_suffix(*.status))]
    Transient {
        /// HTTP status when one was received.
        status: Option<u16>,
        /// Sanitized failure description.
        message: String,
    },
    /// Delivery would overwrite remote work not owned by this scanner.
    #[error("STIG Manager delivery conflict: {message}")]
    Conflict {
        /// Conflict summary.
        message: String,
        /// Rule-level conflicts discovered before delivery.
        conflicts: Vec<ReviewConflict>,
    },
    /// STIG Manager rejected one or more reviews.
    #[error("STIG Manager rejected scanner reviews: {message}")]
    Rejected {
        /// Rejection summary.
        message: String,
        /// Rule-level server rejections, when available.
        rejected: Vec<RejectedReview>,
        /// Complete typed response for a successful HTTP request that both
        /// changed and rejected rows. Callers can reconcile partial writes.
        response: Option<Box<ScannerReviewWriteResponse>>,
        /// Receipt for rows the server reports as affected before rejecting
        /// other rows in the same request.
        receipt: Option<Box<ScannerDeliveryReceipt>>,
    },
    /// The server cannot atomically guarantee that a human review was not
    /// created or changed between ownership preflight and the proposed write.
    #[error("STIG Manager conditional scanner delivery is unsupported: {message}")]
    ConditionalWriteUnsupported {
        /// Actionable safety explanation.
        message: String,
        /// Scanner review rules that still require a remote write.
        pending_rules: Vec<String>,
        /// Exact remote no-ops that were safely omitted.
        unchanged: usize,
    },
    /// Local input or a remote response did not satisfy the expected contract.
    #[error("STIG Manager contract error during {operation}: {message}")]
    Contract {
        /// Operation that detected the contract violation.
        operation: String,
        /// Sanitized failure description.
        message: String,
    },
}

impl StigManagerError {
    /// Return the stable category for this failure.
    pub fn kind(&self) -> StigManagerErrorKind {
        match self {
            Self::Authentication { .. } => StigManagerErrorKind::Authentication,
            Self::Transient { .. } => StigManagerErrorKind::Transient,
            Self::Conflict { .. } => StigManagerErrorKind::Conflict,
            Self::Rejected { .. } => StigManagerErrorKind::Rejected,
            Self::ConditionalWriteUnsupported { .. } => StigManagerErrorKind::Conflict,
            Self::Contract { .. } => StigManagerErrorKind::Contract,
        }
    }

    /// Whether a delivery worker should retry without operator intervention.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }

    fn contract(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Contract {
            operation: operation.into(),
            message: message.into(),
        }
    }
}

fn status_suffix(status: Option<u16>) -> String {
    status.map_or_else(String::new, |value| format!(" (HTTP {value})"))
}

/// Source-control identity returned by `/op/configuration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerCommit {
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub describe: Option<String>,
    #[serde(default)]
    pub sha: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
}

/// Sanitized server configuration returned by `/op/configuration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerServerConfiguration {
    /// STIG Manager application version.
    pub version: String,
    /// Server classification banner value, when configured.
    #[serde(default)]
    pub classification: Option<String>,
    /// Source-control build identity, when published by the server.
    #[serde(default)]
    pub commit: Option<StigManagerCommit>,
    /// Latest applied database migration, when published by the server.
    #[serde(rename = "lastMigration", default)]
    pub last_migration: Option<u64>,
}

/// Scanner-delivery capabilities confirmed by the current API contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerCapabilities {
    /// Sanitized server version and deployment information.
    pub server: StigManagerServerConfiguration,
    /// Asset reads support `projection=stigs`.
    pub projected_asset_assignments: bool,
    /// Review reads support `rules=mapped`.
    pub mapped_review_reads: bool,
    /// Per-asset review writes accept a sparse array of scanner results.
    pub sparse_review_writes: bool,
    /// Atomic review ownership protection for human-safe delivery.
    pub conditional_review_writes: ConditionalReviewWriteSupport,
}

fn require_tested_stig_manager_version(version: &str) -> Result<(), StigManagerError> {
    let version = version.trim();
    if TESTED_STIG_MANAGER_VERSIONS.contains(&version) {
        return Ok(());
    }
    Err(StigManagerError::contract(
        "capability discovery",
        format!(
            "STIG Manager version {version:?} has no tested AutomateSTIG API adapter. Adapter {STIG_MANAGER_API_ADAPTER_ID} is limited to: {}. Use disconnected scanning and a verified selected-run handoff until this server version passes staging acceptance",
            TESTED_STIG_MANAGER_VERSIONS.join(", ")
        ),
    ))
}

/// A collection selectable as a scanner destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerCollection {
    #[serde(rename = "collectionId")]
    pub collection_id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Minimal asset collection reference from the projected asset response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerCollectionRef {
    #[serde(rename = "collectionId")]
    pub collection_id: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// An exact STIG assignment projected on an existing asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerAssignment {
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "revisionStr", alias = "lastRevisionStr")]
    pub revision: String,
    #[serde(rename = "benchmarkDate", default)]
    pub benchmark_date: Option<String>,
    #[serde(rename = "revisionPinned", default)]
    pub revision_pinned: bool,
    #[serde(rename = "ruleCount", default)]
    pub rule_count: Option<u64>,
}

/// Existing STIG Manager asset with its authoritative STIG assignments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerAssetProjection {
    #[serde(rename = "assetId")]
    pub asset_id: String,
    pub name: String,
    #[serde(default)]
    pub fqdn: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    pub collection: StigManagerCollectionRef,
    #[serde(default)]
    pub stigs: Vec<StigManagerAssignment>,
}

/// An exact, pre-selected STIG Manager destination for one scanner run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerDeliveryTarget {
    pub collection_id: String,
    pub asset_id: String,
    pub benchmark_id: String,
    pub revision: String,
}

/// Results that a completed scanner evaluation can deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScannerReviewResult {
    Pass,
    Fail,
    #[serde(rename = "notapplicable")]
    NotApplicable,
}

/// Whether the scanner collected evidence live or evaluated supplied evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerEvidenceSource {
    LiveCollection,
    SuppliedEvidence,
}

/// A single scanner-owned rule determination.
///
/// Delivery always supplies an AutomateSTIG result engine and a `saved` status;
/// callers cannot use this type to submit, accept, or reject reviews.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerReview {
    pub rule_id: String,
    pub result: ScannerReviewResult,
    pub detail: String,
    pub comment: String,
    pub evidence_source: ScannerEvidenceSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<String>,
}

/// Convert only completed evidence-owned checklist findings into sparse reviews.
///
/// Manual, imported, answer-file, collection-error, and Not Reviewed rows are
/// omitted and therefore cannot be asserted or cleared in STIG Manager.
pub fn sparse_scanner_reviews(checklist: &Checklist) -> Vec<ScannerReview> {
    checklist
        .findings
        .iter()
        .filter_map(|finding| {
            let evidence_source = match finding.source {
                FindingSource::Automated => ScannerEvidenceSource::LiveCollection,
                FindingSource::Evidence => ScannerEvidenceSource::SuppliedEvidence,
                FindingSource::Manual
                | FindingSource::Imported
                | FindingSource::AnswerFile
                | FindingSource::CollectionError => return None,
            };
            let result = match finding.status {
                FindingStatus::NotAFinding => ScannerReviewResult::Pass,
                FindingStatus::Open => ScannerReviewResult::Fail,
                FindingStatus::NotApplicable => ScannerReviewResult::NotApplicable,
                FindingStatus::NotReviewed => return None,
            };
            Some(ScannerReview {
                rule_id: finding.rule_id.clone(),
                result,
                detail: finding.finding_details.clone(),
                comment: finding.comments.clone(),
                evidence_source,
                evaluated_at: Some(finding.evaluated_at.to_rfc3339()),
            })
        })
        .collect()
}

/// STIG Manager review workflow state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewWorkflowStatus {
    Saved,
    Submitted,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewStatusRead {
    /// Current remote workflow label.
    pub label: ReviewWorkflowStatus,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReviewStatusWire {
    Label(ReviewWorkflowStatus),
    Object { label: ReviewWorkflowStatus },
}

impl<'de> Deserialize<'de> for ReviewStatusRead {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let label = match ReviewStatusWire::deserialize(deserializer)? {
            ReviewStatusWire::Label(label) | ReviewStatusWire::Object { label } => label,
        };
        Ok(Self { label })
    }
}

/// Result engine identity attached to a remote review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerResultEngine {
    #[serde(rename = "type")]
    pub engine_type: String,
    pub product: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub time: Option<String>,
}

/// Existing mapped review fields used for ownership, workflow protection, and
/// exact idempotency classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingMappedReview {
    pub asset_id: String,
    pub rule_id: String,
    pub result: String,
    pub auto_result: bool,
    pub detail: String,
    pub comment: String,
    pub status: ReviewStatusRead,
    pub result_engine: Option<StigManagerResultEngine>,
}

#[derive(Debug, Deserialize)]
struct ExistingMappedReviewWire {
    #[serde(rename = "assetId", default)]
    asset_id: Option<String>,
    #[serde(rename = "ruleId")]
    rule_id: String,
    result: String,
    #[serde(rename = "autoResult", default)]
    auto_result: bool,
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    detail: String,
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    comment: String,
    status: ReviewStatusRead,
    #[serde(rename = "resultEngine", default)]
    result_engine: Option<StigManagerResultEngine>,
}

impl ExistingMappedReviewWire {
    fn into_review(
        self,
        expected_asset_id: &str,
    ) -> Result<ExistingMappedReview, StigManagerError> {
        let asset_id = self
            .asset_id
            .unwrap_or_else(|| expected_asset_id.to_string());
        if asset_id != expected_asset_id {
            return Err(StigManagerError::contract(
                "list mapped reviews",
                format!(
                    "server returned review for asset {asset_id} while asset {expected_asset_id} was selected"
                ),
            ));
        }
        Ok(ExistingMappedReview {
            asset_id,
            rule_id: self.rule_id,
            result: self.result,
            auto_result: self.auto_result,
            detail: self.detail,
            comment: self.comment,
            status: self.status,
            result_engine: self.result_engine,
        })
    }
}

impl<'de> Deserialize<'de> for ExistingMappedReview {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ExistingMappedReviewWire::deserialize(deserializer)?;
        let asset_id = wire
            .asset_id
            .ok_or_else(|| serde::de::Error::missing_field("assetId"))?;
        Ok(Self {
            asset_id,
            rule_id: wire.rule_id,
            result: wire.result,
            auto_result: wire.auto_result,
            detail: wire.detail,
            comment: wire.comment,
            status: wire.status,
            result_engine: wire.result_engine,
        })
    }
}

fn deserialize_nullable_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

/// Why a remote review cannot be safely replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewConflictKind {
    HumanOrUnowned,
    Submitted,
    Accepted,
    Rejected,
}

/// Rule-level conflict protecting existing STIG Manager work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewConflict {
    pub rule_id: String,
    pub kind: ReviewConflictKind,
    pub existing_result: String,
    pub existing_status: ReviewWorkflowStatus,
    pub existing_engine: Option<String>,
}

/// Classify proposed reviews against mapped STIG Manager reviews.
///
/// Only a `saved` review whose result engine product is AutomateSTIG is
/// scanner-owned. `autoResult=true` by itself never establishes ownership.
pub fn classify_review_conflicts(
    proposed: &[ScannerReview],
    existing: &[ExistingMappedReview],
) -> Vec<ReviewConflict> {
    let proposed_rules: HashSet<&str> = proposed
        .iter()
        .map(|review| review.rule_id.as_str())
        .collect();

    existing
        .iter()
        .filter(|review| proposed_rules.contains(review.rule_id.as_str()))
        .filter_map(|review| {
            let engine = review
                .result_engine
                .as_ref()
                .map(|engine| engine.product.clone());
            let owned = review.status.label == ReviewWorkflowStatus::Saved
                && engine
                    .as_deref()
                    .is_some_and(|product| product.eq_ignore_ascii_case(AUTOMATESTIG_PRODUCT));
            if owned {
                return None;
            }
            let kind = match review.status.label {
                ReviewWorkflowStatus::Saved => ReviewConflictKind::HumanOrUnowned,
                ReviewWorkflowStatus::Submitted => ReviewConflictKind::Submitted,
                ReviewWorkflowStatus::Accepted => ReviewConflictKind::Accepted,
                ReviewWorkflowStatus::Rejected => ReviewConflictKind::Rejected,
            };
            Some(ReviewConflict {
                rule_id: review.rule_id.clone(),
                kind,
                existing_result: review.result.clone(),
                existing_status: review.status.label,
                existing_engine: engine,
            })
        })
        .collect()
}

fn normalized_review_result(result: &str) -> String {
    let normalized: String = result
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    match normalized.as_str() {
        "notafinding" => "pass".to_string(),
        "open" => "fail".to_string(),
        "na" => "notapplicable".to_string(),
        _ => normalized,
    }
}

fn scanner_result_name(result: ScannerReviewResult) -> &'static str {
    match result {
        ScannerReviewResult::Pass => "pass",
        ScannerReviewResult::Fail => "fail",
        ScannerReviewResult::NotApplicable => "notapplicable",
    }
}

/// Return true only when a proposed scanner review is byte-semantically
/// identical to the normalized saved AutomateSTIG review already remote.
/// Preview and delivery share this predicate so the UI never labels a detail,
/// comment, source, workflow, or engine change as an unchanged replay.
pub fn scanner_review_is_exact_noop(
    proposed: &ScannerReview,
    existing: &ExistingMappedReview,
) -> bool {
    let write = ReviewWrite::from(proposed);
    normalized_review_result(&existing.result) == scanner_result_name(write.result)
        && existing.detail == write.detail
        && existing.comment == write.comment
        && existing.auto_result == write.auto_result
        && existing.status.label == ReviewWorkflowStatus::Saved
        && existing.result_engine.as_ref() == Some(&write.result_engine)
}

/// STIG Manager result-write statistics captured as a delivery receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerDeliveryReceipt {
    pub collection_id: String,
    pub asset_id: String,
    pub benchmark_id: String,
    pub revision: String,
    /// Scanner-owned review candidates considered for this attempt.
    pub reviews_considered: usize,
    /// Sparse review rows actually sent to STIG Manager.
    pub reviews_sent: usize,
    /// Exact remote no-ops omitted from the POST.
    pub unchanged: usize,
    pub inserted: u64,
    pub updated: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReviewWrite {
    #[serde(rename = "ruleId")]
    rule_id: String,
    result: ScannerReviewResult,
    detail: String,
    comment: String,
    #[serde(rename = "autoResult")]
    auto_result: bool,
    status: &'static str,
    #[serde(rename = "resultEngine")]
    result_engine: StigManagerResultEngine,
}

impl From<&ScannerReview> for ReviewWrite {
    fn from(review: &ScannerReview) -> Self {
        Self {
            rule_id: review.rule_id.clone(),
            result: review.result,
            // STIG Manager trims these values before storage. Normalize before
            // comparison and transport so an exact replay remains a no-op.
            detail: review.detail.trim_matches(' ').to_string(),
            comment: review.comment.trim_matches(' ').to_string(),
            auto_result: review.evidence_source == ScannerEvidenceSource::LiveCollection,
            status: "saved",
            result_engine: StigManagerResultEngine {
                engine_type: "script".to_string(),
                product: AUTOMATESTIG_PRODUCT.to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                time: review.evaluated_at.clone(),
            },
        }
    }
}

#[derive(Debug, Deserialize)]
struct ServerConfigurationWire {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    classification: Option<String>,
    #[serde(default)]
    commit: Option<StigManagerCommit>,
    #[serde(rename = "lastMigration", default)]
    last_migration: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AssetWire {
    #[serde(rename = "assetId", default)]
    asset_id: Option<String>,
    name: String,
    #[serde(default)]
    fqdn: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    collection: Option<StigManagerCollectionRef>,
    #[serde(rename = "collectionId", default)]
    legacy_collection_id: Option<String>,
    #[serde(default)]
    stigs: Vec<StigManagerAssignment>,
}

impl AssetWire {
    fn into_asset(
        self,
        expected_collection_id: &str,
        contextual_asset_id: Option<&str>,
    ) -> Result<StigManagerAssetProjection, StigManagerError> {
        let asset_id = match (self.asset_id, contextual_asset_id) {
            (Some(asset_id), Some(expected)) if asset_id != expected => {
                return Err(StigManagerError::contract(
                    "projected asset read",
                    format!("server returned asset {asset_id} while asset {expected} was selected"),
                ));
            }
            (Some(asset_id), _) => asset_id,
            (None, Some(expected)) => expected.to_string(),
            (None, None) => {
                return Err(StigManagerError::contract(
                    "projected asset read",
                    "asset list item omitted assetId without an endpoint context",
                ));
            }
        };
        let collection = self.collection.or_else(|| {
            self.legacy_collection_id
                .map(|collection_id| StigManagerCollectionRef {
                    collection_id,
                    name: None,
                })
        });
        let collection = collection.ok_or_else(|| {
            StigManagerError::contract(
                "projected asset read",
                format!("asset {asset_id} omitted its collection projection"),
            )
        })?;
        if collection.collection_id != expected_collection_id {
            return Err(StigManagerError::contract(
                "projected asset read",
                format!(
                    "asset {} belongs to collection {}, not selected collection {}",
                    asset_id, collection.collection_id, expected_collection_id
                ),
            ));
        }
        Ok(StigManagerAssetProjection {
            asset_id,
            name: self.name,
            fqdn: self.fqdn,
            ip: self.ip,
            mac: self.mac,
            collection,
            stigs: self.stigs,
        })
    }
}

/// Counts returned by STIG Manager for a sparse review merge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerReviewAffected {
    pub inserted: u64,
    pub updated: u64,
}

/// Full typed response returned by the per-asset sparse review endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerReviewWriteResponse {
    pub affected: ScannerReviewAffected,
    pub rejected: Vec<RejectedReview>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

struct TokenCache {
    access_token: Zeroizing<String>,
    expires_at: Instant,
}

struct ResolvedEndpoint {
    host: String,
    addresses: Vec<SocketAddr>,
}

/// Canonical connected client for scanner delivery to existing STIG Manager
/// assets and assignments.
pub struct StigManagerClient {
    connection: StigManagerConnection,
    client_secret: StigManagerClientSecret,
    api_http: reqwest::Client,
    token_http: reqwest::Client,
    token: Mutex<Option<TokenCache>>,
    capabilities: Mutex<Option<StigManagerCapabilities>>,
    // There is intentionally no production setter. This remains false until a
    // future, verified server contract supplies a real atomic precondition.
    conditional_review_writes: bool,
}

impl StigManagerClient {
    /// Resolve, authorize, and pin both endpoints, then create the client.
    pub async fn new(
        connection: StigManagerConnection,
        client_secret: StigManagerClientSecret,
    ) -> Result<Self, StigManagerError> {
        Self::new_with_destination_allowlist(connection, client_secret, Vec::<String>::new()).await
    }

    /// Resolve, authorize, and pin both endpoints under an exact hostname,
    /// IP, and/or CIDR allowlist.
    ///
    /// When any entry is configured, the allowlist is strict for both the API
    /// and OAuth endpoints, including globally routed addresses. Private,
    /// special-use, loopback, and link-local results must match an IP/CIDR
    /// entry; an allowlisted hostname alone never grants private-network reach.
    pub async fn new_with_destination_allowlist(
        connection: StigManagerConnection,
        client_secret: StigManagerClientSecret,
        allowed_destinations: impl IntoIterator<Item = String>,
    ) -> Result<Self, StigManagerError> {
        connection.validate()?;
        if client_secret.is_empty() {
            return Err(StigManagerError::contract(
                "connection validation",
                "OAuth client secret must not be empty",
            ));
        }
        let mut allowlist: Vec<String> = connection
            .allowed_private_addresses
            .iter()
            .map(ToString::to_string)
            .collect();
        for entry in allowed_destinations {
            let entry = entry.trim();
            if entry.is_empty() {
                return Err(StigManagerError::contract(
                    "destination authorization",
                    "destination allowlist entries must not be empty",
                ));
            }
            allowlist.push(entry.to_string());
        }
        validate_destination_allowlist(&allowlist)?;
        let api_endpoint =
            resolve_endpoint("STIG Manager API", &connection.api_url, &allowlist).await?;
        let token_endpoint =
            resolve_endpoint("OAuth token", &connection.token_url, &allowlist).await?;
        let api_http = build_http_client(&api_endpoint)?;
        let token_http = build_http_client(&token_endpoint)?;
        let client = Self {
            connection,
            client_secret,
            api_http,
            token_http,
            token: Mutex::new(None),
            capabilities: Mutex::new(None),
            conditional_review_writes: false,
        };
        // Every production client selects a tested API adapter before any
        // authenticated asset/review operation can occur.
        client.discover_capabilities().await?;
        Ok(client)
    }

    #[cfg(test)]
    fn new_for_mock(
        connection: StigManagerConnection,
        client_secret: StigManagerClientSecret,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("mock client");
        Self {
            connection,
            client_secret,
            api_http: client.clone(),
            token_http: client,
            token: Mutex::new(None),
            capabilities: Mutex::new(None),
            conditional_review_writes: false,
        }
    }

    #[cfg(test)]
    fn with_mock_conditional_review_writes(mut self) -> Self {
        // Mock servers use this only to exercise response/reconciliation code.
        // It is not a production claim about STIG Manager's API contract.
        self.conditional_review_writes = true;
        self
    }

    /// Return the sanitized connection without exposing the client secret or
    /// cached access token.
    pub fn connection(&self) -> &StigManagerConnection {
        &self.connection
    }

    /// Discover the unauthenticated server version and scanner delivery
    /// capabilities through the official `/op/configuration` endpoint.
    pub async fn discover_capabilities(&self) -> Result<StigManagerCapabilities, StigManagerError> {
        if let Some(capabilities) = self.capabilities.lock().await.clone() {
            return Ok(capabilities);
        }
        let url = self.api_url("op/configuration")?;
        let response = self
            .api_http
            .get(url)
            .send()
            .await
            .map_err(|error| transient_transport("capability discovery", error))?;
        let wire: ServerConfigurationWire =
            parse_response(response, "capability discovery", ResponsePurpose::Standard).await?;
        let version = wire
            .version
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                StigManagerError::contract(
                    "capability discovery",
                    "server response omitted its API version",
                )
            })?;
        require_tested_stig_manager_version(&version)?;
        let capabilities = StigManagerCapabilities {
            server: StigManagerServerConfiguration {
                version,
                classification: wire.classification,
                commit: wire.commit,
                last_migration: wire.last_migration,
            },
            projected_asset_assignments: true,
            mapped_review_reads: true,
            sparse_review_writes: true,
            conditional_review_writes: ConditionalReviewWriteSupport::Unsupported,
        };
        *self.capabilities.lock().await = Some(capabilities.clone());
        Ok(capabilities)
    }

    /// List collections visible to the OAuth principal.
    pub async fn list_collections(&self) -> Result<Vec<StigManagerCollection>, StigManagerError> {
        let url = self.api_url("collections")?;
        let response = self
            .send_authenticated(Method::GET, url, None, "list collections")
            .await?;
        parse_response(response, "list collections", ResponsePurpose::Standard).await
    }

    /// List existing assets and exact assignments in a collection.
    pub async fn list_assets(
        &self,
        collection_id: &str,
    ) -> Result<Vec<StigManagerAssetProjection>, StigManagerError> {
        let collection_id = numeric_id("collection ID", collection_id)?;
        let mut url = self.api_url("assets")?;
        url.query_pairs_mut()
            .append_pair("collectionId", &collection_id)
            .append_pair("projection", "stigs");
        let response = self
            .send_authenticated(Method::GET, url, None, "list projected assets")
            .await?;
        let assets: Vec<AssetWire> =
            parse_response(response, "list projected assets", ResponsePurpose::Standard).await?;
        assets
            .into_iter()
            .map(|asset| asset.into_asset(&collection_id, None))
            .collect()
    }

    /// Fetch one existing asset with exact STIG assignments.
    pub async fn get_asset(
        &self,
        collection_id: &str,
        asset_id: &str,
    ) -> Result<StigManagerAssetProjection, StigManagerError> {
        let collection_id = numeric_id("collection ID", collection_id)?;
        let asset_id = numeric_id("asset ID", asset_id)?;
        let mut url = self.api_url(&format!("assets/{asset_id}"))?;
        url.query_pairs_mut().append_pair("projection", "stigs");
        let response = self
            .send_authenticated(Method::GET, url, None, "get projected asset")
            .await?;
        let asset: AssetWire =
            parse_response(response, "get projected asset", ResponsePurpose::Standard).await?;
        asset.into_asset(&collection_id, Some(&asset_id))
    }

    /// Require an exact benchmark and revision assignment on an existing asset.
    pub async fn require_exact_assignment(
        &self,
        target: &ScannerDeliveryTarget,
    ) -> Result<StigManagerAssignment, StigManagerError> {
        validate_target(target)?;
        let asset = self
            .get_asset(&target.collection_id, &target.asset_id)
            .await?;
        exact_assignment(&asset, &target.benchmark_id, &target.revision)
    }

    /// Read mapped reviews for one existing asset. This is the ownership and
    /// workflow preflight for sparse delivery.
    pub async fn list_mapped_reviews(
        &self,
        collection_id: &str,
        asset_id: &str,
    ) -> Result<Vec<ExistingMappedReview>, StigManagerError> {
        let collection_id = numeric_id("collection ID", collection_id)?;
        let asset_id = numeric_id("asset ID", asset_id)?;
        let mut url = self.api_url(&format!("collections/{collection_id}/reviews"))?;
        url.query_pairs_mut()
            .append_pair("assetId", &asset_id)
            .append_pair("rules", "mapped");
        let response = self
            .send_authenticated(Method::GET, url, None, "list mapped reviews")
            .await?;
        let reviews: Vec<ExistingMappedReviewWire> =
            parse_response(response, "list mapped reviews", ResponsePurpose::Standard).await?;
        let reviews: Vec<ExistingMappedReview> = reviews
            .into_iter()
            .map(|review| review.into_review(&asset_id))
            .collect::<Result<_, _>>()?;
        let mut seen = HashSet::new();
        if let Some(review) = reviews
            .iter()
            .find(|review| !seen.insert(review.rule_id.as_str()))
        {
            return Err(StigManagerError::contract(
                "list mapped reviews",
                format!("server returned duplicate mapped rule {}", review.rule_id),
            ));
        }
        Ok(reviews)
    }

    /// Reconcile scanner-owned determinations against an exact existing
    /// assignment.
    ///
    /// Exact no-op replays complete without a POST. Any review that needs a
    /// remote change fails closed unless the client has verified a server-side
    /// conditional-write contract. Current supported STIG Manager releases do
    /// not expose such a contract, so this method never claims that a separate
    /// ownership preflight makes an unconditional merge race-free.
    pub async fn deliver_scanner_reviews(
        &self,
        target: &ScannerDeliveryTarget,
        reviews: &[ScannerReview],
    ) -> Result<ScannerDeliveryReceipt, StigManagerError> {
        validate_target(target)?;
        validate_scanner_reviews(reviews)?;
        self.require_exact_assignment(target).await?;

        let existing = self
            .list_mapped_reviews(&target.collection_id, &target.asset_id)
            .await?;
        let conflicts = classify_review_conflicts(reviews, &existing);
        if !conflicts.is_empty() {
            return Err(StigManagerError::Conflict {
                message: format!(
                    "{} proposed review(s) would replace work not owned by AutomateSTIG",
                    conflicts.len()
                ),
                conflicts,
            });
        }

        let collection_id = numeric_id("collection ID", &target.collection_id)?;
        let asset_id = numeric_id("asset ID", &target.asset_id)?;
        let existing_by_rule: HashMap<&str, &ExistingMappedReview> = existing
            .iter()
            .map(|review| (review.rule_id.as_str(), review))
            .collect();
        let mut unchanged = 0;
        let mut pending = Vec::new();
        for review in reviews {
            if existing_by_rule
                .get(review.rule_id.as_str())
                .is_some_and(|existing| scanner_review_is_exact_noop(review, existing))
            {
                unchanged += 1;
            } else {
                pending.push(review);
            }
        }
        if pending.is_empty() {
            return Ok(ScannerDeliveryReceipt {
                collection_id,
                asset_id,
                benchmark_id: target.benchmark_id.clone(),
                revision: target.revision.clone(),
                reviews_considered: reviews.len(),
                reviews_sent: 0,
                unchanged,
                inserted: 0,
                updated: 0,
            });
        }
        if !self.conditional_review_writes {
            return Err(StigManagerError::ConditionalWriteUnsupported {
                message: "the published review API has no ETag, If-Match, review revision, or equivalent atomic precondition; an unconditional merge could overwrite human work created after preflight".to_string(),
                pending_rules: pending
                    .iter()
                    .map(|review| review.rule_id.clone())
                    .collect(),
                unchanged,
            });
        }

        let url = self.api_url(&format!("collections/{collection_id}/reviews/{asset_id}"))?;
        let writes: Vec<ReviewWrite> = pending.into_iter().map(ReviewWrite::from).collect();
        let body = serde_json::to_value(&writes).map_err(|error| {
            StigManagerError::contract(
                "serialize sparse reviews",
                format!("could not serialize scanner reviews: {error}"),
            )
        })?;
        let response = self
            .send_authenticated(Method::POST, url, Some(body), "write sparse reviews")
            .await?;
        let response: ScannerReviewWriteResponse = parse_response(
            response,
            "write sparse reviews",
            ResponsePurpose::ReviewWrite,
        )
        .await?;
        let receipt = ScannerDeliveryReceipt {
            collection_id,
            asset_id,
            benchmark_id: target.benchmark_id.clone(),
            revision: target.revision.clone(),
            reviews_considered: reviews.len(),
            reviews_sent: writes.len(),
            unchanged,
            inserted: response.affected.inserted,
            updated: response.affected.updated,
        };
        if !response.rejected.is_empty() {
            return Err(StigManagerError::Rejected {
                message: format!(
                    "{} of {} scanner review(s) were rejected",
                    response.rejected.len(),
                    writes.len()
                ),
                rejected: response.rejected.clone(),
                response: Some(Box::new(response)),
                receipt: Some(Box::new(receipt)),
            });
        }
        let affected = response.affected.inserted + response.affected.updated;
        if affected > writes.len() as u64 {
            return Err(StigManagerError::contract(
                "write sparse reviews",
                format!(
                    "server reported {affected} affected review(s) for only {} submitted review(s)",
                    writes.len()
                ),
            ));
        }
        // Zero affected is legitimate: the remote value may already have
        // converged after our read. The typed receipt preserves what happened.
        Ok(receipt)
    }

    fn api_url(&self, path: &str) -> Result<Url, StigManagerError> {
        Url::parse(&format!(
            "{}/{}",
            self.connection.api_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        ))
        .map_err(|error| {
            StigManagerError::contract(
                "build API URL",
                format!("configured API URL cannot be extended: {error}"),
            )
        })
    }

    async fn access_token(&self) -> Result<Zeroizing<String>, StigManagerError> {
        let mut token = self.token.lock().await;
        if let Some(cached) = token.as_ref() {
            if Instant::now() < cached.expires_at {
                return Ok(Zeroizing::new(cached.access_token.to_string()));
            }
        }

        let parameters = [
            ("grant_type", "client_credentials"),
            ("client_id", self.connection.client_id.as_str()),
            ("client_secret", self.client_secret.expose()),
        ];
        let response = self
            .token_http
            .post(&self.connection.token_url)
            .form(&parameters)
            .send()
            .await
            .map_err(|error| transient_transport("OAuth token request", error))?;
        let token_response: TokenResponse = parse_response(
            response,
            "OAuth token request",
            ResponsePurpose::Authentication,
        )
        .await?;
        if token_response.access_token.trim().is_empty() {
            return Err(StigManagerError::Authentication {
                status: None,
                message: "token response contained an empty access token".to_string(),
            });
        }
        let ttl = Duration::from_secs(token_response.expires_in.unwrap_or(300));
        let effective_ttl = ttl.saturating_sub(TOKEN_EXPIRY_SKEW);
        let access_token = Zeroizing::new(token_response.access_token);
        let returned = Zeroizing::new(access_token.to_string());
        *token = Some(TokenCache {
            access_token,
            expires_at: Instant::now() + effective_ttl,
        });
        Ok(returned)
    }

    async fn clear_token(&self) {
        let mut token = self.token.lock().await;
        *token = None;
    }

    async fn send_authenticated(
        &self,
        method: Method,
        url: Url,
        body: Option<serde_json::Value>,
        operation: &str,
    ) -> Result<reqwest::Response, StigManagerError> {
        for attempt in 0..2 {
            let token = self.access_token().await?;
            let mut request = self
                .api_http
                .request(method.clone(), url.clone())
                .bearer_auth(token.as_str());
            if let Some(body) = &body {
                request = request.json(body);
            }
            let response = request
                .send()
                .await
                .map_err(|error| transient_transport(operation, error))?;
            if response.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.clear_token().await;
                continue;
            }
            return Ok(response);
        }
        Err(StigManagerError::Authentication {
            status: Some(StatusCode::UNAUTHORIZED.as_u16()),
            message: format!("{operation} remained unauthorized after token refresh"),
        })
    }
}

/// Find an exact assignment without accepting STIG Manager's `latest` alias or
/// silently substituting another benchmark revision.
pub fn exact_assignment(
    asset: &StigManagerAssetProjection,
    benchmark_id: &str,
    revision: &str,
) -> Result<StigManagerAssignment, StigManagerError> {
    if benchmark_id.trim().is_empty() || revision.trim().is_empty() {
        return Err(StigManagerError::contract(
            "exact assignment match",
            "benchmark ID and revision must not be empty",
        ));
    }
    let exact: Vec<&StigManagerAssignment> = asset
        .stigs
        .iter()
        .filter(|assignment| {
            assignment.benchmark_id == benchmark_id && assignment.revision == revision
        })
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0].clone());
    }
    if exact.len() > 1 {
        return Err(StigManagerError::contract(
            "exact assignment match",
            format!(
                "asset {} returned {} indistinguishable assignments for {benchmark_id} {revision}; refuse an ambiguous destination",
                asset.asset_id,
                exact.len()
            ),
        ));
    }
    let assigned_revisions: Vec<&str> = asset
        .stigs
        .iter()
        .filter(|assignment| assignment.benchmark_id == benchmark_id)
        .map(|assignment| assignment.revision.as_str())
        .collect();
    if assigned_revisions.is_empty() {
        return Err(StigManagerError::contract(
            "exact assignment match",
            format!(
                "asset {} is not assigned benchmark {benchmark_id}",
                asset.asset_id
            ),
        ));
    }
    Err(StigManagerError::contract(
        "exact assignment match",
        format!(
            "asset {} has {benchmark_id} revision(s) {}, not required revision {revision}",
            asset.asset_id,
            assigned_revisions.join(", ")
        ),
    ))
}

fn validate_target(target: &ScannerDeliveryTarget) -> Result<(), StigManagerError> {
    numeric_id("collection ID", &target.collection_id)?;
    numeric_id("asset ID", &target.asset_id)?;
    if target.benchmark_id.trim().is_empty() {
        return Err(StigManagerError::contract(
            "delivery target validation",
            "benchmark ID must not be empty",
        ));
    }
    if target.revision.trim().is_empty() || target.revision.eq_ignore_ascii_case("latest") {
        return Err(StigManagerError::contract(
            "delivery target validation",
            "an exact STIG revision is required; the latest alias is not accepted",
        ));
    }
    Ok(())
}

fn validate_scanner_reviews(reviews: &[ScannerReview]) -> Result<(), StigManagerError> {
    if reviews.is_empty() {
        return Err(StigManagerError::contract(
            "scanner review validation",
            "at least one completed scanner-owned review is required",
        ));
    }
    let mut seen = HashSet::new();
    for review in reviews {
        let rule_id = review.rule_id.trim();
        if rule_id.is_empty() || rule_id.chars().count() > MAX_RULE_ID_CHARS {
            return Err(StigManagerError::contract(
                "scanner review validation",
                format!("rule ID must contain between 1 and {MAX_RULE_ID_CHARS} characters"),
            ));
        }
        if !seen.insert(rule_id) {
            return Err(StigManagerError::contract(
                "scanner review validation",
                format!("duplicate scanner review for rule {rule_id}"),
            ));
        }
        if review.detail.chars().count() > MAX_COMMENTARY_CHARS
            || review.comment.chars().count() > MAX_COMMENTARY_CHARS
        {
            return Err(StigManagerError::contract(
                "scanner review validation",
                format!("detail and comment must not exceed {MAX_COMMENTARY_CHARS} characters"),
            ));
        }
    }
    Ok(())
}

fn numeric_id(label: &str, value: &str) -> Result<String, StigManagerError> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StigManagerError::contract(
            "identifier validation",
            format!("STIG Manager {label} must be a numeric identifier"),
        ));
    }
    Ok(value.to_string())
}

pub(super) fn validate_endpoint_url(label: &str, raw: &str) -> Result<Url, StigManagerError> {
    let url = Url::parse(raw).map_err(|error| {
        StigManagerError::contract(
            "connection validation",
            format!("invalid {label} URL: {error}"),
        )
    })?;
    if url.scheme() != "https" {
        return Err(StigManagerError::contract(
            "connection validation",
            format!("{label} must use https://"),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(StigManagerError::contract(
            "connection validation",
            format!("{label} must not contain embedded credentials"),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(StigManagerError::contract(
            "connection validation",
            format!("{label} must not contain a query or fragment"),
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        StigManagerError::contract(
            "connection validation",
            format!("{label} must contain a host"),
        )
    })?;
    let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized_host == "localhost"
        || normalized_host.ends_with(".localhost")
        || normalized_host == "metadata.google.internal"
        || normalized_host.ends_with(".metadata.google.internal")
    {
        return Err(StigManagerError::contract(
            "connection validation",
            format!("{label} host {host} is not an allowed service destination"),
        ));
    }
    Ok(url)
}

fn validate_destination_allowlist(entries: &[String]) -> Result<(), StigManagerError> {
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(StigManagerError::contract(
                "destination authorization",
                "destination allowlist entries must not be empty",
            ));
        }
        if let Ok(address) = entry.parse::<IpAddr>() {
            if automatestig_core::network_policy::classify_ip(address)
                == automatestig_core::network_policy::IpScope::Invalid
            {
                return Err(StigManagerError::contract(
                    "destination authorization",
                    format!("destination allowlist address {entry} is invalid or reserved"),
                ));
            }
            continue;
        }
        if let Some((base, prefix)) = entry.split_once('/') {
            let base = base.parse::<IpAddr>().map_err(|_| {
                StigManagerError::contract(
                    "destination authorization",
                    format!("destination allowlist CIDR {entry:?} has an invalid base address"),
                )
            })?;
            let prefix = prefix.parse::<u32>().map_err(|_| {
                StigManagerError::contract(
                    "destination authorization",
                    format!("destination allowlist CIDR {entry:?} has an invalid prefix"),
                )
            })?;
            let valid_prefix = match base {
                IpAddr::V4(_) => prefix <= 32,
                IpAddr::V6(_) => prefix <= 128,
            };
            if !valid_prefix {
                return Err(StigManagerError::contract(
                    "destination authorization",
                    format!("destination allowlist CIDR {entry:?} has an invalid prefix"),
                ));
            }
            continue;
        }
        if !valid_exact_hostname(entry) {
            return Err(StigManagerError::contract(
                "destination authorization",
                format!(
                    "destination allowlist entry {entry:?} must be an exact hostname, IP address, or CIDR"
                ),
            ));
        }
    }
    Ok(())
}

fn valid_exact_hostname(value: &str) -> bool {
    let value = value.trim_end_matches('.');
    if value.is_empty() || value.len() > 253 || value.contains('*') {
        return false;
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn ip_in_cidr(address: IpAddr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(base) = base.parse::<IpAddr>() else {
        return false;
    };
    let Ok(mut prefix) = prefix.parse::<u32>() else {
        return false;
    };
    let address = automatestig_core::network_policy::normalize_mapped_ip(address);
    let base = match base {
        IpAddr::V6(value) => {
            let Some(mapped) = value.to_ipv4_mapped() else {
                return match (address, value) {
                    (IpAddr::V6(address), base) if prefix <= 128 => {
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u128::MAX << (128 - prefix)
                        };
                        (u128::from(address) & mask) == (u128::from(base) & mask)
                    }
                    _ => false,
                };
            };
            if prefix < 96 {
                return false;
            }
            prefix -= 96;
            IpAddr::V4(mapped)
        }
        IpAddr::V4(value) => IpAddr::V4(value),
    };
    match (address, base) {
        (IpAddr::V4(address), IpAddr::V4(base)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(address) & mask) == (u32::from(base) & mask)
        }
        _ => false,
    }
}

fn allowlist_matches_host(host: &str, entries: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    entries.iter().any(|entry| {
        !entry.contains('/')
            && entry.parse::<IpAddr>().is_err()
            && host == entry.trim_end_matches('.').to_ascii_lowercase()
    })
}

fn allowlist_matches_ip(address: IpAddr, entries: &[String]) -> bool {
    let address = automatestig_core::network_policy::normalize_mapped_ip(address);
    entries.iter().any(|entry| {
        entry.parse::<IpAddr>().is_ok_and(|candidate| {
            automatestig_core::network_policy::normalize_mapped_ip(candidate) == address
        }) || ip_in_cidr(address, entry)
    })
}

fn authorize_resolved_endpoint(
    label: &str,
    host: &str,
    port: u16,
    resolved: impl IntoIterator<Item = SocketAddr>,
    allowlist: &[String],
) -> Result<ResolvedEndpoint, StigManagerError> {
    let host_allowlisted = allowlist_matches_host(host, allowlist);
    let mut addresses = Vec::new();
    for address in resolved {
        if address.port() != port {
            return Err(StigManagerError::contract(
                "destination authorization",
                format!(
                    "{label} resolver returned unexpected port {} for {host}:{port}",
                    address.port()
                ),
            ));
        }
        let normalized = automatestig_core::network_policy::normalize_mapped_ip(address.ip());
        let scope = automatestig_core::network_policy::classify_ip(normalized);
        if scope == automatestig_core::network_policy::IpScope::Invalid {
            return Err(StigManagerError::contract(
                "destination authorization",
                format!("{label} host {host} resolved to invalid address {normalized}"),
            ));
        }
        let ip_allowlisted = allowlist_matches_ip(normalized, allowlist);
        if !allowlist.is_empty() && !host_allowlisted && !ip_allowlisted {
            return Err(StigManagerError::contract(
                "destination authorization",
                format!("{label} host {host} resolved to unlisted address {normalized}"),
            ));
        }
        if scope != automatestig_core::network_policy::IpScope::Global && !ip_allowlisted {
            return Err(StigManagerError::contract(
                "destination authorization",
                format!(
                    "{label} host {host} resolved to {scope:?} address {normalized}, which requires an explicit IP/CIDR allowlist entry"
                ),
            ));
        }
        let pinned = SocketAddr::new(normalized, port);
        if !addresses.contains(&pinned) {
            addresses.push(pinned);
        }
    }
    if addresses.is_empty() {
        return Err(StigManagerError::Transient {
            status: None,
            message: format!("{label} host resolved to no addresses"),
        });
    }
    Ok(ResolvedEndpoint {
        host: host.to_string(),
        addresses,
    })
}

async fn resolve_endpoint(
    label: &str,
    raw: &str,
    allowlist: &[String],
) -> Result<ResolvedEndpoint, StigManagerError> {
    let url = validate_endpoint_url(label, raw)?;
    let host = url
        .host_str()
        .expect("validated URL has a host")
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = tokio::time::timeout(
        REQUEST_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| StigManagerError::Transient {
        status: None,
        message: format!("{label} DNS resolution timed out"),
    })?
    .map_err(|error| StigManagerError::Transient {
        status: None,
        message: format!("{label} DNS resolution failed: {error}"),
    })?;
    authorize_resolved_endpoint(label, &host, port, resolved, allowlist)
}

fn build_http_client(endpoint: &ResolvedEndpoint) -> Result<reqwest::Client, StigManagerError> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(format!("AutomateSTIG/{}", env!("CARGO_PKG_VERSION")))
        .resolve_to_addrs(&endpoint.host, &endpoint.addresses)
        .build()
        .map_err(|error| {
            StigManagerError::contract(
                "HTTP client construction",
                format!("could not build pinned HTTP client: {error}"),
            )
        })
}

fn transient_transport(operation: &str, error: reqwest::Error) -> StigManagerError {
    StigManagerError::Transient {
        status: error.status().map(|status| status.as_u16()),
        message: format!("{operation} transport failed: {error}"),
    }
}

#[derive(Clone, Copy)]
enum ResponsePurpose {
    Standard,
    Authentication,
    ReviewWrite,
}

async fn parse_response<T: DeserializeOwned>(
    mut response: reqwest::Response,
    operation: &str,
    purpose: ResponsePurpose,
) -> Result<T, StigManagerError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(StigManagerError::contract(
            operation,
            format!("response exceeds the {MAX_RESPONSE_BYTES}-byte limit"),
        ));
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(MAX_RESPONSE_BYTES),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| StigManagerError::Transient {
            status: Some(status.as_u16()),
            message: format!("failed while reading {operation} response: {error}"),
        })?
    {
        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
            body.zeroize();
            return Err(StigManagerError::contract(
                operation,
                format!("response exceeds the {MAX_RESPONSE_BYTES}-byte limit"),
            ));
        }
        body.extend_from_slice(&chunk);
    }

    if !status.is_success() {
        body.zeroize();
        return Err(classify_http_error(status, operation, purpose));
    }
    let parsed = serde_json::from_slice(&body).map_err(|error| {
        StigManagerError::contract(operation, format!("server returned invalid JSON: {error}"))
    });
    body.zeroize();
    parsed
}

fn classify_http_error(
    status: StatusCode,
    operation: &str,
    purpose: ResponsePurpose,
) -> StigManagerError {
    if matches!(purpose, ResponsePurpose::Authentication)
        && (status == StatusCode::BAD_REQUEST
            || status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN)
    {
        return StigManagerError::Authentication {
            status: Some(status.as_u16()),
            message: "OAuth server rejected the client credentials grant".to_string(),
        };
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return StigManagerError::Authentication {
            status: Some(status.as_u16()),
            message: format!("{operation} was not authorized"),
        };
    }
    if status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        return StigManagerError::Transient {
            status: Some(status.as_u16()),
            message: format!("{operation} may succeed when the service recovers"),
        };
    }
    if status == StatusCode::CONFLICT {
        return StigManagerError::Conflict {
            message: format!("{operation} received HTTP {}", status.as_u16()),
            conflicts: Vec::new(),
        };
    }
    if matches!(purpose, ResponsePurpose::ReviewWrite) && status == StatusCode::UNPROCESSABLE_ENTITY
    {
        return StigManagerError::Rejected {
            message: format!("{operation} received HTTP {}", status.as_u16()),
            rejected: Vec::new(),
            response: None,
            receipt: None,
        };
    }
    StigManagerError::contract(
        operation,
        format!("unexpected HTTP status {}", status.as_u16()),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Bytes;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, StatusCode as AxumStatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn api_adapter_accepts_only_retained_tested_server_versions() {
        assert!(require_tested_stig_manager_version("1.6.13+1").is_ok());
        for unsupported in ["", "1.6.13", "1.6.15", "1.5.2", "2.0.0"] {
            let error = require_tested_stig_manager_version(unsupported).unwrap_err();
            assert_eq!(error.kind(), StigManagerErrorKind::Contract);
            let message = error.to_string();
            assert!(message.contains("no tested AutomateSTIG API adapter"));
            assert!(message.contains("disconnected scanning"));
        }
    }

    #[derive(Clone)]
    struct MockState {
        inner: Arc<Mutex<MockInner>>,
    }

    struct MockInner {
        existing_reviews: Vec<Value>,
        posted_reviews: Vec<Value>,
        token_forms: Vec<String>,
        post_status: AxumStatusCode,
        post_response: Value,
    }

    impl Default for MockState {
        fn default() -> Self {
            Self {
                inner: Arc::new(Mutex::new(MockInner {
                    existing_reviews: Vec::new(),
                    posted_reviews: Vec::new(),
                    token_forms: Vec::new(),
                    post_status: AxumStatusCode::OK,
                    post_response: json!({
                        "affected": {"inserted": 1, "updated": 0},
                        "rejected": []
                    }),
                })),
            }
        }
    }

    async fn token(State(state): State<MockState>, body: Bytes) -> Json<Value> {
        state
            .inner
            .lock()
            .await
            .token_forms
            .push(String::from_utf8(body.to_vec()).unwrap());
        Json(json!({"access_token": "mock-access-token", "expires_in": 300}))
    }

    async fn configuration() -> Json<Value> {
        Json(json!({
            "version": "1.6.13+1",
            "classification": "CUI",
            "lastMigration": 54,
            "commit": {"sha": "abc123", "tag": "1.6.13+1"}
        }))
    }

    fn authorize(headers: &HeaderMap) {
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer mock-access-token"
        );
    }

    async fn collections(headers: HeaderMap) -> Json<Value> {
        authorize(&headers);
        Json(json!([{
            "collectionId": "7",
            "name": "Fleet Routers",
            "description": "Authoritative collection",
            "settings": {},
            "metadata": {}
        }]))
    }

    async fn assets(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> Json<Value> {
        authorize(&headers);
        assert_eq!(query.get("collectionId").map(String::as_str), Some("7"));
        assert_eq!(query.get("projection").map(String::as_str), Some("stigs"));
        Json(json!([asset_json()]))
    }

    async fn asset(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> Json<Value> {
        authorize(&headers);
        assert_eq!(query.get("projection").map(String::as_str), Some("stigs"));
        Json(asset_json())
    }

    fn asset_json() -> Value {
        json!({
            "assetId": "42",
            "name": "router-42",
            "fqdn": "router-42.example.mil",
            "ip": "192.0.2.42",
            "mac": null,
            "collection": {"collectionId": "7", "name": "Fleet Routers"},
            "stigs": [{
                "benchmarkId": "CISCO_IOS_XE_ROUTER_NDM_STIG",
                "revisionStr": "V3R7",
                "benchmarkDate": "2025-01-01",
                "revisionPinned": true,
                "ruleCount": 34
            }]
        })
    }

    #[test]
    fn exact_assignment_rejects_indistinguishable_remote_duplicates() {
        let mut asset: StigManagerAssetProjection = serde_json::from_value(asset_json()).unwrap();
        asset.stigs.push(asset.stigs[0].clone());

        let error = exact_assignment(&asset, "CISCO_IOS_XE_ROUTER_NDM_STIG", "V3R7").unwrap_err();

        assert_eq!(error.kind(), StigManagerErrorKind::Contract);
        assert!(error.to_string().contains("ambiguous destination"));
    }

    async fn reviews(
        State(state): State<MockState>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> Json<Value> {
        authorize(&headers);
        assert_eq!(query.get("assetId").map(String::as_str), Some("42"));
        assert_eq!(query.get("rules").map(String::as_str), Some("mapped"));
        Json(Value::Array(
            state.inner.lock().await.existing_reviews.clone(),
        ))
    }

    async fn post_reviews(
        State(state): State<MockState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (AxumStatusCode, Json<Value>) {
        authorize(&headers);
        let mut inner = state.inner.lock().await;
        inner.posted_reviews.push(body);
        (inner.post_status, Json(inner.post_response.clone()))
    }

    async fn spawn_mock(state: MockState) -> (StigManagerClient, MockState) {
        let router = Router::new()
            .route("/token", post(token))
            .route("/api/op/configuration", get(configuration))
            .route("/api/collections", get(collections))
            .route("/api/assets", get(assets))
            .route("/api/assets/42", get(asset))
            .route("/api/collections/7/reviews", get(reviews))
            .route("/api/collections/7/reviews/42", post(post_reviews))
            .with_state(state.clone());
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let connection = StigManagerConnection {
            api_url: format!("http://{address}/api"),
            token_url: format!("http://{address}/token"),
            client_id: "scanner-client".to_string(),
            allowed_private_addresses: Vec::new(),
        };
        (
            StigManagerClient::new_for_mock(
                connection,
                StigManagerClientSecret::new("super-secret"),
            )
            .with_mock_conditional_review_writes(),
            state,
        )
    }

    fn target() -> ScannerDeliveryTarget {
        ScannerDeliveryTarget {
            collection_id: "7".to_string(),
            asset_id: "42".to_string(),
            benchmark_id: "CISCO_IOS_XE_ROUTER_NDM_STIG".to_string(),
            revision: "V3R7".to_string(),
        }
    }

    fn proposed_review() -> ScannerReview {
        ScannerReview {
            rule_id: "SV-254239r958388_rule".to_string(),
            result: ScannerReviewResult::Fail,
            detail: "logging destination missing; evidence sha256:abc".to_string(),
            comment: "Collected by the Cisco IOS-XE adapter".to_string(),
            evidence_source: ScannerEvidenceSource::LiveCollection,
            evaluated_at: Some("2026-08-08T12:00:00Z".to_string()),
        }
    }

    fn existing_review(status: &str, product: Option<&str>) -> Value {
        json!({
            "assetId": "42",
            "ruleId": "SV-254239r958388_rule",
            "result": "pass",
            "autoResult": true,
            "detail": "existing details",
            "comment": "existing comment",
            "status": {"label": status},
            "resultEngine": product.map(|product| json!({
                "type": "script",
                "product": product,
                "version": "0.3.0"
            }))
        })
    }

    fn exact_existing_review(include_asset_id: bool, object_status: bool) -> Value {
        let review = proposed_review();
        let write = ReviewWrite::from(&review);
        let mut value = json!({
            "ruleId": write.rule_id,
            "result": "fail",
            "autoResult": write.auto_result,
            "detail": write.detail,
            "comment": write.comment,
            "status": if object_status { json!({"label": "saved"}) } else { json!("saved") },
            "resultEngine": write.result_engine
        });
        if include_asset_id {
            value["assetId"] = json!("42");
        }
        value
    }

    #[test]
    fn connection_and_secret_debug_are_sanitized() {
        let connection = StigManagerConnection {
            api_url: "https://stigman.example.mil/api".to_string(),
            token_url: "https://id.example.mil/token".to_string(),
            client_id: "scanner".to_string(),
            allowed_private_addresses: Vec::new(),
        };
        let serialized = serde_json::to_string(&connection).unwrap();
        assert!(!serialized.contains("client_secret"));
        let secret = StigManagerClientSecret::new("do-not-print");
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("do-not-print"));
        connection.validate().unwrap();
    }

    #[test]
    fn production_connections_require_https_and_reject_embedded_credentials() {
        for api_url in [
            "http://stigman.example.mil/api",
            "https://user:password@stigman.example.mil/api",
            "https://localhost/api",
            "https://stigman.example.mil/api?secret=value",
        ] {
            let connection = StigManagerConnection {
                api_url: api_url.to_string(),
                token_url: "https://id.example.mil/token".to_string(),
                client_id: "scanner".to_string(),
                allowed_private_addresses: Vec::new(),
            };
            assert_eq!(
                connection.validate().unwrap_err().kind(),
                StigManagerErrorKind::Contract
            );
        }
    }

    #[test]
    fn projected_wire_shapes_accept_established_revision_and_context_variants() {
        let wire: AssetWire = serde_json::from_value(json!({
            "name": "router-42",
            "collectionId": "7",
            "stigs": [{
                "benchmarkId": "CISCO_IOS_XE_ROUTER_NDM_STIG",
                "lastRevisionStr": "V3R7"
            }]
        }))
        .unwrap();
        let asset = wire.into_asset("7", Some("42")).unwrap();
        assert_eq!(asset.asset_id, "42");
        assert_eq!(asset.stigs[0].revision, "V3R7");

        let without_context: AssetWire = serde_json::from_value(json!({
            "name": "router-unknown",
            "collectionId": "7",
            "stigs": []
        }))
        .unwrap();
        assert_eq!(
            without_context.into_asset("7", None).unwrap_err().kind(),
            StigManagerErrorKind::Contract
        );
    }

    #[test]
    fn mapped_review_wire_accepts_contextual_asset_and_both_status_shapes() {
        for status in [json!("saved"), json!({"label": "saved"})] {
            let wire: ExistingMappedReviewWire = serde_json::from_value(json!({
                "ruleId": "SV-254239r958388_rule",
                "result": "fail",
                "autoResult": true,
                "detail": null,
                "status": status,
                "resultEngine": {
                    "type": "script",
                    "product": "AutomateSTIG"
                }
            }))
            .unwrap();
            let review = wire.into_review("42").unwrap();
            assert_eq!(review.asset_id, "42");
            assert_eq!(review.status.label, ReviewWorkflowStatus::Saved);
            assert_eq!(review.detail, "");
            assert_eq!(review.comment, "");
        }
    }

    #[test]
    fn configured_destination_allowlist_is_strict_for_hosts_ips_and_cidrs() {
        let public = SocketAddr::new("8.8.8.8".parse().unwrap(), 443);
        let other_public = SocketAddr::new("1.1.1.1".parse().unwrap(), 443);
        let private = SocketAddr::new("10.5.2.3".parse().unwrap(), 443);

        authorize_resolved_endpoint(
            "test",
            "stigman.example.mil",
            443,
            [public],
            &["stigman.example.mil".to_string()],
        )
        .unwrap();
        assert!(authorize_resolved_endpoint(
            "test",
            "other.example.mil",
            443,
            [other_public],
            &["stigman.example.mil".to_string()],
        )
        .is_err());
        assert!(authorize_resolved_endpoint(
            "test",
            "stigman.example.mil",
            443,
            [private],
            &["stigman.example.mil".to_string()],
        )
        .is_err());
        authorize_resolved_endpoint(
            "test",
            "stigman.example.mil",
            443,
            [private],
            &["stigman.example.mil".to_string(), "10.5.0.0/16".to_string()],
        )
        .unwrap();
        authorize_resolved_endpoint(
            "test",
            "other.example.mil",
            443,
            [public],
            &["8.8.8.8".to_string()],
        )
        .unwrap();
    }

    #[test]
    fn malformed_or_reserved_allowlist_entries_fail_closed() {
        for entries in [
            vec!["*.example.mil".to_string()],
            vec!["10.0.0.0/99".to_string()],
            vec!["192.0.2.1".to_string()],
            vec!["not a host".to_string()],
        ] {
            assert!(validate_destination_allowlist(&entries).is_err());
        }
    }

    #[test]
    fn oauth_rejections_are_authentication_errors_not_contract_failures() {
        for status in [StatusCode::BAD_REQUEST, StatusCode::UNAUTHORIZED] {
            let error = classify_http_error(
                status,
                "OAuth token request",
                ResponsePurpose::Authentication,
            );
            assert_eq!(error.kind(), StigManagerErrorKind::Authentication);
            assert!(!error.is_retryable());
        }
    }

    #[tokio::test]
    async fn mock_contract_discovers_lists_maps_and_delivers_sparse_reviews() {
        let (client, state) = spawn_mock(MockState::default()).await;

        let capabilities = client.discover_capabilities().await.unwrap();
        assert_eq!(capabilities.server.version, "1.6.13+1");
        assert!(capabilities.projected_asset_assignments);
        assert_eq!(
            capabilities.conditional_review_writes,
            ConditionalReviewWriteSupport::Unsupported
        );

        let collections = client.list_collections().await.unwrap();
        assert_eq!(collections[0].collection_id, "7");
        let assets = client.list_assets("7").await.unwrap();
        assert_eq!(assets[0].stigs[0].revision, "V3R7");

        let receipt = client
            .deliver_scanner_reviews(&target(), &[proposed_review()])
            .await
            .unwrap();
        assert_eq!(receipt.reviews_sent, 1);
        assert_eq!(receipt.reviews_considered, 1);
        assert_eq!(receipt.unchanged, 0);
        assert_eq!(receipt.inserted, 1);

        let inner = state.inner.lock().await;
        assert_eq!(inner.posted_reviews.len(), 1);
        let posted = inner.posted_reviews[0].as_array().unwrap();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0]["ruleId"], "SV-254239r958388_rule");
        assert_eq!(posted[0]["status"], "saved");
        assert_eq!(posted[0]["autoResult"], true);
        assert_eq!(posted[0]["resultEngine"]["product"], AUTOMATESTIG_PRODUCT);
        assert_eq!(inner.token_forms.len(), 1, "token should be cached");
        assert!(inner.token_forms[0].contains("grant_type=client_credentials"));
        assert!(inner.token_forms[0].contains("client_id=scanner-client"));
        assert!(inner.token_forms[0].contains("client_secret=super-secret"));
    }

    #[tokio::test]
    async fn human_or_workflow_review_blocks_the_entire_write() {
        for (status, product, expected_kind) in [
            ("saved", None, ReviewConflictKind::HumanOrUnowned),
            (
                "submitted",
                Some(AUTOMATESTIG_PRODUCT),
                ReviewConflictKind::Submitted,
            ),
            (
                "accepted",
                Some(AUTOMATESTIG_PRODUCT),
                ReviewConflictKind::Accepted,
            ),
            (
                "rejected",
                Some(AUTOMATESTIG_PRODUCT),
                ReviewConflictKind::Rejected,
            ),
        ] {
            let state = MockState::default();
            state
                .inner
                .lock()
                .await
                .existing_reviews
                .push(existing_review(status, product));
            let (client, state) = spawn_mock(state).await;
            let error = client
                .deliver_scanner_reviews(&target(), &[proposed_review()])
                .await
                .unwrap_err();
            assert_eq!(error.kind(), StigManagerErrorKind::Conflict);
            let StigManagerError::Conflict { conflicts, .. } = error else {
                unreachable!()
            };
            assert_eq!(conflicts[0].kind, expected_kind);
            assert!(state.inner.lock().await.posted_reviews.is_empty());
        }
    }

    #[tokio::test]
    async fn saved_automatestig_review_is_the_only_overwritable_review() {
        let state = MockState::default();
        state
            .inner
            .lock()
            .await
            .existing_reviews
            .push(existing_review("saved", Some("automatestig")));
        let (client, state) = spawn_mock(state).await;
        client
            .deliver_scanner_reviews(&target(), &[proposed_review()])
            .await
            .unwrap();
        assert_eq!(state.inner.lock().await.posted_reviews.len(), 1);
    }

    #[tokio::test]
    async fn exact_replay_is_a_true_sparse_noop_without_post() {
        let state = MockState::default();
        state
            .inner
            .lock()
            .await
            .existing_reviews
            .push(exact_existing_review(false, false));
        let (mut client, state) = spawn_mock(state).await;
        client.conditional_review_writes = false;

        let receipt = client
            .deliver_scanner_reviews(&target(), &[proposed_review()])
            .await
            .unwrap();

        assert_eq!(receipt.reviews_considered, 1);
        assert_eq!(receipt.reviews_sent, 0);
        assert_eq!(receipt.unchanged, 1);
        assert_eq!(receipt.inserted + receipt.updated, 0);
        assert!(state.inner.lock().await.posted_reviews.is_empty());
    }

    #[tokio::test]
    async fn changed_detail_is_not_misclassified_as_an_unchanged_result() {
        let state = MockState::default();
        state
            .inner
            .lock()
            .await
            .existing_reviews
            .push(exact_existing_review(true, true));
        let (mut client, state) = spawn_mock(state).await;
        client.conditional_review_writes = false;
        let mut changed = proposed_review();
        changed.detail.push_str("; newly observed evidence");

        let error = client
            .deliver_scanner_reviews(&target(), &[changed])
            .await
            .unwrap_err();
        let StigManagerError::ConditionalWriteUnsupported {
            pending_rules,
            unchanged,
            ..
        } = error
        else {
            panic!("a changed detail must require a conditionally protected write")
        };
        assert_eq!(pending_rules, vec!["SV-254239r958388_rule"]);
        assert_eq!(unchanged, 0);
        assert!(state.inner.lock().await.posted_reviews.is_empty());
    }

    #[tokio::test]
    async fn current_server_contract_fails_closed_before_any_needed_write() {
        let (mut client, state) = spawn_mock(MockState::default()).await;
        client.conditional_review_writes = false;
        let error = client
            .deliver_scanner_reviews(&target(), &[proposed_review()])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), StigManagerErrorKind::Conflict);
        assert!(matches!(
            error,
            StigManagerError::ConditionalWriteUnsupported { .. }
        ));
        assert!(state.inner.lock().await.posted_reviews.is_empty());
    }

    #[tokio::test]
    async fn revision_mismatch_fails_before_review_read_or_write() {
        let (client, state) = spawn_mock(MockState::default()).await;
        let mut wrong = target();
        wrong.revision = "V3R6".to_string();
        let error = client
            .deliver_scanner_reviews(&wrong, &[proposed_review()])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), StigManagerErrorKind::Contract);
        assert!(state.inner.lock().await.posted_reviews.is_empty());
    }

    #[tokio::test]
    async fn server_rejections_are_typed_and_not_retryable() {
        let state = MockState::default();
        {
            let mut inner = state.inner.lock().await;
            inner.post_response = json!({
                "affected": {"inserted": 0, "updated": 0},
                "rejected": [{
                    "ruleId": "SV-254239r958388_rule",
                    "reason": "insufficient grant"
                }]
            });
        }
        let (client, _) = spawn_mock(state).await;
        let error = client
            .deliver_scanner_reviews(&target(), &[proposed_review()])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), StigManagerErrorKind::Rejected);
        assert!(!error.is_retryable());
        let StigManagerError::Rejected {
            response,
            receipt,
            rejected,
            ..
        } = error
        else {
            unreachable!()
        };
        assert_eq!(rejected.len(), 1);
        assert_eq!(response.unwrap().affected.inserted, 0);
        let receipt = receipt.expect("partial-write receipt must be preserved");
        assert_eq!(receipt.reviews_sent, 1);
        assert_eq!(receipt.inserted, 0);
    }

    #[tokio::test]
    async fn partial_write_response_preserves_affected_rows_and_rejections() {
        let state = MockState::default();
        {
            let mut inner = state.inner.lock().await;
            inner.post_response = json!({
                "affected": {"inserted": 1, "updated": 0},
                "rejected": [{
                    "ruleId": "SV-254240r958389_rule",
                    "reason": "no grant for this asset/ruleId"
                }]
            });
        }
        let (client, _) = spawn_mock(state).await;
        let first = proposed_review();
        let mut second = proposed_review();
        second.rule_id = "SV-254240r958389_rule".to_string();
        let error = client
            .deliver_scanner_reviews(&target(), &[first, second])
            .await
            .unwrap_err();
        let StigManagerError::Rejected {
            response: Some(response),
            receipt: Some(receipt),
            ..
        } = error
        else {
            panic!("partial response and receipt must remain available")
        };
        assert_eq!(response.affected.inserted, 1);
        assert_eq!(response.rejected.len(), 1);
        assert_eq!(receipt.reviews_sent, 2);
        assert_eq!(receipt.inserted, 1);
    }

    #[tokio::test]
    async fn legitimate_zero_affected_response_is_a_receipted_success() {
        let state = MockState::default();
        state.inner.lock().await.post_response = json!({
            "affected": {"inserted": 0, "updated": 0},
            "rejected": []
        });
        let (client, _) = spawn_mock(state).await;
        let receipt = client
            .deliver_scanner_reviews(&target(), &[proposed_review()])
            .await
            .unwrap();
        assert_eq!(receipt.reviews_sent, 1);
        assert_eq!(receipt.inserted + receipt.updated, 0);
    }

    #[tokio::test]
    async fn transient_http_status_is_typed_for_outbox_retry() {
        let state = MockState::default();
        state.inner.lock().await.post_status = AxumStatusCode::SERVICE_UNAVAILABLE;
        let (client, _) = spawn_mock(state).await;
        let error = client
            .deliver_scanner_reviews(&target(), &[proposed_review()])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), StigManagerErrorKind::Transient);
        assert!(error.is_retryable());
    }

    #[test]
    fn sparse_mapping_excludes_every_non_scanner_or_incomplete_source() {
        use automatestig_core::models::asset::Asset;
        use automatestig_core::models::checklist::ChecklistStigInfo;
        use automatestig_core::models::finding::Finding;
        use automatestig_core::models::stig::Severity;

        let mut checklist = Checklist::new(
            Asset::new("router"),
            ChecklistStigInfo {
                stig_id: "CISCO".to_string(),
                title: "Cisco".to_string(),
                version: "3".to_string(),
                release: "7".to_string(),
                release_date: None,
                uuid: None,
                description: None,
                filename: None,
            },
        );
        for (index, source, status) in [
            (1, FindingSource::Automated, FindingStatus::Open),
            (2, FindingSource::Evidence, FindingStatus::NotAFinding),
            (3, FindingSource::Manual, FindingStatus::Open),
            (4, FindingSource::Imported, FindingStatus::Open),
            (5, FindingSource::AnswerFile, FindingStatus::Open),
            (
                6,
                FindingSource::CollectionError,
                FindingStatus::NotReviewed,
            ),
            (7, FindingSource::Automated, FindingStatus::NotReviewed),
        ] {
            let mut finding = Finding::new_not_reviewed(
                &format!("V-{index}"),
                &format!("SV-{index}_rule"),
                &format!("V-{index}"),
                "rule",
                Severity::Medium,
            );
            finding.source = source;
            finding.status = status;
            checklist.findings.push(finding);
        }
        let reviews = sparse_scanner_reviews(&checklist);
        assert_eq!(reviews.len(), 2);
        assert_eq!(
            reviews[0].evidence_source,
            ScannerEvidenceSource::LiveCollection
        );
        assert_eq!(
            reviews[1].evidence_source,
            ScannerEvidenceSource::SuppliedEvidence
        );
    }

    #[test]
    fn identifiers_duplicates_and_latest_revision_fail_closed() {
        let mut invalid_target = target();
        invalid_target.asset_id = "../42".to_string();
        assert_eq!(
            validate_target(&invalid_target).unwrap_err().kind(),
            StigManagerErrorKind::Contract
        );
        let mut latest = target();
        latest.revision = "latest".to_string();
        assert!(validate_target(&latest).is_err());
        let review = proposed_review();
        assert!(validate_scanner_reviews(&[review.clone(), review]).is_err());
    }
}
