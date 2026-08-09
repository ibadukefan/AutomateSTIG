//! Deterministic, ownership-safe XCCDF 1.2 result serialization.
//!
//! The selected-run handoff is intentionally sparse: only rule IDs explicitly
//! owned by a completed scanner evaluation are serialized. Manual, imported,
//! answer-file, collection-error, and Not Reviewed findings are rejected rather
//! than represented as results that could clear another reviewer's work.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use quick_xml::events::{BytesDecl, BytesEnd, BytesRef, BytesStart, BytesText, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use quick_xml::{Writer, XmlVersion};
use thiserror::Error;

use crate::models::checklist::Checklist;
use crate::models::finding::{Finding, FindingSource, FindingStatus};

pub const XCCDF_1_2_NAMESPACE: &str = "http://checklists.nist.gov/xccdf/1.2";
pub const STIG_MANAGER_NAMESPACE: &str = "http://github.com/nuwcdivnpt/stig-manager";
pub const AUTOMATESTIG_XCCDF_NAMESPACE: &str = "https://automatestig.local/ns/xccdf-results/1";
pub const XCCDF_RESULTS_SCHEMA: &str = "automatestig.xccdf-results.v1";
pub const XCCDF_OWNERSHIP_SCOPE: &str = "scanner-owned-sparse";

const DUBLIN_CORE_NAMESPACE: &str = "http://purl.org/dc/elements/1.1/";
const BENCHMARK_ID_PREFIX: &str = "xccdf_mil.disa.stig_benchmark_";
const GROUP_ID_PREFIX: &str = "xccdf_mil.disa.stig_group_";
const RULE_ID_PREFIX: &str = "xccdf_mil.disa.stig_rule_";
const TEST_RESULT_ID_PREFIX: &str = "xccdf_org.automatestig_testresult_";
const AUTOMATESTIG_CHECK_SYSTEM: &str = "urn:automatestig:check:release-bundled";
const AUTOMATESTIG_RESULT_SYSTEM: &str = "urn:automatestig:result:scanner";
const VULN_ID_SYSTEM: &str = "urn:automatestig:disa:vuln-id";
const CCI_SYSTEM: &str = "http://iase.disa.mil/cci";
const DEFAULT_SCORING_SYSTEM: &str = "urn:xccdf:scoring:default";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum XccdfResultsError {
    #[error("invalid sparse XCCDF results input: {0}")]
    InvalidInput(String),
    #[error("failed to serialize sparse XCCDF results: {0}")]
    Serialization(String),
    #[error("generated sparse XCCDF results failed structural validation: {0}")]
    Validation(String),
}

/// Immutable producer, content, and run bindings carried in TestResult metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XccdfResultsProvenance {
    pub run_id: String,
    pub profile_id: String,
    pub scanner_version: String,
    pub scan_source: String,
    pub collection_method: String,
    pub collection_complete: bool,
    pub started_at: String,
    pub completed_at: String,
    pub request_sha256: String,
    pub result_sha256: String,
    pub profile_sha256: String,
    pub benchmark_sha256: String,
    pub benchmark_model_sha256: String,
    pub source_archive_sha256: String,
    pub source_xccdf_sha256: String,
    pub check_pack_sha256: String,
    pub evaluation_plan_sha256: String,
    pub evidence_sha256: String,
    pub collection_plan_sha256: String,
    pub source_url: String,
    pub source_member: String,
    pub coverage_manifest: String,
    pub coverage_manifest_sha256: String,
}

impl XccdfResultsProvenance {
    fn fields(&self) -> BTreeMap<&'static str, &str> {
        BTreeMap::from([
            (
                "benchmark-model-sha256",
                self.benchmark_model_sha256.as_str(),
            ),
            ("benchmark-sha256", self.benchmark_sha256.as_str()),
            ("check-pack-sha256", self.check_pack_sha256.as_str()),
            ("collection-method", self.collection_method.as_str()),
            (
                "collection-plan-sha256",
                self.collection_plan_sha256.as_str(),
            ),
            ("completed-at", self.completed_at.as_str()),
            ("coverage-manifest", self.coverage_manifest.as_str()),
            (
                "coverage-manifest-sha256",
                self.coverage_manifest_sha256.as_str(),
            ),
            (
                "evaluation-plan-sha256",
                self.evaluation_plan_sha256.as_str(),
            ),
            ("evidence-sha256", self.evidence_sha256.as_str()),
            ("profile-id", self.profile_id.as_str()),
            ("profile-sha256", self.profile_sha256.as_str()),
            ("request-sha256", self.request_sha256.as_str()),
            ("result-sha256", self.result_sha256.as_str()),
            ("run-id", self.run_id.as_str()),
            ("scan-source", self.scan_source.as_str()),
            ("scanner-version", self.scanner_version.as_str()),
            ("source-archive-sha256", self.source_archive_sha256.as_str()),
            ("source-member", self.source_member.as_str()),
            ("source-url", self.source_url.as_str()),
            ("source-xccdf-sha256", self.source_xccdf_sha256.as_str()),
            ("started-at", self.started_at.as_str()),
        ])
    }
}

/// XCCDF's result vocabulary used by the scanner boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum XccdfRuleOutcome {
    Pass,
    Fail,
    NotApplicable,
    NotChecked,
    Error,
}

impl XccdfRuleOutcome {
    pub fn from_finding(finding: &Finding) -> Self {
        match (finding.status, finding.source) {
            (FindingStatus::NotAFinding, _) => Self::Pass,
            (FindingStatus::Open, _) => Self::Fail,
            (FindingStatus::NotApplicable, _) => Self::NotApplicable,
            (FindingStatus::NotReviewed, FindingSource::CollectionError) => Self::Error,
            (FindingStatus::NotReviewed, _) => Self::NotChecked,
        }
    }

    pub fn as_xccdf_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotApplicable => "notapplicable",
            Self::NotChecked => "notchecked",
            Self::Error => "error",
        }
    }

    fn from_xccdf_str(value: &str) -> Option<Self> {
        match value {
            "pass" => Some(Self::Pass),
            "fail" => Some(Self::Fail),
            "notapplicable" => Some(Self::NotApplicable),
            "notchecked" => Some(Self::NotChecked),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct SparseRuleResult<'a> {
    finding: &'a Finding,
    outcome: XccdfRuleOutcome,
}

/// Serialize a completed checklist's explicitly scanner-owned findings as a
/// self-contained XCCDF 1.2 Benchmark/TestResult document.
///
/// `scanner_owned_rule_ids` is an allow-list, not a filter hint. Every ID must
/// resolve exactly once to a completed Automated or Evidence finding. Any
/// Not Reviewed or collection-error row makes the export fail closed.
pub fn write_sparse_xccdf_1_2_results(
    checklist: &Checklist,
    scanner_owned_rule_ids: &[String],
    provenance: &XccdfResultsProvenance,
) -> Result<Vec<u8>, XccdfResultsError> {
    let rules = validate_and_select_rules(checklist, scanner_owned_rule_ids, provenance)?;
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .map_err(serialization_error)?;

    let benchmark_id = format!("{BENCHMARK_ID_PREFIX}{}", checklist.stig_info.stig_id);
    let mut benchmark = BytesStart::new("cdf:Benchmark");
    benchmark.push_attribute(("xmlns:cdf", XCCDF_1_2_NAMESPACE));
    benchmark.push_attribute(("xmlns:dc", "http://purl.org/dc/elements/1.1/"));
    benchmark.push_attribute(("xmlns:sm", STIG_MANAGER_NAMESPACE));
    benchmark.push_attribute(("xmlns:ast", AUTOMATESTIG_XCCDF_NAMESPACE));
    benchmark.push_attribute(("id", benchmark_id.as_str()));
    benchmark.push_attribute(("resolved", "false"));
    writer
        .write_event(Event::Start(benchmark))
        .map_err(serialization_error)?;

    text_element(&mut writer, "cdf:status", "accepted", &[])?;
    text_element(&mut writer, "cdf:title", &checklist.stig_info.title, &[])?;
    if let Some(description) = nonempty(checklist.stig_info.description.as_deref()) {
        text_element(&mut writer, "cdf:description", description, &[])?;
    }
    text_element(
        &mut writer,
        "cdf:version",
        &format!(
            "V{}R{}",
            checklist.stig_info.version, checklist.stig_info.release
        ),
        &[],
    )?;

    start_element(&mut writer, "cdf:metadata", &[])?;
    text_element(
        &mut writer,
        "dc:creator",
        "Defense Information Systems Agency",
        &[],
    )?;
    text_element(&mut writer, "dc:publisher", "AutomateSTIG", &[])?;
    empty_element(
        &mut writer,
        "ast:scope",
        &[
            ("schema", XCCDF_RESULTS_SCHEMA),
            ("ownership", XCCDF_OWNERSHIP_SCOPE),
        ],
    )?;
    end_element(&mut writer, "cdf:metadata")?;

    for rule in &rules {
        write_rule_definition(&mut writer, rule.finding)?;
    }
    write_test_result(&mut writer, checklist, &rules, provenance)?;
    end_element(&mut writer, "cdf:Benchmark")?;

    let mut bytes = writer.into_inner();
    bytes.push(b'\n');
    let validation = validate_xccdf_1_2_results(&bytes)?;
    if validation.benchmark_id != benchmark_id
        || validation.rule_ids.len() != rules.len()
        || validation.rule_result_ids.len() != rules.len()
    {
        return Err(XccdfResultsError::Validation(
            "serialized rule/result cardinality or benchmark identity changed".to_string(),
        ));
    }
    Ok(bytes)
}

fn validate_and_select_rules<'a>(
    checklist: &'a Checklist,
    scanner_owned_rule_ids: &[String],
    provenance: &XccdfResultsProvenance,
) -> Result<Vec<SparseRuleResult<'a>>, XccdfResultsError> {
    if !provenance.collection_complete {
        return invalid("an incomplete run cannot be exported");
    }
    let checklist_provenance = checklist
        .evaluation_provenance
        .as_ref()
        .ok_or_else(|| invalid_error("checklist evaluation provenance is missing"))?;
    if !checklist_provenance.collection_complete
        || !checklist_provenance.collection_errors.is_empty()
    {
        return invalid("an incomplete or errored checklist cannot be exported");
    }
    if let Some(reason) = checklist.external_export_block_reason() {
        return invalid(format!("checklist provenance is not exportable: {reason}"));
    }
    validate_ncname_suffix("STIG ID", &checklist.stig_info.stig_id)?;
    validate_ncname_suffix("run ID", &provenance.run_id)?;
    validate_rfc3339("started_at", &provenance.started_at)?;
    validate_rfc3339("completed_at", &provenance.completed_at)?;
    for (name, value) in provenance.fields() {
        validate_text(name, value, 8 * 1024)?;
        if name.ends_with("sha256") {
            validate_sha256(name, value)?;
        }
    }

    if scanner_owned_rule_ids.is_empty() {
        return invalid("no scanner-owned results were selected");
    }
    let mut seen = BTreeSet::new();
    let findings_by_rule: HashMap<&str, &Finding> = checklist
        .findings
        .iter()
        .map(|finding| (finding.rule_id.as_str(), finding))
        .collect();
    if findings_by_rule.len() != checklist.findings.len() {
        return invalid("checklist contains duplicate Rule IDs");
    }

    let mut rules = Vec::with_capacity(scanner_owned_rule_ids.len());
    for rule_id in scanner_owned_rule_ids {
        if !seen.insert(rule_id.as_str()) {
            return invalid(format!("scanner-owned Rule ID {rule_id:?} is duplicated"));
        }
        let finding = findings_by_rule.get(rule_id.as_str()).ok_or_else(|| {
            invalid_error(format!(
                "scanner-owned Rule ID {rule_id:?} has no exact checklist finding"
            ))
        })?;
        validate_rule_identity(finding)?;
        if !matches!(
            finding.source,
            FindingSource::Automated | FindingSource::Evidence
        ) {
            return invalid(format!(
                "Rule ID {rule_id:?} is not owned by scanner evidence"
            ));
        }
        let outcome = XccdfRuleOutcome::from_finding(finding);
        if matches!(
            outcome,
            XccdfRuleOutcome::NotChecked | XccdfRuleOutcome::Error
        ) {
            return invalid(format!(
                "Rule ID {rule_id:?} is unresolved; Not Reviewed and error rows are not handoff-owned"
            ));
        }
        rules.push(SparseRuleResult { finding, outcome });
    }
    rules.sort_by(|left, right| left.finding.rule_id.cmp(&right.finding.rule_id));
    Ok(rules)
}

fn validate_rule_identity(finding: &Finding) -> Result<(), XccdfResultsError> {
    validate_ncname("Vuln ID", &finding.vuln_id)?;
    validate_ncname("Group ID", &finding.group_id)?;
    validate_ncname("Rule ID", &finding.rule_id)?;
    if !finding.vuln_id.starts_with("V-") || finding.group_id != finding.vuln_id {
        return invalid(format!(
            "Rule ID {:?} does not retain one exact DISA V-* Group/Vuln identity",
            finding.rule_id
        ));
    }
    if !finding.rule_id.starts_with("SV-") || !finding.rule_id.ends_with("_rule") {
        return invalid(format!(
            "Rule ID {:?} is not an exact DISA SV-*_rule identity",
            finding.rule_id
        ));
    }
    validate_text("rule title", &finding.rule_title, 64 * 1024)?;
    validate_optional_text("finding detail", &finding.finding_details, 256 * 1024)?;
    validate_optional_text("finding comment", &finding.comments, 64 * 1024)?;
    Ok(())
}

fn write_rule_definition(
    writer: &mut Writer<Vec<u8>>,
    finding: &Finding,
) -> Result<(), XccdfResultsError> {
    let group_id = format!("{GROUP_ID_PREFIX}{}", finding.group_id);
    start_element(writer, "cdf:Group", &[("id", group_id.as_str())])?;
    text_element(
        writer,
        "cdf:title",
        nonempty(Some(finding.group_title.as_str())).unwrap_or(&finding.vuln_id),
        &[],
    )?;

    let rule_id = format!("{RULE_ID_PREFIX}{}", finding.rule_id);
    let weight = decimal_weight(finding.weight);
    start_element(
        writer,
        "cdf:Rule",
        &[
            ("id", rule_id.as_str()),
            ("severity", finding.severity.as_xccdf_str()),
            ("weight", weight.as_str()),
        ],
    )?;
    if let Some(version) = nonempty(Some(finding.rule_version.as_str())) {
        text_element(writer, "cdf:version", version, &[])?;
    }
    text_element(writer, "cdf:title", &finding.rule_title, &[])?;
    if let Some(discussion) = nonempty(Some(finding.discussion.as_str())) {
        text_element(writer, "cdf:description", discussion, &[])?;
    }
    text_element(
        writer,
        "cdf:ident",
        &finding.vuln_id,
        &[("system", VULN_ID_SYSTEM)],
    )?;
    let mut cci_refs: Vec<_> = finding
        .cci_refs
        .iter()
        .map(String::as_str)
        .filter(|cci| !cci.trim().is_empty())
        .collect();
    cci_refs.sort_unstable();
    cci_refs.dedup();
    for cci in cci_refs {
        text_element(writer, "cdf:ident", cci, &[("system", CCI_SYSTEM)])?;
    }
    if let Some(fix) = nonempty(Some(finding.fix_text.as_str())) {
        text_element(writer, "cdf:fixtext", fix, &[])?;
    }
    if let Some(check) = nonempty(Some(finding.check_content.as_str())) {
        start_element(
            writer,
            "cdf:check",
            &[("system", AUTOMATESTIG_CHECK_SYSTEM)],
        )?;
        text_element(writer, "cdf:check-content", check, &[])?;
        end_element(writer, "cdf:check")?;
    }
    end_element(writer, "cdf:Rule")?;
    end_element(writer, "cdf:Group")?;
    Ok(())
}

fn write_test_result(
    writer: &mut Writer<Vec<u8>>,
    checklist: &Checklist,
    rules: &[SparseRuleResult<'_>],
    provenance: &XccdfResultsProvenance,
) -> Result<(), XccdfResultsError> {
    let result_id = format!("{TEST_RESULT_ID_PREFIX}{}", provenance.run_id);
    let test_system = format!(
        "cpe:/a:automatestig:automatestig:{}",
        provenance.scanner_version
    );
    let revision = format!(
        "V{}R{}",
        checklist.stig_info.version, checklist.stig_info.release
    );
    start_element(
        writer,
        "cdf:TestResult",
        &[
            ("id", result_id.as_str()),
            ("start-time", provenance.started_at.as_str()),
            ("end-time", provenance.completed_at.as_str()),
            ("test-system", test_system.as_str()),
            ("version", revision.as_str()),
        ],
    )?;
    text_element(
        writer,
        "cdf:title",
        "AutomateSTIG scanner-owned sparse results",
        &[],
    )?;
    text_element(
        writer,
        "cdf:remark",
        "Only completed scanner-owned determinations are present. Omitted rules are outside this handoff's ownership and must remain unchanged.",
        &[],
    )?;
    text_element(writer, "cdf:organization", "AutomateSTIG", &[])?;
    text_element(writer, "cdf:target", &checklist.asset.hostname, &[])?;
    if let Some(address) = nonempty(checklist.asset.ip_address.as_deref()) {
        text_element(writer, "cdf:target-address", address, &[])?;
    }
    write_target_facts(writer, checklist)?;
    for rule in rules {
        write_rule_result(writer, rule, provenance)?;
    }
    let score = sparse_score(rules);
    text_element(
        writer,
        "cdf:score",
        &score,
        &[("system", DEFAULT_SCORING_SYSTEM), ("maximum", "100")],
    )?;
    write_provenance_metadata(writer, checklist, provenance)?;
    end_element(writer, "cdf:TestResult")?;
    Ok(())
}

fn write_target_facts(
    writer: &mut Writer<Vec<u8>>,
    checklist: &Checklist,
) -> Result<(), XccdfResultsError> {
    const ASSET_FACT_PREFIX: &str = "tag:stig-manager@users.noreply.github.com,2020:asset:";
    let mut facts = BTreeMap::new();
    facts.insert(
        format!("{ASSET_FACT_PREFIX}name"),
        checklist.asset.hostname.clone(),
    );
    facts.insert(
        format!("{ASSET_FACT_PREFIX}noncomputing"),
        (checklist.asset.asset_type.as_ckl_str() == "Non-Computing").to_string(),
    );
    if let Some(value) = nonempty(checklist.asset.ip_address.as_deref()) {
        facts.insert(format!("{ASSET_FACT_PREFIX}ip"), value.to_string());
    }
    if let Some(value) = nonempty(checklist.asset.fqdn.as_deref()) {
        facts.insert(format!("{ASSET_FACT_PREFIX}fqdn"), value.to_string());
    }
    if let Some(value) = nonempty(checklist.asset.mac_address.as_deref()) {
        facts.insert(format!("{ASSET_FACT_PREFIX}mac"), value.to_string());
    }
    if let Some(value) = nonempty(checklist.asset.target_comment.as_deref()) {
        facts.insert(format!("{ASSET_FACT_PREFIX}description"), value.to_string());
    }
    if let Some(value) = nonempty(checklist.asset.os.as_deref()) {
        facts.insert(
            "urn:automatestig:target:operating-system".to_string(),
            value.to_string(),
        );
    }

    start_element(writer, "cdf:target-facts", &[])?;
    for (name, value) in facts {
        text_element(
            writer,
            "cdf:fact",
            &value,
            &[("name", name.as_str()), ("type", "string")],
        )?;
    }
    end_element(writer, "cdf:target-facts")?;
    Ok(())
}

fn write_rule_result(
    writer: &mut Writer<Vec<u8>>,
    rule: &SparseRuleResult<'_>,
    provenance: &XccdfResultsProvenance,
) -> Result<(), XccdfResultsError> {
    let finding = rule.finding;
    let rule_id = format!("{RULE_ID_PREFIX}{}", finding.rule_id);
    let weight = decimal_weight(finding.weight);
    let evaluated_at = finding.evaluated_at.to_rfc3339();
    let version = finding.rule_version.as_str();
    let mut attributes = vec![
        ("idref", rule_id.as_str()),
        ("severity", finding.severity.as_xccdf_str()),
        ("time", evaluated_at.as_str()),
        ("weight", weight.as_str()),
    ];
    if !version.trim().is_empty() {
        attributes.push(("version", version));
    }
    start_element(writer, "cdf:rule-result", &attributes)?;
    text_element(writer, "cdf:result", rule.outcome.as_xccdf_str(), &[])?;
    text_element(
        writer,
        "cdf:ident",
        &finding.vuln_id,
        &[("system", VULN_ID_SYSTEM)],
    )?;
    start_element(writer, "cdf:metadata", &[])?;
    empty_element(
        writer,
        "ast:rule-identity",
        &[
            ("vuln-id", finding.vuln_id.as_str()),
            ("group-id", finding.group_id.as_str()),
            ("rule-id", finding.rule_id.as_str()),
            ("ownership", XCCDF_OWNERSHIP_SCOPE),
        ],
    )?;
    end_element(writer, "cdf:metadata")?;
    if !finding.finding_details.is_empty() {
        text_element(
            writer,
            "cdf:message",
            &finding.finding_details,
            &[("severity", "info")],
        )?;
    }
    start_element(
        writer,
        "cdf:check",
        &[("system", AUTOMATESTIG_RESULT_SYSTEM)],
    )?;
    start_element(writer, "cdf:check-content", &[])?;
    text_element(writer, "sm:detail", &finding.finding_details, &[])?;
    text_element(writer, "sm:comment", &finding.comments, &[])?;
    start_element(writer, "sm:resultEngine", &[])?;
    text_element(writer, "sm:type", "script", &[])?;
    text_element(writer, "sm:product", "AutomateSTIG", &[])?;
    text_element(writer, "sm:version", &provenance.scanner_version, &[])?;
    text_element(writer, "sm:time", &evaluated_at, &[])?;
    start_element(writer, "sm:checkContent", &[])?;
    text_element(writer, "sm:location", &provenance.profile_id, &[])?;
    text_element(writer, "sm:component", &finding.rule_id, &[])?;
    end_element(writer, "sm:checkContent")?;
    end_element(writer, "sm:resultEngine")?;
    end_element(writer, "cdf:check-content")?;
    end_element(writer, "cdf:check")?;
    end_element(writer, "cdf:rule-result")?;
    Ok(())
}

fn write_provenance_metadata(
    writer: &mut Writer<Vec<u8>>,
    checklist: &Checklist,
    provenance: &XccdfResultsProvenance,
) -> Result<(), XccdfResultsError> {
    start_element(writer, "cdf:metadata", &[])?;
    start_element(
        writer,
        "ast:provenance",
        &[
            ("schema", XCCDF_RESULTS_SCHEMA),
            ("ownership", XCCDF_OWNERSHIP_SCOPE),
            ("stig-id", checklist.stig_info.stig_id.as_str()),
        ],
    )?;
    for (name, value) in provenance.fields() {
        empty_element(writer, "ast:field", &[("name", name), ("value", value)])?;
    }
    end_element(writer, "ast:provenance")?;
    end_element(writer, "cdf:metadata")?;
    Ok(())
}

fn sparse_score(rules: &[SparseRuleResult<'_>]) -> String {
    let pass = rules
        .iter()
        .filter(|rule| rule.outcome == XccdfRuleOutcome::Pass)
        .count();
    let applicable = rules
        .iter()
        .filter(|rule| {
            matches!(
                rule.outcome,
                XccdfRuleOutcome::Pass | XccdfRuleOutcome::Fail
            )
        })
        .count();
    if applicable == 0 {
        "0.00".to_string()
    } else {
        format!("{:.2}", pass as f64 * 100.0 / applicable as f64)
    }
}

fn decimal_weight(weight: f64) -> String {
    if !weight.is_finite() || weight < 0.0 {
        return "0".to_string();
    }
    let bounded = weight.min(999.0);
    if bounded.fract() == 0.0 {
        format!("{bounded:.0}")
    } else {
        let rendered = format!("{bounded:.1}");
        rendered
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }
}

fn start_element(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    attributes: &[(&str, &str)],
) -> Result<(), XccdfResultsError> {
    let mut element = BytesStart::new(name);
    for (key, value) in attributes {
        element.push_attribute((*key, *value));
    }
    writer
        .write_event(Event::Start(element))
        .map_err(serialization_error)
}

fn empty_element(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    attributes: &[(&str, &str)],
) -> Result<(), XccdfResultsError> {
    let mut element = BytesStart::new(name);
    for (key, value) in attributes {
        element.push_attribute((*key, *value));
    }
    writer
        .write_event(Event::Empty(element))
        .map_err(serialization_error)
}

fn text_element(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    value: &str,
    attributes: &[(&str, &str)],
) -> Result<(), XccdfResultsError> {
    start_element(writer, name, attributes)?;
    writer
        .write_event(Event::Text(BytesText::new(value)))
        .map_err(serialization_error)?;
    end_element(writer, name)
}

fn end_element(writer: &mut Writer<Vec<u8>>, name: &str) -> Result<(), XccdfResultsError> {
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(serialization_error)
}

fn serialization_error(error: std::io::Error) -> XccdfResultsError {
    XccdfResultsError::Serialization(error.to_string())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, XccdfResultsError> {
    Err(invalid_error(message))
}

fn invalid_error(message: impl Into<String>) -> XccdfResultsError {
    XccdfResultsError::InvalidInput(message.into())
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn validate_text(label: &str, value: &str, maximum_bytes: usize) -> Result<(), XccdfResultsError> {
    if value.trim().is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control)
    {
        return invalid(format!(
            "{label} must be non-empty, bounded to {maximum_bytes} bytes, and contain no control characters"
        ));
    }
    Ok(())
}

fn validate_optional_text(
    label: &str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), XccdfResultsError> {
    if value.len() > maximum_bytes
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
    {
        return invalid(format!(
            "{label} must be bounded to {maximum_bytes} bytes and contain no control characters"
        ));
    }
    Ok(())
}

fn validate_ncname(label: &str, value: &str) -> Result<(), XccdfResultsError> {
    validate_text(label, value, 512)?;
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return invalid(format!("{label} is empty"));
    };
    if !(first.is_ascii_alphabetic() || first == '_')
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        return invalid(format!("{label} {value:?} is not an ASCII XML NCName"));
    }
    Ok(())
}

fn validate_ncname_suffix(label: &str, value: &str) -> Result<(), XccdfResultsError> {
    validate_text(label, value, 512)?;
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    {
        return invalid(format!(
            "{label} {value:?} cannot be represented in an XCCDF identifier"
        ));
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<(), XccdfResultsError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(format!("{label} is not a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_rfc3339(label: &str, value: &str) -> Result<(), XccdfResultsError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| invalid_error(format!("{label} is not RFC 3339")))
}

/// Structural facts returned by the bounded post-serialization validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XccdfResultsValidation {
    pub benchmark_id: String,
    pub test_result_id: String,
    pub target: String,
    pub rule_ids: BTreeSet<String>,
    pub rule_result_ids: BTreeSet<String>,
    pub rule_results: BTreeMap<String, XccdfRuleOutcome>,
    pub rule_details: BTreeMap<String, String>,
    pub rule_comments: BTreeMap<String, String>,
    pub provenance_fields: BTreeMap<String, String>,
}

/// Parse and validate the security-relevant XCCDF 1.2 handoff invariants.
///
/// The producer calls this after serialization. This is a bounded semantic and
/// security validator, not a complete XSD validator. Any release claim about
/// schema validity must run a separate validation against the applicable XSD.
pub fn validate_xccdf_1_2_results(xml: &[u8]) -> Result<XccdfResultsValidation, XccdfResultsError> {
    let mut reader = NsReader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut benchmark_id = None;
    let mut test_result_id = None;
    let mut target = None;
    let mut group_ids = BTreeSet::new();
    let mut rule_ids = BTreeSet::new();
    let mut rule_result_ids = BTreeSet::new();
    let mut current_result_id = None;
    let mut current_element = String::new();
    let mut result_values = BTreeMap::new();
    let mut result_details = BTreeMap::new();
    let mut result_comments = BTreeMap::new();
    let mut result_identities = BTreeMap::new();
    let mut provenance_fields = BTreeMap::new();
    let mut sparse_scope_seen = false;
    let mut sparse_provenance_seen = false;
    let mut provenance_stig_id = None;
    let mut test_result_depth = None;
    let mut provenance_depth = None;
    let mut score_count = 0usize;

    loop {
        match reader.read_resolved_event_into(&mut buffer) {
            Ok((namespace, Event::Start(element))) => {
                let local = String::from_utf8_lossy(element.local_name().as_ref()).into_owned();
                validate_relevant_element_namespace(&local, &namespace)?;
                if depth == 0 {
                    if local != "Benchmark" {
                        return validation("root element is not XCCDF Benchmark");
                    }
                    require_element_namespace(&local, &namespace, XCCDF_1_2_NAMESPACE)?;
                    benchmark_id = attribute(&element, b"id")?;
                } else if local == "Group" && test_result_depth.is_none() {
                    let id = required_attribute(&element, b"id", "Group")?;
                    if !group_ids.insert(id.clone()) {
                        return validation(format!("duplicate Group id {id:?}"));
                    }
                } else if local == "Rule" && test_result_depth.is_none() {
                    let id = required_attribute(&element, b"id", "Rule")?;
                    if !rule_ids.insert(id.clone()) {
                        return validation(format!("duplicate Rule id {id:?}"));
                    }
                } else if local == "TestResult" {
                    if test_result_id.is_some() {
                        return validation("document contains more than one TestResult");
                    }
                    test_result_id = Some(required_attribute(&element, b"id", "TestResult")?);
                    if attribute(&element, b"end-time")?.is_none() {
                        return validation("TestResult is missing required end-time");
                    }
                    test_result_depth = Some(depth);
                } else if local == "rule-result" && test_result_depth.is_some() {
                    let idref = required_attribute(&element, b"idref", "rule-result")?;
                    if !rule_result_ids.insert(idref.clone()) {
                        return validation(format!("duplicate rule-result idref {idref:?}"));
                    }
                    current_result_id = Some(idref);
                } else if local == "score" && test_result_depth.is_some() {
                    score_count += 1;
                } else if local == "detail" {
                    if let Some(idref) = current_result_id.as_ref() {
                        if result_details
                            .insert(idref.clone(), String::new())
                            .is_some()
                        {
                            return validation("rule-result contains duplicate sm:detail elements");
                        }
                    }
                } else if local == "comment" {
                    if let Some(idref) = current_result_id.as_ref() {
                        if result_comments
                            .insert(idref.clone(), String::new())
                            .is_some()
                        {
                            return validation(
                                "rule-result contains duplicate sm:comment elements",
                            );
                        }
                    }
                } else if local == "provenance" {
                    if test_result_depth.is_none() {
                        return validation("ast:provenance is outside TestResult");
                    }
                    if sparse_provenance_seen {
                        return validation("document contains duplicate ast:provenance elements");
                    }
                    let schema = required_attribute(&element, b"schema", "ast:provenance")?;
                    let ownership = required_attribute(&element, b"ownership", "ast:provenance")?;
                    if schema != XCCDF_RESULTS_SCHEMA || ownership != XCCDF_OWNERSHIP_SCOPE {
                        return validation(
                            "ast:provenance does not declare the scanner-owned sparse schema",
                        );
                    }
                    provenance_stig_id =
                        Some(required_attribute(&element, b"stig-id", "ast:provenance")?);
                    sparse_provenance_seen = true;
                    provenance_depth = Some(depth);
                }
                current_element = local;
                depth += 1;
            }
            Ok((namespace, Event::Empty(element))) => {
                let local = String::from_utf8_lossy(element.local_name().as_ref()).into_owned();
                validate_relevant_element_namespace(&local, &namespace)?;
                if local == "scope" {
                    if sparse_scope_seen {
                        return validation("document contains duplicate ast:scope elements");
                    }
                    let schema = required_attribute(&element, b"schema", "ast:scope")?;
                    let ownership = required_attribute(&element, b"ownership", "ast:scope")?;
                    if schema != XCCDF_RESULTS_SCHEMA || ownership != XCCDF_OWNERSHIP_SCOPE {
                        return validation(
                            "ast:scope does not declare the scanner-owned sparse schema",
                        );
                    }
                    sparse_scope_seen = true;
                } else if local == "field" {
                    if provenance_depth.is_none() {
                        return validation("ast:field is outside ast:provenance");
                    }
                    let name = required_attribute(&element, b"name", "ast:field")?;
                    let value = required_attribute(&element, b"value", "ast:field")?;
                    if provenance_fields.insert(name.clone(), value).is_some() {
                        return validation(format!("duplicate provenance field {name:?}"));
                    }
                } else if local == "rule-identity" {
                    if let Some(idref) = current_result_id.as_ref() {
                        let rule_id = required_attribute(&element, b"rule-id", "rule-identity")?;
                        let group_id = required_attribute(&element, b"group-id", "rule-identity")?;
                        let vuln_id = required_attribute(&element, b"vuln-id", "rule-identity")?;
                        let ownership =
                            required_attribute(&element, b"ownership", "rule-identity")?;
                        if ownership != XCCDF_OWNERSHIP_SCOPE
                            || group_id != vuln_id
                            || !vuln_id.starts_with("V-")
                            || idref != &format!("{RULE_ID_PREFIX}{rule_id}")
                        {
                            return validation(format!(
                                "rule-result {idref:?} has invalid exact rule/vulnerability ownership metadata"
                            ));
                        }
                        if result_identities
                            .insert(idref.clone(), (group_id, rule_id))
                            .is_some()
                        {
                            return validation("duplicate sparse rule identity metadata");
                        }
                    }
                } else if local == "Group" && test_result_depth.is_none() {
                    let id = required_attribute(&element, b"id", "Group")?;
                    if !group_ids.insert(id.clone()) {
                        return validation(format!("duplicate Group id {id:?}"));
                    }
                } else if local == "Rule" && test_result_depth.is_none() {
                    let id = required_attribute(&element, b"id", "Rule")?;
                    if !rule_ids.insert(id.clone()) {
                        return validation(format!("duplicate Rule id {id:?}"));
                    }
                }
            }
            Ok((_, Event::Text(text))) => {
                let value = text
                    .xml10_content()
                    .map_err(|error| XccdfResultsError::Validation(error.to_string()))?
                    .into_owned();
                record_text_value(
                    current_element.as_str(),
                    test_result_depth.is_some(),
                    current_result_id.as_ref(),
                    &value,
                    &mut target,
                    &mut result_values,
                    &mut result_details,
                    &mut result_comments,
                )?;
            }
            Ok((_, Event::CData(text))) => {
                let value = text
                    .xml10_content()
                    .map_err(|error| XccdfResultsError::Validation(error.to_string()))?
                    .into_owned();
                record_text_value(
                    current_element.as_str(),
                    test_result_depth.is_some(),
                    current_result_id.as_ref(),
                    &value,
                    &mut target,
                    &mut result_values,
                    &mut result_details,
                    &mut result_comments,
                )?;
            }
            Ok((_, Event::GeneralRef(reference))) => {
                let value = resolve_reference(&reference)?;
                if matches!(current_element.as_str(), "target" | "detail" | "comment") {
                    record_text_value(
                        current_element.as_str(),
                        test_result_depth.is_some(),
                        current_result_id.as_ref(),
                        &value,
                        &mut target,
                        &mut result_values,
                        &mut result_details,
                        &mut result_comments,
                    )?;
                } else if current_element == "result" {
                    return validation("a rule result cannot contain an entity reference");
                }
            }
            Ok((_, Event::End(element))) => {
                depth = depth.saturating_sub(1);
                let local = String::from_utf8_lossy(element.local_name().as_ref()).into_owned();
                if local == "rule-result" {
                    current_result_id = None;
                } else if local == "provenance" {
                    provenance_depth = None;
                } else if local == "TestResult" {
                    test_result_depth = None;
                }
                current_element.clear();
            }
            Ok((_, Event::Eof)) => break,
            Err(error) => {
                return validation(format!(
                    "XML parse error at byte {}: {error}",
                    reader.buffer_position()
                ))
            }
            Ok((_, Event::DocType(_))) => {
                return validation("DOCTYPE declarations are not allowed in XCCDF results")
            }
            _ => {}
        }
        buffer.clear();
    }

    let benchmark_id = benchmark_id
        .filter(|id| id.starts_with(BENCHMARK_ID_PREFIX))
        .ok_or_else(|| validation_error("Benchmark id is missing its STIG Manager/DISA prefix"))?;
    let benchmark_stig_id = benchmark_id
        .strip_prefix(BENCHMARK_ID_PREFIX)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| validation_error("Benchmark id does not contain a STIG identity"))?;
    if provenance_stig_id.as_deref() != Some(benchmark_stig_id) {
        return validation("ast:provenance stig-id does not match the Benchmark STIG identity");
    }
    let test_result_id = test_result_id
        .filter(|id| id.starts_with(TEST_RESULT_ID_PREFIX))
        .ok_or_else(|| validation_error("TestResult id is missing its AutomateSTIG prefix"))?;
    let target = target
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| validation_error("TestResult target is missing or empty"))?;
    if score_count != 1 {
        return validation("TestResult must contain exactly one score");
    }
    if rule_ids.is_empty() || rule_result_ids.is_empty() {
        return validation("document contains no sparse Rule/rule-result rows");
    }
    if rule_ids != rule_result_ids {
        return validation("Rule definitions and rule-result idrefs are not an exact 1:1 set");
    }
    if group_ids.len() != rule_result_ids.len() {
        return validation("Group definitions and sparse rule-results are not an exact 1:1 set");
    }
    if result_values.len() != rule_result_ids.len() {
        return validation("one or more rule-results has no result value");
    }
    if result_details.len() != rule_result_ids.len()
        || result_comments.len() != rule_result_ids.len()
    {
        return validation("one or more rule-results lacks STIG Manager detail/comment metadata");
    }
    if result_identities.len() != rule_result_ids.len() {
        return validation("one or more rule-results lacks exact sparse rule identity metadata");
    }
    for (idref, (group_id, _)) in &result_identities {
        if !group_ids.contains(&format!("{GROUP_ID_PREFIX}{group_id}")) {
            return validation(format!(
                "rule-result {idref:?} has no matching DISA Group definition"
            ));
        }
    }
    if !sparse_scope_seen || !sparse_provenance_seen {
        return validation("document does not declare scanner-owned sparse ownership scope");
    }
    for required in [
        "run-id",
        "profile-id",
        "scanner-version",
        "benchmark-sha256",
        "benchmark-model-sha256",
        "source-xccdf-sha256",
        "check-pack-sha256",
        "evaluation-plan-sha256",
        "evidence-sha256",
    ] {
        if !provenance_fields.contains_key(required) {
            return validation(format!("provenance is missing required field {required:?}"));
        }
    }
    for (name, value) in &provenance_fields {
        if name.ends_with("sha256")
            && (value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return validation(format!(
                "provenance field {name:?} is not a lowercase SHA-256 digest"
            ));
        }
    }
    for name in ["started-at", "completed-at"] {
        let value = provenance_fields
            .get(name)
            .ok_or_else(|| validation_error(format!("provenance is missing field {name:?}")))?;
        if chrono::DateTime::parse_from_rfc3339(value).is_err() {
            return validation(format!("provenance field {name:?} is not RFC 3339"));
        }
    }
    Ok(XccdfResultsValidation {
        benchmark_id,
        test_result_id,
        target,
        rule_ids,
        rule_result_ids,
        rule_results: result_values,
        rule_details: result_details,
        rule_comments: result_comments,
        provenance_fields,
    })
}

fn validate_relevant_element_namespace(
    local: &str,
    namespace: &ResolveResult<'_>,
) -> Result<(), XccdfResultsError> {
    let expected = match local {
        "Benchmark" | "status" | "title" | "description" | "metadata" | "Group" | "Rule"
        | "ident" | "fixtext" | "check" | "check-content" | "TestResult" | "remark"
        | "organization" | "target" | "target-address" | "target-facts" | "fact"
        | "rule-result" | "result" | "message" | "score" => Some(XCCDF_1_2_NAMESPACE),
        "detail" | "comment" | "resultEngine" | "type" | "product" | "time" | "checkContent"
        | "location" | "component" => Some(STIG_MANAGER_NAMESPACE),
        "scope" | "provenance" | "field" | "rule-identity" => Some(AUTOMATESTIG_XCCDF_NAMESPACE),
        "creator" | "publisher" => Some(DUBLIN_CORE_NAMESPACE),
        // Both cdf:version and sm:version are emitted by this serializer.
        "version" => {
            if namespace_matches(namespace, XCCDF_1_2_NAMESPACE)
                || namespace_matches(namespace, STIG_MANAGER_NAMESPACE)
            {
                None
            } else {
                return validation(format!(
                    "element {local:?} is not in the XCCDF 1.2 or STIG Manager namespace"
                ));
            }
        }
        // XCCDF metadata can legally carry other extension elements. They are
        // ignored because they do not contribute to the validated handoff.
        _ => None,
    };
    if let Some(expected) = expected {
        require_element_namespace(local, namespace, expected)?;
    }
    Ok(())
}

fn require_element_namespace(
    local: &str,
    namespace: &ResolveResult<'_>,
    expected: &str,
) -> Result<(), XccdfResultsError> {
    if namespace_matches(namespace, expected) {
        return Ok(());
    }
    let actual = match namespace {
        ResolveResult::Unbound => "unbound".to_string(),
        ResolveResult::Bound(namespace) => String::from_utf8_lossy(namespace.as_ref()).into_owned(),
        ResolveResult::Unknown(prefix) => {
            format!("unknown prefix {:?}", String::from_utf8_lossy(prefix))
        }
    };
    validation(format!(
        "element {local:?} is in namespace {actual:?}; expected {expected:?}"
    ))
}

fn namespace_matches(namespace: &ResolveResult<'_>, expected: &str) -> bool {
    matches!(
        namespace,
        ResolveResult::Bound(namespace) if namespace.as_ref() == expected.as_bytes()
    )
}

fn attribute(element: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, XccdfResultsError> {
    for item in element.attributes() {
        let item = item.map_err(|error| XccdfResultsError::Validation(error.to_string()))?;
        if item.key.as_ref() == name {
            return item
                .normalized_value(XmlVersion::Implicit1_0)
                .map(|value| Some(value.into_owned()))
                .map_err(|error| XccdfResultsError::Validation(error.to_string()));
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn record_text_value(
    current_element: &str,
    in_test_result: bool,
    current_result_id: Option<&String>,
    value: &str,
    target: &mut Option<String>,
    result_values: &mut BTreeMap<String, XccdfRuleOutcome>,
    result_details: &mut BTreeMap<String, String>,
    result_comments: &mut BTreeMap<String, String>,
) -> Result<(), XccdfResultsError> {
    match current_element {
        "target" if in_test_result => target.get_or_insert_default().push_str(value),
        "result" if current_result_id.is_some() => {
            let id = current_result_id.unwrap();
            let normalized = value.trim();
            let Some(outcome) = XccdfRuleOutcome::from_xccdf_str(normalized) else {
                return validation(format!(
                    "rule-result {id:?} has unsupported result {value:?}"
                ));
            };
            if result_values.insert(id.clone(), outcome).is_some() {
                return validation(format!(
                    "rule-result {id:?} contains more than one result value"
                ));
            }
        }
        "detail" if current_result_id.is_some() => {
            let id = current_result_id.unwrap();
            result_details
                .entry(id.clone())
                .or_default()
                .push_str(value);
        }
        "comment" if current_result_id.is_some() => {
            let id = current_result_id.unwrap();
            result_comments
                .entry(id.clone())
                .or_default()
                .push_str(value);
        }
        _ => {}
    }
    Ok(())
}

fn resolve_reference(reference: &BytesRef<'_>) -> Result<String, XccdfResultsError> {
    if let Some(character) = reference
        .resolve_char_ref()
        .map_err(|error| validation_error(format!("invalid XML character reference: {error}")))?
    {
        return Ok(character.to_string());
    }
    let name = reference
        .decode()
        .map_err(|error| validation_error(format!("invalid XML entity reference: {error}")))?;
    let value = match name.as_ref() {
        "lt" => "<",
        "gt" => ">",
        "amp" => "&",
        "apos" => "'",
        "quot" => "\"",
        _ => {
            return validation(format!(
                "unsupported XML entity reference &{name}; in XCCDF results"
            ))
        }
    };
    Ok(value.to_string())
}

fn required_attribute(
    element: &BytesStart<'_>,
    name: &[u8],
    element_name: &str,
) -> Result<String, XccdfResultsError> {
    attribute(element, name)?.ok_or_else(|| {
        validation_error(format!(
            "{element_name} is missing required {} attribute",
            String::from_utf8_lossy(name)
        ))
    })
}

fn validation<T>(message: impl Into<String>) -> Result<T, XccdfResultsError> {
    Err(validation_error(message))
}

fn validation_error(message: impl Into<String>) -> XccdfResultsError {
    XccdfResultsError::Validation(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check_packs::evaluation_plan_sha256;
    use crate::models::asset::Asset;
    use crate::models::checklist::{ChecklistStigInfo, EvaluationOrigin, EvaluationProvenance};
    use crate::models::finding::Finding;
    use crate::models::stig::Severity;
    use chrono::{TimeZone, Utc};

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn fixture() -> (Checklist, XccdfResultsProvenance) {
        let benchmark_sha256 = digest('a');
        let check_pack_sha256 = digest('b');
        let plan_sha256 = evaluation_plan_sha256(
            "Example_STIG",
            "V1R2",
            &benchmark_sha256,
            &check_pack_sha256,
            None,
        )
        .unwrap();
        let mut asset = Asset::new("router<&1");
        asset.ip_address = Some("192.0.2.10".to_string());
        asset.fqdn = Some("router-1.example.test".to_string());
        asset.os = Some("IOS-XE 17.9".to_string());
        let mut checklist = Checklist::new(
            asset,
            ChecklistStigInfo {
                stig_id: "Example_STIG".to_string(),
                title: "Example & Router STIG".to_string(),
                version: "1".to_string(),
                release: "2".to_string(),
                release_date: None,
                uuid: None,
                description: Some("A <bounded> export fixture".to_string()),
                filename: None,
            },
        );
        let evaluated_at = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        checklist.created_at = evaluated_at;
        checklist.modified_at = evaluated_at;
        checklist.generated_by = "AutomateSTIG 0.3.0".to_string();
        checklist.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::EvidenceFile,
            collection_complete: true,
            collection_errors: Vec::new(),
            evidence_sha256: Some(digest('c')),
            claimed_hostname: Some("router<&1".to_string()),
            collector_version: Some("0.3.0".to_string()),
            collected_at: Some("2026-01-02T03:04:05Z".to_string()),
            plan_sha256: Some(digest('d')),
            server_key_fingerprint: None,
            benchmark_sha256: Some(benchmark_sha256.clone()),
            check_pack_sha256: Some(check_pack_sha256.clone()),
            evaluation_plan_sha256: Some(plan_sha256.clone()),
            organization_policy: None,
            answer_file: None,
            answer_files: Vec::new(),
            unsafe_legacy_evidence: false,
        });

        let mut passed = Finding::new_not_reviewed(
            "V-100001",
            "SV-100001r1_rule",
            "V-100001",
            "Escaped <rule> & title",
            Severity::Medium,
        );
        passed.group_title = "SRG-NET-000001-RTR-000001".to_string();
        passed.rule_version = "RTR-NDM-000001".to_string();
        passed.status = FindingStatus::NotAFinding;
        passed.source = FindingSource::Evidence;
        passed.finding_details = "Observed <good> & verified\nSecond line".to_string();
        passed.comments = "Analyst-facing & deterministic\nSecond line".to_string();
        passed.evaluated_at = evaluated_at;
        passed.cci_refs = vec!["CCI-000002".to_string(), "CCI-000001".to_string()];

        let mut failed = Finding::new_not_reviewed(
            "V-100002",
            "SV-100002r2_rule",
            "V-100002",
            "Failed rule",
            Severity::High,
        );
        failed.rule_version = "RTR-NDM-000002".to_string();
        failed.status = FindingStatus::Open;
        failed.source = FindingSource::Automated;
        failed.finding_details = "Condition satisfied: false".to_string();
        failed.evaluated_at = evaluated_at;

        let mut manual = Finding::new_not_reviewed(
            "V-100003",
            "SV-100003r1_rule",
            "V-100003",
            "Human-owned rule",
            Severity::Low,
        );
        manual.status = FindingStatus::Open;
        manual.source = FindingSource::Manual;
        checklist.findings = vec![manual, failed, passed];

        let provenance = XccdfResultsProvenance {
            run_id: "11111111-2222-4333-8444-555555555555".to_string(),
            profile_id: "example_router".to_string(),
            scanner_version: "0.3.0".to_string(),
            scan_source: "configuration".to_string(),
            collection_method: "configuration".to_string(),
            collection_complete: true,
            started_at: "2026-01-02T03:04:05Z".to_string(),
            completed_at: "2026-01-02T03:04:05Z".to_string(),
            request_sha256: digest('1'),
            result_sha256: digest('2'),
            profile_sha256: digest('3'),
            benchmark_sha256,
            benchmark_model_sha256: digest('4'),
            source_archive_sha256: digest('5'),
            source_xccdf_sha256: digest('6'),
            check_pack_sha256,
            evaluation_plan_sha256: plan_sha256,
            evidence_sha256: digest('c'),
            collection_plan_sha256: digest('d'),
            source_url: "https://example.test/stig.zip".to_string(),
            source_member: "example-xccdf.xml".to_string(),
            coverage_manifest: "content/scanner_profiles/example.coverage.json".to_string(),
            coverage_manifest_sha256: digest('7'),
        };
        (checklist, provenance)
    }

    #[test]
    fn outcome_mapping_covers_xccdf_scanner_states() {
        let (mut checklist, _) = fixture();
        let finding = &mut checklist.findings[0];
        finding.status = FindingStatus::NotAFinding;
        assert_eq!(
            XccdfRuleOutcome::from_finding(finding).as_xccdf_str(),
            "pass"
        );
        finding.status = FindingStatus::Open;
        assert_eq!(
            XccdfRuleOutcome::from_finding(finding).as_xccdf_str(),
            "fail"
        );
        finding.status = FindingStatus::NotApplicable;
        assert_eq!(
            XccdfRuleOutcome::from_finding(finding).as_xccdf_str(),
            "notapplicable"
        );
        finding.status = FindingStatus::NotReviewed;
        finding.source = FindingSource::Automated;
        assert_eq!(
            XccdfRuleOutcome::from_finding(finding).as_xccdf_str(),
            "notchecked"
        );
        finding.source = FindingSource::CollectionError;
        assert_eq!(
            XccdfRuleOutcome::from_finding(finding).as_xccdf_str(),
            "error"
        );
    }

    #[test]
    fn output_is_deterministic_sparse_well_formed_and_stig_manager_mappable() {
        let (checklist, provenance) = fixture();
        let owned = vec![
            "SV-100002r2_rule".to_string(),
            "SV-100001r1_rule".to_string(),
        ];
        let first = write_sparse_xccdf_1_2_results(&checklist, &owned, &provenance).unwrap();
        let second = write_sparse_xccdf_1_2_results(
            &checklist,
            &owned.into_iter().rev().collect::<Vec<_>>(),
            &provenance,
        )
        .unwrap();
        assert_eq!(first, second);

        let parsed = validate_xccdf_1_2_results(&first).unwrap();
        assert_eq!(
            parsed.benchmark_id,
            "xccdf_mil.disa.stig_benchmark_Example_STIG"
        );
        assert_eq!(parsed.target, "router<&1");
        assert_eq!(parsed.rule_ids, parsed.rule_result_ids);
        assert_eq!(parsed.rule_ids.len(), 2);
        assert!(parsed
            .rule_ids
            .contains("xccdf_mil.disa.stig_rule_SV-100001r1_rule"));
        assert_eq!(
            parsed
                .rule_details
                .get("xccdf_mil.disa.stig_rule_SV-100001r1_rule")
                .map(String::as_str),
            Some("Observed <good> & verified\nSecond line")
        );
        let text = String::from_utf8(first).unwrap();
        assert!(text.contains("xccdf_mil.disa.stig_group_V-100001"));
        assert!(text.contains("&lt;rule&gt; &amp; title"));
        assert!(!text.contains("SV-100003r1_rule"));
        assert!(text.contains("<cdf:result>pass</cdf:result>"));
        assert!(text.contains("<cdf:result>fail</cdf:result>"));
        assert!(text.contains("ownership=\"scanner-owned-sparse\""));
    }

    #[test]
    fn incomplete_unresolved_and_non_scanner_rows_fail_closed() {
        let (mut checklist, mut provenance) = fixture();
        provenance.collection_complete = false;
        let error = write_sparse_xccdf_1_2_results(
            &checklist,
            &["SV-100001r1_rule".to_string()],
            &provenance,
        )
        .unwrap_err();
        assert!(error.to_string().contains("incomplete run"));

        provenance.collection_complete = true;
        let error = write_sparse_xccdf_1_2_results(
            &checklist,
            &["SV-100003r1_rule".to_string()],
            &provenance,
        )
        .unwrap_err();
        assert!(error.to_string().contains("not owned by scanner evidence"));

        checklist.findings[2].status = FindingStatus::NotReviewed;
        let error = write_sparse_xccdf_1_2_results(
            &checklist,
            &["SV-100001r1_rule".to_string()],
            &provenance,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unresolved"));
    }

    #[test]
    fn validator_rejects_missing_or_unmapped_rule_results() {
        let (checklist, provenance) = fixture();
        let xml = write_sparse_xccdf_1_2_results(
            &checklist,
            &["SV-100001r1_rule".to_string()],
            &provenance,
        )
        .unwrap();
        let broken = String::from_utf8(xml).unwrap().replacen(
            "xccdf_mil.disa.stig_rule_SV-100001r1_rule\" severity=",
            "xccdf_mil.disa.stig_rule_SV-999999r1_rule\" severity=",
            1,
        );
        let error = validate_xccdf_1_2_results(broken.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("not an exact 1:1 set"));
    }

    #[test]
    fn validator_rejects_wrong_security_relevant_namespaces() {
        let (checklist, provenance) = fixture();
        let xml = String::from_utf8(
            write_sparse_xccdf_1_2_results(
                &checklist,
                &["SV-100001r1_rule".to_string()],
                &provenance,
            )
            .unwrap(),
        )
        .unwrap();

        let wrong_xccdf = xml.replacen(XCCDF_1_2_NAMESPACE, "urn:wrong:xccdf", 1);
        let error = validate_xccdf_1_2_results(wrong_xccdf.as_bytes()).unwrap_err();
        assert!(error.to_string().contains(XCCDF_1_2_NAMESPACE));

        let wrong_automatestig =
            xml.replacen(AUTOMATESTIG_XCCDF_NAMESPACE, "urn:wrong:automatestig", 1);
        let error = validate_xccdf_1_2_results(wrong_automatestig.as_bytes()).unwrap_err();
        assert!(error.to_string().contains(AUTOMATESTIG_XCCDF_NAMESPACE));
    }

    #[test]
    fn validator_binds_benchmark_identity_to_provenance() {
        let (checklist, provenance) = fixture();
        let xml = String::from_utf8(
            write_sparse_xccdf_1_2_results(
                &checklist,
                &["SV-100001r1_rule".to_string()],
                &provenance,
            )
            .unwrap(),
        )
        .unwrap();
        let wrong_identity =
            xml.replacen("stig-id=\"Example_STIG\"", "stig-id=\"Different_STIG\"", 1);
        let error = validate_xccdf_1_2_results(wrong_identity.as_bytes()).unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match the Benchmark STIG identity"));
    }
}
