//! CKLB (Checklist B) parser — JSON-based format used by STIG Viewer 3.x.
//!
//! CKLB files are JSON documents that contain the same data as CKL but in a
//! more modern, easier-to-parse format.

use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};

use automatestig_core::models::asset::{Asset, AssetRole, AssetType, TechnologyArea};
use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo, Classification};
use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
use automatestig_core::models::stig::Severity;

use crate::error::{ParseError, ParseResult};
use crate::util::{read_to_string_capped, PARSE_FILE_SIZE_LIMIT_BYTES};

/// Raw CKLB file structure (for deserialization).
#[derive(Debug, Serialize, Deserialize)]
pub struct CklbFile {
    pub title: Option<String>,
    pub id: Option<String>,
    pub cklb_version: Option<String>,
    #[serde(rename = "active")]
    pub active: Option<bool>,
    pub mode: Option<i32>,
    pub has_path: Option<bool>,
    pub target_data: CklbTargetData,
    pub stigs: Vec<CklbStig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CklbTargetData {
    pub target_type: Option<String>,
    pub host_name: Option<String>,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub fqdn: Option<String>,
    pub comments: Option<String>,
    pub role: Option<String>,
    pub is_web_database: Option<bool>,
    pub technology_area: Option<String>,
    pub web_db_site: Option<String>,
    pub web_db_instance: Option<String>,
    #[serde(
        default,
        alias = "operating_system",
        skip_serializing_if = "Option::is_none"
    )]
    pub os: Option<String>,
    pub classification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CklbStig {
    pub stig_name: Option<String>,
    pub display_name: Option<String>,
    pub stig_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_stringish")]
    pub version: Option<String>,
    pub release_info: Option<String>,
    pub uuid: Option<String>,
    pub reference_identifier: Option<String>,
    pub size: Option<i32>,
    pub rules: Vec<CklbRule>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CklbRule {
    pub group_id: Option<String>,
    pub group_id_v: Option<String>,
    pub vuln_num: Option<String>,
    pub group_tree: Option<Vec<CklbGroupTree>>,
    pub rule_id: Option<String>,
    pub rule_id_src: Option<String>,
    pub rule_version: Option<String>,
    pub stig_uuid: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub weight: Option<String>,
    pub classification: Option<String>,
    pub group_title: Option<String>,
    pub rule_title: Option<String>,
    pub fix_text: Option<String>,
    pub false_positives: Option<String>,
    pub false_negatives: Option<String>,
    pub discussion: Option<String>,
    pub check_content: Option<String>,
    pub documentable: Option<String>,
    pub mitigations: Option<String>,
    pub potential_impacts: Option<String>,
    pub third_party_tools: Option<String>,
    pub mitigation_control: Option<String>,
    pub responsibility: Option<String>,
    pub security_override_guidance: Option<String>,
    pub srg_id: Option<String>,
    pub ia_controls: Option<String>,
    pub check_content_ref: Option<CklbCheckContentRef>,
    pub legacy_ids: Option<Vec<String>>,
    pub ccis: Option<Vec<String>>,
    pub detail: Option<String>,
    pub comment: Option<String>,
    pub finding_details: Option<String>,
    pub comments: Option<String>,
    pub severity_override: Option<String>,
    pub severity_justification: Option<String>,
    pub overrides: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CklbGroupTree {
    pub id: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CklbCheckContentRef {
    pub href: Option<String>,
    pub name: Option<String>,
}

fn deserialize_optional_stringish<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(serde_json::Value::Number(value)) => Ok(Some(value.to_string())),
        Some(other) => Err(serde::de::Error::custom(format!(
            "expected a string or number, got {other}"
        ))),
    }
}

/// Parse a CKLB file from a path.
pub fn parse_cklb_file(path: &Path) -> ParseResult<Checklist> {
    let content = read_to_string_capped(path, PARSE_FILE_SIZE_LIMIT_BYTES)?;
    parse_cklb(&content)
}

/// Parse CKLB JSON content into a Checklist.
pub fn parse_cklb(json: &str) -> ParseResult<Checklist> {
    let cklb: CklbFile =
        serde_json::from_str(json).map_err(|e| ParseError::InvalidCklb(e.to_string()))?;

    let td = &cklb.target_data;
    let technology_area = match td.technology_area.as_deref() {
        Some(value) => Some(TechnologyArea::from_ckl_str(value).ok_or_else(|| {
            ParseError::InvalidCklb(format!(
                "unsupported STIG Viewer technology_area value {value:?}"
            ))
        })?),
        None => None,
    };
    let asset = Asset {
        hostname: td.host_name.clone().unwrap_or_default(),
        ip_address: td.ip_address.clone(),
        mac_address: td.mac_address.clone(),
        fqdn: td.fqdn.clone(),
        target_comment: td.comments.clone(),
        role: td
            .role
            .as_deref()
            .map(AssetRole::from_ckl_str)
            .unwrap_or(AssetRole::None),
        asset_type: td
            .target_type
            .as_deref()
            .map(AssetType::from_ckl_str)
            .unwrap_or(AssetType::Computing),
        os: td.os.clone(),
        technology_area,
        web_or_database: td.is_web_database.map(|value| value.to_string()),
        web_db_site: td.web_db_site.clone(),
        web_db_instance: td.web_db_instance.clone(),
        is_active: cklb.active.unwrap_or(true),
    };

    if cklb.stigs.len() != 1 {
        return Err(ParseError::InvalidCklb(format!(
            "A checklist must contain exactly one STIG; found {}",
            cklb.stigs.len()
        )));
    }
    let stig = &cklb.stigs[0];

    let release = stig
        .release_info
        .as_deref()
        .map(extract_release_number)
        .unwrap_or_else(|| "0".to_string());

    let stig_info = ChecklistStigInfo {
        stig_id: stig.stig_id.clone().unwrap_or_default(),
        title: stig
            .stig_name
            .clone()
            .or_else(|| stig.display_name.clone())
            .unwrap_or_default(),
        version: stig.version.clone().unwrap_or_default(),
        release,
        release_date: stig.release_info.as_deref().and_then(extract_release_date),
        uuid: stig.uuid.clone(),
        description: None,
        filename: None,
    };

    let mut checklist = Checklist::new(asset, stig_info);
    checklist.classification = parse_classification(td.classification.as_deref());

    for rule in &stig.rules {
        let vuln_id = rule
            .group_id_v
            .clone()
            .or_else(|| rule.group_id.clone())
            .or_else(|| rule.vuln_num.clone())
            .unwrap_or_default();
        let rule_id = rule
            .rule_id_src
            .clone()
            .or_else(|| rule.rule_id.clone())
            .unwrap_or_default();
        let group_id = rule.group_id.clone().unwrap_or_default();
        let title = rule.rule_title.clone().unwrap_or_default();
        let severity = rule
            .severity
            .as_deref()
            .and_then(Severity::from_cat_str)
            .unwrap_or(Severity::Medium);

        let status_str = rule.status.as_deref().unwrap_or("Not_Reviewed");

        let status = match status_str {
            "not_a_finding" | "NotAFinding" | "Not A Finding" => FindingStatus::NotAFinding,
            "open" | "Open" => FindingStatus::Open,
            "not_applicable" | "Not_Applicable" | "NotApplicable" => FindingStatus::NotApplicable,
            _ => FindingStatus::NotReviewed,
        };

        let mut finding =
            Finding::new_not_reviewed(&vuln_id, &rule_id, &group_id, &title, severity);
        finding.status = status;
        finding.source = FindingSource::Imported;

        finding.finding_details = rule
            .finding_details
            .clone()
            .or_else(|| rule.detail.clone())
            .unwrap_or_default();

        finding.comments = rule
            .comments
            .clone()
            .or_else(|| rule.comment.clone())
            .unwrap_or_default();

        finding.cci_refs = rule.ccis.clone().unwrap_or_default();
        finding.legacy_ids = rule.legacy_ids.clone().unwrap_or_default();
        finding.group_title = rule.group_title.clone().unwrap_or_else(|| group_id.clone());
        finding.rule_version = rule.rule_version.clone().unwrap_or_default();
        finding.weight = match rule.weight.as_deref() {
            Some(value) => value.parse().map_err(|error| {
                ParseError::InvalidCklb(format!("invalid weight for rule {rule_id}: {error}"))
            })?,
            None => severity.default_weight(),
        };
        finding.discussion = rule.discussion.clone().unwrap_or_default();
        finding.check_content = rule.check_content.clone().unwrap_or_default();
        finding.fix_text = rule.fix_text.clone().unwrap_or_default();
        finding.stig_ref = rule.srg_id.clone().filter(|value| !value.is_empty());
        finding.format_metadata = Some(serde_json::json!({
            "format": "cklb",
            "rule": serde_json::to_value(rule)?,
        }));

        if let Some(ref sev_override) = rule.severity_override {
            if !sev_override.is_empty() {
                finding.severity_override = Severity::from_cat_str(sev_override);
                finding.severity_override_justification = rule.severity_justification.clone();
            }
        }

        checklist.findings.push(finding);
    }

    Ok(checklist)
}

/// Write a Checklist to CKLB JSON format.
pub fn write_cklb(checklist: &Checklist) -> ParseResult<String> {
    let is_web_database = parse_web_or_database(checklist.asset.web_or_database.as_deref())?;
    let target_data = CklbTargetData {
        target_type: Some(checklist.asset.asset_type.as_ckl_str().to_string()),
        host_name: Some(checklist.asset.hostname.clone()),
        ip_address: checklist.asset.ip_address.clone(),
        mac_address: checklist.asset.mac_address.clone(),
        fqdn: checklist.asset.fqdn.clone(),
        comments: checklist.asset.target_comment.clone(),
        role: Some(checklist.asset.role.as_ckl_str().to_string()),
        is_web_database: Some(is_web_database),
        technology_area: checklist
            .asset
            .technology_area
            .map(TechnologyArea::as_ckl_str)
            .map(str::to_string),
        web_db_site: checklist.asset.web_db_site.clone(),
        web_db_instance: checklist.asset.web_db_instance.clone(),
        os: checklist.asset.os.clone(),
        classification: Some(checklist.classification.to_string()),
    };

    let rules: Vec<CklbRule> = checklist
        .findings
        .iter()
        .map(|f| -> ParseResult<CklbRule> {
            let mut rule: CklbRule = match f.format_metadata.as_ref() {
                Some(value)
                    if value.get("format").and_then(|item| item.as_str()) == Some("ckl") =>
                {
                    CklbRule::default()
                }
                Some(value)
                    if value.get("format").and_then(|item| item.as_str()) == Some("cklb") =>
                {
                    serde_json::from_value(value.get("rule").cloned().ok_or_else(|| {
                        ParseError::InvalidCklb(format!(
                            "retained CKLB metadata for rule {} is missing rule data",
                            f.rule_id
                        ))
                    })?)
                    .map_err(|error| {
                        ParseError::InvalidCklb(format!(
                            "invalid retained metadata for rule {}: {error}",
                            f.rule_id
                        ))
                    })?
                }
                Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
                    ParseError::InvalidCklb(format!(
                        "invalid retained metadata for rule {}: {error}",
                        f.rule_id
                    ))
                })?,
                None => CklbRule::default(),
            };
            rule.group_id = Some(f.group_id.clone());
            rule.group_id_v = Some(f.vuln_id.clone());
            rule.vuln_num = Some(f.vuln_id.clone());
            rule.rule_id = Some(f.rule_id.clone());
            rule.rule_id_src = Some(f.rule_id.clone());
            rule.rule_version = Some(f.rule_version.clone());
            rule.status = Some(cklb_status(f.status).to_string());
            rule.severity = Some(f.severity.as_xccdf_str().to_string());
            rule.weight = Some(
                if f.weight > 0.0 {
                    f.weight
                } else {
                    f.severity.default_weight()
                }
                .to_string(),
            );
            rule.group_title = Some(if f.group_title.is_empty() {
                f.group_id.clone()
            } else {
                f.group_title.clone()
            });
            rule.rule_title = Some(f.rule_title.clone());
            rule.fix_text = Some(f.fix_text.clone());
            rule.discussion = Some(f.discussion.clone());
            rule.check_content = Some(f.check_content.clone());
            rule.srg_id = f.stig_ref.clone();
            rule.legacy_ids = Some(f.legacy_ids.clone());
            rule.ccis = Some(f.cci_refs.clone());
            rule.finding_details = Some(f.finding_details.clone());
            rule.comments = Some(f.comments.clone());
            rule.severity_override = f.severity_override.map(|s| s.as_xccdf_str().to_string());
            rule.severity_justification = f.severity_override_justification.clone();
            Ok(rule)
        })
        .collect::<ParseResult<_>>()?;

    let version = (!checklist.stig_info.version.trim().is_empty())
        .then(|| checklist.stig_info.version.clone());

    let release_info = format!(
        "Release: {} Benchmark Date: {}",
        checklist.stig_info.release,
        checklist
            .stig_info
            .release_date
            .as_deref()
            .unwrap_or("Unknown")
    );

    let cklb = CklbFile {
        title: Some(checklist.stig_info.title.clone()),
        id: Some(checklist.id.to_string()),
        cklb_version: Some("1.0".to_string()),
        active: Some(checklist.asset.is_active),
        mode: Some(1),
        has_path: Some(true),
        target_data,
        stigs: vec![CklbStig {
            stig_name: Some(checklist.stig_info.title.clone()),
            display_name: Some(checklist.stig_info.title.clone()),
            stig_id: Some(checklist.stig_info.stig_id.clone()),
            version,
            release_info: Some(release_info),
            uuid: checklist.stig_info.uuid.clone(),
            reference_identifier: None,
            size: Some(rules.len() as i32),
            rules,
        }],
    };

    serde_json::to_string_pretty(&cklb).map_err(|e| ParseError::InvalidCklb(e.to_string()))
}

fn parse_classification(value: Option<&str>) -> Classification {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase()
        .as_str()
    {
        "CUI" => Classification::Cui,
        "CONFIDENTIAL" => Classification::Confidential,
        "SECRET" => Classification::Secret,
        "TOP SECRET" => Classification::TopSecret,
        _ => Classification::Unclassified,
    }
}

fn extract_release_number(release_info: &str) -> String {
    release_info
        .find("Release:")
        .and_then(|position| {
            release_info[position + "Release:".len()..]
                .split_whitespace()
                .next()
        })
        .unwrap_or("0")
        .to_string()
}

fn extract_release_date(release_info: &str) -> Option<String> {
    release_info
        .find("Benchmark Date:")
        .map(|position| {
            release_info[position + "Benchmark Date:".len()..]
                .trim()
                .to_string()
        })
        .filter(|value| !value.is_empty())
}

fn parse_web_or_database(value: Option<&str>) -> ParseResult<bool> {
    match value
        .unwrap_or("false")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "false" => Ok(false),
        "true" => Ok(true),
        other => Err(ParseError::InvalidCklb(format!(
            "invalid web_or_database boolean {other:?}"
        ))),
    }
}

fn cklb_status(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::NotReviewed => "not_reviewed",
        FindingStatus::NotAFinding => "not_a_finding",
        FindingStatus::Open => "open",
        FindingStatus::NotApplicable => "not_applicable",
    }
}

/// Write a Checklist to a CKLB file.
pub fn write_cklb_file(checklist: &Checklist, path: &Path) -> ParseResult<()> {
    let json = write_cklb(checklist)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cklb() -> String {
        serde_json::json!({
            "title": "Test STIG",
            "id": "test-id",
            "cklb_version": "1.0",
            "active": false,
            "mode": 1,
            "has_path": true,
            "target_data": {
                "target_type": "Computing",
                "host_name": "webserver01",
                "ip_address": "10.0.1.50",
                "mac_address": "00:11:22:33:44:55",
                "fqdn": "webserver01.example.mil",
                "comments": "Test server",
                "role": "Member Server",
                "is_web_database": true,
                "technology_area": "Web Review",
                "web_db_site": "mission-portal",
                "web_db_instance": "primary-db",
                "os": "FreeBSD 14.3",
                "classification": "CUI"
            },
            "stigs": [{
                "stig_name": "Windows Server 2022 STIG",
                "stig_id": "Windows_Server_2022_STIG",
                "version": "001",
                "release_info": "Release: 4 Benchmark Date: 24 Jul 2024",
                "uuid": "test-uuid",
                "size": 2,
                "rules": [
                    {
                        "group_id": "V-254239",
                        "group_id_v": "V-254239",
                        "rule_id": "SV-254239r958388_rule",
                        "rule_id_src": "SV-254239r958388_rule",
                        "rule_version": "WN22-00-000001",
                        "status": "open",
                        "severity": "high",
                        "weight": "10.0",
                        "group_title": "SRG-OS-000033-GPOS-00014",
                        "rule_title": "TLS 1.2 Required",
                        "discussion": "TLS protects data in transit.",
                        "fix_text": "Enable TLS.",
                        "check_content": "Review the device configuration.",
                        "srg_id": "SRG-OS-000033-GPOS-00014",
                        "group_tree": [{"id":"tree-1","title":"Operating System","description":"tree"}],
                        "viewer_extension": {"retained": true},
                        "finding_details": "Not configured",
                        "comments": "Needs fix",
                        "ccis": ["CCI-000068", "CCI-001084"],
                        "legacy_ids": ["WN22-00-000001", "WN22-TLS-000001"]
                    },
                    {
                        "group_id": "V-254240",
                        "group_id_v": "V-254240",
                        "rule_id": "SV-254240r958392_rule",
                        "rule_id_src": "SV-254240r958392_rule",
                        "status": "not_a_finding",
                        "severity": "medium",
                        "rule_title": "Password Complexity",
                        "finding_details": "Configured correctly",
                        "comments": "Verified"
                    }
                ]
            }]
        })
        .to_string()
    }

    #[test]
    fn test_parse_cklb() {
        let checklist = parse_cklb(&sample_cklb()).unwrap();

        assert_eq!(checklist.asset.hostname, "webserver01");
        assert!(!checklist.asset.is_active);
        assert_eq!(checklist.asset.os.as_deref(), Some("FreeBSD 14.3"));
        assert_eq!(
            checklist.asset.technology_area,
            Some(TechnologyArea::WebReview)
        );
        assert_eq!(checklist.asset.web_or_database.as_deref(), Some("true"));
        assert_eq!(
            checklist.asset.web_db_site.as_deref(),
            Some("mission-portal")
        );
        assert_eq!(
            checklist.asset.web_db_instance.as_deref(),
            Some("primary-db")
        );
        assert_eq!(checklist.classification, Classification::Cui);
        assert_eq!(checklist.stig_info.stig_id, "Windows_Server_2022_STIG");
        assert_eq!(checklist.stig_info.version, "001");
        assert_eq!(
            checklist.stig_info.release_date.as_deref(),
            Some("24 Jul 2024")
        );
        assert_eq!(checklist.findings.len(), 2);

        let f1 = checklist.find_by_vuln_id("V-254239").unwrap();
        assert_eq!(f1.status, FindingStatus::Open);
        assert_eq!(f1.severity, Severity::High);
        assert_eq!(f1.rule_version, "WN22-00-000001");
        assert_eq!(f1.cci_refs, ["CCI-000068", "CCI-001084"]);
        assert_eq!(f1.legacy_ids, ["WN22-00-000001", "WN22-TLS-000001"]);

        let f2 = checklist.find_by_vuln_id("V-254240").unwrap();
        assert_eq!(f2.status, FindingStatus::NotAFinding);
    }

    #[test]
    fn test_cklb_roundtrip() {
        let checklist = parse_cklb(&sample_cklb()).unwrap();
        let json_out = write_cklb(&checklist).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&json_out).unwrap();
        let raw_rule = &raw["stigs"][0]["rules"][0];
        assert_eq!(raw_rule["viewer_extension"]["retained"], true);
        assert_eq!(raw_rule["group_tree"][0]["id"], "tree-1");
        assert_eq!(raw["active"], false);
        assert_eq!(raw["target_data"]["technology_area"], "Web Review");
        assert_eq!(raw["target_data"]["web_db_site"], "mission-portal");
        assert_eq!(raw["target_data"]["web_db_instance"], "primary-db");
        assert_eq!(raw["target_data"]["os"], "FreeBSD 14.3");
        assert_eq!(raw["target_data"]["classification"], "CUI");
        let parsed_back = parse_cklb(&json_out).unwrap();

        assert_eq!(parsed_back.asset.hostname, "webserver01");
        assert_eq!(parsed_back.findings.len(), 2);
        assert_eq!(
            parsed_back.find_by_vuln_id("V-254239").unwrap().status,
            FindingStatus::Open
        );
        let finding = parsed_back.find_by_vuln_id("V-254239").unwrap();
        assert_eq!(finding.group_title, "SRG-OS-000033-GPOS-00014");
        assert_eq!(finding.discussion, "TLS protects data in transit.");
        assert_eq!(finding.fix_text, "Enable TLS.");
        assert_eq!(finding.check_content, "Review the device configuration.");
        assert_eq!(finding.rule_version, "WN22-00-000001");
        assert_eq!(finding.legacy_ids, ["WN22-00-000001", "WN22-TLS-000001"]);
    }

    #[test]
    fn rejects_multi_stig_cklb_instead_of_silently_dropping_data() {
        let mut value: serde_json::Value = serde_json::from_str(&sample_cklb()).unwrap();
        let second = value["stigs"][0].clone();
        value["stigs"].as_array_mut().unwrap().push(second);
        let error = parse_cklb(&value.to_string()).unwrap_err().to_string();
        assert!(error.contains("exactly one STIG"));
    }

    #[test]
    fn rejects_malformed_retained_metadata_instead_of_discarding_it() {
        let mut checklist = parse_cklb(&sample_cklb()).unwrap();
        checklist.findings[0].format_metadata = Some(serde_json::json!("not a CKLB rule"));

        let error = write_cklb(&checklist).unwrap_err().to_string();
        assert!(error.contains("invalid retained metadata"));
    }

    #[test]
    fn ckl_retention_metadata_is_not_emitted_as_nonstandard_cklb_fields() {
        let mut checklist = parse_cklb(&sample_cklb()).unwrap();
        checklist.findings[0].format_metadata = Some(serde_json::json!({
            "format": "ckl",
            "attributes": {"ViewerOnlyCklField": "retained for CKL only"}
        }));

        let output: serde_json::Value =
            serde_json::from_str(&write_cklb(&checklist).unwrap()).unwrap();
        let rule = &output["stigs"][0]["rules"][0];
        assert!(rule.get("format").is_none());
        assert!(rule.get("attributes").is_none());
        assert!(rule.get("ViewerOnlyCklField").is_none());
    }
}
