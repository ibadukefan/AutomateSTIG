//! CKLB (Checklist B) parser — JSON-based format used by STIG Viewer 3.x.
//!
//! CKLB files are JSON documents that contain the same data as CKL but in a
//! more modern, easier-to-parse format.

use std::path::Path;

use serde::{Deserialize, Serialize};

use automatestig_core::models::asset::{Asset, AssetRole, AssetType};
use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
use automatestig_core::models::stig::Severity;

use crate::error::{ParseError, ParseResult};
use crate::util::{read_to_string_capped, PARSE_FILE_SIZE_LIMIT_BYTES};

/// Raw CKLB file structure (for deserialization).
#[derive(Debug, Serialize, Deserialize)]
pub struct CklbFile {
    pub title: Option<String>,
    pub id: Option<String>,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CklbStig {
    pub stig_name: Option<String>,
    pub display_name: Option<String>,
    pub stig_id: Option<String>,
    pub version: Option<i32>,
    pub release_info: Option<String>,
    pub uuid: Option<String>,
    pub reference_identifier: Option<String>,
    pub size: Option<i32>,
    pub rules: Vec<CklbRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CklbRule {
    pub group_id: Option<String>,
    pub group_id_v: Option<String>,
    pub group_tree: Option<Vec<CklbGroupTree>>,
    pub rule_id: Option<String>,
    pub rule_id_src: Option<String>,
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
        os: None,
        technology_area: None,
        web_or_database: None,
        is_active: cklb.active.unwrap_or(true),
    };

    // Take the first STIG (CKLB files can contain multiple).
    let stig = cklb
        .stigs
        .first()
        .ok_or_else(|| ParseError::InvalidCklb("No STIGs found in CKLB file".to_string()))?;

    let release = stig
        .release_info
        .as_deref()
        .map(|r| r.split_whitespace().nth(1).unwrap_or("0").to_string())
        .unwrap_or_else(|| "0".to_string());

    let stig_info = ChecklistStigInfo {
        stig_id: stig.stig_id.clone().unwrap_or_default(),
        title: stig.stig_name.clone().unwrap_or_default(),
        version: stig.version.map(|v| v.to_string()).unwrap_or_default(),
        release,
        release_date: None,
        uuid: stig.uuid.clone(),
        description: None,
        filename: None,
    };

    let mut checklist = Checklist::new(asset, stig_info);

    for rule in &stig.rules {
        let vuln_id = rule
            .group_id_v
            .clone()
            .or_else(|| rule.group_id.clone())
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
    let target_data = CklbTargetData {
        target_type: Some(checklist.asset.asset_type.as_ckl_str().to_string()),
        host_name: Some(checklist.asset.hostname.clone()),
        ip_address: checklist.asset.ip_address.clone(),
        mac_address: checklist.asset.mac_address.clone(),
        fqdn: checklist.asset.fqdn.clone(),
        comments: checklist.asset.target_comment.clone(),
        role: Some(checklist.asset.role.as_ckl_str().to_string()),
        is_web_database: Some(false),
        technology_area: None,
        web_db_site: None,
        web_db_instance: None,
    };

    let rules: Vec<CklbRule> = checklist
        .findings
        .iter()
        .map(|f| CklbRule {
            group_id: Some(f.group_id.clone()),
            group_id_v: Some(f.vuln_id.clone()),
            group_tree: None,
            rule_id: Some(f.rule_id.clone()),
            rule_id_src: Some(f.rule_id.clone()),
            stig_uuid: None,
            status: Some(f.status.as_ckl_str().to_string()),
            severity: Some(f.severity.as_xccdf_str().to_string()),
            weight: Some(f.severity.default_weight().to_string()),
            classification: None,
            group_title: Some(f.group_id.clone()),
            rule_title: Some(f.rule_title.clone()),
            fix_text: None,
            false_positives: None,
            false_negatives: None,
            discussion: None,
            check_content: None,
            documentable: None,
            mitigations: None,
            potential_impacts: None,
            third_party_tools: None,
            mitigation_control: None,
            responsibility: None,
            security_override_guidance: None,
            ia_controls: None,
            check_content_ref: None,
            legacy_ids: Some(f.legacy_ids.clone()),
            ccis: Some(f.cci_refs.clone()),
            detail: None,
            comment: None,
            finding_details: Some(f.finding_details.clone()),
            comments: Some(f.comments.clone()),
            severity_override: f.severity_override.map(|s| s.as_xccdf_str().to_string()),
            severity_justification: f.severity_override_justification.clone(),
            overrides: None,
        })
        .collect();

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
        active: Some(true),
        mode: Some(1),
        has_path: Some(true),
        target_data,
        stigs: vec![CklbStig {
            stig_name: Some(checklist.stig_info.title.clone()),
            display_name: Some(checklist.stig_info.title.clone()),
            stig_id: Some(checklist.stig_info.stig_id.clone()),
            version: checklist.stig_info.version.parse().ok(),
            release_info: Some(release_info),
            uuid: checklist.stig_info.uuid.clone(),
            reference_identifier: None,
            size: Some(rules.len() as i32),
            rules,
        }],
    };

    serde_json::to_string_pretty(&cklb).map_err(|e| ParseError::InvalidCklb(e.to_string()))
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
            "active": true,
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
                "is_web_database": false
            },
            "stigs": [{
                "stig_name": "Windows Server 2022 STIG",
                "stig_id": "Windows_Server_2022_STIG",
                "version": 1,
                "release_info": "Release: 4",
                "uuid": "test-uuid",
                "size": 2,
                "rules": [
                    {
                        "group_id": "V-254239",
                        "group_id_v": "V-254239",
                        "rule_id": "SV-254239r958388_rule",
                        "rule_id_src": "SV-254239r958388_rule",
                        "status": "open",
                        "severity": "high",
                        "rule_title": "TLS 1.2 Required",
                        "finding_details": "Not configured",
                        "comments": "Needs fix",
                        "ccis": ["CCI-000068"]
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
        assert_eq!(checklist.stig_info.stig_id, "Windows_Server_2022_STIG");
        assert_eq!(checklist.findings.len(), 2);

        let f1 = checklist.find_by_vuln_id("V-254239").unwrap();
        assert_eq!(f1.status, FindingStatus::Open);
        assert_eq!(f1.severity, Severity::High);

        let f2 = checklist.find_by_vuln_id("V-254240").unwrap();
        assert_eq!(f2.status, FindingStatus::NotAFinding);
    }

    #[test]
    fn test_cklb_roundtrip() {
        let checklist = parse_cklb(&sample_cklb()).unwrap();
        let json_out = write_cklb(&checklist).unwrap();
        let parsed_back = parse_cklb(&json_out).unwrap();

        assert_eq!(parsed_back.asset.hostname, "webserver01");
        assert_eq!(parsed_back.findings.len(), 2);
        assert_eq!(
            parsed_back.find_by_vuln_id("V-254239").unwrap().status,
            FindingStatus::Open
        );
    }
}
