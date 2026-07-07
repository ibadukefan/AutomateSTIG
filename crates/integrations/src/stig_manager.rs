//! STIG-Manager integration.
//!
//! Provides data structures and export functions for STIG-Manager compatibility.
//! The actual HTTP client is gated behind a feature flag since it requires
//! network access (not available in air-gapped mode).

use serde::{Deserialize, Serialize};

use automatestig_core::models::checklist::Checklist;
use automatestig_core::models::finding::{Finding, FindingSource};

/// STIG-Manager collection import format.
#[derive(Debug, Serialize, Deserialize)]
pub struct StigManagerImport {
    /// Collection name.
    pub collection: String,

    /// Assets with their review data.
    pub assets: Vec<StigManagerAsset>,
}

/// A single asset in STIG-Manager import format.
#[derive(Debug, Serialize, Deserialize)]
pub struct StigManagerAsset {
    /// Asset name (hostname).
    pub name: String,

    /// IP address.
    pub ip: Option<String>,

    /// FQDN.
    pub fqdn: Option<String>,

    /// MAC address.
    pub mac: Option<String>,

    /// STIGs evaluated for this asset.
    pub stigs: Vec<StigManagerStigReview>,
}

/// Review data for one STIG on one asset.
#[derive(Debug, Serialize, Deserialize)]
pub struct StigManagerStigReview {
    /// STIG benchmark ID.
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,

    /// Individual rule reviews.
    pub reviews: Vec<StigManagerReview>,
}

/// A single rule review in STIG-Manager format.
#[derive(Debug, Serialize, Deserialize)]
pub struct StigManagerReview {
    /// Rule ID.
    #[serde(rename = "ruleId")]
    pub rule_id: String,

    /// Result: "pass", "fail", "notapplicable", "notchecked", etc.
    pub result: String,

    /// Result comment / finding details.
    pub detail: String,

    /// Reviewer comment.
    pub comment: String,

    /// Whether this was an automated result.
    #[serde(rename = "autoResult")]
    pub auto_result: bool,

    /// Result engine metadata (for automated results).
    #[serde(rename = "resultEngine", skip_serializing_if = "Option::is_none")]
    pub result_engine: Option<ResultEngine>,

    /// Status (saved, submitted, accepted, rejected).
    pub status: String,
}

/// Result Engine metadata for STIG-Manager.
/// This tells STIG-Manager that the result was produced by automated tooling.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResultEngine {
    /// Engine type identifier.
    #[serde(rename = "type")]
    pub engine_type: String,

    /// Product name.
    pub product: String,

    /// Product version.
    pub version: String,

    /// When the check was performed.
    #[serde(rename = "checkContent", skip_serializing_if = "Option::is_none")]
    pub check_content: Option<CheckContent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckContent {
    /// Location/source of the check.
    pub location: Option<String>,

    /// Hash of the check content for reproducibility.
    #[serde(rename = "component")]
    pub component: Option<String>,
}

/// Convert a Checklist to STIG-Manager import format.
pub fn checklist_to_stig_manager(checklist: &Checklist) -> StigManagerImport {
    let reviews: Vec<StigManagerReview> =
        checklist.findings.iter().map(finding_to_review).collect();

    StigManagerImport {
        collection: String::new(), // Set by caller.
        assets: vec![StigManagerAsset {
            name: checklist.asset.hostname.clone(),
            ip: checklist.asset.ip_address.clone(),
            fqdn: checklist.asset.fqdn.clone(),
            mac: checklist.asset.mac_address.clone(),
            stigs: vec![StigManagerStigReview {
                benchmark_id: checklist.stig_info.stig_id.clone(),
                reviews,
            }],
        }],
    }
}

fn finding_to_review(finding: &Finding) -> StigManagerReview {
    let is_automated = matches!(
        finding.source,
        FindingSource::Automated
            | FindingSource::SccScan
            | FindingSource::AcasScan
            | FindingSource::OpenScap
            | FindingSource::CustomCheck
    );

    let result_engine = if is_automated {
        Some(ResultEngine {
            engine_type: "script".to_string(),
            product: "AutomateSTIG".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            check_content: None,
        })
    } else {
        None
    };

    StigManagerReview {
        rule_id: finding.rule_id.clone(),
        result: finding.status.as_stig_manager_str().to_string(),
        detail: finding.finding_details.clone(),
        comment: finding.comments.clone(),
        auto_result: is_automated,
        result_engine,
        status: "saved".to_string(),
    }
}

/// Export multiple checklists to a single STIG-Manager import JSON.
pub fn export_to_stig_manager_json(
    checklists: &[Checklist],
    collection_name: &str,
) -> Result<String, serde_json::Error> {
    let mut import = StigManagerImport {
        collection: collection_name.to_string(),
        assets: Vec::new(),
    };

    for cl in checklists {
        let single = checklist_to_stig_manager(cl);
        import.assets.extend(single.assets);
    }

    serde_json::to_string_pretty(&import)
}

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
    use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
    use automatestig_core::models::stig::Severity;

    fn golden_checklist() -> Checklist {
        let stig_info = ChecklistStigInfo {
            stig_id: "Golden_STIG".to_string(),
            title: "Golden STIG".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };

        let mut cl = Checklist::new(Asset::new("golden-host"), stig_info);
        let mut f =
            Finding::new_not_reviewed("V-1", "SV-1r1_rule", "V-1", "Golden Rule", Severity::High);
        f.status = FindingStatus::Open;
        f.source = FindingSource::SccScan;
        f.finding_details = "Scanner evidence: registry value missing".to_string();
        f.comments = "Scanner: SCC\nRaw result: fail".to_string();
        f.cci_refs = vec!["CCI-000068".to_string()];
        cl.findings.push(f);
        cl
    }

    #[test]
    fn test_export_to_stig_manager() {
        let stig_info = ChecklistStigInfo {
            stig_id: "Test_STIG".to_string(),
            title: "Test".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };

        let mut cl = Checklist::new(Asset::new("webserver01"), stig_info);
        let mut f = Finding::new_not_reviewed("V-1", "SV-1r1_rule", "V-1", "Test", Severity::High);
        f.status = FindingStatus::Open;
        f.source = FindingSource::SccScan;
        f.finding_details = "Not configured".to_string();
        cl.findings.push(f);

        let json = export_to_stig_manager_json(&[cl], "Test Collection").unwrap();
        let parsed: StigManagerImport = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.collection, "Test Collection");
        assert_eq!(parsed.assets.len(), 1);
        assert_eq!(parsed.assets[0].name, "webserver01");
        assert_eq!(parsed.assets[0].stigs[0].reviews[0].result, "fail");
        assert!(parsed.assets[0].stigs[0].reviews[0].auto_result);
        assert!(parsed.assets[0].stigs[0].reviews[0].result_engine.is_some());
    }

    #[test]
    fn test_stig_manager_golden_payload() {
        let json = export_to_stig_manager_json(&[golden_checklist()], "Golden Collection").unwrap();
        let actual: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/exports/stig_manager_golden.json"
        ))
        .unwrap();

        // resultEngine.version follows CARGO_PKG_VERSION, so the fixture value
        // goes stale on every version bump; normalize it before comparing.
        for asset in expected["assets"].as_array_mut().unwrap() {
            for stig in asset["stigs"].as_array_mut().unwrap() {
                for review in stig["reviews"].as_array_mut().unwrap() {
                    if let Some(engine) = review.get_mut("resultEngine") {
                        engine["version"] =
                            serde_json::Value::String(env!("CARGO_PKG_VERSION").to_string());
                    }
                }
            }
        }

        assert_eq!(actual, expected);
    }
}
