//! STIG-Manager integration.
//!
//! Provides data structures and offline JSON export functions for
//! STIG-Manager compatibility, plus the canonical scanner-delivery API client.

mod client;

pub use client::*;

use serde::{Deserialize, Serialize};

use automatestig_core::models::checklist::Checklist;
use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};

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
}

/// Convert a Checklist to STIG-Manager import format.
pub fn checklist_to_stig_manager(checklist: &Checklist) -> StigManagerImport {
    let reviews: Vec<StigManagerReview> = checklist
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.source,
                FindingSource::Automated | FindingSource::Evidence
            ) && finding.status != FindingStatus::NotReviewed
        })
        .map(finding_to_review)
        .collect();

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
    let is_automated = finding.source == FindingSource::Automated;

    // Supplied evidence is not a live autoResult, but the deterministic
    // AutomateSTIG evaluator still owns the result for provenance/conflict
    // purposes.
    let result_engine = Some(ResultEngine {
        engine_type: "script".to_string(),
        product: "AutomateSTIG".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    });

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
        f.source = FindingSource::Automated;
        f.finding_details = "Collected evidence did not match the expected value".to_string();
        f.comments = "AutomateSTIG evidence transcript".to_string();
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
        f.source = FindingSource::Automated;
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
    fn export_contains_only_completed_scanner_owned_reviews() {
        let mut checklist = golden_checklist();

        let mut manual =
            Finding::new_not_reviewed("V-2", "SV-2_rule", "V-2", "Manual rule", Severity::Medium);
        manual.status = FindingStatus::Open;
        manual.source = FindingSource::Manual;
        checklist.findings.push(manual);

        let mut evidence = Finding::new_not_reviewed(
            "V-3",
            "SV-3_rule",
            "V-3",
            "Supplied evidence rule",
            Severity::Low,
        );
        evidence.status = FindingStatus::NotAFinding;
        evidence.source = FindingSource::Evidence;
        checklist.findings.push(evidence);

        let mut error = Finding::new_not_reviewed(
            "V-4",
            "SV-4_rule",
            "V-4",
            "Collection error",
            Severity::High,
        );
        error.source = FindingSource::CollectionError;
        checklist.findings.push(error);

        let output = checklist_to_stig_manager(&checklist);
        let reviews = &output.assets[0].stigs[0].reviews;
        assert_eq!(reviews.len(), 2);
        assert_eq!(reviews[0].rule_id, "SV-1r1_rule");
        assert!(reviews[0].auto_result);
        assert_eq!(reviews[1].rule_id, "SV-3_rule");
        assert!(!reviews[1].auto_result);
        assert_eq!(
            reviews[1].result_engine.as_ref().unwrap().product,
            "AutomateSTIG"
        );
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
