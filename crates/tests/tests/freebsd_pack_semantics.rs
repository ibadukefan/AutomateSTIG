use std::collections::{HashMap, HashSet};

use automatestig_core::checks::executor::{execute_check, execute_check_pack};
use automatestig_core::checks::{CheckPack, SystemData};
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::remote::generate_collection_plan;
use automatestig_parsers::evidence::{assemble_for_plan, parse_evidence, LegacyEvidencePolicy};

const AUTOMATED_IDS: [&str; 6] = [
    "V-203767", "V-203621", "V-203774", "V-203772", "V-203615", "V-203784",
];

const ADDED_IDS: [&str; 5] = ["V-203767", "V-203621", "V-203774", "V-203772", "V-203784"];

const MANUAL_IDS: [&str; 24] = [
    "V-278977", "V-203595", "V-203665", "V-203597", "V-203683", "V-203594", "V-203625", "V-203626",
    "V-203627", "V-203676", "V-203634", "V-203632", "V-203630", "V-203669", "V-203736", "V-203737",
    "V-203645", "V-203646", "V-203700", "V-203777", "V-203711", "V-203712", "V-203714", "V-203754",
];

fn pack() -> CheckPack {
    serde_json::from_str(include_str!(
        "../../../content/check_packs/freebsd_gpos.json"
    ))
    .expect("the shipped FreeBSD check pack must deserialize")
}

fn coverage_manifest() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../content/coverage/current-checkpacks/freebsd_gpos.current.json"
    ))
    .expect("the shipped FreeBSD coverage manifest must deserialize")
}

fn outputs(entries: &[(&str, &str)]) -> SystemData {
    SystemData {
        collection_complete: true,
        command_outputs: entries
            .iter()
            .map(|(command, output)| ((*command).to_string(), (*output).to_string()))
            .collect::<HashMap<_, _>>(),
        ..SystemData::default()
    }
}

fn fixture_data(raw: &str) -> SystemData {
    let pack = pack();
    let plan = generate_collection_plan(pack.platform, &pack.checks).unwrap();
    let transcript = parse_evidence(raw, LegacyEvidencePolicy::Reject).unwrap();
    assemble_for_plan(&transcript, &plan).unwrap()
}

fn status_for(pack: &CheckPack, data: &SystemData, vuln_id: &str) -> FindingStatus {
    let definition = pack
        .checks
        .iter()
        .find(|definition| definition.vuln_id == vuln_id)
        .unwrap();
    execute_check(definition, data).to_finding_status()
}

#[test]
fn freebsd_pack_contains_the_reviewed_effective_state_checks() {
    let pack = pack();
    let ids = pack
        .checks
        .iter()
        .map(|definition| definition.vuln_id.as_str())
        .collect::<HashSet<_>>();
    assert_eq!(ids, HashSet::from(AUTOMATED_IDS));

    for vuln_id in MANUAL_IDS {
        assert!(
            !ids.contains(vuln_id),
            "{vuln_id} must remain manual until its complete semantics can be collected"
        );
    }

    let plan = generate_collection_plan(pack.platform, &pack.checks).unwrap();
    let commands = plan
        .commands
        .iter()
        .map(|command| command.data_key.as_str())
        .collect::<HashSet<_>>();
    assert_eq!(
        commands,
        HashSet::from([
            "service auditd onestatus",
            "cat /etc/security/audit_control",
            "cat /etc/security/audit_user",
            "sha256 -q /etc/security/audit_class",
            "sha256 -q /etc/security/audit_event",
            "service pf onestatus",
        ])
    );
}

#[test]
fn coverage_preserves_the_reviewed_inventory_and_manual_boundary() {
    let pack = pack();
    let pack_ids = pack
        .checks
        .iter()
        .map(|definition| definition.vuln_id.as_str())
        .collect::<HashSet<_>>();
    let manifest = coverage_manifest();
    let rules = manifest["rules"].as_array().unwrap();
    assert_eq!(manifest["total_rules"], 30);
    assert_eq!(rules.len(), 30);

    let classified = |classification: &str| {
        rules
            .iter()
            .filter(|rule| rule["classification"] == classification)
            .map(|rule| rule["vuln_id"].as_str().unwrap())
            .collect::<HashSet<_>>()
    };
    assert_eq!(classified("automated"), pack_ids);
    assert_eq!(classified("manual"), HashSet::from(MANUAL_IDS));

    for rule in rules
        .iter()
        .filter(|rule| rule["classification"] == "manual")
    {
        assert!(rule.get("check_pack").is_none());
        assert!(rule.get("check_id").is_none());
        assert!(rule["reason"]
            .as_str()
            .unwrap()
            .contains("cannot prove this rule's effective semantics"));
    }
}

#[test]
fn every_added_rule_has_compliant_finding_transport_and_truncation_coverage() {
    let pack = pack();
    let cases = [
        (
            "compliant",
            fixture_data(include_str!(
                "../../../fixtures/bsd/bsd_evidence_compliant.json"
            )),
            FindingStatus::NotAFinding,
        ),
        (
            "finding",
            fixture_data(include_str!(
                "../../../fixtures/bsd/bsd_evidence_findings.json"
            )),
            FindingStatus::Open,
        ),
        (
            "transport",
            fixture_data(include_str!(
                "../../../fixtures/bsd/bsd_evidence_transport_failure.json"
            )),
            FindingStatus::NotReviewed,
        ),
        (
            "truncation",
            fixture_data(include_str!(
                "../../../fixtures/bsd/bsd_evidence_truncated.json"
            )),
            FindingStatus::NotReviewed,
        ),
    ];

    for vuln_id in ADDED_IDS {
        for (scenario, data, expected) in &cases {
            assert_eq!(
                status_for(&pack, data, vuln_id),
                *expected,
                "{vuln_id} did not produce {expected:?} for {scenario} evidence"
            );
        }
    }
}

#[test]
fn missing_or_ambiguous_added_rule_evidence_fails_closed() {
    let pack = pack();
    for vuln_id in ADDED_IDS {
        assert_eq!(
            status_for(&pack, &SystemData::default(), vuln_id),
            FindingStatus::NotReviewed,
            "{vuln_id} accepted missing evidence"
        );
    }

    let ambiguous_audit = outputs(&[
        (
            "sha256 -q /etc/security/audit_class",
            "834a1fde758a45269874a5c0655046ca7354a7afa3cf9aee8d29bbfe5d8ab2fd",
        ),
        (
            "sha256 -q /etc/security/audit_event",
            "124c60b738ec9eb36e497213fded40a7ed9023dc7854258f9c17d5cbcfffcff2",
        ),
        ("service auditd onestatus", "auditd is running as pid 123."),
        (
            "cat /etc/security/audit_control",
            "flags:all\nflags:all\nnaflags:all",
        ),
        ("cat /etc/security/audit_user", "# none"),
    ]);
    for vuln_id in &ADDED_IDS[..4] {
        assert_eq!(
            status_for(&pack, &ambiguous_audit, vuln_id),
            FindingStatus::NotReviewed,
            "{vuln_id} accepted duplicate OpenBSM fields"
        );
    }

    let unreviewed_mapping = outputs(&[
        (
            "sha256 -q /etc/security/audit_class",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "sha256 -q /etc/security/audit_event",
            "124c60b738ec9eb36e497213fded40a7ed9023dc7854258f9c17d5cbcfffcff2",
        ),
        ("service auditd onestatus", "auditd is running as pid 123."),
        ("cat /etc/security/audit_control", "flags:all\nnaflags:all"),
        ("cat /etc/security/audit_user", "# none"),
    ]);
    for vuln_id in &ADDED_IDS[..4] {
        assert_eq!(
            status_for(&pack, &unreviewed_mapping, vuln_id),
            FindingStatus::NotReviewed,
            "{vuln_id} trusted an unreviewed OpenBSM class mapping"
        );
    }

    let ambiguous_pf = outputs(&[("service pf onestatus", "Status: Enabled\nStatus: Disabled")]);
    assert_eq!(
        status_for(&pack, &ambiguous_pf, "V-203784"),
        FindingStatus::NotReviewed
    );
}

#[test]
fn valid_counterexamples_are_findings_not_automated_passes() {
    let data = outputs(&[
        (
            "sha256 -q /etc/security/audit_class",
            "834a1fde758a45269874a5c0655046ca7354a7afa3cf9aee8d29bbfe5d8ab2fd",
        ),
        (
            "sha256 -q /etc/security/audit_event",
            "124c60b738ec9eb36e497213fded40a7ed9023dc7854258f9c17d5cbcfffcff2",
        ),
        ("service auditd onestatus", "auditd is not running."),
        (
            "cat /etc/security/audit_control",
            "flags:+lo,+aa,+ad,+fr,+fw,+fa,+fm,+fc,+fd\nnaflags:-lo,-aa,-ad,-fr,-fw,-fa,-fm,-fc,-fd",
        ),
        ("cat /etc/security/audit_user", "root:no:lo,aa,ad"),
        ("service pf onestatus", "Status: Disabled"),
    ]);

    let results = execute_check_pack(&pack(), &data);
    assert_eq!(results.len(), AUTOMATED_IDS.len());
    assert!(results
        .iter()
        .all(|result| result.to_finding_status() == FindingStatus::Open));
    for vuln_id in MANUAL_IDS {
        assert!(results.iter().all(|result| result.vuln_id != vuln_id));
    }
}

#[test]
fn compliant_fixture_passes_every_automated_rule() {
    let data = fixture_data(include_str!(
        "../../../fixtures/bsd/bsd_evidence_compliant.json"
    ));
    let results = execute_check_pack(&pack(), &data);
    assert_eq!(results.len(), AUTOMATED_IDS.len());
    assert!(results
        .iter()
        .all(|result| result.to_finding_status() == FindingStatus::NotAFinding));
}
