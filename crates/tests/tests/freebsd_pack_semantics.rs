use std::collections::{HashMap, HashSet};

use automatestig_core::checks::executor::execute_check_pack;
use automatestig_core::checks::{CheckPack, SystemData};
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::remote::generate_collection_plan;

const RETAINED_IDS: [&str; 3] = ["V-203615", "V-203714", "V-203754"];

const REMOVED_IDS: [&str; 27] = [
    "V-278977", "V-203595", "V-203665", "V-203597", "V-203683", "V-203594", "V-203625", "V-203626",
    "V-203627", "V-203676", "V-203634", "V-203632", "V-203630", "V-203669", "V-203736", "V-203737",
    "V-203645", "V-203646", "V-203767", "V-203621", "V-203774", "V-203772", "V-203700", "V-203777",
    "V-203711", "V-203712", "V-203784",
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

#[test]
fn freebsd_pack_contains_only_direct_effective_state_checks() {
    let pack = pack();
    let ids = pack
        .checks
        .iter()
        .map(|definition| definition.vuln_id.as_str())
        .collect::<HashSet<_>>();
    assert_eq!(ids, HashSet::from(RETAINED_IDS));

    for vuln_id in REMOVED_IDS {
        assert!(
            !ids.contains(vuln_id),
            "{vuln_id} must remain manual until its effective semantics can be collected"
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
            "cat /var/db/zoneinfo",
            "sysctl kern.elf64.aslr.enable",
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
    assert_eq!(classified("manual"), HashSet::from(REMOVED_IDS));

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
fn known_configuration_counterexamples_cannot_be_automated_passes() {
    // These are the exact false-pass shapes which motivated removing raw-file
    // heuristics. They intentionally include conflicting first/effective
    // directives, disabled PAM enforcement, audit prefixes, and an unbound
    // banner. Keeping the text here makes any future re-automation confront
    // the complete adversarial corpus instead of reintroducing a line regex.
    let data = outputs(&[
        ("freebsd-version -k", "13.4-RELEASE-p9"),
        (
            "cat /etc/ssh/sshd_config",
            "Banner none\nBanner /etc/issue\nBanner /etc/empty\n\
             MaxSessions 100\nMaxSessions 10\n\
             ClientAliveInterval 1200\nClientAliveInterval 600\n\
             ClientAliveCountMax 100\n\
             Ciphers 3des-cbc\nCiphers aes256-ctr\n\
             MACs hmac-md5\nMACs hmac-sha2-256\n\
             Include /usr/local/etc/ssh/sshd_config.d/*.conf\n\
             Match User example\nProtocol 2",
        ),
        (
            "cat /etc/rc.conf",
            "blacklistd_enable=YES\nblacklistd_enable=NO\n\
             auditdistd_enable=YES\nauditdistd_enable=NO\n\
             ntpd_enable=YES\nntpd_enable=NO\n\
             pf_enable=YES\npf_enable=NO\ntelnetd_enable=YES",
        ),
        (
            "cat /etc/pam.d/passwd",
            "password sufficient pam_unix.so\n\
             password optional pam_passwdqc.so \
             min=disabled,disabled,disabled,disabled,15 enforce=none",
        ),
        (
            "cat /etc/security/audit_control",
            "flags:-lo,+aa,-ad,+fr\nexpire-after:14d",
        ),
        (
            "cat /etc/login.conf",
            "default:\\\n  :passwordtime=90d:\nunused:\\\n  :passwordtime=60d:",
        ),
        (
            "cat /etc/motd.template /etc/motd",
            "You are accessing a U.S. Government (USG) Information System",
        ),
        ("cat /etc/ntp.conf", "server not-authoritative.invalid"),
        ("service auditd onestatus", "auditd is not running."),
        ("cat /var/db/zoneinfo", "Etc/GMT+5"),
        (
            "sysctl kern.elf64.aslr.enable",
            "kern.elf64.aslr.enable: 0\nkern.elf64.aslr.enable: 1",
        ),
    ]);

    let results = execute_check_pack(&pack(), &data);
    assert_eq!(results.len(), RETAINED_IDS.len());
    assert!(results
        .iter()
        .all(|result| result.to_finding_status() == FindingStatus::Open));
    for vuln_id in REMOVED_IDS {
        assert!(
            results.iter().all(|result| result.vuln_id != vuln_id),
            "removed heuristic {vuln_id} must not produce NotAFinding"
        );
    }
}

#[test]
fn exact_effective_state_evidence_can_pass_the_retained_checks() {
    let data = outputs(&[
        ("service auditd onestatus", "auditd is running as pid 812."),
        ("cat /var/db/zoneinfo", "Etc/UTC\n"),
        (
            "sysctl kern.elf64.aslr.enable",
            "kern.elf64.aslr.enable: 1\n",
        ),
    ]);
    let results = execute_check_pack(&pack(), &data);
    assert_eq!(results.len(), RETAINED_IDS.len());
    assert!(results
        .iter()
        .all(|result| result.to_finding_status() == FindingStatus::NotAFinding));
}

#[test]
fn retained_patterns_reject_ambiguous_or_embedded_success_text() {
    let cases = [
        (
            "service auditd onestatus",
            "auditd is running? no",
            "cat /var/db/zoneinfo",
            "UTC",
            "sysctl kern.elf64.aslr.enable",
            "kern.elf64.aslr.enable: 1",
        ),
        (
            "service auditd onestatus",
            "auditd is running as pid 0.",
            "cat /var/db/zoneinfo",
            "America/UTCville",
            "sysctl kern.elf64.aslr.enable",
            "kern.elf64.aslr.enable: 1",
        ),
        (
            "service auditd onestatus",
            "auditd is running.",
            "cat /var/db/zoneinfo",
            "UTC",
            "sysctl kern.elf64.aslr.enable",
            "warning\nkern.elf64.aslr.enable: 1",
        ),
    ];

    for (service_cmd, service, zone_cmd, zone, sysctl_cmd, sysctl) in cases {
        let data = outputs(&[
            (service_cmd, service),
            (zone_cmd, zone),
            (sysctl_cmd, sysctl),
        ]);
        let results = execute_check_pack(&pack(), &data);
        assert!(
            results
                .iter()
                .any(|result| result.to_finding_status() == FindingStatus::Open),
            "at least one deliberately ambiguous effective-state value must fail"
        );
    }
}
