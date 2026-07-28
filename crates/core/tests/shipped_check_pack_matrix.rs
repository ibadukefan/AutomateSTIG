//! Synthetic contract matrix for every curated check definition shipped by AutomateSTIG.
//!
//! This deliberately tests the check-pack schema and deterministic executor only. The
//! generated values are not vendor-device or DISA procedure oracles. Live command syntax,
//! collector normalization, device firmware behavior, and the correctness of each curated
//! expected value require independent field calibration.

use std::fs;
use std::path::{Path, PathBuf};

use automatestig_core::checks::executor::execute_check;
use automatestig_core::checks::{Check, CheckDefinition, CheckPack, ExpectedResult, SystemData};
use automatestig_core::models::finding::FindingStatus;
use regex::Regex;

const EXPECTED_SHIPPED_PACKS: usize = 3;
const EXPECTED_TOP_LEVEL_DEFINITIONS: usize = 37;
const EXPECTED_RECURSIVE_CHECK_NODES: usize = 41;
const EXPECTED_COMPOUND_NODES: usize = 2;

const CONTRACT_EXCLUSIONS: &[&str] = &[
    "vendor command/output correctness",
    "live SSH transport and privilege behavior",
    "collector-to-SystemData normalization",
    "independent DISA procedure/oracle validation",
];

const COMMAND_PREDICATE_CANDIDATES: &[&str] = &[
    "online",
    "tcp_trace=TRUE",
    "off",
    "0",
    "1",
    "audit",
    "disabled",
    "auditing on",
    "loginretries=3",
    "account_locked=false",
    "minlen=15",
    "maxage=8",
    "minage=1",
];

const EXPECTED_REGEX_CANDIDATES: &[&str] = &[
    "14.0",
    "auditd is running as pid 123.",
    "Banner /etc/issue",
    "You are accessing a U.S. Government (USG) Information System",
    "MaxSessions 10",
    "ClientAliveInterval 600",
    "blacklistd_enable=\"YES\"",
    "auth required pam_passwdqc.so min=disabled,disabled,disabled,disabled,15",
    "min=disabled,disabled,disabled,disabled,15",
    ":passwordtime=60d",
    "Ciphers aes256-ctr",
    "MACs hmac-sha2-256",
    "flags:lo aa ad fr",
    "expire-after: 7d",
    "service is running",
    "auditdistd_enable=\"YES\"",
    "ntpd_enable=\"YES\"",
    "server time.example.test",
    "UTC",
    "kern.elf64.aslr.enable: 1",
    "pf_enable=\"YES\"",
    "cluster cli admin 1",
    "timeout 10",
    "tcp",
    "1 entry was displayed",
    "Maximum Number of Failed Attempts: 3",
    "backup.7z",
    "15",
    "admin 1",
    "enabled",
    "true",
    "time.example.test true",
    "FIPS Mode: true",
    "192.0.2.10",
    "server.example.test 443 tcp",
];

#[derive(Default)]
struct MatrixCounts {
    packs: usize,
    definitions: usize,
    recursive_nodes: usize,
    compound_nodes: usize,
    not_a_finding: usize,
    open: usize,
    not_reviewed: usize,
    mechanical_exclusions: Vec<String>,
}

#[test]
fn every_shipped_definition_covers_pass_fail_and_collection_error_contracts() {
    let packs = load_shipped_packs();
    let mut counts = MatrixCounts {
        packs: packs.len(),
        ..MatrixCounts::default()
    };

    for (path, pack) in &packs {
        assert_eq!(
            pack.checks
                .iter()
                .filter(|definition| definition.platform != pack.platform)
                .count(),
            0,
            "{} contains a definition whose platform differs from its pack",
            path.display()
        );

        for definition in &pack.checks {
            counts.definitions += 1;
            count_recursive_nodes(
                &definition.check,
                &mut counts.recursive_nodes,
                &mut counts.compound_nodes,
            );

            match synthesize_data(definition, true) {
                Ok(data) => {
                    let result = execute_check(definition, &data);
                    assert!(
                        result.error.is_none() && result.passed,
                        "{} {} synthetic compliant path failed: {result:?}",
                        pack.stig_id,
                        definition.vuln_id
                    );
                    assert_eq!(result.to_finding_status(), FindingStatus::NotAFinding);
                    counts.not_a_finding += 1;
                }
                Err(reason) => counts.mechanical_exclusions.push(format!(
                    "{} {} compliant: {reason}",
                    pack.stig_id, definition.vuln_id
                )),
            }

            match synthesize_data(definition, false) {
                Ok(data) => {
                    let result = execute_check(definition, &data);
                    assert!(
                        result.error.is_none() && !result.passed,
                        "{} {} synthetic noncompliant path did not open: {result:?}",
                        pack.stig_id,
                        definition.vuln_id
                    );
                    assert_eq!(result.to_finding_status(), FindingStatus::Open);
                    counts.open += 1;
                }
                Err(reason) => counts.mechanical_exclusions.push(format!(
                    "{} {} noncompliant: {reason}",
                    pack.stig_id, definition.vuln_id
                )),
            }

            let missing = execute_check(definition, &SystemData::default());
            assert!(
                missing.error.is_some() && !missing.passed,
                "{} {} missing collection did not fail closed: {missing:?}",
                pack.stig_id,
                definition.vuln_id
            );
            assert_eq!(missing.to_finding_status(), FindingStatus::NotReviewed);
            counts.not_reviewed += 1;
        }
    }

    assert_eq!(counts.packs, EXPECTED_SHIPPED_PACKS);
    assert_eq!(counts.definitions, EXPECTED_TOP_LEVEL_DEFINITIONS);
    assert_eq!(counts.recursive_nodes, EXPECTED_RECURSIVE_CHECK_NODES);
    assert_eq!(counts.compound_nodes, EXPECTED_COMPOUND_NODES);
    assert!(
        counts.mechanical_exclusions.is_empty(),
        "mechanically unsynthesizable executor paths: {:#?}",
        counts.mechanical_exclusions
    );
    assert_eq!(counts.not_a_finding, EXPECTED_TOP_LEVEL_DEFINITIONS);
    assert_eq!(counts.open, EXPECTED_TOP_LEVEL_DEFINITIONS);
    assert_eq!(counts.not_reviewed, EXPECTED_TOP_LEVEL_DEFINITIONS);

    eprintln!(
        "synthetic executor matrix: {} packs, {} top-level definitions, {} recursive nodes, \
         {} compound nodes, {} NotAFinding, {} Open, {} NotReviewed; mechanical exclusions: 0",
        counts.packs,
        counts.definitions,
        counts.recursive_nodes,
        counts.compound_nodes,
        counts.not_a_finding,
        counts.open,
        counts.not_reviewed
    );
    eprintln!(
        "not claimed by this contract test: {}",
        CONTRACT_EXCLUSIONS.join(", ")
    );
}

fn load_shipped_packs() -> Vec<(PathBuf, CheckPack)> {
    let pack_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../content/check_packs");
    let mut paths: Vec<PathBuf> = fs::read_dir(&pack_dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", pack_dir.display()))
        .map(|entry| {
            entry
                .expect("failed to read check-pack directory entry")
                .path()
        })
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            let pack = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
            (path, pack)
        })
        .collect()
}

fn count_recursive_nodes(check: &Check, nodes: &mut usize, compounds: &mut usize) {
    *nodes += 1;
    match check {
        Check::All { checks } | Check::Any { checks } => {
            *compounds += 1;
            for child in checks {
                count_recursive_nodes(child, nodes, compounds);
            }
        }
        _ => {}
    }
}

fn synthesize_data(definition: &CheckDefinition, should_pass: bool) -> Result<SystemData, String> {
    match &definition.check {
        Check::Command {
            command,
            pattern: None,
            ..
        } => {
            let actual = expected_actual(&definition.expected, should_pass)?;
            let mut data = SystemData::default();
            data.command_outputs.insert(command.clone(), actual);
            verify_synthesis(definition, data, should_pass)
        }
        _ => {
            let mut failures = Vec::new();
            for desired_boolean in [true, false] {
                let mut data = SystemData::default();
                if let Err(error) = populate_boolean(&definition.check, desired_boolean, &mut data)
                {
                    failures.push(error);
                    continue;
                }
                let result = execute_check(definition, &data);
                if result.error.is_none() && result.passed == should_pass {
                    return Ok(data);
                }
                failures.push(format!(
                    "raw {desired_boolean} produced passed={} error={:?} actual={:?}",
                    result.passed, result.error, result.actual_value
                ));
            }
            Err(failures.join("; "))
        }
    }
}

fn verify_synthesis(
    definition: &CheckDefinition,
    data: SystemData,
    should_pass: bool,
) -> Result<SystemData, String> {
    let result = execute_check(definition, &data);
    if result.error.is_none() && result.passed == should_pass {
        Ok(data)
    } else {
        Err(format!(
            "candidate produced passed={} error={:?} actual={:?}",
            result.passed, result.error, result.actual_value
        ))
    }
}

fn populate_boolean(check: &Check, desired: bool, data: &mut SystemData) -> Result<(), String> {
    match check {
        Check::ConfigLine {
            pattern,
            context,
            should_exist,
        } => {
            let config = data.network_config.get_or_insert_with(String::new);
            let must_add = desired == *should_exist;
            if must_add {
                if let Some(context) = context {
                    config.push_str(context);
                    config.push_str(" synthetic-context\n ");
                    config.push_str(pattern);
                    config.push_str("\n!\n");
                } else {
                    config.push_str(pattern);
                    config.push('\n');
                }
            }
        }
        Check::Command {
            command,
            pattern,
            is_regex,
        } => {
            let output = match (pattern, is_regex, desired) {
                (Some(pattern), true, true) => {
                    regex_witness(pattern, COMMAND_PREDICATE_CANDIDATES)?
                }
                (Some(pattern), true, false) => regex_non_witness(pattern)?,
                (Some(pattern), false, true) => pattern.clone(),
                (Some(pattern), false, false) if pattern.is_empty() => {
                    return Err("an empty literal command predicate cannot return false".into());
                }
                (Some(_), false, false) => "synthetic-noncompliant".to_string(),
                (None, _, true) => "true".to_string(),
                (None, _, false) => "false".to_string(),
            };
            data.command_outputs.insert(command.clone(), output);
        }
        Check::All { checks } => {
            if checks.is_empty() && !desired {
                return Err("an empty all check cannot return false".into());
            }
            for (index, child) in checks.iter().enumerate() {
                let child_desired = desired || index + 1 != checks.len();
                populate_boolean(child, child_desired, data)?;
            }
        }
        Check::Any { checks } => {
            if checks.is_empty() && desired {
                return Err("an empty any check cannot return true".into());
            }
            for (index, child) in checks.iter().enumerate() {
                populate_boolean(child, desired && index == 0, data)?;
            }
        }
    }
    Ok(())
}

fn expected_actual(expected: &ExpectedResult, should_pass: bool) -> Result<String, String> {
    match expected {
        ExpectedResult::Matches { pattern } => {
            if should_pass {
                regex_witness(pattern, EXPECTED_REGEX_CANDIDATES)
            } else {
                regex_non_witness(pattern)
            }
        }
        ExpectedResult::MatchCountAtLeast { pattern, min } => {
            if !should_pass && *min == 0 {
                return Err("match_count_at_least min=0 has no failing value".into());
            }
            let wanted = if should_pass { *min } else { min - 1 };
            regex_output_with_matches(pattern, wanted)
        }
        ExpectedResult::NotContains { substring } => {
            if should_pass && substring.is_empty() {
                return Err("not_contains an empty string has no passing value".into());
            }
            Ok(if should_pass {
                String::new()
            } else {
                substring.clone()
            })
        }
        ExpectedResult::IsTrue => Ok(if should_pass { "true" } else { "false" }.into()),
    }
}

fn regex_witness(pattern: &str, candidates: &[&str]) -> Result<String, String> {
    let regex =
        Regex::new(pattern).map_err(|error| format!("invalid regex {pattern:?}: {error}"))?;
    candidates
        .iter()
        .find(|candidate| regex.is_match(candidate))
        .map(|candidate| (*candidate).to_string())
        .ok_or_else(|| format!("no synthetic witness is registered for regex {pattern:?}"))
}

fn regex_non_witness(pattern: &str) -> Result<String, String> {
    let regex =
        Regex::new(pattern).map_err(|error| format!("invalid regex {pattern:?}: {error}"))?;
    ["synthetic-noncompliant", "", "!", "no-match-000"]
        .into_iter()
        .find(|candidate| !regex.is_match(candidate))
        .map(str::to_string)
        .ok_or_else(|| format!("regex {pattern:?} matches every non-witness candidate"))
}

fn regex_output_with_matches(pattern: &str, wanted: usize) -> Result<String, String> {
    let regex =
        Regex::new(pattern).map_err(|error| format!("invalid regex {pattern:?}: {error}"))?;
    let witness = regex_witness(pattern, EXPECTED_REGEX_CANDIDATES)?;
    if wanted == 0 {
        return regex_non_witness(pattern);
    }

    let mut output = String::new();
    while regex.find_iter(&output).count() < wanted {
        output.push_str(&witness);
        output.push('\n');
    }
    if regex.find_iter(&output).count() == wanted {
        Ok(output)
    } else {
        Err(format!(
            "could not synthesize exactly {wanted} matches for regex {pattern:?}"
        ))
    }
}
