//! Generate deterministic native adapter evidence for the localhost scanner harness.
//!
//! The repository's older `automatestig-evidence/v2` fixtures are useful, but
//! the scanner API deliberately accepts only the adapter-bound v1 envelope.
//! This example bridges those reviewed synthetic command outputs through the
//! production adapter API. It does not invent plan IDs, digests, or operation
//! requests and it never contains a usable credential or host key.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use automatestig_core::target_adapters::{
    AdapterEvidenceEnvelope, AdapterOperationEvidence, AdapterOperationStatus,
    BuiltInTargetAdapter, DeviceFingerprint, EvidenceTransportIdentity,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const SYNTHETIC_HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Debug, Deserialize)]
struct LegacyEvidence {
    hostname: String,
    collected_at: String,
    complete: bool,
    commands: Vec<LegacyCommand>,
}

#[derive(Debug, Deserialize)]
struct LegacyCommand {
    data_key: String,
    status: String,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    duration_ms: u64,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Clone, Copy)]
struct EvidenceCase {
    adapter: BuiltInTargetAdapter,
    case_name: &'static str,
    source: &'static str,
    software_version: &'static str,
}

const CASES: [EvidenceCase; 6] = [
    EvidenceCase {
        adapter: BuiltInTargetAdapter::NetAppOntap9,
        case_name: "compliant",
        source: "ontap/ontap_evidence_compliant.json",
        software_version: "9.15.1P2",
    },
    EvidenceCase {
        adapter: BuiltInTargetAdapter::NetAppOntap9,
        case_name: "findings",
        source: "ontap/ontap_evidence_findings.json",
        software_version: "9.15.1P2",
    },
    EvidenceCase {
        adapter: BuiltInTargetAdapter::NetAppOntap9,
        case_name: "incomplete",
        source: "ontap/ontap_evidence_transport_failure.json",
        software_version: "9.15.1P2",
    },
    EvidenceCase {
        adapter: BuiltInTargetAdapter::FreeBsdGpos,
        case_name: "compliant",
        source: "bsd/bsd_evidence_compliant.json",
        software_version: "14.1-RELEASE-p3",
    },
    EvidenceCase {
        adapter: BuiltInTargetAdapter::FreeBsdGpos,
        case_name: "findings",
        source: "bsd/bsd_evidence_findings.json",
        software_version: "14.1-RELEASE-p3",
    },
    EvidenceCase {
        adapter: BuiltInTargetAdapter::FreeBsdGpos,
        case_name: "incomplete",
        source: "bsd/bsd_evidence_transport_failure.json",
        software_version: "14.1-RELEASE-p3",
    },
];

struct Options {
    output_dir: PathBuf,
    fixtures_root: PathBuf,
    fresh_collected_at: bool,
}

fn usage() -> &'static str {
    "Usage: cargo run -p automatestig-core --example scanner_scenario_evidence -- \
        --output-dir DIR [--fixtures-root DIR] [--fresh-collected-at]"
}

fn parse_options() -> Result<Option<Options>, Box<dyn Error>> {
    let mut output_dir = None;
    let mut fixtures_root = PathBuf::from("fixtures");
    let mut fresh_collected_at = false;
    let mut args = env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--output-dir") => {
                output_dir = Some(PathBuf::from(required_value(&mut args, "--output-dir")?));
            }
            Some("--fixtures-root") => {
                fixtures_root = PathBuf::from(required_value(&mut args, "--fixtures-root")?);
            }
            Some("--fresh-collected-at") => fresh_collected_at = true,
            Some("--help" | "-h") => {
                println!("{}", usage());
                return Ok(None);
            }
            _ => {
                return Err(
                    invalid_data(format!("unknown argument {:?}\n{}", argument, usage())).into(),
                );
            }
        }
    }
    let output_dir = output_dir.ok_or_else(|| invalid_data(usage()))?;
    Ok(Some(Options {
        output_dir,
        fixtures_root,
        fresh_collected_at,
    }))
}

fn required_value(
    args: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> Result<OsString, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| invalid_data(format!("{option} requires a value")))
        .map_err(Into::into)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn failed_status(value: &str) -> Result<AdapterOperationStatus, Box<dyn Error>> {
    let status = match value {
        "permission_denied" => AdapterOperationStatus::PermissionDenied,
        "authentication_failed" => AdapterOperationStatus::AuthenticationFailed,
        "timeout" => AdapterOperationStatus::Timeout,
        "transport_error" => AdapterOperationStatus::TransportError,
        "protocol_error" => AdapterOperationStatus::ProtocolError,
        "response_limit" => AdapterOperationStatus::ResponseLimit,
        "semantic_error" => AdapterOperationStatus::SemanticError,
        other => {
            return Err(
                invalid_data(format!("unsupported synthetic command status {other:?}")).into(),
            );
        }
    };
    Ok(status)
}

fn load_legacy(path: &Path) -> Result<LegacyEvidence, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let fixture: LegacyEvidence = serde_json::from_slice(&bytes)?;
    if fixture.hostname.trim().is_empty() {
        return Err(invalid_data(format!("{} has an empty hostname", path.display())).into());
    }
    Ok(fixture)
}

fn make_envelope(
    evidence_case: EvidenceCase,
    fixture: LegacyEvidence,
    collected_at_override: Option<DateTime<Utc>>,
) -> Result<(AdapterEvidenceEnvelope, String), Box<dyn Error>> {
    let (vendor, product_family) = match evidence_case.adapter {
        BuiltInTargetAdapter::NetAppOntap9 => ("NetApp", "ONTAP"),
        BuiltInTargetAdapter::FreeBsdGpos => ("FreeBSD", "FreeBSD"),
        BuiltInTargetAdapter::CiscoIosXeRouterNdm => {
            return Err(invalid_data("the localhost native-evidence generator is SSH-only").into());
        }
    };
    let device = DeviceFingerprint::new(
        fixture.hostname,
        vendor,
        product_family,
        evidence_case.software_version,
    );
    let plan = evidence_case.adapter.preview(&device)?;

    let mut by_key = HashMap::new();
    for command in &fixture.commands {
        if by_key.insert(command.data_key.as_str(), command).is_some() {
            return Err(invalid_data(format!(
                "legacy evidence repeats data key {:?}",
                command.data_key
            ))
            .into());
        }
    }

    let mut operations = Vec::with_capacity(plan.operations.len());
    for operation in &plan.operations {
        let command = by_key.get(operation.data_key.as_str()).ok_or_else(|| {
            invalid_data(format!(
                "legacy evidence omitted required operation data key {:?}",
                operation.data_key
            ))
        })?;
        let mut record = if command.status == "success" {
            AdapterOperationEvidence::success(operation, &command.stdout, command.duration_ms)
        } else {
            AdapterOperationEvidence::failed(
                operation,
                failed_status(&command.status)?,
                command
                    .error
                    .as_deref()
                    .unwrap_or("synthetic collection failure"),
                command.duration_ms,
            )?
        };
        record.diagnostics = command.stderr.clone();
        operations.push(record);
    }

    let collected_at = collected_at_override
        .unwrap_or(DateTime::parse_from_rfc3339(&fixture.collected_at)?.with_timezone(&Utc));
    let envelope = AdapterEvidenceEnvelope::seal(
        &plan,
        device,
        EvidenceTransportIdentity::SshHostKey {
            fingerprint: SYNTHETIC_HOST_KEY.to_string(),
        },
        collected_at,
        operations,
    )?;
    if envelope.complete != fixture.complete {
        return Err(invalid_data(format!(
            "fixture completeness {} differs from sealed adapter completeness {}",
            fixture.complete, envelope.complete
        ))
        .into());
    }
    let replay = evidence_case.adapter.replay(&envelope)?;
    if replay.completeness.complete != fixture.complete {
        return Err(invalid_data(format!(
            "fixture completeness {} differs from replay completeness {}",
            fixture.complete, replay.completeness.complete
        ))
        .into());
    }
    Ok((envelope, replay.replay_sha256))
}

fn main() -> Result<(), Box<dyn Error>> {
    let Some(options) = parse_options()? else {
        return Ok(());
    };
    if !options.fixtures_root.is_dir() {
        return Err(invalid_data(format!(
            "fixtures root does not exist: {}",
            options.fixtures_root.display()
        ))
        .into());
    }
    fs::create_dir_all(&options.output_dir)?;
    let collected_at_override = options.fresh_collected_at.then(Utc::now);

    let mut generated = Vec::new();
    for evidence_case in CASES {
        let source_path = options.fixtures_root.join(evidence_case.source);
        let legacy = load_legacy(&source_path)?;
        let (envelope, replay_sha256) =
            make_envelope(evidence_case, legacy, collected_at_override)?;
        let filename = format!(
            "{}-{}.native-evidence.json",
            evidence_case.adapter.target_key(),
            evidence_case.case_name
        );
        let mut bytes = serde_json::to_vec_pretty(&envelope)?;
        bytes.push(b'\n');
        fs::write(options.output_dir.join(&filename), &bytes)?;
        generated.push(json!({
            "profile_id": evidence_case.adapter.target_key(),
            "case": evidence_case.case_name,
            "source_fixture": evidence_case.source,
            "path": filename,
            "sha256": sha256_hex(&bytes),
            "evidence_sha256": envelope.evidence_sha256,
            "plan_sha256": envelope.plan_sha256,
            "replay_sha256": replay_sha256,
            "complete": envelope.complete,
            "operation_count": envelope.operations.len(),
        }));
    }

    generated.sort_by_key(|entry| {
        (
            entry["profile_id"].as_str().unwrap_or_default().to_string(),
            entry["case"].as_str().unwrap_or_default().to_string(),
        )
    });
    let manifest = json!({
        "schema": "automatestig.localhost-native-evidence/v1",
        "synthetic_only": true,
        "files": generated,
    });
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    fs::write(options.output_dir.join("manifest.json"), manifest_bytes)?;

    let counts: BTreeMap<&str, usize> = [("profiles", 2), ("evidence_envelopes", CASES.len())]
        .into_iter()
        .collect();
    println!("{}", serde_json::to_string(&counts)?);
    Ok(())
}
