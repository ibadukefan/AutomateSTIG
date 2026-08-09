use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use automatestig_core::answer::AnswerFile;
use automatestig_core::check_packs::CheckPackRegistry;
use automatestig_core::checks::{CheckPack, CheckPlatform, CheckResult, SystemData};
use automatestig_core::engine::EvaluationEngine;
use automatestig_core::library::StigLibrary;
use automatestig_core::models::asset::Asset;
use automatestig_core::models::checklist::{
    AnswerFileProvenance, EvaluationOrigin, EvaluationProvenance, OrganizationPolicyProvenance,
};
use automatestig_core::models::finding::FindingSource;
use automatestig_core::models::Checklist;
use automatestig_core::remote::cisco_config_hostname;
use automatestig_parsers::ckl;
use automatestig_parsers::cklb;
use automatestig_parsers::evidence::{
    assemble_for_plan, parse_evidence, EvidenceTranscript, LegacyEvidencePolicy,
};
use automatestig_storage::Database;
use sha2::{Digest, Sha256};

use super::{db_path, library_path, organization_policy_keys_dir, trusted_keys_dir};
use crate::ui;

const MAX_EVIDENCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RUNNING_CONFIG_BYTES: u64 = 100 * 1024 * 1024;

/// Create a detached signature on an isolated signing host.
///
/// The private key is loaded only from the explicit path and the output is
/// create-new so a signing ceremony cannot silently replace prior evidence.
pub fn sign_organization_policy(
    policy_path: &str,
    signing_key_path: &str,
    output_path: &str,
) -> Result<()> {
    let policy =
        read_regular_file_bounded(Path::new(policy_path), 64 * 1024, "organization policy")?;
    // Refuse malformed or structurally incomplete JSON before asking an
    // offline custodian to sign it. Asset/release/time binding is checked
    // again by the online verifier because those values are contextual.
    automatestig_core::organization_policy::OrganizationPolicyDocument::validate_for_signing(
        &policy,
        chrono::Utc::now(),
    )
    .map_err(anyhow::Error::msg)
    .context("Organization policy is not valid and currently effective")?;

    let private_path = Path::new(signing_key_path);
    let public_path = private_path.with_extension("pub");
    let (private_key, public_key) =
        automatestig_stigpack::signing::load_signing_key_pair(private_path, &public_path)
            .context("Failed to load external organization-policy signing key pair")?;
    let signature = automatestig_stigpack::signing::sign_manifest(&policy, &private_key)
        .context("Failed to sign organization policy")?;

    let output = Path::new(output_path);
    if output == Path::new(policy_path) || output == private_path || output == public_path {
        anyhow::bail!("signature output must differ from the policy and signing-key paths");
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(output)
        .with_context(|| format!("Failed to create signature output: {}", output.display()))?;
    file.write_all(&signature)
        .context("Failed to write organization-policy signature")?;
    file.sync_all()
        .context("Failed to persist organization-policy signature")?;

    ui::print_banner();
    ui::section("Sign Organization Policy");
    ui::detail(
        "Signing key",
        &automatestig_stigpack::signing::public_key_fingerprint(&public_key),
    );
    ui::detail("Policy SHA-256", &sha256_hex(&policy));
    ui::output_file(
        "Signature",
        &output.display().to_string(),
        "detached Ed25519 signature",
    );
    Ok(())
}

pub struct EvaluateArgs {
    pub stig_id: String,
    pub evidence: Option<String>,
    pub allow_legacy_evidence: bool,
    pub config: Option<String>,
    pub organization_policy: Option<String>,
    pub organization_policy_signature: Option<String>,
    pub answer_paths: Vec<String>,
    pub host: Option<String>,
    pub output: Option<String>,
    pub format: Option<String>,
    pub merge: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum EvaluationInput {
    Evidence(String),
    Config(String),
}

#[derive(Debug)]
struct SelectedAnswerFile {
    id: String,
    answer_file: AnswerFile,
    sha256: String,
}

fn load_selected_answer_files(
    answer_paths: &[String],
    stig_id: &str,
    benchmark_vuln_ids: &HashSet<String>,
) -> Result<Vec<SelectedAnswerFile>> {
    let mut selected = Vec::with_capacity(answer_paths.len());

    for (index, path_string) in answer_paths.iter().enumerate() {
        ui::detail("Answer file", path_string);
        let path = Path::new(path_string);
        let basename = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("Answer file path must end in a UTF-8 filename")?;
        let display_id = automatestig_core::path_safety::safe_filename(basename)
            .unwrap_or_else(|_| format!("answer-{}", index + 1));

        let answer_file = AnswerFile::load(path)
            .with_context(|| format!("Failed to load answer file: {path_string}"))?;
        let validation_issues = answer_file.validate();
        if !validation_issues.is_empty() {
            anyhow::bail!(
                "Answer file {display_id:?} is invalid: {}",
                validation_issues.join("; ")
            );
        }
        if answer_file
            .stig_id
            .as_deref()
            .is_some_and(|answer_stig_id| answer_stig_id != stig_id)
        {
            anyhow::bail!(
                "Answer file {display_id:?} targets {} rather than {stig_id}",
                answer_file.stig_id.as_deref().unwrap_or_default()
            );
        }
        let mut unknown_vuln_ids: Vec<_> = answer_file
            .entries
            .iter()
            .map(|entry| entry.vuln_id.as_str())
            .filter(|vuln_id| !benchmark_vuln_ids.contains(*vuln_id))
            .collect();
        unknown_vuln_ids.sort_unstable();
        unknown_vuln_ids.dedup();
        if !unknown_vuln_ids.is_empty() {
            anyhow::bail!(
                "Answer file {display_id:?} references unknown Vuln ID(s) for {stig_id}: {}",
                unknown_vuln_ids.join(", ")
            );
        }
        let sha256 = automatestig_core::check_packs::canonical_json_sha256(&answer_file)
            .with_context(|| format!("Failed to bind answer file {display_id:?}"))?;
        let mut id = automatestig_core::path_safety::safe_filename(basename).ok();
        if id.as_ref().is_none_or(|candidate| {
            selected
                .iter()
                .any(|prior: &SelectedAnswerFile| prior.id.eq_ignore_ascii_case(candidate))
        }) {
            let extension = path
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or("json");
            id = Some(format!(
                "answer-{}-{}.{}",
                index + 1,
                &sha256[..12],
                extension
            ));
        }
        selected.push(SelectedAnswerFile {
            id: id.expect("provenance ID fallback is always set"),
            answer_file,
            sha256,
        });
    }

    Ok(selected)
}

impl EvaluationInput {
    fn path(&self) -> &str {
        match self {
            Self::Evidence(path) | Self::Config(path) => path,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Evidence(_) => "evidence",
            Self::Config(_) => "config",
        }
    }
}

fn select_evaluation_input(
    evidence: Option<String>,
    config: Option<String>,
) -> Result<EvaluationInput> {
    match (evidence, config) {
        (Some(path), None) => Ok(EvaluationInput::Evidence(path)),
        (None, Some(path)) => Ok(EvaluationInput::Config(path)),
        (None, None) => {
            anyhow::bail!("evaluation requires exactly one of --evidence or --config")
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("--evidence and --config are mutually exclusive")
        }
    }
}

fn bind_input_hostname(
    requested: Option<&str>,
    claimed: Option<&str>,
    input_kind: &str,
) -> Result<String> {
    let claimed = claimed
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("the selected evaluation input has no hostname")?;
    if let Some(requested) = requested {
        let requested = requested.trim();
        if !requested.eq_ignore_ascii_case(claimed) {
            anyhow::bail!(
                "--host '{}' does not match {} hostname '{}'",
                requested,
                input_kind,
                claimed
            );
        }
        return Ok(requested.to_string());
    }
    Ok(claimed.to_string())
}

fn default_output_path(hostname: &str, stig_id: &str) -> Result<String> {
    let hostname = automatestig_core::path_safety::safe_filename(hostname)
        .context("the evaluated hostname is unsafe for a default output filename")?;
    let stig_id = automatestig_core::path_safety::safe_filename(stig_id)
        .context("the STIG ID is unsafe for a default output filename")?;
    Ok(format!("{hostname}_{stig_id}.ckl"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_regular_file_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect {label} file: {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        anyhow::bail!("{label} input must be a regular, non-symlink file");
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Failed to open {label} file: {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect open {label} file: {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        anyhow::bail!("{label} input exceeds the {max_bytes}-byte regular-file limit");
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read {label} file: {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{label} input exceeds the {max_bytes}-byte limit");
    }
    Ok(bytes)
}

fn load_organization_policy(
    policy_path: Option<&str>,
    signature_path: Option<&str>,
    stig_id: &str,
    stig_release: &str,
    hostname: &str,
) -> Result<Option<automatestig_core::organization_policy::VerifiedOrganizationPolicy>> {
    let (policy_path, signature_path) = match (policy_path, signature_path) {
        (None, None) => return Ok(None),
        (Some(policy), Some(signature)) => (policy, signature),
        _ => anyhow::bail!(
            "--organization-policy and --organization-policy-signature must be supplied together"
        ),
    };
    let raw = read_regular_file_bounded(Path::new(policy_path), 64 * 1024, "organization policy")?;
    let signature = read_regular_file_bounded(
        Path::new(signature_path),
        64,
        "organization policy signature",
    )?;
    if signature.len() != 64 {
        anyhow::bail!("organization policy signature must contain exactly 64 bytes");
    }
    let trust_dir = organization_policy_keys_dir();
    let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
    let loaded = trust_store
        .load_from_directory(&trust_dir)
        .with_context(|| {
            format!(
                "Failed to load organization-policy trust anchors from {}",
                trust_dir.display()
            )
        })?;
    if loaded == 0 {
        anyhow::bail!(
            "no organization-policy trust anchors are installed in {}",
            trust_dir.display()
        );
    }
    let trusted_public_keys = trust_store.public_keys();
    let policy =
        automatestig_core::organization_policy::VerifiedOrganizationPolicy::verify_and_parse(
            &raw,
            &signature,
            &trusted_public_keys,
            stig_id,
            stig_release,
            hostname,
            chrono::Utc::now(),
        )
        .map_err(anyhow::Error::msg)?;
    Ok(Some(policy))
}

pub fn run(args: EvaluateArgs, cli: &crate::Cli) -> Result<()> {
    let EvaluateArgs {
        stig_id,
        evidence,
        allow_legacy_evidence,
        config,
        organization_policy,
        organization_policy_signature,
        answer_paths,
        host,
        output,
        format,
        merge,
    } = args;

    let evaluation_input = select_evaluation_input(evidence, config)?;
    if allow_legacy_evidence && matches!(&evaluation_input, EvaluationInput::Config(_)) {
        anyhow::bail!("--allow-legacy-evidence is valid only with --evidence");
    }

    ui::print_banner();

    let lib_path = library_path(cli);
    let library = StigLibrary::open(&lib_path)
        .context("Failed to open STIG library. Run 'automatestig library init' first.")?;

    let benchmark = library
        .load_benchmark(&stig_id)
        .context(format!("Failed to load STIG benchmark '{}'", stig_id))?;
    let check_packs =
        load_matching_check_packs(&library, &benchmark.id, &benchmark.version_string())?;
    if check_packs.is_empty() {
        anyhow::bail!(
            "no exact-release check pack is installed for {} {}",
            benchmark.id,
            benchmark.version_string()
        );
    }
    validate_check_pack_membership(&benchmark, &check_packs)?;

    ui::section(&format!(
        "{} ({}) — {} rules",
        benchmark.title,
        benchmark.version_string(),
        benchmark.rules.len()
    ));

    let (evidence_transcript, config_text, input_sha256) = match &evaluation_input {
        EvaluationInput::Evidence(evidence_path) => {
            ui::detail("Evidence source", evidence_path);
            let raw = read_regular_file_bounded(
                Path::new(evidence_path),
                MAX_EVIDENCE_BYTES,
                "evidence",
            )?;
            let digest = sha256_hex(&raw);
            let raw = String::from_utf8(raw)
                .context(format!("Failed to read evidence file: {}", evidence_path))?;
            let legacy_policy = if allow_legacy_evidence {
                LegacyEvidencePolicy::AssumeSuccess
            } else {
                LegacyEvidencePolicy::Reject
            };
            let transcript = parse_evidence(&raw, legacy_policy)
                .context(format!("Failed to parse evidence file: {}", evidence_path))?;
            if transcript.legacy {
                ui::warn(
                    "Unsafe legacy evidence enabled: the transcript contains no command exit statuses",
                );
            }
            (Some(transcript), None, digest)
        }
        EvaluationInput::Config(config_path) => {
            ui::detail("Config source", config_path);
            let raw = read_regular_file_bounded(
                Path::new(config_path),
                MAX_RUNNING_CONFIG_BYTES,
                "running configuration",
            )?;
            let digest = sha256_hex(&raw);
            let text = String::from_utf8(raw)
                .context(format!("Failed to read config file: {}", config_path))?;
            (None, Some(text), digest)
        }
    };
    let provenance = format!(
        "Supplied {} provenance (not a live observation by this process):\n{}: {} (SHA-256: {})",
        evaluation_input.kind(),
        evaluation_input.kind(),
        evaluation_input.path(),
        input_sha256
    );

    // Load, validate, and bind all answer files in application order. Only
    // safe basenames are retained in durable provenance; arbitrary host paths
    // never cross into the checklist artifact.
    let benchmark_vuln_ids: HashSet<_> = benchmark
        .rules
        .iter()
        .map(|rule| rule.vuln_id.clone())
        .collect();
    let selected_answer_files =
        load_selected_answer_files(&answer_paths, &stig_id, &benchmark_vuln_ids)?;

    // Bind the checklist identity to the identity inside the one consumed
    // primary input. `--host` is only an optional corroborating claim.
    let input_hostname = if let Some(transcript) = &evidence_transcript {
        transcript.hostname.clone()
    } else {
        Some(
            cisco_config_hostname(
                config_text
                    .as_deref()
                    .context("selected config input was not loaded")?,
            )
            .map_err(anyhow::Error::msg)?,
        )
    };
    let hostname = bind_input_hostname(
        host.as_deref(),
        input_hostname.as_deref(),
        evaluation_input.kind(),
    )?;

    let asset = Asset::new(&hostname);
    ui::detail("Target", &hostname);

    if organization_policy.is_some() && !matches!(&evaluation_input, EvaluationInput::Config(_)) {
        anyhow::bail!("organization policy is valid only with --config");
    }
    let benchmark_sha256 = automatestig_core::check_packs::canonical_json_sha256(&benchmark)?;
    let check_pack_sha256 = automatestig_core::check_packs::canonical_json_sha256(&check_packs)?;
    let verified_policy = load_organization_policy(
        organization_policy.as_deref(),
        organization_policy_signature.as_deref(),
        &benchmark.id,
        &benchmark.version_string(),
        &hostname,
    )?;
    if verified_policy.is_none()
        && check_packs
            .iter()
            .flat_map(|pack| &pack.checks)
            .any(|definition| definition.check.requires_organization_policy())
    {
        anyhow::bail!(
            "this check pack requires --organization-policy and \
             --organization-policy-signature; no checklist was written"
        );
    }
    let organization_policy_provenance =
        verified_policy
            .as_ref()
            .map(|policy| OrganizationPolicyProvenance {
                policy_id: policy.document().policy_id.clone(),
                policy_version: policy.document().policy_version.clone(),
                policy_sha256: policy.sha256().to_string(),
                signer_fingerprint: policy.signer_fingerprint().to_string(),
                signature_verified: true,
            });
    let answer_file_provenance: Vec<_> = selected_answer_files
        .iter()
        .map(|selected| AnswerFileProvenance {
            id: selected.id.clone(),
            sha256: selected.sha256.clone(),
        })
        .collect();
    let answer_file_bindings: Vec<_> = answer_file_provenance
        .iter()
        .map(|answer_file| (answer_file.id.as_str(), answer_file.sha256.as_str()))
        .collect();
    let organization_policy_sha256 = verified_policy.as_ref().map(|policy| policy.sha256());
    let evaluation_plan_sha256 = if answer_file_bindings.is_empty() {
        automatestig_core::check_packs::evaluation_plan_sha256(
            &benchmark.id,
            &benchmark.version_string(),
            &benchmark_sha256,
            &check_pack_sha256,
            organization_policy_sha256,
        )
    } else {
        automatestig_core::check_packs::evaluation_plan_sha256_with_answer_files(
            &benchmark.id,
            &benchmark.version_string(),
            &benchmark_sha256,
            &check_pack_sha256,
            organization_policy_sha256,
            &answer_file_bindings,
        )
    }?;

    // Run evaluation.
    let engine = EvaluationEngine::with_defaults();
    let mut checklist = engine.evaluate(&benchmark, &asset, &[])?;
    let system_data = build_evidence_system_data(
        evidence_transcript.as_ref(),
        config_text,
        &check_packs,
        verified_policy,
    )?;
    let check_results = execute_evidence_checks(&check_packs, &system_data);
    apply_check_results_to_checklist(
        &mut checklist,
        &check_results,
        &provenance,
        FindingSource::Evidence,
    );
    let mut collection_errors: Vec<String> = system_data
        .collection_errors
        .iter()
        .map(|(key, error)| format!("{key}: {error}"))
        .collect();
    collection_errors.extend(check_results.iter().filter_map(|result| {
        result
            .error
            .as_ref()
            .map(|error| format!("{}: {error}", result.vuln_id))
    }));
    let unsafe_legacy_evidence = evidence_transcript
        .as_ref()
        .is_some_and(|transcript| transcript.legacy);
    if unsafe_legacy_evidence {
        collection_errors
            .push("legacy evidence has no authenticated per-command completion status".to_string());
    }
    collection_errors.sort();
    collection_errors.dedup();
    let evaluation_complete =
        system_data.collection_complete && collection_errors.is_empty() && !unsafe_legacy_evidence;
    checklist.evaluation_provenance = Some(if let Some(transcript) = &evidence_transcript {
        EvaluationProvenance {
            origin: EvaluationOrigin::EvidenceFile,
            collection_complete: evaluation_complete,
            collection_errors,
            evidence_sha256: Some(input_sha256),
            claimed_hostname: transcript.hostname.clone(),
            collector_version: transcript.collector_version.clone(),
            collected_at: transcript.collected_at.clone(),
            plan_sha256: transcript.plan_sha256.clone(),
            server_key_fingerprint: transcript.server_key_fingerprint.clone(),
            benchmark_sha256: Some(benchmark_sha256.clone()),
            check_pack_sha256: Some(check_pack_sha256.clone()),
            evaluation_plan_sha256: Some(evaluation_plan_sha256.clone()),
            organization_policy: organization_policy_provenance.clone(),
            answer_file: None,
            answer_files: answer_file_provenance.clone(),
            unsafe_legacy_evidence,
        }
    } else {
        EvaluationProvenance {
            origin: EvaluationOrigin::ConfigFile,
            collection_complete: evaluation_complete,
            collection_errors,
            evidence_sha256: Some(input_sha256),
            claimed_hostname: input_hostname.clone(),
            collector_version: None,
            collected_at: None,
            plan_sha256: None,
            server_key_fingerprint: None,
            benchmark_sha256: Some(benchmark_sha256.clone()),
            check_pack_sha256: Some(check_pack_sha256.clone()),
            evaluation_plan_sha256: Some(evaluation_plan_sha256.clone()),
            organization_policy: organization_policy_provenance,
            answer_file: None,
            answer_files: answer_file_provenance,
            unsafe_legacy_evidence: false,
        }
    });

    if !evaluation_complete {
        let errors = checklist
            .evaluation_provenance
            .as_ref()
            .map(|provenance| provenance.collection_errors.clone())
            .unwrap_or_default();
        let failures = errors.len();
        let details = serde_json::json!({
            "hostname": hostname,
            "stig_id": stig_id,
            "origin": checklist.evaluation_provenance.as_ref().map(|value| value.origin),
            "collection_errors": errors,
            "evidence_sha256": checklist
                .evaluation_provenance
                .as_ref()
                .and_then(|value| value.evidence_sha256.as_deref()),
            "unsafe_legacy_evidence": unsafe_legacy_evidence,
            "artifact_written": false,
            "checklist_saved": false,
        });
        let db = Database::open(&db_path(cli))?;
        db.record_incomplete_evaluation("cli-evaluate", &details.to_string())?;
        anyhow::bail!(
            "evaluation is incomplete: {failures} collection/evaluation error(s); no checklist was written or saved"
        );
    }

    apply_answer_files_to_checklist(&mut checklist, &selected_answer_files)?;

    // Merge with previous if requested.
    if let Some(ref merge_path) = merge {
        ui::detail("Merging", merge_path);
        let path = Path::new(merge_path);
        let previous = load_checklist_from_file(path)?;
        engine.merge_previous(&mut checklist, &previous)?;
    }

    // Print summary.
    let summary = checklist.summary();
    ui::print_summary_table(
        summary.total,
        summary.open,
        summary.not_a_finding,
        summary.not_applicable,
        summary.not_reviewed,
        summary.cat_i_open,
        summary.cat_ii_open,
        summary.cat_iii_open,
        ui::SummaryScoreDisplay::Available {
            assessed_pass_pct: summary.assessed_pass_pct_opt(),
            benchmark_coverage_pct: summary.benchmark_coverage_pct(),
        },
    );

    // Write output.
    super::ensure_external_export_allowed(&checklist)?;
    let output_path = match output {
        Some(output) => output,
        None => default_output_path(&hostname, &stig_id)?,
    };

    let out_format = format
        .as_deref()
        .or_else(|| Path::new(&output_path).extension().and_then(|e| e.to_str()))
        .unwrap_or("ckl");

    let (artifact, artifact_label) = match out_format {
        "ckl" => (ckl::write_ckl(&checklist)?.into_bytes(), "CKL"),
        "cklb" => (cklb::write_cklb(&checklist)?.into_bytes(), "CKLB"),
        "json" => (serde_json::to_vec_pretty(&checklist)?, "JSON"),
        _ => {
            anyhow::bail!("Unsupported output format: {}", out_format);
        }
    };
    let mut consumed_inputs = vec![Path::new(evaluation_input.path())];
    consumed_inputs.extend(answer_paths.iter().map(Path::new));
    if let Some(path) = organization_policy.as_deref() {
        consumed_inputs.push(Path::new(path));
    }
    if let Some(path) = organization_policy_signature.as_deref() {
        consumed_inputs.push(Path::new(path));
    }
    if let Some(path) = merge.as_deref() {
        consumed_inputs.push(Path::new(path));
    }
    super::ensure_safe_artifact_output(Path::new(&output_path), &consumed_inputs, cli)?;
    write_evaluation_output_atomic(Path::new(&output_path), &artifact)?;
    ui::output_file("Output", &output_path, artifact_label);

    // Save to database. The output artifact is already durable at this point,
    // so any database failure is a partial success rather than a cleanly
    // retryable evaluation failure.
    let partial_save_context = || {
        format!(
            "evaluation artifact exists at {output_path:?}, but its database record was not saved; preserve the artifact and correct the database problem before deciding whether to rerun"
        )
    };
    let db = Database::open(&db_path(cli)).with_context(partial_save_context)?;
    let log_detail = format!(
        "input_kind={}, input_path={}, collection_complete={}, collection_errors={}",
        evaluation_input.kind(),
        evaluation_input.path(),
        system_data.collection_complete,
        system_data.collection_errors.len()
    );
    db.save_evaluation(&checklist, "cli-evaluate", Some(&log_detail))
        .with_context(partial_save_context)?;

    ui::success("Evaluation complete");

    Ok(())
}

fn build_evidence_system_data(
    transcript: Option<&EvidenceTranscript>,
    network_config: Option<String>,
    check_packs: &[CheckPack],
    organization_policy: Option<automatestig_core::organization_policy::VerifiedOrganizationPolicy>,
) -> Result<SystemData> {
    let platform = check_packs
        .first()
        .map(|pack| pack.platform)
        .context("no check pack is installed")?;
    if let Some(network_config) = network_config {
        if platform != CheckPlatform::CiscoIos {
            anyhow::bail!("--config is supported only for the Cisco IOS-XE check pack");
        }
        automatestig_core::remote::validate_network_config(platform, &network_config)
            .map_err(anyhow::Error::msg)?;
        return Ok(SystemData {
            collection_complete: true,
            network_config: Some(network_config),
            organization_policy,
            ..Default::default()
        });
    }

    let transcript = transcript.context("--evidence transcript is required")?;
    let mut seen_vuln_ids = HashSet::new();
    let definitions: Vec<_> = check_packs
        .iter()
        .flat_map(|pack| pack.checks.iter())
        .filter(|check| seen_vuln_ids.insert(check.vuln_id.clone()))
        .cloned()
        .collect();
    let plan = automatestig_core::remote::generate_collection_plan(platform, &definitions)
        .map_err(anyhow::Error::msg)?;

    assemble_for_plan(transcript, &plan).map_err(anyhow::Error::new)
}

fn execute_evidence_checks(
    check_packs: &[CheckPack],
    system_data: &SystemData,
) -> Vec<CheckResult> {
    let mut check_results: Vec<CheckResult> = check_packs
        .iter()
        .flat_map(|pack| pack.checks.iter())
        .map(|definition| {
            automatestig_core::checks::executor::execute_check(definition, system_data)
        })
        .collect();

    let mut seen_vuln_ids: HashSet<String> = HashSet::new();
    // Curated packs load before reviewed imported ones; first result per vuln wins.
    check_results.retain(|cr| seen_vuln_ids.insert(cr.vuln_id.clone()));
    check_results
}

pub(crate) fn load_matching_check_packs(
    library: &StigLibrary,
    stig_id: &str,
    release: &str,
) -> Result<Vec<CheckPack>> {
    let mut registry = CheckPackRegistry::new();
    registry.load_embedded()?;
    let mut trust_store = automatestig_stigpack::signing::TrustStore::new();
    let trust_dir = trusted_keys_dir();
    trust_store
        .load_from_directory(&trust_dir)
        .with_context(|| {
            format!(
                "Failed to load executable-content trust anchors from {}",
                trust_dir.display()
            )
        })?;
    let trusted_public_keys = trust_store.public_keys();
    registry.load_from_trusted_library_directory(
        library,
        "custom_checks",
        20,
        &trusted_public_keys,
    )?;

    // Only generated packs promoted by a trusted signed .stigpack import are
    // executable. Pre-v0.2 prose-generated files remain quarantined under
    // auto_check_packs/ and are deliberately never loaded.
    registry.load_from_trusted_library_directory(
        library,
        "reviewed_check_packs",
        30,
        &trusted_public_keys,
    )?;

    Ok(registry
        .check_packs_for_stig_release(stig_id, release)
        .into_iter()
        .cloned()
        .collect())
}

pub(crate) fn validate_check_pack_membership(
    benchmark: &automatestig_core::models::stig::StigBenchmark,
    check_packs: &[CheckPack],
) -> Result<()> {
    let missing = automatestig_core::check_packs::check_pack_vuln_ids_missing_from_benchmark(
        benchmark,
        check_packs,
    );
    if !missing.is_empty() {
        anyhow::bail!(
            "trusted check pack for {} {} references rule(s) absent from the installed benchmark: {}",
            benchmark.id,
            benchmark.version_string(),
            missing.join(", ")
        );
    }
    Ok(())
}

fn apply_check_results_to_checklist(
    checklist: &mut Checklist,
    check_results: &[CheckResult],
    provenance: &str,
    source: FindingSource,
) {
    for cr in check_results {
        if let Some(finding) = checklist.find_by_vuln_id_mut(&cr.vuln_id) {
            finding.status = cr.to_finding_status();
            finding.source = if cr.error.is_some() {
                FindingSource::CollectionError
            } else {
                source
            };
            finding.finding_details = cr.evidence.clone();
            if !provenance.is_empty() {
                finding.comments = provenance.to_string();
            }
            finding.evaluated_at = chrono::Utc::now();
            finding.evaluated_by = format!("AutomateSTIG {}", env!("CARGO_PKG_VERSION"));
        }
    }

    checklist.touch();
}

fn apply_answer_files_to_checklist(
    checklist: &mut Checklist,
    answer_files: &[SelectedAnswerFile],
) -> Result<()> {
    let engine = EvaluationEngine::with_defaults();
    for selected in answer_files {
        engine
            .apply_answer_file(checklist, &selected.answer_file)
            .with_context(|| format!("Failed to apply answer file {:?}", selected.id))?;
    }
    Ok(())
}

fn load_checklist_from_file(path: &Path) -> Result<automatestig_core::models::Checklist> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "ckl" => Ok(ckl::parse_ckl_file(path)?),
        "cklb" => Ok(cklb::parse_cklb_file(path)?),
        "json" => {
            let content = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        }
        _ => anyhow::bail!("Unsupported checklist format: {}", ext),
    }
}

pub(crate) fn write_evaluation_output_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_evaluation_output_atomic_with_hook(path, bytes, |_| Ok(()))
}

/// Validate every directory/destination constraint without creating the final
/// artifact. Remote collection uses this before credentials or SSH so a known
/// bad destination cannot discard an otherwise useful collection result.
pub(crate) fn preflight_artifact_output(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    secure_evaluation_output_directory(parent)?;
    validate_existing_evaluation_output(path)?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("artifact output path must have a UTF-8 filename")?;
    let operation_parent = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to resolve artifact output parent {}",
            parent.display()
        )
    })?;
    validate_existing_evaluation_output(&operation_parent.join(filename))
}

fn write_evaluation_output_atomic_with_hook<F>(
    path: &Path,
    bytes: &[u8],
    before_commit: F,
) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    write_evaluation_output_atomic_with_hooks(
        path,
        bytes,
        before_commit,
        sync_artifact_output_directory,
    )
}

fn write_evaluation_output_atomic_with_hooks<F, G>(
    path: &Path,
    bytes: &[u8],
    before_commit: F,
    sync_directory: G,
) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
    G: FnOnce(&Path) -> std::io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    secure_evaluation_output_directory(parent)?;
    validate_existing_evaluation_output(path)?;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("artifact output path must have a UTF-8 filename")?;
    // Resolve the verified parent once and use that path for staging, commit,
    // cleanup, and directory fsync. An intermediate symlink in the original
    // spelling cannot redirect only the later commit or cleanup operation.
    let operation_parent = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to resolve artifact output parent {}",
            parent.display()
        )
    })?;
    let operation_path = operation_parent.join(filename);
    validate_existing_evaluation_output(&operation_path)?;
    let (temporary, mut file) = loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate =
            operation_parent.join(format!(".{filename}.tmp-{}-{sequence}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        match options.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create {}", candidate.display()))
            }
        }
    };

    let result = (|| -> Result<()> {
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", temporary.display()))?;
        drop(file);
        before_commit(&temporary)?;

        // Recheck immediately before rename. The containing directory is
        // current-user-owned and not writable by group/other users.
        validate_existing_evaluation_output(&operation_path)?;
        replace_output_file_atomic(&temporary, &operation_path).with_context(|| {
            format!("failed to atomically replace {}", operation_path.display())
        })?;
        if let Err(error) = sync_directory(&operation_parent) {
            anyhow::bail!(
                "artifact was committed at {}, but directory durability sync failed: {error}. Preserve and inspect that artifact before deciding whether to retry",
                operation_path.display()
            );
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn sync_artifact_output_directory(parent: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(parent)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_output_file_atomic(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_output_file_atomic(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn secure_evaluation_output_directory(parent: &Path) -> Result<()> {
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "artifact output parent must be a real directory: {}",
                parent.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                anyhow::ensure!(
                    metadata.uid() == unsafe { libc::geteuid() },
                    "artifact output directory is not owned by the current user: {}",
                    parent.display()
                );
                anyhow::ensure!(
                    metadata.permissions().mode() & 0o022 == 0,
                    "artifact output directory is writable by group or other users: {}. Choose a private output directory",
                    parent.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn validate_existing_evaluation_output(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "artifact output must be a regular non-symlink file: {}",
                path.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.uid() == unsafe { libc::geteuid() },
                    "artifact output is not owned by the current user: {}",
                    path.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        bind_input_hostname, cisco_config_hostname, default_output_path, load_matching_check_packs,
        load_selected_answer_files, preflight_artifact_output, read_regular_file_bounded,
        select_evaluation_input, sha256_hex, validate_check_pack_membership,
        write_evaluation_output_atomic, write_evaluation_output_atomic_with_hook,
        write_evaluation_output_atomic_with_hooks, EvaluationInput,
    };
    use automatestig_core::checks::{
        Check, CheckDefinition, CheckPack, CheckPlatform, ExpectedResult,
    };
    use automatestig_core::library::StigLibrary;

    #[test]
    fn sha256_hex_hashes_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn atomic_evaluation_output_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("result.ckl");

        write_evaluation_output_atomic(&output, b"artifact").unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), b"artifact");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn atomic_evaluation_output_replaces_an_existing_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("result.ckl");
        std::fs::write(&output, b"old artifact").unwrap();

        write_evaluation_output_atomic(&output, b"new artifact").unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), b"new artifact");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_evaluation_output_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.ckl");
        let output = dir.path().join("result.ckl");
        std::fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &output).unwrap();

        let error = write_evaluation_output_atomic(&output, b"replacement").unwrap_err();

        assert!(error.to_string().contains("regular non-symlink file"));
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    }

    #[test]
    fn atomic_evaluation_output_preserves_existing_file_on_precommit_failure() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("result.ckl");
        std::fs::write(&output, b"existing").unwrap();

        let error = write_evaluation_output_atomic_with_hook(&output, b"replacement", |_| {
            anyhow::bail!("injected pre-commit failure")
        })
        .unwrap_err();

        assert!(error.to_string().contains("injected pre-commit failure"));
        assert_eq!(std::fs::read(&output).unwrap(), b"existing");
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".result.ckl.tmp-")
        }));
    }

    #[test]
    fn atomic_output_reports_directory_sync_failure_as_committed() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("result.ckl");

        let error = write_evaluation_output_atomic_with_hooks(
            &output,
            b"committed artifact",
            |_| Ok(()),
            |_| {
                Err(std::io::Error::other(
                    "injected directory durability failure",
                ))
            },
        )
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("artifact was committed at"));
        assert!(message.contains("directory durability sync failed"));
        assert!(message.contains("before deciding whether to retry"));
        assert_eq!(std::fs::read(&output).unwrap(), b"committed artifact");
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".result.ckl.tmp-")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn collection_output_preflight_rejects_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let output = shared.join("evidence.json");

        let error = preflight_artifact_output(&output).unwrap_err();

        assert!(error
            .to_string()
            .contains("writable by group or other users"));
        assert!(!output.exists());
        assert_eq!(std::fs::read_dir(&shared).unwrap().count(), 0);
    }

    #[test]
    fn bounded_input_reader_rejects_oversize_and_symlinks() {
        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("input.json");
        std::fs::write(&input, b"12345").unwrap();
        assert!(read_regular_file_bounded(&input, 4, "test").is_err());
        assert_eq!(
            read_regular_file_bounded(&input, 5, "test").unwrap(),
            b"12345"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = dir.path().join("link.json");
            symlink(&input, &link).unwrap();
            assert!(read_regular_file_bounded(&link, 5, "test").is_err());
        }
    }

    #[test]
    fn runtime_input_selection_requires_exactly_one_source() {
        assert_eq!(
            select_evaluation_input(Some("evidence.json".into()), None).unwrap(),
            EvaluationInput::Evidence("evidence.json".into())
        );
        assert_eq!(
            select_evaluation_input(None, Some("running-config.txt".into())).unwrap(),
            EvaluationInput::Config("running-config.txt".into())
        );
        assert!(select_evaluation_input(None, None).is_err());
        assert!(select_evaluation_input(
            Some("evidence.json".into()),
            Some("running-config.txt".into())
        )
        .is_err());
    }

    #[test]
    fn answer_selection_binds_ordered_safe_ids_without_rejecting_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let first_dir = temporary.path().join("first");
        let second_dir = temporary.path().join("second");
        std::fs::create_dir_all(&first_dir).unwrap();
        std::fs::create_dir_all(&second_dir).unwrap();
        let first_path = first_dir.join("same.json");
        let second_path = second_dir.join("same.json");
        let unicode_path = temporary.path().join("résumé.json");

        let first = automatestig_core::answer::AnswerFile::new("First", Some("TEST_STIG"));
        let second = automatestig_core::answer::AnswerFile::new("Second", Some("TEST_STIG"));
        let third = automatestig_core::answer::AnswerFile::new("Third", Some("TEST_STIG"));
        first.save_json(&first_path).unwrap();
        second.save_json(&second_path).unwrap();
        third.save_json(&unicode_path).unwrap();

        let paths = vec![
            first_path.to_string_lossy().into_owned(),
            second_path.to_string_lossy().into_owned(),
            unicode_path.to_string_lossy().into_owned(),
        ];
        let selected =
            load_selected_answer_files(&paths, "TEST_STIG", &std::collections::HashSet::new())
                .unwrap();

        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].id, "same.json");
        assert!(selected[1].id.starts_with("answer-2-"));
        assert!(selected[2].id.starts_with("answer-3-"));
        for answer_file in &selected {
            assert_eq!(
                automatestig_core::path_safety::safe_filename(&answer_file.id).unwrap(),
                answer_file.id
            );
            assert_eq!(answer_file.sha256.len(), 64);
        }
    }

    #[test]
    fn answer_selection_rejects_invalid_and_unknown_entries() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("answers.json");
        let mut answer = automatestig_core::answer::AnswerFile::new("Answers", Some("TEST_STIG"));
        answer.entries.push(automatestig_core::answer::AnswerEntry {
            vuln_id: "V-UNKNOWN".to_string(),
            status: automatestig_core::models::finding::FindingStatus::Open,
            finding_details: None,
            comments: None,
            severity_override: None,
            severity_override_justification: None,
            force_override: false,
        });
        answer.save_json(&path).unwrap();
        let paths = vec![path.to_string_lossy().into_owned()];
        let error =
            load_selected_answer_files(&paths, "TEST_STIG", &std::collections::HashSet::new())
                .unwrap_err();
        assert!(error.to_string().contains("unknown Vuln ID"));

        answer.entries[0].vuln_id = "  ".to_string();
        answer.save_json(&path).unwrap();
        let error =
            load_selected_answer_files(&paths, "TEST_STIG", &std::collections::HashSet::new())
                .unwrap_err();
        assert!(error.to_string().contains("Vuln ID is blank"));
    }

    #[test]
    fn cisco_config_hostname_ignores_banner_payload_and_binds_host() {
        let config = "version 17.9\n\
                      hostname rtr01\n\
                      banner login ^C\n\
                      hostname attacker-controlled-prose\n\
                      ^C\n\
                      line vty 0 4\n\
                       transport input ssh\n\
                      end\n";
        let claimed = cisco_config_hostname(config).unwrap();
        assert_eq!(claimed, "rtr01");
        assert_eq!(
            bind_input_hostname(Some("RTR01"), Some(&claimed), "config").unwrap(),
            "RTR01"
        );

        let error = bind_input_hostname(Some("rtr02"), Some(&claimed), "config")
            .expect_err("a different claimed host must fail closed");
        assert!(error
            .to_string()
            .contains("--host 'rtr02' does not match config hostname 'rtr01'"));
    }

    #[test]
    fn cisco_config_hostname_rejects_ambiguous_identity() {
        let config = "hostname rtr01\nhostname rtr02\n";
        assert!(cisco_config_hostname(config).is_err());
        assert!(cisco_config_hostname("banner login #hostname fake#\n").is_err());
        assert!(cisco_config_hostname("hostname ../../outside\n").is_err());
    }

    #[test]
    fn default_output_path_rejects_hostname_traversal() {
        assert_eq!(
            default_output_path("router-01", "Cisco_IOS-XE_Router_NDM_STIG").unwrap(),
            "router-01_Cisco_IOS-XE_Router_NDM_STIG.ckl"
        );
        for hostname in ["../../outside", "router/name", r"router\\name"] {
            assert!(default_output_path(hostname, "Cisco_IOS-XE_Router_NDM_STIG").is_err());
        }
    }

    #[test]
    fn cli_rejects_check_pack_rules_absent_from_the_benchmark() {
        let pack = CheckPack {
            stig_id: "TEST_STIG".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V1R1".to_string(),
            priority: 100,
            checks: vec![CheckDefinition {
                vuln_id: "V-CHECK".to_string(),
                platform: CheckPlatform::Bsd,
                check: Check::Command {
                    command: "sysctl test.value".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::Matches {
                    pattern: "test.value: 1".to_string(),
                },
                description: None,
            }],
        };
        let mut benchmark = automatestig_core::models::stig::StigBenchmark {
            id: "TEST_STIG".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: automatestig_core::models::stig::Platform::default(),
            rules: Vec::new(),
        };
        let error =
            validate_check_pack_membership(&benchmark, std::slice::from_ref(&pack)).unwrap_err();
        assert!(error.to_string().contains("V-CHECK"));

        benchmark
            .rules
            .push(automatestig_core::models::stig::StigRule {
                vuln_id: "V-CHECK".to_string(),
                rule_id: "SV-CHECKr1_rule".to_string(),
                group_id: "V-CHECK".to_string(),
                group_title: "V-CHECK".to_string(),
                title: "Test rule".to_string(),
                rule_version: "test".to_string(),
                discussion: "test".to_string(),
                severity: automatestig_core::models::stig::Severity::Medium,
                check_content: "test".to_string(),
                fix_text: "test".to_string(),
                cci_refs: Vec::new(),
                legacy_ids: Vec::new(),
                stig_ref: None,
                weight: 8.0,
                automatable: automatestig_core::models::stig::CheckAutomation::Full,
            });
        assert!(validate_check_pack_membership(&benchmark, &[pack]).is_ok());
    }

    #[test]
    fn runtime_rejects_bare_reviewed_pack_and_ignores_legacy_auto_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("library");
        let library = StigLibrary::init(&root).unwrap();
        let pack = |vuln_id: &str| CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![CheckDefinition {
                vuln_id: vuln_id.to_string(),
                platform: CheckPlatform::Bsd,
                check: Check::Command {
                    command: "service auditd onestatus".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::Matches {
                    pattern: "(?i)\\bauditd\\s+is\\s+running\\b".to_string(),
                },
                description: None,
            }],
        };
        std::fs::write(
            root.join("reviewed_check_packs/reviewed.json"),
            serde_json::to_vec(&pack("V-REVIEWED")).unwrap(),
        )
        .unwrap();
        std::fs::create_dir(root.join("auto_check_packs")).unwrap();
        std::fs::write(
            root.join("auto_check_packs/legacy.json"),
            serde_json::to_vec(&pack("V-LEGACY-PROSE")).unwrap(),
        )
        .unwrap();

        let error = load_matching_check_packs(&library, "General_Purpose_Operating_System", "V3R3")
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("has no trusted signed provenance"));
    }
}
