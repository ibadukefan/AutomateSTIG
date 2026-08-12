use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use automatestig_core::models::checklist::EvaluationOrigin;
use automatestig_core::path_safety::{
    configure_no_follow, open_sensitive_file, validate_open_sensitive_file,
    validate_sensitive_directory, SensitiveDirectoryGuard, SensitiveFilePolicy,
};
use automatestig_core::scanner_profiles::ScannerEvidenceMode;
use automatestig_core::target_adapters::AdapterEvidenceEnvelope;
use automatestig_parsers::cklb;
use automatestig_scanner::{
    configuration_envelope, evaluate_adapter_envelope, resolve_bundled_profile,
    validate_evidence_age, ScannerEvaluation,
};
use sha2::{Digest, Sha256};

use super::organization_policy_keys_dir;
use crate::ui;

const MAX_EVIDENCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RUNNING_CONFIG_BYTES: u64 = 100 * 1024 * 1024;
const DEFAULT_MAX_EVIDENCE_AGE_HOURS: i64 = 168;

fn windows_integrity_policy() -> SensitiveFilePolicy {
    #[cfg(windows)]
    {
        SensitiveFilePolicy::IntegrityProtected
    }
    #[cfg(not(windows))]
    {
        SensitiveFilePolicy::UntrustedInput
    }
}

/// Create a detached signature on an isolated signing host.
#[cfg(feature = "maintainer")]
pub fn sign_organization_policy(
    policy_path: &str,
    signing_key_path: &str,
    output_path: &str,
) -> Result<()> {
    let policy = read_regular_file_bounded(
        Path::new(policy_path),
        64 * 1024,
        "organization policy",
        windows_integrity_policy(),
    )?;
    automatestig_core::organization_policy::OrganizationPolicyDocument::validate_for_signing(
        &policy,
        chrono::Utc::now(),
    )
    .map_err(anyhow::Error::msg)
    .context("Organization policy is not valid and currently effective")?;

    let private_path = Path::new(signing_key_path);
    let public_path = private_path.with_extension("pub");
    let _private_key_guard = open_sensitive_file(
        private_path,
        "organization-policy private signing key",
        SensitiveFilePolicy::Private,
    )
    .map_err(anyhow::Error::from)?;
    let _public_key_guard = open_sensitive_file(
        &public_path,
        "organization-policy public signing key",
        windows_integrity_policy(),
    )
    .map_err(anyhow::Error::from)?;
    let (private_key, public_key) =
        automatestig_stigpack::signing::load_signing_key_pair(private_path, &public_path)
            .context("Failed to load external organization-policy signing key pair")?;
    let signature = automatestig_stigpack::signing::sign_manifest(&policy, &private_key)
        .context("Failed to sign organization policy")?;

    let output = Path::new(output_path);
    if output == Path::new(policy_path) || output == private_path || output == public_path {
        anyhow::bail!("signature output must differ from the policy and signing-key paths");
    }
    let output_parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _output_parent_guard = secure_evaluation_output_directory(output_parent)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    configure_no_follow(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(output)
        .with_context(|| format!("Failed to create signature output: {}", output.display()))?;
    validate_open_sensitive_file(
        &file,
        output,
        "organization-policy signature output",
        windows_integrity_policy(),
    )
    .map_err(anyhow::Error::from)?;
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
    pub config: Option<String>,
    pub organization_policy: Option<String>,
    pub organization_policy_signature: Option<String>,
    pub host: Option<String>,
    pub output: Option<String>,
    pub format: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum EvaluationInput {
    Evidence(String),
    Config(String),
}

impl EvaluationInput {
    fn path(&self) -> &str {
        match self {
            Self::Evidence(path) | Self::Config(path) => path,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Evidence(_) => "native adapter evidence",
            Self::Config(_) => "running configuration",
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
        (None, None) => anyhow::bail!("evaluation requires exactly one of --evidence or --config"),
        (Some(_), Some(_)) => anyhow::bail!("--evidence and --config are mutually exclusive"),
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
    Ok(format!("{hostname}_{stig_id}.scanner-result.json"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_regular_file_bounded(
    path: &Path,
    max_bytes: u64,
    label: &str,
    policy: SensitiveFilePolicy,
) -> Result<Vec<u8>> {
    let file = open_sensitive_file(path, label, policy).map_err(anyhow::Error::from)?;
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
    let raw = read_regular_file_bounded(
        Path::new(policy_path),
        64 * 1024,
        "organization policy",
        windows_integrity_policy(),
    )?;
    let signature = read_regular_file_bounded(
        Path::new(signature_path),
        64,
        "organization policy signature",
        windows_integrity_policy(),
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
    automatestig_core::organization_policy::VerifiedOrganizationPolicy::verify_and_parse(
        &raw,
        &signature,
        &trusted_public_keys,
        stig_id,
        stig_release,
        hostname,
        chrono::Utc::now(),
    )
    .map(Some)
    .map_err(anyhow::Error::msg)
}

fn maximum_evidence_age_hours() -> i64 {
    std::env::var("AUTOMATESTIG_MAX_EVIDENCE_AGE_HOURS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|hours| (1..=720).contains(hours))
        .unwrap_or(DEFAULT_MAX_EVIDENCE_AGE_HOURS)
}

pub fn run(args: EvaluateArgs, cli: &crate::Cli) -> Result<()> {
    let EvaluateArgs {
        stig_id,
        evidence,
        config,
        organization_policy,
        organization_policy_signature,
        host,
        output,
        format,
    } = args;
    let input = select_evaluation_input(evidence, config)?;
    let profile = resolve_bundled_profile(&stig_id).map_err(anyhow::Error::msg)?;
    match (&input, profile.evidence_mode()) {
        (EvaluationInput::Evidence(_), ScannerEvidenceMode::SshTranscript)
        | (EvaluationInput::Config(_), ScannerEvidenceMode::RunningConfiguration) => {}
        (EvaluationInput::Evidence(_), ScannerEvidenceMode::RunningConfiguration) => {
            anyhow::bail!(
                "{} must be evaluated with --config and a signed organization policy",
                profile.display_name()
            )
        }
        (EvaluationInput::Config(_), ScannerEvidenceMode::SshTranscript) => {
            anyhow::bail!(
                "{} requires a native adapter evidence envelope produced by collect",
                profile.display_name()
            )
        }
    }

    ui::print_banner();
    ui::section(&format!(
        "{} — {} {}",
        profile.display_name(),
        profile.stig_id(),
        profile.stig_release()
    ));
    ui::detail("Input", input.path());

    let (envelope, origin, source_sha256) = match &input {
        EvaluationInput::Evidence(path) => {
            if organization_policy.is_some() || organization_policy_signature.is_some() {
                anyhow::bail!("organization policy is valid only with --config");
            }
            let raw = read_regular_file_bounded(
                Path::new(path),
                MAX_EVIDENCE_BYTES,
                "native adapter evidence",
                SensitiveFilePolicy::UntrustedInput,
            )?;
            let source_sha256 = sha256_hex(&raw);
            let envelope: AdapterEvidenceEnvelope = serde_json::from_slice(&raw)
                .context("Evidence must be a native AutomateSTIG adapter envelope")?;
            validate_evidence_age(&envelope, chrono::Utc::now(), maximum_evidence_age_hours())
                .map_err(anyhow::Error::msg)?;
            (envelope, EvaluationOrigin::EvidenceFile, source_sha256)
        }
        EvaluationInput::Config(path) => {
            let raw = read_regular_file_bounded(
                Path::new(path),
                MAX_RUNNING_CONFIG_BYTES,
                "running configuration",
                SensitiveFilePolicy::UntrustedInput,
            )?;
            let source_sha256 = sha256_hex(&raw);
            let envelope = configuration_envelope(&stig_id, &raw, chrono::Utc::now())
                .map_err(anyhow::Error::msg)?;
            (envelope, EvaluationOrigin::ConfigFile, source_sha256)
        }
    };
    let hostname = bind_input_hostname(
        host.as_deref(),
        Some(&envelope.device.hostname),
        input.kind(),
    )?;
    ui::detail("Observed target", &hostname);
    ui::detail("Observed version", &envelope.device.software_version);
    ui::detail("Input SHA-256", &source_sha256);
    ui::detail("Evidence SHA-256", &envelope.evidence_sha256);

    let verified_policy = load_organization_policy(
        organization_policy.as_deref(),
        organization_policy_signature.as_deref(),
        profile.stig_id(),
        profile.stig_release(),
        &hostname,
    )?;
    if profile.evidence_mode() == ScannerEvidenceMode::RunningConfiguration
        && verified_policy.is_none()
    {
        anyhow::bail!(
            "IOS-XE configuration evaluation requires --organization-policy and --organization-policy-signature"
        );
    }
    let evaluation = evaluate_adapter_envelope(&stig_id, &envelope, origin, verified_policy)
        .map_err(anyhow::Error::msg)?;
    print_evaluation_summary(&evaluation);

    let output_path = output
        .map(Ok)
        .unwrap_or_else(|| default_output_path(&hostname, profile.stig_id()))?;
    let out_format = format
        .as_deref()
        .or_else(|| {
            Path::new(&output_path)
                .extension()
                .and_then(|value| value.to_str())
        })
        .unwrap_or("json")
        .to_ascii_lowercase();
    let (artifact, artifact_label) = match out_format.as_str() {
        "json" => (
            serde_json::to_vec_pretty(&evaluation)?,
            "native scanner result JSON",
        ),
        "cklb" => {
            if !evaluation.collection_complete {
                anyhow::bail!(
                    "evaluation is incomplete; no CKLB projection is permitted. Use --format json to retain diagnostic result metadata"
                );
            }
            super::ensure_external_export_allowed(&evaluation.checklist)?;
            (
                cklb::write_cklb(&evaluation.checklist)?.into_bytes(),
                "supplemental CKLB projection",
            )
        }
        other => anyhow::bail!(
            "Unsupported output format: {other}. Use json or cklb; CKL and portfolio exports belong outside the scanner workflow"
        ),
    };
    let mut consumed_inputs = vec![Path::new(input.path())];
    if let Some(path) = organization_policy.as_deref() {
        consumed_inputs.push(Path::new(path));
    }
    if let Some(path) = organization_policy_signature.as_deref() {
        consumed_inputs.push(Path::new(path));
    }
    super::ensure_safe_artifact_output(Path::new(&output_path), &consumed_inputs, cli)?;
    write_evaluation_output_atomic(Path::new(&output_path), &artifact)?;
    ui::output_file("Output", &output_path, artifact_label);

    if !evaluation.collection_complete {
        anyhow::bail!(
            "evaluation is incomplete: {} collection/evaluation error(s); diagnostic scanner result written, but no deliverable reviews were produced",
            evaluation.collection_errors.len()
        );
    }
    ui::success("Evaluation complete; scanner-owned reviews are ready for selected-run handoff");
    Ok(())
}

fn print_evaluation_summary(evaluation: &ScannerEvaluation) {
    let summary = evaluation.checklist.summary();
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
            assessed_pass_pct: evaluation.summary.assessed_pass_pct,
            benchmark_coverage_pct: evaluation.summary.benchmark_coverage_pct,
        },
    );
    ui::detail(
        "Automation coverage",
        &format!(
            "{} assessed of {} executable checks; {} manual rules untouched",
            evaluation.summary.checks_assessed,
            evaluation.summary.checks_planned,
            evaluation.summary.manual_not_reviewed
        ),
    );
}

pub(crate) fn write_evaluation_output_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_evaluation_output_atomic_with_hook(path, bytes, |_| Ok(()))
}

/// Validate every directory/destination constraint without creating the final
/// artifact. Remote collection uses this before credentials or SSH.
pub(crate) fn preflight_artifact_output(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _parent_guard = secure_evaluation_output_directory(parent)?;
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
    let _parent_guard = secure_evaluation_output_directory(parent)?;
    validate_existing_evaluation_output(path)?;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
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
    let operation_path = operation_parent.join(filename);
    validate_existing_evaluation_output(&operation_path)?;
    let (temporary, mut file) = loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate =
            operation_parent.join(format!(".{filename}.tmp-{}-{sequence}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        configure_no_follow(&mut options);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        match options.open(&candidate) {
            Ok(file) => {
                validate_open_sensitive_file(
                    &file,
                    &candidate,
                    "artifact temporary output",
                    SensitiveFilePolicy::Private,
                )
                .map_err(anyhow::Error::from)?;
                break (candidate, file);
            }
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

fn secure_evaluation_output_directory(parent: &Path) -> Result<SensitiveDirectoryGuard> {
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
    validate_sensitive_directory(parent, "artifact output directory").map_err(anyhow::Error::from)
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
            let _guard = open_sensitive_file(path, "artifact output", windows_integrity_policy())
                .map_err(anyhow::Error::from)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_hashes_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn input_selection_requires_exactly_one_source() {
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
    fn hostname_claim_must_match_evidence_identity() {
        assert_eq!(
            bind_input_hostname(Some("RTR01"), Some("rtr01"), "config").unwrap(),
            "RTR01"
        );
        assert!(bind_input_hostname(Some("rtr02"), Some("rtr01"), "config").is_err());
        assert!(bind_input_hostname(None, None, "config").is_err());
    }

    #[test]
    fn default_output_is_native_result_and_rejects_traversal() {
        assert_eq!(
            default_output_path("router-01", "Cisco_IOS-XE_Router_NDM_STIG").unwrap(),
            "router-01_Cisco_IOS-XE_Router_NDM_STIG.scanner-result.json"
        );
        for hostname in ["../../outside", "router/name", r"router\name"] {
            assert!(default_output_path(hostname, "Cisco_IOS-XE_Router_NDM_STIG").is_err());
        }
    }

    #[test]
    fn bounded_input_reader_rejects_oversize_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.json");
        std::fs::write(&input, b"12345").unwrap();
        assert!(
            read_regular_file_bounded(&input, 4, "test", SensitiveFilePolicy::UntrustedInput)
                .is_err()
        );
        assert_eq!(
            read_regular_file_bounded(&input, 5, "test", SensitiveFilePolicy::UntrustedInput)
                .unwrap(),
            b"12345"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = dir.path().join("link.json");
            symlink(&input, &link).unwrap();
            assert!(read_regular_file_bounded(
                &link,
                5,
                "test",
                SensitiveFilePolicy::UntrustedInput
            )
            .is_err());
        }
    }

    #[test]
    fn atomic_evaluation_output_is_private_and_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("result.json");
        write_evaluation_output_atomic(&output, b"artifact").unwrap();
        write_evaluation_output_atomic(&output, b"replacement").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"replacement");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn atomic_evaluation_output_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let output = dir.path().join("result.json");
        std::fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &output).unwrap();
        assert!(write_evaluation_output_atomic(&output, b"replacement").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    }

    #[test]
    fn atomic_output_preserves_existing_file_on_precommit_failure() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("result.json");
        std::fs::write(&output, b"existing").unwrap();
        let error = write_evaluation_output_atomic_with_hook(&output, b"replacement", |_| {
            anyhow::bail!("injected pre-commit failure")
        })
        .unwrap_err();
        assert!(error.to_string().contains("injected pre-commit failure"));
        assert_eq!(std::fs::read(&output).unwrap(), b"existing");
    }

    #[test]
    fn atomic_output_reports_directory_sync_failure_as_committed() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("result.json");
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
        assert!(error.to_string().contains("artifact was committed at"));
        assert_eq!(std::fs::read(&output).unwrap(), b"committed artifact");
    }

    #[cfg(unix)]
    #[test]
    fn output_preflight_rejects_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let output = shared.join("evidence.json");
        assert!(preflight_artifact_output(&output).is_err());
        assert!(!output.exists());
    }
}
