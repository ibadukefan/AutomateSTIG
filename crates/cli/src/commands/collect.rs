use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use automatestig_collector::{SshAuth, SshConfig};
use automatestig_core::scanner_profiles::ScannerEvidenceMode;
use automatestig_core::target_adapters::AdapterOperationStatus;
use automatestig_scanner::{bundled_profile_collection_plan, collect_ssh_envelope, preflight_ssh};

pub struct CollectArgs {
    pub stig_id: String,
    pub host: String,
    pub hostname: Option<String>,
    pub username: String,
    pub port: u16,
    pub key: Option<String>,
    pub password_env: String,
    pub passphrase_env: String,
    pub timeout_secs: u64,
    pub output: String,
    pub trust_on_first_use: bool,
}

fn bind_connection_endpoint(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        anyhow::bail!("--host must identify the SSH connection endpoint");
    }
    Ok(host.to_string())
}

fn corroborate_observed_hostname(observed: &str, claimed: Option<&str>) -> Result<()> {
    let Some(claimed) = claimed else {
        return Ok(());
    };
    let observed = observed.trim().trim_end_matches('.');
    let claimed = claimed.trim().trim_end_matches('.');
    if claimed.is_empty() {
        anyhow::bail!("--hostname must not be blank when supplied");
    }
    if !claimed.eq_ignore_ascii_case(observed) {
        anyhow::bail!(
            "--hostname did not corroborate the observed device identity: expected '{}', observed '{}'",
            claimed,
            observed
        );
    }
    Ok(())
}

pub fn run(args: CollectArgs, cli: &crate::Cli) -> Result<()> {
    // Keep the network endpoint separate from the device identity observed by
    // the adapter's read-only identity preflight.
    let connection_endpoint = bind_connection_endpoint(&args.host)?;
    // Resolve immutable release content and reject non-SSH profiles before
    // reading credentials, preparing a destination, or starting a runtime.
    let (profile_id, legacy_plan_sha256) = resolve_ssh_profile_contract(&args.stig_id)?;
    let key_input = args.key.clone();

    if args.output != "-" {
        let consumed_inputs: Vec<&Path> = key_input.as_deref().map(Path::new).into_iter().collect();
        super::ensure_safe_artifact_output(Path::new(&args.output), &consumed_inputs, cli)?;
        // Fail before credentials and SSH if the destination cannot satisfy
        // the private atomic writer's ownership/type/mode requirements.
        super::evaluate::preflight_artifact_output(Path::new(&args.output))?;
    }

    let auth = if let Some(path) = args.key {
        SshAuth::key_file(path, std::env::var(&args.passphrase_env).ok())
    } else {
        let password = std::env::var(&args.password_env).with_context(|| {
            format!(
                "password authentication requires the {} environment variable (or use --key)",
                args.password_env
            )
        })?;
        SshAuth::password(password)
    };
    if args.trust_on_first_use {
        std::env::set_var("AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE", "1");
    }
    let config = SshConfig {
        host: connection_endpoint,
        port: args.port,
        username: args.username,
        auth,
        timeout_secs: args.timeout_secs,
    };
    let runtime = tokio::runtime::Runtime::new().context("failed to start collection runtime")?;
    let preflight = runtime
        .block_on(preflight_ssh(&profile_id, &config))
        .map_err(anyhow::Error::msg)
        .context("SSH identity preflight failed")?;
    corroborate_observed_hostname(&preflight.device.hostname, args.hostname.as_deref())?;
    if preflight.profile_id != profile_id
        || preflight.plan.legacy_collection_plan_sha256 != legacy_plan_sha256
    {
        anyhow::bail!(
            "SSH preflight operation plan does not match the release-bundled scanner contract"
        );
    }
    let envelope = runtime
        .block_on(collect_ssh_envelope(&config, &preflight))
        .map_err(anyhow::Error::msg)
        .context("SSH evidence collection failed")?;
    let bytes = serde_json::to_vec_pretty(&envelope)?;
    if args.output != "-" {
        let consumed_inputs: Vec<&Path> = key_input.as_deref().map(Path::new).into_iter().collect();
        // Collection can take long enough for filesystem state to change.
        // Revalidate immediately before the atomic artifact commit.
        super::ensure_safe_artifact_output(Path::new(&args.output), &consumed_inputs, cli)?;
    }
    write_atomic_or_stdout(&args.output, &bytes)?;

    let failed_operations = envelope
        .operations
        .iter()
        .filter(|operation| operation.status != AdapterOperationStatus::Success)
        .count();
    if !envelope.complete {
        anyhow::bail!(
            "collection is incomplete: {} operation(s) did not succeed; native adapter evidence written to {} (SHA-256 {})",
            failed_operations,
            args.output,
            envelope.evidence_sha256
        );
    }
    eprintln!(
        "Native adapter evidence for {} ({}) written to {} (SHA-256 {})",
        envelope.device.hostname, envelope.target_key, args.output, envelope.evidence_sha256
    );
    Ok(())
}

fn resolve_ssh_profile_contract(profile_id_or_stig_id: &str) -> Result<(String, String)> {
    let bundled = bundled_profile_collection_plan(profile_id_or_stig_id)
        .map_err(anyhow::Error::msg)
        .with_context(|| {
            format!(
                "failed to resolve bundled scanner profile '{}'",
                profile_id_or_stig_id
            )
        })?;
    if bundled.profile().evidence_mode() != ScannerEvidenceMode::SshTranscript {
        anyhow::bail!(
            "scanner profile '{}' requires an authorized complete running configuration; SSH collection is unsupported",
            bundled.profile().target_key()
        );
    }
    Ok((
        bundled.profile().target_key().to_string(),
        bundled.collection_plan().digest(),
    ))
}

fn write_atomic_or_stdout(output: &str, bytes: &[u8]) -> Result<()> {
    if output == "-" {
        std::io::stdout().write_all(bytes)?;
        std::io::stdout().write_all(b"\n")?;
        return Ok(());
    }
    super::evaluate::write_evaluation_output_atomic(Path::new(output), bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_endpoint_is_normalized_without_claiming_device_identity() {
        assert_eq!(
            bind_connection_endpoint("Device.Example.").unwrap(),
            "Device.Example"
        );
        assert_eq!(bind_connection_endpoint("10.0.0.8").unwrap(), "10.0.0.8");
        assert!(bind_connection_endpoint(" ").is_err());
    }

    #[test]
    fn optional_hostname_must_match_the_observed_device_not_the_endpoint() {
        assert!(corroborate_observed_hostname("Device.Example.", None).is_ok());
        assert!(corroborate_observed_hostname("Device.Example.", Some("device.example")).is_ok());
        assert!(
            corroborate_observed_hostname("device.example", Some("production-router")).is_err()
        );
        assert!(corroborate_observed_hostname("device.example", Some(" ")).is_err());
    }

    #[test]
    fn ssh_collection_uses_the_exact_release_bundled_plan() {
        let bundled = bundled_profile_collection_plan("netapp_ontap9").unwrap();
        let expected_digest = bundled.collection_plan().digest();

        let (profile_id, plan_sha256) = resolve_ssh_profile_contract("netapp_ontap9").unwrap();

        assert_eq!(profile_id, "netapp_ontap9");
        assert_eq!(plan_sha256, expected_digest);
    }

    #[test]
    fn running_configuration_profile_fails_before_ssh_setup() {
        let error = resolve_ssh_profile_contract("cisco_ios_xe_router_ndm").unwrap_err();

        assert!(error
            .to_string()
            .contains("requires an authorized complete running configuration"));
        assert!(error.to_string().contains("SSH collection is unsupported"));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_evidence_write_is_private_and_rejects_symlink_destination() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("evidence.json");
        write_atomic_or_stdout(output.to_str().unwrap(), b"sensitive evidence").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"sensitive evidence");
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );

        std::fs::remove_file(&output).unwrap();
        let target = dir.path().join("unrelated");
        std::fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &output).unwrap();
        assert!(write_atomic_or_stdout(output.to_str().unwrap(), b"overwrite").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    }
}
