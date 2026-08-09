use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use automatestig_collector::{collect_plan, SshAuth, SshConfig};
use automatestig_core::checks::{CheckPack, CheckPlatform};
use automatestig_core::library::StigLibrary;
use automatestig_core::models::stig::StigBenchmark;
use automatestig_parsers::evidence::EvidenceTranscript;

use super::{
    evaluate::{load_matching_check_packs, validate_check_pack_membership},
    library_path,
};

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

fn bind_connection_identity(host: &str, claimed_hostname: Option<&str>) -> Result<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        anyhow::bail!("--host must identify the SSH connection endpoint");
    }
    if let Some(claimed_hostname) = claimed_hostname {
        let claimed_hostname = claimed_hostname.trim().trim_end_matches('.');
        if !claimed_hostname.eq_ignore_ascii_case(host) {
            anyhow::bail!(
                "--hostname cannot relabel the SSH endpoint: expected '{}', got '{}'",
                host,
                claimed_hostname
            );
        }
    }
    Ok(host.to_string())
}

pub fn run(args: CollectArgs, cli: &crate::Cli) -> Result<()> {
    // The asset identity is the exact endpoint name/address whose host key is
    // verified by the collector. Do not present an unobserved OS/device
    // hostname as though collection established it.
    let evidence_identity = bind_connection_identity(&args.host, args.hostname.as_deref())?;
    let library = StigLibrary::open(&library_path(cli))
        .context("Failed to open STIG library. Run 'automatestig library init' first.")?;
    let benchmark = library
        .load_benchmark(&args.stig_id)
        .with_context(|| format!("Failed to load STIG benchmark '{}'", args.stig_id))?;
    let packs = load_matching_check_packs(&library, &benchmark.id, &benchmark.version_string())?;
    if packs.is_empty() {
        anyhow::bail!(
            "no exact-release check pack is installed for {} {}",
            benchmark.id,
            benchmark.version_string()
        );
    }
    let (platform, plan) = build_collection_plan(&benchmark, &packs)?;
    let key_input = args.key.clone();

    if args.output != "-" {
        let consumed_inputs: Vec<&Path> = key_input.as_deref().map(Path::new).into_iter().collect();
        super::ensure_safe_artifact_output(Path::new(&args.output), &consumed_inputs, cli)?;
        // Fail before credentials and SSH if the destination cannot satisfy
        // the private atomic writer's ownership/type/mode requirements.
        super::evaluate::preflight_artifact_output(Path::new(&args.output))?;
    }

    let auth = if let Some(path) = args.key {
        SshAuth::KeyFile {
            path,
            passphrase: std::env::var(&args.passphrase_env).ok(),
        }
    } else {
        let password = std::env::var(&args.password_env).with_context(|| {
            format!(
                "password authentication requires the {} environment variable (or use --key)",
                args.password_env
            )
        })?;
        SshAuth::Password { password }
    };
    if args.trust_on_first_use {
        std::env::set_var("AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE", "1");
    }
    let config = SshConfig {
        host: args.host.clone(),
        port: args.port,
        username: args.username,
        auth,
        timeout_secs: args.timeout_secs,
    };
    let runtime = tokio::runtime::Runtime::new().context("failed to start collection runtime")?;
    let report = runtime.block_on(collect_plan(&config, &plan));
    let mut evidence =
        EvidenceTranscript::new_v2(evidence_identity, platform, plan.digest(), report.commands);
    evidence.server_key_fingerprint = report.server_key_fingerprint;
    let bytes = serde_json::to_vec_pretty(&evidence)?;
    if args.output != "-" {
        let consumed_inputs: Vec<&Path> = key_input.as_deref().map(Path::new).into_iter().collect();
        // Collection can take long enough for filesystem state to change.
        // Revalidate immediately before the atomic artifact commit.
        super::ensure_safe_artifact_output(Path::new(&args.output), &consumed_inputs, cli)?;
    }
    write_atomic_or_stdout(&args.output, &bytes)?;

    if !evidence.complete {
        anyhow::bail!(
            "collection is incomplete: {} command(s) failed; diagnostic evidence written to {}",
            evidence.collection_error_count(),
            args.output
        );
    }
    eprintln!("Evidence v2 written to {}", args.output);
    Ok(())
}

fn build_collection_plan(
    benchmark: &StigBenchmark,
    packs: &[CheckPack],
) -> Result<(CheckPlatform, automatestig_core::remote::CollectionPlan)> {
    // This content-integrity guard intentionally precedes plan construction,
    // credential lookup, runtime creation, and every SSH side effect.
    validate_check_pack_membership(benchmark, packs)?;
    let platform = packs
        .first()
        .context("no exact-release check pack is installed")?
        .platform;
    if platform == automatestig_core::checks::CheckPlatform::CiscoIos {
        anyhow::bail!(
            "Cisco IOS-XE is config-file-only; evaluate an authorized running configuration"
        );
    }
    if packs.iter().any(|pack| pack.platform != platform) {
        anyhow::bail!("matching check packs disagree on target platform");
    }
    let mut seen = HashSet::new();
    let definitions: Vec<_> = packs
        .iter()
        .flat_map(|pack| pack.checks.iter())
        .filter(|definition| seen.insert(definition.vuln_id.clone()))
        .cloned()
        .collect();
    let plan = automatestig_core::remote::generate_collection_plan(platform, &definitions)
        .map_err(anyhow::Error::msg)?;
    Ok((platform, plan))
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
    fn collection_identity_cannot_relabel_the_verified_endpoint() {
        assert_eq!(
            bind_connection_identity("Device.Example.", Some("device.example")).unwrap(),
            "Device.Example"
        );
        assert!(bind_connection_identity("10.0.0.8", Some("production-router")).is_err());
        assert!(bind_connection_identity(" ", None).is_err());
    }

    #[test]
    fn incompatible_same_release_content_fails_before_collection_setup() {
        let benchmark = StigBenchmark {
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
        let pack = CheckPack {
            stig_id: benchmark.id.clone(),
            platform: CheckPlatform::Bsd,
            version: benchmark.version_string(),
            priority: 100,
            checks: vec![automatestig_core::checks::CheckDefinition {
                vuln_id: "V-NOT-IN-BENCHMARK".to_string(),
                platform: CheckPlatform::Bsd,
                check: automatestig_core::checks::Check::Command {
                    command: "service auditd onestatus".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: automatestig_core::checks::ExpectedResult::Matches {
                    pattern: "(?i)\\bauditd\\s+is\\s+running\\b".to_string(),
                },
                description: None,
            }],
        };

        let error = match build_collection_plan(&benchmark, &[pack]) {
            Err(error) => error,
            Ok(_) => panic!("incompatible content must fail before plan or SSH setup"),
        };
        assert!(error.to_string().contains("V-NOT-IN-BENCHMARK"));
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
