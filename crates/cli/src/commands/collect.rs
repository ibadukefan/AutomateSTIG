use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use automatestig_collector::{collect_plan, SshAuth, SshConfig};
use automatestig_core::library::StigLibrary;
use automatestig_parsers::evidence::EvidenceTranscript;

use super::{evaluate::load_matching_check_packs, library_path};

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

pub fn run(args: CollectArgs, cli: &crate::Cli) -> Result<()> {
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
    let platform = packs[0].platform;
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
    let hostname = args.hostname.unwrap_or(args.host);
    let mut evidence =
        EvidenceTranscript::new_v2(hostname, platform, plan.digest(), report.commands);
    evidence.server_key_fingerprint = report.server_key_fingerprint;
    let bytes = serde_json::to_vec_pretty(&evidence)?;
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

fn write_atomic_or_stdout(output: &str, bytes: &[u8]) -> Result<()> {
    if output == "-" {
        std::io::stdout().write_all(bytes)?;
        std::io::stdout().write_all(b"\n")?;
        return Ok(());
    }
    let path = Path::new(output);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    secure_output_directory(parent)?;
    validate_existing_output(path)?;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("evidence output path must have a UTF-8 filename")?;
    let (temporary, mut file) = loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{filename}.tmp-{}-{sequence}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
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
        file.sync_all()
            .with_context(|| format!("failed to sync {}", temporary.display()))?;
        drop(file);
        // Recheck immediately before rename. The containing directory is
        // current-user-owned and not writable by group/other users.
        validate_existing_output(path)?;
        std::fs::rename(&temporary, path)
            .with_context(|| format!("failed to atomically replace {}", path.display()))?;
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("failed to sync {}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn secure_output_directory(parent: &Path) -> Result<()> {
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "evidence output parent must be a real directory: {}",
                parent.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                anyhow::ensure!(
                    metadata.uid() == unsafe { libc::geteuid() },
                    "evidence output directory is not owned by the current user: {}",
                    parent.display()
                );
                anyhow::ensure!(
                    metadata.permissions().mode() & 0o022 == 0,
                    "evidence output directory is writable by group or other users: {}",
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

fn validate_existing_output(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "evidence output must be a regular non-symlink file: {}",
                path.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.uid() == unsafe { libc::geteuid() },
                    "evidence output is not owned by the current user: {}",
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
    use super::*;

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
