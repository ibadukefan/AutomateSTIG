//! Shared fail-closed SSH transport for CLI and GUI collection.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use automatestig_core::remote::{
    validate_command_output, CollectionCommand, CollectionPlan, CommandEvidence, CommandStatus,
};
use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
use serde::{Deserialize, Serialize};

pub const MAX_COMMAND_OUTPUT: usize = 50 * 1024 * 1024;
pub const MAX_COLLECTION_OUTPUT: usize = 256 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
const MAX_KNOWN_HOSTS_BYTES: u64 = 1024 * 1024;
const TRUST_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// The environment switch is an enrollment arm, not a permanent policy. A
/// long-running GUI process may enroll at most one collection after startup;
/// restart it to deliberately arm another enrollment. CLI collection already
/// runs once per process, so its `--trust-on-first-use` behavior is unchanged.
static ENV_TOFU_ARM_CONSUMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub timeout_secs: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshAuth {
    Password {
        password: String,
    },
    KeyFile {
        path: String,
        passphrase: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct CollectionReport {
    pub commands: Vec<CommandEvidence>,
    pub server_key_fingerprint: Option<String>,
}

#[derive(Debug)]
struct RawCommandResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<u32>,
}

#[derive(Debug)]
enum CommandFailure {
    Transport(String),
    Timeout,
    OutputLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetTrustClass {
    Loopback,
    Private,
    Public,
    LinkLocal,
}

async fn resolve_scan_target(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Err("SSH target host must not be empty or contain whitespace".to_string());
    }
    if port == 0 {
        return Err("SSH target port must not be zero".to_string());
    }
    let lookup = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port))).await;
    let addresses = match lookup {
        Ok(Ok(addresses)) => addresses.collect::<Vec<_>>(),
        Ok(Err(error)) => {
            return Err(format!(
                "failed to resolve SSH target {host}:{port}: {error}"
            ));
        }
        Err(_) => {
            return Err(format!(
                "SSH target resolution timed out after {} second(s) for {host}:{port}",
                timeout.as_secs()
            ));
        }
    };
    select_resolved_target(
        host,
        port,
        addresses,
        environment_switch_enabled("AUTOMATESTIG_SSH_ALLOW_LINK_LOCAL"),
    )
}

fn select_resolved_target(
    host: &str,
    port: u16,
    addresses: Vec<SocketAddr>,
    allow_link_local: bool,
) -> Result<SocketAddr, String> {
    let mut unique = Vec::with_capacity(addresses.len());
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    let Some(&selected) = unique.first() else {
        return Err(format!("SSH target {host}:{port} resolved to no addresses"));
    };

    let first_class = classify_target_address(selected.ip(), allow_link_local)?;
    for address in unique.iter().skip(1) {
        let class = classify_target_address(address.ip(), allow_link_local)?;
        if class != first_class {
            return Err(format!(
                "SSH target {host}:{port} resolves across trust classes ({first_class:?} and {class:?}); refusing a rebinding-prone target"
            ));
        }
    }
    Ok(selected)
}

fn classify_target_address(
    address: IpAddr,
    allow_link_local: bool,
) -> Result<TargetTrustClass, String> {
    let address = match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    };
    if address.is_unspecified() {
        return Err(format!("SSH target address {address} is unspecified"));
    }
    if address.is_multicast() {
        return Err(format!("SSH target address {address} is multicast"));
    }
    if address == IpAddr::V4(Ipv4Addr::BROADCAST) {
        return Err(format!("SSH target address {address} is broadcast"));
    }
    let link_local = match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    };
    if link_local {
        return if allow_link_local {
            Ok(TargetTrustClass::LinkLocal)
        } else {
            Err(format!(
                "SSH target address {address} is link-local; set AUTOMATESTIG_SSH_ALLOW_LINK_LOCAL=1 only for an explicitly scoped device"
            ))
        };
    }
    if address.is_loopback() {
        return Ok(TargetTrustClass::Loopback);
    }
    let private = match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.is_unique_local(),
    };
    if private {
        Ok(TargetTrustClass::Private)
    } else {
        Ok(TargetTrustClass::Public)
    }
}

/// Collect every command in a plan. Individual failures do not erase partial
/// evidence or prevent later commands from being attempted.
pub async fn collect_plan(config: &SshConfig, plan: &CollectionPlan) -> CollectionReport {
    let fingerprint = Arc::new(Mutex::new(None));
    let phase_timeout = Duration::from_secs(config.timeout_secs.max(1));
    let target = match resolve_scan_target(&config.host, config.port, phase_timeout).await {
        Ok(target) => target,
        Err(error) => return transport_failure_report(plan, &fingerprint, error),
    };
    let russh_config = Arc::new(client::Config {
        inactivity_timeout: Some(phase_timeout),
        ..Default::default()
    });
    let handler =
        SshHandler::new_with_fingerprint(&config.host, config.port, Arc::clone(&fingerprint));
    let connect = tokio::time::timeout(
        phase_timeout,
        client::connect(russh_config, target, handler),
    )
    .await;
    let mut session = match connect {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            return transport_failure_report(
                plan,
                &fingerprint,
                format!(
                    "SSH connection failed to {}:{} via {target}: {error}",
                    config.host, config.port,
                ),
            );
        }
        Err(_) => {
            return transport_failure_report(
                plan,
                &fingerprint,
                format!(
                    "SSH connection and handshake timed out after {} second(s) for {}:{}",
                    phase_timeout.as_secs(),
                    config.host,
                    config.port
                ),
            );
        }
    };

    let authenticated = match &config.auth {
        SshAuth::Password { password } => match tokio::time::timeout(
            phase_timeout,
            session.authenticate_password(&config.username, password),
        )
        .await
        {
            Ok(Ok(result)) => result.success(),
            Ok(Err(error)) => {
                return transport_failure_report(
                    plan,
                    &fingerprint,
                    format!("SSH password authentication failed: {error}"),
                );
            }
            Err(_) => {
                return transport_failure_report(
                    plan,
                    &fingerprint,
                    format!(
                        "SSH password authentication timed out after {} second(s)",
                        phase_timeout.as_secs()
                    ),
                );
            }
        },
        SshAuth::KeyFile { path, passphrase } => {
            let key =
                match load_private_key_for_auth(path, passphrase.as_deref(), phase_timeout).await {
                    Ok(key) => key,
                    Err(error) => {
                        return transport_failure_report(plan, &fingerprint, error);
                    }
                };
            match tokio::time::timeout(
                phase_timeout,
                session.authenticate_publickey(
                    &config.username,
                    PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256)),
                ),
            )
            .await
            {
                Ok(Ok(result)) => result.success(),
                Ok(Err(error)) => {
                    return transport_failure_report(
                        plan,
                        &fingerprint,
                        format!("SSH public-key authentication failed: {error}"),
                    );
                }
                Err(_) => {
                    return transport_failure_report(
                        plan,
                        &fingerprint,
                        format!(
                            "SSH public-key authentication timed out after {} second(s)",
                            phase_timeout.as_secs()
                        ),
                    );
                }
            }
        }
    };
    if !authenticated {
        return transport_failure_report(
            plan,
            &fingerprint,
            format!(
                "SSH authentication failed for {}@{}",
                config.username, config.host
            ),
        );
    }

    let mut commands = Vec::with_capacity(plan.commands.len());
    let mut aggregate_bytes = 0usize;
    for item in &plan.commands {
        if aggregate_bytes >= MAX_COLLECTION_OUTPUT {
            commands.push(CommandEvidence::failed(
                &item.data_key,
                &item.command,
                CommandStatus::OutputLimit,
                format!(
                    "collection output exceeded the {MAX_COLLECTION_OUTPUT}-byte aggregate limit"
                ),
            ));
            continue;
        }
        let record = collect_one(
            &mut session,
            plan,
            item,
            Duration::from_secs(config.timeout_secs.max(1)),
        )
        .await;
        aggregate_bytes = aggregate_bytes
            .saturating_add(record.stdout.len())
            .saturating_add(record.stderr.len());
        if aggregate_bytes > MAX_COLLECTION_OUTPUT {
            commands.push(
                CommandEvidence::failed(
                    &item.data_key,
                    &item.command,
                    CommandStatus::OutputLimit,
                    format!(
                    "collection output exceeded the {MAX_COLLECTION_OUTPUT}-byte aggregate limit"
                ),
                )
                .with_diagnostics(
                    String::new(),
                    String::new(),
                    record.exit_code,
                    record.duration_ms,
                ),
            );
        } else {
            commands.push(record);
        }
    }

    CollectionReport {
        commands,
        server_key_fingerprint: fingerprint.lock().ok().and_then(|value| value.clone()),
    }
}

fn transport_failure_report(
    plan: &CollectionPlan,
    fingerprint: &Arc<Mutex<Option<String>>>,
    error: impl AsRef<str>,
) -> CollectionReport {
    CollectionReport {
        commands: fail_remaining(plan, CommandStatus::TransportError, error.as_ref()),
        server_key_fingerprint: fingerprint.lock().ok().and_then(|value| value.clone()),
    }
}

async fn load_private_key_for_auth(
    path: &str,
    passphrase: Option<&str>,
    timeout: Duration,
) -> Result<russh::keys::PrivateKey, String> {
    let path = PathBuf::from(path);
    let display_path = path.display().to_string();
    let passphrase = passphrase.map(str::to_owned);
    let worker =
        tokio::task::spawn_blocking(move || load_private_key_secure(&path, passphrase.as_deref()));

    match tokio::time::timeout(timeout, worker).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(format!(
            "SSH private-key loading worker failed for {display_path}: {error}"
        )),
        Err(_) => Err(format!(
            "SSH private-key loading timed out after {} second(s) for {display_path}",
            timeout.as_secs()
        )),
    }
}

fn load_private_key_secure(
    path: &Path,
    passphrase: Option<&str>,
) -> Result<russh::keys::PrivateKey, String> {
    let roots = configured_private_key_roots();
    load_private_key_secure_with_roots(path, passphrase, &roots)
}

fn configured_private_key_roots() -> Vec<PathBuf> {
    let home = home_dir();
    let additional = std::env::var_os("AUTOMATESTIG_SSH_KEY_ROOTS");
    configured_private_key_roots_from(&home, additional.as_deref())
}

fn configured_private_key_roots_from(
    home: &Path,
    additional: Option<&std::ffi::OsStr>,
) -> Vec<PathBuf> {
    let mut roots = vec![home.join(".ssh"), home.join(".automatestig/ssh_keys")];
    if let Some(value) = additional {
        for root in std::env::split_paths(value).filter(|root| !root.as_os_str().is_empty()) {
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
    }
    roots
}

fn load_private_key_secure_with_roots(
    path: &Path,
    passphrase: Option<&str>,
    roots: &[PathBuf],
) -> Result<russh::keys::PrivateKey, String> {
    if path.as_os_str().is_empty() {
        return Err("SSH private-key path must not be empty".to_string());
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("failed to resolve SSH private-key path: {error}"))?
            .join(path)
    };
    let path = path.as_path();
    reject_symlink_components(path, "SSH private-key path")?;

    let initial = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect SSH private key {}: {error}",
            path.display()
        )
    })?;
    validate_private_key_metadata(path, &initial)?;
    validate_private_key_parent(path)?;
    let canonical_path = authorize_private_key_path(path, &initial, roots)?;
    let path = canonical_path.as_path();

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to open SSH private key {}: {error}", path.display()))?;
    let opened = file.metadata().map_err(|error| {
        format!(
            "failed to inspect open SSH private key {}: {error}",
            path.display()
        )
    })?;
    validate_private_key_metadata(path, &opened)?;
    ensure_same_file(&initial, &opened, path, "SSH private key")?;

    let mut bytes = Vec::with_capacity((opened.len().min(MAX_PRIVATE_KEY_BYTES)) as usize);
    Read::by_ref(&mut file)
        .take(MAX_PRIVATE_KEY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read SSH private key {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_PRIVATE_KEY_BYTES {
        return Err(format!(
            "SSH private key {} exceeds the {MAX_PRIVATE_KEY_BYTES}-byte limit",
            path.display()
        ));
    }
    let encoded = std::str::from_utf8(&bytes)
        .map_err(|error| format!("SSH private key {} is not UTF-8: {error}", path.display()))?;
    russh::keys::decode_secret_key(encoded, passphrase).map_err(|error| {
        format!(
            "failed to decode SSH private key {}: {error}",
            path.display()
        )
    })
}

fn validate_private_key_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    if !metadata.file_type().is_file() {
        return Err(format!(
            "SSH private key {} is not a regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(format!(
            "SSH private key {} exceeds the {MAX_PRIVATE_KEY_BYTES}-byte limit",
            path.display()
        ));
    }
    #[cfg(unix)]
    validate_unix_private_file(path, metadata, "SSH private key", true)?;
    Ok(())
}

fn validate_private_key_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let Some(parent) = parent else {
        return Ok(());
    };
    let metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        format!(
            "failed to inspect SSH private-key directory {}: {error}",
            parent.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "SSH private-key directory {} is not a real directory",
            parent.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid {
            return Err(format!(
                "SSH private-key directory {} is not owned by the current user",
                parent.display()
            ));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "SSH private-key directory {} is writable by group or other users",
                parent.display()
            ));
        }
    }
    Ok(())
}

fn authorize_private_key_path(
    path: &Path,
    initial: &std::fs::Metadata,
    roots: &[PathBuf],
) -> Result<PathBuf, String> {
    let canonical_path = std::fs::canonicalize(path).map_err(|error| {
        format!(
            "failed to canonicalize SSH private key {}: {error}",
            path.display()
        )
    })?;
    let canonical_metadata = std::fs::metadata(&canonical_path).map_err(|error| {
        format!(
            "failed to inspect canonical SSH private key {}: {error}",
            canonical_path.display()
        )
    })?;
    ensure_same_file(
        initial,
        &canonical_metadata,
        &canonical_path,
        "SSH private key",
    )?;

    for root in roots {
        let root = if root.is_absolute() {
            root.clone()
        } else {
            std::env::current_dir()
                .map_err(|error| format!("failed to resolve configured SSH key root: {error}"))?
                .join(root)
        };
        let metadata = match std::fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "failed to inspect configured SSH key root {}: {error}",
                    root.display()
                ));
            }
        };
        let canonical_root = match std::fs::canonicalize(&root) {
            Ok(root) => root,
            Err(_) => continue,
        };
        if !canonical_path.starts_with(&canonical_root) {
            continue;
        }
        validate_private_key_root(&root, &metadata)?;
        let canonical_root_metadata = std::fs::metadata(&canonical_root).map_err(|error| {
            format!(
                "failed to inspect canonical SSH key root {}: {error}",
                canonical_root.display()
            )
        })?;
        ensure_same_file(
            &metadata,
            &canonical_root_metadata,
            &canonical_root,
            "configured SSH key root",
        )?;
        return Ok(canonical_path);
    }
    let configured = if roots.is_empty() {
        "(none)".to_string()
    } else {
        roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(format!(
        "SSH private key {} is outside permitted key roots: {configured}; use ~/.ssh, ~/.automatestig/ssh_keys, or explicitly set AUTOMATESTIG_SSH_KEY_ROOTS",
        canonical_path.display()
    ))
}

fn validate_private_key_root(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "configured SSH key root {} is not a real directory",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid && metadata.uid() != 0 {
            return Err(format!(
                "configured SSH key root {} is not owned by the current user or root",
                path.display()
            ));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "configured SSH key root {} is writable by group or other users",
                path.display()
            ));
        }
    }
    Ok(())
}

fn reject_symlink_components(path: &Path, label: &str) -> Result<(), String> {
    // Reject the file itself and its containing directory. Older platforms
    // commonly expose system aliases such as macOS `/var -> /private/var`, so
    // rejecting every ancestor would make otherwise secure user-owned key
    // directories unusable. The direct directory ownership/mode check below
    // prevents another user from swapping deeper components.
    for component_path in [Some(path), path.parent()]
        .into_iter()
        .flatten()
        .filter(|part| !part.as_os_str().is_empty())
    {
        let metadata = std::fs::symlink_metadata(component_path).map_err(|error| {
            format!(
                "failed to inspect {label} component {}: {error}",
                component_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{label} contains a symbolic link: {}",
                component_path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_private_file(
    path: &Path,
    metadata: &std::fs::Metadata,
    label: &str,
    reject_any_group_or_other_access: bool,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let current_uid = unsafe { libc::geteuid() };
    if metadata.uid() != current_uid {
        return Err(format!(
            "{label} {} is not owned by the current user",
            path.display()
        ));
    }
    let mode = metadata.permissions().mode();
    let forbidden = if reject_any_group_or_other_access {
        0o077
    } else {
        0o022
    };
    if mode & forbidden != 0 {
        return Err(format!(
            "{label} {} has insecure permissions {:04o}",
            path.display(),
            mode & 0o7777
        ));
    }
    Ok(())
}

fn ensure_same_file(
    initial: &std::fs::Metadata,
    opened: &std::fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if initial.dev() != opened.dev() || initial.ino() != opened.ino() {
            return Err(format!(
                "{label} {} changed while it was being opened",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (initial, opened, path, label);
    }
    Ok(())
}

fn fail_remaining(
    plan: &CollectionPlan,
    status: CommandStatus,
    error: &str,
) -> Vec<CommandEvidence> {
    plan.commands
        .iter()
        .map(|item| CommandEvidence::failed(&item.data_key, &item.command, status, error))
        .collect()
}

async fn collect_one(
    session: &mut client::Handle<SshHandler>,
    plan: &CollectionPlan,
    item: &CollectionCommand,
    timeout: Duration,
) -> CommandEvidence {
    let started = Instant::now();
    let raw =
        match tokio::time::timeout(timeout, execute_single_command(session, &item.command)).await {
            Err(_) => Err(CommandFailure::Timeout),
            Ok(result) => result,
        };
    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let raw = match raw {
        Ok(raw) => raw,
        Err(CommandFailure::Timeout) => {
            return CommandEvidence::failed(
                &item.data_key,
                &item.command,
                CommandStatus::Timeout,
                "command timed out before a complete exit status was received",
            )
            .with_diagnostics(String::new(), String::new(), None, duration_ms);
        }
        Err(CommandFailure::OutputLimit) => {
            return CommandEvidence::failed(
                &item.data_key,
                &item.command,
                CommandStatus::OutputLimit,
                format!("command output exceeded the {MAX_COMMAND_OUTPUT}-byte safety limit"),
            )
            .with_diagnostics(String::new(), String::new(), None, duration_ms);
        }
        Err(CommandFailure::Transport(error)) => {
            return CommandEvidence::failed(
                &item.data_key,
                &item.command,
                CommandStatus::TransportError,
                error,
            )
            .with_diagnostics(String::new(), String::new(), None, duration_ms);
        }
    };

    let stdout = match String::from_utf8(raw.stdout) {
        Ok(value) => value,
        Err(error) => {
            return CommandEvidence::failed(
                &item.data_key,
                &item.command,
                CommandStatus::ProtocolError,
                format!("command stdout was not valid UTF-8: {error}"),
            )
            .with_diagnostics(String::new(), String::new(), raw.exit_code, duration_ms);
        }
    };
    let stderr = match String::from_utf8(raw.stderr) {
        Ok(value) => value,
        Err(error) => {
            return CommandEvidence::failed(
                &item.data_key,
                &item.command,
                CommandStatus::ProtocolError,
                format!("command stderr was not valid UTF-8: {error}"),
            )
            .with_diagnostics(stdout, String::new(), raw.exit_code, duration_ms);
        }
    };
    let Some(exit_code) = raw.exit_code else {
        return CommandEvidence::failed(
            &item.data_key,
            &item.command,
            CommandStatus::MissingExitStatus,
            "SSH channel closed without an exit status",
        )
        .with_diagnostics(stdout, stderr, None, duration_ms);
    };
    if !item.accepted_exit_codes.contains(&exit_code) {
        let detail = stderr.trim().chars().take(500).collect::<String>();
        return CommandEvidence::failed(
            &item.data_key,
            &item.command,
            CommandStatus::ExitFailure,
            if detail.is_empty() {
                format!("command exited with status {exit_code}")
            } else {
                format!("command exited with status {exit_code}: {detail}")
            },
        )
        .with_diagnostics(stdout, stderr, Some(exit_code), duration_ms);
    }
    if let Err(error) = validate_command_output(plan.platform, item, &stdout, &stderr) {
        return CommandEvidence::failed(
            &item.data_key,
            &item.command,
            CommandStatus::SemanticError,
            error,
        )
        .with_diagnostics(stdout, stderr, Some(exit_code), duration_ms);
    }
    CommandEvidence::success(
        &item.data_key,
        &item.command,
        stdout,
        stderr,
        exit_code,
        duration_ms,
    )
}

async fn execute_single_command(
    session: &mut client::Handle<SshHandler>,
    command: &str,
) -> Result<RawCommandResult, CommandFailure> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|error| CommandFailure::Transport(format!("channel open failed: {error}")))?;
    channel
        .exec(true, command)
        .await
        .map_err(|error| CommandFailure::Transport(format!("exec request failed: {error}")))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = None;
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Data { data }) => {
                if stdout
                    .len()
                    .saturating_add(stderr.len())
                    .saturating_add(data.len())
                    > MAX_COMMAND_OUTPUT
                {
                    return Err(CommandFailure::OutputLimit);
                }
                stdout.extend_from_slice(&data);
            }
            Some(russh::ChannelMsg::ExtendedData { data, ext: 1 }) => {
                if stdout
                    .len()
                    .saturating_add(stderr.len())
                    .saturating_add(data.len())
                    > MAX_COMMAND_OUTPUT
                {
                    return Err(CommandFailure::OutputLimit);
                }
                stderr.extend_from_slice(&data);
            }
            Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = Some(exit_status);
            }
            Some(russh::ChannelMsg::Eof) => {}
            Some(russh::ChannelMsg::Close) | None => break,
            _ => {}
        }
    }
    Ok(RawCommandResult {
        stdout,
        stderr,
        exit_code,
    })
}

/// SSH client handler with host-scoped fingerprint pinning.
pub struct SshHandler {
    pub host: String,
    pub port: u16,
    pub accept_unknown: bool,
    fingerprint: Arc<Mutex<Option<String>>>,
}

impl SshHandler {
    pub fn new(host: &str, port: u16) -> Self {
        Self::new_with_fingerprint(host, port, Arc::new(Mutex::new(None)))
    }

    fn new_with_fingerprint(
        host: &str,
        port: u16,
        fingerprint: Arc<Mutex<Option<String>>>,
    ) -> Self {
        let accept_unknown = consume_environment_tofu_arm();
        if accept_unknown {
            tracing::warn!(
                "one-shot SSH trust-on-first-use enrollment armed for {}:{}",
                host,
                port
            );
        }
        Self {
            host: host.to_string(),
            port,
            accept_unknown,
            fingerprint,
        }
    }

    pub fn with_accept_unknown(mut self, accept_unknown: bool) -> Self {
        self.accept_unknown = accept_unknown;
        self
    }
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let key_id = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        if let Ok(mut value) = self.fingerprint.lock() {
            *value = Some(key_id.clone());
        }
        let known_hosts_path = home_dir().join(".automatestig").join("known_hosts");
        let host = self.host.clone();
        let port = self.port;
        let accept_unknown = self.accept_unknown;
        let task = tokio::task::spawn_blocking(move || {
            verify_or_enroll_host_key(&known_hosts_path, &host, port, &key_id, accept_unknown)
        })
        .await;
        match task {
            Ok(Ok(HostKeyDecision::Trusted)) => Ok(true),
            Ok(Ok(HostKeyDecision::Unknown)) => {
                tracing::warn!(
                    "SSH server key is not trusted; explicit enrollment is required for {}:{}",
                    self.host,
                    self.port
                );
                Ok(false)
            }
            Ok(Ok(HostKeyDecision::Changed)) => {
                tracing::error!(
                    "SSH server key changed for {}:{}; rejecting possible MITM",
                    self.host,
                    self.port
                );
                Ok(false)
            }
            Ok(Err(error)) => {
                tracing::error!("SSH host-key trust check failed closed: {error}");
                Ok(false)
            }
            Err(error) => {
                tracing::error!("SSH host-key trust worker failed closed: {error}");
                Ok(false)
            }
        }
    }
}

fn environment_tofu_enabled() -> bool {
    environment_switch_enabled("AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE")
}

fn environment_switch_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn consume_environment_tofu_arm() -> bool {
    environment_tofu_enabled()
        && ENV_TOFU_ARM_CONSUMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKeyDecision {
    Trusted,
    Unknown,
    Changed,
}

fn verify_or_enroll_host_key(
    known_hosts_path: &Path,
    host: &str,
    port: u16,
    key_id: &str,
    accept_unknown: bool,
) -> Result<HostKeyDecision, String> {
    validate_host_key_field(host, "SSH host")?;
    validate_host_key_field(key_id, "SSH server-key fingerprint")?;
    let trust_dir = known_hosts_path
        .parent()
        .ok_or_else(|| "SSH known_hosts path has no parent directory".to_string())?;
    ensure_secure_trust_directory(trust_dir)?;

    let lock_path = trust_dir.join("known_hosts.lock");
    let lock_file = open_secure_trust_file(&lock_path, true, "SSH trust lock")?
        .ok_or_else(|| "failed to create SSH trust lock".to_string())?;
    acquire_trust_lock(&lock_file, &lock_path)?;

    let entry = format!("{host}:{port} {key_id}");
    let host_prefix = format!("{host}:{port} ");
    let Some(mut known_hosts) =
        open_secure_trust_file(known_hosts_path, accept_unknown, "SSH known_hosts file")?
    else {
        return Ok(HostKeyDecision::Unknown);
    };
    let content = read_bounded_text(
        &mut known_hosts,
        known_hosts_path,
        MAX_KNOWN_HOSTS_BYTES,
        "SSH known_hosts file",
    )?;
    for line in content.lines().map(str::trim) {
        if line == entry {
            return Ok(HostKeyDecision::Trusted);
        }
        if line.starts_with(&host_prefix) {
            return Ok(HostKeyDecision::Changed);
        }
    }
    if !accept_unknown {
        return Ok(HostKeyDecision::Unknown);
    }

    let separator = if content.is_empty() || content.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let addition = format!("{separator}{entry}\n");
    let final_size = content
        .len()
        .checked_add(addition.len())
        .ok_or_else(|| "SSH known_hosts size overflow".to_string())?;
    if final_size as u64 > MAX_KNOWN_HOSTS_BYTES {
        return Err(format!(
            "SSH known_hosts file {} would exceed the {MAX_KNOWN_HOSTS_BYTES}-byte limit",
            known_hosts_path.display()
        ));
    }
    known_hosts
        .seek(SeekFrom::End(0))
        .and_then(|_| known_hosts.write_all(addition.as_bytes()))
        .and_then(|_| known_hosts.sync_all())
        .map_err(|error| {
            format!(
                "failed to persist SSH server key in {}: {error}",
                known_hosts_path.display()
            )
        })?;
    Ok(HostKeyDecision::Trusted)
}

fn acquire_trust_lock(file: &File, path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + TRUST_LOCK_TIMEOUT;
    loop {
        match File::try_lock(file) {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(format!(
                    "timed out waiting for SSH trust-store lock {}",
                    path.display()
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(format!(
                    "failed to lock SSH trust store {}: {error}",
                    path.display()
                ));
            }
        }
    }
}

fn validate_host_key_field(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(format!("{label} contains invalid whitespace"));
    }
    Ok(())
}

fn ensure_secure_trust_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            format!(
                "failed to inspect SSH trust directory {}: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "SSH trust directory {} is not a real directory",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let current_uid = unsafe { libc::geteuid() };
            if metadata.uid() != current_uid {
                return Err(format!(
                    "SSH trust directory {} is not owned by the current user",
                    path.display()
                ));
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
                    |error| {
                        format!(
                            "failed to secure SSH trust directory {}: {error}",
                            path.display()
                        )
                    },
                )?;
            }
        }
        return Ok(());
    }

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        format!(
            "failed to create SSH trust directory {}: {error}",
            path.display()
        )
    })?;
    // Recheck after creation to catch a concurrent symlink or non-directory.
    ensure_secure_trust_directory(path)
}

fn open_secure_trust_file(path: &Path, create: bool, label: &str) -> Result<Option<File>, String> {
    let initial = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "failed to inspect {label} {}: {error}",
                path.display()
            ))
        }
    };
    if let Some(metadata) = &initial {
        validate_trust_file_metadata(path, metadata, label)?;
    } else if !create {
        return Ok(None);
    }

    let mut options = OpenOptions::new();
    options.read(true).append(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("failed to open {label} {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("failed to inspect open {label} {}: {error}", path.display()))?;
    validate_trust_file_metadata(path, &opened, label)?;
    if let Some(initial) = &initial {
        ensure_same_file(initial, &opened, path, label)?;
    }
    Ok(Some(file))
}

fn validate_trust_file_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    label: &str,
) -> Result<(), String> {
    if !metadata.file_type().is_file() {
        return Err(format!("{label} {} is not a regular file", path.display()));
    }
    if metadata.len() > MAX_KNOWN_HOSTS_BYTES {
        return Err(format!(
            "{label} {} exceeds the {MAX_KNOWN_HOSTS_BYTES}-byte limit",
            path.display()
        ));
    }
    #[cfg(unix)]
    validate_unix_private_file(path, metadata, label, false)?;
    Ok(())
}

fn read_bounded_text(
    file: &mut File,
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<String, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("failed to seek {label} {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {label} {}: {error}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "{label} {} exceeds the {limit}-byte limit",
            path.display()
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| format!("{label} {} is not UTF-8: {error}", path.display()))
}

fn home_dir() -> std::path::PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    use automatestig_core::checks::CheckPlatform;
    use automatestig_core::remote::{
        CollectionCommand, CollectionPlan, CommandStatus, OutputPolicy,
    };
    use russh::keys::ssh_key::{Algorithm, LineEnding};
    use russh::keys::PrivateKey;
    use russh::server::{self, Auth};
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    static ENVIRONMENT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct EnvironmentRestore {
        home: Option<std::ffi::OsString>,
        tofu: Option<std::ffi::OsString>,
    }

    impl EnvironmentRestore {
        fn capture() -> Self {
            Self {
                home: std::env::var_os("HOME"),
                tofu: std::env::var_os("AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE"),
            }
        }
    }

    impl Drop for EnvironmentRestore {
        fn drop(&mut self) {
            if let Some(value) = &self.home {
                std::env::set_var("HOME", value);
            } else {
                std::env::remove_var("HOME");
            }
            if let Some(value) = &self.tofu {
                std::env::set_var("AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE", value);
            } else {
                std::env::remove_var("AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE");
            }
        }
    }

    fn probe_plan() -> CollectionPlan {
        CollectionPlan {
            platform: CheckPlatform::Bsd,
            commands: vec![CollectionCommand {
                command: "collect".to_string(),
                data_key: "probe".to_string(),
                accepted_exit_codes: vec![0],
                output_policy: OutputPolicy::Any,
            }],
            check_definitions_sha256: "test-check-definitions".to_string(),
        }
    }

    fn password_config(port: u16) -> SshConfig {
        SshConfig {
            host: "127.0.0.1".to_string(),
            port,
            username: "scanner".to_string(),
            auth: SshAuth::Password {
                password: "correct-password".to_string(),
            },
            timeout_secs: 1,
        }
    }

    fn write_test_private_key(path: &Path) {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let encoded = key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(path, encoded.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn load_test_private_key(
        path: &Path,
        roots: &[PathBuf],
    ) -> Result<russh::keys::PrivateKey, String> {
        load_private_key_secure_with_roots(path, None, roots)
    }

    #[test]
    fn private_key_loader_accepts_only_bounded_secure_regular_files() {
        let temp = TempDir::new().unwrap();
        let roots = vec![temp.path().to_path_buf()];
        let valid = temp.path().join("id_ed25519");
        write_test_private_key(&valid);
        let valid_result = load_test_private_key(&valid, &roots);
        assert!(
            valid_result.is_ok(),
            "unexpected error: {:?}",
            valid_result.err()
        );

        let directory = temp.path().join("not-a-key");
        std::fs::create_dir(&directory).unwrap();
        assert!(load_test_private_key(&directory, &roots)
            .unwrap_err()
            .contains("not a regular file"));

        let oversized = temp.path().join("oversized-key");
        std::fs::write(&oversized, vec![b'x'; MAX_PRIVATE_KEY_BYTES as usize + 1]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(load_test_private_key(&oversized, &roots)
            .unwrap_err()
            .contains("exceeds"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&valid, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_test_private_key(&valid, &roots)
                .unwrap_err()
                .contains("insecure permissions"));
        }
    }

    #[test]
    fn private_key_loader_restricts_keys_to_approved_roots() {
        let temp = TempDir::new().unwrap();
        let approved = temp.path().join("approved");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&approved).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let approved_key = approved.join("id_ed25519");
        let outside_key = outside.join("id_ed25519");
        write_test_private_key(&approved_key);
        write_test_private_key(&outside_key);

        assert!(load_test_private_key(&approved_key, std::slice::from_ref(&approved)).is_ok());
        assert!(
            load_test_private_key(&outside_key, std::slice::from_ref(&approved))
                .unwrap_err()
                .contains("outside permitted key roots")
        );
    }

    #[test]
    fn configured_key_roots_include_defaults_and_platform_separated_opt_ins() {
        let temp = TempDir::new().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let additional = std::env::join_paths([&first, &second]).unwrap();
        let roots = configured_private_key_roots_from(temp.path(), Some(&additional));

        assert_eq!(roots[0], temp.path().join(".ssh"));
        assert_eq!(roots[1], temp.path().join(".automatestig/ssh_keys"));
        assert!(roots.contains(&first));
        assert!(roots.contains(&second));
    }

    #[cfg(unix)]
    #[test]
    fn private_key_loader_rejects_insecure_configured_root() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("insecure-root");
        let key_dir = root.join("user");
        std::fs::create_dir_all(&key_dir).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = key_dir.join("id_ed25519");
        write_test_private_key(&key);

        assert!(load_test_private_key(&key, &[root])
            .unwrap_err()
            .contains("writable by group or other users"));
    }

    #[test]
    fn scan_target_rejects_unsafe_and_mixed_resolution_results() {
        let address = |value: &str| value.parse::<IpAddr>().unwrap();
        for unsafe_address in [
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "169.254.10.20",
            "fe80::1",
        ] {
            assert!(select_resolved_target(
                "device.example.test",
                22,
                vec![SocketAddr::new(address(unsafe_address), 22)],
                false,
            )
            .is_err());
        }

        let mixed = select_resolved_target(
            "device.example.test",
            22,
            vec![
                SocketAddr::new(address("192.168.1.10"), 22),
                SocketAddr::new(address("203.0.113.10"), 22),
            ],
            false,
        )
        .unwrap_err();
        assert!(mixed.contains("resolves across trust classes"));

        assert_eq!(
            select_resolved_target(
                "device.example.test",
                22,
                vec![SocketAddr::new(address("169.254.10.20"), 22)],
                true,
            )
            .unwrap()
            .ip(),
            address("169.254.10.20")
        );
    }

    #[test]
    fn scan_target_accepts_lan_and_dual_stack_within_one_trust_class() {
        let lan = vec![
            "192.168.1.10:22".parse().unwrap(),
            "[fd00::10]:22".parse().unwrap(),
        ];
        assert_eq!(
            select_resolved_target("device.lan", 22, lan.clone(), false).unwrap(),
            lan[0]
        );

        let public = vec![
            "203.0.113.10:22".parse().unwrap(),
            "[2001:db8::10]:22".parse().unwrap(),
        ];
        assert_eq!(
            select_resolved_target("device.example.test", 22, public.clone(), false).unwrap(),
            public[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_loader_rejects_file_and_parent_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = TempDir::new().unwrap();
        let roots = vec![temp.path().to_path_buf()];
        let real_dir = temp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::set_permissions(&real_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let real_key = real_dir.join("id_ed25519");
        write_test_private_key(&real_key);

        let file_link = temp.path().join("file-link");
        symlink(&real_key, &file_link).unwrap();
        assert!(load_test_private_key(&file_link, &roots)
            .unwrap_err()
            .contains("symbolic link"));

        let parent_link = temp.path().join("parent-link");
        symlink(&real_dir, &parent_link).unwrap();
        assert!(
            load_test_private_key(&parent_link.join("id_ed25519"), &roots)
                .unwrap_err()
                .contains("symbolic link")
        );

        assert!(
            load_test_private_key(Path::new("/dev/null"), &[PathBuf::from("/dev")])
                .unwrap_err()
                .contains("not a regular file")
        );
    }

    #[test]
    fn concurrent_tofu_enrollment_accepts_exactly_one_different_key() {
        let temp = TempDir::new().unwrap();
        let known_hosts = temp.path().join("trust/known_hosts");
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for key in ["SHA256:first", "SHA256:second"] {
            let known_hosts = known_hosts.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                (
                    key,
                    verify_or_enroll_host_key(&known_hosts, "device.example.test", 22, key, true)
                        .unwrap(),
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();

        assert_eq!(
            results
                .iter()
                .filter(|(_, result)| *result == HostKeyDecision::Trusted)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, result)| *result == HostKeyDecision::Changed)
                .count(),
            1
        );
        let content = std::fs::read_to_string(&known_hosts).unwrap();
        assert_eq!(content.lines().count(), 1);
        let enrolled = results
            .iter()
            .find(|(_, decision)| *decision == HostKeyDecision::Trusted)
            .unwrap()
            .0;
        assert!(content.contains(enrolled));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(known_hosts.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(&known_hosts)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    fn trust_store_lock_wait_is_bounded() {
        let temp = TempDir::new().unwrap();
        let trust_dir = temp.path().join("trust");
        ensure_secure_trust_directory(&trust_dir).unwrap();
        let lock_path = trust_dir.join("known_hosts.lock");
        let held_lock = open_secure_trust_file(&lock_path, true, "SSH trust lock")
            .unwrap()
            .unwrap();
        File::lock(&held_lock).unwrap();

        let started = Instant::now();
        let error = verify_or_enroll_host_key(
            &trust_dir.join("known_hosts"),
            "device.example.test",
            22,
            "SHA256:test",
            true,
        )
        .unwrap_err();
        File::unlock(&held_lock).unwrap();

        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(error.contains("timed out waiting for SSH trust-store lock"));
    }

    #[cfg(unix)]
    #[test]
    fn trust_store_rejects_symlinks_and_group_writable_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = TempDir::new().unwrap();
        let trust = temp.path().join("trust");
        std::fs::create_dir(&trust).unwrap();
        std::fs::set_permissions(&trust, std::fs::Permissions::from_mode(0o700)).unwrap();
        let external = temp.path().join("external");
        std::fs::write(&external, b"sentinel\n").unwrap();
        let known_hosts = trust.join("known_hosts");
        symlink(&external, &known_hosts).unwrap();
        assert!(verify_or_enroll_host_key(
            &known_hosts,
            "device.example.test",
            22,
            "SHA256:test",
            true,
        )
        .is_err());
        assert_eq!(std::fs::read(&external).unwrap(), b"sentinel\n");

        std::fs::remove_file(&known_hosts).unwrap();
        std::fs::write(&known_hosts, b"device.example.test:22 SHA256:test\n").unwrap();
        std::fs::set_permissions(&known_hosts, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(verify_or_enroll_host_key(
            &known_hosts,
            "device.example.test",
            22,
            "SHA256:test",
            false,
        )
        .is_err());

        let external_dir = temp.path().join("external-dir");
        std::fs::create_dir(&external_dir).unwrap();
        let trust_link = temp.path().join("trust-link");
        symlink(&external_dir, &trust_link).unwrap();
        assert!(verify_or_enroll_host_key(
            &trust_link.join("known_hosts"),
            "device.example.test",
            22,
            "SHA256:test",
            true,
        )
        .is_err());
        assert!(!external_dir.join("known_hosts").exists());
    }

    #[tokio::test]
    async fn connection_and_ssh_banner_are_bounded_by_phase_timeout() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let started = Instant::now();
        let report = collect_plan(&password_config(port), &probe_plan()).await;
        server.abort();
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(report.commands[0].status, CommandStatus::TransportError);
        assert!(report.commands[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("handshake timed out")));
    }

    #[derive(Clone)]
    struct SlowAuthenticationServer;

    impl server::Handler for SlowAuthenticationServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<Auth, Self::Error> {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(Auth::Accept)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authentication_is_bounded_by_phase_timeout() {
        let _environment = ENVIRONMENT_LOCK.lock().await;
        let _restore_environment = EnvironmentRestore::capture();
        let home = TempDir::new().unwrap();
        std::env::set_var("HOME", home.path());
        std::env::remove_var("AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE");

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let fingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let mut server_config = server::Config {
            inactivity_timeout: Some(Duration::from_secs(20)),
            ..Default::default()
        };
        server_config.keys.push(host_key);
        let server_config = Arc::new(server_config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = server::run_stream(server_config, stream, SlowAuthenticationServer).await;
        });
        let known_hosts = home.path().join(".automatestig/known_hosts");
        assert_eq!(
            verify_or_enroll_host_key(&known_hosts, "127.0.0.1", port, &fingerprint, true,)
                .unwrap(),
            HostKeyDecision::Trusted
        );

        let started = Instant::now();
        let report = collect_plan(&password_config(port), &probe_plan()).await;
        server.abort();

        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(report.commands[0].status, CommandStatus::TransportError);
        assert!(report.commands[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("authentication timed out")));
    }
}
