//! SSH transport for remote data collection.
//!
//! Connects to remote Linux/Unix hosts and network devices via SSH,
//! executes collection commands, and returns the raw output for parsing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
use serde::{Deserialize, Serialize};
/// SSH connection configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub timeout_secs: u64,
}

/// SSH authentication method.
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

/// Result of a remote command execution.
#[derive(Debug, Clone, Serialize)]
pub struct CommandResult {
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<u32>,
    pub success: bool,
}

fn ssh_allowlist_entries() -> Vec<String> {
    crate::outbound::allowlist_entries("AUTOMATESTIG_SSH_TARGET_ALLOWLIST")
}

fn host_matches_allowlist(host: &str, entries: &[String]) -> bool {
    crate::outbound::host_or_ip_matches_allowlist(host, None, entries)
}

/// Validate a remote SSH scan destination before opening an outbound connection.
///
/// If AUTOMATESTIG_SSH_TARGET_ALLOWLIST is set, every scan host must match an
/// exact hostname/IP entry or an IP CIDR entry. Private, loopback, link-local,
/// multicast, documentation, and cloud metadata literal IPs are blocked by
/// default unless they are explicitly allowlisted or the lab override
/// AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN=1 is set.
pub(crate) fn validate_scan_target(host: &str) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("SSH scan host must not be empty".to_string());
    }
    if host.contains('/') || host.contains('\\') || host.contains('\0') {
        return Err("SSH scan host contains unsafe characters".to_string());
    }

    let allowlist = ssh_allowlist_entries();
    let allowlisted = !allowlist.is_empty() && host_matches_allowlist(host, &allowlist);
    if !allowlist.is_empty() && !allowlisted {
        return Err("SSH scan host is not in AUTOMATESTIG_SSH_TARGET_ALLOWLIST".to_string());
    }

    let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
    if matches!(host_lc.as_str(), "localhost" | "metadata.google.internal")
        || host_lc.ends_with(".localhost")
        || host_lc.ends_with(".metadata.google.internal")
    {
        return Err("SSH scan host is local/metadata and is not allowed".to_string());
    }

    if let Ok(ip) = host_lc.parse::<std::net::IpAddr>() {
        if crate::outbound::is_private_or_local_ip(ip)
            && !allowlisted
            && !crate::outbound::env_flag("AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN")
        {
            return Err("SSH scan to private/local/link-local literal IP requires explicit allowlist or AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN=1".to_string());
        }
    }

    Ok(())
}

/// Execute a list of commands on a remote host via SSH.
/// Returns a map of command -> output.
pub async fn execute_commands(
    config: &SshConfig,
    commands: &[(&str, &str)], // (label, command)
) -> Result<HashMap<String, String>, String> {
    validate_scan_target(&config.host)?;
    crate::outbound::validate_resolved_destination(
        "SSH scan target",
        &config.host,
        config.port,
        "AUTOMATESTIG_SSH_TARGET_ALLOWLIST",
        "AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN",
        None,
    )
    .await?;

    let russh_config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(config.timeout_secs)),
        ..Default::default()
    });

    let handler = SshHandler::new(&config.host, config.port);
    let mut session = client::connect(russh_config, (config.host.as_str(), config.port), handler)
        .await
        .map_err(|e| {
            format!(
                "SSH connection failed to {}:{}: {}",
                config.host, config.port, e
            )
        })?;

    // Authenticate.
    let auth_result = match &config.auth {
        SshAuth::Password { password } => session
            .authenticate_password(&config.username, password)
            .await
            .map_err(|e| format!("SSH auth failed: {}", e))?,
        SshAuth::KeyFile { path, passphrase } => {
            let key_pair = russh::keys::load_secret_key(path, passphrase.as_deref())
                .map_err(|e| format!("Failed to load SSH key {}: {}", path, e))?;
            session
                .authenticate_publickey(
                    &config.username,
                    PrivateKeyWithHashAlg::new(Arc::new(key_pair), Some(HashAlg::Sha256)),
                )
                .await
                .map_err(|e| format!("SSH key auth failed: {}", e))?
        }
    };

    if !auth_result.success() {
        return Err(format!(
            "SSH authentication failed for {}@{}",
            config.username, config.host
        ));
    }

    // Execute each command and collect output.
    let mut results = HashMap::new();

    for (label, command) in commands {
        match execute_single_command(&mut session, command).await {
            Ok(output) => {
                results.insert(label.to_string(), output.stdout);
            }
            Err(e) => {
                tracing::warn!("Command '{}' failed on {}: {}", label, config.host, e);
                results.insert(label.to_string(), String::new());
            }
        }
    }

    Ok(results)
}

/// Execute a single command on an SSH session.
async fn execute_single_command(
    session: &mut client::Handle<SshHandler>,
    command: &str,
) -> Result<CommandResult, String> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("Channel open failed: {}", e))?;

    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("Exec failed: {}", e))?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = None;
    const MAX_OUTPUT: usize = 50 * 1024 * 1024; // 50 MB cap

    // Read channel output.
    loop {
        let msg = channel.wait().await;
        match msg {
            Some(russh::ChannelMsg::Data { data }) if stdout.len() < MAX_OUTPUT => {
                stdout.push_str(&String::from_utf8_lossy(&data));
            }
            Some(russh::ChannelMsg::ExtendedData { data, ext })
                if ext == 1 && stderr.len() < MAX_OUTPUT =>
            {
                stderr.push_str(&String::from_utf8_lossy(&data));
            }
            Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = Some(exit_status);
            }
            Some(russh::ChannelMsg::Eof) | None => break,
            _ => {}
        }
    }

    Ok(CommandResult {
        command: command.to_string(),
        stdout,
        stderr,
        exit_code,
        success: exit_code == Some(0),
    })
}

/// Collect system data from a remote Linux host.
pub async fn collect_linux_data(config: &SshConfig) -> Result<HashMap<String, String>, String> {
    let commands: Vec<(&str, &str)> = vec![
        ("sysctl_raw", "sysctl -a 2>/dev/null"),
        ("file:/etc/ssh/sshd_config", "cat /etc/ssh/sshd_config 2>/dev/null"),
        ("file:/etc/login.defs", "cat /etc/login.defs 2>/dev/null"),
        ("file:/etc/pam.d/system-auth", "cat /etc/pam.d/system-auth 2>/dev/null || cat /etc/pam.d/common-auth 2>/dev/null"),
        ("file_permissions_raw", "stat -c '%a %U %G %n' /etc/shadow /etc/passwd /etc/group /etc/gshadow /etc/ssh/sshd_config 2>/dev/null"),
        ("services_raw", "systemctl list-units --type=service --all --no-pager 2>/dev/null"),
        ("packages_raw", "rpm -qa --queryformat '%{NAME}\\n' 2>/dev/null || dpkg-query -W -f '${Package}\\n' 2>/dev/null"),
        ("os_release", "cat /etc/os-release 2>/dev/null"),
        ("hostname", "hostname"),
    ];

    execute_commands(config, &commands).await
}

/// SSH client handler (minimal implementation).
/// SSH client handler with known_hosts checking.
struct SshHandler {
    host: String,
    port: u16,
    /// If true, accept any server key (first-connect mode).
    accept_unknown: bool,
}

impl SshHandler {
    fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            accept_unknown: std::env::var("AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE")
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false),
        }
    }
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // Log the server's public key fingerprint for auditing.
        let fingerprint = format!("{:?}", server_public_key);
        tracing::info!(
            "SSH server key: {}",
            &fingerprint[..fingerprint.len().min(80)]
        );
        let key_id = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        let entry = format!("{}:{} {}", self.host, self.port, key_id);
        let host_prefix = format!("{}:{} ", self.host, self.port);

        // Check known_hosts file if it exists.
        let known_hosts_path = dirs_or_home().join(".automatestig").join("known_hosts");
        if known_hosts_path.exists() {
            match std::fs::read_to_string(&known_hosts_path) {
                Ok(content) => {
                    for line in content.lines().map(str::trim) {
                        if line == entry {
                            return Ok(true); // Key is in known_hosts.
                        }
                        if line.starts_with(&host_prefix) {
                            tracing::error!(
                                "SSH server key changed for {}:{}; rejecting possible MITM",
                                self.host,
                                self.port
                            );
                            return Ok(false);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read SSH known_hosts: {}", e);
                    return Ok(false);
                }
            }
        }

        // First connection or accept_unknown mode: save the key and accept.
        if self.accept_unknown {
            let _ = std::fs::create_dir_all(
                known_hosts_path
                    .parent()
                    .unwrap_or(std::path::Path::new(".")),
            );
            let key_str = format!("{}\n", entry);
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&known_hosts_path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, key_str.as_bytes()));
            tracing::info!(
                "SSH server key for {}:{} saved to known_hosts (explicit trust-on-first-use override)",
                self.host,
                self.port
            );
            Ok(true)
        } else {
            tracing::warn!("SSH server key is not trusted; set AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE=1 only for explicit enrollment");
            Ok(false)
        }
    }
}

fn dirs_or_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_scan_target_rejects_private_and_local_literals() {
        for host in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.1.10",
            "192.168.1.10",
            "169.254.169.254",
            "::1",
            "fc00::1",
            "localhost",
            "metadata.google.internal",
        ] {
            assert!(
                validate_scan_target(host).is_err(),
                "{host} should be rejected by default"
            );
        }
    }

    #[test]
    fn validate_scan_target_accepts_public_hosts() {
        validate_scan_target("server01.example.mil").unwrap();
        validate_scan_target("203.0.113.10").unwrap_err(); // documentation range is intentionally blocked
        validate_scan_target("8.8.8.8").unwrap();
    }

    #[test]
    fn allowlist_matches_exact_hosts_and_cidrs() {
        let entries = vec![
            "server01.example.mil".to_string(),
            "10.5.0.0/16".to_string(),
        ];
        assert!(host_matches_allowlist("server01.example.mil", &entries));
        assert!(host_matches_allowlist("10.5.2.3", &entries));
        assert!(!host_matches_allowlist("server02.example.mil", &entries));
        assert!(!host_matches_allowlist("10.6.2.3", &entries));
    }

    #[test]
    fn test_ssh_config_serialization() {
        let config = SshConfig {
            host: "10.0.1.50".to_string(),
            port: 22,
            username: "admin".to_string(),
            auth: SshAuth::Password {
                password: "secret".to_string(),
            },
            timeout_secs: 30,
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: SshConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, "10.0.1.50");
        assert_eq!(parsed.port, 22);
    }

    #[test]
    fn test_ssh_key_auth_config() {
        let config = SshConfig {
            host: "server01".to_string(),
            port: 22,
            username: "root".to_string(),
            auth: SshAuth::KeyFile {
                path: "/home/user/.ssh/id_ed25519".to_string(),
                passphrase: None,
            },
            timeout_secs: 30,
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("key_file"));
    }

    #[test]
    fn test_known_hosts_entry_is_host_scoped() {
        let key_id = "AAAAC3NzaC1lZDI1NTE5AAAAIKnownKey";
        let host_a = "server01.example.test";
        let host_b = "server02.example.test";
        let port = 22;

        let entry_a = format!("{}:{} {}", host_a, port, key_id);
        let entry_b = format!("{}:{} {}", host_b, port, key_id);
        let host_prefix_a = format!("{}:{} ", host_a, port);
        let host_prefix_b = format!("{}:{} ", host_b, port);

        assert_ne!(entry_a, entry_b);
        assert_ne!(host_prefix_a, host_prefix_b);
        assert!(entry_a.starts_with(&host_prefix_a));
        assert!(entry_b.starts_with(&host_prefix_b));
        assert!(!entry_a.starts_with(&host_prefix_b));
        assert!(!entry_b.starts_with(&host_prefix_a));
    }
}
