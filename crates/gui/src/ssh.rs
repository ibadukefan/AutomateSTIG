//! SSH transport for remote data collection.
//!
//! Connects to remote Linux/Unix hosts and network devices via SSH,
//! executes collection commands, and returns the raw output for parsing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::client;
use russh_keys::key;
use serde::{Deserialize, Serialize};
/// SSH connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub timeout_secs: u64,
}

/// SSH authentication method.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshAuth {
    Password { password: String },
    KeyFile { path: String, passphrase: Option<String> },
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

/// Execute a list of commands on a remote host via SSH.
/// Returns a map of command -> output.
pub async fn execute_commands(
    config: &SshConfig,
    commands: &[(&str, &str)], // (label, command)
) -> Result<HashMap<String, String>, String> {
    let russh_config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(config.timeout_secs)),
        ..Default::default()
    });

    let handler = SshHandler;
    let mut session = client::connect(
        russh_config,
        (config.host.as_str(), config.port),
        handler,
    )
    .await
    .map_err(|e| format!("SSH connection failed to {}:{}: {}", config.host, config.port, e))?;

    // Authenticate.
    let auth_result = match &config.auth {
        SshAuth::Password { password } => session
            .authenticate_password(&config.username, password)
            .await
            .map_err(|e| format!("SSH auth failed: {}", e))?,
        SshAuth::KeyFile { path, passphrase } => {
            let key_pair = russh_keys::load_secret_key(path, passphrase.as_deref())
                .map_err(|e| format!("Failed to load SSH key {}: {}", path, e))?;
            session
                .authenticate_publickey(&config.username, Arc::new(key_pair))
                .await
                .map_err(|e| format!("SSH key auth failed: {}", e))?
        }
    };

    if !auth_result {
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

    // Read channel output.
    loop {
        let msg = channel.wait().await;
        match msg {
            Some(russh::ChannelMsg::Data { data }) => {
                stdout.push_str(&String::from_utf8_lossy(&data));
            }
            Some(russh::ChannelMsg::ExtendedData { data, ext }) => {
                if ext == 1 {
                    // stderr
                    stderr.push_str(&String::from_utf8_lossy(&data));
                }
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
pub async fn collect_linux_data(
    config: &SshConfig,
) -> Result<HashMap<String, String>, String> {
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

/// Collect running config from a network device.
pub async fn collect_network_config(
    config: &SshConfig,
) -> Result<HashMap<String, String>, String> {
    let commands: Vec<(&str, &str)> = vec![
        ("running_config", "show running-config"),
        ("show_version", "show version"),
    ];

    execute_commands(config, &commands).await
}

/// SSH client handler (minimal implementation).
struct SshHandler;

#[async_trait]
impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all server keys.
        // TODO: Implement known_hosts checking for production.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
