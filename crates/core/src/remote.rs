//! Remote data collection framework.
//!
//! Defines the interface for collecting system data from remote hosts
//! via pluggable transport implementations. This module defines the
//! collection protocol and data gathering commands.

use std::collections::HashMap;

use crate::checks::{CheckPlatform, FilePermData, SystemData};

/// Commands to collect system data, organized by platform.
pub struct CollectionPlan {
    /// Commands to execute, in order.
    pub commands: Vec<CollectionCommand>,
}

/// A single data collection command.
pub struct CollectionCommand {
    /// Human-readable description.
    pub description: String,

    /// The command to execute.
    pub command: String,

    /// How to parse the output.
    pub parser: OutputParser,

    /// Data key to store the result under.
    pub data_key: String,
}

/// How to parse command output.
pub enum OutputParser {
    /// Store raw output as-is (for file contents, configs).
    Raw,
    /// Parse as key=value pairs (sysctl, secedit).
    KeyValue,
    /// Parse as JSON.
    Json,
    /// Custom parser function name.
    Custom(String),
}

/// Generate a collection plan for a given platform.
pub fn generate_collection_plan(platform: CheckPlatform) -> CollectionPlan {
    match platform {
        CheckPlatform::Windows => windows_collection_plan(),
        CheckPlatform::Linux => linux_collection_plan(),
        CheckPlatform::CiscoIos | CheckPlatform::CiscoNxos | CheckPlatform::CiscoAsa => {
            network_collection_plan()
        }
        CheckPlatform::Ontap => ontap_collection_plan(),
        CheckPlatform::Bsd => bsd_collection_plan(),
        CheckPlatform::Generic => CollectionPlan {
            commands: Vec::new(),
        },
    }
}

fn windows_collection_plan() -> CollectionPlan {
    CollectionPlan {
        commands: vec![
            CollectionCommand {
                description: "Export security policy".to_string(),
                command: "secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg /quiet && type C:\\Windows\\Temp\\secpol.cfg".to_string(),
                parser: OutputParser::Raw,
                data_key: "security_policy_raw".to_string(),
            },
            CollectionCommand {
                description: "Export audit policy".to_string(),
                command: "auditpol /get /category:* /r".to_string(),
                parser: OutputParser::Raw,
                data_key: "audit_policy_raw".to_string(),
            },
            CollectionCommand {
                description: "List services".to_string(),
                command: "Get-Service | Select-Object Name,Status,StartType | ConvertTo-Json".to_string(),
                parser: OutputParser::Json,
                data_key: "services_raw".to_string(),
            },
            CollectionCommand {
                description: "List installed features".to_string(),
                command: "Get-WindowsFeature | Where-Object {$_.Installed} | Select-Object Name | ConvertTo-Json".to_string(),
                parser: OutputParser::Json,
                data_key: "features_raw".to_string(),
            },
            CollectionCommand {
                description: "Collect registry - SCHANNEL protocols".to_string(),
                command: "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\" /s".to_string(),
                parser: OutputParser::Raw,
                data_key: "registry_schannel".to_string(),
            },
            CollectionCommand {
                description: "Collect registry - LSA settings".to_string(),
                command: "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /s".to_string(),
                parser: OutputParser::Raw,
                data_key: "registry_lsa".to_string(),
            },
            CollectionCommand {
                description: "Collect registry - Windows policies".to_string(),
                command: "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\" /s".to_string(),
                parser: OutputParser::Raw,
                data_key: "registry_policies".to_string(),
            },
            CollectionCommand {
                description: "System info".to_string(),
                command: "systeminfo".to_string(),
                parser: OutputParser::Raw,
                data_key: "systeminfo".to_string(),
            },
        ],
    }
}

fn linux_collection_plan() -> CollectionPlan {
    CollectionPlan {
        commands: vec![
            CollectionCommand {
                description: "Collect sysctl values".to_string(),
                command: "sysctl -a 2>/dev/null".to_string(),
                parser: OutputParser::KeyValue,
                data_key: "sysctl_raw".to_string(),
            },
            CollectionCommand {
                description: "SSH daemon configuration".to_string(),
                command: "cat /etc/ssh/sshd_config 2>/dev/null".to_string(),
                parser: OutputParser::Raw,
                data_key: "file:/etc/ssh/sshd_config".to_string(),
            },
            CollectionCommand {
                description: "PAM configuration".to_string(),
                command: "cat /etc/pam.d/system-auth 2>/dev/null || cat /etc/pam.d/common-auth 2>/dev/null".to_string(),
                parser: OutputParser::Raw,
                data_key: "file:/etc/pam.d/system-auth".to_string(),
            },
            CollectionCommand {
                description: "Login defs".to_string(),
                command: "cat /etc/login.defs 2>/dev/null".to_string(),
                parser: OutputParser::Raw,
                data_key: "file:/etc/login.defs".to_string(),
            },
            CollectionCommand {
                description: "File permissions - critical files".to_string(),
                command: "stat -c '%a %U %G %n' /etc/shadow /etc/passwd /etc/group /etc/gshadow /etc/ssh/sshd_config 2>/dev/null".to_string(),
                parser: OutputParser::Raw,
                data_key: "file_permissions_raw".to_string(),
            },
            CollectionCommand {
                description: "Service statuses".to_string(),
                command: "systemctl list-units --type=service --all --no-pager 2>/dev/null".to_string(),
                parser: OutputParser::Raw,
                data_key: "services_raw".to_string(),
            },
            CollectionCommand {
                description: "Installed packages (RPM)".to_string(),
                command: "rpm -qa --queryformat '%{NAME}\\n' 2>/dev/null || dpkg-query -W -f '${Package}\\n' 2>/dev/null".to_string(),
                parser: OutputParser::Raw,
                data_key: "packages_raw".to_string(),
            },
            CollectionCommand {
                description: "Firewall rules".to_string(),
                command: "iptables -L -n 2>/dev/null || firewall-cmd --list-all 2>/dev/null".to_string(),
                parser: OutputParser::Raw,
                data_key: "firewall_raw".to_string(),
            },
            CollectionCommand {
                description: "OS release info".to_string(),
                command: "cat /etc/os-release 2>/dev/null".to_string(),
                parser: OutputParser::Raw,
                data_key: "os_release".to_string(),
            },
        ],
    }
}

fn network_collection_plan() -> CollectionPlan {
    CollectionPlan {
        commands: vec![
            CollectionCommand {
                description: "Running configuration".to_string(),
                command: "show running-config".to_string(),
                parser: OutputParser::Raw,
                data_key: "running_config".to_string(),
            },
            CollectionCommand {
                description: "Version information".to_string(),
                command: "show version".to_string(),
                parser: OutputParser::Raw,
                data_key: "show_version".to_string(),
            },
            CollectionCommand {
                description: "NTP status".to_string(),
                command: "show ntp status".to_string(),
                parser: OutputParser::Raw,
                data_key: "ntp_status".to_string(),
            },
            CollectionCommand {
                description: "AAA configuration".to_string(),
                command: "show aaa".to_string(),
                parser: OutputParser::Raw,
                data_key: "aaa_config".to_string(),
            },
        ],
    }
}

fn ontap_collection_plan() -> CollectionPlan {
    let plain_commands = [
        "security session limit show -interface cli",
        "system timeout show",
        "cluster log-forwarding show",
        "security login show -role admin -authentication-method password",
        "security login role config show -role admin -instance",
        "security login banner show",
        "vserver audit show -fields audit-guarantee",
        "cluster time-service ntp server show",
        "cluster date show",
        "security login show -authentication-method domain",
        "security login show -role admin -authentication-method domain",
        "options -option-name snmp*",
        "security snmpusers -authmethod usm",
        "security login role config show -role admin -fields passwd-minlength",
        "security login role config show -role admin -fields passwd-min-uppercase-chars",
        "security login role config show -role admin -fields passwd-min-lowercase-chars",
        "security login role config show -role admin -fields passwd-alphanum",
        "security login role config show -role admin -fields passwd-min-special-chars",
    ];

    let privileged_commands = ["system configuration backup show", "security config show"];

    let mut commands: Vec<CollectionCommand> =
        plain_commands.into_iter().map(ontap_command).collect();
    commands.extend(
        privileged_commands
            .into_iter()
            .map(privileged_ontap_command),
    );

    CollectionPlan { commands }
}

fn ontap_command(command: &str) -> CollectionCommand {
    CollectionCommand {
        description: format!("ONTAP command: {}", command),
        command: command.to_string(),
        parser: OutputParser::Raw,
        data_key: command.to_string(),
    }
}

fn privileged_ontap_command(command: &str) -> CollectionCommand {
    CollectionCommand {
        description: format!("ONTAP privileged command: {}", command),
        command: format!("set -privilege advanced -confirmations off; {}", command),
        parser: OutputParser::Raw,
        data_key: command.to_string(),
    }
}

fn bsd_collection_plan() -> CollectionPlan {
    let commands = [
        "freebsd-version -k",
        "cat /etc/ssh/sshd_config",
        "cat /etc/motd.template /etc/motd",
        "cat /etc/login.conf",
        "cat /etc/pam.d/passwd",
        "cat /etc/security/audit_control",
        "service auditd onestatus",
        "cat /etc/ntp.conf",
        "cat /var/db/zoneinfo",
        "sysctl kern.elf64.aslr.enable",
        "cat /etc/rc.conf",
    ];

    CollectionPlan {
        commands: commands.into_iter().map(bsd_command).collect(),
    }
}

fn bsd_command(command: &str) -> CollectionCommand {
    CollectionCommand {
        description: format!("BSD command: {}", command),
        command: command.to_string(),
        parser: OutputParser::Raw,
        data_key: command.to_string(),
    }
}

/// Assemble a SystemData struct from raw collected outputs.
pub fn assemble_system_data(
    platform: CheckPlatform,
    hostname: &str,
    raw_outputs: &HashMap<String, String>,
) -> SystemData {
    let mut data = SystemData {
        platform: format!("{:?}", platform).to_lowercase(),
        hostname: hostname.to_string(),
        ..Default::default()
    };

    match platform {
        CheckPlatform::Linux => {
            // Parse sysctl.
            if let Some(raw) = raw_outputs.get("sysctl_raw") {
                data.sysctl = crate::checks::linux::parse_sysctl_output(raw);
            }

            // Parse services.
            if let Some(raw) = raw_outputs.get("services_raw") {
                data.services = crate::checks::linux::parse_systemctl_output(raw);
            }

            // Parse packages.
            if let Some(raw) = raw_outputs.get("packages_raw") {
                data.packages = crate::checks::linux::parse_dpkg_packages(raw);
                // Merge with RPM if dpkg gave nothing.
                if data.packages.is_empty() {
                    data.packages = crate::checks::linux::parse_rpm_packages(raw);
                }
            }

            // Store file contents.
            for (key, value) in raw_outputs {
                if let Some(path) = key.strip_prefix("file:") {
                    data.file_contents.insert(path.to_string(), value.clone());
                }
            }

            // Parse file permissions.
            if let Some(raw) = raw_outputs.get("file_permissions_raw") {
                for line in raw.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let path = parts[3].to_string();
                        data.file_permissions.insert(
                            path,
                            FilePermData {
                                mode: Some(format!("0{}", parts[0])),
                                owner: Some(parts[1].to_string()),
                                group: Some(parts[2].to_string()),
                                exists: true,
                            },
                        );
                    }
                }
            }
        }

        CheckPlatform::Windows => {
            // Parse security policy.
            if let Some(raw) = raw_outputs.get("security_policy_raw") {
                data.security_policy = crate::checks::registry::parse_security_policy(raw);
            }

            // Parse audit policy.
            if let Some(raw) = raw_outputs.get("audit_policy_raw") {
                data.audit_policy = crate::checks::registry::parse_audit_policy(raw);
            }

            // Parse registry data.
            for (key, value) in raw_outputs {
                if key.starts_with("registry_") {
                    let entries = crate::checks::registry::parse_reg_query_output(value);
                    data.registry.extend(entries);
                }
            }
        }

        CheckPlatform::CiscoIos | CheckPlatform::CiscoNxos | CheckPlatform::CiscoAsa => {
            data.network_config = raw_outputs.get("running_config").cloned();
        }

        CheckPlatform::Ontap | CheckPlatform::Bsd => {
            data.command_outputs = raw_outputs.clone();
        }

        CheckPlatform::Generic => {}
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collection_plan_linux() {
        let plan = generate_collection_plan(CheckPlatform::Linux);
        assert!(!plan.commands.is_empty());
        assert!(plan
            .commands
            .iter()
            .any(|c| c.description.contains("sysctl")));
    }

    #[test]
    fn test_collection_plan_windows() {
        let plan = generate_collection_plan(CheckPlatform::Windows);
        assert!(!plan.commands.is_empty());
        assert!(plan
            .commands
            .iter()
            .any(|c| c.description.contains("security policy")));
    }

    #[test]
    fn test_collection_plan_ontap_uses_plain_keys() {
        let plan = generate_collection_plan(CheckPlatform::Ontap);
        let plain = "system configuration backup show";
        let command = plan
            .commands
            .iter()
            .find(|c| c.data_key == plain)
            .expect("privileged command is present");

        assert_eq!(command.data_key, plain);
        assert_eq!(
            command.command,
            "set -privilege advanced -confirmations off; system configuration backup show"
        );
        assert!(plan.commands.iter().any(|c| {
            c.data_key == "security session limit show -interface cli"
                && c.command == "security session limit show -interface cli"
        }));
    }

    #[test]
    fn test_collection_plan_bsd_uses_plain_keys() {
        let plan = generate_collection_plan(CheckPlatform::Bsd);
        let command = "freebsd-version -k";
        let collected = plan
            .commands
            .iter()
            .find(|c| c.data_key == command)
            .expect("BSD command is present");

        assert_eq!(collected.data_key, command);
        assert_eq!(collected.command, command);
        assert!(plan.commands.iter().any(|c| {
            c.data_key == "sysctl kern.elf64.aslr.enable"
                && c.command == "sysctl kern.elf64.aslr.enable"
        }));
    }

    #[test]
    fn test_assemble_linux_data() {
        let mut outputs = HashMap::new();
        outputs.insert(
            "sysctl_raw".to_string(),
            "net.ipv4.ip_forward = 0\nkernel.randomize_va_space = 2\n".to_string(),
        );
        outputs.insert(
            "file:/etc/ssh/sshd_config".to_string(),
            "PermitRootLogin no\n".to_string(),
        );

        let data = assemble_system_data(CheckPlatform::Linux, "testhost", &outputs);
        assert_eq!(
            data.sysctl.get("net.ipv4.ip_forward"),
            Some(&"0".to_string())
        );
        assert!(data.file_contents.contains_key("/etc/ssh/sshd_config"));
    }
}
