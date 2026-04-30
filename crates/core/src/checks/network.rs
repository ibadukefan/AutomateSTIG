//! Network device check helpers.
//!
//! Parses Cisco IOS/NX-OS/ASA running configs for STIG compliance.

use std::collections::HashMap;

/// Extract specific configuration values from a Cisco IOS running config.
pub fn extract_ios_settings(config: &str) -> HashMap<String, String> {
    let mut settings = HashMap::new();

    for line in config.lines() {
        let trimmed = line.trim();

        // SSH settings.
        if trimmed.starts_with("ip ssh version") {
            settings.insert(
                "ip_ssh_version".to_string(),
                trimmed.replace("ip ssh version ", ""),
            );
        }
        if trimmed.starts_with("ip ssh time-out") {
            settings.insert(
                "ip_ssh_timeout".to_string(),
                trimmed.replace("ip ssh time-out ", ""),
            );
        }

        // Services.
        if trimmed == "service password-encryption" {
            settings.insert(
                "service_password_encryption".to_string(),
                "enabled".to_string(),
            );
        }
        if trimmed == "service timestamps log datetime msec" {
            settings.insert(
                "service_timestamps_log".to_string(),
                "datetime msec".to_string(),
            );
        }

        // AAA.
        if trimmed.starts_with("aaa new-model") {
            settings.insert("aaa_new_model".to_string(), "enabled".to_string());
        }

        // Hostname.
        if trimmed.starts_with("hostname ") {
            settings.insert("hostname".to_string(), trimmed.replace("hostname ", ""));
        }

        // Banner.
        if trimmed.starts_with("banner login") || trimmed.starts_with("banner motd") {
            settings.insert("banner_configured".to_string(), "true".to_string());
        }

        // NTP.
        if trimmed.starts_with("ntp server") {
            let count = settings
                .get("ntp_server_count")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            settings.insert("ntp_server_count".to_string(), (count + 1).to_string());
        }
    }

    settings
}

/// Check if a specific configuration line exists in the running config.
pub fn config_line_exists(config: &str, pattern: &str) -> bool {
    config.lines().any(|line| line.trim().contains(pattern))
}

/// Check if a line exists within a specific interface/context block.
pub fn config_line_in_context(config: &str, context: &str, pattern: &str) -> bool {
    let mut in_context = false;

    for line in config.lines() {
        let trimmed = line.trim();

        if trimmed == context || trimmed.starts_with(&format!("{} ", context)) {
            in_context = true;
            continue;
        }

        if in_context {
            if !line.starts_with(' ')
                && !line.starts_with('\t')
                && !trimmed.is_empty()
                && trimmed != "!"
            {
                in_context = false;
            } else if trimmed.contains(pattern) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"hostname CORE-RTR-01
!
service password-encryption
service timestamps log datetime msec
!
aaa new-model
!
ip ssh version 2
ip ssh time-out 60
!
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 shutdown
!
ntp server 10.0.0.100
ntp server 10.0.0.101
!
banner login ^
Authorized users only.
^
!
"#;

    #[test]
    fn test_extract_settings() {
        let settings = extract_ios_settings(SAMPLE_CONFIG);
        assert_eq!(settings.get("ip_ssh_version"), Some(&"2".to_string()));
        assert_eq!(settings.get("hostname"), Some(&"CORE-RTR-01".to_string()));
        assert_eq!(
            settings.get("service_password_encryption"),
            Some(&"enabled".to_string())
        );
        assert_eq!(settings.get("aaa_new_model"), Some(&"enabled".to_string()));
        assert_eq!(settings.get("ntp_server_count"), Some(&"2".to_string()));
        assert_eq!(settings.get("banner_configured"), Some(&"true".to_string()));
    }

    #[test]
    fn test_config_line_exists() {
        assert!(config_line_exists(SAMPLE_CONFIG, "ip ssh version 2"));
        assert!(!config_line_exists(SAMPLE_CONFIG, "ip ssh version 1"));
    }

    #[test]
    fn test_config_line_in_context() {
        assert!(config_line_in_context(
            SAMPLE_CONFIG,
            "interface GigabitEthernet0/0",
            "no shutdown"
        ));
        assert!(!config_line_in_context(
            SAMPLE_CONFIG,
            "interface GigabitEthernet0/1",
            "no shutdown"
        ));
    }
}
