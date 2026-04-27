//! Windows registry check helpers.
//!
//! Provides utilities for parsing Windows registry data collected via
//! PowerShell's Get-ItemProperty or reg.exe query output.

use std::collections::HashMap;

/// Parse `reg query` output into a HashMap of path\name -> value.
pub fn parse_reg_query_output(output: &str) -> HashMap<String, serde_json::Value> {
    let mut results = HashMap::new();
    let mut current_key = String::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // Key header line (e.g., "HKEY_LOCAL_MACHINE\SOFTWARE\...")
        if trimmed.starts_with("HKEY_") || trimmed.starts_with("HKLM\\") {
            current_key = trimmed.to_string();
            continue;
        }

        // Value line: "    ValueName    REG_TYPE    Data"
        if !current_key.is_empty() && trimmed.contains("REG_") {
            let parts: Vec<&str> = trimmed.splitn(3, "    ").collect();
            if parts.len() >= 3 {
                let name = parts[0].trim();
                let reg_type = parts[1].trim();
                let data = parts[2].trim();

                let key = format!("{}\\{}", current_key, name);
                let value = parse_reg_value(reg_type, data);
                results.insert(key, value);
            }
        }
    }

    results
}

fn parse_reg_value(reg_type: &str, data: &str) -> serde_json::Value {
    match reg_type {
        "REG_DWORD" => {
            if let Some(hex) = data.strip_prefix("0x") {
                u32::from_str_radix(hex, 16)
                    .map(|v| serde_json::json!(v))
                    .unwrap_or(serde_json::json!(data))
            } else {
                data.parse::<u32>()
                    .map(|v| serde_json::json!(v))
                    .unwrap_or(serde_json::json!(data))
            }
        }
        "REG_SZ" | "REG_EXPAND_SZ" => serde_json::json!(data),
        "REG_MULTI_SZ" => {
            let parts: Vec<&str> = data.split("\\0").collect();
            serde_json::json!(parts)
        }
        "REG_QWORD" => data
            .parse::<u64>()
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::json!(data)),
        _ => serde_json::json!(data),
    }
}

/// Parse Windows security policy (secedit) INI-style output.
pub fn parse_security_policy(content: &str) -> HashMap<String, String> {
    let mut results = HashMap::new();
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].to_string();
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let full_key = format!("{}\\{}", current_section, key.trim());
            results.insert(full_key, value.trim().to_string());
            results.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    results
}

/// Parse Windows audit policy (auditpol /get /category:*) output.
pub fn parse_audit_policy(content: &str) -> HashMap<String, String> {
    let mut results = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        // Format: "  Subcategory                  Setting"
        if trimmed.contains("Success")
            || trimmed.contains("Failure")
            || trimmed.contains("No Auditing")
        {
            let parts: Vec<&str> = trimmed.rsplitn(2, "  ").collect();
            if parts.len() == 2 {
                let setting = parts[0].trim().to_string();
                let subcategory = parts[1].trim().to_string();
                results.insert(subcategory, setting);
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_security_policy() {
        let input = r#"[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1

[Event Audit]
AuditLogonEvents = 3
"#;
        let result = parse_security_policy(input);
        assert_eq!(
            result.get("System Access\\MinimumPasswordLength"),
            Some(&"14".to_string())
        );
        assert_eq!(result.get("MinimumPasswordLength"), Some(&"14".to_string()));
    }

    #[test]
    fn test_parse_reg_value_dword() {
        let val = parse_reg_value("REG_DWORD", "0x1");
        assert_eq!(val, serde_json::json!(1));
    }
}
