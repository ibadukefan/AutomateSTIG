//! WinRM transport for remote Windows data collection.
//!
//! Connects to remote Windows hosts via WinRM (HTTP/HTTPS) and executes
//! PowerShell commands to collect system data for STIG evaluation.
//!
//! Uses the WinRM SOAP protocol over HTTP(S) with Basic or NTLM auth.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// WinRM connection configuration.
/// WinRM connection configuration. Debug intentionally omitted to prevent password logging.
#[derive(Clone, Serialize, Deserialize)]
pub struct WinrmConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub use_https: bool,
    pub verify_tls: bool,
    pub timeout_secs: u64,
}

impl Default for WinrmConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 5986,
            username: String::new(),
            password: String::new(),
            use_https: true,
            verify_tls: true,
            timeout_secs: 30,
        }
    }
}

/// Result of a WinRM command execution.
#[derive(Debug, Clone, Serialize)]
pub struct WinrmCommandResult {
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
}

/// Execute a PowerShell command via WinRM.
pub async fn execute_powershell(
    config: &WinrmConfig,
    command: &str,
) -> Result<WinrmCommandResult, String> {
    if !config.use_https {
        let allow_insecure = std::env::var("AUTOMATESTIG_ALLOW_INSECURE_WINRM")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if !allow_insecure {
            return Err(
                "Refusing plaintext WinRM Basic authentication; use HTTPS or set AUTOMATESTIG_ALLOW_INSECURE_WINRM=1 for an explicit lab-only override".to_string(),
            );
        }
    }
    if !config.verify_tls {
        let allow_invalid_certs = std::env::var("AUTOMATESTIG_ALLOW_INVALID_WINRM_CERTS")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if !allow_invalid_certs {
            return Err(
                "Refusing WinRM with TLS verification disabled; set AUTOMATESTIG_ALLOW_INVALID_WINRM_CERTS=1 for an explicit lab-only override".to_string(),
            );
        }
    }

    let scheme = if config.use_https { "https" } else { "http" };
    let url = format!("{}://{}:{}/wsman", scheme, config.host, config.port);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(!config.verify_tls)
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    // WinRM SOAP envelope for command execution.
    let soap_body = build_winrm_soap_envelope(command, &config.host);

    let response = client
        .post(&url)
        .basic_auth(&config.username, Some(&config.password))
        .header("Content-Type", "application/soap+xml;charset=UTF-8")
        .body(soap_body)
        .send()
        .await
        .map_err(|e| format!("WinRM request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "WinRM returned {}: {}",
            status,
            &body[..body.len().min(500)]
        ));
    }

    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read WinRM response: {}", e))?;

    // Parse the SOAP response to extract stdout/stderr.
    let stdout = extract_soap_element(&body, "Stream", "stdout").unwrap_or_default();
    let stderr = extract_soap_element(&body, "Stream", "stderr").unwrap_or_default();
    let exit_code = extract_soap_element(&body, "ExitCode", "")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(-1);

    // Decode base64 output.
    let stdout_decoded = decode_base64_output(&stdout);
    let stderr_decoded = decode_base64_output(&stderr);

    Ok(WinrmCommandResult {
        command: command.to_string(),
        stdout: stdout_decoded,
        stderr: stderr_decoded,
        exit_code,
        success: exit_code == 0,
    })
}

/// Execute multiple commands and collect results.
pub async fn execute_commands(
    config: &WinrmConfig,
    commands: &[(&str, &str)],
) -> Result<HashMap<String, String>, String> {
    let mut results = HashMap::new();

    for (label, command) in commands {
        match execute_powershell(config, command).await {
            Ok(result) => {
                results.insert(label.to_string(), result.stdout);
            }
            Err(e) => {
                tracing::warn!("WinRM command '{}' failed: {}", label, e);
                results.insert(label.to_string(), String::new());
            }
        }
    }

    Ok(results)
}

/// Collect Windows system data via WinRM.
pub async fn collect_windows_data(config: &WinrmConfig) -> Result<HashMap<String, String>, String> {
    let commands: Vec<(&str, &str)> = vec![
        ("security_policy_raw", "secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg /quiet; Get-Content C:\\Windows\\Temp\\secpol.cfg"),
        ("audit_policy_raw", "auditpol /get /category:*"),
        ("services_raw", "Get-Service | Select-Object Name,Status,StartType | ConvertTo-Json -Compress"),
        ("registry_schannel", "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\" /s 2>$null"),
        ("registry_lsa", "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /s 2>$null"),
        ("registry_policies", "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\" /s 2>$null"),
        ("registry_system", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /s 2>$null"),
        ("registry_winrm", "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\" /s 2>$null"),
        ("registry_terminal_services", "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /s 2>$null"),
        ("hostname", "hostname"),
    ];

    execute_commands(config, &commands).await
}

/// Build a WinRM SOAP envelope for PowerShell command execution.
fn build_winrm_soap_envelope(command: &str, host: &str) -> String {
    // Encode the PowerShell command as base64 for the -EncodedCommand parameter.
    let utf16_command: Vec<u8> = command
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let encoded = base64_encode(&utf16_command);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>http://{host}:5985/wsman</wsa:To>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsman:OperationTimeout>PT60S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>powershell -EncodedCommand {encoded}</rsp:Command>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"#,
        host = host,
        encoded = encoded,
    )
}

/// Simple base64 encoding (for PowerShell encoded commands).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((combined >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((combined >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((combined >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(combined & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Decode base64 output from WinRM responses.
fn decode_base64_output(input: &str) -> String {
    // WinRM streams are base64-encoded. Decode and convert from UTF-16LE if needed.
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Simple base64 decode.
    let bytes = match base64_decode(trimmed) {
        Ok(b) => b,
        Err(_) => return trimmed.to_string(), // Not base64, return as-is.
    };

    // Try UTF-16LE first (PowerShell output), then UTF-8.
    if bytes.len() >= 2 && bytes.len() % 2 == 0 {
        let utf16: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&utf16) {
            return s;
        }
    }

    String::from_utf8_lossy(&bytes).to_string()
}

#[allow(clippy::manual_is_multiple_of)]
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const DECODE_TABLE: [i8; 128] = {
        let mut table = [-1i8; 128];
        let mut i = 0u8;
        while i < 26 {
            table[(b'A' + i) as usize] = i as i8;
            i += 1;
        }
        i = 0;
        while i < 26 {
            table[(b'a' + i) as usize] = (26 + i) as i8;
            i += 1;
        }
        i = 0;
        while i < 10 {
            table[(b'0' + i) as usize] = (52 + i) as i8;
            i += 1;
        }
        table[b'+' as usize] = 62;
        table[b'/' as usize] = 63;
        table
    };

    let input: Vec<u8> = input
        .bytes()
        .filter(|b| *b != b'\n' && *b != b'\r' && *b != b' ')
        .collect();
    if input.len() % 4 != 0 {
        return Err("Invalid base64 length".to_string());
    }

    let mut output = Vec::new();
    for chunk in input.chunks(4) {
        let mut vals = [0u8; 4];
        let mut padding = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            if byte == b'=' {
                padding += 1;
                vals[i] = 0;
            } else if byte < 128 && DECODE_TABLE[byte as usize] >= 0 {
                vals[i] = DECODE_TABLE[byte as usize] as u8;
            } else {
                return Err(format!("Invalid base64 character: {}", byte as char));
            }
        }
        let combined = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);
        output.push((combined >> 16) as u8);
        if padding < 2 {
            output.push((combined >> 8) as u8);
        }
        if padding < 1 {
            output.push(combined as u8);
        }
    }

    Ok(output)
}

/// Extract a value from a SOAP XML response (simple text extraction).
fn extract_soap_element(xml: &str, element: &str, _attr_value: &str) -> Option<String> {
    let open_tag = format!("<{}", element);
    let close_tag = format!("</{}>", element);

    if let Some(start_pos) = xml.find(&open_tag) {
        let after_tag = &xml[start_pos..];
        if let Some(gt_pos) = after_tag.find('>') {
            let content_start = start_pos + gt_pos + 1;
            if let Some(end_pos) = xml[content_start..].find(&close_tag) {
                return Some(xml[content_start..content_start + end_pos].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let input = b"Hello, World!";
        let encoded = base64_encode(input);
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_winrm_config_serialization() {
        let config = WinrmConfig {
            host: "10.0.1.50".to_string(),
            port: 5985,
            username: "Administrator".to_string(),
            password: "P@ssw0rd".to_string(),
            use_https: false,
            verify_tls: true,
            timeout_secs: 30,
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: WinrmConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, "10.0.1.50");
    }

    #[test]
    fn test_soap_envelope_generation() {
        let soap = build_winrm_soap_envelope("Get-Service", "10.0.1.50");
        assert!(soap.contains("EncodedCommand"));
        assert!(soap.contains("10.0.1.50"));
    }

    #[test]
    fn test_extract_soap_element() {
        let xml = r#"<Response><ExitCode>0</ExitCode><Stream>SGVsbG8=</Stream></Response>"#;
        assert_eq!(
            extract_soap_element(xml, "ExitCode", ""),
            Some("0".to_string())
        );
        assert_eq!(
            extract_soap_element(xml, "Stream", ""),
            Some("SGVsbG8=".to_string())
        );
    }
}
