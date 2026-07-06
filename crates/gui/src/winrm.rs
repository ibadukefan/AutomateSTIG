//! WinRM transport for remote Windows data collection.
//!
//! Connects to remote Windows hosts via WinRM (HTTP/HTTPS) and executes
//! PowerShell commands to collect system data for STIG evaluation.
//!
//! Uses the WinRM SOAP protocol over HTTP(S) with Basic or NTLM auth.
//! The WS-Management shell lifecycle implemented here requires validation
//! against a real WinRM listener.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

    let url = winrm_endpoint(config);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(!config.verify_tls)
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let create_envelope = build_create_shell_envelope(&url, config.timeout_secs);
    let create_response = post_soap(
        &client,
        &url,
        &config.username,
        &config.password,
        create_envelope,
    )
    .await?;
    let shell_id = parse_shell_id(&create_response).ok_or_else(|| {
        format!(
            "WinRM Create response did not include ShellId: {}",
            response_snippet(&create_response)
        )
    })?;

    let encoded = encode_powershell_command(command);
    let command_envelope = build_command_envelope(&url, config.timeout_secs, &shell_id, &encoded);
    let command_response = match post_soap(
        &client,
        &url,
        &config.username,
        &config.password,
        command_envelope,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            delete_shell_best_effort(
                &client,
                &url,
                &config.username,
                &config.password,
                config.timeout_secs,
                &shell_id,
            )
            .await;
            return Err(error);
        }
    };

    let command_id = match parse_command_id(&command_response) {
        Some(command_id) => command_id,
        None => {
            delete_shell_best_effort(
                &client,
                &url,
                &config.username,
                &config.password,
                config.timeout_secs,
                &shell_id,
            )
            .await;
            return Err(format!(
                "WinRM Command response did not include CommandId: {}",
                response_snippet(&command_response)
            ));
        }
    };

    let output = match receive_command_output(
        &client,
        &url,
        &config.username,
        &config.password,
        config.timeout_secs,
        &shell_id,
        &command_id,
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            signal_command_best_effort(
                &client,
                &url,
                &config.username,
                &config.password,
                config.timeout_secs,
                &shell_id,
                &command_id,
            )
            .await;
            delete_shell_best_effort(
                &client,
                &url,
                &config.username,
                &config.password,
                config.timeout_secs,
                &shell_id,
            )
            .await;
            return Err(error);
        }
    };

    signal_command_best_effort(
        &client,
        &url,
        &config.username,
        &config.password,
        config.timeout_secs,
        &shell_id,
        &command_id,
    )
    .await;
    delete_shell_best_effort(
        &client,
        &url,
        &config.username,
        &config.password,
        config.timeout_secs,
        &shell_id,
    )
    .await;

    Ok(WinrmCommandResult {
        command: command.to_string(),
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.exit_code,
        success: output.exit_code == 0,
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

fn winrm_endpoint(config: &WinrmConfig) -> String {
    let scheme = if config.use_https { "https" } else { "http" };
    format!("{}://{}:{}/wsman", scheme, config.host, config.port)
}

const ACTION_CREATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
const ACTION_COMMAND: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
const ACTION_RECEIVE: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
const ACTION_SIGNAL: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
const ACTION_DELETE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";
const RESOURCE_URI: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
const REPLY_TO_ANONYMOUS: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";
const SIGNAL_TERMINATE: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate";
const MAX_RECEIVE_ITERATIONS: usize = 60;

struct ReceiveOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

async fn post_soap(
    client: &reqwest::Client,
    url: &str,
    user: &str,
    pass: &str,
    envelope: String,
) -> Result<String, String> {
    let response = client
        .post(url)
        .basic_auth(user, Some(pass))
        .header("Content-Type", "application/soap+xml;charset=UTF-8")
        .body(envelope)
        .send()
        .await
        .map_err(|e| format!("WinRM request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read WinRM response: {}", e))?;

    if !status.is_success() {
        return Err(format!(
            "WinRM returned {}: {}",
            status,
            response_snippet(&body)
        ));
    }

    Ok(body)
}

async fn receive_command_output(
    client: &reqwest::Client,
    url: &str,
    user: &str,
    pass: &str,
    timeout_secs: u64,
    shell_id: &str,
    command_id: &str,
) -> Result<ReceiveOutput, String> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = None;
    let mut done = false;

    for _ in 0..MAX_RECEIVE_ITERATIONS {
        let receive_envelope = build_receive_envelope(url, timeout_secs, shell_id, command_id);
        let response = post_soap(client, url, user, pass, receive_envelope).await?;

        stdout.push_str(&decode_streams(&response, "stdout"));
        stderr.push_str(&decode_streams(&response, "stderr"));
        if let Some(code) = parse_exit_code(&response) {
            exit_code = Some(code);
        }
        if parse_command_state_done(&response) {
            done = true;
            break;
        }
    }

    Ok(ReceiveOutput {
        stdout,
        stderr,
        exit_code: if done { exit_code.unwrap_or(0) } else { -1 },
    })
}

async fn signal_command_best_effort(
    client: &reqwest::Client,
    url: &str,
    user: &str,
    pass: &str,
    timeout_secs: u64,
    shell_id: &str,
    command_id: &str,
) {
    let signal_envelope = build_signal_envelope(url, timeout_secs, shell_id, command_id);
    let _ = post_soap(client, url, user, pass, signal_envelope).await;
}

async fn delete_shell_best_effort(
    client: &reqwest::Client,
    url: &str,
    user: &str,
    pass: &str,
    timeout_secs: u64,
    shell_id: &str,
) {
    let delete_envelope = build_delete_shell_envelope(url, timeout_secs, shell_id);
    let _ = post_soap(client, url, user, pass, delete_envelope).await;
}

fn build_create_shell_envelope(endpoint: &str, timeout_secs: u64) -> String {
    let option_set = r#"<wsman:OptionSet><wsman:Option Name="WINRS_NOPROFILE">FALSE</wsman:Option><wsman:Option Name="WINRS_CODEPAGE">65001</wsman:Option></wsman:OptionSet>"#;
    let body = r#"<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>"#;
    build_soap_envelope(
        endpoint,
        timeout_secs,
        ACTION_CREATE,
        None,
        Some(option_set),
        body,
    )
}

fn build_command_envelope(
    endpoint: &str,
    timeout_secs: u64,
    shell_id: &str,
    encoded: &str,
) -> String {
    let option_set = r#"<wsman:OptionSet><wsman:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</wsman:Option><wsman:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</wsman:Option></wsman:OptionSet>"#;
    let body = format!(
        r#"<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command><rsp:Arguments>-NonInteractive -EncodedCommand {encoded}</rsp:Arguments></rsp:CommandLine>"#,
        encoded = escape_xml_text(encoded)
    );
    build_soap_envelope(
        endpoint,
        timeout_secs,
        ACTION_COMMAND,
        Some(shell_id),
        Some(option_set),
        &body,
    )
}

fn build_receive_envelope(
    endpoint: &str,
    timeout_secs: u64,
    shell_id: &str,
    command_id: &str,
) -> String {
    let body = format!(
        r#"<rsp:Receive><rsp:DesiredStream CommandId="{command_id}">stdout stderr</rsp:DesiredStream></rsp:Receive>"#,
        command_id = escape_xml_attr(command_id)
    );
    build_soap_envelope(
        endpoint,
        timeout_secs,
        ACTION_RECEIVE,
        Some(shell_id),
        None,
        &body,
    )
}

fn build_signal_envelope(
    endpoint: &str,
    timeout_secs: u64,
    shell_id: &str,
    command_id: &str,
) -> String {
    let body = format!(
        r#"<rsp:Signal CommandId="{command_id}"><rsp:Code>{code}</rsp:Code></rsp:Signal>"#,
        command_id = escape_xml_attr(command_id),
        code = SIGNAL_TERMINATE
    );
    build_soap_envelope(
        endpoint,
        timeout_secs,
        ACTION_SIGNAL,
        Some(shell_id),
        None,
        &body,
    )
}

fn build_delete_shell_envelope(endpoint: &str, timeout_secs: u64, shell_id: &str) -> String {
    build_soap_envelope(
        endpoint,
        timeout_secs,
        ACTION_DELETE,
        Some(shell_id),
        None,
        "",
    )
}

fn build_soap_envelope(
    endpoint: &str,
    timeout_secs: u64,
    action: &str,
    shell_id: Option<&str>,
    option_set: Option<&str>,
    body: &str,
) -> String {
    let selector_set = shell_id.map(|id| {
        format!(
            r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{}</wsman:Selector></wsman:SelectorSet>"#,
            escape_xml_text(id)
        )
    });
    let body = if body.is_empty() {
        "<s:Body />".to_string()
    } else {
        format!("<s:Body>{}</s:Body>", body)
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
            xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>{endpoint}</wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">{resource_uri}</wsman:ResourceURI>
    <wsa:ReplyTo><wsa:Address s:mustUnderstand="true">{reply_to}</wsa:Address></wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">{action}</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{message_id}</wsa:MessageID>
    <wsman:Locale xml:lang="en-US" s:mustUnderstand="false" />
    <wsman:OperationTimeout>PT{timeout_secs}S</wsman:OperationTimeout>
    {selector_set}
    {option_set}
  </s:Header>
  {body}
</s:Envelope>"#,
        endpoint = escape_xml_text(endpoint),
        resource_uri = RESOURCE_URI,
        reply_to = REPLY_TO_ANONYMOUS,
        action = action,
        message_id = Uuid::new_v4(),
        timeout_secs = timeout_secs,
        selector_set = selector_set.as_deref().unwrap_or(""),
        option_set = option_set.unwrap_or(""),
        body = body
    )
}

fn encode_powershell_command(command: &str) -> String {
    let utf16_command: Vec<u8> = command
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    base64_encode(&utf16_command)
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

    if looks_like_utf16le(&bytes) {
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

fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xff, 0xfe]) {
        return true;
    }

    let pairs = bytes.chunks_exact(2);
    if !pairs.remainder().is_empty() {
        return false;
    }

    let pair_count = pairs.len();
    if pair_count == 0 {
        return false;
    }

    let nul_high_bytes = bytes.chunks_exact(2).filter(|pair| pair[1] == 0).count();
    nul_high_bytes * 2 >= pair_count
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

struct StartTag<'a> {
    raw: &'a str,
    qname: &'a str,
    content_start: usize,
    after_tag: usize,
    self_closing: bool,
}

fn parse_shell_id(xml: &str) -> Option<String> {
    extract_first_element_text(xml, "ShellId")
        .filter(|id| !id.trim().is_empty())
        .or_else(|| extract_selector(xml, "ShellId"))
}

fn parse_command_id(xml: &str) -> Option<String> {
    extract_first_element_text(xml, "CommandId").filter(|id| !id.trim().is_empty())
}

fn parse_command_state_done(xml: &str) -> bool {
    find_start_tag(xml, "CommandState", 0)
        .and_then(|tag| extract_attribute(tag.raw, "State"))
        .map(|state| state.ends_with("/CommandState/Done"))
        .unwrap_or(false)
}

fn parse_exit_code(xml: &str) -> Option<i32> {
    extract_first_element_text(xml, "ExitCode").and_then(|code| code.trim().parse().ok())
}

fn decode_streams(xml: &str, stream_name: &str) -> String {
    extract_stream_bodies(xml, stream_name)
        .into_iter()
        .map(|body| decode_base64_output(&body))
        .collect()
}

fn extract_stream_bodies(xml: &str, stream_name: &str) -> Vec<String> {
    let mut bodies = Vec::new();
    let mut search_start = 0;

    while let Some(tag) = find_start_tag(xml, "Stream", search_start) {
        let matches_stream = extract_attribute(tag.raw, "Name")
            .map(|name| name == stream_name)
            .unwrap_or(false);
        let Some((content, next_search_start)) = element_content(xml, &tag) else {
            break;
        };

        if matches_stream {
            bodies.push(xml_unescape_text(content.trim()));
        }
        search_start = next_search_start;
    }

    bodies
}

fn extract_selector(xml: &str, selector_name: &str) -> Option<String> {
    let mut search_start = 0;

    while let Some(tag) = find_start_tag(xml, "Selector", search_start) {
        let matches_selector = extract_attribute(tag.raw, "Name")
            .map(|name| name == selector_name)
            .unwrap_or(false);
        let Some((content, next_search_start)) = element_content(xml, &tag) else {
            break;
        };

        if matches_selector {
            let value = xml_unescape_text(content.trim());
            if !value.is_empty() {
                return Some(value);
            }
        }
        search_start = next_search_start;
    }

    None
}

fn extract_first_element_text(xml: &str, element: &str) -> Option<String> {
    let tag = find_start_tag(xml, element, 0)?;
    let (content, _) = element_content(xml, &tag)?;
    Some(xml_unescape_text(content.trim()))
}

fn find_start_tag<'a>(xml: &'a str, local_name: &str, from: usize) -> Option<StartTag<'a>> {
    let mut search_start = from;

    while let Some(relative_start) = xml[search_start..].find('<') {
        let start = search_start + relative_start;
        let after_lt = &xml[start + 1..];
        if after_lt.starts_with('/') || after_lt.starts_with('?') || after_lt.starts_with('!') {
            search_start = start + 1;
            continue;
        }

        let gt_pos = after_lt.find('>')?;
        let tag_content = &after_lt[..gt_pos];
        let raw = tag_content.trim();
        let name_end = raw
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(raw.len());
        let qname = &raw[..name_end];

        if qname.rsplit(':').next() == Some(local_name) {
            let after_tag = start + gt_pos + 2;
            return Some(StartTag {
                raw,
                qname,
                content_start: after_tag,
                after_tag,
                self_closing: raw.ends_with('/'),
            });
        }

        search_start = start + 1;
    }

    None
}

fn element_content<'a>(xml: &'a str, tag: &StartTag<'_>) -> Option<(&'a str, usize)> {
    if tag.self_closing {
        return Some(("", tag.after_tag));
    }

    let close_tag = format!("</{}>", tag.qname);
    let end_relative = xml[tag.content_start..].find(&close_tag)?;
    let end = tag.content_start + end_relative;
    Some((&xml[tag.content_start..end], end + close_tag.len()))
}

fn extract_attribute(tag: &str, attr_name: &str) -> Option<String> {
    for (pos, _) in tag.match_indices(attr_name) {
        let before_ok = pos == 0
            || tag
                .as_bytes()
                .get(pos - 1)
                .map(|b| b.is_ascii_whitespace())
                .unwrap_or(false);
        let after_pos = pos + attr_name.len();
        let after_ok = tag
            .as_bytes()
            .get(after_pos)
            .map(|b| b.is_ascii_whitespace() || *b == b'=')
            .unwrap_or(true);
        if !before_ok || !after_ok {
            continue;
        }

        let Some(rest) = tag[after_pos..].trim_start().strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(quote) = rest.chars().next() else {
            continue;
        };
        if quote != '"' && quote != '\'' {
            continue;
        }

        let value_start = quote.len_utf8();
        if let Some(value_end) = rest[value_start..].find(quote) {
            return Some(xml_unescape_text(
                &rest[value_start..value_start + value_end],
            ));
        }
    }

    None
}

fn response_snippet(body: &str) -> String {
    body.chars().take(500).collect()
}

fn escape_xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_xml_attr(value: &str) -> String {
    escape_xml_text(value)
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_unescape_text(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
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
    fn test_create_envelope_has_transfer_create_action_and_shell_body() {
        let config = WinrmConfig {
            host: "10.0.1.50".to_string(),
            port: 5986,
            username: "Administrator".to_string(),
            password: "[REDACTED]".to_string(),
            use_https: true,
            verify_tls: true,
            timeout_secs: 30,
        };
        let endpoint = winrm_endpoint(&config);
        let soap = build_create_shell_envelope(&endpoint, 30);
        assert!(soap.contains(ACTION_CREATE));
        assert!(soap.contains("<rsp:Shell>"));
        assert!(soap.contains("<rsp:InputStreams>stdin</rsp:InputStreams>"));
        assert!(soap.contains("<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>"));
        assert!(soap.contains(r#"<wsman:Option Name="WINRS_NOPROFILE">FALSE</wsman:Option>"#));
        assert!(soap.contains(r#"<wsman:Option Name="WINRS_CODEPAGE">65001</wsman:Option>"#));
        assert!(soap.contains("https://10.0.1.50:5986/wsman"));
        assert!(!soap.contains("http://10.0.1.50:5985/wsman"));
    }

    #[test]
    fn test_command_envelope_has_shellid_selector_and_encoded_command() {
        let endpoint = "https://10.0.1.50:5986/wsman";
        let encoded = encode_powershell_command("Get-Service");
        let soap = build_command_envelope(endpoint, 45, "shell-123", &encoded);

        assert!(soap.contains(r#"<wsman:Selector Name="ShellId">shell-123</wsman:Selector>"#));
        assert!(soap.contains("<rsp:Command>powershell.exe</rsp:Command>"));
        assert!(soap.contains(&format!(
            "<rsp:Arguments>-NonInteractive -EncodedCommand {encoded}</rsp:Arguments>"
        )));
        assert!(soap.contains(ACTION_COMMAND));
        assert!(soap.contains("<wsman:OperationTimeout>PT45S</wsman:OperationTimeout>"));
    }

    #[test]
    fn test_receive_envelope_targets_command_id() {
        let soap = build_receive_envelope(
            "https://10.0.1.50:5986/wsman",
            30,
            "shell-123",
            "command-456",
        );

        assert!(soap.contains(ACTION_RECEIVE));
        assert!(soap.contains(r#"<wsman:Selector Name="ShellId">shell-123</wsman:Selector>"#));
        assert!(soap.contains(
            r#"<rsp:DesiredStream CommandId="command-456">stdout stderr</rsp:DesiredStream>"#
        ));
    }

    #[test]
    fn test_each_envelope_has_unique_message_id() {
        let first = build_create_shell_envelope("https://10.0.1.50:5986/wsman", 30);
        let second = build_create_shell_envelope("https://10.0.1.50:5986/wsman", 30);
        let first_id = extract_first_element_text(&first, "MessageID").unwrap();
        let second_id = extract_first_element_text(&second, "MessageID").unwrap();

        assert!(first_id.starts_with("uuid:"));
        assert!(second_id.starts_with("uuid:"));
        assert_ne!(first_id, second_id);
    }

    #[test]
    fn test_extract_all_streams_concatenates_and_base64_decodes() {
        let xml = r#"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Body>
    <rsp:Stream Name="stdout" CommandId="command-456">QUI=</rsp:Stream>
    <rsp:Stream Name="stderr" CommandId="command-456">RVJS</rsp:Stream>
    <rsp:Stream Name="stdout" CommandId="command-456" End="true">Q0Q=</rsp:Stream>
  </s:Body>
</s:Envelope>"#;

        assert_eq!(decode_streams(xml, "stdout"), "ABCD");
    }

    #[test]
    fn test_parse_shell_id() {
        let direct =
            r#"<s:Envelope><s:Body><rsp:ShellId>shell-direct</rsp:ShellId></s:Body></s:Envelope>"#;
        let selector = r#"
<s:Envelope>
  <s:Header>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">shell-selector</wsman:Selector>
    </wsman:SelectorSet>
  </s:Header>
</s:Envelope>"#;

        assert_eq!(parse_shell_id(direct), Some("shell-direct".to_string()));
        assert_eq!(parse_shell_id(selector), Some("shell-selector".to_string()));
    }

    #[test]
    fn test_parse_command_state_done() {
        let xml = r#"
<rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
  <rsp:ExitCode>0</rsp:ExitCode>
</rsp:CommandState>"#;

        assert!(parse_command_state_done(xml));
        assert_eq!(parse_exit_code(xml), Some(0));
    }
}
