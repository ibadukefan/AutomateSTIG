//! Remediation script generation for AutomateSTIG.
//!
//! Generates platform-specific remediation scripts (Ansible, PowerShell, Bash)
//! from STIG findings. Scripts are deterministic and auditable.

use automatestig_core::checks::{Check, ExpectedResult, ServiceStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A remediation script that can be applied to fix a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationScript {
    /// Script identifier.
    pub id: String,

    /// Target Vuln ID(s) this script addresses.
    pub vuln_ids: Vec<String>,

    /// Human-readable description of what the script does.
    pub description: String,

    /// Script format/language.
    pub format: ScriptFormat,

    /// The actual script content.
    pub content: String,

    /// Whether this script requires elevated privileges.
    pub requires_admin: bool,

    /// Whether this script requires a reboot after application.
    pub requires_reboot: bool,

    /// Risk level of applying this remediation.
    pub risk: RemediationRisk,

    /// Whether this script is reversible.
    pub reversible: bool,

    /// Rollback script (if reversible).
    pub rollback_content: Option<String>,
}

/// Remediation script format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptFormat {
    #[serde(rename = "powershell")]
    PowerShell,
    #[serde(rename = "bash")]
    Bash,
    #[serde(rename = "ansible")]
    Ansible,
    #[serde(rename = "cmd")]
    Cmd,
}

impl std::fmt::Display for ScriptFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PowerShell => write!(f, "PowerShell"),
            Self::Bash => write!(f, "Bash"),
            Self::Ansible => write!(f, "Ansible"),
            Self::Cmd => write!(f, "CMD"),
        }
    }
}

/// Risk level of applying a remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemediationRisk {
    /// Safe to apply — low impact, easily reversible.
    #[serde(rename = "low")]
    Low,
    /// Moderate impact — may affect service availability.
    #[serde(rename = "medium")]
    Medium,
    /// High impact — could cause outage or require significant testing.
    #[serde(rename = "high")]
    High,
}

/// A remediation plan — a collection of scripts to fix multiple findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    /// Plan name.
    pub name: String,

    /// Target hostname.
    pub target_host: String,

    /// Scripts in execution order.
    pub scripts: Vec<RemediationScript>,

    /// Whether the plan requires a reboot at the end.
    pub requires_reboot: bool,

    /// Overall risk assessment.
    pub overall_risk: RemediationRisk,
}

impl RemediationPlan {
    /// Create a new empty remediation plan.
    pub fn new(name: &str, target_host: &str) -> Self {
        Self {
            name: name.to_string(),
            target_host: target_host.to_string(),
            scripts: Vec::new(),
            requires_reboot: false,
            overall_risk: RemediationRisk::Low,
        }
    }

    /// Add a script to the plan.
    pub fn add_script(&mut self, script: RemediationScript) {
        if script.requires_reboot {
            self.requires_reboot = true;
        }
        if script.risk as u8 > self.overall_risk as u8 {
            self.overall_risk = script.risk;
        }
        self.scripts.push(script);
    }

    /// Get the total number of findings addressed.
    pub fn findings_addressed(&self) -> usize {
        self.scripts.iter().map(|s| s.vuln_ids.len()).sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryValueType {
    DWord,
    String,
}

impl RegistryValueType {
    fn powershell_name(self) -> &'static str {
        match self {
            Self::DWord => "DWord",
            Self::String => "String",
        }
    }

    fn ansible_name(self) -> &'static str {
        match self {
            Self::DWord => "dword",
            Self::String => "string",
        }
    }
}

/// Generate a remediation script for a structured check.
pub fn generate_for_check(
    vuln_id: &str,
    description: &str,
    check: &Check,
    expected: &ExpectedResult,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    match check {
        Check::Registry {
            path,
            value_name,
            value_type,
        } => generate_registry_check_script(
            vuln_id,
            description,
            path,
            value_name,
            value_type.as_deref(),
            expected,
            format,
        ),
        Check::Service {
            name,
            expected_status,
        } => generate_service_script(vuln_id, description, name, *expected_status, format),
        Check::Sysctl { key } => {
            generate_sysctl_script(vuln_id, description, key, expected, format)
        }
        Check::Package {
            name,
            should_be_installed,
        } => generate_package_script(vuln_id, description, name, *should_be_installed, format),
        Check::WindowsFeature {
            name,
            should_be_installed,
        } => generate_windows_feature_script(
            vuln_id,
            description,
            name,
            *should_be_installed,
            format,
        ),
        Check::ConfigLine {
            pattern,
            context,
            should_exist,
        } => generate_config_line_script(
            vuln_id,
            description,
            pattern,
            context.as_deref(),
            *should_exist,
            format,
        ),
        Check::FilePermission {
            path,
            owner,
            group,
            mode,
        } => generate_file_permission_script(
            vuln_id,
            description,
            path,
            owner.as_deref(),
            group.as_deref(),
            mode.as_deref(),
            format,
        ),
        Check::All { checks } => {
            generate_all_script(vuln_id, description, checks, expected, format)
        }
        Check::SecurityPolicy { .. }
        | Check::AuditPolicy { .. }
        | Check::FileContent { .. }
        | Check::Command { .. }
        | Check::Any { .. } => None,
    }
}

/// Build a remediation plan from structured checks, skipping unsupported items.
pub fn build_remediation_plan(
    name: &str,
    target_host: &str,
    items: &[(String, String, Check, ExpectedResult)],
    format: ScriptFormat,
) -> RemediationPlan {
    let mut plan = RemediationPlan::new(name, target_host);

    for (vuln_id, description, check, expected) in items {
        if let Some(script) = generate_for_check(vuln_id, description, check, expected, format) {
            plan.add_script(script);
        }
    }

    plan
}

fn generate_registry_check_script(
    vuln_id: &str,
    description: &str,
    path: &str,
    value_name: &str,
    value_type: Option<&str>,
    expected: &ExpectedResult,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    let ExpectedResult::Equals { value } = expected else {
        return None;
    };

    if !is_nonempty_single_line(path) || !is_nonempty_single_line(value_name) {
        return None;
    }

    let reg_path = registry_powershell_path(path)?;
    let reg_type = registry_value_type(value_type);

    match format {
        ScriptFormat::PowerShell => {
            let value_literal = registry_powershell_value(value, reg_type)?;
            let body = format!(
                "$ErrorActionPreference = 'Stop'\n\n\
                 $regPath = {}\n\n\
                 if (-not (Test-Path $regPath)) {{\n\
                     New-Item -Path $regPath -Force | Out-Null\n\
                 }}\n\n\
                 Set-ItemProperty -Path $regPath -Name {} -Value {} -Type {}\n",
                ps_quote(&reg_path),
                ps_quote(value_name),
                value_literal,
                reg_type.powershell_name()
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::PowerShell,
                body,
                true,
                false,
                RemediationRisk::Low,
            ))
        }
        ScriptFormat::Ansible => {
            let data = registry_ansible_value(value, reg_type)?;
            let body = format!(
                r#"---
- name: Remediate {}
  hosts: all
  tasks:
    - name: Set registry value {}
      ansible.windows.win_regedit:
        path: {}
        name: {}
        data: {}
        type: {}
"#,
                yaml_string(vuln_id),
                yaml_string(value_name),
                yaml_string(&reg_path),
                yaml_string(value_name),
                data,
                reg_type.ansible_name()
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Ansible,
                body,
                true,
                false,
                RemediationRisk::Low,
            ))
        }
        ScriptFormat::Bash | ScriptFormat::Cmd => None,
    }
}

fn generate_service_script(
    vuln_id: &str,
    description: &str,
    name: &str,
    expected_status: ServiceStatus,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    if !is_nonempty_single_line(name) {
        return None;
    }

    let body = match format {
        ScriptFormat::PowerShell => {
            let service_name = ps_quote(name);
            match expected_status {
                ServiceStatus::Running => format!(
                    "$ErrorActionPreference = 'Stop'\n\n\
                     Set-Service -Name {service_name} -StartupType Automatic\n\
                     Start-Service -Name {service_name}\n"
                ),
                ServiceStatus::Stopped => format!(
                    "$ErrorActionPreference = 'Stop'\n\n\
                     Stop-Service -Name {service_name}\n"
                ),
                ServiceStatus::Disabled => format!(
                    "$ErrorActionPreference = 'Stop'\n\n\
                     Stop-Service -Name {service_name} -ErrorAction SilentlyContinue\n\
                     Set-Service -Name {service_name} -StartupType Disabled\n"
                ),
            }
        }
        ScriptFormat::Bash => match expected_status {
            ServiceStatus::Running => {
                format!(
                    "set -euo pipefail\n\nsystemctl enable --now {}\n",
                    sh_quote(name)
                )
            }
            ServiceStatus::Stopped => {
                format!("set -euo pipefail\n\nsystemctl stop {}\n", sh_quote(name))
            }
            ServiceStatus::Disabled => {
                format!(
                    "set -euo pipefail\n\nsystemctl disable --now {}\n",
                    sh_quote(name)
                )
            }
        },
        ScriptFormat::Ansible => ansible_service_body(vuln_id, name, expected_status),
        ScriptFormat::Cmd => return None,
    };

    Some(remediation_script(
        vuln_id,
        description,
        format,
        body,
        true,
        false,
        RemediationRisk::Medium,
    ))
}

fn generate_sysctl_script(
    vuln_id: &str,
    description: &str,
    key: &str,
    expected: &ExpectedResult,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    let ExpectedResult::Equals { value } = expected else {
        return None;
    };

    if !is_nonempty_single_line(key) {
        return None;
    }

    let value = scalar_value_to_string(value)?;
    if !is_single_line(&value) {
        return None;
    }

    match format {
        ScriptFormat::Bash => {
            let body = format!(
                r#"set -euo pipefail

key={}
value={}
config='/etc/sysctl.d/99-automatestig.conf'

sysctl -w "$key=$value"

mkdir -p "$(dirname "$config")"
touch "$config"
tmp_file="$(mktemp)"
awk -F= -v key="$key" -v value="$value" '
BEGIN {{ updated = 0 }}
{{
    left = $1
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", left)
    if (left == key) {{
        print key " = " value
        updated = 1
        next
    }}
    print
}}
END {{
    if (updated == 0) {{
        print key " = " value
    }}
}}
' "$config" > "$tmp_file"
cat "$tmp_file" > "$config"
rm -f "$tmp_file"
"#,
                sh_quote(key),
                sh_quote(&value)
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Bash,
                body,
                true,
                false,
                RemediationRisk::Low,
            ))
        }
        ScriptFormat::Ansible => {
            let body = format!(
                r#"---
- name: Remediate {}
  hosts: all
  tasks:
    - name: Set sysctl {}
      become: true
      ansible.posix.sysctl:
        name: {}
        value: {}
        sysctl_set: true
        reload: true
"#,
                yaml_string(vuln_id),
                yaml_string(key),
                yaml_string(key),
                yaml_string(&value)
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Ansible,
                body,
                true,
                false,
                RemediationRisk::Low,
            ))
        }
        ScriptFormat::PowerShell | ScriptFormat::Cmd => None,
    }
}

fn generate_package_script(
    vuln_id: &str,
    description: &str,
    name: &str,
    should_be_installed: bool,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    if !is_nonempty_single_line(name) {
        return None;
    }

    match format {
        ScriptFormat::Bash => {
            let action = if should_be_installed {
                "install"
            } else {
                "remove"
            };
            let body = format!(
                "set -euo pipefail\n\napt-get {action} -y {pkg} || yum {action} -y {pkg}\n",
                pkg = sh_quote(name)
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Bash,
                body,
                true,
                false,
                RemediationRisk::Medium,
            ))
        }
        ScriptFormat::Ansible => {
            let state = if should_be_installed {
                "present"
            } else {
                "absent"
            };
            let body = format!(
                r#"---
- name: Remediate {}
  hosts: all
  tasks:
    - name: Ensure package {} is {}
      become: true
      ansible.builtin.package:
        name: {}
        state: {state}
"#,
                yaml_string(vuln_id),
                yaml_string(name),
                state,
                yaml_string(name)
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Ansible,
                body,
                true,
                false,
                RemediationRisk::Medium,
            ))
        }
        ScriptFormat::PowerShell | ScriptFormat::Cmd => None,
    }
}

fn generate_windows_feature_script(
    vuln_id: &str,
    description: &str,
    name: &str,
    should_be_installed: bool,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    if !is_nonempty_single_line(name) {
        return None;
    }

    match format {
        ScriptFormat::PowerShell => {
            let command = if should_be_installed {
                "Install-WindowsFeature"
            } else {
                "Uninstall-WindowsFeature"
            };
            let fallback = if should_be_installed {
                "Enable-WindowsOptionalFeature"
            } else {
                "Disable-WindowsOptionalFeature"
            };
            let body = format!(
                "$ErrorActionPreference = 'Stop'\n\n\
                 {command} -Name {}\n\
                 # On Windows client SKUs, use {fallback} -Online -FeatureName {} if {command} is unavailable.\n",
                ps_quote(name),
                ps_quote(name)
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::PowerShell,
                body,
                true,
                true,
                RemediationRisk::Medium,
            ))
        }
        ScriptFormat::Ansible => {
            let state = if should_be_installed {
                "present"
            } else {
                "absent"
            };
            let body = format!(
                r#"---
- name: Remediate {}
  hosts: all
  tasks:
    - name: Ensure Windows feature {} is {}
      ansible.windows.win_feature:
        name: {}
        state: {state}
"#,
                yaml_string(vuln_id),
                yaml_string(name),
                state,
                yaml_string(name)
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Ansible,
                body,
                true,
                true,
                RemediationRisk::Medium,
            ))
        }
        ScriptFormat::Bash | ScriptFormat::Cmd => None,
    }
}

fn generate_config_line_script(
    vuln_id: &str,
    description: &str,
    pattern: &str,
    context: Option<&str>,
    should_exist: bool,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    let path = context?;
    if !is_nonempty_single_line(path) || !is_nonempty_single_line(pattern) {
        return None;
    }

    match format {
        ScriptFormat::Bash => {
            let body = if should_exist {
                format!(
                    "set -euo pipefail\n\n\
                     file={}\n\
                     line={}\n\n\
                     touch \"$file\"\n\
                     if ! grep -qxF -- \"$line\" \"$file\"; then\n\
                         printf '%s\\n' \"$line\" >> \"$file\"\n\
                     fi\n",
                    sh_quote(path),
                    sh_quote(pattern)
                )
            } else {
                format!(
                    "set -euo pipefail\n\n\
                     file={}\n\
                     line={}\n\n\
                     if [ -f \"$file\" ]; then\n\
                         tmp_file=\"$(mktemp)\"\n\
                         grep -vxF -- \"$line\" \"$file\" > \"$tmp_file\" || true\n\
                         cat \"$tmp_file\" > \"$file\"\n\
                         rm -f \"$tmp_file\"\n\
                     fi\n",
                    sh_quote(path),
                    sh_quote(pattern)
                )
            };

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Bash,
                body,
                true,
                false,
                RemediationRisk::Low,
            ))
        }
        ScriptFormat::Ansible => {
            let state = if should_exist { "present" } else { "absent" };
            let body = format!(
                r#"---
- name: Remediate {}
  hosts: all
  tasks:
    - name: Ensure config line is {}
      become: true
      ansible.builtin.lineinfile:
        path: {}
        line: {}
        state: {state}
"#,
                yaml_string(vuln_id),
                state,
                yaml_string(path),
                yaml_string(pattern)
            );

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Ansible,
                body,
                true,
                false,
                RemediationRisk::Low,
            ))
        }
        ScriptFormat::PowerShell | ScriptFormat::Cmd => None,
    }
}

fn generate_file_permission_script(
    vuln_id: &str,
    description: &str,
    path: &str,
    owner: Option<&str>,
    group: Option<&str>,
    mode: Option<&str>,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    if !is_nonempty_single_line(path) || (owner.is_none() && group.is_none() && mode.is_none()) {
        return None;
    }
    if !optional_valid_file_attr(owner)
        || !optional_valid_file_attr(group)
        || !optional_valid_file_attr(mode)
    {
        return None;
    }
    if owner.is_some_and(|value| value.contains(':'))
        || group.is_some_and(|value| value.contains(':'))
    {
        return None;
    }

    match format {
        ScriptFormat::Bash => {
            let mut lines = vec!["set -euo pipefail".to_string(), String::new()];
            if let Some(mode) = mode {
                lines.push(format!("chmod {} {}", sh_quote(mode), sh_quote(path)));
            }
            if owner.is_some() || group.is_some() {
                let ownership = match (owner, group) {
                    (Some(owner), Some(group)) => format!("{owner}:{group}"),
                    (Some(owner), None) => owner.to_string(),
                    (None, Some(group)) => format!(":{group}"),
                    (None, None) => unreachable!("checked above"),
                };
                lines.push(format!("chown {} {}", sh_quote(&ownership), sh_quote(path)));
            }
            lines.push(String::new());

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Bash,
                lines.join("\n"),
                true,
                false,
                RemediationRisk::Medium,
            ))
        }
        ScriptFormat::Ansible => {
            let mut body = format!(
                r#"---
- name: Remediate {}
  hosts: all
  tasks:
    - name: Set file permissions for {}
      become: true
      ansible.builtin.file:
        path: {}
"#,
                yaml_string(vuln_id),
                yaml_string(path),
                yaml_string(path)
            );
            if let Some(mode) = mode {
                body.push_str(&format!("        mode: {}\n", yaml_string(mode)));
            }
            if let Some(owner) = owner {
                body.push_str(&format!("        owner: {}\n", yaml_string(owner)));
            }
            if let Some(group) = group {
                body.push_str(&format!("        group: {}\n", yaml_string(group)));
            }

            Some(remediation_script(
                vuln_id,
                description,
                ScriptFormat::Ansible,
                body,
                true,
                false,
                RemediationRisk::Medium,
            ))
        }
        ScriptFormat::PowerShell | ScriptFormat::Cmd => None,
    }
}

fn generate_all_script(
    vuln_id: &str,
    description: &str,
    checks: &[Check],
    expected: &ExpectedResult,
    format: ScriptFormat,
) -> Option<RemediationScript> {
    let scripts: Vec<_> = checks
        .iter()
        .filter_map(|check| generate_for_check(vuln_id, description, check, expected, format))
        .collect();

    if scripts.is_empty() {
        return None;
    }

    let requires_admin = scripts.iter().any(|script| script.requires_admin);
    let requires_reboot = scripts.iter().any(|script| script.requires_reboot);
    let risk = scripts.iter().fold(RemediationRisk::Low, |risk, script| {
        max_risk(risk, script.risk)
    });
    let content = scripts
        .into_iter()
        .map(|script| script.content)
        .collect::<Vec<_>>()
        .join("\n\n");

    Some(RemediationScript {
        id: format!("fix-{}", vuln_id.to_lowercase()),
        vuln_ids: vec![vuln_id.to_string()],
        description: description.to_string(),
        format,
        content,
        requires_admin,
        requires_reboot,
        risk,
        reversible: false,
        rollback_content: None,
    })
}

fn ansible_service_body(vuln_id: &str, name: &str, expected_status: ServiceStatus) -> String {
    let (state, linux_enabled, win_start_mode) = match expected_status {
        ServiceStatus::Running => ("started", Some(true), Some("auto")),
        ServiceStatus::Stopped => ("stopped", None, None),
        ServiceStatus::Disabled => ("stopped", Some(false), Some("disabled")),
    };

    let mut body = format!(
        r#"---
- name: Remediate {}
  hosts: all
  tasks:
    - name: Ensure Windows service {} is {}
      ansible.windows.win_service:
        name: {}
        state: {state}
"#,
        yaml_string(vuln_id),
        yaml_string(name),
        state,
        yaml_string(name)
    );
    if let Some(start_mode) = win_start_mode {
        body.push_str(&format!("        start_mode: {start_mode}\n"));
    }
    body.push_str("      when: ansible_os_family == \"Windows\"\n\n");
    body.push_str(&format!(
        r#"    - name: Ensure service {} is {}
      become: true
      ansible.builtin.service:
        name: {}
        state: {state}
"#,
        yaml_string(name),
        state,
        yaml_string(name)
    ));
    if let Some(enabled) = linux_enabled {
        body.push_str(&format!("        enabled: {enabled}\n"));
    }
    body.push_str("      when: ansible_os_family != \"Windows\"\n");

    body
}

fn remediation_script(
    vuln_id: &str,
    description: &str,
    format: ScriptFormat,
    body: String,
    requires_admin: bool,
    requires_reboot: bool,
    risk: RemediationRisk,
) -> RemediationScript {
    RemediationScript {
        id: format!("fix-{}", vuln_id.to_lowercase()),
        vuln_ids: vec![vuln_id.to_string()],
        description: description.to_string(),
        format,
        content: format!("{}{}", header_comment(vuln_id, description), body),
        requires_admin,
        requires_reboot,
        risk,
        reversible: false,
        rollback_content: None,
    }
}

fn header_comment(vuln_id: &str, description: &str) -> String {
    format!(
        "# AutomateSTIG Remediation - {}\n\
         # Description: {}\n\
         # Generated by AutomateSTIG - review before applying\n\n",
        comment_text(vuln_id),
        comment_text(description)
    )
}

fn comment_text(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

fn registry_value_type(value_type: Option<&str>) -> RegistryValueType {
    let normalized = value_type
        .unwrap_or("REG_DWORD")
        .replace(['_', '-'], "")
        .to_ascii_uppercase();

    match normalized.as_str() {
        "REGSZ" | "SZ" | "STRING" => RegistryValueType::String,
        "REGDWORD" | "DWORD" => RegistryValueType::DWord,
        _ => RegistryValueType::DWord,
    }
}

fn registry_powershell_path(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || !is_single_line(path) {
        return None;
    }

    let upper_path = path.to_ascii_uppercase();
    let powershell_hives = ["HKLM:\\", "HKCU:\\", "HKCR:\\", "HKU:\\", "HKCC:\\"];
    if powershell_hives
        .iter()
        .any(|prefix| upper_path.starts_with(prefix))
    {
        return Some(path.to_string());
    }

    let mappings = [
        ("HKEY_LOCAL_MACHINE\\", "HKLM:\\"),
        ("HKLM\\", "HKLM:\\"),
        ("HKEY_CURRENT_USER\\", "HKCU:\\"),
        ("HKCU\\", "HKCU:\\"),
        ("HKEY_CLASSES_ROOT\\", "HKCR:\\"),
        ("HKCR\\", "HKCR:\\"),
        ("HKEY_USERS\\", "HKU:\\"),
        ("HKU\\", "HKU:\\"),
        ("HKEY_CURRENT_CONFIG\\", "HKCC:\\"),
        ("HKCC\\", "HKCC:\\"),
    ];

    for (prefix, replacement) in mappings {
        if upper_path.starts_with(prefix) {
            let rest = &path[prefix.len()..];
            return Some(format!("{replacement}{rest}"));
        }
    }

    None
}

fn registry_powershell_value(value: &Value, value_type: RegistryValueType) -> Option<String> {
    match value_type {
        RegistryValueType::DWord => dword_value(value).map(|value| value.to_string()),
        RegistryValueType::String => scalar_value_to_string(value).map(|value| ps_quote(&value)),
    }
}

fn registry_ansible_value(value: &Value, value_type: RegistryValueType) -> Option<String> {
    match value_type {
        RegistryValueType::DWord => dword_value(value).map(|value| value.to_string()),
        RegistryValueType::String => scalar_value_to_string(value).map(|value| yaml_string(&value)),
    }
}

fn dword_value(value: &Value) -> Option<u32> {
    match value {
        Value::Bool(value) => Some(if *value { 1 } else { 0 }),
        Value::Number(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .or_else(|| value.as_i64().and_then(|value| u32::try_from(value).ok())),
        Value::String(value) => value.trim().parse::<u32>().ok(),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn scalar_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sh_quote(value: &str) -> String {
    if value.is_empty() {
        "''".to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn optional_valid_file_attr(value: Option<&str>) -> bool {
    value.is_none_or(is_nonempty_single_line)
}

fn is_nonempty_single_line(value: &str) -> bool {
    !value.trim().is_empty() && is_single_line(value)
}

fn is_single_line(value: &str) -> bool {
    !value.contains('\r') && !value.contains('\n')
}

fn max_risk(left: RemediationRisk, right: RemediationRisk) -> RemediationRisk {
    if risk_rank(right) > risk_rank(left) {
        right
    } else {
        left
    }
}

fn risk_rank(risk: RemediationRisk) -> u8 {
    match risk {
        RemediationRisk::Low => 0,
        RemediationRisk::Medium => 1,
        RemediationRisk::High => 2,
    }
}

/// Generate a registry fix script for Windows.
pub fn generate_registry_fix(
    vuln_id: &str,
    description: &str,
    reg_path: &str,
    value_name: &str,
    value_type: &str,
    value_data: &str,
) -> RemediationScript {
    let ps_content = format!(
        r#"# AutomateSTIG Remediation - {vuln_id}
# {description}
# Generated by AutomateSTIG - DO NOT EDIT MANUALLY

$ErrorActionPreference = 'Stop'

$regPath = '{reg_path}'
$valueName = '{value_name}'
$valueType = '{value_type}'
$valueData = '{value_data}'

# Ensure the registry path exists.
if (-not (Test-Path $regPath)) {{
    New-Item -Path $regPath -Force | Out-Null
    Write-Host "Created registry path: $regPath"
}}

# Set the value.
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType
Write-Host "Set $regPath\$valueName = $valueData ($valueType)"
Write-Host "Remediation for {vuln_id} applied successfully."
"#
    );

    RemediationScript {
        id: format!("fix-{}", vuln_id.to_lowercase()),
        vuln_ids: vec![vuln_id.to_string()],
        description: description.to_string(),
        format: ScriptFormat::PowerShell,
        content: ps_content,
        requires_admin: true,
        requires_reboot: false,
        risk: RemediationRisk::Low,
        reversible: true,
        rollback_content: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_remediation_plan() {
        let mut plan = RemediationPlan::new("Fix TLS", "webserver01");

        plan.add_script(RemediationScript {
            id: "fix-v-254239".to_string(),
            vuln_ids: vec!["V-254239".to_string()],
            description: "Enable TLS 1.2".to_string(),
            format: ScriptFormat::PowerShell,
            content: "# Enable TLS 1.2".to_string(),
            requires_admin: true,
            requires_reboot: true,
            risk: RemediationRisk::Medium,
            reversible: true,
            rollback_content: None,
        });

        assert_eq!(plan.findings_addressed(), 1);
        assert!(plan.requires_reboot);
        assert_eq!(plan.overall_risk, RemediationRisk::Medium);
    }

    #[test]
    fn test_generate_registry_fix() {
        let script = generate_registry_fix(
            "V-254239",
            "Enable TLS 1.2",
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client",
            "Enabled",
            "DWord",
            "1",
        );

        assert_eq!(script.vuln_ids, vec!["V-254239"]);
        assert_eq!(script.format, ScriptFormat::PowerShell);
        assert!(script.content.contains("TLS 1.2"));
        assert!(script.requires_admin);
    }

    #[test]
    fn test_generate_for_check_registry_equals_powershell() {
        let check = Check::Registry {
            path: "HKLM\\SOFTWARE\\Example".to_string(),
            value_name: "Enabled".to_string(),
            value_type: Some("REG_DWORD".to_string()),
        };
        let expected = ExpectedResult::Equals { value: json!(1) };

        let script = generate_for_check(
            "V-100001",
            "Enable example setting",
            &check,
            &expected,
            ScriptFormat::PowerShell,
        )
        .expect("registry equals should generate PowerShell");

        assert!(script
            .content
            .starts_with("# AutomateSTIG Remediation - V-100001"));
        assert!(script
            .content
            .contains("# Generated by AutomateSTIG - review before applying"));
        assert!(script.content.contains("Set-ItemProperty"));
        assert!(script.content.contains("Enabled"));
        assert!(script.content.contains("-Value 1"));
        assert!(script.content.contains("HKLM:\\SOFTWARE\\Example"));
        assert!(!script.reversible);
    }

    #[test]
    fn test_generate_for_check_registry_bash_returns_none() {
        let check = Check::Registry {
            path: "HKLM\\SOFTWARE\\Example".to_string(),
            value_name: "Enabled".to_string(),
            value_type: Some("REG_DWORD".to_string()),
        };
        let expected = ExpectedResult::Equals { value: json!(1) };

        assert!(generate_for_check(
            "V-100001",
            "Enable example setting",
            &check,
            &expected,
            ScriptFormat::Bash,
        )
        .is_none());
    }

    #[test]
    fn test_generate_for_check_service_running_bash() {
        let check = Check::Service {
            name: "sshd".to_string(),
            expected_status: ServiceStatus::Running,
        };

        let script = generate_for_check(
            "V-100002",
            "Ensure SSH is running",
            &check,
            &ExpectedResult::IsTrue,
            ScriptFormat::Bash,
        )
        .expect("running service should generate Bash");

        assert!(script.content.contains("systemctl enable --now 'sshd'"));
        assert_eq!(script.risk, RemediationRisk::Medium);
    }

    #[test]
    fn test_generate_for_check_sysctl_equals_bash() {
        let check = Check::Sysctl {
            key: "net.ipv4.ip_forward".to_string(),
        };
        let expected = ExpectedResult::Equals { value: json!("0") };

        let script = generate_for_check(
            "V-100003",
            "Disable IP forwarding",
            &check,
            &expected,
            ScriptFormat::Bash,
        )
        .expect("sysctl equals should generate Bash");

        assert!(script.content.contains("sysctl -w"));
        assert!(script
            .content
            .contains("/etc/sysctl.d/99-automatestig.conf"));
        assert!(script.content.contains("net.ipv4.ip_forward"));
    }

    #[test]
    fn test_generate_for_check_package_remove_ansible() {
        let check = Check::Package {
            name: "telnet".to_string(),
            should_be_installed: false,
        };

        let script = generate_for_check(
            "V-100004",
            "Remove telnet",
            &check,
            &ExpectedResult::IsFalse,
            ScriptFormat::Ansible,
        )
        .expect("package removal should generate Ansible");

        assert!(script.content.contains("ansible.builtin.package"));
        assert!(script.content.contains("state: absent"));
    }

    #[test]
    fn test_generate_for_check_security_policy_returns_none() {
        let check = Check::SecurityPolicy {
            section: "System Access".to_string(),
            key: "MinimumPasswordLength".to_string(),
        };
        let expected = ExpectedResult::Equals { value: json!(14) };

        assert!(generate_for_check(
            "V-100005",
            "Set password length",
            &check,
            &expected,
            ScriptFormat::PowerShell,
        )
        .is_none());
    }

    #[test]
    fn test_build_remediation_plan_skips_unsupported_items() {
        let items = vec![
            (
                "V-100006".to_string(),
                "Ensure SSH is running".to_string(),
                Check::Service {
                    name: "sshd".to_string(),
                    expected_status: ServiceStatus::Running,
                },
                ExpectedResult::IsTrue,
            ),
            (
                "V-100007".to_string(),
                "Set password length".to_string(),
                Check::SecurityPolicy {
                    section: "System Access".to_string(),
                    key: "MinimumPasswordLength".to_string(),
                },
                ExpectedResult::Equals { value: json!(14) },
            ),
        ];

        let plan = build_remediation_plan("Linux fixes", "host01", &items, ScriptFormat::Bash);

        assert_eq!(plan.scripts.len(), 1);
        assert_eq!(plan.findings_addressed(), 1);
        assert_eq!(plan.scripts[0].vuln_ids, vec!["V-100006"]);
        assert!(plan.scripts[0].content.contains("systemctl enable --now"));
    }
}
