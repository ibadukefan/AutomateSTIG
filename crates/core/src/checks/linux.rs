//! Linux check helpers.
//!
//! Parses collected Linux system data — sysctl, file permissions,
//! package lists, service statuses, etc.

use std::collections::HashMap;

use super::FilePermData;

/// Parse `sysctl -a` output into a HashMap.
pub fn parse_sysctl_output(output: &str) -> HashMap<String, String> {
    let mut results = HashMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            results.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    results
}

/// Parse `ls -la` output for file permissions.
pub fn parse_ls_permissions(output: &str, _file_path: &str) -> FilePermData {
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 9 {
            let mode_str = parts[0];
            let owner = parts[2].to_string();
            let group = parts[3].to_string();

            return FilePermData {
                owner: Some(owner),
                group: Some(group),
                mode: Some(parse_symbolic_to_octal(mode_str)),
                exists: true,
            };
        }
    }

    FilePermData {
        exists: false,
        ..Default::default()
    }
}

/// Parse `stat -c '%a %U %G'` output.
pub fn parse_stat_output(output: &str) -> FilePermData {
    let parts: Vec<&str> = output.split_whitespace().collect();
    if parts.len() >= 3 {
        FilePermData {
            mode: Some(format!("0{}", parts[0])),
            owner: Some(parts[1].to_string()),
            group: Some(parts[2].to_string()),
            exists: true,
        }
    } else {
        FilePermData {
            exists: false,
            ..Default::default()
        }
    }
}

/// Parse `systemctl list-units --type=service --all --no-pager` output.
pub fn parse_systemctl_output(output: &str) -> HashMap<String, String> {
    let mut results = HashMap::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let name = parts[0]
                .trim_start_matches('\u{25CF}')
                .trim_start()
                .trim_end_matches(".service");
            let active = parts[2]; // "active" or "inactive"
            results.insert(name.to_string(), active.to_string());
        }
    }
    results
}

/// Parse `rpm -qa --queryformat '%{NAME}\n'` output into installed packages.
/// If given raw `rpm -qa` output (name-version-release.arch), extracts the
/// name portion by splitting from the right at version boundaries.
pub fn parse_rpm_packages(output: &str) -> HashMap<String, bool> {
    let mut packages = HashMap::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // If the output is from `rpm -qa --queryformat '%{NAME}\n'`, each line is
        // just the package name. If it's raw `rpm -qa`, it's name-version-release.arch.
        // Heuristic: if the line contains no '.', it's likely just a name.
        // Otherwise, try to extract name by finding the last segment that starts
        // with a digit (version), and take everything before it.
        let name = extract_rpm_name(trimmed);
        packages.insert(name, true);
    }
    packages
}

/// Extract the package name from an RPM NVRA string (e.g., "openssh-server-8.7p1-34.el9.x86_64").
fn extract_rpm_name(nvra: &str) -> String {
    // If there's no digit after a hyphen, treat the whole string as the name
    // (it's likely from --queryformat '%{NAME}\n').
    let bytes = nvra.as_bytes();
    let mut last_name_end = nvra.len();

    // Walk backwards looking for `-<digit>` which marks the start of the version.
    for i in (1..nvra.len()).rev() {
        if bytes[i - 1] == b'-' && bytes[i].is_ascii_digit() {
            last_name_end = i - 1;
            break;
        }
    }

    nvra[..last_name_end].to_string()
}

/// Parse `dpkg -l` output.
pub fn parse_dpkg_packages(output: &str) -> HashMap<String, bool> {
    let mut packages = HashMap::new();
    for line in output.lines() {
        if line.starts_with("ii") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                packages.insert(parts[1].to_string(), true);
            }
        }
    }
    packages
}

/// Convert symbolic permissions (e.g., "-rw-r-----") to octal (e.g., "0640").
fn parse_symbolic_to_octal(symbolic: &str) -> String {
    if symbolic.len() < 10 {
        return symbolic.to_string();
    }

    let chars: Vec<char> = symbolic.chars().collect();
    let owner = perm_bits(chars[1], chars[2], chars[3]);
    let group = perm_bits(chars[4], chars[5], chars[6]);
    let other = perm_bits(chars[7], chars[8], chars[9]);

    format!("0{}{}{}", owner, group, other)
}

fn perm_bits(r: char, w: char, x: char) -> u8 {
    let mut bits = 0u8;
    if r != '-' { bits += 4; }
    if w != '-' { bits += 2; }
    if x != '-' && x != 'S' && x != 'T' { bits += 1; }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sysctl() {
        let output = "net.ipv4.ip_forward = 0\nkernel.randomize_va_space = 2\n";
        let result = parse_sysctl_output(output);
        assert_eq!(result.get("net.ipv4.ip_forward"), Some(&"0".to_string()));
        assert_eq!(result.get("kernel.randomize_va_space"), Some(&"2".to_string()));
    }

    #[test]
    fn test_parse_stat() {
        let output = "640 root shadow";
        let result = parse_stat_output(output);
        assert_eq!(result.mode.as_deref(), Some("0640"));
        assert_eq!(result.owner.as_deref(), Some("root"));
        assert_eq!(result.group.as_deref(), Some("shadow"));
    }

    #[test]
    fn test_symbolic_to_octal() {
        assert_eq!(parse_symbolic_to_octal("-rwxr-xr-x"), "0755");
        assert_eq!(parse_symbolic_to_octal("-rw-r-----"), "0640");
        assert_eq!(parse_symbolic_to_octal("-rw-------"), "0600");
    }

    #[test]
    fn test_parse_dpkg() {
        let output = "ii  openssh-server  1:8.9p1  amd64  secure shell server\nii  aide  0.17  amd64  file integrity checker\n";
        let result = parse_dpkg_packages(output);
        assert!(result.contains_key("openssh-server"));
        assert!(result.contains_key("aide"));
    }
}
