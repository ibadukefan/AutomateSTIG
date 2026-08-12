//! FreeBSD 13–14 effective-state parsers for the reviewed GPOS V3R3 subset.
//!
//! These parsers deliberately reject malformed or ambiguous native output.
//! A syntactically valid but noncompliant state returns `Ok(false)`; evidence
//! that cannot support a determination returns `Err` and therefore remains
//! `NotReviewed` in the check executor.

use std::collections::HashSet;

use regex::Regex;

use super::SystemData;

pub(crate) const AUDITD_STATUS_COMMAND: &str = "service auditd onestatus";
pub(crate) const AUDIT_CONTROL_COMMAND: &str = "cat /etc/security/audit_control";
pub(crate) const AUDIT_USER_COMMAND: &str = "cat /etc/security/audit_user";
pub(crate) const AUDIT_CLASS_SHA256_COMMAND: &str = "sha256 -q /etc/security/audit_class";
pub(crate) const AUDIT_EVENT_SHA256_COMMAND: &str = "sha256 -q /etc/security/audit_event";
pub(crate) const PF_STATUS_COMMAND: &str = "service pf onestatus";

const APPROVED_AUDIT_CLASS_SHA256: [&str; 2] = [
    // FreeBSD 13.4/13.5 and 14.1-14.4.
    "834a1fde758a45269874a5c0655046ca7354a7afa3cf9aee8d29bbfe5d8ab2fd",
    // FreeBSD 14.0.
    "f74be6d9013137cecc953ec4b0e6b6a53fd21d221f8329cb9d65fd18737379a1",
];
const APPROVED_AUDIT_EVENT_SHA256: [&str; 2] = [
    // FreeBSD 13.4/13.5 and 14.1-14.4.
    "124c60b738ec9eb36e497213fded40a7ed9023dc7854258f9c17d5cbcfffcff2",
    // FreeBSD 14.0.
    "6c6a2929126159f08a68915069971c3b5974032d74b835db5eb560d943285a6f",
];

const AUDIT_CLASSES: [&str; 18] = [
    "fr", "fw", "fa", "fm", "fc", "fd", "cl", "pc", "nt", "ip", "na", "ad", "lo", "aa", "ap", "io",
    "ex", "ot",
];

#[derive(Debug, Default)]
struct AuditMask {
    success: HashSet<String>,
    failure: HashSet<String>,
}

impl AuditMask {
    fn includes_both(&self, classes: &[String]) -> bool {
        classes
            .iter()
            .all(|class| self.success.contains(class) && self.failure.contains(class))
    }

    fn intersects(&self, classes: &[String]) -> bool {
        classes
            .iter()
            .any(|class| self.success.contains(class) || self.failure.contains(class))
    }
}

fn audit_class_targets(value: &str) -> Result<Vec<&'static str>, String> {
    if value == "no" {
        return Ok(Vec::new());
    }
    if value == "all" {
        return Ok(AUDIT_CLASSES.to_vec());
    }
    AUDIT_CLASSES
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .map(|class| vec![class])
        .ok_or_else(|| format!("unknown FreeBSD audit class {value:?}"))
}

/// Parse OpenBSM's documented left-to-right event-selection grammar.
///
/// No prefix adds successful and failed events, `+`/`-` add one outcome,
/// and `^`, `^+`, and `^-` remove both or one outcome respectively.
fn parse_audit_mask(expression: &str) -> Result<AuditMask, String> {
    let mut mask = AuditMask::default();
    if expression.trim().is_empty() {
        return Ok(mask);
    }
    if expression != expression.trim() || expression.chars().any(char::is_whitespace) {
        return Err("audit selection expression contains whitespace".to_string());
    }

    for term in expression.split(',') {
        if term.is_empty() {
            return Err("audit selection expression contains an empty term".to_string());
        }
        let (operation, class) = if let Some(class) = term.strip_prefix("^+") {
            ("remove_success", class)
        } else if let Some(class) = term.strip_prefix("^-") {
            ("remove_failure", class)
        } else if let Some(class) = term.strip_prefix('^') {
            ("remove_both", class)
        } else if let Some(class) = term.strip_prefix('+') {
            ("add_success", class)
        } else if let Some(class) = term.strip_prefix('-') {
            ("add_failure", class)
        } else {
            ("add_both", term)
        };
        if class.is_empty() {
            return Err("audit selection prefix has no class".to_string());
        }
        for class in audit_class_targets(class)? {
            match operation {
                "remove_success" => {
                    mask.success.remove(class);
                }
                "remove_failure" => {
                    mask.failure.remove(class);
                }
                "remove_both" => {
                    mask.success.remove(class);
                    mask.failure.remove(class);
                }
                "add_success" => {
                    mask.success.insert(class.to_string());
                }
                "add_failure" => {
                    mask.failure.insert(class.to_string());
                }
                "add_both" => {
                    mask.success.insert(class.to_string());
                    mask.failure.insert(class.to_string());
                }
                _ => unreachable!("operation is selected above"),
            }
        }
    }
    Ok(mask)
}

fn audit_control_masks(document: &str) -> Result<(AuditMask, AuditMask), String> {
    let mut flags = None;
    let mut naflags = None;
    for (index, raw_line) in document.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("audit_control line {} is not a name:value entry", index + 1))?;
        if name.is_empty() || name != name.trim() || value != value.trim() {
            return Err(format!(
                "audit_control line {} has ambiguous whitespace",
                index + 1
            ));
        }
        match name {
            "flags" => {
                if flags.replace(parse_audit_mask(value)?).is_some() {
                    return Err("audit_control contains multiple flags entries".to_string());
                }
            }
            "naflags" => {
                if naflags.replace(parse_audit_mask(value)?).is_some() {
                    return Err("audit_control contains multiple naflags entries".to_string());
                }
            }
            _ => {}
        }
    }
    Ok((
        flags.ok_or_else(|| "audit_control has no flags entry".to_string())?,
        naflags.ok_or_else(|| "audit_control has no naflags entry".to_string())?,
    ))
}

fn audit_user_excludes(document: &str, classes: &[String]) -> Result<bool, String> {
    let mut users = HashSet::new();
    for (index, raw_line) in document.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 3
            || fields[0].is_empty()
            || fields.iter().any(|field| *field != field.trim())
        {
            return Err(format!(
                "audit_user line {} is not an exact user:always:never entry",
                index + 1
            ));
        }
        if !users.insert(fields[0]) {
            return Err(format!(
                "audit_user contains multiple entries for {:?}",
                fields[0]
            ));
        }
        // Validate both masks even though the global masks must independently
        // cover every account. A malformed always-audit field is ambiguous.
        parse_audit_mask(fields[1])?;
        if parse_audit_mask(fields[2])?.intersects(classes) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn command_output<'a>(data: &'a SystemData, command: &str) -> Result<&'a str, String> {
    if let Some(error) = data.collection_errors.get(command) {
        return Err(format!("Command collection failed: {error}"));
    }
    data.command_outputs
        .get(command)
        .map(String::as_str)
        .ok_or_else(|| format!("Command output not found: {command}"))
}

fn approved_sha256(output: &str, approved: &[&str], label: &str) -> Result<(), String> {
    let digest = output.trim();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} SHA-256 output is malformed"));
    }
    if !approved
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(digest))
    {
        return Err(format!(
            "{label} does not match a reviewed FreeBSD 13.4/13.5/14.x mapping"
        ));
    }
    Ok(())
}

pub(crate) fn audit_classes_selected(
    data: &SystemData,
    classes: &[String],
) -> Result<bool, String> {
    if classes.is_empty()
        || classes.iter().any(|class| {
            *class == "all" || *class == "no" || !AUDIT_CLASSES.contains(&class.as_str())
        })
    {
        return Err("typed FreeBSD audit check requested an invalid class set".to_string());
    }

    approved_sha256(
        command_output(data, AUDIT_CLASS_SHA256_COMMAND)?,
        &APPROVED_AUDIT_CLASS_SHA256,
        "audit_class",
    )?;
    approved_sha256(
        command_output(data, AUDIT_EVENT_SHA256_COMMAND)?,
        &APPROVED_AUDIT_EVENT_SHA256,
        "audit_event",
    )?;

    let auditd = command_output(data, AUDITD_STATUS_COMMAND)?;
    let running = Regex::new(r"(?i)\A\s*auditd\s+is\s+running(?:\s+as\s+pid\s+[1-9]\d*)?\.?\s*\z")
        .expect("static auditd regex")
        .is_match(auditd);
    if !running {
        let stopped = Regex::new(r"(?i)\A\s*auditd\s+is\s+not\s+running\.?\s*\z")
            .expect("static auditd stopped regex")
            .is_match(auditd);
        if stopped {
            return Ok(false);
        }
        return Err("FreeBSD auditd status output is ambiguous".to_string());
    }

    let (flags, naflags) = audit_control_masks(command_output(data, AUDIT_CONTROL_COMMAND)?)?;
    if !flags.includes_both(classes) || !naflags.includes_both(classes) {
        return Ok(false);
    }
    if audit_user_excludes(command_output(data, AUDIT_USER_COMMAND)?, classes)? {
        return Ok(false);
    }
    Ok(true)
}

pub(crate) fn pf_enabled(output: &str) -> Result<bool, String> {
    let statuses: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("Status:"))
        .collect();
    if statuses.len() != 1 {
        return Err("PF status output does not contain exactly one Status field".to_string());
    }
    let value = statuses[0]
        .strip_prefix("Status:")
        .expect("filtered prefix")
        .trim();
    if value == "Disabled" {
        return Ok(false);
    }
    if value == "Enabled" || value.starts_with("Enabled for ") {
        return Ok(true);
    }
    Err("PF status field is not a canonical Enabled or Disabled state".to_string())
}

pub(crate) fn pf_enabled_from_system_data(data: &SystemData) -> Result<bool, String> {
    pf_enabled(command_output(data, PF_STATUS_COMMAND)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_prefixes_are_applied_left_to_right() {
        let mask = parse_audit_mask("all,^all,lo,+aa,-ad").unwrap();
        assert!(mask.includes_both(&["lo".to_string()]));
        assert!(mask.success.contains("aa"));
        assert!(!mask.failure.contains("aa"));
        assert!(!mask.success.contains("ad"));
        assert!(mask.failure.contains("ad"));

        let mask = parse_audit_mask("lo,^+lo").unwrap();
        assert!(!mask.success.contains("lo"));
        assert!(mask.failure.contains("lo"));
    }

    #[test]
    fn pf_parser_distinguishes_findings_from_ambiguous_output() {
        assert!(pf_enabled("Status: Enabled for 0 days 00:02:00\n").unwrap());
        assert!(!pf_enabled("Status: Disabled\n").unwrap());
        assert!(pf_enabled("Status: maybe\n").is_err());
        assert!(pf_enabled("Status: Enabled\nStatus: Disabled\n").is_err());
    }
}
