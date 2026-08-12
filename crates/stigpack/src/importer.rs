//! Stigpack importer — extracts and imports .stigpack content into the STIG library.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use automatestig_core::checks::CheckPack;
use automatestig_core::library::{
    BenchmarkImport, GeneratedCheckPackIntent, LibraryFileImport, StigLibrary,
    TrustedExecutableFileImport, TrustedExecutablePackImport,
};
use automatestig_core::models::stig::StigBenchmark;

use crate::signing::TrustStore;
use crate::{StigpackError, StigpackResult};

/// Import result with details about what was imported.
#[derive(Debug)]
pub struct ImportResult {
    /// Pack ID that was imported.
    pub pack_id: String,

    /// Pack version.
    pub pack_version: String,

    /// Number of benchmarks imported.
    pub benchmarks_imported: usize,

    /// Number of answer templates imported.
    pub answer_templates_imported: usize,

    /// Number of curated custom check files imported.
    pub custom_checks_imported: usize,

    /// Number of generated check-pack files imported.
    pub auto_check_packs_imported: usize,

    /// Any warnings during import.
    pub warnings: Vec<String>,
}

/// Import a .stigpack file without establishing signature trust.
///
/// This explicit bypass is for isolated tests and lab workflows only. Normal
/// callers must use [`import_pack_trusted`]. Steps:
/// 1. Verify pack integrity (SHA-256 hashes).
/// 2. Verify signature (if present).
/// 3. Extract benchmarks and add to library.
/// 4. Extract answer templates and executable check packs.
pub fn import_pack_untrusted(
    pack_path: &Path,
    library: &mut StigLibrary,
) -> StigpackResult<ImportResult> {
    let prepared = crate::verifier::prepare_pack(pack_path, None, false)?;
    import_prepared_pack(prepared, library)
}

/// Import a .stigpack file after verifying its signature against a trust store.
pub fn import_pack_trusted(
    pack_path: &Path,
    library: &mut StigLibrary,
    trust_store: &TrustStore,
) -> StigpackResult<ImportResult> {
    let prepared = crate::verifier::prepare_pack(pack_path, Some(trust_store), true)?;
    import_prepared_pack(prepared, library)
}

fn import_prepared_pack(
    prepared: crate::verifier::PreparedPack,
    library: &mut StigLibrary,
) -> StigpackResult<ImportResult> {
    let crate::verifier::PreparedPack {
        manifest,
        manifest_json,
        signature,
        trusted_signing_public_key,
        contents,
        verification,
    } = prepared;

    // Step 1 & 2: Verify.
    if !verification.manifest_valid {
        return Err(StigpackError::ManifestError(
            "Failed to parse manifest".to_string(),
        ));
    }
    if !verification.integrity_valid {
        return Err(StigpackError::IntegrityError {
            file: "pack".to_string(),
            expected: "valid".to_string(),
            actual: format!("integrity failures: {:?}", verification.issues),
        });
    }
    let executable_content_trusted = verification.signature_valid == Some(true);

    let mut result = ImportResult {
        pack_id: manifest.pack_id.clone(),
        pack_version: manifest.version.clone(),
        benchmarks_imported: 0,
        answer_templates_imported: 0,
        custom_checks_imported: 0,
        auto_check_packs_imported: 0,
        warnings: Vec::new(),
    };

    // Parse and validate every structured artifact before changing the library.
    let mut benchmarks = Vec::new();
    let mut auto_check_packs = BTreeMap::new();
    let mut ancillary = Vec::new();
    let mut executable_provenance_paths = Vec::new();
    for path in manifest.files.keys() {
        crate::validate_member_path(path)?;
        if path.starts_with("benchmarks/") && path.ends_with(".json") {
            let content = contents
                .get(path)
                .ok_or_else(|| StigpackError::MissingFile(path.clone()))?;
            let benchmark: StigBenchmark = serde_json::from_slice(content).map_err(|error| {
                StigpackError::ManifestError(format!("invalid benchmark {path}: {error}"))
            })?;
            benchmarks.push(benchmark);
        }

        if path.starts_with("answer_templates/") {
            let content = contents
                .get(path)
                .ok_or_else(|| StigpackError::MissingFile(path.clone()))?;
            std::str::from_utf8(content).map_err(|error| {
                StigpackError::InvalidPack(format!(
                    "answer template {path} is not valid UTF-8: {error}"
                ))
            })?;
            ancillary.push((path.clone(), content.as_slice()));
            result.answer_templates_imported += 1;
        }

        if path.starts_with("custom_checks/") {
            if !executable_content_trusted {
                return Err(StigpackError::SignatureError(
                    "trusted signature required to import executable custom checks".to_string(),
                ));
            }
            let content = contents
                .get(path)
                .ok_or_else(|| StigpackError::MissingFile(path.clone()))?;
            let pack = parse_check_pack(path, content)?;
            validate_check_pack(path, &pack)?;
            ancillary.push((path.clone(), content.as_slice()));
            executable_provenance_paths.push((path.clone(), path.clone()));
            result.custom_checks_imported += 1;
        }

        if path.starts_with("auto_check_packs/") {
            if !executable_content_trusted {
                return Err(StigpackError::SignatureError(
                    "trusted signature required to import executable generated checks".to_string(),
                ));
            }
            let content = contents
                .get(path)
                .ok_or_else(|| StigpackError::MissingFile(path.clone()))?;
            let pack = parse_check_pack(path, content)?;
            validate_check_pack(path, &pack)?;
            validate_auto_check_pack_path(path, &pack)?;
            let stig_id = pack.stig_id.clone();
            if auto_check_packs
                .insert(stig_id.clone(), (path.clone(), pack))
                .is_some()
            {
                return Err(StigpackError::InvalidPack(format!(
                    "multiple auto check packs target benchmark {stig_id}"
                )));
            }
            result.auto_check_packs_imported += 1;
        }
    }

    // The archive name remains compatible with existing signed .stigpack
    // producers, but trusted generated content is promoted into a directory
    // that runtime loaders can distinguish from stale local prose output.
    for (path, _) in auto_check_packs.values() {
        let content = contents
            .get(path)
            .ok_or_else(|| StigpackError::MissingFile(path.clone()))?;
        let filename = path
            .strip_prefix("auto_check_packs/")
            .expect("validated auto check-pack prefix");
        ancillary.push((
            format!("reviewed_check_packs/{filename}"),
            content.as_slice(),
        ));
        executable_provenance_paths
            .push((format!("reviewed_check_packs/{filename}"), path.clone()));
    }

    let imports: Vec<_> = benchmarks
        .iter()
        // Remove any legacy, locally prose-generated pack for the benchmark.
        // Its signed replacement (when present) is staged above in the reviewed
        // directory in the same durable transaction.
        .map(|benchmark| BenchmarkImport::new(benchmark, GeneratedCheckPackIntent::Remove))
        .collect();

    // Benchmarks, reviewed generated packs, templates, and curated checks share
    // one journal and one durable commit point.
    let ancillary_files = ancillary
        .iter()
        .map(|(relative_path, bytes)| LibraryFileImport {
            relative_path,
            bytes,
        })
        .collect::<Vec<_>>();
    let trusted_files = executable_provenance_paths
        .iter()
        .map(
            |(relative_path, manifest_member_path)| TrustedExecutableFileImport {
                relative_path,
                manifest_member_path,
            },
        )
        .collect::<Vec<_>>();
    let trusted_pack = if trusted_files.is_empty() {
        Vec::new()
    } else {
        let signature = signature.as_deref().ok_or_else(|| {
            StigpackError::SignatureError(
                "trusted executable import is missing its manifest signature".to_string(),
            )
        })?;
        let signing_public_key = trusted_signing_public_key.as_ref().ok_or_else(|| {
            StigpackError::SignatureError(
                "trusted executable import is missing its verified signing key".to_string(),
            )
        })?;
        let signing_key_fingerprint =
            manifest.signing_key_fingerprint.as_deref().ok_or_else(|| {
                StigpackError::SignatureError(
                    "trusted executable import is missing its signing-key fingerprint".to_string(),
                )
            })?;
        vec![TrustedExecutablePackImport {
            pack_id: &manifest.pack_id,
            pack_version: &manifest.version,
            signing_key_fingerprint,
            signing_public_key,
            manifest_json: &manifest_json,
            signature,
            files: &trusted_files,
        }]
    };
    library
        .import_benchmarks_and_files_with_provenance(&imports, &ancillary_files, &trusted_pack)
        .map_err(|error| StigpackError::Library(error.to_string()))?;
    result.benchmarks_imported = benchmarks.len();

    Ok(result)
}

/// Safely join a path from a ZIP entry onto a root, preventing path traversal.
/// Returns None if the resolved path would escape the root directory.
#[cfg(test)]
fn safe_join_path(root: &Path, relative: &str) -> Option<std::path::PathBuf> {
    crate::validate_member_path(relative).ok()?;
    let dest = root.join(relative);
    if dest.starts_with(root) {
        Some(dest)
    } else {
        None
    }
}

fn parse_check_pack(path: &str, content: &[u8]) -> StigpackResult<CheckPack> {
    let text = std::str::from_utf8(content).map_err(|error| {
        StigpackError::InvalidPack(format!("check pack {path} is not valid UTF-8: {error}"))
    })?;
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("json") => serde_json::from_str(text).map_err(|error| {
            StigpackError::InvalidPack(format!("invalid check pack {path}: {error}"))
        }),
        Some("yaml" | "yml") => serde_norway::from_str(text).map_err(|error| {
            StigpackError::InvalidPack(format!("invalid check pack {path}: {error}"))
        }),
        _ => Err(StigpackError::InvalidPack(format!(
            "check pack must use .json, .yaml, or .yml: {path}"
        ))),
    }
}

fn validate_check_pack(path: &str, pack: &CheckPack) -> StigpackResult<()> {
    if pack.stig_id.trim().is_empty() {
        return Err(StigpackError::InvalidPack(format!(
            "check pack {path} has an empty STIG ID"
        )));
    }
    let mut vuln_ids = HashSet::new();
    for definition in &pack.checks {
        if definition.vuln_id.trim().is_empty() {
            return Err(StigpackError::InvalidPack(format!(
                "check pack {path} contains an empty vulnerability ID"
            )));
        }
        if definition.platform != pack.platform {
            return Err(StigpackError::InvalidPack(format!(
                "check {} platform does not match check pack {path}",
                definition.vuln_id
            )));
        }
        if !vuln_ids.insert(definition.vuln_id.as_str()) {
            return Err(StigpackError::InvalidPack(format!(
                "check pack {path} contains duplicate vulnerability ID {}",
                definition.vuln_id
            )));
        }
    }
    automatestig_core::check_packs::validate_pack(pack).map_err(|error| {
        StigpackError::InvalidPack(format!("check pack {path} is not executable: {error}"))
    })
}

fn validate_auto_check_pack_path(path: &str, pack: &CheckPack) -> StigpackResult<()> {
    let relative = path.strip_prefix("auto_check_packs/").ok_or_else(|| {
        StigpackError::InvalidPack(format!("invalid auto check-pack path: {path}"))
    })?;
    if relative.contains('/') {
        return Err(StigpackError::InvalidPack(format!(
            "auto check packs must be direct files under auto_check_packs/: {path}"
        )));
    }
    let stem = Path::new(relative)
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| StigpackError::InvalidPack(format!("invalid check-pack name: {path}")))?;
    let expected = automatestig_core::path_safety::safe_filename(&pack.stig_id)
        .map_err(|error| StigpackError::InvalidPack(error.to_string()))?;
    if stem != expected {
        return Err(StigpackError::InvalidPack(format!(
            "auto check-pack filename {stem:?} does not match its STIG ID {:?}",
            pack.stig_id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::PackBuilder;
    use crate::signing::{generate_keypair, TrustStore};
    use automatestig_core::checks::{CheckPack, CheckPlatform};
    use automatestig_core::models::stig::*;

    fn make_test_benchmark() -> StigBenchmark {
        StigBenchmark {
            id: "General_Purpose_Operating_System".to_string(),
            title: "General Purpose Operating System".to_string(),
            description: "Test".to_string(),
            version: "3".to_string(),
            release: "3".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: Platform {
                family: "test".to_string(),
                name: "Test".to_string(),
                cpe: vec![],
            },
            rules: vec![StigRule {
                vuln_id: "V-1".to_string(),
                rule_id: "SV-1".to_string(),
                group_id: "V-1".to_string(),
                group_title: "V-1".to_string(),
                title: "Test Rule".to_string(),
                rule_version: "V-1".to_string(),
                discussion: "Test".to_string(),
                severity: Severity::Medium,
                check_content: "Check".to_string(),
                fix_text: "Fix".to_string(),
                cci_refs: vec![],
                legacy_ids: vec![],
                stig_ref: None,
                weight: 8.0,
                automatable: CheckAutomation::Manual,
            }],
        }
    }

    #[test]
    fn rejects_unsafe_pack_member_paths() {
        for path in [
            "",
            "/absolute/file",
            "../escape.json",
            "benchmarks/../../escape.json",
            "benchmarks\\evil.json",
            "benchmarks/evil\0.json",
        ] {
            assert!(
                crate::validate_member_path(path).is_err(),
                "{path} should be rejected"
            );
            assert!(safe_join_path(Path::new("/tmp/stiglib"), path).is_none());
        }
        assert!(crate::validate_member_path("benchmarks/Test_STIG.json").is_ok());
    }

    #[test]
    fn test_import_pack() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("test.stigpack");
        let lib_path = dir.path().join("stiglib");

        // Build a test pack with a benchmark.
        let benchmark = make_test_benchmark();
        let benchmark_json = serde_json::to_string_pretty(&benchmark).unwrap();
        let check_pack = CheckPack {
            stig_id: benchmark.id.clone(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![],
        };
        let check_pack_json = serde_json::to_vec(&check_pack).unwrap();

        let (private_key, public_key) = generate_keypair().unwrap();
        PackBuilder::new("test-pack", "Test Pack", "1.0.0")
            .signing_key(private_key)
            .add_file_bytes(
                "benchmarks/General_Purpose_Operating_System.json",
                benchmark_json.as_bytes(),
            )
            .add_file_bytes(
                "custom_checks/General_Purpose_Operating_System.json",
                &check_pack_json,
            )
            .add_file_bytes(
                "auto_check_packs/General_Purpose_Operating_System.json",
                &check_pack_json,
            )
            .build(&pack_path)
            .unwrap();

        // Import into a fresh library.
        let mut library = StigLibrary::init(&lib_path).unwrap();
        let mut trust = TrustStore::new();
        trust.add_key("test", public_key);
        let result = import_pack_trusted(&pack_path, &mut library, &trust).unwrap();

        assert_eq!(result.pack_id, "test-pack");
        assert_eq!(result.benchmarks_imported, 1);
        assert_eq!(result.custom_checks_imported, 1);
        assert_eq!(result.auto_check_packs_imported, 1);
        assert!(result.warnings.is_empty());
        assert!(lib_path
            .join("custom_checks/General_Purpose_Operating_System.json")
            .exists());
        assert!(lib_path
            .join("reviewed_check_packs/General_Purpose_Operating_System.json")
            .exists());
        assert!(!lib_path
            .join("auto_check_packs/General_Purpose_Operating_System.json")
            .exists());
        let trusted_keys = trust.public_keys();
        assert_eq!(
            library
                .load_trusted_executable_files("custom_checks", &trusted_keys)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            library
                .load_trusted_executable_files("reviewed_check_packs", &trusted_keys)
                .unwrap()
                .len(),
            1
        );
        assert!(library
            .load_trusted_executable_files("custom_checks", &[])
            .is_err());

        // Verify the benchmark is now in the library.
        let loaded = library
            .load_benchmark("General_Purpose_Operating_System")
            .unwrap();
        assert_eq!(loaded.title, "General Purpose Operating System");
        assert_eq!(loaded.rules.len(), 1);
    }

    #[test]
    fn runtime_rejects_bare_and_post_import_modified_executable_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("trusted.stigpack");
        let lib_path = dir.path().join("library");
        let check_pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![],
        };
        let check_pack_json = serde_json::to_vec(&check_pack).unwrap();
        let (private_key, public_key) = generate_keypair().unwrap();
        PackBuilder::new("trusted", "Trusted", "1.0.0")
            .signing_key(private_key)
            .add_file_bytes(
                "custom_checks/General_Purpose_Operating_System.json",
                &check_pack_json,
            )
            .build(&pack_path)
            .unwrap();

        let mut trust = TrustStore::new();
        trust.add_key("test", public_key);
        let trusted_keys = trust.public_keys();
        let mut library = StigLibrary::init(&lib_path).unwrap();
        import_pack_trusted(&pack_path, &mut library, &trust).unwrap();

        let catalog_path = lib_path.join("trusted-executable-content.json");
        let original_catalog = std::fs::read(&catalog_path).unwrap();
        let mut catalog: serde_json::Value = serde_json::from_slice(&original_catalog).unwrap();
        let proofs = catalog["proofs"].as_object_mut().unwrap();
        proofs.values_mut().next().unwrap()["pack_version"] =
            serde_json::Value::String("forged".to_string());
        std::fs::write(&catalog_path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();
        assert!(library
            .load_trusted_executable_files("custom_checks", &trusted_keys)
            .is_err());
        std::fs::write(&catalog_path, original_catalog).unwrap();

        let installed = lib_path.join("custom_checks/General_Purpose_Operating_System.json");
        std::fs::write(&installed, b"{}").unwrap();
        assert!(library
            .load_trusted_executable_files("custom_checks", &trusted_keys)
            .is_err());

        let bare = lib_path.join("reviewed_check_packs/bare.json");
        std::fs::write(&bare, check_pack_json).unwrap();
        assert!(library
            .load_trusted_executable_files("reviewed_check_packs", &trusted_keys)
            .is_err());
    }

    #[test]
    fn benchmark_without_generated_pack_removes_stale_installed_pack() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("benchmark-only.stigpack");
        let lib_path = dir.path().join("stiglib");
        let benchmark = make_test_benchmark();
        let generated = CheckPack {
            stig_id: benchmark.id.clone(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![],
        };
        let mut library = StigLibrary::init(&lib_path).unwrap();
        library
            .import_benchmarks(&[BenchmarkImport::new(
                &benchmark,
                GeneratedCheckPackIntent::Replace(&generated),
            )])
            .unwrap();
        let generated_path =
            lib_path.join("auto_check_packs/General_Purpose_Operating_System.json");
        assert!(generated_path.exists());

        PackBuilder::new("benchmark-only", "Benchmark Only", "2.0.0")
            .add_file_bytes(
                "benchmarks/General_Purpose_Operating_System.json",
                &serde_json::to_vec_pretty(&benchmark).unwrap(),
            )
            .build(&pack_path)
            .unwrap();
        import_pack_untrusted(&pack_path, &mut library).unwrap();

        assert!(!generated_path.exists());
        assert_eq!(
            library
                .load_benchmark("General_Purpose_Operating_System")
                .unwrap()
                .id,
            "General_Purpose_Operating_System"
        );
    }

    #[test]
    fn invalid_structured_content_makes_no_library_changes() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("invalid.stigpack");
        let lib_path = dir.path().join("stiglib");
        let benchmark = make_test_benchmark();
        let benchmark_json = serde_json::to_vec_pretty(&benchmark).unwrap();

        let (private_key, public_key) = generate_keypair().unwrap();
        PackBuilder::new("test-pack", "Test Pack", "1.0.0")
            .signing_key(private_key)
            .add_file_bytes(
                "benchmarks/General_Purpose_Operating_System.json",
                &benchmark_json,
            )
            .add_file_bytes("custom_checks/invalid.json", br#"{"checks":[]}"#)
            .build(&pack_path)
            .unwrap();

        let mut library = StigLibrary::init(&lib_path).unwrap();
        let mut trust = TrustStore::new();
        trust.add_key("test", public_key);
        assert!(import_pack_trusted(&pack_path, &mut library, &trust).is_err());
        assert!(library.list_benchmarks().is_empty());
        assert!(!lib_path
            .join("benchmarks/General_Purpose_Operating_System.json")
            .exists());
        assert!(!lib_path.join("custom_checks/invalid.json").exists());
    }

    #[test]
    fn ancillary_files_roll_back_when_atomic_benchmark_batch_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("duplicate.stigpack");
        let lib_path = dir.path().join("stiglib");
        let benchmark = make_test_benchmark();
        let benchmark_json = serde_json::to_vec_pretty(&benchmark).unwrap();

        PackBuilder::new("test-pack", "Test Pack", "1.0.0")
            .add_file_bytes("benchmarks/first.json", &benchmark_json)
            .add_file_bytes("benchmarks/second.json", &benchmark_json)
            .add_file_bytes("answer_templates/test.yaml", b"new: value\n")
            .build(&pack_path)
            .unwrap();

        let mut library = StigLibrary::init(&lib_path).unwrap();
        let answer = lib_path.join("answer_templates/test.yaml");
        std::fs::write(&answer, b"old: value\n").unwrap();

        assert!(import_pack_untrusted(&pack_path, &mut library).is_err());
        assert!(library.list_benchmarks().is_empty());
        assert_eq!(std::fs::read(answer).unwrap(), b"old: value\n");
    }

    #[test]
    fn trusted_pack_can_install_a_valid_standalone_auto_check_pack() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("standalone.stigpack");
        let lib_path = dir.path().join("stiglib");
        let check_pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![],
        };
        let check_pack_json = serde_json::to_vec(&check_pack).unwrap();
        let (private_key, public_key) = generate_keypair().unwrap();
        PackBuilder::new("test-pack", "Test Pack", "1.0.0")
            .signing_key(private_key)
            .add_file_bytes(
                "auto_check_packs/General_Purpose_Operating_System.json",
                &check_pack_json,
            )
            .build(&pack_path)
            .unwrap();

        let mut trust = TrustStore::new();
        trust.add_key("test", public_key);
        let mut library = StigLibrary::init(&lib_path).unwrap();
        let imported = import_pack_trusted(&pack_path, &mut library, &trust).unwrap();
        assert_eq!(imported.auto_check_packs_imported, 1);
        assert!(library.list_benchmarks().is_empty());
        assert!(lib_path
            .join("reviewed_check_packs/General_Purpose_Operating_System.json")
            .exists());

        // Re-packing uses the compatible archive prefix, and a second trusted
        // import promotes the same reviewed bytes again rather than reviving the
        // quarantined legacy directory.
        let repacked = dir.path().join("repacked.stigpack");
        let (second_private, second_public) = generate_keypair().unwrap();
        PackBuilder::new("repacked", "Repacked", "1.0.0")
            .signing_key(second_private)
            .add_directory("auto_check_packs", &lib_path.join("reviewed_check_packs"))
            .unwrap()
            .build(&repacked)
            .unwrap();
        let second_lib = dir.path().join("second-library");
        let mut second_library = StigLibrary::init(&second_lib).unwrap();
        let mut second_trust = TrustStore::new();
        second_trust.add_key("second", second_public);
        import_pack_trusted(&repacked, &mut second_library, &second_trust).unwrap();
        assert!(second_lib
            .join("reviewed_check_packs/General_Purpose_Operating_System.json")
            .exists());
        assert!(!second_lib.join("auto_check_packs").exists());
    }

    #[test]
    fn unsigned_import_cannot_install_executable_checks() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("unsigned-executable.stigpack");
        let lib_path = dir.path().join("library");
        let check_pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![],
        };
        PackBuilder::new("unsigned", "Unsigned", "1.0.0")
            .add_file_bytes(
                "auto_check_packs/General_Purpose_Operating_System.json",
                &serde_json::to_vec(&check_pack).unwrap(),
            )
            .build(&pack_path)
            .unwrap();
        let mut library = StigLibrary::init(&lib_path).unwrap();
        assert!(matches!(
            import_pack_untrusted(&pack_path, &mut library),
            Err(StigpackError::SignatureError(_))
        ));
        assert!(!lib_path
            .join("reviewed_check_packs/General_Purpose_Operating_System.json")
            .exists());
    }

    #[test]
    fn standalone_auto_check_pack_filename_must_match_its_stig_id() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("mismatched.stigpack");
        let lib_path = dir.path().join("stiglib");
        let check_pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![],
        };
        let (private_key, public_key) = generate_keypair().unwrap();
        PackBuilder::new("test-pack", "Test Pack", "1.0.0")
            .signing_key(private_key)
            .add_file_bytes(
                "auto_check_packs/Wrong_STIG.json",
                &serde_json::to_vec(&check_pack).unwrap(),
            )
            .build(&pack_path)
            .unwrap();

        let mut library = StigLibrary::init(&lib_path).unwrap();
        let mut trust = TrustStore::new();
        trust.add_key("test", public_key);
        assert!(import_pack_trusted(&pack_path, &mut library, &trust).is_err());
        assert!(!lib_path.join("auto_check_packs/Wrong_STIG.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn ancillary_install_rejects_symlinked_parent_without_external_write() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("symlink-parent.stigpack");
        let lib_path = dir.path().join("stiglib");
        let external = dir.path().join("external");
        std::fs::create_dir(&external).unwrap();

        let check_pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "V3R3".to_string(),
            priority: 100,
            checks: vec![],
        };
        let (private_key, public_key) = generate_keypair().unwrap();
        PackBuilder::new("test-pack", "Test Pack", "1.0.0")
            .signing_key(private_key)
            .add_file_bytes(
                "custom_checks/General_Purpose_Operating_System.json",
                &serde_json::to_vec(&check_pack).unwrap(),
            )
            .build(&pack_path)
            .unwrap();

        let mut library = StigLibrary::init(&lib_path).unwrap();
        std::fs::remove_dir(lib_path.join("custom_checks")).unwrap();
        symlink(&external, lib_path.join("custom_checks")).unwrap();

        let mut trust = TrustStore::new();
        trust.add_key("test", public_key);
        assert!(import_pack_trusted(&pack_path, &mut library, &trust).is_err());
        assert!(!external
            .join("General_Purpose_Operating_System.json")
            .exists());
    }
}
