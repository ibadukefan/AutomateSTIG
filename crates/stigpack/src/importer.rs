//! Stigpack importer — extracts and imports .stigpack content into the STIG library.

use std::io::Read;
use std::path::Path;

use automatestig_core::library::StigLibrary;
use automatestig_core::models::stig::StigBenchmark;

use crate::signing::TrustStore;
use crate::verifier::{verify_pack, verify_pack_with_trust};
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

    /// Number of remediation scripts imported.
    pub remediation_scripts_imported: usize,

    /// Any warnings during import.
    pub warnings: Vec<String>,
}

/// Import a .stigpack file into the STIG library.
///
/// This is the primary entry point for the "Import Update" workflow.
/// Steps:
/// 1. Verify pack integrity (SHA-256 hashes).
/// 2. Verify signature (if present).
/// 3. Extract benchmarks and add to library.
/// 4. Extract answer templates and remediation scripts.
pub fn import_pack(pack_path: &Path, library: &mut StigLibrary) -> StigpackResult<ImportResult> {
    // Existing programmatic/import tests use integrity verification only. UI and
    // production callers should use import_pack_trusted when policy requires
    // trusted signatures.
    import_pack_with_verification(pack_path, library, verify_pack(pack_path)?)
}

/// Import a .stigpack file after verifying its signature against a trust store.
pub fn import_pack_trusted(
    pack_path: &Path,
    library: &mut StigLibrary,
    trust_store: &TrustStore,
) -> StigpackResult<ImportResult> {
    let verification = verify_pack_with_trust(pack_path, Some(trust_store))?;
    if verification.signature_valid != Some(true) {
        return Err(StigpackError::SignatureError(format!(
            "trusted signature required for .stigpack import: {:?}",
            verification.issues
        )));
    }
    import_pack_with_verification(pack_path, library, verification)
}

fn import_pack_with_verification(
    pack_path: &Path,
    library: &mut StigLibrary,
    verification: crate::verifier::VerificationResult,
) -> StigpackResult<ImportResult> {
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

    // Step 3: Extract and import.
    let file = std::fs::File::open(pack_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    // Read manifest.
    let manifest = {
        let mut mf = archive
            .by_name("manifest.json")
            .map_err(StigpackError::Zip)?;
        let mut json = String::new();
        mf.read_to_string(&mut json)?;
        crate::manifest::PackManifest::from_json(&json)
            .map_err(|e| StigpackError::ManifestError(e.to_string()))?
    };

    let mut result = ImportResult {
        pack_id: manifest.pack_id.clone(),
        pack_version: manifest.version.clone(),
        benchmarks_imported: 0,
        answer_templates_imported: 0,
        remediation_scripts_imported: 0,
        warnings: Vec::new(),
    };

    // Import benchmarks.
    for path in manifest.files.keys() {
        if path.starts_with("benchmarks/") && path.ends_with(".json") {
            match read_zip_file(&mut archive, path) {
                Ok(content) => {
                    let json = String::from_utf8_lossy(&content);
                    match serde_json::from_str::<StigBenchmark>(&json) {
                        Ok(benchmark) => {
                            if let Err(e) = library.add_benchmark(&benchmark) {
                                result
                                    .warnings
                                    .push(format!("Failed to add benchmark {}: {}", path, e));
                            } else {
                                result.benchmarks_imported += 1;
                            }
                        }
                        Err(e) => {
                            result
                                .warnings
                                .push(format!("Failed to parse benchmark {}: {}", path, e));
                        }
                    }
                }
                Err(e) => {
                    result
                        .warnings
                        .push(format!("Failed to read {}: {}", path, e));
                }
            }
        }

        // Copy answer templates to library.
        if path.starts_with("answer_templates/") {
            if let Some(dest) = safe_join_path(library.root(), path) {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if let Ok(content) = read_zip_file(&mut archive, path) {
                    std::fs::write(&dest, &content)?;
                    result.answer_templates_imported += 1;
                }
            } else {
                result
                    .warnings
                    .push(format!("Rejected unsafe path: {}", path));
            }
        }

        // Copy remediation scripts to library.
        if path.starts_with("remediation/") {
            if let Some(dest) = safe_join_path(library.root(), path) {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if let Ok(content) = read_zip_file(&mut archive, path) {
                    std::fs::write(&dest, &content)?;
                    result.remediation_scripts_imported += 1;
                }
            } else {
                result
                    .warnings
                    .push(format!("Rejected unsafe path: {}", path));
            }
        }
    }

    Ok(result)
}

/// Safely join a path from a ZIP entry onto a root, preventing path traversal.
/// Returns None if the resolved path would escape the root directory.
fn safe_join_path(root: &Path, relative: &str) -> Option<std::path::PathBuf> {
    // Reject paths containing ".." components or absolute paths.
    if relative.contains("..") || relative.starts_with('/') || relative.starts_with('\\') {
        return None;
    }
    let dest = root.join(relative);
    // Canonicalize-style check: ensure the resolved path starts with root.
    // Since the directories may not exist yet, we check component-by-component.
    let root_canonical = root.to_path_buf();
    if dest.starts_with(&root_canonical) {
        Some(dest)
    } else {
        None
    }
}

fn read_zip_file(
    archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> StigpackResult<Vec<u8>> {
    let mut file = archive
        .by_name(name)
        .map_err(|_| StigpackError::MissingFile(name.to_string()))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::PackBuilder;
    use automatestig_core::models::stig::*;

    fn make_test_benchmark() -> StigBenchmark {
        StigBenchmark {
            id: "Test_STIG".to_string(),
            title: "Test STIG".to_string(),
            description: "Test".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
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
                title: "Test Rule".to_string(),
                discussion: "Test".to_string(),
                severity: Severity::Medium,
                check_content: "Check".to_string(),
                fix_text: "Fix".to_string(),
                cci_refs: vec![],
                legacy_ids: vec![],
                stig_ref: None,
                weight: 8.0,
                automatable: CheckAutomation::Manual,
                automated_check: None,
                remediation_ids: vec![],
            }],
        }
    }

    #[test]
    fn test_import_pack() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("test.stigpack");
        let lib_path = dir.path().join("stiglib");

        // Build a test pack with a benchmark.
        let benchmark = make_test_benchmark();
        let benchmark_json = serde_json::to_string_pretty(&benchmark).unwrap();

        PackBuilder::new("test-pack", "Test Pack", "1.0.0")
            .add_file_bytes("benchmarks/Test_STIG.json", benchmark_json.as_bytes())
            .build(&pack_path)
            .unwrap();

        // Import into a fresh library.
        let mut library = StigLibrary::init(&lib_path).unwrap();
        let result = import_pack(&pack_path, &mut library).unwrap();

        assert_eq!(result.pack_id, "test-pack");
        assert_eq!(result.benchmarks_imported, 1);
        assert!(result.warnings.is_empty());

        // Verify the benchmark is now in the library.
        let loaded = library.load_benchmark("Test_STIG").unwrap();
        assert_eq!(loaded.title, "Test STIG");
        assert_eq!(loaded.rules.len(), 1);
    }
}
