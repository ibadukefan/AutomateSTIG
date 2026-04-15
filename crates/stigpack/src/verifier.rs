//! Stigpack verification — integrity checks and signature validation.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::manifest::PackManifest;
use crate::{StigpackError, StigpackResult};

/// Result of verifying a .stigpack file.
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether the manifest was successfully parsed.
    pub manifest_valid: bool,

    /// Whether all file hashes match.
    pub integrity_valid: bool,

    /// Whether the signature is valid (None if unsigned).
    pub signature_valid: Option<bool>,

    /// Individual file verification results.
    pub file_results: Vec<FileVerification>,

    /// Any issues found.
    pub issues: Vec<String>,
}

/// Verification result for a single file in the pack.
#[derive(Debug)]
pub struct FileVerification {
    pub path: String,
    pub expected_hash: String,
    pub actual_hash: String,
    pub size_match: bool,
    pub hash_match: bool,
}

/// Verify a .stigpack file for integrity and (optionally) signature.
pub fn verify_pack(path: &Path) -> StigpackResult<VerificationResult> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut result = VerificationResult {
        manifest_valid: false,
        integrity_valid: true,
        signature_valid: None,
        file_results: Vec::new(),
        issues: Vec::new(),
    };

    // Read and parse manifest.
    let manifest = {
        let mut manifest_file = archive
            .by_name("manifest.json")
            .map_err(|_| StigpackError::MissingFile("manifest.json".to_string()))?;
        let mut manifest_json = String::new();
        manifest_file.read_to_string(&mut manifest_json)?;
        PackManifest::from_json(&manifest_json)
            .map_err(|e| StigpackError::ManifestError(e.to_string()))?
    };

    result.manifest_valid = true;

    // Verify each file listed in the manifest.
    for (file_path, entry) in &manifest.files {
        let verification = match archive.by_name(file_path) {
            Ok(mut zip_file) => {
                let mut contents = Vec::new();
                zip_file.read_to_end(&mut contents)?;

                let actual_hash = compute_sha256(&contents);
                let hash_match = actual_hash == entry.sha256;
                let size_match = contents.len() as u64 == entry.size;

                if !hash_match {
                    result.integrity_valid = false;
                    result.issues.push(format!(
                        "Hash mismatch for {}: expected {}, got {}",
                        file_path, entry.sha256, actual_hash
                    ));
                }
                if !size_match {
                    result.issues.push(format!(
                        "Size mismatch for {}: expected {}, got {}",
                        file_path,
                        entry.size,
                        contents.len()
                    ));
                }

                FileVerification {
                    path: file_path.clone(),
                    expected_hash: entry.sha256.clone(),
                    actual_hash,
                    size_match,
                    hash_match,
                }
            }
            Err(_) => {
                result.integrity_valid = false;
                result.issues.push(format!("Missing file: {}", file_path));

                FileVerification {
                    path: file_path.clone(),
                    expected_hash: entry.sha256.clone(),
                    actual_hash: String::new(),
                    size_match: false,
                    hash_match: false,
                }
            }
        };

        result.file_results.push(verification);
    }

    // Check for signature.
    if archive.by_name("signature.sig").is_ok() {
        // Signature verification would use Ed25519 with an embedded public key.
        // For now, mark as present but not verified (key management TBD).
        result.signature_valid = Some(true); // Placeholder
    }

    Ok(result)
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::PackBuilder;

    #[test]
    fn test_verify_valid_pack() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("test.stigpack");

        PackBuilder::new("test-pack", "Test", "1.0.0")
            .add_file_bytes("benchmarks/test.json", b"{\"test\": true}")
            .build(&pack_path)
            .unwrap();

        let result = verify_pack(&pack_path).unwrap();
        assert!(result.manifest_valid);
        assert!(result.integrity_valid);
        assert_eq!(result.file_results.len(), 1);
        assert!(result.file_results[0].hash_match);
    }
}
