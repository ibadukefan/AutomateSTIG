//! Stigpack verification — bounded integrity checks and signature validation.

use std::collections::BTreeMap;
use std::path::Path;

use automatestig_archive_safety::{ArchivePolicy, SafeZipArchive};
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

    /// Whether the signature is trusted (None if absent or no trust store was supplied).
    pub signature_valid: Option<bool>,

    /// Whether a signature file is present, independent of trust configuration.
    pub signature_present: bool,

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

const MAX_STIGPACK_COMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_STIGPACK_ENTRIES: usize = 1_000;
const MAX_STIGPACK_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_STIGPACK_MEMBER_BYTES: u64 = 50 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const ED25519_SIGNATURE_BYTES: u64 = 64;

pub(crate) struct PreparedPack {
    pub manifest: PackManifest,
    pub manifest_json: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub trusted_signing_public_key: Option<[u8; 32]>,
    pub contents: BTreeMap<String, Vec<u8>>,
    pub verification: VerificationResult,
}

/// Resource policy shared by every `.stigpack` verification/import path.
pub fn stigpack_archive_policy() -> ArchivePolicy {
    let mut policy = ArchivePolicy::strict(
        MAX_STIGPACK_COMPRESSED_BYTES,
        MAX_STIGPACK_ENTRIES,
        MAX_STIGPACK_MEMBER_BYTES,
        MAX_STIGPACK_UNCOMPRESSED_BYTES,
    );
    policy.max_compression_ratio = Some(100);
    policy.compression_ratio_grace_bytes = 1024 * 1024;
    policy
}

/// Verify a .stigpack file for integrity and (optionally) signature.
/// If a trust_store is provided, signature verification uses it.
/// If None, signature presence is noted but not verified against a key.
pub fn verify_pack(path: &Path) -> StigpackResult<VerificationResult> {
    verify_pack_with_trust(path, None)
}

/// Verify a .stigpack with an optional trust store for signature checking.
pub fn verify_pack_with_trust(
    path: &Path,
    trust_store: Option<&crate::signing::TrustStore>,
) -> StigpackResult<VerificationResult> {
    Ok(prepare_pack(path, trust_store, false)?.verification)
}

pub(crate) fn prepare_pack(
    path: &Path,
    trust_store: Option<&crate::signing::TrustStore>,
    require_trusted_signature: bool,
) -> StigpackResult<PreparedPack> {
    prepare_pack_with_policy(
        path,
        trust_store,
        require_trusted_signature,
        stigpack_archive_policy(),
    )
}

fn prepare_pack_with_policy(
    path: &Path,
    trust_store: Option<&crate::signing::TrustStore>,
    require_trusted_signature: bool,
    policy: ArchivePolicy,
) -> StigpackResult<PreparedPack> {
    let mut archive = SafeZipArchive::open_path(path, policy)?;
    let mut budget = archive.new_read_budget();

    let mut result = VerificationResult {
        manifest_valid: false,
        integrity_valid: true,
        signature_valid: None,
        signature_present: false,
        file_results: Vec::new(),
        issues: Vec::new(),
    };

    // The manifest and signature are tightly bounded and handled before any
    // content member is decompressed. Trusted import can therefore reject an
    // untrusted archive before doing attacker-controlled bulk work.
    if archive.entry("manifest.json").is_none() {
        return Err(StigpackError::MissingFile("manifest.json".to_string()));
    }
    let manifest_json =
        archive.read_named_with_limit("manifest.json", MAX_MANIFEST_BYTES, &mut budget)?;
    let manifest = serde_json::from_slice::<PackManifest>(&manifest_json)
        .map_err(|e| StigpackError::ManifestError(e.to_string()))?;
    manifest.validate().map_err(StigpackError::ManifestError)?;

    result.manifest_valid = true;

    let sig_bytes = if archive.entry("signature.sig").is_some() {
        let bytes =
            archive.read_named_with_limit("signature.sig", ED25519_SIGNATURE_BYTES, &mut budget)?;
        if bytes.len() as u64 != ED25519_SIGNATURE_BYTES {
            return Err(StigpackError::SignatureError(format!(
                "signature.sig must contain exactly {ED25519_SIGNATURE_BYTES} bytes"
            )));
        }
        Some(bytes)
    } else {
        None
    };

    let mut trusted_signing_public_key = None;
    if let Some(sig_bytes) = &sig_bytes {
        result.signature_present = true;
        if let Some(store) = trust_store {
            match store.verify_against_trusted_key(&manifest_json, sig_bytes) {
                Ok(Some(key)) => {
                    let key_label = &key.label;
                    let key_fingerprint = crate::signing::public_key_fingerprint(&key.public_key);
                    if manifest.signing_key_fingerprint.as_deref() != Some(key_fingerprint.as_str())
                    {
                        result.signature_valid = Some(false);
                        result.issues.push(format!(
                            "Signature key identity mismatch: manifest {:?}, verified {}",
                            manifest.signing_key_fingerprint, key_fingerprint
                        ));
                    } else {
                        result.signature_valid = Some(true);
                        trusted_signing_public_key = Some(key.public_key);
                        result.issues.push(format!(
                            "Signature verified with trusted key: {} ({})",
                            key_label, key_fingerprint
                        ));
                    }
                }
                Ok(None) => {
                    result.signature_valid = Some(false);
                    result.issues.push(
                        "Signature present but not verified: no matching trusted key".to_string(),
                    );
                }
                Err(e) => {
                    result.signature_valid = Some(false);
                    result
                        .issues
                        .push(format!("Signature verification error: {}", e));
                }
            }
        } else {
            // No trust store provided — note signature is present but unverified.
            result.signature_valid = None;
            result.issues.push(
                "Signature present but no trust store configured for verification".to_string(),
            );
        }
    }

    if require_trusted_signature && result.signature_valid != Some(true) {
        return Err(StigpackError::SignatureError(format!(
            "trusted signature required for .stigpack import: {:?}",
            result.issues
        )));
    }

    // Every non-reserved regular member must be authenticated by the manifest.
    // This is checked before content reads so hidden archive members cannot be
    // smuggled through an otherwise valid pack.
    for archive_entry in archive.entries() {
        if archive_entry.is_directory
            || matches!(
                archive_entry.name.as_str(),
                "manifest.json" | "signature.sig"
            )
        {
            continue;
        }
        if !manifest.files.contains_key(&archive_entry.name) {
            result.integrity_valid = false;
            result.issues.push(format!(
                "Archive contains unlisted file: {}",
                archive_entry.name
            ));
        }
    }

    // Read each authenticated member exactly once under the same actual-byte
    // budget. Import reuses these verified bytes rather than reopening the ZIP.
    let mut contents_by_name = BTreeMap::new();
    for (file_path, entry) in &manifest.files {
        let Some(archive_entry) = archive.entry(file_path) else {
            result.integrity_valid = false;
            result.issues.push(format!("Missing file: {}", file_path));
            result.file_results.push(FileVerification {
                path: file_path.clone(),
                expected_hash: entry.sha256.clone(),
                actual_hash: String::new(),
                size_match: false,
                hash_match: false,
            });
            continue;
        };
        if archive_entry.is_directory {
            result.integrity_valid = false;
            result
                .issues
                .push(format!("Manifest path is a directory: {}", file_path));
            result.file_results.push(FileVerification {
                path: file_path.clone(),
                expected_hash: entry.sha256.clone(),
                actual_hash: String::new(),
                size_match: false,
                hash_match: false,
            });
            continue;
        }

        let contents = archive.read_named(file_path, &mut budget)?;
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
            result.integrity_valid = false;
            result.issues.push(format!(
                "Size mismatch for {}: expected {}, got {}",
                file_path,
                entry.size,
                contents.len()
            ));
        }

        result.file_results.push(FileVerification {
            path: file_path.clone(),
            expected_hash: entry.sha256.clone(),
            actual_hash,
            size_match,
            hash_match,
        });
        contents_by_name.insert(file_path.clone(), contents);
    }

    Ok(PreparedPack {
        manifest,
        manifest_json,
        signature: sig_bytes,
        trusted_signing_public_key,
        contents: contents_by_name,
        verification: result,
    })
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use crate::builder::PackBuilder;
    use crate::manifest::PackManifest;
    use crate::signing::{generate_keypair, TrustStore};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn raw_pack(manifest: &[u8], signature: Option<&[u8]>, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut output);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            writer.start_file("manifest.json", options).unwrap();
            writer.write_all(manifest).unwrap();
            if let Some(signature) = signature {
                writer.start_file("signature.sig", options).unwrap();
                writer.write_all(signature).unwrap();
            }
            for (name, contents) in files {
                let options = SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);
                writer.start_file(*name, options).unwrap();
                writer.write_all(contents).unwrap();
            }
            writer.finish().unwrap();
        }
        output.into_inner()
    }

    fn forge_declared_size(bytes: &mut [u8], target_name: &str, declared_size: u32) {
        let mut offset = 0usize;
        while offset + 46 <= bytes.len() {
            let Some(relative) = bytes[offset..]
                .windows(4)
                .position(|window| window == b"PK\x01\x02")
            else {
                break;
            };
            let central = offset + relative;
            if central + 46 > bytes.len() {
                break;
            }
            let name_len = u16::from_le_bytes([bytes[central + 28], bytes[central + 29]]) as usize;
            let name_start = central + 46;
            let name_end = name_start + name_len;
            if name_end <= bytes.len() && &bytes[name_start..name_end] == target_name.as_bytes() {
                bytes[central + 24..central + 28].copy_from_slice(&declared_size.to_le_bytes());
                return;
            }
            offset = central + 4;
        }
        panic!("missing central-directory entry {target_name}");
    }

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

    #[test]
    fn rejects_oversized_manifest_and_signature_before_parsing() {
        let dir = tempfile::TempDir::new().unwrap();
        let manifest_path = dir.path().join("oversized-manifest.stigpack");
        let oversized_manifest = vec![b' '; (MAX_MANIFEST_BYTES + 1) as usize];
        std::fs::write(&manifest_path, raw_pack(&oversized_manifest, None, &[])).unwrap();
        let error = verify_pack(&manifest_path).unwrap_err();
        assert!(matches!(
            error,
            StigpackError::Archive(
                automatestig_archive_safety::ArchiveError::DeclaredMemberSizeExceeded { .. }
            )
        ));

        let signature_path = dir.path().join("oversized-signature.stigpack");
        let manifest = PackManifest::new("test", "Test", "1").to_json().unwrap();
        std::fs::write(
            &signature_path,
            raw_pack(manifest.as_bytes(), Some(&[0u8; 65]), &[]),
        )
        .unwrap();
        let error = verify_pack(&signature_path).unwrap_err();
        assert!(matches!(
            error,
            StigpackError::Archive(
                automatestig_archive_safety::ArchiveError::DeclaredMemberSizeExceeded { .. }
            )
        ));
    }

    #[test]
    fn trusted_signature_failure_precedes_forged_size_decompression() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("signature-first.stigpack");
        let payload = vec![b'A'; 1_025];
        let mut manifest = PackManifest::new("test", "Test", "1");
        manifest.add_file(
            "benchmarks/payload.json",
            &compute_sha256(&payload),
            payload.len() as u64,
        );
        let manifest_json = manifest.to_json().unwrap();
        let mut bytes = raw_pack(
            manifest_json.as_bytes(),
            Some(&[0u8; ED25519_SIGNATURE_BYTES as usize]),
            &[("benchmarks/payload.json", &payload)],
        );
        forge_declared_size(&mut bytes, "benchmarks/payload.json", 1);
        std::fs::write(&path, bytes).unwrap();

        let (_, public_key) = generate_keypair().unwrap();
        let mut trust = TrustStore::new();
        trust.add_key("test", public_key);
        let policy = ArchivePolicy::strict(16 * 1024, 16, 1_024, 8 * 1024);
        let error = prepare_pack_with_policy(&path, Some(&trust), true, policy.clone())
            .err()
            .unwrap();
        assert!(matches!(error, StigpackError::SignatureError(_)));

        // Without a trust gate the same forged member reaches decompression and
        // is stopped by the actual N+1 byte probe.
        let error = prepare_pack_with_policy(&path, None, false, policy)
            .err()
            .unwrap();
        assert!(matches!(
            error,
            StigpackError::Archive(
                automatestig_archive_safety::ArchiveError::ActualMemberSizeExceeded { .. }
            )
        ));
    }
}
