//! Stigpack builder — creates .stigpack archives from source files.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::manifest::PackManifest;
use crate::{StigpackError, StigpackResult};

/// Builder for creating .stigpack archives.
pub struct PackBuilder {
    manifest: PackManifest,
    files: Vec<(String, Vec<u8>)>,
    signing_key: Option<[u8; 32]>,
}

impl PackBuilder {
    /// Create a new pack builder.
    pub fn new(pack_id: &str, name: &str, version: &str) -> Self {
        Self {
            manifest: PackManifest::new(pack_id, name, version),
            files: Vec::new(),
            signing_key: None,
        }
    }

    /// Set the pack description.
    pub fn description(mut self, desc: &str) -> Self {
        self.manifest.description = desc.to_string();
        self
    }

    /// Set the author.
    pub fn author(mut self, author: &str) -> Self {
        self.manifest.author = author.to_string();
        self
    }

    /// Set an Ed25519 signing key for this pack.
    pub fn signing_key(mut self, key: [u8; 32]) -> Self {
        let public_key = ed25519_dalek::SigningKey::from_bytes(&key)
            .verifying_key()
            .to_bytes();
        self.manifest.signing_key_fingerprint =
            Some(crate::signing::public_key_fingerprint(&public_key));
        self.signing_key = Some(key);
        self
    }

    /// Add a file to the pack from raw bytes.
    pub fn add_file_bytes(mut self, pack_path: &str, data: &[u8]) -> Self {
        let hash = compute_sha256(data);
        self.manifest.add_file(pack_path, &hash, data.len() as u64);
        self.files.push((pack_path.to_string(), data.to_vec()));
        self
    }

    /// Add all files from a directory, preserving relative paths.
    pub fn add_directory(mut self, pack_prefix: &str, dir_path: &Path) -> StigpackResult<Self> {
        let mut entries = WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|entry| match entry {
                Ok(entry) if entry.file_type().is_file() => Some(Ok(entry)),
                Ok(_) => None,
                Err(error) => Some(Err(StigpackError::InvalidPack(error.to_string()))),
            })
            .collect::<StigpackResult<Vec<_>>>()?;
        entries.sort_by(|left, right| left.path().cmp(right.path()));
        for entry in entries {
            let relative = entry
                .path()
                .strip_prefix(dir_path)
                .map_err(|e| StigpackError::InvalidPack(e.to_string()))?;
            let pack_path = format!(
                "{}/{}",
                pack_prefix.trim_end_matches('/'),
                relative.to_string_lossy()
            );
            let data = std::fs::read(entry.path())?;
            let hash = compute_sha256(&data);
            self.manifest.add_file(&pack_path, &hash, data.len() as u64);
            self.files.push((pack_path, data));
        }
        Ok(self)
    }

    /// Build the .stigpack archive and write it to the given path.
    pub fn build(mut self, output_path: &Path) -> StigpackResult<()> {
        self.files.sort_by(|left, right| left.0.cmp(&right.0));
        let mut seen = HashSet::new();
        for (path, _) in &self.files {
            crate::validate_member_path(path)?;
            if matches!(path.as_str(), "manifest.json" | "signature.sig") {
                return Err(StigpackError::InvalidPack(format!(
                    "reserved .stigpack member name: {path}"
                )));
            }
            if !seen.insert(path) {
                return Err(StigpackError::InvalidPack(format!(
                    "duplicate .stigpack member: {path}"
                )));
            }
        }
        self.manifest
            .validate()
            .map_err(StigpackError::ManifestError)?;
        let file = std::fs::File::create(output_path)?;
        let mut zip = ZipWriter::new(file);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        // Write manifest first.
        let manifest_json = self
            .manifest
            .to_json()
            .map_err(|e| StigpackError::ManifestError(e.to_string()))?;

        zip.start_file("manifest.json", options)
            .map_err(StigpackError::Zip)?;
        zip.write_all(manifest_json.as_bytes())?;

        // Sign the manifest if a signing key is provided.
        if let Some(ref key) = self.signing_key {
            let signature = crate::signing::sign_manifest(manifest_json.as_bytes(), key)?;
            zip.start_file("signature.sig", options)
                .map_err(StigpackError::Zip)?;
            zip.write_all(&signature)?;
        }

        // Write all content files.
        for (path, data) in &self.files {
            zip.start_file(path.as_str(), options)
                .map_err(StigpackError::Zip)?;
            zip.write_all(data)?;
        }

        zip.finish().map_err(StigpackError::Zip)?;
        Ok(())
    }
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_pack() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("test.stigpack");

        let builder = PackBuilder::new("test-pack", "Test Pack", "1.0.0")
            .description("Test content pack")
            .author("Test Author")
            .add_file_bytes("benchmarks/test.json", b"{\"id\": \"test\"}");

        builder.build(&output).unwrap();
        assert!(output.exists());

        // Verify it's a valid ZIP.
        let file = std::fs::File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        assert!(archive.by_name("manifest.json").is_ok());
        assert!(archive.by_name("benchmarks/test.json").is_ok());
    }

    #[test]
    fn rejects_duplicate_unsafe_and_reserved_members() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("bad.stigpack");

        let duplicate = PackBuilder::new("test", "Test", "1")
            .add_file_bytes("benchmarks/test.json", b"one")
            .add_file_bytes("benchmarks/test.json", b"two");
        assert!(duplicate.build(&output).is_err());

        let unsafe_path =
            PackBuilder::new("test", "Test", "1").add_file_bytes("../test.json", b"content");
        assert!(unsafe_path.build(&output).is_err());

        let reserved =
            PackBuilder::new("test", "Test", "1").add_file_bytes("manifest.json", b"content");
        assert!(reserved.build(&output).is_err());
    }
}
