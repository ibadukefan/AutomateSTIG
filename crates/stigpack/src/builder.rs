//! Stigpack builder — creates .stigpack archives from source files.

use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::manifest::{PackManifest, PackType};
use crate::{StigpackError, StigpackResult};

/// Builder for creating .stigpack archives.
pub struct PackBuilder {
    manifest: PackManifest,
    files: Vec<(String, Vec<u8>)>,
}

impl PackBuilder {
    /// Create a new pack builder.
    pub fn new(pack_id: &str, name: &str, version: &str) -> Self {
        Self {
            manifest: PackManifest::new(pack_id, name, version),
            files: Vec::new(),
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

    /// Set the pack type.
    pub fn pack_type(mut self, pack_type: PackType) -> Self {
        self.manifest.pack_type = pack_type;
        self
    }

    /// Set the minimum app version.
    pub fn min_app_version(mut self, version: &str) -> Self {
        self.manifest.min_app_version = Some(version.to_string());
        self
    }

    /// Add a file to the pack from raw bytes.
    pub fn add_file_bytes(mut self, pack_path: &str, data: &[u8]) -> Self {
        let hash = compute_sha256(data);
        self.manifest
            .add_file(pack_path, &hash, data.len() as u64);
        self.files.push((pack_path.to_string(), data.to_vec()));
        self
    }

    /// Add a file to the pack from a filesystem path.
    pub fn add_file_from_path(self, pack_path: &str, fs_path: &Path) -> StigpackResult<Self> {
        let data = std::fs::read(fs_path)?;
        Ok(self.add_file_bytes(pack_path, &data))
    }

    /// Add all files from a directory, preserving relative paths.
    pub fn add_directory(mut self, pack_prefix: &str, dir_path: &Path) -> StigpackResult<Self> {
        for entry in WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
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
            self.manifest
                .add_file(&pack_path, &hash, data.len() as u64);
            self.files.push((pack_path, data));
        }
        Ok(self)
    }

    /// Build the .stigpack archive and write it to the given path.
    pub fn build(self, output_path: &Path) -> StigpackResult<()> {
        let file = std::fs::File::create(output_path)?;
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        // Write manifest first.
        let manifest_json = self
            .manifest
            .to_json()
            .map_err(|e| StigpackError::ManifestError(e.to_string()))?;

        zip.start_file("manifest.json", options)
            .map_err(StigpackError::Zip)?;
        zip.write_all(manifest_json.as_bytes())?;

        // Write all content files.
        for (path, data) in &self.files {
            zip.start_file(path.as_str(), options)
                .map_err(StigpackError::Zip)?;
            zip.write_all(data)?;
        }

        zip.finish().map_err(StigpackError::Zip)?;
        Ok(())
    }

    /// Build and return the archive as in-memory bytes.
    pub fn build_to_bytes(self) -> StigpackResult<Vec<u8>> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("pack.stigpack");
        self.build(&path)?;
        Ok(std::fs::read(&path)?)
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
}
