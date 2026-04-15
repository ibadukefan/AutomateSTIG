//! Stigpack manifest — metadata about pack contents.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The manifest file included in every .stigpack archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifest {
    /// Manifest format version.
    pub format_version: String,

    /// Pack identifier (unique, e.g., "disa-stigs-2024q3").
    pub pack_id: String,

    /// Pack name (human-readable).
    pub name: String,

    /// Description.
    pub description: String,

    /// Pack version (semver-like, e.g., "2024.3.1").
    pub version: String,

    /// When this pack was created.
    pub created_at: DateTime<Utc>,

    /// Who created/signed this pack.
    pub author: String,

    /// Minimum AutomateSTIG version required.
    pub min_app_version: Option<String>,

    /// Pack type.
    pub pack_type: PackType,

    /// Files included in this pack with their SHA-256 hashes.
    pub files: HashMap<String, FileEntry>,
}

/// Type of content pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackType {
    /// Full STIG content pack — benchmarks + templates + remediation.
    #[serde(rename = "stig_content")]
    StigContent,

    /// Application update pack.
    #[serde(rename = "app_update")]
    AppUpdate,

    /// Custom checks only.
    #[serde(rename = "custom_checks")]
    CustomChecks,

    /// Remediation scripts only.
    #[serde(rename = "remediation")]
    Remediation,
}

/// A file entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path within the pack.
    pub path: String,

    /// SHA-256 hash of the file contents.
    pub sha256: String,

    /// File size in bytes.
    pub size: u64,

    /// MIME type or content type hint.
    pub content_type: Option<String>,
}

impl PackManifest {
    /// Create a new empty manifest.
    pub fn new(pack_id: &str, name: &str, version: &str) -> Self {
        Self {
            format_version: "1".to_string(),
            pack_id: pack_id.to_string(),
            name: name.to_string(),
            description: String::new(),
            version: version.to_string(),
            created_at: Utc::now(),
            author: String::new(),
            min_app_version: None,
            pack_type: PackType::StigContent,
            files: HashMap::new(),
        }
    }

    /// Add a file entry to the manifest.
    pub fn add_file(&mut self, path: &str, sha256: &str, size: u64) {
        self.files.insert(
            path.to_string(),
            FileEntry {
                path: path.to_string(),
                sha256: sha256.to_string(),
                size,
                content_type: None,
            },
        );
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_roundtrip() {
        let mut manifest = PackManifest::new("test-pack", "Test Pack", "1.0.0");
        manifest.description = "A test pack".to_string();
        manifest.author = "AutomateSTIG CI".to_string();
        manifest.add_file("benchmarks/test.json", "abc123", 1024);

        let json = manifest.to_json().unwrap();
        let parsed = PackManifest::from_json(&json).unwrap();

        assert_eq!(parsed.pack_id, "test-pack");
        assert_eq!(parsed.files.len(), 1);
        assert!(parsed.files.contains_key("benchmarks/test.json"));
    }
}
