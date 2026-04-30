//! STIG Library management.
//!
//! The STIG Library is the local store of all available STIG benchmarks,
//! answer file templates, custom checks, and remediation scripts.
//! It's populated by importing .stigpack files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::models::stig::StigBenchmark;
use crate::{Error, Result};

/// The STIG Library — local repository of all STIG content.
#[derive(Debug)]
pub struct StigLibrary {
    /// Root directory of the library on disk.
    root: PathBuf,

    /// Index of all available benchmarks.
    index: LibraryIndex,
}

/// Serializable index of library contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryIndex {
    /// Library format version.
    pub format_version: String,

    /// When this index was last updated.
    pub last_updated: String,

    /// Available STIG benchmarks.
    pub benchmarks: HashMap<String, BenchmarkEntry>,
}

/// An entry in the library index for a single benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkEntry {
    /// Benchmark ID.
    pub id: String,

    /// Title.
    pub title: String,

    /// Version string (e.g., "V1R4").
    pub version: String,

    /// Relative path to the benchmark data file.
    pub data_path: String,

    /// SHA-256 hash of the data file.
    pub sha256: String,

    /// Platform family.
    pub platform_family: String,

    /// Number of rules.
    pub rule_count: usize,

    /// Whether answer file templates are available.
    pub has_answer_templates: bool,

    /// Whether remediation scripts are available.
    pub has_remediation: bool,
}

impl StigLibrary {
    /// Initialize a new STIG library at the given root directory.
    pub fn init(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;

        let index = LibraryIndex {
            format_version: "1".to_string(),
            last_updated: chrono::Utc::now().to_rfc3339(),
            benchmarks: HashMap::new(),
        };

        let lib = Self {
            root: root.to_path_buf(),
            index,
        };
        lib.save_index()?;

        // Create subdirectories.
        std::fs::create_dir_all(root.join("benchmarks"))?;
        std::fs::create_dir_all(root.join("answer_templates"))?;
        std::fs::create_dir_all(root.join("remediation"))?;
        std::fs::create_dir_all(root.join("custom_checks"))?;

        Ok(lib)
    }

    /// Open an existing STIG library.
    pub fn open(root: &Path) -> Result<Self> {
        let index_path = root.join("index.json");
        if !index_path.exists() {
            return Err(Error::LibraryError(format!(
                "No STIG library found at {}",
                root.display()
            )));
        }

        let content = std::fs::read_to_string(&index_path)?;
        let index: LibraryIndex =
            serde_json::from_str(&content).map_err(|e| Error::LibraryError(e.to_string()))?;

        Ok(Self {
            root: root.to_path_buf(),
            index,
        })
    }

    /// Open or initialize a library.
    pub fn open_or_init(root: &Path) -> Result<Self> {
        if root.join("index.json").exists() {
            Self::open(root)
        } else {
            Self::init(root)
        }
    }

    /// List all available benchmarks.
    pub fn list_benchmarks(&self) -> Vec<&BenchmarkEntry> {
        self.index.benchmarks.values().collect()
    }

    /// Get a benchmark entry by ID.
    pub fn get_benchmark_entry(&self, id: &str) -> Option<&BenchmarkEntry> {
        self.index.benchmarks.get(id)
    }

    /// Load a full benchmark by ID.
    pub fn load_benchmark(&self, id: &str) -> Result<StigBenchmark> {
        let entry = self
            .index
            .benchmarks
            .get(id)
            .ok_or_else(|| Error::StigNotFound(id.to_string()))?;

        let path = self.root.join(&entry.data_path);
        let content = std::fs::read_to_string(&path)?;

        // Verify integrity.
        let hash = compute_sha256(content.as_bytes());
        if hash != entry.sha256 {
            return Err(Error::IntegrityError {
                expected: entry.sha256.clone(),
                actual: hash,
            });
        }

        let benchmark: StigBenchmark =
            serde_json::from_str(&content).map_err(|e| Error::LibraryError(e.to_string()))?;
        Ok(benchmark)
    }

    /// Add a benchmark to the library.
    pub fn add_benchmark(&mut self, benchmark: &StigBenchmark) -> Result<()> {
        let data = serde_json::to_string_pretty(benchmark)?;
        let hash = compute_sha256(data.as_bytes());
        let filename = format!("{}.json", crate::path_safety::safe_filename(&benchmark.id)?);
        let data_path = format!("benchmarks/{}", filename);
        let path = crate::path_safety::safe_join_under(&self.root.join("benchmarks"), &filename)?;

        std::fs::write(path, &data)?;

        let entry = BenchmarkEntry {
            id: benchmark.id.clone(),
            title: benchmark.title.clone(),
            version: benchmark.version_string(),
            data_path,
            sha256: hash,
            platform_family: benchmark.platform.family.clone(),
            rule_count: benchmark.rules.len(),
            has_answer_templates: false,
            has_remediation: false,
        };

        self.index.benchmarks.insert(benchmark.id.clone(), entry);
        self.index.last_updated = chrono::Utc::now().to_rfc3339();
        self.save_index()?;

        Ok(())
    }

    /// Get the library root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Save the index to disk.
    fn save_index(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.index)?;
        std::fs::write(self.root.join("index.json"), content)?;
        Ok(())
    }
}

/// Compute SHA-256 hash of data, returning hex string.
pub fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::stig::{CheckAutomation, Platform, Severity, StigRule};
    use tempfile::TempDir;

    fn make_benchmark() -> StigBenchmark {
        StigBenchmark {
            id: "Test_STIG".to_string(),
            title: "Test STIG".to_string(),
            description: "A test".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: Platform {
                family: "test".to_string(),
                name: "Test Platform".to_string(),
                cpe: vec![],
            },
            rules: vec![StigRule {
                vuln_id: "V-1".to_string(),
                rule_id: "SV-1r1_rule".to_string(),
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
    fn test_library_init_and_open() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");

        let lib = StigLibrary::init(&root).unwrap();
        assert!(lib.list_benchmarks().is_empty());

        let lib2 = StigLibrary::open(&root).unwrap();
        assert!(lib2.list_benchmarks().is_empty());
    }

    #[test]
    fn test_library_add_and_load() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");

        let mut lib = StigLibrary::init(&root).unwrap();
        let benchmark = make_benchmark();

        lib.add_benchmark(&benchmark).unwrap();
        assert_eq!(lib.list_benchmarks().len(), 1);

        let loaded = lib.load_benchmark("Test_STIG").unwrap();
        assert_eq!(loaded.title, "Test STIG");
        assert_eq!(loaded.rules.len(), 1);
    }

    #[test]
    fn test_library_integrity_check() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");

        let mut lib = StigLibrary::init(&root).unwrap();
        lib.add_benchmark(&make_benchmark()).unwrap();

        // Tamper with the data file.
        let data_path = root.join("benchmarks/Test_STIG.json");
        std::fs::write(&data_path, "tampered content").unwrap();

        let result = lib.load_benchmark("Test_STIG");
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256() {
        let hash = compute_sha256(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
