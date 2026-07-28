//! STIG Library management.
//!
//! The STIG Library is the local store of all available STIG benchmarks,
//! answer file templates, and custom checks.
//! It's populated by importing .stigpack files.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checks::CheckPack;
use crate::library_transaction::{LibraryInstallStep, LibraryTransaction, LibraryWriteGuard};
use crate::models::stig::StigBenchmark;
use crate::{Error, Result};

const EXECUTABLE_CONTENT_CATALOG: &str = "trusted-executable-content.json";
const EXECUTABLE_CONTENT_FORMAT_VERSION: u32 = 1;

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
}

/// Explicit disposition of a benchmark's generated check pack.
#[derive(Debug, Clone, Copy)]
pub enum GeneratedCheckPackIntent<'a> {
    /// Preserve any generated pack already installed for this benchmark.
    Keep,
    /// Atomically create or replace the generated pack.
    Replace(&'a CheckPack),
    /// Atomically remove any generated pack for this benchmark.
    Remove,
}

/// One benchmark and its generated-check disposition in an atomic batch import.
#[derive(Debug, Clone, Copy)]
pub struct BenchmarkImport<'a> {
    pub benchmark: &'a StigBenchmark,
    pub generated_check_pack: GeneratedCheckPackIntent<'a>,
}

/// An already validated ancillary file to commit with a benchmark batch.
///
/// Paths are relative to the library root and are restricted to managed content
/// directories. This lets `.stigpack` import use the same durable transaction as
/// its benchmarks instead of composing two independently recoverable commits.
#[derive(Debug, Clone, Copy)]
pub struct LibraryFileImport<'a> {
    pub relative_path: &'a str,
    pub bytes: &'a [u8],
}

/// One executable file authenticated by a signed `.stigpack` manifest.
#[derive(Debug, Clone, Copy)]
pub struct TrustedExecutableFileImport<'a> {
    /// Final path relative to the library root.
    pub relative_path: &'a str,
    /// Original member name in the signed `.stigpack` manifest.
    pub manifest_member_path: &'a str,
}

/// Cryptographic proof retained with executable files from one trusted pack.
///
/// The importer supplies the exact manifest bytes and signature that it
/// verified against a configured trust anchor. The library verifies the proof
/// again before committing it and runtime loading verifies it against the
/// *current* trust store, so removing a trust anchor revokes execution.
#[derive(Debug, Clone, Copy)]
pub struct TrustedExecutablePackImport<'a> {
    pub pack_id: &'a str,
    pub pack_version: &'a str,
    pub signing_key_fingerprint: &'a str,
    pub signing_public_key: &'a [u8; 32],
    pub manifest_json: &'a [u8],
    pub signature: &'a [u8],
    pub files: &'a [TrustedExecutableFileImport<'a>],
}

/// Verified executable bytes returned from a library trust boundary.
#[derive(Debug)]
pub struct TrustedExecutableFile {
    pub relative_path: PathBuf,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedExecutableCatalog {
    format_version: u32,
    entries: BTreeMap<String, TrustedExecutableEntry>,
    proofs: BTreeMap<String, TrustedExecutableProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedExecutableEntry {
    sha256: String,
    manifest_member_path: String,
    proof_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedExecutableProof {
    pack_id: String,
    pack_version: String,
    signing_key_fingerprint: String,
    signing_public_key_hex: String,
    manifest_sha256: String,
    manifest_json: String,
    signature_hex: String,
}

#[derive(Debug, Deserialize)]
struct ProvenanceManifest {
    pack_id: String,
    version: String,
    signing_key_fingerprint: Option<String>,
    files: BTreeMap<String, ProvenanceManifestFile>,
}

#[derive(Debug, Deserialize)]
struct ProvenanceManifestFile {
    sha256: String,
}

impl<'a> BenchmarkImport<'a> {
    /// Prepare an import with an explicit generated-check disposition.
    pub fn new(
        benchmark: &'a StigBenchmark,
        generated_check_pack: GeneratedCheckPackIntent<'a>,
    ) -> Self {
        Self {
            benchmark,
            generated_check_pack,
        }
    }
}

/// Outcome of a successfully committed benchmark batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BenchmarkBatchImportResult {
    /// Benchmark IDs that were not present before this transaction.
    pub added_ids: Vec<String>,

    /// Benchmark IDs whose existing index entries were replaced.
    pub updated_ids: Vec<String>,

    /// Benchmark IDs for which a generated check pack was committed.
    pub generated_check_pack_ids: Vec<String>,

    /// Benchmark IDs for which generated check-pack removal was committed.
    pub removed_generated_check_pack_ids: Vec<String>,
}

impl BenchmarkBatchImportResult {
    /// Number of newly added benchmarks.
    pub fn added_count(&self) -> usize {
        self.added_ids.len()
    }

    /// Number of updated benchmarks.
    pub fn updated_count(&self) -> usize {
        self.updated_ids.len()
    }

    /// Number of generated check packs written by the transaction.
    pub fn generated_check_pack_count(&self) -> usize {
        self.generated_check_pack_ids.len()
    }

    /// Number of generated check-pack removal intents committed.
    pub fn removed_generated_check_pack_count(&self) -> usize {
        self.removed_generated_check_pack_ids.len()
    }
}

#[derive(Debug)]
struct PreparedArtifact {
    relative_path: PathBuf,
    operation: PreparedArtifactOperation,
}

#[derive(Debug)]
enum PreparedArtifactOperation {
    Replace(Vec<u8>),
    Remove,
}

#[derive(Debug)]
struct PreparedBatch {
    index: LibraryIndex,
    index_bytes: Vec<u8>,
    artifacts: Vec<PreparedArtifact>,
    result: BenchmarkBatchImportResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportStep {
    SerializeBenchmark,
    SerializeCheckPack,
    SerializeIndex,
    StageArtifact,
    StageIndex,
    CommitArtifact,
    CommitIndex,
}

impl StigLibrary {
    /// Initialize a new STIG library at the given root directory.
    pub fn init(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let guard = LibraryWriteGuard::acquire(root)?;
        if root.join("index.json").exists() {
            return Self::open_locked(root, &guard);
        }
        Self::init_locked(root, &guard)
    }

    /// Open an existing STIG library.
    pub fn open(root: &Path) -> Result<Self> {
        let guard = LibraryWriteGuard::acquire(root)?;
        Self::open_locked(root, &guard)
    }

    /// Open or initialize a library.
    pub fn open_or_init(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let guard = LibraryWriteGuard::acquire(root)?;
        if root.join("index.json").exists() {
            Self::open_locked(root, &guard)
        } else {
            Self::init_locked(root, &guard)
        }
    }

    fn init_locked(root: &Path, guard: &LibraryWriteGuard) -> Result<Self> {
        // Create the stable directory skeleton before advertising a valid index.
        // Empty directories left by an initialization error are harmless; a
        // missing or partial index is recovered by the shared transaction layer.
        fs::create_dir_all(root.join("benchmarks"))?;
        fs::create_dir_all(root.join("answer_templates"))?;
        fs::create_dir_all(root.join("custom_checks"))?;
        fs::create_dir_all(root.join("reviewed_check_packs"))?;

        let index = LibraryIndex {
            format_version: "1".to_string(),
            last_updated: chrono::Utc::now().to_rfc3339(),
            benchmarks: HashMap::new(),
        };
        let bytes = serde_json::to_vec_pretty(&index)?;
        let trusted_content = empty_trusted_executable_catalog();
        let trusted_content_bytes = serde_json::to_vec_pretty(&trusted_content)?;
        let mut transaction = LibraryTransaction::new(guard)?;
        transaction.stage_file(Path::new("index.json"), &bytes)?;
        transaction.stage_file(
            Path::new(EXECUTABLE_CONTENT_CATALOG),
            &trusted_content_bytes,
        )?;
        transaction.install_and_commit(|_, _| Ok(()))?;
        Ok(Self {
            root: root.to_path_buf(),
            index,
        })
    }

    fn open_locked(root: &Path, guard: &LibraryWriteGuard) -> Result<Self> {
        debug_assert_eq!(guard.root(), root);
        let index = read_index(root)?;
        ensure_real_directory(root)?;
        ensure_real_directory(&root.join("benchmarks"))?;
        Ok(Self {
            root: root.to_path_buf(),
            index,
        })
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
        // A long-lived handle may predate another process's import. Reload the
        // index while holding the same lock as writers so an index/artifact pair
        // is always observed from one committed generation.
        let _guard = LibraryWriteGuard::acquire(&self.root)?;
        let index = read_index(&self.root)?;
        let entry = index
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

    /// Add a benchmark to the library as a one-item atomic batch.
    pub fn add_benchmark(&mut self, benchmark: &StigBenchmark) -> Result<()> {
        self.import_benchmarks(&[BenchmarkImport::new(
            benchmark,
            GeneratedCheckPackIntent::Keep,
        )])?;
        Ok(())
    }

    /// Atomically import benchmarks and their generated check packs.
    ///
    /// Every identifier is validated and every benchmark, check pack, and the
    /// resulting index are serialized while holding the library's cross-process
    /// lock. Staged bytes and transaction intent are synced before visible
    /// renames. A process or machine failure is rolled back on the next open or
    /// write unless the durable committed marker was already persisted.
    pub fn import_benchmarks(
        &mut self,
        imports: &[BenchmarkImport<'_>],
    ) -> Result<BenchmarkBatchImportResult> {
        self.import_benchmarks_and_files(imports, &[])
    }

    /// Atomically import benchmarks and prevalidated ancillary library files.
    pub fn import_benchmarks_and_files(
        &mut self,
        imports: &[BenchmarkImport<'_>],
        files: &[LibraryFileImport<'_>],
    ) -> Result<BenchmarkBatchImportResult> {
        self.import_benchmarks_and_files_with_provenance(imports, files, &[])
    }

    /// Atomically import benchmarks, ancillary files, and signed executable
    /// provenance. Every file under `custom_checks/` or
    /// `reviewed_check_packs/` must be covered by one verified proof.
    pub fn import_benchmarks_and_files_with_provenance(
        &mut self,
        imports: &[BenchmarkImport<'_>],
        files: &[LibraryFileImport<'_>],
        provenance: &[TrustedExecutablePackImport<'_>],
    ) -> Result<BenchmarkBatchImportResult> {
        self.import_benchmarks_and_files_with_hook(imports, files, provenance, |_, _| Ok(()))
    }

    #[cfg(test)]
    fn import_benchmarks_with_hook<F>(
        &mut self,
        imports: &[BenchmarkImport<'_>],
        hook: F,
    ) -> Result<BenchmarkBatchImportResult>
    where
        F: FnMut(ImportStep, &Path) -> Result<()>,
    {
        self.import_benchmarks_and_files_with_hook(imports, &[], &[], hook)
    }

    fn import_benchmarks_and_files_with_hook<F>(
        &mut self,
        imports: &[BenchmarkImport<'_>],
        files: &[LibraryFileImport<'_>],
        provenance: &[TrustedExecutablePackImport<'_>],
        mut hook: F,
    ) -> Result<BenchmarkBatchImportResult>
    where
        F: FnMut(ImportStep, &Path) -> Result<()>,
    {
        if imports.is_empty() && files.is_empty() && provenance.is_empty() {
            return Ok(BenchmarkBatchImportResult::default());
        }

        let guard = LibraryWriteGuard::acquire(&self.root)?;
        // A handle may have been opened before another process committed. Never
        // derive a new index from that stale snapshot.
        self.index = read_index(&self.root)?;
        let prepared = self.prepare_batch(imports, files, provenance, &mut hook)?;
        self.commit_prepared_batch(prepared, &guard, &mut hook)
    }

    fn prepare_batch<F>(
        &self,
        imports: &[BenchmarkImport<'_>],
        files: &[LibraryFileImport<'_>],
        provenance: &[TrustedExecutablePackImport<'_>],
        hook: &mut F,
    ) -> Result<PreparedBatch>
    where
        F: FnMut(ImportStep, &Path) -> Result<()>,
    {
        let mut seen_ids = HashSet::new();
        let mut artifact_paths = HashSet::new();
        let mut artifacts = Vec::with_capacity(imports.len() * 2 + files.len());
        let mut imported_file_bytes = BTreeMap::new();
        let mut index = self.index.clone();
        let mut result = BenchmarkBatchImportResult::default();

        for import in imports {
            let benchmark = import.benchmark;
            if !seen_ids.insert(benchmark.id.clone()) {
                return Err(Error::LibraryError(format!(
                    "benchmark {} appears more than once in the import batch",
                    benchmark.id
                )));
            }

            let safe_id = crate::path_safety::safe_filename(&benchmark.id)?;
            let filename = format!("{safe_id}.json");
            let relative_path = PathBuf::from("benchmarks").join(&filename);
            if !artifact_paths.insert(relative_path.clone()) {
                return Err(Error::LibraryError(format!(
                    "benchmark {} collides with another destination in the import batch",
                    benchmark.id
                )));
            }

            hook(ImportStep::SerializeBenchmark, &relative_path)?;
            let bytes = serde_json::to_vec_pretty(benchmark)?;
            let hash = compute_sha256(&bytes);
            let data_path = format!("benchmarks/{filename}");

            if self.index.benchmarks.contains_key(&benchmark.id) {
                result.updated_ids.push(benchmark.id.clone());
            } else {
                result.added_ids.push(benchmark.id.clone());
            }

            index.benchmarks.insert(
                benchmark.id.clone(),
                BenchmarkEntry {
                    id: benchmark.id.clone(),
                    title: benchmark.title.clone(),
                    version: benchmark.version_string(),
                    data_path,
                    sha256: hash,
                    platform_family: benchmark.platform.family.clone(),
                    rule_count: benchmark.rules.len(),
                },
            );
            artifacts.push(PreparedArtifact {
                relative_path,
                operation: PreparedArtifactOperation::Replace(bytes),
            });

            match import.generated_check_pack {
                GeneratedCheckPackIntent::Keep => {}
                GeneratedCheckPackIntent::Replace(check_pack) => {
                    if check_pack.stig_id != benchmark.id {
                        return Err(Error::LibraryError(format!(
                            "generated check pack {} does not match benchmark {}",
                            check_pack.stig_id, benchmark.id
                        )));
                    }

                    let relative_path = PathBuf::from("auto_check_packs").join(&filename);
                    if !artifact_paths.insert(relative_path.clone()) {
                        return Err(Error::LibraryError(format!(
                            "generated check pack for {} collides with another destination",
                            benchmark.id
                        )));
                    }
                    hook(ImportStep::SerializeCheckPack, &relative_path)?;
                    let bytes = serde_json::to_vec_pretty(check_pack)?;
                    artifacts.push(PreparedArtifact {
                        relative_path,
                        operation: PreparedArtifactOperation::Replace(bytes),
                    });
                    result.generated_check_pack_ids.push(benchmark.id.clone());
                }
                GeneratedCheckPackIntent::Remove => {
                    let relative_path = PathBuf::from("auto_check_packs").join(&filename);
                    if !artifact_paths.insert(relative_path.clone()) {
                        return Err(Error::LibraryError(format!(
                            "generated check pack for {} collides with another destination",
                            benchmark.id
                        )));
                    }
                    artifacts.push(PreparedArtifact {
                        relative_path,
                        operation: PreparedArtifactOperation::Remove,
                    });
                    result
                        .removed_generated_check_pack_ids
                        .push(benchmark.id.clone());
                }
            }
        }

        for file in files {
            let relative_path = validate_managed_file_path(file.relative_path)?;
            if !artifact_paths.insert(relative_path.clone()) {
                return Err(Error::LibraryError(format!(
                    "ancillary file collides with another import destination: {}",
                    relative_path.display()
                )));
            }
            let relative_string = relative_path
                .to_str()
                .ok_or_else(|| {
                    Error::LibraryError(format!(
                        "ancillary file path is not UTF-8: {}",
                        relative_path.display()
                    ))
                })?
                .replace('\\', "/");
            imported_file_bytes.insert(relative_string, file.bytes);
            artifacts.push(PreparedArtifact {
                relative_path,
                operation: PreparedArtifactOperation::Replace(file.bytes.to_vec()),
            });
        }

        let imports_executable_content = imported_file_bytes
            .keys()
            .any(|path| is_executable_content_path(path));
        if imports_executable_content || !provenance.is_empty() {
            let catalog =
                prepare_trusted_executable_catalog(&self.root, &imported_file_bytes, provenance)?;
            let relative_path = PathBuf::from(EXECUTABLE_CONTENT_CATALOG);
            if !artifact_paths.insert(relative_path.clone()) {
                return Err(Error::LibraryError(
                    "trusted executable catalog collides with an import destination".to_string(),
                ));
            }
            artifacts.push(PreparedArtifact {
                relative_path,
                operation: PreparedArtifactOperation::Replace(serde_json::to_vec_pretty(&catalog)?),
            });
        }

        // A space in an ID is normalized to `_`, so validate the complete future
        // index rather than only checking duplicate IDs in this batch.
        let mut future_paths = HashMap::new();
        for entry in index.benchmarks.values() {
            if let Some(other_id) = future_paths.insert(entry.data_path.clone(), entry.id.clone()) {
                if other_id != entry.id {
                    return Err(Error::LibraryError(format!(
                        "benchmarks {other_id} and {} resolve to the same data path {}",
                        entry.id, entry.data_path
                    )));
                }
            }
        }

        result.added_ids.sort();
        result.updated_ids.sort();
        result.generated_check_pack_ids.sort();
        result.removed_generated_check_pack_ids.sort();
        artifacts.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

        index.last_updated = chrono::Utc::now().to_rfc3339();
        hook(ImportStep::SerializeIndex, Path::new("index.json"))?;
        let index_bytes = serde_json::to_vec_pretty(&index)?;

        Ok(PreparedBatch {
            index,
            index_bytes,
            artifacts,
            result,
        })
    }

    fn commit_prepared_batch<F>(
        &mut self,
        prepared: PreparedBatch,
        guard: &LibraryWriteGuard,
        hook: &mut F,
    ) -> Result<BenchmarkBatchImportResult>
    where
        F: FnMut(ImportStep, &Path) -> Result<()>,
    {
        debug_assert_eq!(guard.root(), self.root);
        ensure_real_directory(&self.root)?;
        ensure_real_directory(&self.root.join("benchmarks"))?;
        let mut transaction = LibraryTransaction::new(guard)?;

        for artifact in &prepared.artifacts {
            hook(ImportStep::StageArtifact, &artifact.relative_path)?;
            match &artifact.operation {
                PreparedArtifactOperation::Replace(bytes) => {
                    transaction.stage_file(&artifact.relative_path, bytes)?;
                }
                PreparedArtifactOperation::Remove => {
                    transaction.remove_file(&artifact.relative_path)?;
                }
            }
        }

        hook(ImportStep::StageIndex, Path::new("index.json"))?;
        transaction.stage_file(Path::new("index.json"), &prepared.index_bytes)?;
        transaction.install_and_commit(|step, relative_path| {
            if step != LibraryInstallStep::BeforeInstall {
                return Ok(());
            }
            if relative_path == Path::new("index.json") {
                hook(ImportStep::CommitIndex, relative_path)
            } else {
                hook(ImportStep::CommitArtifact, relative_path)
            }
        })?;

        self.index = prepared.index;
        Ok(prepared.result)
    }

    /// Load executable library files only when their retained signed-manifest
    /// proof is intact and its exact public key remains in the current trust
    /// store. Bare files, modified files, missing proof records, revoked keys,
    /// and modified proofs are fatal rather than silently skipped.
    pub fn load_trusted_executable_files(
        &self,
        directory: &str,
        trusted_public_keys: &[[u8; 32]],
    ) -> Result<Vec<TrustedExecutableFile>> {
        if !matches!(directory, "custom_checks" | "reviewed_check_packs") {
            return Err(Error::LibraryError(format!(
                "untrusted executable directory requested: {directory}"
            )));
        }

        let _guard = LibraryWriteGuard::acquire(&self.root)?;
        let catalog = read_trusted_executable_catalog(&self.root)?;
        let directory_path = self.root.join(directory);
        ensure_real_directory(&directory_path)?;

        let mut paths = Vec::new();
        collect_regular_files(&directory_path, &mut paths)?;
        paths.sort();

        let mut loaded = Vec::new();
        let mut observed = HashSet::new();
        let mut verified_proofs = HashSet::new();
        for path in paths {
            if !matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("json" | "yaml" | "yml")
            ) {
                continue;
            }
            let relative_path = path.strip_prefix(&self.root).map_err(|_| {
                Error::LibraryError(format!(
                    "executable content escaped the library root: {}",
                    path.display()
                ))
            })?;
            let relative_string = relative_path
                .to_str()
                .ok_or_else(|| {
                    Error::LibraryError(format!(
                        "executable content path is not UTF-8: {}",
                        relative_path.display()
                    ))
                })?
                .replace('\\', "/");
            observed.insert(relative_string.clone());

            let entry = catalog.entries.get(&relative_string).ok_or_else(|| {
                Error::LibraryError(format!(
                    "executable content has no trusted signed provenance and will not run: {relative_string}"
                ))
            })?;
            let proof = catalog.proofs.get(&entry.proof_id).ok_or_else(|| {
                Error::LibraryError(format!(
                    "trusted executable proof {} is missing for {relative_string}",
                    entry.proof_id
                ))
            })?;
            if verified_proofs.insert(entry.proof_id.clone()) {
                verify_stored_executable_proof(&entry.proof_id, proof, trusted_public_keys)?;
            }

            let bytes = fs::read(&path)?;
            let actual_sha256 = compute_sha256(&bytes);
            if actual_sha256 != entry.sha256 {
                return Err(Error::IntegrityError {
                    expected: entry.sha256.clone(),
                    actual: actual_sha256,
                });
            }
            let manifest: ProvenanceManifest =
                serde_json::from_str(&proof.manifest_json).map_err(|error| {
                    Error::LibraryError(format!(
                        "stored signed manifest {} is invalid: {error}",
                        entry.proof_id
                    ))
                })?;
            let manifest_file =
                manifest
                    .files
                    .get(&entry.manifest_member_path)
                    .ok_or_else(|| {
                        Error::LibraryError(format!(
                            "stored signed manifest does not authorize {} for {relative_string}",
                            entry.manifest_member_path
                        ))
                    })?;
            if manifest_file.sha256 != entry.sha256 {
                return Err(Error::LibraryError(format!(
                    "stored signed manifest hash does not match trusted catalog for {relative_string}"
                )));
            }
            loaded.push(TrustedExecutableFile {
                relative_path: relative_path.to_path_buf(),
                bytes,
            });
        }

        let prefix = format!("{directory}/");
        for relative_path in catalog
            .entries
            .keys()
            .filter(|path| path.starts_with(&prefix))
        {
            if !observed.contains(relative_path) {
                return Err(Error::LibraryError(format!(
                    "trusted executable content is missing: {relative_path}"
                )));
            }
        }

        Ok(loaded)
    }

    /// Get the library root path.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn empty_trusted_executable_catalog() -> TrustedExecutableCatalog {
    TrustedExecutableCatalog {
        format_version: EXECUTABLE_CONTENT_FORMAT_VERSION,
        entries: BTreeMap::new(),
        proofs: BTreeMap::new(),
    }
}

fn read_trusted_executable_catalog(root: &Path) -> Result<TrustedExecutableCatalog> {
    let path = root.join(EXECUTABLE_CONTENT_CATALOG);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Compatibility with an older library is deliberately fail-closed:
            // its executable directories may still be opened, but every bare
            // file will be rejected because this empty catalog authorizes none.
            return Ok(empty_trusted_executable_catalog());
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::LibraryError(format!(
            "trusted executable catalog is not a regular file: {}",
            path.display()
        )));
    }
    let bytes = fs::read(&path)?;
    let catalog: TrustedExecutableCatalog = serde_json::from_slice(&bytes).map_err(|error| {
        Error::LibraryError(format!(
            "trusted executable catalog is invalid at {}: {error}",
            path.display()
        ))
    })?;
    if catalog.format_version != EXECUTABLE_CONTENT_FORMAT_VERSION {
        return Err(Error::LibraryError(format!(
            "unsupported trusted executable catalog version {}",
            catalog.format_version
        )));
    }
    Ok(catalog)
}

fn prepare_trusted_executable_catalog(
    root: &Path,
    imported_files: &BTreeMap<String, &[u8]>,
    provenance: &[TrustedExecutablePackImport<'_>],
) -> Result<TrustedExecutableCatalog> {
    let mut catalog = read_trusted_executable_catalog(root)?;
    let mut covered = HashSet::new();

    for pack in provenance {
        let manifest_json = std::str::from_utf8(pack.manifest_json).map_err(|error| {
            Error::LibraryError(format!(
                "signed manifest for {} is not UTF-8: {error}",
                pack.pack_id
            ))
        })?;
        let manifest_sha256 = compute_sha256(pack.manifest_json);
        let proof_id = manifest_sha256.clone();
        let manifest: ProvenanceManifest =
            serde_json::from_slice(pack.manifest_json).map_err(|error| {
                Error::LibraryError(format!(
                    "signed manifest for {} is invalid: {error}",
                    pack.pack_id
                ))
            })?;
        if manifest.pack_id != pack.pack_id || manifest.version != pack.pack_version {
            return Err(Error::LibraryError(format!(
                "signed manifest identity does not match provenance for {} v{}",
                pack.pack_id, pack.pack_version
            )));
        }
        if manifest.signing_key_fingerprint.as_deref() != Some(pack.signing_key_fingerprint) {
            return Err(Error::LibraryError(format!(
                "signed manifest key fingerprint does not match provenance for {}",
                pack.pack_id
            )));
        }

        verify_signing_proof(
            pack.manifest_json,
            pack.signature,
            pack.signing_public_key,
            pack.signing_key_fingerprint,
        )?;
        if pack.files.is_empty() {
            return Err(Error::LibraryError(format!(
                "trusted executable provenance for {} covers no files",
                pack.pack_id
            )));
        }

        for file in pack.files {
            let relative_path = validate_managed_file_path(file.relative_path)?;
            let relative_string = relative_path
                .to_str()
                .ok_or_else(|| {
                    Error::LibraryError(format!(
                        "trusted executable path is not UTF-8: {}",
                        relative_path.display()
                    ))
                })?
                .replace('\\', "/");
            if !is_executable_content_path(&relative_string) {
                return Err(Error::LibraryError(format!(
                    "trusted executable provenance targets a non-executable path: {relative_string}"
                )));
            }
            if !covered.insert(relative_string.clone()) {
                return Err(Error::LibraryError(format!(
                    "executable import is covered by multiple provenance records: {relative_string}"
                )));
            }
            let bytes = imported_files.get(&relative_string).ok_or_else(|| {
                Error::LibraryError(format!(
                    "trusted executable provenance has no matching staged file: {relative_string}"
                ))
            })?;
            let file_sha256 = compute_sha256(bytes);
            let manifest_file = manifest
                .files
                .get(file.manifest_member_path)
                .ok_or_else(|| {
                    Error::LibraryError(format!(
                        "signed manifest does not list executable member {}",
                        file.manifest_member_path
                    ))
                })?;
            if manifest_file.sha256 != file_sha256 {
                return Err(Error::IntegrityError {
                    expected: manifest_file.sha256.clone(),
                    actual: file_sha256,
                });
            }
            catalog.entries.insert(
                relative_string,
                TrustedExecutableEntry {
                    sha256: manifest_file.sha256.clone(),
                    manifest_member_path: file.manifest_member_path.to_string(),
                    proof_id: proof_id.clone(),
                },
            );
        }

        catalog.proofs.insert(
            proof_id,
            TrustedExecutableProof {
                pack_id: pack.pack_id.to_string(),
                pack_version: pack.pack_version.to_string(),
                signing_key_fingerprint: pack.signing_key_fingerprint.to_string(),
                signing_public_key_hex: hex_encode(pack.signing_public_key),
                manifest_sha256,
                manifest_json: manifest_json.to_string(),
                signature_hex: hex_encode(pack.signature),
            },
        );
    }

    for relative_path in imported_files
        .keys()
        .filter(|path| is_executable_content_path(path))
    {
        if !covered.contains(relative_path) {
            return Err(Error::LibraryError(format!(
                "executable library file lacks trusted signed provenance: {relative_path}"
            )));
        }
    }

    let referenced_proofs = catalog
        .entries
        .values()
        .map(|entry| entry.proof_id.clone())
        .collect::<HashSet<_>>();
    catalog
        .proofs
        .retain(|proof_id, _| referenced_proofs.contains(proof_id));
    catalog.format_version = EXECUTABLE_CONTENT_FORMAT_VERSION;
    Ok(catalog)
}

fn verify_stored_executable_proof(
    proof_id: &str,
    proof: &TrustedExecutableProof,
    trusted_public_keys: &[[u8; 32]],
) -> Result<()> {
    let manifest_sha256 = compute_sha256(proof.manifest_json.as_bytes());
    if manifest_sha256 != proof.manifest_sha256 || manifest_sha256 != proof_id {
        return Err(Error::LibraryError(format!(
            "stored executable proof manifest hash is invalid: {proof_id}"
        )));
    }
    let public_key_bytes = hex_decode_fixed::<32>(&proof.signing_public_key_hex, "public key")?;
    if !trusted_public_keys
        .iter()
        .any(|trusted| trusted == &public_key_bytes)
    {
        return Err(Error::LibraryError(format!(
            "signing key {} is no longer trusted for executable pack {} v{}",
            proof.signing_key_fingerprint, proof.pack_id, proof.pack_version
        )));
    }
    let signature = hex_decode(&proof.signature_hex, "signature")?;
    verify_signing_proof(
        proof.manifest_json.as_bytes(),
        &signature,
        &public_key_bytes,
        &proof.signing_key_fingerprint,
    )?;
    let manifest: ProvenanceManifest =
        serde_json::from_str(&proof.manifest_json).map_err(|error| {
            Error::LibraryError(format!(
                "stored executable proof manifest is invalid: {error}"
            ))
        })?;
    if manifest.pack_id != proof.pack_id
        || manifest.version != proof.pack_version
        || manifest.signing_key_fingerprint.as_deref()
            != Some(proof.signing_key_fingerprint.as_str())
    {
        return Err(Error::LibraryError(format!(
            "stored executable proof identity is inconsistent: {proof_id}"
        )));
    }
    Ok(())
}

fn verify_signing_proof(
    manifest_json: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8; 32],
    expected_fingerprint: &str,
) -> Result<()> {
    let actual_fingerprint = format!("SHA256:{}", compute_sha256(public_key_bytes));
    if actual_fingerprint != expected_fingerprint {
        return Err(Error::LibraryError(format!(
            "executable signing-key fingerprint mismatch: expected {expected_fingerprint}, got {actual_fingerprint}"
        )));
    }
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes).map_err(|error| {
        Error::LibraryError(format!("invalid executable signing public key: {error}"))
    })?;
    let signature = Signature::from_slice(signature_bytes).map_err(|error| {
        Error::LibraryError(format!("invalid executable manifest signature: {error}"))
    })?;
    let digest = Sha256::digest(manifest_json);
    verifying_key.verify(&digest, &signature).map_err(|_| {
        Error::LibraryError("executable manifest signature verification failed".to_string())
    })
}

fn is_executable_content_path(relative_path: &str) -> bool {
    relative_path.starts_with("custom_checks/")
        || relative_path.starts_with("reviewed_check_packs/")
}

fn collect_regular_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::LibraryError(format!(
                "executable content path must not be a symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_regular_files(&path, output)?;
        } else if metadata.is_file() {
            output.push(path);
        } else {
            return Err(Error::LibraryError(format!(
                "executable content path is not a regular file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(value: &str, label: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::LibraryError(format!(
            "stored executable {label} has invalid hexadecimal length"
        )));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or_else(|| {
                Error::LibraryError(format!("stored executable {label} is not hexadecimal"))
            })?;
            let low = hex_nibble(pair[1]).ok_or_else(|| {
                Error::LibraryError(format!("stored executable {label} is not hexadecimal"))
            })?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let decoded = hex_decode(value, label)?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        Error::LibraryError(format!(
            "stored executable {label} must contain {N} bytes, got {}",
            bytes.len()
        ))
    })
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn read_index(root: &Path) -> Result<LibraryIndex> {
    let index_path = root.join("index.json");
    if !index_path.exists() {
        return Err(Error::LibraryError(format!(
            "No STIG library found at {}",
            root.display()
        )));
    }
    let content = fs::read_to_string(index_path)?;
    serde_json::from_str(&content).map_err(|error| Error::LibraryError(error.to_string()))
}

fn validate_managed_file_path(relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute() || relative.contains('\\') || relative.contains('\0') {
        return Err(Error::LibraryError(format!(
            "unsafe ancillary library path: {relative}"
        )));
    }
    let components = path.components().collect::<Vec<_>>();
    if components.len() < 2
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(value) if !value.is_empty()))
    {
        return Err(Error::LibraryError(format!(
            "ancillary library path is not canonical: {relative}"
        )));
    }
    let Some(Component::Normal(top)) = components.first() else {
        unreachable!("normal components checked above")
    };
    if !matches!(
        top.to_str(),
        Some("answer_templates" | "custom_checks" | "auto_check_packs" | "reviewed_check_packs")
    ) {
        return Err(Error::LibraryError(format!(
            "ancillary file is outside a managed content directory: {relative}"
        )));
    }
    Ok(path.to_path_buf())
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("library path is not a real directory: {}", path.display()),
        )));
    }
    Ok(())
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
    use crate::checks::{CheckPack, CheckPlatform};
    use crate::models::stig::{CheckAutomation, Platform, Severity, StigRule};
    use std::collections::BTreeMap;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    const PROCESS_ROOT_ENV: &str = "AUTOMATESTIG_TEST_LIBRARY_PROCESS_ROOT";
    const PROCESS_ID_ENV: &str = "AUTOMATESTIG_TEST_LIBRARY_PROCESS_ID";
    const PROCESS_READY_ENV: &str = "AUTOMATESTIG_TEST_LIBRARY_PROCESS_READY";
    const PROCESS_GATE_ENV: &str = "AUTOMATESTIG_TEST_LIBRARY_PROCESS_GATE";

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

    fn make_benchmark_with_id(id: &str) -> StigBenchmark {
        let mut benchmark = make_benchmark();
        benchmark.id = id.to_string();
        benchmark.title = format!("{id} title");
        benchmark
    }

    fn make_check_pack(stig_id: &str, version: &str) -> CheckPack {
        CheckPack {
            stig_id: stig_id.to_string(),
            platform: CheckPlatform::Bsd,
            version: version.to_string(),
            priority: 100,
            checks: Vec::new(),
        }
    }

    fn filesystem_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, path: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            entries.sort();

            for entry in entries {
                let relative = entry.strip_prefix(root).unwrap().to_path_buf();
                let metadata = fs::symlink_metadata(&entry).unwrap();
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    snapshot.insert(relative, b"<directory>".to_vec());
                    visit(root, &entry, snapshot);
                } else {
                    snapshot.insert(relative, fs::read(&entry).unwrap());
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    fn injected_storage_error(message: &str) -> Error {
        Error::Io(std::io::Error::other(message.to_string()))
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
    fn batch_import_commits_benchmarks_check_packs_and_reports_ids() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");
        let mut library = StigLibrary::init(&root).unwrap();
        let first = make_benchmark_with_id("First_STIG");
        let second = make_benchmark_with_id("Second_STIG");
        let first_pack = make_check_pack(&first.id, "generated-1");

        let outcome = library
            .import_benchmarks(&[
                BenchmarkImport::new(&second, GeneratedCheckPackIntent::Keep),
                BenchmarkImport::new(&first, GeneratedCheckPackIntent::Replace(&first_pack)),
            ])
            .unwrap();

        assert_eq!(
            outcome.added_ids,
            vec!["First_STIG".to_string(), "Second_STIG".to_string()]
        );
        assert!(outcome.updated_ids.is_empty());
        assert_eq!(
            outcome.generated_check_pack_ids,
            vec!["First_STIG".to_string()]
        );
        assert_eq!(outcome.added_count(), 2);
        assert_eq!(outcome.updated_count(), 0);
        assert_eq!(outcome.generated_check_pack_count(), 1);
        let loaded_first = library.load_benchmark("First_STIG").unwrap();
        assert_eq!(loaded_first.id, first.id);
        assert_eq!(loaded_first.title, first.title);
        let loaded_second = library.load_benchmark("Second_STIG").unwrap();
        assert_eq!(loaded_second.id, second.id);
        assert_eq!(loaded_second.title, second.title);

        let generated: CheckPack = serde_json::from_slice(
            &fs::read(root.join("auto_check_packs/First_STIG.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(generated.stig_id, "First_STIG");
        assert_eq!(generated.version, "generated-1");

        let old_pack_bytes = fs::read(root.join("auto_check_packs/First_STIG.json")).unwrap();
        let mut updated = first.clone();
        updated.title = "updated title".to_string();
        let outcome = library
            .import_benchmarks(&[BenchmarkImport::new(
                &updated,
                GeneratedCheckPackIntent::Keep,
            )])
            .unwrap();
        assert!(outcome.added_ids.is_empty());
        assert_eq!(outcome.updated_ids, vec!["First_STIG".to_string()]);
        assert!(outcome.generated_check_pack_ids.is_empty());
        assert_eq!(
            library.load_benchmark("First_STIG").unwrap().title,
            updated.title
        );
        assert_eq!(
            fs::read(root.join("auto_check_packs/First_STIG.json")).unwrap(),
            old_pack_bytes,
            "a benchmark-only update must preserve an existing generated pack"
        );

        let outcome = library
            .import_benchmarks(&[BenchmarkImport::new(
                &updated,
                GeneratedCheckPackIntent::Remove,
            )])
            .unwrap();
        assert!(outcome.generated_check_pack_ids.is_empty());
        assert_eq!(
            outcome.removed_generated_check_pack_ids,
            vec!["First_STIG".to_string()]
        );
        assert_eq!(outcome.removed_generated_check_pack_count(), 1);
        assert!(!root.join("auto_check_packs/First_STIG.json").exists());
    }

    #[test]
    fn preparation_failures_cause_zero_filesystem_mutation() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");
        let mut library = StigLibrary::init(&root).unwrap();
        let existing = make_benchmark_with_id("Existing_STIG");
        library.add_benchmark(&existing).unwrap();
        let baseline = filesystem_snapshot(&root);

        let candidate = make_benchmark_with_id("Candidate_STIG");
        let wrong_pack = make_check_pack("Different_STIG", "generated-1");
        assert!(library
            .import_benchmarks(&[BenchmarkImport::new(
                &candidate,
                GeneratedCheckPackIntent::Replace(&wrong_pack),
            )])
            .is_err());
        assert_eq!(filesystem_snapshot(&root), baseline);

        assert!(library
            .import_benchmarks(&[
                BenchmarkImport::new(&candidate, GeneratedCheckPackIntent::Keep),
                BenchmarkImport::new(&candidate, GeneratedCheckPackIntent::Keep),
            ])
            .is_err());
        assert_eq!(filesystem_snapshot(&root), baseline);

        let colliding = make_benchmark_with_id("Candidate STIG");
        assert!(library
            .import_benchmarks(&[
                BenchmarkImport::new(&candidate, GeneratedCheckPackIntent::Keep),
                BenchmarkImport::new(&colliding, GeneratedCheckPackIntent::Keep),
            ])
            .is_err());
        assert_eq!(filesystem_snapshot(&root), baseline);

        let result = library.import_benchmarks_with_hook(
            &[BenchmarkImport::new(
                &candidate,
                GeneratedCheckPackIntent::Keep,
            )],
            |step, _| {
                if step == ImportStep::SerializeIndex {
                    Err(Error::LibraryError(
                        "injected index serialization failure".to_string(),
                    ))
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(filesystem_snapshot(&root), baseline);
        assert!(library.get_benchmark_entry("Candidate_STIG").is_none());
    }

    #[test]
    fn staged_write_artifact_commit_and_index_commit_failures_roll_back() {
        for failure_step in [
            ImportStep::StageArtifact,
            ImportStep::CommitArtifact,
            ImportStep::CommitIndex,
        ] {
            let dir = TempDir::new().unwrap();
            let root = dir.path().join("stiglib");
            let mut library = StigLibrary::init(&root).unwrap();
            let original = make_benchmark_with_id("Existing_STIG");
            let original_pack = make_check_pack(&original.id, "original");
            library
                .import_benchmarks(&[BenchmarkImport::new(
                    &original,
                    GeneratedCheckPackIntent::Replace(&original_pack),
                )])
                .unwrap();
            let baseline = filesystem_snapshot(&root);

            let mut updated = original.clone();
            updated.title = "replacement that must roll back".to_string();
            let updated_pack = make_check_pack(&updated.id, "replacement");
            let added = make_benchmark_with_id("Added_STIG");
            let imports = [
                BenchmarkImport::new(&updated, GeneratedCheckPackIntent::Replace(&updated_pack)),
                BenchmarkImport::new(&added, GeneratedCheckPackIntent::Keep),
            ];
            let mut matching_steps = 0;
            let result = library.import_benchmarks_with_hook(&imports, |step, _| {
                if step == failure_step {
                    matching_steps += 1;
                    let fail_now = match failure_step {
                        ImportStep::StageArtifact | ImportStep::CommitArtifact => {
                            matching_steps == 2
                        }
                        ImportStep::CommitIndex => true,
                        _ => false,
                    };
                    if fail_now {
                        return Err(injected_storage_error("injected transaction failure"));
                    }
                }
                Ok(())
            });

            assert!(matches!(result, Err(Error::Io(_))), "{failure_step:?}");
            assert_eq!(
                filesystem_snapshot(&root),
                baseline,
                "{failure_step:?} left visible filesystem mutations"
            );
            assert_eq!(
                library.load_benchmark("Existing_STIG").unwrap().title,
                original.title
            );
            assert!(library.get_benchmark_entry("Added_STIG").is_none());
            assert!(fs::read_dir(&root).unwrap().all(|entry| {
                let name = entry.unwrap().file_name();
                let name = name.to_string_lossy();
                !name.starts_with(".library-transaction-") && !name.starts_with(".library-cleanup-")
            }));
        }
    }

    #[test]
    fn real_storage_error_is_propagated_without_a_partial_import() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");
        let mut library = StigLibrary::init(&root).unwrap();
        fs::write(root.join("auto_check_packs"), b"not a directory").unwrap();
        let baseline = filesystem_snapshot(&root);
        let benchmark = make_benchmark_with_id("Candidate_STIG");
        let pack = make_check_pack(&benchmark.id, "generated-1");

        let result = library.import_benchmarks(&[BenchmarkImport::new(
            &benchmark,
            GeneratedCheckPackIntent::Replace(&pack),
        )]);

        assert!(matches!(result, Err(Error::Io(_))));
        assert_eq!(filesystem_snapshot(&root), baseline);
        assert!(library.get_benchmark_entry("Candidate_STIG").is_none());
    }

    #[test]
    fn generated_check_pack_removal_rolls_back_with_the_benchmark_and_index() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");
        let mut library = StigLibrary::init(&root).unwrap();
        let original = make_benchmark_with_id("Existing_STIG");
        let original_pack = make_check_pack(&original.id, "original");
        library
            .import_benchmarks(&[BenchmarkImport::new(
                &original,
                GeneratedCheckPackIntent::Replace(&original_pack),
            )])
            .unwrap();
        let baseline = filesystem_snapshot(&root);
        let mut updated = original.clone();
        updated.title = "update that must roll back".to_string();

        let result = library.import_benchmarks_with_hook(
            &[BenchmarkImport::new(
                &updated,
                GeneratedCheckPackIntent::Remove,
            )],
            |step, _| {
                if step == ImportStep::CommitIndex {
                    Err(injected_storage_error("injected index commit failure"))
                } else {
                    Ok(())
                }
            },
        );

        assert!(matches!(result, Err(Error::Io(_))));
        assert_eq!(filesystem_snapshot(&root), baseline);
        assert_eq!(
            library.load_benchmark("Existing_STIG").unwrap().title,
            original.title
        );
        let restored: CheckPack = serde_json::from_slice(
            &fs::read(root.join("auto_check_packs/Existing_STIG.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.version, "original");
    }

    #[test]
    fn concurrent_stale_handles_do_not_lose_either_import() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");
        drop(StigLibrary::init(&root).unwrap());
        let first = StigLibrary::open(&root).unwrap();
        let second = StigLibrary::open(&root).unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let first_barrier = Arc::clone(&barrier);
        let first_worker = thread::spawn(move || {
            let mut library = first;
            let benchmark = make_benchmark_with_id("Thread_First_STIG");
            first_barrier.wait();
            library.add_benchmark(&benchmark)
        });
        let second_barrier = Arc::clone(&barrier);
        let second_worker = thread::spawn(move || {
            let mut library = second;
            let benchmark = make_benchmark_with_id("Thread_Second_STIG");
            second_barrier.wait();
            library.add_benchmark(&benchmark)
        });
        barrier.wait();

        first_worker.join().unwrap().unwrap();
        second_worker.join().unwrap().unwrap();
        let library = StigLibrary::open(&root).unwrap();
        assert!(library.get_benchmark_entry("Thread_First_STIG").is_some());
        assert!(library.get_benchmark_entry("Thread_Second_STIG").is_some());
    }

    // This test is also the subprocess entrypoint used below. In an ordinary
    // test run it has no environment contract and exits without side effects.
    #[test]
    fn cross_process_import_worker() {
        let Ok(root) = std::env::var(PROCESS_ROOT_ENV) else {
            return;
        };
        let id = std::env::var(PROCESS_ID_ENV).unwrap();
        let ready = PathBuf::from(std::env::var(PROCESS_READY_ENV).unwrap());
        let gate = PathBuf::from(std::env::var(PROCESS_GATE_ENV).unwrap());
        let mut library = StigLibrary::open(Path::new(&root)).unwrap();
        fs::write(&ready, b"ready").unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while !gate.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for parent process gate"
            );
            thread::sleep(Duration::from_millis(10));
        }
        library.add_benchmark(&make_benchmark_with_id(&id)).unwrap();
    }

    fn spawn_import_worker(root: &Path, id: &str, ready: &Path, gate: &Path) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("library::tests::cross_process_import_worker")
            .arg("--nocapture")
            .env(PROCESS_ROOT_ENV, root)
            .env(PROCESS_ID_ENV, id)
            .env(PROCESS_READY_ENV, ready)
            .env(PROCESS_GATE_ENV, gate)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn wait_for_workers_ready(children: &mut [&mut Child], ready: &[&Path]) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if ready.iter().all(|path| path.exists()) {
                return;
            }
            for child in children.iter_mut() {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!("library import worker exited before the gate: {status}");
                }
            }
            if Instant::now() >= deadline {
                for child in children.iter_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                panic!("timed out waiting for library import workers");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn concurrent_processes_do_not_lose_either_import() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("stiglib");
        drop(StigLibrary::init(&root).unwrap());
        let ready_first = dir.path().join("ready-first");
        let ready_second = dir.path().join("ready-second");
        let gate = dir.path().join("gate");
        let mut first = spawn_import_worker(&root, "Process_First_STIG", &ready_first, &gate);
        let mut second = spawn_import_worker(&root, "Process_Second_STIG", &ready_second, &gate);
        wait_for_workers_ready(
            &mut [&mut first, &mut second],
            &[ready_first.as_path(), ready_second.as_path()],
        );
        fs::write(&gate, b"go").unwrap();

        for (name, child) in [("first", first), ("second", second)] {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{name} import worker failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let library = StigLibrary::open(&root).unwrap();
        assert!(library.get_benchmark_entry("Process_First_STIG").is_some());
        assert!(library.get_benchmark_entry("Process_Second_STIG").is_some());
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
