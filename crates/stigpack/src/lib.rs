//! STIG Content Pack (.stigpack) format.
//!
//! A .stigpack is a signed ZIP archive containing STIG benchmarks, answer file
//! templates, custom checks, and remediation scripts. The format supports:
//! - SHA-256 integrity verification
//! - Ed25519 digital signatures
//! - Version metadata and dependency tracking
//! - Incremental updates (delta packs)
//!
//! ## Pack Structure
//! ```text
//! my_stig_pack.stigpack (ZIP)
//! ├── manifest.json          # Pack metadata, file list, hashes
//! ├── signature.sig          # Ed25519 signature of manifest.json
//! ├── benchmarks/            # STIG benchmark data files (JSON)
//! │   ├── Windows_Server_2022_STIG.json
//! │   └── RHEL_9_STIG.json
//! ├── answer_templates/      # Pre-built answer files
//! │   └── Windows_Server_2022_answers.yaml
//! ├── custom_checks/         # Custom check definitions
//! └── remediation/           # Remediation scripts
//!     ├── ansible/
//!     ├── powershell/
//!     └── bash/
//! ```

pub mod builder;
pub mod importer;
pub mod manifest;
pub mod signing;
pub mod verifier;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StigpackError {
    #[error("Invalid stigpack: {0}")]
    InvalidPack(String),

    #[error("Manifest error: {0}")]
    ManifestError(String),

    #[error("Integrity check failed for {file}: expected {expected}, got {actual}")]
    IntegrityError {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    #[error("Missing file in pack: {0}")]
    MissingFile(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type StigpackResult<T> = std::result::Result<T, StigpackError>;
