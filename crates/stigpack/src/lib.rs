//! STIG Content Pack (.stigpack) format.
//!
//! A .stigpack is a signed ZIP archive containing STIG benchmarks, answer file
//! templates, curated checks, and generated check packs. The format supports:
//! - SHA-256 integrity verification
//! - Ed25519 digital signatures
//! - Version metadata
//!
//! ## Pack Structure
//! ```text
//! my_stig_pack.stigpack (ZIP)
//! ├── manifest.json          # Pack metadata, file list, hashes
//! ├── signature.sig          # Ed25519 signature of manifest.json
//! ├── benchmarks/            # STIG benchmark data files (JSON)
//! │   └── RHEL_9_STIG.json
//! ├── answer_templates/      # Pre-built answer files
//! │   └── RHEL_9_answers.yaml
//! ├── custom_checks/         # Curated check definitions
//! └── auto_check_packs/      # Signed reviewed generated definitions on the wire
//! ```
//!
//! Trusted import promotes `auto_check_packs/` members into the local
//! `reviewed_check_packs/` directory. Runtime evaluation never loads the legacy
//! local `auto_check_packs/` directory.

pub mod builder;
pub mod importer;
pub mod manifest;
pub mod signing;
pub mod verifier;

use std::path::{Component, Path};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StigpackError {
    #[error("Unsafe archive: {0}")]
    Archive(#[from] automatestig_archive_safety::ArchiveError),

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

    #[error("STIG library transaction failed: {0}")]
    Library(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type StigpackResult<T> = std::result::Result<T, StigpackError>;

pub(crate) fn validate_member_path(relative: &str) -> StigpackResult<()> {
    if relative.trim().is_empty() || relative.contains('\\') || relative.contains('\0') {
        return Err(StigpackError::ManifestError(format!(
            "unsafe .stigpack member path: {relative}"
        )));
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err(StigpackError::ManifestError(format!(
            "absolute .stigpack member paths are not allowed: {relative}"
        )));
    }
    for component in path.components() {
        match component {
            Component::Normal(part) if !part.is_empty() => {}
            _ => {
                return Err(StigpackError::ManifestError(format!(
                    "unsafe .stigpack member path: {relative}"
                )))
            }
        }
    }
    Ok(())
}
