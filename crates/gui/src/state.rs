//! Application state shared across API handlers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use automatestig_storage::Database;

use crate::scanner_api::StoredPreflight;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub db: Mutex<Database>,
    pub data_dir: PathBuf,
    /// Short-lived, non-secret preflight bindings. The scanner API stores only
    /// target/profile/destination identity and observed fingerprints here;
    /// device credentials remain in the request that performs the check.
    pub(crate) scanner_preflights: Mutex<HashMap<String, StoredPreflight>>,
}

impl AppState {
    /// Initialize application state with default paths.
    pub fn init() -> anyhow::Result<Self> {
        let data_dir = default_data_dir();
        secure_private_directory(&data_dir)?;

        let db_path = data_dir.join("data.db");
        let db = Database::open(&db_path)?;

        Ok(Self {
            inner: Arc::new(AppStateInner {
                db: Mutex::new(db),
                data_dir,
                scanner_preflights: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Get a reference to the database.
    pub fn db(&self) -> std::sync::MutexGuard<'_, Database> {
        // Recover from poison because Database state is not corrupted by a panic while locked.
        self.inner
            .db
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(crate) fn secure_private_directory(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "security-sensitive path must be a real directory: {}",
                path.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                anyhow::ensure!(
                    metadata.uid() == unsafe { libc::geteuid() },
                    "security-sensitive directory is not owned by the current user: {}",
                    path.display()
                );
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(error) => return Err(error.into()),
    }
    automatestig_core::path_safety::validate_sensitive_directory(
        path,
        "security-sensitive directory",
    )
    .map(|_| ())
    .map_err(anyhow::Error::from)
}

fn default_data_dir() -> PathBuf {
    std::env::var_os("AUTOMATESTIG_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".automatestig")
        })
}
