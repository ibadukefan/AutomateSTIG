//! Application state shared across API handlers.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use automatestig_core::library::StigLibrary;
use automatestig_storage::Database;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub db: Mutex<Database>,
    pub library_path: PathBuf,
    pub data_dir: PathBuf,
}

impl AppState {
    /// Initialize application state with default paths.
    pub fn init() -> anyhow::Result<Self> {
        let data_dir = default_data_dir();
        std::fs::create_dir_all(&data_dir)?;

        let db_path = data_dir.join("data.db");
        let db = Database::open(&db_path)?;

        let library_path = data_dir.join("library");
        // Ensure library exists.
        let _ = StigLibrary::open_or_init(&library_path);

        Ok(Self {
            inner: Arc::new(AppStateInner {
                db: Mutex::new(db),
                library_path,
                data_dir,
            }),
        })
    }

    /// Get a reference to the database.
    pub fn db(&self) -> std::sync::MutexGuard<'_, Database> {
        // Use expect here — a poisoned mutex means a handler panicked,
        // which is a programming error we want to surface clearly.
        self.inner
            .db
            .lock()
            .expect("Database mutex poisoned — a previous operation panicked")
    }

    /// Open the STIG library.
    pub fn library(&self) -> anyhow::Result<StigLibrary> {
        StigLibrary::open_or_init(&self.inner.library_path)
            .map_err(|e| anyhow::anyhow!("Failed to open library: {}", e))
    }
}

fn default_data_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".automatestig")
}
