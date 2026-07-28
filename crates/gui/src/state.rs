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
    /// Serializes all library-writing content imports. Each import still does
    /// parsing/decompression on the blocking pool while holding this permit.
    pub content_import_lock: Arc<tokio::sync::Semaphore>,
}

impl AppState {
    /// Initialize application state with default paths.
    pub fn init() -> anyhow::Result<Self> {
        let data_dir = default_data_dir();
        secure_private_directory(&data_dir)?;

        let db_path = data_dir.join("data.db");
        secure_database_path(&db_path)?;
        let db = Database::open(&db_path)?;

        let library_path = data_dir.join("library");
        secure_private_directory(&library_path)?;
        StigLibrary::open_or_init(&library_path)
            .map_err(|error| anyhow::anyhow!("Failed to initialize STIG library: {error}"))?;

        Ok(Self {
            inner: Arc::new(AppStateInner {
                db: Mutex::new(db),
                library_path,
                data_dir,
                content_import_lock: Arc::new(tokio::sync::Semaphore::new(1)),
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

    /// Open the STIG library.
    pub fn library(&self) -> anyhow::Result<StigLibrary> {
        StigLibrary::open_or_init(&self.inner.library_path)
            .map_err(|e| anyhow::anyhow!("Failed to open library: {}", e))
    }
}

fn secure_private_directory(path: &std::path::Path) -> anyhow::Result<()> {
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
    Ok(())
}

fn secure_database_path(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "database path must be a regular non-symlink file: {}",
                path.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                anyhow::ensure!(
                    metadata.uid() == unsafe { libc::geteuid() },
                    "database is not owned by the current user: {}",
                    path.display()
                );
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            options.open(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn default_data_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".automatestig")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiter_cannot_release_a_running_blocking_workers_permit() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();

        let worker = tokio::task::spawn_blocking(move || {
            // This is the same ownership boundary used by every content import:
            // the permit belongs to the blocking operation, not its HTTP waiter.
            let _permit = permit;
            started_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
        });
        started_receiver.await.unwrap();

        // Aborting a JoinHandle cannot stop an already-running blocking task.
        // It must therefore also be unable to release that task's permit.
        worker.abort();
        assert!(semaphore.clone().try_acquire_owned().is_err());

        release_sender.send(()).unwrap();
        let reacquired =
            tokio::time::timeout(Duration::from_secs(2), semaphore.clone().acquire_owned())
                .await
                .expect("blocking worker did not release its permit")
                .unwrap();
        drop(reacquired);
        let _ = worker.await;
    }
}
