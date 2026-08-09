//! Application state shared across API handlers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

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
    /// Serializes each STIG Manager asset lookup/create/push flow by remote
    /// collection and case-insensitive checklist hostname. Weak entries avoid
    /// retaining an unbounded set of one-off asset identities.
    pub stigman_push_locks: StigManagerPushLocks,
    /// Serializes operations that publish, mutate, or delete one checklist.
    /// A push holds this lock through the remote review write so it cannot
    /// publish a snapshot concurrently replaced or deleted by the GUI.
    pub checklist_operation_locks: ChecklistOperationLocks,
    /// Short-lived, non-secret preflight bindings. The scanner API stores only
    /// target/profile/destination identity and observed fingerprints here;
    /// device credentials remain in the request that performs the check.
    pub scanner_preflights: Mutex<HashMap<String, serde_json::Value>>,
}

/// Per-remote-asset locks for idempotent STIG Manager list-then-create flows.
#[derive(Default)]
pub struct StigManagerPushLocks {
    entries: Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
}

impl StigManagerPushLocks {
    pub fn lock_for(&self, collection_id: &str, hostname: &str) -> Arc<tokio::sync::Mutex<()>> {
        let key = format!(
            "{}\0{}",
            collection_id.trim(),
            hostname.trim().to_ascii_lowercase()
        );
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = entries.get(&key).and_then(Weak::upgrade) {
            return lock;
        }

        let lock = Arc::new(tokio::sync::Mutex::new(()));
        entries.insert(key, Arc::downgrade(&lock));
        lock
    }
}

/// Per-checklist locks for local mutation and external publication boundaries.
#[derive(Default)]
pub struct ChecklistOperationLocks {
    entries: Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
}

impl ChecklistOperationLocks {
    pub fn lock_for(&self, checklist_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let key = checklist_id.trim().to_owned();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = entries.get(&key).and_then(Weak::upgrade) {
            return lock;
        }

        let lock = Arc::new(tokio::sync::Mutex::new(()));
        entries.insert(key, Arc::downgrade(&lock));
        lock
    }
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
                stigman_push_locks: StigManagerPushLocks::default(),
                checklist_operation_locks: ChecklistOperationLocks::default(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stigman_push_locks_serialize_case_insensitive_remote_asset_identity() {
        let locks = StigManagerPushLocks::default();
        let first = locks.lock_for(" collection-7 ", " Router.Example.Mil ");
        let same = locks.lock_for("collection-7", "router.example.mil");
        let other_collection = locks.lock_for("collection-8", "router.example.mil");
        let other_hostname = locks.lock_for("collection-7", "switch.example.mil");

        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other_collection));
        assert!(!Arc::ptr_eq(&first, &other_hostname));

        let first_guard = first.lock().await;
        assert!(other_collection.try_lock().is_ok());
        assert!(other_hostname.try_lock().is_ok());
        assert!(tokio::time::timeout(Duration::from_millis(20), same.lock())
            .await
            .is_err());
        drop(first_guard);
        let _second_guard = tokio::time::timeout(Duration::from_secs(1), same.lock())
            .await
            .expect("same remote asset stayed locked");
    }

    #[tokio::test]
    async fn checklist_operation_locks_serialize_only_the_same_checklist() {
        let locks = ChecklistOperationLocks::default();
        let first = locks.lock_for(" checklist-7 ");
        let same = locks.lock_for("checklist-7");
        let other = locks.lock_for("checklist-8");

        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other));

        let first_guard = first.lock().await;
        assert!(other.try_lock().is_ok());
        assert!(tokio::time::timeout(Duration::from_millis(20), same.lock())
            .await
            .is_err());
        drop(first_guard);
        let _second_guard = tokio::time::timeout(Duration::from_secs(1), same.lock())
            .await
            .expect("same checklist stayed locked");
    }

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
