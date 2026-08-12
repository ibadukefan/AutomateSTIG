//! Durable, crash-recoverable filesystem transactions for STIG library content.
//!
//! All compliant library writers take the same cross-process lock. Transactions
//! stage and sync bytes under the library root, persist an immutable journal,
//! create an `applying` marker before the first visible rename, and create a
//! `committed` marker after the last rename. Recovery can therefore either roll
//! an interrupted transaction back or finish cleanup without guessing intent.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const LOCK_FILE: &str = ".library.lock";
const ACTIVE_PREFIX: &str = ".library-transaction-";
const CLEANUP_PREFIX: &str = ".library-cleanup-";
const JOURNAL_FILE: &str = "journal.json";
const APPLYING_MARKER: &str = "applying";
const COMMITTED_MARKER: &str = "committed";
const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;

/// The two mutation boundaries exposed to fault-injection hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryInstallStep {
    /// Any previous destination is safely in the transaction backup.
    BeforeInstall,
    /// The staged replacement is now at its final destination.
    Installed,
}

/// Exclusive cross-process ownership of one library root.
pub struct LibraryWriteGuard {
    root: PathBuf,
    lock_file: File,
}

impl LibraryWriteGuard {
    /// Acquire the library lock and recover every interrupted transaction before
    /// allowing the caller to inspect or mutate managed content.
    pub fn acquire(root: &Path) -> Result<Self> {
        ensure_real_directory(root, "library root")?;
        let lock_path = root.join(LOCK_FILE);
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::LibraryError(format!(
                    "library lock path is not a regular file: {}",
                    lock_path.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        lock_file.lock()?;

        let guard = Self {
            root: root.to_path_buf(),
            lock_file,
        };
        if let Err(error) = recover_library_transactions(root) {
            // Unlock explicitly so a recovery failure never holds the process
            // hostage until an unrelated owner is dropped.
            let _ = guard.lock_file.unlock();
            return Err(error);
        }
        Ok(guard)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for LibraryWriteGuard {
    fn drop(&mut self) {
        let _ = self.lock_file.unlock();
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionJournal {
    version: u32,
    entries: Vec<JournalEntry>,
    created_directories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    relative_path: String,
    had_original: bool,
    #[serde(default)]
    operation: JournalOperation,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalOperation {
    #[default]
    Replace,
    Remove,
}

/// One durable multi-file mutation transaction under a held library lock.
pub struct LibraryTransaction<'a> {
    guard: &'a LibraryWriteGuard,
    path: PathBuf,
    journal: TransactionJournal,
    seen_paths: HashSet<PathBuf>,
    prepared: bool,
    applying: bool,
    finished: bool,
}

impl<'a> LibraryTransaction<'a> {
    pub fn new(guard: &'a LibraryWriteGuard) -> Result<Self> {
        let path = guard
            .root
            .join(format!("{ACTIVE_PREFIX}{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        if let Err(error) =
            fs::create_dir(path.join("stage")).and_then(|_| fs::create_dir(path.join("backup")))
        {
            let _ = fs::remove_dir_all(&path);
            return Err(error.into());
        }
        sync_directory(guard.root())?;
        Ok(Self {
            guard,
            path,
            journal: TransactionJournal {
                version: JOURNAL_VERSION,
                entries: Vec::new(),
                created_directories: Vec::new(),
            },
            seen_paths: HashSet::new(),
            prepared: false,
            applying: false,
            finished: false,
        })
    }

    /// Stage one regular file. The immutable original-existence decision is
    /// captured while the cross-process lock is held.
    pub fn stage_file(&mut self, relative_path: &Path, bytes: &[u8]) -> Result<()> {
        if self.prepared || self.applying || self.finished {
            return Err(Error::LibraryError(
                "cannot add mutations after a library transaction is prepared".to_string(),
            ));
        }
        let relative_path = validate_relative_path(relative_path)?;
        if !self.seen_paths.insert(relative_path.clone()) {
            return Err(Error::LibraryError(format!(
                "duplicate library transaction destination: {}",
                relative_path.display()
            )));
        }

        let destination = self.guard.root.join(&relative_path);
        ensure_real_parent_chain(self.guard.root(), &destination, true)?;
        let had_original = match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::LibraryError(format!(
                    "library transaction destination is not a regular file: {}",
                    destination.display()
                )));
            }
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };

        let staged = self.path.join("stage").join(&relative_path);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent)?;
            sync_directory_chain(parent, &self.path)?;
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // File sync persists the bytes; directory sync persists the newly
        // created staged name that the journal will reference after a crash.
        sync_parent(&staged)?;

        let relative_string = relative_path.to_str().ok_or_else(|| {
            Error::LibraryError(format!(
                "library transaction path is not UTF-8: {}",
                relative_path.display()
            ))
        })?;
        self.journal.entries.push(JournalEntry {
            relative_path: relative_string.replace('\\', "/"),
            had_original,
            operation: JournalOperation::Replace,
        });
        Ok(())
    }

    /// Stage removal of one regular file. Missing destinations are an
    /// idempotent no-op; existing files move into the transaction backup during
    /// apply so an interrupted or failed removal can be restored.
    pub fn remove_file(&mut self, relative_path: &Path) -> Result<()> {
        if self.prepared || self.applying || self.finished {
            return Err(Error::LibraryError(
                "cannot add mutations after a library transaction is prepared".to_string(),
            ));
        }
        let relative_path = validate_relative_path(relative_path)?;
        if !self.seen_paths.insert(relative_path.clone()) {
            return Err(Error::LibraryError(format!(
                "duplicate library transaction destination: {}",
                relative_path.display()
            )));
        }

        let destination = self.guard.root.join(&relative_path);
        ensure_real_parent_chain(self.guard.root(), &destination, true)?;
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::LibraryError(format!(
                    "library transaction removal target is not a regular file: {}",
                    destination.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }

        let relative_string = relative_path.to_str().ok_or_else(|| {
            Error::LibraryError(format!(
                "library transaction path is not UTF-8: {}",
                relative_path.display()
            ))
        })?;
        self.journal.entries.push(JournalEntry {
            relative_path: relative_string.replace('\\', "/"),
            had_original: true,
            operation: JournalOperation::Remove,
        });
        Ok(())
    }

    /// Install every staged file and durably commit the transaction. Any error
    /// before the committed marker is persisted triggers an immediate rollback;
    /// a failed rollback leaves the journal and backups in place for recovery.
    pub fn install_and_commit<F>(&mut self, mut hook: F) -> Result<()>
    where
        F: FnMut(LibraryInstallStep, &Path) -> Result<()>,
    {
        let operation = (|| -> Result<()> {
            self.prepare()?;
            self.begin_apply()?;
            self.apply_raw(&mut hook)?;
            self.mark_committed()?;
            Ok(())
        })();

        match operation {
            Ok(()) => {
                self.finish_committed_cleanup();
                Ok(())
            }
            Err(original) => match self.rollback_internal() {
                Ok(()) => Err(original),
                Err(rollback) => Err(Error::LibraryError(format!(
                    "library transaction failed ({original}); rollback also failed ({rollback}); backups preserved at {}",
                    self.path.display()
                ))),
            },
        }
    }

    fn prepare(&mut self) -> Result<()> {
        if self.prepared {
            return Ok(());
        }
        self.journal.entries.sort_by(|left, right| {
            let left_is_index = left.relative_path == "index.json";
            let right_is_index = right.relative_path == "index.json";
            left_is_index
                .cmp(&right_is_index)
                .then_with(|| left.relative_path.cmp(&right.relative_path))
        });
        self.collect_missing_directories()?;

        let journal_path = self.path.join(JOURNAL_FILE);
        let bytes = serde_json::to_vec_pretty(&self.journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(Error::LibraryError(format!(
                "library transaction journal exceeds {MAX_JOURNAL_BYTES} bytes"
            )));
        }
        let mut journal = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&journal_path)?;
        journal.write_all(&bytes)?;
        journal.sync_all()?;
        sync_directory(&self.path)?;
        self.prepared = true;
        Ok(())
    }

    fn collect_missing_directories(&mut self) -> Result<()> {
        let mut missing = HashSet::new();
        for entry in &self.journal.entries {
            if entry.operation == JournalOperation::Remove {
                continue;
            }
            let relative = Path::new(&entry.relative_path);
            let Some(parent) = relative.parent() else {
                continue;
            };
            let mut relative_directory = PathBuf::new();
            for component in parent.components() {
                let Component::Normal(component) = component else {
                    return Err(Error::LibraryError(format!(
                        "non-normal library transaction path: {}",
                        relative.display()
                    )));
                };
                relative_directory.push(component);
                let destination = self.guard.root.join(&relative_directory);
                match fs::symlink_metadata(&destination) {
                    Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                        return Err(not_a_directory_error(
                            "library transaction parent",
                            &destination,
                        ));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        missing.insert(relative_directory.clone());
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let mut missing = missing.into_iter().collect::<Vec<_>>();
        missing.sort_by(|left, right| {
            left.components()
                .count()
                .cmp(&right.components().count())
                .then_with(|| left.cmp(right))
        });
        self.journal.created_directories = missing
            .into_iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect();
        Ok(())
    }

    fn begin_apply(&mut self) -> Result<()> {
        if self.applying {
            return Ok(());
        }
        durable_marker(&self.path.join(APPLYING_MARKER))?;
        sync_directory(&self.path)?;
        self.applying = true;

        for relative in &self.journal.created_directories {
            let directory = self.guard.root.join(relative);
            match fs::create_dir(&directory) {
                Ok(()) => {
                    if let Some(parent) = directory.parent() {
                        sync_directory(parent)?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_real_directory(&directory, "library transaction parent")?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn apply_raw<F>(&mut self, hook: &mut F) -> Result<()>
    where
        F: FnMut(LibraryInstallStep, &Path) -> Result<()>,
    {
        for entry in &self.journal.entries {
            let relative = Path::new(&entry.relative_path);
            let destination = self.guard.root.join(relative);
            let staged = self.path.join("stage").join(relative);
            let backup = self.path.join("backup").join(relative);
            ensure_real_parent_chain(self.guard.root(), &destination, false)?;

            if entry.had_original {
                if let Some(parent) = backup.parent() {
                    fs::create_dir_all(parent)?;
                    sync_directory_chain(parent, &self.path)?;
                }
                fs::rename(&destination, &backup)?;
                sync_parent(&destination)?;
                sync_parent(&backup)?;
            } else if fs::symlink_metadata(&destination).is_ok() {
                return Err(Error::LibraryError(format!(
                    "library destination appeared during a locked transaction: {}",
                    destination.display()
                )));
            }

            hook(LibraryInstallStep::BeforeInstall, relative)?;
            match entry.operation {
                JournalOperation::Replace => {
                    fs::rename(&staged, &destination)?;
                    sync_parent(&staged)?;
                    sync_parent(&destination)?;
                }
                JournalOperation::Remove => {
                    // The backup rename above is the removal. Its source and
                    // destination directories were both synchronized already.
                    debug_assert!(!destination.exists());
                }
            }
            hook(LibraryInstallStep::Installed, relative)?;
        }
        Ok(())
    }

    fn mark_committed(&mut self) -> Result<()> {
        let marker_path = self.path.join(COMMITTED_MARKER);
        let marker = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&marker_path)?;
        // Once the committed name is visible, rollback is no longer safe. If a
        // subsequent flush fails, leave the transaction for recovery: the marker
        // will either survive (keep the new generation) or be absent after a
        // crash (roll the applying generation back), but recovery never sees a
        // partially rolled-back transaction carrying a committed marker.
        self.finished = true;
        marker.sync_all()?;
        sync_directory(&self.path)?;
        Ok(())
    }

    fn finish_committed_cleanup(&mut self) {
        let _ = move_to_cleanup_and_remove(self.guard.root(), &mut self.path);
    }

    fn rollback_internal(&mut self) -> std::io::Result<()> {
        if self.finished {
            return Ok(());
        }
        if !self.applying && !self.path.join(APPLYING_MARKER).exists() {
            self.finished = true;
            return move_to_cleanup_and_remove(self.guard.root(), &mut self.path);
        }
        rollback_journal(self.guard.root(), &self.path, &self.journal)?;
        self.finished = true;
        move_to_cleanup_and_remove(self.guard.root(), &mut self.path)
    }

    #[cfg(test)]
    pub(crate) fn apply_without_commit_for_test(&mut self) -> Result<()> {
        self.prepare()?;
        self.begin_apply()?;
        self.apply_raw(&mut |_, _| Ok(()))
    }

    #[cfg(test)]
    pub(crate) fn transaction_path_for_test(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn mark_committed_for_test(&mut self) -> Result<()> {
        self.mark_committed()
    }

    #[cfg(test)]
    pub(crate) fn rollback_for_test(&mut self) -> std::io::Result<()> {
        self.rollback_internal()
    }
}

impl Drop for LibraryTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // rollback_internal preserves the active transaction on error. Never
            // remove the only backup merely because a destructor is running.
            let _ = self.rollback_internal();
        }
    }
}

fn recover_library_transactions(root: &Path) -> Result<()> {
    let mut entries = fs::read_dir(root)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let path = entry.path();
        if name.starts_with(CLEANUP_PREFIX) {
            // A cleanup-only name is the durable indication that no rollback is
            // ever appropriate, even if an earlier recursive delete was partial.
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Error::LibraryError(format!(
                    "library cleanup state is not a real directory: {}",
                    path.display()
                )));
            }
            fs::remove_dir_all(&path).map_err(|error| {
                Error::LibraryError(format!(
                    "failed to finish library transaction cleanup at {}: {error}; remaining backups preserved",
                    path.display()
                ))
            })?;
            sync_directory(root)?;
            continue;
        }
        if !name.starts_with(ACTIVE_PREFIX) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::LibraryError(format!(
                "abandoned library transaction is not a real directory: {}",
                path.display()
            )));
        }
        if path.join(COMMITTED_MARKER).exists() {
            let mut cleanup_path = path.clone();
            move_to_cleanup_and_remove(root, &mut cleanup_path)?;
            continue;
        }
        if !path.join(APPLYING_MARKER).exists() {
            let mut cleanup_path = path.clone();
            move_to_cleanup_and_remove(root, &mut cleanup_path)?;
            continue;
        }

        let journal = read_journal(&path)?;
        rollback_journal(root, &path, &journal).map_err(|error| {
            Error::LibraryError(format!(
                "failed to recover abandoned library transaction {}: {error}; backups preserved",
                path.display()
            ))
        })?;
        let mut cleanup_path = path;
        move_to_cleanup_and_remove(root, &mut cleanup_path)?;
    }
    Ok(())
}

fn read_journal(transaction_path: &Path) -> Result<TransactionJournal> {
    let path = transaction_path.join(JOURNAL_FILE);
    let metadata = fs::metadata(&path)?;
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(Error::LibraryError(format!(
            "transaction journal exceeds {MAX_JOURNAL_BYTES} bytes: {}",
            path.display()
        )));
    }
    let bytes = fs::read(&path)?;
    let journal: TransactionJournal = serde_json::from_slice(&bytes)?;
    if journal.version != JOURNAL_VERSION {
        return Err(Error::LibraryError(format!(
            "unsupported library transaction journal version {} at {}",
            journal.version,
            path.display()
        )));
    }
    let mut seen = HashSet::new();
    for entry in &journal.entries {
        let relative = validate_relative_path(Path::new(&entry.relative_path))?;
        if !seen.insert(relative) {
            return Err(Error::LibraryError(format!(
                "duplicate path in transaction journal: {}",
                entry.relative_path
            )));
        }
    }
    for directory in &journal.created_directories {
        validate_relative_path(Path::new(directory))?;
    }
    Ok(journal)
}

fn rollback_journal(
    root: &Path,
    transaction_path: &Path,
    journal: &TransactionJournal,
) -> std::io::Result<()> {
    for entry in journal.entries.iter().rev() {
        let relative = Path::new(&entry.relative_path);
        let destination = root.join(relative);
        let staged = transaction_path.join("stage").join(relative);
        let backup = transaction_path.join("backup").join(relative);

        if entry.had_original {
            if backup.exists() {
                remove_regular_file_if_present(&destination)?;
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::rename(&backup, &destination)?;
                sync_parent(&backup)?;
                sync_parent(&destination)?;
            }
        } else {
            match entry.operation {
                JournalOperation::Replace if !staged.exists() => {
                    // Rename semantics guarantee that a missing staged file
                    // means the transaction installed it (or an earlier
                    // rollback removed it).
                    remove_regular_file_if_present(&destination)?;
                    sync_parent(&destination)?;
                }
                JournalOperation::Replace if destination.exists() => {
                    return Err(std::io::Error::other(format!(
                        "unexpected destination appeared while staged file remains: {}",
                        destination.display()
                    )));
                }
                JournalOperation::Replace => {}
                JournalOperation::Remove if destination.exists() => {
                    return Err(std::io::Error::other(format!(
                        "unexpected destination appeared for absent removal target: {}",
                        destination.display()
                    )));
                }
                JournalOperation::Remove => {}
            }
        }
    }

    for relative in journal.created_directories.iter().rev() {
        let directory = root.join(relative);
        match fs::remove_dir(&directory) {
            Ok(()) => sync_parent(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn move_to_cleanup_and_remove(root: &Path, path: &mut PathBuf) -> std::io::Result<()> {
    if path.exists() {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(ACTIVE_PREFIX);
        if name.starts_with(ACTIVE_PREFIX) {
            let suffix = name.strip_prefix(ACTIVE_PREFIX).unwrap_or(name);
            let cleanup = root.join(format!("{CLEANUP_PREFIX}{suffix}"));
            fs::rename(&*path, &cleanup)?;
            sync_directory(root)?;
            *path = cleanup;
        }
        // On failure the cleanup-only name is intentionally preserved. Recovery
        // will retry deletion and will never roll its remaining backups back.
        fs::remove_dir_all(&*path)?;
        sync_directory(root)?;
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(Error::LibraryError(format!(
            "library transaction path must be relative: {}",
            path.display()
        )));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) if !value.is_empty() => normalized.push(value),
            _ => {
                return Err(Error::LibraryError(format!(
                    "library transaction path is not canonical: {}",
                    path.display()
                )))
            }
        }
    }
    if normalized.as_os_str().is_empty()
        || normalized == Path::new(LOCK_FILE)
        || normalized
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with(ACTIVE_PREFIX) || name.starts_with(CLEANUP_PREFIX))
    {
        return Err(Error::LibraryError(format!(
            "reserved library transaction path: {}",
            path.display()
        )));
    }
    Ok(normalized)
}

fn ensure_real_parent_chain(root: &Path, destination: &Path, allow_missing: bool) -> Result<()> {
    ensure_real_directory(root, "library root")?;
    let relative = destination.strip_prefix(root).map_err(|error| {
        Error::LibraryError(format!(
            "library destination {} is outside root {}: {error}",
            destination.display(),
            root.display()
        ))
    })?;
    let Some(parent) = relative.parent() else {
        return Err(Error::LibraryError(format!(
            "library destination has no parent: {}",
            destination.display()
        )));
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(Error::LibraryError(format!(
                "library destination has a non-normal parent: {}",
                destination.display()
            )));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(not_a_directory_error(
                    "library destination parent",
                    &current,
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && allow_missing => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn ensure_real_directory(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::LibraryError(format!(
            "{description} is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn not_a_directory_error(description: &str, path: &Path) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotADirectory,
        format!("{description} is not a real directory: {}", path.display()),
    ))
}

fn durable_marker(path: &Path) -> std::io::Result<()> {
    let file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.sync_all()
}

fn remove_regular_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(path)
        }
        Ok(_) => Err(std::io::Error::other(format!(
            "refusing to remove non-file transaction destination: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent)
    } else {
        Ok(())
    }
}

fn sync_directory_chain(path: &Path, stop: &Path) -> std::io::Result<()> {
    if !path.starts_with(stop) {
        return Err(std::io::Error::other(format!(
            "directory {} is outside sync root {}",
            path.display(),
            stop.display()
        )));
    }
    let mut current = path;
    loop {
        sync_directory(current)?;
        if current == stop {
            return Ok(());
        }
        current = current.parent().ok_or_else(|| {
            std::io::Error::other(format!(
                "directory {} has no ancestor {}",
                path.display(),
                stop.display()
            ))
        })?;
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    // FILE_FLAG_BACKUP_SEMANTICS permits a directory handle. sync_all then
    // invokes FlushFileBuffers so rename/create metadata reaches the volume.
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "durable library transactions are unsupported on this platform: {}",
            path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::mpsc::RecvTimeoutError;
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    const LOCK_ROOT_ENV: &str = "AUTOMATESTIG_TEST_LOCK_ROOT";
    const LOCK_ACQUIRED_ENV: &str = "AUTOMATESTIG_TEST_LOCK_ACQUIRED";
    const LOCK_RELEASE_ENV: &str = "AUTOMATESTIG_TEST_LOCK_RELEASE";

    fn create_root() -> TempDir {
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("content")).unwrap();
        root
    }

    #[test]
    fn abandoned_applying_transaction_is_rolled_back_on_next_lock() {
        let root = create_root();
        let destination = root.path().join("content/value.txt");
        fs::write(&destination, b"original").unwrap();

        let guard = LibraryWriteGuard::acquire(root.path()).unwrap();
        let mut transaction = LibraryTransaction::new(&guard).unwrap();
        transaction
            .stage_file(Path::new("content/value.txt"), b"replacement")
            .unwrap();
        transaction
            .stage_file(Path::new("new/nested/value.txt"), b"created")
            .unwrap();
        transaction.apply_without_commit_for_test().unwrap();
        let transaction_path = transaction.transaction_path_for_test().to_path_buf();
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert_eq!(
            fs::read(root.path().join("new/nested/value.txt")).unwrap(),
            b"created"
        );

        // Leaking models a process that dies after visible renames but before
        // either Drop or the committed marker can run.
        std::mem::forget(transaction);
        drop(guard);

        let recovered = LibraryWriteGuard::acquire(root.path()).unwrap();
        drop(recovered);
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert!(!root.path().join("new").exists());
        assert!(!transaction_path.exists());
    }

    #[test]
    fn abandoned_committed_transaction_is_kept_and_cleaned_on_next_lock() {
        let root = create_root();
        let destination = root.path().join("content/value.txt");
        fs::write(&destination, b"original").unwrap();

        let guard = LibraryWriteGuard::acquire(root.path()).unwrap();
        let mut transaction = LibraryTransaction::new(&guard).unwrap();
        transaction
            .stage_file(Path::new("content/value.txt"), b"replacement")
            .unwrap();
        transaction.apply_without_commit_for_test().unwrap();
        transaction.mark_committed_for_test().unwrap();
        let transaction_path = transaction.transaction_path_for_test().to_path_buf();
        drop(transaction);
        drop(guard);

        let recovered = LibraryWriteGuard::acquire(root.path()).unwrap();
        drop(recovered);
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert!(!transaction_path.exists());
    }

    #[test]
    fn abandoned_applying_removal_restores_the_original_file() {
        let root = create_root();
        let destination = root.path().join("content/generated.json");
        fs::write(&destination, b"generated pack").unwrap();

        let guard = LibraryWriteGuard::acquire(root.path()).unwrap();
        let mut transaction = LibraryTransaction::new(&guard).unwrap();
        transaction
            .remove_file(Path::new("content/generated.json"))
            .unwrap();
        transaction.apply_without_commit_for_test().unwrap();
        let transaction_path = transaction.transaction_path_for_test().to_path_buf();
        assert!(!destination.exists());
        assert_eq!(
            fs::read(transaction_path.join("backup/content/generated.json")).unwrap(),
            b"generated pack"
        );

        std::mem::forget(transaction);
        drop(guard);
        let recovered = LibraryWriteGuard::acquire(root.path()).unwrap();
        drop(recovered);

        assert_eq!(fs::read(destination).unwrap(), b"generated pack");
        assert!(!transaction_path.exists());
    }

    #[test]
    fn abandoned_committed_removal_stays_removed() {
        let root = create_root();
        let destination = root.path().join("content/generated.json");
        fs::write(&destination, b"generated pack").unwrap();

        let guard = LibraryWriteGuard::acquire(root.path()).unwrap();
        let mut transaction = LibraryTransaction::new(&guard).unwrap();
        transaction
            .remove_file(Path::new("content/generated.json"))
            .unwrap();
        transaction.apply_without_commit_for_test().unwrap();
        transaction.mark_committed_for_test().unwrap();
        let transaction_path = transaction.transaction_path_for_test().to_path_buf();
        drop(transaction);
        drop(guard);

        let recovered = LibraryWriteGuard::acquire(root.path()).unwrap();
        drop(recovered);
        assert!(!destination.exists());
        assert!(!transaction_path.exists());
    }

    #[test]
    fn rollback_failure_preserves_the_journal_and_original_backup() {
        let root = create_root();
        let destination = root.path().join("content/value.txt");
        fs::write(&destination, b"original").unwrap();

        let guard = LibraryWriteGuard::acquire(root.path()).unwrap();
        let mut transaction = LibraryTransaction::new(&guard).unwrap();
        transaction
            .stage_file(Path::new("content/value.txt"), b"replacement")
            .unwrap();
        transaction.apply_without_commit_for_test().unwrap();
        let transaction_path = transaction.transaction_path_for_test().to_path_buf();

        // Make rollback fail safely: it must refuse to replace a directory and
        // retain the only copy of the original bytes for operator recovery.
        fs::remove_file(&destination).unwrap();
        fs::create_dir(&destination).unwrap();
        let error = transaction.rollback_for_test().unwrap_err();
        assert!(error.to_string().contains("refusing to remove non-file"));
        assert_eq!(
            fs::read(transaction_path.join("backup/content/value.txt")).unwrap(),
            b"original"
        );
        assert!(transaction_path.join(JOURNAL_FILE).is_file());
        drop(transaction);
        assert!(transaction_path.exists());
    }

    #[test]
    fn cleanup_failure_preserves_the_active_transaction_backup() {
        let root = create_root();
        let mut active = root.path().join(format!("{ACTIVE_PREFIX}collision"));
        let backup = active.join("backup/content/value.txt");
        fs::create_dir_all(backup.parent().unwrap()).unwrap();
        fs::write(&backup, b"original").unwrap();
        // A pre-existing cleanup destination deterministically makes the state
        // transition fail on every platform.
        let cleanup = root.path().join(format!("{CLEANUP_PREFIX}collision"));
        fs::create_dir(&cleanup).unwrap();
        fs::write(cleanup.join("occupied"), b"occupied").unwrap();

        assert!(move_to_cleanup_and_remove(root.path(), &mut active).is_err());
        assert_eq!(fs::read(&backup).unwrap(), b"original");
        assert!(active.exists());
    }

    #[test]
    fn cross_process_lock_holder() {
        let Ok(root) = std::env::var(LOCK_ROOT_ENV) else {
            return;
        };
        let acquired = PathBuf::from(std::env::var(LOCK_ACQUIRED_ENV).unwrap());
        let release = PathBuf::from(std::env::var(LOCK_RELEASE_ENV).unwrap());
        let _guard = LibraryWriteGuard::acquire(Path::new(&root)).unwrap();
        fs::write(acquired, b"locked").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !release.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting to release test library lock"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn independent_process_blocks_other_handles_until_lock_release() {
        let root = TempDir::new().unwrap();
        let acquired = root.path().join("holder-acquired");
        let release = root.path().join("release-holder");
        let mut holder = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("library_transaction::tests::cross_process_lock_holder")
            .arg("--nocapture")
            .env(LOCK_ROOT_ENV, root.path())
            .env(LOCK_ACQUIRED_ENV, &acquired)
            .env(LOCK_RELEASE_ENV, &release)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while !acquired.exists() {
            if let Some(status) = holder.try_wait().unwrap() {
                panic!("lock holder exited before acquiring its lock: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for lock holder"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let contender_root = root.path().to_path_buf();
        let (attempted_sender, attempted_receiver) = std::sync::mpsc::channel();
        let (acquired_sender, acquired_receiver) = std::sync::mpsc::channel();
        let contender = thread::spawn(move || {
            attempted_sender.send(()).unwrap();
            let guard = LibraryWriteGuard::acquire(&contender_root).unwrap();
            acquired_sender.send(()).unwrap();
            drop(guard);
        });
        attempted_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let premature = acquired_receiver.recv_timeout(Duration::from_millis(250));
        if premature != Err(RecvTimeoutError::Timeout) {
            let _ = fs::write(&release, b"release");
            let _ = holder.wait();
            let _ = contender.join();
            panic!("a second handle acquired a lock still held by another process");
        }

        fs::write(&release, b"release").unwrap();
        acquired_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("contending handle did not acquire after process released lock");
        contender.join().unwrap();
        let output = holder.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "lock holder failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
