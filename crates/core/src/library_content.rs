//! Symlink-safe, atomic writes for mutable ancillary library content.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::library_transaction::{LibraryInstallStep, LibraryTransaction, LibraryWriteGuard};
use crate::{Error, Result};

const ANSWER_TEMPLATES_DIRECTORY: &str = "answer_templates";
const ANSWER_TEMPLATE_EXTENSIONS: &[&str] = &["json", "yaml", "yml"];
const ANSWER_TEMPLATE_SIZE_LIMIT_BYTES: u64 = 128 * 1024 * 1024;

/// A coherent, bounded snapshot of one answer-template file. The bytes and
/// digest are read while holding the same cross-process library guard used by
/// writers, so an editor can use `sha256` as an optimistic-lock token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerTemplateSnapshot {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStep {
    Staged,
    BackedUp,
    Installed,
}

/// Collision policy for an answer-template write. The policy is checked while
/// holding the cross-process library write guard, so create and replace flows
/// cannot race another AutomateSTIG process between inspection and commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerTemplateWriteMode {
    CreateNew,
    ReplaceExisting,
    CreateOrReplace,
}

/// Atomically create or replace one direct answer-template file.
///
/// The library root and answer-template directory must be real directories;
/// symlinked parents and destinations are rejected. Bytes are staged under the
/// library root, then installed with backup/rollback semantics.
pub fn write_answer_template_atomic(
    library_root: &Path,
    filename: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    write_answer_template_with_hook(library_root, filename, bytes, |_, _| Ok(()))
}

/// Atomically write one answer template using an explicit collision policy.
pub fn write_answer_template_atomic_with_mode(
    library_root: &Path,
    filename: &str,
    bytes: &[u8],
    mode: AnswerTemplateWriteMode,
) -> Result<PathBuf> {
    write_answer_template_with_mode_and_hook(library_root, filename, bytes, mode, None, |_, _| {
        Ok(())
    })
}

/// Atomically replace an answer template only when its current raw-byte
/// SHA-256 matches `expected_sha256`. The comparison happens while holding the
/// cross-process library write guard, immediately before staging the update.
pub fn replace_answer_template_atomic_if_match(
    library_root: &Path,
    filename: &str,
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<PathBuf> {
    write_answer_template_with_mode_and_hook(
        library_root,
        filename,
        bytes,
        AnswerTemplateWriteMode::ReplaceExisting,
        Some(expected_sha256),
        |_, _| Ok(()),
    )
}

fn write_answer_template_with_hook<F>(
    library_root: &Path,
    filename: &str,
    bytes: &[u8],
    hook: F,
) -> Result<PathBuf>
where
    F: FnMut(WriteStep, &Path) -> Result<()>,
{
    write_answer_template_with_mode_and_hook(
        library_root,
        filename,
        bytes,
        AnswerTemplateWriteMode::CreateOrReplace,
        None,
        hook,
    )
}

fn write_answer_template_with_mode_and_hook<F>(
    library_root: &Path,
    filename: &str,
    bytes: &[u8],
    mode: AnswerTemplateWriteMode,
    expected_sha256: Option<&str>,
    mut hook: F,
) -> Result<PathBuf>
where
    F: FnMut(WriteStep, &Path) -> Result<()>,
{
    let filename = validate_answer_template_filename(filename)?;
    let guard = LibraryWriteGuard::acquire(library_root)?;
    let content_directory = library_root.join(ANSWER_TEMPLATES_DIRECTORY);
    let destination = content_directory.join(&filename);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::LibraryError(format!(
                    "answer-template destination is not a regular file: {}",
                    destination.display()
                )));
            }
            if mode == AnswerTemplateWriteMode::CreateNew {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("answer template already exists: {}", destination.display()),
                )
                .into());
            }
            if let Some(expected) = expected_sha256 {
                if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(Error::Other(
                        "answer-template precondition must be a 64-character SHA-256 digest"
                            .to_string(),
                    ));
                }
                let actual = answer_template_sha256(&destination, &metadata)?;
                if !actual.eq_ignore_ascii_case(expected) {
                    return Err(Error::IntegrityError {
                        expected: expected.to_ascii_lowercase(),
                        actual,
                    });
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if mode == AnswerTemplateWriteMode::ReplaceExisting {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("answer template does not exist: {}", destination.display()),
                )
                .into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let relative = Path::new(ANSWER_TEMPLATES_DIRECTORY).join(&filename);
    let mut transaction = LibraryTransaction::new(&guard)?;
    transaction.stage_file(&relative, bytes)?;
    hook(WriteStep::Staged, &destination)?;
    transaction.install_and_commit(|step, _| match step {
        LibraryInstallStep::BeforeInstall => hook(WriteStep::BackedUp, &destination),
        LibraryInstallStep::Installed => hook(WriteStep::Installed, &destination),
    })?;
    Ok(destination)
}

/// Read one direct answer-template file and calculate its raw-byte SHA-256
/// under the cross-process library guard. Reads are capped at the same 128 MiB
/// limit used by answer-file parsing.
pub fn read_answer_template_snapshot(
    library_root: &Path,
    filename: &str,
) -> Result<AnswerTemplateSnapshot> {
    let guard = LibraryWriteGuard::acquire(library_root)?;
    read_answer_template_snapshot_locked(&guard, filename)
}

/// Read one answer template while the caller holds the library transaction
/// guard. This is crate-private so only coherent higher-level snapshots can
/// bypass acquiring their own guard.
pub(crate) fn read_answer_template_snapshot_locked(
    guard: &LibraryWriteGuard,
    filename: &str,
) -> Result<AnswerTemplateSnapshot> {
    let library_root = guard.root();
    let filename = validate_answer_template_filename(filename)?;
    let content_directory = library_root.join(ANSWER_TEMPLATES_DIRECTORY);
    let directory_metadata = fs::symlink_metadata(&content_directory)?;
    ensure_directory_metadata(
        &content_directory,
        "answer-template directory",
        &directory_metadata,
    )?;
    let path = content_directory.join(filename);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::LibraryError(format!(
            "answer-template source is not a regular file: {}",
            path.display()
        )));
    }
    let bytes = read_answer_template_bytes(&path, &metadata)?;
    let sha256 = sha256_hex(&bytes);
    Ok(AnswerTemplateSnapshot { bytes, sha256 })
}

fn answer_template_sha256(path: &Path, metadata: &fs::Metadata) -> Result<String> {
    Ok(sha256_hex(&read_answer_template_bytes(path, metadata)?))
}

fn read_answer_template_bytes(path: &Path, metadata: &fs::Metadata) -> Result<Vec<u8>> {
    if metadata.len() > ANSWER_TEMPLATE_SIZE_LIMIT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "answer template exceeds 128 MB parse limit",
        )
        .into());
    }
    Ok(fs::read(path)?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// List direct, regular answer-template files without following symlinks.
pub fn list_answer_template_files(library_root: &Path) -> Result<Vec<PathBuf>> {
    let _guard = LibraryWriteGuard::acquire(library_root)?;
    let content_directory = library_root.join(ANSWER_TEMPLATES_DIRECTORY);
    match fs::symlink_metadata(&content_directory) {
        Ok(metadata) => {
            ensure_directory_metadata(&content_directory, "answer-template directory", &metadata)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(&content_directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(Error::LibraryError(format!(
                "answer-template entry is a symlink: {}",
                entry.path().display()
            )));
        }
        if !file_type.is_file() {
            continue;
        }
        let filename = entry.file_name().into_string().map_err(|_| {
            Error::LibraryError("answer-template filename is not UTF-8".to_string())
        })?;
        validate_answer_template_filename(&filename)?;
        paths.push(entry.path());
    }
    paths.sort();
    Ok(paths)
}

fn validate_answer_template_filename(filename: &str) -> Result<String> {
    let safe = crate::path_safety::safe_filename(filename)?;
    if safe != filename {
        return Err(Error::LibraryError(format!(
            "answer-template filename is not canonical: {filename:?}"
        )));
    }
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str());
    if !extension.is_some_and(|value| ANSWER_TEMPLATE_EXTENSIONS.contains(&value)) {
        return Err(Error::LibraryError(format!(
            "unsupported answer-template extension: {filename}"
        )));
    }
    Ok(safe)
}

fn ensure_directory_metadata(
    path: &Path,
    description: &str,
    metadata: &fs::Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::LibraryError(format!(
            "{description} is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn library_root() -> tempfile::TempDir {
        let root = tempfile::TempDir::new().unwrap();
        fs::create_dir(root.path().join(ANSWER_TEMPLATES_DIRECTORY)).unwrap();
        root
    }

    #[test]
    fn writes_replaces_and_lists_answer_templates() {
        let root = library_root();
        let destination = write_answer_template_atomic(root.path(), "site.json", b"old").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"old");

        write_answer_template_atomic(root.path(), "site.json", b"new").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert_eq!(
            list_answer_template_files(root.path()).unwrap(),
            vec![destination]
        );
    }

    #[test]
    fn explicit_answer_template_collision_modes_are_guarded() {
        let root = library_root();
        write_answer_template_atomic_with_mode(
            root.path(),
            "site.json",
            b"old",
            AnswerTemplateWriteMode::CreateNew,
        )
        .unwrap();

        let duplicate = write_answer_template_atomic_with_mode(
            root.path(),
            "site.json",
            b"unexpected",
            AnswerTemplateWriteMode::CreateNew,
        )
        .unwrap_err();
        assert!(matches!(
            duplicate,
            Error::Io(ref error) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(
            fs::read(root.path().join("answer_templates/site.json")).unwrap(),
            b"old"
        );

        write_answer_template_atomic_with_mode(
            root.path(),
            "site.json",
            b"replacement",
            AnswerTemplateWriteMode::ReplaceExisting,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.path().join("answer_templates/site.json")).unwrap(),
            b"replacement"
        );

        let missing = write_answer_template_atomic_with_mode(
            root.path(),
            "missing.json",
            b"value",
            AnswerTemplateWriteMode::ReplaceExisting,
        )
        .unwrap_err();
        assert!(matches!(
            missing,
            Error::Io(ref error) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn answer_template_replacement_requires_the_current_snapshot_digest() {
        let root = library_root();
        write_answer_template_atomic_with_mode(
            root.path(),
            "site.json",
            b"old",
            AnswerTemplateWriteMode::CreateNew,
        )
        .unwrap();
        let snapshot = read_answer_template_snapshot(root.path(), "site.json").unwrap();
        assert_eq!(snapshot.bytes, b"old");
        assert_eq!(snapshot.sha256.len(), 64);

        write_answer_template_atomic(root.path(), "site.json", b"newer").unwrap();
        let stale = replace_answer_template_atomic_if_match(
            root.path(),
            "site.json",
            b"stale overwrite",
            &snapshot.sha256,
        )
        .unwrap_err();
        assert!(matches!(stale, Error::IntegrityError { .. }));
        assert_eq!(
            fs::read(root.path().join("answer_templates/site.json")).unwrap(),
            b"newer"
        );

        let current = read_answer_template_snapshot(root.path(), "site.json").unwrap();
        replace_answer_template_atomic_if_match(
            root.path(),
            "site.json",
            b"replacement",
            &current.sha256,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.path().join("answer_templates/site.json")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn injected_post_install_failure_restores_previous_file() {
        let root = library_root();
        let destination = root.path().join("answer_templates/site.json");
        fs::write(&destination, b"old").unwrap();

        let result =
            write_answer_template_with_hook(root.path(), "site.json", b"new", |step, _| {
                if step == WriteStep::Installed {
                    return Err(Error::Other("injected interruption".to_string()));
                }
                Ok(())
            });

        assert!(result.is_err());
        assert_eq!(fs::read(destination).unwrap(), b"old");
        assert!(!fs::read_dir(root.path()).unwrap().flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with(".library-transaction-") || name.starts_with(".library-cleanup-")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_directory_destination_and_list_entries() {
        use std::os::unix::fs::symlink;

        let root = tempfile::TempDir::new().unwrap();
        let external = tempfile::TempDir::new().unwrap();
        symlink(
            external.path(),
            root.path().join(ANSWER_TEMPLATES_DIRECTORY),
        )
        .unwrap();
        assert!(write_answer_template_atomic(root.path(), "site.json", b"new").is_err());
        assert!(!external.path().join("site.json").exists());
        assert!(list_answer_template_files(root.path()).is_err());

        fs::remove_file(root.path().join(ANSWER_TEMPLATES_DIRECTORY)).unwrap();
        fs::create_dir(root.path().join(ANSWER_TEMPLATES_DIRECTORY)).unwrap();
        fs::write(external.path().join("outside.json"), b"outside").unwrap();
        symlink(
            external.path().join("outside.json"),
            root.path().join("answer_templates/outside.json"),
        )
        .unwrap();
        assert!(list_answer_template_files(root.path()).is_err());
    }

    #[test]
    fn rejects_unsafe_or_non_answer_template_names() {
        let root = library_root();
        for filename in ["../outside.json", "site.txt", "site answer.json"] {
            assert!(write_answer_template_atomic(root.path(), filename, b"value").is_err());
        }
    }
}
