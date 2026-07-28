//! Symlink-safe, atomic writes for mutable ancillary library content.

use std::fs;
use std::path::{Path, PathBuf};

use crate::library_transaction::{LibraryInstallStep, LibraryTransaction, LibraryWriteGuard};
use crate::{Error, Result};

const ANSWER_TEMPLATES_DIRECTORY: &str = "answer_templates";
const ANSWER_TEMPLATE_EXTENSIONS: &[&str] = &["json", "yaml", "yml"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStep {
    Staged,
    BackedUp,
    Installed,
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

fn write_answer_template_with_hook<F>(
    library_root: &Path,
    filename: &str,
    bytes: &[u8],
    mut hook: F,
) -> Result<PathBuf>
where
    F: FnMut(WriteStep, &Path) -> Result<()>,
{
    let filename = validate_answer_template_filename(filename)?;
    let guard = LibraryWriteGuard::acquire(library_root)?;
    let content_directory = library_root.join(ANSWER_TEMPLATES_DIRECTORY);
    let destination = content_directory.join(&filename);
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
