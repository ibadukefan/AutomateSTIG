use std::path::{Component, Path, PathBuf};

use crate::{Error, Result};

/// Convert a user/content supplied identifier into a safe single filename.
///
/// The returned value never contains path separators, parent traversal, control
/// characters, or absolute path components. Spaces are normalized to `_`.
pub fn safe_filename(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Other("filename cannot be empty".to_string()));
    }
    if trimmed == "." || trimmed == ".." || trimmed.contains("..") {
        return Err(Error::Other(format!("unsafe filename: {input}")));
    }

    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.' => out.push(c),
            ' ' => out.push('_'),
            _ => {
                return Err(Error::Other(format!(
                    "unsafe character in filename: {input}"
                )))
            }
        }
    }

    if out.is_empty() || out == "." || out == ".." || out.contains("..") {
        return Err(Error::Other(format!("unsafe filename: {input}")));
    }

    Ok(out)
}

/// Safely join a single child path under a trusted base directory.
pub fn safe_join_under(base: &Path, child: &str) -> Result<PathBuf> {
    let filename = safe_filename(child)?;
    let candidate = base.join(filename);
    ensure_under_base(base, &candidate)?;
    Ok(candidate)
}

/// Ensure a candidate path cannot escape the base directory through absolute
/// components or parent traversal.
pub fn ensure_under_base(base: &Path, candidate: &Path) -> Result<()> {
    if candidate.is_absolute() && !candidate.starts_with(base) {
        return Err(Error::Other(format!(
            "path {} is outside base {}",
            candidate.display(),
            base.display()
        )));
    }

    for component in candidate.components() {
        match component {
            Component::ParentDir => {
                return Err(Error::Other(format!(
                    "path traversal is not allowed: {}",
                    candidate.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(Error::Other(format!(
                    "platform path prefixes are not allowed: {}",
                    candidate.display()
                )));
            }
            _ => {}
        }
    }

    if candidate.is_absolute() && !candidate.starts_with(base) {
        return Err(Error::Other(format!(
            "path {} is outside base {}",
            candidate.display(),
            base.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_allows_expected_identifiers() {
        assert_eq!(
            safe_filename("Windows_Server_2022_STIG").unwrap(),
            "Windows_Server_2022_STIG"
        );
        assert_eq!(safe_filename("site answers").unwrap(), "site_answers");
        assert_eq!(safe_filename("rhel8-v1.2").unwrap(), "rhel8-v1.2");
    }

    #[test]
    fn safe_filename_rejects_path_traversal_and_separators() {
        for value in [
            "",
            "..",
            "../evil",
            "a/evil",
            "a\\evil",
            "evil\0name",
            "a..b",
        ] {
            assert!(safe_filename(value).is_err(), "{value} should be rejected");
        }
    }

    #[test]
    fn safe_join_under_rejects_unsafe_children() {
        let base = Path::new("/tmp/automatestig");
        assert!(safe_join_under(base, "benchmark")
            .unwrap()
            .ends_with("benchmark"));
        assert!(safe_join_under(base, "../../etc/passwd").is_err());
    }
}
