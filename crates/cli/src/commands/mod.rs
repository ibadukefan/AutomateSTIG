#[cfg(feature = "maintainer")]
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod build_pack;
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod collect;
#[cfg(feature = "maintainer")]
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod coverage;
#[cfg(feature = "maintainer")]
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod disa_import;
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod evaluate;
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod handoff;
#[cfg(feature = "maintainer")]
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod import;
#[cfg(feature = "maintainer")]
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod library;
#[cfg(feature = "transition")]
#[allow(dead_code)]
pub mod migration;
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod status;
#[cfg(feature = "maintainer")]
#[cfg_attr(feature = "transition", allow(dead_code))]
pub mod verify;

use std::path::{Component, Path, PathBuf};

use automatestig_core::models::Checklist;

pub(crate) fn ensure_external_export_allowed(checklist: &Checklist) -> anyhow::Result<()> {
    if let Some(reason) = checklist.external_export_block_reason() {
        anyhow::bail!("Checklist cannot be exported: {reason}");
    }
    Ok(())
}

/// Get the default AutomateSTIG data directory.
pub fn default_data_dir() -> PathBuf {
    default_data_dir_from(std::env::var_os("AUTOMATESTIG_DATA_DIR"), dirs_or_default())
}

fn default_data_dir_from(override_path: Option<std::ffi::OsString>, home: PathBuf) -> PathBuf {
    override_path
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".automatestig"))
}

/// Trust anchors used for both `.stigpack` import and runtime executable
/// provenance verification.
pub fn trusted_keys_dir() -> PathBuf {
    std::env::var("AUTOMATESTIG_TRUSTED_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_data_dir().join("trusted_keys"))
}

/// Dedicated trust anchors for signed organization policy artifacts.
pub fn organization_policy_keys_dir() -> PathBuf {
    std::env::var("AUTOMATESTIG_ORGANIZATION_POLICY_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_data_dir().join("organization_policy_keys"))
}

/// Dedicated trust anchors for detached selected-run handoff signatures.
/// Handoff producer identity is intentionally isolated from executable-content
/// and organization-policy trust domains.
pub fn handoff_trusted_keys_dir() -> PathBuf {
    std::env::var("AUTOMATESTIG_HANDOFF_TRUSTED_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_data_dir().join("handoff_trusted_keys"))
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Get library path from CLI args or default.
pub fn library_path(cli: &crate::Cli) -> PathBuf {
    cli.library
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_data_dir().join("library"))
}

/// Get database path from CLI args or default.
pub fn db_path(cli: &crate::Cli) -> PathBuf {
    cli.db
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_data_dir().join("data.db"))
}

/// Refuse output destinations that would replace a consumed input or mutable
/// AutomateSTIG state. Callers must run this before opening or writing the
/// destination; the atomic writer performs a second destination-type check at
/// commit time.
pub(crate) fn ensure_safe_artifact_output(
    output: &Path,
    inputs: &[&Path],
    cli: &crate::Cli,
) -> anyhow::Result<()> {
    let output_resolved = resolved_path(output)?;
    for input in inputs {
        if paths_refer_to_same_file(output, input)? || output_resolved == resolved_path(input)? {
            anyhow::bail!(
                "output {} would replace consumed input {}; choose a different output path",
                output.display(),
                input.display()
            );
        }
    }

    let database = db_path(cli);
    for managed_database_path in sqlite_managed_paths(&database) {
        if paths_refer_to_same_file(output, &managed_database_path)?
            || managed_paths_equal(&output_resolved, &resolved_path(&managed_database_path)?)
        {
            anyhow::bail!(
                "output {} targets the AutomateSTIG database or one of its SQLite sidecars; choose a path outside managed state",
                output.display()
            );
        }
    }

    for (managed_root, label) in [
        (default_data_dir(), "AutomateSTIG data directory"),
        (library_path(cli), "AutomateSTIG library"),
        (trusted_keys_dir(), "content trust store"),
        (
            organization_policy_keys_dir(),
            "organization-policy trust store",
        ),
        (handoff_trusted_keys_dir(), "handoff trust store"),
    ] {
        let managed_root = resolved_path(&managed_root)?;
        if managed_path_starts_with(&output_resolved, &managed_root) {
            anyhow::bail!(
                "output {} is inside the {label}; choose a path outside managed state",
                output.display()
            );
        }
    }
    Ok(())
}

fn sqlite_managed_paths(database: &Path) -> Vec<PathBuf> {
    let mut paths = vec![database.to_path_buf()];
    let Some(filename) = database.file_name() else {
        return paths;
    };
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar_name = filename.to_os_string();
        sidecar_name.push(suffix);
        paths.push(database.with_file_name(sidecar_name));
    }
    paths
}

fn managed_paths_equal(left: &Path, right: &Path) -> bool {
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        let folded = |path: &Path| {
            path.components()
                .map(|component| managed_component_key(component.as_os_str()))
                .collect::<Vec<_>>()
        };
        folded(left) == folded(right)
    } else {
        left == right
    }
}

fn managed_path_starts_with(path: &Path, root: &Path) -> bool {
    let path_components: Vec<_> = path.components().collect();
    let root_components: Vec<_> = root.components().collect();
    root_components.len() <= path_components.len()
        && path_components
            .iter()
            .zip(root_components.iter())
            .all(|(candidate, expected)| {
                if cfg!(any(target_os = "macos", target_os = "windows")) {
                    managed_component_key(candidate.as_os_str())
                        == managed_component_key(expected.as_os_str())
                } else {
                    candidate == expected
                }
            })
}

fn managed_component_key(component: &std::ffi::OsStr) -> String {
    use unicode_normalization::UnicodeNormalization;

    component.to_string_lossy().to_lowercase().nfd().collect()
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> anyhow::Result<bool> {
    if !left.exists() || !right.exists() {
        return Ok(false);
    }
    same_file::is_same_file(left, right).map_err(anyhow::Error::from)
}

fn resolved_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.exists() {
        return std::fs::canonicalize(path).map_err(anyhow::Error::from);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut ancestor = absolute.as_path();
    let mut missing = Vec::new();
    while !ancestor.exists() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve output path {}", path.display()))?;
        missing.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve output path {}", path.display()))?;
    }
    let mut absolute = std::fs::canonicalize(ancestor)?;
    for component in missing.into_iter().rev() {
        absolute.push(component);
    }
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
    use automatestig_core::models::finding::{Finding, FindingSource};
    use automatestig_core::models::stig::Severity;

    use super::{
        default_data_dir_from, ensure_external_export_allowed, ensure_safe_artifact_output,
    };

    #[test]
    fn explicit_data_directory_overrides_home_default() {
        assert_eq!(
            default_data_dir_from(
                Some(std::ffi::OsString::from("/managed/automatestig")),
                std::path::PathBuf::from("/ignored/home"),
            ),
            std::path::PathBuf::from("/managed/automatestig")
        );
        assert_eq!(
            default_data_dir_from(None, std::path::PathBuf::from("/operator/home")),
            std::path::PathBuf::from("/operator/home/.automatestig")
        );
    }

    fn checklist_with_source(source: FindingSource) -> Checklist {
        let mut checklist = Checklist::new(
            Asset::new("host"),
            ChecklistStigInfo {
                stig_id: "Example_STIG".to_string(),
                title: "Example".to_string(),
                version: "1".to_string(),
                release: "1".to_string(),
                release_date: None,
                uuid: None,
                description: None,
                filename: None,
            },
        );
        let mut finding =
            Finding::new_not_reviewed("V-1", "SV-1", "V-1", "Example", Severity::Medium);
        finding.source = source;
        checklist.findings.push(finding);
        checklist
    }

    #[test]
    fn export_boundary_allows_imports_but_rejects_unbound_evaluations() {
        assert!(
            ensure_external_export_allowed(&checklist_with_source(FindingSource::Imported)).is_ok()
        );
        for source in [FindingSource::Automated, FindingSource::Evidence] {
            let error = ensure_external_export_allowed(&checklist_with_source(source))
                .expect_err("evaluated findings require durable provenance");
            assert_eq!(
                error.to_string(),
                "Checklist cannot be exported: automated findings are missing durable evaluation provenance"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn artifact_output_rejects_input_hard_links_and_managed_state() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input.json");
        let output = root.path().join("output.json");
        std::fs::write(&input, b"input").unwrap();
        std::fs::hard_link(&input, &output).unwrap();

        let cli = crate::Cli::command_test_fixture(
            root.path().join("library").display().to_string(),
            root.path().join("data.db").display().to_string(),
        );
        let error = ensure_safe_artifact_output(&output, &[Path::new(&input)], &cli)
            .expect_err("hard-linked output must be rejected");
        assert!(error.to_string().contains("would replace consumed input"));

        std::fs::remove_file(&output).unwrap();
        let library = root.path().join("library");
        std::fs::create_dir(&library).unwrap();
        let error = ensure_safe_artifact_output(&library.join("benchmark.json"), &[], &cli)
            .expect_err("library output must be rejected");
        assert!(error
            .to_string()
            .contains("inside the AutomateSTIG library"));

        let error = ensure_safe_artifact_output(&root.path().join("data.db"), &[], &cli)
            .expect_err("database output must be rejected");
        assert!(error
            .to_string()
            .contains("targets the AutomateSTIG database"));

        for sidecar in ["data.db-wal", "data.db-shm", "data.db-journal"] {
            let error = ensure_safe_artifact_output(&root.path().join(sidecar), &[], &cli)
                .expect_err("SQLite sidecar output must be rejected");
            assert!(error
                .to_string()
                .contains("targets the AutomateSTIG database"));
        }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            std::fs::remove_dir(&library).unwrap();
            let error = ensure_safe_artifact_output(&root.path().join("DATA.DB"), &[], &cli)
                .expect_err("case-only database aliases must be rejected");
            assert!(error
                .to_string()
                .contains("targets the AutomateSTIG database"));

            let error = ensure_safe_artifact_output(
                &root.path().join("LIBRARY/new-benchmark.json"),
                &[],
                &cli,
            )
            .expect_err("case-only library aliases must be rejected");
            assert!(error
                .to_string()
                .contains("inside the AutomateSTIG library"));

            let unicode_cli = crate::Cli::command_test_fixture(
                cli.library.clone().unwrap(),
                root.path().join("d\u{e9}.db").display().to_string(),
            );
            let canonically_equivalent = root.path().join("de\u{301}.db");
            let error = ensure_safe_artifact_output(&canonically_equivalent, &[], &unicode_cli)
                .expect_err("Unicode-equivalent database aliases must be rejected");
            assert!(error
                .to_string()
                .contains("targets the AutomateSTIG database"));
        }
    }
}
