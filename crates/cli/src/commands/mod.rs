pub mod build_pack;
pub mod collect;
pub mod convert;
pub mod coverage;
pub mod disa_import;
pub mod evaluate;
pub mod export;
pub mod gen_answer;
pub mod import;
pub mod library;
pub mod status;
pub mod summary;
pub mod verify;

use std::path::PathBuf;

use automatestig_core::models::Checklist;

pub(crate) fn ensure_external_export_allowed(checklist: &Checklist) -> anyhow::Result<()> {
    if let Some(reason) = checklist.external_export_block_reason() {
        anyhow::bail!("Checklist cannot be exported: {reason}");
    }
    Ok(())
}

/// Get the default AutomateSTIG data directory.
pub fn default_data_dir() -> PathBuf {
    dirs_or_default().join(".automatestig")
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

#[cfg(test)]
mod tests {
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
    use automatestig_core::models::finding::{Finding, FindingSource};
    use automatestig_core::models::stig::Severity;

    use super::ensure_external_export_allowed;

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
}
