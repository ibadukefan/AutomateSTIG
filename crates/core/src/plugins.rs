//! Plugin system for extending AutomateSTIG.
//!
//! Plugins allow community contributors and organizations to add:
//! - Custom check definitions for new STIGs/platforms
//! - Data collection adapters for new target types
//! - Export format handlers
//! - Remediation script generators
//!
//! Plugins are JSON/YAML files loaded from the plugin directory.
//! No executable code — all plugins are data-driven and interpreted
//! by the core engine for deterministic behavior.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::checks::{CheckDefinition, CheckPack, CheckPlatform};

#[derive(rust_embed::Embed)]
#[folder = "../../content/check_packs"]
#[include = "*.json"]
#[exclude = "generated-candidates/*"]
struct EmbeddedCheckPacks;

/// A plugin manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin identifier.
    pub id: String,

    /// Display name.
    pub name: String,

    /// Description.
    pub description: String,

    /// Plugin version.
    pub version: String,

    /// Author.
    pub author: String,

    /// Minimum AutomateSTIG version required.
    pub min_app_version: Option<String>,

    /// Plugin type.
    pub plugin_type: PluginType,

    /// Platform this plugin targets.
    pub platform: Option<CheckPlatform>,

    /// STIG IDs this plugin provides checks for.
    pub stig_ids: Vec<String>,
}

/// Plugin types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    /// Additional check definitions for a STIG.
    CheckPack,

    /// Custom data collection commands.
    Collector,

    /// Custom export format.
    Exporter,

    /// Remediation scripts.
    Remediation,

    /// Cloud provider adapter (AWS, Azure, GCP).
    CloudAdapter,

    /// Container/Kubernetes adapter.
    ContainerAdapter,
}

/// A loaded plugin.
#[derive(Debug, Clone)]
pub struct Plugin {
    /// Plugin manifest.
    pub manifest: PluginManifest,

    /// Check packs provided by this plugin.
    pub check_packs: Vec<CheckPack>,

    /// Source path.
    pub source_path: String,
}

/// Plugin registry — manages loaded plugins.
#[derive(Debug, Default)]
pub struct PluginRegistry {
    plugins: Vec<Plugin>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load all plugins from a directory.
    pub fn load_from_directory(&mut self, dir: &Path) -> crate::Result<usize> {
        if !dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "json" || ext == "yaml" || ext == "yml" {
                    match self.load_plugin(&path) {
                        Ok(()) => count += 1,
                        Err(e) => {
                            tracing::warn!("Failed to load plugin {}: {}", path.display(), e);
                        }
                    }
                }
            } else if path.is_dir() {
                // Look for manifest.json in subdirectory.
                let manifest_path = path.join("manifest.json");
                if manifest_path.exists() {
                    match self.load_plugin_dir(&path) {
                        Ok(()) => count += 1,
                        Err(e) => {
                            tracing::warn!("Failed to load plugin {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    /// Register the check packs compiled into the binary. Filesystem-loaded
    /// packs take precedence: an embedded pack is skipped when a plugin with
    /// the same manifest id (stig_id) is already registered. Returns how many
    /// embedded packs were registered.
    pub fn load_embedded(&mut self) -> usize {
        let mut count = 0;

        for path in EmbeddedCheckPacks::iter() {
            let Some(content) = EmbeddedCheckPacks::get(path.as_ref()) else {
                tracing::warn!("Embedded check pack {} was not found", path);
                continue;
            };

            let check_pack = match serde_json::from_slice::<CheckPack>(content.data.as_ref()) {
                Ok(check_pack) => check_pack,
                Err(e) => {
                    tracing::warn!("Failed to parse embedded check pack {}: {}", path, e);
                    continue;
                }
            };

            if self.has_plugin_manifest_id(&check_pack.stig_id) {
                continue;
            }

            self.register_check_pack(check_pack, format!("embedded:{path}"));
            count += 1;
        }

        count
    }

    /// Load a single plugin file (a CheckPack JSON/YAML).
    fn load_plugin(&mut self, path: &Path) -> crate::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let check_pack: CheckPack = match ext {
            "json" => serde_json::from_str(&content)?,
            "yaml" | "yml" => {
                serde_norway::from_str(&content).map_err(|e| crate::Error::Other(e.to_string()))?
            }
            _ => return Err(crate::Error::Other("Unsupported format".to_string())),
        };

        self.register_check_pack(check_pack, path.display().to_string());

        Ok(())
    }

    fn register_check_pack(&mut self, check_pack: CheckPack, source_path: String) {
        let manifest = PluginManifest {
            id: check_pack.stig_id.clone(),
            name: format!("Check pack: {}", check_pack.stig_id),
            description: format!(
                "{} checks for {}",
                check_pack.checks.len(),
                check_pack.stig_id
            ),
            version: check_pack.version.clone(),
            author: String::new(),
            min_app_version: None,
            plugin_type: PluginType::CheckPack,
            platform: Some(check_pack.platform),
            stig_ids: vec![check_pack.stig_id.clone()],
        };

        self.plugins.push(Plugin {
            manifest,
            check_packs: vec![check_pack],
            source_path,
        });
    }

    fn has_plugin_manifest_id(&self, id: &str) -> bool {
        self.plugins.iter().any(|plugin| plugin.manifest.id == id)
    }

    /// Load a plugin from a directory with manifest.json.
    fn load_plugin_dir(&mut self, dir: &Path) -> crate::Result<()> {
        let manifest_path = dir.join("manifest.json");
        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PluginManifest = serde_json::from_str(&content)?;

        let mut check_packs = Vec::new();

        // Load check packs from the directory.
        let checks_dir = dir.join("checks");
        if checks_dir.exists() {
            for entry in std::fs::read_dir(&checks_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    let content = std::fs::read_to_string(&path)?;
                    if let Ok(pack) = serde_json::from_str::<CheckPack>(&content) {
                        check_packs.push(pack);
                    }
                }
            }
        }

        self.plugins.push(Plugin {
            manifest,
            check_packs,
            source_path: dir.display().to_string(),
        });

        Ok(())
    }

    /// Get all loaded plugins.
    pub fn list(&self) -> &[Plugin] {
        &self.plugins
    }

    /// Get all check definitions for a specific STIG.
    pub fn checks_for_stig(&self, stig_id: &str) -> Vec<&CheckDefinition> {
        self.plugins
            .iter()
            .flat_map(|p| p.check_packs.iter())
            .filter(|pack| pack.stig_id == stig_id)
            .flat_map(|pack| pack.checks.iter())
            .collect()
    }

    /// Total number of check definitions across all plugins.
    pub fn total_checks(&self) -> usize {
        self.plugins
            .iter()
            .flat_map(|p| p.check_packs.iter())
            .map(|pack| pack.checks.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::*;
    use std::path::Path;
    use tempfile::TempDir;

    const NETAPP_STIG_ID: &str = "NetApp_ONTAP_DSC_9-x_STIG";

    fn top_level_check_pack_json_count() -> usize {
        let check_packs_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../content/check_packs");

        std::fs::read_dir(check_packs_dir)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                let path = entry.path();
                path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json")
            })
            .count()
    }

    fn pre_registered_plugin(id: &str) -> Plugin {
        Plugin {
            manifest: PluginManifest {
                id: id.to_string(),
                name: "Pre-registered check pack".to_string(),
                description: "Loaded from filesystem first".to_string(),
                version: "1.0.0".to_string(),
                author: String::new(),
                min_app_version: None,
                plugin_type: PluginType::CheckPack,
                platform: Some(CheckPlatform::Ontap),
                stig_ids: vec![id.to_string()],
            },
            check_packs: vec![CheckPack {
                stig_id: id.to_string(),
                platform: CheckPlatform::Ontap,
                version: "1.0.0".to_string(),
                checks: Vec::new(),
            }],
            source_path: "filesystem".to_string(),
        }
    }

    #[test]
    fn test_embedded_check_pack_count_matches_top_level_json_files() {
        assert_eq!(
            EmbeddedCheckPacks::iter().count(),
            top_level_check_pack_json_count()
        );
    }

    #[test]
    fn test_load_embedded_includes_netapp_check_pack() {
        let mut registry = PluginRegistry::new();
        let count = registry.load_embedded();

        assert!(count > 0);
        assert!(registry
            .list()
            .iter()
            .any(|plugin| plugin.manifest.id == NETAPP_STIG_ID));
    }

    #[test]
    fn test_load_embedded_twice_registers_zero_second_time() {
        let mut registry = PluginRegistry::new();

        assert!(registry.load_embedded() > 0);
        assert_eq!(registry.load_embedded(), 0);
    }

    #[test]
    fn test_load_embedded_skips_pre_registered_plugin_with_same_stig_id() {
        let mut baseline_registry = PluginRegistry::new();
        let baseline_count = baseline_registry.load_embedded();
        assert!(baseline_registry
            .list()
            .iter()
            .any(|plugin| plugin.manifest.id == NETAPP_STIG_ID));

        let mut registry = PluginRegistry::new();
        registry.plugins.push(pre_registered_plugin(NETAPP_STIG_ID));

        let count = registry.load_embedded();

        assert_eq!(count + 1, baseline_count);
        assert_eq!(
            registry
                .list()
                .iter()
                .filter(|plugin| plugin.manifest.id == NETAPP_STIG_ID)
                .count(),
            1
        );
        assert!(!registry.list().iter().any(|plugin| {
            plugin.manifest.id == NETAPP_STIG_ID && plugin.source_path.starts_with("embedded:")
        }));
    }

    #[test]
    fn test_plugin_registry_load() {
        let dir = TempDir::new().unwrap();

        // Create a check pack file.
        let pack = CheckPack {
            stig_id: "Test_STIG".to_string(),
            platform: CheckPlatform::Linux,
            version: "1.0.0".to_string(),
            checks: vec![CheckDefinition {
                vuln_id: "V-1".to_string(),
                platform: CheckPlatform::Linux,
                check: Check::Sysctl {
                    key: "net.ipv4.ip_forward".to_string(),
                },
                expected: ExpectedResult::Equals {
                    value: serde_json::json!("0"),
                },
                description: Some("IP forwarding must be disabled".to_string()),
            }],
        };

        let pack_path = dir.path().join("test_checks.json");
        std::fs::write(&pack_path, serde_json::to_string_pretty(&pack).unwrap()).unwrap();

        let mut registry = PluginRegistry::new();
        let count = registry.load_from_directory(dir.path()).unwrap();
        assert_eq!(count, 1);
        assert_eq!(registry.total_checks(), 1);
        assert_eq!(registry.checks_for_stig("Test_STIG").len(), 1);
    }

    #[test]
    fn test_plugin_manifest_json() {
        let manifest = PluginManifest {
            id: "aws-stig-checks".to_string(),
            name: "AWS STIG Checks".to_string(),
            description: "Automated checks for AWS-related STIGs".to_string(),
            version: "1.0.0".to_string(),
            author: "Community".to_string(),
            min_app_version: Some("0.2.0".to_string()),
            plugin_type: PluginType::CloudAdapter,
            platform: None,
            stig_ids: vec!["AWS_EC2_STIG".to_string()],
        };

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: PluginManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "aws-stig-checks");
    }
}
