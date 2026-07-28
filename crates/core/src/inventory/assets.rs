//! Managed asset inventory.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::checks::CheckPlatform;

/// A managed asset — a host/device under ongoing STIG evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedAsset {
    /// Unique identifier.
    pub id: String,

    /// Display name / hostname.
    pub name: String,

    /// IP address or FQDN for remote connection.
    pub address: String,

    /// Platform type.
    pub platform: CheckPlatform,

    /// SSH connection port (None = 22).
    pub port: Option<u16>,

    /// STIGs assigned to this asset.
    pub assigned_stigs: Vec<String>,

    /// Tags for organizing assets into groups.
    pub tags: Vec<String>,

    /// Operating system description.
    pub os_info: Option<String>,

    /// Notes.
    pub notes: Option<String>,

    /// Whether this asset is active (should be scanned).
    pub enabled: bool,

    /// Last evaluation timestamp.
    pub last_evaluated: Option<DateTime<Utc>>,

    /// Last compliance percentage.
    pub last_compliance_pct: Option<f64>,

    /// Last evaluation checklist IDs (one per STIG).
    pub last_checklist_ids: Vec<String>,

    /// When this asset was added.
    pub created_at: DateTime<Utc>,
}

impl ManagedAsset {
    /// Create a new managed asset.
    pub fn new(name: &str, address: &str, platform: CheckPlatform) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            address: address.to_string(),
            platform,
            port: None,
            assigned_stigs: Vec::new(),
            tags: Vec::new(),
            os_info: None,
            notes: None,
            enabled: true,
            last_evaluated: None,
            last_compliance_pct: None,
            last_checklist_ids: Vec::new(),
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_asset() {
        let asset = ManagedAsset::new("freebsd01", "10.0.1.50", CheckPlatform::Bsd);
        assert_eq!(asset.name, "freebsd01");
        assert!(asset.enabled);
    }

    #[test]
    fn test_asset_json_roundtrip() {
        let mut asset = ManagedAsset::new("rtr01", "10.0.1.1", CheckPlatform::CiscoIos);
        asset.assigned_stigs = vec!["Cisco_IOS_XE_Router_STIG".to_string()];
        asset.tags = vec!["network".to_string(), "core".to_string()];

        let json = serde_json::to_string(&asset).unwrap();
        let parsed: ManagedAsset = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "rtr01");
        assert_eq!(parsed.tags.len(), 2);
    }
}
