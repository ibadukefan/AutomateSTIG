use serde::{Deserialize, Serialize};

/// An asset (host/device) being evaluated for STIG compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// Hostname or device name.
    pub hostname: String,

    /// IP address.
    pub ip_address: Option<String>,

    /// MAC address.
    pub mac_address: Option<String>,

    /// Fully qualified domain name.
    pub fqdn: Option<String>,

    /// Target/comment field.
    pub target_comment: Option<String>,

    /// Role of the asset (e.g., "Member Server", "Domain Controller").
    pub role: AssetRole,

    /// Asset type.
    pub asset_type: AssetType,

    /// Operating system or platform info.
    pub os: Option<String>,

    /// Technology area.
    pub technology_area: Option<TechnologyArea>,

    /// Web site details (for web-related STIGs).
    pub web_or_database: Option<String>,

    /// Web/database site identifier used by CKL and CKLB target metadata.
    pub web_db_site: Option<String>,

    /// Web/database instance identifier used by CKL and CKLB target metadata.
    pub web_db_instance: Option<String>,

    /// Whether the asset is still in the network.
    pub is_active: bool,
}

impl Asset {
    /// Create a new asset with minimal required info.
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            ip_address: None,
            mac_address: None,
            fqdn: None,
            target_comment: None,
            role: AssetRole::None,
            asset_type: AssetType::Computing,
            os: None,
            technology_area: None,
            web_or_database: None,
            web_db_site: None,
            web_db_instance: None,
            is_active: true,
        }
    }
}

impl Default for Asset {
    fn default() -> Self {
        Self::new("Unknown")
    }
}

/// Asset role classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetRole {
    #[serde(rename = "None")]
    None,
    #[serde(rename = "Workstation")]
    Workstation,
    #[serde(rename = "Member Server")]
    MemberServer,
    #[serde(rename = "Domain Controller")]
    DomainController,
}

impl AssetRole {
    pub fn from_ckl_str(s: &str) -> Self {
        match s.trim() {
            "Workstation" => Self::Workstation,
            "Member Server" => Self::MemberServer,
            "Domain Controller" => Self::DomainController,
            _ => Self::None,
        }
    }

    pub fn as_ckl_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Workstation => "Workstation",
            Self::MemberServer => "Member Server",
            Self::DomainController => "Domain Controller",
        }
    }
}

impl std::fmt::Display for AssetRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ckl_str())
    }
}

/// Asset type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetType {
    #[serde(rename = "Computing")]
    Computing,
    #[serde(rename = "Non-Computing")]
    NonComputing,
}

impl AssetType {
    pub fn from_ckl_str(s: &str) -> Self {
        match s.trim() {
            "Non-Computing" => Self::NonComputing,
            _ => Self::Computing,
        }
    }

    pub fn as_ckl_str(&self) -> &'static str {
        match self {
            Self::Computing => "Computing",
            Self::NonComputing => "Non-Computing",
        }
    }
}

/// Technology area for the asset/STIG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TechnologyArea {
    #[serde(rename = "")]
    None,
    #[serde(rename = "Application Review")]
    ApplicationReview,
    #[serde(rename = "Boundary Security")]
    BoundarySecurity,
    #[serde(rename = "CDS Admin Review")]
    CdsAdminReview,
    #[serde(rename = "CDS Technical Review")]
    CdsTechnicalReview,
    #[serde(rename = "Database Review")]
    DatabaseReview,
    #[serde(rename = "Domain Name System (DNS)")]
    Dns,
    #[serde(rename = "Exchange Server")]
    ExchangeServer,
    #[serde(rename = "Host Based System Security (HBSS)")]
    Hbss,
    #[serde(rename = "Internal Network")]
    InternalNetwork,
    #[serde(rename = "Mobility")]
    Mobility,
    #[serde(rename = "Releasable Networks (REL)")]
    ReleasableNetworks,
    #[serde(rename = "Traditional Security")]
    TraditionalSecurity,
    #[serde(rename = "Unix OS")]
    UnixOs,
    #[serde(rename = "VVOIP Review")]
    VvoipReview,
    #[serde(rename = "Other Review")]
    OtherReview,
    #[serde(rename = "Web Review")]
    WebReview,
    #[serde(rename = "Windows OS")]
    WindowsOs,
    #[serde(rename = "Workstation")]
    Workstation,
    #[serde(rename = "Member Server")]
    MemberServer,
    #[serde(rename = "Domain Controller")]
    DomainController,
}

impl TechnologyArea {
    /// Parse the exact values accepted by current STIG Viewer releases.
    pub fn from_ckl_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "none" => Some(Self::None),
            "application review" => Some(Self::ApplicationReview),
            "boundary security" => Some(Self::BoundarySecurity),
            "cds admin review" => Some(Self::CdsAdminReview),
            "cds technical review" => Some(Self::CdsTechnicalReview),
            "database review" => Some(Self::DatabaseReview),
            "domain name system (dns)" => Some(Self::Dns),
            "exchange server" => Some(Self::ExchangeServer),
            "host based system security (hbss)" => Some(Self::Hbss),
            "internal network" => Some(Self::InternalNetwork),
            "mobility" => Some(Self::Mobility),
            "releasable networks (rel)" => Some(Self::ReleasableNetworks),
            "traditional security" => Some(Self::TraditionalSecurity),
            "unix os" => Some(Self::UnixOs),
            "vvoip review" => Some(Self::VvoipReview),
            "other review" => Some(Self::OtherReview),
            "web review" => Some(Self::WebReview),
            "windows os" => Some(Self::WindowsOs),
            "workstation" => Some(Self::Workstation),
            "member server" => Some(Self::MemberServer),
            "domain controller" => Some(Self::DomainController),
            _ => None,
        }
    }

    pub fn as_ckl_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::ApplicationReview => "Application Review",
            Self::BoundarySecurity => "Boundary Security",
            Self::CdsAdminReview => "CDS Admin Review",
            Self::CdsTechnicalReview => "CDS Technical Review",
            Self::DatabaseReview => "Database Review",
            Self::Dns => "Domain Name System (DNS)",
            Self::ExchangeServer => "Exchange Server",
            Self::Hbss => "Host Based System Security (HBSS)",
            Self::InternalNetwork => "Internal Network",
            Self::Mobility => "Mobility",
            Self::ReleasableNetworks => "Releasable Networks (REL)",
            Self::TraditionalSecurity => "Traditional Security",
            Self::UnixOs => "Unix OS",
            Self::VvoipReview => "VVOIP Review",
            Self::OtherReview => "Other Review",
            Self::WebReview => "Web Review",
            Self::WindowsOs => "Windows OS",
            Self::Workstation => "Workstation",
            Self::MemberServer => "Member Server",
            Self::DomainController => "Domain Controller",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_creation() {
        let asset = Asset::new("webserver01");
        assert_eq!(asset.hostname, "webserver01");
        assert_eq!(asset.role, AssetRole::None);
        assert!(asset.is_active);
    }

    #[test]
    fn test_asset_role_roundtrip() {
        for role in [
            AssetRole::None,
            AssetRole::Workstation,
            AssetRole::MemberServer,
            AssetRole::DomainController,
        ] {
            let s = role.as_ckl_str();
            assert_eq!(AssetRole::from_ckl_str(s), role);
        }
    }

    #[test]
    fn test_stig_viewer_technology_area_roundtrip() {
        for area in [
            TechnologyArea::None,
            TechnologyArea::ApplicationReview,
            TechnologyArea::DatabaseReview,
            TechnologyArea::ReleasableNetworks,
            TechnologyArea::UnixOs,
            TechnologyArea::WindowsOs,
            TechnologyArea::DomainController,
        ] {
            assert_eq!(TechnologyArea::from_ckl_str(area.as_ckl_str()), Some(area));
        }
        assert_eq!(
            TechnologyArea::from_ckl_str("NONE"),
            Some(TechnologyArea::None)
        );
        assert_eq!(TechnologyArea::from_ckl_str("not a Viewer value"), None);
    }
}
