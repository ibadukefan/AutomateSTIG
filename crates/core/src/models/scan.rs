use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metadata about a scan source (SCC, ACAS, OpenSCAP, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSource {
    /// Type of scanner.
    pub scanner: ScannerType,

    /// Scanner version.
    pub scanner_version: Option<String>,

    /// When the scan was performed.
    pub scan_date: Option<DateTime<Utc>>,

    /// Path to the original scan file.
    pub source_file: Option<String>,

    /// The target hostname/IP.
    pub target: Option<String>,

    /// Benchmark profile used (if SCAP/XCCDF).
    pub profile: Option<String>,
}

/// Types of scanners that produce importable results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScannerType {
    /// DISA SCC (SCAP Compliance Checker).
    #[serde(rename = "scc")]
    Scc,

    /// ACAS / Tenable Nessus.
    #[serde(rename = "acas")]
    Acas,

    /// OpenSCAP.
    #[serde(rename = "openscap")]
    OpenScap,

    /// Manual config dump (show running-config, etc.).
    #[serde(rename = "config_dump")]
    ConfigDump,

    /// Evaluate-STIG compatible format.
    #[serde(rename = "evaluate_stig")]
    EvaluateStig,

    /// AutomateSTIG native format.
    #[serde(rename = "automatestig")]
    AutomateStig,

    /// Generic / unknown.
    #[serde(rename = "other")]
    Other,
}

/// A single result from a scan, mapped to a STIG rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Rule identifier (Vuln ID or Rule ID or CCE, depending on scanner).
    pub rule_ref: String,

    /// Whether the check passed or failed.
    pub passed: Option<bool>,

    /// Raw result string from the scanner.
    pub raw_result: String,

    /// Evidence / output from the check.
    pub evidence: Option<String>,

    /// Benchmark this result belongs to.
    pub benchmark_ref: Option<String>,
}

/// A collection of scan results from a single scan execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultSet {
    /// Scan metadata.
    pub source: ScanSource,

    /// Individual results.
    pub results: Vec<ScanResult>,
}
