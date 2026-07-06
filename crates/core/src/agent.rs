//! Agent mode — scheduled scanning, drift detection, and continuous compliance.
//!
//! The agent runs as a background process that:
//! 1. Periodically evaluates configured targets against their assigned STIGs
//! 2. Detects drift from previous baselines
//! 3. Generates alerts and reports when compliance changes
//! 4. Optionally pushes results to STIG-Manager automatically

use crate::models::finding::FindingStatus;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Whether the agent is enabled.
    pub enabled: bool,

    /// Scan interval in minutes.
    pub scan_interval_minutes: u64,

    /// Targets to monitor.
    pub targets: Vec<MonitoredTarget>,

    /// Whether to auto-push to STIG-Manager.
    pub auto_push_stigman: bool,

    /// Whether to generate alerts on new findings.
    pub alert_on_new_findings: bool,

    /// Notification settings.
    pub notifications: NotificationConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_minutes: 1440, // 24 hours
            targets: Vec::new(),
            auto_push_stigman: false,
            alert_on_new_findings: true,
            notifications: NotificationConfig::default(),
        }
    }
}

/// A target being monitored by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredTarget {
    /// Target identifier.
    pub id: String,

    /// Hostname.
    pub hostname: String,

    /// STIGs to evaluate.
    pub stig_ids: Vec<String>,

    /// Last scan time.
    pub last_scan: Option<DateTime<Utc>>,

    /// Last compliance percentage.
    pub last_compliance_pct: Option<f64>,

    /// Whether this target is enabled.
    pub enabled: bool,
}

/// Notification configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Log file path for agent events.
    pub log_file: Option<String>,

    /// Whether to create desktop notifications.
    pub desktop_notifications: bool,

    /// Webhook URL for agent alerts.
    #[serde(default)]
    pub webhook_url: Option<String>,
}

/// Result of a drift detection comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    /// Target hostname.
    pub hostname: String,

    /// STIG ID.
    pub stig_id: String,

    /// When the comparison was made.
    pub compared_at: DateTime<Utc>,

    /// Previous compliance percentage.
    pub previous_compliance: f64,

    /// Current compliance percentage.
    pub current_compliance: f64,

    /// Change in compliance.
    pub compliance_delta: f64,

    /// New open findings (were previously not open).
    pub new_open: Vec<DriftFinding>,

    /// Newly resolved findings (were previously open).
    pub newly_resolved: Vec<DriftFinding>,

    /// Changed findings (status changed but not open<->resolved).
    pub changed: Vec<DriftFinding>,
}

/// A finding that changed between scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftFinding {
    /// Vuln ID.
    pub vuln_id: String,

    /// Rule title.
    pub title: String,

    /// Previous status.
    pub previous_status: FindingStatus,

    /// Current status.
    pub current_status: FindingStatus,

    /// Severity.
    pub severity: String,
}

impl DriftReport {
    /// Whether there are any changes.
    pub fn has_changes(&self) -> bool {
        !self.new_open.is_empty() || !self.newly_resolved.is_empty() || !self.changed.is_empty()
    }

    /// Whether compliance degraded.
    pub fn is_regression(&self) -> bool {
        self.compliance_delta < -0.1
    }
}

/// Compare two checklists and generate a drift report.
pub fn detect_drift(
    previous: &crate::models::Checklist,
    current: &crate::models::Checklist,
) -> DriftReport {
    let prev_summary = previous.summary();
    let curr_summary = current.summary();

    let prev_compliance = prev_summary.compliance_pct();
    let curr_compliance = curr_summary.compliance_pct();

    let mut new_open = Vec::new();
    let mut newly_resolved = Vec::new();
    let mut changed = Vec::new();

    for curr_finding in &current.findings {
        let prev_finding = previous
            .findings
            .iter()
            .find(|f| f.vuln_id == curr_finding.vuln_id);

        if let Some(prev) = prev_finding {
            if prev.status != curr_finding.status {
                let drift = DriftFinding {
                    vuln_id: curr_finding.vuln_id.clone(),
                    title: curr_finding.rule_title.clone(),
                    previous_status: prev.status,
                    current_status: curr_finding.status,
                    severity: curr_finding
                        .severity_override
                        .unwrap_or(curr_finding.severity)
                        .as_cat_str()
                        .to_string(),
                };

                match (prev.status, curr_finding.status) {
                    (_, FindingStatus::Open) if prev.status != FindingStatus::Open => {
                        new_open.push(drift);
                    }
                    (FindingStatus::Open, FindingStatus::NotAFinding)
                    | (FindingStatus::Open, FindingStatus::NotApplicable) => {
                        newly_resolved.push(drift);
                    }
                    _ => {
                        changed.push(drift);
                    }
                }
            }
        }
    }

    DriftReport {
        hostname: current.asset.hostname.clone(),
        stig_id: current.stig_info.stig_id.clone(),
        compared_at: Utc::now(),
        previous_compliance: prev_compliance,
        current_compliance: curr_compliance,
        compliance_delta: curr_compliance - prev_compliance,
        new_open,
        newly_resolved,
        changed,
    }
}

/// Schedule entry for a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleEntry {
    pub target_id: String,
    pub next_run: DateTime<Utc>,
    pub stig_ids: Vec<String>,
}

/// Generate the next schedule based on agent config.
pub fn generate_schedule(config: &AgentConfig) -> Vec<ScheduleEntry> {
    let now = Utc::now();
    let interval = chrono::Duration::minutes(config.scan_interval_minutes as i64);

    config
        .targets
        .iter()
        .filter(|t| t.enabled)
        .map(|target| {
            let next_run = target
                .last_scan
                .map(|last| last + interval)
                .filter(|next| *next > now)
                .unwrap_or(now);

            ScheduleEntry {
                target_id: target.id.clone(),
                next_run,
                stig_ids: target.stig_ids.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::asset::Asset;
    use crate::models::checklist::{Checklist, ChecklistStigInfo};
    use crate::models::finding::{Finding, FindingStatus};
    use crate::models::stig::Severity;

    fn make_checklist(statuses: &[(FindingStatus, &str)]) -> Checklist {
        let info = ChecklistStigInfo {
            stig_id: "Test".to_string(),
            title: "Test".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };
        let mut cl = Checklist::new(Asset::new("host1"), info);
        for (i, (status, title)) in statuses.iter().enumerate() {
            let vid = format!("V-{}", i + 1);
            let mut f = Finding::new_not_reviewed(&vid, &vid, &vid, title, Severity::Medium);
            f.status = *status;
            cl.findings.push(f);
        }
        cl
    }

    #[test]
    fn test_drift_detection_no_changes() {
        let prev = make_checklist(&[
            (FindingStatus::NotAFinding, "Rule 1"),
            (FindingStatus::Open, "Rule 2"),
        ]);
        let curr = make_checklist(&[
            (FindingStatus::NotAFinding, "Rule 1"),
            (FindingStatus::Open, "Rule 2"),
        ]);

        let report = detect_drift(&prev, &curr);
        assert!(!report.has_changes());
        assert_eq!(report.compliance_delta, 0.0);
    }

    #[test]
    fn test_drift_detection_new_finding() {
        let prev = make_checklist(&[
            (FindingStatus::NotAFinding, "Rule 1"),
            (FindingStatus::NotAFinding, "Rule 2"),
        ]);
        let curr = make_checklist(&[
            (FindingStatus::NotAFinding, "Rule 1"),
            (FindingStatus::Open, "Rule 2"),
        ]);

        let report = detect_drift(&prev, &curr);
        assert!(report.has_changes());
        assert!(report.is_regression());
        assert_eq!(report.new_open.len(), 1);
        assert_eq!(report.new_open[0].vuln_id, "V-2");
    }

    #[test]
    fn test_drift_detection_resolved() {
        let prev = make_checklist(&[
            (FindingStatus::Open, "Rule 1"),
            (FindingStatus::Open, "Rule 2"),
        ]);
        let curr = make_checklist(&[
            (FindingStatus::NotAFinding, "Rule 1"),
            (FindingStatus::Open, "Rule 2"),
        ]);

        let report = detect_drift(&prev, &curr);
        assert!(report.has_changes());
        assert!(!report.is_regression());
        assert_eq!(report.newly_resolved.len(), 1);
    }

    #[test]
    fn test_schedule_generation() {
        let config = AgentConfig {
            enabled: true,
            scan_interval_minutes: 60,
            targets: vec![MonitoredTarget {
                id: "t1".to_string(),
                hostname: "host1".to_string(),
                stig_ids: vec!["STIG1".to_string()],
                last_scan: None,
                last_compliance_pct: None,
                enabled: true,
            }],
            ..Default::default()
        };

        let schedule = generate_schedule(&config);
        assert_eq!(schedule.len(), 1);
    }
}
