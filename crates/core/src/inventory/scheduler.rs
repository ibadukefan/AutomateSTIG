//! Evaluation scheduler — recurring and one-time scan jobs.
//!
//! Supports:
//! - Cron-like recurring schedules (daily, weekly, monthly, custom)
//! - One-time evaluations
//! - Parallel execution of multiple assets
//! - Staggered start times to avoid overloading the network
//! - Automatic retry on connection failure
//! - Post-evaluation actions (push to STIG-Manager, generate reports, alert on drift)

use chrono::{DateTime, Datelike, NaiveTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A scheduled evaluation job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationSchedule {
    /// Unique schedule ID.
    pub id: String,

    /// Display name (e.g., "Weekly Windows Server Scan").
    pub name: String,

    /// Description.
    pub description: Option<String>,

    /// Asset IDs to evaluate.
    pub asset_ids: Vec<String>,

    /// Alternatively, evaluate all assets matching these tags.
    pub asset_tags: Vec<String>,

    /// Whether the schedule is active.
    pub enabled: bool,

    /// Schedule frequency.
    pub frequency: ScheduleFrequency,

    /// Time of day to run (UTC, 24-hour).
    pub run_at_hour: u32,
    pub run_at_minute: u32,

    /// Maximum parallel connections.
    pub max_parallel: usize,

    /// Seconds to stagger between starting each asset scan.
    pub stagger_seconds: u64,

    /// Retry failed connections this many times.
    pub retry_count: u32,

    /// Seconds between retries.
    pub retry_delay_seconds: u64,

    /// Post-evaluation actions.
    pub post_actions: PostActions,

    /// When this schedule was last executed.
    pub last_run: Option<DateTime<Utc>>,

    /// Result of the last execution.
    pub last_run_status: Option<ScheduleRunStatus>,

    /// When the next run is scheduled.
    pub next_run: Option<DateTime<Utc>>,

    /// When this schedule was created.
    pub created_at: DateTime<Utc>,
}

/// How often a schedule runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScheduleFrequency {
    /// Run once (one-time job).
    Once,

    /// Run every N hours.
    Hourly { interval: u32 },

    /// Run daily.
    Daily,

    /// Run on specific days of the week.
    Weekly { days: Vec<String> },

    /// Run on a specific day of each month.
    Monthly { day_of_month: u32 },

    /// Run every N minutes (for testing/continuous compliance).
    Custom { interval_minutes: u64 },
}

/// Actions to take after an evaluation completes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostActions {
    /// Push results to STIG-Manager automatically.
    pub push_to_stigman: bool,

    /// STIG-Manager collection ID (if pushing).
    pub stigman_collection_id: Option<String>,

    /// Generate an HTML report.
    pub generate_report: bool,

    /// Alert if any new CAT I findings are detected.
    pub alert_on_cat_i: bool,

    /// Alert if compliance drops below this threshold (0-100).
    pub alert_below_compliance: Option<f64>,

    /// Alert if any drift is detected from the previous scan.
    pub alert_on_drift: bool,
}

/// Status of a schedule execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRunStatus {
    pub completed_at: DateTime<Utc>,
    pub assets_scanned: usize,
    pub assets_failed: usize,
    pub total_findings: usize,
    pub total_open: usize,
    pub avg_compliance: f64,
    pub errors: Vec<String>,
}

impl EvaluationSchedule {
    /// Create a new schedule.
    pub fn new(name: &str, frequency: ScheduleFrequency) -> Self {
        let mut schedule = Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            asset_ids: Vec::new(),
            asset_tags: Vec::new(),
            enabled: true,
            frequency,
            run_at_hour: 2, // Default: 2 AM UTC
            run_at_minute: 0,
            max_parallel: 5,
            stagger_seconds: 10,
            retry_count: 2,
            retry_delay_seconds: 30,
            post_actions: PostActions::default(),
            last_run: None,
            last_run_status: None,
            next_run: None,
            created_at: Utc::now(),
        };
        schedule.next_run = Some(schedule.calculate_next_run(Utc::now()));
        schedule
    }

    /// Calculate the next run time after the given timestamp.
    pub fn calculate_next_run(&self, after: DateTime<Utc>) -> DateTime<Utc> {
        let target_time = NaiveTime::from_hms_opt(self.run_at_hour, self.run_at_minute, 0)
            .unwrap_or(NaiveTime::from_hms_opt(2, 0, 0).unwrap());

        match &self.frequency {
            ScheduleFrequency::Once => {
                // Next occurrence of the target time.
                let today_at = after.date_naive().and_time(target_time).and_utc();
                if today_at > after {
                    today_at
                } else {
                    (after.date_naive() + chrono::Duration::days(1))
                        .and_time(target_time)
                        .and_utc()
                }
            }

            ScheduleFrequency::Hourly { interval } => {
                after + chrono::Duration::hours(*interval as i64)
            }

            ScheduleFrequency::Daily => {
                let today_at = after.date_naive().and_time(target_time).and_utc();
                if today_at > after {
                    today_at
                } else {
                    (after.date_naive() + chrono::Duration::days(1))
                        .and_time(target_time)
                        .and_utc()
                }
            }

            ScheduleFrequency::Weekly { days } => {
                let target_weekdays: Vec<Weekday> = days
                    .iter()
                    .filter_map(|d| match d.to_lowercase().as_str() {
                        "monday" | "mon" => Some(Weekday::Mon),
                        "tuesday" | "tue" => Some(Weekday::Tue),
                        "wednesday" | "wed" => Some(Weekday::Wed),
                        "thursday" | "thu" => Some(Weekday::Thu),
                        "friday" | "fri" => Some(Weekday::Fri),
                        "saturday" | "sat" => Some(Weekday::Sat),
                        "sunday" | "sun" => Some(Weekday::Sun),
                        _ => None,
                    })
                    .collect();

                // Find the next matching day.
                for offset in 0..8 {
                    let candidate_date = after.date_naive() + chrono::Duration::days(offset);
                    let candidate = candidate_date.and_time(target_time).and_utc();
                    if candidate > after && target_weekdays.contains(&candidate_date.weekday()) {
                        return candidate;
                    }
                }
                // Fallback: next week same day.
                after + chrono::Duration::weeks(1)
            }

            ScheduleFrequency::Monthly { day_of_month } => {
                let day = (*day_of_month).min(28); // Safe for all months.
                let this_month = after
                    .date_naive()
                    .with_day(day)
                    .map(|d| d.and_time(target_time).and_utc());

                if let Some(candidate) = this_month {
                    if candidate > after {
                        return candidate;
                    }
                }

                // Next month.
                let next_month = if after.month() == 12 {
                    after
                        .date_naive()
                        .with_month(1)
                        .and_then(|d| d.with_year(after.year() + 1))
                } else {
                    after.date_naive().with_month(after.month() + 1)
                };
                next_month
                    .and_then(|d| d.with_day(day))
                    .map(|d| d.and_time(target_time).and_utc())
                    .unwrap_or(after + chrono::Duration::days(30))
            }

            ScheduleFrequency::Custom { interval_minutes } => {
                after + chrono::Duration::minutes(*interval_minutes as i64)
            }
        }
    }

    /// Mark as executed and calculate the next run.
    pub fn mark_executed(&mut self, status: ScheduleRunStatus) {
        let now = Utc::now();
        self.last_run = Some(now);
        self.last_run_status = Some(status);

        // Calculate next run (unless it's a one-time job).
        if matches!(self.frequency, ScheduleFrequency::Once) {
            self.enabled = false;
            self.next_run = None;
        } else {
            self.next_run = Some(self.calculate_next_run(now));
        }
    }
}

/// Configuration for the scheduler engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// All configured schedules.
    pub schedules: Vec<EvaluationSchedule>,

    /// Global maximum parallel connections across all schedules.
    pub global_max_parallel: usize,

    /// Whether the scheduler is enabled.
    pub enabled: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            schedules: Vec::new(),
            global_max_parallel: 10,
            enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daily_schedule() {
        let schedule = EvaluationSchedule::new("Daily scan", ScheduleFrequency::Daily);
        assert!(schedule.next_run.is_some());
        assert!(schedule.enabled);
    }

    #[test]
    fn test_weekly_schedule() {
        let schedule = EvaluationSchedule::new(
            "Weekly Monday",
            ScheduleFrequency::Weekly {
                days: vec!["monday".to_string()],
            },
        );
        let next = schedule.next_run.unwrap();
        assert!(next > Utc::now());
    }

    #[test]
    fn test_monthly_schedule() {
        let schedule = EvaluationSchedule::new(
            "Monthly 1st",
            ScheduleFrequency::Monthly { day_of_month: 1 },
        );
        assert!(schedule.next_run.is_some());
    }

    #[test]
    fn test_custom_interval() {
        let schedule = EvaluationSchedule::new(
            "Every 30 min",
            ScheduleFrequency::Custom {
                interval_minutes: 30,
            },
        );
        let next = schedule.next_run.unwrap();
        let diff = next - Utc::now();
        assert!(diff.num_minutes() >= 29 && diff.num_minutes() <= 31);
    }

    #[test]
    fn test_one_time_disables_after_run() {
        let mut schedule = EvaluationSchedule::new("One-shot", ScheduleFrequency::Once);
        assert!(schedule.enabled);

        schedule.mark_executed(ScheduleRunStatus {
            completed_at: Utc::now(),
            assets_scanned: 1,
            assets_failed: 0,
            total_findings: 100,
            total_open: 5,
            avg_compliance: 95.0,
            errors: Vec::new(),
        });

        assert!(!schedule.enabled);
        assert!(schedule.next_run.is_none());
    }

    #[test]
    fn test_schedule_json_roundtrip() {
        let mut schedule = EvaluationSchedule::new("Test", ScheduleFrequency::Daily);
        schedule.asset_ids = vec!["asset-1".to_string(), "asset-2".to_string()];
        schedule.post_actions.push_to_stigman = true;
        schedule.post_actions.alert_on_cat_i = true;

        let json = serde_json::to_string_pretty(&schedule).unwrap();
        let parsed: EvaluationSchedule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Test");
        assert_eq!(parsed.asset_ids.len(), 2);
        assert!(parsed.post_actions.push_to_stigman);
    }
}
