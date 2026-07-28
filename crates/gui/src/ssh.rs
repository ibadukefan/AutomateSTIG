//! Shared SSH transport facade for the GUI.

pub use automatestig_collector::{SshAuth, SshConfig};

/// Validate target syntax early enough to return a client error. Destination
/// resolution and authorization occur exactly once inside the collector.
pub(crate) fn validate_scan_target(host: &str) -> Result<(), String> {
    automatestig_collector::validate_ssh_target_syntax(host)
}

#[cfg(test)]
pub(crate) use automatestig_collector::SshHandler;

#[cfg(test)]
pub(crate) async fn collect_plan(
    config: &SshConfig,
    plan: &automatestig_core::remote::CollectionPlan,
) -> automatestig_collector::CollectionReport {
    let policy =
        automatestig_collector::SshTargetPolicy::explicit(["127.0.0.1", "::1"], false, false);
    automatestig_collector::collect_plan_with_policy(config, plan, &policy).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_scan_target_rejects_local_names_and_unsafe_syntax() {
        for host in [
            "localhost",
            "metadata.google.internal",
            "space in name",
            "../device",
            "device\\name",
            "device\0name",
        ] {
            assert!(
                validate_scan_target(host).is_err(),
                "{host} should be rejected by default"
            );
        }
    }

    #[test]
    fn validate_scan_target_defers_address_policy_to_collector() {
        validate_scan_target("server01.example.mil").unwrap();
        validate_scan_target("10.0.0.5").unwrap();
        validate_scan_target("203.0.113.10").unwrap();
        validate_scan_target("8.8.8.8").unwrap();
    }

    #[test]
    fn syntax_validation_rejects_empty_host() {
        assert!(validate_scan_target("").is_err());
        assert!(validate_scan_target("device.example.mil").is_ok());
    }

    #[test]
    fn ssh_config_serialization_uses_shared_collector_types() {
        let config = SshConfig {
            host: "10.0.1.50".to_string(),
            port: 22,
            username: "admin".to_string(),
            auth: SshAuth::Password {
                password: "secret".to_string(),
            },
            timeout_secs: 30,
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: SshConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, "10.0.1.50");
        assert_eq!(parsed.port, 22);
    }
}

#[cfg(test)]
#[path = "ssh_fault_tests.rs"]
mod ssh_fault_tests;
