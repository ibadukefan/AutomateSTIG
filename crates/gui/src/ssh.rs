//! Shared SSH transport facade for the GUI.

pub use automatestig_collector::{SshAuth, SshConfig};

fn ssh_allowlist_entries() -> Vec<String> {
    crate::outbound::allowlist_entries("AUTOMATESTIG_SSH_TARGET_ALLOWLIST")
}

fn host_matches_allowlist(host: &str, entries: &[String]) -> bool {
    crate::outbound::host_or_ip_matches_allowlist(host, None, entries)
}

/// Validate a remote SSH scan destination before resolving or connecting.
///
/// If `AUTOMATESTIG_SSH_TARGET_ALLOWLIST` is set, every scan host must match an
/// exact hostname/IP entry or an IP CIDR entry. Private, loopback, link-local,
/// multicast, documentation, and cloud metadata literal IPs are blocked by
/// default unless explicitly allowlisted or the isolated-lab override
/// `AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN=1` is set.
pub(crate) fn validate_scan_target(host: &str) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("SSH scan host must not be empty".to_string());
    }
    if host.contains('/') || host.contains('\\') || host.contains('\0') {
        return Err("SSH scan host contains unsafe characters".to_string());
    }

    let allowlist = ssh_allowlist_entries();
    let allowlisted = !allowlist.is_empty() && host_matches_allowlist(host, &allowlist);
    if !allowlist.is_empty() && !allowlisted {
        return Err("SSH scan host is not in AUTOMATESTIG_SSH_TARGET_ALLOWLIST".to_string());
    }

    let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
    if crate::outbound::hostname_is_local_or_metadata(&host_lc) {
        return Err("SSH scan host is local/metadata and is not allowed".to_string());
    }

    if let Ok(ip) = host_lc.parse::<std::net::IpAddr>() {
        if crate::outbound::is_private_or_local_ip(ip)
            && !allowlisted
            && !crate::outbound::env_flag("AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN")
        {
            return Err("SSH scan to private/local/link-local literal IP requires explicit allowlist or AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN=1".to_string());
        }
    }

    Ok(())
}

/// Validate resolved addresses immediately before the shared collector opens
/// the connection. This complements the collector's trust-class and rebinding
/// checks with the GUI's explicit outbound allowlist boundary.
pub(crate) async fn validate_scan_target_for_connection(
    host: &str,
    port: u16,
) -> Result<(), String> {
    validate_scan_target(host)?;
    if port == 0 {
        return Err("SSH scan port must be greater than zero".to_string());
    }
    crate::outbound::validate_resolved_destination(
        "SSH scan target",
        host,
        port,
        "AUTOMATESTIG_SSH_TARGET_ALLOWLIST",
        "AUTOMATESTIG_ALLOW_PRIVATE_SSH_SCAN",
        None,
    )
    .await
}

#[cfg(test)]
pub(crate) use automatestig_collector::{collect_plan, SshHandler};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_scan_target_rejects_private_and_local_literals() {
        for host in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.1.10",
            "192.168.1.10",
            "169.254.169.254",
            "::1",
            "fc00::1",
            "localhost",
            "metadata.google.internal",
        ] {
            assert!(
                validate_scan_target(host).is_err(),
                "{host} should be rejected by default"
            );
        }
    }

    #[test]
    fn validate_scan_target_accepts_public_hosts() {
        validate_scan_target("server01.example.mil").unwrap();
        validate_scan_target("203.0.113.10").unwrap_err();
        validate_scan_target("8.8.8.8").unwrap();
    }

    #[test]
    fn allowlist_matches_exact_hosts_and_cidrs() {
        let entries = vec![
            "server01.example.mil".to_string(),
            "10.5.0.0/16".to_string(),
        ];
        assert!(host_matches_allowlist("server01.example.mil", &entries));
        assert!(host_matches_allowlist("10.5.2.3", &entries));
        assert!(!host_matches_allowlist("server02.example.mil", &entries));
        assert!(!host_matches_allowlist("10.6.2.3", &entries));
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
