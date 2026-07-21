//! Shared outbound destination validation helpers.
//!
//! These helpers keep connected-mode integrations from becoming SSRF or
//! network-pivot primitives when AutomateSTIG is run outside pure localhost
//! desktop mode.

use std::net::IpAddr;

/// Whether an environment variable is enabled with a truthy value.
pub(crate) fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

/// Parse a comma-separated allowlist environment variable.
pub(crate) fn allowlist_entries(env_name: &str) -> Vec<String> {
    std::env::var(env_name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(crate) fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                || v4.octets()[0] >= 224
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.segments()[0] & 0xff00 == 0xff00
        }
    }
}

pub(crate) fn hostname_is_local_or_metadata(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h == "metadata.google.internal"
        || h.ends_with(".metadata.google.internal")
}

pub(crate) fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(base_ip) = base.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match (ip, base_ip) {
        (IpAddr::V4(ip), IpAddr::V4(base)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(ip) & mask) == (u32::from(base) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(ip) & mask) == (u128::from(base) & mask)
        }
        _ => false,
    }
}

/// Match exact host/IP entries or IP CIDR entries.
pub(crate) fn host_or_ip_matches_allowlist(
    host: &str,
    ip: Option<IpAddr>,
    entries: &[String],
) -> bool {
    let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
    let parsed_ip = ip.or_else(|| host_lc.parse::<IpAddr>().ok());
    entries.iter().any(|entry| {
        let entry_lc = entry.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ip) = parsed_ip {
            if ip_in_cidr(ip, &entry_lc) {
                return true;
            }
        }
        host_lc == entry_lc
    })
}

/// Validate already-resolved addresses for a destination host.
pub(crate) fn validate_resolved_ips(
    label: &str,
    host: &str,
    ips: &[IpAddr],
    allowlist: &[String],
    allow_private_env: &str,
    broad_private_override_env: Option<&str>,
) -> Result<(), String> {
    let allow_private =
        env_flag(allow_private_env) || broad_private_override_env.map(env_flag).unwrap_or(false);

    for ip in ips {
        let allowlisted = host_or_ip_matches_allowlist(host, Some(*ip), allowlist);
        if is_private_or_local_ip(*ip) && !allowlisted && !allow_private {
            return Err(format!(
                "{label} resolves to private/local/link-local address {ip}; add an exact host/IP/CIDR allowlist entry or set {allow_private_env}=1 only for an isolated lab"
            ));
        }
    }
    Ok(())
}

/// Resolve a host and validate its destination addresses.
pub(crate) async fn validate_resolved_destination(
    label: &str,
    host: &str,
    port: u16,
    allowlist_env: &str,
    allow_private_env: &str,
    broad_private_override_env: Option<&str>,
) -> Result<(), String> {
    let allowlist = allowlist_entries(allowlist_env);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("Failed to resolve {label} host {host}: {e}"))?;
    let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
    if ips.is_empty() {
        return Err(format!("{label} host {host} resolved to no addresses"));
    }
    validate_resolved_ips(
        label,
        host,
        &ips,
        &allowlist,
        allow_private_env,
        broad_private_override_env,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matches_exact_hosts_ips_and_cidrs() {
        let entries = vec![
            "server01.example.mil".to_string(),
            "10.5.0.0/16".to_string(),
        ];
        assert!(host_or_ip_matches_allowlist(
            "server01.example.mil",
            None,
            &entries
        ));
        assert!(host_or_ip_matches_allowlist(
            "host.example",
            Some("10.5.2.3".parse().unwrap()),
            &entries
        ));
        assert!(!host_or_ip_matches_allowlist(
            "server02.example.mil",
            None,
            &entries
        ));
        assert!(!host_or_ip_matches_allowlist(
            "host.example",
            Some("10.6.2.3".parse().unwrap()),
            &entries
        ));
    }

    #[test]
    fn resolved_private_ip_requires_allowlist_or_override() {
        let entries: Vec<String> = vec![];
        assert!(validate_resolved_ips(
            "test",
            "public-looking.example",
            &["10.0.0.10".parse().unwrap()],
            &entries,
            "AUTOMATESTIG_TEST_ALLOW_PRIVATE_DESTINATION",
            None,
        )
        .is_err());

        let entries = vec!["10.0.0.0/8".to_string()];
        validate_resolved_ips(
            "test",
            "public-looking.example",
            &["10.0.0.10".parse().unwrap()],
            &entries,
            "AUTOMATESTIG_TEST_ALLOW_PRIVATE_DESTINATION",
            None,
        )
        .unwrap();
    }
}
