//! Shared outbound destination validation helpers.
//!
//! These helpers keep connected-mode integrations from becoming SSRF or
//! network-pivot primitives when AutomateSTIG is run outside pure localhost
//! desktop mode.

use std::net::IpAddr;

use automatestig_core::network_policy::{classify_ip, normalize_mapped_ip, IpScope};

fn normalize_ip(ip: IpAddr) -> IpAddr {
    normalize_mapped_ip(ip)
}

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
    classify_ip(ip) != IpScope::Global
}

pub(crate) fn is_invalid_ip(ip: IpAddr) -> bool {
    classify_ip(ip) == IpScope::Invalid
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
    let Ok(mut prefix) = prefix.parse::<u32>() else {
        return false;
    };
    let ip = normalize_ip(ip);
    let base_ip = match base_ip {
        IpAddr::V6(v6) => {
            let Some(v4) = v6.to_ipv4_mapped() else {
                return match (ip, IpAddr::V6(v6)) {
                    (IpAddr::V6(ip), IpAddr::V6(base)) if prefix <= 128 => {
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u128::MAX << (128 - prefix)
                        };
                        (u128::from(ip) & mask) == (u128::from(base) & mask)
                    }
                    _ => false,
                };
            };
            // IPv4-mapped IPv6 occupies ::ffff:0:0/96. A shorter prefix is
            // not an IPv4 network and must not authorize mapped destinations.
            if prefix < 96 {
                return false;
            }
            prefix -= 96;
            IpAddr::V4(v4)
        }
        IpAddr::V4(v4) => IpAddr::V4(v4),
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
        _ => false,
    }
}

/// Match exact host/IP entries or IP CIDR entries.
pub(crate) fn host_or_ip_matches_allowlist(
    host: &str,
    ip: Option<IpAddr>,
    entries: &[String],
) -> bool {
    allowlist_matches_host(host, entries)
        || ip
            .or_else(|| host.trim_end_matches('.').parse::<IpAddr>().ok())
            .is_some_and(|ip| allowlist_matches_ip(ip, entries))
}

pub(crate) fn allowlist_matches_host(host: &str, entries: &[String]) -> bool {
    let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
    entries.iter().any(|entry| {
        !entry.contains('/')
            && entry.parse::<IpAddr>().is_err()
            && host_lc == entry.trim_end_matches('.').to_ascii_lowercase()
    })
}

pub(crate) fn allowlist_matches_ip(ip: IpAddr, entries: &[String]) -> bool {
    let ip = normalize_ip(ip);
    entries.iter().any(|entry| {
        entry
            .parse::<IpAddr>()
            .is_ok_and(|candidate| normalize_ip(candidate) == ip)
            || ip_in_cidr(ip, entry)
    })
}

pub(crate) fn validate_resolved_ips_with_policy(
    label: &str,
    host: &str,
    ips: &[IpAddr],
    allowlist: &[String],
    allow_private: bool,
) -> Result<(), String> {
    let host_allowlisted = allowlist_matches_host(host, allowlist);

    for ip in ips {
        if is_invalid_ip(*ip) {
            return Err(format!(
                "{label} host {host} resolves to invalid, reserved, multicast, or documentation address {ip}"
            ));
        }
        let ip_allowlisted = allowlist_matches_ip(*ip, allowlist);
        if !allowlist.is_empty() && !host_allowlisted && !ip_allowlisted {
            return Err(format!(
                "{label} host {host} resolves to unlisted address {ip}; update the configured target allowlist"
            ));
        }
        // An exact hostname entry is enough to constrain public routing once
        // the resulting addresses are pinned. Private/local/link-local
        // destinations additionally require an explicit IP/CIDR or lab
        // override so a compromised DNS answer cannot turn a public hostname
        // allowlist entry into an internal-network capability.
        if is_private_or_local_ip(*ip) && !ip_allowlisted && !allow_private {
            return Err(format!(
                "{label} host {host} resolves to private/local/link-local address {ip} and requires explicit private destination authorization"
            ));
        }
    }
    Ok(())
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
        assert!(validate_resolved_ips_with_policy(
            "test",
            "public-looking.example",
            &["10.0.0.10".parse().unwrap()],
            &entries,
            false,
        )
        .is_err());

        let entries = vec!["10.0.0.0/8".to_string()];
        validate_resolved_ips_with_policy(
            "test",
            "public-looking.example",
            &["10.0.0.10".parse().unwrap()],
            &entries,
            false,
        )
        .unwrap();

        validate_resolved_ips_with_policy(
            "test",
            "public-looking.example",
            &["10.0.0.10".parse().unwrap()],
            &[],
            true,
        )
        .unwrap();
    }

    #[test]
    fn configured_allowlist_rejects_unlisted_public_destinations() {
        let entries = vec!["allowed.example.mil".to_string()];
        assert!(validate_resolved_ips_with_policy(
            "test",
            "unlisted.example.mil",
            &["8.8.8.8".parse().unwrap()],
            &entries,
            false,
        )
        .unwrap_err()
        .contains("unlisted"));

        validate_resolved_ips_with_policy(
            "test",
            "allowed.example.mil",
            &["8.8.8.8".parse().unwrap()],
            &entries,
            false,
        )
        .unwrap();
    }

    #[test]
    fn hostname_allowlist_cannot_rebind_to_private_space() {
        let hostname_only = vec!["allowed.example.mil".to_string()];
        assert!(validate_resolved_ips_with_policy(
            "test",
            "allowed.example.mil",
            &["10.0.0.8".parse().unwrap()],
            &hostname_only,
            false,
        )
        .is_err());

        let pinned_private_range =
            vec!["allowed.example.mil".to_string(), "10.0.0.0/24".to_string()];
        validate_resolved_ips_with_policy(
            "test",
            "allowed.example.mil",
            &["10.0.0.8".parse().unwrap()],
            &pinned_private_range,
            false,
        )
        .unwrap();
    }

    #[test]
    fn hostname_allowlist_cannot_rebind_to_non_global_special_space() {
        let hostname_only = vec!["allowed.example.mil".to_string()];
        for address in [
            "100.64.0.1",
            "198.18.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2002::1",
            "fec0::1",
        ] {
            assert!(
                validate_resolved_ips_with_policy(
                    "test",
                    "allowed.example.mil",
                    &[address.parse().unwrap()],
                    &hostname_only,
                    false,
                )
                .is_err(),
                "{address} must require explicit special-use authorization"
            );
        }
    }

    #[test]
    fn invalid_destinations_cannot_be_enabled_by_an_allowlist_or_lab_override() {
        for address in [
            "0.0.0.0",
            "192.0.2.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "100:0:0:1::1",
            "2001:db8::1",
            "4000::1",
            "8000::1",
            "ff02::1",
        ] {
            let ip = address.parse().unwrap();
            assert!(
                validate_resolved_ips_with_policy(
                    "test",
                    "allowed.example.mil",
                    &[ip],
                    &[address.to_string()],
                    true,
                )
                .is_err(),
                "{address} must remain invalid under every destination policy"
            );
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_uses_embedded_ipv4_security_classification() {
        for mapped in ["::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
            assert!(
                is_private_or_local_ip(mapped.parse().unwrap()),
                "{mapped} must retain the embedded IPv4 security classification"
            );
        }
        assert!(!is_private_or_local_ip("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn mapped_ipv4_cannot_bypass_private_destination_authorization() {
        let mapped_private = "::ffff:10.0.0.8".parse().unwrap();
        let hostname_only = vec!["allowed.example.mil".to_string()];
        assert!(validate_resolved_ips_with_policy(
            "test",
            "allowed.example.mil",
            &[mapped_private],
            &hostname_only,
            false,
        )
        .is_err());

        let broad_ipv6 = vec!["allowed.example.mil".to_string(), "::/0".to_string()];
        assert!(validate_resolved_ips_with_policy(
            "test",
            "allowed.example.mil",
            &[mapped_private],
            &broad_ipv6,
            false,
        )
        .is_err());

        for explicit_private_range in ["10.0.0.0/24", "::ffff:10.0.0.0/120"] {
            let entries = vec![
                "allowed.example.mil".to_string(),
                explicit_private_range.to_string(),
            ];
            validate_resolved_ips_with_policy(
                "test",
                "allowed.example.mil",
                &[mapped_private],
                &entries,
                false,
            )
            .unwrap();
        }
    }
}
