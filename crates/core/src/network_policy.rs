//! Shared classification for outbound network destinations.
//!
//! Hostname allowlists are not sufficient authorization for special-use
//! address space: DNS can change after configuration review. Callers use this
//! module after resolving once and require an explicit IP/CIDR or lab override
//! for every address that is not ordinary global unicast.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScope {
    Global,
    PrivateOrSpecial,
    LinkLocal,
    Loopback,
    Invalid,
}

pub fn normalize_mapped_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        IpAddr::V4(_) => address,
    }
}

fn ipv4_in_prefix(address: Ipv4Addr, base: Ipv4Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(address) & mask) == (u32::from(base) & mask)
}

fn ipv6_in_prefix(address: Ipv6Addr, base: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(address) & mask) == (u128::from(base) & mask)
}

pub fn classify_ip(address: IpAddr) -> IpScope {
    match normalize_mapped_ip(address) {
        IpAddr::V4(address) => {
            if address.is_unspecified()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || address.octets()[0] == 0
                || address.octets()[0] >= 240
            {
                return IpScope::Invalid;
            }
            if address.is_loopback() {
                return IpScope::Loopback;
            }
            if address.is_link_local() {
                return IpScope::LinkLocal;
            }
            if address.is_private()
                // Shared address space (carrier-grade NAT).
                || ipv4_in_prefix(address, Ipv4Addr::new(100, 64, 0, 0), 10)
                // IETF protocol assignments and deprecated relay anycast.
                || ipv4_in_prefix(address, Ipv4Addr::new(192, 0, 0, 0), 24)
                || ipv4_in_prefix(address, Ipv4Addr::new(192, 88, 99, 0), 24)
                // Benchmarking and other explicitly special-use anycast blocks.
                || ipv4_in_prefix(address, Ipv4Addr::new(198, 18, 0, 0), 15)
                || ipv4_in_prefix(address, Ipv4Addr::new(192, 31, 196, 0), 24)
                || ipv4_in_prefix(address, Ipv4Addr::new(192, 52, 193, 0), 24)
                || ipv4_in_prefix(address, Ipv4Addr::new(192, 175, 48, 0), 24)
            {
                IpScope::PrivateOrSpecial
            } else {
                IpScope::Global
            }
        }
        IpAddr::V6(address) => {
            if address.is_unspecified()
                || address.is_multicast()
                || ipv6_in_prefix(
                    address,
                    "2001:db8::".parse().expect("constant IPv6 prefix"),
                    32,
                )
                || ipv6_in_prefix(address, "3fff::".parse().expect("constant IPv6 prefix"), 20)
                // IANA Dummy IPv6 Prefix: not valid as a source or destination.
                || ipv6_in_prefix(
                    address,
                    "100:0:0:1::".parse().expect("constant IPv6 prefix"),
                    64,
                )
            {
                return IpScope::Invalid;
            }
            if address.is_loopback() {
                return IpScope::Loopback;
            }
            if address.is_unicast_link_local() {
                return IpScope::LinkLocal;
            }
            if address.is_unique_local()
                // IPv4-compatible, NAT64, discard-only, protocol-assignment,
                // 6to4, segment-routing, and deprecated site-local space.
                || ipv6_in_prefix(address, Ipv6Addr::UNSPECIFIED, 96)
                || ipv6_in_prefix(
                    address,
                    "64:ff9b::".parse().expect("constant IPv6 prefix"),
                    96,
                )
                || ipv6_in_prefix(
                    address,
                    "64:ff9b:1::".parse().expect("constant IPv6 prefix"),
                    48,
                )
                || ipv6_in_prefix(
                    address,
                    "100::".parse().expect("constant IPv6 prefix"),
                    64,
                )
                || ipv6_in_prefix(
                    address,
                    "2001::".parse().expect("constant IPv6 prefix"),
                    23,
                )
                || ipv6_in_prefix(
                    address,
                    "2002::".parse().expect("constant IPv6 prefix"),
                    16,
                )
                || ipv6_in_prefix(
                    address,
                    "5f00::".parse().expect("constant IPv6 prefix"),
                    16,
                )
                || ipv6_in_prefix(
                    address,
                    "fec0::".parse().expect("constant IPv6 prefix"),
                    10,
                )
            {
                IpScope::PrivateOrSpecial
            } else if ipv6_in_prefix(address, "2000::".parse().expect("constant IPv6 prefix"), 3) {
                // Only the ordinary IPv6 global-unicast allocation is public
                // by default. Reserved and future-use ranges fail closed.
                IpScope::Global
            } else {
                IpScope::Invalid
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_use_addresses_are_never_global() {
        for value in [
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.0.9",
            "192.168.1.1",
            "198.18.0.1",
            "::ffff:100.64.0.1",
            "::1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "4000::1",
            "8000::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
        ] {
            let address = value.parse().expect("test address");
            assert_ne!(classify_ip(address), IpScope::Global, "{value}");
        }
    }

    #[test]
    fn ordinary_public_unicast_remains_global() {
        for value in [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            assert_eq!(
                classify_ip(value.parse().expect("test address")),
                IpScope::Global,
                "{value}"
            );
        }
    }

    #[test]
    fn unallocated_ipv6_and_dummy_prefix_fail_closed() {
        for value in ["100:0:0:1::1", "4000::1", "8000::1"] {
            assert_eq!(
                classify_ip(value.parse().expect("test address")),
                IpScope::Invalid,
                "{value}"
            );
        }
    }
}
