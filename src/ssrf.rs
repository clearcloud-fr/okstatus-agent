use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

// OKS-401 — private mode (customer-deployed agent inside its own network):
// probing private IPs is the feature, so the runtime SSRF guard is lifted.
// Set once at startup by enroll.rs; fleet agents never touch it.
static ALLOW_PRIVATE_TARGETS: AtomicBool = AtomicBool::new(false);

pub fn set_allow_private_targets(allow: bool) {
    ALLOW_PRIVATE_TARGETS.store(allow, Ordering::Relaxed);
}

pub fn allow_private_targets() -> bool {
    ALLOW_PRIVATE_TARGETS.load(Ordering::Relaxed)
}

// OKS-668 — names that only ever resolve inside a cluster or a LAN. Mirrors
// isPrivateHostname() in the backend (shared/url-validator.ts); checked
// BEFORE resolving so a cluster-internal name is refused even when the
// agent's own resolver would happily answer it.
const PRIVATE_HOSTNAME_SUFFIXES: &[&str] =
    &[".localhost", ".local", ".internal", ".svc", ".cluster.local", ".lan", ".home.arpa"];

pub fn is_private_hostname(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h == "localhost" || h == "metadata.google.internal" || h == "instance-data" {
        return true;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return is_private_ip(&ip);
    }
    if PRIVATE_HOSTNAME_SUFFIXES.iter().any(|s| h.ends_with(s)) {
        return true;
    }
    // Single-label names (`postgres`, `redis`) only resolve via a search domain.
    !h.contains('.')
}

/// Returns true if the given IP address is private, reserved, loopback, or link-local.
/// Used to prevent SSRF attacks via DNS server configuration or HTTP redirects.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()           // 127.0.0.0/8
            || v4.is_private()         // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local()      // 169.254.0.0/16
            || v4.is_unspecified()     // 0.0.0.0
            || v4.is_broadcast()       // 255.255.255.255
            || v4.octets()[0] == 100 && (v4.octets()[1] >= 64 && v4.octets()[1] <= 127) // shared address space 100.64.0.0/10
            || v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19)  // benchmark 198.18.0.0/15
            || v4.octets() == [192, 0, 0, 0] || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0) // IETF protocol 192.0.0.0/24
            || v4.octets() == [192, 0, 2, 0] || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 2) // TEST-NET-1 192.0.2.0/24
            || (v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100) // TEST-NET-2 198.51.100.0/24
            || (v4.octets()[0] == 203 && v4.octets()[1] == 0 && v4.octets()[2] == 113)  // TEST-NET-3 203.0.113.0/24
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()           // ::1
            || v6.is_unspecified()     // ::
            || {
                let segments = v6.segments();
                // fc00::/7 — unique local
                (segments[0] & 0xfe00) == 0xfc00
                // fe80::/10 — link-local
                || (segments[0] & 0xffc0) == 0xfe80
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_private_ipv4() {
        let cases = vec![
            ("127.0.0.1", true),
            ("10.0.0.1", true),
            ("172.16.0.1", true),
            ("192.168.1.1", true),
            ("169.254.169.254", true),
            ("0.0.0.0", true),
            ("8.8.8.8", false),
            ("1.1.1.1", false),
            ("93.184.216.34", false),
        ];
        for (ip_str, expected) in cases {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert_eq!(is_private_ip(&ip), expected, "failed for {ip_str}");
        }
    }

    #[test]
    fn test_private_hostname() {
        for h in ["redis", "db.svc", "api.okstatus.svc.cluster.local", "foo.internal", "localhost", "10.0.0.1", "fd00::1"] {
            assert!(is_private_hostname(h), "{h}");
        }
        for h in ["example.com", "node1.database.cloud.ovh.net", "8.8.8.8"] {
            assert!(!is_private_hostname(h), "{h}");
        }
    }

    #[test]
    fn test_private_ipv6() {
        let cases = vec![
            ("::1", true),
            ("::", true),
            ("fc00::1", true),
            ("fe80::1", true),
            ("2001:db8::1", false),
        ];
        for (ip_str, expected) in cases {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert_eq!(is_private_ip(&ip), expected, "failed for {ip_str}");
        }
    }
}
