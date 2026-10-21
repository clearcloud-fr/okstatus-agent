use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

// OKS-401 — private mode (customer-deployed agent inside its own network):
// probing private IPs is the feature, so the runtime SSRF guard is lifted —
// except for the cloud metadata endpoints (see ALLOW_CLOUD_METADATA).
// Set once at startup by enroll.rs; fleet agents never touch it.
static ALLOW_PRIVATE_TARGETS: AtomicBool = AtomicBool::new(false);

pub fn set_allow_private_targets(allow: bool) {
    ALLOW_PRIVATE_TARGETS.store(allow, Ordering::Relaxed);
}

pub fn allow_private_targets() -> bool {
    ALLOW_PRIVATE_TARGETS.load(Ordering::Relaxed)
}

// Private mode still refuses the cloud metadata endpoints: a monitor created
// in the dashboard must not be able to read the instance credentials of the
// machine the customer installed the agent on. OKSTATUS_ALLOW_CLOUD_METADATA=true
// lifts it for the rare customer who really monitors that endpoint.
static ALLOW_CLOUD_METADATA: AtomicBool = AtomicBool::new(false);

pub fn set_allow_cloud_metadata(allow: bool) {
    ALLOW_CLOUD_METADATA.store(allow, Ordering::Relaxed);
}

fn allow_cloud_metadata() -> bool {
    ALLOW_CLOUD_METADATA.load(Ordering::Relaxed)
}

/// Instance metadata services: AWS/GCP/Azure/OpenStack/OVH/Scaleway
/// (169.254.169.254), AWS ECS task credentials (169.254.170.2), AWS IPv6
/// (fd00:ec2::254), Alibaba (100.100.100.200).
pub fn is_cloud_metadata_ip(ip: &IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => return *v6 == std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
        },
        v4 => *v4,
    };
    matches!(
        ip,
        IpAddr::V4(v4) if [[169, 254, 169, 254], [169, 254, 170, 2], [100, 100, 100, 200]].contains(&v4.octets())
    )
}

fn is_cloud_metadata_hostname(host: &str) -> bool {
    let h = host
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if matches!(h.as_str(), "metadata.google.internal" | "metadata" | "instance-data" | "instance-data.ec2.internal") {
        return true;
    }
    h.parse::<IpAddr>().map(|ip| is_cloud_metadata_ip(&ip)).unwrap_or(false)
}

/// The address a check must refuse: every private address on a fleet agent,
/// only the cloud metadata endpoints on a private agent.
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    blocked_ip(ip, allow_private_targets(), allow_cloud_metadata())
}

/// Same rule as `is_blocked_ip`, for a name checked before resolving it.
pub fn is_blocked_hostname(host: &str) -> bool {
    blocked_hostname(host, allow_private_targets(), allow_cloud_metadata())
}

fn blocked_ip(ip: &IpAddr, private_mode: bool, allow_metadata: bool) -> bool {
    if private_mode {
        !allow_metadata && is_cloud_metadata_ip(ip)
    } else {
        is_private_ip(ip)
    }
}

fn blocked_hostname(host: &str, private_mode: bool, allow_metadata: bool) -> bool {
    if private_mode {
        !allow_metadata && is_cloud_metadata_hostname(host)
    } else {
        is_private_hostname(host)
    }
}

// OKS-668 — names that only ever resolve inside a cluster or a LAN. Mirrors
// isPrivateHostname() in the backend (shared/url-validator.ts); checked
// BEFORE resolving so a cluster-internal name is refused even when the
// agent's own resolver would happily answer it.
const PRIVATE_HOSTNAME_SUFFIXES: &[&str] =
    &[".localhost", ".local", ".internal", ".svc", ".cluster.local", ".lan", ".home.arpa"];

pub fn is_private_hostname(host: &str) -> bool {
    // A bracketed IPv6 literal (`[::1]`) must be judged as the address it is.
    let h = host
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
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
            || v4.octets()[0] == 0     // 0.0.0.0/8 "this network" (routes to localhost on Linux)
            || v4.is_broadcast()       // 255.255.255.255
            || v4.is_multicast()       // 224.0.0.0/4
            || v4.octets()[0] >= 240   // 240.0.0.0/4 reserved
            || v4.octets()[0] == 100 && (v4.octets()[1] >= 64 && v4.octets()[1] <= 127) // shared address space 100.64.0.0/10
            || v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19)  // benchmark 198.18.0.0/15
            || v4.octets() == [192, 0, 0, 0] || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0) // IETF protocol 192.0.0.0/24
            || v4.octets() == [192, 0, 2, 0] || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 2) // TEST-NET-1 192.0.2.0/24
            || (v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100) // TEST-NET-2 198.51.100.0/24
            || (v4.octets()[0] == 203 && v4.octets()[1] == 0 && v4.octets()[2] == 113)  // TEST-NET-3 203.0.113.0/24
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let embedded = |hi: u16, lo: u16| {
                std::net::Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
            };
            // OKS-414 #3 — IPv6 transition forms carry an IPv4 address that
            // must be judged as such: mapped ::ffff:a.b.c.d, deprecated
            // compat ::a.b.c.d, NAT64 64:ff9b::/96, SIIT ::ffff:0:a.b.c.d,
            // 6to4 2002:AABB:CCDD::/48.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(&IpAddr::V4(v4));
            }
            if s[..6] == [0, 0, 0, 0, 0, 0] && !(s[6] == 0 && s[7] <= 1) {
                return is_private_ip(&IpAddr::V4(embedded(s[6], s[7])));
            }
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                return is_private_ip(&IpAddr::V4(embedded(s[6], s[7])));
            }
            if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
                return is_private_ip(&IpAddr::V4(embedded(s[6], s[7])));
            }
            if s[0] == 0x2002 {
                return is_private_ip(&IpAddr::V4(embedded(s[1], s[2])));
            }
            v6.is_loopback()           // ::1
            || v6.is_unspecified()     // ::
            || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 — unique local
            || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 — link-local
            || (s[0] & 0xff00) == 0xff00 // ff00::/8 — multicast
            || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 — documentation
        }
    }
}

/// OKS-414 #2/#5 — the guard every network check runs before touching the
/// wire, unless the agent is in private mode: refuse names that only exist
/// inside a network, then refuse anything that *resolves* to a private
/// address (a public name pointed at 10.x, or a resolver that answers
/// differently from inside our network). Mirrors the http.rs hop guard.
pub async fn check_public_target(host: &str, port: u16) -> Result<(), String> {
    if is_blocked_hostname(host) {
        return Err(format!("Target is a private address: {host}"));
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match tokio::net::lookup_host((bare, port)).await {
        Ok(addrs) => {
            if addrs.into_iter().any(|a| is_blocked_ip(&a.ip())) {
                return Err(format!("Target resolves to a private address: {host}"));
            }
            Ok(())
        }
        // Private mode used to skip the lookup altogether: a name only the
        // check itself can resolve (its own resolver, a proxy) must keep working.
        Err(_) if allow_private_targets() => Ok(()),
        Err(e) => Err(format!("DNS lookup error for {host}: {e}")),
    }
}

/// Revue sécurité 2026-09-14 (F7) — DNS resolver handed to reqwest so the
/// private-address guard runs on the very addresses the connection will use.
/// The pre-checks in http.rs resolve once for the guard and reqwest resolved
/// again for the request: a zone with TTL 0 could answer a public IP to the
/// first lookup and 10.x to the second (DNS rebinding). With the guard inside
/// the resolver there is no second lookup to race. Private mode (OKS-401)
/// lifts the guard except for the cloud metadata endpoints, like everywhere else.
pub struct GuardedResolver;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            if is_blocked_hostname(&host) {
                return Err(format!("Target is a private address: {host}").into());
            }
            // The port is irrelevant for resolution; reqwest rewrites it from the URL.
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if addrs.iter().any(|a| is_blocked_ip(&a.ip())) {
                return Err(format!("Target resolves to a private address: {host}").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_private_ipv4() {
        let cases = vec![
            ("0.0.0.1", true),
            ("224.0.0.1", true),
            ("240.0.0.1", true),
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
            ("2001:db8::1", true), // documentation range, refused since OKS-414 #3
        ];
        for (ip_str, expected) in cases {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert_eq!(is_private_ip(&ip), expected, "failed for {ip_str}");
        }
    }

    #[test]
    fn test_ipv6_transition_forms_judge_the_embedded_ipv4() {
        // OKS-414 #3
        for (lit, private) in [
            ("::ffff:169.254.169.254", true),
            ("::ffff:127.0.0.1", true),
            ("::ffff:1.1.1.1", false),
            ("::10.0.0.1", true),
            ("::ffff:0.0.0.1", true),
            ("::ffff:224.0.0.1", true),
            ("64:ff9b::192.168.1.1", true),
            ("64:ff9b::8.8.8.8", false),
            ("2002:a9fe:a9fe::", true),
            ("2001:db8::1", true),
            ("ff02::1", true),
            ("2606:4700:4700::1111", false),
        ] {
            let ip: IpAddr = lit.parse().unwrap();
            assert_eq!(is_private_ip(&ip), private, "{lit}");
        }
    }

    #[tokio::test]
    async fn guarded_resolver_refuses_private_targets() {
        use reqwest::dns::Resolve;
        let r = GuardedResolver;
        // Refused before any lookup (cluster-only name) and after it (loopback).
        for host in ["redis.svc", "localhost", "127.0.0.1"] {
            let name: reqwest::dns::Name = host.parse().unwrap();
            assert!(r.resolve(name).await.is_err(), "{host}");
        }
    }

    #[test]
    fn cloud_metadata_endpoints_are_recognised() {
        for ip in ["169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254"] {
            assert!(is_cloud_metadata_ip(&ip.parse().unwrap()), "{ip}");
        }
        for ip in ["169.254.1.1", "10.0.0.1", "192.168.1.1", "8.8.8.8"] {
            assert!(!is_cloud_metadata_ip(&ip.parse().unwrap()), "{ip}");
        }
        for h in ["metadata.google.internal", "METADATA.google.internal.", "instance-data", "169.254.169.254", "[fd00:ec2::254]"] {
            assert!(is_cloud_metadata_hostname(h), "{h}");
        }
        assert!(!is_cloud_metadata_hostname("db.internal"));
    }

    // The process-wide flags are left alone: tests run in parallel and other
    // modules assume fleet mode.
    #[test]
    fn private_mode_still_blocks_cloud_metadata() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        // Fleet agent: every private address.
        assert!(blocked_ip(&ip("10.0.0.5"), false, false));
        assert!(blocked_hostname("postgres", false, false));
        // Private agent: the LAN is the point, metadata stays out.
        assert!(!blocked_ip(&ip("10.0.0.5"), true, false));
        assert!(!blocked_ip(&ip("127.0.0.1"), true, false));
        assert!(!blocked_hostname("postgres", true, false));
        assert!(blocked_ip(&ip("169.254.169.254"), true, false));
        assert!(blocked_ip(&ip("::ffff:169.254.169.254"), true, false));
        assert!(blocked_hostname("metadata.google.internal", true, false));
        assert!(blocked_hostname("169.254.170.2", true, false));
        // OKSTATUS_ALLOW_CLOUD_METADATA=true
        assert!(!blocked_ip(&ip("169.254.169.254"), true, true));
        assert!(!blocked_hostname("metadata.google.internal", true, true));
    }

    #[test]
    fn test_bracketed_ipv6_hostname_is_private() {
        assert!(is_private_hostname("[::1]"));
        assert!(is_private_hostname("[fd00::1]"));
        assert!(is_private_hostname("[::ffff:169.254.169.254]"));
        assert!(!is_private_hostname("[2606:4700:4700::1111]"));
    }
}
