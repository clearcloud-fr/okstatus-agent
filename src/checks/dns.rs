use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Instant;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RecordType};
use hickory_resolver::Resolver;

use crate::models::{CheckResult, CheckTask};
use crate::ssrf;

pub async fn check_dns(task: &CheckTask) -> CheckResult {
    let start = Instant::now();

    let record_type_str = task.dns_record_type.as_deref().unwrap_or("A");
    let record_type = match record_type_str {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "CNAME" => RecordType::CNAME,
        "MX" => RecordType::MX,
        "NS" => RecordType::NS,
        "TXT" => RecordType::TXT,
        "SOA" => RecordType::SOA,
        "CAA" => RecordType::CAA,
        "SRV" => RecordType::SRV,
        other => {
            return error_result(task, &start, format!("Unsupported DNS record type: {other}"));
        }
    };

    // Build resolver — custom DNS server or system default
    let resolver = if let Some(ref server) = task.dns_server {
        let addr = if server.contains(':') {
            match SocketAddr::from_str(server) {
                Ok(a) => a,
                Err(e) => return error_result(task, &start, format!("Invalid DNS server address: {e}")),
            }
        } else {
            match format!("{server}:53").parse() {
                Ok(a) => a,
                Err(e) => return error_result(task, &start, format!("Invalid DNS server: {e}")),
            }
        };

        // Anti-SSRF: reject private/reserved IPs for DNS server (UPT-48).
        // OKS-401 — lifted in private mode: a customer's agent querying its
        // own internal DNS server is the expected use.
        if ssrf::is_blocked_ip(&addr.ip()) {
            return error_result(task, &start, "DNS server address is a private or reserved IP".to_string());
        }

        // hickory 0.26 (revue sécurité 2026-09-14, RUSTSEC-2026-0119) : le
        // port vit dans la connexion, plus dans l'adresse du serveur.
        let mut udp = ConnectionConfig::udp();
        udp.port = addr.port();
        let config = ResolverConfig::from_name_servers(vec![NameServerConfig::new(addr.ip(), true, vec![udp])]);

        Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(ResolverOpts::default())
            .build()
    } else {
        // 2026-10-05 — was ResolverConfig::default(): Google's servers under
        // hickory 0.24, but an EMPTY server list since the 0.26 upgrade
        // (2026-09-15, RUSTSEC-2026-0119), so every DNS check without a
        // custom server failed with "no connections available". Now the
        // host's resolvers: CoreDNS for the public agents, the customer's
        // own DNS for a private agent (internal names resolve).
        let (config, options) = default_resolver_config();
        Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
    };
    let resolver = match resolver {
        Ok(r) => r,
        Err(e) => return error_result(task, &start, format!("Resolver setup failed: {e}")),
    };

    // The target for DNS is the hostname (stored in `url` field for DNS
    // monitors). 2026-10-05 — users paste URLs ("https://example.com/"):
    // the creation test (src/shared/test-check.ts, extractHost) strips them
    // and passed, while every scheduled check sent the raw string to hickory
    // and failed with "Label contains invalid characters". Same extraction
    // here, then a relaxed parse so `_` inside a label (Node accepts it)
    // doesn't trip hickory's strict IDNA/STD3 path either.
    let hostname = dns_query_host(&task.target);
    let name = match Name::from_str_relaxed(hostname) {
        // Absolute name: the pod's resolv.conf search list (ndots:5) must not
        // turn "example.com" into example.com.<ns>.svc.cluster.local first.
        Ok(mut n) => {
            n.set_fqdn(true);
            n
        }
        Err(e) => return error_result(task, &start, format!("Invalid DNS name '{hostname}': {e}")),
    };

    match resolver.lookup(name, record_type).await {
        Ok(lookup) => {
            let latency = start.elapsed().as_millis() as u64;

            // Collect resolved values as strings
            let values: Vec<String> = lookup.answers().iter()
                .map(|r| r.data.to_string())
                .collect();
            let values_str = values.join(", ");

            // Check expected value if provided
            let success = if let Some(ref expected) = task.dns_expected_value {
                values.iter().any(|v: &String| v.contains(expected.as_str()))
            } else {
                !values.is_empty()
            };

            let error = if !success {
                Some(format!(
                    "DNS {} lookup for '{}' returned '{}', expected '{}'",
                    record_type_str,
                    hostname,
                    values_str,
                    task.dns_expected_value.as_deref().unwrap_or("any result"),
                ))
            } else {
                None
            };

            CheckResult {
                task_id: task.task_id.clone(),
                monitor_id: task.monitor_id.clone(),
                region: task.region.clone(),
                agent_type: String::new(),
                success,
                latency_ms: Some(latency),
                status_code: None,
                ssl_days_left: None,
                error,
                state: None,
                ttft_ms: None,
                tpot_ms: None,
                itl_ms: None,
                checked_at: chrono::Utc::now().to_rfc3339(),
            }
        }
        Err(e) => error_result(task, &start, format!("DNS lookup failed: {e}")),
    }
}

/// Resolvers used when the monitor names none: the system's (resolv.conf),
/// or Quad9 if that can't be read — never an empty list, which hickory 0.26
/// accepts silently and turns into "no connections available" on every query.
pub(crate) fn default_resolver_config() -> (ResolverConfig, ResolverOpts) {
    match hickory_resolver::system_conf::read_system_conf() {
        Ok((config, options)) if !config.name_servers.is_empty() => {
            // Keep the servers and timeouts, drop the search domains.
            (ResolverConfig::from_name_servers(config.name_servers.to_vec()), options)
        }
        _ => (
            ResolverConfig::udp_and_tcp(&hickory_resolver::config::QUAD9),
            ResolverOpts::default(),
        ),
    }
}

/// Bare host of a DNS monitor's target — mirrors `extractHost` in
/// src/shared/test-check.ts: trims, drops any `scheme://`, the path and the
/// port; keeps a bracketed IPv6 literal whole.
fn dns_query_host(target: &str) -> &str {
    let t = target.trim();
    let t = match t.find("://") {
        Some(i) if t[..i].chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)) => &t[i + 3..],
        _ => t,
    };
    let t = t.split(['/', '?', '#']).next().unwrap_or(t);
    if let Some(rest) = t.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    t.split(':').next().unwrap_or(t)
}

fn error_result(task: &CheckTask, start: &Instant, error: String) -> CheckResult {
    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        success: false,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        status_code: None,
        ssl_days_left: None,
        error: Some(error),
        state: None,
        ttft_ms: None,
        tpot_ms: None,
        itl_ms: None,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_what_users_paste_like_the_creation_test_does() {
        assert_eq!(dns_query_host("example.com"), "example.com");
        assert_eq!(dns_query_host("  example.com  "), "example.com");
        assert_eq!(dns_query_host("https://example.com/"), "example.com");
        assert_eq!(dns_query_host("http://www.example.com:8080/a?b#c"), "www.example.com");
        assert_eq!(dns_query_host("example.com/path"), "example.com");
        assert_eq!(dns_query_host("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn the_default_resolver_always_has_servers() {
        // ResolverConfig::default() has none under hickory 0.26: every check
        // without a custom server failed with "no connections available".
        assert!(ResolverConfig::default().name_servers.is_empty());
        let (config, _) = default_resolver_config();
        assert!(!config.name_servers.is_empty());
        assert!(config.search.is_empty());
    }

    #[test]
    fn every_pasted_form_becomes_a_valid_query_name() {
        // Raw "https://example.com/" is what failed in prod with
        // "Label contains invalid characters"; "my_host" is accepted by Node.
        for t in ["https://example.com/", "example.com", "my_host.example.com", "_dmarc.example.com", "bücher.example"] {
            assert!(Name::from_str_relaxed(dns_query_host(t)).is_ok(), "{t}");
        }
        assert!(Name::from_utf8("https://example.com/").is_err());
    }

    /// Real lookup through the default (system) resolver, the path every
    /// DNS monitor without a custom server takes. Network: run with
    /// `cargo test -- --ignored dns_resolves`.
    #[tokio::test]
    #[ignore]
    async fn dns_resolves_a_pasted_url_through_the_system_resolver() {
        let task: CheckTask = serde_json::from_str(
            r#"{"taskId":"t","monitorId":"m","orgId":"o","tenantId":"okstatus","target":"https://clearcloud.fr","checkType":"dns","region":"fr-dc3","dnsRecordType":"A"}"#,
        )
        .unwrap();
        let r = check_dns(&task).await;
        assert!(r.success, "{:?}", r.error);
    }
}
