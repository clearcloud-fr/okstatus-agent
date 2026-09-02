use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Instant;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

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
        if !ssrf::allow_private_targets() && ssrf::is_private_ip(&addr.ip()) {
            return error_result(task, &start, "DNS server address is a private or reserved IP".to_string());
        }

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));

        TokioAsyncResolver::tokio(config, ResolverOpts::default())
    } else {
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    };

    // The target for DNS is the hostname (stored in `url` field for DNS monitors)
    let hostname = &task.target;

    match resolver.lookup(hostname, record_type).await {
        Ok(lookup) => {
            let latency = start.elapsed().as_millis() as u64;

            // Collect resolved values as strings
            let values: Vec<String> = lookup.record_iter()
                .filter_map(|r| r.data())
                .map(|rdata| rdata.to_string())
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
