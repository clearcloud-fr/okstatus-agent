use std::net::IpAddr;
use std::time::{Duration, Instant};

use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};

use crate::models::{CheckResult, CheckTask};

/// Ports tried, in order, when ICMP is unavailable or unanswered.
///
/// This is a *fallback*, not the check: it exists so a host behind a firewall
/// that drops ICMP echo — very common — is not reported down when it plainly
/// serves traffic. Kept deliberately short; every extra port widens what
/// counts as "reachable".
const TCP_FALLBACK_PORTS: [u16; 2] = [443, 80];

/// Outcome of the ICMP attempt, so the caller can tell "the host is silent"
/// (a real result) from "this agent may not send ICMP at all" (an environment
/// problem that must not be reported as the host being down).
enum IcmpOutcome {
    Reply(u64),
    NoReply(String),
    Unavailable(String),
}

pub async fn check_ping(task: &CheckTask) -> CheckResult {
    let timeout = Duration::from_millis(task.timeout.unwrap_or(5_000));
    let start = Instant::now();

    let host = extract_host(&task.target);

    // Resolve hostname to IP
    let ip: IpAddr = match tokio::net::lookup_host(format!("{host}:0")).await {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip(),
            None => {
                return error_result(task, &start, format!("DNS resolution failed for {host}"));
            }
        },
        Err(e) => {
            return error_result(task, &start, format!("DNS lookup error for {host}: {e}"));
        }
    };

    // OKS-682 — a real ICMP echo, which is what a "ping" monitor is supposed
    // to be. This used to be a TCP connect to port 80 and nothing else, so any
    // host that answered ICMP but served nothing on :80 was reported down.
    //
    // The socket is an unprivileged ICMP datagram socket (surge-ping's default
    // hint, falling back to a raw socket): it needs no CAP_NET_RAW, only
    // `net.ipv4.ping_group_range` to cover the agent's gid. Where neither
    // socket can be opened we fall back to the old TCP probe rather than fail,
    // so an agent on a host without that sysctl keeps working as before.
    // `timeout` is the budget for the WHOLE check, not for each probe inside
    // it. Giving it to the ICMP attempt and then again to each fallback port
    // made an unreachable host take three times the configured timeout, which
    // on an agent means holding a worker slot three times as long as the
    // scheduler budgeted for.
    //
    // Half to ICMP: a silent host must leave enough for the TCP fallback to
    // mean anything. A host that answers spends only its round-trip.
    let icmp_budget = timeout / 2;
    let deadline = start + timeout;
    match icmp_probe(ip, icmp_budget).await {
        IcmpOutcome::Reply(rtt_ms) => success_result(task, rtt_ms),
        IcmpOutcome::NoReply(reason) | IcmpOutcome::Unavailable(reason) => {
            let left = deadline.saturating_duration_since(Instant::now());
            match tcp_probe(ip, left).await {
                Some(latency_ms) => success_result(task, latency_ms),
                None => error_result(
                    task,
                    &start,
                    format!(
                        "{host} ({ip}) unreachable: {reason}, and no TCP connect on port {}",
                        TCP_FALLBACK_PORTS
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(" or ")
                    ),
                ),
            }
        }
    }
}

/// Accepts `host`, `host:port`, `http(s)://host/path` — ping monitors store a
/// bare host or IP, but a URL pasted into the field must not break the check.
fn extract_host(target: &str) -> &str {
    target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target)
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target)
}

async fn icmp_probe(ip: IpAddr, timeout: Duration) -> IcmpOutcome {
    let kind = if ip.is_ipv6() { ICMP::V6 } else { ICMP::V4 };
    let client = match Client::new(&Config::builder().kind(kind).build()) {
        Ok(c) => c,
        Err(e) => {
            return IcmpOutcome::Unavailable(format!("ICMP socket unavailable ({e})"));
        }
    };

    // Identifier only has to be unique among this agent's in-flight pings.
    let ident = PingIdentifier(rand_ident());
    let mut pinger = client.pinger(ip, ident).await;
    pinger.timeout(timeout);

    match pinger.ping(PingSequence(0), &[0u8; 32]).await {
        Ok((_packet, rtt)) => IcmpOutcome::Reply(rtt.as_millis() as u64),
        Err(e) => IcmpOutcome::NoReply(format!("no ICMP echo reply ({e})")),
    }
}

/// Cheap non-cryptographic identifier — uniqueness within the process is all
/// the ICMP echo id needs, and this avoids pulling `rand` in for one number.
fn rand_ident() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Returns the connect latency of the first port that accepts, if any.
///
/// `budget` covers ALL the ports together: they are tried in sequence, so
/// giving each the full timeout multiplies the wait by the number of ports.
async fn tcp_probe(ip: IpAddr, budget: Duration) -> Option<u64> {
    // Never let the budget round down to nothing — an instant "timeout" says
    // nothing about the target.
    const MIN_PROBE: Duration = Duration::from_millis(250);
    let deadline = Instant::now() + budget;
    let total = TCP_FALLBACK_PORTS.len();
    for (index, port) in TCP_FALLBACK_PORTS.iter().enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        // Share what is left evenly over the ports still to try.
        let per_port = std::cmp::max(left / (total - index) as u32, MIN_PROBE);
        let addr = std::net::SocketAddr::new(ip, *port);
        let start = Instant::now();
        if let Ok(Ok(_)) =
            tokio::time::timeout(per_port, tokio::net::TcpStream::connect(addr)).await
        {
            return Some(start.elapsed().as_millis() as u64);
        }
    }
    None
}

fn success_result(task: &CheckTask, latency_ms: u64) -> CheckResult {
    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        success: true,
        latency_ms: Some(latency_ms),
        status_code: None,
        ssl_days_left: None,
        error: None,
        state: None,
        ttft_ms: None,
        tpot_ms: None,
        itl_ms: None,
        checked_at: chrono::Utc::now().to_rfc3339(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_handles_bare_ip_host_port_and_url() {
        assert_eq!(extract_host("51.68.206.174"), "51.68.206.174");
        assert_eq!(extract_host("example.com:8443"), "example.com");
        assert_eq!(extract_host("https://example.com/health"), "example.com");
        assert_eq!(extract_host("http://example.com"), "example.com");
    }

    #[test]
    fn idents_do_not_repeat_back_to_back() {
        assert_ne!(rand_ident(), rand_ident());
    }
}

// Network-dependent, so not part of the default suite. Run with:
//   cargo test --package uptime-agent -- --ignored icmp
#[cfg(test)]
mod net_tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn icmp_reaches_a_host_that_serves_nothing_on_port_80() {
        let ip: IpAddr = "51.68.206.174".parse().unwrap();
        match icmp_probe(ip, Duration::from_secs(5)).await {
            IcmpOutcome::Reply(rtt) => println!("ICMP reply in {rtt} ms"),
            IcmpOutcome::NoReply(r) => panic!("expected an echo reply, got: {r}"),
            IcmpOutcome::Unavailable(r) => println!("ICMP unavailable here: {r} (fallback path)"),
        }
    }
}
