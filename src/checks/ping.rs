use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::models::{CheckResult, CheckTask};

pub async fn check_ping(task: &CheckTask) -> CheckResult {
    let timeout = Duration::from_millis(task.timeout.unwrap_or(5_000));
    let start = Instant::now();

    // Extract hostname from target URL or use directly
    let host = task
        .target
        .strip_prefix("http://")
        .or_else(|| task.target.strip_prefix("https://"))
        .unwrap_or(&task.target)
        .split('/')
        .next()
        .unwrap_or(&task.target)
        .split(':')
        .next()
        .unwrap_or(&task.target);

    // Resolve hostname to IP
    let ip: IpAddr = match tokio::net::lookup_host(format!("{host}:0")).await {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip(),
            None => {
                return error_result(task, &start, format!("DNS resolution failed for {host}"));
            }
        },
        Err(e) => {
            return error_result(task, &start, format!("DNS lookup error: {e}"));
        }
    };

    // TCP connect to port 80 as reachability probe.
    // NOTE: This is NOT a real ICMP ping — ICMP requires raw sockets (CAP_NET_RAW).
    // This checks TCP reachability on port 80 as a connectivity proxy.
    let addr = std::net::SocketAddr::new(ip, 80);
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            let latency = start.elapsed().as_millis() as u64;
            CheckResult {
                task_id: task.task_id.clone(),
                monitor_id: task.monitor_id.clone(),
                region: task.region.clone(),
                agent_type: String::new(),
                success: true,
                latency_ms: Some(latency),
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
        Ok(Err(e)) => error_result(task, &start, format!("ping failed: {e}")),
        Err(_) => error_result(task, &start, "ping timeout".to_string()),
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
