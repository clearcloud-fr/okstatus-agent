use std::time::{Duration, Instant};

use crate::models::{CheckResult, CheckTask};

pub async fn check_tcp(task: &CheckTask) -> CheckResult {
    let timeout = Duration::from_millis(task.timeout.unwrap_or(5_000));
    let port = task.port.unwrap_or(443);
    let start = Instant::now();

    // Extract hostname
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

    let addr = format!("{host}:{port}");

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
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
        Ok(Err(e)) => {
            let latency = start.elapsed().as_millis() as u64;
            CheckResult {
                task_id: task.task_id.clone(),
                monitor_id: task.monitor_id.clone(),
                region: task.region.clone(),
                agent_type: String::new(),
                success: false,
                latency_ms: Some(latency),
                status_code: None,
                ssl_days_left: None,
                error: Some(format!("TCP connect failed: {e}")),
                state: None,
                ttft_ms: None,
                tpot_ms: None,
                itl_ms: None,
                checked_at: chrono::Utc::now().to_rfc3339(),
            }
        }
        Err(_) => CheckResult {
            task_id: task.task_id.clone(),
            monitor_id: task.monitor_id.clone(),
            region: task.region.clone(),
            agent_type: String::new(),
            success: false,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            status_code: None,
            ssl_days_left: None,
            error: Some(format!("TCP connect timeout after {timeout:?}")),
            state: None,
            ttft_ms: None,
            tpot_ms: None,
            itl_ms: None,
            checked_at: chrono::Utc::now().to_rfc3339(),
        },
    }
}
