// OKS-416 — batched result delivery. Check tasks used to POST their result
// to the aggregator themselves (one HTTP round-trip per result, 3 retries
// with backoff) while still holding their semaphore permit — worst case
// ~90s of a concurrency slot spent on network retries, not checks. Now every
// check pushes its result into an mpsc channel and releases its permit
// immediately; this sender task flushes the channel in batches.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::config::Config;
use crate::metrics;
use crate::models::CheckResult;

/// How long the flusher may sit on a non-empty buffer before posting it,
/// measured from the first result buffered — not from the last one, so a
/// steady trickle of results can't postpone the flush indefinitely.
pub fn spawn_result_sender(
    client: reqwest::Client,
    config: &Config,
) -> (mpsc::Sender<CheckResult>, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<CheckResult>(config.results_batch_max.max(1) * 4);

    let aggregator_url = config.aggregator_url.clone();
    let agent_secret = config.agent_secret.clone();
    let agent_id = config.agent_id.clone();
    let instance_id = config.instance_id.clone();
    let flush_interval = Duration::from_millis(config.results_flush_interval_ms.max(100));
    let batch_max = config.results_batch_max.max(1);

    let handle = tokio::spawn(async move {
        let mut buf: Vec<CheckResult> = Vec::with_capacity(batch_max);
        let mut deadline: Option<tokio::time::Instant> = None;

        loop {
            // The `deadline.is_some()` guard keeps the sleep branch disabled
            // while the buffer is empty; the placeholder instant is never
            // actually slept on.
            let sleep_until = deadline
                .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));

            tokio::select! {
                received = rx.recv() => match received {
                    Some(result) => {
                        if buf.is_empty() {
                            deadline = Some(tokio::time::Instant::now() + flush_interval);
                        }
                        buf.push(result);
                        if buf.len() >= batch_max {
                            flush(&client, &aggregator_url, &agent_secret, agent_id.as_deref(), &instance_id, &mut buf).await;
                            deadline = None;
                        }
                    }
                    // Channel closed (graceful shutdown, after all in-flight
                    // checks were joined): recv() only returns None once the
                    // queue is empty, so a final flush of the buffer is all
                    // that's left.
                    None => {
                        if !buf.is_empty() {
                            flush(&client, &aggregator_url, &agent_secret, agent_id.as_deref(), &instance_id, &mut buf).await;
                        }
                        break;
                    }
                },
                _ = tokio::time::sleep_until(sleep_until), if deadline.is_some() => {
                    flush(&client, &aggregator_url, &agent_secret, agent_id.as_deref(), &instance_id, &mut buf).await;
                    deadline = None;
                }
            }
        }
    });

    (tx, handle)
}

async fn flush(
    client: &reqwest::Client,
    aggregator_url: &str,
    agent_secret: &str,
    agent_id: Option<&str>,
    instance_id: &str,
    buf: &mut Vec<CheckResult>,
) {
    let count = buf.len();
    match post_batch(client, aggregator_url, agent_secret, agent_id, instance_id, buf).await {
        Ok(()) => {
            debug!(count, "Result batch posted");
        }
        Err(BatchError::EndpointMissing) => {
            // Aggregator not redeployed with /internal/results/batch yet —
            // fall back to the legacy one-POST-per-result endpoint so an old
            // backend and a new agent stay compatible in either deploy order.
            warn!(count, "Batch endpoint unavailable — falling back to per-result posts");
            for result in buf.iter() {
                if let Err(e) = post_result(client, aggregator_url, agent_secret, agent_id, instance_id, result).await {
                    metrics::ERRORS_TOTAL.with_label_values(&["post_result"]).inc();
                    error!(task_id = %result.task_id, error = %e, "Failed to post result");
                }
            }
        }
        Err(BatchError::Failed(e)) => {
            metrics::ERRORS_TOTAL.with_label_values(&["post_batch"]).inc();
            error!(count, error = %e, "Failed to post result batch — dropping batch");
        }
    }
    buf.clear();
}

enum BatchError {
    /// 404/405 from the aggregator — endpoint not deployed there yet.
    EndpointMissing,
    Failed(String),
}

async fn post_batch(
    client: &reqwest::Client,
    aggregator_url: &str,
    agent_secret: &str,
    agent_id: Option<&str>,
    instance_id: &str,
    results: &[CheckResult],
) -> Result<(), BatchError> {
    let url = format!("{aggregator_url}/internal/results/batch");
    let body = serde_json::json!({ "results": results });

    let mut last_err = String::from("unknown error");
    for attempt in 0..3u32 {
        let mut req = client
            .post(&url)
            .header("X-Agent-Secret", agent_secret)
            .header("Content-Type", "application/json");
        if let Some(id) = agent_id {
            req = req.header("X-Agent-Id", id).header("X-Agent-Instance", instance_id);
        }
        match req.json(&body).send().await
        {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp)
                if resp.status() == reqwest::StatusCode::NOT_FOUND
                    || resp.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED =>
            {
                return Err(BatchError::EndpointMissing);
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::CONFLICT => {
                error!("another instance of this agent is already running — exiting");
                std::process::exit(1);
            }
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                last_err = format!(
                    "aggregator returned HTTP {} — body: {}",
                    status,
                    &text[..text.len().min(500)]
                );
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }

        if attempt < 2 {
            let delay = Duration::from_millis(100 * 2u64.pow(attempt));
            tokio::time::sleep(delay).await;
        }
    }

    Err(BatchError::Failed(last_err))
}

async fn post_result(
    client: &reqwest::Client,
    aggregator_url: &str,
    agent_secret: &str,
    agent_id: Option<&str>,
    instance_id: &str,
    result: &CheckResult,
) -> Result<(), String> {
    let url = format!("{aggregator_url}/internal/results");

    // Retry with exponential backoff (3 attempts)
    let mut last_err = String::from("unknown error");
    for attempt in 0..3u32 {
        let mut req = client
            .post(&url)
            .header("X-Agent-Secret", agent_secret)
            .header("Content-Type", "application/json");
        if let Some(id) = agent_id {
            req = req.header("X-Agent-Id", id).header("X-Agent-Instance", instance_id);
        }
        match req.json(result).send().await
        {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) if resp.status() == reqwest::StatusCode::CONFLICT => {
                error!("another instance of this agent is already running — exiting");
                std::process::exit(1);
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                last_err = format!(
                    "aggregator returned HTTP {} — body: {}",
                    status,
                    &body[..body.len().min(500)]
                );
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }

        if attempt < 2 {
            let delay = Duration::from_millis(100 * 2u64.pow(attempt));
            tokio::time::sleep(delay).await;
        }
    }

    Err(last_err)
}
