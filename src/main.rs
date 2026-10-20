mod host_info;
mod auth;
mod checks;
mod circuit_breaker;
mod config;
mod enroll;
mod metrics;
mod models;
mod results;
mod seal;
mod ssrf;

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use config::Config;
use models::{CheckResult, CheckTask, CheckType, TasksResponse};
use serde::Serialize;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use circuit_breaker::CircuitBreaker;

const BANNER: &str = r#"
 ██████╗ ██╗  ██╗███████╗████████╗ █████╗ ████████╗██╗   ██╗███████╗
██╔═══██╗██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║   ██║██╔════╝
██║   ██║█████╔╝ ███████╗   ██║   ███████║   ██║   ██║   ██║███████╗
██║   ██║██╔═██╗ ╚════██║   ██║   ██╔══██║   ██║   ██║   ██║╚════██║
╚██████╔╝██║  ██╗███████║   ██║   ██║  ██║   ██║   ╚██████╔╝███████║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
"#;

/// Shared state for health + metrics endpoints
struct AgentState {
    config: Config,
    checks_completed: AtomicU64,
    // OKS-405 follow-up — real concurrency in use right now (permits held),
    // as opposed to checks_completed which is a lifetime total. Sent on
    // every heartbeat so the backend/Grafana can see actual load per agent
    // instead of the region-wide monitor count the admin dashboard uses.
    active_checks: AtomicUsize,
    last_result_at: Mutex<Option<String>>,
    circuit_breaker: CircuitBreaker,
    aggregator_connected: AtomicBool,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    region: String,
    agent_type: String,
    aggregator_connected: bool,
    checks_completed: u64,
    active_checks: usize,
    max_concurrent_checks: usize,
    last_result_at: Option<String>,
}

/// rustls 0.23 picks its crypto provider from crate features, and this agent
/// enables two of them (`ring` through tonic, `aws-lc-rs` through the AWS SDK
/// used by Bedrock checks). Faced with both it refuses to choose and PANICS
/// at the first handshake that relies on the process default — every gRPC
/// check over TLS (grpcs://, or :443) died inside its task, no result was
/// ever posted, and the monitor went silently `stale` (2026-09-14).
/// Installing one explicitly settles it; a second call is a harmless no-op.
fn install_tls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::main]
async fn main() {
    install_tls_crypto_provider();
    let mut config = Config::from_env();
    // OKS-401 — private-agent bootstrap: exchanges OKSTATUS_TOKEN for
    // per-agent credentials (or loads persisted ones) and flips the config
    // into private mode. Fleet agents fall straight through.
    let private_mode = enroll::bootstrap(&mut config).await;
    let config = config;
    // OKS-880 — identified agents (fleet or private) derive their seal key
    // from their secret; its public half goes out with every heartbeat.
    if config.agent_id.is_some() {
        seal::init(&config.agent_secret);
    }
    // OKS-355 — APP_VERSION is stamped by the Docker build (= image tag);
    // an unset OR empty value falls back to the Cargo package version, which
    // the same build also rewrites, so both paths agree.
    let version = std::env::var("APP_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    // Print banner before tracing init for clean stdout output
    println!("{}", BANNER);
    println!(
        "  agent {} Rust · Axum — Multi-region OKStatus check agent\n",
        version
    );
    println!("  Region:              {}", config.region);
    println!("  Agent type:          {}", config.agent_type);
    if private_mode {
        println!("  Private mode:        enrolled as {}", config.agent_id.as_deref().unwrap_or("?"));
    } else if let Some(id) = &config.agent_id {
        println!("  Fleet identity:      {}", id);
    }
    println!("  Aggregator URL:      {}", config.aggregator_url);
    println!("  Poll interval:       {}ms", config.poll_interval_ms);
    println!("  Max concurrent:      {}", config.max_concurrent_checks);
    println!(
        "  Health port:         {}\n",
        std::env::var("HEALTH_PORT").unwrap_or_else(|_| "9091".to_string())
    );

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    info!(
        region = %config.region,
        agent_type = %config.agent_type,
        aggregator = %config.aggregator_url,
        poll_interval_ms = config.poll_interval_ms,
        max_concurrent = config.max_concurrent_checks,
        version = %version,
        "Starting uptime-agent"
    );

    let state = Arc::new(AgentState {
        config: config.clone(),
        checks_completed: AtomicU64::new(0),
        active_checks: AtomicUsize::new(0),
        last_result_at: Mutex::new(None),
        // Circuit breaker: open after 5 consecutive failures,
        // backoff starts at 10s, caps at 5min
        circuit_breaker: CircuitBreaker::new(
            5,
            Duration::from_secs(10),
            Duration::from_secs(300),
        ),
        aggregator_connected: AtomicBool::new(false),
    });

    // Start health + metrics HTTP server on :9091
    let health_port: u16 = std::env::var("HEALTH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9091);

    let health_state = state.clone();
    tokio::spawn(async move {
        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .with_state(health_state);

        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{health_port}"))
            .await
            .expect("failed to bind health port");

        info!(port = health_port, "Health + metrics server started");
        axum::serve(listener, app).await.expect("health server failed");
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    // Shared check client — built once to avoid rebuilding the native-tls context
    // (CA bundle load) on every individual HTTP check call.
    let check_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .redirect(reqwest::redirect::Policy::none()) // Anti-SSRF (UPT-48)
        .dns_resolver(std::sync::Arc::new(ssrf::GuardedResolver)) // Anti-SSRF, DNS rebinding (F7)
        .build()
        .expect("failed to build check HTTP client");

    // Heartbeat sender — POST /internal/heartbeat every 60s
    let hb_client = client.clone();
    let hb_config = config.clone();
    let hb_state = state.clone();
    let hb_version = version.clone();
    // 2026-10-03 — private agents page v2: where the agent runs (platform,
    // start time; host and private IP are read on each beat).
    let hb_started_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let hb_platform = host_info::platform();
    tokio::spawn(async move {
        // Small initial delay so the first poll cycle can establish connectivity
        tokio::time::sleep(Duration::from_secs(5)).await;

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let checks_completed = hb_state.checks_completed.load(Ordering::Relaxed);
            let active_checks = hb_state.active_checks.load(Ordering::Relaxed);
            let url = format!("{}/internal/heartbeat", hb_config.aggregator_url);
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            let payload = serde_json::json!({
                "region": hb_config.region,
                "agentType": hb_config.agent_type,
                // Private mode: the enrolled id (the backend keys heartbeats
                // on it); fleet mode keeps the hostname, identified or not
                // (OKS-873: the admin agent list shows it).
                "agentId": if hb_config.agent_type == "private" {
                    hb_config.agent_id.as_deref().unwrap_or(&hostname)
                } else {
                    &hostname
                },
                "version": hb_version,
                "checksLast1h": checks_completed,
                "activeChecks": active_checks,
                "maxConcurrentChecks": hb_config.max_concurrent_checks,
                "hostname": hostname,
                "privateIp": host_info::private_ip(&hb_config.aggregator_url),
                "platform": hb_platform,
                "startedAt": hb_started_at_ms,
            });
            let mut payload = payload;
            if let Some(key) = seal::public_key() {
                payload["sealPublicKey"] = serde_json::Value::from(key);
            }

            let mut req = hb_client
                .post(&url)
                .header("X-Agent-Secret", &hb_config.agent_secret)
                .header("Content-Type", "application/json");
            if let Some(id) = &hb_config.agent_id {
                req = req.header("X-Agent-Id", id);
                req = req.header("X-Agent-Instance", &hb_config.instance_id);
            }
            match req.json(&payload).send().await
            {
                Ok(resp) if resp.status() == reqwest::StatusCode::CONFLICT => {
                    // Single-instance lease: another pod holds this agent's
                    // identity. A duplicate instance must not keep running.
                    error!("another instance of this agent is already running — exiting");
                    std::process::exit(1);
                }
                Ok(resp) if resp.status().is_success() => {
                    // Parse response to extract queueDepth
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Some(depth) = body.get("queueDepth").and_then(|v| v.as_f64()) {
                            metrics::QUEUE_DEPTH.set(depth);
                            tracing::debug!(
                                region = %hb_config.region,
                                queue_depth = depth,
                                "Heartbeat sent"
                            );
                        }
                    }
                }
                Ok(resp) => {
                    warn!(
                        region = %hb_config.region,
                        status = %resp.status(),
                        "Heartbeat rejected by aggregator"
                    );
                }
                Err(e) => {
                    warn!(
                        region = %hb_config.region,
                        error = %e,
                        "Heartbeat send failed"
                    );
                }
            }
        }
    });

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_checks));

    // OKS-416 — checks push their results into this channel and release
    // their semaphore permit immediately; a dedicated sender task flushes
    // them to the aggregator in batches (see results.rs).
    let (result_tx, sender_handle) = results::spawn_result_sender(client.clone(), &config);

    // Graceful shutdown — with a single agent replica per region (no
    // rolling-update overlap), a plain SIGTERM kill would abandon whatever
    // checks the last poll_and_execute() batch already claimed from the
    // aggregator's queue (removed on dispatch, per OKS-405's lock) with no
    // other agent able to pick them back up — a genuinely lost check, not
    // just a late one. Since OKS-415 checks run detached from the poll loop
    // (check_tasks JoinSet below), so the shutdown path drains that set,
    // then closes the result channel and waits for the sender's final
    // flush. Worst case in flight is bounded by CHECK_START_JITTER_MS +
    // CHECK_TIMEOUT_MS (default 1s + 5s, checks run concurrently not
    // sequentially) plus one batch post — well inside the 30s default
    // terminationGracePeriodSeconds.
    let shutdown = Arc::new(Notify::new());
    {
        let shutdown = shutdown.clone();
        let release_client = client.clone();
        let release_config = config.clone();
        tokio::spawn(async move {
            match signal(SignalKind::terminate()) {
                Ok(mut sigterm) => {
                    sigterm.recv().await;
                    info!("SIGTERM received — finishing in-flight checks, then exiting");
                    // Release the single-instance lease so a replacement pod
                    // takes over immediately instead of waiting for the TTL.
                    // Best-effort, private mode only.
                    if let Some(id) = &release_config.agent_id {
                        let url =
                            format!("{}/internal/heartbeat", release_config.aggregator_url);
                        let _ = release_client
                            .post(&url)
                            .header("X-Agent-Secret", &release_config.agent_secret)
                            .header("X-Agent-Id", id)
                            .header("X-Agent-Instance", &release_config.instance_id)
                            .header("X-Agent-Release", "1")
                            .header("Content-Type", "application/json")
                            .body("{}")
                            .timeout(Duration::from_secs(3))
                            .send()
                            .await;
                    }
                    // notify_one, not notify_waiters: SIGTERM almost always
                    // arrives while the loop is inside poll_and_execute(),
                    // not yet at the tokio::select! below — notify_waiters
                    // only wakes callers already waiting at the moment it's
                    // called and doesn't store anything, so that signal
                    // would be silently lost and one extra full poll cycle
                    // would run before shutdown took effect. notify_one
                    // stores a permit if nobody's listening yet, so the
                    // very next .notified() call (whenever the loop gets
                    // there) fires immediately. Confirmed empirically: with
                    // notify_waiters a live test dispatched a second batch
                    // of tasks after SIGTERM before finally exiting.
                    shutdown.notify_one();
                }
                Err(e) => {
                    error!(error = %e, "Failed to install SIGTERM handler — graceful shutdown disabled");
                }
            }
        });
    }

    // OKS-415 — in-flight check tasks, detached from the poll cadence. The
    // poll loop used to await the whole batch before polling again, so one
    // slow check delayed every other monitor in the region; now it only
    // reaps finished tasks and the semaphore alone bounds concurrency.
    let mut check_tasks: JoinSet<()> = JoinSet::new();

    // Main poll loop with exponential backoff on aggregator failures
    loop {
        // Reap finished check tasks (surfacing panics) without blocking
        while let Some(joined) = check_tasks.try_join_next() {
            if let Err(e) = joined {
                error!(error = %e, "Check task panicked");
            }
        }

        // Check circuit breaker before polling
        if let Some(backoff) = state.circuit_breaker.check_backoff().await {
            warn!(
                backoff_secs = backoff.as_secs(),
                "Circuit breaker open — skipping poll cycle"
            );
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = shutdown.notified() => {
                    info!("Shutdown during circuit-breaker backoff — draining in-flight checks, then exiting");
                    break;
                }
            }
            continue;
        }

        metrics::POLL_CYCLES_TOTAL.inc();

        let full_batch = match poll_and_execute(
            &client,
            &check_client,
            &config,
            &semaphore,
            &state,
            &result_tx,
            &mut check_tasks,
        )
        .await
        {
            Ok(count) => {
                state.circuit_breaker.record_success();
                metrics::AGGREGATOR_UP.set(1.0);

                // Log first successful connection
                if !state.aggregator_connected.swap(true, Ordering::Relaxed) {
                    info!(
                        region = %config.region,
                        aggregator = %config.aggregator_url,
                        "Aggregator connection established — agent ready"
                    );
                }

                if count > 0 {
                    metrics::TASKS_RECEIVED_TOTAL.inc_by(count as f64);
                    info!(
                        count,
                        region = %config.region,
                        "Tasks received — executing checks"
                    );
                }

                count >= FULL_BATCH_THRESHOLD
            }
            Err(e) => {
                state.circuit_breaker.record_failure().await;
                state.aggregator_connected.store(false, Ordering::Relaxed);
                metrics::AGGREGATOR_UP.set(0.0);
                metrics::ERRORS_TOTAL
                    .with_label_values(&["poll"])
                    .inc();
                warn!(
                    error = %e,
                    region = %config.region,
                    aggregator = %config.aggregator_url,
                    "Poll cycle failed"
                );

                false
            }
        };

        // OKS-759 — un lot plein veut dire « la file a plus de travail que ce
        // qu'un poll en rapporte » : on repart tout de suite au lieu de dormir
        // POLL_INTERVAL_MS. Sans ça, le débit d'une région était plafonné à
        // un lot par intervalle — 50 tâches / 10 s ≈ 300 checks/min — quoi
        // qu'encaisse le backend. Mesuré le 2026-09-11 : 400 checks/min
        // demandés sur fr-dc3, 306 servis, et un retard qui montait de 18 s
        // par minute sans jamais se résorber (backend à 8 % de CPU).
        //
        // Rien ne s'emballe : `poll_and_execute` acquiert un permis du
        // sémaphore AVANT de lancer chaque check, donc dès que
        // MAX_CONCURRENT_CHECKS est atteint la boucle attend là. Le palier de
        // 100 ms borne malgré tout le cas dégénéré (lots pleins servis
        // instantanément) à ~10 polls/s par région.
        let next_poll = next_poll_delay(full_batch, config.poll_interval_ms);

        tokio::select! {
            _ = tokio::time::sleep(next_poll) => {}
            _ = shutdown.notified() => {
                info!("Shutdown requested — draining in-flight checks, then exiting");
                break;
            }
        }
    }

    // Drain: finish every claimed check (they're gone from the aggregator's
    // queue — abandoning them would lose them, see OKS-405 note above), then
    // close the result channel so the sender task performs its final flush.
    let in_flight = check_tasks.len();
    if in_flight > 0 {
        info!(in_flight, "Waiting for in-flight checks to finish");
    }
    while let Some(joined) = check_tasks.join_next().await {
        if let Err(e) = joined {
            error!(error = %e, "Check task panicked");
        }
    }
    drop(result_tx);
    if let Err(e) = sender_handle.await {
        error!(error = %e, "Result sender task failed during shutdown");
    }
    info!("All in-flight checks completed and results flushed — exiting");
}

async fn health_handler(State(state): State<Arc<AgentState>>) -> Json<HealthResponse> {
    let last = state.last_result_at.lock().await.clone();
    let connected = state.aggregator_connected.load(Ordering::Relaxed);
    Json(HealthResponse {
        status: if connected { "ok".to_string() } else { "disconnected".to_string() },
        region: state.config.region.clone(),
        agent_type: state.config.agent_type.clone(),
        aggregator_connected: connected,
        checks_completed: state.checks_completed.load(Ordering::Relaxed),
        active_checks: state.active_checks.load(Ordering::Relaxed),
        max_concurrent_checks: state.config.max_concurrent_checks,
        last_result_at: last,
    })
}

async fn metrics_handler() -> impl IntoResponse {
    let body = metrics::render_metrics();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

async fn poll_and_execute(
    client: &reqwest::Client,
    check_client: &reqwest::Client,
    config: &Config,
    semaphore: &Arc<Semaphore>,
    state: &Arc<AgentState>,
    result_tx: &mpsc::Sender<CheckResult>,
    check_tasks: &mut JoinSet<()>,
) -> Result<usize, Box<dyn std::error::Error>> {
    // 1. Poll tasks from aggregator
    let url = format!(
        "{}/internal/tasks?region={}",
        config.aggregator_url, config.region
    );

    let mut req = client
        .get(&url)
        .header("X-Agent-Secret", &config.agent_secret);
    if let Some(id) = &config.agent_id {
        req = req.header("X-Agent-Id", id);
        req = req.header("X-Agent-Instance", &config.instance_id);
        // OKS-708 — this build can run one-shot tests from the dashboard
        // (private agents only; OKS-873 fleet identities have an id too).
        if config.agent_type == "private" {
            req = req.header("X-Agent-Capabilities", "test-tasks");
        }
    }
    let resp = req.send().await?;

    let status = resp.status();
    if status == reqwest::StatusCode::CONFLICT {
        // Single-instance lease: another pod holds this agent's identity.
        error!("another instance of this agent is already running — exiting");
        std::process::exit(1);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "aggregator returned HTTP {} — body: {}",
            status,
            &body[..body.len().min(500)]
        ).into());
    }

    let body_text = resp.text().await?;
    let tasks_resp: TasksResponse = match serde_json::from_str(&body_text) {
        Ok(t) => t,
        Err(e) => {
            let preview = &body_text[..body_text.len().min(500)];
            return Err(format!(
                "failed to decode aggregator response: {} — body preview: {}",
                e, preview
            ).into());
        }
    };
    let count = tasks_resp.tasks.len();

    if tasks_resp.tasks.is_empty() {
        return Ok(0);
    }

    // 2. Spawn checks into the shared JoinSet — bounded by the semaphore,
    // not awaited here (OKS-415): the poll loop keeps polling while checks
    // run, and the shutdown path drains the JoinSet.
    for mut task in tasks_resp.tasks {
        // OKS-880 — secrets sealed for this agent: opened in memory here. A
        // task we cannot open is skipped, never run without its credentials
        // (that would report a false outage, e.g. 401).
        if let Err(e) = seal::open(config.agent_id.as_deref(), &mut task) {
            error!(
                task_id = %task.task_id,
                monitor_id = %task.monitor_id,
                error = %e,
                "Skipping task: sealed secrets unreadable"
            );
            metrics::SEALED_TASKS_UNREADABLE.inc();
            continue;
        }
        // Task already deserialized fine (CheckType::Unknown is serde's
        // catch-all for a check_type string this build doesn't recognize —
        // see models.rs), but there's no handler to run it with. Skip
        // rather than let it crash `execute_check`'s match below or post a
        // bogus result for a check type we can't actually perform.
        if task.check_type == CheckType::Unknown {
            warn!(
                task_id = %task.task_id,
                monitor_id = %task.monitor_id,
                "Skipping task with unrecognized check_type — agent build is behind the aggregator"
            );
            continue;
        }

        let permit = semaphore.clone().acquire_owned().await?;
        state.active_checks.fetch_add(1, Ordering::Relaxed);
        let check_client = check_client.clone();
        let agent_type = config.agent_type.clone();
        let task_state = state.clone();
        let tx = result_tx.clone();
        let jitter_ms = config.check_start_jitter_ms;

        // OKS-708 — a test answers straight to the waiting dashboard request:
        // no jitter, no batch, no metrics, no stored result.
        if let Some(test_id) = task.test_id.clone() {
            let client = client.clone();
            let aggregator_url = config.aggregator_url.clone();
            let agent_secret = config.agent_secret.clone();
            let agent_id = config.agent_id.clone();
            let instance_id = config.instance_id.clone();
            check_tasks.spawn(async move {
                let result = execute_check(&check_client, &task).await;
                if let Err(e) = results::post_test_result(
                    &client,
                    &aggregator_url,
                    &agent_secret,
                    agent_id.as_deref(),
                    &instance_id,
                    &test_id,
                    &result,
                )
                .await
                {
                    warn!(test_id = %test_id, error = %e, "Test result not delivered");
                }
                task_state.active_checks.fetch_sub(1, Ordering::Relaxed);
                drop(permit);
            });
            continue;
        }

        check_tasks.spawn(async move {
            // Start jitter (OKS-415 follow-up) — without it every check of
            // the batch fires at the same instant and the burst inflates
            // measured p95-p99 latency (validated on the load harness:
            // p99 116ms vs 8ms for a 5ms target). Hash of the task id gives
            // a uniform-enough spread with no rand dependency; the latency
            // timer starts inside execute_check, after this sleep.
            if jitter_ms > 0 {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                task.task_id.hash(&mut hasher);
                let delay = hasher.finish() % jitter_ms;
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            let mut result = execute_check(&check_client, &task).await;
            result.agent_type = agent_type;

            // Record check metrics
            let check_type_str = match task.check_type {
                CheckType::Http => "http",
                CheckType::Ping => "ping",
                CheckType::Tcp => "tcp",
                CheckType::Dns => "dns",
                CheckType::Llm => "llm",
                CheckType::Grpc => "grpc",
                CheckType::Postgres => "postgres",
                CheckType::Mysql => "mysql",
                CheckType::Mongodb => "mongodb",
                CheckType::Smtp => "smtp",
                CheckType::Imap => "imap",
                CheckType::Redis => "redis",
                // Unreachable in practice — the outer loop `continue`s past
                // CheckType::Unknown before spawning this task at all.
                CheckType::Unknown => "unknown",
            };
            metrics::record_check(check_type_str, result.success, result.latency_ms);

            task_state.checks_completed.fetch_add(1, Ordering::Relaxed);
            *task_state.last_result_at.lock().await = Some(chrono::Utc::now().to_rfc3339());

            // 3. Hand the result to the batch sender (OKS-416) — the permit
            // is released right after, instead of being held through up to
            // three posting retries like before.
            if let Err(e) = tx.send(result).await {
                error!(
                    task_id = %task.task_id,
                    error = %e,
                    "Result channel closed — result dropped"
                );
            }

            task_state.active_checks.fetch_sub(1, Ordering::Relaxed);
            drop(permit);
        });
    }

    Ok(count)
}

async fn execute_check(client: &reqwest::Client, task: &CheckTask) -> CheckResult {
    let mut result = dispatch_check(client, task).await;
    // Dernier filet AVANT que le message ne parte vers l'agrégateur : une
    // erreur de transport cite volontiers l'URL complète, clé d'API en
    // paramètre comprise ; un serveur bavard renvoie l'identifiant refusé.
    // Le champ `error` finit dans check_results, l'historique d'événements,
    // les alertes et les exports — il ne doit porter aucun secret.
    if let Some(error) = result.error.take() {
        result.error = Some(crate::auth::scrub_secrets(&error, task));
    }
    result
}

async fn dispatch_check(client: &reqwest::Client, task: &CheckTask) -> CheckResult {
    match task.check_type {
        CheckType::Http => checks::http::check_http(client, task).await,
        CheckType::Ping => checks::ping::check_ping(task).await,
        CheckType::Tcp => checks::tcp::check_tcp(task).await,
        CheckType::Dns => checks::dns::check_dns(task).await,
        CheckType::Llm => checks::llm::check_llm(client, task).await,
        CheckType::Grpc => checks::grpc::check_grpc(task).await,
        // OKS-668 — one handler for the three database dialects.
        CheckType::Postgres | CheckType::Mysql | CheckType::Mongodb => checks::db::check_db(task).await,
        CheckType::Smtp | CheckType::Imap | CheckType::Redis => {
            checks::service::check_service(task).await
        }
        // The poll loop `continue`s past CheckType::Unknown before this is
        // ever called (see poll_and_execute) — there's no handler to run an
        // unrecognized check type with.
        CheckType::Unknown => unreachable!("Unknown check_type filtered out before dispatch"),
    }
}

/// OKS-759 — un poll qui revient PLEIN signifie que la file de la région a
/// plus de travail qu'un seul poll n'en rapporte. `/internal/tasks` en rend
/// 50 au plus (51 en pratique : la borne de fin est inclusive côté BullMQ),
/// donc à partir de ce seuil le lot est considéré plein.
const FULL_BATCH_THRESHOLD: usize = 50;

/// Palier de sécurité pour le cas dégénéré (des lots pleins servis
/// instantanément) : ~10 polls/s par région au maximum.
const FULL_BATCH_REPOLL_DELAY_MS: u64 = 100;

/// OKS-759 — combien de temps attendre avant le prochain poll.
///
/// Un lot plein veut dire que la file de la région a plus de travail qu'un
/// poll n'en rapporte : on repart presque tout de suite, au lieu d'attendre
/// l'intervalle complet. Sans ça le débit d'une région était plafonné à un
/// lot par intervalle (50 tâches / 10 s ≈ 300 checks/min) quoi qu'encaisse le
/// backend, et le retard des checks grimpait sans jamais se résorber.
fn next_poll_delay(full_batch: bool, poll_interval_ms: u64) -> Duration {
    if full_batch {
        Duration::from_millis(FULL_BATCH_REPOLL_DELAY_MS)
    } else {
        Duration::from_millis(poll_interval_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Régression OKS-759 : mesuré en charge le 2026-09-11 — 400 checks/min
    // demandés sur une région, 306 servis, et un retard qui montait de 18 s
    // par minute. La cause était ce sommeil inconditionnel après un lot plein.
    #[test]
    fn repolls_almost_immediately_after_a_full_batch() {
        let delay = next_poll_delay(true, 10_000);
        assert_eq!(delay, Duration::from_millis(FULL_BATCH_REPOLL_DELAY_MS));
        assert!(
            delay < Duration::from_millis(10_000),
            "un lot plein ne doit pas attendre l'intervalle de poll"
        );
    }

    // Le cas nominal ne change pas : file vide ou partiellement servie, on
    // attend l'intervalle configuré (sinon l'agent interrogerait le backend
    // en boucle pour rien).
    #[test]
    fn keeps_the_configured_interval_when_the_batch_is_not_full() {
        assert_eq!(next_poll_delay(false, 10_000), Duration::from_millis(10_000));
        assert_eq!(next_poll_delay(false, 2_500), Duration::from_millis(2_500));
    }
}


#[cfg(test)]
mod tls_provider_tests {
    // Without install_tls_crypto_provider() this panics with "Could not
    // automatically determine the process-level CryptoProvider" — exactly
    // what every TLS gRPC check hit in production.
    #[test]
    fn rustls_client_config_builds_once_the_provider_is_installed() {
        super::install_tls_crypto_provider();
        let _ = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    }
}
