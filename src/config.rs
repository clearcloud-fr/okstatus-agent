use std::env;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub region: String,
    pub agent_type: String,  // 'k8s', 'vps' or 'private' (OKS-401)
    pub aggregator_url: String,
    pub agent_secret: String,
    // OKS-401 — set after enrollment (enroll.rs) for a private agent, or from
    // FLEET_AGENT_ID for an identified agent of our network (OKS-873; then
    // agent_type stays k8s/vps). Some = every /internal/* request carries
    // X-Agent-Id alongside the per-agent X-Agent-Secret.
    pub agent_id: Option<String>,
    // OKS-401 — unique id for THIS running process, sent as X-Agent-Instance
    // on every /internal/* call in private mode. The backend's single-instance
    // lease uses it to reject a second pod started with the same credentials.
    pub instance_id: String,
    pub poll_interval_ms: u64,
    pub max_concurrent_checks: usize,
    pub check_timeout_ms: u64,
    pub results_flush_interval_ms: u64,
    pub results_batch_max: usize,
    pub check_start_jitter_ms: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            region: env::var("REGION").unwrap_or_else(|_| "fr".to_string()),
            agent_type: env::var("AGENT_TYPE").unwrap_or_else(|_| "k8s".to_string()),
            aggregator_url: env::var("AGGREGATOR_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            agent_secret: env::var("AGENT_SECRET").unwrap_or_default(),
            agent_id: None,
            // Unique per process: pod name (HOSTNAME, unique per k8s pod) +
            // pid + start nanos, so two pods — or two processes — never share
            // an instance id. Not a secret, just an identity for the lease.
            instance_id: {
                let host = env::var("HOSTNAME").unwrap_or_else(|_| "agent".to_string());
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                format!("{}-{}-{}", host, std::process::id(), nanos)
            },
            poll_interval_ms: env::var("POLL_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2_000),
            max_concurrent_checks: env::var("MAX_CONCURRENT_CHECKS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            check_timeout_ms: env::var("CHECK_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5_000),
            results_flush_interval_ms: env::var("RESULTS_FLUSH_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2_000),
            results_batch_max: env::var("RESULTS_BATCH_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            // OKS-415 follow-up — spread each poll batch's checks over this
            // window instead of firing them all at the same instant: the
            // synchronized burst inflates measured p95-p99 latency (checks
            // racing each other on a shared target or the agent's uplink).
            // 0 disables the jitter.
            check_start_jitter_ms: env::var("CHECK_START_JITTER_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_000),
        }
    }
}
