use prometheus::{
    register_counter_vec, register_histogram_vec, register_counter, register_gauge,
    CounterVec, HistogramVec, Counter, Gauge, Encoder, TextEncoder,
};
use std::sync::LazyLock;

pub static CHECKS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "uptime_agent_checks_total",
        "Total checks executed by this agent",
        &["check_type", "success"]
    )
    .expect("failed to register checks_total")
});

pub static CHECK_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "uptime_agent_check_latency_ms",
        "Check latency in milliseconds",
        &["check_type"],
        vec![10.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0]
    )
    .expect("failed to register check_latency")
});

pub static ERRORS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "uptime_agent_errors_total",
        "Total errors encountered by this agent",
        &["error_type"]
    )
    .expect("failed to register errors_total")
});

pub static POLL_CYCLES_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "uptime_agent_poll_cycles_total",
        "Total poll cycles executed"
    )
    .expect("failed to register poll_cycles_total")
});

pub static AGGREGATOR_UP: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "uptime_agent_aggregator_up",
        "Whether the agent can reach the aggregator (1 = up, 0 = down)"
    )
    .expect("failed to register aggregator_up")
});

pub static TASKS_RECEIVED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "uptime_agent_tasks_received_total",
        "Total tasks received from the aggregator"
    )
    .expect("failed to register tasks_received_total")
});

pub static QUEUE_DEPTH: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "uptime_agent_queue_depth",
        "Number of pending check jobs in this agent's region queue"
    )
    .expect("failed to register queue_depth")
});

/// Record a completed check in metrics
pub fn record_check(check_type: &str, success: bool, latency_ms: Option<u64>) {
    CHECKS_TOTAL
        .with_label_values(&[check_type, if success { "true" } else { "false" }])
        .inc();

    if let Some(latency) = latency_ms {
        CHECK_LATENCY
            .with_label_values(&[check_type])
            .observe(latency as f64);
    }
}

/// Render all metrics as Prometheus text format
pub fn render_metrics() -> String {
    // Force lazy initialization
    let _ = &*CHECKS_TOTAL;
    let _ = &*CHECK_LATENCY;
    let _ = &*ERRORS_TOTAL;
    let _ = &*POLL_CYCLES_TOTAL;
    let _ = &*AGGREGATOR_UP;
    let _ = &*TASKS_RECEIVED_TOTAL;
    let _ = &*QUEUE_DEPTH;

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
