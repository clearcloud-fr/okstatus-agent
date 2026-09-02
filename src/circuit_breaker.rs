use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;

/// Simple circuit breaker: tracks consecutive failures and applies exponential backoff.
/// After `threshold` failures within `window`, the circuit opens and requires
/// an exponentially increasing backoff delay before the next attempt.
pub struct CircuitBreaker {
    threshold: u64,
    consecutive_failures: AtomicU64,
    last_failure: Mutex<Option<Instant>>,
    base_backoff: Duration,
    max_backoff: Duration,
}

impl CircuitBreaker {
    pub fn new(threshold: u64, base_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            threshold,
            consecutive_failures: AtomicU64::new(0),
            last_failure: Mutex::new(None),
            base_backoff,
            max_backoff,
        }
    }

    /// Check if the circuit is open (should backoff).
    /// Returns the backoff duration if open, None if closed.
    pub async fn check_backoff(&self) -> Option<Duration> {
        let failures = self.consecutive_failures.load(Ordering::Relaxed);
        if failures < self.threshold {
            return None;
        }

        let last = self.last_failure.lock().await;
        if let Some(last_time) = *last {
            let exponent = (failures - self.threshold).min(10) as u32;
            let backoff = self.base_backoff * 2u32.pow(exponent);
            let backoff = backoff.min(self.max_backoff);

            let elapsed = last_time.elapsed();
            if elapsed < backoff {
                return Some(backoff - elapsed);
            }
        }

        None
    }

    /// Record a successful call — resets the failure counter.
    pub fn record_success(&self) {
        let prev = self.consecutive_failures.swap(0, Ordering::Relaxed);
        if prev >= self.threshold {
            warn!(
                previous_failures = prev,
                "Circuit breaker closed — aggregator recovered"
            );
        }
    }

    /// Record a failed call — increments the failure counter.
    pub async fn record_failure(&self) {
        let count = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure.lock().await = Some(Instant::now());

        if count == self.threshold {
            warn!(
                threshold = self.threshold,
                "Circuit breaker opened — backing off aggregator calls"
            );
        }
    }
}
