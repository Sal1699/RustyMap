use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Adaptive concurrency controller.
///
/// Tracks timeout vs success ratio over a sliding window of the last N
/// observations and grows or shrinks the target parallelism accordingly.
/// Uses a tokio Semaphore as the underlying inflight-limiter; when the
/// target drops, we simply stop returning permits to the pool.
pub struct AdaptiveLimiter {
    sem: Arc<Semaphore>,
    target: AtomicUsize,
    min_parallel: usize,
    max_parallel: usize,
    successes: AtomicU64,
    timeouts: AtomicU64,
    total_rtt_ms: AtomicU64,
    /// Persistent EWMA of observed RTT in microseconds (NOT reset by
    /// `adjust()`, unlike `total_rtt_ms`). Drives `adaptive_timeout` so a
    /// filtered port on a fast LAN stops costing the full `--timeout`.
    ewma_rtt_us: AtomicU64,
    rtt_samples: AtomicU64,
    verbose: bool,
}

/// How much headroom over the mean RTT to allow before calling a probe lost.
/// nmap uses `srtt + 4·rttvar`; a flat 10× mean is a stable, slightly
/// conservative proxy that still collapses a 1500 ms LAN wait to the floor.
pub const RTT_TIMEOUT_MULT: u32 = 10;

/// nmap-style adaptive per-probe timeout. Until we have observed real RTTs
/// the full `base` (the user's `--timeout`) is used; once we have a mean,
/// the wait shrinks toward `RTT_TIMEOUT_MULT × rtt`, clamped to
/// `[floor, base]`. On a LAN (RTT < 1 ms) this collapses the dominant cost
/// of small SYN/connect scans — a filtered port waited the full 1.5 s × retries
/// before — while a slow WAN host (high RTT) keeps a long timeout because the
/// product rises with the measured RTT. Self-scaling, never below `floor`.
pub fn adaptive_timeout(base: Duration, mean_rtt: Option<Duration>, floor: Duration) -> Duration {
    match mean_rtt {
        Some(rtt) if !rtt.is_zero() => rtt
            .saturating_mul(RTT_TIMEOUT_MULT)
            .clamp(floor.min(base), base),
        _ => base,
    }
}

/// The per-probe timeout floor derived from the user's base timeout: one
/// tenth of it, bounded to a sane LAN range so `adaptive_timeout` never waits
/// absurdly little (missing a slow reply) nor as long as the full base.
pub fn timeout_floor(base: Duration) -> Duration {
    (base / 10).clamp(Duration::from_millis(50), Duration::from_millis(300))
}

impl AdaptiveLimiter {
    pub fn new(initial: usize, min_parallel: usize, max_parallel: usize, verbose: bool) -> Arc<Self> {
        let clamped = initial.clamp(min_parallel, max_parallel);
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(clamped)),
            target: AtomicUsize::new(clamped),
            min_parallel,
            max_parallel,
            successes: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            total_rtt_ms: AtomicU64::new(0),
            ewma_rtt_us: AtomicU64::new(0),
            rtt_samples: AtomicU64::new(0),
            verbose,
        })
    }

    /// Mean observed RTT, once at least a few replies have been seen.
    /// `None` until then so the scan uses the full base timeout while warming
    /// up. Reads the persistent EWMA, not the per-interval `total_rtt_ms`.
    pub fn mean_rtt(&self) -> Option<Duration> {
        if self.rtt_samples.load(Ordering::Relaxed) < 3 {
            return None;
        }
        let us = self.ewma_rtt_us.load(Ordering::Relaxed);
        if us == 0 {
            None
        } else {
            Some(Duration::from_micros(us))
        }
    }

    pub fn semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.sem)
    }

    #[allow(dead_code)]
    pub fn target(&self) -> usize {
        self.target.load(Ordering::Relaxed)
    }

    pub fn record(&self, timed_out: bool, rtt: Duration) {
        if timed_out {
            self.timeouts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.successes.fetch_add(1, Ordering::Relaxed);
            self.total_rtt_ms.fetch_add(rtt.as_millis() as u64, Ordering::Relaxed);
            // Persistent RTT EWMA (α=0.25) in microseconds, surviving
            // `adjust()`. A racy load/store is fine for a timing heuristic.
            let sample = rtt.as_micros().min(u64::MAX as u128) as u64;
            let prev = self.ewma_rtt_us.load(Ordering::Relaxed);
            let next = if prev == 0 {
                sample
            } else {
                (prev * 3 + sample) / 4
            };
            self.ewma_rtt_us.store(next, Ordering::Relaxed);
            self.rtt_samples.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Recompute and apply a new target parallelism based on observations
    /// since the last call. Safe to call from a single background task.
    pub fn adjust(&self) {
        let s = self.successes.swap(0, Ordering::Relaxed);
        let t = self.timeouts.swap(0, Ordering::Relaxed);
        let total = s + t;
        if total < 10 {
            return;
        }
        let ratio = t as f64 / total as f64;
        let cur = self.target.load(Ordering::Relaxed);

        let new = if ratio > 0.30 {
            (cur as f64 * 0.6) as usize
        } else if ratio > 0.15 {
            (cur as f64 * 0.85) as usize
        } else if ratio < 0.02 {
            (cur as f64 * 1.4) as usize
        } else if ratio < 0.05 {
            (cur as f64 * 1.15) as usize
        } else {
            cur
        };

        let new = new.clamp(self.min_parallel, self.max_parallel);
        if new == cur {
            return;
        }

        self.target.store(new, Ordering::Relaxed);
        if new > cur {
            self.sem.add_permits(new - cur);
        } else {
            let to_remove = cur - new;
            let sem = Arc::clone(&self.sem);
            tokio::spawn(async move {
                for _ in 0..to_remove {
                    if let Ok(p) = sem.acquire().await {
                        p.forget();
                    }
                }
            });
        }
        if self.verbose {
            eprintln!(
                "[adaptive] timeout_ratio={:.2} cur={} -> new={}",
                ratio, cur, new
            );
        }
        self.total_rtt_ms.store(0, Ordering::Relaxed);
    }

    pub fn spawn_adjuster(self: &Arc<Self>, interval_ms: u64) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_millis(interval_ms));
            t.tick().await;
            loop {
                t.tick().await;
                me.adjust();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_timeout_uses_base_without_samples() {
        let base = Duration::from_millis(1500);
        assert_eq!(adaptive_timeout(base, None, timeout_floor(base)), base);
    }

    #[test]
    fn adaptive_timeout_collapses_on_fast_lan() {
        let base = Duration::from_millis(1500);
        let floor = timeout_floor(base); // 150ms
        // 0.3ms LAN RTT → 10× = 3ms, clamped up to the 150ms floor (not 1500).
        let eff = adaptive_timeout(base, Some(Duration::from_micros(300)), floor);
        assert_eq!(eff, floor);
        assert!(eff < base);
    }

    #[test]
    fn adaptive_timeout_rises_for_slow_wan() {
        let base = Duration::from_millis(1500);
        let floor = timeout_floor(base);
        // 80ms WAN RTT → 10× = 800ms, between floor and base.
        let eff = adaptive_timeout(base, Some(Duration::from_millis(80)), floor);
        assert_eq!(eff, Duration::from_millis(800));
    }

    #[test]
    fn adaptive_timeout_never_exceeds_base() {
        let base = Duration::from_millis(1500);
        let floor = timeout_floor(base);
        // 500ms RTT → 10× = 5s, capped at base.
        let eff = adaptive_timeout(base, Some(Duration::from_millis(500)), floor);
        assert_eq!(eff, base);
    }

    #[test]
    fn timeout_floor_is_tenth_bounded() {
        assert_eq!(timeout_floor(Duration::from_millis(1500)), Duration::from_millis(150));
        // Tiny base → floored at 50ms.
        assert_eq!(timeout_floor(Duration::from_millis(200)), Duration::from_millis(50));
        // Huge base → capped at 300ms.
        assert_eq!(timeout_floor(Duration::from_millis(9000)), Duration::from_millis(300));
    }

    #[test]
    fn mean_rtt_none_until_three_samples() {
        let lim = AdaptiveLimiter::new(100, 4, 500, false);
        lim.record(false, Duration::from_millis(10));
        lim.record(false, Duration::from_millis(10));
        assert!(lim.mean_rtt().is_none());
        lim.record(false, Duration::from_millis(10));
        assert_eq!(lim.mean_rtt(), Some(Duration::from_millis(10)));
    }
}
