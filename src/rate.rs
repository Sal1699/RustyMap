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
    verbose: bool,
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
            verbose,
        })
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
